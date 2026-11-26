//! Network stage: DNS, takeover checks, liveness and the infrastructure modules.

use std::sync::Arc;
use std::time::Duration;

use foca_core::Severity;
use serde_json::Value;

use crate::analysis::facts::{self, NetFacts};
use crate::analysis::rules::{self, KnownHost};
use crate::engine::lock;

use super::search::{host_source_label, K_HOST_SRC};
use super::takeover::dangling;
use super::*;

fn cloud_of(holder: &str) -> &'static str {
    let h = holder.to_lowercase();
    if h.contains("cloudflare") {
        "Cloudflare"
    } else if h.contains("amazon") {
        "AWS"
    } else if h.contains("microsoft") {
        "Azure"
    } else if h.contains("google") {
        "Google Cloud"
    } else if h.contains("akamai") {
        "Akamai"
    } else if h.contains("fastly") {
        "Fastly"
    } else {
        "-"
    }
}

pub(super) async fn stage_network(c: &mut Ctx) -> Result<(), Stop> {
    let cfg = c.e.cfg.clone();
    let dns: Arc<dyn foca_net::dns::DnsLookup> = match &cfg.dns {
        Some(d) => d.clone(),
        // through a proxy or Tor: DoH via the same proxy (settings.net.dns_mode, `auto` by default)
        None => {
            let mode = c.e.store().settings_get().unwrap_or_default()["net"]["dns_mode"]
                .as_str()
                .map(foca_net::doh::DnsMode::parse)
                .unwrap_or_default();
            match foca_net::doh::resolver(mode, &Default::default(), &c.net) {
                Ok(d) => d,
                Err(e) => return Err(Stop::Error(e.to_string())),
            }
        }
    };
    let now = c.e.now_iso();
    let sid = c.scan_id.clone();
    let mut f: NetFacts = facts::get(&lock(&c.db), facts::K_NET);
    let hosts_known = known_hosts(&lock(&c.db));
    let scope = c.scope.clone();
    let in_scope = move |h: &str, hosts: &[KnownHost]| rules::check(&scope, h, hosts);
    let steps = 5.0;
    let (m_dns, m_ct, m_alive, m_axfr) = (
        c.module("dns"),
        c.module("dns") || c.module("crt"),
        c.module("alive"),
        c.module("axfr"),
    );
    let cached_canary = lock(&c.st).canary.clone();
    let canary = match cached_canary {
        Some(rep) => rep,
        None => {
            let live_endpoints = cfg.endpoints.crtsh.starts_with("https://crt.sh");
            let ccfg = cfg
                .canary
                .clone()
                .or_else(|| (live_endpoints && !c.net.is_local_only()).then(Default::default));
            let rep = match ccfg {
                Some(ccfg) => {
                    foca_net::canary::check_network(
                        &c.net,
                        dns.as_ref(),
                        c.level == "external",
                        &ccfg,
                    )
                    .await
                }
                None => foca_net::canary::CanaryReport::default(),
            };
            {
                let mut st = lock(&c.st);
                st.canary = Some(rep.clone());
                c.e.persist_run(&st);
            }
            if rep.tcp_intercept {
                c.warn(
                    "canary.tcp_intercept",
                    "Сеть устройства перехватывает TCP (локальный VPN/AdGuard): проверка живости хостов подтверждается по протоколу",
                );
            }
            if rep.dns_hijack {
                c.warn(
                    "canary.dns_hijack",
                    &format!(
                        "Обнаружена подмена DNS для зоны .invalid ({})",
                        rep.dns_hijack_ips.join(", ")
                    ),
                );
            }
            if rep.tls_mitm {
                c.warn(
                    "canary.tls_mitm",
                    &format!(
                        "Обнаружен TLS MITM / инспекция трафика ({})",
                        rep.tls_issuer.as_deref().unwrap_or("unknown CA")
                    ),
                );
            }
            rep
        }
    };
    // 1. DNS summary of target domains: records, SPF/DMARC, dangling CNAME
    let dns_domains: Vec<String> = c
        .domains
        .iter()
        .take(if m_dns { 5 } else { 0 })
        .cloned()
        .collect();
    let mut sub = (!dns_domains.is_empty()).then(|| c.sub_begin("dns", dns_domains.len()));
    for (k, d) in dns_domains.iter().enumerate() {
        c.gate().await?;
        if let Some(s) = sub.as_mut() {
            c.sub_tick(s, k, dns_domains.len(), Value::Null);
        }
        let rep = foca_net::dns::dns_report(dns.as_ref(), d).await;
        if rep.nxdomain {
            continue;
        }
        let h = f.host(d);
        h.source = if h.source.is_empty() {
            "DNS".into()
        } else {
            h.source.clone()
        };
        if h.first_scan.is_none() {
            h.first_scan = Some(sid.clone());
        }
        let mut rows = Vec::new();
        for (t, vals) in &rep.records {
            for v in vals {
                let note = if t == "TXT" && v.starts_with("v=spf1") {
                    if v.contains("~all") {
                        "SPF ~all"
                    } else {
                        "SPF"
                    }
                } else {
                    ""
                };
                if ["A", "AAAA", "CNAME", "MX", "TXT", "NS"].contains(&t.as_str()) {
                    rows.push((t.clone(), v.clone(), note.to_string()));
                }
            }
        }
        if let Some(dm) = &rep.mail.dmarc {
            rows.push((
                "TXT".into(),
                format!("_dmarc: {}", dm.record),
                format!("DMARC p={}", dm.p),
            ));
        }
        for (ip, ptr) in &rep.ptr {
            for p in ptr {
                rows.push(("PTR".into(), p.clone(), ip.clone()));
            }
        }
        if let Some(a) = rep.records.get("A").and_then(|v| v.first()) {
            h.ip = a.clone();
        }
        h.dns = rows;
        for i in &rep.mail.issues {
            if i.id == "dkim_not_found" {
                continue;
            }
            let nf = facts::net_finding(
                &format!("mail-{}", i.id),
                d,
                i.title.clone(),
                sev_of(&i.sev),
                d,
                "mail",
                "SPF/DMARC",
                "dns",
                false,
                &now,
                Some(&sid),
                i.detail.clone(),
                "Настроить SPF с -all и DMARC p=reject после анализа отчётов rua.",
                format!(
                    "{}\n{}",
                    rep.mail
                        .spf
                        .as_ref()
                        .map(|s| s.record.as_str())
                        .unwrap_or("SPF: нет"),
                    rep.mail
                        .dmarc
                        .as_ref()
                        .map(|s| s.record.as_str())
                        .unwrap_or("DMARC: нет")
                ),
                Some(format!("dns://{d}")),
            );
            f.findings.entry(nf.id).or_insert(nf);
        }
        for dg in &rep.dangling {
            dangling(&mut f, dg, &now, &sid);
        }
    }
    if let Some(s) = sub.take() {
        c.sub_end(s, dns_domains.len(), "done", "");
    }
    // 1b. infrastructure (all levels): SaaS, M365 tenant, mail policies, CT history, CDN/origin
    infra::passive(c, &dns, &mut f, &now, &sid).await?;
    c.progress(4, 1.0 / steps);
    // 2. subdomains from CT: addresses and dangling CNAMEs (excluded names are never touched)
    let cand: Vec<String> = f
        .ct_hosts
        .iter()
        .filter(|h| {
            c.domains
                .iter()
                .any(|d| *h == d || h.ends_with(&format!(".{d}")))
        })
        .filter(|h| in_scope(h, &hosts_known).code != "excluded")
        .take(if m_ct { cfg.host_limit } else { 0 })
        .cloned()
        .collect();
    c.gate().await?;
    let hsrc: std::collections::BTreeMap<String, Vec<String>> =
        facts::get(&lock(&c.db), K_HOST_SRC);
    let sub = c.sub_begin("resolve", cand.len());
    let alive = foca_net::dns::resolve_alive(dns.clone(), &cand, 4).await;
    c.sub_end(
        sub,
        cand.len(),
        "done",
        &format!("с адресом: {}", alive.len()),
    );
    for (h, ips) in alive {
        let x = f.host(&h);
        if x.source.is_empty() || x.source == "crt.sh" {
            x.source = host_source_label(hsrc.get(&h).map(Vec::as_slice).unwrap_or(&[]));
        }
        if x.first_scan.is_none() {
            x.first_scan = Some(sid.clone());
        }
        if let Some(ip) = ips.first() {
            x.ip = ip.clone();
        }
        x.dns = ips
            .iter()
            .map(|i| ("A".into(), i.clone(), String::new()))
            .collect();
    }
    let mut sub = c.sub_begin("takeover", cand.len());
    let checked = takeover::check_all(
        dns.clone(),
        &cand,
        takeover::CONCURRENCY,
        c.pause.clone(),
        c.cancel.clone(),
        |n| c.sub_tick(&mut sub, n, cand.len(), Value::Null),
    )
    .await?;
    let mut hits = 0usize;
    for dg in checked.iter().flatten() {
        hits += 1;
        dangling(&mut f, dg, &now, &sid);
    }
    c.sub_end(sub, cand.len(), "done", &format!("висячих CNAME: {hits}"));
    // 2b. subdomain enumeration (standard/full): brute force, permutations, NSEC, PTR
    infra::enumerate(c, &dns, &mut f, &hosts_known, &now, &sid).await?;
    c.progress(4, 2.0 / steps);
    // 2c. direct IP / CIDR / IP-range / IP-URL targets: seed into NetFacts so RDAP, InternetDB,
    // TCP liveness, TLS and ports process them with full scope & ADR-0009 enforcement.
    for ip in &c.direct_ips {
        if in_scope(ip, &hosts_known).code == "excluded" {
            continue;
        }
        let h = f.host(ip);
        if h.ip.is_empty() {
            h.ip = ip.clone();
        }
        if h.source.is_empty() {
            h.source = "Цель скоупа".into();
        }
        if h.first_scan.is_none() {
            h.first_scan = Some(sid.clone());
        }
    }
    // 3. RDAP: network/ASN of in-scope host addresses (passive)
    let ips: Vec<(String, String)> = f
        .hosts
        .values()
        .filter(|h| rules::ip4(&h.ip).is_some() && h.asn.is_none())
        .map(|h| (h.name.clone(), h.ip.clone()))
        .take(if m_ct { cfg.rdap_limit } else { 0 })
        .collect();
    let recon_net = c.group_net("recon")?;
    let n_ips = ips.len();
    let mut sub = (n_ips > 0).then(|| c.sub_begin("rdap", n_ips));
    for (k, (name, ip)) in ips.into_iter().enumerate() {
        c.gate().await?;
        if let Some(s) = sub.as_mut() {
            c.sub_tick(s, k, n_ips, Value::Null);
        }
        let Ok(addr) = ip.parse() else { continue };
        if let Ok(info) = foca_net::rdap::ip_info(&recon_net, &cfg.endpoints.rdap, addr).await {
            let holder = info.holder.clone().unwrap_or_default();
            let h = f.host(&name);
            h.asn = info
                .asns
                .first()
                .map(|a| format!("AS{a} · {}", if holder.is_empty() { "-" } else { &holder }));
            if h.cloud == "-" || h.cloud.is_empty() {
                h.cloud = cloud_of(&holder).into();
            }
        }
    }
    if let Some(s) = sub.take() {
        c.sub_end(s, n_ips, "done", "");
    }
    // 3b. Shodan InternetDB (keyless, passive): ports, CPEs and CVEs by host IP
    if m_ct
        && source_enabled(
            &c.e.store().settings_get().unwrap_or_default()["sources"],
            "internetdb",
        )
        && lock(&c.st).source_ids.iter().any(|x| x == "internetdb")
    {
        c.gate().await?;
        let base = cfg
            .endpoints
            .sources
            .get("internetdb")
            .cloned()
            .unwrap_or_else(|| "https://internetdb.shodan.io".into());
        let known: Vec<KnownHost> = f
            .hosts
            .values()
            .map(|h| KnownHost {
                name: h.name.clone(),
                ip: h.ip.clone(),
            })
            .collect();
        let n = crate::analysis::intel::internetdb_stage(
            &recon_net,
            &base,
            &mut f,
            &now,
            &sid,
            |name| in_scope(name, &known).ok,
            |id, st, n, e| c.source_event_full(id, st, n, e),
        )
        .await;
        if let Err(foca_net::NetError::Cancelled) = n {
            return Err(Stop::Cancelled);
        }
    }
    // 3c. user-installed sandboxed plugins (scope- and passive-mode-checked, never fail the scan)
    plugins::run(c, &dns, &mut f, &hosts_known, &now, &sid).await?;
    c.progress(4, 3.0 / steps);
    let target_net = c.group_net("target")?;
    // 4. TCP liveness: only hosts in scope and not excluded (target/active levels)
    if c.level != "external" && m_alive {
        let known: Vec<KnownHost> = f
            .hosts
            .values()
            .map(|h| KnownHost {
                name: h.name.clone(),
                ip: h.ip.clone(),
            })
            .chain(hosts_known.iter().cloned())
            .collect();
        // CDN / cloud / shared-hosting addresses of bulk-added names are never probed
        let held = ports::held_names(c, &f);
        let names: Vec<String> = f
            .hosts
            .values()
            .filter(|h| h.dangling.is_none() && in_scope(&h.name, &known).ok)
            .filter(|h| !held.contains(&h.name))
            .map(|h| h.name.clone())
            .take(cfg.host_limit)
            .collect();
        let verify_proto = canary.tcp_intercept;
        let mut liveness_warned = false;
        let n_names = names.len();
        let mut sub = c.sub_begin("liveness", n_names);
        let mut live = 0usize;
        for (k, n) in names.into_iter().enumerate() {
            c.gate().await?;
            c.sub_tick(&mut sub, k, n_names, Value::Null);
            match foca_net::tcp::tcp_alive_checked(
                &target_net,
                &n,
                &cfg.alive_ports,
                Duration::from_secs(5),
                verify_proto,
            )
            .await
            {
                Ok(a) => {
                    if a.unreliable {
                        if !liveness_warned {
                            liveness_warned = true;
                            c.warn(
                                "liveness.unreliable",
                                "Проверка живости хоста недостоверна: TCP-соединение принимается без ответа сервиса (перехват VPN/AdGuard)",
                            );
                        }
                        continue;
                    }
                    let h = f.host(&n);
                    if a.ports.iter().any(|p| p.open && p.verified) {
                        live += 1;
                    }
                    for p in a.ports.iter().filter(|p| p.open && p.verified) {
                        let svc = match p.port {
                            443 | 8443 => "https",
                            80 | 8080 => "http",
                            22 => "ssh",
                            21 => "ftp",
                            25 => "smtp",
                            _ => "tcp",
                        };
                        let k = format!("{}/tcp", p.port);
                        if !h.services.iter().any(|s| s.0 == k) {
                            h.services.push((k, svc.into(), String::new()));
                        }
                    }
                }
                Err(foca_net::NetError::Cancelled) => return Err(Stop::Cancelled),
                Err(_) => {}
            }
        }
        c.sub_end(sub, n_names, "done", &format!("отвечают: {live}"));
    }
    // 4b. TLS certificate inspection of live in-scope hosts (standard/full)
    infra::tls_standard(c, &mut f, &hosts_known, &now, &sid).await?;
    c.progress(4, 4.0 / steps);
    // 5. AXFR (active stage): target domains from the scope, minus exclusions
    if c.level == "active" && m_axfr {
        for d in c.domains.clone() {
            c.gate().await?;
            if !in_scope(&d, &hosts_known).ok {
                continue;
            }
            if let Ok(res) =
                foca_net::axfr::axfr(&target_net, dns.as_ref(), &d, Duration::from_secs(10)).await
            {
                for r in res.into_iter().filter(|r| r.ok) {
                    let nf = facts::net_finding(
                        "axfr-open",
                        &format!("{d}@{}", r.server),
                        format!("Разрешён трансфер зоны (AXFR) на {}", r.server),
                        Severity::High,
                        &r.server,
                        "dns",
                        "DNS (AXFR)",
                        "axfr",
                        true,
                        &now,
                        Some(&sid),
                        format!(
                            "Сервер {} отдаёт полную копию зоны {d}: {} записей.",
                            r.server,
                            r.records.len()
                        ),
                        "Ограничить AXFR адресами вторичных серверов (allow-transfer) и использовать TSIG.",
                        r.records
                            .iter()
                            .take(10)
                            .map(|x| format!("{} {} {}", x.name, x.rtype, x.value))
                            .collect::<Vec<_>>()
                            .join("\n"),
                        Some(format!("dns://{}", r.server)),
                    );
                    f.findings.entry(nf.id).or_insert(nf);
                }
            }
        }
    }
    infra::roles(c, &mut f, &now, &sid);
    facts::put(&lock(&c.db), facts::K_NET, &f)?;
    let new = reanalyze_bg(c).await?;
    c.findings_events(&new);
    Ok(())
}
