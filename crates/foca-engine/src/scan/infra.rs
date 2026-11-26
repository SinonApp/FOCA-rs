//! Infrastructure modules of the scan, embedded into the existing stages:
//!
//! * network stage, every level ([`passive`]): SaaS map from DNS, Microsoft 365 tenant
//!   (Microsoft endpoints only), mail policies (BIMI/MTA-STS/TLS-RPT/CAA/DNSSEC), CT history
//!   (timeline, abandoned subdomains, `O=` pivot as out-of-scope candidates), CDN/cloud
//!   classification and origin candidates; host roles at the end of the stage ([`roles`]);
//! * network stage, standard and full ([`enumerate`], [`tls_standard`]): subdomain brute force
//!   (top-1500 / top-5000 / custom), smart permutations (subdomains + document tokens), PTR of
//!   in-scope addresses, MTA-STS policy fetch, TLS certificate inspection of live hosts; NSEC
//!   walking at the active level only;
//! * ports stage, active level ([`tls_active`]): legacy TLS versions and weak ciphers, STARTTLS
//!   on open mail/DB/RDP ports, no-SNI probes of in-scope addresses;
//!
//! Every result is stored in the project `infra` table (see `docs/API.md` → `infra_get`);
//! findings join the network facts and are merged by the re-analysis.

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use foca_analysis::infra::{self as rules_infra, InfraFinding};
use foca_analysis::roles::{classify_host, HostRoles};
use foca_core::Severity;
use foca_net::dns::{DnsLookup, RType};
use foca_net::tls::{self, AuditConfig, InspectOptions, Issue, StartTls, TlsInspection};
use foca_net::NetError;
use serde_json::{json, Value};

use super::{Ctx, Stop, RESOLVER_STEPS, SRC_SUBDOMAINS, SRC_TLS};
use crate::analysis::facts::{self, NetFacts, NetHost};
use crate::analysis::rules::{self, KnownHost};
use crate::engine::lock;

/// Default TLS ports inspected on live hosts (in addition to services detected as `https`).
pub const TLS_PORTS: &[u16] = &[443, 8443, 4443, 9443, 10443];
/// Default `settings.net.rps`: brute force follows its own pace unless the user lowered it.
const DEFAULT_RPS: f64 = 5.0;
const MAX_DOMAINS: usize = 5;
const MAX_TLS_HOSTS: usize = 20;
const MAX_TLS_HOSTS_HEADLESS: usize = 5;
const ORIGIN_MIN_SCORE: u8 = 60;
const ABANDONED_GRACE_DAYS: i64 = 30;

fn cancelled(e: &NetError) -> bool {
    matches!(e, NetError::Cancelled)
}

fn put(c: &Ctx, kind: &str, key: &str, v: &Value) {
    let db = lock(&c.db);
    if let Err(e) = db.infra_put(kind, key, v, Some(&c.scan_id)) {
        tracing::warn!(target: "foca::scan", "infra {kind}/{key}: {e}");
    }
}

/// Records an out-of-scope candidate (never requested): `kind` is `san`, `org_pivot`,
/// `tenant_domain`, `origin_ip`, `ptr`, `federation` or `csp` (web audit).
pub(super) fn oos(c: &Ctx, host: &str, kind: &str, via: &str, why: &str) {
    let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
    if host.is_empty() {
        return;
    }
    put(
        c,
        "oos",
        &host,
        &json!({ "host": host, "kind": kind, "via": via, "why": why, "why_key": format!("oos.why.{kind}") }),
    );
}

pub(super) fn known_of(f: &NetFacts, extra: &[KnownHost]) -> Vec<KnownHost> {
    f.hosts
        .values()
        .map(|h| KnownHost {
            name: h.name.clone(),
            ip: h.ip.clone(),
        })
        .chain(extra.iter().cloned())
        .collect()
}

fn in_zone(h: &str, domains: &[String]) -> bool {
    domains
        .iter()
        .any(|d| h == d || h.ends_with(&format!(".{d}")))
}

/// Category and recommendation of a mail/domain policy issue. The rule id keeps its `mail-`
/// prefix (finding ids and triage depend on it), but a missing CAA record is a certificate
/// issuance problem, not a mail transport one.
pub(crate) fn mail_policy_advice(id: &str) -> (&'static str, &'static str) {
    match id {
        "caa_missing" => (
            "tls",
            "Добавить записи CAA (issue/issuewild) с разрешёнными УЦ и iodef для уведомлений.",
        ),
        _ => (
            "mail",
            "Настроить MTA-STS (mode: enforce), TLS-RPT, CAA и DNSSEC для домена.",
        ),
    }
}

fn add_finding(f: &mut NetFacts, x: InfraFinding<'_>) {
    let nf = rules_infra::finding(x);
    f.findings.entry(nf.id).or_insert(nf);
}

/// A host found by an infrastructure module (provenance in `source`, no request made here).
fn add_host(f: &mut NetFacts, name: &str, ips: &[String], source: &str, sid: &str) -> bool {
    let fresh = !f.hosts.contains_key(name);
    let h = f.host(name);
    if h.source.is_empty() || h.source == "crt.sh" {
        h.source = source.to_string();
    }
    if h.first_scan.is_none() {
        h.first_scan = Some(sid.to_string());
    }
    if let Some(ip) = ips.first() {
        if h.ip.is_empty() || h.ip == "-" {
            h.ip = ip.clone();
        }
        if h.dns.is_empty() {
            h.dns = ips
                .iter()
                .map(|i| ("A".into(), i.clone(), String::new()))
                .collect();
        }
    }
    fresh
}

/// Open ports of a host confirmed by our liveness check or port scan (`port/tcp`, service).
pub(crate) fn open_ports(h: &NetHost) -> Vec<(u16, String)> {
    h.services
        .iter()
        .filter(|s| s.2 != "Shodan InternetDB")
        .filter_map(|s| Some((s.0.split('/').next()?.parse().ok()?, s.1.clone())))
        .collect()
}

/// Host name, address and open ports (`open_ports`).
type HostPorts = (String, String, Vec<(u16, String)>);

fn now_unix(c: &Ctx) -> i64 {
    c.e.cfg.clock.now().unix_timestamp()
}

fn audit_cfg(c: &Ctx) -> AuditConfig {
    AuditConfig {
        now: now_unix(c),
        ..Default::default()
    }
}

// ---------------------------------------------------------------- passive part

/// Passive infrastructure checks (all levels; the passive level never touches the target:
/// DNS goes through resolvers, HTTP only to Microsoft and crt.sh).
pub(super) async fn passive(
    c: &mut Ctx,
    dns: &Arc<dyn DnsLookup>,
    f: &mut NetFacts,
    now: &str,
    sid: &str,
) -> Result<(), Stop> {
    if !c.module("infra") {
        return Ok(());
    }
    let cfg = c.e.cfg.clone();
    let recon_net = c.group_net("recon")?;
    let target_net = c.group_net("target")?;
    let domains: Vec<String> = c.domains.iter().take(MAX_DOMAINS).cloned().collect();
    let m365_base = cfg.endpoints.sources.get("m365").cloned();
    let m365_ep = match &m365_base {
        Some(b) => foca_net::m365::M365Endpoints {
            login: b.clone(),
            autodiscover: Some(b.clone()),
        },
        None => Default::default(),
    };
    let ct_ep = foca_net::ct::CtEndpoints {
        crtsh: cfg.endpoints.crtsh.clone(),
        certspotter: cfg
            .endpoints
            .sources
            .get("certspotter")
            .cloned()
            .unwrap_or_else(|| "https://api.certspotter.com".into()),
    };
    let scope = c.scope.clone();
    // CT history follows the crt.sh source switch (wizard / Settings → Sources)
    let ct_on = {
        let ss = c.e.store().settings_get().unwrap_or_default()["sources"].clone();
        lock(&c.st).source_ids.iter().any(|x| x == "crt") && super::source_enabled(&ss, "crt")
    };
    for d in &domains {
        c.gate().await?;
        // 1. SaaS / cloud services from TXT, MX and CNAME records
        let saas = foca_net::saas::saas_map(dns.as_ref(), d).await;
        put(
            c,
            "saas",
            d,
            &serde_json::to_value(&saas).unwrap_or_default(),
        );
        if !saas.hits.is_empty() {
            let names: Vec<&str> = saas.services().into_iter().collect();
            add_finding(
                f,
                InfraFinding {
                    code: "saas_inventory",
                    sev: Severity::Info,
                    host: d,
                    object: d,
                    detail: &names.join(", "),
                    evidence: saas
                        .hits
                        .iter()
                        .take(12)
                        .map(|h| h.record.clone())
                        .collect::<Vec<_>>()
                        .join("\n"),
                    module: "saas",
                    active: false,
                    time: now,
                    scan: Some(sid),
                    url: Some(format!("dns://{d}")),
                    tags: vec![],
                },
            );
        }
        // 2. mail policies; the MTA-STS policy file is fetched from the target (not passive)
        c.gate().await?;
        let mail = foca_net::mail::check_mail(dns.as_ref(), d).await;
        let policy = if c.level != "external" {
            let has_sts = dns
                .lookup(&format!("_mta-sts.{d}"), RType::TXT)
                .await
                .map(|a| {
                    a.values(RType::TXT)
                        .iter()
                        .any(|t| t.to_ascii_lowercase().starts_with("v=stsv1"))
                })
                .unwrap_or(false);
            if has_sts {
                let base = cfg.endpoints.sources.get("mta_sts").map(String::as_str);
                match foca_net::mail::fetch_mta_sts_policy(&target_net, d, base).await {
                    Ok(p) => Some(Ok(p)),
                    Err(e) if cancelled(&e) => return Err(Stop::Cancelled),
                    Err(e) => Some(Err(e.to_string())),
                }
            } else {
                None
            }
        } else {
            None
        };
        let pol =
            foca_net::mail::check_mail_policies(dns.as_ref(), d, mail.dmarc.clone(), policy).await;
        let mut pv = serde_json::to_value(&pol).unwrap_or_default();
        pv["domain"] = json!(d);
        put(c, "mail_policy", d, &pv);
        for i in pol.issues.iter().filter(|i| i.sev != "info") {
            let (category, recommendation) = mail_policy_advice(&i.id);
            let nf = facts::net_finding(
                &format!("mail-{}", i.id),
                d,
                i.title.clone(),
                super::sev_of(&i.sev),
                d,
                category,
                "Mail policies",
                "dns",
                false,
                now,
                Some(sid),
                i.detail.clone(),
                recommendation,
                i.detail.clone(),
                Some(format!("dns://{d}")),
            );
            f.findings.entry(nf.id).or_insert(nf);
        }
        // 3. Microsoft 365 / Entra ID tenant (Microsoft endpoints only)
        c.gate().await?;
        match foca_net::m365::discover_tenant(&recon_net, Some(dns.as_ref()), &m365_ep, d).await {
            Ok(t) if t.exists => {
                put(
                    c,
                    "tenant",
                    d,
                    &serde_json::to_value(&t).unwrap_or_default(),
                );
                let tid = t
                    .openid
                    .as_ref()
                    .map(|o| o.tenant_id.clone())
                    .unwrap_or_default();
                add_finding(
                    f,
                    InfraFinding {
                        code: "m365_tenant",
                        sev: Severity::Info,
                        host: d,
                        object: d,
                        detail: &format!("tenant {tid}"),
                        evidence: t.onmicrosoft.join("\n"),
                        module: "m365",
                        active: false,
                        time: now,
                        scan: Some(sid),
                        url: None,
                        tags: vec![],
                    },
                );
                if let Some(fh) = &t.federation_host {
                    if t.adfs {
                        add_finding(
                            f,
                            InfraFinding {
                                code: "m365_federated_adfs",
                                sev: Severity::Low,
                                host: d,
                                object: fh,
                                detail: "federated sign-in through AD FS",
                                evidence: t
                                    .realm
                                    .as_ref()
                                    .and_then(|r| r.auth_url.clone())
                                    .unwrap_or_default(),
                                module: "m365",
                                active: false,
                                time: now,
                                scan: Some(sid),
                                url: None,
                                tags: vec![],
                            },
                        );
                    }
                    // the AD FS host is never requested here: in scope -> a host, else a candidate
                    let known = known_of(f, &[]);
                    if rules::check(&scope, fh, &known).ok {
                        add_host(f, fh, &[], "m365", sid);
                    } else {
                        oos(
                            c,
                            fh,
                            "federation",
                            d,
                            "AD FS / federation host of the tenant",
                        );
                    }
                }
                for td in t.tenant_domains.iter().filter(|x| !in_zone(x, &domains)) {
                    oos(
                        c,
                        td,
                        "tenant_domain",
                        d,
                        "domain of the same Microsoft 365 tenant",
                    );
                }
            }
            Ok(_) => {}
            Err(e) if cancelled(&e) => return Err(Stop::Cancelled),
            Err(e) => tracing::info!(target: "foca::scan", "m365 {d}: {e}"),
        }
        // 4. CT history: timeline, abandoned subdomains, organization pivot (crt.sh only)
        c.gate().await?;
        let ct = if ct_on {
            foca_net::ct::crtsh_certs(&recon_net, &ct_ep, d).await
        } else {
            Err(NetError::Parse("crt.sh disabled".into()))
        };
        match ct {
            Ok(certs) => {
                let tl = foca_net::ct::cert_timeline(&certs, d);
                let ab = foca_net::ct::abandoned_hosts(&tl, now_unix(c), ABANDONED_GRACE_DAYS);
                let mut orgs: BTreeMap<String, usize> = BTreeMap::new();
                for o in certs.iter().filter_map(|x| x.org.clone()) {
                    *orgs.entry(o).or_default() += 1;
                }
                put(
                    c,
                    "ct",
                    d,
                    &json!({ "domain": d, "certs": certs.len(), "timeline": tl, "abandoned": ab, "orgs": orgs }),
                );
                for a in &ab {
                    let roles = classify_host(&a.host, Some(d));
                    let sev = rules_infra::role_boost(Severity::Low, Some(&roles));
                    add_finding(
                        f,
                        InfraFinding {
                            code: "ct_abandoned_subdomain",
                            sev,
                            host: &a.host,
                            object: &a.host,
                            detail: &format!(
                                "last certificate expired {} days ago ({} certificates)",
                                a.days_since_expiry, a.cert_count
                            ),
                            evidence: a.last_issuer.clone().unwrap_or_default(),
                            module: "crt",
                            active: false,
                            time: now,
                            scan: Some(sid),
                            url: None,
                            tags: rules_infra::role_tags(Some(&roles)),
                        },
                    );
                }
                // organization pivot: candidates outside the scope, never visited
                let mut top: Vec<(String, usize)> = orgs.into_iter().collect();
                top.sort_by_key(|x| std::cmp::Reverse(x.1));
                for (org, _) in top.into_iter().take(2) {
                    c.gate().await?;
                    match foca_net::ct::crtsh_org_pivot(&recon_net, &ct_ep, &org).await {
                        Ok(cands) => {
                            for cd in cands.iter().filter(|x| !in_zone(&x.domain, &domains)) {
                                oos(
                                    c,
                                    &cd.domain,
                                    "org_pivot",
                                    &org,
                                    "certificates with the same O=",
                                );
                            }
                        }
                        Err(e) if cancelled(&e) => return Err(Stop::Cancelled),
                        Err(_) => {}
                    }
                }
            }
            Err(e) if cancelled(&e) => return Err(Stop::Cancelled),
            Err(e) => tracing::info!(target: "foca::scan", "ct history {d}: {e}"),
        }
    }
    // 5. CDN / cloud classification (offline table) and origin candidates (DNS only)
    classify_cdn(c, f);
    for d in &domains {
        c.gate().await?;
        let front: Vec<IpAddr> = f
            .hosts
            .get(d)
            .map(|h| {
                h.dns
                    .iter()
                    .filter(|r| r.0 == "A" || r.0 == "AAAA")
                    .filter_map(|r| r.1.parse().ok())
                    .collect()
            })
            .unwrap_or_default();
        let behind_cdn = front.iter().any(|ip| {
            foca_net::cdn::classify_ip(*ip).is_some_and(|x| x.kind == foca_net::cdn::RangeKind::Cdn)
        });
        if !behind_cdn {
            continue;
        }
        let subs: Vec<String> = f
            .hosts
            .keys()
            .filter(|h| h.ends_with(&format!(".{d}")))
            .take(50)
            .cloned()
            .collect();
        let cands = foca_net::cdn::collect_dns_candidates(dns.as_ref(), d, &subs).await;
        let an = foca_net::cdn::rank_origin_candidates(&front, &cands);
        put(
            c,
            "origin",
            d,
            &serde_json::to_value(&an).unwrap_or_default(),
        );
        let known = known_of(f, &[]);
        for v in an.candidates.iter().filter(|v| v.score >= ORIGIN_MIN_SCORE) {
            let ip = v.ip.to_string();
            add_finding(
                f,
                InfraFinding {
                    code: "origin_exposed",
                    sev: Severity::Medium,
                    host: d,
                    object: &ip,
                    detail: &format!(
                        "candidate for verification, score {} ({})",
                        v.score,
                        v.reasons.join(", ")
                    ),
                    evidence: an.cdn.clone().unwrap_or_default(),
                    module: "cdn",
                    active: false,
                    time: now,
                    scan: Some(sid),
                    url: None,
                    tags: vec![],
                },
            );
            if !rules::check(&scope, &ip, &known).ok {
                oos(c, &ip, "origin_ip", d, "possible origin IP behind the CDN");
            }
        }
    }
    Ok(())
}

/// Tags hosts with their CDN / cloud / hosting provider (by address, then by CNAME).
fn classify_cdn(c: &Ctx, f: &mut NetFacts) {
    for h in f.hosts.values_mut() {
        let by_ip = h
            .dns
            .iter()
            .filter(|r| r.0 == "A" || r.0 == "AAAA")
            .filter_map(|r| r.1.parse::<IpAddr>().ok())
            .chain(h.ip.parse::<IpAddr>().ok())
            .find_map(|ip| foca_net::cdn::classify_ip(ip).map(|x| (ip, x)));
        let rec = match by_ip {
            Some((ip, x)) => Some(json!({ "host": h.name, "ip": ip.to_string(), "provider": x.provider,
                "name": foca_net::cdn::provider_name(&x.provider), "kind": x.kind, "prefix": x.prefix, "via": "ip" })),
            None => h
                .dns
                .iter()
                .filter(|r| r.0 == "CNAME")
                .find_map(|r| foca_net::cdn::classify_cname(&r.1).map(|x| (r.1.clone(), x)))
                .map(|(cn, (p, k))| json!({ "host": h.name, "ip": h.ip, "provider": p,
                    "name": foca_net::cdn::provider_name(p), "kind": k, "prefix": cn, "via": "cname" })),
        };
        if let Some(r) = rec {
            if h.cloud.is_empty() || h.cloud == "-" {
                h.cloud = r["name"].as_str().unwrap_or("-").to_string();
            }
            put(c, "cdn", &h.name, &r);
        }
    }
}

// ---------------------------------------------------------------- subdomain enumeration

/// Brute force pace: the module's own preset (Wi-Fi, or DoH through a proxy), never faster than
/// a global limit the user explicitly lowered below the default.
fn pace(c: &Ctx) -> foca_net::bruteforce::Pace {
    if c.e.cfg.dns_unthrottled {
        return foca_net::bruteforce::Pace {
            initial_rps: 5000.0,
            min_rps: 1000.0,
            max_rps: 10000.0,
            concurrency: 32,
            ..Default::default()
        };
    }
    let mut p = if c.net.has_proxy() {
        foca_net::bruteforce::Pace::doh()
    } else {
        foca_net::bruteforce::Pace::wifi()
    };
    let user = c.e.store().settings_get().unwrap_or_default()["net"]["rps"].as_f64();
    if let Some(r) = user.filter(|r| *r > 0.0 && *r < DEFAULT_RPS) {
        p.max_rps = p.max_rps.min(r);
        p.initial_rps = p.initial_rps.min(r);
        p.min_rps = p.min_rps.min(r);
    }
    p
}

/// Wordlist of the run: wizard/settings `subdomains.wordlist` (`top-1500` | `top-5000` |
/// `custom` with `subdomains.custom`), else top-1500 for standard and top-5000 for full.
fn wordlist(c: &Ctx) -> foca_net::bruteforce::Wordlist {
    use foca_net::bruteforce::Wordlist;
    let s = c.e.store().settings_get().unwrap_or_default();
    let run: Value = facts::get(&lock(&c.db), &run_key(&c.scan_id));
    let pick = |k: &str| -> Value {
        if !run[k].is_null() {
            run[k].clone()
        } else {
            s["subdomains"][k].clone()
        }
    };
    match pick("wordlist").as_str() {
        Some("custom") => {
            let words: Vec<String> = match pick("custom") {
                Value::Array(a) => a
                    .iter()
                    .filter_map(|x| x.as_str().map(String::from))
                    .collect(),
                Value::String(t) => foca_net::bruteforce::parse_wordlist(&t),
                _ => vec![],
            };
            Wordlist::Custom(foca_net::bruteforce::parse_wordlist(&words.join("\n")))
        }
        Some("top-5000") => Wordlist::Top5000,
        Some("top-1500") => Wordlist::Top1500,
        _ if c.level == "active" => Wordlist::Top5000,
        _ => Wordlist::Top1500,
    }
}

/// Returns `true` when `d` is in scope only as a URL target: its subdomains are not.
fn url_target_only(scope: &foca_core::api::ScopeDto, d: &str) -> bool {
    let url_target = scope
        .targets
        .iter()
        .any(|t| matches!(rules::entry(&t.v, Some(&t.kind)), rules::Entry::Url(h) if h == d));
    url_target && !rules::check(scope, &format!("scope-check.{d}"), &[]).ok
}

/// `wordlist: "off"` (wizard or `settings.subdomains`): no brute force; permutations, NSEC and PTR
/// still run.
fn brute_off(c: &Ctx) -> bool {
    let run: Value = facts::get(&lock(&c.db), &run_key(&c.scan_id));
    let w = if run["wordlist"].is_null() {
        c.e.store().settings_get().unwrap_or_default()["subdomains"]["wordlist"].clone()
    } else {
        run["wordlist"].clone()
    };
    w.as_str() == Some("off")
}

/// Facts key of the wizard's subdomain parameters (`scan_start.subdomains`).
pub(crate) fn run_key(scan_id: &str) -> String {
    format!("subdomains_opts:{scan_id}")
}

/// Document tokens for permutations: internal host names, printers and UNC paths.
fn doc_tokens(c: &Ctx) -> Vec<foca_net::permute::Token> {
    let db = lock(&c.db);
    let hosts: Vec<foca_core::api::Host> =
        serde_json::from_value(db.entity("hosts").unwrap_or(Value::Null)).unwrap_or_default();
    let printers: Vec<foca_core::api::Printer> =
        serde_json::from_value(db.entity("printers").unwrap_or(Value::Null)).unwrap_or_default();
    let paths: Vec<foca_core::api::PathItem> =
        serde_json::from_value(db.entity("paths").unwrap_or(Value::Null)).unwrap_or_default();
    let pcs: Vec<foca_core::api::Pc> =
        serde_json::from_value(db.entity("pcs").unwrap_or(Value::Null)).unwrap_or_default();
    drop(db);
    let mut items: Vec<(String, String)> = Vec::new();
    for h in hosts.iter().filter(|h| h.internal) {
        items.push((h.source.clone(), h.name.clone()));
    }
    for p in &printers {
        items.push((
            "printer".into(),
            p.host.clone().unwrap_or_else(|| p.name.clone()),
        ));
    }
    for p in &paths {
        items.push(("path".into(), p.path.clone()));
    }
    for p in &pcs {
        items.push((p.source.clone(), p.name.clone()));
    }
    foca_net::permute::tokens_from_metadata(items.iter().map(|(a, b)| (a.as_str(), b.as_str())))
}

/// Subdomain enumeration (standard and full levels): brute force, permutations, NSEC walking
/// (active level) and PTR of in-scope addresses. New hosts join the project with provenance.
pub(super) async fn enumerate(
    c: &mut Ctx,
    dns: &Arc<dyn DnsLookup>,
    f: &mut NetFacts,
    hosts_known: &[KnownHost],
    now: &str,
    sid: &str,
) -> Result<(), Stop> {
    if c.level == "external" || !c.module(SRC_SUBDOMAINS) {
        return Ok(());
    }
    let ss = c.e.store().settings_get().unwrap_or_default()["sources"].clone();
    if !super::source_enabled(&ss, SRC_SUBDOMAINS) {
        c.source_event(SRC_SUBDOMAINS, "off", None);
        return Ok(());
    }
    if lock(&c.skip).contains(SRC_SUBDOMAINS) {
        c.source_event(SRC_SUBDOMAINS, "skipped", None);
        return Ok(());
    }
    let headless = lock(&c.st).headless;
    // a resolver that answers for non-existent names makes brute force meaningless
    if lock(&c.st).canary.as_ref().is_some_and(|r| r.dns_hijack) {
        c.source_event_full(SRC_SUBDOMAINS, "skipped", None, Some("canary.dns_hijack"));
        return Ok(());
    }
    c.source_event(SRC_SUBDOMAINS, "running", None);
    let net = c.group_net("target")?;
    let resolvers = foca_net::bruteforce::Resolvers::single(dns.clone());
    let progress = Arc::new(foca_net::bruteforce::Progress::default());
    let bcfg = foca_net::bruteforce::BruteConfig {
        pace: pace(c),
        progress: Some(progress.clone()),
        ..Default::default()
    };
    let wl = wordlist(c);
    let domains: Vec<String> = c.domains.iter().take(MAX_DOMAINS).cloned().collect();
    let tokens = doc_tokens(c);
    let brute_off = brute_off(c);
    let mut found = 0usize;
    let mut skipped = false;
    let mut summary: BTreeMap<String, Value> = BTreeMap::new();
    let hold_keys = [format!("source:{SRC_SUBDOMAINS}")];
    // `only`: a pass that re-runs one resolver step after a restart asked once it was over
    let mut only: Option<&str> = None;
    'passes: loop {
        for d in &domains {
            c.hold(&hold_keys).await?;
            // "Skip source" (scan_skip_source) takes effect between domains
            if lock(&c.skip).contains(SRC_SUBDOMAINS) {
                skipped = true;
                break;
            }
            if !rules::check(&c.scope, d, &known_of(f, hosts_known)).ok {
                continue;
            }
            // A URL target covers only its own host: every brute force or permutation candidate
            // would be refused by the scope, so say so instead of announcing 0/0 passes.
            if url_target_only(&c.scope, d) {
                if only.is_none() {
                    let note = super::steps::url_target_note(d);
                    c.sub_skip("brute", &note);
                    c.sub_skip("permute", &note);
                }
                let wl_id = if brute_off { "off" } else { wl.id() };
                summary.insert(
                    d.clone(),
                    json!({ "domain": d, "wordlist": wl_id, "headless": headless,
                        "brute": { "skipped": "url_target" }, "permute": { "skipped": "url_target" } }),
                );
                continue;
            }
            let wl_id = if brute_off { "off" } else { wl.id() };
            let mut rec = summary
                .get(d)
                .cloned()
                .unwrap_or_else(|| json!({ "domain": d, "wordlist": wl_id, "headless": headless }));
            // 1. brute force (skipped in headless background runs: long and noisy; or turned off in the wizard)
            if only.is_some_and(|o| o != "brute") {
                // a re-run of permutations keeps this domain's brute force record
            } else if headless || brute_off {
                rec["brute"] = json!({ "skipped": if headless { "headless" } else { "off" } });
            } else if c.step_skipped("brute") {
                rec["brute"] = json!({ "skipped": "user" });
            } else {
                loop {
                    // a restart asked before the pass began is served by this pass
                    c.take_restart("step", "brute");
                    let mut sub = c.sub_begin("brute", wl.words().len());
                    let res = c
                        .tracked(
                            &mut sub,
                            &progress,
                            foca_net::bruteforce::bruteforce(&net, &resolvers, d, &wl, &bcfg),
                        )
                        .await;
                    let (done, total, failed) = progress.snapshot();
                    sub.total = total;
                    let cut = progress.stop.load(std::sync::atomic::Ordering::Relaxed);
                    c.sub_end(
                        sub,
                        done,
                        if cut { "skipped" } else { "done" },
                        &format!(
                            "{d}: найдено {}, ошибок резолвера {failed}",
                            res.as_ref().map_or(0, |r| r.hits.len())
                        ),
                    );
                    match res {
                        Ok(r) => {
                            for h in &r.hits {
                                if add_host(f, &h.host, &h.ips, "bruteforce", sid) {
                                    found += 1;
                                }
                                if h.ips.is_empty() {
                                    if let Some(dg) =
                                        foca_net::takeover::check_dangling(dns.as_ref(), &h.host)
                                            .await
                                    {
                                        super::takeover::dangling(f, &dg, now, sid);
                                    }
                                }
                            }
                            for w in r.wildcard_levels.iter().filter(|w| w.wildcard) {
                                add_finding(
                                    f,
                                    InfraFinding {
                                        code: "dns_wildcard",
                                        sev: Severity::Info,
                                        host: d,
                                        object: &w.level,
                                        detail: &format!(
                                            "*.{} -> {}",
                                            w.level,
                                            w.ips
                                                .iter()
                                                .chain(w.cnames.iter())
                                                .cloned()
                                                .collect::<Vec<_>>()
                                                .join(", ")
                                        ),
                                        evidence: String::new(),
                                        module: "bruteforce",
                                        active: false,
                                        time: now,
                                        scan: Some(sid),
                                        url: None,
                                        tags: vec![],
                                    },
                                );
                            }
                            if !r.unverified.is_empty() {
                                add_finding(
                                    f,
                                    InfraFinding {
                                        code: "dns_resolver_hijack",
                                        sev: Severity::Info,
                                        host: d,
                                        object: d,
                                        detail: &format!(
                                            "{} names not confirmed",
                                            r.unverified.len()
                                        ),
                                        evidence: r
                                            .unverified
                                            .iter()
                                            .take(10)
                                            .cloned()
                                            .collect::<Vec<_>>()
                                            .join("\n"),
                                        module: "bruteforce",
                                        active: false,
                                        time: now,
                                        scan: Some(sid),
                                        url: None,
                                        tags: vec![],
                                    },
                                );
                            }
                            rec["brute"] = json!({ "tried": r.tried, "hits": r.hits.len(),
                        "wildcard_levels": r.wildcard_levels.iter().filter(|w| w.wildcard).map(|w| &w.level).collect::<Vec<_>>(),
                        "wildcard_filtered": r.wildcard_filtered.len(), "unverified": r.unverified.len(),
                        "failed": r.failed.len(), "final_rps": r.final_rps, "lowest_rps": r.lowest_rps,
                        "throttled": r.lowest_rps < bcfg.pace.initial_rps });
                        }
                        Err(e) if cancelled(&e) => return Err(Stop::Cancelled),
                        Err(e) => rec["brute"] = json!({ "error": e.to_string() }),
                    }
                    // restart asked while the pass ran: run it again for this domain
                    if !c.take_restart("step", "brute") {
                        break;
                    }
                }
            }
            // 2. permutations of known subdomains and document tokens
            c.hold(&hold_keys).await?;
            if !headless && !c.step_skipped("permute") && only.is_none_or(|o| o == "permute") {
                loop {
                    let known: Vec<String> = f
                        .hosts
                        .keys()
                        .filter(|h| h.ends_with(&format!(".{d}")))
                        .cloned()
                        .collect();
                    let pcfg = foca_net::permute::PermuteConfig::default();
                    c.take_restart("step", "permute");
                    let mut sub = c.sub_begin("permute", pcfg.max_candidates);
                    let res = c
                        .tracked(
                            &mut sub,
                            &progress,
                            foca_net::permute::permute_and_resolve(
                                &net, &resolvers, d, &known, &tokens, &pcfg, &bcfg,
                            ),
                        )
                        .await;
                    let (done, total, failed) = progress.snapshot();
                    sub.total = total;
                    let cut = progress.stop.load(std::sync::atomic::Ordering::Relaxed);
                    c.sub_end(
                        sub,
                        done,
                        if cut { "skipped" } else { "done" },
                        &format!(
                            "{d}: найдено {}, ошибок резолвера {failed}",
                            res.as_ref().map_or(0, |r| r.hits.len())
                        ),
                    );
                    match res {
                        Ok(r) => {
                            for ph in &r.hits {
                                let src = match &ph.candidate.source {
                                    foca_net::permute::TokenSource::Document { name } => {
                                        format!("doc_token:{name}")
                                    }
                                    _ => "permute".to_string(),
                                };
                                if add_host(f, &ph.hit.host, &ph.hit.ips, &src, sid) {
                                    found += 1;
                                }
                            }
                            rec["permute"] = json!({ "generated": r.generated, "hits": r.hits.len(),
                        "via_docs": r.hits.iter().filter(|h| matches!(h.candidate.source, foca_net::permute::TokenSource::Document { .. })).count() });
                        }
                        Err(e) if cancelled(&e) => return Err(Stop::Cancelled),
                        Err(e) => rec["permute"] = json!({ "error": e.to_string() }),
                    }
                    if !c.take_restart("step", "permute") {
                        break;
                    }
                }
            }
            // 3. NSEC walking: active level only (like AXFR)
            if c.level == "active" && c.module("nsec") && !headless && only.is_none() {
                c.gate().await?;
                let ncfg = foca_net::nsec::NsecConfig::default();
                match foca_net::nsec::nsec_walk(&net, dns.as_ref(), d, &ncfg).await {
                    Ok(w) => {
                        let names: Vec<String> = w
                            .names
                            .iter()
                            .filter(|n| !n.starts_with("*."))
                            .cloned()
                            .collect();
                        for n in &names {
                            if rules::check(&c.scope, n, &known_of(f, hosts_known)).ok
                                && add_host(f, n, &[], "nsec", sid)
                            {
                                found += 1;
                            }
                        }
                        if w.signing == foca_net::nsec::Signing::Nsec && !w.names.is_empty() {
                            add_finding(
                                f,
                                InfraFinding {
                                    code: "nsec_walkable",
                                    sev: Severity::Medium,
                                    host: d,
                                    object: d,
                                    detail: &format!(
                                        "{} names via NSEC ({})",
                                        w.names.len(),
                                        w.server
                                    ),
                                    evidence: w
                                        .names
                                        .iter()
                                        .take(15)
                                        .cloned()
                                        .collect::<Vec<_>>()
                                        .join("\n"),
                                    module: "nsec",
                                    active: true,
                                    time: now,
                                    scan: Some(sid),
                                    url: Some(format!("dns://{}", w.server)),
                                    tags: vec![],
                                },
                            );
                        }
                        rec["nsec"] = json!({ "signing": w.signing, "names": w.names.len(), "complete": w.complete,
                        "stopped": w.stopped, "server": w.server, "queries": w.queries });
                    }
                    Err(e) if cancelled(&e) => return Err(Stop::Cancelled),
                    Err(e) => rec["nsec"] = json!({ "error": e.to_string() }),
                }
            }
            summary.insert(d.clone(), rec);
        }
        // a restart asked after the step was over for these domains: one more pass of that step
        match RESOLVER_STEPS.iter().find(|s| c.take_restart("step", s)) {
            Some(s) if !skipped => only = Some(s),
            _ => break 'passes,
        }
    }
    for (d, rec) in &summary {
        put(c, "dns_enum", d, rec);
    }
    // 4. PTR of in-scope addresses of known hosts
    c.gate().await?;
    let pairs: Vec<(String, Vec<String>)> = f
        .hosts
        .values()
        .filter(|h| rules::ip4(&h.ip).is_some())
        .map(|h| (h.name.clone(), vec![h.ip.clone()]))
        .collect();
    let targets = foca_net::ptr::group_by_ip(&pairs);
    if !targets.is_empty() {
        let pcfg = foca_net::ptr::PtrConfig::default();
        match foca_net::ptr::ptr_lookup(&net, dns.clone(), &targets, &domains, &pcfg).await {
            Ok(r) => {
                for e in &r.entries {
                    put(
                        c,
                        "ptr",
                        &e.ip,
                        &serde_json::to_value(e).unwrap_or_default(),
                    );
                    let host = e.hosts.first().cloned().unwrap_or_else(|| e.ip.clone());
                    if e.hosting == foca_net::ptr::Hosting::Shared {
                        add_finding(
                            f,
                            InfraFinding {
                                code: "ptr_shared_hosting",
                                sev: Severity::Info,
                                host: &host,
                                object: &e.ip,
                                detail: &e.signals.join(", "),
                                evidence: e.names.join("\n"),
                                module: "ptr",
                                active: false,
                                time: now,
                                scan: Some(sid),
                                url: None,
                                tags: vec![],
                            },
                        );
                    }
                    if e.signals.iter().any(|s| s == "fcrdns_mismatch") {
                        add_finding(
                            f,
                            InfraFinding {
                                code: "ptr_fcrdns_mismatch",
                                sev: Severity::Info,
                                host: &host,
                                object: &e.ip,
                                detail: &e.names.join(", "),
                                evidence: String::new(),
                                module: "ptr",
                                active: false,
                                time: now,
                                scan: Some(sid),
                                url: None,
                                tags: vec![],
                            },
                        );
                    }
                }
                for n in &r.new_hosts {
                    if rules::check(&c.scope, n, &known_of(f, hosts_known)).ok {
                        if add_host(f, n, &[], "ptr", sid) {
                            found += 1;
                        }
                    } else {
                        oos(c, n, "ptr", "PTR", "PTR name of an in-scope address");
                    }
                }
            }
            Err(e) if cancelled(&e) => return Err(Stop::Cancelled),
            Err(_) => {}
        }
    }
    let status = if skipped {
        "skipped"
    } else if headless {
        "skipped_headless"
    } else {
        "ok"
    };
    c.source_event(SRC_SUBDOMAINS, status, Some(found));
    tracing::info!(target: "foca::scan", "{}: subdomains {found} new hosts", c.scan_id);
    Ok(())
}

// ---------------------------------------------------------------- TLS inspection

/// IPs flagged as shared hosting by PTR: no IP-based active checks against them.
fn shared_ips(c: &Ctx) -> BTreeSet<String> {
    lock(&c.db)
        .infra_list("ptr")
        .unwrap_or_default()
        .into_iter()
        .filter(|(_, v)| v["hosting"] == "shared")
        .map(|(k, _)| k)
        .collect()
}

fn caa_records(c: &Ctx, domain: &str) -> Vec<String> {
    lock(&c.db)
        .infra_get("mail_policy", domain)
        .ok()
        .flatten()
        .map(|v| {
            v["caa"]
                .as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(|x| {
                            Some(format!(
                                "{} {} \"{}\"",
                                x["flags"].as_u64().unwrap_or(0),
                                x["tag"].as_str()?,
                                x["value"].as_str()?
                            ))
                        })
                        .collect()
                })
                .unwrap_or_default()
        })
        .unwrap_or_default()
}

/// Stores one inspection and turns its issues into findings; SAN names in scope become hosts,
/// foreign ones out-of-scope candidates.
#[allow(clippy::too_many_arguments)]
fn record_inspection(
    c: &Ctx,
    f: &mut NetFacts,
    hosts_known: &[KnownHost],
    mode: &str,
    module: &str,
    ins: &TlsInspection,
    extra: Vec<Issue>,
    legacy: Option<&tls::LegacyReport>,
    now: &str,
    sid: &str,
) {
    let cfg = audit_cfg(c);
    let host = ins.host.clone();
    let object = format!("{}:{}", host, ins.port);
    let audit = tls::audit_chain(&ins.chain_der, ins.sni.as_deref(), &cfg).ok();
    let mut issues = ins.issues(&cfg);
    if let Some(leaf) = ins.leaf() {
        if mode == "tls" {
            let zone = c
                .domains
                .iter()
                .find(|d| in_zone(&host, std::slice::from_ref(d)))
                .cloned();
            if let Some(z) = zone {
                let caa = caa_records(c, &z);
                if let Some(i) = tls::check_caa(&caa, leaf, host.starts_with("*.")).issue() {
                    issues.push(i);
                }
            }
        }
    }
    issues.extend(extra);
    let mut seen = BTreeSet::new();
    issues.retain(|i| seen.insert(i.code.clone()));
    let pki: Vec<Value> = ins
        .leaf()
        .map(|l| {
            tls::pki_hints(l)
                .into_iter()
                .map(|h| serde_json::to_value(h).unwrap_or_default())
                .collect()
        })
        .unwrap_or_default();
    let mut rec = json!({ "host": host, "port": ins.port, "mode": mode, "ip": ins.ip, "sni": ins.sni,
        "starttls": ins.starttls, "version": ins.version, "cipher": ins.cipher, "alpn": ins.alpn,
        "ocsp_stapled": ins.ocsp_stapled, "error": ins.error, "chain": ins.chain,
        "trust": audit.as_ref().map(|a| serde_json::to_value(&a.trust).unwrap_or_default()),
        "hostname_match": audit.as_ref().and_then(|a| a.hostname_match),
        "days_left": audit.as_ref().map(|a| a.days_left),
        "issues": issues, "pki": pki, "scan": sid, "at": now });
    if let Some(l) = legacy {
        rec["legacy"] = json!({ "versions": l.versions, "weak_suites": l.weak_suites });
    }
    let key = if mode == "tls" {
        object.clone()
    } else {
        format!("{object}/{mode}")
    };
    put(c, "cert", &key, &rec);
    let roles = classify_host(&host, c.domains.first().map(String::as_str));
    let mut tags = rules_infra::role_tags(Some(&roles));
    // an explicit target on a CDN edge: what answered is the CDN (see `ports::cdn_edge_tag`)
    let ip = ins
        .ip
        .clone()
        .or_else(|| f.hosts.get(&host).map(|h| h.ip.clone()))
        .unwrap_or_default();
    tags.extend(super::ports::cdn_edge_tag(&ip));
    let active = module != "tls";
    for i in &issues {
        add_finding(
            f,
            InfraFinding {
                code: &i.code,
                sev: i.severity,
                host: &host,
                object: &object,
                detail: &i.detail,
                evidence: ins
                    .leaf()
                    .map(|l| {
                        format!(
                            "{}\nissuer: {}\nsha256: {}",
                            l.subject.text, l.issuer.text, l.sha256
                        )
                    })
                    .unwrap_or_default(),
                module,
                active,
                time: now,
                scan: Some(sid),
                url: Some(format!("tls://{object}")),
                tags: tags.clone(),
            },
        );
    }
    // SAN names: in scope -> project hosts (no request), foreign -> out-of-scope candidates
    if let Some(leaf) = ins.leaf() {
        let known = known_of(f, hosts_known);
        for n in &leaf.san_dns {
            let name = n.trim_start_matches("*.").to_ascii_lowercase();
            if name.is_empty() || name == host {
                continue;
            }
            if rules::check(&c.scope, &name, &known).ok && in_zone(&name, &c.domains) {
                add_host(f, &name, &[], "tls_san", sid);
            } else {
                oos(c, &name, "san", &object, "name in the certificate SAN");
            }
        }
    }
    let h = f.host(&host);
    h.tls = Some(
        json!({ "port": ins.port, "version": ins.version, "issuer": ins.leaf().map(|l| l.issuer.text.clone()),
        "not_after": ins.leaf().map(|l| l.not_after), "days_left": audit.as_ref().map(|a| a.days_left),
        "issues": issues.iter().map(|i| i.code.clone()).collect::<Vec<_>>() }),
    );
}

fn opts() -> InspectOptions {
    InspectOptions {
        timeout: Duration::from_secs(6),
        ..Default::default()
    }
}

/// Standard TLS inspection (standard and full levels): live in-scope hosts, on their open TLS
/// ports (443/8443/... or services detected as https).
pub(super) async fn tls_standard(
    c: &mut Ctx,
    f: &mut NetFacts,
    hosts_known: &[KnownHost],
    now: &str,
    sid: &str,
) -> Result<(), Stop> {
    if c.level == "external" || !c.module(SRC_TLS) {
        return Ok(());
    }
    let ss = c.e.store().settings_get().unwrap_or_default()["sources"].clone();
    if !super::source_enabled(&ss, SRC_TLS) {
        c.source_event(SRC_TLS, "off", None);
        return Ok(());
    }
    if lock(&c.skip).contains(SRC_TLS) {
        c.source_event(SRC_TLS, "skipped", None);
        return Ok(());
    }
    let tls_ports = c.e.cfg.tls_ports.clone();
    let max = if lock(&c.st).headless {
        MAX_TLS_HOSTS_HEADLESS
    } else {
        MAX_TLS_HOSTS
    };
    let known = known_of(f, hosts_known);
    let held = super::ports::held_names(c, f);
    let list: Vec<(String, u16)> = f
        .hosts
        .values()
        .filter(|h| h.dangling.is_none() && rules::check(&c.scope, &h.name, &known).ok)
        .filter(|h| !held.contains(&h.name))
        .flat_map(|h| {
            open_ports(h)
                .into_iter()
                .filter(|(p, s)| tls_ports.contains(p) || s == "https")
                .map(|(p, _)| (h.name.clone(), p))
                .collect::<Vec<_>>()
        })
        .take(max * 2)
        .collect();
    c.source_event(SRC_TLS, "running", None);
    let net = c.group_net("target")?;
    let mut n = 0usize;
    let mut skipped = false;
    let total = list.len();
    let mut sub = c.sub_begin("tls", total);
    let mut checked = 0usize;
    let hold_keys = [format!("source:{SRC_TLS}")];
    for (host, port) in list {
        c.hold(&hold_keys).await?;
        c.sub_tick(&mut sub, checked, total, Value::Null);
        checked += 1;
        // "Skip source" (scan_skip_source) takes effect between hosts
        if lock(&c.skip).contains(SRC_TLS) {
            skipped = true;
            break;
        }
        match tls::inspect_standard(&net, &host, port, &opts()).await {
            Ok(ins) if !ins.chain.is_empty() => {
                record_inspection(
                    c,
                    f,
                    hosts_known,
                    "tls",
                    "tls",
                    &ins,
                    vec![],
                    None,
                    now,
                    sid,
                );
                n += 1;
            }
            Ok(_) => {}
            Err(e) if cancelled(&e) => return Err(Stop::Cancelled),
            Err(e) => tracing::debug!(target: "foca::scan", "tls {host}:{port}: {e}"),
        }
    }
    c.sub_end(
        sub,
        checked,
        if skipped { "skipped" } else { "done" },
        &format!("сертификатов: {n}"),
    );
    c.source_event(SRC_TLS, if skipped { "skipped" } else { "ok" }, Some(n));
    Ok(())
}

/// Active TLS checks after the ports stage (active level): legacy versions / weak ciphers on TLS
/// ports, STARTTLS on mail/DB/RDP ports, no-SNI probes of in-scope addresses and in-scope
/// origin candidates.
pub(super) async fn tls_active(c: &mut Ctx) -> Result<(), Stop> {
    if c.level != "active" || !c.module(SRC_TLS) || lock(&c.skip).contains(SRC_TLS) {
        return Ok(());
    }
    let ss = c.e.store().settings_get().unwrap_or_default()["sources"].clone();
    if !super::source_enabled(&ss, SRC_TLS) {
        return Ok(());
    }
    let now = c.e.now_iso();
    let sid = c.scan_id.clone();
    let tls_ports = c.e.cfg.tls_ports.clone();
    let (mut f, hosts_known): (NetFacts, Vec<KnownHost>) = {
        let db = lock(&c.db);
        (facts::get(&db, facts::K_NET), super::known_hosts(&db))
    };
    let known = known_of(&f, &hosts_known);
    let shared = shared_ips(c);
    let net = c.group_net("target")?;
    let held = super::ports::held_names(c, &f);
    let hosts: Vec<HostPorts> = f
        .hosts
        .values()
        .filter(|h| h.dangling.is_none() && rules::check(&c.scope, &h.name, &known).ok)
        .filter(|h| !held.contains(&h.name))
        .map(|h| (h.name.clone(), h.ip.clone(), open_ports(h)))
        .filter(|x| !x.2.is_empty())
        .take(MAX_TLS_HOSTS)
        .collect();
    let mut n = 0usize;
    let cfg = audit_cfg(c);
    for (host, ip, ports) in &hosts {
        for (port, svc) in ports {
            c.gate().await?;
            let is_tls = tls_ports.contains(port) || svc == "https";
            if is_tls {
                // A modern handshake first when the network stage had no port list for this host
                // yet: ALPN and OCSP are judged only on it, never on the raw legacy hellos below.
                let have_modern = lock(&c.db)
                    .infra_get("cert", &format!("{host}:{port}"))
                    .ok()
                    .flatten()
                    .is_some();
                if !have_modern {
                    match tls::inspect_standard(&net, host, *port, &opts()).await {
                        Ok(ins) if !ins.chain.is_empty() => {
                            record_inspection(
                                c,
                                &mut f,
                                &hosts_known,
                                "tls",
                                "tls",
                                &ins,
                                vec![],
                                None,
                                &now,
                                &sid,
                            );
                            n += 1;
                        }
                        Ok(_) => {}
                        Err(e) if cancelled(&e) => return Err(Stop::Cancelled),
                        Err(e) => tracing::debug!(target: "foca::scan", "tls {host}:{port}: {e}"),
                    }
                }
                // legacy versions and weak suites
                match tls::probe_legacy(&net, host, *port, &tls::LegacyConfig::default()).await {
                    Ok(rep) => {
                        let have_cert = lock(&c.db)
                            .infra_get("cert", &format!("{host}:{port}"))
                            .ok()
                            .flatten()
                            .is_some();
                        if !rep.issues.is_empty() || (!have_cert && !rep.certs.is_empty()) {
                            // a server rustls cannot talk to: audit the certificate it sent in clear
                            let mut extra = rep.issues.clone();
                            if !have_cert {
                                if let Ok(a) = tls::audit_chain(&rep.certs, Some(host), &cfg) {
                                    extra.extend(a.issues);
                                }
                            }
                            let ins = TlsInspection {
                                host: host.clone(),
                                port: *port,
                                ip: None,
                                sni: Some(host.clone()),
                                starttls: None,
                                version: rep.versions.iter().find(|v| v.supported).and_then(|v| {
                                    serde_json::to_value(v.version)
                                        .ok()
                                        .and_then(|x| x.as_str().map(String::from))
                                }),
                                cipher: rep.versions.iter().find_map(|v| v.cipher.clone()),
                                alpn: None,
                                ocsp_stapled: false,
                                // raw hellos offer no ALPN / status_request
                                alpn_offered: false,
                                chain: rep
                                    .certs
                                    .iter()
                                    .filter_map(|d| tls::parse_cert(d).ok())
                                    .collect(),
                                chain_der: if have_cert { vec![] } else { rep.certs.clone() },
                                error: None,
                            };
                            record_inspection(
                                c,
                                &mut f,
                                &hosts_known,
                                "legacy",
                                "tls-legacy",
                                &ins,
                                extra,
                                Some(&rep),
                                &now,
                                &sid,
                            );
                            n += 1;
                        }
                    }
                    Err(e) if cancelled(&e) => return Err(Stop::Cancelled),
                    Err(_) => {}
                }
            }
            if StartTls::for_port(*port).is_some() && !is_tls {
                match tls::starttls_inspect(&net, host, *port, None, &opts()).await {
                    Ok(ins) if !ins.chain.is_empty() => {
                        record_inspection(
                            c,
                            &mut f,
                            &hosts_known,
                            "starttls",
                            "starttls",
                            &ins,
                            vec![],
                            None,
                            &now,
                            &sid,
                        );
                        n += 1;
                    }
                    Ok(_) => {}
                    Err(e) if cancelled(&e) => return Err(Stop::Cancelled),
                    Err(_) => {}
                }
            }
        }
        // no-SNI probe of the host's address: only when the address itself is in scope and not shared
        if rules::ip4(ip).is_some()
            && !shared.contains(ip)
            && rules::check(&c.scope, ip, &known).ok
            && ports.iter().any(|(p, _)| *p == 443)
        {
            c.gate().await?;
            match tls::inspect_no_sni(&net, ip, 443, &opts()).await {
                Ok(ins) if !ins.chain.is_empty() => {
                    let extra: Vec<Issue> = tls::handshake::no_sni_issue(&ins, host)
                        .into_iter()
                        .collect();
                    record_inspection(
                        c,
                        &mut f,
                        &hosts_known,
                        "no_sni",
                        "tls-no-sni",
                        &ins,
                        extra,
                        None,
                        &now,
                        &sid,
                    );
                    n += 1;
                }
                Ok(_) => {}
                Err(e) if cancelled(&e) => return Err(Stop::Cancelled),
                Err(_) => {}
            }
        }
    }
    // origin candidates: confirmed only when the candidate IP is in scope (never otherwise)
    let origins = lock(&c.db).infra_list("origin").unwrap_or_default();
    for (domain, an) in origins {
        for v in an["candidates"].as_array().cloned().unwrap_or_default() {
            let Some(ip) = v["ip"].as_str() else { continue };
            if (v["score"].as_u64().unwrap_or(0) as u8) < ORIGIN_MIN_SCORE
                || shared.contains(ip)
                || !rules::check(&c.scope, ip, &known).ok
            {
                continue;
            }
            c.gate().await?;
            match tls::inspect_no_sni(&net, ip, 443, &opts()).await {
                Ok(ins) if !ins.chain.is_empty() => {
                    let extra: Vec<Issue> = tls::handshake::no_sni_issue(&ins, &domain)
                        .into_iter()
                        .collect();
                    record_inspection(
                        c,
                        &mut f,
                        &hosts_known,
                        "no_sni",
                        "tls-no-sni",
                        &ins,
                        extra,
                        None,
                        &now,
                        &sid,
                    );
                    n += 1;
                }
                Ok(_) => {}
                Err(e) if cancelled(&e) => return Err(Stop::Cancelled),
                Err(_) => {}
            }
        }
    }
    facts::put(&lock(&c.db), facts::K_NET, &f)?;
    if n > 0 {
        c.source_event(SRC_TLS, "ok", Some(n));
        let ids = super::reanalyze_bg(c).await?;
        c.findings_events(&ids);
    }
    Ok(())
}

// ---------------------------------------------------------------- roles

/// Classifies host names by role and raises exposure findings for live dev/admin/CI/DB hosts.
pub(super) fn roles(c: &Ctx, f: &mut NetFacts, now: &str, sid: &str) {
    if !c.module("infra") {
        return;
    }
    let zone = c.domains.first().cloned();
    let names: Vec<String> = f.hosts.keys().cloned().collect();
    for n in names {
        let r: HostRoles = classify_host(&n, zone.as_deref());
        if r.tags.is_empty() {
            continue;
        }
        let alive = f.hosts.get(&n).is_some_and(|h| !open_ports(h).is_empty());
        let sev = r.exposure_severity(alive);
        put(
            c,
            "role",
            &n,
            &json!({ "host": n, "roles": r.roles().into_iter().map(|x| x.as_str()).collect::<Vec<_>>(),
                "tags": r.tags, "priority": r.priority, "alive": alive, "severity": sev }),
        );
        if alive && sev != Severity::Info {
            let roles: Vec<&str> = r.roles().into_iter().map(|x| x.as_str()).collect();
            add_finding(
                f,
                InfraFinding {
                    code: "host_role_exposed",
                    sev,
                    host: &n,
                    object: &n,
                    detail: &format!("roles {}", roles.join(", ")),
                    evidence: r
                        .tags
                        .iter()
                        .map(|t| format!("{}: {}", t.role.as_str(), t.token))
                        .collect::<Vec<_>>()
                        .join("\n"),
                    module: "roles",
                    active: false,
                    time: now,
                    scan: Some(sid),
                    url: None,
                    tags: rules_infra::role_tags(Some(&r)),
                },
            );
        }
    }
}

// ---------------------------------------------------------------- views

/// All infrastructure records for `infra_get` and report snapshots: `{ kind: [record] }`.
pub(crate) fn view(db: &foca_store::ProjectDb) -> Value {
    let all = db.infra_all().unwrap_or_default();
    let mut out = serde_json::Map::new();
    for k in [
        "saas",
        "tenant",
        "mail_policy",
        "cert",
        "ct",
        "cdn",
        "origin",
        "role",
        "ptr",
        "dns_enum",
        "oos",
    ] {
        out.insert(k.into(), json!(all.get(k).cloned().unwrap_or_default()));
    }
    Value::Object(out)
}

/// Report view: `null` when there are no records (keeps report goldens of old projects stable).
pub(crate) fn report_view(db: &foca_store::ProjectDb) -> Value {
    if db.infra_all().map(|m| m.is_empty()).unwrap_or(true) {
        return Value::Null;
    }
    view(db)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_caa_is_a_tls_issue_with_its_own_advice() {
        let (cat, rec) = mail_policy_advice("caa_missing");
        assert_eq!(cat, "tls");
        assert!(rec.contains("CAA") && !rec.contains("MTA-STS"), "{rec}");
        assert_eq!(mail_policy_advice("mta_sts_missing").0, "mail");
        // Every report language translates the new recommendation.
        for lang in ["en", "ru", "uk"] {
            let path = format!(
                "{}/../../locales/{lang}/findings.json",
                env!("CARGO_MANIFEST_DIR")
            );
            let v: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
            assert!(
                v["catalog"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|e| e["pattern"] == rec && e["rules"] == "mail-caa_missing"),
                "{lang}: no catalog entry for the CAA recommendation"
            );
        }
    }
}
