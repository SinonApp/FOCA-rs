//! Responses in contract format: snapshot, project summary, out-of-scope candidates, settings.

use std::collections::{BTreeMap, BTreeSet};

use foca_core::api::{ProjectSummary, Snapshot};
use foca_store::ProjectDb;
use serde_json::{json, Value};

use crate::analysis::facts::{self, FidMap, NetFacts};
use crate::analysis::rules::{self, KnownHost};
use crate::engine::{lock, Core};
use crate::util::{base36, fnv, mask};
use crate::{CmdError, CmdResult, Engine};

pub const KEY_SERVICES: &[&str] = foca_store::settings::KEY_SERVICES;

/// Masks `{{s:value}}` markers; returns the masked text and the `f<id>:<k>` references.
pub fn mask_evidence(ev: &str, fid: u64) -> (String, Vec<String>) {
    let mut out = String::new();
    let mut refs = Vec::new();
    let mut rest = ev;
    while let Some(i) = rest.find("{{s:") {
        out.push_str(&rest[..i]);
        let after = &rest[i + 4..];
        match after.find("}}") {
            Some(j) => {
                out.push_str(&format!("{{{{s:{}}}}}", mask(&after[..j])));
                refs.push(format!("f{fid}:{}", refs.len()));
                rest = &after[j + 2..];
            }
            None => {
                out.push_str(&rest[i..]);
                rest = "";
            }
        }
    }
    out.push_str(rest);
    (out, refs)
}

/// Wraps secret values that appear in evidence outside `{{s:...}}` in a marker (the analysis
/// sometimes leaves a connection string password in clear text next to a marker).
pub fn protect_evidence(ev: &str, secrets: &[String]) -> String {
    if secrets.is_empty() || ev.is_empty() {
        return ev.to_string();
    }
    let mut out = String::new();
    let mut rest = ev;
    loop {
        let (plain, marker, tail) = match rest.find("{{s:") {
            Some(i) => match rest[i..].find("}}") {
                Some(j) => (&rest[..i], &rest[i..i + j + 2], &rest[i + j + 2..]),
                None => (rest, "", ""),
            },
            None => (rest, "", ""),
        };
        let mut p = plain.to_string();
        for s in secrets {
            if p.contains(s.as_str()) {
                p = p.replace(s.as_str(), &format!("{{{{s:{s}}}}}"));
            }
        }
        out.push_str(&p);
        out.push_str(marker);
        if marker.is_empty() {
            break;
        }
        rest = tail;
    }
    out
}

/// Returns all `{{s:...}}` values in evidence (for `secret_reveal`).
pub fn evidence_secrets(ev: &str) -> Vec<String> {
    let mut v = Vec::new();
    let mut rest = ev;
    while let Some(i) = rest.find("{{s:") {
        let after = &rest[i + 4..];
        let Some(j) = after.find("}}") else { break };
        v.push(after[..j].to_string());
        rest = &after[j + 2..];
    }
    v
}

/// The `cve_list` query of a CVE summary finding, from its `nvd:` provenance field.
fn cve_query(f: &Value) -> Option<Value> {
    let raw = f["provenance"]["fields"]
        .as_array()?
        .iter()
        .filter_map(Value::as_str)
        .find_map(|x| x.strip_prefix("nvd:"))?;
    let mut it = raw.splitn(3, '|');
    let (product, version) = (it.next()?, it.next().unwrap_or(""));
    let mut q = json!({ "product": product, "version": version });
    if let Some(y) = it.next().and_then(|y| y.parse::<u16>().ok()) {
        q["until_year"] = json!(y);
    }
    Some(q)
}

/// Standards of a finding rule for the UI (`foca_analysis::standards`), `null` when the rule is
/// not mapped. Computed on every response, never stored.
pub fn standards_json(rule: &str) -> Value {
    match foca_analysis::standards::Standards::builtin().for_rule(rule) {
        Some(r) if !r.is_empty() => json!({
            "mitre": r.mitre,
            "cwe": r.cwe,
            "owasp": r.owasp,
            "wstg": r.wstg,
            "iso27001": r.iso27001,
            "nist": r.nist,
            "privacy": r.privacy,
            "ndtzi": r.ndtzi,
            "kszi": r.kszi,
            "cwe_top25": r
                .cwe
                .iter()
                .filter(|c| foca_analysis::standards::is_cwe_top25(c))
                .collect::<Vec<_>>(),
        }),
        _ => Value::Null,
    }
}

/// Converts an analysis address pattern (`{f}.{last}`) into the localized placeholders used by the UI screens.
pub fn ui_pattern(p: &str) -> String {
    p.replace("{first}", "{имя}")
        .replace("{last}", "{фамилия}")
        .replace("{f}", "{и}")
        .replace("{l}", "{ф}")
}

fn host_sev(findings: &[Value], name: &str, internal: bool) -> &'static str {
    let mut best: Option<u8> = None;
    for f in findings {
        if f["host"] == name && rules::is_live_status(f["status"].as_str().unwrap_or("")) {
            let r = rules::sev_rank(f["sev"].as_str().unwrap_or("info"));
            best = Some(best.map_or(r, |b| b.max(r)));
        }
    }
    match best {
        Some(4) => "crit",
        Some(3) => "high",
        Some(2) => "warn",
        Some(1) => "low",
        Some(_) => "info",
        None if internal => "info",
        None => "ok",
    }
}

impl Core {
    /// Builds a typed snapshot with short finding ids and plain secrets; used only for reports
    /// inside the core and never sent to the UI.
    pub(crate) fn core_snapshot(&self, id: &str) -> Result<(Snapshot, FidMap), CmdError> {
        let settings = self.public_settings()?;
        let scan = self.scan_status(Some(id));
        let db = self.db(id)?;
        let db = lock(&db);
        let map = facts::assign_fids(&db)?;
        let mut s = db.snapshot(settings, scan)?;
        s.recon = crate::scan::recon::snapshot(&db);
        s.ports = crate::scan::ports::report_view(&db);
        s.infra = crate::scan::infra::report_view(&db);
        host_scope(&mut s);
        let running = self.running_scan().map(|r| r.1);
        s.scans
            .retain(|x| x.status != "running" && Some(&x.id) != running.as_ref());
        let sv = crate::settings::secret_values(&db);
        for f in &mut s.findings {
            f.id = map.get(f.id);
            f.evidence = protect_evidence(&f.evidence, &sv);
        }
        for x in &mut s.secrets {
            x.finding = x.finding.map(|h| map.get(h));
        }
        Ok((s, map))
    }

    pub(crate) fn summary_of(&self, db: &ProjectDb) -> Result<ProjectSummary, CmdError> {
        let mut s = db.summary()?;
        let running = self.running_scan();
        let scans: Vec<Value> = db
            .scans()?
            .into_iter()
            .filter(|x| x.status != "running" && running.as_ref().map(|r| &r.1) != Some(&x.id))
            .map(|x| {
                let extra: Value = facts::get(db, &facts::scan_key(&x.id));
                json!({ "status": x.status, "stage": extra.get("stage").cloned().unwrap_or(Value::Null),
                        "finished_at": x.finished_at, "started_at": x.started_at, "profile": x.profile })
            })
            .collect();
        let findings: Vec<Value> = db
            .findings()?
            .iter()
            .map(|f| json!({ "sev": f.sev, "status": f.status }))
            .collect();
        s.scans = scans.len() as u32;
        s.last_scan_at = scans.last().and_then(|x| {
            x["finished_at"]
                .as_str()
                .or(x["started_at"].as_str())
                .map(String::from)
        });
        s.last_profile = scans
            .last()
            .and_then(|x| x["profile"].as_str().map(String::from));
        // an offline import (reference case, imported folder) has analyzed documents and findings
        // without any scan: it is assessed as well
        let imported = scans.is_empty() && s.docs > 0;
        s.risk = (imported || rules::analyzed_scans(&scans)).then(|| rules::risk_score(&findings));
        match running {
            Some((p, _, prog)) if p == s.id => {
                s.scanning = true;
                s.progress = prog;
            }
            _ => {
                s.scanning = false;
                s.progress = 0;
            }
        }
        Ok(s)
    }
}

impl Engine {
    /// Sets `Report.path`, the absolute file path in the private data directory. The Share/Save bridge
    /// reads the file from there; it leaves the app only as a copy via FileProvider / MediaStore.
    pub(crate) fn add_report_paths(&self, project: &str, v: &mut Value) {
        if let Some(arr) = v.as_array_mut() {
            for r in arr {
                let name = r["name"].as_str().unwrap_or("").to_string();
                if !name.is_empty() {
                    r["path"] = json!(self.report_file(project, &name).to_string_lossy());
                }
            }
        }
    }

    pub(crate) fn snapshot_json(&self, id: &str) -> CmdResult {
        let (s, _) = self.core_snapshot(id)?;
        let db = self.db(id)?;
        let db = lock(&db);
        let mut v = serde_json::to_value(&s)?;
        let net: NetFacts = facts::get(&db, facts::K_NET);
        let cleaned: BTreeMap<String, Value> = facts::get(&db, facts::K_CLEANED);
        self.add_report_paths(id, &mut v["reports"]);
        // file SHA-256 (document card, finding provenance), `null` until the file is downloaded
        if let Ok(stored) = db.documents(true) {
            let sha: BTreeMap<u64, String> = stored
                .into_iter()
                .filter(|d| !d.doc.sha256.is_empty())
                .map(|d| (d.doc.id, d.doc.sha256))
                .collect();
            if let Some(arr) = v["docs"].as_array_mut() {
                for d in arr {
                    let k = d["id"].as_u64().unwrap_or(0);
                    d["sha256"] = sha.get(&k).map_or(Value::Null, |x| json!(x));
                }
            }
        }
        // history records: modules, growth, and progress and stage for stopped scans
        if let Some(arr) = v["scans"].as_array_mut() {
            for sc in arr {
                let id = sc["id"].as_str().unwrap_or("").to_string();
                let extra: Value = facts::get(&db, &facts::scan_key(&id));
                let o = sc.as_object_mut().expect("scan");
                o.insert(
                    "modules".into(),
                    extra.get("modules").cloned().unwrap_or(json!([])),
                );
                o.insert(
                    "added".into(),
                    extra
                        .get("added")
                        .cloned()
                        .unwrap_or(json!({ "docs": 0, "people": 0, "hosts": 0, "findings": 0 })),
                );
                // incomplete snapshot: reconnaissance sources that did not answer in this scan
                o.insert(
                    "incomplete".into(),
                    extra.get("incomplete").cloned().unwrap_or(json!([])),
                );
                if o.get("status") == Some(&json!("stopped")) {
                    for k in ["progress", "stage"] {
                        o.insert(k.into(), extra.get(k).cloned().unwrap_or(Value::Null));
                    }
                }
            }
        }
        // timeline texts are written in Russian: `<field>_msg` lets the UI render them in its language
        if let Some(arr) = v["events"].as_array_mut() {
            for e in arr {
                crate::services::i18n::annotate(e, &["k", "t", "s"]);
            }
        }
        let deleted: BTreeSet<u64> = s.docs.iter().filter(|d| d.deleted).map(|d| d.id).collect();
        if let Some(arr) = v["docs"].as_array_mut() {
            for d in arr {
                let id = d["id"].as_u64().unwrap_or(0).to_string();
                d["cleaned"] = cleaned.get(&id).cloned().unwrap_or(Value::Null);
            }
        }
        if let Some(arr) = v["people"].as_array_mut() {
            for p in arr {
                if p["src_kind"] == "text"
                    && p["src_doc"].as_u64().is_some_and(|d| deleted.contains(&d))
                {
                    p["src_deleted"] = json!(true);
                }
            }
        }
        if let Some(arr) = v["secrets"].as_array_mut() {
            for x in arr {
                let m = mask(x["value"].as_str().unwrap_or(""));
                let o = x.as_object_mut().expect("secret");
                o.remove("value");
                o.insert("mask".into(), json!(m));
            }
        }
        if let Some(arr) = v["findings"].as_array_mut() {
            for f in arr {
                let id = f["id"].as_u64().unwrap_or(0);
                let (ev, refs) = mask_evidence(f["evidence"].as_str().unwrap_or(""), id);
                f["evidence"] = json!(ev);
                f["secret_refs"] = json!(refs);
                f["standards"] = standards_json(f["provenance"]["rule"].as_str().unwrap_or(""));
                if let Some(q) = cve_query(f) {
                    f["cve_query"] = q;
                }
            }
        }
        if let Some(arr) = v["patterns"].as_array_mut() {
            for p in arr {
                p["p"] = json!(ui_pattern(p["p"].as_str().unwrap_or("")));
            }
        }
        let findings = v["findings"].as_array().cloned().unwrap_or_default();
        let roles: BTreeMap<String, Value> = db
            .infra_list("role")
            .unwrap_or_default()
            .into_iter()
            .collect();
        let cdn: BTreeMap<String, Value> = db
            .infra_list("cdn")
            .unwrap_or_default()
            .into_iter()
            .collect();
        if let Some(arr) = v["hosts"].as_array_mut() {
            for h in arr {
                let name = h["name"].as_str().unwrap_or("").to_string();
                let internal = h["internal"].as_bool().unwrap_or(false);
                let nh = net.hosts.get(&name);
                h["sev"] = json!(host_sev(&findings, &name, internal));
                h["dns"] = json!(nh.map(|x| x.dns.clone()).unwrap_or_default());
                h["asn"] = json!(nh.and_then(|x| x.asn.clone()));
                h["tls"] = nh.and_then(|x| x.tls.clone()).unwrap_or(Value::Null);
                let (pl, ps) = nh
                    .map(crate::scan::ports::host_view)
                    .unwrap_or((json!([]), Value::Null));
                h["ports"] = pl;
                h["ports_scan"] = ps;
                let role = roles.get(&name);
                h["roles"] = role
                    .map(|r| r["roles"].clone())
                    .unwrap_or_else(|| json!([]));
                h["priority"] = role.map(|r| r["priority"].clone()).unwrap_or(json!(0));
                h["cdn"] = cdn.get(&name).cloned().unwrap_or(Value::Null);
                if let Some(x) = nh {
                    if h["cloud"] == "-" || h["cloud"] == "" {
                        h["cloud"] = json!(x.cloud);
                    }
                }
            }
        }
        for k in ["os", "graph", "activity"] {
            v[k] = db.entity(k).unwrap_or(Value::Null);
        }
        drop(db);
        v["oos"] = self.oos_json(id)?;
        Ok(v)
    }

    pub(crate) fn project_list(&self) -> CmdResult {
        let list = self.store().list_projects()?;
        let mut out = Vec::new();
        for p in list {
            // A project whose database does not open or summarise (newer schema, damaged file)
            // stays listed with its cached summary: opening it then reports the error instead of
            // the project silently vanishing from the list.
            match self.db(&p.id).and_then(|db| self.summary_of(&lock(&db))) {
                Ok(s) => out.push(s),
                Err(e) => {
                    tracing::warn!(target: "foca::store", "project_list {}: {} {}", p.id, e.code, e.message);
                    out.push(p);
                }
            }
        }
        Ok(serde_json::to_value(out)?)
    }

    /// Out-of-scope candidates, derived from hosts, findings and CT on every request;
    /// decisions are stored separately and survive new scans.
    pub(crate) fn oos_json(&self, id: &str) -> CmdResult {
        let db = self.db(id)?;
        let db = lock(&db);
        let map = facts::assign_fids(&db)?;
        let scope = db.scope_get()?;
        let dec: BTreeMap<String, String> = facts::get(&db, facts::K_OOS);
        let net: NetFacts = facts::get(&db, facts::K_NET);
        let hosts: Vec<foca_core::api::Host> = match db.entity("hosts")? {
            Value::Null => vec![],
            v => serde_json::from_value(v)?,
        };
        let findings = db.findings()?;
        let infra_oos = db.infra_list("oos").unwrap_or_default();
        drop(db);
        let known: Vec<KnownHost> = hosts
            .iter()
            .map(|h| KnownHost {
                name: h.name.clone(),
                ip: h.ip.clone(),
            })
            .collect();
        let chk = |h: &str| rules::check(&scope, h, &known);
        let mut out: Vec<Value> = Vec::new();
        let mut add = |o: Value| {
            let host = o["host"].as_str().unwrap_or("").to_string();
            if host.is_empty() || out.iter().any(|x| x["host"] == host.as_str()) {
                return;
            }
            let decision = dec.get(&host).cloned().unwrap_or_else(|| "new".into());
            let c = chk(&host);
            if decision == "new" && c.ok {
                return;
            }
            let mut x = json!({ "id": format!("oos-{}", base36(fnv(&host) as u64)), "n": null,
                "finding": null, "blocked": null, "via": null, "own": false });
            for (k, val) in o.as_object().expect("oos") {
                x[k] = val.clone();
            }
            if x["blocked"].is_null() && c.code == "excluded" {
                x["blocked"] =
                    json!("В исключениях скоупа: сначала уберите исключение на экране «Скоуп»");
            }
            x["decision"] = json!(decision);
            crate::services::i18n::annotate(&mut x, &["why", "hint", "blocked"]);
            out.push(x);
        };
        let ext: Vec<&foca_core::api::Host> = hosts.iter().filter(|h| !h.internal).collect();
        // 1. dangling CNAME: the name is free and must not be scanned
        for h in &ext {
            let Some(t) = h.ip.strip_prefix("CNAME → ") else {
                continue;
            };
            let f = findings
                .iter()
                .find(|f| f.host == h.name && f.category == "dns")
                .map(|f| map.get(f.id));
            add(
                json!({ "host": t, "kind": "cname", "via": h.name, "why": format!("CNAME с {}", h.name),
                "own": false, "finding": f,
                "hint": "Ресурс не существует (NXDOMAIN): владелец не заказчик",
                "blocked": match f { Some(id) => format!("Имя свободно, не сканировать, см. находку №{id}"),
                                     None => "Имя свободно, не сканировать".into() } }),
            );
        }
        // 2-3. addresses of in-scope hosts outside the scope networks: CDN is denied, cloud is `own`,
        // anything else is offered as a single IP with a shared hosting warning. A network (/24) is
        // never offered: on shared hosting neighboring addresses belong to other owners.
        let mut ips: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for h in &ext {
            if rules::ip4(&h.ip).is_none() || !chk(&h.name).ok {
                continue;
            }
            let fresh = !chk(&h.ip).ok || dec.contains_key(&h.ip);
            let cloud = net
                .hosts
                .get(&h.name)
                .map(|x| x.cloud.clone())
                .filter(|c| c != "-" && !c.is_empty())
                .unwrap_or_else(|| h.cloud.clone());
            let has_cloud = !cloud.is_empty() && cloud != "-";
            if has_cloud && fresh {
                let l = cloud.to_lowercase();
                if l.contains("cloudflare") || l.contains("akamai") || l.contains("fastly") {
                    add(
                        json!({ "host": h.ip, "kind": "cdn", "via": h.name, "why": format!("A-запись {} → {cloud}", h.name),
                        "own": false, "hint": "Общий адрес CDN, на нём сайты других компаний", "blocked": "Общий IP CDN, не сканировать" }),
                    );
                } else {
                    add(
                        json!({ "host": h.ip, "kind": "ip", "via": h.name, "why": format!("A-запись {} ({cloud}) вне сетей скоупа", h.name),
                        "own": true, "hint": "Адрес облака: уточните у заказчика, что он закреплён за ним" }),
                    );
                }
            } else if !has_cloud && fresh {
                ips.entry(h.ip.clone()).or_default().push(h.name.clone());
            }
        }
        for (ip, hs) in ips {
            let k = hs.len();
            add(
                json!({ "host": ip, "kind": "ip", "via": hs[0], "n": k, "shared": true,
                "why": format!("A-запись {k} {} из скоупа ({}{}) вне сетей скоупа", if k == 1 { "хоста" } else { "хостов" },
                               hs.iter().take(2).cloned().collect::<Vec<_>>().join(", "), if k > 2 { "…" } else { "" }),
                "own": false,
                "hint": "Возможен общий хостинг: на этом IP могут быть сайты других владельцев. В скоуп добавляется только этот адрес, не сеть: подтвердите у заказчика (whois/RDAP)" }),
            );
        }
        // 4a. infrastructure candidates (never requested): certificate SAN names, `O=` pivot,
        // tenant domains, origin IPs, PTR names, federation hosts
        for (host, o) in &infra_oos {
            let kind = o["kind"].as_str().unwrap_or("link");
            let (why, hint) = match kind {
                "san" => ("Имя в SAN сертификата", "Чужое имя в сертификате хоста из скоупа: владелец не подтверждён"),
                "org_pivot" => ("Сертификаты с той же организацией (O=)", "Возможный сестринский домен: подтвердите у заказчика"),
                "tenant_domain" => ("Домен того же арендатора Microsoft 365", "Домен организации вне скоупа: подтвердите у заказчика"),
                "origin_ip" => ("Возможный исходный IP за CDN", "Кандидат для проверки: добавляйте в скоуп только после подтверждения владельца"),
                "ptr" => ("PTR-имя адреса из скоупа", "Имя из обратной зоны вне скоупа: владелец не подтверждён"),
                "csp" => ("Домен из CSP / карты исходников сайта", "Хост из политики CSP или source map вне скоупа: запросы к нему не выполнялись, владелец не подтверждён"),
                _ => ("Хост федерации (AD FS)", "Хост входа арендатора вне скоупа: владелец не подтверждён"),
            };
            let ip_kind = if kind == "origin_ip" { "ip" } else { "link" };
            add(
                json!({ "host": host, "kind": ip_kind, "via": o["via"], "why": format!("{why} ({})", o["via"].as_str().unwrap_or("")),
                "why_msg": { "code": "oos.via", "params": { "via": o["via"],
                    "why": crate::services::i18n::classify(why).map(|mut m| { m["text"] = json!(why); m }) } },
                "why_key": o["why_key"], "source": kind, "own": false, "hint": hint }),
            );
        }
        // 4. names from certificates (CT) and from document metadata/text not covered by the scope
        for h in &net.ct_hosts {
            add(
                json!({ "host": h, "kind": "link", "why": "Имя в сертификатах (crt.sh)",
                "own": false, "hint": "Имя из CT-логов вне скоупа: владелец не подтверждён, уточните у владельца" }),
            );
        }
        for h in &ext {
            if rules::ip4(&h.ip).is_some() || h.ip.starts_with("CNAME") || h.name.contains(' ') {
                continue;
            }
            if rules::ip4(&h.name).is_some() || !h.name.contains('.') {
                continue;
            }
            add(json!({ "host": h.name, "kind": "link",
                "why": format!("Хост в документах ({})", if h.source.is_empty() { "метаданные" } else { &h.source }),
                "own": false, "hint": "Хост из метаданных или текста документов, владелец не подтверждён" }));
        }
        Ok(Value::Array(out))
    }
}

/// Sets `Host.scope` for every host from the current scope with the same rules as the scan; hosts
/// from the network stage arrived without a status, and hosts from documents went stale after scope edits.
fn host_scope(s: &mut Snapshot) {
    let known: Vec<KnownHost> = s
        .hosts
        .iter()
        .map(|h| KnownHost {
            name: h.name.clone(),
            ip: h.ip.clone(),
        })
        .collect();
    for h in &mut s.hosts {
        let c = rules::check(&s.scope, &h.name, &known);
        h.scope = match c.code {
            "excluded" => "excluded",
            _ if c.ok => "in_scope",
            _ => "out_of_scope",
        }
        .into();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn standards_of_mapped_and_unmapped_rules() {
        let s = standards_json("doc.bad_redaction");
        assert_eq!(s["cwe"], json!(["CWE-212"]));
        assert_eq!(s["mitre"], json!(["T1213"]));
        assert!(s["owasp"].as_array().is_some_and(Vec::is_empty));
        assert!(standards_json("no.such.rule").is_null());
        assert!(standards_json("").is_null());
    }

    #[test]
    fn evidence_masking() {
        let (m, r) = mask_evidence("a {{s:Kont0so#2024!}} b {{s:x}}", 7);
        assert_eq!(m, "a {{s:Kon••••••••4!}} b {{s:••••••••}}");
        assert_eq!(r, vec!["f7:0", "f7:1"]);
        assert_eq!(evidence_secrets("{{s:a}}{{s:b}}"), vec!["a", "b"]);
        assert_eq!(ui_pattern("{f}.{last}"), "{и}.{фамилия}");
    }

    #[test]
    fn host_scope_for_every_host() {
        use foca_core::api::{Host, ScopeTarget};
        let mut s = Snapshot::default();
        s.scope.targets = vec![ScopeTarget {
            v: "kyiv.test".into(),
            kind: "domain".into(),
        }];
        s.scope.excl = vec!["old.kyiv.test".into()];
        let h = |n: &str, scope: &str| Host {
            name: n.into(),
            scope: scope.into(),
            ..Default::default()
        };
        s.hosts = vec![
            h("www.kyiv.test", ""),
            h("old.kyiv.test", "in_scope"),
            h("other.test", "in_scope"),
        ];
        host_scope(&mut s);
        let got: Vec<&str> = s.hosts.iter().map(|h| h.scope.as_str()).collect();
        assert_eq!(got, ["in_scope", "excluded", "out_of_scope"]);
    }
}
