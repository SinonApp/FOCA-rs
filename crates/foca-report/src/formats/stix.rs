//! Pure-Rust OASIS STIX 2.1 JSON bundle generator (`ExportFormat::Stix`).
//!
//! Exports safe, redacted threat intelligence and attack-surface observables (identities,
//! infrastructure, domains, IPs, URLs, emails, files, software, CVEs/vulnerabilities,
//! indicators, notes and relationships) suitable for MISP, OpenCTI and SIEM ingestion.
//!
//! Secret safety invariant: raw secret values and raw PII never enter any STIX object, regardless
//! of export options; every string runs through `SecretMode::Hide` and [`crate::mask::Pii`].

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::net::IpAddr;

use foca_core::api::Snapshot;
use foca_core::{FindingStatus, Severity};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use crate::mask::{Pii, Redactor};
use crate::opts::{Lang, SecretMode};
use crate::safe;

const CREATED_TS: &str = "2026-01-01T00:00:00.000Z";

/// Generates a deterministic STIX 2.1 UUIDv5-shaped identifier `<stix_type>--<uuid>`.
fn stix_id(stix_type: &str, key: &str) -> String {
    let mut h = Sha256::new();
    h.update(b"foca-stix-2.1\0");
    h.update(stix_type.as_bytes());
    h.update(b"\0");
    h.update(key.as_bytes());
    let sum = h.finalize();
    let mut u = [0u8; 16];
    u.copy_from_slice(&sum[..16]);
    u[6] = (u[6] & 0x0f) | 0x50; // version 5
    u[8] = (u[8] & 0x3f) | 0x80; // RFC 4122 variant
    format!(
        "{stix_type}--{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        u[0], u[1], u[2], u[3], u[4], u[5], u[6], u[7], u[8], u[9], u[10], u[11], u[12], u[13], u[14], u[15]
    )
}

fn stix_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\'' => out.push_str("\\'"),
            c if c.is_control() => {}
            c => out.push(c),
        }
    }
    out
}

fn sanitize_line(red: &Redactor, pii: &Pii, s: &str) -> String {
    let masked = pii.text(&red.text(s));
    masked
        .chars()
        .filter(|c| !c.is_control() || *c == ' ')
        .collect::<String>()
        .trim()
        .to_string()
}

fn timestamp_or_default(snap: &Snapshot) -> String {
    snap.scans
        .iter()
        .filter_map(|s| s.finished_at.as_deref().or(Some(s.started_at.as_str())))
        .filter(|t| t.len() >= 19 && t.ends_with('Z'))
        .max()
        .map(String::from)
        .unwrap_or_else(|| CREATED_TS.to_string())
}

fn sev_confidence(s: Severity) -> u64 {
    match s {
        Severity::Critical => 90,
        Severity::High => 80,
        Severity::Medium => 65,
        Severity::Low => 45,
        Severity::Info => 30,
    }
}

fn valid_stix_url(red: &Redactor, pii: &Pii, raw: &str) -> Option<String> {
    let raw = raw.trim();
    // A URL that carried a secret or personal data is dropped as a whole: a masked URL
    // (`?token=[…]`, `••••`) is not an indicator anyone can match, and comparing with the
    // source does not depend on the placeholder text of a particular locale or mode.
    if sanitize_line(red, pii, raw) != raw {
        return None;
    }
    safe::safe_href(raw).map(str::to_string)
}

struct BundleBuilder {
    objects: Vec<Value>,
    seen_ids: BTreeSet<String>,
}

impl BundleBuilder {
    fn new() -> Self {
        Self {
            objects: Vec::new(),
            seen_ids: BTreeSet::new(),
        }
    }

    fn push(&mut self, obj: Value) -> Option<String> {
        let id = obj.get("id")?.as_str()?.to_string();
        if self.seen_ids.insert(id.clone()) {
            self.objects.push(obj);
        }
        Some(id)
    }

    fn relate(
        &mut self,
        source_ref: &str,
        relationship_type: &str,
        target_ref: &str,
        ts: &str,
        created_by: &str,
    ) {
        if source_ref == target_ref
            || !self.seen_ids.contains(source_ref)
            || !self.seen_ids.contains(target_ref)
        {
            return;
        }
        let id = stix_id(
            "relationship",
            &format!("{source_ref}|{relationship_type}|{target_ref}"),
        );
        self.push(json!({
            "type": "relationship",
            "spec_version": "2.1",
            "id": id,
            "created": ts,
            "modified": ts,
            "created_by_ref": created_by,
            "relationship_type": relationship_type,
            "source_ref": source_ref,
            "target_ref": target_ref,
        }));
    }
}

/// Builds a STIX 2.1 JSON bundle from `snap`. Raw secrets are always redacted via `SecretMode::Hide`.
pub fn export_bundle(snap: &Snapshot, pretty: bool) -> (Vec<u8>, usize) {
    let red = Redactor::new(snap, SecretMode::Hide, Lang::Ru);
    let pii = Pii::new(snap);
    let ts = timestamp_or_default(snap);
    let mut b = BundleBuilder::new();

    // 1. Producer identity & optional organization identity.
    let producer_id = stix_id("identity", "FOCA-rs");
    b.push(json!({
        "type": "identity",
        "spec_version": "2.1",
        "id": producer_id,
        "created": ts,
        "modified": ts,
        "name": "FOCA-rs",
        "identity_class": "system",
    }));

    let org_raw = if !snap.scope.client.trim().is_empty() {
        &snap.scope.client
    } else {
        &snap.project.name
    };
    let org_name = sanitize_line(&red, &pii, org_raw);
    let org_id = if !org_name.is_empty() {
        let oid = stix_id("identity", &org_name);
        b.push(json!({
            "type": "identity",
            "spec_version": "2.1",
            "id": oid,
            "created": ts,
            "modified": ts,
            "created_by_ref": producer_id,
            "name": org_name,
            "identity_class": "organization",
        }));
        Some(oid)
    } else {
        None
    };

    // 2. Host/Domain/IP SCOs & Infrastructure SDOs.
    let mut host_ids: BTreeMap<String, String> = BTreeMap::new();

    for h in &snap.hosts {
        let name = sanitize_line(&red, &pii, &h.name).to_ascii_lowercase();
        if name.is_empty() || h.scope == "excluded" {
            continue;
        }
        let mut resolves_to = Vec::new();
        for tok in
            h.ip.split(|c: char| c == ',' || c.is_whitespace())
                .map(str::trim)
                .filter(|s| !s.is_empty())
        {
            if let Ok(ip) = tok.parse::<IpAddr>() {
                let stype = if ip.is_ipv6() {
                    "ipv6-addr"
                } else {
                    "ipv4-addr"
                };
                let iid = stix_id(stype, &ip.to_string());
                b.push(json!({
                    "type": stype,
                    "spec_version": "2.1",
                    "id": iid,
                    "value": ip.to_string(),
                }));
                resolves_to.push(iid);
            }
        }
        if let Ok(ip) = name.parse::<IpAddr>() {
            let stype = if ip.is_ipv6() {
                "ipv6-addr"
            } else {
                "ipv4-addr"
            };
            let iid = stix_id(stype, &ip.to_string());
            b.push(json!({
                "type": stype,
                "spec_version": "2.1",
                "id": iid,
                "value": ip.to_string(),
            }));
            host_ids.insert(name, iid);
        } else {
            let did = stix_id("domain-name", &name);
            let mut dom = Map::new();
            dom.insert("type".into(), json!("domain-name"));
            dom.insert("spec_version".into(), json!("2.1"));
            dom.insert("id".into(), json!(did));
            dom.insert("value".into(), json!(name));
            if !resolves_to.is_empty() {
                dom.insert("resolves_to_refs".into(), json!(resolves_to));
            }
            b.push(Value::Object(dom));
            host_ids.insert(name, did);
        }
    }

    // 3. URL SCOs from live documents & findings.
    let mut url_ids: BTreeMap<String, String> = BTreeMap::new();
    for u in snap
        .docs
        .iter()
        .filter(|d| !d.deleted)
        .map(|d| d.url.as_str())
        .chain(snap.findings.iter().filter_map(|f| f.url.as_deref()))
    {
        if let Some(clean_u) = valid_stix_url(&red, &pii, u) {
            let uid = stix_id("url", &clean_u);
            b.push(json!({
                "type": "url",
                "spec_version": "2.1",
                "id": uid,
                "value": clean_u,
            }));
            url_ids.insert(clean_u, uid);
        }
    }

    // 4. Email SCOs.
    for e in &snap.emails {
        let addr = sanitize_line(&red, &pii, &e.addr).to_ascii_lowercase();
        if addr.contains('@') && !addr.contains("скрыт") && !addr.contains("прихован")
        {
            let eid = stix_id("email-addr", &addr);
            b.push(json!({
                "type": "email-addr",
                "spec_version": "2.1",
                "id": eid,
                "value": addr,
            }));
        }
    }

    // 5. File SCOs for analyzed documents (limit 250).
    for d in snap.docs.iter().filter(|d| !d.deleted).take(250) {
        let fname = sanitize_line(&red, &pii, &d.name);
        if fname.is_empty() {
            continue;
        }
        let fid = stix_id("file", &format!("{}:{}", d.id, fname));
        b.push(json!({
            "type": "file",
            "spec_version": "2.1",
            "id": fid,
            "name": fname,
            "size": d.size.saturating_mul(1024),
        }));
    }

    // 6. Software SCOs.
    for s in &snap.software {
        let name = sanitize_line(&red, &pii, &s.name);
        if name.is_empty() {
            continue;
        }
        let ver = sanitize_line(&red, &pii, &s.ver);
        let sid = stix_id("software", &format!("{name}:{ver}"));
        let mut obj = json!({
            "type": "software",
            "spec_version": "2.1",
            "id": sid,
            "name": name,
        });
        if !ver.is_empty() {
            obj["version"] = json!(ver);
        }
        b.push(obj);
    }

    // 7. Vulnerabilities (unique CVEs) and Indicators + Relationships for live findings.
    let mut vuln_ids: BTreeMap<String, String> = BTreeMap::new();
    let mut project_refs: Vec<String> = Vec::new();
    if let Some(oid) = &org_id {
        project_refs.push(oid.clone());
    }

    for f in snap.findings.iter().filter(|f| {
        !matches!(
            f.status,
            FindingStatus::FalsePositive | FindingStatus::Fixed
        )
    }) {
        for cve in &f.cve {
            let cve_clean = sanitize_line(&red, &pii, cve).to_ascii_uppercase();
            if cve_clean.starts_with("CVE-") {
                let vid = stix_id("vulnerability", &cve_clean);
                b.push(json!({
                    "type": "vulnerability",
                    "spec_version": "2.1",
                    "id": vid,
                    "created": ts,
                    "modified": ts,
                    "created_by_ref": producer_id,
                    "name": cve_clean,
                    "external_references": [{
                        "source_name": "cve",
                        "external_id": cve_clean,
                        "url": format!("https://nvd.nist.gov/vuln/detail/{cve_clean}"),
                    }],
                }));
                vuln_ids.insert(cve_clean, vid);
            }
        }

        let host_clean = sanitize_line(&red, &pii, &f.host).to_ascii_lowercase();
        let url_clean = f.url.as_deref().and_then(|u| valid_stix_url(&red, &pii, u));

        let pattern = if let Some(u) = &url_clean {
            format!("[url:value = '{}']", stix_escape(u))
        } else if let Ok(ip) = host_clean.parse::<IpAddr>() {
            let prop = if ip.is_ipv6() {
                "ipv6-addr:value"
            } else {
                "ipv4-addr:value"
            };
            format!("[{prop} = '{}']", stix_escape(&ip.to_string()))
        } else if !host_clean.is_empty() {
            format!("[domain-name:value = '{}']", stix_escape(&host_clean))
        } else {
            continue;
        };

        let ind_id = stix_id("indicator", &format!("{}:{}", f.id, pattern));
        let title = sanitize_line(&red, &pii, &f.title);
        let desc = sanitize_line(&red, &pii, &f.description);
        let mut labels = vec![format!("sev:{}", crate::data::sev_id(f.sev))];
        if !f.category.is_empty() {
            labels.push(sanitize_line(&red, &pii, &f.category));
        }
        if !f.provenance.rule.is_empty() {
            labels.push(sanitize_line(&red, &pii, &f.provenance.rule));
        }

        b.push(json!({
            "type": "indicator",
            "spec_version": "2.1",
            "id": ind_id,
            "created": ts,
            "modified": ts,
            "created_by_ref": producer_id,
            "name": title,
            "description": desc,
            "indicator_types": ["anomalous-activity"],
            "pattern": pattern,
            "pattern_type": "stix",
            "valid_from": ts,
            "confidence": sev_confidence(f.sev),
            "labels": labels,
        }));
        project_refs.push(ind_id.clone());

        if let Some(hid) = host_ids.get(&host_clean).cloned() {
            b.relate(&ind_id, "based-on", &hid, &ts, &producer_id);
        } else if let Some(uid) = url_clean.as_ref().and_then(|u| url_ids.get(u)).cloned() {
            b.relate(&ind_id, "based-on", &uid, &ts, &producer_id);
        }
        for cve in &f.cve {
            let k = sanitize_line(&red, &pii, cve).to_ascii_uppercase();
            if let Some(vid) = vuln_ids.get(&k).cloned() {
                b.relate(&ind_id, "indicates", &vid, &ts, &producer_id);
            }
        }
    }

    if project_refs.len() > 1 || (!project_refs.is_empty() && !b.objects.is_empty()) {
        let proj_clean = sanitize_line(&red, &pii, &snap.project.name);
        let valid_refs: Vec<String> = project_refs
            .into_iter()
            .filter(|id| b.seen_ids.contains(id))
            .collect();
        if !valid_refs.is_empty() {
            let nid = stix_id("note", &format!("summary:{proj_clean}"));
            b.push(json!({
                "type": "note",
                "spec_version": "2.1",
                "id": nid,
                "created": ts,
                "modified": ts,
                "created_by_ref": producer_id,
                "abstract": format!("FOCA-rs exposure summary for {proj_clean}"),
                "content": format!(
                    "Findings: {}, Hosts: {}, Secrets detected (values redacted): {}",
                    snap.findings.len(),
                    snap.hosts.len(),
                    snap.secrets.len()
                ),
                "object_refs": valid_refs,
            }));
        }
    }

    let bundle_key = {
        let mut k = String::new();
        let _ = write!(k, "{}:{}:{}", snap.project.name, ts, b.objects.len());
        k
    };
    let count = b.objects.len();
    let bundle = json!({
        "type": "bundle",
        "id": stix_id("bundle", &bundle_key),
        "objects": b.objects,
    });
    let bytes = if pretty {
        serde_json::to_vec_pretty(&bundle)
    } else {
        serde_json::to_vec(&bundle)
    }
    .unwrap_or_default();
    (bytes, count)
}
