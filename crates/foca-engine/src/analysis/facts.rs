//! Engine state stored in the project file (the project `settings` table): network facts (hosts
//! and DNS/SPF/DMARC/AXFR findings), the finding id map, extra scan record fields, out-of-scope
//! candidate decisions and cleaned copy details. Also re-analysis that merges them in.

use std::collections::{BTreeMap, BTreeSet};

use foca_analysis::Analysis;
use foca_core::api::{self, FindingProvenance, FindingRel};
use foca_core::{FindingStatus, Severity};
use foca_store::ProjectDb;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::CmdError;

pub const K_NET: &str = "engine.net";
pub const K_FIDS: &str = "engine.fids";
pub const K_OOS: &str = "engine.oos";
pub const K_CLEANED: &str = "engine.cleaned";
pub const K_ALERT_SNAP: &str = "engine.alert_snap";
pub const K_ALERT_FIRED: &str = "engine.alert_fired";
pub const K_ALERT_LOG: &str = "engine.alert_log";
pub const K_ALERT_CFG: &str = "engine.alert_cfg";

pub fn scan_key(id: &str) -> String {
    format!("engine.scan.{id}")
}

pub fn get<T: for<'de> Deserialize<'de> + Default>(db: &ProjectDb, key: &str) -> T {
    db.setting(key)
        .ok()
        .flatten()
        .and_then(|v| serde_json::from_value(v).ok())
        .unwrap_or_default()
}

pub fn put<T: Serialize>(db: &ProjectDb, key: &str, v: &T) -> Result<(), CmdError> {
    db.set_setting(key, &serde_json::to_value(v)?)?;
    Ok(())
}

/// A host from the network stage.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct NetHost {
    pub name: String,
    pub ip: String,
    pub role: String,
    pub tech: String,
    pub cloud: String,
    pub source: String,
    pub services: Vec<(String, String, String)>,
    pub dns: Vec<(String, String, String)>,
    pub asn: Option<String>,
    pub tls: Option<Value>,
    pub first_scan: Option<String>,
    /// Dangling CNAME: the chain target.
    pub dangling: Option<String>,
    /// Result of the built-in port scan (`scan::ports::PortsScanInfo`, full profile only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ports_scan: Option<Value>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct NetFacts {
    pub hosts: BTreeMap<String, NetHost>,
    pub findings: BTreeMap<u64, api::Finding>,
    /// Subdomains from CT (crt.sh) and sources: candidates for the DNS stage and `oos`.
    pub ct_hosts: BTreeSet<String>,
}

impl NetFacts {
    pub fn host(&mut self, name: &str) -> &mut NetHost {
        self.hosts
            .entry(name.to_string())
            .or_insert_with(|| NetHost {
                name: name.to_string(),
                ip: "-".into(),
                tech: "-".into(),
                cloud: "-".into(),
                ..Default::default()
            })
    }
}

/// A network stage finding (the id is a stable hash of the rule and the object, as in the analysis).
#[allow(clippy::too_many_arguments)]
pub fn net_finding(
    rule: &str,
    key: &str,
    title: String,
    sev: Severity,
    host: &str,
    category: &str,
    source: &str,
    module: &str,
    active: bool,
    time: &str,
    scan: Option<&str>,
    description: String,
    recommendation: &str,
    evidence: String,
    url: Option<String>,
) -> api::Finding {
    api::Finding {
        id: foca_analysis::findings::finding_id(rule, key),
        title,
        sev,
        status: FindingStatus::New,
        host: host.to_string(),
        category: category.into(),
        source: source.into(),
        module: module.into(),
        active,
        time: time.to_string(),
        first_scan: scan.map(str::to_string),
        fixed_scan: None,
        tags: vec![],
        cve: vec![],
        cvss: None,
        mitre: String::new(),
        description,
        recommendation: recommendation.into(),
        evidence,
        request: String::new(),
        url,
        doc: None,
        notes: vec![],
        photos: vec![],
        rel: FindingRel::default(),
        provenance: FindingProvenance {
            rule: rule.into(),
            fields: vec![],
            docs: vec![],
        },
    }
}

/// Map between hash finding ids and short numbers (screens and `f<id>:<k>` work with small numbers).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct FidMap {
    pub map: BTreeMap<u64, u64>,
    pub next: u64,
}

impl FidMap {
    pub fn seq(&mut self, hash: u64) -> u64 {
        if let Some(s) = self.map.get(&hash) {
            return *s;
        }
        self.next = self.next.max(self.map.values().copied().max().unwrap_or(0)) + 1;
        self.map.insert(hash, self.next);
        self.next
    }
    pub fn get(&self, hash: u64) -> u64 {
        self.map.get(&hash).copied().unwrap_or(hash)
    }
    /// Drops the numbers of deleted findings (`scan_delete`).
    pub fn forget(&mut self, gone: &[u64]) {
        self.map.retain(|h, _| !gone.contains(h));
    }
    pub fn hash_of(&self, seq: u64) -> Option<u64> {
        self.map.iter().find(|(_, s)| **s == seq).map(|(h, _)| *h)
    }
}

/// Assigns short numbers to all project findings (deterministically, by severity and title).
pub fn assign_fids(db: &ProjectDb) -> Result<FidMap, CmdError> {
    let mut m: FidMap = get(db, K_FIDS);
    let before = m.clone();
    let mut fl = db.findings()?;
    fl.sort_by(|a, b| {
        a.sev
            .cmp(&b.sev)
            .then(a.title.cmp(&b.title))
            .then(a.id.cmp(&b.id))
    });
    for f in &fl {
        m.seq(f.id);
    }
    if m != before {
        put(db, K_FIDS, &m)?;
    }
    Ok(m)
}

pub(crate) fn merge_facts(
    a: &mut Analysis,
    f: &NetFacts,
    scan_id: Option<&str>,
    prev: &foca_analysis::PrevState,
) {
    for h in f.hosts.values() {
        if let Some(x) = a.hosts.iter_mut().find(|x| x.name == h.name) {
            if (x.ip.is_empty() || x.ip == "-") && !h.ip.is_empty() {
                x.ip = h.ip.clone();
            }
            if (x.tech.is_empty() || x.tech == "-") && !h.tech.is_empty() {
                x.tech = h.tech.clone();
            }
            if x.services.is_empty() {
                x.services = h.services.clone();
            }
            if !h.role.is_empty() && (x.role.is_empty() || x.role == "-") {
                x.role = h.role.clone();
            }
            continue;
        }
        a.hosts.push(api::Host {
            name: h.name.clone(),
            ip: h.ip.clone(),
            role: if h.role.is_empty() {
                "-".into()
            } else {
                h.role.clone()
            },
            tech: h.tech.clone(),
            cloud: h.cloud.clone(),
            services: h.services.clone(),
            source: h.source.clone(),
            internal: false,
            sev: "ok".into(),
            first_scan: h.first_scan.clone().or(scan_id.map(str::to_string)),
            scope: String::new(),
        });
    }
    for nf in f.findings.values() {
        a.resolved.retain(|id| *id != nf.id);
        if !a.findings.iter().any(|x| x.id == nf.id) {
            a.findings.push(nf.clone());
        }
    }
    // TLS settings of CDN edges belong to the provider's dashboard; then one finding per rule
    // and host instead of one per port.
    let mut dropped =
        foca_analysis::infra::adjust_cdn_edges(&mut a.findings, &a.hosts, &prev.findings);
    dropped.extend(foca_analysis::portmerge::merge_ports(
        &mut a.findings,
        &prev.findings,
    ));
    let ids: std::collections::BTreeSet<u64> = a.findings.iter().map(|f| f.id).collect();
    a.resolved
        .retain(|id| !ids.contains(id) && !dropped.contains(id));
    a.dropped = dropped;
}
