//! Shared builders of the analysis findings: the finding skeleton, triage restore and the rule
//! ids that several producers refer to.

use foca_analysis::findings::finding_id;
use foca_analysis::PrevState;
use foca_core::api::{self, FindingProvenance, FindingRel};
use foca_core::{FindingStatus, Severity};

pub const RULE_KEV: &str = "sw.kev";
/// Known CVEs of a detected product version (offline NVD table, [`super::cves`]).
pub const RULE_CVE: &str = "sw.cve";

/// Keeps the triage of an earlier run (status, severity override, notes, photos, tags, first
/// scan, time) on a regenerated finding.
pub(crate) fn restore_triage(f: &mut api::Finding, prev: &PrevState) {
    if let Some(p) = prev.findings.get(&f.id) {
        f.status = match p.status {
            FindingStatus::Fixed => FindingStatus::New,
            s => s,
        };
        if let Some(s) = p.sev {
            f.sev = s;
        }
        f.notes = p.notes.clone();
        f.photos = p.photos.clone();
        for t in &p.tags {
            if !f.tags.contains(t) {
                f.tags.push(t.clone());
            }
        }
        if p.first_scan.is_some() {
            f.first_scan = p.first_scan.clone();
        }
        if let Some(t) = &p.time {
            f.time = t.clone();
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn finding(
    rule: &str,
    key: &str,
    title: String,
    sev: Severity,
    category: &str,
    mitre: &str,
    description: String,
    recommendation: &str,
    evidence: String,
    docs: Vec<u64>,
    now: &str,
    scan: Option<&str>,
) -> api::Finding {
    api::Finding {
        id: finding_id(rule, key),
        title,
        sev,
        status: FindingStatus::New,
        host: "-".into(),
        category: category.into(),
        source: "Аналитика".into(),
        module: "analysis".into(),
        active: false,
        time: now.to_string(),
        first_scan: scan.map(str::to_string),
        fixed_scan: None,
        tags: vec![],
        cve: vec![],
        cvss: None,
        mitre: mitre.into(),
        description,
        recommendation: recommendation.into(),
        evidence,
        request: String::new(),
        url: None,
        doc: docs.first().copied(),
        notes: vec![],
        photos: vec![],
        rel: FindingRel {
            people: vec![],
            pcs: vec![],
            docs: docs.clone(),
        },
        provenance: FindingProvenance {
            rule: rule.into(),
            fields: vec![],
            docs,
        },
    }
}
