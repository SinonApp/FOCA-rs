//! Recon findings in the same style as `foca-analysis` (severity, MITRE, recommendation,
//! evidence), convertible into [`foca_core::api::Finding`].

use foca_core::api::{Finding, FindingProvenance, FindingRel};
use foca_core::{FindingStatus, Severity};
use serde::{Deserialize, Serialize};

/// A site recon finding.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReconFinding {
    /// Rule identifier (`recon.bucket_listing`, `recon.js_secret`, …), stable across versions.
    pub rule: String,
    /// Object key (bucket name, technology, secret hash); together with `rule` it yields a
    /// stable id.
    pub key: String,
    pub title: String,
    pub sev: Severity,
    pub category: String,
    pub host: String,
    pub mitre: String,
    pub description: String,
    pub recommendation: String,
    /// Evidence (secrets only in masked form).
    pub evidence: String,
    pub url: Option<String>,
    pub tags: Vec<String>,
}

impl ReconFinding {
    /// Creates a finding with empty texts (category `web`, tag `recon`).
    pub fn new(
        rule: &str,
        key: impl Into<String>,
        title: impl Into<String>,
        sev: Severity,
        host: &str,
    ) -> ReconFinding {
        ReconFinding {
            rule: rule.into(),
            key: key.into(),
            title: title.into(),
            sev,
            category: "web".into(),
            host: host.into(),
            mitre: String::new(),
            description: String::new(),
            recommendation: String::new(),
            evidence: String::new(),
            url: None,
            tags: vec!["recon".into()],
        }
    }

    /// Returns a stable id: FNV-1a 64 of `rule` + `key`, like `foca-analysis` findings but with
    /// its own hash.
    pub fn stable_id(&self) -> u64 {
        let mut h: u64 = 0xcbf29ce484222325;
        for b in self.rule.bytes().chain([0u8]).chain(self.key.bytes()) {
            h ^= u64::from(b);
            h = h.wrapping_mul(0x100000001b3);
        }
        h & 0x1f_ffff_ffff_ffff // fits into an f64 / JS Number
    }

    /// Converts into the shared finding model (`time` is the ISO time of the scan).
    pub fn to_finding(&self, time: &str) -> Finding {
        Finding {
            id: self.stable_id(),
            title: self.title.clone(),
            sev: self.sev,
            status: FindingStatus::default(),
            host: self.host.clone(),
            category: self.category.clone(),
            source: "Разведка сайта".into(),
            module: "recon".into(),
            active: false,
            time: time.into(),
            first_scan: None,
            fixed_scan: None,
            tags: self.tags.clone(),
            cve: vec![],
            cvss: None,
            mitre: self.mitre.clone(),
            description: self.description.clone(),
            recommendation: self.recommendation.clone(),
            evidence: self.evidence.clone(),
            request: String::new(),
            url: self.url.clone(),
            doc: None,
            notes: vec![],
            photos: vec![],
            rel: FindingRel::default(),
            provenance: FindingProvenance {
                rule: self.rule.clone(),
                fields: vec![],
                docs: vec![],
            },
        }
    }
}
