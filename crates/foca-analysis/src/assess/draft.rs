//! A finding under construction: rule, object key, texts and links, filled in by the rule
//! modules and turned into findings with stable ids by `findings`.

use foca_core::Severity;

pub(crate) struct Draft {
    pub(crate) rule: &'static str,
    pub(crate) key: String,
    pub(crate) title: String,
    pub(crate) sev: Severity,
    pub(crate) category: &'static str,
    pub(crate) source: &'static str,
    pub(crate) module: &'static str,
    pub(crate) mitre: &'static str,
    pub(crate) cvss: Option<f32>,
    pub(crate) description: String,
    pub(crate) recommendation: &'static str,
    pub(crate) evidence: String,
    pub(crate) docs: Vec<u64>,
    pub(crate) people: Vec<String>,
    pub(crate) pcs: Vec<String>,
    pub(crate) fields: Vec<String>,
    pub(crate) tags: Vec<&'static str>,
    pub(crate) host: Option<String>,
}

/// CVSS v3 qualitative band of a score: 9.0+ critical, 7.0-8.9 high, 4.0-6.9 medium, below low.
pub fn cvss_band(score: f32) -> Severity {
    if score >= 9.0 {
        Severity::Critical
    } else if score >= 7.0 {
        Severity::High
    } else if score >= 4.0 {
        Severity::Medium
    } else {
        Severity::Low
    }
}

/// The score shown with a rule whose severity is set by the rule itself: one value per band, so
/// the severity label and the CVSS number never disagree.
pub fn band_cvss(sev: Severity) -> f32 {
    match sev {
        Severity::Critical => 9.1,
        Severity::High => 7.5,
        Severity::Medium => 5.3,
        _ => 3.7,
    }
}

impl Draft {
    pub(crate) fn new(
        rule: &'static str,
        key: impl Into<String>,
        title: impl Into<String>,
        sev: Severity,
    ) -> Self {
        Draft {
            rule,
            key: key.into(),
            title: title.into(),
            sev,
            category: "docs",
            source: "Метаданные",
            module: "meta",
            mitre: "",
            cvss: None,
            description: String::new(),
            recommendation: "",
            evidence: String::new(),
            docs: vec![],
            people: vec![],
            pcs: vec![],
            fields: vec![],
            tags: vec![],
            host: None,
        }
    }
}
