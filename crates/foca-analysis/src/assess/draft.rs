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
