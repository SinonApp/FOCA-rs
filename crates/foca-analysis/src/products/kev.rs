//! Offline CISA KEV catalog: "this product has known exploited CVEs".
//!
//! The CISA Known Exploited Vulnerabilities catalog (public domain) is embedded as a filtered,
//! gzip-compressed TSV snapshot (`signatures/kev.tsv.gz`, refreshed by
//! `signatures/update_kev.py`). Only vendors/products comparable with what FOCA-rs detects are
//! kept; the mapping lives in `signatures/kev_products.toml` and is shared with the script.
//!
//! KEV carries no affected version ranges, so a match never claims a vulnerability: it says
//! "N exploited CVEs exist for product X, check the version". The signal is stronger for a
//! version out of vendor support (EOL): CVEs added to KEV after the EOL date will not get a fix
//! for that version.

use std::io::Read;
use std::sync::OnceLock;

use foca_core::Severity;
use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::Analysis;

/// Embedded snapshot.
pub const KEV_GZ: &[u8] = include_bytes!("../../signatures/kev.tsv.gz");
/// Product mapping shared with the update script.
pub const PRODUCTS_TOML: &str = include_str!("../../signatures/kev_products.toml");

/// One KEV record of the snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct KevEntry {
    pub cve: String,
    /// Product keys of `kev_products.toml`.
    pub keys: Vec<String>,
    pub vendor: String,
    pub product: String,
    /// Date the CVE was added to KEV (`YYYY-MM-DD`).
    pub date_added: String,
    /// Known use in ransomware campaigns.
    pub ransomware: bool,
    pub name: String,
}

#[derive(Debug, Deserialize)]
struct ProductDef {
    key: String,
    label: String,
    kind: String,
    #[serde(rename = "match")]
    re: String,
}

#[derive(Debug, Deserialize)]
struct ProductFile {
    product: Vec<ProductDef>,
}

/// A product group of the mapping.
#[derive(Debug, Clone)]
pub struct KevProduct {
    pub key: String,
    pub label: String,
    pub kind: String,
    re: Regex,
}

impl KevProduct {
    /// Whether a detected software/technology name belongs to the product.
    pub fn matches(&self, name: &str) -> bool {
        self.re.is_match(name)
    }
}

/// The parsed catalog.
#[derive(Debug, Clone)]
pub struct KevCatalog {
    /// `catalogVersion` of the snapshot (`2026.11.20`).
    pub version: String,
    /// `dateReleased` of the snapshot (`YYYY-MM-DD`).
    pub released: String,
    /// Records in the full CISA catalog at the snapshot date.
    pub total: usize,
    pub entries: Vec<KevEntry>,
    products: Vec<KevProduct>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KevError(pub String);

impl std::fmt::Display for KevError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl KevCatalog {
    /// Number of product (CPE) mappings that link software names to catalog entries.
    pub fn product_count(&self) -> usize {
        self.products.len()
    }

    /// Parses a gzip TSV snapshot and the product mapping.
    pub fn parse(gz: &[u8], products_toml: &str) -> Result<KevCatalog, KevError> {
        let mut text = String::new();
        flate2::read::GzDecoder::new(gz)
            .read_to_string(&mut text)
            .map_err(|e| KevError(format!("kev snapshot: {e}")))?;
        let pf: ProductFile =
            toml::from_str(products_toml).map_err(|e| KevError(format!("kev products: {e}")))?;
        let mut products = Vec::with_capacity(pf.product.len());
        for p in pf.product {
            let re = Regex::new(&format!("(?i){}", p.re))
                .map_err(|e| KevError(format!("kev product {}: {e}", p.key)))?;
            products.push(KevProduct {
                key: p.key,
                label: p.label,
                kind: p.kind,
                re,
            });
        }
        let mut cat = KevCatalog {
            version: String::new(),
            released: String::new(),
            total: 0,
            entries: Vec::new(),
            products,
        };
        for line in text.lines() {
            if let Some(h) = line.strip_prefix('#') {
                for kv in h.split_whitespace() {
                    match kv.split_once('=') {
                        Some(("catalog", v)) => cat.version = v.into(),
                        Some(("released", v)) => cat.released = v.into(),
                        Some(("total", v)) => cat.total = v.parse().unwrap_or(0),
                        _ => {}
                    }
                }
                continue;
            }
            let f: Vec<&str> = line.split('\t').collect();
            if f.len() != 7 {
                continue;
            }
            cat.entries.push(KevEntry {
                cve: f[0].into(),
                keys: f[1].split(',').map(str::to_string).collect(),
                vendor: f[2].into(),
                product: f[3].into(),
                date_added: f[4].into(),
                ransomware: f[5] == "R",
                name: f[6].into(),
            });
        }
        Ok(cat)
    }

    /// The embedded snapshot.
    pub fn builtin() -> &'static KevCatalog {
        static CAT: OnceLock<KevCatalog> = OnceLock::new();
        CAT.get_or_init(|| {
            KevCatalog::parse(KEV_GZ, PRODUCTS_TOML).expect("embedded KEV snapshot is valid")
        })
    }

    /// Records of a product key.
    pub fn for_key<'a>(&'a self, key: &'a str) -> impl Iterator<Item = &'a KevEntry> + 'a {
        self.entries
            .iter()
            .filter(move |e| e.keys.iter().any(|k| k == key))
    }

    /// Returns a cloned catalog extended with additional KEV entries (deduplicated by CVE+key).
    pub fn with_additions(&self, extra: Vec<KevEntry>) -> KevCatalog {
        if extra.is_empty() {
            return self.clone();
        }
        let mut cat = self.clone();
        for e in extra {
            if let Some(existing) = cat.entries.iter_mut().find(|x| x.cve == e.cve) {
                for k in e.keys {
                    if !existing.keys.contains(&k) {
                        existing.keys.push(k);
                    }
                }
                existing.ransomware |= e.ransomware;
            } else {
                cat.entries.push(e);
                cat.total += 1;
            }
        }
        cat
    }

    /// Product groups a detected name belongs to.
    pub fn products_for(&self, name: &str) -> Vec<&KevProduct> {
        self.products.iter().filter(|p| p.matches(name)).collect()
    }
}

/// Where a matched subject comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SubjectKind {
    /// Document software (`Analysis.software`): installed on the authors' workstations.
    Software,
    /// Operating system from document metadata (`Analysis.os`).
    Os,
    /// Web technology or server banner of a host.
    Tech,
}

/// A detected product to look up.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct KevSubject {
    pub kind: SubjectKind,
    /// Software id, OS id or host name.
    pub id: String,
    /// Display name (`Microsoft Office Word 2010`, `Apache HTTP Server 2.4.49`).
    pub name: String,
    pub ver: String,
    /// Vendor support has ended.
    pub eol: bool,
    pub eol_date: Option<String>,
    /// Number of documents (software/OS) or 0 for hosts.
    pub docs: u32,
    /// Optional host/banner context (e.g. other technologies on the same host) for OS checks.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub context: String,
}

/// A short KEV reference.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct KevRef {
    pub cve: String,
    pub date_added: String,
    pub ransomware: bool,
    pub name: String,
}

/// Lookup result for one subject and product group.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct KevMatch {
    pub product_key: String,
    pub product_label: String,
    pub subject: KevSubject,
    /// All exploited CVEs of the product group, newest first (capped at 25 in `cves`).
    pub total: u32,
    pub ransomware: u32,
    /// CVEs added to KEV after the subject's EOL date (only for EOL subjects with a date).
    pub after_eol: u32,
    pub cves: Vec<KevRef>,
    /// `possible` (product matches, version unknown against KEV) or `likely` (EOL version and
    /// exploited CVEs published after support ended).
    pub confidence: String,
    /// 0-100.
    pub score: u8,
    pub sev: Severity,
    /// Russian title and explanation (the core language).
    pub title: String,
    pub reason: String,
}

/// Subjects from an analysis: document software, operating systems and host technologies
/// (`Host.tech`, comma-separated).
pub fn subjects_from(a: &Analysis) -> Vec<KevSubject> {
    let mut out: Vec<KevSubject> = a
        .software
        .iter()
        .filter(|s| !matches!(s.kind.as_str(), "camera" | "scanner"))
        .map(|s| KevSubject {
            kind: SubjectKind::Software,
            id: s.id.clone(),
            name: s.name.clone(),
            ver: s.ver.clone(),
            eol: s.eol,
            eol_date: s.eol_date.clone(),
            docs: s.docs,
            context: String::new(),
        })
        .collect();
    out.extend(a.os.iter().map(|o| KevSubject {
        kind: SubjectKind::Os,
        id: o.id.clone(),
        name: o.name.clone(),
        ver: o.ver.clone(),
        eol: o.eol,
        eol_date: o.eol_date.clone(),
        docs: o.docs,
        context: String::new(),
    }));
    for h in &a.hosts {
        for t in h
            .tech
            .split([',', ';'])
            .map(str::trim)
            .filter(|t| !t.is_empty())
        {
            out.push(KevSubject {
                kind: SubjectKind::Tech,
                id: h.name.clone(),
                name: t.to_string(),
                ver: String::new(),
                eol: false,
                eol_date: None,
                docs: 0,
                context: h.tech.clone(),
            });
        }
    }
    out
}

/// Matches subjects against the catalog. One result per (subject, product group); a subject
/// may belong to several groups (e.g. Windows and Internet Explorer).
pub fn lookup(cat: &KevCatalog, subjects: &[KevSubject]) -> Vec<KevMatch> {
    let mut out = Vec::new();
    for s in subjects {
        let probe = if s.ver.is_empty() || s.name.contains(&s.ver) {
            s.name.clone()
        } else {
            format!("{} {}", s.name, s.ver)
        };
        for p in cat.products_for(&probe) {
            let ver_eval = crate::vercmp::eval_product_version_with_context(
                &p.key, &s.name, &s.ver, &s.context,
            );
            if matches!(ver_eval, crate::vercmp::VersionEval::Patched { .. }) {
                // Exact version is strictly newer than or equal to the highest known fix threshold
                // for this product group -> suppress false-positive KEV match.
                continue;
            }
            let mut refs: Vec<&KevEntry> = cat.for_key(&p.key).collect();
            if refs.is_empty() {
                continue;
            }
            refs.sort_by(|a, b| b.date_added.cmp(&a.date_added).then(a.cve.cmp(&b.cve)));
            let mut version_confirmed = false;
            if let crate::vercmp::VersionEval::Confirmed { ref cves, .. } = ver_eval {
                // Restrict to CVEs confirmed by version range when present in KEV so unrelated
                // legacy CVEs (e.g. CVE-2021-41773 on 2.4.58) do not pollute the finding.
                let filtered: Vec<&KevEntry> = refs
                    .iter()
                    .copied()
                    .filter(|e| cves.contains(&e.cve.as_str()))
                    .collect();
                if !filtered.is_empty() {
                    refs = filtered;
                    version_confirmed = true;
                }
            }
            let ransomware = refs.iter().filter(|e| e.ransomware).count() as u32;
            let after: Vec<&&KevEntry> = match (&s.eol_date, s.eol) {
                (Some(d), true) => refs
                    .iter()
                    .filter(|e| e.date_added.as_str() > d.as_str())
                    .collect(),
                _ => vec![],
            };
            let after_ransom = after.iter().any(|e| e.ransomware);
            let (confidence, score, sev) = match &ver_eval {
                crate::vercmp::VersionEval::Confirmed {
                    distro_backport: false,
                    ..
                } if version_confirmed => ("likely", 85u8, Severity::High),
                crate::vercmp::VersionEval::Confirmed {
                    distro_backport: true,
                    ..
                } if version_confirmed => ("possible", 45u8, Severity::Medium),
                _ if s.eol && !after.is_empty() => {
                    let sev = if after_ransom {
                        Severity::High
                    } else {
                        Severity::Medium
                    };
                    ("likely", 60u8, sev)
                }
                _ if s.eol => ("possible", 45, Severity::Medium),
                _ => ("possible", 30, Severity::Low),
            };
            let side = match s.kind {
                SubjectKind::Software | SubjectKind::Os => {
                    "ПО найдено в метаданных документов: оно стоит на рабочих станциях авторов (риск фишинга и вредоносных вложений)"
                }
                SubjectKind::Tech => "Технология обнаружена на хосте организации",
            };
            let mut reason = format!(
                "{side}. В каталоге CISA KEV для продукта «{}» {} эксплуатируемых уязвимостей{}.",
                p.label,
                refs.len(),
                if ransomware > 0 {
                    format!(", из них {ransomware}: в кампаниях вымогателей")
                } else {
                    String::new()
                },
            );
            match &ver_eval {
                crate::vercmp::VersionEval::Confirmed {
                    ver,
                    cves,
                    fixed_in,
                    distro_backport: false,
                } if version_confirmed => {
                    reason.push_str(&format!(
                        " Семантическая проверка CPE/CVE: версия {ver} попадает в уязвимый диапазон < {fixed_in} ({}).",
                        cves.join(", ")
                    ));
                }
                crate::vercmp::VersionEval::Confirmed {
                    ver,
                    cves,
                    fixed_in,
                    distro_backport: true,
                } if version_confirmed => {
                    reason.push_str(&format!(
                        " Базовая версия {ver} (< {fixed_in}: {}), однако выявлен дистрибутивный пакет (возможны бэкпорты исправлений): сверьте патч-уровень {probe} в ОС.",
                        cves.join(", ")
                    ));
                }
                _ => {
                    reason.push_str(&format!(
                        " KEV не указывает уязвимые версии: сверьте версию {probe} с бюллетенями производителя."
                    ));
                }
            }
            if s.eol {
                reason.push_str(&format!(
                    " Версия снята с поддержки{}: исправления для неё больше не выходят",
                    s.eol_date
                        .as_deref()
                        .map(|d| format!(" ({d})"))
                        .unwrap_or_default()
                ));
                if !after.is_empty() {
                    reason.push_str(&format!(
                        "; {} CVE добавлены в KEV уже после окончания поддержки.",
                        after.len()
                    ));
                } else {
                    reason.push('.');
                }
            }
            out.push(KevMatch {
                product_key: p.key.clone(),
                product_label: p.label.clone(),
                subject: s.clone(),
                total: refs.len() as u32,
                ransomware,
                after_eol: after.len() as u32,
                cves: refs
                    .iter()
                    .take(25)
                    .map(|e| KevRef {
                        cve: e.cve.clone(),
                        date_added: e.date_added.clone(),
                        ransomware: e.ransomware,
                        name: e.name.clone(),
                    })
                    .collect(),
                confidence: confidence.into(),
                score,
                sev,
                title: format!("Эксплуатируемые CVE (KEV) для {}: {}", probe, refs.len()),
                reason,
            });
        }
    }
    out.sort_by(|a, b| {
        b.sev
            .rank()
            .cmp(&a.sev.rank())
            .then(b.total.cmp(&a.total))
            .then(a.subject.id.cmp(&b.subject.id))
            .then(a.product_key.cmp(&b.product_key))
    });
    out
}

/// Convenience: [`lookup`] over [`subjects_from`] with the embedded catalog.
pub fn match_analysis(a: &Analysis) -> Vec<KevMatch> {
    lookup(KevCatalog::builtin(), &subjects_from(a))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn subj(kind: SubjectKind, name: &str, eol: Option<&str>) -> KevSubject {
        KevSubject {
            kind,
            id: name.to_lowercase(),
            name: name.into(),
            ver: String::new(),
            eol: eol.is_some(),
            eol_date: eol.map(str::to_string),
            docs: 1,
            context: String::new(),
        }
    }

    #[test]
    fn builtin_snapshot_is_small_and_consistent() {
        assert!(KEV_GZ.len() < 200 * 1024);
        let c = KevCatalog::builtin();
        assert!(!c.version.is_empty() && c.released.len() == 10);
        assert!(c.entries.len() > 100 && c.entries.len() <= c.total);
        let keys: std::collections::BTreeSet<&str> =
            c.products.iter().map(|p| p.key.as_str()).collect();
        for e in &c.entries {
            assert!(e.cve.starts_with("CVE-"), "{}", e.cve);
            assert_eq!(e.date_added.len(), 10);
            for k in &e.keys {
                assert!(keys.contains(k.as_str()), "unknown key {k}");
            }
        }
        // Every product group has records (stale mappings are removed from the TOML).
        for k in &keys {
            assert!(c.for_key(k).next().is_some(), "no KEV records for {k}");
        }
    }

    #[test]
    fn product_names_map_to_groups() {
        let c = KevCatalog::builtin();
        let keys =
            |n: &str| -> Vec<String> { c.products_for(n).iter().map(|p| p.key.clone()).collect() };
        assert_eq!(keys("Microsoft Office Word 2007"), vec!["ms_office"]);
        assert_eq!(keys("Microsoft Excel для Microsoft 365"), vec!["ms_office"]);
        assert_eq!(keys("Windows 7"), vec!["ms_windows"]);
        assert_eq!(keys("Acrobat Distiller 9.0"), vec!["adobe_acrobat"]);
        assert_eq!(keys("Apache HTTP Server"), vec!["apache_httpd"]);
        assert_eq!(keys("Apache Tomcat"), vec!["apache_tomcat"]);
        assert_eq!(keys("Microsoft IIS"), vec!["ms_iis"]);
        assert_eq!(keys("Outlook Web App"), vec!["ms_exchange"]);
        assert!(keys("LibreOffice 7.2").is_empty());
        assert!(keys("Nginx").is_empty());
        assert!(keys("Adobe Photoshop CC").is_empty());
    }

    #[test]
    fn eol_strengthens_but_never_claims() {
        let c = KevCatalog::builtin();
        let m = lookup(
            c,
            &[
                subj(
                    SubjectKind::Software,
                    "Microsoft Office Word 2010",
                    Some("2020-10-13"),
                ),
                subj(SubjectKind::Tech, "WordPress", None),
            ],
        );
        let word = m.iter().find(|x| x.product_key == "ms_office").unwrap();
        assert_eq!(word.confidence, "likely");
        assert!(matches!(word.sev, Severity::High | Severity::Medium));
        assert!(word.after_eol > 0 && word.total >= word.after_eol);
        assert!(word.reason.contains("сверьте версию"));
        let wp = m.iter().find(|x| x.product_key == "wordpress").unwrap();
        assert_eq!(
            (wp.confidence.as_str(), wp.sev),
            ("possible", Severity::Low)
        );
        assert!(wp.cves.len() as u32 == wp.total.min(25));
    }

    #[test]
    fn semver_range_confirms_vulnerable_and_suppresses_patched_versions() {
        let c = KevCatalog::builtin();
        let m = lookup(
            c,
            &[
                subj(SubjectKind::Tech, "Apache HTTP Server 2.4.49", None),
                subj(SubjectKind::Tech, "Apache HTTP Server 2.4.62", None),
                subj(SubjectKind::Tech, "Apache Tomcat 9.0.30", None),
                subj(SubjectKind::Tech, "Apache Tomcat 10.1.35", None),
            ],
        );
        // Patched 2.4.62 and 10.1.35 must produce zero false-positive KEV matches.
        assert_eq!(m.len(), 2);
        let httpd = m.iter().find(|x| x.product_key == "apache_httpd").unwrap();
        assert_eq!(httpd.subject.name, "Apache HTTP Server 2.4.49");
        assert_eq!(httpd.confidence, "likely");
        assert_eq!(httpd.sev, Severity::High);
        assert!(httpd.reason.contains("CVE-2021-41773"));

        let tomcat = m.iter().find(|x| x.product_key == "apache_tomcat").unwrap();
        assert_eq!(tomcat.subject.name, "Apache Tomcat 9.0.30");
        assert_eq!(tomcat.confidence, "likely");
        assert_eq!(tomcat.sev, Severity::High);
        assert!(tomcat.reason.contains("CVE-2020-1938"));
    }

    #[test]
    fn ubuntu_linux_php_and_apache2458_accuracy() {
        let c = KevCatalog::builtin();
        // Ubuntu Linux must not match linux_kernel.
        assert!(c.products_for("Ubuntu Linux").is_empty());
        // Apache 2.4.58 must only list CVE-2024-38475, never CVE-2021-41773 (2.4.49-2.4.50).
        let m_ap = lookup(
            c,
            &[subj(SubjectKind::Tech, "Apache HTTP Server 2.4.58", None)],
        );
        assert_eq!(m_ap.len(), 1);
        assert!(m_ap[0].cves.iter().all(|r| r.cve != "CVE-2021-41773"));
        assert!(!m_ap[0].reason.contains("KEV не указывает уязвимые версии"));

        // PHP 8.1.2 on Ubuntu host must not be flagged High for Windows-only CVE-2024-4577.
        let mut php_ub = subj(SubjectKind::Tech, "PHP 8.1.2", None);
        php_ub.context = "Apache HTTP Server 2.4.52, Ubuntu Linux, PHP 8.1.2".into();
        let m_php = lookup(c, &[php_ub]);
        assert!(m_php.is_empty(), "{m_php:?}");

        // with_additions appends bundle KEV items.
        let c2 = c.with_additions(vec![KevEntry {
            cve: "CVE-2099-99999".into(),
            keys: vec!["nginx".into()],
            vendor: "F5".into(),
            product: "NGINX".into(),
            date_added: "2099-01-01".into(),
            ransomware: true,
            name: "Synthetic Test KEV".into(),
        }]);
        assert!(c2.for_key("nginx").any(|e| e.cve == "CVE-2099-99999"));
    }
}
