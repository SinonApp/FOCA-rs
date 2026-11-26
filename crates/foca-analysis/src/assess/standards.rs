//! Finding rule → security standards mapping (`signatures/standards.toml`): MITRE ATT&CK v20,
//! CWE (with the 2025 Top 25 flag), OWASP Top 10:2025, OWASP WSTG v4.2, ISO/IEC 27001:2022
//! Annex A, NIST SP 800-53 Rev. 5 / НД ТЗІ 3.6-006-24 measures, personal data law articles
//! (GDPR, Law of Ukraine No. 2297-VI) and the legacy НД ТЗІ 2.5-004-99 functional services and
//! НД ТЗІ 3.7-003-05 КСЗІ stages.
//!
//! Every field is optional; the file lists only correspondences that hold without a stretch.
//! The mapping is a guide for the auditor, not a conclusion of a КСЗІ expert examination (see
//! [`Standards::disclaimer`]).

use std::collections::BTreeMap;
use std::sync::OnceLock;

use serde::Deserialize;

/// The embedded mapping.
pub const STANDARDS_TOML: &str = include_str!("../../signatures/standards.toml");

/// ATT&CK release the technique ids were checked against (ATT&CK-v20.0 STIX bundle).
pub const ATTACK_VERSION: &str = "ATT&CK v20";

/// OWASP Top 10 edition of the `owasp` ids.
pub const OWASP_TOP10: &str = "OWASP Top 10:2025";

/// NIST SP 800-53 release of the `nist` ids.
pub const NIST_800_53: &str = "NIST SP 800-53 Rev. 5";

/// Ukrainian catalogue that reuses the NIST SP 800-53 measure codes.
pub const NDTZI_3_6_006: &str = "НД ТЗІ 3.6-006-24";

/// ISO/IEC 27001 edition and its Ukrainian adoption.
pub const ISO_27001: &str = "ISO/IEC 27001:2022 (ДСТУ ISO/IEC 27001:2023)";

/// The 2025 CWE Top 25 Most Dangerous Software Weaknesses (cwe.mitre.org/top25), in rank order.
pub const CWE_TOP25_2025: [&str; 25] = [
    "CWE-79", "CWE-89", "CWE-352", "CWE-862", "CWE-787", "CWE-22", "CWE-416", "CWE-125", "CWE-78",
    "CWE-94", "CWE-120", "CWE-434", "CWE-476", "CWE-121", "CWE-502", "CWE-122", "CWE-863",
    "CWE-20", "CWE-284", "CWE-200", "CWE-306", "CWE-918", "CWE-77", "CWE-639", "CWE-770",
];

/// Note shown next to НД ТЗІ 2.5-004-99 and НД ТЗІ 3.7-003-05: they apply to systems certified
/// under the КСЗІ scheme, new systems follow the security profiles (НД ТЗІ 3.6-006-24).
pub fn legacy_note(lang: &str) -> &'static str {
    match lang {
        "uk" => "для систем, атестованих за КСЗІ",
        "ru" => "для систем, аттестованных по КСЗИ",
        _ => "for systems certified under КСЗІ",
    }
}

/// True if the CWE id is in the 2025 CWE Top 25.
pub fn is_cwe_top25(cwe: &str) -> bool {
    CWE_TOP25_2025.contains(&cwe)
}

/// Standards of one finding rule.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RuleStandards {
    /// Finding rule (`provenance.rule`).
    pub id: String,
    /// MITRE ATT&CK technique ids (`T1213`, `T1590.005`).
    pub mitre: Vec<String>,
    /// CWE ids (`CWE-212`).
    pub cwe: Vec<String>,
    /// OWASP Top 10:2025 categories (`A01:2025`).
    pub owasp: Vec<String>,
    /// OWASP WSTG v4.2 test ids (`WSTG-INFO-01`).
    pub wstg: Vec<String>,
    /// ISO/IEC 27001:2022 Annex A controls (`8.12`).
    pub iso27001: Vec<String>,
    /// NIST SP 800-53 Rev. 5 controls (`SC-8`, `IA-5(7)`), same codes in НД ТЗІ 3.6-006-24.
    pub nist: Vec<String>,
    /// Personal data law articles (keys of [`Standards::privacy`]).
    pub privacy: Vec<String>,
    /// НД ТЗІ 2.5-004-99 functional service codes (`КВ`, `НИ`).
    pub ndtzi: Vec<String>,
    /// НД ТЗІ 3.7-003-05 clauses (`6.1.2.5`).
    pub kszi: Vec<String>,
}

impl RuleStandards {
    /// True if no standard is mapped.
    pub fn is_empty(&self) -> bool {
        self.mitre.is_empty()
            && self.cwe.is_empty()
            && self.owasp.is_empty()
            && self.wstg.is_empty()
            && self.iso27001.is_empty()
            && self.nist.is_empty()
            && self.privacy.is_empty()
            && self.ndtzi.is_empty()
            && self.kszi.is_empty()
    }
}

/// A text in the three report languages.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Tri {
    pub uk: String,
    pub ru: String,
    pub en: String,
}

impl Tri {
    /// Text for a language code (`uk`, `ru`, anything else → English).
    pub fn get(&self, lang: &str) -> &str {
        match lang {
            "uk" => &self.uk,
            "ru" => &self.ru,
            _ => &self.en,
        }
    }
}

/// Personal data law article.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PrivacyRef {
    /// Short label for chips and tables (`GDPR Art. 32`).
    pub code: String,
    pub uk: String,
    pub ru: String,
    pub en: String,
}

impl PrivacyRef {
    pub fn title(&self, lang: &str) -> &str {
        match lang {
            "uk" => &self.uk,
            "ru" => &self.ru,
            _ => &self.en,
        }
    }
}

/// НД ТЗІ 2.5-004-99 functional service.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct NdTziService {
    /// Clause of the document that defines the service (`6.5`).
    pub clause: String,
    pub uk: String,
    pub ru: String,
    pub en: String,
}

impl NdTziService {
    pub fn name(&self, lang: &str) -> &str {
        match lang {
            "uk" => &self.uk,
            "ru" => &self.ru,
            _ => &self.en,
        }
    }
}

/// The whole mapping.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Standards {
    /// Auditor disclaimer.
    pub disclaimer: Tri,
    /// ISO/IEC 27001:2022 Annex A control → title (English, as in the standard).
    pub iso27001: BTreeMap<String, String>,
    /// NIST SP 800-53 control → title (en from NIST, uk from НД ТЗІ 3.6-006-24).
    pub nist: BTreeMap<String, Tri>,
    /// Personal data law article key → short code and title.
    pub privacy: BTreeMap<String, PrivacyRef>,
    /// НД ТЗІ 2.5-004-99 service code → description.
    pub ndtzi: BTreeMap<String, NdTziService>,
    /// НД ТЗІ 3.7-003-05 clause → title.
    pub kszi: BTreeMap<String, Tri>,
    #[serde(rename = "rule")]
    pub rules: Vec<RuleStandards>,
}

impl Standards {
    /// Parses a mapping file.
    pub fn parse(s: &str) -> Result<Standards, toml::de::Error> {
        toml::from_str(s)
    }

    /// The embedded mapping.
    pub fn builtin() -> &'static Standards {
        static S: OnceLock<Standards> = OnceLock::new();
        S.get_or_init(|| {
            Standards::parse(STANDARDS_TOML).expect("embedded standards.toml is valid")
        })
    }

    /// Standards of a finding rule, if mapped.
    pub fn for_rule(&self, rule: &str) -> Option<&RuleStandards> {
        self.rules.iter().find(|r| r.id == rule)
    }

    /// Checks the format of every id and that every referenced ISO control, НД ТЗІ service and
    /// КСЗІ clause is described. Returns the problems found (empty when valid).
    pub fn validate(&self) -> Vec<String> {
        let mut errs = Vec::new();
        let mut seen = std::collections::BTreeSet::new();
        for r in &self.rules {
            if !seen.insert(r.id.as_str()) {
                errs.push(format!("duplicate rule {}", r.id));
            }
            if r.is_empty() {
                errs.push(format!("{}: no standards", r.id));
            }
            let mut check = |field: &str, v: &[String], ok: &dyn Fn(&str) -> bool| {
                let mut s = std::collections::BTreeSet::new();
                for x in v {
                    if !ok(x) {
                        errs.push(format!("{}: invalid {field} id {x}", r.id));
                    }
                    if !s.insert(x) {
                        errs.push(format!("{}: duplicate {field} id {x}", r.id));
                    }
                }
            };
            check("mitre", &r.mitre, &is_mitre);
            check("cwe", &r.cwe, &is_cwe);
            check("owasp", &r.owasp, &is_owasp);
            check("wstg", &r.wstg, &is_wstg);
            check("iso27001", &r.iso27001, &|x| {
                is_iso(x) && self.iso27001.contains_key(x)
            });
            check("nist", &r.nist, &|x| {
                is_nist(x) && self.nist.contains_key(x)
            });
            check("privacy", &r.privacy, &|x| self.privacy.contains_key(x));
            check("ndtzi", &r.ndtzi, &|x| self.ndtzi.contains_key(x));
            check("kszi", &r.kszi, &|x| self.kszi.contains_key(x));
        }
        for k in self.iso27001.keys() {
            if !is_iso(k) {
                errs.push(format!("invalid ISO control {k}"));
            }
        }
        for (k, v) in &self.nist {
            if !is_nist(k) || v.uk.is_empty() || v.ru.is_empty() || v.en.is_empty() {
                errs.push(format!("invalid NIST control {k}"));
            }
        }
        for (k, v) in &self.privacy {
            if v.code.is_empty() || v.uk.is_empty() || v.ru.is_empty() || v.en.is_empty() {
                errs.push(format!("incomplete privacy reference {k}"));
            }
        }
        for (k, v) in &self.ndtzi {
            if !NDTZI_SERVICES.contains(&k.as_str()) || v.clause.is_empty() {
                errs.push(format!("unknown НД ТЗІ service {k}"));
            }
        }
        if self.disclaimer.uk.is_empty()
            || self.disclaimer.ru.is_empty()
            || self.disclaimer.en.is_empty()
        {
            errs.push("disclaimer must be set in uk, ru and en".into());
        }
        errs
    }
}

/// Service codes listed in section 4 of НД ТЗІ 2.5-004-99. The document prints "ДВ" for both
/// fault tolerance (8.2) and recovery (8.4); the fault-tolerance service is commonly written
/// "ДС", which is kept here as well.
pub const NDTZI_SERVICES: &[&str] = &[
    "КД", "КА", "КО", "КК", "КВ", "ЦД", "ЦА", "ЦО", "ЦВ", "ДР", "ДС", "ДЗ", "ДВ", "НР", "НИ", "НК",
    "НО", "НЦ", "НТ", "НВ", "НА", "НП",
];

fn digits(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())
}

/// `T1234` or `T1234.001`.
pub fn is_mitre(s: &str) -> bool {
    let Some(rest) = s.strip_prefix('T') else {
        return false;
    };
    match rest.split_once('.') {
        Some((t, sub)) => t.len() == 4 && digits(t) && sub.len() == 3 && digits(sub),
        None => rest.len() == 4 && digits(rest),
    }
}

/// `CWE-<n>`.
pub fn is_cwe(s: &str) -> bool {
    s.strip_prefix("CWE-")
        .is_some_and(|n| digits(n) && !n.starts_with('0'))
}

/// `A01:2025` … `A10:2025`.
pub fn is_owasp(s: &str) -> bool {
    s.strip_suffix(":2025")
        .and_then(|a| a.strip_prefix('A'))
        .and_then(|n| n.parse::<u8>().ok().filter(|_| n.len() == 2))
        .is_some_and(|n| (1..=10).contains(&n))
}

/// NIST SP 800-53 Rev. 5 control families (also the НД ТЗІ 3.6-006-24 classes).
pub const NIST_FAMILIES: &[&str] = &[
    "AC", "AT", "AU", "CA", "CM", "CP", "IA", "IR", "MA", "MP", "PE", "PL", "PM", "PS", "PT", "RA",
    "SA", "SC", "SI", "SR",
];

/// `AC-3` or a control enhancement `IA-5(7)`.
pub fn is_nist(s: &str) -> bool {
    let Some((fam, rest)) = s.split_once('-') else {
        return false;
    };
    if !NIST_FAMILIES.contains(&fam) {
        return false;
    }
    let (n, enh) = match rest.split_once('(') {
        Some((n, e)) => (n, Some(e)),
        None => (rest, None),
    };
    let num = |x: &str| digits(x) && !x.starts_with('0') && x.len() <= 2;
    num(n) && enh.is_none_or(|e| e.strip_suffix(')').is_some_and(num))
}

/// `WSTG-<CAT>-<nn>`.
pub fn is_wstg(s: &str) -> bool {
    let mut p = s.split('-');
    matches!(
        (p.next(), p.next(), p.next(), p.next()),
        (Some("WSTG"), Some(c), Some(n), None)
            if c.len() == 4 && c.bytes().all(|b| b.is_ascii_uppercase()) && n.len() == 2 && digits(n)
    )
}

/// ISO/IEC 27001:2022 Annex A control: 5.1-5.37, 6.1-6.8, 7.1-7.14, 8.1-8.34.
pub fn is_iso(s: &str) -> bool {
    let Some((a, b)) = s.split_once('.') else {
        return false;
    };
    let Ok(n) = b.parse::<u8>() else {
        return false;
    };
    if b.starts_with('0') {
        return false;
    }
    let max = match a {
        "5" => 37,
        "6" => 8,
        "7" => 14,
        "8" => 34,
        _ => return false,
    };
    (1..=max).contains(&n)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_is_valid() {
        let s = Standards::builtin();
        assert!(s.rules.len() > 40);
        let errs = s.validate();
        assert!(errs.is_empty(), "{errs:#?}");
    }

    #[test]
    fn id_formats() {
        assert!(is_mitre("T1213") && is_mitre("T1590.005"));
        assert!(!is_mitre("T12") && !is_mitre("T1590.5") && !is_mitre("1213"));
        assert!(is_cwe("CWE-22") && !is_cwe("CWE-") && !is_cwe("CWE-022") && !is_cwe("cwe-22"));
        assert!(is_owasp("A01:2025") && is_owasp("A10:2025"));
        assert!(!is_owasp("A11:2025") && !is_owasp("A1:2025") && !is_owasp("A01:2021"));
        assert!(is_nist("AC-3") && is_nist("IA-5(7)") && is_nist("SI-12(1)") && is_nist("SR-11"));
        assert!(!is_nist("AC-03") && !is_nist("XX-1") && !is_nist("IA-5(") && !is_nist("IA-5(7"));
        assert!(!is_nist("ac-3") && !is_nist("AC-") && !is_nist("AC-3()") && !is_nist("AC-3(01)"));
        assert!(is_cwe_top25("CWE-22") && is_cwe_top25("CWE-200") && !is_cwe_top25("CWE-497"));
        assert!(is_wstg("WSTG-INFO-01") && !is_wstg("WSTG-INFO-1") && !is_wstg("WSTG-info-01"));
        assert!(is_iso("5.37") && is_iso("8.34") && is_iso("7.14"));
        assert!(!is_iso("5.38") && !is_iso("6.9") && !is_iso("A.8.12") && !is_iso("8.01"));
    }

    /// OWASP Top 10:2025 lists the CWE ids mapped to each category; a rule may name a category
    /// only if one of its CWE ids is listed there (A03 also stands alone for vulnerable
    /// components). Subsets of the "List of Mapped CWEs" in github.com/OWASP/Top10 2025/docs/en.
    #[test]
    fn owasp_matches_cwe() {
        let listed: &[(&str, &[&str])] = &[
            (
                "A01:2025",
                &[
                    "CWE-22", "CWE-200", "CWE-359", "CWE-497", "CWE-538", "CWE-540", "CWE-548",
                    "CWE-749",
                ],
            ),
            ("A02:2025", &["CWE-614", "CWE-942", "CWE-1004"]),
            ("A03:2025", &["CWE-1104"]),
            ("A04:2025", &["CWE-319", "CWE-326", "CWE-327"]),
            ("A06:2025", &["CWE-256", "CWE-693", "CWE-1021"]),
            ("A07:2025", &["CWE-798"]),
        ];
        for r in &Standards::builtin().rules {
            for o in &r.owasp {
                let cwes = listed
                    .iter()
                    .find(|(k, _)| k == o)
                    .map(|(_, v)| *v)
                    .unwrap_or_else(|| panic!("{}: {o} is not expected", r.id));
                let ok = r.cwe.iter().any(|c| cwes.contains(&c.as_str()))
                    || (o == "A03:2025" && r.cwe.is_empty());
                assert!(ok, "{}: {o} without a matching CWE", r.id);
            }
        }
    }

    /// Technique ids present, not revoked and not deprecated in the ATT&CK-v20.0 Enterprise
    /// STIX bundle (github.com/mitre/cti, tag ATT&CK-v20.0).
    const ATTACK_V20: &[&str] = &[
        "T1059.005",
        "T1087",
        "T1135",
        "T1189",
        "T1190",
        "T1204.002",
        "T1213",
        "T1530",
        "T1539",
        "T1552.001",
        "T1557",
        "T1565.001",
        "T1566",
        "T1584",
        "T1589.001",
        "T1589.002",
        "T1589.003",
        "T1590",
        "T1590.002",
        "T1590.005",
        "T1591.001",
        "T1592",
        "T1592.001",
        "T1592.002",
        "T1594",
    ];

    #[test]
    fn mitre_ids_exist_in_attack_v20() {
        for r in &Standards::builtin().rules {
            for t in &r.mitre {
                assert!(
                    ATTACK_V20.contains(&t.as_str()),
                    "{}: {t} not checked against v20",
                    r.id
                );
            }
        }
    }

    /// Controls listed in the NIST SP 800-53 Rev. 5.2.0 OSCAL catalogue (not withdrawn) and in
    /// section 9 of НД ТЗІ 3.6-006-24 under the same code.
    #[test]
    fn nist_ids_exist_in_both_catalogues() {
        const CHECKED: &[&str] = &[
            "AC-3", "AC-4", "AC-22", "AT-2(3)", "CM-7", "IA-5(7)", "RA-5", "SA-22", "SC-7", "SC-8",
            "SC-12", "SC-13", "SC-17", "SC-18", "SC-23", "SI-2", "SI-10", "SI-12(1)",
        ];
        let s = Standards::builtin();
        for k in s.nist.keys() {
            assert!(
                CHECKED.contains(&k.as_str()),
                "{k} not checked against the catalogues"
            );
        }
    }

    /// WSTG v4.2 ids that exist in the stable release (github.com/OWASP/wstg, tag v4.2).
    #[test]
    fn wstg_ids_exist_in_v4_2() {
        let mut known: Vec<String> = Vec::new();
        known.extend((1..=10).map(|n| format!("WSTG-INFO-{n:02}")));
        known.extend((1..=11).map(|n| format!("WSTG-CONF-{n:02}")));
        known.extend((1..=4).map(|n| format!("WSTG-CRYP-{n:02}")));
        known.extend((1..=13).map(|n| format!("WSTG-CLNT-{n:02}")));
        known.extend((1..=9).map(|n| format!("WSTG-SESS-{n:02}")));
        for r in &Standards::builtin().rules {
            for w in &r.wstg {
                assert!(known.contains(w), "{}: {w} is not a WSTG v4.2 id", r.id);
            }
        }
    }

    #[test]
    fn duplicates_and_bad_ids_are_reported() {
        let s = Standards::parse(
            r#"
            [disclaimer]
            uk = "u"
            ru = "r"
            en = "e"
            [iso27001]
            "8.12" = "Data leakage prevention"
            [[rule]]
            id = "x"
            cwe = ["CWE-1", "CWE-1"]
            [[rule]]
            id = "x"
            iso27001 = ["8.13"]
            ndtzi = ["КЦ"]
            nist = ["SC-8", "AC-03"]
            privacy = ["gdpr-99"]
            "#,
        )
        .unwrap();
        let e = s.validate().join("\n");
        assert!(e.contains("duplicate rule x"), "{e}");
        assert!(e.contains("duplicate cwe id CWE-1"), "{e}");
        assert!(e.contains("invalid iso27001 id 8.13"), "{e}");
        assert!(e.contains("invalid ndtzi id КЦ"), "{e}");
        assert!(e.contains("invalid nist id SC-8"), "{e}");
        assert!(e.contains("invalid nist id AC-03"), "{e}");
        assert!(e.contains("invalid privacy id gdpr-99"), "{e}");
    }
}
