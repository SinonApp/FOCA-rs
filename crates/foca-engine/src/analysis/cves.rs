//! CVE findings from the offline NVD table ([`foca_analysis::cve`]).
//!
//! Rules (owner decisions):
//! * a CVE finding needs a known version; without one the product only gets an info line
//!   ("N known CVEs, version not determined") on an existing KEV/EOL finding and on its card;
//! * severity = highest CVSS band of the matched CVEs, one step higher when any is in CISA KEV;
//!   workstation software (document authors' desktops, OS from metadata) is reconnaissance and
//!   capped at medium;
//! * when a KEV or EOL finding already covers the subject, the CVE data is merged into it
//!   instead of a second finding.

use foca_analysis::cve::{self, CveMatch};
use foca_analysis::findings::finding_id;
use foca_analysis::insights::Insights;
use foca_analysis::kev::SubjectKind;
use foca_analysis::{Analysis, PrevState};
use foca_core::api::{self, CveSummary};
use foca_core::Severity;
use foca_store::ProjectDb;

use super::draft::{finding, restore_triage, RULE_CVE, RULE_KEV};

/// Project fact of the site recon (`scan::recon::K_RECON`), read here as JSON so the analysis
/// does not depend on the scan module.
pub(crate) const RECON_KEY: &str = "engine.recon";

/// Site technologies of every host in the recon facts as CVE subjects.
pub(crate) fn tech_inputs(db: &ProjectDb) -> Vec<cve::TechInput> {
    tech_inputs_of(&super::facts::get(db, RECON_KEY))
}

/// [`tech_inputs`] over the recon facts as JSON.
pub(crate) fn tech_inputs_of(rf: &serde_json::Value) -> Vec<cve::TechInput> {
    let mut out = Vec::new();
    for (host, site) in rf["sites"].as_object().into_iter().flatten() {
        for t in site["report"]["technologies"]
            .as_array()
            .into_iter()
            .flatten()
        {
            let s = |k: &str| t[k].as_str().map(str::to_string);
            out.push(cve::TechInput {
                host: host.clone(),
                name: s("name").unwrap_or_default(),
                version: s("version"),
                cpe: s("cpe"),
                slug: s("slug"),
                plugin_of: s("plugin_of"),
                evidence: t["evidence"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(|e| e.as_str().map(str::to_string))
                    .collect(),
            });
        }
    }
    out
}

/// Evidence rows shown before "… и ещё N".
const TOP: usize = 25;

fn kind_ord(k: SubjectKind) -> u8 {
    match k {
        SubjectKind::Tech => 1,
        _ => 0,
    }
}

/// Id of the KEV finding that covers the same subject, if `ins.kev` has one.
fn kev_target(ins: &Insights, m: &CveMatch) -> Option<u64> {
    let name = m.name.to_ascii_lowercase();
    ins.kev
        .iter()
        .find(|k| {
            k.subject.kind == m.kind
                && match m.kind {
                    SubjectKind::Tech => {
                        m.hosts.contains(&k.subject.id)
                            && k.subject.name.to_ascii_lowercase().contains(&name)
                    }
                    _ => k.subject.id == m.id,
                }
        })
        .map(|k| {
            let probe = if k.subject.ver.is_empty() {
                k.subject.name.clone()
            } else {
                format!("{} {}", k.subject.name, k.subject.ver)
            };
            let key = format!(
                "{}|{}|{}",
                k.product_key,
                probe.to_ascii_lowercase(),
                kind_ord(k.subject.kind)
            );
            finding_id(RULE_KEV, &key)
        })
}

/// Id of the EOL finding of a document software or OS subject.
fn eol_target(m: &CveMatch) -> Option<u64> {
    match m.kind {
        SubjectKind::Software => Some(finding_id("eol-software", &m.id)),
        SubjectKind::Os => Some(finding_id("eol-os", &m.id)),
        SubjectKind::Tech => None,
    }
}

fn source_label(s: &str) -> &'static str {
    match s {
        "header" => "заголовок HTTP",
        "js" => "скрипт",
        "plugin_path" => "путь плагина",
        "readme" => "readme плагина",
        "meta" => "метаданные документа",
        _ => "HTML",
    }
}

fn num(x: Option<f32>) -> String {
    x.map_or_else(|| "-".into(), |v| format!("{v}"))
}

/// Description lines (Russian, translated by the report catalog).
fn lines(m: &CveMatch, s: &CveSummary) -> Vec<String> {
    let mut d = Vec::new();
    match (m.kind, m.side.as_str()) {
        (SubjectKind::Tech, _) => {
            d.push(format!(
                "Технология обнаружена на сайте организации: {}.",
                m.hosts.join(", ")
            ));
            if let Some(cms) = &m.plugin_of {
                d.push(format!("Это расширение {cms}."));
            }
        }
        (_, "server") => d.push(
            "Файлы на сайте созданы серверным генератором: уязвимости относятся к серверу, который выпускает документы."
                .into(),
        ),
        _ => d.push(
            "ПО найдено в метаданных документов: оно стоит на рабочих станциях авторов. Это разведданные (устаревшее ПО, вектор фишинга с вредоносными вложениями), а не уязвимость сайта."
                .into(),
        ),
    }
    d.push(format!(
        "Версия {} (источник: {}).",
        s.version,
        source_label(&s.source)
    ));
    d.push(format!(
        "Известных CVE для этой версии в базе NVD: {}. Критических: {}, высоких: {}, средних: {}, низких: {}; CVSS до {}.",
        s.matched,
        s.critical,
        s.high,
        s.medium,
        s.low,
        num(s.max_cvss)
    ));
    if s.kev > 0 {
        d.push(format!("Из них эксплуатируются (CISA KEV): {}.", s.kev));
    }
    if let Some(e) = s.max_epss {
        d.push(format!(
            "Наибольшая вероятность эксплуатации по EPSS: {e:.2}."
        ));
    }
    if let Some(date) = &m.last_doc {
        d.push(format!("Последний документ с этой версией: {date}."));
    }
    d
}

/// Evidence: product, version and the top CVEs (`CVE-… CVSS 9.8 KEV EPSS 0.95`).
fn evidence(m: &CveMatch, s: &CveSummary) -> String {
    let mut ev = vec![format!("NVD: {} {}", s.product, s.version)];
    for c in s.cves.iter().take(TOP) {
        let mut l = c.id.clone();
        if let Some(v) = c.cvss {
            l.push_str(&format!(" CVSS {v}"));
        }
        if c.kev {
            l.push_str(" KEV");
        }
        if let Some(e) = c.epss {
            l.push_str(&format!(" EPSS {e:.2}"));
        }
        ev.push(l);
    }
    if s.cves.len() > TOP {
        ev.push(format!("… и ещё {}", s.cves.len() - TOP));
    }
    if m.kind == SubjectKind::Tech && m.hosts.len() > 1 {
        ev.push(format!("Хосты: {}", m.hosts.join(", ")));
    }
    ev.join("\n")
}

fn cap(m: &CveMatch) -> Option<Severity> {
    m.is_workstation().then_some(Severity::Medium)
}

fn merge_into(f: &mut api::Finding, m: &CveMatch, s: &CveSummary) {
    let sev = cve::finding_severity(s, cap(m));
    if sev.rank() > f.sev.rank() {
        f.sev = sev;
    }
    f.description.push('\n');
    f.description.push_str(&lines(m, s).join("\n"));
    f.evidence.push('\n');
    f.evidence.push_str(&evidence(m, s));
    for c in s.cves.iter().take(TOP) {
        if !f.cve.contains(&c.id) {
            f.cve.push(c.id.clone());
        }
    }
    f.cvss = match (f.cvss, s.max_cvss) {
        (Some(a), Some(b)) => Some(a.max(b)),
        (a, b) => a.or(b),
    };
    for t in ["nvd", side_tag(m)] {
        if !f.tags.iter().any(|x| x == t) {
            f.tags.push(t.into());
        }
    }
}

fn side_tag(m: &CveMatch) -> &'static str {
    match (m.kind, m.side.as_str()) {
        (SubjectKind::Tech, _) => "site",
        (_, "server") => "server",
        _ => "workstation",
    }
}

fn new_finding(m: &CveMatch, s: &CveSummary, now: &str, scan: Option<&str>) -> api::Finding {
    let title = match side_tag(m) {
        "workstation" => format!(
            "Устаревшее ПО на рабочих станциях (NVD): {}, известных CVE: {}",
            m.probe, s.matched
        ),
        "server" => format!(
            "Уязвимый генератор документов на сервере (NVD): {}, известных CVE: {}",
            m.probe, s.matched
        ),
        _ => format!(
            "Уязвимая версия технологии (NVD): {}, известных CVE: {}",
            m.probe, s.matched
        ),
    };
    let rec = if m.is_workstation() {
        "Обновить ПО на рабочих станциях и включить централизованное обновление; учитывать при оценке фишинговых рисков."
    } else {
        "Обновить продукт до версии без известных уязвимостей; сверить список CVE с бюллетенями производителя."
    };
    let key = format!(
        "{}|{}|{}",
        s.product,
        s.version.to_ascii_lowercase(),
        kind_ord(m.kind)
    );
    let docs: Vec<u64> = m.docs.iter().copied().take(50).collect();
    let mut f = finding(
        RULE_CVE,
        &key,
        title,
        cve::finding_severity(s, cap(m)),
        "software",
        if m.kind == SubjectKind::Tech {
            "T1190"
        } else {
            "T1203"
        },
        lines(m, s).join("\n"),
        rec,
        evidence(m, s),
        docs,
        now,
        scan,
    );
    f.host = match m.hosts.as_slice() {
        [] => "-".into(),
        [h] => h.clone(),
        [h, rest @ ..] => format!("{h} (+{})", rest.len()),
    };
    f.source = "NVD".into();
    f.cve = s.cves.iter().take(TOP).map(|c| c.id.clone()).collect();
    f.cvss = s.max_cvss;
    f.tags = vec!["nvd".into(), side_tag(m).into()];
    f
}

/// Adds the CVE findings (or merges them into KEV/EOL findings) and fills the per-entry CVE
/// summaries of the software and OS cards. Runs after the insight findings are in `a`.
pub fn apply(a: &mut Analysis, ins: &Insights, prev: &PrevState, now: &str) {
    cve::annotate(a, &cve::db());
    for m in &ins.cve {
        let s = &m.summary;
        let target = kev_target(ins, m)
            .into_iter()
            .chain(eol_target(m))
            .find(|id| a.findings.iter().any(|f| f.id == *id));
        if !s.version_known || s.matched == 0 {
            if let (false, Some(id)) = (s.version_known, target) {
                if let Some(f) = a.findings.iter_mut().find(|f| f.id == id) {
                    let line = format!(
                        "Известных CVE для продукта в базе NVD: {}, версия не определена.",
                        s.known
                    );
                    if s.known > 0 && !f.description.contains(&line) {
                        f.description.push('\n');
                        f.description.push_str(&line);
                    }
                }
            }
            continue;
        }
        if let Some(f) = target.and_then(|id| a.findings.iter_mut().find(|f| f.id == id)) {
            merge_into(f, m, s);
            continue;
        }
        let mut f = new_finding(m, s, now, prev.scan_id.as_deref());
        restore_triage(&mut f, prev);
        a.resolved.retain(|id| *id != f.id);
        if !a.findings.iter().any(|x| x.id == f.id) {
            a.findings.push(f);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use foca_analysis::kev::{self, KevSubject};
    use foca_core::api::CveRef;

    const NOW: &str = "2026-11-27T00:00:00Z";

    fn summary(version: &str, max: f32, kev: u32) -> CveSummary {
        CveSummary {
            product: "vendor_x:product_x".into(),
            version: version.into(),
            version_known: !version.is_empty(),
            source: "meta".into(),
            known: 12,
            matched: if version.is_empty() { 0 } else { 2 },
            critical: u32::from(max >= 9.0),
            high: u32::from((7.0..9.0).contains(&max)),
            max_cvss: (!version.is_empty()).then_some(max),
            kev,
            cves: if version.is_empty() {
                vec![]
            } else {
                vec![
                    CveRef {
                        id: "CVE-2099-0001".into(),
                        cvss: Some(max),
                        kev: kev > 0,
                        epss: Some(0.5),
                    },
                    CveRef {
                        id: "CVE-2099-0002".into(),
                        cvss: Some(4.0),
                        kev: false,
                        epss: None,
                    },
                ]
            },
            ..Default::default()
        }
    }

    fn m(kind: SubjectKind, id: &str, name: &str, side: &str, s: CveSummary) -> CveMatch {
        CveMatch {
            kind,
            id: id.into(),
            probe: format!("{name} {}", s.version).trim().to_string(),
            name: name.into(),
            ver: s.version.clone(),
            side: side.into(),
            last_doc: (kind != SubjectKind::Tech).then(|| "2026-05-01".to_string()),
            docs: vec![7],
            hosts: if kind == SubjectKind::Tech {
                vec!["www.example.com".into()]
            } else {
                vec![]
            },
            plugin_of: None,
            summary: s,
        }
    }

    fn run(a: &mut Analysis, ins: &Insights) -> Vec<api::Finding> {
        apply(a, ins, &PrevState::default(), NOW);
        a.findings.clone()
    }

    fn cve_findings(f: &[api::Finding]) -> Vec<&api::Finding> {
        f.iter().filter(|f| f.provenance.rule == RULE_CVE).collect()
    }

    #[test]
    fn server_and_workstation_software_differ() {
        let mut a = Analysis::default();
        let ins = Insights {
            cve: vec![
                m(
                    SubjectKind::Software,
                    "tcpdf",
                    "TCPDF",
                    "server",
                    summary("6.2.13", 9.8, 0),
                ),
                m(
                    SubjectKind::Software,
                    "lo75",
                    "LibreOffice",
                    "workstation",
                    summary("7.5.1", 9.8, 0),
                ),
            ],
            ..Default::default()
        };
        let f = run(&mut a, &ins);
        let c = cve_findings(&f);
        assert_eq!(c.len(), 2);
        let srv = c.iter().find(|f| f.title.contains("TCPDF")).unwrap();
        assert_eq!(srv.sev, Severity::Critical);
        assert!(srv
            .title
            .starts_with("Уязвимый генератор документов на сервере (NVD)"));
        assert!(srv.tags.contains(&"server".to_string()));
        assert_eq!(srv.cvss, Some(9.8));
        assert!(srv.evidence.contains("CVE-2099-0001 CVSS 9.8 EPSS 0.50"));
        let ws = c.iter().find(|f| f.title.contains("LibreOffice")).unwrap();
        assert_eq!(ws.sev, Severity::Medium, "workstation cap");
        assert!(ws
            .title
            .starts_with("Устаревшее ПО на рабочих станциях (NVD)"));
        assert!(ws.description.contains("а не уязвимость сайта"));
        assert!(ws
            .description
            .contains("Последний документ с этой версией: 2026-05-01."));
        assert_eq!(ws.rel.docs, vec![7]);
    }

    #[test]
    fn kev_raises_and_unversioned_products_get_no_finding() {
        let mut a = Analysis::default();
        let ins = Insights {
            cve: vec![
                m(
                    SubjectKind::Tech,
                    "www.example.com",
                    "Nginx",
                    "site",
                    summary("1.18.0", 7.5, 1),
                ),
                m(
                    SubjectKind::Tech,
                    "www.example.com",
                    "Jetty",
                    "site",
                    summary("", 0.0, 0),
                ),
            ],
            ..Default::default()
        };
        let f = run(&mut a, &ins);
        let c = cve_findings(&f);
        assert_eq!(c.len(), 1, "no finding without a version");
        assert_eq!(c[0].sev, Severity::Critical, "high raised by KEV");
        assert_eq!(c[0].host, "www.example.com");
        assert!(c[0].description.contains("эксплуатируются (CISA KEV): 1."));
        assert!(c[0]
            .description
            .contains("Версия 1.18.0 (источник: метаданные документа)."));
    }

    #[test]
    fn merges_into_eol_and_kev_findings() {
        // EOL finding of a server generator: CVE data merged, severity raised, no new finding.
        let mut a = Analysis::default();
        let mut eol = finding(
            "eol-software",
            "itext2",
            "iText 2 (EOL)".into(),
            Severity::Medium,
            "sw",
            "",
            "EOL".into(),
            "",
            "".into(),
            vec![7],
            NOW,
            None,
        );
        eol.id = finding_id("eol-software", "itext2");
        a.findings.push(eol);
        let ins = Insights {
            cve: vec![
                m(
                    SubjectKind::Software,
                    "itext2",
                    "iText",
                    "server",
                    summary("2.1.7", 7.5, 0),
                ),
                m(
                    SubjectKind::Os,
                    "win7",
                    "Windows 7",
                    "workstation",
                    summary("", 0.0, 0),
                ),
            ],
            ..Default::default()
        };
        a.findings.push({
            let mut f = finding(
                "eol-os",
                "win7",
                "Windows 7".into(),
                Severity::Medium,
                "sw",
                "",
                "OS".into(),
                "",
                "".into(),
                vec![],
                NOW,
                None,
            );
            f.id = finding_id("eol-os", "win7");
            f
        });
        let f = run(&mut a, &ins);
        assert!(cve_findings(&f).is_empty());
        let e = f
            .iter()
            .find(|x| x.id == finding_id("eol-software", "itext2"))
            .unwrap();
        assert_eq!(e.sev, Severity::High);
        assert!(e.cve.contains(&"CVE-2099-0001".to_string()));
        assert!(e.tags.contains(&"nvd".to_string()));
        let os = f
            .iter()
            .find(|x| x.id == finding_id("eol-os", "win7"))
            .unwrap();
        assert!(os
            .description
            .contains("Известных CVE для продукта в базе NVD: 12, версия не определена."));
        assert_eq!(os.sev, Severity::Medium);

        // KEV finding of the same document software.
        let subj = KevSubject {
            kind: SubjectKind::Software,
            id: "word2010".into(),
            name: "Microsoft Office Word 2010".into(),
            ver: String::new(),
            eol: true,
            eol_date: Some("2020-10-13".into()),
            docs: 1,
            context: String::new(),
        };
        let kev_m = kev::lookup(kev::KevCatalog::builtin(), &[subj]);
        assert!(!kev_m.is_empty());
        let mut a = Analysis::default();
        let ins = Insights {
            kev: kev_m,
            cve: vec![m(
                SubjectKind::Software,
                "word2010",
                "Microsoft Office Word 2010",
                "workstation",
                summary("2010", 9.8, 1),
            )],
            ..Default::default()
        };
        a.findings = crate::analysis::insights::findings(&a, &ins, NOW, None);
        let n_before = a.findings.len();
        let f = run(&mut a, &ins);
        assert_eq!(f.len(), n_before, "merged, not duplicated");
        let k = f.iter().find(|x| x.provenance.rule == RULE_KEV).unwrap();
        assert!(k
            .description
            .contains("Известных CVE для этой версии в базе NVD: 2."));
        assert!(k.tags.contains(&"workstation".to_string()));
    }
}
