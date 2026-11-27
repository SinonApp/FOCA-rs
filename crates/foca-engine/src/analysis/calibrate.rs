//! Severity calibration once every analysis finding exists (beta.4.1 owner decisions):
//!
//! * Microsoft Office from document metadata: one "outdated office software" finding that lists
//!   the versions with document counts and last-seen dates, the CVE summary per edition (no
//!   double counting across Word, Excel, ...) and KEV, capped at medium;
//! * other document software and OS: one finding per product, KEV, end of life and CVE data
//!   merged, capped at medium (reconnaissance about workstations, not a site vulnerability);
//! * server-side generators: high only when their documents came from hosts in the scope;
//! * out-of-scope context: info, tagged `context`;
//! * a capped finding's CVSS follows its severity band; the project risk is recomputed.

use std::collections::BTreeSet;

use foca_analysis::cve::{self, CveMatch, CveQuery};
use foca_analysis::findings::{band_cvss, cvss_band, finding_id, OUT_OF_SCOPE_TAG};
use foca_analysis::insights::Insights;
use foca_analysis::kev::{KevMatch, SubjectKind};
use foca_analysis::{Analysis, PrevState};
use foca_core::api;
use foca_core::Severity;

use super::draft::{finding, restore_triage, RULE_CVE, RULE_KEV};

/// One finding for every outdated Microsoft Office version seen in documents.
pub const RULE_OFFICE: &str = "sw.office_outdated";
/// Tag of findings shown as environment context (outside the scope).
pub const CONTEXT_TAG: &str = "context";

fn kind_ord(k: SubjectKind) -> u8 {
    match k {
        SubjectKind::Tech => 1,
        _ => 0,
    }
}

/// Id of the KEV finding of a match (same key as `insights::findings`).
pub(crate) fn kev_id(k: &KevMatch) -> u64 {
    let probe = if k.subject.ver.is_empty() {
        k.subject.name.clone()
    } else {
        format!("{} {}", k.subject.name, k.subject.ver)
    };
    finding_id(
        RULE_KEV,
        &format!(
            "{}|{}|{}",
            k.product_key,
            probe.to_ascii_lowercase(),
            kind_ord(k.subject.kind)
        ),
    )
}

/// Id of the stand-alone CVE finding of a match (same key as `cves::new_finding`).
pub(crate) fn cve_id(m: &CveMatch) -> u64 {
    let s = &m.summary;
    finding_id(
        RULE_CVE,
        &format!(
            "{}|{}|{}",
            s.product,
            s.version.to_ascii_lowercase(),
            kind_ord(m.kind)
        ),
    )
}

fn eol_id(kind: SubjectKind, id: &str) -> Option<u64> {
    match kind {
        SubjectKind::Software => Some(finding_id("eol-software", id)),
        SubjectKind::Os => Some(finding_id("eol-os", id)),
        SubjectKind::Tech => None,
    }
}

/// Removes a finding that another one absorbed: the store deletes its row instead of marking
/// it fixed.
fn take(a: &mut Analysis, prev: &PrevState, id: u64) -> Option<api::Finding> {
    let i = a.findings.iter().position(|f| f.id == id)?;
    let f = a.findings.remove(i);
    a.resolved.retain(|x| *x != id);
    if prev.findings.contains_key(&id) && !a.dropped.contains(&id) {
        a.dropped.push(id);
    }
    Some(f)
}

fn push_lines(into: &mut String, from: &str) {
    for l in from.lines().filter(|l| !l.trim().is_empty()) {
        if !into.lines().any(|x| x == l) {
            if !into.is_empty() {
                into.push('\n');
            }
            into.push_str(l);
        }
    }
}

fn absorb(into: &mut api::Finding, from: &api::Finding) {
    if from.sev.rank() > into.sev.rank() {
        into.sev = from.sev;
    }
    push_lines(&mut into.description, &from.description);
    push_lines(&mut into.evidence, &from.evidence);
    for d in &from.rel.docs {
        if !into.rel.docs.contains(d) && into.rel.docs.len() < 50 {
            into.rel.docs.push(*d);
        }
    }
    for d in &from.provenance.docs {
        if !into.provenance.docs.contains(d) && into.provenance.docs.len() < 50 {
            into.provenance.docs.push(*d);
        }
    }
    for c in &from.cve {
        if !into.cve.contains(c) && into.cve.len() < 25 {
            into.cve.push(c.clone());
        }
    }
    into.cvss = match (into.cvss, from.cvss) {
        (Some(x), Some(y)) => Some(x.max(y)),
        (x, y) => x.or(y),
    };
    for t in &from.tags {
        if !into.tags.contains(t) {
            into.tags.push(t.clone());
        }
    }
}

fn cap(f: &mut api::Finding, max: Severity) {
    if f.sev.rank() > max.rank() {
        f.sev = max;
    }
}

fn year(d: Option<&str>) -> Option<u16> {
    d.and_then(|d| d.get(..4)).and_then(|y| y.parse().ok())
}

/// Office software ids from document metadata.
fn office_ids(a: &Analysis) -> BTreeSet<String> {
    a.software
        .iter()
        .filter(|s| s.kind == "office" && s.cpe.iter().any(|c| c == "microsoft:office"))
        .map(|s| s.id.clone())
        .collect()
}

fn merge_office(a: &mut Analysis, ins: &Insights, prev: &PrevState, now: &str) {
    let ids = office_ids(a);
    if ids.is_empty() {
        return;
    }
    let mut comp: Vec<u64> = Vec::new();
    let mut listed: BTreeSet<String> = BTreeSet::new();
    let mut add = |id: Option<u64>, sid: &str, comp: &mut Vec<u64>| {
        if let Some(id) = id {
            if a.findings.iter().any(|f| f.id == id) && !comp.contains(&id) {
                comp.push(id);
                listed.insert(sid.to_string());
            }
        }
    };
    for s in a.software.iter().filter(|s| ids.contains(&s.id)) {
        add(eol_id(SubjectKind::Software, &s.id), &s.id, &mut comp);
    }
    for k in ins
        .kev
        .iter()
        .filter(|k| k.subject.kind == SubjectKind::Software && ids.contains(&k.subject.id))
    {
        add(Some(kev_id(k)), &k.subject.id, &mut comp);
    }
    for m in ins
        .cve
        .iter()
        .filter(|m| m.kind == SubjectKind::Software && ids.contains(&m.id))
    {
        add(Some(cve_id(m)), &m.id, &mut comp);
    }
    if comp.is_empty() {
        return;
    }
    let parts: Vec<api::Finding> = comp.iter().filter_map(|id| take(a, prev, *id)).collect();
    let mut versions: Vec<&api::Software> = a
        .software
        .iter()
        .filter(|s| listed.contains(&s.id))
        .collect();
    versions.sort_by(|x, y| y.last_doc.cmp(&x.last_doc).then(x.name.cmp(&y.name)));
    versions.dedup_by(|x, y| x.id == y.id && x.ver == y.ver);
    let mut d = vec![
        "Документы организации созданы в версиях Microsoft Office без поддержки или с известными уязвимостями: это разведданные о рабочих станциях авторов (фишинг с вредоносными вложениями), а не уязвимость сайта.".to_string(),
    ];
    let mut ev: Vec<String> = Vec::new();
    let mut docs: Vec<u64> = Vec::new();
    for s in &versions {
        let mut l = format!(
            "{}: документов {}, последний {}",
            s.name,
            s.docs,
            s.last_doc.as_deref().unwrap_or("-")
        );
        if s.eol {
            match &s.eol_date {
                Some(e) => l.push_str(&format!(", поддержка завершена {e}")),
                None => l.push_str(", снято с поддержки"),
            }
        }
        l.push('.');
        ev.push(l.clone());
        d.push(l);
        for f in a.facts.iter().filter(|f| f.software.contains(&s.id)) {
            if docs.len() < 50 && !docs.contains(&f.id) {
                docs.push(f.id);
            }
        }
    }
    // CVEs per edition with every app key of the edition at once: a CVE of Office itself
    // counts once, not once per Word, Excel, ...
    let mut editions: Vec<(String, Vec<String>, Option<u16>)> = Vec::new();
    for s in &versions {
        let Some(ed) = cve::office_editions(&s.ver).into_iter().next() else {
            continue;
        };
        let y = year(s.last_doc.as_deref());
        match editions.iter_mut().find(|e| e.0 == ed) {
            Some(e) => {
                for c in &s.cpe {
                    if !e.1.contains(c) {
                        e.1.push(c.clone());
                    }
                }
                e.2 = e.2.max(y);
            }
            None => editions.push((ed, s.cpe.clone(), y)),
        }
    }
    let db = cve::db();
    let mut cves: Vec<String> = Vec::new();
    for (ed, keys, y) in &editions {
        let Some(sum) = db.lookup(&CveQuery {
            keys: keys.clone(),
            version: Some(ed.clone()),
            source: "meta".into(),
            until_year: *y,
            ..Default::default()
        }) else {
            continue;
        };
        if sum.matched == 0 {
            continue;
        }
        d.push(format!(
            "Microsoft Office {ed}: известных CVE для этой версии в NVD: {} (критических: {}, высоких: {}), из них в CISA KEV: {}.",
            sum.matched, sum.critical, sum.high, sum.kev
        ));
        for c in sum.cves.iter().take(10) {
            let mut l = c.id.clone();
            if let Some(v) = c.cvss {
                l.push_str(&format!(" CVSS {v}"));
            }
            if c.kev {
                l.push_str(" KEV");
            }
            if !cves.contains(&c.id) {
                cves.push(c.id.clone());
                ev.push(format!("Office {ed}: {l}"));
            }
        }
    }
    let kev_parts: Vec<&api::Finding> = parts
        .iter()
        .filter(|f| f.tags.iter().any(|t| t == "kev"))
        .collect();
    if !kev_parts.is_empty() {
        let n: BTreeSet<&String> = kev_parts.iter().flat_map(|f| f.cve.iter()).collect();
        d.push(format!(
            "Каталог CISA KEV называет эксплуатируемые уязвимости этих продуктов: {}.",
            n.len()
        ));
        for c in n {
            if !cves.contains(c) {
                cves.push(c.clone());
            }
        }
    }
    let sev = parts
        .iter()
        .map(|f| f.sev)
        .max_by_key(|s| s.rank())
        .unwrap_or(Severity::Medium);
    docs.sort_unstable();
    let mut f = finding(
        RULE_OFFICE,
        "office",
        format!(
            "Устаревший Microsoft Office на рабочих станциях: версий {}",
            versions.len()
        ),
        sev,
        "sw",
        "T1203",
        d.join("\n"),
        "Обновить Microsoft Office до поддерживаемой версии и включить централизованное обновление; учитывать при оценке фишинговых рисков.",
        ev.join("\n"),
        docs,
        now,
        prev.scan_id.as_deref(),
    );
    cap(&mut f, Severity::Medium);
    f.source = "ПО → EOL".into();
    f.cve = cves.into_iter().take(25).collect();
    f.tags = vec!["outdated".into(), "workstation".into(), "nvd".into()];
    if !kev_parts.is_empty() {
        f.tags.push("kev".into());
    }
    restore_triage(&mut f, prev);
    a.resolved.retain(|x| *x != f.id);
    a.findings.retain(|x| x.id != f.id);
    a.findings.push(f);
}

/// Document software (not Office) and OS: one finding per product, capped at medium.
fn merge_products(a: &mut Analysis, ins: &Insights, prev: &PrevState) {
    let office = office_ids(a);
    let mut subjects: Vec<(SubjectKind, String)> = Vec::new();
    for (kind, id) in ins
        .kev
        .iter()
        .map(|k| (k.subject.kind, k.subject.id.clone()))
        .chain(ins.cve.iter().map(|m| (m.kind, m.id.clone())))
    {
        if kind != SubjectKind::Tech
            && !office.contains(&id)
            && !subjects.contains(&(kind, id.clone()))
        {
            subjects.push((kind, id));
        }
    }
    for (kind, id) in subjects {
        let server = kind == SubjectKind::Software
            && a.software.iter().any(|s| s.id == id && s.side == "server");
        let mut ids: Vec<u64> = ins
            .kev
            .iter()
            .filter(|k| k.subject.kind == kind && k.subject.id == id)
            .map(kev_id)
            .collect();
        ids.extend(eol_id(kind, &id));
        ids.extend(
            ins.cve
                .iter()
                .filter(|m| m.kind == kind && m.id == id)
                .map(cve_id),
        );
        let present: Vec<u64> = ids
            .into_iter()
            .filter(|i| a.findings.iter().any(|f| f.id == *i))
            .fold(Vec::new(), |mut v, i| {
                if !v.contains(&i) {
                    v.push(i);
                }
                v
            });
        let Some((&head, rest)) = present.split_first() else {
            continue;
        };
        let absorbed: Vec<api::Finding> = rest.iter().filter_map(|i| take(a, prev, *i)).collect();
        if let Some(f) = a.findings.iter_mut().find(|f| f.id == head) {
            for x in &absorbed {
                absorb(f, x);
            }
            if !server {
                cap(f, Severity::Medium);
                if !f.tags.iter().any(|t| t == "workstation") {
                    f.tags.push("workstation".into());
                }
            }
        }
    }
}

/// Server-side generators: high only for documents served by hosts in the scope.
fn calibrate_servers(a: &mut Analysis, ins: &Insights) {
    for m in ins
        .cve
        .iter()
        .filter(|m| m.side == "server" && m.kind == SubjectKind::Software)
    {
        let mut hosts: Vec<String> = Vec::new();
        let mut elsewhere: Vec<String> = Vec::new();
        for d in a.facts.iter().filter(|f| m.docs.contains(&f.id)) {
            let uh = d
                .url
                .as_deref()
                .and_then(|u| url::Url::parse(u).ok())
                .and_then(|u| u.host_str().map(str::to_ascii_lowercase))
                .unwrap_or_default();
            let served = !uh.is_empty()
                && uh == d.host.to_ascii_lowercase()
                && !foca_analysis::util::is_storage_provider(&uh)
                && !uh.ends_with("archive.org");
            let list = if served { &mut hosts } else { &mut elsewhere };
            let h = if uh.is_empty() { d.host.clone() } else { uh };
            if !h.is_empty() && !list.contains(&h) {
                list.push(h);
            }
        }
        let mut ids = vec![cve_id(m)];
        ids.extend(eol_id(m.kind, &m.id));
        ids.extend(
            ins.kev
                .iter()
                .filter(|k| k.subject.kind == m.kind && k.subject.id == m.id)
                .map(kev_id),
        );
        for f in a.findings.iter_mut().filter(|f| ids.contains(&f.id)) {
            let line = if hosts.is_empty() {
                cap(f, Severity::Medium);
                format!(
                    "Документы с этой версией получены не с хостов в скоупе ({}): генератор может принадлежать не организации.",
                    elsewhere.join(", ")
                )
            } else {
                format!("Документы отданы хостами в скоупе: {}.", hosts.join(", "))
            };
            if !f.description.contains(&line) {
                f.description.push('\n');
                f.description.push_str(&line);
            }
        }
    }
}

/// Runs every calibration step and recomputes the risk (see the module docs).
pub fn apply(a: &mut Analysis, ins: &Insights, prev: &PrevState, now: &str) {
    merge_office(a, ins, prev, now);
    merge_products(a, ins, prev);
    calibrate_servers(a, ins);
    for f in &mut a.findings {
        if f.tags.iter().any(|t| t == OUT_OF_SCOPE_TAG) {
            f.sev = Severity::Info;
            if !f.tags.iter().any(|t| t == CONTEXT_TAG) {
                f.tags.push(CONTEXT_TAG.into());
            }
        }
        if let Some(c) = f.cvss {
            if cvss_band(c).rank() > f.sev.rank() {
                f.cvss = (f.sev != Severity::Info).then(|| band_cvss(f.sev));
            }
        }
    }
    let has_data = a.risk.score.is_some();
    a.risk = foca_analysis::findings::risk(&a.findings, has_data);
}

#[cfg(test)]
#[allow(clippy::field_reassign_with_default)]
mod tests {
    use super::*;
    use foca_analysis::DocFacts;
    use foca_core::api::{CveRef, CveSummary, Software};

    const NOW: &str = "2026-11-27T00:00:00Z";

    fn sum(version: &str, max: f32, kev: u32) -> CveSummary {
        CveSummary {
            product: "vendor_x:product_x".into(),
            version: version.into(),
            version_known: true,
            source: "meta".into(),
            known: 12,
            matched: 2,
            critical: u32::from(max >= 9.0),
            high: u32::from((7.0..9.0).contains(&max)),
            max_cvss: Some(max),
            kev,
            cves: vec![CveRef {
                id: "CVE-2099-0001".into(),
                cvss: Some(max),
                kev: kev > 0,
                ..Default::default()
            }],
            ..Default::default()
        }
    }

    fn m(id: &str, name: &str, ver: &str, side: &str, s: CveSummary) -> CveMatch {
        CveMatch {
            kind: SubjectKind::Software,
            id: id.into(),
            probe: format!("{name} {ver}"),
            name: name.into(),
            ver: ver.into(),
            side: side.into(),
            last_doc: Some("2024-05-01".into()),
            docs: vec![7],
            hosts: vec![],
            plugin_of: None,
            summary: s,
        }
    }

    fn office(id: &str, app: &str, ver: &str, eol: Option<&str>, docs: u32) -> Software {
        Software {
            id: id.into(),
            name: format!("Microsoft Office {app} {ver}"),
            ver: ver.into(),
            kind: "office".into(),
            eol: eol.is_some(),
            eol_date: eol.map(str::to_string),
            docs,
            cpe: vec![
                "microsoft:office".into(),
                format!("microsoft:{}", app.to_lowercase()),
            ],
            side: "workstation".into(),
            last_doc: Some("2024-05-01".into()),
            ..Default::default()
        }
    }

    fn doc(id: u64, sw: &str, url: &str, host: &str) -> DocFacts {
        DocFacts {
            id,
            key: format!("k{id}"),
            name: format!("d{id}.pdf"),
            url: Some(url.into()),
            host: host.into(),
            analyzed: true,
            software: vec![sw.into()],
            modified: Some("2024-05-01T10:00:00Z".into()),
            ..Default::default()
        }
    }

    fn eol_finding(id: &str, sev: Severity) -> api::Finding {
        let mut f = finding(
            "eol-software",
            id,
            format!("{id} (EOL)"),
            sev,
            "sw",
            "",
            "EOL".into(),
            "",
            "".into(),
            vec![7],
            NOW,
            None,
        );
        f.id = finding_id("eol-software", id);
        f
    }

    fn run(a: &mut Analysis, ins: &Insights) {
        super::super::cves::apply(a, ins, &PrevState::default(), NOW);
        apply(a, ins, &PrevState::default(), NOW);
    }

    #[test]
    fn office_versions_become_one_finding_capped_at_medium() {
        let mut a = Analysis::default();
        a.software = vec![
            office("word2010", "Word", "2010", Some("2020-10-13"), 3),
            office("excel2016", "Excel", "16.0", None, 2),
        ];
        a.facts = vec![
            doc(
                7,
                "word2010",
                "https://www.example.com/a.docx",
                "www.example.com",
            ),
            doc(
                8,
                "excel2016",
                "https://www.example.com/b.xlsx",
                "www.example.com",
            ),
        ];
        a.findings.push(eol_finding("word2010", Severity::Medium));
        let ins = Insights {
            cve: vec![
                m(
                    "word2010",
                    "Microsoft Office Word",
                    "2010",
                    "workstation",
                    sum("2010", 9.8, 1),
                ),
                m(
                    "excel2016",
                    "Microsoft Office Excel",
                    "16.0",
                    "workstation",
                    sum("16.0", 8.8, 0),
                ),
            ],
            ..Default::default()
        };
        run(&mut a, &ins);
        let rules: Vec<&str> = a
            .findings
            .iter()
            .map(|f| f.provenance.rule.as_str())
            .collect();
        assert_eq!(rules, vec![RULE_OFFICE], "{rules:?}");
        let f = &a.findings[0];
        assert_eq!(f.sev, Severity::Medium);
        assert!(f.title.ends_with("версий 2"), "{}", f.title);
        assert!(f.description.contains(
            "Microsoft Office Word 2010: документов 3, последний 2024-05-01, поддержка завершена 2020-10-13."
        ));
        assert!(f
            .description
            .contains("Microsoft Office 2010: известных CVE"));
        assert!(f.cvss.is_none_or(|c| cvss_band(c) == Severity::Medium));
        assert_eq!(f.rel.docs, vec![7, 8]);
    }

    #[test]
    fn document_product_findings_merge_and_server_generators_need_scope() {
        // LibreOffice: EOL and CVE findings of one product become one (EOL absorbs CVE in
        // cves::apply), capped at medium.
        let mut a = Analysis::default();
        a.software = vec![
            Software {
                id: "lo6".into(),
                name: "LibreOffice 6".into(),
                side: "workstation".into(),
                ..Default::default()
            },
            Software {
                id: "tcpdf".into(),
                name: "TCPDF".into(),
                side: "server".into(),
                ..Default::default()
            },
        ];
        a.facts = vec![doc(
            7,
            "tcpdf",
            "https://drive.google.com/file/d/x/view",
            "www.example.com",
        )];
        a.findings.push(eol_finding("lo6", Severity::Medium));
        let ins = Insights {
            cve: vec![
                m(
                    "lo6",
                    "LibreOffice",
                    "6.0",
                    "workstation",
                    sum("6.0", 9.8, 1),
                ),
                m("tcpdf", "TCPDF", "6.2.13", "server", sum("6.2.13", 9.8, 0)),
            ],
            ..Default::default()
        };
        run(&mut a, &ins);
        let lo = a
            .findings
            .iter()
            .find(|f| f.id == finding_id("eol-software", "lo6"))
            .unwrap();
        assert_eq!(lo.sev, Severity::Medium);
        assert!(lo.tags.contains(&"workstation".to_string()));
        let srv = a
            .findings
            .iter()
            .find(|f| f.title.contains("TCPDF"))
            .unwrap();
        assert_eq!(
            srv.sev,
            Severity::Medium,
            "documents not from in-scope hosts"
        );
        assert!(srv
            .description
            .contains("получены не с хостов в скоупе (drive.google.com)"));
        assert_eq!(srv.cvss, Some(band_cvss(Severity::Medium)));

        // The same generator on the organisation's own host keeps its severity.
        let mut b = Analysis::default();
        b.software = a.software.clone();
        b.facts = vec![doc(
            7,
            "tcpdf",
            "https://www.example.com/r.pdf",
            "www.example.com",
        )];
        run(&mut b, &ins);
        let srv = b
            .findings
            .iter()
            .find(|f| f.title.contains("TCPDF"))
            .unwrap();
        assert_eq!(srv.sev, Severity::Critical);
        assert!(srv
            .description
            .contains("Документы отданы хостами в скоупе: www.example.com."));
    }

    #[test]
    fn out_of_scope_findings_are_context() {
        let mut a = Analysis::default();
        let mut f = eol_finding("x", Severity::High);
        f.cvss = Some(8.1);
        f.tags.push(OUT_OF_SCOPE_TAG.into());
        a.findings.push(f);
        a.risk.score = Some(0);
        apply(&mut a, &Insights::default(), &PrevState::default(), NOW);
        assert_eq!(a.findings[0].sev, Severity::Info);
        assert!(a.findings[0].tags.contains(&CONTEXT_TAG.to_string()));
        assert_eq!(a.findings[0].cvss, None);
        assert_eq!(a.risk.score, Some(0));
    }
}
