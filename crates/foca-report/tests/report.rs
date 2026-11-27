//! Integration tests for reports and exports on a snapshot of the `tests/corpus` corpus
//! (foca-meta → foca-store/foca-analysis → `Snapshot`).
//!
//! Golden files live in `tests/golden/*`; regenerate them with
//! `UPDATE_GOLDEN=1 cargo test -p foca-report --test report`.
//! Sample HTML: `FOCA_REPORT_SAMPLE=1 cargo test -p foca-report --test report sample`
//! writes `examples/out/report-sample.html`.
//!
//! Golden files, JSON schema, risk/count rules and finding order shared by every format.
//! Other areas live in the sibling test files; the fixture and helpers are in `common/`.

mod common;

use common::*;

#[test]
fn golden_md_csv_json() {
    let snap = &fixture().snap;
    assert!(snap.docs.len() >= 25 && !snap.findings.is_empty());
    let md = build(snap, &opts(ReportFormat::Md));
    assert_eq!(md.file_name, "Отчёт_пентест_contoso.example_v1.md");
    golden("report.ru.md", &text(&md));
    let csv = build(snap, &opts(ReportFormat::Csv));
    assert_eq!(csv.file_name, "Data_contoso.example_v1.csv");
    assert_eq!(csv.lang, "-");
    golden("report.csv", &text(&csv));
    let json = build(snap, &opts(ReportFormat::Json));
    golden("report.json", &text(&json));
    let mut eo = ExportOptions {
        date: "2026-11-20".into(),
        ..Default::default()
    };
    let dict = export_with_log(snap, &[], ExportKind::Users, ExportFormat::Dict, &eo);
    assert_eq!(dict.file_name, "contoso_dict-users_2026-11-20.txt");
    golden("users.dict.txt", std::str::from_utf8(&dict.bytes).unwrap());
    eo.bom = false;
    let f = export_with_log(snap, &[], ExportKind::Findings, ExportFormat::Csv, &eo);
    golden("findings.csv", std::str::from_utf8(&f.bytes).unwrap());
}

// ---------------------------------------------------------------- HTML

#[test]
fn risk_counts_follow_included_findings() {
    let snap = &fixture().snap;
    let all = build(snap, &opts(ReportFormat::Json));
    let s = &all.summary;
    assert_eq!(
        s.counts.crit + s.counts.high + s.counts.warn + s.counts.low + s.counts.info,
        s.total
    );
    // No false positives or fixed findings among the main ones; fixed findings are listed
    // separately.
    let main: Vec<_> = snap
        .findings
        .iter()
        .filter(|f| all.results_snapshot.finding_ids.contains(&f.id))
        .collect();
    assert!(main.iter().all(|f| !matches!(
        f.status,
        FindingStatus::FalsePositive | FindingStatus::Fixed
    )));
    assert_eq!(all.results_snapshot.fixed_ids.len(), 1);
    assert!(s.project_risk.is_some() && s.risk == s.project_risk);
    // With only High and above selected, risk is computed over those findings, not the whole
    // project.
    let hi = build(
        snap,
        &ReportOptions {
            min_sev: Some(Severity::High),
            ..opts(ReportFormat::Json)
        },
    );
    let incl: Vec<_> = snap
        .findings
        .iter()
        .filter(|f| hi.results_snapshot.finding_ids.contains(&f.id))
        .collect();
    assert!(incl.iter().all(|f| f.sev.rank() >= Severity::High.rank()));
    assert_eq!(hi.summary.risk, risk_of(&incl, true));
    assert!(hi.summary.risk <= all.summary.risk);
    assert_eq!(
        hi.summary.counts.warn + hi.summary.counts.low + hi.summary.counts.info,
        0
    );
    // A selection of a single low finding gives low risk even though the project's risk is high.
    let low = snap
        .findings
        .iter()
        .find(|f| f.sev == Severity::Low && f.status != FindingStatus::FalsePositive)
        .unwrap();
    let one = build(
        snap,
        &ReportOptions {
            picked_only: true,
            picked: vec![low.id],
            ..opts(ReportFormat::Html)
        },
    );
    assert_eq!(one.results_snapshot.finding_ids, vec![low.id]);
    assert_eq!(one.summary.risk_level, "low");
    assert_ne!(one.summary.risk, one.summary.project_risk);
    // The JSON report shows the same risk.
    let v: Value = serde_json::from_slice(&hi.bytes).unwrap();
    assert_eq!(
        v["summary"]["risk"].as_u64().map(|x| x as u8),
        hi.summary.risk
    );
    // History record in the docs/API.md shape.
    let rec = hi.report_record(7, "2026-11-20T12:00:00", "Данные");
    for k in [
        "id",
        "name",
        "tpl",
        "fmt",
        "lang",
        "created_at",
        "size",
        "opts",
        "result",
    ] {
        assert!(rec.get(k).is_some(), "{k}");
    }
    for k in [
        "finding_ids",
        "fixed_ids",
        "counts",
        "total",
        "risk",
        "risk_level",
        "pages",
        "project_risk",
        "at_scan",
    ] {
        assert!(rec["result"].get(k).is_some(), "result.{k}");
    }
    assert_eq!(rec["result"]["at_scan"], "s1");
}

#[test]
fn confirmed_only_filter() {
    let snap = &fixture().snap;
    let a = build(
        snap,
        &ReportOptions {
            confirmed: true,
            ..opts(ReportFormat::Md)
        },
    );
    let ids = &a.results_snapshot.finding_ids;
    assert!(!ids.is_empty());
    for f in snap.findings.iter().filter(|f| ids.contains(&f.id)) {
        assert_eq!(f.status, FindingStatus::Confirmed, "F-{}", f.id);
    }
    let confirmed = snap
        .findings
        .iter()
        .filter(|f| f.status == FindingStatus::Confirmed)
        .count();
    assert_eq!(ids.len(), confirmed);
    // Fixed findings keep their own section even with the confirmed-only filter.
    assert_eq!(a.results_snapshot.fixed_ids.len(), 1);
    let md = text(&a);
    let fp = snap
        .findings
        .iter()
        .find(|f| f.status == FindingStatus::FalsePositive)
        .unwrap();
    assert!(!a.results_snapshot.finding_ids.contains(&fp.id));
    assert!(md.contains("findings_crit:"));
}

// JSON schema.

#[test]
fn json_matches_schema() {
    let schema: Value = serde_json::from_str(foca_report::REPORT_SCHEMA).unwrap();
    let snap = &fixture().snap;
    for o in [
        opts(ReportFormat::Json),
        ReportOptions {
            tpl: Template::Data,
            sections: Sections::for_template(Template::Data),
            ..opts(ReportFormat::Json)
        },
        ReportOptions {
            secrets: SecretMode::Partial,
            lang: Lang::En,
            confirmed: true,
            min_sev: Some(Severity::Medium),
            ..opts(ReportFormat::Json)
        },
    ] {
        let a = build(snap, &o);
        assert_eq!(a.mime, "application/json");
        let v: Value = serde_json::from_slice(&a.bytes).unwrap();
        assert_eq!(v["schema_version"], 1);
        check(&schema, &schema, &v, "$");
    }
    // Every array is non-empty in the full report, so the schema is checked on items too.
    let v: Value = serde_json::from_slice(&build(snap, &opts(ReportFormat::Json)).bytes).unwrap();
    for k in [
        "findings",
        "fixed",
        "people",
        "emails",
        "hosts",
        "pcs",
        "software",
        "paths",
        "documents",
        "secrets",
    ] {
        assert!(!v[k].as_array().unwrap().is_empty(), "{k} is empty");
    }
    assert!(!v["request_log"]["requests"].as_array().unwrap().is_empty());
}

// Export.

#[test]
fn dictionaries_unique_sorted() {
    let snap = &fixture().snap;
    let eo = ExportOptions::default();
    for (kind, dk) in [
        (ExportKind::Users, "users"),
        (ExportKind::Emails, "emails"),
        (ExportKind::Paths, "paths"),
        (ExportKind::Software, "software"),
    ] {
        let a = export_with_log(snap, &[], kind, ExportFormat::Dict, &eo);
        assert!(
            a.file_name.contains(&format!("_dict-{dk}_")),
            "{}",
            a.file_name
        );
        let s = String::from_utf8(a.bytes).unwrap();
        let lines: Vec<&str> = s.lines().collect();
        assert!(!lines.is_empty(), "{dk}");
        let mut sorted = lines.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(lines, sorted, "{dk}: not unique or not sorted");
        assert_eq!(a.count, lines.len());
        assert!(lines
            .iter()
            .all(|l| *l == l.to_lowercase() && !l.trim().is_empty()));
    }
    let u = String::from_utf8(
        export_with_log(snap, &[], ExportKind::Users, ExportFormat::Dict, &eo).bytes,
    )
    .unwrap();
    for v in ["o.kovalenko", "okovalenko", "kovalenko.o", "kovalenko"] {
        assert!(u.lines().any(|l| l == v), "missing variant {v}");
    }
    let plain = export_with_log(
        snap,
        &[],
        ExportKind::Users,
        ExportFormat::Dict,
        &ExportOptions {
            login_variants: false,
            ..Default::default()
        },
    );
    assert!(!String::from_utf8(plain.bytes)
        .unwrap()
        .lines()
        .any(|l| l == "okovalenko"));
    let custom = export_with_log(
        snap,
        &[],
        ExportKind::Hosts,
        ExportFormat::Dict,
        &ExportOptions {
            items: Some(vec!["B".into(), "a".into(), "b\n".into()]),
            ..Default::default()
        },
    );
    assert_eq!(String::from_utf8(custom.bytes).unwrap(), "a\nb\n");
}

// Sample.

#[test]
fn sample_html() {
    let snap = &fixture().snap;
    let o = ReportOptions {
        logo: Logo::Initials,
        secrets: SecretMode::Partial,
        ..opts(ReportFormat::Html)
    };
    let a = build(snap, &o);
    assert_safe_html(&text(&a));
    if std::env::var("FOCA_REPORT_SAMPLE").is_ok_and(|v| v == "1") {
        let dir = root().join("examples/out");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("report-sample.html"), &a.bytes).unwrap();
        let md = build(
            snap,
            &ReportOptions {
                fmt: ReportFormat::Md,
                ..o
            },
        );
        std::fs::write(dir.join("report-sample.md"), &md.bytes).unwrap();
    }
}

/// 100/100 with critical findings yields the critical level and its own CSS class, not high.
#[test]
fn riskbox_critical_level() {
    use foca_report::data::risk_level;
    assert_eq!(risk_level(Some(100), true), "crit");
    assert_eq!(risk_level(Some(100), false), "high");
    assert_eq!(risk_level(Some(89), true), "high");
    assert_eq!(risk_level(None, true), "none");
    let mut s = fixture().snap.clone();
    for f in s.findings.iter_mut().take(6) {
        f.sev = Severity::Critical;
        f.status = FindingStatus::New;
    }
    let o = ReportOptions {
        lang: Lang::Uk,
        ..opts(ReportFormat::Html)
    };
    let a = build(&s, &o);
    let h = text(&a);
    assert!(a.results_snapshot.risk.unwrap_or(0) >= 90);
    {
        assert_eq!(a.results_snapshot.risk_level, "crit");
        assert!(
            h.contains("<div class=\"risk crit\">") && h.contains("Критичний"),
            "riskbox crit"
        );
    }
}

/// The critical level needs a critical finding that the score counts: one tagged out of scope
/// (excluded from the score) cannot lift a high score to critical.
#[test]
fn out_of_scope_critical_does_not_raise_the_level() {
    let mut s = fixture().snap.clone();
    let tpl = s.findings[0].clone();
    // Eight critical web findings: 1 - 0.75^8 = 90 when all count, 87 with one out of scope.
    s.findings = (0..8u64)
        .map(|i| {
            let mut f = tpl.clone();
            f.id = 9000 + i;
            f.status = FindingStatus::New;
            f.tags.clear();
            f.category = "web".into();
            f.sev = Severity::Critical;
            f
        })
        .collect();
    s.findings[7].tags.push("out_of_scope".into());
    let a = build(&s, &opts(ReportFormat::Html));
    assert_eq!(a.results_snapshot.risk, Some(87), "seven critical findings");
    assert_eq!(a.results_snapshot.risk_level, "high");
    // control: the same critical finding in scope makes the level critical
    s.findings[7].tags.clear();
    let a = build(&s, &opts(ReportFormat::Html));
    assert_eq!(a.results_snapshot.risk_level, "crit");
}

#[test]
fn golden_extra_templates() {
    let snap = &fixture().snap;
    for (tpl, id) in EXTRA_TEMPLATES {
        for lang in [Lang::Uk, Lang::Ru, Lang::En] {
            let md = text(&build(snap, &tpl_opts(tpl, lang, ReportFormat::Md)));
            golden(&format!("tpl-{id}.{}.md", lang.code()), &md);
            assert!(md.contains(&format!("template: {id}")));
            let html = build(snap, &tpl_opts(tpl, lang, ReportFormat::Html));
            let h = text(&html);
            assert_safe_html(&h);
            assert!(h.contains("Content-Security-Policy") && h.contains("default-src 'none'"));
            if lang != Lang::En {
                golden(&format!("tpl-{id}.{}.html", lang.code()), &h);
            }
            // The record keeps the template id for the UI.
            assert_eq!(html.opts["tpl_id"], id);
        }
    }
}

#[test]
fn finding_numbers_follow_report_order_in_every_format() {
    let snap = &fixture().snap;
    for fmt in [ReportFormat::Html, ReportFormat::Md, ReportFormat::Docx] {
        let a = build(snap, &opts(fmt));
        let body = if fmt == ReportFormat::Docx {
            let mut z = zip::ZipArchive::new(std::io::Cursor::new(a.bytes.clone())).unwrap();
            let mut x = String::new();
            z.by_name("word/document.xml")
                .unwrap()
                .read_to_string(&mut x)
                .unwrap();
            x
        } else {
            text(&a)
        };
        assert!(!body.contains("F-F-"), "{fmt:?}: doubled prefix");
        // Finding cards are the last mention of each number; their sequence must be
        // 1, 2, 3, … without gaps.
        let refs = finding_refs(&body);
        let mut seen = Vec::new();
        for n in refs {
            if !seen.contains(&n) {
                seen.push(n);
            }
        }
        let total = a.summary.total as usize;
        assert!(total > 3, "{fmt:?}");
        let mut sorted = seen.clone();
        sorted.sort();
        assert_eq!(seen, sorted, "{fmt:?}: numbers out of order");
        assert_eq!(sorted.first(), Some(&1), "{fmt:?}");
        assert!(
            sorted.len() >= total && sorted[total - 1] == total as u64,
            "{fmt:?}: {sorted:?}"
        );
    }
}

#[test]
fn out_of_scope_findings_get_a_caveat_in_every_format() {
    let mut s = fixture().snap.clone();
    for f in s.findings.iter_mut().take(2) {
        f.tags.push("out_of_scope".into());
    }
    for fmt in [ReportFormat::Html, ReportFormat::Md, ReportFormat::Docx] {
        let o = ReportOptions {
            lang: Lang::En,
            ..opts(fmt)
        };
        let a = build(&s, &o);
        let body = if fmt == ReportFormat::Docx {
            docx_xml(&a)
        } else {
            text(&a)
        };
        assert!(
            body.contains("2 finding(s) relate to hosts outside the scope"),
            "{fmt:?}: no out-of-scope caveat"
        );
    }
    let plain = text(&build(&fixture().snap, &opts(ReportFormat::Md)));
    assert!(!plain.contains("вне скоупа: "));
}

#[test]
fn findings_with_one_title_are_told_apart() {
    let snap = &fixture().snap;
    for lang in [Lang::Ru, Lang::En] {
        let o = ReportOptions {
            lang,
            ..opts(ReportFormat::Md)
        };
        let md = text(&build(snap, &o));
        let titles: Vec<&str> = md
            .lines()
            .filter(|l| l.starts_with("### F-"))
            .map(|l| l.split_once(" · ").unwrap().1)
            .collect();
        let mut uniq = titles.clone();
        uniq.sort();
        uniq.dedup();
        assert_eq!(
            uniq.len(),
            titles.len(),
            "{lang:?}: duplicate finding titles"
        );
    }
}

/// A finding without a host shows the first scope target, the old `software` category key is
/// `sw`, and storage providers are not counted as discovered hosts.
#[test]
fn empty_hosts_and_category_keys_are_normalized() {
    let mut s = fixture().snap.clone();
    let target = foca_report::default_host(&s);
    assert_ne!(target, "n/a", "the fixture has a scope target");
    s.findings[0].host = String::new();
    s.findings[1].host = "-".into();
    s.findings[1].category = "software".into();
    let mut n = s.clone();
    foca_report::normalize_finding_labels(&mut n);
    assert_eq!(n.findings[0].host, target);
    assert_eq!(n.findings[1].host, target);
    assert_eq!(n.findings[1].category, "sw");
    let j: serde_json::Value =
        serde_json::from_str(&text(&build(&s, &opts(ReportFormat::Json)))).unwrap();
    let fs = j["findings"].as_array().unwrap();
    assert!(
        fs.iter()
            .all(|f| !matches!(f["host"].as_str(), Some("" | "-"))),
        "{j}"
    );
    assert!(fs.iter().all(|f| f["category"] != "software"));
    let mut none = s.clone();
    none.scope.targets.clear();
    foca_report::normalize_finding_labels(&mut none);
    assert_eq!(none.findings[0].host, "n/a");

    let before = foca_report::data::overview(&s, Lang::En).hosts;
    s.hosts.push(foca_core::api::Host {
        name: "drive.google.com".into(),
        ..Default::default()
    });
    assert_eq!(foca_report::data::overview(&s, Lang::En).hosts, before);
}
