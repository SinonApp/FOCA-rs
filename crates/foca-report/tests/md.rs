//! Report integration tests: Markdown report output.

mod common;

use common::*;

#[test]
fn md_export_front_matter_quotes_the_date() {
    let snap = &fixture().snap;
    let a = export_with_log(
        snap,
        &fixture().log,
        ExportKind::Findings,
        ExportFormat::Md,
        &ExportOptions {
            date: "2026-01-01\nevil: true".into(),
            ..Default::default()
        },
    );
    let txt = String::from_utf8(a.bytes).unwrap();
    let front = txt.split("\n---\n").next().unwrap();
    assert!(
        front.contains("date: \"2026-01-01\\nevil: true\""),
        "{front}"
    );
    assert!(!front.lines().any(|l| l.starts_with("evil:")));
}

#[test]
fn markdown_has_no_html_entities_dangling_provenance_or_empty_tables() {
    let mut snap = fixture().snap.clone();
    snap.findings[0].provenance.docs.clear();
    snap.findings[0].provenance.rule = "doc.example".into();
    snap.findings[0].mitre = "T1213 · MITRE ATT&CK".into();
    let o = ReportOptions {
        custody: true,
        ..opts(ReportFormat::Md)
    };
    let md = text(&build(&snap, &o));
    assert!(!md.contains("&amp;") && !md.contains("&lt;") && !md.contains("&gt;"));
    assert!(md.contains("ATT&CK"));
    assert!(!md.contains(": *\n"), "dangling provenance label");
    // Code spans show their content literally: no backslash escapes inside.
    for span in md.split('`').skip(1).step_by(2) {
        assert!(
            !span.contains("\\_") && !span.contains("\\+"),
            "escaped code span: {span}"
        );
    }
    // Every table header is followed by at least one data row.
    let lines: Vec<&str> = md.lines().collect();
    for (i, l) in lines.iter().enumerate() {
        if l.starts_with("| --- |") {
            assert!(
                lines.get(i + 1).is_some_and(|n| n.starts_with('|')),
                "empty table before line {i}: {}",
                lines[i - 1]
            );
        }
    }
    let empty = text(&build(&Snapshot::default(), &opts(ReportFormat::Md)));
    assert!(empty.contains("*нет данных*"));
}

#[test]
fn markdown_matches_html_sections() {
    let mut s = fixture().snap.clone();
    s.hosts[0].tech = "nginx 1.18.0".into();
    s.recon = serde_json::json!({
        "sitemap": [{ "loc": "https://www.example.com/a" }, { "loc": "https://www.example.com/b" }],
        "sitemap_total": 250
    });
    let o = ReportOptions {
        lang: Lang::En,
        ..opts(ReportFormat::Md)
    };
    let md = text(&build(&s, &o));
    assert!(md.contains("| Host | IP | Role | Technologies |") || md.contains("| Technologies |"));
    assert!(md.contains("nginx 1.18.0"));
    assert!(md.contains("Testing period"), "log period missing");
    assert!(md.contains("### Scans"), "scans appendix missing");
    assert!(md.contains("### Report parameters"));
    assert!(md.contains("(2 of 250)"), "sitemap counter missing");
}
