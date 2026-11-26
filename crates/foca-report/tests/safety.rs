//! Report integration tests: Escaping of hostile input, CSV injection, safe file names, secret and PII redaction.

mod common;

use common::*;

#[test]
fn xss_everything_escaped() {
    let snap = hostile();
    let o = ReportOptions {
        logo: Logo::from_data("data:image/svg+xml;base64,PHN2ZyBvbmxvYWQ9YWxlcnQoMSk+"),
        ..opts(ReportFormat::Html)
    };
    assert_eq!(o.logo, Logo::None);
    let h = text(&build(&snap, &o));
    assert_safe_html(&h);
    assert!(h.contains("&lt;script&gt;alert(1)&lt;/script&gt;"));
    assert!(h.contains("&quot;&gt;&lt;img src=x onerror=alert(1)&gt;"));
    // `javascript:` links are rendered as text, http(s) links are clickable.
    assert!(h.contains("javascript:alert(1)") && !h.contains("href=\"javascript"));
    assert!(h.contains("href=\"https://portal.contoso.example/login?next=/\""));
    // File name derived from a hostile project name.
    let a = build(&snap, &o);
    assert!(
        !a.file_name.contains(['/', '<', '>', '"']) && !a.file_name.contains(".."),
        "{}",
        a.file_name
    );
    // Markdown: HTML is neutralized and `|` in cells is escaped.
    let md = text(&build(
        &snap,
        &ReportOptions {
            tpl: Template::Summary,
            ..opts(ReportFormat::Md)
        },
    ));
    assert!(!raw_md_tag(&md, "<script") && !raw_md_tag(&md, "<img") && !raw_md_tag(&md, "<iframe"));
    for line in md.lines().filter(|l| l.starts_with('|')) {
        // The number of unescaped `|` in a table row equals the column count + 1.
        let raw = line
            .match_indices('|')
            .filter(|(i, _)| *i == 0 || &line[i - 1..*i] != "\\")
            .count();
        let header_cols = line.split(" | ").count();
        assert!(raw >= 2 && raw <= header_cols + 1, "{line}");
    }
    // GraphML: XML escaping.
    let g = export_with_log(
        &snap,
        &[],
        ExportKind::All,
        ExportFormat::Graphml,
        &ExportOptions::default(),
    );
    let gx = String::from_utf8(g.bytes).unwrap();
    assert!(!gx.contains("<script") && !gx.contains("<iframe"));
    let mut r = quick_xml::Reader::from_str(&gx);
    loop {
        match r.read_event() {
            Ok(quick_xml::events::Event::Eof) => break,
            Ok(_) => {}
            Err(e) => panic!("GraphML is not valid XML: {e}"),
        }
    }
}

// ---------------------------------------------------------------- CSV

#[test]
fn csv_injection_and_rfc4180() {
    let mut snap = fixture().snap.clone();
    snap.findings[0].title = "=HYPERLINK(\"http://evil\",\"x\")".into();
    snap.findings[0].host = "+cmd|' /C calc'!A0".into();
    snap.people[0].login = "@SUM(1+1)".into();
    snap.people[0].name = "-2+3".into();
    snap.emails[0].addr = "\t=1".into();
    let a = build(&snap, &opts(ReportFormat::Csv));
    assert!(a.bytes.starts_with("\u{feff}".as_bytes()), "missing BOM");
    let s = text(&a);
    assert!(s.contains("\r\n"));
    let rows = csv_cells(&s);
    let width = rows[0].len();
    assert!(
        rows.iter().all(|r| r.len() == width),
        "rows differ in width"
    );
    for r in &rows {
        for c in r {
            assert!(
                !c.starts_with(['=', '+', '-', '@', '\t', '\r']),
                "injection: {c:?}"
            );
        }
    }
    assert!(rows
        .iter()
        .any(|r| r.iter().any(|c| c.starts_with("'=HYPERLINK"))));
    for (kind, needle) in [
        (ExportKind::Users, "'@SUM(1+1)"),
        (ExportKind::Emails, "'\t=1"),
    ] {
        let e = export_with_log(
            &snap,
            &[],
            kind,
            ExportFormat::Csv,
            &ExportOptions::default(),
        );
        let rows = csv_cells(std::str::from_utf8(&e.bytes).unwrap());
        assert!(rows.iter().flatten().any(|c| c == needle), "{kind:?}");
        assert!(rows
            .iter()
            .flatten()
            .all(|c| !c.starts_with(['=', '+', '-', '@', '\t'])));
    }
    let m = export_with_log(
        &snap,
        &[],
        ExportKind::All,
        ExportFormat::MaltegoCsv,
        &ExportOptions::default(),
    );
    let rows = csv_cells(std::str::from_utf8(&m.bytes).unwrap());
    assert!(m.count > 10 && rows.len() == m.count + 1);
    assert!(rows
        .iter()
        .flatten()
        .all(|c| !c.starts_with(['=', '+', '-', '@', '\t'])));
}

#[test]
fn file_names_safe() {
    let mut snap = fixture().snap.clone();
    for evil in [
        "../../etc/passwd",
        "a/b\\c:d*e?f\"g<h>i|j",
        "con",
        "\u{202e}fdp.exe",
        "..",
    ] {
        snap.project.name = evil.into();
        let r = build(&snap, &opts(ReportFormat::Html));
        let e = export_with_log(
            &snap,
            &[],
            ExportKind::Users,
            ExportFormat::Dict,
            &ExportOptions::default(),
        );
        for n in [&r.file_name, &e.file_name] {
            assert!(
                !n.contains(['/', '\\', ':', '*', '?', '"', '<', '>', '|', '\u{202e}']),
                "{n}"
            );
            assert!(
                !n.contains("..") && !n.starts_with('.') && n.len() > 4,
                "{n}"
            );
        }
    }
    // N is a project-wide counter.
    snap.project.name = "contoso.example".into();
    snap.reports.push(foca_core::api::Report {
        name: "Звіт_пентест_contoso.example_v4.pdf".into(),
        ..Default::default()
    });
    let r = build(
        &snap,
        &ReportOptions {
            lang: Lang::Uk,
            ..opts(ReportFormat::Html)
        },
    );
    assert_eq!(r.file_name, "Звіт_пентест_contoso.example_v5.html");
    assert_eq!(r.version, 5);
}

// Secrets.

#[test]
fn secrets_hidden_by_default() {
    let snap = &fixture().snap;
    let secrets = secret_values(snap);
    assert!(
        secrets.iter().any(|s| s == "Buh2023!"),
        "corpus has no secrets: {secrets:?}"
    );
    for (name, out) in all_outputs(snap, SecretMode::Hide) {
        for s in &secrets {
            assert!(!out.contains(s.as_str()), "{name}: secret leaked {s:?}");
        }
    }
    // Partial mode does not reveal values either.
    for (name, out) in all_outputs(snap, SecretMode::Partial).into_iter().take(4) {
        for s in &secrets {
            assert!(!out.contains(s.as_str()), "{name} (partial): {s:?}");
        }
        assert!(out.contains("••••••"), "{name}: mask missing");
    }
    // Sanity check of the check itself: with explicit full mode the secret is visible.
    let full = text(&build(
        snap,
        &ReportOptions {
            secrets: SecretMode::Full,
            ..opts(ReportFormat::Html)
        },
    ));
    assert!(full.contains("Buh2023!"));
    let e = export_with_log(
        snap,
        &[],
        ExportKind::Findings,
        ExportFormat::Csv,
        &ExportOptions {
            include_secrets: true,
            ..Default::default()
        },
    );
    assert!(e.secrets && String::from_utf8(e.bytes).unwrap().contains("Buh2023!"));
}

#[test]
fn pii_redacted_on_request() {
    let snap = &fixture().snap;
    let eo = ExportOptions {
        redact_pii: true,
        ..Default::default()
    };
    for kind in [ExportKind::Users, ExportKind::Emails, ExportKind::Docs] {
        let a = export_with_log(snap, &[], kind, ExportFormat::Csv, &eo);
        assert!(a.pii_redacted);
        let s = String::from_utf8(a.bytes).unwrap();
        assert!(
            !s.contains("Олена Коваленко") && !s.contains("o.kovalenko@"),
            "{kind:?}"
        );
    }
}

// Selection and risk.

#[test]
fn pii_table_kind_and_count_survive_localization() {
    let mut snap = fixture().snap.clone();
    let f = snap
        .findings
        .iter_mut()
        .find(|f| f.provenance.rule == "pii" && f.title.contains("РНОКПП"))
        .expect("fixture has an RNOKPP finding");
    f.description = "В документе найдено значений: 3. Значения проверены по контрольным суммам, где это возможно; в базе и отчёте хранятся только маски.".into();
    for (lang, kind) in [
        (Lang::En, "Individual tax number (RNOKPP)"),
        (Lang::Uk, "РНОКПП (ІПН)"),
        (Lang::Ru, "РНОКПП (ІПН)"),
    ] {
        let o = ReportOptions {
            lang,
            ..opts(ReportFormat::Md)
        };
        let md = text(&build(&snap, &o));
        let row = format!("| personal.docx | {kind} | 3 |");
        assert!(md.contains(&row), "{lang:?}: no row {row}");
        let pii_rows: Vec<&str> = md
            .lines()
            .filter(|l| l.starts_with("| personal.docx | ") && l.matches(" | ").count() == 3)
            .collect();
        assert!(
            pii_rows.iter().all(|l| !l.contains("| - |")),
            "{lang:?}: unknown PII kind in {pii_rows:?}"
        );
    }
}
