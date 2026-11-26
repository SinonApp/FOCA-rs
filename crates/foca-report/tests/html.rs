//! Report integration tests: HTML report structure and styling.

mod common;

use common::*;

#[test]
fn html_self_contained_structure() {
    let snap = &fixture().snap;
    let a = build(snap, &opts(ReportFormat::Html));
    assert_eq!(a.mime, "text/html; charset=utf-8");
    assert_eq!(a.file_name, "Отчёт_пентест_contoso.example_v1.html");
    let h = text(&a);
    assert_safe_html(&h);
    for s in [
        "<style>",
        "size: A4",
        "Content-Security-Policy",
        "<svg",
        "id=\"summary\"",
        "id=\"scope\"",
        "id=\"findings\"",
        "id=\"fixed\"",
        "id=\"people\"",
        "id=\"infra\"",
        "id=\"docs\"",
        "id=\"log\"",
        "id=\"appx\"",
        "Критический",
        "Письменное разрешение владельца от 01.11.2026",
        "MITRE ATT&amp;CK",
        "Заблокированные скоупом",
        "mail.contoso.example/owa/",
        "Устаревшее ПО",
        "Документы по типам",
        "Топ пользователей",
    ] {
        assert!(h.contains(s), "missing {s:?}");
    }
    // Passive requests to third-party services appear only in the summary, not per line.
    assert!(!h.contains("crt.sh/?q="));
    // Ukrainian and English severity terms.
    let uk = text(&build(
        snap,
        &ReportOptions {
            lang: Lang::Uk,
            ..opts(ReportFormat::Html)
        },
    ));
    assert!(uk.contains("Критичний") && uk.contains("lang=\"uk\"") && uk.contains("Знахідки"));
    assert_safe_html(&uk);
    let en = build(
        snap,
        &ReportOptions {
            lang: Lang::En,
            ..opts(ReportFormat::Html)
        },
    );
    assert_eq!(en.file_name, "Pentest_report_contoso.example_v1.html");
    assert!(text(&en).contains("Critical") && text(&en).contains("Executive summary"));
    // The summary and data templates have no finding cards with evidence.
    for tpl in [Template::Summary, Template::Data] {
        let o = ReportOptions {
            tpl,
            sections: Sections::for_template(tpl),
            ..opts(ReportFormat::Html)
        };
        let h = text(&build(snap, &o));
        assert_safe_html(&h);
        assert!(!h.contains("class=\"finding "), "{tpl:?}");
    }
}

#[test]
fn incomplete_scan_env_renders_warning_in_html_and_md_only_when_incomplete() {
    use foca_core::api::ScanEnv;

    let mut clean_snap = fixture().snap.clone();
    if let Some(last) = clean_snap.scans.last_mut() {
        last.env = Some(ScanEnv {
            egress: "Direct".into(),
            incomplete: false,
            ..Default::default()
        });
    }
    let clean_html = text(&build(&clean_snap, &opts(ReportFormat::Html)));
    let baseline_html = text(&build(&fixture().snap, &opts(ReportFormat::Html)));
    assert_eq!(clean_html, baseline_html);

    let mut inc_snap = fixture().snap.clone();
    if let Some(last) = inc_snap.scans.last_mut() {
        last.env = Some(ScanEnv {
            egress: "v2rayNG".into(),
            proxy_used: true,
            tcp_intercept: true,
            incomplete: true,
            incomplete_sources: vec!["wayback".into(), "otx_url".into()],
            ..Default::default()
        });
    }
    for (lang, needle) in [
        (Lang::Ru, "Неполный снимок сканирования"),
        (Lang::Uk, "Неповний знімок сканування"),
        (Lang::En, "Incomplete scan snapshot"),
    ] {
        let html = text(&build(
            &inc_snap,
            &ReportOptions {
                lang,
                ..opts(ReportFormat::Html)
            },
        ));
        assert!(html.contains(needle), "{lang:?}");
        assert!(html.contains("wayback, otx_url"), "{lang:?}");
        assert!(html.contains("TCP intercept"), "{lang:?}");

        let md = text(&build(
            &inc_snap,
            &ReportOptions {
                lang,
                ..opts(ReportFormat::Md)
            },
        ));
        assert!(md.contains(needle), "{lang:?}");
        assert!(
            md.contains("wayback") && md.contains("otx") && md.contains("TCP intercept"),
            "{lang:?}: {md}"
        );
    }
}

#[test]
fn incomplete_sources_get_a_reason_table_in_the_appendix() {
    use foca_core::api::{IncompleteSource, ScanEnv};

    let why = |id: &str, status: &str, http: Option<u16>| IncompleteSource {
        id: id.into(),
        status: status.into(),
        http,
    };
    let mut snap = fixture().snap.clone();
    let last = snap.scans.last_mut().unwrap();
    last.env = Some(ScanEnv {
        incomplete: true,
        incomplete_sources: ["fuzz", "cc", "startpage", "otx_dns", "recon"]
            .map(String::from)
            .to_vec(),
        incomplete_reasons: vec![
            why("fuzz", "blocked", None),
            why("cc", "error", Some(502)),
            why("startpage", "captcha", None),
            why("otx_dns", "lost", Some(429)),
        ],
        ..Default::default()
    });
    for (lang, rows) in [
        (
            Lang::En,
            [
                "| `fuzz` | stopped: site limited requests |",
                "| `cc` | service unavailable (HTTP 502) |",
                "| `startpage` | captcha |",
                "| `otx_dns` | rate limit (HTTP 429) |",
                "| `recon` | reason not recorded |",
            ],
        ),
        (
            Lang::Uk,
            [
                "| `fuzz` | зупинено: сайт обмежив запити |",
                "| `cc` | сервіс недоступний (HTTP 502) |",
                "| `startpage` | капча |",
                "| `otx_dns` | ліміт запитів (HTTP 429) |",
                "| `recon` | причину не записано |",
            ],
        ),
    ] {
        let o = ReportOptions {
            lang,
            ..opts(ReportFormat::Md)
        };
        let md = text(&build(&snap, &o));
        for r in rows {
            assert!(md.contains(r), "{lang:?}: {r}\n{md}");
        }
        let html = text(&build(
            &snap,
            &ReportOptions {
                lang,
                ..opts(ReportFormat::Html)
            },
        ));
        assert!(html.contains("<span class=\"mono\">cc</span>"), "{lang:?}");
    }
    // A complete scan has no such table.
    let md = text(&build(&fixture().snap, &opts(ReportFormat::Md)));
    assert!(!md.contains("Неполные источники"));
}

// ---------------------------------------------------------------- executive / compliance / lab

#[test]
fn html_styles_warnings_and_lists_custody_in_toc() {
    let snap = &fixture().snap;
    let on = ReportOptions {
        custody: true,
        ..opts(ReportFormat::Html)
    };
    let h = text(&build(snap, &on));
    assert!(h.contains("p.warn {"), "no style for warning paragraphs");
    let toc = h.split("<nav class=\"toc\">").nth(1).unwrap();
    let toc = toc.split("</nav>").next().unwrap();
    assert!(
        toc.contains("href=\"#custody\""),
        "custody missing from ToC"
    );
    assert!(h.contains("<section id=\"custody\">"));
    let off = text(&build(snap, &opts(ReportFormat::Html)));
    assert!(!off.contains("href=\"#custody\""));
}
