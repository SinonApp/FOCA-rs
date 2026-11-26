//! Report integration tests: DOCX report: OOXML validity, layout and tables.

mod common;

use common::*;

#[test]
fn docx_reports_are_valid_ooxml_with_png_chart_and_redacted_secrets() {
    let snap = &fixture().snap;
    let validate_docx = |bytes: &[u8]| {
        let mut ar = zip::ZipArchive::new(std::io::Cursor::new(bytes)).expect("valid docx zip");
        let required = [
            "[Content_Types].xml",
            "_rels/.rels",
            "docProps/core.xml",
            "docProps/app.xml",
            "word/_rels/document.xml.rels",
            "word/styles.xml",
            "word/document.xml",
            "word/media/chart_sev.png",
        ];
        let mut zip_names = Vec::new();
        for i in 0..ar.len() {
            zip_names.push(ar.by_index(i).unwrap().name().unwrap().to_string());
        }
        for req in required {
            assert!(
                zip_names.iter().any(|n| n == req),
                "DOCX missing {req}; got {zip_names:?}"
            );
        }
        // Parse every XML & .rels entry with quick-xml to guarantee well-formed OOXML.
        for name in &zip_names {
            if !name.ends_with(".xml") && !name.ends_with(".rels") {
                continue;
            }
            let mut body = String::new();
            ar.by_name(name).unwrap().read_to_string(&mut body).unwrap();
            let mut r = quick_xml::Reader::from_str(&body);
            let mut depth = 0usize;
            loop {
                match r.read_event() {
                    Ok(quick_xml::events::Event::Start(_)) => depth += 1,
                    Ok(quick_xml::events::Event::End(_)) => {
                        depth = depth.checked_sub(1).expect("balanced end tag");
                    }
                    Ok(quick_xml::events::Event::Eof) => break,
                    Err(e) => panic!("{name}: malformed XML: {e}"),
                    _ => {}
                }
            }
            assert_eq!(depth, 0, "{name}: unclosed XML tags");
        }
        let mut doc_xml = String::new();
        ar.by_name("word/document.xml")
            .unwrap()
            .read_to_string(&mut doc_xml)
            .unwrap();
        assert!(doc_xml.contains("r:embed=\"rIdChart1\""));
        let mut rels_xml = String::new();
        ar.by_name("word/_rels/document.xml.rels")
            .unwrap()
            .read_to_string(&mut rels_xml)
            .unwrap();
        assert!(rels_xml.contains("Target=\"media/chart_sev.png\""));

        let mut png = Vec::new();
        ar.by_name("word/media/chart_sev.png")
            .unwrap()
            .read_to_end(&mut png)
            .unwrap();
        assert!(png.starts_with(b"\x89PNG\r\n\x1a\n"));
        assert!(png.windows(4).any(|w| w == b"IHDR"));
        assert!(png.windows(4).any(|w| w == b"IDAT"));
        assert!(png.windows(4).any(|w| w == b"IEND"));
        doc_xml
    };

    for (tpl, lang) in [
        (Template::Full, Lang::Ru),
        (Template::Executive, Lang::Uk),
        (Template::Compliance, Lang::En),
        (Template::Lab, Lang::Uk),
    ] {
        let mut o = tpl_opts(tpl, lang, ReportFormat::Docx);
        o.custody = true;
        let a = build(snap, &o);
        assert!(a.file_name.ends_with(".docx"), "{}", a.file_name);
        let xml = validate_docx(&a.bytes);
        for sec in snap.secrets.iter().filter(|s| s.kind != "host") {
            let v = sec.value.expose();
            if v.len() >= 8 {
                assert!(!xml.contains(v), "raw secret leaked in DOCX {tpl:?}");
            }
        }
    }

    // Hostile XML characters / XSS payloads still produce valid XML.
    let bad = hostile();
    let mut ho = tpl_opts(Template::Full, Lang::En, ReportFormat::Docx);
    ho.custody = true;
    let a_bad = build(&bad, &ho);
    let bad_xml = validate_docx(&a_bad.bytes);
    assert!(!bad_xml.contains("<script>alert(1)</script>"));
}

#[test]
fn docx_multiline_text_uses_paragraphs_and_sections_start_new_pages() {
    let mut snap = fixture().snap.clone();
    snap.findings[0].description = "First sentence.\nSecond sentence.".into();
    snap.findings[0].evidence = "line one\nline two\nline three".into();
    snap.hosts[0].tech = "Apache 2.4\nPHP 8.1".into();
    let xml = docx_xml(&build(&snap, &opts(ReportFormat::Docx)));
    assert!(!xml.contains("<w:br/>"), "line breaks inside runs");
    for l in [
        "First sentence.",
        "Second sentence.",
        "line two",
        "line three",
    ] {
        assert!(
            xml.contains(&format!(
                "<w:t xml:space=\"preserve\">{l}</w:t></w:r></w:p>"
            )),
            "{l} is not its own paragraph"
        );
    }
    let breaks = xml.matches("<w:pageBreakBefore/>").count();
    assert!(breaks >= 3, "page breaks: {breaks}");
}

#[test]
fn docx_classic_has_infra_sections_finding_fields_and_log_note() {
    let mut s = fixture().snap.clone();
    s.hosts[0].name = "www.example.com".into();
    s.ports = serde_json::json!([{ "host": "www.example.com", "ports": [
        { "port": 443, "proto": "tcp", "service": "https", "product": "nginx", "version": "1.18.0", "source": "scan" }
    ] }]);
    s.infra = serde_json::json!({
        "mail_policy": [{ "domain": "example.com", "dnssec": "unsigned" }],
        "saas": [{ "domain": "example.com", "hits": [{ "id": "google", "name": "Google Workspace" }] }],
    });
    s.recon = serde_json::json!({ "tech": [
        { "name": "WordPress", "version": "6.1", "category": "cms", "host": "www.example.com" }
    ] });
    let id = s.findings[0].id;
    let f = &mut s.findings[0];
    f.cve = vec!["CVE-2021-44228".into()];
    f.mitre = "T1190 · Exploit Public-Facing Application".into();
    f.url = Some("https://www.example.com/login".into());
    let entry = fixture().log[0].clone();
    let log: Vec<RequestEntry> = (0..150).map(|_| entry.clone()).collect();
    let o = ReportOptions {
        lang: Lang::En,
        ..opts(ReportFormat::Docx)
    };
    let xml = docx_xml(&build_report_with_log(&s, &log, &o, NOW));
    for want in [
        "Open ports",
        "nginx 1.18.0",
        "Mail policies",
        "SaaS and clouds",
        "Google Workspace",
        "Website and technologies",
        "WordPress",
        "CVE-2021-44228",
        "MITRE ATT&amp;CK",
        "https://www.example.com/login",
        "Category",
        "Provenance",
        "Showing 100 of 150 requests",
    ] {
        assert!(xml.contains(want), "DOCX lacks {want}");
    }
    assert!(s.findings.iter().any(|f| f.id == id));
}

#[test]
fn docx_severity_table_is_a_colored_chart_legend() {
    let xml = docx_xml(&build(&fixture().snap, &opts(ReportFormat::Docx)));
    for fill in ["FECACA", "FED7AA", "FDE68A", "BFDBFE", "E2E8F0"] {
        assert!(
            xml.contains(&format!("w:fill=\"{fill}\"")),
            "no legend color {fill}"
        );
    }
}
