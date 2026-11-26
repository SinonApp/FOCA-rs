//! Report integration tests: Table exports, Maltego, STIX 2.1, httpx and nuclei.

mod common;

use common::*;

#[test]
fn export_all_kinds_and_formats() {
    let snap = &fixture().snap;
    let log = &fixture().log;
    let eo = ExportOptions {
        date: "2026-11-20".into(),
        ..Default::default()
    };
    let kinds = [
        ExportKind::Findings,
        ExportKind::Users,
        ExportKind::Emails,
        ExportKind::Paths,
        ExportKind::Software,
        ExportKind::Hosts,
        ExportKind::Docs,
        ExportKind::Log,
        ExportKind::All,
    ];
    let fmts = [
        ExportFormat::List,
        ExportFormat::Dict,
        ExportFormat::Csv,
        ExportFormat::Json,
        ExportFormat::MaltegoCsv,
        ExportFormat::Graphml,
        ExportFormat::Md,
    ];
    for k in kinds {
        for f in fmts {
            let a = export_with_log(snap, log, k, f, &eo);
            assert!(a.file_name.starts_with("contoso_"), "{}", a.file_name);
            assert!(a.file_name.contains("_2026-11-20."), "{}", a.file_name);
            assert!(!a.bytes.is_empty(), "{k:?}/{f:?}");
            if matches!(f, ExportFormat::Json) {
                let v: Value = serde_json::from_slice(&a.bytes).unwrap();
                assert_eq!(v["count"].as_u64(), Some(a.count as u64));
                assert_eq!(v["schema_version"], 1);
            }
        }
    }
    let users = export_with_log(snap, log, ExportKind::Users, ExportFormat::Csv, &eo);
    assert_eq!(users.file_name, "contoso_users_2026-11-20.csv");
    assert_eq!(users.count, snap.people.len());
    let lg = export_with_log(snap, log, ExportKind::Log, ExportFormat::Csv, &eo);
    assert_eq!(lg.count, 5);
    assert_eq!(lg.file_name, "contoso_requests-log_2026-11-20.csv");
    // Selected columns.
    let cols = ExportOptions {
        columns: Some(vec!["name".into(), "login".into(), "nope".into()]),
        bom: false,
        ..eo.clone()
    };
    let c = export_with_log(snap, log, ExportKind::Users, ExportFormat::Csv, &cols);
    assert!(String::from_utf8(c.bytes)
        .unwrap()
        .starts_with("name,login\r\n"));
    // Finding selection by id.
    let id = snap.findings[0].id;
    let one = export_with_log(
        snap,
        log,
        ExportKind::Findings,
        ExportFormat::Json,
        &ExportOptions {
            ids: Some(vec![id]),
            ..eo.clone()
        },
    );
    assert_eq!(one.count, 1);
    // Markdown "many notes" mode: a ZIP vault for Obsidian.
    let many = export_with_log(
        snap,
        log,
        ExportKind::Users,
        ExportFormat::Md,
        &ExportOptions {
            md_layout: foca_report::MdLayout::Many,
            ..eo.clone()
        },
    );
    assert!(many.file_name.ends_with(".zip") && many.bytes.starts_with(b"PK"));
    let gm = export_with_log(snap, log, ExportKind::All, ExportFormat::Graphml, &eo);
    assert!(gm.file_name.ends_with(".graphml") && gm.count > 10);
}

/// Every finding ends up in the Maltego/GraphML graph: via its host, source document or the
/// project domain.
#[test]
fn maltego_graph_links_every_finding() {
    let fx = fixture();
    let o = ExportOptions::default();
    let a = export_with_log(
        &fx.snap,
        &fx.log,
        ExportKind::Findings,
        ExportFormat::MaltegoCsv,
        &o,
    );
    let text = String::from_utf8(a.bytes).unwrap();
    for f in &fx.snap.findings {
        assert!(
            text.contains(&format!("F-{} ", f.id)),
            "finding {} has no link in the graph",
            f.id
        );
    }
    let g = export_with_log(
        &fx.snap,
        &fx.log,
        ExportKind::Findings,
        ExportFormat::Graphml,
        &o,
    );
    assert!(g.count >= fx.snap.findings.len());
}

#[test]
fn stix_2_1_bundle_valid_referential_integrity_and_never_leaks_secrets() {
    let snap = &fixture().snap;
    let a = export_with_log(
        snap,
        &fixture().log,
        ExportKind::All,
        ExportFormat::Stix,
        &ExportOptions {
            include_secrets: true,
            redact_pii: false,
            pretty: true,
            ..Default::default()
        },
    );
    assert!(a.file_name.ends_with(".json") && a.file_name.contains("stix"));
    assert!(!a.secrets, "STIX bundle must never expose raw secrets");
    assert!(a.pii_redacted);
    let txt = String::from_utf8(a.bytes).unwrap();
    for sec in snap.secrets.iter().filter(|s| s.kind != "host") {
        let v = sec.value.expose();
        if v.len() >= 8 {
            assert!(!txt.contains(v), "raw secret leaked in STIX bundle");
        }
    }

    let bundle: Value = serde_json::from_str(&txt).unwrap();
    assert_eq!(bundle["type"], "bundle");
    assert!(bundle["id"].as_str().unwrap().starts_with("bundle--"));
    let objects = bundle["objects"].as_array().unwrap();
    assert!(!objects.is_empty());

    let mut all_ids = std::collections::BTreeSet::new();
    let mut types = std::collections::BTreeSet::new();
    for obj in objects {
        let ty = obj["type"].as_str().unwrap();
        let id = obj["id"].as_str().unwrap();
        assert_eq!(obj["spec_version"], "2.1", "{id}");
        assert!(id.starts_with(&format!("{ty}--")), "{id} vs {ty}");
        let uuid = id.split_once("--").unwrap().1;
        assert_eq!(uuid.len(), 36, "bad STIX UUID: {id}");
        assert!(all_ids.insert(id.to_string()), "duplicate STIX id {id}");
        types.insert(ty.to_string());
    }
    assert!(types.contains("identity"));
    assert!(types.contains("domain-name"));
    assert!(types.contains("indicator"));
    assert!(types.contains("relationship"));

    // Verify referential integrity across every relationship/ref field.
    for obj in objects {
        if let Some(c) = obj.get("created_by_ref").and_then(Value::as_str) {
            assert!(all_ids.contains(c), "missing created_by_ref {c}");
        }
        if obj["type"] == "relationship" {
            let src = obj["source_ref"].as_str().unwrap();
            let tgt = obj["target_ref"].as_str().unwrap();
            assert!(all_ids.contains(src), "dangling source_ref {src}");
            assert!(all_ids.contains(tgt), "dangling target_ref {tgt}");
        }
        for arr_key in ["object_refs", "resolves_to_refs"] {
            if let Some(arr) = obj.get(arr_key).and_then(Value::as_array) {
                for r in arr {
                    let id = r.as_str().unwrap();
                    assert!(all_ids.contains(id), "dangling {arr_key} {id}");
                }
            }
        }
    }
}

#[test]
fn httpx_and_nuclei_exports_are_clean_and_deduplicated() {
    let snap = &fixture().snap;
    for (fmt, tag) in [
        (ExportFormat::Httpx, "httpx"),
        (ExportFormat::Nuclei, "nuclei"),
    ] {
        let a = export_with_log(
            snap,
            &fixture().log,
            ExportKind::All,
            fmt,
            &ExportOptions {
                include_secrets: true,
                ..Default::default()
            },
        );
        assert!(a.file_name.ends_with(".txt") && a.file_name.contains(tag));
        let body = String::from_utf8(a.bytes).unwrap();
        let lines: Vec<&str> = body.lines().collect();
        assert!(!lines.is_empty());
        assert_eq!(lines.len(), a.count);
        let uniq: std::collections::BTreeSet<&str> = lines.iter().copied().collect();
        assert_eq!(uniq.len(), lines.len(), "{tag}: duplicate lines");
        assert!(lines
            .iter()
            .all(|l| !l.is_empty() && !l.contains("10.0.0.")));
        for sec in snap.secrets.iter().filter(|s| s.kind != "host") {
            let v = sec.value.expose();
            if v.len() >= 8 {
                assert!(!body.contains(v), "raw secret leaked in {tag}");
            }
        }
    }
}

#[test]
fn stix_drops_urls_that_carried_secrets() {
    let mut snap = fixture().snap.clone();
    let secret = snap
        .secrets
        .iter()
        .filter(|s| s.kind != "host")
        .map(|s| s.value.expose().to_string())
        .find(|v| v.len() >= 8 && v.chars().all(|c| c.is_ascii_alphanumeric()))
        .expect("fixture has a URL-safe secret");
    let leaky = format!("https://example.com/api?key={secret}");
    snap.findings[0].url = Some(leaky);
    snap.findings[1].url = Some("https://example.com/plain".into());
    let a = export_with_log(
        &snap,
        &fixture().log,
        ExportKind::All,
        ExportFormat::Stix,
        &ExportOptions {
            pretty: true,
            ..Default::default()
        },
    );
    let txt = String::from_utf8(a.bytes).unwrap();
    assert!(!txt.contains(&secret));
    assert!(!txt.contains("example.com/api?key="), "masked URL kept");
    for marker in ["[скрыто]", "[hidden]", "[приховано]", "••"] {
        assert!(
            !txt.contains(&format!("key={marker}")),
            "placeholder {marker} in a URL"
        );
    }
    assert!(txt.contains("https://example.com/plain"));
}
