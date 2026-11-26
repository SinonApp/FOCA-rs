//! Built-in reference offline case (`demo_case_import`): a project from the embedded synthetic
//! archive with every demo feature, without a single network request.

use std::time::Instant;

use crate::common::*;
use serde_json::{json, Value};

#[tokio::test]
async fn demo_case_imports_offline_with_all_features() {
    let e = env(0).await;
    // language left at "auto" on a Ukrainian device: the default name follows the UI language
    e.call("settings_set", json!({ "patch": { "lang": "auto" } }))
        .await;
    e.call("i18n_bundle", json!({ "device_locale": "uk-UA" }))
        .await;
    let t0 = Instant::now();
    let r = e.call("demo_case_import", json!({})).await;
    let took = t0.elapsed();
    let id = r["project"].as_str().expect("project id").to_string();
    // 12 documents + the archive itself; generous bound for unoptimised test builds.
    assert_eq!(r["imported"].as_u64(), Some(13), "{r}");
    assert_eq!(r["errors"].as_array().map(Vec::len), Some(0), "{r}");
    assert_eq!(r["demo_case"], true);
    assert!(took.as_secs_f32() < 20.0, "import took {took:?}");
    eprintln!("demo_case_import: {took:?}");

    let list = e.call("project_list", json!({})).await;
    let p = list
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["id"] == id.as_str())
        .expect("project listed");
    assert_eq!(p["name"], "Еталонний кейс", "{p}");
    // imported documents and findings are assessed without a scan
    assert!(p["risk"].as_u64().is_some_and(|r| r > 0), "{p}");
    assert!(p["findings"].as_u64().unwrap_or(0) > 0, "{p}");

    // No network at all: neither the test server nor the request journal saw a request.
    assert!(e.server.requests().is_empty(), "{:?}", e.server.requests());
    let log = e
        .call("request_log_get", json!({ "project": id, "limit": 100 }))
        .await;
    assert_eq!(log.as_array().map(Vec::len).unwrap_or(0), 0, "{log}");

    let s = e.snap(&id).await;
    let rules: Vec<&str> = s["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|f| f["provenance"]["rule"].as_str())
        .collect();
    for want in [
        "doc.bad_redaction",
        "doc.signer_identity",
        "gps",
        "doc.lineage",
        "doc.hidden_content",
        "doc.data_connection",
        "pdf-revisions",
    ] {
        assert!(rules.contains(&want), "no {want} in {rules:?}");
    }
    assert!(rules.iter().any(|r| r.starts_with("doc.lnk_")), "{rules:?}");
    assert!(rules.iter().any(|r| r.starts_with("mail.")), "{rules:?}");

    // Link graph and internal network map have data.
    let ins = e.call("insights_get", json!({ "project": id })).await;
    let n = |v: &Value| v.as_array().map(Vec::len).unwrap_or(0);
    assert!(n(&ins["graph"]["nodes"]) > 5, "{}", ins["graph"]);
    assert!(n(&ins["netmap"]["nodes"]) > 0, "{}", ins["netmap"]);
    assert!(ins["counts"]["lineages"].as_u64().unwrap_or(0) >= 1);

    // The laboratory-work report builds from it.
    let rep = e
        .call(
            "report_build",
            json!({ "project": id, "template": "lab", "opts": { "fmt": "html", "lang": "UA" } }),
        )
        .await;
    let html = std::fs::read_to_string(rep["path"].as_str().unwrap()).unwrap();
    assert!(html.contains("Лабораторна робота") && html.contains("CWE-212"));
    assert!(html.contains("Виконав") && html.contains("Перевірив"));

    // A second import creates another project; a custom name is honoured.
    let r2 = e
        .call("demo_case_import", json!({ "name": "Demo case" }))
        .await;
    assert_ne!(r2["project"], r["project"]);
    assert!(e.server.requests().is_empty());
}
