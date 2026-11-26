//! Site reconnaissance stage on offline fixtures: the passive profile takes the home page, favicon
//! and JavaScript from the archive copy (no requests to the target), grep.app with a challenge
//! yields `blocked` without failing, buckets are only listed; the `recon` snapshot and `recon.*` findings.

use crate::common::*;
use serde_json::json;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn passive_recon_from_archive() {
    let e = env(0).await;
    let id = e.project("example.test").await;
    e.call(
        "scan_start",
        json!({ "project": id, "profile": "passive",
            "sources": ["recon", "wellknown", "buckets", "grepapp"] }),
    )
    .await;
    e.wait().await;
    let s = e.snap(&id).await;
    let r = &s["recon"];
    assert_eq!(r["level"], "external", "{r}");
    assert_eq!(r["sites"][0]["via"], "archive", "{r}");
    let tech: Vec<&str> = r["tech"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    assert!(
        tech.contains(&"jQuery") && tech.contains(&"Nginx"),
        "{tech:?}"
    );
    let jq = r["tech"]
        .as_array()
        .unwrap()
        .iter()
        .find(|t| t["name"] == "jQuery")
        .unwrap();
    assert_eq!(jq["version"], "1.8.2");
    assert!(jq["outdated"].is_string());
    assert!(r["sites"][0]["favicon"]["mmh3"].is_number(), "{r}");
    assert_eq!(r["analytics"][0]["id"], "G-ABC123XYZ9");
    assert!(r["endpoints"]
        .as_array()
        .unwrap()
        .iter()
        .any(|x| x["url"].as_str().unwrap().contains("/api/v2/users")));
    let sec = &r["secrets"][0];
    assert_eq!(sec["kind"], "aws_access_key");
    assert!(!sec["mask"].as_str().unwrap().contains("Q7XK2M9PLR4TZW8N"));
    assert!(
        r["hidden_paths"]
            .as_array()
            .unwrap()
            .iter()
            .any(|p| p["path"] == "/admin/"),
        "{r}"
    );
    assert_eq!(r["buckets"][0]["name"], "contoso-backup");
    assert_eq!(r["buckets"][0]["status"], "unchecked");
    assert_eq!(r["sources"]["grepapp"]["status"], "blocked", "{r}");
    assert!(r["code"].is_null());
    // reconnaissance findings are in the shared list; the secret has no value
    let rec: Vec<&serde_json::Value> = s["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|f| f["module"] == "recon")
        .collect();
    assert!(!rec.is_empty());
    let all = serde_json::to_string(&s).unwrap();
    assert!(!all.contains("Q7XK2M9PLR4TZW8N"), "secret in the snapshot");
    let scans = s["scans"].as_array().unwrap();
    assert_eq!(scans.last().unwrap()["status"], "done");
    // the scan snapshot carries technologies for scan comparison
    assert_eq!(scans.last().unwrap()["snapshot"]["tech"]["jQuery"], "1.8.2");
}

/// Reconnaissance did not answer (standard profile: the bench site is not served): earlier data is
/// kept, the snapshot is marked incomplete, and technologies do not "disappear" from it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn failed_recon_keeps_previous_data() {
    let e = env(0).await;
    let id = e.project("example.test").await;
    e.call(
        "scan_start",
        json!({ "project": id, "profile": "passive", "sources": ["recon", "wellknown"] }),
    )
    .await;
    e.wait().await;
    e.call(
        "scan_start",
        json!({ "project": id, "profile": "std", "sources": ["recon"] }),
    )
    .await;
    e.wait().await;
    let s = e.snap(&id).await;
    let st: Vec<String> = e
        .events()
        .iter()
        .filter(|x| x["type"] == "source" && x["id"] == "recon")
        .map(|x| x["status"].as_str().unwrap_or("").to_string())
        .collect();
    assert_eq!(st.last().map(String::as_str), Some("error"), "{st:?}");
    let r = &s["recon"];
    let tech: Vec<&str> = r["tech"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    assert!(
        tech.contains(&"jQuery") && tech.contains(&"Nginx"),
        "{tech:?}"
    );
    assert_eq!(r["sites"][0]["incomplete"], true, "{r}");
    let scans = s["scans"].as_array().unwrap();
    let last = scans.last().unwrap();
    assert_eq!(last["snapshot"]["tech"]["jQuery"], "1.8.2", "{last}");
    assert!(last["incomplete"]
        .as_array()
        .unwrap()
        .iter()
        .any(|x| x == "recon"));
    assert_eq!(scans[0]["incomplete"], json!([]));
}
