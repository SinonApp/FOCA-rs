//! `scope_add_hosts`: bulk-adds out-of-scope names to the scope (dry run stores nothing), keeps
//! exclusions, and the follow-up scan of only those names works.

use crate::common::*;
use serde_json::json;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn scope_add_hosts_dry_run_then_add_and_scan_only_them() {
    let e = env(0).await;
    let id = e.project("example.test").await;
    // a URL target covers only its own host: subdomains are out of scope
    e.call(
        "scope_set",
        json!({ "project": id, "scope": {
            "targets": [{ "v": "https://example.test/", "type": "url" }],
            "excl": ["vpn.example.test"] } }),
    )
    .await;
    let hosts = json!([
        "www.example.test",
        "vpn.example.test",
        "example.test",
        "1.2.3.4"
    ]);
    let dry = e
        .call(
            "scope_add_hosts",
            json!({ "project": id, "hosts": hosts, "dry_run": true }),
        )
        .await;
    assert_eq!(dry["dry_run"], true);
    assert_eq!(dry["added"], json!(["www.example.test"]));
    let sc = e.call("scope_get", json!({ "project": id })).await;
    assert_eq!(
        sc["targets"].as_array().unwrap().len(),
        1,
        "dry run stores nothing"
    );

    let r = e
        .call("scope_add_hosts", json!({ "project": id, "hosts": hosts }))
        .await;
    assert_eq!(r["added"], json!(["www.example.test"]));
    let codes: Vec<&str> = r["skipped"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s["code"].as_str().unwrap())
        .collect();
    assert_eq!(codes, vec!["excluded", "already_in_scope", "invalid"]);
    assert!(r["scope"]["targets"]
        .as_array()
        .unwrap()
        .iter()
        .any(|t| t["v"] == "www.example.test" && t["type"] == "domain"));
    // the exclusion stays and the target was not duplicated on a repeat call
    let again = e
        .call(
            "scope_add_hosts",
            json!({ "project": id, "hosts": ["www.example.test"] }),
        )
        .await;
    assert_eq!(again["added"], json!([]));
    assert_eq!(again["skipped"][0]["code"], "already_in_scope");
    // a scan of only the added names is accepted by the scope check
    e.call(
        "scan_start",
        json!({ "project": id, "profile": "passive", "targets": ["www.example.test"], "sources": ["crt"] }),
    )
    .await;
    e.wait().await;
    let snap = e.snap(&id).await;
    let last = snap["scans"].as_array().unwrap().last().unwrap().clone();
    assert_eq!(last["targets"], json!(["www.example.test"]));
    // invalid calls
    let err = e
        .engine
        .invoke("scope_add_hosts", json!({ "project": id, "hosts": [] }))
        .await
        .unwrap_err();
    assert_eq!(err.code, "bad_args");
}
