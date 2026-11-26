//! Enabled custom plugins run in the network stage of a real scan: a blocked plugin (passive mode
//! towards the target, or a private address) never sends a request and never fails the scan. A
//! real failure (a private address) ends the `plugins` source as `error` naming the plugin; the
//! passive-mode policy alone ends it as `skipped` with a note and keeps the scan complete.

use crate::common::*;
use serde_json::{json, Value};

fn manifest(id: &str, url: &str) -> Value {
    json!({
        "id": id, "name": id, "version": "1.0.0", "kind": "source", "runtime": "declarative",
        "permissions": ["net:passive"], "enabled": true,
        "declarative": { "url_template": url, "extract_kind": "hosts", "pattern": "([a-z0-9.-]+\\.example\\.test)" }
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn blocked_plugins_do_not_fail_the_scan_and_send_nothing() {
    let e = env(0).await;
    let id = e.project("example.test").await;
    e.call(
        "plugin_install",
        json!({ "manifest": manifest("target-probe", "https://{domain}/hosts.txt") }),
    )
    .await;
    e.call(
        "plugin_install",
        json!({ "manifest": manifest("local-probe", "http://127.0.0.1:9/{domain}") }),
    )
    .await;
    e.call(
        "scan_start",
        json!({ "project": id, "profile": "passive", "sources": ["crt", "plugins"] }),
    )
    .await;
    e.wait().await;
    let ev = e.events();
    assert_eq!(ev.last().unwrap()["type"], "done", "scan finished");
    let last: Vec<&Value> = ev
        .iter()
        .filter(|x| x["type"] == "source" && x["id"] == "plugins")
        .collect();
    assert!(
        last.iter().any(|x| x["status"] == "running"),
        "plugin step started: {last:?}"
    );
    let fin = last.last().unwrap();
    assert_eq!(fin["status"], "error", "{fin}");
    let err = fin["error"].as_str().unwrap_or("");
    assert!(err.contains("target-probe"), "{err}");
    assert!(
        err.contains("local-probe") && err.contains("blocked_ssrf"),
        "{err}"
    );
    let log = e.call("request_log_get", json!({ "project": id })).await;
    let rows = log["rows"]
        .as_array()
        .or_else(|| log.as_array())
        .cloned()
        .unwrap_or_default();
    assert!(
        !rows.iter().any(|r| r["module"] == "plugin"),
        "blocked plugins sent no request"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn no_custom_plugins_turns_the_source_off() {
    let e = env(0).await;
    let id = e.project("example.test").await;
    e.call(
        "scan_start",
        json!({ "project": id, "profile": "passive", "sources": ["crt", "plugins"] }),
    )
    .await;
    e.wait().await;
    let st: Vec<Value> = e
        .events()
        .into_iter()
        .filter(|x| x["type"] == "source" && x["id"] == "plugins")
        .collect();
    assert_eq!(st.last().unwrap()["status"], "off", "{st:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn passive_policy_skip_is_not_an_error_or_incomplete() {
    let e = env(0).await;
    let id = e.project("example.test").await;
    e.call(
        "plugin_install",
        json!({ "manifest": manifest("target-probe", "https://{domain}/hosts.txt") }),
    )
    .await;
    e.call(
        "scan_start",
        json!({ "project": id, "profile": "passive", "sources": ["crt", "plugins"] }),
    )
    .await;
    e.wait().await;
    let st: Vec<Value> = e
        .events()
        .into_iter()
        .filter(|x| x["type"] == "source" && x["id"] == "plugins")
        .collect();
    let fin = st.last().unwrap();
    assert_eq!(fin["status"], "skipped", "{st:?}");
    assert!(
        fin["error"].as_str().unwrap_or("").contains("target-probe"),
        "the note names the plugin: {fin}"
    );
    let snap = e.snap(&id).await;
    let scan = snap["scans"].as_array().unwrap().last().unwrap().clone();
    assert_eq!(scan["status"], "done", "{scan}");
    let env = &scan["env"];
    assert!(
        !env["incomplete_sources"]
            .as_array()
            .map(|a| a.iter().any(|x| x == "plugins"))
            .unwrap_or(false),
        "{env}"
    );
}
