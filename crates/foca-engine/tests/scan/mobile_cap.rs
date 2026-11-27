//! Monthly mobile data limit: the engine counts request bytes only on a mobile network
//! (`Engine::mobile_network`, fed by the app's device monitor) and emits `mobile_cap` once.

use std::sync::Arc;

use foca_engine::MemoryKeys;
use serde_json::{json, Value};

use crate::common;

const MB: u64 = 1024 * 1024;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn mobile_traffic_is_counted_and_cap_is_signalled() {
    let dir = tempfile::tempdir().unwrap();
    let server = common::server(0).await;
    // this month (2026-11 in device local time) is 64 bytes short of a 1 MB limit
    std::fs::write(
        dir.path().join("mobile_usage.json"),
        json!({ "month": "2026-11", "bytes": MB - 64 }).to_string(),
    )
    .unwrap();
    let (engine, events, _) = common::open(dir.path(), &server.url(), Arc::new(MemoryKeys::new()));
    let call = |cmd: &'static str, args: Value| {
        let e = engine.clone();
        async move { e.invoke(cmd, args).await.unwrap() }
    };
    call(
        "settings_set",
        json!({ "patch": { "power": { "lim_on": true, "mob_limit": 1 } } }),
    )
    .await;
    let p = call(
        "project_create",
        json!({ "name": "Contoso", "targets": [{ "v": "example.test", "type": "domain" }] }),
    )
    .await;
    let id = p["id"].as_str().unwrap().to_string();
    let scan = |id: String| {
        let e = engine.clone();
        async move {
            e.invoke(
                "scan_start",
                json!({ "project": id, "profile": "passive", "sources": ["crt", "wayback", "cc"] }),
            )
            .await
            .unwrap();
            assert!(e.wait_idle(std::time::Duration::from_secs(120)).await);
        }
    };

    // Wi-Fi (the default): nothing is counted
    scan(id.clone()).await;
    let u = call("mobile_usage", json!({})).await;
    assert_eq!(u["bytes"], MB - 64, "{u}");
    assert_eq!(u["limit_mb"], 1);
    assert_eq!(u["metered"], false);
    assert_eq!(u["reached"], false);
    assert!(!engine.mobile_cap_reached());

    // mobile data: the scan's bytes count and cross the limit once
    assert!(!engine.mobile_network(true));
    scan(id.clone()).await;
    let u = call("mobile_usage", json!({})).await;
    assert!(u["bytes"].as_u64().unwrap() > MB, "{u}");
    assert_eq!(u["month"], "2026-11");
    assert_eq!(u["reached"], true);
    assert!(engine.mobile_cap_reached());
    let caps: Vec<Value> = events
        .lock()
        .unwrap()
        .iter()
        .filter(|e| e["type"] == "mobile_cap")
        .cloned()
        .collect();
    assert_eq!(caps.len(), 1, "{caps:?}");
    assert_eq!(caps[0]["limit_mb"], 1);
    assert!(caps[0]["used_mb"].as_f64().unwrap() >= 1.0);

    // a raised limit lifts the cap; turning the limit off too
    call(
        "settings_set",
        json!({ "patch": { "power": { "mob_limit": 50 } } }),
    )
    .await;
    assert!(!engine.mobile_cap_reached());
    call(
        "settings_set",
        json!({ "patch": { "power": { "mob_limit": 1, "lim_on": false } } }),
    )
    .await;
    assert!(!engine.mobile_cap_reached());
    assert_eq!(call("mobile_usage", json!({})).await["limit_mb"], 0);
}
