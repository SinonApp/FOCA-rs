//! A hung source does not hold up the search stage: the overall timeout (`timeout`) and "skip source"
//! (`scan_skip_source`, status `skipped`); `source` events are emitted as they happen (`wait -> running -> ...`).

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::common::*;
use foca_engine::{Engine, EventSink, FnEvents, MemoryKeys};
use foca_net::testserver::{TestResponse, TestServer};
use serde_json::{json, Value};

/// Spawns a server whose web archive hangs for `hang` seconds while crt.sh answers immediately.
async fn slow_server(hang: u64) -> TestServer {
    TestServer::start(move |r| {
        let p = r.path().to_string();
        if p == "/cdx/search/cdx" {
            return TestResponse::ok(b"[]".to_vec()).delay(Duration::from_secs(hang));
        }
        if p == "/" && r.query("output").is_some() {
            return TestResponse::ok(br#"[{"name_value":"www.example.test"}]"#.to_vec());
        }
        if p == "/collinfo.json" {
            return TestResponse::ok(b"[]".to_vec());
        }
        TestResponse::status(404)
    })
    .await
}

fn engine(
    dir: &std::path::Path,
    base: &str,
    timeout: Duration,
) -> (Engine, Arc<Mutex<Vec<Value>>>) {
    let ev: Arc<Mutex<Vec<Value>>> = Arc::new(Mutex::new(Vec::new()));
    let e2 = ev.clone();
    let sink: Arc<dyn EventSink> = Arc::new(FnEvents(move |e: &Value| {
        e2.lock().unwrap().push(e.clone())
    }));
    let mut cfg = config(dir, base);
    cfg.source_timeout = timeout;
    (
        Engine::open(cfg, Arc::new(MemoryKeys::new()), sink).unwrap(),
        ev,
    )
}

async fn project(e: &Engine) -> String {
    let p = e
        .invoke(
            "project_create",
            json!({ "name": "example.test", "client": "", "targets": ["example.test"], "excludes": [] }),
        )
        .await
        .unwrap();
    p["id"].as_str().unwrap().to_string()
}

fn statuses(ev: &[Value], id: &str) -> Vec<String> {
    ev.iter()
        .filter(|x| x["type"] == "source" && x["id"] == id)
        .map(|x| x["status"].as_str().unwrap_or("").to_string())
        .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn hanging_source_times_out_and_scan_finishes() {
    let dir = tempfile::tempdir().unwrap();
    let srv = slow_server(30).await;
    let (e, ev) = engine(dir.path(), &srv.url(), Duration::from_secs(2));
    let id = project(&e).await;
    let t0 = Instant::now();
    e.invoke(
        "scan_start",
        json!({ "project": id, "profile": "passive", "sources": ["crt", "wayback", "cc"] }),
    )
    .await
    .unwrap();
    assert!(
        e.wait_idle(Duration::from_secs(25)).await,
        "the scan hung on a source"
    );
    assert!(t0.elapsed() < Duration::from_secs(20));
    let ev_all = ev;
    let ev = ev_all.lock().unwrap().clone();
    let wb = statuses(&ev, "wayback");
    assert_eq!(wb.first().map(String::as_str), Some("wait"), "{wb:?}");
    assert!(wb.contains(&"running".to_string()), "{wb:?}");
    assert_eq!(wb.last().map(String::as_str), Some("timeout"), "{wb:?}");
    let last = ev
        .iter()
        .rev()
        .find(|x| x["type"] == "source" && x["id"] == "wayback")
        .unwrap();
    // Wayback is a slow archive: timeout ×3 (budget), 2 s becomes 6 s
    assert!(last["error"].as_str().unwrap().contains("6 с"), "{last}");
    // crt.sh is ok and did not wait for the hung archive; the scan completed
    assert_eq!(statuses(&ev, "crt").last().map(String::as_str), Some("ok"));
    // done may arrive slightly after wait_idle saw the scan end
    tokio::time::sleep(Duration::from_millis(300)).await;
    let ev = ev_all.lock().unwrap().clone();
    let done = ev.iter().find(|x| x["type"] == "done").expect("no done");
    let rec = &done["scan"];
    assert!(
        rec["sources"]
            .as_array()
            .unwrap()
            .iter()
            .any(|s| s["id"] == "wayback" && s["status"] == "timeout"),
        "{rec}"
    );
    // log: source start and end with duration
    let logs = e
        .invoke("logs_get", json!({ "level": "info", "limit": 2000 }))
        .await
        .unwrap();
    let msgs: Vec<&str> = logs
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|l| l["msg"].as_str())
        .collect();
    assert!(
        msgs.iter().any(|m| m.starts_with("wayback: старт")),
        "{msgs:?}"
    );
    assert!(
        msgs.iter().any(|m| m.starts_with("wayback: Timeout")),
        "{msgs:?}"
    );
    assert!(
        msgs.iter().any(|m| m.contains("этап «Поиск», готово за")),
        "{msgs:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn skip_source_unblocks_search() {
    let dir = tempfile::tempdir().unwrap();
    let srv = slow_server(30).await;
    let (e, ev) = engine(dir.path(), &srv.url(), Duration::from_secs(60));
    let id = project(&e).await;
    // before the scan: ok:false
    let r = e
        .invoke("scan_skip_source", json!({ "id": "wayback" }))
        .await
        .unwrap();
    assert_eq!(r["ok"], false);
    assert_eq!(
        e.invoke("scan_skip_source", json!({ "id": "nope" }))
            .await
            .unwrap_err()
            .code,
        "not_found"
    );
    e.invoke(
        "scan_start",
        json!({ "project": id, "profile": "passive", "sources": ["crt", "wayback", "cc"] }),
    )
    .await
    .unwrap();
    // wait until the archive starts hanging
    for _ in 0..200 {
        if statuses(&ev.lock().unwrap(), "wayback").contains(&"running".to_string()) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    let t0 = Instant::now();
    let r = e
        .invoke("scan_skip_source", json!({ "id": "wayback" }))
        .await
        .unwrap();
    assert_eq!(r["ok"], true);
    // a source that has not started can be skipped too; cc is queried in parallel and can finish
    // concurrently right around the skip call (`skipped` or `error` if it completed first)
    let cc_skip = e
        .invoke("scan_skip_source", json!({ "id": "cc" }))
        .await
        .unwrap();
    let cc_ok_to_skip = cc_skip["ok"] == true;
    assert!(e.wait_idle(Duration::from_secs(20)).await);
    assert!(
        t0.elapsed() < Duration::from_secs(10),
        "skipping did not release the stage"
    );
    let mut snap_ev = Vec::new();
    for _ in 0..120 {
        snap_ev = ev.lock().unwrap().clone();
        if snap_ev.iter().any(|x| x["type"] == "done")
            && statuses(&snap_ev, "wayback").last().map(String::as_str) == Some("skipped")
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert_eq!(
        statuses(&snap_ev, "wayback").last().map(String::as_str),
        Some("skipped")
    );
    let cc_last_binding = statuses(&snap_ev, "cc");
    let cc_last = cc_last_binding.last().map(String::as_str);
    if cc_ok_to_skip {
        assert!(
            matches!(cc_last, Some("skipped" | "error")),
            "unexpected cc status after skip: {cc_last:?}"
        );
    } else {
        assert_eq!(cc_last, Some("error"));
    }
    assert!(snap_ev.iter().any(|x| x["type"] == "done"));
    // after the search stage: ok:false
    let r = e
        .invoke("scan_skip_source", json!({ "id": "crt" }))
        .await
        .unwrap();
    assert_eq!(r["ok"], false);
}
