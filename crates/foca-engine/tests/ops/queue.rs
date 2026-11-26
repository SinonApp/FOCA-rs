//! Scan queue: projects scanned one after another through the regular `scan_start`, never two
//! scans at once (manual or scheduled monitoring scans make the queue wait), a shared pause, stop
//! of the current scan pausing the queue, removal, and continuation after a process restart.

use std::sync::Arc;
use std::time::Duration;

use crate::common::*;
use serde_json::{json, Value};

async fn queue(e: &foca_engine::Engine) -> Value {
    e.invoke("queue_list", json!({})).await.unwrap()
}

/// Polls `queue_list` until `pred` holds (60 s at most).
async fn wait_queue(e: &foca_engine::Engine, what: &str, pred: impl Fn(&Value) -> bool) -> Value {
    for _ in 0..1200 {
        let q = queue(e).await;
        if pred(&q) {
            return q;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("queue: {what}, {}", queue(e).await);
}

async fn wait_paused_any(e: &foca_engine::Engine) {
    for _ in 0..3000 {
        if e.invoke("scan_status", json!({})).await.unwrap()["paused"] == true {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("the scan never paused");
}

fn scans(snap: &Value) -> Vec<Value> {
    snap["scans"].as_array().cloned().unwrap_or_default()
}

const ARGS: &str = r#"{ "sources": ["wayback"] }"#;

fn args() -> Value {
    serde_json::from_str(ARGS).unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn queue_scans_projects_one_after_another() {
    let e = env(0).await;
    let p1 = e.project("q1.test").await;
    let p2 = e.project("q2.test").await;
    let q = e
        .call(
            "queue_add",
            json!({ "projects": [p1, p2], "profile": "passive", "args": args() }),
        )
        .await;
    assert_eq!(q["total"], 2);
    assert_eq!(q["added"].as_array().unwrap().len(), 2);
    // a project already waiting is not queued twice
    let again = e
        .call(
            "queue_add",
            json!({ "projects": [p2], "profile": "passive" }),
        )
        .await;
    assert_eq!(again["skipped"], json!([p2]));
    assert_eq!(again["total"], 2);

    let q = wait_queue(&e.engine, "both done", |q| q["done"] == 2).await;
    assert_eq!(q["percent"], 100);
    assert_eq!(q["running"], false);
    for it in q["items"].as_array().unwrap() {
        assert_eq!(it["status"], "done", "{it}");
        assert!(it["scan_id"].is_string());
    }
    for p in [&p1, &p2] {
        let s = scans(&e.snap(p).await);
        assert_eq!(s.len(), 1);
        assert_eq!(s[0]["status"], "done");
        assert_eq!(s[0]["profile_id"], "passive");
    }
    // strictly sequential: the second scan starts after the first one is done
    let ev = e.events();
    let pos = |t: &str, p: &str| {
        ev.iter()
            .position(|x| x["type"] == t && x["project"] == p)
            .unwrap_or_else(|| panic!("no {t} for {p}"))
    };
    assert!(pos("done", &p1) < pos("started", &p2));
    // queue events carry the current item, its index and the overall percentage
    let qe: Vec<&Value> = ev.iter().filter(|x| x["type"] == "queue").collect();
    assert!(qe
        .iter()
        .any(|x| x["current"]["index"] == 1 && x["current"]["project"] == p2));
    let pct: Vec<u64> = qe.iter().filter_map(|x| x["percent"].as_u64()).collect();
    assert!(pct.windows(2).all(|w| w[0] <= w[1]), "{pct:?}");
    assert_eq!(*pct.last().unwrap(), 100);

    // clearing removes finished items; the file disappears with the last item
    let q = e.call("queue_clear", json!({})).await;
    assert_eq!(q["total"], 0);
    assert!(!e.dir.path().join("scan_queue.json").exists());
    let err = e.err("queue_add", json!({ "projects": ["nope"] })).await;
    assert_eq!(err.code, "not_found");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn queue_waits_for_other_scans_and_stops_with_the_current_one() {
    let e = env(0).await;
    let p1 = e.project("w1.test").await;
    let p2 = e.project("w2.test").await;
    let p3 = e.project("w3.test").await;
    // a manual scan is running (paused at meta): the queue must wait for it
    *e.pause_at.lock().unwrap() = Some("meta".into());
    e.call(
        "scan_start",
        json!({ "project": p1, "profile": "passive", "sources": ["wayback"] }),
    )
    .await;
    e.wait_paused("meta").await;
    *e.pause_at.lock().unwrap() = None;
    e.call(
        "queue_add",
        json!({ "projects": [p2, p3], "profile": "passive", "args": args() }),
    )
    .await;
    let q = wait_queue(&e.engine, "waiting", |q| q["waiting"] == true).await;
    assert_eq!(q["running"], false);
    assert!(scans(&e.snap(&p2).await).is_empty(), "nothing started yet");
    e.call("scan_resume", json!({})).await;
    e.wait().await;

    // the queue takes over: pause the first queued scan at meta, then the shared pause
    *e.pause_at.lock().unwrap() = Some("meta".into());
    wait_queue(&e.engine, "p2 running", |q| q["current"]["project"] == p2).await;
    wait_paused_any(&e.engine).await;
    *e.pause_at.lock().unwrap() = None;
    // a scheduled monitoring rescan cannot start a second scan
    let busy = e
        .err(
            "scan_start",
            json!({ "project": p1, "profile": "passive", "trigger": "schedule" }),
        )
        .await;
    assert_eq!(busy.code, "busy");
    let q = e.call("queue_pause", json!({})).await;
    assert_eq!(q["paused"], true);
    assert_eq!(q["pause_reason"], "user");
    // the user stops the current scan: the item is stopped, the queue stays paused, p3 waits
    e.call("scan_stop", json!({ "reason": "user" })).await;
    let q = wait_queue(&e.engine, "p2 stopped", |q| {
        q["items"][0]["status"] == "stopped"
    })
    .await;
    assert_eq!(q["paused"], true);
    assert_eq!(q["items"][0]["reason"], "user");
    assert_eq!(q["items"][1]["status"], "pending");
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert!(scans(&e.snap(&p3).await).is_empty());

    let q = e.call("queue_resume", json!({})).await;
    assert_eq!(q["paused"], false);
    let q = wait_queue(&e.engine, "p3 done", |q| q["items"][1]["status"] == "done").await;
    assert_eq!(q["done"], 2);
    assert_eq!(q["percent"], 100);
    assert_eq!(scans(&e.snap(&p2).await)[0]["status"], "stopped");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn removing_the_running_item_moves_on() {
    let e = env(0).await;
    let p1 = e.project("r1.test").await;
    let p2 = e.project("r2.test").await;
    *e.pause_at.lock().unwrap() = Some("meta".into());
    let q = e
        .call(
            "queue_add",
            json!({ "projects": [p1, p2], "profile": "passive", "args": args() }),
        )
        .await;
    let first = q["items"][0]["id"].as_str().unwrap().to_string();
    wait_paused_any(&e.engine).await;
    *e.pause_at.lock().unwrap() = None;
    let q = e.call("queue_remove", json!({ "id": first })).await;
    assert_eq!(q["total"], 1);
    let q = wait_queue(&e.engine, "p2 done", |q| q["done"] == 1).await;
    assert_eq!(q["paused"], false, "a removal does not pause the queue");
    let s1 = scans(&e.snap(&p1).await);
    assert_eq!(s1[0]["status"], "stopped");
    assert_eq!(s1[0]["reason"], "queue");
    assert_eq!(scans(&e.snap(&p2).await)[0]["status"], "done");
    let err = e.err("queue_remove", json!({ "id": "q999" })).await;
    assert_eq!(err.code, "not_found");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn queue_continues_after_a_process_restart() {
    let dir = tempfile::tempdir().unwrap();
    let srv = server(0).await;
    let keys = Arc::new(foca_engine::MemoryKeys::new());
    let (en, _ev, pause_at) = open(dir.path(), &srv.url(), keys.clone());
    let mk = |n: &str| json!({ "name": n, "targets": [{ "v": "example.test", "type": "domain" }], "excludes": [] });
    let p1 = en.invoke("project_create", mk("k1.test")).await.unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();
    let p2 = en.invoke("project_create", mk("k2.test")).await.unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();
    *pause_at.lock().unwrap() = Some("meta".into());
    en.invoke(
        "queue_add",
        json!({ "projects": [p1, p2], "profile": "passive", "args": args() }),
    )
    .await
    .unwrap();
    wait_paused_any(&en).await;
    let sid = queue(&en).await["items"][0]["scan_id"]
        .as_str()
        .unwrap()
        .to_string();
    // the system kills the process mid-scan
    en.abandon().await;
    drop(en);

    // next launch: the queue continues by itself, resuming the same scan record
    let (en2, ev2, _) = open_with(dir.path(), &srv.url(), keys, |c| {
        c.queue_start_delay = Duration::ZERO;
    });
    let q = wait_queue(&en2, "both done after restart", |q| q["done"] == 2).await;
    assert_eq!(q["items"][0]["status"], "done", "{q}");
    let s1 = scans(
        &en2.invoke("project_snapshot", json!({ "id": p1 }))
            .await
            .unwrap(),
    );
    assert_eq!(
        s1.len(),
        1,
        "the interrupted scan was resumed, not restarted"
    );
    assert_eq!(s1[0]["id"], sid);
    assert_eq!(s1[0]["status"], "done");
    let s2 = scans(
        &en2.invoke("project_snapshot", json!({ "id": p2 }))
            .await
            .unwrap(),
    );
    assert_eq!(s2[0]["status"], "done");
    assert!(ev2
        .lock()
        .unwrap()
        .iter()
        .any(|e| e["type"] == "started" && e["resumed"] == true && e["auto"] == true));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn queue_respects_auto_resume_off_after_restart() {
    let dir = tempfile::tempdir().unwrap();
    let srv = server(0).await;
    let keys = Arc::new(foca_engine::MemoryKeys::new());
    let (en, _ev, pause_at) = open(dir.path(), &srv.url(), keys.clone());
    en.invoke(
        "settings_set",
        json!({ "patch": { "power": { "auto_resume": false } } }),
    )
    .await
    .unwrap();
    let p1 = en
        .invoke(
            "project_create",
            json!({ "name": "o1.test", "targets": [{ "v": "example.test", "type": "domain" }], "excludes": [] }),
        )
        .await
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();
    *pause_at.lock().unwrap() = Some("meta".into());
    en.invoke(
        "queue_add",
        json!({ "projects": [p1], "profile": "passive", "args": args() }),
    )
    .await
    .unwrap();
    wait_paused_any(&en).await;
    en.abandon().await;
    drop(en);
    let (en2, _ev2, _) = open_with(dir.path(), &srv.url(), keys, |c| {
        c.queue_start_delay = Duration::ZERO;
    });
    let q = wait_queue(&en2, "paused after restart", |q| q["paused"] == true).await;
    assert_eq!(q["pause_reason"], "restart");
    assert_eq!(q["items"][0]["status"], "stopped");
    assert!(!en2.is_scanning());
}
