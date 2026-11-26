//! Deleting one scan (`scan_delete`): a stopped scan, a paused running scan, a scan whose
//! results a later scan also listed; reference cases stay out of the restored project.

use crate::common::*;
use serde_json::{json, Value};

fn scan_ids(s: &Value) -> Vec<String> {
    s["scans"]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| x["id"].as_str().unwrap().to_string())
        .collect()
}

fn files_in(dir: &std::path::Path) -> usize {
    std::fs::read_dir(dir).map_or(0, |d| {
        d.filter_map(Result::ok)
            .map(|e| {
                let p = e.path();
                if p.is_dir() {
                    files_in(&p)
                } else {
                    1
                }
            })
            .sum()
    })
}

/// A stopped first scan is erased with its documents, files, findings and request log; it can
/// no longer be resumed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn delete_stopped_scan_erases_its_results() {
    let e = env(0).await;
    let id = e.project("example.test").await;
    *e.pause_at.lock().unwrap() = Some("network".into());
    let r = e
        .call(
            "scan_start",
            json!({ "project": id, "profile": "passive", "sources": ["wayback"] }),
        )
        .await;
    let sid = r["scan_id"].as_str().unwrap().to_string();
    e.wait_paused("network").await;
    *e.pause_at.lock().unwrap() = None;
    e.call("scan_stop", json!({ "reason": "user" })).await;
    let s = e.snap(&id).await;
    assert_eq!(scan_ids(&s), vec![sid.clone()]);
    let docs = s["docs"].as_array().unwrap().len();
    assert!(docs > 0);
    assert!(!s["findings"].as_array().unwrap().is_empty());
    let files_dir = e.dir.path().join("files").join(&id);
    assert!(files_in(&files_dir) > 0);

    let dry = e
        .call(
            "scan_delete",
            json!({ "project": id, "scan_id": sid, "dry_run": true }),
        )
        .await;
    assert_eq!(dry["dry_run"], true);
    assert_eq!(dry["docs"].as_u64(), Some(docs as u64), "{dry}");
    assert!(dry["requests"].as_u64().unwrap() > 0);
    assert_eq!(
        scan_ids(&e.snap(&id).await).len(),
        1,
        "dry run deletes nothing"
    );

    let out = e
        .call("scan_delete", json!({ "project": id, "scan_id": sid }))
        .await;
    assert_eq!(out["ok"], true);
    assert_eq!(out["docs"].as_u64(), Some(docs as u64), "{out}");
    assert!(out["findings"].as_u64().unwrap() > 0, "{out}");
    assert!(out["files"].as_u64().unwrap() > 0, "{out}");
    let s = e.snap(&id).await;
    assert!(scan_ids(&s).is_empty());
    assert!(s["docs"].as_array().unwrap().is_empty());
    assert!(
        s["findings"].as_array().unwrap().is_empty(),
        "{}",
        s["findings"]
    );
    assert_eq!(files_in(&files_dir), 0, "document files are wiped");
    let log = e
        .call("request_log_get", json!({ "project": id, "limit": 1000 }))
        .await;
    let rows = log
        .get("items")
        .unwrap_or(&log)
        .as_array()
        .cloned()
        .unwrap_or_default();
    assert!(
        rows.iter().all(|x| x["scan_id"] != json!(sid)),
        "request log rows of the deleted scan remain"
    );
    // nothing to resume
    let err = e
        .err(
            "scan_start",
            json!({ "project": id, "profile": "passive", "resume_from": sid }),
        )
        .await;
    assert_eq!(err.code, "not_found");
    let err = e
        .err("scan_delete", json!({ "project": id, "scan_id": sid }))
        .await;
    assert_eq!(err.code, "not_found");
    let p = e.call("project_list", json!({})).await;
    assert_eq!(p[0]["scans"], 0);
}

/// A paused running rescan is cancelled and erased: no history record, no run file, no
/// auto-resume; the earlier scan and its documents stay.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn delete_paused_running_scan() {
    let e = env(0).await;
    let id = e.project("example.test").await;
    let first = e.passive_scan(&id).await["scan_id"]
        .as_str()
        .unwrap()
        .to_string();
    let before = e.snap(&id).await;
    let c0 = counts(&before);
    *e.pause_at.lock().unwrap() = Some("network".into());
    let r = e
        .call(
            "scan_start",
            json!({ "project": id, "profile": "passive", "sources": ["crt", "wayback"] }),
        )
        .await;
    let sid = r["scan_id"].as_str().unwrap().to_string();
    e.wait_paused("network").await;
    *e.pause_at.lock().unwrap() = None;
    assert!(e.dir.path().join("engine_run.json").exists());
    let out = e
        .call("scan_delete", json!({ "project": id, "scan_id": sid }))
        .await;
    assert_eq!(out["ok"], true, "{out}");
    let st = e.call("scan_status", json!({})).await;
    assert_eq!(st["running"], false, "{st}");
    assert!(!e.dir.path().join("engine_run.json").exists());
    assert!(foca_engine::resume::interrupted_scan(e.dir.path()).is_none());
    assert!(e
        .events()
        .iter()
        .any(|x| x["type"] == "stopped" && x["reason"] == "deleted" && x["scan_id"] == json!(sid)));
    let s = e.snap(&id).await;
    assert_eq!(scan_ids(&s), vec![first]);
    assert_eq!(counts(&s), c0, "results of the earlier scan stay");
}

/// Deleting a scan while another scan of the project runs is refused.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn delete_refused_while_another_scan_runs() {
    let e = env(0).await;
    let id = e.project("example.test").await;
    let first = e.passive_scan(&id).await["scan_id"]
        .as_str()
        .unwrap()
        .to_string();
    *e.pause_at.lock().unwrap() = Some("network".into());
    e.call(
        "scan_start",
        json!({ "project": id, "profile": "passive", "sources": ["wayback"] }),
    )
    .await;
    e.wait_paused("network").await;
    *e.pause_at.lock().unwrap() = None;
    let err = e
        .err("scan_delete", json!({ "project": id, "scan_id": first }))
        .await;
    assert_eq!(err.code, "busy");
    e.call("scan_stop", json!({ "reason": "user" })).await;
}

/// Results of the first scan that the second scan also listed stay, attributed to the second
/// scan; the history of the second scan keeps its counts.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn delete_first_of_two_scans_keeps_shared_results() {
    let e = env(0).await;
    let id = e.project("example.test").await;
    let first = e.passive_scan(&id).await["scan_id"]
        .as_str()
        .unwrap()
        .to_string();
    let second = e.passive_scan(&id).await["scan_id"]
        .as_str()
        .unwrap()
        .to_string();
    let before = e.snap(&id).await;
    let c0 = counts(&before);
    let out = e
        .call("scan_delete", json!({ "project": id, "scan_id": first }))
        .await;
    assert_eq!(out["docs"], 0, "{out}");
    let s = e.snap(&id).await;
    assert_eq!(scan_ids(&s), vec![second.clone()]);
    assert_eq!(counts(&s), c0);
    for d in s["docs"].as_array().unwrap() {
        assert_eq!(d["first_scan"], json!(second), "{d}");
    }
    for f in s["findings"].as_array().unwrap() {
        assert_ne!(f["first_scan"], json!(first), "{f}");
    }
    let rec = &s["scans"][0];
    assert_eq!(rec["docs"], before["scans"][1]["docs"]);
}

/// A reference case is listed with `reference: true` and opening it does not make it the last
/// opened project.
#[tokio::test]
async fn reference_case_is_not_restored_on_start() {
    let e = env(0).await;
    let own = e.project("example.test").await;
    e.call("project_open", json!({ "id": own })).await;
    let r = e.call("demo_case_import", json!({})).await;
    let rid = r["project"].as_str().unwrap().to_string();
    e.call("project_open", json!({ "id": rid })).await;
    let st = e.call("settings_get", json!({})).await;
    assert_eq!(st["last_project"], json!(own));
    let list = e.call("project_list", json!({})).await;
    let by = |pid: &str| {
        list.as_array()
            .unwrap()
            .iter()
            .find(|p| p["id"] == pid)
            .cloned()
            .unwrap()
    };
    assert_eq!(by(&rid)["reference"], true);
    assert_eq!(by(&own)["reference"], false);
}
