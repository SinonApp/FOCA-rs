//! Auto-resume after a process unload (Android): `resume::interrupted_scan` before `Engine::open`,
//! then the `power.auto_resume` setting, then `scan_start { resume_from }` continues the same record.

use std::sync::Arc;

use crate::common::*;
use foca_engine::resume;
use serde_json::json;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn killed_process_scan_auto_resumes_when_enabled() {
    let dir = tempfile::tempdir().unwrap();
    let srv = server(0).await;
    let keys = Arc::new(foca_engine::MemoryKeys::new());
    let (en, _ev, pause_at) = open(dir.path(), &srv.url(), keys.clone());
    let p = en
        .invoke("project_create", json!({ "name": "auto.test", "targets": [{ "v": "example.test", "type": "domain", "active": false }], "excludes": [] }))
        .await
        .unwrap();
    let id = p["id"].as_str().unwrap().to_string();
    // no running scan, nothing to resume
    assert!(resume::interrupted_scan(dir.path()).is_none());
    *pause_at.lock().unwrap() = Some("meta".into());
    let r = en
        .invoke(
            "scan_start",
            json!({ "project": id, "profile": "passive", "sources": ["wayback"] }),
        )
        .await
        .unwrap();
    for _ in 0..500 {
        if en.invoke("scan_status", json!({})).await.unwrap()["paused"] == true {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    // the process is "killed by the system"
    en.abandon().await;
    drop(en);

    // next launch: read the interrupted scan first, then open the engine
    let args = resume::interrupted_scan(dir.path()).expect("interrupted scan");
    assert_eq!(args["resume_from"], r["scan_id"]);
    assert_eq!(args["project"], id);
    assert_eq!(args["profile"], "passive");
    assert_eq!(args["sources"], json!(["wayback"]));
    let (en2, ev2, _) = open(dir.path(), &srv.url(), keys);
    // the engine consumed and removed the file, so there will be no second auto-resume
    assert!(resume::interrupted_scan(dir.path()).is_none());

    let settings = en2.invoke("settings_get", json!({})).await.unwrap();
    assert!(resume::enabled(&settings), "enabled by default");
    assert_eq!(
        resume::note_attempt(dir.path(), args["resume_from"].as_str().unwrap(), 1),
        1
    );
    let rr = en2.invoke("scan_start", args.clone()).await.unwrap();
    assert_eq!(rr["scan_id"], r["scan_id"]);
    assert_eq!(rr["resumed"], true);
    assert!(ev2
        .lock()
        .unwrap()
        .iter()
        .any(|e| e["type"] == "started" && e["resumed"] == true));
    assert!(en2.wait_idle(std::time::Duration::from_secs(60)).await);
    let s = en2
        .invoke("project_snapshot", json!({ "id": id }))
        .await
        .unwrap();
    let scans = s["scans"].as_array().unwrap();
    assert_eq!(scans.len(), 1, "resuming keeps the same history record");
    assert_eq!(scans[0]["status"], "done");

    // with the setting off, the decision is not to resume
    let off = en2
        .invoke(
            "settings_set",
            json!({ "patch": { "power": { "auto_resume": false } } }),
        )
        .await
        .unwrap();
    assert!(!resume::enabled(&off));
}

fn downloaded(s: &serde_json::Value) -> Vec<String> {
    s["docs"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|d| d["status"] == "downloaded" || d["status"] == "analyzed")
        .map(|d| d["url"].as_str().unwrap_or("").to_string())
        .collect()
}

/// The process is killed in the middle of a download (not at a stage boundary): downloaded files
/// are already in SQLite and the running scan file is left behind, so `Engine::open` writes
/// `stopped/restart` with progress within the stage. The auto-resume (`auto: true`) is visible in
/// `scan_status` together with source statuses, and the scan completes without duplicates or
/// losses: exactly as many documents as the same scan without an unload.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn killed_mid_download_keeps_data_and_resumes_without_duplicates() {
    let target = json!({ "name": "kill.test", "targets": [{ "v": "example.test", "type": "domain", "active": false }], "excludes": [] });
    let scan = |id: &str| json!({ "project": id, "profile": "passive", "sources": ["wayback"] });
    // reference: the same scan without an unload
    let ref_dir = tempfile::tempdir().unwrap();
    let srv0 = server(0).await;
    let (en0, _e0, _) = open(
        ref_dir.path(),
        &srv0.url(),
        Arc::new(foca_engine::MemoryKeys::new()),
    );
    let id0 = en0.invoke("project_create", target.clone()).await.unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();
    en0.invoke("scan_start", scan(&id0)).await.unwrap();
    assert!(en0.wait_idle(std::time::Duration::from_secs(60)).await);
    let want = downloaded(
        &en0.invoke("project_snapshot", json!({ "id": id0 }))
            .await
            .unwrap(),
    )
    .len();
    assert!(want >= 3, "the reference scan downloaded {want}");

    let dir = tempfile::tempdir().unwrap();
    let srv = server(250).await; // each document takes about 250 ms, so the download takes noticeable time
    let keys = Arc::new(foca_engine::MemoryKeys::new());
    let (en, _ev, _) = open(dir.path(), &srv.url(), keys.clone());
    let id = en.invoke("project_create", target).await.unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();
    let r = en.invoke("scan_start", scan(&id)).await.unwrap();
    let mut before = 0;
    for _ in 0..1000 {
        let st = en.invoke("scan_status", json!({})).await.unwrap();
        let s = en
            .invoke("project_snapshot", json!({ "id": id }))
            .await
            .unwrap();
        before = downloaded(&s).len();
        if st["stage"] == "download"
            && st["progress"].as_u64().unwrap_or(0) > 100 / 7
            && before >= 1
            && before < want
        {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert!(
        before >= 1 && before < want,
        "unloaded mid-download: {before} of {want} downloaded"
    );
    // "kill -9": the scan task is dropped without writing a result; the running scan file remains
    en.abandon().await;
    drop(en);
    assert!(
        dir.path().join("engine_run.json").exists(),
        "the running scan file survived the unload"
    );
    let args = resume::interrupted_scan(dir.path()).expect("interrupted scan");

    let (en2, ev2, _) = open(dir.path(), &srv.url(), keys);
    assert_eq!(
        en2.invoke("scan_status", json!({})).await.unwrap()["running"],
        false,
        "after the unload the scan is not running"
    );
    let s = en2
        .invoke("project_snapshot", json!({ "id": id }))
        .await
        .unwrap();
    let rec = s["scans"].as_array().unwrap().last().unwrap().clone();
    assert_eq!(
        (rec["status"].as_str(), rec["reason"].as_str()),
        (Some("stopped"), Some("restart"))
    );
    assert_eq!(rec["stage"], "download");
    assert!(
        rec["progress"].as_u64().unwrap() > 100 / 7,
        "progress within the download stage: {}",
        rec["progress"]
    );
    let kept = downloaded(&s);
    assert!(
        kept.len() >= before,
        "files downloaded before the unload are present: {} of {before}",
        kept.len()
    );

    let mut a = args;
    a["auto"] = json!(true);
    let rr = en2.invoke("scan_start", a).await.unwrap();
    assert_eq!(
        (
            rr["scan_id"].clone(),
            rr["resumed"].clone(),
            rr["auto"].clone()
        ),
        (r["scan_id"].clone(), json!(true), json!(true))
    );
    let st = en2.invoke("scan_status", json!({})).await.unwrap();
    assert_eq!(
        (st["running"].clone(), st["auto"].clone()),
        (json!(true), json!(true))
    );
    assert!(
        st["sources"]
            .as_array()
            .is_some_and(|v| v.iter().any(|x| x["id"] == "wayback")),
        "{st}"
    );
    assert!(en2.wait_idle(std::time::Duration::from_secs(60)).await);
    assert!(ev2.lock().unwrap().iter().any(|e| e["type"] == "done"));
    let s = en2
        .invoke("project_snapshot", json!({ "id": id }))
        .await
        .unwrap();
    let urls = downloaded(&s);
    let uniq: std::collections::BTreeSet<&String> = urls.iter().collect();
    assert_eq!(uniq.len(), urls.len(), "no duplicates");
    assert_eq!(
        urls.len(),
        want,
        "nothing lost: same as a scan without an unload"
    );
    for u in &kept {
        assert!(
            urls.contains(u),
            "files downloaded before the unload are not lost: {u}"
        );
    }
    let scans = s["scans"].as_array().unwrap();
    assert_eq!(scans.len(), 1, "resuming keeps the same record");
    assert_eq!(scans[0]["status"], "done");
}
