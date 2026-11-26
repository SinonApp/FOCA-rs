//! Stop, pause, resume and restart, triage during a scan, scope and the active stage.

use std::collections::BTreeMap;
use std::sync::Arc;

use crate::common::*;
use serde_json::{json, Value};

const STAGES: &[&str] = &[
    "search", "download", "meta", "analysis", "network", "ports", "recon", "fuzz", "report",
];

fn last_scan(s: &Value) -> Value {
    s["scans"].as_array().unwrap().last().cloned().unwrap()
}

/// Stopping a rescan at any stage erases nothing; resuming keeps the same record.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stop_at_every_stage_and_resume_keeps_data() {
    let e = env(0).await;
    let id = e.project("example.test").await;
    e.passive_scan(&id).await;
    let s0 = e.snap(&id).await;
    let c0 = counts(&s0);
    let f0 = last_scan(&s0)["findings"].clone();
    for st in STAGES {
        *e.pause_at.lock().unwrap() = Some(st.to_string());
        let r = e
            .call(
                "scan_start",
                json!({ "project": id, "profile": "passive", "sources": ["crt", "wayback"] }),
            )
            .await;
        e.wait_paused(st).await;
        *e.pause_at.lock().unwrap() = None;
        assert_eq!(
            e.call("scan_stop", json!({ "reason": "user" })).await["ok"],
            true
        );
        let s1 = e.snap(&id).await;
        assert_eq!(counts(&s1), c0, "stop at {st} erased data");
        // this scan's record (by id: the test clock is frozen, and from the 10th scan on id order is "s10" < "s9")
        let rec = s1["scans"]
            .as_array()
            .unwrap()
            .iter()
            .find(|x| x["id"] == r["scan_id"])
            .cloned()
            .unwrap();
        assert_eq!(rec["status"], "stopped", "{st} {rec}");
        assert_eq!(rec["reason"], "user");
        assert_eq!(rec["stage"], *st, "{rec}");
        assert!(rec["progress"].is_number());
        assert!(e
            .events()
            .iter()
            .any(|x| x["type"] == "stopped" && x["reason"] == "user"));
        // resume: the same record, progress from where it stopped
        e.clear_events();
        let rr = e
            .call("scan_start", json!({ "project": id, "profile": "passive", "resume_from": rec["id"], "sources": ["crt", "wayback"] }))
            .await;
        assert_eq!(rr["scan_id"], r["scan_id"]);
        assert_eq!(rr["resumed"], true);
        e.wait().await;
        let ev = e.events();
        if let Some(p) = ev.iter().find(|x| x["type"] == "progress") {
            assert!(
                p["progress"].as_u64() >= rec["progress"].as_u64(),
                "{p} < {rec}"
            );
        }
        let first_stage = ev.iter().find(|x| x["type"] == "stage").unwrap();
        assert_eq!(first_stage["stage"], *st);
        let s2 = e.snap(&id).await;
        assert_eq!(counts(&s2), c0, "resume after {st}");
        let done = s2["scans"]
            .as_array()
            .unwrap()
            .iter()
            .find(|x| x["id"] == rec["id"])
            .cloned()
            .unwrap();
        assert_eq!(
            done["status"], "done",
            "resume after {st}: {}",
            done["reason"]
        );
        assert!(!s2["scans"]
            .as_array()
            .unwrap()
            .iter()
            .any(|x| x["status"] == "stopped"));
        // a repeat without changes: the same numbers and no new findings
        assert_eq!(done["findings"], f0);
        assert_eq!(done["new_findings"], 0);
    }
}

/// First scan stopped after the download stage: documents are downloaded and risk shows no data;
/// resuming yields parsed documents and findings.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn first_scan_stopped_before_meta_then_resumed() {
    let e = env(0).await;
    let id = e.project("example.test").await;
    *e.pause_at.lock().unwrap() = Some("meta".into());
    e.call(
        "scan_start",
        json!({ "project": id, "profile": "passive", "sources": ["wayback"] }),
    )
    .await;
    e.wait_paused("meta").await;
    let st = e.call("scan_status", json!({})).await;
    for k in [
        "active",
        "profile",
        "profile_id",
        "targets",
        "modules",
        "started_at",
    ] {
        assert!(st.get(k).is_some(), "scan_status lacks {k}");
    }
    assert_eq!(st["paused"], true);
    e.call("scan_stop", json!({ "reason": "battery" })).await;
    *e.pause_at.lock().unwrap() = None;
    let s = e.snap(&id).await;
    let c = counts(&s);
    assert_eq!(c["docs"], DOCS.len());
    assert_eq!(c["analyzed"], 0);
    let list = e.call("project_list", json!({})).await;
    assert!(
        list[0]["risk"].is_null(),
        "no risk data before the analysis stage"
    );
    let rec = last_scan(&s);
    e.call("scan_start", json!({ "project": id, "profile": "passive", "resume_from": rec["id"], "sources": ["wayback"] }))
        .await;
    e.wait().await;
    let s = e.snap(&id).await;
    assert!(counts(&s)["analyzed"].as_u64().unwrap() >= 6);
    assert!(e.call("project_list", json!({})).await[0]["risk"].is_number());
    // already downloaded files are not downloaded again
    let hits = e
        .server
        .requests()
        .iter()
        .filter(|r| r.method == "GET" && r.path().ends_with("contract.docx"))
        .count();
    assert_eq!(hits, 1, "document downloaded again");
}

/// User triage and deletions made during a scan are preserved.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn triage_and_delete_during_scan_survive() {
    let e = env(0).await;
    let id = e.project("example.test").await;
    e.passive_scan(&id).await;
    let s = e.snap(&id).await;
    let fl = s["findings"].as_array().unwrap();
    let del_doc = s["docs"]
        .as_array()
        .unwrap()
        .iter()
        .find(|d| d["name"] == "letter.odt")
        .unwrap()["id"]
        .as_u64()
        .unwrap();
    let indep: Vec<&Value> = fl
        .iter()
        .filter(|f| f["doc"].as_u64() != Some(del_doc))
        .collect();
    let (a, b, c) = (
        indep[0]["id"].clone(),
        indep[1]["id"].clone(),
        indep[2]["id"].clone(),
    );
    *e.pause_at.lock().unwrap() = Some("download".into());
    e.call(
        "scan_start",
        json!({ "project": id, "profile": "passive", "sources": ["crt", "wayback"] }),
    )
    .await;
    e.wait_paused("download").await;
    e.call(
        "finding_set_status",
        json!({ "project": id, "id": a, "status": "confirmed" }),
    )
    .await;
    e.call(
        "finding_set_status",
        json!({ "project": id, "id": b, "status": "false" }),
    )
    .await;
    let upd = e
        .call("finding_update", json!({ "project": id, "id": c, "patch": {
            "sev": "high", "tags": ["в отчёт"], "notes": [{ "text": "моя заметка", "who": "Вы", "time": "20.11" }] } }))
        .await;
    assert_eq!(upd["sev"], "high");
    assert_eq!(
        e.call("doc_delete", json!({ "project": id, "ids": [del_doc] }))
            .await["deleted"],
        1
    );
    *e.pause_at.lock().unwrap() = None;
    e.engine.resume();
    e.wait().await;
    let s = e.snap(&id).await;
    let f = |id: &Value| {
        s["findings"]
            .as_array()
            .unwrap()
            .iter()
            .find(|x| x["id"] == *id)
            .cloned()
            .unwrap()
    };
    assert_eq!(f(&a)["status"], "confirmed");
    assert_eq!(f(&b)["status"], "false");
    assert_eq!(f(&c)["sev"], "high");
    assert_eq!(f(&c)["notes"][0]["text"], "моя заметка");
    assert_eq!(f(&c)["tags"][0], "в отчёт");
    let d = s["docs"]
        .as_array()
        .unwrap()
        .iter()
        .find(|d| d["id"] == del_doc)
        .cloned()
        .unwrap();
    assert_eq!(d["deleted"], true);
    // derived data reflects only live documents
    assert!(!s["secrets"]
        .as_array()
        .unwrap()
        .iter()
        .any(|x| x["doc"] == del_doc));
    assert_eq!(last_scan(&s)["status"], "done");
    // restore
    assert_eq!(
        e.call("doc_restore", json!({ "project": id, "ids": [del_doc] }))
            .await["restored"],
        1
    );
}

/// A process unload during a scan becomes `stopped/restart` on the next start, and the scan can be resumed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn process_restart_marks_stopped_and_resumes() {
    let dir = tempfile::tempdir().unwrap();
    let srv = server(0).await;
    let keys = Arc::new(foca_engine::MemoryKeys::new());
    let (en, _ev, pause_at) = open(dir.path(), &srv.url(), keys.clone());
    let p = en
        .invoke("project_create", json!({ "name": "reload.test", "targets": [{ "v": "example.test", "type": "domain", "active": false }], "excludes": [] }))
        .await
        .unwrap();
    let id = p["id"].as_str().unwrap().to_string();
    *pause_at.lock().unwrap() = Some("meta".into());
    let r = en
        .invoke(
            "scan_start",
            json!({ "project": id, "profile": "passive", "sources": ["wayback"] }),
        )
        .await
        .unwrap();
    for _ in 0..500 {
        let s = en.invoke("scan_status", json!({})).await.unwrap();
        if s["paused"] == true {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    en.abandon().await;
    drop(en);
    let (en2, _ev2, _) = open(dir.path(), &srv.url(), keys);
    assert_eq!(
        en2.invoke("scan_status", json!({})).await.unwrap()["running"],
        false
    );
    let s = en2
        .invoke("project_snapshot", json!({ "id": id }))
        .await
        .unwrap();
    let rec = last_scan(&s);
    assert_eq!(rec["id"], r["scan_id"]);
    assert_eq!(rec["status"], "stopped");
    assert_eq!(rec["reason"], "restart");
    assert_eq!(rec["stage"], "meta");
    assert!(rec["progress"].as_u64().unwrap() > 0);
    assert!(en2.invoke("project_list", json!({})).await.unwrap()[0]["risk"].is_null());
    en2.invoke("scan_start", json!({ "project": id, "profile": "passive", "resume_from": rec["id"], "sources": ["wayback"] }))
        .await
        .unwrap();
    assert!(en2.wait_idle(std::time::Duration::from_secs(60)).await);
    let s = en2
        .invoke("project_snapshot", json!({ "id": id }))
        .await
        .unwrap();
    assert_eq!(s["scans"].as_array().unwrap().len(), 1);
    assert_eq!(last_scan(&s)["status"], "done");
    assert!(counts(&s)["analyzed"].as_u64().unwrap() > 0);
}

/// The standard profile touches the target, but never an excluded host or its IP (request log).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn excluded_host_and_ip_untouched_in_request_log() {
    let e = env(0).await;
    let id = e.project("example.test").await;
    let r = e
        .call(
            "scan_start",
            json!({ "project": id, "profile": "std", "sources": ["crt", "wayback"] }),
        )
        .await;
    assert_eq!(r["active"], false);
    e.wait().await;
    let s = e.snap(&id).await;
    assert_eq!(last_scan(&s)["status"], "done");
    let db = foca_store::Store::open(e.dir.path())
        .unwrap()
        .open_project(&id)
        .unwrap();
    let log = db.requests(None, false).unwrap();
    assert!(!log.is_empty());
    assert!(
        log.iter()
            .any(|l| l.host == "example.test" && l.module == "ping"),
        "target TCP liveness"
    );
    for l in &log {
        assert!(
            !l.host.contains("mail.example.test")
                && l.host != "127.0.0.2"
                && !l.url.contains("127.0.0.2"),
            "request to an excluded host: {l:?}"
        );
    }
    // a passive scan does not touch the target at all
    let p2 = e.project("passive-only").await;
    e.passive_scan(&p2).await;
    let db2 = foca_store::Store::open(e.dir.path())
        .unwrap()
        .open_project(&p2)
        .unwrap();
    assert!(
        db2.requests(None, true).unwrap().is_empty(),
        "passive profile: requests to the target"
    );
}

/// Active stage: the full profile and custom profiles with active modules start with a single call,
/// without switches or confirmations (0.2.x fields are ignored); scope checks; busy state; resume uses the current scope.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn launch_rules_no_confirmations_scope_busy() {
    let e = env(300).await;
    // an old client sends allow_active: false and active: false on the target; both are ignored
    let p = e
        .call("project_create", json!({ "name": "noactive.test", "targets": [{ "v": "example.test", "type": "domain", "active": false }],
            "excludes": [], "allow_active": false }))
        .await;
    let na = p["id"].as_str().unwrap();
    let sc = e.call("scope_get", json!({ "project": na })).await;
    assert!(sc.get("allow_active").is_none(), "{sc}");
    assert!(sc["targets"][0].get("active").is_none(), "{sc}");
    for args in [
        json!({ "project": na, "profile": "full", "sources": [] }),
        json!({ "project": na, "profile": "custom", "modules": ["axfr"], "sources": [] }),
    ] {
        let st = e.call("scan_start", args).await;
        assert!(st["scan_id"].is_string(), "{st}");
        let s = e.call("scan_status", json!({})).await;
        assert_eq!(s["active"], true, "{s}");
        e.call("scan_stop", json!({ "reason": "user" })).await;
        e.wait().await;
    }
    // the confirmation log no longer exists
    assert!(!e
        .err("active_acks", json!({ "project": na }))
        .await
        .code
        .is_empty());
    // a target outside the scope: out_of_scope with a list for the standard profile; allowed for passive
    let er = e
        .err(
            "scan_start",
            json!({ "project": na, "profile": "std", "targets": ["evil-competitor.com"] }),
        )
        .await;
    assert_eq!(er.code, "out_of_scope");
    assert_eq!(er.targets.as_ref().unwrap().len(), 1);
    // busy
    let id = e.project("example.test").await;
    e.call(
        "scope_set",
        json!({ "id": id, "scope": { "targets": [
        { "v": "example.test", "type": "domain" },
        { "v": "shop.example.org", "type": "domain", "active": false } ] } }),
    )
    .await;
    *e.pause_at.lock().unwrap() = Some("download".into());
    let r = e
        .call(
            "scan_start",
            json!({ "project": id, "profile": "std", "sources": ["wayback"] }),
        )
        .await;
    assert_eq!(r["targets"], json!(["example.test", "shop.example.org"]));
    let er = e
        .err("scan_start", json!({ "project": na, "profile": "passive" }))
        .await;
    assert_eq!(er.code, "busy");
    e.wait_paused("download").await;
    e.call("scan_stop", json!({ "reason": "vpn" })).await;
    *e.pause_at.lock().unwrap() = None;
    let rec = last_scan(&e.snap(&id).await);
    assert_eq!(rec["targets"], json!(["example.test", "shop.example.org"]));
    // the scope changed: resuming takes targets from the current scope
    e.call(
        "scope_set",
        json!({ "id": id, "scope": { "targets": [{ "v": "example.test", "type": "domain" }] } }),
    )
    .await;
    let er = e
        .err("scan_start", json!({ "project": id, "profile": "std", "resume_from": rec["id"], "targets": ["shop.example.org"] }))
        .await;
    assert_eq!(er.code, "out_of_scope");
    e.call(
        "scope_set",
        json!({ "id": id, "scope": { "excl": ["mail.example.test", "example.test"] } }),
    )
    .await;
    let er = e
        .err(
            "scan_start",
            json!({ "project": id, "profile": "std", "resume_from": rec["id"] }),
        )
        .await;
    assert_eq!(er.code, "out_of_scope", "excluded target on resume");
    e.call(
        "scope_set",
        json!({ "id": id, "scope": { "excl": ["mail.example.test"] } }),
    )
    .await;
    let rr = e
        .call("scan_start", json!({ "project": id, "profile": "std", "resume_from": rec["id"], "sources": ["wayback"] }))
        .await;
    assert_eq!(rr["targets"], json!(["example.test"]));
    assert_eq!(rr["scan_id"], rec["id"]);
    e.wait().await;
    let er = e
        .err(
            "scan_start",
            json!({ "project": id, "resume_from": "nope" }),
        )
        .await;
    assert_eq!(er.code, "not_found");
}

/// PIN (hash, attempts, panic PIN triggers a wipe), settings, and keys exposed only as masks.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pin_keys_settings_wipe() {
    let e = env(0).await;
    let id = e.project("example.test").await;
    assert_eq!(
        e.err("pin_set", json!({ "pin": "12a" })).await.code,
        "bad_pin"
    );
    e.call("pin_set", json!({ "pin": "2580", "panic": "1111" }))
        .await;
    let p1 = e.call("pin_check", json!({ "pin": "0000" })).await;
    assert_eq!(
        p1,
        json!({ "ok": false, "panic": false, "attempts_left": 4 })
    );
    let p2 = e.call("pin_check", json!({ "pin": "2580" })).await;
    assert_eq!(p2["ok"], true);
    let st = e.call("settings_get", json!({})).await;
    let js = st.to_string();
    assert_eq!(st["sec"]["pin_set"], true);
    assert!(!js.contains("pin_hash") && !js.contains("2580"));
    let pin_file = std::fs::read_to_string(e.dir.path().join("pin.json")).unwrap();
    assert!(!pin_file.contains("2580"));
    // keys: the value goes to the KeyProvider, only the mask comes out
    let k = e
        .call(
            "key_set",
            json!({ "service": "brave", "value": "BSAqVERYSECRETab12" }),
        )
        .await;
    assert_eq!(k["status"], "ok");
    assert_eq!(k["mask"], "BSAq…ab12");
    assert!(!e
        .call("settings_get", json!({}))
        .await
        .to_string()
        .contains("VERYSECRET"));
    use foca_engine::KeyProvider;
    assert_eq!(e.keys.get("brave").as_deref(), Some("BSAqVERYSECRETab12"));
    // settings: deep merge
    let s = e
        .call(
            "settings_set",
            json!({ "patch": { "net": { "rps": 3 }, "ui": { "look": { "theme": "dark" } } } }),
        )
        .await;
    assert_eq!(s["net"]["rps"], 3);
    assert_eq!(s["net"]["timeout"], 15);
    assert_eq!(s["ui"]["look"]["theme"], "dark");
    // a retired Google CSE key in old settings is ignored without errors
    let s = e
        .call(
            "settings_set",
            json!({ "patch": { "keys": { "gcse": { "status": "ok", "mask": "AIza…cx01" } } } }),
        )
        .await;
    assert!(s["keys"].get("gcse").is_none());
    assert!(e.call("settings_get", json!({})).await["keys"]
        .get("gcse")
        .is_none());
    // panic PIN: everything is wiped
    let p3 = e.call("pin_check", json!({ "pin": "1111" })).await;
    assert_eq!(p3["panic"], true);
    assert_eq!(e.call("project_list", json!({})).await, json!([]));
    assert!(e.keys.get("brave").is_none());
    assert_eq!(
        e.call("settings_get", json!({})).await["sec"]["pin_set"],
        false
    );
    assert_eq!(
        e.err("project_snapshot", json!({ "id": id })).await.code,
        "not_found"
    );
    assert_eq!(
        e.err("wipe_all", json!({ "confirm": "no" })).await.code,
        "bad_confirm"
    );
}

/// 5 wrong PIN attempts trigger exponential lockout; `wipe_all` removes logs, plugins, wordlists, and dork-cache.json.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pin_lockout_and_wipe_clears_auxiliary_dirs() {
    let e = env(0).await;
    e.call("pin_set", json!({ "pin": "2580" })).await;
    for expected_left in [4, 3, 2, 1] {
        let r = e.call("pin_check", json!({ "pin": "0000" })).await;
        assert_eq!(r["ok"], false);
        assert_eq!(r["attempts_left"], expected_left);
    }
    let locked = e.call("pin_check", json!({ "pin": "0000" })).await;
    assert_eq!(locked["ok"], false);
    assert_eq!(locked["locked"], true);
    assert_eq!(locked["attempts_left"], 0);
    assert!(locked["retry_after"].as_i64().unwrap_or(0) >= 29);

    // Even the correct PIN is rejected while locked out.
    let still_locked = e.call("pin_check", json!({ "pin": "2580" })).await;
    assert_eq!(still_locked["ok"], false);
    assert_eq!(still_locked["locked"], true);

    // Auxiliary artifacts in data_dir are removed by wipe_all.
    for d in ["logs", "plugins", "wordlists", "exports"] {
        std::fs::create_dir_all(e.dir.path().join(d)).unwrap();
        std::fs::write(e.dir.path().join(d).join("artifact.txt"), b"x").unwrap();
    }
    std::fs::write(e.dir.path().join("dork-cache.json"), b"{}").unwrap();
    std::fs::write(e.dir.path().join("auto_resume.json"), b"{}").unwrap();

    let w = e.call("wipe_all", json!({ "confirm": "WIPE" })).await;
    assert_eq!(w["ok"], true);
    for p in [
        "plugins",
        "wordlists",
        "exports",
        "dork-cache.json",
        "auto_resume.json",
    ] {
        assert!(
            !e.dir.path().join(p).exists(),
            "{p} should be removed by wipe_all"
        );
    }
}

/// net_check, AI (preview with replacements, stale_preview, no_key), doc_clean, report and export.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn beta_commands() {
    let e = env(0).await;
    let id = e.project("example.test").await;
    e.passive_scan(&id).await;
    let n = e.call("net_check", json!({})).await;
    assert_eq!(n["ok"], true, "{n}");
    assert_eq!(n["out_ip"], "203.0.113.7", "{n}");
    assert_eq!(n["country"], "DE", "{n}");
    assert_eq!(n["via"], "Напрямую", "{n}");
    assert!(n["latency_ms"].is_u64(), "{n}");
    assert!(n["org"].is_string(), "{n}");
    assert_eq!(n["ip_kind"], "unknown", "{n}");
    assert_eq!(n["canary"]["unreliable"], false, "{n}");
    let pc = e.call("net_proxy_check", json!({})).await;
    assert_eq!(pc["ok"], true, "{pc}");
    assert_eq!(pc["out_ip"], "203.0.113.7", "{pc}");
    let ct = e
        .call("search_captcha_test", json!({ "engine": "startpage" }))
        .await;
    assert_eq!(ct["ok"], false, "{ct}");
    assert_eq!(ct["supported"], false, "{ct}");
    // AI
    let ap = e
        .call(
            "ai_preview",
            json!({ "project": id, "opts": { "redact": { "evid": true } } }),
        )
        .await;
    let text = ap["text"].as_str().unwrap();
    assert!(
        text.contains("[КЛИЕНТ]") || text.contains("[КЛИЕНТ-ДОМЕН]"),
        "{text}"
    );
    assert!(!text.contains("example.test"), "{text}");
    assert!(!text.contains("Tender2024"), "{text}");
    for k in ["СЕКРЕТ", "EMAIL", "ФИО", "КЛИЕНТ", "IP-ВНУТР"] {
        assert!(ap["marks"][k].is_number());
    }
    assert_eq!(
        e.err(
            "ai_summarize",
            json!({ "project": id, "preview_id": ap["id"], "opts": {} })
        )
        .await
        .code,
        "no_key"
    );
    e.call(
        "settings_set",
        json!({ "patch": { "ai": { "provider": "deepseek", "model": "deepseek-chat" } } }),
    )
    .await;
    e.call(
        "key_set",
        json!({ "service": "ai", "value": "sk-test-0000000000" }),
    )
    .await;
    let ap = e
        .call("ai_preview", json!({ "project": id, "opts": {} }))
        .await;
    let er = e
        .err(
            "ai_summarize",
            json!({ "project": id, "preview_id": "aip-old", "opts": {} }),
        )
        .await;
    assert_eq!(er.code, "stale_preview");
    let sm = e
        .call(
            "ai_summarize",
            json!({ "project": id, "preview_id": ap["id"], "opts": {} }),
        )
        .await;
    assert!(sm["md"].as_str().unwrap().contains("Ключевые риски"));
    assert_eq!(sm["tokens_in"], 321);
    let req = e
        .server
        .requests()
        .into_iter()
        .find(|r| r.path() == "/ai/chat/completions")
        .unwrap();
    assert_eq!(
        req.headers.get("authorization").map(String::as_str),
        Some("Bearer sk-test-0000000000")
    );
    // doc_clean: a *_clean.ext copy; a secret in the text becomes a manual item
    let s = e.snap(&id).await;
    let docx = s["docs"]
        .as_array()
        .unwrap()
        .iter()
        .find(|d| d["name"] == "contract.docx")
        .unwrap()["id"]
        .clone();
    let jpg = s["docs"]
        .as_array()
        .unwrap()
        .iter()
        .find(|d| d["name"] == "photo.jpg")
        .unwrap()["id"]
        .clone();
    let cl = e
        .call("doc_clean", json!({ "project": id, "ids": [docx, jpg] }))
        .await;
    let c0 = &cl["cleaned"][0];
    assert_eq!(c0["name"], "contract_clean.docx");
    assert!(e
        .dir
        .path()
        .join("clean")
        .join(&id)
        .join("contract_clean.docx")
        .exists());
    assert!(c0["removed"]
        .as_array()
        .unwrap()
        .iter()
        .any(|x| x == "author"));
    let c1 = &cl["cleaned"][1];
    assert_eq!(c1["name"], "photo_clean.jpg");
    let s = e.snap(&id).await;
    let d = s["docs"]
        .as_array()
        .unwrap()
        .iter()
        .find(|d| d["id"] == docx)
        .unwrap()
        .clone();
    assert_eq!(d["cleaned"]["name"], "contract_clean.docx");
    // report (foca-report) and history with a result snapshot
    let rep = e
        .call("report_build", json!({ "project": id, "opts": { "tpl": "Полный отчёт пентеста", "tpl_id": "full", "fmt": "html", "lang": "RU", "min_sev": "low", "confirmed": false, "sections": { "summary": true, "findings": true } } }))
        .await;
    assert!(rep["name"].as_str().unwrap().ends_with("_v1.html"), "{rep}");
    assert!(rep["result"]["finding_ids"].is_array());
    assert!(
        rep.get("size").is_some()
            && rep["created_at"]
                .as_str()
                .unwrap()
                .starts_with("2026-11-20T12:00")
    );
    let list = e.call("report_list", json!({ "project": id })).await;
    assert_eq!(list[0]["result"], rep["result"]);
    // Report templates: catalog in the UI language, `template` wins over `opts.tpl_id`.
    let tpls = e.call("report_templates", json!({ "lang": "UA" })).await;
    assert_eq!(tpls[3]["id"], "lab");
    assert_eq!(tpls[3]["title"], "Лабораторна робота");
    let lab = e
        .call(
            "report_build",
            json!({ "project": id, "template": "lab", "opts": { "tpl": "Полный отчёт пентеста", "tpl_id": "full", "fmt": "html", "lang": "UA" } }),
        )
        .await;
    assert_eq!(lab["tpl"], "Лабораторна робота", "{lab}");
    assert_eq!(lab["opts"]["tpl_id"], "lab");
    let html = std::fs::read_to_string(lab["path"].as_str().unwrap()).unwrap();
    assert!(html.contains("Виконав") && html.contains("default-src 'none'"));
    let bad = e
        .err(
            "report_build",
            json!({ "project": id, "template": "nope", "opts": { "fmt": "html" } }),
        )
        .await;
    assert_eq!(bad.code, "bad_args");
    e.call("report_delete", json!({ "project": id, "id": lab["id"] }))
        .await;
    let ex = e
        .call(
            "export_build",
            json!({ "project": id, "kind": "users", "fmt": "dict", "opts": { "dict": "users" } }),
        )
        .await;
    // `path` is the real file path in the export directory, `saved_as` where Save to files will put it
    assert!(std::path::Path::new(ex["path"].as_str().unwrap()).is_file());
    assert!(ex["saved_as"]
        .as_str()
        .unwrap()
        .starts_with("Download/FOCA-rs/"));
    assert!(e
        .engine
        .config()
        .export_dir
        .join(ex["name"].as_str().unwrap())
        .exists());
    assert_eq!(
        e.call("report_delete", json!({ "project": id, "id": rep["id"] }))
            .await["ok"],
        true
    );
    // oos: decision and atomic addition to the scope
    let oos = e.call("oos_list", json!({ "project": id })).await;
    let blk = oos
        .as_array()
        .unwrap()
        .iter()
        .find(|o| o["blocked"].is_string())
        .unwrap();
    assert_eq!(
        e.err(
            "oos_decide",
            json!({ "project": id, "id": blk["id"], "decision": "scope" })
        )
        .await
        .code,
        "blocked"
    );
    if let Some(c) = oos
        .as_array()
        .unwrap()
        .iter()
        .find(|o| o["blocked"].is_null())
    {
        let r = e
            .call("oos_add_to_scope", json!({ "project": id, "id": c["id"] }))
            .await;
        assert!(r["scope"]["targets"]
            .as_array()
            .unwrap()
            .iter()
            .any(|t| t["v"] == c["host"]));
        assert!(r["oos"]
            .as_array()
            .unwrap()
            .iter()
            .any(|o| o["host"] == c["host"] && o["decision"] == "scope"));
    }
    let mut seen = BTreeMap::new();
    for o in e
        .call("oos_list", json!({ "project": id }))
        .await
        .as_array()
        .unwrap()
    {
        assert!(
            seen.insert(o["id"].to_string(), 1).is_none(),
            "duplicate oos entries"
        );
        // a network (/24) is never offered from discovered addresses, only a single IP (shared hosting)
        let host = o["host"].as_str().unwrap();
        assert!(o["kind"] != "net" && !host.contains('/'), "{o}");
        if o["shared"] == true {
            assert!(o["kind"] == "ip" && o["own"] == false, "{o}");
            assert!(host.parse::<std::net::Ipv4Addr>().is_ok(), "{o}");
        }
    }
    // unknown command
    assert_eq!(e.err("nope", json!({})).await.code, "unknown_command");
}

/// Direct IP / CIDR / IP-range targets flow into passive RDAP without touching target hosts (ADR-0009).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn direct_ip_and_cidr_targets_flow_through_passive_rdap() {
    let e = env(0).await;
    let p = e
        .call(
            "project_create",
            json!({
                "name": "ip-scope.test",
                "targets": [
                    { "v": "203.0.113.10", "type": "ip" },
                    { "v": "203.0.113.16/30", "type": "cidr" }
                ],
                "excludes": ["203.0.113.18"]
            }),
        )
        .await;
    let id = p["id"].as_str().unwrap().to_string();
    e.call(
        "scan_start",
        json!({ "project": id, "profile": "passive", "sources": ["crt"] }),
    )
    .await;
    e.wait().await;
    let snap = e.snap(&id).await;
    let hosts: Vec<&str> = snap["hosts"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|h| h["name"].as_str())
        .collect();
    assert!(hosts.contains(&"203.0.113.10"), "{hosts:?}");
    assert!(hosts.contains(&"203.0.113.17"), "{hosts:?}");
    assert!(
        !hosts.contains(&"203.0.113.18"),
        "excluded IP must never be seeded: {hosts:?}"
    );
    let log = e
        .call("request_log_get", json!({ "project": id, "limit": 500 }))
        .await;
    assert!(
        log.as_array().unwrap().iter().all(|r| r["active"] != true),
        "passive scan over IP/CIDR must never send active requests: {log}"
    );
}
