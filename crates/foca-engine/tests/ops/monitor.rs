//! Scheduled monitoring rescans (`scan_start { trigger: "schedule" }`): the full profile is rejected
//! without a single request, the passive one runs, and the scan record has `trigger: "schedule"`.

use crate::common::*;
use serde_json::json;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn schedule_trigger_refuses_active_and_marks_record() {
    let e = env(0).await;
    let id = e.project("example.test").await;
    for prof in ["full", "custom"] {
        let mut a = json!({ "project": id, "profile": prof, "trigger": "schedule" });
        if prof == "custom" {
            a["modules"] = json!(["crt", "ports"]);
        }
        let err = e.err("scan_start", a).await;
        assert_eq!(err.code, "monitor_active", "{prof}: {err:?}");
    }
    let log = e
        .call("request_log_get", json!({ "project": id, "limit": 1000 }))
        .await;
    assert!(
        log.as_array().unwrap().is_empty(),
        "denied without requests"
    );
    e.call(
        "scan_start",
        json!({ "project": id, "profile": "passive", "trigger": "schedule", "sources": ["crt"] }),
    )
    .await;
    e.wait().await;
    let s = e.snap(&id).await;
    let rec = s["scans"].as_array().unwrap().last().unwrap().clone();
    assert_eq!(rec["status"], "done", "{rec}");
    assert_eq!(rec["trigger"], "schedule", "{rec}");
    // a regular start is manual
    e.call(
        "scan_start",
        json!({ "project": id, "profile": "passive", "sources": ["crt"] }),
    )
    .await;
    e.wait().await;
    let s = e.snap(&id).await;
    assert!(s["scans"]
        .as_array()
        .unwrap()
        .iter()
        .any(|x| x["trigger"] == "manual"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn headless_schedule_skips_webview_without_incomplete_or_error() {
    let srv = server(0).await;
    let dir = tempfile::tempdir().unwrap();
    let keys = std::sync::Arc::new(foca_engine::MemoryKeys::new());
    let (en, ev, _) = open_with(dir.path(), &srv.url(), keys, |cfg| {
        cfg.headless = true;
        cfg.render = None;
    });
    let p = en
        .invoke(
            "project_create",
            json!({
                "name": "headless.test",
                "targets": [{ "v": "example.test", "type": "domain", "active": false }],
                "excludes": []
            }),
        )
        .await
        .unwrap();
    let id = p["id"].as_str().unwrap().to_string();
    en.invoke(
        "scan_start",
        json!({
            "project": id,
            "profile": "passive",
            "trigger": "schedule",
            "headless": true,
            "sources": ["crt", "startpage", "brave_web", "yahoo", "searx_pool"]
        }),
    )
    .await
    .unwrap();
    assert!(en.wait_idle(std::time::Duration::from_secs(60)).await);
    assert!(ev.lock().unwrap().iter().any(|x| x["type"] == "done"));

    let snap = en
        .invoke("project_snapshot", json!({ "id": id }))
        .await
        .unwrap();
    let rec = snap["scans"].as_array().unwrap().last().unwrap().clone();
    assert_eq!(rec["status"], "done", "{rec}");
    assert_eq!(rec["trigger"], "schedule", "{rec}");
    assert_eq!(
        rec["env"]["incomplete"], false,
        "skipped_headless must not flag snapshot incomplete: {rec}"
    );
    let srcs = rec["sources"].as_array().unwrap();
    for wid in ["startpage", "brave_web", "yahoo", "searx_pool"] {
        let s = srcs
            .iter()
            .find(|x| x["id"] == wid)
            .unwrap_or_else(|| panic!("missing source {wid} in {srcs:?}"));
        assert_eq!(s["status"], "skipped_headless", "{wid}: {s}");
    }

    let settings = en.invoke("settings_get", json!({})).await.unwrap();
    let ms = &settings["monitor_status"][&id];
    assert_eq!(ms["status"], "done", "{ms}");
    assert_eq!(ms["headless"], true, "{ms}");
    assert_eq!(ms["profile"], "passive", "{ms}");
    assert!(
        settings["source_status"]["startpage"].is_null(),
        "skipped_headless should not overwrite last live source_status: {settings}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn schedule_budget_soft_cancels_and_resumes_cleanly() {
    let e = env(400).await;
    let id = e.project("example.test").await;
    let r = e
        .call(
            "scan_start",
            json!({
                "project": id,
                "profile": "passive",
                "trigger": "schedule",
                "headless": true,
                "sources": ["wayback"],
                "budget_ms": 150
            }),
        )
        .await;
    assert!(e.engine.wait_idle(std::time::Duration::from_secs(30)).await);
    assert!(
        e.events
            .lock()
            .unwrap()
            .iter()
            .any(|x| x["type"] == "stopped" && x["reason"] == "budget"),
        "expected budget stopped event: {:?}",
        *e.events.lock().unwrap()
    );
    let snap = e.snap(&id).await;
    let rec = snap["scans"].as_array().unwrap().last().unwrap().clone();
    assert_eq!(rec["id"], r["scan_id"]);
    assert_eq!(rec["status"], "stopped", "{rec}");
    assert_eq!(rec["reason"], "budget", "{rec}");
    let settings = e.call("settings_get", json!({})).await;
    assert_eq!(settings["monitor_status"][&id]["status"], "budget");

    // Checkpoint is intact and can resume to completion.
    e.call(
        "scan_start",
        json!({
            "project": id,
            "profile": "passive",
            "trigger": "schedule",
            "resume_from": r["scan_id"],
            "sources": ["wayback"]
        }),
    )
    .await;
    e.wait().await;
    let snap2 = e.snap(&id).await;
    let rec2 = snap2["scans"].as_array().unwrap().last().unwrap().clone();
    assert_eq!(rec2["status"], "done", "{rec2}");
    let settings2 = e.call("settings_get", json!({})).await;
    assert_eq!(settings2["monitor_status"][&id]["status"], "done");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn second_engine_on_same_dir_returns_busy_until_dropped() {
    let srv = server(0).await;
    let dir = tempfile::tempdir().unwrap();
    let keys = std::sync::Arc::new(foca_engine::MemoryKeys::new());
    let sink = std::sync::Arc::new(foca_engine::MemoryEvents::new());
    let mut cfg1 = config(dir.path(), &srv.url());
    cfg1.lock_wait = std::time::Duration::from_millis(50);
    let en1 = foca_engine::Engine::open(cfg1, keys.clone(), sink.clone()).unwrap();

    let mut cfg2 = config(dir.path(), &srv.url());
    cfg2.headless = true;
    cfg2.lock_wait = std::time::Duration::from_millis(50);
    let err = match foca_engine::Engine::open(cfg2.clone(), keys.clone(), sink.clone()) {
        Ok(_) => panic!("second Engine::open on locked dir must fail with busy"),
        Err(e) => e,
    };
    assert_eq!(err.code, "busy", "{err:?}");

    drop(en1);
    let en2 = foca_engine::Engine::open(cfg2, keys, sink)
        .expect("Engine::open succeeds after first owner drops");
    assert!(en2.is_headless());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn alert_rules_and_test_delivery_never_leak_tokens() {
    use foca_net::testserver::{TestResponse, TestServer};
    use std::sync::Arc;

    let tg_seen = Arc::new(std::sync::Mutex::new(Vec::<(String, String)>::new()));
    let wh_seen = Arc::new(std::sync::Mutex::new(Vec::<(String, String)>::new()));
    let tg_c = tg_seen.clone();
    let wh_c = wh_seen.clone();

    let srv = TestServer::start(move |r| {
        let body = String::from_utf8_lossy(&r.body).into_owned();
        if r.path().contains("/sendMessage") {
            tg_c.lock().unwrap().push((r.path().to_string(), body));
            TestResponse::ok(br#"{"ok":true,"result":{"message_id":77}}"#.to_vec())
        } else if r.path().starts_with("/hook/") {
            wh_c.lock().unwrap().push((r.path().to_string(), body));
            TestResponse::ok(br#"{"ok":true}"#.to_vec())
        } else {
            TestResponse::status(404)
        }
    })
    .await;

    let base = srv.url();
    let dir = tempfile::tempdir().unwrap();
    let keys = Arc::new(foca_engine::MemoryKeys::new());
    let (en, _ev, _) = open_with(dir.path(), &base, keys, |c| {
        c.endpoints.sources.insert("telegram".into(), base.clone());
        c.endpoints
            .sources
            .insert("webhook".into(), format!("{base}/hook/fallback"));
    });
    let p = en
        .invoke(
            "project_create",
            json!({
                "name": "alerts.test",
                "targets": [{ "v": "example.test", "type": "domain", "active": false }],
                "excludes": []
            }),
        )
        .await
        .unwrap();
    let id = p["id"].as_str().unwrap().to_string();

    let bot_tok = "123456:AAFakeSecretBotTokenXYZ";
    let wh_secret_url = format!("{base}/hook/super-secret-wh-991");
    en.invoke("key_set", json!({ "service": "tg_bot", "value": bot_tok }))
        .await
        .unwrap();
    en.invoke(
        "key_set",
        json!({ "service": "webhook", "value": wh_secret_url }),
    )
    .await
    .unwrap();

    // Even if someone passes secret-like fields inside patch, settings_set/alert_rules_set strips them.
    let cfg = en
        .invoke(
            "alert_rules_set",
            json!({
                "project": id,
                "patch": {
                    "enabled": true,
                    "min_severity": "info",
                    "telegram": { "enabled": true, "chat_id": "99887766", "token": bot_tok },
                    "webhook": { "enabled": true, "kind": "generic", "url": wh_secret_url },
                    "lang": "ru"
                }
            }),
        )
        .await
        .unwrap();
    assert_eq!(cfg["enabled"], true);
    assert_eq!(cfg["telegram"]["ready"], true);
    assert_eq!(cfg["webhook"]["ready"], true);
    assert!(!cfg.to_string().contains(bot_tok));
    assert!(!cfg.to_string().contains("super-secret-wh-991"));

    let t_tg = en
        .invoke(
            "alert_test",
            json!({ "project": id, "channel": "telegram" }),
        )
        .await
        .unwrap();
    assert_eq!(t_tg["ok"], true, "{t_tg}");
    assert_eq!(t_tg["sent"], 1);

    let t_wh = en
        .invoke("alert_test", json!({ "project": id, "channel": "webhook" }))
        .await
        .unwrap();
    assert_eq!(t_wh["ok"], true, "{t_wh}");
    assert_eq!(t_wh["sent"], 1);

    assert_eq!(tg_seen.lock().unwrap().len(), 1);
    assert_eq!(wh_seen.lock().unwrap().len(), 1);
    assert!(wh_seen.lock().unwrap()[0]
        .1
        .contains("monitor-test.invalid"));

    let log = en
        .invoke("request_log_get", json!({ "project": id, "limit": 100 }))
        .await
        .unwrap();
    let log_str = log.to_string();
    assert!(!log_str.contains(bot_tok), "bot token leaked: {log_str}");
    assert!(
        !log_str.contains("super-secret-wh-991"),
        "webhook secret leaked: {log_str}"
    );
    assert!(log
        .as_array()
        .unwrap()
        .iter()
        .all(|r| r["module"] == "notify"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn monitor_scan_evaluates_alerts_deduplicates_and_tracks_risk_trend() {
    use foca_net::testserver::{TestResponse, TestServer};
    use std::sync::Arc;

    let deliveries = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
    let del_c = deliveries.clone();
    let wh_srv = TestServer::start(move |r| {
        del_c
            .lock()
            .unwrap()
            .push(String::from_utf8_lossy(&r.body).into_owned());
        TestResponse::ok(br#"{"ok":true}"#.to_vec())
    })
    .await;

    let srv = server(0).await;
    let dir = tempfile::tempdir().unwrap();
    let keys = Arc::new(foca_engine::MemoryKeys::new());
    let (en, ev, _) = open_with(dir.path(), &srv.url(), keys, |c| {
        c.endpoints.sources.insert("webhook".into(), wh_srv.url());
    });

    let wh_url = format!("{}/hook/scan-alerts-77", wh_srv.url());
    en.invoke("key_set", json!({ "service": "webhook", "value": wh_url }))
        .await
        .unwrap();
    en.invoke(
        "alert_rules_set",
        json!({
            "patch": {
                "enabled": true,
                "min_severity": "info",
                "webhook": { "enabled": true, "kind": "generic" },
                "lang": "ru"
            }
        }),
    )
    .await
    .unwrap();

    let p = en
        .invoke(
            "project_create",
            json!({
                "name": "trend.test",
                "targets": [{ "v": "example.test", "type": "domain", "active": false }],
                "excludes": []
            }),
        )
        .await
        .unwrap();
    let id = p["id"].as_str().unwrap().to_string();

    // Scan 1: baseline establishes snapshot (no diff alerts yet).
    en.invoke(
        "scan_start",
        json!({ "project": id, "profile": "passive", "trigger": "schedule", "sources": ["crt"] }),
    )
    .await
    .unwrap();
    assert!(en.wait_idle(std::time::Duration::from_secs(60)).await);
    let first_deliveries = deliveries.lock().unwrap().len();

    // Import an offline document with secret / GPS metadata, then run Scan 2.
    en.invoke(
        "doc_import",
        json!({ "project": id, "paths": [corpus_dir().join("ooxml/contract.docx").to_string_lossy()] }),
    )
    .await
    .unwrap();
    en.invoke(
        "scan_start",
        json!({ "project": id, "profile": "passive", "trigger": "schedule", "sources": ["crt"] }),
    )
    .await
    .unwrap();
    assert!(en.wait_idle(std::time::Duration::from_secs(60)).await);

    let after_second = deliveries.lock().unwrap().len();
    assert!(
        after_second > first_deliveries,
        "expected alert webhook delivery after new doc/finding scan"
    );
    let evs = ev.lock().unwrap().clone();
    let alert_evs: Vec<_> = evs.iter().filter(|x| x["type"] == "alert").collect();
    assert!(!alert_evs.is_empty(), "expected alert event in scan stream");
    let last_done = evs.iter().rfind(|x| x["type"] == "done").unwrap();
    assert!(last_done["alerts_fired"].as_u64().unwrap_or(0) > 0);
    // Secret plaintext must never be echoed into webhook body.
    let body_all = deliveries.lock().unwrap().join("\n");
    assert!(!body_all.contains("{{s:"));

    // Scan 3 with identical state must deduplicate and not re-fire the same alerts.
    en.invoke(
        "scan_start",
        json!({ "project": id, "profile": "passive", "trigger": "schedule", "sources": ["crt"] }),
    )
    .await
    .unwrap();
    assert!(en.wait_idle(std::time::Duration::from_secs(60)).await);
    assert_eq!(deliveries.lock().unwrap().len(), after_second);

    let trend = en
        .invoke("risk_trend_get", json!({ "project": id }))
        .await
        .unwrap();
    assert_eq!(trend["points"].as_array().unwrap().len(), 3, "{trend}");
    assert!(trend["current"].as_u64().is_some());
    assert!(trend["previous"].as_u64().is_some());
    assert!(trend["direction"].as_str().is_some());

    let rules_view = en
        .invoke("alert_rules_get", json!({ "project": id }))
        .await
        .unwrap();
    assert!(!rules_view["history"].as_array().unwrap().is_empty());
    assert!(!rules_view.to_string().contains("scan-alerts-77"));
}

/// Switching a channel on without its required settings is refused with a coded error, and a
/// test send of an incomplete channel reports a translatable error (`error_msg`).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn incomplete_alert_channels_are_refused_with_coded_errors() {
    let e = env(0).await;
    let err = e
        .err(
            "alert_rules_set",
            json!({ "patch": { "telegram": { "enabled": true, "chat_id": "" } } }),
        )
        .await;
    assert_eq!(err.code, "alert_not_ready");
    let ser = serde_json::to_value(&err).unwrap();
    assert_eq!(
        ser["message_msg"]["code"], "alert.tg_token_missing",
        "{ser}"
    );

    e.call(
        "key_set",
        json!({ "service": "tg_bot", "value": "123:abc" }),
    )
    .await;
    let err = e
        .err(
            "alert_rules_set",
            json!({ "patch": { "telegram": { "enabled": true, "chat_id": "  " } } }),
        )
        .await;
    let ser = serde_json::to_value(&err).unwrap();
    assert_eq!(ser["message_msg"]["code"], "alert.tg_chat_missing", "{ser}");

    let err = e
        .err(
            "alert_rules_set",
            json!({ "patch": { "webhook": { "enabled": true } } }),
        )
        .await;
    let ser = serde_json::to_value(&err).unwrap();
    assert_eq!(ser["message_msg"]["code"], "alert.webhook_missing", "{ser}");

    // nothing was switched on; other settings still save
    let cfg = e
        .call(
            "alert_rules_set",
            json!({ "patch": { "min_severity": "high" } }),
        )
        .await;
    assert_ne!(cfg["telegram"]["enabled"], true);
    assert_ne!(cfg["webhook"]["enabled"], true);

    let t = e.call("alert_test", json!({ "channel": "telegram" })).await;
    assert_eq!(t["ok"], false);
    assert_eq!(t["error_msg"]["code"], "alert.tg_chat_missing", "{t}");
}
