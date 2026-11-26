//! Debug tab and first run: terms_get/terms_accept (plus reset by wipe_all), core and Android logs,
//! crashes, the project request log, ZIP log export without secrets, and clearing.

mod common;

use std::io::Read as _;

use common::*;
use serde_json::{json, Value};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn terms_accept_and_wipe_resets() {
    let e = env(0).await;
    let t = e.call("terms_get", json!({})).await;
    assert_eq!(t["accepted"], false);
    assert_eq!(t["version"], foca_engine::TERMS_VERSION);
    let er = e.err("terms_accept", json!({ "version": "0" })).await;
    assert_eq!(er.code, "bad_args");
    // acceptance cannot be forged through settings_set
    e.call(
        "settings_set",
        json!({ "patch": { "terms": { "terms_version": foca_engine::TERMS_VERSION, "accepted_at": "x" } } }),
    )
    .await;
    assert_eq!(e.call("terms_get", json!({})).await["accepted"], false);
    let t = e
        .call(
            "terms_accept",
            json!({ "version": foca_engine::TERMS_VERSION }),
        )
        .await;
    assert_eq!(t["accepted"], true);
    assert!(t["accepted_at"].as_str().unwrap().starts_with("20"));
    assert!(e
        .call("settings_get", json!({}))
        .await
        .get("terms")
        .is_none());
    e.call("wipe_all", json!({ "confirm": "WIPE" })).await;
    assert_eq!(e.call("terms_get", json!({})).await["accepted"], false);
}

fn zip_text(path: &str) -> (Vec<String>, String) {
    let f = std::fs::File::open(path).unwrap();
    let mut z = zip::ZipArchive::new(f).unwrap();
    let mut names = Vec::new();
    let mut all = String::new();
    for i in 0..z.len() {
        let mut x = z.by_index(i).unwrap();
        names.push(x.name().map(|n| n.to_string()).unwrap_or_default());
        let mut s = String::new();
        x.read_to_string(&mut s).unwrap();
        all.push_str(&s);
    }
    (names, all)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn debug_logs_requests_crashes_export_without_secrets() {
    let e = env(0).await;
    let id = e.project("example.test").await;
    e.passive_scan(&id).await;
    // an API key in the key store and secrets from project documents
    e.call(
        "key_set",
        json!({ "service": "brave", "value": "BSAqTOPSECRETkey9876" }),
    )
    .await;
    let logs = e.dir.path().join("logs");
    std::fs::create_dir_all(&logs).unwrap();
    std::fs::write(
        logs.join("android.log"),
        "2026-11-20T12:00:00.000 I [main] старт\n\
         2026-11-20T12:00:01.000 W [io] GET https://api.search.brave.com/res?q=x&key=BSAqTOPSECRETkey9876\n\
         2026-11-20T12:00:02.000 E [io] прокси socks5://ivan:Hunter22pass@10.0.0.1:1080 недоступен | java.lang.X\n    at a.b(C.kt:1)\n",
    )
    .unwrap();
    std::fs::write(
        logs.join("crash-20261120-120000-000.txt"),
        "паника: token=abcSECRETtoken123 при разборе\n",
    )
    .unwrap();
    // logs: core and Android
    let all = e
        .call("logs_get", json!({ "source": "all", "limit": 2000 }))
        .await;
    let all = all.as_array().unwrap();
    assert!(
        all.iter().any(|x| x["source"] == "core"),
        "no core log entries after the scan"
    );
    assert!(all
        .iter()
        .any(|x| x["source"] == "android" && x["level"] == "error"));
    let errs = e
        .call("logs_get", json!({ "source": "android", "level": "error" }))
        .await;
    assert_eq!(errs.as_array().unwrap().len(), 1);
    // project requests with their access class
    let req = e.call("request_log_get", json!({ "project": id })).await;
    let req = req.as_array().unwrap();
    assert!(!req.is_empty());
    assert!(req.iter().all(|r| r["access"].is_string()));
    let only = e
        .call(
            "request_log_get",
            json!({ "project": id, "only_active": true }),
        )
        .await;
    assert!(only
        .as_array()
        .unwrap()
        .iter()
        .all(|r| r["access"] != "passive"));
    // crashes
    let cl = e.call("crash_list", json!({})).await;
    assert_eq!(cl.as_array().unwrap().len(), 1);
    let c = e
        .call(
            "crash_get",
            json!({ "name": "crash-20261120-120000-000.txt" }),
        )
        .await;
    assert!(!c["text"].as_str().unwrap().contains("abcSECRETtoken123"));
    let er = e
        .err("crash_get", json!({ "name": "../projects.db" }))
        .await;
    assert_eq!(er.code, "bad_args");
    // export: a ZIP without secrets
    let secrets: Vec<String> = {
        let s = e.snap(&id).await;
        let mut v = vec![
            "BSAqTOPSECRETkey9876".to_string(),
            "Hunter22pass".into(),
            "abcSECRETtoken123".into(),
        ];
        for x in s["secrets"].as_array().cloned().unwrap_or_default() {
            let r = e
                .call("secret_reveal", json!({ "project": id, "id": x["id"] }))
                .await;
            if let Some(val) = r["value"].as_str().filter(|v| v.chars().count() >= 4) {
                v.push(val.to_string());
            }
        }
        v
    };
    let x = e
        .call(
            "logs_export",
            json!({ "device": "Модель: Test · ключ BSAqTOPSECRETkey9876" }),
        )
        .await;
    let (names, text) = zip_text(x["path"].as_str().unwrap());
    for n in ["foca.log", "android.log", "device.txt"] {
        assert!(
            names.iter().any(|m| m == n),
            "{n} missing from the archive: {names:?}"
        );
    }
    assert!(names.iter().any(|m| m.starts_with("crashes/crash-")));
    for s in &secrets {
        assert!(
            !text.contains(s.as_str()),
            "secret {s} leaked into the archive"
        );
    }
    assert!(text.contains("socks5://ivan:***@10.0.0.1:1080"));
    assert!(text.contains("старт"));
    // runtime log level and build info
    e.call(
        "settings_set",
        json!({ "patch": { "debug": { "level": "debug" } } }),
    )
    .await;
    let a = e.call("app_info", json!({})).await;
    assert_eq!(a["log_level"], "debug");
    assert!(a["version"].is_string());
    // clearing
    e.call("logs_clear", json!({})).await;
    assert!(e
        .call("crash_list", json!({}))
        .await
        .as_array()
        .unwrap()
        .is_empty());
    let left: Value = e.call("logs_get", json!({ "source": "android" })).await;
    assert!(left.as_array().unwrap().is_empty());
}
