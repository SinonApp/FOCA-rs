//! Search side resilience in a core scan: dork groups lost to captchas are postponed per project
//! and retried (in the same scan after the cool-down, and on demand), the deep Common Crawl sweep
//! runs beside the other sources and resumes from its cache, and the key/instance checks of the
//! Brave API and own SearXNG answer from local fixtures.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use crate::common::*;
use foca_engine::{BoxFuture, MemoryKeys, RenderFetch, RenderPage, RenderRequest};
use foca_net::testserver::{TestResponse, TestServer};
use serde_json::{json, Value};

/// Startpage through a fake browser: a captcha while `captcha` is set (or for the first
/// `first_captchas` pages), results otherwise.
struct Flaky {
    captcha: AtomicBool,
    first_captchas: usize,
    n: AtomicUsize,
}

impl RenderFetch for Flaky {
    fn fetch<'a>(&'a self, _req: RenderRequest) -> BoxFuture<'a, Result<RenderPage, String>> {
        let n = self.n.fetch_add(1, Ordering::SeqCst);
        let captcha = self.captcha.load(Ordering::SeqCst) || n < self.first_captchas;
        Box::pin(async move {
            if captcha {
                return Ok(RenderPage {
                    html: "<html><body><h1>Please solve the captcha</h1></body></html>".into(),
                    url: "https://www.startpage.com/sp/captcha".into(),
                    aborted: Some("/captcha".into()),
                    ..Default::default()
                });
            }
            Ok(RenderPage {
                html: r#"<html><body><a class="result-title result-link" href="https://www.example.test/files/later.pdf">r</a></body></html>"#.into(),
                url: "https://www.startpage.com/sp/search".into(),
                ..Default::default()
            })
        })
    }
}

async fn invoke(e: &foca_engine::Engine, cmd: &str, a: Value) -> Value {
    e.invoke(cmd, a.clone())
        .await
        .unwrap_or_else(|x| panic!("{cmd} {a}: {x}"))
}

async fn project(e: &foca_engine::Engine) -> String {
    let p = invoke(
        e,
        "project_create",
        json!({ "name": "t", "targets": [{ "v": "example.test", "type": "domain" }] }),
    )
    .await;
    p["id"].as_str().unwrap().to_string()
}

async fn idle(e: &foca_engine::Engine, events: &Arc<std::sync::Mutex<Vec<Value>>>) {
    if !e.wait_idle(Duration::from_secs(60)).await {
        let ev = events.lock().unwrap().clone();
        let tail: Vec<String> = ev.iter().rev().take(12).map(|x| x.to_string()).collect();
        panic!("the scan did not finish: {tail:#?}");
    }
}

async fn pending_until(e: &foca_engine::Engine, id: &str, want: u64) -> Value {
    for _ in 0..400 {
        let p = invoke(e, "dorks_pending", json!({ "project": id })).await;
        if p["pending"] == want {
            return p;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("pending never reached {want}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn lost_dorks_are_postponed_and_retry_now_clears_them() {
    let dir = tempfile::tempdir().unwrap();
    let srv = server(0).await;
    let br = Arc::new(Flaky {
        captcha: AtomicBool::new(true),
        first_captchas: 0,
        n: AtomicUsize::new(0),
    });
    let b2 = br.clone();
    let (engine, events, _) =
        open_with(dir.path(), &srv.url(), Arc::new(MemoryKeys::new()), |cfg| {
            cfg.render = Some(b2)
        });
    let id = project(&engine).await;
    invoke(
        &engine,
        "scan_start",
        json!({ "project": id, "profile": "passive", "sources": ["startpage"], "exts": ["pdf"] }),
    )
    .await;
    idle(&engine, &events).await;
    let ev = events.lock().unwrap().clone();
    assert!(
        ev.iter()
            .any(|x| x["type"] == "warning" && x["code"] == "search_dorks_lost"),
        "{ev:?}"
    );
    let d = ev.iter().find(|x| x["type"] == "dorks").unwrap();
    assert_eq!(d["pending"], 1, "{d}");
    // the postponed group survives in the project
    let p = invoke(&engine, "dorks_pending", json!({ "project": id })).await;
    assert_eq!(p["pending"], 1, "{p}");
    assert_eq!(p["items"][0]["exts"], json!(["pdf"]));
    assert_eq!(p["items"][0]["domain"], "example.test");
    assert_eq!(p["items"][0]["tries"], 1);

    // the engine is healthy again: "Retry now" without a running scan starts a narrowed scan
    br.captcha.store(false, Ordering::SeqCst);
    events.lock().unwrap().clear();
    let r = invoke(&engine, "dorks_retry", json!({ "project": id })).await;
    assert_eq!(r["mode"], "scan", "{r}");
    idle(&engine, &events).await;
    let p = invoke(&engine, "dorks_pending", json!({ "project": id })).await;
    assert_eq!(p["pending"], 0, "{p}");
    let ev = events.lock().unwrap().clone();
    let started = ev.iter().find(|x| x["type"] == "started").unwrap();
    assert_eq!(
        started["stages"],
        json!(["search", "download", "meta", "analysis", "report"]),
        "a narrowed run of the dork engines: {started}"
    );
    let r = invoke(&engine, "dorks_retry", json!({ "project": id })).await;
    assert_eq!(r["mode"], "none");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn in_scan_retry_runs_after_cool_down_while_the_scan_runs() {
    let dir = tempfile::tempdir().unwrap();
    let srv = server(0).await;
    let br = Arc::new(Flaky {
        captcha: AtomicBool::new(false),
        first_captchas: 1,
        n: AtomicUsize::new(0),
    });
    let b2 = br.clone();
    let (engine, events, pause_at) =
        open_with(dir.path(), &srv.url(), Arc::new(MemoryKeys::new()), |cfg| {
            cfg.render = Some(b2)
        });
    invoke(
        &engine,
        "settings_set",
        json!({ "patch": { "search": { "dork_retry_min": 0.003, "dork_retry_gap_s": 0 } } }),
    )
    .await;
    let id = project(&engine).await;
    // the scan waits at the download stage, so it is still running when the cool-down ends
    *pause_at.lock().unwrap() = Some("download".into());
    invoke(
        &engine,
        "scan_start",
        json!({ "project": id, "profile": "passive", "sources": ["startpage"], "exts": ["pdf"] }),
    )
    .await;
    let d = loop {
        let ev = events.lock().unwrap().clone();
        if let Some(d) = ev
            .iter()
            .find(|x| x["type"] == "dorks" && x["retry_at"].is_number())
        {
            break d.clone();
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    };
    assert_eq!(d["pending"], 1, "{d}");
    // the retry ran Startpage again (no captcha now) and queued its document
    pending_until(&engine, &id, 0).await;
    let ev = events.lock().unwrap().clone();
    assert!(ev
        .iter()
        .any(|x| x["type"] == "dorks" && x["pending"] == 0 && x["retry_at"].is_null()));
    assert_eq!(br.n.load(Ordering::SeqCst), 2, "one captcha, one retry");
    *pause_at.lock().unwrap() = None;
    invoke(&engine, "scan_resume", json!({})).await;
    idle(&engine, &events).await;
}

/// Common Crawl index with two snapshots; counts every index call.
async fn cc_server() -> TestServer {
    let base = Arc::new(OnceLock::<String>::new());
    let b2 = base.clone();
    let srv = TestServer::start(move |r| {
        let b = b2.get().unwrap();
        match r.path() {
            "/collinfo.json" => TestResponse::ok(format!(
                r#"[{{"id":"CC-MAIN-2026-43","cdx-api":"{b}/A-index"}},{{"id":"CC-MAIN-2019-04","cdx-api":"{b}/B-index"}}]"#
            )),
            "/A-index" if r.query("showNumPages").is_some() => TestResponse::ok(r#"{"pages": 1}"#),
            "/A-index" => TestResponse::ok(
                "{\"url\": \"https://www.example.test/cc-new.pdf\", \"timestamp\": \"20261010000000\", \"mime\": \"application/pdf\", \"status\": \"200\"}\n",
            ),
            "/B-index" if r.query("showNumPages").is_some() => TestResponse::ok(r#"{"pages": 1}"#),
            "/B-index" => TestResponse::ok(
                "{\"url\": \"https://www.example.test/cc-old.pdf\", \"timestamp\": \"20190110000000\", \"mime\": \"application/pdf\", \"status\": \"200\"}\n",
            ),
            _ => TestResponse::status(404),
        }
    })
    .await;
    base.set(srv.url()).unwrap();
    srv
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn deep_common_crawl_runs_beside_sources_and_resumes_from_cache() {
    let dir = tempfile::tempdir().unwrap();
    let srv = server(0).await;
    let cc = cc_server().await;
    let col = format!("{}/collinfo.json", cc.url());
    let (engine, events, _) =
        open_with(dir.path(), &srv.url(), Arc::new(MemoryKeys::new()), |cfg| {
            cfg.endpoints.cc_collinfo = col
        });
    let id = project(&engine).await;
    let scan = |cc_depth: &'static str| {
        let (engine, id) = (engine.clone(), id.clone());
        async move {
            invoke(
                &engine,
                "scan_start",
                json!({ "project": id, "profile": "passive", "sources": ["cc", "crt"],
                    "exts": ["pdf"], "cc_depth": cc_depth }),
            )
            .await;
            assert!(engine.wait_idle(Duration::from_secs(60)).await);
        }
    };
    scan("all").await;
    let ev = events.lock().unwrap().clone();
    let last = ev
        .iter()
        .rfind(|x| x["type"] == "source" && x["id"] == "cc")
        .cloned()
        .unwrap();
    assert_eq!(last["status"], "ok", "{last}");
    assert_eq!(last["n"], 2, "both snapshots of the deep sweep: {last}");
    // crt answered on its own, not after the sweep
    assert!(ev
        .iter()
        .any(|x| x["type"] == "source" && x["id"] == "crt" && x["status"] == "ok"));
    assert!(dir.path().join("cc-cache").read_dir().unwrap().count() >= 1);
    let calls = cc.hits("/A-index") + cc.hits("/B-index");
    assert_eq!(calls, 4);
    // the wizard depth survives in the scan options; a rescan resumes: no index call
    scan("all").await;
    assert_eq!(cc.hits("/A-index") + cc.hits("/B-index"), calls);
    // quick mode reuses the cached snapshots as well
    scan("latest").await;
    assert_eq!(cc.hits("/B-index"), 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn key_check_for_brave_and_own_searx() {
    let dir = tempfile::tempdir().unwrap();
    let srv = server(0).await;
    let api = TestServer::start(|r| match r.path() {
        "/res/v1/web/search" => match r.headers.get("x-subscription-token").map(String::as_str) {
            Some("BSA-good") => TestResponse::ok(r#"{"web":{"results":[]}}"#)
                .header("X-RateLimit-Limit", "1, 1000")
                .header("X-RateLimit-Remaining", "1, 990"),
            _ => TestResponse::status(401),
        },
        "/search" => TestResponse::ok(r#"{"results":[{"url":"https://www.example.test/a.pdf"}]}"#),
        _ => TestResponse::status(404),
    })
    .await;
    let base = api.url();
    let (engine, _, _) = open_with(dir.path(), &srv.url(), Arc::new(MemoryKeys::new()), |cfg| {
        cfg.endpoints.sources.insert("brave".into(), base);
    });
    let r = invoke(
        &engine,
        "key_check",
        json!({ "service": "brave", "value": "BSA-good" }),
    )
    .await;
    assert_eq!(r["ok"], true, "{r}");
    assert_eq!(
        (r["remaining"].as_u64(), r["limit"].as_u64()),
        (Some(990), Some(1000))
    );
    let r = invoke(
        &engine,
        "key_check",
        json!({ "service": "brave", "value": "nope" }),
    )
    .await;
    assert_eq!(r["code"], "rejected");
    let r = invoke(&engine, "key_check", json!({ "service": "brave" })).await;
    assert_eq!(r["code"], "nokey");
    let r = invoke(
        &engine,
        "key_check",
        json!({ "service": "searx", "value": api.url() }),
    )
    .await;
    assert_eq!(r["ok"], true, "{r}");
    assert_eq!(r["instances"][0]["results"], 1);
}
