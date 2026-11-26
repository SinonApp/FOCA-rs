//! Dorks through the embedded browser in a core scan: without a RenderFetch (CLI/serve) the
//! Startpage/Brave sources report `unavailable` and the scan moves on; with a fake browser they find URLs.

use std::sync::Arc;

use crate::common::*;
use foca_engine::{BoxFuture, MemoryKeys, RenderFetch, RenderPage, RenderRequest};
use serde_json::{json, Value};

fn src_events(ev: &[Value], id: &str) -> Vec<Value> {
    ev.iter()
        .filter(|x| x["type"] == "source" && x["id"] == id)
        .cloned()
        .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn without_webview_sources_are_unavailable() {
    let e = env(0).await;
    let id = e.project("example.test").await;
    e.call(
        "scan_start",
        json!({ "project": id, "profile": "passive", "sources": ["startpage", "brave_web", "crt"] }),
    )
    .await;
    e.wait().await;
    let ev = e.events();
    for s in ["startpage", "brave_web"] {
        let last = src_events(&ev, s).last().cloned().unwrap();
        assert_eq!(last["status"], "unavailable", "{last}");
        assert!(
            last["error"].as_str().unwrap().contains("WebView"),
            "{last}"
        );
    }
    let done = ev.iter().find(|x| x["type"] == "done").unwrap();
    assert_ne!(done["status"], "error", "{done}");
    // names for the scan screen
    let sp = src_events(&ev, "startpage").last().cloned().unwrap();
    assert_eq!(sp["name"], "Startpage (через браузер)");
}

struct FakeBrowser;

impl RenderFetch for FakeBrowser {
    fn fetch<'a>(&'a self, req: RenderRequest) -> BoxFuture<'a, Result<RenderPage, String>> {
        let q = serde_json::to_string(&req.steps).unwrap();
        let ext = ["pdf", "docx", "xlsx"]
            .into_iter()
            .find(|x| q.contains(&format!("filetype:{x}")))
            .unwrap_or("txt");
        let html = format!(
            r#"<html><body><a class="result-title result-link" href="https://www.example.test/files/startpage-1.{ext}">r</a>
               <a class="result-link" href="https://evil.example.org/x.{ext}">out of scope</a></body></html>"#
        );
        Box::pin(async move {
            Ok(RenderPage {
                html,
                url: "https://www.startpage.com/sp/search".into(),
                ms: 1,
                ..Default::default()
            })
        })
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn with_webview_startpage_finds_documents() {
    let dir = tempfile::tempdir().unwrap();
    let srv = server(0).await;
    let (engine, events, _) =
        open_with(dir.path(), &srv.url(), Arc::new(MemoryKeys::new()), |cfg| {
            cfg.render = Some(Arc::new(FakeBrowser))
        });
    let p = engine
        .invoke(
            "project_create",
            json!({ "name": "t", "targets": [{ "v": "example.test", "type": "domain" }] }),
        )
        .await
        .unwrap();
    let id = p["id"].as_str().unwrap().to_string();
    engine
        .invoke(
            "scan_start",
            json!({ "project": id, "profile": "passive", "sources": ["startpage"] }),
        )
        .await
        .unwrap();
    assert!(engine.wait_idle(std::time::Duration::from_secs(60)).await);
    let ev = events.lock().unwrap().clone();
    let last = src_events(&ev, "startpage").last().cloned().unwrap();
    assert_eq!(last["status"], "ok", "{last}");
    assert!(last["n"].as_u64().unwrap() >= 1, "{last}");
    // request log: RENDER to the search engine, passive; nothing to evil.example.org
    let log = engine
        .invoke("request_log_get", json!({ "project": id }))
        .await
        .unwrap();
    let rows = log.as_array().unwrap();
    assert!(rows
        .iter()
        .any(|r| r["method"] == "RENDER" && r["module"] == "startpage"));
    assert!(!log.to_string().contains("evil.example.org"));
}

/// The run wizard sends only the disabled sources (`sources_off`); all others, including those not
/// shown in the wizard (ddg/bing/mojeek dorks, subdomain sources), must be queried.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn wizard_sources_off_keeps_unlisted_sources() {
    let e = env(0).await;
    let id = e.project("example.test").await;
    e.call(
        "scan_start",
        json!({ "project": id, "profile": "passive", "sources_off": ["wayback"] }),
    )
    .await;
    e.wait().await;
    let ev = e.events();
    let last = |s: &str| src_events(&ev, s).last().cloned();
    let wb = last("wayback").expect("wayback is in the source list");
    assert_eq!(wb["status"], "off", "{wb}");
    for s in ["ddg", "bing", "mojeek", "crtname", "hackertarget"] {
        let x = last(s).unwrap_or_else(|| panic!("no events for source {s}"));
        assert_ne!(x["status"], "off", "{s} dropped out of the scan: {x}");
    }
}

/// Startpage shows a captcha: status `blocked` with `verify_url` (the manual check button);
/// `scan_retry_source` during the search stage queries the source again and it answers `ok`; after
/// the scan a retry is rejected with an accurate reason.
struct CaptchaOnce {
    sp: std::sync::atomic::AtomicUsize,
}

impl RenderFetch for CaptchaOnce {
    fn fetch<'a>(&'a self, req: RenderRequest) -> BoxFuture<'a, Result<RenderPage, String>> {
        Box::pin(async move {
            if req.session == "brave" {
                // a slow neighboring source keeps the search stage running
                tokio::time::sleep(std::time::Duration::from_millis(2500)).await;
                return Ok(RenderPage {
                    html: "<html><body>no results</body></html>".into(),
                    url: "https://search.brave.com/search".into(),
                    ..Default::default()
                });
            }
            let n = self.sp.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if n == 0 {
                return Ok(RenderPage {
                    html: "<html><body><h1>Please solve the captcha</h1></body></html>".into(),
                    url: "https://www.startpage.com/sp/captcha".into(),
                    aborted: Some("/captcha".into()),
                    ..Default::default()
                });
            }
            Ok(RenderPage {
                html: r#"<html><body><a class="result-title result-link" href="https://www.example.test/files/after-captcha.pdf">r</a></body></html>"#.into(),
                url: "https://www.startpage.com/sp/search".into(),
                ..Default::default()
            })
        })
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn captcha_verify_then_retry_source() {
    let dir = tempfile::tempdir().unwrap();
    let srv = server(0).await;
    let (engine, events, _) =
        open_with(dir.path(), &srv.url(), Arc::new(MemoryKeys::new()), |cfg| {
            cfg.render = Some(Arc::new(CaptchaOnce {
                sp: Default::default(),
            }))
        });
    let p = engine
        .invoke(
            "project_create",
            json!({ "name": "t", "targets": [{ "v": "example.test", "type": "domain" }] }),
        )
        .await
        .unwrap();
    let id = p["id"].as_str().unwrap().to_string();
    let bad = engine
        .invoke("scan_retry_source", json!({ "id": "crt" }))
        .await;
    assert!(
        bad.is_err(),
        "the rerun covers only browser-based search engines"
    );
    engine
        .invoke(
            "scan_start",
            json!({ "project": id, "profile": "passive", "sources": ["startpage", "brave_web"], "exts": ["pdf"] }),
        )
        .await
        .unwrap();
    // wait for the Startpage captcha
    let t0 = std::time::Instant::now();
    let blocked = loop {
        let ev = events.lock().unwrap().clone();
        if let Some(x) = src_events(&ev, "startpage")
            .into_iter()
            .find(|x| x["status"] == "blocked")
        {
            break x;
        }
        assert!(t0.elapsed().as_secs() < 20, "no blocked: {ev:?}");
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    };
    assert_eq!(
        blocked["verify_url"], "https://www.startpage.com/",
        "{blocked}"
    );
    assert!(blocked["error"].as_str().unwrap().contains("капч"));
    let r = engine
        .invoke("scan_retry_source", json!({ "id": "startpage" }))
        .await
        .unwrap();
    assert_eq!(r["ok"], true, "{r}");
    assert!(engine.wait_idle(std::time::Duration::from_secs(60)).await);
    let ev = events.lock().unwrap().clone();
    let last = src_events(&ev, "startpage").last().cloned().unwrap();
    assert_eq!(last["status"], "ok", "rerun after the check: {last}");
    assert!(last["n"].as_u64().unwrap() >= 1, "{last}");
    let r = engine
        .invoke("scan_retry_source", json!({ "id": "startpage" }))
        .await
        .unwrap();
    assert_eq!(r["ok"], false);
    assert!(r["reason"].as_str().unwrap().contains("следующий скан"));
}

/// Debug → Search engines: the embedded browser fingerprint, the engine statistics and the page for Chrome.
struct FpBrowser;

impl RenderFetch for FpBrowser {
    fn fetch<'a>(&'a self, req: RenderRequest) -> BoxFuture<'a, Result<RenderPage, String>> {
        assert_eq!(req.session, "fingerprint");
        assert!(req.html.as_deref().unwrap().contains("visibilityState"));
        assert_eq!(req.ua, "mobile");
        Box::pin(async move {
            Ok(RenderPage {
                html: r#"<html><body><pre id="out">{"userAgent":"Mozilla/5.0 (Linux; Android 14; X) Chrome/141 Mobile Safari/537.36","visibilityState":"hidden","issues":["страница не видима (hidden)"]}</pre><i id="done"></i></body></html>"#.into(),
                url: "https://fingerprint.foca.invalid/".into(),
                ..Default::default()
            })
        })
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn search_fingerprint_journal_and_page() {
    let dir = tempfile::tempdir().unwrap();
    let srv = server(0).await;
    let (engine, _, _) = open_with(dir.path(), &srv.url(), Arc::new(MemoryKeys::new()), |cfg| {
        cfg.render = Some(Arc::new(FpBrowser))
    });
    let r = engine
        .invoke("search_fingerprint", json!({}))
        .await
        .unwrap();
    assert_eq!(r["fp"]["visibilityState"], "hidden");
    assert_eq!(r["issues"][0], "страница не видима (hidden)");
    let j = engine.invoke("search_journal", json!({})).await.unwrap();
    assert!(j["engines"].is_object());
    let pg = engine
        .invoke("search_fingerprint_page", json!({}))
        .await
        .unwrap();
    let html = std::fs::read_to_string(pg["path"].as_str().unwrap()).unwrap();
    assert!(html.contains("navigator.userAgentData"));
    // without an embedded browser: an explicit "app only"
    let (e2, _, _) = open_with(
        tempfile::tempdir().unwrap().path(),
        &srv.url(),
        Arc::new(MemoryKeys::new()),
        |_| {},
    );
    let err = e2
        .invoke("search_fingerprint", json!({}))
        .await
        .unwrap_err();
    assert_eq!(err.code, "unsupported");
}
