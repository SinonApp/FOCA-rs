//! Deep Common Crawl sweep, adaptive rate limiting and the keyed dork engines (own SearXNG,
//! Brave Search API) against local fake servers. No real service is contacted.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use foca_core::Scope;
use foca_net::testserver::{TestResponse, TestServer};
use foca_net::{MemorySink, NetClient, NetConfig};
use foca_search::sources::{check_brave, check_searx, Brave, CcDepth, CommonCrawl, Searx, Wayback};
use foca_search::{run_sources, DocumentSource, ExtFilter, SearchCtx, SourceStatus};

fn net() -> NetClient {
    let (scope, _) = Scope::from_lines("", "");
    let cfg = NetConfig {
        global_rps: None,
        source_rps: Default::default(),
        retries: 0,
        backoff_base: Duration::from_millis(5),
        ..Default::default()
    };
    NetClient::new(cfg, scope, Arc::new(MemorySink::new())).unwrap()
}

fn ctx() -> SearchCtx {
    let mut c = SearchCtx::new(net());
    c.filter = ExtFilter::parse("pdf,docx");
    c
}

fn row(url: &str, ts: &str) -> String {
    format!(
        "{{\"url\": \"{url}\", \"timestamp\": \"{ts}\", \"mime\": \"application/pdf\", \"status\": \"200\", \"length\": \"100\"}}\n"
    )
}

/// Five snapshots behaving like the real index on a bad day: two pages, "no captures" (404),
/// transient 502/504 before a good answer, an empty snapshot and one that always fails.
async fn flaky_index() -> (TestServer, Arc<AtomicUsize>) {
    let base = Arc::new(OnceLock::<String>::new());
    let b2 = base.clone();
    let c_calls = Arc::new(AtomicUsize::new(0));
    let c2 = c_calls.clone();
    let srv = TestServer::start(move |r| {
        let b = b2.get().unwrap();
        let num = r.query("showNumPages").is_some();
        match r.path() {
            "/collinfo.json" => TestResponse::ok(format!(
                r#"[{{"id":"CC-MAIN-2026-43","cdx-api":"{b}/A-index"}},
                    {{"id":"CC-MAIN-2026-30","cdx-api":"{b}/B-index"}},
                    {{"id":"CC-MAIN-2025-51","cdx-api":"{b}/C-index"}},
                    {{"id":"CC-MAIN-2025-08","cdx-api":"{b}/D-index"}},
                    {{"id":"CC-MAIN-2019-04","cdx-api":"{b}/E-index"}}]"#
            )),
            "/A-index" => {
                assert_eq!(r.query("url").as_deref(), Some("*.example.com"));
                if num {
                    return TestResponse::ok(r#"{"pages": 2}"#);
                }
                // filters run on the server: status and the file type regex of the URL
                assert!(r.target.contains("filter=status%3A200"), "{}", r.target);
                assert!(r.query("filter").is_some());
                assert!(r.target.contains("%7Eurl%3A"), "{}", r.target);
                match r.query("page").as_deref() {
                    Some("0") => TestResponse::ok(
                        row("https://www.example.com/a.pdf", "20261010000000")
                            + &row("https://www.example.com/page.html", "20261010000000"),
                    ),
                    _ => TestResponse::ok(row("https://docs.example.com/b.docx", "20261011000000")),
                }
            }
            // "No Captures found": skipped without a page request
            "/B-index" => TestResponse::status(404),
            "/C-index" => match c2.fetch_add(1, Ordering::SeqCst) {
                0 => TestResponse::status(502),
                1 => TestResponse::status(504),
                _ if num => TestResponse::ok(r#"{"pages": 1}"#),
                // the same document as in A, captured earlier
                _ => TestResponse::ok(row("http://www.example.com/a.pdf", "20251201000000")),
            },
            "/D-index" => {
                assert!(num, "an empty snapshot gets no page request");
                TestResponse::ok(r#"{"pages": 0}"#)
            }
            _ => TestResponse::status(500),
        }
    })
    .await;
    base.set(srv.url()).unwrap();
    (srv, c_calls)
}

#[tokio::test]
async fn deep_sweep_paces_retries_dedupes_and_resumes() {
    let (srv, _) = flaky_index().await;
    let dir = tempfile::tempdir().unwrap();
    let cc = CommonCrawl {
        pace: Some(Duration::from_millis(20)),
        backoff: Some(Duration::from_millis(5)),
        retries: 2,
        cache_dir: Some(dir.path().to_path_buf()),
        ..CommonCrawl::with_collinfo(&format!("{}/collinfo.json?deep", srv.url()))
    }
    .with_depth(CcDepth::All);
    let c = ctx();
    let t0 = Instant::now();
    let f = cc.find(&c, "example.com").await.unwrap();
    let elapsed = t0.elapsed();
    let mut urls: Vec<&str> = f.urls.iter().map(|u| u.url.as_str()).collect();
    urls.sort();
    assert_eq!(
        urls,
        vec![
            "https://docs.example.com/b.docx",
            "https://www.example.com/a.pdf"
        ],
        "html dropped, a.pdf from two snapshots kept once"
    );
    // the newest capture is the date (the Wayback fallback looks for a copy near it)
    let a = f.urls.iter().find(|u| u.url.ends_with("a.pdf")).unwrap();
    assert_eq!(a.date.as_deref(), Some("20261010000000"));
    assert!(f.hosts.contains(&"docs.example.com".to_string()));
    // E always fails: partial note with resume hint
    let note = f.note.clone().unwrap();
    assert!(note.contains("E-index"), "{note}");
    assert!(note.contains("остальные продолжатся"), "{note}");
    assert_eq!(srv.hits("/A-index"), 3);
    assert_eq!(srv.hits("/B-index"), 1);
    assert_eq!(srv.hits("/C-index"), 4, "502 and 504 retried");
    assert_eq!(srv.hits("/D-index"), 1);
    assert_eq!(srv.hits("/E-index"), 3, "one call plus two retries");
    // paced: at least 20 ms between the 12 index calls
    assert!(elapsed >= Duration::from_millis(200), "{elapsed:?}");
    // first and last capture are kept in the cache file
    let st = cc.load_state("example.com", &c.filter);
    let h = st.hits.values().find(|h| h.url.ends_with("a.pdf")).unwrap();
    assert_eq!(
        (h.first.as_str(), h.last.as_str()),
        ("20251201000000", "20261010000000")
    );
    assert_eq!(st.done.len(), 4);

    // a rescan resumes: finished snapshots send nothing, only E is asked again
    let f2 = cc.find(&c, "example.com").await.unwrap();
    assert_eq!(f2.urls.len(), 2);
    assert_eq!(srv.hits("/A-index"), 3);
    assert_eq!(srv.hits("/C-index"), 4);
    assert_eq!(srv.hits("/E-index"), 6);
}

#[tokio::test]
async fn quick_mode_stops_after_latest_answers() {
    let (srv, _) = flaky_index().await;
    let cc = CommonCrawl {
        max_indexes: 2,
        ..CommonCrawl::with_collinfo(&format!("{}/collinfo.json?quick", srv.url()))
    };
    let f = cc.find(&ctx(), "example.com").await.unwrap();
    assert_eq!(f.urls.len(), 2);
    // A and B answered (B with "no captures"); older snapshots are not touched
    assert_eq!(srv.hits("/C-index"), 0);
    assert_eq!(srv.hits("/E-index"), 0);
}

#[tokio::test]
async fn years_depth_skips_old_snapshots() {
    let (srv, _) = flaky_index().await;
    let cc = CommonCrawl::with_collinfo(&format!("{}/collinfo.json?years", srv.url()))
        .with_depth(CcDepth::Years(2));
    let _ = cc.find(&ctx(), "example.com").await.unwrap();
    assert!(
        srv.hits("/D-index") >= 1,
        "2025 is within two years of 2026"
    );
    assert_eq!(srv.hits("/E-index"), 0, "2019 is outside");
}

#[tokio::test]
async fn throttled_index_stops_with_limit_status() {
    let base = Arc::new(OnceLock::<String>::new());
    let b2 = base.clone();
    let srv = TestServer::start(move |r| match r.path() {
        "/collinfo.json" => TestResponse::ok(format!(
            r#"[{{"id":"CC-MAIN-2026-43","cdx-api":"{0}/A-index"}},{{"id":"CC-MAIN-2026-30","cdx-api":"{0}/B-index"}}]"#,
            b2.get().unwrap()
        )),
        _ => TestResponse::status(503).header("Retry-After", "0"),
    })
    .await;
    base.set(srv.url()).unwrap();
    let cc = CommonCrawl::with_collinfo(&format!("{}/collinfo.json?thr", srv.url()))
        .with_depth(CcDepth::All);
    let srcs: Vec<Box<dyn DocumentSource>> = vec![Box::new(cc)];
    let res = run_sources(&srcs, &ctx(), "example.com", |_| {})
        .await
        .unwrap();
    let r = &res.sources[0];
    assert_eq!(r.status, SourceStatus::Limit, "{r:?}");
    assert!(r.error.as_deref().unwrap().contains("HTTP 429"), "{r:?}");
    // three limited answers in a row stop the sweep: B is never asked
    assert_eq!(srv.hits("/A-index"), 3);
    assert_eq!(srv.hits("/B-index"), 0);
}

#[tokio::test]
async fn wayback_honours_retry_after_then_stops_with_note() {
    let srv = TestServer::start(|r| {
        if r.query("showNumPages").is_some() {
            return TestResponse::ok("6");
        }
        if r.query("page").is_none() {
            return TestResponse::status(504);
        }
        match r.query("page").as_deref() {
            Some("0") => TestResponse::ok(
                "20200101000000 https://www.example.com/a.pdf application/pdf 200 1\n",
            ),
            _ => TestResponse::status(429).header("Retry-After", "0"),
        }
    })
    .await;
    let f = Wayback::with_base(&srv.url())
        .find(&ctx(), "example.com")
        .await
        .unwrap();
    assert_eq!(f.urls.len(), 1);
    assert!(
        f.note.as_deref().unwrap().contains("ограничил частоту"),
        "{f:?}"
    );
    // page 0 ok, then three limited pages stop the source: pages 4 and 5 are never asked
    let mut pages: Vec<String> = srv
        .requests()
        .iter()
        .filter_map(|r| r.query("page"))
        .collect();
    pages.sort();
    pages.dedup();
    assert_eq!(pages, vec!["0", "1", "2", "3"]);
}

#[tokio::test]
async fn service_503_after_retries_is_limit_status() {
    let srv = TestServer::start(|_| TestResponse::status(503)).await;
    let srcs: Vec<Box<dyn DocumentSource>> = vec![Box::new(Searx::local(&srv.url()))];
    let res = run_sources(&srcs, &ctx(), "example.com", |_| {})
        .await
        .unwrap();
    assert_eq!(res.sources[0].status, SourceStatus::Limit);
    assert!(res.sources[0]
        .error
        .as_deref()
        .unwrap()
        .contains("HTTP 429"));
}

const SEARX_JSON: &str = r#"{"results": [
  {"url": "https://www.example.com/files/plan.pdf", "publishedDate": "2025-01-02"},
  {"url": "https://www.example.com/report.docx"},
  {"url": "https://other.example.org/x.pdf"}
]}"#;

#[tokio::test]
async fn own_searx_skips_instance_without_json_and_runs_dorks() {
    let bad = TestServer::start(|_| TestResponse::status(403)).await;
    let good = TestServer::start(|r| {
        assert_eq!(r.path(), "/search");
        assert_eq!(r.query("format").as_deref(), Some("json"));
        assert!(r.query("q").unwrap().starts_with("site:example.com"));
        TestResponse::ok(SEARX_JSON)
    })
    .await;
    let sx = Searx::local(&format!("{}/, {}", bad.url(), good.url()));
    assert_eq!(sx.instances.len(), 2);
    let f = sx.find(&ctx(), "example.com").await.unwrap();
    let mut urls: Vec<&str> = f.urls.iter().map(|u| u.url.as_str()).collect();
    urls.sort();
    assert_eq!(
        urls,
        vec![
            "https://www.example.com/files/plan.pdf",
            "https://www.example.com/report.docx"
        ]
    );
    assert_eq!(
        bad.hits("/search"),
        1,
        "an instance without JSON is skipped after one try"
    );
    // pdf and the doc family: one OR query per group
    assert_eq!(good.hits("/search"), 2);
}

#[tokio::test]
async fn own_searx_requires_public_https() {
    // plain HTTP on loopback is refused outside tests and the local bench
    let srv = TestServer::start(|_| TestResponse::ok(SEARX_JSON)).await;
    let sx = Searx::new(Some(srv.url()));
    let srcs: Vec<Box<dyn DocumentSource>> = vec![Box::new(sx)];
    let res = run_sources(&srcs, &ctx(), "example.com", |_| {})
        .await
        .unwrap();
    assert_eq!(res.sources[0].status, SourceStatus::Error);
    assert_eq!(srv.hits("/search"), 0);
    let checks = check_searx(&net(), &srv.url(), false).await;
    assert_eq!(checks[0].1.code, "bad_url");
    assert_eq!(srv.hits("/search"), 0);
    assert!(foca_search::sources::public_https_url(
        "https://searx.example.com"
    ));
    assert!(!foca_search::sources::public_https_url(
        "https://192.168.1.5"
    ));
}

#[tokio::test]
async fn searx_check_reports_json_and_results() {
    let srv = TestServer::start(|r| match r.path() {
        "/off/search" => TestResponse::status(403),
        _ => TestResponse::ok(SEARX_JSON),
    })
    .await;
    let raw = format!("{0}\n{0}/off", srv.url());
    let v = check_searx(&net(), &raw, true).await;
    assert_eq!(v.len(), 2);
    assert_eq!((v[0].1.code.as_str(), v[0].1.results), ("ok", Some(3)));
    assert_eq!(v[1].1.code, "json_off");
}

const BRAVE_JSON: &str = r#"{"query": {"more_results_available": false},
  "web": {"results": [{"url": "https://www.example.com/a.pdf"}, {"url": "https://www.example.com/b.docx"}]}}"#;

#[tokio::test]
async fn brave_api_retries_429_then_stops_on_quota() {
    let n = Arc::new(AtomicUsize::new(0));
    let n2 = n.clone();
    let srv = TestServer::start(move |r| {
        assert_eq!(
            r.headers.get("x-subscription-token").map(String::as_str),
            Some("BSA-key")
        );
        match n2.fetch_add(1, Ordering::SeqCst) {
            0 => TestResponse::status(429).header("Retry-After", "0"),
            1 => TestResponse::ok(BRAVE_JSON),
            _ => {
                let mut r = TestResponse::status(429);
                r.body = br#"{"error":{"code":"QUOTA_LIMITED"}}"#.to_vec();
                r
            }
        }
    })
    .await;
    let b = Brave::new(Some("BSA-key".into())).with_base(&srv.url());
    let f = b.find(&ctx(), "example.com").await.unwrap();
    assert_eq!(f.urls.len(), 2);
    // the second group hit the spent monthly quota: no more requests
    assert_eq!(srv.requests().len(), 3);
    assert!(
        f.note.as_deref().unwrap_or("").contains("HTTP 429"),
        "{f:?}"
    );
    // with nothing collected the quota is the `limit` status
    let srcs: Vec<Box<dyn DocumentSource>> = vec![Box::new(
        Brave::new(Some("BSA-key".into())).with_base(&srv.url()),
    )];
    let res = run_sources(&srcs, &ctx(), "example.com", |_| {})
        .await
        .unwrap();
    assert_eq!(res.sources[0].status, SourceStatus::Limit);
}

#[tokio::test]
async fn brave_key_check_reads_quota_headers() {
    let srv = TestServer::start(|r| {
        assert_eq!(r.query("count").as_deref(), Some("1"));
        match r.headers.get("x-subscription-token").map(String::as_str) {
            Some("good") => TestResponse::ok(BRAVE_JSON)
                .header("X-RateLimit-Limit", "1, 1000")
                .header("X-RateLimit-Remaining", "0, 958"),
            Some("busy") => TestResponse::status(429),
            _ => TestResponse::status(401),
        }
    })
    .await;
    let ok = check_brave(&net(), &srv.url(), "good").await;
    assert!(ok.ok);
    assert_eq!((ok.remaining, ok.limit), (Some(958), Some(1000)));
    assert_eq!(
        check_brave(&net(), &srv.url(), "bad").await.code,
        "rejected"
    );
    assert_eq!(check_brave(&net(), &srv.url(), "busy").await.code, "limit");
}
