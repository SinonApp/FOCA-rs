//! Offline source tests against fixtures (a local HTTP server instead of public APIs).

use std::sync::Arc;

use foca_core::Scope;
use foca_net::testserver::{TestResponse, TestServer};
use foca_net::{MemorySink, NetClient, NetConfig};
use foca_search::sources::{
    by_ids, Brave, CommonCrawl, Crawler, CrtSh, Searx, SourceKeys, Wayback,
};
use foca_search::{run_sources, DocumentSource, ExtFilter, SearchCtx, SourceStatus};

const WAYBACK: &str = include_str!("fixtures/wayback_cdx.json");
const CC_COLLINFO: &str = include_str!("fixtures/cc_collinfo.json");
const CC_INDEX: &str = include_str!("fixtures/cc_index.ndjson");
const CRTSH: &str = include_str!("../../foca-net/tests/fixtures/crtsh.json");
const BRAVE: &str = include_str!("fixtures/brave.json");
const SEARX: &str = include_str!("fixtures/searx.json");

fn ctx(targets: &str, excludes: &str) -> (SearchCtx, Arc<MemorySink>) {
    let (scope, errs) = Scope::from_lines(targets, excludes);
    assert!(errs.is_empty());
    let sink = Arc::new(MemorySink::new());
    let cfg = NetConfig {
        global_rps: None,
        source_rps: Default::default(),
        retries: 0,
        ..Default::default()
    };
    let net = NetClient::new(cfg, scope, sink.clone()).unwrap();
    (SearchCtx::new(net), sink)
}

#[tokio::test]
async fn wayback_cdx_with_pagination() {
    let srv = TestServer::start(|r| {
        assert_eq!(r.path(), "/cdx/search/cdx");
        assert_eq!(r.query("matchType").as_deref(), Some("domain"));
        if r.query("showNumPages").is_some() {
            return TestResponse::ok("3\n");
        }
        // quick unpaginated document query: the gateway returns 504 on a large domain
        if r.query("page").is_none() {
            assert_eq!(r.query("limit").as_deref(), Some("20"));
            return TestResponse::status(504);
        }
        // no heavy MIME filter over the whole domain: only extensions on the page block
        assert!(!r.target.contains("mimetype%3A"), "{}", r.target);
        assert_eq!(r.query("collapse").as_deref(), Some("urlkey"));
        assert!(r.query("filter").unwrap().starts_with("original:(?i).*\\.("));
        match r.query("page").as_deref() {
            Some("0") => TestResponse::ok(WAYBACK),
            // text output: a font posing as .pdf, a 404 and an HTML placeholder are filtered out locally;
            // images get a separate quota
            Some("1") => TestResponse::ok(
                "20200101000000 https://www.iana.org/x/report.docx application/vnd.openxmlformats-officedocument.wordprocessingml.document 200 1234\n\
                 20200101000000 https://www.iana.org/x/font.pdf application/vnd.ms-fontobject 200 99\n\
                 20200101000000 https://www.iana.org/x/gone.pdf text/html 200 99\n\
                 20200101000000 https://www.iana.org/x/missing.pdf application/pdf 404 99\n\
                 20200101000000 https://www.iana.org/x/a.jpg image/jpeg 200 10\n\
                 20200101000000 https://www.iana.org/x/b.jpg image/jpeg 200 10\n\
                 20200101000000 https://www.iana.org/x/c.jpg image/jpeg 200 10\n\
                 20200101000000 https://www.iana.org/x/d.jpg image/jpeg 200 10\n",
            ),
            // JSON cut off mid-response (200): complete rows are not lost
            Some("2") => TestResponse::ok(
                "[[\"timestamp\",\"original\",\"mimetype\",\"statuscode\",\"length\"],\n\
                 [\"20210101000000\",\"https://handbook.iana.org/h.xlsx\",\"application/octet-stream\",\"200\",\"5\"],\n\
                 [\"20210101000000\",\"https://handbook.iana.org/cut",
            ),
            p => panic!("page {p:?}"),
        }
    })
    .await;
    let (mut ctx, sink) = ctx("", "");
    ctx.limit = 9;
    ctx.images = 2;
    let wb = Wayback::with_base(&srv.url());
    let f = wb.find(&ctx, "iana.org").await.unwrap();
    let names: Vec<&str> = f.urls.iter().map(|u| u.target_url()).collect();
    // 6 pdf + docx + xlsx documents within the limit, images on their own cap of 2
    assert_eq!(f.urls.len(), 10, "{names:#?}");
    let first = &f.urls[0];
    assert_eq!(
        first.url,
        format!(
            "{}/web/20150906192024id_/http://www.iana.org/about/informational-booklet.pdf",
            srv.url()
        )
    );
    assert_eq!(
        first.original.as_deref(),
        Some("http://www.iana.org/about/informational-booklet.pdf")
    );
    assert_eq!(first.size, Some(2209338));
    assert_eq!(first.hint_ext.as_deref(), Some("pdf"));
    assert!(names.contains(&"https://www.iana.org/x/report.docx"));
    assert!(names.contains(&"https://handbook.iana.org/h.xlsx"));
    assert!(!names
        .iter()
        .any(|n| n.contains("font") || n.contains("gone") || n.contains("missing")));
    assert_eq!(names.iter().filter(|n| n.ends_with(".jpg")).count(), 2);
    assert!(f.hosts.contains(&"handbook.iana.org".to_string()));
    assert_eq!(srv.requests().len(), 5);
    assert!(sink
        .records()
        .iter()
        .all(|r| !r.active && r.module == "wayback"));
}

#[test]
fn wayback_page_plan_spreads() {
    use foca_search::sources::page_plan;
    assert_eq!(page_plan(3, 40), vec![0, 1, 2]);
    let p = page_plan(3489, 5);
    assert_eq!(p, vec![0, 872, 1744, 2616, 3488]);
    assert!(page_plan(0, 5).is_empty());
}

#[tokio::test]
async fn wayback_retries_504_and_keeps_partial() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let n = Arc::new(AtomicUsize::new(0));
    let n2 = n.clone();
    let srv = TestServer::start(move |r| {
        if r.query("showNumPages").is_some() {
            return TestResponse::ok("2");
        }
        if r.query("page").is_none() {
            return TestResponse::status(504);
        }
        match r.query("page").as_deref() {
            // the first attempt gets a gateway 504, the retry gets data
            Some("0") if n2.fetch_add(1, Ordering::SeqCst) == 0 => TestResponse::status(504),
            Some("0") => TestResponse::ok(
                "20200101000000 https://www.iana.org/a.pdf application/pdf 200 1\n",
            ),
            // the second page always returns 504; the source still returns what it collected
            _ => TestResponse::status(504),
        }
    })
    .await;
    let (scope, _) = Scope::from_lines("", "");
    let cfg = NetConfig {
        global_rps: None,
        source_rps: Default::default(),
        retries: 0,
        backoff_base: std::time::Duration::from_millis(10),
        ..Default::default()
    };
    let net = NetClient::new(cfg, scope, Arc::new(MemorySink::new())).unwrap();
    let ctx = SearchCtx::new(net);
    let f = Wayback::with_base(&srv.url())
        .find(&ctx, "iana.org")
        .await
        .unwrap();
    assert_eq!(f.urls.len(), 1);
    assert_eq!(n.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn common_crawl_latest_index() {
    let base = Arc::new(std::sync::OnceLock::<String>::new());
    let b2 = base.clone();
    let srv = TestServer::start(move |r| match r.path() {
        "/collinfo.json" => TestResponse::ok(
            CC_COLLINFO.replace("https://index.commoncrawl.org", b2.get().unwrap()),
        ),
        "/CC-MAIN-2026-43-index" => {
            assert_eq!(r.query("url").as_deref(), Some("*.iana.org"));
            assert_eq!(r.query("output").as_deref(), Some("json"));
            if r.query("showNumPages").is_some() {
                return TestResponse::ok(r#"{"pages": 1, "pageSize": 5, "blocks": 1}"#);
            }
            assert!(r.target.contains("filter=status%3A200"));
            TestResponse::ok(CC_INDEX)
        }
        // the second index is unavailable (504), the third returns "No Captures found"
        "/CC-MAIN-2026-39-index" => TestResponse::status(504),
        _ => TestResponse::status(404),
    })
    .await;
    base.set(srv.url()).unwrap();
    let (ctx, sink) = ctx("", "");
    let cc = CommonCrawl::with_collinfo(&format!("{}/collinfo.json", srv.url()));
    let f = cc.find(&ctx, "iana.org").await.unwrap();
    // json is filtered out by extension; the http/https duplicate is merged
    assert_eq!(f.urls.len(), 2, "{:#?}", f.urls);
    assert!(f
        .urls
        .iter()
        .all(|u| u.source == "cc" && u.hint_ext.as_deref() == Some("pdf")));
    assert_eq!(f.urls[0].size, Some(2101234));
    assert_eq!(srv.hits("/collinfo.json"), 1);
    assert_eq!(srv.hits("/CC-MAIN-2026-43-index"), 2);
    assert!(srv.hits("/CC-MAIN-2026-39-index") >= 1);
    assert!(sink.records().iter().all(|r| r.module == "cc" && !r.active));
    // collinfo is cached for a day
    let _ = cc.find(&ctx, "iana.org").await.unwrap();
    assert_eq!(srv.hits("/collinfo.json"), 1);
}

#[tokio::test]
async fn common_crawl_all_indexes_down_is_error() {
    let srv = TestServer::start(|r| match r.path() {
        "/collinfo.json" => TestResponse::ok(
            r#"[{"id":"A","cdx-api":"http://127.0.0.1:1/A-index"},{"id":"B","cdx-api":"http://127.0.0.1:1/B-index"}]"#,
        ),
        _ => TestResponse::status(404),
    })
    .await;
    let (ctx, _) = ctx("", "");
    let cc = CommonCrawl::with_collinfo(&format!("{}/collinfo.json", srv.url()));
    let e = cc.find(&ctx, "iana.org").await.unwrap_err();
    assert!(e.to_string().contains("A-index"), "{e}");
}

#[tokio::test]
async fn crtsh_hosts() {
    let srv = TestServer::start(|r| {
        assert_eq!(r.query("q").as_deref(), Some("%.iana.org"));
        TestResponse::ok(CRTSH)
    })
    .await;
    let (ctx, _) = ctx("", "");
    let f = CrtSh::with_base(&srv.url())
        .find(&ctx, "iana.org")
        .await
        .unwrap();
    assert!(f.urls.is_empty());
    assert!(f.hosts.contains(&"www.iana.org".to_string()));
    assert!(f.hosts.contains(&"handbook.int.iana.org".to_string()));
    assert!(f.hosts.iter().all(|h| h.ends_with("iana.org")));
}

#[tokio::test]
async fn search_engines_with_keys() {
    let srv = TestServer::start(|r| match r.path() {
        "/res/v1/web/search" => {
            if r.headers.get("x-subscription-token").map(|s| s.as_str()) != Some("BSA-test") {
                return TestResponse::status(401);
            }
            assert!(r.query("q").unwrap().starts_with("site:iana.org filetype:"));
            TestResponse::ok(BRAVE)
        }
        "/search" => {
            assert_eq!(r.query("format").as_deref(), Some("json"));
            TestResponse::ok(SEARX)
        }
        _ => TestResponse::status(404),
    })
    .await;
    let (mut ctx, sink) = ctx("", "");
    ctx.filter = ExtFilter::parse("pdf");
    let brave = Brave::new(Some("BSA-test".into())).with_base(&srv.url());
    let f = brave.find(&ctx, "iana.org").await.unwrap();
    // example.net is dropped (not the target domain)
    assert_eq!(f.urls.len(), 2);
    assert!(f.urls.iter().all(|u| u.source == "brave"));

    let bad = Brave::new(Some("wrong".into())).with_base(&srv.url());
    let res = run_sources(
        &[
            Box::new(bad) as Box<dyn DocumentSource>,
            Box::new(Brave::new(None)),
        ],
        &ctx,
        "iana.org",
        |_| {},
    )
    .await
    .unwrap();
    assert_eq!(res.sources[0].status, SourceStatus::Nokey);
    assert_eq!(res.sources[1].status, SourceStatus::Nokey);

    let sx = Searx::local(&srv.url());
    let f = sx.find(&ctx, "iana.org").await.unwrap();
    // like every dork engine, an extensionless link counts as the requested type (MIME decides later)
    assert_eq!(f.urls.len(), 2);
    assert_eq!(
        f.urls[0].url,
        "https://www.iana.org/_files/2023/iana-annual-report.pdf"
    );
    assert!(
        sink.records().iter().all(|r| !r.url.contains("BSA-test")),
        "the key must not reach the log"
    );
}

#[tokio::test]
async fn run_sources_dedupes_and_reports() {
    let srv = TestServer::start(|r| match r.path() {
        "/cdx/search/cdx" => TestResponse::ok(WAYBACK),
        "/idx" => TestResponse::ok(CC_INDEX),
        "/" => TestResponse::ok(CRTSH),
        _ => TestResponse::status(404),
    })
    .await;
    let (ctx, _) = ctx("", "");
    let cc = CommonCrawl {
        index_api: Some(format!("{}/idx", srv.url())),
        ..Default::default()
    };
    let sources: Vec<Box<dyn DocumentSource>> = vec![
        Box::new(CrtSh::with_base(&srv.url())),
        Box::new(Wayback::with_base(&srv.url())),
        Box::new(cc),
        Box::new(Searx::new(None)),
    ];
    let mut events = Vec::new();
    let res = run_sources(&sources, &ctx, "iana.org", |r| events.push(r.id.clone()))
        .await
        .unwrap();
    assert_eq!(events, vec!["crt", "wayback", "cc", "searx"]);
    let st: Vec<_> = res
        .sources
        .iter()
        .map(|s| (s.id.as_str(), s.status))
        .collect();
    assert_eq!(
        st,
        vec![
            ("crt", SourceStatus::Ok),
            ("wayback", SourceStatus::Ok),
            ("cc", SourceStatus::Ok),
            ("searx", SourceStatus::Nokey)
        ]
    );
    // the booklet is in both Wayback and CC (http and https); a single copy remains, from Wayback
    let booklets: Vec<_> = res
        .urls
        .iter()
        .filter(|u| u.target_url().ends_with("informational-booklet.pdf"))
        .collect();
    assert_eq!(booklets.len(), 1);
    assert_eq!(booklets[0].source, "wayback");
    assert_eq!(res.urls.len(), 6 + 1);
    assert!(res.hosts.contains(&"www.iana.org".to_string()));
}

#[test]
fn wayback_mime_regex() {
    use foca_search::sources::mime_regex;
    assert_eq!(mime_regex(&ExtFilter::parse("pdf")), "(application/pdf)");
    let r = mime_regex(&ExtFilter::parse("docx,xlsx,jpg,rdp"));
    assert!(!r.contains("vnd\\..*"), "{r}");
    assert!(
        r.contains("wordprocessingml") && r.contains("spreadsheetml") && r.contains("image/jpeg")
    );
}

#[test]
fn mime_fits_rejects_fonts_and_html() {
    use foca_search::filter::mime_fits;
    assert!(!mime_fits(Some("application/vnd.ms-fontobject"), "pdf"));
    assert!(!mime_fits(Some("text/html"), "docx"));
    assert!(mime_fits(Some("application/octet-stream"), "xls"));
    assert!(mime_fits(Some("warc/revisit"), "pdf"));
    assert!(mime_fits(None, "pdf"));
    assert!(!mime_fits(Some("application/pdf"), "jpg"));
}

#[test]
fn source_ids_match_ui() {
    let ids: Vec<String> = [
        "wayback", "cc", "crtsh", "crawler", "brave", "searx", "gcse", "bing", "anubis", "nope",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    let (src, unknown) = by_ids(&ids, &SourceKeys::default());
    let got: Vec<_> = src.iter().map(|s| s.id()).collect();
    assert_eq!(
        got,
        vec!["wayback", "cc", "crt", "crawler", "brave", "searx", "bing", "anubis"]
    );
    assert_eq!(unknown, vec!["nope"]);
    assert!(src.iter().filter(|s| s.needs_key()).all(|s| !s.has_key()));
    assert_eq!(
        src.iter().find(|s| s.id() == "crawler").unwrap().kind(),
        foca_search::SourceKind::TouchesTarget
    );
}

#[tokio::test]
async fn crawler_respects_scope_robots_and_depth() {
    let srv = TestServer::start(|r| {
        let html = |b: &str| {
            TestResponse::ok(b.to_string()).header("Content-Type", "text/html; charset=utf-8")
        };
        match r.path() {
            "/robots.txt" => {
                TestResponse::ok("User-agent: *\nDisallow: /private/\nSitemap: /sitemap.xml\n")
            }
            "/sitemap.xml" => {
                TestResponse::ok("<urlset><url><loc>/from-sitemap.pdf</loc></url></urlset>")
            }
            "/" => html(
                r#"<a href="/docs/">docs</a><a href="/private/secret.html">p</a>
                   <a href="/files/a.pdf">a</a><a href="http://evil.example/x.pdf">evil</a>
                   <a href="/away">away</a><a href="/img/logo.png">png</a>"#,
            ),
            "/docs/" => html(r#"<a href="report.docx">r</a><a href="/docs/level2.html">2</a>"#),
            "/docs/level2.html" => {
                html(r#"<a href="/docs/level3.html">3</a><a href="deep.xlsx">d</a>"#)
            }
            "/docs/level3.html" => html(r#"<a href="toodeep.pdf">x</a>"#),
            "/private/secret.html" => html(r#"<a href="/private/hidden.pdf">h</a>"#),
            "/away" => TestResponse::redirect(302, "http://evil.example/"),
            _ => TestResponse::status(404),
        }
    })
    .await;
    let (mut ctx, sink) = ctx("127.0.0.1", "");
    ctx.filter = ExtFilter::parse("pdf,docx,xlsx");
    let mut cr = Crawler::with_start(&format!("{}/", srv.url()));
    cr.max_depth = 2;
    let (f, stats) = cr.crawl(&ctx, "127.0.0.1").await.unwrap();
    let mut names: Vec<String> = f
        .urls
        .iter()
        .map(|u| u.url.rsplit('/').next().unwrap().to_string())
        .collect();
    names.sort();
    // level3 is at depth 3 (not fetched), hidden.pdf is behind robots, evil is out of scope
    assert_eq!(
        names,
        vec!["a.pdf", "deep.xlsx", "from-sitemap.pdf", "report.docx"]
    );
    assert_eq!(srv.hits("/private/secret.html"), 0);
    assert_eq!(srv.hits("/docs/level3.html"), 0);
    assert_eq!(
        srv.hits("/files/a.pdf"),
        0,
        "the crawler does not download documents"
    );
    assert!(stats.robots_skipped >= 1);
    assert!(stats.scope_skipped >= 1);
    let log = sink.records();
    assert!(log.iter().all(|r| r.active && r.module == "crawler"));
    // the redirect /away -> evil.example is blocked and logged
    assert!(log.iter().any(|r| r.blocked && r.host == "evil.example"));
    assert!(log
        .iter()
        .filter(|r| !r.blocked)
        .all(|r| r.host == "127.0.0.1"));
    // out of scope, the crawler does not start at all
    let (ctx2, sink2) = self::ctx("contoso.ua", "");
    let (f2, _) = cr.crawl(&ctx2, "127.0.0.1").await.unwrap();
    assert!(f2.urls.is_empty());
    assert!(sink2.records().iter().all(|r| r.blocked) || sink2.is_empty());
}

#[tokio::test]
async fn keyless_host_and_url_sources_offline() {
    use foca_search::sources::{host_source, url_source_with_base};
    let srv = TestServer::start(|r| match r.path() {
        "/anubis/subdomains/testfire.net" => TestResponse::ok(
            r#"["altoro.testfire.net","demo.testfire.net","testfire.net"]"#,
        ),
        "/hostsearch/" => TestResponse::ok("error check your search parameter"),
        "/api/v1/indicators/domain/testfire.net/url_list" => TestResponse::ok(
            r#"{"url_list":[{"url":"https://demo.testfire.net/pr/Q3_earnings.rtf","hostname":"demo.testfire.net"},{"url":"https://demo.testfire.net/index.jsp","hostname":"demo.testfire.net"},{"url":"https://evil.example/x.pdf","hostname":"evil.example"}],"has_next":false}"#,
        ),
        "/html/" => TestResponse::ok(
            r#"<a class="result__a" href="//duckduckgo.com/l/?uddg=https%3A%2F%2Fdemo.testfire.net%2Fadmin%2Fclients.xls&amp;rut=1">x</a>"#,
        ),
        "/search" => TestResponse::status(403).header("x", "y"),
        _ => TestResponse::status(404),
    })
    .await;
    let (mut ctx, sink) = ctx("", "");
    ctx.limit = 10;
    let an = host_source("anubis").unwrap().with_base(&srv.url());
    let f = an.find(&ctx, "testfire.net").await.unwrap();
    assert_eq!(
        f.hosts,
        vec!["altoro.testfire.net", "demo.testfire.net", "testfire.net"]
    );
    let otx = url_source_with_base("otx_url", &srv.url()).unwrap();
    let f = otx.find(&ctx, "testfire.net").await.unwrap();
    assert_eq!(f.urls.len(), 1, "{:?}", f.urls);
    assert_eq!(
        f.urls[0].url,
        "https://demo.testfire.net/pr/Q3_earnings.rtf"
    );
    assert!(f.hosts.contains(&"demo.testfire.net".to_string()));
    let ddg = url_source_with_base("ddg", &srv.url()).unwrap();
    let f = ddg.find(&ctx, "testfire.net").await.unwrap();
    assert!(
        f.urls.iter().any(|u| u.url.ends_with("clients.xls")),
        "{:?}",
        f.urls
    );
    // Mojeek: 403 "automated queries" yields status blocked, not a plain error
    let res = run_sources(
        &[url_source_with_base("mojeek", &srv.url()).unwrap()],
        &ctx,
        "testfire.net",
        |_| {},
    )
    .await
    .unwrap();
    assert_eq!(res.sources[0].status, SourceStatus::Blocked);
    assert!(sink.records().iter().all(|r| !r.active));
}

#[tokio::test]
async fn wayback_quick_query_hits_documents_without_pages() {
    let srv = TestServer::start(|r| {
        if r.query("page").is_none() && r.query("showNumPages").is_none() {
            // documents only, no images; server-side status filter
            let f = r.target.clone();
            assert!(f.contains("pdf") && !f.contains("%7Cjpg%7C"), "{f}");
            return TestResponse::ok(
                "20200101000000 https://www.kernel.org/doc/a.pdf application/pdf 200 1\n\
                 20200101000000 https://www.kernel.org/doc/b.pdf application/pdf 200 1\n",
            );
        }
        if r.query("showNumPages").is_some() {
            return TestResponse::ok("1");
        }
        TestResponse::ok("")
    })
    .await;
    let (ctx, _) = ctx("", "");
    let f = Wayback::with_base(&srv.url())
        .find(&ctx, "kernel.org")
        .await
        .unwrap();
    assert_eq!(f.urls.len(), 2);
}

/// OTX answers 429: a retry honoring `Retry-After`, then status `limit` (not an error) with a clear
/// message; the second OTX source in the same scan does not contact the service (shared host flag).
#[tokio::test]
async fn otx_rate_limit_is_shared_and_reported() {
    use foca_search::sources::url_source_with_base;
    let hits = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let h = hits.clone();
    let srv = TestServer::start(move |_r| {
        h.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        TestResponse::status(429).header("Retry-After", "1")
    })
    .await;
    let port = srv
        .url()
        .rsplit(':')
        .next()
        .unwrap()
        .trim_end_matches('/')
        .to_string();
    let base = format!("http://otx.alienvault.com:{port}");
    let sink = Arc::new(MemorySink::new());
    let mut over = std::collections::HashMap::new();
    over.insert(
        "otx.alienvault.com".to_string(),
        vec!["127.0.0.1".parse().unwrap()],
    );
    let cfg = NetConfig {
        global_rps: None,
        source_rps: Default::default(),
        retries: 1,
        host_overrides: over,
        ..Default::default()
    };
    let net = NetClient::new(cfg, Scope::default(), sink.clone()).unwrap();
    let ctx = SearchCtx::new(net);
    let srcs: Vec<Box<dyn DocumentSource>> = vec![
        Box::new(
            foca_search::sources::host_source("otx_dns")
                .unwrap()
                .with_base(&base),
        ),
        url_source_with_base("otx_url", &base).unwrap(),
    ];
    let t0 = std::time::Instant::now();
    let res = run_sources(&srcs, &ctx, "testfire.net", |_| {})
        .await
        .unwrap();
    let first = &res.sources[0];
    assert_eq!(first.status, SourceStatus::Limit, "{first:?}");
    assert!(first.error.as_deref().unwrap().contains("429"), "{first:?}");
    assert!(
        t0.elapsed() >= std::time::Duration::from_millis(900),
        "Retry-After is honored"
    );
    let second = &res.sources[1];
    assert_eq!(second.status, SourceStatus::Limit, "{second:?}");
    // only the first attempt and one retry of the first source reach the service
    assert_eq!(hits.load(std::sync::atomic::Ordering::SeqCst), 2);
    assert!(sink.records().iter().any(|r| r
        .error
        .as_deref()
        .is_some_and(|e| e.contains("не отправлен"))));
    assert_eq!(serde_json::to_value(SourceStatus::Limit).unwrap(), "limit");
}

/// The newest Common Crawl index answers 504: the source moves to an older one from collinfo and
/// returns results (status ok with a note) instead of an error.
#[tokio::test]
async fn common_crawl_first_index_504_falls_back() {
    let base = Arc::new(std::sync::OnceLock::<String>::new());
    let b2 = base.clone();
    let srv = TestServer::start(move |r| match r.path() {
        "/collinfo.json" => TestResponse::ok(format!(
            r#"[{{"id":"N","cdx-api":"{0}/N-index"}},{{"id":"O","cdx-api":"{0}/O-index"}}]"#,
            b2.get().unwrap()
        )),
        "/N-index" => TestResponse::status(504),
        "/O-index" => {
            if r.query("showNumPages").is_some() {
                return TestResponse::ok(r#"{"pages": 1}"#);
            }
            TestResponse::ok(CC_INDEX)
        }
        _ => TestResponse::status(404),
    })
    .await;
    base.set(srv.url()).unwrap();
    let (ctx, _) = ctx("", "");
    let cc = CommonCrawl::with_collinfo(&format!("{}/collinfo.json?k22", srv.url()));
    let srcs: Vec<Box<dyn DocumentSource>> = vec![Box::new(cc)];
    let res = run_sources(&srcs, &ctx, "iana.org", |_| {}).await.unwrap();
    let r = &res.sources[0];
    assert_eq!(r.status, SourceStatus::Ok, "{r:?}");
    assert!(r.n >= 1, "{r:?}");
    assert!(
        r.error.as_deref().unwrap().contains("N-index"),
        "note: {r:?}"
    );
    assert!(srv.hits("/N-index") >= 1 && srv.hits("/O-index") >= 2);
}

#[tokio::test]
async fn vt_securitytrails_and_github_passive_collectors_work_and_hide_api_keys() {
    use foca_search::sources::{GitHubCode, SecurityTrails, VirusTotal};

    let srv = TestServer::start(|r| match r.path() {
        "/api/v3/domains/example.org/subdomains" => {
            let key = r
                .headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case("x-apikey"))
                .map(|(_, v)| v.as_str());
            if key != Some("VT_SECRET_KEY_999") {
                return TestResponse::status(401);
            }
            TestResponse::ok(
                r#"{"data":[{"id":"api.example.org"},{"id":"portal.example.org"},{"id":"evil.other.com"}]}"#,
            )
            .header("content-type", "application/json")
        }
        "/api/v3/domains/example.org/urls" => TestResponse::ok(
            r#"{"data":[{"attributes":{"url":"https://portal.example.org/docs/policy.pdf"}}]}"#,
        )
        .header("content-type", "application/json"),
        "/v1/domain/example.org/subdomains" => {
            let key = r
                .headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case("apikey"))
                .map(|(_, v)| v.as_str());
            if key != Some("ST_SECRET_KEY_888") {
                return TestResponse::status(403);
            }
            TestResponse::ok(r#"{"subdomains":["vpn","stage","mail.example.org"]}"#)
                .header("content-type", "application/json")
        }
        "/search/code" => {
            let auth = r
                .headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case("authorization"))
                .map(|(_, v)| v.as_str());
            if auth != Some("Bearer GH_SECRET_TOKEN_777") {
                return TestResponse::status(401);
            }
            TestResponse::ok(
                r#"{"items":[{"html_url":"https://github.com/org/repo/blob/main/.env","text_matches":[{"fragment":"API_URL=https://git-internal.example.org/export/spec.xlsx\nDB_HOST=db.example.org"}]}]}"#,
            )
            .header("content-type", "application/json")
        }
        _ => TestResponse::status(404),
    })
    .await;

    let (ctx, sink) = ctx("", "");
    let srcs: Vec<Box<dyn DocumentSource>> = vec![
        Box::new(VirusTotal::new(Some("VT_SECRET_KEY_999".into())).with_base(&srv.url())),
        Box::new(SecurityTrails::new(Some("ST_SECRET_KEY_888".into())).with_base(&srv.url())),
        Box::new(GitHubCode::new(Some("GH_SECRET_TOKEN_777".into())).with_base(&srv.url())),
        Box::new(VirusTotal::new(None).with_base(&srv.url())),
    ];
    let res = run_sources(&srcs, &ctx, "example.org", |_| {})
        .await
        .unwrap();

    assert_eq!(res.sources[0].status, SourceStatus::Ok);
    assert_eq!(res.sources[1].status, SourceStatus::Ok);
    assert_eq!(res.sources[2].status, SourceStatus::Ok);
    assert_eq!(res.sources[3].status, SourceStatus::Nokey);

    assert!(res.hosts.contains(&"api.example.org".to_string()));
    assert!(res.hosts.contains(&"portal.example.org".to_string()));
    assert!(res.hosts.contains(&"vpn.example.org".to_string()));
    assert!(res.hosts.contains(&"stage.example.org".to_string()));
    assert!(res.hosts.contains(&"git-internal.example.org".to_string()));
    assert!(res.hosts.contains(&"db.example.org".to_string()));
    assert!(!res.hosts.iter().any(|h| h.contains("other.com")));

    let urls: Vec<&str> = res.urls.iter().map(|u| u.url.as_str()).collect();
    assert!(urls.contains(&"https://portal.example.org/docs/policy.pdf"));
    assert!(urls.contains(&"https://git-internal.example.org/export/spec.xlsx"));

    // Request log must have 0 active requests and must never leak API keys.
    let recs = sink.records();
    assert!(!recs.is_empty());
    for rec in &recs {
        assert!(!rec.active);
        let serialized = format!("{rec:?}");
        assert!(!serialized.contains("VT_SECRET_KEY_999"));
        assert!(!serialized.contains("ST_SECRET_KEY_888"));
        assert!(!serialized.contains("GH_SECRET_TOKEN_777"));
    }
}
