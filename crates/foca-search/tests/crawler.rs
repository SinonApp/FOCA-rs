//! Crawler: junk links with an embedded URL and canonical dedup after redirects (seen in a real
//! report: `/https://site/...` redirected with 302 to `/https:/site/...`, and the home page,
//! robots and sitemap were crawled twice via www./test.).

use std::sync::Arc;

use foca_core::Scope;
use foca_net::testserver::{TestResponse, TestServer};
use foca_net::{MemorySink, NetClient, NetConfig};
use foca_search::crawl::RateState;
use foca_search::sources::{CrawlStop, Crawler};
use foca_search::storage::{ItemKind, Provider, StorageEndpoints};
use foca_search::{BoxFuture, ExtFilter, RenderFetch, RenderPage, RenderRequest, SearchCtx};

fn ctx(targets: &str) -> (SearchCtx, Arc<MemorySink>) {
    let (scope, errs) = Scope::from_lines(targets, "");
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
async fn crawler_skips_nested_url_links_and_dedups_after_redirect() {
    let srv = TestServer::start(|r| {
        let html =
            |b: String| TestResponse::ok(b).header("Content-Type", "text/html; charset=utf-8");
        let host = "127.0.0.1";
        match r.path() {
            "/" => html(format!(
                r#"<a href="/https://{host}/vstupniku/a">bad1</a>
                   <a href="https://{host}/https:/{host}/vstupniku/b">bad2</a>
                   <a href="/http%3A//{host}/c">bad3</a>
                   <a href=" /old ">old</a><a href="/new">new</a><a href="/news">news</a>"#
            )),
            "/old" => TestResponse::redirect(302, "/new"),
            "/new" => html(r#"<a href="/files/x.pdf">x</a>"#.into()),
            "/news" => html(r#"<a href="/new">again</a>"#.into()),
            _ => TestResponse::status(404),
        }
    })
    .await;
    let (mut ctx, sink) = ctx("127.0.0.1");
    ctx.filter = ExtFilter::parse("pdf");
    let mut cr = Crawler::with_start(&format!("{}/", srv.url()));
    cr.max_depth = 3;
    // one request at a time: with two in flight /old and /new could both be on the wire
    cr.per_host = 1;
    cr.respect_robots = false;
    cr.use_sitemap = false;
    let (f, _) = cr.crawl(&ctx, "127.0.0.1").await.unwrap();
    assert!(f.urls.iter().any(|u| u.url.ends_with("/files/x.pdf")));
    let log = sink.records();
    // no requests for links with an embedded http(s):/
    assert!(
        log.iter().all(|r| !r.url.contains("/https:")
            && !r.url.contains("/http:")
            && !r.url.to_ascii_lowercase().contains("http%3a")),
        "{:?}",
        log.iter().map(|r| r.url.clone()).collect::<Vec<_>>()
    );
    // /new was reached through the redirect from /old and is not requested again via the direct link
    assert_eq!(srv.hits("/new"), 1, "canonical dedup after a redirect");
    assert_eq!(srv.hits("/"), 1);
}

fn html(b: impl Into<String>) -> TestResponse {
    TestResponse::ok(b.into()).header("Content-Type", "text/html; charset=utf-8")
}

fn gzip(data: &[u8]) -> Vec<u8> {
    use std::io::Write;
    let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    e.write_all(data).unwrap();
    e.finish().unwrap()
}

/// A chain of pages five links deep, a sitemap index (gzip) with a page no link points to, and a
/// robots.txt `Sitemap:` line.
#[tokio::test]
async fn crawl_goes_deep_and_reads_sitemap_index_gz() {
    let srv = TestServer::start(|r| match r.path() {
        "/robots.txt" => TestResponse::ok("User-agent: *\nDisallow: /private/\nSitemap: /maps/index.xml.gz\n"),
        "/maps/index.xml.gz" => TestResponse::ok(gzip(
            b"<sitemapindex><sitemap><loc>/maps/pages.xml.gz</loc></sitemap></sitemapindex>",
        )),
        "/maps/pages.xml.gz" => TestResponse::ok(gzip(
            b"<urlset><url><loc>/orphan</loc></url><url><loc>/files/listed.pdf</loc></url></urlset>",
        )),
        "/" => html(r#"<a href="/l1">1</a><a href="/private/x">p</a>"#),
        "/l1" => html(r#"<a href="/l2">2</a>"#),
        "/l2" => html(r#"<a href="/l3">3</a>"#),
        "/l3" => html(r#"<a href="/l4">4</a>"#),
        "/l4" => html(r#"<a href="/files/deep.docx">deep</a>"#),
        "/orphan" => html(r#"<a href="/files/orphan.xlsx">o</a>"#),
        _ => TestResponse::status(404),
    })
    .await;
    let (mut ctx, _) = ctx("127.0.0.1");
    ctx.filter = ExtFilter::parse("pdf,docx,xlsx");
    let cr = Crawler::with_start(&format!("{}/", srv.url()));
    let (f, st) = cr.crawl(&ctx, "127.0.0.1").await.unwrap();
    let urls: Vec<&str> = f.urls.iter().map(|u| u.url.as_str()).collect();
    for want in [
        "/files/deep.docx",
        "/files/orphan.xlsx",
        "/files/listed.pdf",
    ] {
        assert!(urls.iter().any(|u| u.ends_with(want)), "{want}: {urls:?}");
    }
    assert_eq!(st.sitemaps, 2);
    assert!(st.finished);
    assert_eq!(srv.hits("/private/x"), 0, "robots.txt is honoured");
    let out = cr.out.lock().unwrap().clone();
    assert!(out
        .doc_pages
        .iter()
        .any(|(d, p)| d.ends_with("/files/deep.docx") && p.ends_with("/l4")));
    assert!(out.frontier.is_empty());
}

/// Calendar pages generate an endless URL space: the template cap stops it; logout links are
/// never followed; tracking parameters do not make new pages.
#[tokio::test]
async fn crawl_collapses_traps_and_skips_logout() {
    let srv = TestServer::start(|r| {
        let p = r.path().to_string();
        if let Some(rest) = p.strip_prefix("/cal/") {
            let n: u32 = rest.parse().unwrap_or(0);
            return html(format!(r#"<a href="/cal/{}">next</a><a href="/cal/{}?utm_source=x">same</a>"#, n + 1, n));
        }
        match p.as_str() {
            "/" => html(r#"<a href="/cal/1">calendar</a><a href="/account/logout">bye</a><a href="/news?utm_campaign=a">n</a><a href="/news">n</a>"#),
            "/news" => html("<p>news</p>"),
            _ => TestResponse::status(404),
        }
    })
    .await;
    let (ctx, _) = ctx("127.0.0.1");
    let mut cr = Crawler::with_start(&format!("{}/", srv.url()));
    cr.use_sitemap = false;
    cr.respect_robots = false;
    cr.max_depth = 1000;
    cr.per_template = 10;
    let (_, st) = cr.crawl(&ctx, "127.0.0.1").await.unwrap();
    assert_eq!(srv.hits("/account/logout"), 0);
    assert_eq!(srv.hits("/news"), 1);
    let cal = srv
        .requests()
        .iter()
        .filter(|r| r.path().starts_with("/cal/"))
        .count();
    assert_eq!(cal, 10, "per-template cap");
    assert!(st.trap_skipped >= 1 && st.risky_skipped == 1);
}

/// Linked files on public storage are collected with the page that linked them, not crawled;
/// images become EXIF candidates.
#[tokio::test]
async fn crawl_collects_storage_links_and_images() {
    const ID: &str = "1AbCdEfGhIjKlMnOpQrStUvWxYz012345";
    let srv = TestServer::start(|r| match r.path() {
        "/" => html(
            r#"<a href="/docs-page">docs</a><img src="/img/hall.jpg" width="1200" height="800"><img src="/img/logo.png">"#,
        ),
        "/docs-page" => html(format!(
            r#"<a href="https://drive.google.com/file/d/{ID}/view?usp=sharing">plan</a>
               <a href="https://drive.google.com/drive/folders/{ID}">folder</a>
               <a href="https://docs.google.com/document/d/{ID}/edit">minutes</a>
               <a href="https://drive.google.com/">drive home</a>"#
        )),
        _ => TestResponse::status(404),
    })
    .await;
    let (ctx, sink) = ctx("127.0.0.1");
    let mut cr = Crawler::with_start(&format!("{}/", srv.url()));
    cr.use_sitemap = false;
    cr.respect_robots = false;
    cr.storage = Some(StorageEndpoints::default());
    cr.collect_images = true;
    let (f, st) = cr.crawl(&ctx, "127.0.0.1").await.unwrap();
    let out = cr.out.lock().unwrap().clone();
    assert_eq!(st.storage, 3);
    let kinds: Vec<(Provider, ItemKind)> = out
        .storage
        .iter()
        .map(|s| (s.link.provider, s.link.kind))
        .collect();
    assert!(kinds.contains(&(Provider::GoogleDrive, ItemKind::File)));
    assert!(kinds.contains(&(Provider::GoogleDrive, ItemKind::Folder)));
    assert!(kinds.contains(&(Provider::GoogleDocs, ItemKind::Export)));
    assert!(out.storage.iter().all(|s| s.page.ends_with("/docs-page")));
    // nothing was requested from the storage host by the crawler
    assert!(sink.records().iter().all(|r| r.host == "127.0.0.1"));
    assert_eq!(out.images.len(), 2);
    assert!(
        f.urls.iter().all(|u| !u.url.ends_with(".jpg")),
        "images are candidates, not documents"
    );
}

/// 429 answers halve the host's pace; repeated ones stop the host and the pages stay in the frontier.
#[tokio::test]
async fn crawl_slows_down_then_stops_on_429() {
    let srv = TestServer::start(|r| match r.path() {
        "/" => html(
            (1..=6)
                .map(|i| format!(r#"<a href="/p{i}">{i}</a>"#))
                .collect::<String>(),
        ),
        _ => TestResponse::status(429).header("Retry-After", "0"),
    })
    .await;
    let (ctx, _) = ctx("127.0.0.1");
    let mut cr = Crawler::with_start(&format!("{}/", srv.url()));
    cr.use_sitemap = false;
    cr.respect_robots = false;
    cr.per_host = 1;
    cr.limit_stop = 3;
    let t0 = std::time::Instant::now();
    let (_, st) = cr.crawl(&ctx, "127.0.0.1").await.unwrap();
    // 1st limit: 0.5 s, 2nd: 1 s, 3rd: stop
    assert!(
        t0.elapsed() >= std::time::Duration::from_millis(1400),
        "{:?}",
        t0.elapsed()
    );
    let limited = srv.requests().iter().filter(|r| r.path() != "/").count();
    assert_eq!(limited, 3, "the host is not contacted after it was stopped");
    assert_eq!(st.rate, RateState::Stopped);
    assert_eq!(st.stopped_hosts, vec!["127.0.0.1".to_string()]);
    assert_eq!(st.stop, Some(CrawlStop::Limited));
    assert!(!st.finished);
    assert_eq!(cr.out.lock().unwrap().frontier.queue.len(), 6);
}

/// A crawl cut by its page limit leaves a frontier; the next crawl continues from it without
/// fetching the same pages again.
#[tokio::test]
async fn crawl_resumes_frontier() {
    let srv = TestServer::start(|r| match r.path() {
        "/" => html(r#"<a href="/a">a</a><a href="/b">b</a><a href="/c">c</a>"#),
        "/a" | "/b" => html("<p>x</p>"),
        "/c" => html(r#"<a href="/d">d</a>"#),
        "/d" => html(r#"<a href="/files/late.pdf">late</a>"#),
        _ => TestResponse::status(404),
    })
    .await;
    let (mut ctx, _) = ctx("127.0.0.1");
    ctx.filter = ExtFilter::parse("pdf");
    let mut cr = Crawler::with_start(&format!("{}/", srv.url()));
    cr.use_sitemap = false;
    cr.respect_robots = false;
    cr.per_host = 1;
    cr.max_pages = 2;
    let (f, st) = cr.crawl(&ctx, "127.0.0.1").await.unwrap();
    assert!(f.urls.is_empty());
    assert_eq!(st.stop, Some(CrawlStop::Pages));
    let frontier = cr.out.lock().unwrap().frontier.clone();
    assert_eq!(frontier.queue.len(), 2);
    assert_eq!(frontier.pages, 2);
    let mut next = Crawler::with_start(&format!("{}/", srv.url()))
        .with_resume([("127.0.0.1".to_string(), frontier)].into_iter().collect());
    next.use_sitemap = false;
    next.respect_robots = false;
    let (f, st) = next.crawl(&ctx, "127.0.0.1").await.unwrap();
    assert!(st.resumed && st.finished);
    assert!(f.urls.iter().any(|u| u.url.ends_with("/files/late.pdf")));
    for p in ["/", "/a", "/b", "/c", "/d"] {
        assert_eq!(srv.hits(p), 1, "{p} fetched once over both runs");
    }
    assert_eq!(next.out.lock().unwrap().frontier.pages, 5);
}

/// Renders pages through a fixed DOM, as the Android WebView would after running the app's scripts.
struct FakeRender(Arc<std::sync::Mutex<Vec<String>>>);

impl RenderFetch for FakeRender {
    fn fetch<'a>(&'a self, req: RenderRequest) -> BoxFuture<'a, Result<RenderPage, String>> {
        Box::pin(async move {
            let url = req.url.clone().unwrap_or_default();
            self.0.lock().unwrap().push(url.clone());
            Ok(RenderPage {
                html: r#"<html><body><div id="root"><nav><a href="/app/reports">Reports</a></nav>
                    <a href="/files/app-report.pdf">Report</a></div></body></html>"#
                    .into(),
                url,
                status: Some(200),
                ..Default::default()
            })
        })
    }
}

/// A JavaScript app shell has no links in its HTML: the crawler renders it through the platform
/// browser and follows the links of the rendered DOM; without a browser it carries on gracefully.
#[tokio::test]
async fn crawl_renders_app_shell() {
    let srv = TestServer::start(|r| match r.path() {
        "/" | "/app/reports" => html(
            r#"<!doctype html><html><head><script type="module" src="/assets/index.js"></script></head>
            <body><div id="root"></div></body></html>"#,
        ),
        _ => TestResponse::status(404),
    })
    .await;
    let (mut ctx, sink) = ctx("127.0.0.1");
    ctx.filter = ExtFilter::parse("pdf");
    let mk = || {
        let mut cr = Crawler::with_start(&format!("{}/", srv.url()));
        cr.use_sitemap = false;
        cr.respect_robots = false;
        cr
    };
    let cr = mk();
    let (f, st) = cr.crawl(&ctx, "127.0.0.1").await.unwrap();
    assert!(f.urls.is_empty());
    assert_eq!(st.render_missing, 1);
    assert_eq!(st.rendered, 0);
    let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
    ctx.render = Some(Arc::new(FakeRender(seen.clone())));
    let mut cr = mk();
    cr.max_rendered = 1;
    let (f, st) = cr.crawl(&ctx, "127.0.0.1").await.unwrap();
    assert!(f
        .urls
        .iter()
        .any(|u| u.url.ends_with("/files/app-report.pdf")));
    assert_eq!(st.rendered, 1, "render cap");
    assert_eq!(
        srv.hits("/app/reports"),
        1,
        "links of the rendered DOM are crawled"
    );
    assert_eq!(seen.lock().unwrap().len(), 1);
    assert!(sink
        .records()
        .iter()
        .any(|r| r.method == "RENDER" && r.module == "crawler"));
    assert!(cr
        .out
        .lock()
        .unwrap()
        .scripts
        .iter()
        .any(|(s, _)| s.ends_with("/assets/index.js")));
}
