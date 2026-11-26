//! Crawler: junk links with an embedded URL and canonical dedup after redirects (seen in a real
//! report: `/https://site/...` redirected with 302 to `/https:/site/...`, and the home page,
//! robots and sitemap were crawled twice via www./test.).

use std::sync::Arc;

use foca_core::Scope;
use foca_net::testserver::{TestResponse, TestServer};
use foca_net::{MemorySink, NetClient, NetConfig};
use foca_search::sources::Crawler;
use foca_search::{ExtFilter, SearchCtx};

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
