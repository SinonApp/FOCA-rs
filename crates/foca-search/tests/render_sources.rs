//! Dorks through the embedded browser (Startpage, keyless Brave, Mojeek): parsing of real result
//! pages (`fixtures/render/`, captured with Playwright following the RenderFetcher.kt script, see
//! the README), challenge/captcha/block detection, pagination and stopping, statuses without a WebView.

use std::sync::{Arc, Mutex};

use foca_core::Scope;
use foca_net::{MemorySink, NetClient, NetConfig};
use foca_search::render::NO_RENDER;
use foca_search::sources::{
    classify, parse_brave_web, parse_mojeek, parse_startpage, startpage_has_next, url_source,
    url_source_with_base, verify_url, PageKind, RenderDork, RenderEngine, CAPTCHA_ABORT,
};
use foca_search::{
    run_sources, BoxFuture, DocumentSource, ExtFilter, RenderFetch, RenderPage, RenderRequest,
    SearchCtx, SourceStatus,
};

const SP_VERIFY: &str = include_str!("fixtures/render/startpage_verify.html");
const SP_NASA_1: &str = include_str!("fixtures/render/startpage_nasa_gov_pdf_p1.html");
const SP_NASA_2: &str = include_str!("fixtures/render/startpage_nasa_gov_pdf_p2.html");
const SP_TESTFIRE: &str = include_str!("fixtures/render/startpage_testfire_net_pdf_p1.html");
const BR_NASA_1: &str = include_str!("fixtures/render/brave_nasa_gov_pdf_p1.html");
const BR_NASA_2: &str = include_str!("fixtures/render/brave_nasa_gov_pdf_p2.html");
const BR_TESTFIRE: &str = include_str!("fixtures/render/brave_testfire_net_pdf_p1.html");
const BR_EMPTY: &str = include_str!("fixtures/render/brave_testfire_net_pdf_p2_empty.html");
const MJ_403: &str = include_str!("fixtures/render/mojeek_403.html");
const MJ_TESTFIRE: &str = include_str!("fixtures/render/mojeek_testfire_net_pdf_manual.html");

fn ctx() -> (SearchCtx, Arc<MemorySink>) {
    let sink = Arc::new(MemorySink::new());
    let cfg = NetConfig {
        global_rps: None,
        retries: 0,
        ..Default::default()
    };
    let net = NetClient::new(cfg, Scope::default(), sink.clone()).unwrap();
    let mut c = SearchCtx::new(net);
    c.filter = ExtFilter::parse("pdf");
    (c, sink)
}

type Handler = dyn Fn(&RenderRequest, usize) -> Result<RenderPage, String> + Send + Sync;

/// Fake browser: serves fixtures per request and records the requests.
struct Fake {
    seen: Mutex<Vec<RenderRequest>>,
    f: Box<Handler>,
}

impl Fake {
    fn new(
        f: impl Fn(&RenderRequest, usize) -> Result<RenderPage, String> + Send + Sync + 'static,
    ) -> Arc<Self> {
        Arc::new(Fake {
            seen: Mutex::new(vec![]),
            f: Box::new(f),
        })
    }
    fn reqs(&self) -> Vec<RenderRequest> {
        self.seen.lock().unwrap().clone()
    }
}

impl RenderFetch for Fake {
    fn fetch<'a>(&'a self, req: RenderRequest) -> BoxFuture<'a, Result<RenderPage, String>> {
        let n = {
            let mut g = self.seen.lock().unwrap();
            g.push(req.clone());
            g.len()
        };
        let r = (self.f)(&req, n);
        Box::pin(async move { r })
    }
}

fn page(html: &str, url: &str) -> RenderPage {
    RenderPage {
        html: html.into(),
        url: url.into(),
        ms: 10,
        status: Some(200),
        ..Default::default()
    }
}

#[test]
fn startpage_real_results_parsed() {
    let l = parse_startpage(SP_NASA_1);
    assert!(l.len() >= 8, "{l:?}");
    assert!(l.iter().all(|u| !u.contains("startpage.com")), "{l:?}");
    assert!(l.contains(&"https://oig.nasa.gov/docs/IG-18-016.pdf".to_string()));
    assert!(startpage_has_next(SP_NASA_1));
    let l2 = parse_startpage(SP_NASA_2);
    assert!(l2.len() >= 8);
    assert!(
        l2.iter().any(|u| !l.contains(u)),
        "the second page has different results"
    );
    let t = parse_startpage(SP_TESTFIRE);
    assert_eq!(t, vec!["http://testfire.net/pr/communityannualreport.pdf"]);
    assert_eq!(
        classify(
            RenderEngine::Startpage,
            &page(SP_NASA_1, "https://www.startpage.com/sp/search")
        ),
        PageKind::Results
    );
}

#[test]
fn startpage_verify_page_detected() {
    let mut p = page(SP_VERIFY, "https://www.startpage.com/");
    p.wait_timeout = true;
    assert_eq!(classify(RenderEngine::Startpage, &p), PageKind::Verify);
    assert!(parse_startpage(SP_VERIFY).is_empty());
}

#[test]
fn brave_real_results_rebuilt_from_meta_url() {
    let l = parse_brave_web(BR_NASA_1);
    assert_eq!(l.len(), 20, "{l:?}");
    assert!(l.contains(
        &"https://www.nasa.gov/wp-content/uploads/2023/01/55583main_vision_space_exploration2.pdf"
            .to_string()
    ));
    assert!(l
        .iter()
        .all(|u| !u.contains("brave.com") && !u.contains("/go/v1")));
    let l2 = parse_brave_web(BR_NASA_2);
    // Brave's truncated path "…-v14." is not a document URL
    assert!(l2.iter().all(|u| !u.ends_with('.')), "{l2:?}");
    // ...while the full URL of the same result (`…-v14.pdf`) is taken from the page data
    assert!(l2
        .iter()
        .any(|u| u.ends_with("nasashutdownfurloughguideforemployees-v14.pdf")));
    assert_eq!(l2.len(), 20);
    assert!(l2.contains(
        &"https://eospso.nasa.gov/sites/default/files/publications/NASA%20Science%20Resources.pdf"
            .to_string()
    ));
    let t = parse_brave_web(BR_TESTFIRE);
    assert_eq!(
        t,
        vec![
            "https://demo.testfire.net/pr/communityannualreport.pdf",
            "http://testfire.net/pr/communityannualreport.pdf"
        ]
    );
    assert_eq!(
        classify(
            RenderEngine::BraveWeb,
            &page(BR_NASA_1, "https://search.brave.com/search")
        ),
        PageKind::Results
    );
    // "few matches" is an empty result, not a captcha (the scripts contain a "...CAPTCHA" string; verified live)
    assert!(BR_EMPTY.to_ascii_lowercase().contains("captcha"));
    assert_eq!(
        classify(
            RenderEngine::BraveWeb,
            &page(BR_EMPTY, "https://search.brave.com/search")
        ),
        PageKind::Results
    );
    assert!(parse_brave_web(BR_EMPTY).is_empty());
    let cap = page(
        "<html><body><h1>Captcha</h1><p>Please complete the captcha</p></body></html>",
        "https://search.brave.com/search",
    );
    assert_eq!(classify(RenderEngine::BraveWeb, &cap), PageKind::Captcha);
}

#[test]
fn mojeek_results_and_ip_block() {
    let l = parse_mojeek(MJ_TESTFIRE);
    assert_eq!(
        l,
        vec![
            "https://demo.testfire.net/pr/communityannualreport.pdf",
            "http://testfire.net/pr/communityannualreport.pdf",
            "https://demo.testfire.net/pr/Q3_earnings.pdf?a=1&b=2",
            "https://www.example.org/testfire-review.pdf",
        ]
    );
    let mut p = page(MJ_403, "https://www.mojeek.com/search?q=x");
    p.status = Some(403);
    assert_eq!(classify(RenderEngine::Mojeek, &p), PageKind::BlockedIp);
    // and without a status (the WebView does not always report it), detected by text
    p.status = None;
    assert_eq!(classify(RenderEngine::Mojeek, &p), PageKind::BlockedIp);
    assert!(parse_mojeek(MJ_403).is_empty());
}

#[tokio::test]
async fn startpage_source_paginates_and_stops() {
    let fake = Fake::new(|r, _| {
        if r.url.is_some() {
            return Ok(page(SP_NASA_1, "https://www.startpage.com/sp/search"));
        }
        // a second page exists; on the third there is no Next button
        let n = r.steps.len();
        assert!(n >= 1);
        Ok(page(SP_NASA_2, "https://www.startpage.com/sp/search"))
    });
    let (mut c, sink) = ctx();
    c.render = Some(fake.clone());
    let mut s = RenderDork::new(RenderEngine::Startpage).no_delay();
    s.max_pages = 2;
    let f = s.find(&c, "nasa.gov").await.unwrap();
    assert!(f.urls.len() >= 10, "{:?}", f.urls);
    assert!(f
        .urls
        .iter()
        .all(|u| u.hint_ext.as_deref() == Some("pdf") && u.source == "startpage"));
    // filetype:pdf without an extension in the URL is still a document (the downloader checks the MIME type)
    assert!(f
        .urls
        .iter()
        .any(|u| u.url == "https://mars.nasa.gov/internal_resources/815/"));
    assert!(f
        .urls
        .iter()
        .all(|u| foca_search::sources::url_in_domain(&u.url, "nasa.gov")));
    let reqs = fake.reqs();
    // pdf only (filter), two pages: home page plus form, then "Next" without a URL
    assert_eq!(reqs.len(), 2);
    assert_eq!(reqs[0].url.as_deref(), Some("https://www.startpage.com/"));
    assert_eq!(reqs[0].session, "startpage");
    assert!(serde_json::to_string(&reqs[0].steps)
        .unwrap()
        .contains("site:nasa.gov filetype:pdf"));
    assert!(reqs[1].url.is_none());
    // request log: RENDER, passive
    let recs = sink.records();
    assert_eq!(recs.len(), 2);
    assert!(recs
        .iter()
        .all(|r| r.method == "RENDER" && !r.active && r.module == "startpage"));
}

#[tokio::test]
async fn brave_stops_when_no_new_links() {
    // first visit: home page, then results; the page has 2 links (< PAGE_FULL), so no
    // second page is requested
    let fake = Fake::new(|_, _| Ok(page(BR_TESTFIRE, "https://search.brave.com/search")));
    let (mut c, _) = ctx();
    c.render = Some(fake.clone());
    let s = RenderDork::new(RenderEngine::BraveWeb).no_delay();
    let f = s.find(&c, "testfire.net").await.unwrap();
    assert_eq!(f.urls.len(), 2, "{:?}", f.urls);
    let reqs = fake.reqs();
    assert_eq!(reqs.len(), 2);
    assert_eq!(reqs[0].url.as_deref(), Some("https://search.brave.com/"));
    assert!(reqs[1].url.as_deref().unwrap().ends_with("&source=web"));
}

#[tokio::test]
async fn verify_not_passed_and_no_webview_statuses() {
    let fake = Fake::new(|_, _| {
        let mut p = page(SP_VERIFY, "https://www.startpage.com/");
        p.wait_timeout = true;
        Ok(p)
    });
    let (mut c, _) = ctx();
    c.render = Some(fake);
    let srcs: Vec<Box<dyn DocumentSource>> = vec![Box::new(
        RenderDork::new(RenderEngine::Startpage).no_delay(),
    )];
    let res = run_sources(&srcs, &c, "nasa.gov", |_| {}).await.unwrap();
    assert_eq!(res.sources[0].status, SourceStatus::Blocked);
    assert!(res.sources[0]
        .error
        .as_deref()
        .unwrap()
        .contains("проверка поисковика не пройдена"));

    // without an embedded browser (CLI/serve): "WebView required", no crash
    let (c, sink) = ctx();
    let srcs: Vec<Box<dyn DocumentSource>> = vec![
        url_source("startpage").unwrap(),
        url_source("brave_web").unwrap(),
    ];
    let res = run_sources(&srcs, &c, "nasa.gov", |_| {}).await.unwrap();
    for r in &res.sources {
        assert_eq!(r.status, SourceStatus::Unavailable, "{r:?}");
        assert_eq!(r.error.as_deref(), Some(NO_RENDER));
    }
    assert!(sink.records().is_empty());
    let v = serde_json::to_value(SourceStatus::Unavailable).unwrap();
    assert_eq!(v, "unavailable");

    // In headless background mode, NO_RENDER maps to skipped_headless
    let (mut c_hl, _) = ctx();
    c_hl.headless = true;
    let res_hl = run_sources(&srcs, &c_hl, "nasa.gov", |_| {}).await.unwrap();
    for r in &res_hl.sources {
        assert_eq!(r.status, SourceStatus::SkippedHeadless, "{r:?}");
    }
    assert_eq!(
        serde_json::to_value(SourceStatus::SkippedHeadless).unwrap(),
        "skipped_headless"
    );
}

#[tokio::test]
async fn mojeek_goes_through_webview_when_available() {
    // with a browser, Mojeek goes through it; 403 "automated queries" means blocked by IP
    let fake = Fake::new(|r, _| {
        assert_eq!(r.session, "mojeek");
        let u = r.url.as_deref().unwrap();
        // the first visit in a scan goes to the home page
        assert!(
            u == "https://www.mojeek.com/" || u.starts_with("https://www.mojeek.com/search?q=")
        );
        let mut p = page(MJ_403, r.url.as_deref().unwrap());
        p.status = Some(403);
        Ok(p)
    });
    let (mut c, _) = ctx();
    c.render = Some(fake.clone());
    let srcs: Vec<Box<dyn DocumentSource>> = vec![url_source("mojeek").unwrap()];
    let res = run_sources(&srcs, &c, "testfire.net", |_| {})
        .await
        .unwrap();
    assert_eq!(res.sources[0].status, SourceStatus::Blocked);
    assert!(res.sources[0]
        .error
        .as_deref()
        .unwrap()
        .contains("заблокировал IP"));
    assert_eq!(fake.reqs().len(), 1);

    // results: scope filter (example.org dropped), dedup; home page, then results without s=;
    // 3 links (< PAGE_FULL), so no second page is requested
    let fake = Fake::new(|r, _| Ok(page(MJ_TESTFIRE, r.url.as_deref().unwrap())));
    let (mut c, _) = ctx();
    c.render = Some(fake.clone());
    let s = url_source_with_base("mojeek", "http://127.0.0.1:9").unwrap();
    let f = s.find(&c, "testfire.net").await.unwrap();
    let got: Vec<_> = f.urls.iter().map(|u| u.url.as_str()).collect();
    assert_eq!(got.len(), 3, "{got:?}");
    assert!(got.iter().all(|u| u.contains("testfire.net")));
    let reqs = fake.reqs();
    assert_eq!(reqs.len(), 2);
    assert_eq!(reqs[0].url.as_deref(), Some("https://www.mojeek.com/"));
    assert!(!reqs[1].url.as_deref().unwrap().contains("&s="));
}

#[tokio::test]
async fn browser_error_is_reported() {
    let fake = Fake::new(|_, _| {
        Err("WebView не поддерживает прокси: запрос напрямую не отправлен".into())
    });
    let (mut c, _) = ctx();
    c.render = Some(fake);
    let srcs: Vec<Box<dyn DocumentSource>> =
        vec![Box::new(RenderDork::new(RenderEngine::BraveWeb).no_delay())];
    let res = run_sources(&srcs, &c, "nasa.gov", |_| {}).await.unwrap();
    assert_eq!(res.sources[0].status, SourceStatus::Error);
    assert!(res.sources[0].error.as_deref().unwrap().contains("прокси"));
}

/// A Startpage/Mojeek captcha triggers an early exit (the `abort` condition while waiting), status
/// `blocked` with a captcha reason and a manual check URL; without a captcha there is no such URL.
#[tokio::test]
async fn captcha_fast_exit_and_verify_url() {
    for (engine, id, url) in [
        (
            RenderEngine::Startpage,
            "startpage",
            "https://www.startpage.com/sp/captcha",
        ),
        (
            RenderEngine::Mojeek,
            "mojeek",
            "https://www.mojeek.com/captcha",
        ),
    ] {
        let fake = Fake::new(move |_, _| {
            let mut p = page(
                "<html><body><h1>Captcha</h1><p>Please solve the captcha</p></body></html>",
                url,
            );
            p.aborted = Some("captcha".into());
            Ok(p)
        });
        let (mut c, _) = ctx();
        c.render = Some(fake.clone());
        let srcs: Vec<Box<dyn DocumentSource>> = vec![Box::new(RenderDork::new(engine).no_delay())];
        let res = run_sources(&srcs, &c, "nasa.gov", |_| {}).await.unwrap();
        let r = &res.sources[0];
        assert_eq!(r.status, SourceStatus::Blocked, "{id}: {r:?}");
        let e = r.error.as_deref().unwrap();
        assert!(e.contains("капч"), "{e}");
        assert!(verify_url(id, e).is_some(), "{id}");
        assert_eq!(fake.reqs().len(), 1, "{id}: no requests after the captcha");
        // every wait step carries the captcha markers for an early exit
        let req = &fake.reqs()[0];
        let v = serde_json::to_value(req).unwrap();
        let waits: Vec<_> = v["steps"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|s| s["op"] == "wait")
            .collect();
        assert!(!waits.is_empty());
        for w in waits {
            assert!(w["abort"]
                .as_array()
                .unwrap()
                .iter()
                .any(|x| x == CAPTCHA_ABORT[0]));
        }
    }
    assert!(verify_url("startpage", "HTTP 504").is_none());
    assert!(verify_url("ddg", "капча / заблокировано: поисковик показал капчу").is_none());
}

#[tokio::test]
async fn captcha_hands_dorks_to_other_engine() {
    // shared board: Startpage hits a captcha, its groups go to Brave, no dorks are lost
    let fake = Fake::new(|r, _| {
        if r.session == "startpage" {
            let mut p = page(
                "<html><body>complete the captcha</body></html>",
                "https://www.startpage.com/sp/captcha",
            );
            p.aborted = Some("/captcha".into());
            Ok(p)
        } else {
            Ok(page(BR_NASA_1, "https://search.brave.com/search"))
        }
    });
    let (mut c, _) = ctx();
    c.filter = ExtFilter::parse("pdf,doc,docx,xls");
    c.render = Some(fake.clone());
    let board = Arc::new(foca_search::sources::DorkBoard::default());
    c.dorks = Some(board.clone());
    let srcs: Vec<Box<dyn DocumentSource>> = vec![
        Box::new(RenderDork::new(RenderEngine::Startpage).no_delay()),
        Box::new(RenderDork::new(RenderEngine::BraveWeb).no_delay()),
    ];
    let res = run_sources(&srcs, &c, "nasa.gov", |_| {}).await.unwrap();
    let st = board.stats();
    // Brave ran all 3 groups (pdf, doc|docx, xls), with doc|docx as a single OR query
    let brave_q: Vec<String> = fake
        .reqs()
        .iter()
        .filter(|r| r.session == "brave")
        .filter_map(|r| r.url.clone())
        .filter(|u| u.contains("/search?") && !u.contains("&offset="))
        .collect();
    assert_eq!(brave_q.len(), 3, "{brave_q:?}");
    assert!(brave_q.iter().any(|u| u.contains("OR")), "{brave_q:?}");
    assert!(
        st["startpage"].blocked && st["startpage"].captchas >= 1,
        "{st:?}"
    );
    assert_eq!(board.lost("nasa.gov"), 0);
    let br = res.sources.iter().find(|r| r.id == "brave_web").unwrap();
    assert_eq!(br.status, SourceStatus::Ok);
    assert!(br.n > 0);
    // a repeat within a day with the same cache makes no browser requests
    let dir = tempfile::tempdir().unwrap();
    let mk = || {
        Arc::new(foca_search::sources::DorkBoard::new(
            foca_search::sources::DorkCache::new(Some(dir.path().join("dork-cache.json"))),
        ))
    };
    let s = RenderDork::new(RenderEngine::BraveWeb).no_delay();
    c.dorks = Some(mk());
    s.find(&c, "nasa.gov").await.unwrap();
    let before = fake.reqs().len();
    c.dorks = Some(mk());
    let f = s.find(&c, "nasa.gov").await.unwrap();
    assert!(!f.urls.is_empty());
    // only the home page of the first visit; results come from the cache
    assert!(
        fake.reqs().len() <= before + 1,
        "{}",
        fake.reqs().len() - before
    );
}

// mobile pages (Playwright emulating Android, like a WebView with a mobile UA)
const BR_MOBILE: &str = include_str!("fixtures/render/brave_nasa_gov_pdf_mobile.html");
const BR_CAPTCHA: &str = include_str!("fixtures/render/brave_captcha_429_mobile.html");
const YH_MOBILE: &str = include_str!("fixtures/render/yahoo_python_org_pdf_mobile.html");
const SX_PAGE: &str = include_str!("fixtures/render/searx_python_org_pdf.html");
const SP_MOBILE: &str = include_str!("fixtures/render/startpage_python_org_pdf_mobile.html");

#[test]
fn mobile_pages_parse_and_classify() {
    let sp = page(SP_MOBILE, "https://www.startpage.com/sp/search");
    assert_eq!(classify(RenderEngine::Startpage, &sp), PageKind::Results);
    assert!(parse_startpage(SP_MOBILE).len() >= 8);
    assert!(startpage_has_next(SP_MOBILE));
    let b = page(BR_MOBILE, "https://search.brave.com/search?q=x");
    assert_eq!(classify(RenderEngine::BraveWeb, &b), PageKind::Results);
    let n = parse_brave_web(BR_MOBILE)
        .iter()
        .filter(|u| u.contains("nasa.gov"))
        .count();
    assert!(n >= 15, "brave mobile: {n}");
    let mut c = page(BR_CAPTCHA, "https://search.brave.com/search?q=x");
    c.status = Some(429);
    assert_eq!(classify(RenderEngine::BraveWeb, &c), PageKind::Captcha);
    assert!(CAPTCHA_ABORT
        .iter()
        .any(|a| BR_CAPTCHA.to_lowercase().contains(a)));

    let y = page(YH_MOBILE, "https://search.yahoo.com/search?p=x");
    assert_eq!(classify(RenderEngine::Yahoo, &y), PageKind::Results);
    let yl = foca_search::sources::parse_yahoo(YH_MOBILE);
    assert!(yl.len() >= 4, "{yl:?}");
    assert!(yl.iter().all(|u| !u.contains("yahoo.com")), "{yl:?}");
    let consent = page(
        "<html>consent</html>",
        "https://consent.yahoo.com/v2/collectConsent?x",
    );
    assert_eq!(classify(RenderEngine::Yahoo, &consent), PageKind::Captcha);
    assert_eq!(
        verify_url("yahoo", "капча / заблокировано: поисковик показал капчу"),
        Some("https://search.yahoo.com/")
    );

    let sx = foca_search::sources::parse_searx_html(SX_PAGE);
    assert!(
        sx.iter().filter(|u| u.contains("python.org")).count() >= 8,
        "{sx:?}"
    );
    assert_eq!(
        foca_search::sources::searx_pool::classify_searx(Some(200), SX_PAGE),
        PageKind::Results
    );
}

#[tokio::test]
async fn searx_pool_rotates_instances_through_webview() {
    // the first instance answers 429, the second with results
    let fake = Fake::new(|r, _| {
        let u = r.url.clone().unwrap();
        assert_eq!(r.session, "searx");
        if u.starts_with("https://bad.example/") {
            let mut p = page("Too Many Requests", &u);
            p.status = Some(429);
            Ok(p)
        } else {
            Ok(page(SX_PAGE, &u))
        }
    });
    let (mut c, _) = ctx();
    c.render = Some(fake.clone());
    let mut s = foca_search::sources::SearxPool::with_base("https://bad.example");
    s.fixed = Some(vec![
        "https://bad.example".into(),
        "https://good.example".into(),
    ]);
    let f = s.find(&c, "python.org").await.unwrap();
    assert!(!f.urls.is_empty());
    let urls: Vec<String> = fake.reqs().iter().filter_map(|r| r.url.clone()).collect();
    assert!(urls[0].starts_with("https://bad.example/search?q=site%3Apython.org"));
    assert!(urls[1].starts_with("https://good.example/"));
    // the bad instance is not contacted again
    assert!(urls[2..]
        .iter()
        .all(|u| u.starts_with("https://good.example/")));
    // without a WebView: an explicit "WebView required"
    let (c, _) = ctx();
    let e = s.find(&c, "python.org").await.unwrap_err().to_string();
    assert!(e.contains(NO_RENDER), "{e}");
}
