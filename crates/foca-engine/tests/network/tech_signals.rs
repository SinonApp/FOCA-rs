//! Technology signals in the site recon stage: JS file content, stylesheets, visible text,
//! WordPress plugins/theme with `?ver=` (the core version is ignored), Drupal and Joomla module
//! paths, browser-only signals from a fake platform browser (home page render with the probe
//! script), no render in the passive profile, and plugin readmes only in the full profile.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use crate::common::*;
use foca_engine::{BoxFuture, MemoryKeys, RenderFetch, RenderPage, RenderRequest};
use foca_net::testserver::{TestRequest, TestResponse, TestServer};
use serde_json::{json, Value};

fn host_of(r: &TestRequest) -> String {
    let h = r.headers.get("host").cloned().unwrap_or_default();
    h.split(':').next().unwrap_or("").to_string()
}

fn html(b: &str) -> TestResponse {
    TestResponse::ok(b.as_bytes().to_vec()).header("content-type", "text/html; charset=utf-8")
}

const WP: &str = r#"<html><head><meta name="generator" content="WordPress 6.4.2">
<link rel="stylesheet" href="/wp-content/plugins/contact-form-7/includes/css/styles.css?ver=5.8.4">
<link rel="stylesheet" href="/wp-content/plugins/fancy-gallery-x/g.css?ver=6.4.2">
<script src="/wp-content/plugins/woocommerce/assets/js/cart.min.js?ver=8.3.1"></script>
<link rel="stylesheet" href="/wp-content/themes/agency-pro/style.css?ver=2.0.1">
<link rel="stylesheet" href="/assets/app.css">
<script src="/assets/vendor.js"></script>
<style>.hero{--tw-rotate:0}</style>
</head><body><p>Powered by SLAED CMS</p></body></html>"#;

const DRUPAL: &str = r#"<html><head>
<script type="application/json" data-drupal-selector="drupal-settings-json">{}</script>
<link href="/modules/contrib/webform/css/webform.css" rel="stylesheet">
<script src="/sites/all/modules/views_slideshow/js/v.js"></script>
</head><body>x</body></html>"#;

const JOOMLA: &str = r#"<html><head><script src="/media/jui/js/jquery.min.js"></script>
<link href="/components/com_virtuemart/assets/css/vm.css" rel="stylesheet">
<link href="/templates/protostar/css/template.css" rel="stylesheet">
</head><body>x</body></html>"#;

fn bench(r: &TestRequest) -> TestResponse {
    let host = host_of(r);
    let p = r.path().to_string();
    if host == "127.0.0.1" {
        return TestResponse::status(404);
    }
    match (host.as_str(), p.as_str()) {
        ("example.test", "/") => html(WP),
        ("example.test", "/assets/vendor.js") => TestResponse::ok(
            b"/*!\n * @overview  Ember - JavaScript Application Framework\n * @version   3.28.1\n */"
                .to_vec(),
        ),
        ("example.test", "/assets/app.css") => {
            TestResponse::ok(b".MuiPaper-root{color:red}".to_vec())
        }
        ("example.test", "/wp-content/plugins/fancy-gallery-x/readme.txt") => {
            TestResponse::ok(b"=== Fancy ===\nStable tag: 2.4.1\n".to_vec())
        }
        ("contoso.test", "/") => html(DRUPAL),
        ("fabrikam.test", "/") => html(JOOMLA),
        _ => TestResponse::status(404),
    }
}

/// Fake platform browser: answers the recon probe with a jQuery global and a request host.
struct FakeBrowser {
    recon_calls: AtomicUsize,
}

impl RenderFetch for FakeBrowser {
    fn fetch<'a>(&'a self, req: RenderRequest) -> BoxFuture<'a, Result<RenderPage, String>> {
        let probe = serde_json::to_value(&req.steps)
            .unwrap()
            .as_array()
            .unwrap()
            .iter()
            .any(|s| s["op"] == "eval");
        if req.session == "recon" {
            self.recon_calls.fetch_add(1, Ordering::SeqCst);
        }
        let url = req.url.clone().unwrap_or_default();
        Box::pin(async move {
            Ok(RenderPage {
                html: "<html><body>rendered</body></html>".into(),
                url,
                ms: 1,
                eval: probe.then(|| {
                    r#"{"j":{"jQuery.fn.jquery":"3.6.0"},"d":{},"cut":false}"#.to_string()
                }),
                hosts: vec!["widget.10to8.com".into()],
                ..Default::default()
            })
        })
    }
}

async fn stand(browser: Arc<FakeBrowser>) -> Env {
    let dir = tempfile::tempdir().unwrap();
    let server = TestServer::start(bench).await;
    let keys = Arc::new(MemoryKeys::new());
    let port = server.port();
    let (engine, events, pause_at) = open_with(dir.path(), &server.url(), keys.clone(), |c| {
        c.site_port = Some(port);
        for h in ["contoso.test", "fabrikam.test"] {
            c.net
                .host_overrides
                .insert(h.into(), vec!["127.0.0.1".parse().unwrap()]);
        }
        c.render = Some(browser);
    });
    Env {
        dir,
        server,
        engine,
        events,
        pause_at,
        keys,
    }
}

async fn scan(e: &Env, profile: &str) -> Value {
    let p = e
        .call(
            "project_create",
            json!({ "name": "tech", "targets": [
                { "v": "example.test", "type": "domain" },
                { "v": "contoso.test", "type": "domain" },
                { "v": "fabrikam.test", "type": "domain" } ] }),
        )
        .await;
    let id = p["id"].as_str().unwrap().to_string();
    e.call(
        "scan_start",
        json!({ "project": id, "profile": profile, "sources": ["recon"] }),
    )
    .await;
    // the full profile goes on to the site fuzz stage: stop once recon is over
    for _ in 0..600 {
        let past_recon = e
            .events()
            .iter()
            .any(|x| x["type"] == "stage" && x["stage"] == "fuzz");
        if past_recon {
            e.call("scan_stop", json!({ "reason": "user" })).await;
            break;
        }
        if e.engine
            .wait_idle(std::time::Duration::from_millis(200))
            .await
        {
            break;
        }
    }
    e.wait().await;
    e.snap(&id).await
}

fn tech<'a>(s: &'a Value, host: &str, pred: impl Fn(&Value) -> bool) -> Option<&'a Value> {
    s["recon"]["tech"]
        .as_array()
        .unwrap()
        .iter()
        .find(|t| t["host"] == host && pred(t))
}

fn by_slug<'a>(s: &'a Value, host: &str, slug: &str) -> &'a Value {
    tech(s, host, |t| t["slug"] == slug).unwrap_or_else(|| panic!("{slug}: {}", s["recon"]["tech"]))
}

fn by_name<'a>(s: &'a Value, host: &str, name: &str) -> &'a Value {
    tech(s, host, |t| t["name"] == name).unwrap_or_else(|| panic!("{name}: {}", s["recon"]["tech"]))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn standard_scan_reads_static_browser_and_plugin_signals() {
    let browser = Arc::new(FakeBrowser {
        recon_calls: AtomicUsize::new(0),
    });
    let e = stand(browser.clone()).await;
    let s = scan(&e, "std").await;
    let h = "example.test";
    // WordPress plugins and theme with versions; the core version is no plugin version
    let cf7 = by_slug(&s, h, "contact-form-7");
    assert_eq!(cf7["version"], "5.8.4");
    assert_eq!(cf7["plugin_of"], "wordpress");
    assert!(cf7["signals"]
        .as_array()
        .unwrap()
        .contains(&json!("plugin_path")));
    assert_eq!(by_slug(&s, h, "woocommerce")["version"], "8.3.1");
    let fg = by_slug(&s, h, "fancy-gallery-x");
    assert!(fg["version"].is_null(), "{fg}");
    assert_eq!(
        fg["cpe"],
        "cpe:2.3:a:*:fancy_gallery_x:*:*:*:*:*:wordpress:*:*"
    );
    let theme = by_slug(&s, h, "agency-pro");
    assert_eq!(theme["version"], "2.0.1");
    assert_eq!(theme["category"], "Темы WordPress");
    // static signals over fetched files and the page text
    let ember = by_name(&s, h, "Ember.js");
    assert_eq!(ember["version"], "3.28.1");
    assert_eq!(ember["signals"], json!(["script"]));
    assert_eq!(by_name(&s, h, "Material UI")["signals"], json!(["css"]));
    assert_eq!(by_name(&s, h, "Tailwind CSS")["signals"], json!(["css"]));
    assert_eq!(by_name(&s, h, "SLAED CMS")["signals"], json!(["text"]));
    // browser signals from the home page render
    let jq = by_name(&s, h, "jQuery");
    assert_eq!(jq["version"], "3.6.0");
    assert!(jq["evidence"]
        .as_array()
        .unwrap()
        .contains(&json!("JS: jQuery.fn.jquery = 3.6.0")));
    assert!(by_name(&s, h, "10to8")["signals"]
        .as_array()
        .unwrap()
        .contains(&json!("xhr")));
    // one render per site home page
    assert_eq!(browser.recon_calls.load(Ordering::SeqCst), 3);
    // Drupal and Joomla modules
    assert_eq!(
        by_slug(&s, "contoso.test", "webform")["plugin_of"],
        "drupal"
    );
    by_slug(&s, "contoso.test", "views_slideshow");
    assert_eq!(
        by_slug(&s, "fabrikam.test", "com_virtuemart")["plugin_of"],
        "joomla"
    );
    by_slug(&s, "fabrikam.test", "protostar");
    // no readme requests below the full profile
    let readmes = e
        .server
        .requests()
        .iter()
        .filter(|r| r.path().ends_with("/readme.txt"))
        .count();
    assert_eq!(readmes, 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn render_budget_setting_limits_home_page_renders() {
    let browser = Arc::new(FakeBrowser {
        recon_calls: AtomicUsize::new(0),
    });
    let e = stand(browser.clone()).await;
    e.call(
        "settings_set",
        json!({ "patch": { "recon": { "render_hosts": 1 } } }),
    )
    .await;
    let s = scan(&e, "std").await;
    assert_eq!(browser.recon_calls.load(Ordering::SeqCst), 1);
    let rendered = s["recon"]["tech"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|t| t["name"] == "jQuery" && t["version"] == "3.6.0")
        .count();
    assert_eq!(rendered, 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn passive_profile_renders_nothing() {
    let browser = Arc::new(FakeBrowser {
        recon_calls: AtomicUsize::new(0),
    });
    let e = stand(browser.clone()).await;
    let _ = scan(&e, "passive").await;
    assert_eq!(browser.recon_calls.load(Ordering::SeqCst), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn full_profile_reads_plugin_readmes() {
    let browser = Arc::new(FakeBrowser {
        recon_calls: AtomicUsize::new(0),
    });
    let e = stand(browser).await;
    let s = scan(&e, "full").await;
    let fg = by_slug(&s, "example.test", "fancy-gallery-x");
    assert_eq!(fg["version"], "2.4.1", "{fg}");
    assert!(fg["signals"].as_array().unwrap().contains(&json!("readme")));
    let readmes = e
        .server
        .requests()
        .iter()
        .filter(|r| r.path().ends_with("/readme.txt"))
        .count();
    // contact-form-7, fancy-gallery-x and woocommerce: one GET each
    assert_eq!(readmes, 3);
}
