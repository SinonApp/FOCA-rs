//! Subdomain takeover HTTP check on offline fixtures: a CNAME to a live resource of a service
//! from the can-i-take-over-xyz table is fetched (standard profile only) and its body matched
//! against the unclaimed-resource fingerprint; the passive profile never contacts the host. The
//! DNS-only case (NXDOMAIN target) keeps its own finding.

use std::sync::Arc;

use crate::common::*;
use foca_engine::MemoryKeys;
use foca_net::dns::StaticDns;
use foca_net::testserver::{TestRequest, TestResponse, TestServer};
use serde_json::{json, Value};

const TAKEOVER_ZONE: &str = "
example.test A 127.0.0.1
www.example.test A 127.0.0.1
shop.example.test CNAME unclaimed-example.s3.amazonaws.com
unclaimed-example.s3.amazonaws.com A 127.0.0.1
blog.example.test CNAME live-example.ghost.io
live-example.ghost.io A 127.0.0.1
gone.example.test CNAME gone-example.azurewebsites.net
";

const S3_404: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<Error><Code>NoSuchBucket</Code>\
<Message>The specified bucket does not exist</Message><BucketName>shop.example.test</BucketName></Error>";

fn host_of(r: &TestRequest) -> String {
    let h = r.headers.get("host").cloned().unwrap_or_default();
    h.split(':').next().unwrap_or("").to_string()
}

fn bench(r: &TestRequest) -> TestResponse {
    match host_of(r).as_str() {
        "shop.example.test" => TestResponse {
            status: 404,
            body: S3_404.as_bytes().to_vec(),
            ..Default::default()
        }
        .header("content-type", "application/xml"),
        "blog.example.test" => {
            TestResponse::ok(b"<html><body>Our blog</body></html>".to_vec())
                .header("content-type", "text/html")
        }
        "127.0.0.1" if r.path() == "/" && r.query("output").is_some() => TestResponse::ok(
            br#"[{"name_value":"www.example.test\nshop.example.test\nblog.example.test\ngone.example.test"}]"#
                .to_vec(),
        ),
        "127.0.0.1" if r.path() == "/cdx/search/cdx" => TestResponse::ok(b"[]".to_vec()),
        _ => TestResponse::status(404),
    }
}

async fn bench_env() -> Env {
    let dir = tempfile::tempdir().unwrap();
    let server = TestServer::start(bench).await;
    let keys = Arc::new(MemoryKeys::new());
    let port = server.port();
    let (engine, events, pause_at) = open_with(dir.path(), &server.url(), keys.clone(), |c| {
        c.site_port = Some(port);
        c.dns = Some(Arc::new(StaticDns::from_zone_text(TAKEOVER_ZONE)));
        for h in [
            "shop.example.test",
            "blog.example.test",
            "gone.example.test",
        ] {
            c.net
                .host_overrides
                .insert(h.into(), vec!["127.0.0.1".parse().unwrap()]);
        }
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

async fn run(e: &Env, profile: &str) -> (String, Value) {
    let p = e
        .call(
            "project_create",
            json!({ "name": "takeover", "targets": [{ "v": "example.test", "type": "domain" }] }),
        )
        .await;
    let id = p["id"].as_str().unwrap().to_string();
    e.call(
        "scan_start",
        json!({ "project": id, "profile": profile, "sources": ["crt"] }),
    )
    .await;
    e.wait().await;
    let s = e.snap(&id).await;
    (id, s)
}

fn takeover_findings(s: &Value) -> Vec<Value> {
    s["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|f| {
            f["title"]
                .as_str()
                .unwrap_or("")
                .contains("subdomain takeover")
        })
        .cloned()
        .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn standard_profile_matches_unclaimed_service_body() {
    let e = bench_env().await;
    let (id, s) = run(&e, "std").await;
    let found = takeover_findings(&s);
    let http: Vec<&Value> = found
        .iter()
        .filter(|f| f["title"] == "Возможен subdomain takeover (сервис AWS/S3)")
        .collect();
    assert_eq!(http.len(), 1, "{found:#?}");
    let f = http[0];
    assert_eq!(f["host"], "shop.example.test");
    assert_eq!(f["sev"], "high");
    let d = f["description"].as_str().unwrap();
    assert!(
        d.contains("CNAME → unclaimed-example.s3.amazonaws.com (AWS/S3)")
            && d.contains("HTTP 404")
            && d.contains("«The specified bucket does not exist»"),
        "{d}"
    );
    let ev = f["evidence"].as_str().unwrap();
    assert!(
        ev.contains("unclaimed-example.s3.amazonaws.com")
            && ev.contains("The specified bucket does not exist"),
        "{ev}"
    );
    // a live resource without the fingerprint text is not a finding
    assert!(
        found.iter().all(|f| f["host"] != "blog.example.test"),
        "{found:#?}"
    );
    // the DNS-only case (NXDOMAIN target) stays
    assert!(
        found.iter().any(|f| f["host"] == "gone.example.test"
            && f["title"].as_str().unwrap().starts_with("Висящий CNAME")),
        "{found:#?}"
    );
    // GET only, logged as a target request of the takeover module
    let log = e
        .call("request_log_get", json!({ "project": id, "limit": 100000 }))
        .await;
    let rows: Vec<&Value> = log["items"]
        .as_array()
        .or_else(|| log.as_array())
        .unwrap()
        .iter()
        .filter(|r| r["module"] == "takeover")
        .collect();
    assert!(!rows.is_empty(), "{log}");
    assert!(rows.iter().all(|r| r["method"] == "GET"), "{rows:#?}");
    assert!(
        rows.iter().any(|r| r["host"] == "shop.example.test"),
        "{rows:#?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn passive_profile_never_fetches_the_subdomain() {
    let e = bench_env().await;
    let (_, s) = run(&e, "passive").await;
    let found = takeover_findings(&s);
    assert!(
        found.iter().all(|f| f["host"] != "shop.example.test"),
        "{found:#?}"
    );
    let touched: Vec<String> = e
        .server
        .requests()
        .iter()
        .map(host_of)
        .filter(|h| h != "127.0.0.1")
        .collect();
    assert!(touched.is_empty(), "requests to target hosts: {touched:?}");
    // the NXDOMAIN case is DNS only and still reported
    assert!(
        found.iter().any(|f| f["host"] == "gone.example.test"),
        "{found:#?}"
    );
}
