//! Network functions exercised against a local test server (no external network).

use std::sync::Arc;

use foca_core::Scope;
use foca_net::testserver::{TestResponse, TestServer};
use foca_net::{MemorySink, NetClient, NetConfig};
use foca_recon::buckets::{self, BucketCheckOptions, BucketStatus};
use foca_recon::grepapp::{self, GrepAppError};
use foca_recon::wellknown::{harvest_from_archive, HarvestOptions};

fn client() -> (NetClient, Arc<MemorySink>) {
    let sink = Arc::new(MemorySink::default());
    let c = NetClient::new(NetConfig::default(), Scope::default(), sink.clone()).unwrap();
    (c, sink)
}

#[tokio::test]
async fn grepapp_search_via_netclient() {
    let fx = include_str!("fixtures/grepapp_google.json");
    let srv = TestServer::start(move |r| {
        if r.path() == "/api/search" && r.query("q").as_deref() == Some("google.com") {
            TestResponse::ok(fx).header("Content-Type", "application/json")
        } else {
            TestResponse::status(429).header("Content-Type", "application/json")
        }
    })
    .await;
    let (c, _sink) = client();
    let r = grepapp::search(&c, &srv.url(), "google.com", 1)
        .await
        .unwrap();
    assert_eq!(r.hits.len(), 3);
    assert_eq!(srv.hits("/api/search"), 1);
}

#[tokio::test]
async fn grepapp_challenge_is_reported() {
    let srv = TestServer::start(|_| {
        let mut t = TestResponse::ok(r#"{"error":{"code":"challenge"}}"#);
        t.status = 429;
        t
    })
    .await;
    let (c, _) = client();
    let e = grepapp::search(&c, &srv.url(), "python.org", 1)
        .await
        .unwrap_err();
    assert!(matches!(e, GrepAppError::Challenge), "{e}");
}

#[tokio::test]
async fn harvest_wellknown_from_archive() {
    let srv = TestServer::start(|r| {
        let p = r.path().to_string();
        let body = if p.ends_with("/https://ex.com/robots.txt") {
            "User-agent: *\nDisallow: /old_admin/\nDisallow: /docs/plan.pdf\nSitemap: https://ex.com/sitemap_index.xml\n"
        } else if p.ends_with("/https://ex.com/sitemap_index.xml") {
            "<sitemapindex><sitemap><loc>https://ex.com/sitemap-1.xml</loc></sitemap></sitemapindex>"
        } else if p.ends_with("/https://ex.com/sitemap-1.xml") {
            "<urlset><url><loc>https://ex.com/a</loc></url><url><loc>https://ex.com/f/report.pdf</loc></url></urlset>"
        } else if p.ends_with("/.well-known/security.txt") {
            "Contact: mailto:sec@ex.com\n"
        } else {
            return TestResponse::status(404);
        };
        TestResponse::ok(body)
    })
    .await;
    let cdx = "k 20240101000000 https://ex.com/robots.txt text/plain 200 A 1\n\
k 20240101000000 https://ex.com/.well-known/security.txt text/plain 200 B 1\n\
k 20240101000000 https://ex.com/sitemap.xml text/xml 200 C 1\n";
    let (c, sink) = client();
    let opts = HarvestOptions {
        archive_base: srv.url(),
        ..Default::default()
    };
    let r = harvest_from_archive(&c, cdx, &opts).await;
    assert_eq!(r.hidden_paths.len(), 2, "{r:?}");
    assert!(r
        .documents
        .contains(&"https://ex.com/f/report.pdf".to_string()));
    assert!(r.documents.contains(&"/docs/plan.pdf".to_string()));
    assert_eq!(r.sitemap_urls.len(), 2);
    assert_eq!(r.security[0].emails, vec!["sec@ex.com".to_string()]);
    assert_eq!(r.errors.len(), 1, "sitemap.xml → 404: {:?}", r.errors);
    assert!(sink.records().iter().all(|x| x.access == "passive"));
}

#[tokio::test]
async fn bucket_check_off_by_default_and_classifies() {
    let srv = TestServer::start(|r| match r.path() {
        "/open/" => TestResponse::ok("<ListBucketResult><Name>open</Name><Contents><Key>secret.pdf</Key></Contents></ListBucketResult>"),
        "/closed/" => {
            let mut t = TestResponse::ok("<Error><Code>AccessDenied</Code></Error>");
            t.status = 403;
            t
        }
        _ => TestResponse::status(404),
    })
    .await;
    let (c, sink) = client();
    let mut b = buckets::find_buckets("https://acme-x.s3.amazonaws.com/a", "p");
    buckets::check_buckets(&c, &mut b, &BucketCheckOptions::default()).await;
    assert_eq!(b[0].status, BucketStatus::Unchecked);
    assert!(
        sink.records().is_empty(),
        "no requests without the opt-in flag"
    );
    let a = foca_net::Access::Passive;
    let open = buckets::check_bucket_at(&c, &format!("{}/open/", srv.url()), a.clone()).await;
    assert!(
        matches!(open, BucketStatus::PublicListing { keys: 1, .. }),
        "{open:?}"
    );
    let closed = buckets::check_bucket_at(&c, &format!("{}/closed/", srv.url()), a.clone()).await;
    assert_eq!(closed, BucketStatus::Closed);
    let nf = buckets::check_bucket_at(&c, &format!("{}/none/", srv.url()), a).await;
    assert_eq!(nf, BucketStatus::NotFound);
    assert!(sink.records().iter().all(|r| r.module == "buckets"));
}
