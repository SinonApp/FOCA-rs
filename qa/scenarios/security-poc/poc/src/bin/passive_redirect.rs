//! PoC: a passive request follows a redirect to a target host / a scope-excluded host without a check.
//! Mirrors the engine in the passive profile: the downloader fetches a copy from the "web archive" (passive_hosts),
//! the archive answers 302 to the target site, and the request goes to the target (even to an excluded host) while
//! the log records `access=passive, active=false`.
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;

use foca_core::scope::Scope;
use foca_net::testserver::{TestResponse, TestServer};
use foca_net::{Access, MemorySink, NetClient, NetConfig, NetRequest};
use foca_search::{DownloadConfig, Downloader};

#[tokio::main]
async fn main() {
    let srv = TestServer::start(|r| {
        let host = r.headers.get("host").cloned().unwrap_or_default();
        if host.starts_with("web.archive.test") {
            let port = host.rsplit(':').next().unwrap_or("0").to_string();
            // "Nearest copy": the archive redirects to the same path, but on an excluded target host.
            return TestResponse::redirect(302, &format!("http://secret.example.test:{port}/a.pdf"));
        }
        TestResponse::ok(b"%PDF-1.4 leaked".to_vec())
    })
    .await;
    let port = srv.addr.port();
    let lo: IpAddr = "127.0.0.1".parse().unwrap();
    let mut ov = HashMap::new();
    for h in ["web.archive.test", "secret.example.test", "example.test"] {
        ov.insert(h.to_string(), vec![lo]);
    }
    let cfg = NetConfig { host_overrides: ov, retries: 0, global_rps: None, ..Default::default() };
    // Scope: target example.test, secret.example.test EXCLUDED; passive profile (active_phase=false).
    let (scope, errs) = Scope::from_lines("example.test", "secret.example.test");
    assert!(errs.is_empty());
    let sink = Arc::new(MemorySink::new());
    let net = NetClient::new(cfg, scope.clone(), sink.clone()).unwrap();
    println!("scope.allows_host(secret.example.test) = {}", scope.allows_host("secret.example.test"));

    // (A) Same path as stage_download in the passive profile: archive copy URL → Access::Passive.
    let dir = std::env::temp_dir().join(format!("r1-poc-{}", std::process::id()));
    let mut dc = DownloadConfig { head_first: false, ..Default::default() };
    dc.passive_hosts.push("web.archive.test".into());
    let dl = Downloader::new(net.clone(), &dir, dc);
    let u = format!("http://web.archive.test:{port}/web/2025id_/http://example.test/a.pdf");
    println!("access_for(archive url) = {:?}", dl.access_for(&u));
    let r = dl.download(&u).await;
    println!("download result: {:?}", r.as_ref().map(|d| (&d.final_url, d.size)));

    // (B) Direct passive request to the excluded host: authorize() returns Ok for Passive right away.
    let r2 = net
        .send(NetRequest::get(&format!("http://secret.example.test:{port}/direct"), "wayback", Access::Passive).unwrap())
        .await
        .map(|r| r.status());
    println!("direct passive GET to excluded host: {r2:?}");

    println!("--- requests received by the server (Host header) ---");
    for q in srv.requests() {
        println!("{} {} host={}", q.method, q.path(), q.headers.get("host").cloned().unwrap_or_default());
    }
    println!("--- request_log journal (MemorySink) ---");
    for rec in sink.records() {
        println!("module={} host={} access={} active={} blocked={} status={:?} err={:?}", rec.module, rec.host, rec.access, rec.active, rec.blocked, rec.status, rec.error);
    }
    let _ = std::fs::remove_dir_all(dir);
}
