//! Several hosts of one scan are worked on at once (`settings.net.hosts_parallel`): site
//! discovery, the port scan and site recon run up to N hosts concurrently, `1` keeps the old
//! one-by-one order, the shared request budget holds across workers, a host that answers 429 does
//! not stop the others, and pause, stop and the stage Skip reach every worker. The running hosts
//! are reported as the `hosts` sub-step (`running`, `done`, `total`).

use std::sync::Arc;
use std::time::Duration;

use super::fuzz::site;
use crate::common::*;
use foca_engine::MemoryKeys;
use foca_net::testserver::{TestRequest, TestResponse, TestServer};
use serde_json::{json, Value};
use tokio::net::TcpListener;

/// Internet sources on 127.0.0.1 (Wayback, crt.sh) and the fuzz bench for every other `Host`.
/// `limited` answers 429 to every request for that host; `delay` slows site answers so the
/// workers really overlap.
fn bench(r: &TestRequest, limited: Option<&str>, delay: Duration) -> TestResponse {
    let host = site::host_of(r);
    let p = r.path().to_string();
    if host == "127.0.0.1" {
        if p == "/" && r.query("output").is_some() {
            return TestResponse::ok(br#"[{"name_value":"www.example.test"}]"#.to_vec());
        }
        if p == "/cdx/search/cdx" {
            return TestResponse::ok(b"[]".to_vec());
        }
        if p == "/collinfo.json" {
            return TestResponse::ok(b"[]".to_vec());
        }
        return TestResponse::status(404);
    }
    if limited == Some(host.as_str()) {
        return TestResponse::status(429).header("Retry-After", "120");
    }
    site::site(r, site::SiteOpts { soft404: true }).delay(delay)
}

async fn fuzz_env_with(limited: Option<&'static str>, delay_ms: u64) -> Env {
    let dir = tempfile::tempdir().unwrap();
    let delay = Duration::from_millis(delay_ms);
    let server = TestServer::start(move |r| bench(r, limited, delay)).await;
    let keys = Arc::new(MemoryKeys::new());
    let (engine, events, pause_at) = open_with(dir.path(), &server.url(), keys.clone(), |c| {
        c.fuzz_unthrottled = true;
    });
    let e = Env {
        dir,
        server,
        engine,
        events,
        pause_at,
        keys,
    };
    e.call(
        "settings_set",
        json!({ "patch": { "net": { "rps": 0, "threads": 8 },
            "fuzz": { "modules": ["docs", "backups", "exposed", "dirlisting"],
            "max_requests": 30000, "max_hosts": 2, "threads": 2 } } }),
    )
    .await;
    e
}

async fn set_parallel(e: &Env, n: u64) {
    e.call(
        "settings_set",
        json!({ "patch": { "net": { "hosts_parallel": n } } }),
    )
    .await;
}

fn full(id: &str) -> Value {
    json!({ "project": id, "profile": "full", "sources": ["crt", "wayback"] })
}

/// Brute-force requests in the order they were logged (oldest first).
async fn fuzz_rows(e: &Env, id: &str) -> Vec<Value> {
    let log = e
        .call("request_log_get", json!({ "project": id, "limit": 100000 }))
        .await;
    let mut rows: Vec<Value> = log
        .as_array()
        .unwrap()
        .iter()
        .filter(|r| r["module"] == "fuzz")
        .cloned()
        .collect();
    rows.sort_by_key(|r| r["id"].as_i64().unwrap_or(0));
    rows
}

fn hosts_of(rows: &[Value]) -> Vec<String> {
    rows.iter()
        .map(|r| r["host"].as_str().unwrap_or("").to_string())
        .collect()
}

/// How many times the log switches from one host to another.
fn switches(hosts: &[String]) -> usize {
    hosts.windows(2).filter(|w| w[0] != w[1]).count()
}

/// `hosts` sub-step events of a stage.
fn host_steps(e: &Env, stage: &str) -> Vec<Value> {
    e.events()
        .into_iter()
        .filter(|x| x["type"] == "substep" && x["id"] == "hosts" && x["stage"] == stage)
        .collect()
}

fn max_running(steps: &[Value]) -> usize {
    steps
        .iter()
        .map(|x| x["running"].as_array().map_or(0, Vec::len))
        .max()
        .unwrap_or(0)
}

fn fuzz_events(e: &Env) -> Vec<Value> {
    e.events()
        .into_iter()
        .filter(|x| x["type"] == "source" && x["id"] == "fuzz")
        .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn fuzz_runs_hosts_concurrently() {
    let e = fuzz_env_with(None, 2).await;
    set_parallel(&e, 4).await;
    let id = e.project("example.test").await;
    e.call("scan_start", full(&id)).await;
    e.wait().await;
    let rows = fuzz_rows(&e, &id).await;
    let hosts = hosts_of(&rows);
    let distinct: std::collections::BTreeSet<&String> = hosts.iter().collect();
    assert_eq!(
        distinct.len(),
        2,
        "two web hosts brute-forced: {distinct:?}"
    );
    assert!(
        switches(&hosts) >= 4,
        "the two hosts' requests interleave: {} switches",
        switches(&hosts)
    );
    let steps = host_steps(&e, "fuzz");
    assert_eq!(max_running(&steps), 2, "{steps:#?}");
    let last = steps.last().unwrap();
    assert_eq!(last["state"], "done", "{last}");
    assert_eq!(last["done"], 2, "{last}");
    assert_eq!(last["total"], 2, "{last}");
    assert_eq!(fuzz_events(&e).last().unwrap()["status"], "ok");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn one_host_at_a_time_keeps_the_old_order() {
    let e = fuzz_env_with(None, 0).await;
    set_parallel(&e, 1).await;
    let id = e.project("example.test").await;
    e.call("scan_start", full(&id)).await;
    e.wait().await;
    let hosts = hosts_of(&fuzz_rows(&e, &id).await);
    assert_eq!(
        switches(&hosts),
        1,
        "with 1 host in parallel the hosts are brute-forced one after another"
    );
    assert_eq!(max_running(&host_steps(&e, "fuzz")), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn shared_budget_holds_across_workers() {
    let e = fuzz_env_with(None, 0).await;
    set_parallel(&e, 4).await;
    e.call(
        "settings_set",
        json!({ "patch": { "fuzz": { "max_requests": 120 } } }),
    )
    .await;
    let id = e.project("example.test").await;
    e.call("scan_start", full(&id)).await;
    e.wait().await;
    let rows = fuzz_rows(&e, &id).await;
    assert!(
        rows.len() <= 120,
        "the request budget is shared by all hosts: {} requests",
        rows.len()
    );
    assert!(rows.len() >= 100, "the budget was used: {}", rows.len());
    let last = fuzz_events(&e).last().unwrap().clone();
    assert_eq!(last["status"], "stopped", "{last}");
    assert_eq!(last["stop"], json!({ "kind": "budget" }), "{last}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rate_limit_on_one_host_does_not_stop_the_others() {
    // example.test is first in line; with the old loop its 429 ended the whole brute force
    let e = fuzz_env_with(Some("example.test"), 0).await;
    set_parallel(&e, 1).await;
    let id = e.project("example.test").await;
    e.call("scan_start", full(&id)).await;
    e.wait().await;
    let hosts = hosts_of(&fuzz_rows(&e, &id).await);
    let www = hosts.iter().filter(|h| *h == "www.example.test").count();
    assert!(
        www > 100,
        "www.example.test is still brute-forced after example.test answered 429: {www}"
    );
    let ev = e.events();
    assert!(
        ev.iter()
            .any(|x| x["type"] == "warning" && x["code"] == "fuzz_blocked"),
        "the blocked host is still reported"
    );
    let last = fuzz_events(&e).last().unwrap().clone();
    assert_eq!(last["status"], "blocked", "{last}");
    assert_eq!(last["blocked_hosts"], 1, "{last}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pause_and_stop_reach_every_worker() {
    let e = fuzz_env_with(None, 25).await;
    set_parallel(&e, 4).await;
    let id = e.project("example.test").await;
    e.call("scan_start", full(&id)).await;
    // both hosts are being brute-forced
    let mut both = false;
    for _ in 0..1500 {
        let hosts = hosts_of(&fuzz_rows(&e, &id).await);
        let a = hosts.iter().filter(|h| *h == "example.test").count();
        let b = hosts.iter().filter(|h| *h == "www.example.test").count();
        if a > 5 && b > 5 {
            both = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(both, "both hosts start before the pause");
    e.call("scan_pause", json!({})).await;
    tokio::time::sleep(Duration::from_millis(900)).await;
    let n1 = fuzz_rows(&e, &id).await.len();
    tokio::time::sleep(Duration::from_millis(1200)).await;
    let n2 = fuzz_rows(&e, &id).await.len();
    assert!(n2 <= n1 + 8, "a worker runs on while paused: {n1} -> {n2}");
    e.call("scan_resume", json!({})).await;
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert!(
        fuzz_rows(&e, &id).await.len() > n2,
        "the workers resume together with the scan"
    );
    e.call("scan_stop", json!({})).await;
    tokio::time::timeout(Duration::from_secs(20), e.wait())
        .await
        .expect("the scan did not stop");
    let n3 = fuzz_rows(&e, &id).await.len();
    tokio::time::sleep(Duration::from_millis(800)).await;
    assert_eq!(
        fuzz_rows(&e, &id).await.len(),
        n3,
        "no requests from any worker after stop"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stage_skip_reaches_every_worker() {
    let e = fuzz_env_with(None, 25).await;
    set_parallel(&e, 4).await;
    let id = e.project("example.test").await;
    e.call("scan_start", full(&id)).await;
    for _ in 0..1500 {
        if max_running(&host_steps(&e, "fuzz")) == 2 && fuzz_rows(&e, &id).await.len() > 20 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(max_running(&host_steps(&e, "fuzz")), 2);
    let r = e
        .call(
            "scan_control",
            json!({ "kind": "stage", "id": "fuzz", "action": "skip" }),
        )
        .await;
    assert_eq!(r["state"], "skipped", "{r}");
    let t0 = std::time::Instant::now();
    // each host still has well over a thousand slow requests to go: only a stop of every worker
    // ends the stage this soon
    for _ in 0..500 {
        if e.events()
            .iter()
            .any(|x| x["type"] == "stage" && x["stage"] == "report")
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(
        t0.elapsed() < Duration::from_secs(4),
        "the stage ended {:?} after Skip",
        t0.elapsed()
    );
    tokio::time::timeout(Duration::from_secs(20), e.wait())
        .await
        .expect("the scan did not finish after Skip on the running stage");
    assert!(e.events().iter().any(|x| x["type"] == "done"));
    let n1 = fuzz_rows(&e, &id).await.len();
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(
        fuzz_rows(&e, &id).await.len(),
        n1,
        "no worker goes on after Skip"
    );
}

/// Listener that accepts and holds connections without a greeting (banner reads wait).
async fn silent(ip: &str, port: u16) {
    let l = TcpListener::bind((ip, port)).await.unwrap();
    tokio::spawn(async move {
        while let Ok((s, _)) = l.accept().await {
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_millis(800)).await;
                drop(s);
            });
        }
    });
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn port_scan_runs_hosts_concurrently() {
    let dir = tempfile::tempdir().unwrap();
    let server = server(0).await;
    let keys = Arc::new(MemoryKeys::new());
    // www lives on its own address, so the port scan has two hosts (one scan per IP)
    let zone = ZONE.replace(
        "www.example.test A 127.0.0.1",
        "www.example.test A 127.0.0.3",
    );
    let (engine, events, pause_at) = open_with(dir.path(), &server.url(), keys.clone(), |c| {
        c.dns = Some(Arc::new(foca_net::dns::StaticDns::from_zone_text(&zone)));
    });
    let e = Env {
        dir,
        server,
        engine,
        events,
        pause_at,
        keys,
    };
    let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = probe.local_addr().unwrap().port();
    drop(probe);
    silent("127.0.0.1", port).await;
    silent("127.0.0.3", port).await;
    e.call(
        "settings_set",
        json!({ "patch": { "net": { "rps": 0, "hosts_parallel": 4 },
            "ports": { "top": 0, "list": port.to_string() },
            "fuzz": { "max_requests": 50, "max_hosts": 1, "rate": 50 } } }),
    )
    .await;
    let id = e.project("example.test").await;
    e.call("scan_start", full(&id)).await;
    e.wait().await;
    let snap = e.snap(&id).await;
    for name in ["example.test", "www.example.test"] {
        let h = snap["hosts"]
            .as_array()
            .unwrap()
            .iter()
            .find(|h| h["name"] == name)
            .unwrap_or_else(|| panic!("{name} missing: {}", snap["hosts"]));
        assert_eq!(h["ports_scan"]["open"], 1, "{name}: {}", h["ports_scan"]);
    }
    let steps = host_steps(&e, "ports");
    assert_eq!(max_running(&steps), 2, "{steps:#?}");
    let last = steps.last().unwrap();
    assert_eq!(
        (last["done"].as_u64(), last["total"].as_u64()),
        (Some(2), Some(2))
    );
    let src: Vec<Value> = e
        .events()
        .into_iter()
        .filter(|x| x["type"] == "source" && x["id"] == "ports")
        .collect();
    let fin = src.last().unwrap();
    assert_eq!(fin["status"], "ok", "{src:#?}");
    assert_eq!(fin["n"], 2, "one open port per host: {fin}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn site_recon_runs_sites_concurrently() {
    let dir = tempfile::tempdir().unwrap();
    let server = TestServer::start(|r| {
        let host = site::host_of(r);
        if host == "127.0.0.1" {
            return TestResponse::status(404);
        }
        if r.path() == "/" {
            return TestResponse::ok(
                b"<html><head><title>Site</title></head><body>hello</body></html>".to_vec(),
            )
            .header("content-type", "text/html")
            .delay(Duration::from_millis(400));
        }
        TestResponse::status(404)
    })
    .await;
    let keys = Arc::new(MemoryKeys::new());
    let port = server.port();
    let (engine, events, pause_at) = open_with(dir.path(), &server.url(), keys.clone(), |c| {
        c.site_port = Some(port);
        c.net
            .host_overrides
            .insert("contoso.test".into(), vec!["127.0.0.1".parse().unwrap()]);
    });
    let e = Env {
        dir,
        server,
        engine,
        events,
        pause_at,
        keys,
    };
    set_parallel(&e, 4).await;
    let p = e
        .call(
            "project_create",
            json!({ "name": "two sites", "targets": [
                { "v": "example.test", "type": "domain" },
                { "v": "contoso.test", "type": "domain" } ] }),
        )
        .await;
    let id = p["id"].as_str().unwrap().to_string();
    e.call(
        "scan_start",
        json!({ "project": id, "profile": "std", "sources": ["recon"] }),
    )
    .await;
    e.wait().await;
    let steps = host_steps(&e, "recon");
    assert_eq!(max_running(&steps), 2, "{steps:#?}");
    let s = e.snap(&id).await;
    let sites: Vec<&str> = s["recon"]["sites"]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| x["host"].as_str().unwrap())
        .collect();
    assert_eq!(sites, ["contoso.test", "example.test"], "{}", s["recon"]);
}
