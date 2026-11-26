//! Sub-step progress of the network stage and per-item scan controls.

use std::sync::Arc;

use crate::common::{open_with, Env};
use foca_engine::MemoryKeys;
use foca_net::bruteforce::testdns::FakeDns;
use foca_net::testserver::{TestRequest, TestResponse, TestServer};
use serde_json::{json, Value};

fn handler(r: &TestRequest) -> TestResponse {
    if r.path() == "/" && r.query("output").is_some() {
        return TestResponse::ok(b"[]".to_vec());
    }
    TestResponse::status(404)
}

async fn dns_env(dns: FakeDns) -> Env {
    let dir = tempfile::tempdir().unwrap();
    let server = TestServer::start(handler).await;
    let keys = Arc::new(MemoryKeys::new());
    let (engine, events, pause_at) = open_with(dir.path(), &server.url(), keys.clone(), |c| {
        c.dns = Some(Arc::new(dns));
        c.dns_unthrottled = true;
    });
    let e = Env {
        dir,
        server,
        engine,
        events,
        pause_at,
        keys,
    };
    e.call("settings_set", json!({ "patch": { "net": { "rps": 0 } } }))
        .await;
    e
}

async fn project(e: &Env, target: &str) -> String {
    let p = e
        .call(
            "project_create",
            json!({ "name": target, "client": "К",
                "targets": [{ "v": target, "type": "domain" }], "excludes": [] }),
        )
        .await;
    p["id"].as_str().unwrap().to_string()
}

fn substeps<'a>(ev: &'a [Value], id: &str) -> Vec<&'a Value> {
    ev.iter()
        .filter(|x| x["type"] == "substep" && x["id"] == id)
        .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn network_stage_reports_substeps_with_counters() {
    let dns = FakeDns::new()
        .host("example.test", &["127.0.0.1"], 300)
        .host("www.example.test", &["127.0.0.1"], 300);
    let e = dns_env(dns).await;
    let id = project(&e, "example.test").await;
    let words = ["www", "api", "mail", "vpn", "dev"];
    e.call(
        "scan_start",
        json!({ "project": id, "profile": "std", "sources": ["crt"],
            "subdomains": { "wordlist": "custom", "custom": words } }),
    )
    .await;
    e.wait().await;
    let ev = e.events();
    let brute = substeps(&ev, "brute");
    assert!(brute.len() >= 2, "{brute:?}");
    assert_eq!(brute[0]["state"], "running");
    assert_eq!(brute[0]["stage"], "network");
    assert_eq!(brute[0]["total"], words.len());
    let last = brute.last().unwrap();
    assert_eq!(last["state"], "done", "{last}");
    assert_eq!(last["done"], words.len(), "{last}");
    assert_eq!(last["total"], words.len(), "{last}");
    for k in ["eta_s", "slow"] {
        assert!(last.get(k).is_some(), "{k} missing: {last}");
    }
    let perm = substeps(&ev, "permute");
    assert_eq!(perm.last().unwrap()["state"], "done", "{perm:?}");
    for id in ["dns", "takeover"] {
        assert!(!substeps(&ev, id).is_empty(), "no {id} sub-step");
    }
    // the running sub-step is cleared once the scan is over
    let st = e.call("scan_status", json!({})).await;
    assert_eq!(st["running"], false);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn url_target_skips_subdomain_passes_with_a_reason() {
    let dns = FakeDns::new().host("example.test", &["127.0.0.1"], 300);
    let e = dns_env(dns).await;
    let p = e
        .call(
            "project_create",
            json!({ "name": "example.test", "client": "К",
                "targets": [{ "v": "https://example.test", "type": "url" }], "excludes": [] }),
        )
        .await;
    let id = p["id"].as_str().unwrap().to_string();
    e.call(
        "scan_start",
        json!({ "project": id, "profile": "std", "sources": ["crt"],
            "subdomains": { "wordlist": "custom", "custom": ["www", "api"] } }),
    )
    .await;
    e.wait().await;
    let ev = e.events();
    for step in ["brute", "permute"] {
        let s = substeps(&ev, step);
        // no "running" announcement with a planned count that can never be checked
        assert_eq!(s.len(), 1, "{s:?}");
        assert_eq!(s[0]["state"], "skipped");
        assert_eq!(s[0]["total"], 0);
        assert_eq!(s[0]["reason_msg"]["code"], "sub.url_target", "{}", s[0]);
        assert_eq!(s[0]["reason_msg"]["params"]["domain"], "example.test");
    }
}

/// Found documents of hosts outside the scope never reach the download queue; the search stage
/// reports how many were dropped and why (queue summary sub-step).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn search_queue_summary_counts_out_of_scope_documents() {
    for (target, kind, in_scope) in [
        ("example.test", "domain", true),
        // the archive fixture lists documents on example.test, outside this URL target
        ("https://www.example.test", "url", false),
    ] {
        let e = crate::common::env(0).await;
        let p = e
            .call(
                "project_create",
                json!({ "name": "q", "client": "К",
                    "targets": [{ "v": target, "type": kind }], "excludes": [] }),
            )
            .await;
        let id = p["id"].as_str().unwrap().to_string();
        e.call(
            "scan_start",
            json!({ "project": id, "profile": "passive", "sources": ["wayback"] }),
        )
        .await;
        e.wait().await;
        let ev = e.events();
        let q = substeps(&ev, "queue");
        assert_eq!(q.len(), 1, "{target}: {q:?}");
        let q = q[0];
        assert_eq!(q["stage"], "search");
        assert_eq!(q["reason_msg"]["code"], "search.queue", "{q}");
        let found = q["total"].as_u64().unwrap();
        assert!(found > 0, "{q}");
        let oos: u64 = q["reason_msg"]["params"]["oos"]
            .as_str()
            .unwrap()
            .parse()
            .unwrap();
        if in_scope {
            assert_eq!(oos, 0, "{q}");
            assert!(q["done"].as_u64().unwrap() > 0, "{q}");
        } else {
            assert_eq!((oos, q["done"].as_u64().unwrap()), (found, 0), "{q}");
            let docs = e.snap(&id).await["docs"].as_array().map_or(0, Vec::len);
            assert_eq!(docs, 0, "no out-of-scope document is downloaded");
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn slow_resolver_warns_and_brute_force_can_be_skipped() {
    let words: Vec<String> = (0..300).map(|i| format!("w{i}")).collect();
    let mut dns = FakeDns::new().host("example.test", &["127.0.0.1"], 300);
    for w in words.iter().step_by(2) {
        dns = dns.fail(&format!("{w}.example.test"), 1000);
    }
    let dir = tempfile::tempdir().unwrap();
    let server = TestServer::start(handler).await;
    let keys = Arc::new(MemoryKeys::new());
    let (engine, events, pause_at) = open_with(dir.path(), &server.url(), keys.clone(), |c| {
        c.dns = Some(Arc::new(dns));
        c.dns_unthrottled = false;
    });
    let e = Env {
        dir,
        server,
        engine,
        events,
        pause_at,
        keys,
    };
    // a user rate limit keeps the pass slow enough for an ETA over a minute
    e.call("settings_set", json!({ "patch": { "net": { "rps": 3 } } }))
        .await;
    let id = project(&e, "example.test").await;
    e.call(
        "scan_start",
        json!({ "project": id, "profile": "std", "sources": ["crt"],
            "subdomains": { "wordlist": "custom", "custom": words } }),
    )
    .await;
    let t0 = std::time::Instant::now();
    let warned = loop {
        let ev = e.events();
        if let Some(w) = ev
            .iter()
            .find(|x| x["type"] == "warning" && x["code"] == "dns.slow")
        {
            break w.clone();
        }
        assert!(
            t0.elapsed().as_secs() < 60,
            "no dns.slow warning: {:?}",
            substeps(&ev, "brute").last()
        );
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    };
    assert!(
        warned["message"].as_str().unwrap().contains("мин"),
        "{warned}"
    );
    let ev = e.events();
    let slow = substeps(&ev, "brute")
        .into_iter()
        .rev()
        .find(|x| x["state"] == "running")
        .cloned()
        .unwrap();
    assert_eq!(slow["slow"], true, "{slow}");
    assert!(slow["eta_s"].as_u64().unwrap() >= 60, "{slow}");
    let r = e.call("scan_skip_source", json!({ "id": "brute" })).await;
    assert_eq!(r["ok"], true, "{r}");
    e.wait().await;
    let ev = e.events();
    let last = *substeps(&ev, "brute").last().unwrap();
    assert_eq!(last["state"], "skipped", "{last}");
    assert!(
        last["done"].as_u64().unwrap() < words.len() as u64,
        "{last}"
    );
    // permutations still run after brute force was skipped
    assert!(!substeps(&ev, "permute").is_empty());
    let n = ev
        .iter()
        .filter(|x| x["type"] == "warning" && x["code"] == "dns.slow")
        .count();
    assert_eq!(n, 1, "one warning per scan");
}

async fn std_scan_paused_at_network(e: &Env, id: &str) {
    *e.pause_at.lock().unwrap() = Some("network".into());
    e.call(
        "scan_start",
        json!({ "project": id, "profile": "std", "sources": ["crt"],
            "subdomains": { "wordlist": "custom", "custom": ["www", "api"] } }),
    )
    .await;
    e.wait_paused("network").await;
    *e.pause_at.lock().unwrap() = None;
}

async fn control(e: &Env, kind: &str, id: &str, action: &str) -> Value {
    e.call(
        "scan_control",
        json!({ "kind": kind, "id": id, "action": action }),
    )
    .await
}

fn count(ev: &[Value], id: &str, state: &str) -> usize {
    substeps(ev, id)
        .iter()
        .filter(|x| x["state"] == state)
        .count()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stage_controls_pause_restart_and_queue() {
    let dns = FakeDns::new()
        .host("example.test", &["127.0.0.1"], 300)
        .host("www.example.test", &["127.0.0.1"], 300);
    let e = dns_env(dns).await;
    let id = project(&e, "example.test").await;
    let idle = control(&e, "stage", "network", "pause").await;
    assert_eq!(
        idle,
        json!({ "ok": false, "state": "", "reason": "no_scan" })
    );
    std_scan_paused_at_network(&e, &id).await;
    let st = e.call("scan_status", json!({})).await;
    assert_eq!(
        st["controls"]["stage:*"],
        json!(["pause", "resume", "skip", "restart"])
    );
    // hold the network stage, then lift the global pause: the stage stays put
    let r = control(&e, "stage", "network", "pause").await;
    assert_eq!(r["state"], "paused", "{r}");
    e.call("scan_resume", json!({})).await;
    tokio::time::sleep(std::time::Duration::from_millis(800)).await;
    let st = e.call("scan_status", json!({})).await;
    assert_eq!(st["stage"], "network", "{st}");
    assert_eq!(st["held"], json!(["stage:network"]), "{st}");
    // a stage that is over can only be queued for a follow-up run; a future one is pending
    let q = control(&e, "stage", "search", "restart").await;
    assert_eq!(q, json!({ "ok": true, "state": "queued", "reason": "" }));
    let p = control(&e, "stage", "fuzz", "restart").await;
    assert_eq!(p["reason"], "pending", "{p}");
    let past = control(&e, "source", "crt", "pause").await;
    assert_eq!(past["reason"], "unsupported", "{past}");
    // restart the running stage, then release it: network runs twice
    let r = control(&e, "stage", "network", "restart").await;
    assert_eq!(r["state"], "restarting", "{r}");
    control(&e, "stage", "network", "resume").await;
    e.wait().await;
    let ev = e.events();
    assert!(count(&ev, "dns", "done") >= 1, "network ran");
    let starts = ev
        .iter()
        .filter(|x| x["type"] == "stage" && x["stage"] == "network")
        .count();
    assert_eq!(starts, 2, "network stage restarted once");
    let done = ev.iter().find(|x| x["type"] == "done").unwrap();
    assert_eq!(done["followup"], json!(["stage:search"]), "{done}");
    assert!(ev
        .iter()
        .any(|x| x["type"] == "control" && x["kind"] == "stage" && x["state"] == "queued"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stage_and_step_skip_and_follow_up_run() {
    let dns = FakeDns::new()
        .host("example.test", &["127.0.0.1"], 300)
        .host("www.example.test", &["127.0.0.1"], 300);
    let e = dns_env(dns).await;
    let id = project(&e, "example.test").await;
    std_scan_paused_at_network(&e, &id).await;
    // brute force skipped alone: permutations still run
    let r = control(&e, "step", "brute", "skip").await;
    assert_eq!(r["state"], "skipped", "{r}");
    // ports skipped before it starts
    let r = control(&e, "stage", "ports", "skip").await;
    assert_eq!(r["ok"], true, "{r}");
    e.call("scan_resume", json!({})).await;
    e.wait().await;
    let ev = e.events();
    assert_eq!(
        count(&ev, "brute", "running"),
        0,
        "brute force ran after a skip"
    );
    assert!(count(&ev, "permute", "done") >= 1);
    assert!(!ev
        .iter()
        .any(|x| x["type"] == "source" && x["id"] == "ports" && x["status"] == "running"));
    // a follow-up run from the network stage
    e.clear_events();
    let r = e
        .call(
            "scan_start",
            json!({ "project": id, "profile": "std", "sources": ["crt"], "from_stage": "network" }),
        )
        .await;
    assert!(r["scan_id"].is_string(), "{r}");
    e.wait().await;
    let ev = e.events();
    let stages: Vec<&str> = ev
        .iter()
        .filter(|x| x["type"] == "stage")
        .filter_map(|x| x["stage"].as_str())
        .collect();
    assert_eq!(stages.first(), Some(&"network"), "{stages:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn verified_search_engine_after_search_is_queued_for_restart() {
    let dns = FakeDns::new().host("example.test", &["127.0.0.1"], 300);
    let e = dns_env(dns).await;
    let id = project(&e, "example.test").await;
    std_scan_paused_at_network(&e, &id).await;
    // the check passed after the search stage: no live retry, the restart is queued instead
    let r = e
        .call("scan_retry_source", json!({ "id": "startpage" }))
        .await;
    assert_eq!(r["ok"], false, "{r}");
    assert_eq!(r["reason_msg"]["code"], "scan.retry_later", "{r}");
    let q = control(&e, "source", "startpage", "restart").await;
    assert_eq!(q, json!({ "ok": true, "state": "queued", "reason": "" }));
    let st = e.call("scan_status", json!({})).await;
    assert_eq!(st["followup"], json!(["source:startpage"]), "{st}");
    e.call("scan_resume", json!({})).await;
    e.wait().await;
    let ev = e.events();
    let done = ev.iter().find(|x| x["type"] == "done").unwrap();
    assert_eq!(done["followup"], json!(["source:startpage"]), "{done}");
}
