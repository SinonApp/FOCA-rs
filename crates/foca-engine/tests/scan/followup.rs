//! Follow-up run of chosen scan items (`scan_start { only }`): only the stages that own the
//! chosen items run, the others are reported as not selected; and the `no_network` warning
//! stays for real connectivity loss, not for sources that only limited or blocked us.

use std::sync::Arc;

use crate::common::{env, open_with, Env};
use foca_engine::MemoryKeys;
use foca_net::bruteforce::testdns::FakeDns;
use foca_net::testserver::{TestRequest, TestResponse, TestServer};
use serde_json::{json, Value};

fn ran_stages(ev: &[Value]) -> Vec<String> {
    ev.iter()
        .filter(|x| x["type"] == "stage")
        .filter_map(|x| x["stage"].as_str().map(String::from))
        .collect()
}

fn substep_ids(ev: &[Value]) -> Vec<String> {
    let mut v: Vec<String> = ev
        .iter()
        .filter(|x| x["type"] == "substep")
        .filter_map(|x| x["id"].as_str().map(String::from))
        .collect();
    v.dedup();
    v
}

fn ran_sources(ev: &[Value]) -> Vec<String> {
    let mut v: Vec<String> = ev
        .iter()
        .filter(|x| x["type"] == "source" && x["status"] == "running")
        .filter_map(|x| x["id"].as_str().map(String::from))
        .collect();
    v.sort();
    v.dedup();
    v
}

async fn scan_modules(e: &Env, project: &str, scan_id: &str) -> Vec<String> {
    let log = e
        .call(
            "request_log_get",
            json!({ "project": project, "limit": 5000 }),
        )
        .await;
    let mut v: Vec<String> = log
        .as_array()
        .unwrap()
        .iter()
        .filter(|r| r["scan_id"] == scan_id)
        .filter_map(|r| r["module"].as_str().map(String::from))
        .collect();
    v.sort();
    v.dedup();
    v
}

/// A follow-up of one search source in a full (active) profile: Search plus the document
/// pipeline for the new documents, nothing from Network, Ports, Site recon or Site search.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn follow_up_of_search_sources_runs_only_search_and_documents() {
    let e = env(0).await;
    let id = e.project("example.test").await;
    e.call("settings_set", json!({ "patch": { "net": { "rps": 0 } } }))
        .await;
    let r = e
        .call(
            "scan_start",
            json!({ "project": id, "profile": "full", "sources": ["wayback"],
                "from_stage": "search", "only": ["source:wayback"] }),
        )
        .await;
    let sid = r["scan_id"].as_str().unwrap().to_string();
    assert_eq!(
        r["stages"],
        json!(["search", "download", "meta", "analysis", "report"]),
        "{r}"
    );
    e.wait().await;
    let ev = e.events();
    assert_eq!(
        ran_stages(&ev),
        ["search", "download", "meta", "analysis", "report"],
        "{:?}",
        ran_stages(&ev)
    );
    let subs = substep_ids(&ev);
    assert!(!subs.iter().any(|s| s == "dns"), "DNS step ran: {subs:?}");
    for s in [
        "dns", "takeover", "resolve", "brute", "permute", "rdap", "liveness",
    ] {
        assert!(!subs.iter().any(|x| x == s), "{s} ran: {subs:?}");
    }
    let srcs = ran_sources(&ev);
    for s in [
        "subdomains",
        "tls",
        "ports",
        "recon",
        "webaudit",
        "wellknown",
        "fuzz",
    ] {
        assert!(!srcs.iter().any(|x| x == s), "{s} ran: {srcs:?}");
    }
    assert_eq!(srcs, ["wayback"], "{srcs:?}");
    // requests of this run come from the chosen source and the downloads of its documents
    let mods = scan_modules(&e, &id, &sid).await;
    assert!(
        mods.iter().all(|m| m == "wayback" || m == "download"),
        "{mods:?}"
    );
    // new documents were processed
    let done = ev.iter().find(|x| x["type"] == "done").unwrap();
    assert!(
        done["scan"]["added"]["docs"].as_u64().unwrap() > 0,
        "{done}"
    );
    // the stored record names the selection and the stages that ran
    assert_eq!(done["scan"]["only"], json!(["source:wayback"]), "{done}");
    assert_eq!(
        done["scan"]["stages"],
        json!(["search", "download", "meta", "analysis", "report"])
    );
    let scans = e.snap(&id).await["scans"].clone();
    let rec = scans
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["id"] == sid.as_str())
        .unwrap()
        .clone();
    assert_eq!(rec["status"], "done", "{rec}");
    // sources outside the selection are not part of this run
    let src = |id: &str| {
        rec["sources"]
            .as_array()
            .unwrap()
            .iter()
            .find(|s| s["id"] == id)
            .map(|s| s["status"].clone())
    };
    for s in ["subdomains", "tls", "ports", "recon", "fuzz"] {
        if let Some(st) = src(s) {
            assert_eq!(st, "off", "{s}: {rec}");
        }
    }
}

fn dns_handler(r: &TestRequest) -> TestResponse {
    if r.path() == "/" && r.query("output").is_some() {
        return TestResponse::ok(b"[]".to_vec());
    }
    TestResponse::status(404)
}

async fn dns_env() -> Env {
    let dns = FakeDns::new()
        .host("example.test", &["127.0.0.1"], 300)
        .host("www.example.test", &["127.0.0.1"], 300);
    let dir = tempfile::tempdir().unwrap();
    let server = TestServer::start(dns_handler).await;
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

/// A follow-up of the brute force step runs the Network stage with that step alone: no search,
/// no DNS summary, no permutations, no later stages.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn follow_up_of_a_subdomain_step_runs_only_that_step() {
    let e = dns_env().await;
    let p = e
        .call(
            "project_create",
            json!({ "name": "example.test", "client": "К",
                "targets": [{ "v": "example.test", "type": "domain" }], "excludes": [] }),
        )
        .await;
    let id = p["id"].as_str().unwrap().to_string();
    let r = e
        .call(
            "scan_start",
            json!({ "project": id, "profile": "full", "sources": ["subdomains"],
                "from_stage": "network", "only": ["step:brute"],
                "subdomains": { "wordlist": "custom", "custom": ["www", "api"] } }),
        )
        .await;
    let sid = r["scan_id"].as_str().unwrap().to_string();
    e.wait().await;
    let ev = e.events();
    assert_eq!(
        ran_stages(&ev),
        ["network", "report"],
        "{:?}",
        ran_stages(&ev)
    );
    let subs = substep_ids(&ev);
    assert!(subs.iter().any(|s| s == "brute"), "{subs:?}");
    for s in ["dns", "permute", "takeover", "rdap", "liveness", "tls"] {
        assert!(!subs.iter().any(|x| x == s), "{s} ran: {subs:?}");
    }
    let srcs = ran_sources(&ev);
    assert_eq!(srcs, ["subdomains"], "{srcs:?}");
    let mods = scan_modules(&e, &id, &sid).await;
    assert!(
        mods.is_empty(),
        "HTTP requests in a brute force run: {mods:?}"
    );
    // brute force found www
    let snap = e.snap(&id).await;
    assert!(
        snap["hosts"]
            .as_array()
            .unwrap()
            .iter()
            .any(|h| h["name"] == "www.example.test"),
        "{}",
        snap["hosts"]
    );
}

/// A follow-up that holds a whole stage runs that stage only, not every stage after it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn follow_up_of_a_whole_stage_runs_that_stage_only() {
    let e = dns_env().await;
    let p = e
        .call(
            "project_create",
            json!({ "name": "example.test", "client": "К",
                "targets": [{ "v": "example.test", "type": "domain" }], "excludes": [] }),
        )
        .await;
    let id = p["id"].as_str().unwrap().to_string();
    e.call(
        "scan_start",
        json!({ "project": id, "profile": "full", "sources": [],
            "from_stage": "network", "only": ["stage:network"],
            "subdomains": { "wordlist": "custom", "custom": ["www"] } }),
    )
    .await;
    e.wait().await;
    let ev = e.events();
    assert_eq!(
        ran_stages(&ev),
        ["network", "report"],
        "{:?}",
        ran_stages(&ev)
    );
    let subs = substep_ids(&ev);
    // the whole stage keeps its usual steps
    assert!(subs.iter().any(|s| s == "dns"), "{subs:?}");
    assert!(subs.iter().any(|s| s == "brute"), "{subs:?}");
}

/// Every chosen source answered with a rate limit or a captcha while the network itself works:
/// no `no_network`, a warning that names the real reason instead.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn limited_sources_with_working_network_are_not_no_network() {
    let dir = tempfile::tempdir().unwrap();
    let server = TestServer::start(|_r: &TestRequest| TestResponse::status(429)).await;
    let keys = Arc::new(MemoryKeys::new());
    let (engine, events, pause_at) = open_with(dir.path(), &server.url(), keys.clone(), |_| {});
    let e = Env {
        dir,
        server,
        engine,
        events,
        pause_at,
        keys,
    };
    let id = e.project("example.test").await;
    e.call(
        "scan_start",
        json!({ "project": id, "profile": "passive", "sources": ["otx_dns", "crt"],
            "only": ["source:otx_dns", "source:crt"] }),
    )
    .await;
    e.wait().await;
    let ev = e.events();
    let codes: Vec<&str> = ev
        .iter()
        .filter(|x| x["type"] == "warning")
        .filter_map(|x| x["code"].as_str())
        .collect();
    assert!(!codes.contains(&"no_network"), "{codes:?}");
    assert!(codes.contains(&"search_sources_limited"), "{codes:?}");
    let w = ev
        .iter()
        .find(|x| x["type"] == "warning" && x["code"] == "search_sources_limited")
        .unwrap();
    assert_eq!(w["message_msg"]["code"], "search.sources_limited", "{w}");
}
