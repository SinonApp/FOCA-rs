//! Site discovery (`foca-fuzz`) in the engine against the offline bench `tests/fixtures/fuzz-site`:
//! a full scan finds documents and parses them; findings carry masked evidence; pause, stop and
//! resume; "stop brute force"; the full profile starts with a single call and no confirmations;
//! the standard profile makes no brute-force requests.

#[path = "../../../foca-fuzz/tests/common/mod.rs"]
pub(super) mod site;

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use crate::common::*;
use foca_engine::MemoryKeys;
use foca_net::testserver::{TestRequest, TestResponse, TestServer};
use serde_json::{json, Value};

/// Returns a real corpus document instead of the bench placeholder (so metadata gets parsed).
fn corpus_for(path: &str) -> Option<Vec<u8>> {
    let f = if path.ends_with(".pdf") {
        "pdf/report.pdf"
    } else if path.ends_with(".docx") {
        "ooxml/contract.docx"
    } else if path.ends_with(".xlsx") {
        "ooxml/schedule.xlsx"
    } else {
        return None;
    };
    std::fs::read(corpus_dir().join(f)).ok()
}

fn handler(r: &TestRequest) -> TestResponse {
    let host = site::host_of(r);
    let p = r.path().to_string();
    // "internet sources" (Wayback, crt.sh) live at 127.0.0.1
    if host == "127.0.0.1" {
        if p == "/cdx/search/cdx" {
            let rows = json!([
                ["timestamp", "original", "mimetype", "length", "statuscode"],
                [
                    "20240301000000",
                    "https://www.example.test/files/report_2023.pdf",
                    "application/pdf",
                    "1000",
                    "200"
                ]
            ]);
            return TestResponse::ok(serde_json::to_vec(&rows).unwrap());
        }
        if p == "/" && r.query("output").is_some() {
            return TestResponse::ok(br#"[{"name_value":"www.example.test"}]"#.to_vec());
        }
        if p == "/collinfo.json" {
            return TestResponse::ok(b"[]".to_vec());
        }
        if p.starts_with("/SecLists/") {
            return TestResponse::ok(b"www\nadmin\n".to_vec());
        }
        return TestResponse::status(404);
    }
    let resp = site::site(r, site::SiteOpts { soft404: true });
    if resp.status == 200 {
        let fs = site::fs_path(&site::root_for(&host), &p);
        if fs.is_file() {
            if let Some(mut b) = corpus_for(&p) {
                // different bench PDFs are different files (otherwise SHA-256 dedup would merge them)
                if p.ends_with(".pdf") {
                    b.extend_from_slice(format!("\n% {p}\n").as_bytes());
                }
                return TestResponse::ok(b);
            }
        }
    }
    resp
}

async fn fuzz_env() -> Env {
    let dir = tempfile::tempdir().unwrap();
    let server = TestServer::start(handler).await;
    let keys = Arc::new(MemoryKeys::new());
    let (engine, events, pause_at) = open_with(dir.path(), &server.url(), keys.clone(), |c| {
        c.fuzz_unthrottled = true;
        c.endpoints
            .sources
            .insert("seclists".into(), format!("{}/SecLists", server.url()));
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
            "max_requests": 30000, "max_hosts": 2, "exclude_paths": ["/private"] } } }),
    )
    .await;
    e
}

fn full(id: &str) -> Value {
    json!({ "project": id, "profile": "full", "sources": ["crt", "wayback"] })
}

async fn fuzz_log(e: &Env, id: &str) -> Vec<Value> {
    let log = e
        .call("request_log_get", json!({ "project": id, "limit": 100000 }))
        .await;
    log.as_array()
        .unwrap()
        .iter()
        .filter(|r| r["module"] == "fuzz")
        .cloned()
        .collect()
}

fn fuzz_events(e: &Env) -> Vec<Value> {
    e.events()
        .into_iter()
        .filter(|x| x["type"] == "source" && x["id"] == "fuzz")
        .collect()
}

fn doc_status(s: &Value, name: &str) -> Option<String> {
    s["docs"]
        .as_array()
        .unwrap()
        .iter()
        .find(|d| d["name"] == name)
        .map(|d| d["status"].as_str().unwrap_or("").to_string())
}

fn fuzz_findings(s: &Value) -> Vec<Value> {
    s["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|f| f["module"] == "fuzz")
        .cloned()
        .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn full_scan_fuzz_finds_documents_and_they_are_parsed() {
    let e = fuzz_env().await;
    let id = e.project("example.test").await;
    let est = e.call("fuzz_estimate", json!({ "project": id })).await;
    assert!(est["requests"].as_u64().unwrap() > 100, "{est}");
    // The note carries a message code that matches its RU fallback text.
    assert_eq!(est["note_msg"]["code"], "fuzz.estimate_note", "{est}");
    let known = foca_engine::i18n::classify(est["note"].as_str().unwrap()).unwrap();
    assert_eq!(known["code"], est["note_msg"]["code"]);
    e.call("scan_start", full(&id)).await;
    e.wait().await;
    let ev = e.events();
    let done = ev.iter().find(|x| x["type"] == "done");
    assert!(
        done.is_some(),
        "no done: {:?}",
        ev.iter()
            .filter(|x| x["type"] != "progress")
            .collect::<Vec<_>>()
    );
    assert!(ev
        .iter()
        .any(|x| x["type"] == "stage" && x["stage"] == "fuzz"));
    let fe = fuzz_events(&e);
    let last = fe.last().unwrap();
    assert_eq!(last["status"], "ok", "{fe:#?}");
    assert!(last["checked"].as_u64().unwrap() > 100, "{last}");
    assert!(
        last["filtered"].as_u64().unwrap() > 0,
        "soft 404 filtered out by calibration: {last}"
    );
    assert!(fe.iter().any(|x| x["status"] == "running"));

    let s = e.snap(&id).await;
    let hosts: Vec<&Value> = fe.iter().map(|x| &x["host"]).collect();
    eprintln!("fuzz hosts: {hosts:?}\nlast: {last}");
    for d in s["docs"].as_array().unwrap() {
        eprintln!("DOC {} {} {}", d["name"], d["status"], d["url"]);
    }
    for d in [
        "report_2024.pdf",
        "secret-plan_2024.pdf",
        "annual_report.docx",
        "internal.pdf",
    ] {
        assert_eq!(
            doc_status(&s, d).as_deref(),
            Some("analyzed"),
            "{d} found by brute force and parsed; docs: {}",
            s["docs"]
        );
    }
    let ff = fuzz_findings(&s);
    let has = |t: &str| ff.iter().any(|f| f["title"].as_str().unwrap().contains(t));
    let titles: Vec<&str> = ff.iter().map(|f| f["title"].as_str().unwrap()).collect();
    assert!(has("/.git/HEAD"), "{titles:#?}");
    assert!(has("/.env"), "{titles:#?}");
    assert!(has("/docs/"), "{titles:#?}");
    assert!(has("/.DS_Store"), "{titles:#?}");
    for f in &ff {
        assert_eq!(f["active"], true);
    }
    // the .env evidence is masked (the bench secret is never fully visible)
    let env = ff
        .iter()
        .find(|f| f["title"].as_str().unwrap().contains("/.env"))
        .unwrap();
    let env_raw = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/fuzz-site/www/.env"),
    )
    .unwrap();
    for line in env_raw.lines() {
        if let Some((_, v)) = line.split_once('=') {
            if v.len() >= 8 {
                assert!(
                    !env.to_string().contains(v),
                    "secret {v} is not masked: {env}"
                );
            }
        }
    }
    // report: the "found on the site" subsection
    e.call(
        "report_build",
        json!({ "project": id, "opts": { "tpl_id": "full", "fmt": "html", "lang": "RU", "min_sev": "low" } }),
    )
    .await;
    let rdir = e.dir.path().join("reports").join(&id);
    let html: String = std::fs::read_dir(&rdir)
        .unwrap()
        .filter_map(Result::ok)
        .map(|f| std::fs::read_to_string(f.path()).unwrap_or_default())
        .collect();
    assert!(
        html.contains("Найдено на сайте"),
        "section missing from the report"
    );
    assert!(html.contains("/.git/HEAD"));
    // log: brute force sends active requests only to in-scope hosts; the excluded path is untouched
    let log = fuzz_log(&e, &id).await;
    assert!(log.len() > 100);
    for r in &log {
        assert_eq!(r["access"], "active", "{r}");
        let u = r["url"].as_str().unwrap();
        let path = url::Url::parse(u).unwrap().path().to_string();
        assert!(
            path != "/private" && !path.starts_with("/private/"),
            "excluded path requested: {u}"
        );
        assert!(!u.contains("mail.example.test"), "{u}");
    }
    // the site answers with soft 404s: discarded responses and calibration probes are annotated in the log
    let note = |n: &str| log.iter().filter(|r| r["note"] == n).count();
    assert!(
        note("calibration") > 0 && note("soft404") > 0,
        "brute-force annotations in the log"
    );
    assert!(log
        .iter()
        .filter(|r| r["note"] == "soft404")
        .all(|r| r["bytes"].as_u64().unwrap_or(0) > 0));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn fuzz_pause_stop_and_resume() {
    let e = fuzz_env().await;
    let id = e.project("example.test").await;
    // slower, so there is time to pause mid-run
    e.call(
        "settings_set",
        json!({ "patch": { "fuzz": { "threads": 1, "max_hosts": 1 } } }),
    )
    .await;
    *e.pause_at.lock().unwrap() = Some("fuzz".into());
    let r = e.call("scan_start", full(&id)).await;
    let sid = r["scan_id"].as_str().unwrap().to_string();
    e.wait_paused("fuzz").await;
    assert!(
        fuzz_log(&e, &id).await.is_empty(),
        "no requests while paused before the stage"
    );
    *e.pause_at.lock().unwrap() = None;
    e.call("scan_resume", json!({})).await;
    // wait for the brute force to start
    for _ in 0..500 {
        if fuzz_log(&e, &id).await.len() > 20 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    e.call("scan_pause", json!({})).await;
    tokio::time::sleep(Duration::from_millis(900)).await;
    let n1 = fuzz_log(&e, &id).await.len();
    tokio::time::sleep(Duration::from_millis(1200)).await;
    let n2 = fuzz_log(&e, &id).await.len();
    assert!(
        n2 <= n1 + 4,
        "brute force continues while paused: {n1} -> {n2}"
    );
    e.call("scan_stop", json!({})).await;
    let n3 = fuzz_log(&e, &id).await.len();
    tokio::time::sleep(Duration::from_millis(800)).await;
    assert_eq!(fuzz_log(&e, &id).await.len(), n3, "no requests after stop");
    let s = e.snap(&id).await;
    let last = s["scans"]
        .as_array()
        .unwrap()
        .iter()
        .find(|x| x["id"] == sid)
        .unwrap()
        .clone();
    assert_eq!(last["status"], "stopped");
    // resuming re-enters the site discovery stage and runs to the end
    e.call(
        "settings_set",
        json!({ "patch": { "fuzz": { "threads": 4 } } }),
    )
    .await;
    let mut a = full(&id);
    a["resume_from"] = json!(sid);
    e.clear_events();
    e.call("scan_start", a).await;
    e.wait().await;
    assert!(e.events().iter().any(|x| x["type"] == "done"));
    let s = e.snap(&id).await;
    assert!(!fuzz_findings(&s).is_empty());
    assert_eq!(
        doc_status(&s, "secret-plan_2024.pdf").as_deref(),
        Some("analyzed")
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stop_fuzz_only_keeps_scan_going() {
    let e = fuzz_env().await;
    let id = e.project("example.test").await;
    e.call(
        "settings_set",
        json!({ "patch": { "fuzz": { "threads": 1, "max_hosts": 1 } } }),
    )
    .await;
    // "stop brute force" ahead of time (before the stage): the stage records the stop and the scan completes
    *e.pause_at.lock().unwrap() = Some("fuzz".into());
    e.call("scan_start", full(&id)).await;
    e.wait_paused("fuzz").await;
    let r = e.call("scan_skip_source", json!({ "id": "fuzz" })).await;
    assert_eq!(r["ok"], true);
    *e.pause_at.lock().unwrap() = None;
    e.call("scan_resume", json!({})).await;
    e.wait().await;
    assert!(e.events().iter().any(|x| x["type"] == "done"));
    let fe = fuzz_events(&e);
    assert_eq!(fe.last().unwrap()["status"], "stopped", "{fe:#?}");
    assert!(fuzz_log(&e, &id).await.is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stage_buttons_reach_a_running_brute_force() {
    let e = fuzz_env().await;
    let id = e.project("example.test").await;
    e.call(
        "settings_set",
        json!({ "patch": { "fuzz": { "threads": 1, "max_hosts": 1 } } }),
    )
    .await;
    e.call("scan_start", full(&id)).await;
    for _ in 0..500 {
        if fuzz_log(&e, &id).await.len() > 20 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    // the stage's own Pause holds the brute force, not only the next checkpoint
    let r = e
        .call(
            "scan_control",
            json!({ "kind": "stage", "id": "fuzz", "action": "pause" }),
        )
        .await;
    assert_eq!(r["state"], "paused", "{r}");
    tokio::time::sleep(Duration::from_millis(900)).await;
    let n1 = fuzz_log(&e, &id).await.len();
    tokio::time::sleep(Duration::from_millis(1200)).await;
    let n2 = fuzz_log(&e, &id).await.len();
    assert!(
        n2 <= n1 + 4,
        "brute force runs on while the stage is paused: {n1} -> {n2}"
    );
    // Skip on the stage cuts the brute force short and the scan finishes
    let r = e
        .call(
            "scan_control",
            json!({ "kind": "stage", "id": "fuzz", "action": "skip" }),
        )
        .await;
    assert_eq!(r["state"], "skipped", "{r}");
    tokio::time::timeout(Duration::from_secs(20), e.wait())
        .await
        .expect("the scan did not finish after Skip on the running stage");
    assert!(e.events().iter().any(|x| x["type"] == "done"));
    let n3 = fuzz_log(&e, &id).await.len();
    assert!(n3 <= n2 + 8, "brute force went on after Skip: {n2} -> {n3}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn standard_profile_means_zero_fuzz_requests() {
    let e = fuzz_env().await;
    let id = e.project("example.test").await;
    e.call(
        "scan_start",
        json!({ "project": id, "profile": "std", "sources": ["crt", "wayback"] }),
    )
    .await;
    e.wait().await;
    assert!(
        fuzz_log(&e, &id).await.is_empty(),
        "no brute-force requests without the active stage"
    );
    let fe = fuzz_events(&e);
    assert!(fe.iter().all(|x| x["status"] == "off"), "{fe:#?}");
    assert!(fuzz_findings(&e.snap(&id).await).is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wordlists_commands() {
    let e = fuzz_env().await;
    let l = e.call("wordlists_list", json!({})).await;
    let items = l["items"].as_array().unwrap();
    assert!(items.iter().any(|x| x["id"] == "quickhits"
        && x["kind"] == "builtin"
        && x["lines"].as_u64().unwrap() > 100));
    assert!(items
        .iter()
        .any(|x| x["kind"] == "remote" && x["downloaded"] == false));
    assert_eq!(l["modules"].as_array().unwrap().len(), 6);
    // custom wordlist
    let f = e.dir.path().join("my words.txt");
    std::fs::write(&f, "backup\nold-site\n../etc\n\nbackup\n").unwrap();
    let r = e
        .call("wordlists_import", json!({ "path": f.to_string_lossy() }))
        .await;
    assert_eq!(r["id"], "custom:my_words.txt");
    assert_eq!(r["lines"], 2);
    e.call(
        "settings_set",
        json!({ "patch": { "fuzz": { "wordlists": ["custom:my_words.txt"] } } }),
    )
    .await;
    let id = e.project("example.test").await;
    let est = e
        .call("fuzz_estimate", json!({ "project": id, "modules": [] }))
        .await;
    assert!(est["per_module"]["content"].as_u64().unwrap() >= 2, "{est}");
    let l = e.call("wordlists_list", json!({})).await;
    assert!(l["items"]
        .as_array()
        .unwrap()
        .iter()
        .any(|x| x["id"] == "custom:my_words.txt"));
    let r = e
        .call("wordlists_delete", json!({ "id": "custom:my_words.txt" }))
        .await;
    assert_eq!(r["ok"], true);
    let s = e.call("settings_get", json!({})).await;
    assert_eq!(s["fuzz"]["wordlists"], json!([]));
    assert_eq!(
        e.err("wordlists_delete", json!({ "id": "common" }))
            .await
            .code,
        "bad_args"
    );
    // download: the mirror serves the wrong file, so the size/SHA-256 check rejects it
    let remote = items.iter().find(|x| x["kind"] == "remote").unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();
    let err = e.err("wordlists_download", json!({ "id": remote })).await;
    assert!(
        ["too_large", "checksum"].contains(&err.code.as_str()),
        "{err:?}"
    );
}
