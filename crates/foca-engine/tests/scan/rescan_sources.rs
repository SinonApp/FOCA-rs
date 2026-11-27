//! A rescan picks up new documents (dedup against the database before the limit), the custom
//! profile honors its modules, and with no network an explicit `no_network` warning appears in the
//! `warning` event and in `done.warnings`.

use crate::common::*;
use serde_json::{json, Value};

async fn scan(e: &Env, args: Value) {
    e.call("scan_start", args).await;
    e.wait().await;
}

/// Downloaded documents without images (images have their own budget, apart from `limit`).
fn doc_names(s: &Value) -> Vec<String> {
    s["docs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|d| d["name"].as_str().unwrap_or("").to_string())
        .filter(|n| !n.ends_with(".jpg"))
        .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rescan_downloads_new_documents() {
    let e = env(0).await;
    let id = e.project("example.test").await;
    let a = json!({ "project": id, "profile": "passive", "sources": ["wayback"], "limit": 3 });
    scan(&e, a.clone()).await;
    let n1 = doc_names(&e.snap(&id).await).len();
    assert_eq!(n1, 3);
    e.clear_events();
    scan(&e, a.clone()).await;
    let n2 = doc_names(&e.snap(&id).await).len();
    if n2 != 6 {
        for x in e.events() {
            if x["type"] != "progress" {
                eprintln!("{x}");
            }
        }
    }
    assert_eq!(n2, 6, "the second scan must download 3 new files, not 0");
    scan(&e, a).await;
    let s = e.snap(&id).await;
    // every document and the image (on its own budget) are in by now
    assert_eq!(counts(&s)["docs"], DOCS.len());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn custom_profile_runs_only_chosen_modules() {
    let e = env(0).await;
    let id = e.project("example.test").await;
    scan(
        &e,
        json!({ "project": id, "profile": "custom", "modules": ["wayback"] }),
    )
    .await;
    let ev = e.events();
    let running: Vec<&str> = ev
        .iter()
        .filter(|x| x["type"] == "source" && x["status"] == "running")
        .map(|x| x["id"].as_str().unwrap())
        .collect();
    assert!(running.contains(&"wayback"), "{running:?}");
    assert!(
        !running
            .iter()
            .any(|r| ["crt", "crawler", "brave"].contains(r)),
        "{running:?}"
    );
    let crt = ev
        .iter()
        .find(|x| x["type"] == "source" && x["id"] == "crt")
        .unwrap();
    assert_eq!(crt["status"], "off");
    // the DNS module is not selected, so there is no DNS summary (SPF/DMARC)
    let s = e.snap(&id).await;
    let titles: Vec<String> = s["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["title"].as_str().unwrap().to_string())
        .collect();
    assert!(!titles.iter().any(|t| t.contains("DMARC")), "{titles:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn no_network_warning() {
    let e = env(0).await;
    let id = e.project("example.test").await;
    e.call(
        "settings_set",
        json!({ "patch": { "net": { "proxy_on": true, "type": "socks5", "addr": "127.0.0.1:9" } } }),
    )
    .await;
    e.passive_scan(&id).await;
    let ev = e.events();
    assert!(
        ev.iter()
            .any(|x| x["type"] == "warning" && x["code"] == "no_network"),
        "{ev:#?}"
    );
    let done = ev.iter().find(|x| x["type"] == "done").unwrap();
    assert_eq!(done["warnings"][0]["code"], "no_network");
}

/// A source disabled in Settings → Sources is not queried by any stage (search/archives,
/// subdomains, InternetDB, reconnaissance): status `off`, no requests.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sources_disabled_in_settings_are_not_queried() {
    let e = env(0).await;
    let id = e.project("example.test").await;
    let off = ["wayback", "crt", "internetdb", "recon", "wellknown"];
    let mut patch = serde_json::Map::new();
    for s in off {
        patch.insert(s.into(), json!({ "enabled": false }));
    }
    e.call("settings_set", json!({ "patch": { "sources": patch } }))
        .await;
    // both without a list and with an explicit source list
    for args in [
        json!({ "project": id, "profile": "passive" }),
        json!({ "project": id, "profile": "passive", "sources": ["wayback", "crt", "cc", "recon"] }),
    ] {
        e.clear_events();
        scan(&e, args).await;
        let ev = e.events();
        for s in off {
            let st: Vec<&str> = ev
                .iter()
                .filter(|x| x["type"] == "source" && x["id"] == s)
                .map(|x| x["status"].as_str().unwrap_or(""))
                .collect();
            assert!(st.iter().all(|x| *x == "off"), "{s}: {st:?}");
        }
        let snap = e.snap(&id).await;
        let scan = snap["scans"].as_array().unwrap().last().unwrap().clone();
        for s in off {
            let src = scan["sources"]
                .as_array()
                .unwrap()
                .iter()
                .find(|x| x["id"] == s);
            if let Some(src) = src {
                assert_eq!(src["status"], "off", "{s}: {src}");
            }
        }
    }
    let bad: Vec<String> = e
        .server
        .requests()
        .iter()
        .filter(|r| {
            r.path() == "/cdx/search/cdx" || (r.path() == "/" && r.query("output").is_some())
        })
        .map(|r| r.target.clone())
        .collect();
    assert!(bad.is_empty(), "disabled sources were queried: {bad:?}");
}

/// Wizard parameters reach the core: `exts: ["pdf"]` downloads only PDFs, `limit` caps the number
/// of documents, and the parameters are saved for resume.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn wizard_doc_types_and_limits_apply() {
    let e = env(0).await;
    let id = e.project("example.test").await;
    scan(
        &e,
        json!({ "project": id, "profile": "passive", "sources": ["wayback"],
            "exts": ["pdf"], "limit": 50, "crawl_depth": 1, "max_size_mb": 5, "ua": "firefox" }),
    )
    .await;
    let s = e.snap(&id).await;
    let names: Vec<String> = s["docs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|d| d["name"].as_str().unwrap_or("").to_string())
        .collect();
    assert!(!names.is_empty(), "nothing downloaded");
    assert!(names.iter().all(|n| n.ends_with(".pdf")), "{names:?}");
    // the wizard UA is used in every request of this scan
    let uas: Vec<String> = e
        .server
        .requests()
        .iter()
        .filter_map(|r| r.headers.get("user-agent").cloned())
        .collect();
    assert!(
        !uas.is_empty() && uas.iter().all(|u| u.contains("Firefox/")),
        "{uas:?}"
    );
    // limit: a second scan without types and limit 2 adds at most 2 new documents
    let before = names.len();
    scan(
        &e,
        json!({ "project": id, "profile": "passive", "sources": ["wayback"], "limit": 2 }),
    )
    .await;
    let after = doc_names(&e.snap(&id).await).len();
    assert!(after > before && after - before <= 2, "{before} → {after}");
}
