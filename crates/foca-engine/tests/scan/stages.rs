//! A scan without internet: a local source server and documents from tests/corpus.

use crate::common::*;
use serde_json::json;

const STAGES: &[&str] = &[
    "search", "download", "meta", "analysis", "network", "ports", "recon", "fuzz", "report",
];

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn passive_scan_full_pipeline_and_event_order() {
    let e = env(0).await;
    let id = e.project("example.test").await;
    let started = e.passive_scan(&id).await;
    assert_eq!(started["profile"], "Пассивный");
    assert_eq!(started["profile_id"], "passive");
    assert_eq!(started["active"], false);
    let s = e.snap(&id).await;
    let c = counts(&s);
    assert_eq!(c["docs"], DOCS.len(), "{c}");
    assert!(c["analyzed"].as_u64().unwrap() >= 6, "{c}");
    assert!(c["findings"].as_u64().unwrap() > 0, "{c}");
    assert!(c["people"].as_u64().unwrap() > 0, "{c}");
    // events: started, source..., stages in order, finding, done
    let ev = e.events();
    let types: Vec<&str> = ev.iter().map(|x| x["type"].as_str().unwrap()).collect();
    assert_eq!(types[0], "started", "{types:?}");
    assert_eq!(*types.last().unwrap(), "done", "{types:?}");
    let stages: Vec<&str> = ev
        .iter()
        .filter(|x| x["type"] == "stage")
        .map(|x| x["stage"].as_str().unwrap())
        .collect();
    assert_eq!(stages, STAGES);
    assert!(types.contains(&"finding") && types.contains(&"source") && types.contains(&"db"));
    let mut last = 0;
    for p in ev.iter().filter(|x| x["type"] == "progress") {
        let v = p["progress"].as_u64().unwrap();
        assert!(v >= last, "progress is not monotonic");
        last = v;
    }
    let fi = types.iter().position(|t| *t == "finding").unwrap();
    let an = ev
        .iter()
        .position(|x| x["type"] == "stage" && x["stage"] == "analysis")
        .unwrap();
    assert!(fi > an, "findings appear after the analysis stage");
    // history record
    let scans = s["scans"].as_array().unwrap();
    assert_eq!(scans.len(), 1);
    assert_eq!(scans[0]["status"], "done");
    assert_eq!(scans[0]["id"], started["scan_id"]);
    assert_eq!(
        scans[0]["findings"].as_u64().unwrap() as usize,
        scans[0]["snapshot"]["findings"].as_object().unwrap().len()
    );
    assert_eq!(scans[0]["new_findings"], scans[0]["added"]["findings"]);
    // passive: not a single request to the target
    let st = e.call("scan_status", json!({})).await;
    assert_eq!(st["running"], false);
    // DNS stage: SPF ~all / DMARC none produce findings, a dangling CNAME becomes an out-of-scope candidate
    let titles: Vec<String> = s["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["title"].as_str().unwrap().to_string())
        .collect();
    assert!(titles.iter().any(|t| t.contains("CNAME")), "{titles:?}");
    let oos = s["oos"].as_array().unwrap();
    assert!(
        oos.iter()
            .any(|o| o["kind"] == "cname" && o["blocked"].is_string()),
        "{oos:?}"
    );
    // risk: a number after a finished scan
    let list = e.call("project_list", json!({})).await;
    assert!(list[0]["risk"].is_number());
    assert_eq!(list[0]["scans"], 1);
    // secrets only as masks
    let js = serde_json::to_string(&s).unwrap();
    assert!(s["secrets"]
        .as_array()
        .unwrap()
        .iter()
        .all(|x| x.get("value").is_none() && x["mask"].is_string()));
    assert!(!s["secrets"].as_array().unwrap().is_empty());
    let sec = &s["secrets"][0];
    let rv = e
        .call("secret_reveal", json!({ "project": id, "id": sec["id"] }))
        .await;
    let val = rv["value"].as_str().unwrap();
    assert!(
        !val.is_empty() && !js.contains(val),
        "plain value in the snapshot"
    );
    // link to the evidence fragment
    let fr = s["findings"]
        .as_array()
        .unwrap()
        .iter()
        .find_map(|f| {
            f["secret_refs"]
                .as_array()
                .filter(|r| !r.is_empty())
                .map(|r| r[0].clone())
        })
        .expect("no secret_refs");
    let rv = e
        .call("secret_reveal", json!({ "project": id, "id": fr }))
        .await;
    assert!(!rv["value"].as_str().unwrap().is_empty());
    // finding ids are short numbers
    assert!(s["findings"]
        .as_array()
        .unwrap()
        .iter()
        .all(|f| f["id"].as_u64().unwrap() < 10_000));
    // address patterns use the UI placeholders
    for p in s["patterns"].as_array().unwrap() {
        assert!(!p["p"].as_str().unwrap().contains("{f}"), "{p}");
    }
    // dates are local time (UTC+2) without an offset
    assert!(scans[0]["started_at"]
        .as_str()
        .unwrap()
        .starts_with("2026-11-20T12:00"));
}
