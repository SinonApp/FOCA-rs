//! "Blocked by scope" in the report reads the same records the request journal marks as
//! refused by the scope: a PTR lookup the scope policy denied is logged as
//! `out_of_scope: <reason>` without a network call.

use crate::common;
use serde_json::json;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn scope_refused_ptr_is_listed_as_blocked_in_journal_and_report() {
    let e = common::env(0).await;
    let id = e.project("example.test").await;
    let ptr_url = "dns://7.100.51.198.in-addr.arpa/PTR";
    {
        let st = foca_store::Store::open(e.dir.path()).unwrap();
        let db = st.open_project(&id).unwrap();
        // As written by foca_net::dns::ptr for an excluded address (no query sent).
        db.log_request(&foca_store::RequestLog {
            module: "ptr".into(),
            method: "PTR".into(),
            url: ptr_url.into(),
            host: "198.51.100.7".into(),
            active: true,
            error: Some("out_of_scope: excluded".into()),
            ..Default::default()
        })
        .unwrap();
        db.log_request(&foca_store::RequestLog {
            module: "httpmap".into(),
            method: "GET".into(),
            url: "https://www.example.test/".into(),
            host: "www.example.test".into(),
            status: Some(200),
            active: true,
            ..Default::default()
        })
        .unwrap();
    }

    let log = e
        .call("request_log_get", json!({ "project": id, "limit": 100 }))
        .await;
    let rows = log.as_array().unwrap();
    let ptr = rows.iter().find(|r| r["url"] == ptr_url).expect("ptr row");
    assert_eq!(ptr["blocked"], true, "{ptr}");
    assert_eq!(ptr["error_code"], "out_of_scope", "{ptr}");
    assert!(ptr["error_detail"].is_string(), "{ptr}");
    let get = rows
        .iter()
        .find(|r| r["module"] == "httpmap")
        .expect("httpmap row");
    assert_eq!(get["blocked"], false, "{get}");

    let rep = e
        .call(
            "report_build",
            json!({ "project": id, "opts": { "fmt": "md", "lang": "EN", "min_sev": "all",
                "confirmed": false, "sections": { "summary": true, "log": true } } }),
        )
        .await;
    let md = std::fs::read_to_string(rep["path"].as_str().unwrap()).unwrap();
    let section = |title: &str| -> String {
        let i = md
            .find(&format!("### {title}\n"))
            .unwrap_or_else(|| panic!("no {title}:\n{md}"));
        let rest = &md[i + title.len() + 5..];
        rest[..rest.find("\n#").unwrap_or(rest.len())].to_string()
    };
    let blocked = section("Blocked by scope");
    assert!(blocked.contains(ptr_url), "{blocked}");
    assert!(!blocked.contains("www.example.test"), "{blocked}");
    let active = section("Requests to target");
    assert!(!active.contains(ptr_url), "{active}");
}
