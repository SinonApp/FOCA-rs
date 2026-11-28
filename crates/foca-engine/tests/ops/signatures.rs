//! `signatures_update` against a feed server: a missing bundle (HTTP 404) reports `no_update` and
//! keeps the built-in database, a bundle signed with a foreign key fails with a coded error that
//! the UI can translate, and both checks land in `last_check` of `signatures_status`.

use crate::common::*;
use foca_engine::sigbundle::{self, SigBundleV1, SigCounts};
use foca_net::testserver::{TestResponse, TestServer};
use serde_json::json;

fn foreign_bundle() -> String {
    let mut b = SigBundleV1 {
        schema: sigbundle::BUNDLE_SCHEMA.into(),
        version: "2099.1.1".into(),
        released_at: "2099-01-01".into(),
        counts: SigCounts {
            cpe: 0,
            cve: 0,
            secrets: 0,
            standards: 0,
        },
        kev_catalog: None,
        kev_additions: vec![],
        cpe_additions: vec![],
        secret_additions: vec![],
        tables: Default::default(),
        sha256: String::new(),
        signature_ed25519: String::new(),
    };
    sigbundle::sign_bundle_with_seed(&mut b, &[0x42; 32]).unwrap();
    serde_json::to_string(&b).unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn feed_outcomes_are_reported_honestly() {
    let e = env(0).await;
    let body = foreign_bundle();
    let feed = TestServer::start(move |r| match r.path() {
        "/foreign/signatures.bundle" => TestResponse::ok(body.clone()),
        _ => TestResponse::status(404),
    })
    .await;

    let st0 = e.call("signatures_status", json!({})).await;
    assert_eq!(st0["source"], "builtin");
    assert!(st0["last_check"].is_null(), "never checked: {st0}");
    assert_eq!(st0["feed_url"], sigbundle::DEFAULT_FEED_URL);
    assert!(st0["kev"]["used"].as_u64().unwrap() < st0["kev"]["total"].as_u64().unwrap());

    // Nothing published at the feed: no update, never a success claim.
    let url = format!("{}/missing/signatures.bundle", feed.url());
    let st = e.call("signatures_update", json!({ "url": url })).await;
    assert_eq!(st["source"], "builtin");
    assert_eq!(st["version"], st0["version"]);
    assert_eq!(st["last_check"]["outcome"], "no_update", "{st}");
    assert_eq!(st["last_check"]["feed_url"], url);
    assert!(st["last_check"]["at"].as_str().unwrap().len() >= 19);

    // A bundle signed with a key the app does not trust: coded error, database unchanged.
    let url = format!("{}/foreign/signatures.bundle", feed.url());
    let err = e.err("signatures_update", json!({ "url": url })).await;
    assert_eq!(err.code, "bad_signature");
    let ser = serde_json::to_value(&err).unwrap();
    assert_eq!(ser["message_msg"]["code"], "sig.bad_signature", "{ser}");
    let st = e.call("signatures_status", json!({})).await;
    assert_eq!(st["source"], "builtin");
    assert_eq!(st["last_check"]["outcome"], "failed");
    assert_eq!(st["last_check"]["error_code"], "bad_signature");
    assert_eq!(
        st["last_check"]["error_msg"]["code"], "sig.bad_signature",
        "{st}"
    );

    // A URL that is neither HTTPS nor loopback is refused before any request.
    let err = e
        .err(
            "signatures_update",
            json!({ "url": "http://example.test/signatures.bundle" }),
        )
        .await;
    assert_eq!(err.code, "bad_args");
    let ser = serde_json::to_value(&err).unwrap();
    assert_eq!(ser["message_msg"]["code"], "sig.bad_url", "{ser}");
}

/// The scheduled check (`auto: true`): due on first start, then waits for the interval; off,
/// metered with Wi-Fi only and the schedule show up as `skipped` with a reason, and `auto` in
/// the status tells the screen when the next check runs. The official feeds point at the local
/// server here (404: `no_update`).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn automatic_check_follows_the_schedule() {
    let e = env(0).await;
    let st = e.call("signatures_status", json!({})).await;
    assert_eq!(st["auto"]["mode"], "daily");
    assert_eq!(st["auto"]["wifi_only"], true);
    assert!(st["auto"]["checked_at"].is_null(), "{st}");
    assert!(st["auto"]["next_at"].as_i64().unwrap() > 0);

    // Metered network with Wi-Fi only: skipped, nothing recorded.
    e.engine.mobile_network(true);
    let v = e.call("signatures_update", json!({ "auto": true })).await;
    assert_eq!(v["outcome"], "skipped");
    assert_eq!(v["skipped"], "metered");
    assert!(v["last_check"].is_null());
    e.engine.mobile_network(false);

    // Due: checks both official feeds (404) and records the outcome.
    let v = e.call("signatures_update", json!({ "auto": true })).await;
    assert_eq!(v["outcome"], "no_update", "{v}");
    assert_eq!(v["source"], "builtin");
    assert!(v["last_check"]["feed_url"]
        .as_str()
        .unwrap()
        .ends_with("/sig-feed/signatures.bundle"));
    let checked = v["auto"]["checked_at"].as_i64().unwrap();
    assert!(v["auto"]["next_at"].as_i64().unwrap() >= checked + 24 * 3600);

    // Within the interval: skipped until the next day.
    let v = e.call("signatures_update", json!({ "auto": true })).await;
    assert_eq!(v["skipped"], "not_due");

    // Weekly and off come from the settings.
    e.call(
        "settings_set",
        json!({ "patch": { "signatures": { "auto": "off" } } }),
    )
    .await;
    let v = e.call("signatures_update", json!({ "auto": true })).await;
    assert_eq!(v["skipped"], "disabled");
    assert!(v["auto"]["next_at"].is_null());
    // A manual check still works with automatic checks off.
    let v = e.call("signatures_update", json!({})).await;
    assert_eq!(v["outcome"], "no_update");
}
