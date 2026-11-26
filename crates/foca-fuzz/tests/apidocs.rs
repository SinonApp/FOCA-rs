//! Exposed API documentation found by the `exposed` module is parsed into a masked summary
//! (endpoint count, API version, auth schemes; Actuator property names without values).

mod common;

use common::*;
use foca_fuzz::{FuzzTask, Fuzzer, HitKind, Module, Risk, StopReason};
use foca_net::testserver::{TestResponse, TestServer};
use url::Url;

#[tokio::test]
async fn apidocs_hits_are_summarized_without_values() {
    let srv = TestServer::start(|r| match r.path() {
        "/v3/api-docs" => TestResponse::ok(
            r#"{"openapi":"3.0.1","info":{"title":"Portal","version":"2.4"},"components":{"securitySchemes":{"jwt":{"type":"http","scheme":"bearer"}}},"security":[{"jwt":[]}],"paths":{"/users":{"get":{}},"/login":{"post":{"security":[]}}}}"#,
        )
        .header("Content-Type", "application/json"),
        "/actuator/env" => TestResponse::ok(
            r#"{"activeProfiles":["prod"],"propertySources":[{"name":"applicationConfig","properties":{"spring.datasource.password":{"value":"VerySecretDbPass2024"},"spring.datasource.url":{"value":"jdbc:postgresql://db.internal:5432/app"}}}]}"#,
        )
        .header("Content-Type", "application/json"),
        p => soft404(p),
    })
    .await;
    let (net, _sink) = client("127.0.0.1", "", true);
    let task = FuzzTask::new(
        Url::parse(&format!("{}/", srv.url())).unwrap(),
        vec![Module::Exposed],
    );
    let rep = Fuzzer::new(net, fast_cfg()).run(&task).await;
    assert_eq!(rep.stop, StopReason::Completed, "{:?}", rep.stats);
    assert!(
        srv.requests()
            .iter()
            .all(|q| q.method == "GET" || q.method == "HEAD"),
        "fuzzing never changes data"
    );
    let find = |p: &str| {
        rep.hits
            .iter()
            .find(|h| Url::parse(&h.url).unwrap().path() == p)
            .unwrap_or_else(|| panic!("{p} not found: {:?}", rep.hits))
    };
    let spec = find("/v3/api-docs");
    assert_eq!(spec.kind, HitKind::Exposed);
    let a = spec.artifact.as_ref().expect("openapi summary");
    assert_eq!(a.kind, "apidoc_openapi");
    let lines = a.lines.join("\n");
    assert!(lines.contains("Версия API: 2.4"), "{lines}");
    assert!(
        lines.contains("Путей: 2, операций: 2, без авторизации: 1"),
        "{lines}"
    );
    assert!(lines.contains("jwt (http bearer)"), "{lines}");

    let env = find("/actuator/env");
    let a = env.artifact.as_ref().expect("actuator summary");
    assert_eq!(a.kind, "apidoc_actuator");
    assert_eq!(env.risk, Risk::High);
    let ser = serde_json::to_string(env).unwrap();
    assert!(!ser.contains("VerySecretDbPass2024"), "{ser}");
    assert!(
        !ser.contains("db.internal"),
        "env values must not be kept: {ser}"
    );
    assert!(ser.contains("spring.datasource.password"));
}
