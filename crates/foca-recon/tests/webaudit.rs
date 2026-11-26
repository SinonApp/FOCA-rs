//! Web audit against a local test server: access classes per profile (passive sends nothing,
//! standard sends GET only, active never sends PUT/DELETE), source maps, API docs, CORS and
//! HTTP methods.

use std::sync::Arc;

use foca_core::Scope;
use foca_net::testserver::{TestResponse, TestServer};
use foca_net::{MemorySink, NetClient, NetConfig};
use foca_recon::apidocs::ApiDocKind;
use foca_recon::methods;
use foca_recon::tech::PageInput;
use foca_recon::webaudit::{run, AuditLevel, AuditScript, WebAuditInput, WebAuditOptions};

fn client(active: bool) -> (NetClient, Arc<MemorySink>) {
    let sink = Arc::new(MemorySink::default());
    let (mut scope, _) = Scope::from_lines("127.0.0.1", "");
    scope.active_phase = active;
    let cfg = NetConfig {
        global_rps: None,
        retries: 0,
        ..NetConfig::default()
    };
    let c = NetClient::new(cfg, scope, sink.clone()).unwrap();
    (c, sink)
}

const MAP: &str = r#"{"version":3,"sources":["webpack:///./src/app.ts","webpack:///./node_modules/.pnpm/axios@0.21.1/node_modules/axios/index.js"],"sourcesContent":["fetch('https://api.internal.contoso.ua/v1'); const k='AKIAZ7Q3RT5XW2LMNPV6';",""],"mappings":"AAAA"}"#;

async fn site() -> TestServer {
    TestServer::start(|r| match (r.method.as_str(), r.path()) {
        ("GET", "/") => {
            let mut t = TestResponse::ok("<html>hi</html>").header("Content-Type", "text/html");
            if let Some(o) = r.headers.get("origin") {
                t = t
                    .header("Access-Control-Allow-Origin", o)
                    .header("Access-Control-Allow-Credentials", "true");
            }
            t
        }
        ("GET", "/static/app.js.map") => TestResponse::ok(MAP).header("Content-Type", "application/json"),
        ("GET", "/static/other.js.map") => TestResponse::ok("<html>soft 404</html>"),
        ("GET", "/v3/api-docs") => TestResponse::ok(
            r#"{"openapi":"3.0.1","info":{"title":"Portal","version":"2.4"},"paths":{"/users":{"get":{},"post":{}},"/orders":{"get":{}}}}"#,
        ),
        ("GET", "/actuator") => TestResponse::ok(
            r#"{"_links":{"self":{"href":"/actuator"},"health":{"href":"/actuator/health"},"env":{"href":"/actuator/env"},"heapdump":{"href":"/actuator/heapdump"}}}"#,
        ),
        ("GET", "/actuator/env") => TestResponse::ok(
            r#"{"activeProfiles":[],"propertySources":[{"name":"a","properties":{"db.password":{"value":"TopSecretValue123"},"server.port":{"value":"8080"}}}]}"#,
        ),
        ("GET", "/actuator/health") => TestResponse::ok(r#"{"status":"UP"}"#),
        ("GET", _) => TestResponse::ok("<html>soft 404 page</html>").header("Content-Type", "text/html"),
        ("OPTIONS", _) => TestResponse::ok("")
            .header("Allow", "GET, HEAD, POST, PUT, DELETE, OPTIONS, TRACE, PROPFIND")
            .header("DAV", "1,2"),
        ("TRACE", _) => {
            let mut echo = format!("TRACE {} HTTP/1.1\r\n", r.target);
            for (k, v) in &r.headers {
                echo.push_str(&format!("{k}: {v}\r\n"));
            }
            TestResponse::ok(echo).header("Content-Type", "message/http")
        }
        ("PROPFIND", _) => {
            let mut t = TestResponse::ok(r#"<?xml version="1.0"?><D:multistatus xmlns:D="DAV:"><D:response/></D:multistatus>"#);
            t.status = 207;
            t
        }
        ("POST", "/graphql") => TestResponse::ok(
            r#"{"data":{"__schema":{"queryType":{"name":"Query"},"mutationType":null,"types":[{"name":"Query","kind":"OBJECT","fields":[{"name":"me"}]}]}}}"#,
        ),
        _ => TestResponse::status(405),
    })
    .await
}

fn input(base: &str) -> WebAuditInput {
    WebAuditInput {
        pages: vec![PageInput {
            url: format!("{base}/"),
            headers: vec![
                ("Content-Type".into(), "text/html".into()),
                ("Server".into(), "Apache/2.4.41".into()),
                (
                    "Content-Security-Policy".into(),
                    "script-src 'self' 'unsafe-inline' https://cdn.thirdparty.net https://api.dev.contoso.ua".into(),
                ),
            ],
            html: "<html></html>".into(),
        }],
        scripts: vec![
            AuditScript {
                url: format!("{base}/static/app.js"),
                body: "var a=1;\n//# sourceMappingURL=app.js.map".into(),
                headers: vec![],
            },
            AuditScript {
                url: format!("{base}/static/other.js"),
                body: "var b=2;".into(),
                headers: vec![],
            },
            AuditScript {
                url: "https://cdn.thirdparty.net/lib.js".into(),
                body: "//# sourceMappingURL=lib.js.map".into(),
                headers: vec![],
            },
        ],
        graphql_endpoints: vec![],
        from_archive: false,
    }
}

fn opts(level: AuditLevel) -> WebAuditOptions {
    let (mut scope, _) = Scope::from_lines("127.0.0.1\ncontoso.ua", "");
    scope.active_phase = level == AuditLevel::Active;
    WebAuditOptions {
        level,
        scope: Some(scope),
        ..Default::default()
    }
}

#[tokio::test]
async fn passive_profile_sends_nothing() {
    let srv = site().await;
    let (c, sink) = client(false);
    let r = run(&c, &input(&srv.url()), &opts(AuditLevel::Passive)).await;
    assert_eq!(srv.requests().len(), 0, "passive must not touch the target");
    assert_eq!(sink.len(), 0);
    assert_eq!(r.requests, 0);
    // Passive analysis still yields header/CSP findings and candidates.
    assert!(r
        .findings
        .iter()
        .any(|f| f.rule == "recon.web.csp_unsafe_inline"));
    assert!(r
        .findings
        .iter()
        .any(|f| f.rule == "recon.web.version_disclosure"));
    assert_eq!(r.hosts, ["api.dev.contoso.ua"]);
    assert_eq!(r.candidates, ["cdn.thirdparty.net"]);
    assert_eq!(r.map_refs.len(), 2);
    assert!(r.source_maps.is_empty());
}

#[tokio::test]
async fn archive_copy_raises_no_header_findings() {
    let srv = site().await;
    let (c, _sink) = client(false);
    let mut inp = input(&srv.url());
    inp.from_archive = true;
    let r = run(&c, &inp, &opts(AuditLevel::Passive)).await;
    assert!(r.from_archive);
    // Header analysis of an archived response must not be attributed to the live site.
    assert!(
        !r.findings
            .iter()
            .any(|f| f.tags.iter().any(|t| t == "headers")),
        "{:?}",
        r.findings.iter().map(|f| &f.rule).collect::<Vec<_>>()
    );
    assert!(!r
        .findings
        .iter()
        .any(|f| f.rule == "recon.web.version_disclosure"));
    // Content-derived results stay, marked as coming from the archive.
    assert_eq!(r.map_refs.len(), 2);
    assert!(!r.findings.is_empty());
    assert!(r
        .findings
        .iter()
        .all(|f| f.tags.iter().any(|t| t == "archive")));
}

#[tokio::test]
async fn standard_profile_get_only() {
    let srv = site().await;
    let (c, sink) = client(false);
    let r = run(&c, &input(&srv.url()), &opts(AuditLevel::Standard)).await;
    let reqs = srv.requests();
    assert!(!reqs.is_empty());
    assert!(reqs.iter().all(|q| q.method == "GET"), "standard: GET only");
    assert!(reqs.iter().all(|q| !q.headers.contains_key("origin")));
    assert!(sink.records().iter().all(|x| x.access != "active"));
    // Source map: referenced map parsed, guessed soft-404 rejected, third-party map not requested.
    assert_eq!(r.source_maps.len(), 1, "{:?}", r.errors);
    let m = &r.source_maps[0];
    assert_eq!(m.packages, ["axios@0.21.1"]);
    assert_eq!(m.secrets.len(), 1);
    assert!(sink
        .records()
        .iter()
        .all(|x| !x.host.contains("thirdparty")));
    assert!(r.hosts.contains(&"api.internal.contoso.ua".to_string()));
    // API docs.
    let kinds: Vec<ApiDocKind> = r.api_docs.iter().map(|d| d.kind).collect();
    assert!(kinds.contains(&ApiDocKind::OpenApi), "{kinds:?}");
    let spec = r
        .api_docs
        .iter()
        .find(|d| d.kind == ApiDocKind::OpenApi)
        .unwrap();
    assert_eq!(
        (spec.endpoints, spec.operations, spec.unauthenticated),
        (2, 3, 3)
    );
    let env = r
        .api_docs
        .iter()
        .find(|d| d.spec_version.as_deref() == Some("actuator env"))
        .unwrap();
    assert_eq!(env.secret_names, ["db.password"]);
    assert_eq!(
        srv.hits("/actuator/heapdump"),
        0,
        "heapdump is never fetched"
    );
    assert_eq!(
        srv.hits("/health"),
        0,
        "legacy paths only without /actuator"
    );
    let ser = serde_json::to_string(&r).unwrap();
    assert!(!ser.contains("TopSecretValue123"), "actuator value leaked");
    assert!(!ser.contains("AKIAZ7Q3RT5XW2LMNPV6"), "map secret leaked");
    assert!(r
        .findings
        .iter()
        .any(|f| f.rule == "recon.web.sourcemap_secret"));
    assert!(r
        .findings
        .iter()
        .any(|f| f.rule == "recon.web.apidoc_actuator"));
    assert!(r.cors.is_empty() && r.methods.is_empty());
}

#[tokio::test]
async fn header_findings_carry_observed_headers_as_evidence() {
    let srv = site().await;
    let (c, _sink) = client(false);
    let r = run(&c, &input(&srv.url()), &opts(AuditLevel::Standard)).await;
    let fs = foca_recon::webaudit::build_findings(&r);
    let hdr: Vec<_> = fs
        .iter()
        .filter(|f| f.tags.iter().any(|t| t == "headers"))
        .collect();
    assert!(!hdr.is_empty(), "the test site misses security headers");
    for f in hdr {
        assert_ne!(f.evidence, f.description, "{}", f.rule);
        assert!(f.evidence.starts_with("URL: "), "{}", f.evidence);
        assert!(
            f.evidence.contains("Strict-Transport-Security: "),
            "{}",
            f.evidence
        );
        assert!(
            f.evidence.contains("X-Content-Type-Options: "),
            "{}",
            f.evidence
        );
    }
}

#[tokio::test]
async fn active_profile_never_sends_put_or_delete() {
    let srv = site().await;
    let (c, sink) = client(true);
    let r = run(&c, &input(&srv.url()), &opts(AuditLevel::Active)).await;
    let reqs = srv.requests();
    for q in &reqs {
        assert!(
            matches!(
                q.method.as_str(),
                "GET" | "OPTIONS" | "TRACE" | "PROPFIND" | "POST"
            ),
            "unexpected method {}",
            q.method
        );
    }
    let posts: Vec<_> = reqs.iter().filter(|q| q.method == "POST").collect();
    assert!(
        posts.iter().all(|q| q.path().contains("graphql")),
        "POST only for introspection"
    );
    let propfind = reqs.iter().find(|q| q.method == "PROPFIND").unwrap();
    assert_eq!(propfind.headers.get("depth").map(String::as_str), Some("0"));
    assert!(sink
        .records()
        .iter()
        .filter(|x| x.method != "GET")
        .all(|x| x.access == "active"));
    let m = &r.methods[0];
    assert_eq!(m.unsafe_advertised, ["PUT", "DELETE"]);
    assert!(m.trace_reflected && m.webdav);
    assert!(r.cors[0].reflected && r.cors[0].allow_credentials);
    assert!(r.api_docs.iter().any(|d| d.kind == ApiDocKind::Graphql));
    let rules: Vec<&str> = r.findings.iter().map(|f| f.rule.as_str()).collect();
    for want in [
        "recon.web.cors_reflected",
        "recon.web.methods_unsafe_allowed",
        "recon.web.trace_enabled",
        "recon.web.webdav",
        "recon.web.apidoc_graphql",
    ] {
        assert!(rules.contains(&want), "{want} not in {rules:?}");
    }
}

#[tokio::test]
async fn active_checks_denied_outside_active_stage() {
    let srv = site().await;
    // Options ask for active checks, but the network scope is not in its active stage.
    let (c, sink) = client(false);
    let r = run(&c, &input(&srv.url()), &opts(AuditLevel::Active)).await;
    assert!(srv
        .requests()
        .iter()
        .all(|q| q.method == "GET" && !q.headers.contains_key("origin")));
    assert!(sink
        .records()
        .iter()
        .filter(|x| x.access == "active")
        .all(|x| x.blocked));
    assert!(
        r.methods.is_empty(),
        "methods skipped after the denied CORS probe"
    );
}

#[tokio::test]
async fn send_probe_refuses_state_changing_methods() {
    let srv = site().await;
    let (c, _) = client(true);
    for m in ["PUT", "DELETE", "PATCH", "MKCOL"] {
        let e = methods::send_probe(&c, m, &format!("{}/", srv.url()), "x", &[], None)
            .await
            .unwrap_err();
        assert!(e.to_string().contains("запрещён"), "{e}");
    }
    assert_eq!(srv.requests().len(), 0);
}

/// Live run against an intentionally vulnerable public test site (the only allowed targets for
/// active checks): `FOCA_LIVE_HOST=testfire.net cargo test -p foca-recon --test webaudit --
/// --ignored --nocapture` (default `testphp.vulnweb.com`).
#[tokio::test]
#[ignore = "live network: testphp.vulnweb.com / testfire.net only"]
async fn live_testphp_vulnweb() {
    let host = std::env::var("FOCA_LIVE_HOST").unwrap_or_else(|_| "testphp.vulnweb.com".into());
    assert!(
        matches!(host.as_str(), "testphp.vulnweb.com" | "testfire.net"),
        "active checks are allowed only on the public test sites"
    );
    let host = host.as_str();
    let sink = Arc::new(MemorySink::default());
    let (mut scope, _) = Scope::from_lines(host, "");
    scope.active_phase = true;
    let c = NetClient::new(NetConfig::default(), scope.clone(), sink.clone()).unwrap();
    let mut recon = foca_recon::ReconInput::default();
    let opts = foca_recon::collect::CollectOptions::default();
    let url = foca_recon::collect::fetch_site(&c, host, &opts, &mut recon)
        .await
        .expect("home page");
    let mut input = WebAuditInput::from_recon(&recon);
    input.graphql_endpoints.clear();
    let r = run(
        &c,
        &input,
        &WebAuditOptions {
            level: AuditLevel::Active,
            scope: Some(scope),
            ..Default::default()
        },
    )
    .await;
    println!("home: {url}, scripts: {}", input.scripts.len());
    for f in &r.findings {
        println!("[{:?}] {} - {} | {}", f.sev, f.rule, f.title, f.evidence);
    }
    println!("methods: {:?}", r.methods);
    println!("cors: {:?}", r.cors);
    println!("api docs: {}", r.api_docs.len());
    println!("errors: {:?}", r.errors);
    let methods: std::collections::BTreeSet<String> =
        sink.records().iter().map(|x| x.method.clone()).collect();
    println!("requests: {} {:?}", sink.len(), methods);
    assert!(!methods.contains("PUT") && !methods.contains("DELETE"));
}
