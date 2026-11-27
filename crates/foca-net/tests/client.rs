//! Offline `NetClient` tests: scope (including redirects and resolved IPs), logging, size limit,
//! cancellation, retries, rate limiting and concurrency.

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use foca_core::Scope;
use foca_net::testserver::{TestResponse, TestServer};
use foca_net::{Access, MemorySink, NetClient, NetConfig, NetError, NetRequest};

fn cfg() -> NetConfig {
    NetConfig {
        retries: 2,
        backoff_base: Duration::from_millis(20),
        global_rps: None,
        ..Default::default()
    }
}

fn client(targets: &str, excludes: &str, cfg: NetConfig) -> (NetClient, Arc<MemorySink>) {
    let (scope, errs) = Scope::from_lines(targets, excludes);
    assert!(errs.is_empty(), "{errs:?}");
    let sink = Arc::new(MemorySink::new());
    (NetClient::new(cfg, scope, sink.clone()).unwrap(), sink)
}

#[tokio::test]
async fn passive_request_is_logged_with_bytes() {
    let srv = TestServer::start(|_| TestResponse::ok("hello")).await;
    let (net, sink) = client("", "", cfg());
    let t = net
        .get_text(
            &format!("{}/x?key=SECRET&q=1", srv.url()),
            "wayback",
            Access::Passive,
        )
        .await
        .unwrap();
    assert_eq!(t, "hello");
    let log = sink.records();
    assert_eq!(log.len(), 1);
    let r = &log[0];
    assert_eq!(
        (r.module.as_str(), r.method.as_str(), r.status, r.bytes),
        ("wayback", "GET", Some(200), 5)
    );
    assert!(!r.active && !r.blocked);
    assert_eq!(r.host, "127.0.0.1");
    assert!(!r.url.contains("SECRET"), "{}", r.url);
}

#[tokio::test]
async fn target_out_of_scope_blocked_before_network() {
    let srv = TestServer::start(|_| TestResponse::ok("x")).await;
    let (net, sink) = client("contoso.ua", "", cfg());
    let e = net
        .get_text(
            &format!("{}/doc.pdf", srv.url()),
            "crawler",
            Access::TouchesTarget,
        )
        .await
        .unwrap_err();
    assert!(matches!(e, NetError::OutOfScope { .. }), "{e:?}");
    assert_eq!(srv.requests().len(), 0, "no network call expected");
    let log = sink.records();
    assert_eq!(log.len(), 1);
    assert!(log[0].blocked && log[0].active);
    assert!(log[0].error.as_deref().unwrap().starts_with("out_of_scope"));
}

#[tokio::test]
async fn redirect_out_of_scope_is_blocked_and_logged() {
    let srv = TestServer::start(|r| match r.path() {
        "/away" => TestResponse::redirect(302, "http://evil.example/steal"),
        "/hop" => TestResponse::redirect(301, "/final"),
        _ => TestResponse::ok("final"),
    })
    .await;
    let (net, sink) = client("127.0.0.1", "", cfg());
    // a redirect within the scope is followed
    let t = net
        .get_text(
            &format!("{}/hop", srv.url()),
            "crawler",
            Access::TouchesTarget,
        )
        .await
        .unwrap();
    assert_eq!(t, "final");
    // a redirect out of the scope is denied at that hop
    let e = net
        .get_text(
            &format!("{}/away", srv.url()),
            "crawler",
            Access::TouchesTarget,
        )
        .await
        .unwrap_err();
    assert!(
        matches!(e, NetError::OutOfScope { ref host, .. } if host == "evil.example"),
        "{e:?}"
    );
    let log = sink.records();
    let blocked: Vec<_> = log.iter().filter(|r| r.blocked).collect();
    assert_eq!(blocked.len(), 1);
    assert_eq!(blocked[0].host, "evil.example");
    assert!(log.iter().any(
        |r| r.status == Some(302) && r.error.as_deref().unwrap_or("").contains("evil.example")
    ));
    // a passive request on the same redirect is not limited by the scope (but the hop is logged)
    let (pnet, psink) = client(
        "",
        "",
        NetConfig {
            retries: 0,
            ..cfg()
        },
    );
    let _ = pnet
        .get_text(&format!("{}/away", srv.url()), "wayback", Access::Passive)
        .await;
    assert!(psink.records().iter().all(|r| !r.blocked));
}

#[tokio::test]
async fn resolved_ip_in_excludes_is_blocked() {
    let srv = TestServer::start(|_| TestResponse::ok("x")).await;
    let mut c = cfg();
    let mut ov = HashMap::new();
    ov.insert(
        "portal.contoso.ua".to_string(),
        vec!["127.0.0.1".parse().unwrap()],
    );
    c.host_overrides = ov;
    let (net, sink) = client("contoso.ua", "127.0.0.0/8", c);
    let url = format!("http://portal.contoso.ua:{}/a.pdf", srv.port());
    let e = net
        .get_text(&url, "download", Access::TouchesTarget)
        .await
        .unwrap_err();
    assert!(
        matches!(e, NetError::OutOfScope { ref reason, .. } if reason.contains("IP")),
        "{e:?}"
    );
    assert_eq!(srv.requests().len(), 0);
    assert!(sink.records()[0].blocked);
    // without the exclusion the request reaches the server through the static name mapping
    let mut c = cfg();
    c.host_overrides.insert(
        "portal.contoso.ua".into(),
        vec!["127.0.0.1".parse().unwrap()],
    );
    let (net, _) = client("contoso.ua", "", c);
    assert_eq!(
        net.get_text(&url, "download", Access::TouchesTarget)
            .await
            .unwrap(),
        "x"
    );
}

#[tokio::test]
async fn active_requires_project_toggle() {
    let srv = TestServer::start(|_| TestResponse::ok("x")).await;
    let (net, sink) = client("127.0.0.1", "", cfg());
    let req = NetRequest::get(&srv.url(), "httpmap", Access::active("httpmap")).unwrap();
    let e = net.send(req).await.unwrap_err();
    assert!(matches!(e, NetError::ActiveDenied(_)), "{e:?}");
    assert!(sink.records()[0].blocked);
    assert_eq!(srv.requests().len(), 0);
}

#[tokio::test]
async fn size_limit_aborts_stream_ignoring_content_length() {
    // HEAD lies (10 bytes); GET returns 8 MiB without Content-Length
    let srv = TestServer::start(|r| {
        if r.method == "HEAD" {
            TestResponse::ok("").header("Content-Length", "10")
        } else {
            TestResponse {
                status: 200,
                stream_len: Some(8 * 1024 * 1024),
                ..Default::default()
            }
        }
    })
    .await;
    let (net, sink) = client("", "", cfg());
    let head = net
        .send(NetRequest::head(&srv.url(), "download", Access::Passive).unwrap())
        .await
        .unwrap();
    assert_eq!(head.content_length(), Some(10));
    drop(head);
    let r = net
        .send(NetRequest::get(&srv.url(), "download", Access::Passive).unwrap())
        .await
        .unwrap();
    let e = r.bytes_limited(1024 * 1024).await.unwrap_err();
    assert_eq!(e, NetError::TooLarge { limit: 1024 * 1024 });
    let log = sink.records();
    let last = log.last().unwrap();
    assert!(last.error.as_deref().unwrap().starts_with("too_large"));
    assert!(last.bytes <= 1024 * 1024 + 64 * 1024, "{}", last.bytes);
}

#[tokio::test]
async fn cancel_interrupts_request() {
    let srv = TestServer::start(|_| TestResponse::ok("late").delay(Duration::from_secs(5))).await;
    let (net, sink) = client("", "", cfg());
    let n2 = net.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(200)).await;
        n2.cancel();
    });
    let t = Instant::now();
    let e = net
        .get_text(&srv.url(), "cc", Access::Passive)
        .await
        .unwrap_err();
    assert_eq!(e, NetError::Cancelled);
    assert!(t.elapsed() < Duration::from_secs(2));
    assert_eq!(sink.records()[0].error.as_deref(), Some("cancelled"));
    // after cancellation no new requests go out
    assert_eq!(
        net.get_text(&srv.url(), "cc", Access::Passive)
            .await
            .unwrap_err(),
        NetError::Cancelled
    );
}

#[tokio::test]
async fn retries_on_503_then_success() {
    let n = Arc::new(AtomicUsize::new(0));
    let n2 = n.clone();
    let srv = TestServer::start(move |_| {
        if n2.fetch_add(1, Ordering::SeqCst) < 2 {
            TestResponse::status(503).header("Retry-After", "0")
        } else {
            TestResponse::ok("ok")
        }
    })
    .await;
    let (net, sink) = client("", "", cfg());
    assert_eq!(
        net.get_text(&srv.url(), "brave", Access::Passive)
            .await
            .unwrap(),
        "ok"
    );
    assert_eq!(n.load(Ordering::SeqCst), 3);
    let st: Vec<_> = sink.records().iter().map(|r| r.status).collect();
    assert_eq!(st, vec![Some(503), Some(503), Some(200)]);
    // retries exhausted: the status is returned to the caller
    let srv = TestServer::start(|_| TestResponse::status(500)).await;
    let e = net
        .get_text(&srv.url(), "brave", Access::Passive)
        .await
        .unwrap_err();
    assert_eq!(e, NetError::Status(500));
    assert_eq!(srv.requests().len(), 3);
}

#[tokio::test]
async fn per_source_rate_limit() {
    let srv = TestServer::start(|_| TestResponse::ok("x")).await;
    let mut c = cfg();
    c.source_rps.insert("slow".into(), 5.0);
    let (net, _) = client("", "", c);
    let t = Instant::now();
    for _ in 0..4 {
        net.get_text(&srv.url(), "slow", Access::Passive)
            .await
            .unwrap();
    }
    assert!(
        t.elapsed() >= Duration::from_millis(580),
        "{:?}",
        t.elapsed()
    );
    // another module is not limited by this bucket
    let t = Instant::now();
    for _ in 0..4 {
        net.get_text(&srv.url(), "fast", Access::Passive)
            .await
            .unwrap();
    }
    assert!(
        t.elapsed() < Duration::from_millis(500),
        "{:?}",
        t.elapsed()
    );
}

/// A paused scan stops new requests at the client: requests already waiting for the limiter do
/// not start while paused, the one in flight finishes, and everything resumes after the pause.
#[tokio::test]
async fn pause_holds_queued_requests_and_keeps_the_one_in_flight() {
    let srv = TestServer::start(|r| match r.path() {
        "/slow" => TestResponse::ok("slow").delay(Duration::from_millis(400)),
        _ => TestResponse::ok("x"),
    })
    .await;
    let mut c = cfg();
    c.global_rps = Some(5.0);
    let (net, _) = client("", "", c);
    let (tx, rx) = tokio::sync::watch::channel(None::<String>);
    let net = net.with_pause(rx);
    // the bucket starts with 5 tokens: drain them so the queued requests wait for the limiter
    for _ in 0..5 {
        net.rate_limit("drain").await.unwrap();
    }
    let slow = {
        let (net, u) = (net.clone(), format!("{}/slow", srv.url()));
        tokio::spawn(async move { net.get_text(&u, "m", Access::Passive).await })
    };
    tokio::time::sleep(Duration::from_millis(250)).await;
    assert_eq!(srv.requests().len(), 1, "the in-flight request started");
    let queued: Vec<_> = (0..3)
        .map(|i| {
            let (net, u) = (net.clone(), format!("{}/q{i}", srv.url()));
            tokio::spawn(async move { net.get_text(&u, "m", Access::Passive).await })
        })
        .collect();
    tx.send_replace(Some("user".into()));
    // the in-flight request still completes during the pause
    assert_eq!(slow.await.unwrap().unwrap(), "slow");
    tokio::time::sleep(Duration::from_millis(900)).await;
    assert_eq!(
        srv.requests().len(),
        1,
        "no request may start while paused: {:?}",
        srv.requests()
            .iter()
            .map(|r| r.path().to_string())
            .collect::<Vec<_>>()
    );
    // a clone with its own cancellation keeps following the pause
    let other = net.with_cancel(foca_net::CancellationToken::new());
    let held = {
        let u = format!("{}/other", srv.url());
        tokio::spawn(async move { other.get_text(&u, "m", Access::Passive).await })
    };
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(srv.requests().len(), 1);
    tx.send_replace(None);
    for q in queued {
        q.await.unwrap().unwrap();
    }
    held.await.unwrap().unwrap();
    assert_eq!(srv.requests().len(), 5);
}

/// Stopping a paused scan cancels the requests waiting for the pause to end.
#[tokio::test]
async fn cancel_ends_a_request_held_by_the_pause() {
    let srv = TestServer::start(|_| TestResponse::ok("x")).await;
    let (net, _) = client("", "", cfg());
    let (_tx, rx) = tokio::sync::watch::channel(Some("user".to_string()));
    let net = net.with_pause(rx);
    let n2 = net.clone();
    let u = srv.url();
    let h = tokio::spawn(async move { n2.get_text(&u, "m", Access::Passive).await });
    tokio::time::sleep(Duration::from_millis(100)).await;
    net.cancel();
    assert_eq!(h.await.unwrap(), Err(NetError::Cancelled));
    assert!(srv.requests().is_empty());
}

#[tokio::test]
async fn global_rate_limit_and_concurrency() {
    let srv = TestServer::start(|_| TestResponse::ok("x").delay(Duration::from_millis(250))).await;
    let mut c = cfg();
    c.max_concurrency = 1;
    let (net, _) = client("", "", c);
    let t = Instant::now();
    let u = srv.url();
    let (a, b) = tokio::join!(
        net.get_text(&u, "a", Access::Passive),
        net.get_text(&u, "b", Access::Passive)
    );
    a.unwrap();
    b.unwrap();
    assert!(
        t.elapsed() >= Duration::from_millis(490),
        "semaphore: {:?}",
        t.elapsed()
    );

    let srv = TestServer::start(|_| TestResponse::ok("x")).await;
    let mut c = cfg();
    c.global_rps = Some(4.0);
    let (net, _) = client("", "", c);
    let t = Instant::now();
    for i in 0..6 {
        net.get_text(&srv.url(), &format!("m{i}"), Access::Passive)
            .await
            .unwrap();
    }
    // bucket capacity 4: four at once, then one every 250 ms
    assert!(
        t.elapsed() >= Duration::from_millis(450),
        "{:?}",
        t.elapsed()
    );
}

#[tokio::test]
async fn tcp_alive_respects_scope() {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move { while l.accept().await.is_ok() {} });
    let (net, sink) = client("127.0.0.1", "", cfg());
    let r = foca_net::tcp::tcp_alive(&net, "127.0.0.1", &[port, 1], Duration::from_secs(2))
        .await
        .unwrap();
    assert!(r.alive);
    assert!(r.ports[0].open && !r.ports[1].open);
    assert!(sink.records().iter().all(|x| x.method == "TCP" && x.active));
    let e = foca_net::tcp::tcp_alive(&net, "10.9.9.9", &[80], Duration::from_secs(1))
        .await
        .unwrap_err();
    assert!(matches!(e, NetError::OutOfScope { .. }));
    assert!(sink.records().last().unwrap().blocked);
}

// ---- passive access never reaches exclusions, nor target hosts with the passive profile ----

fn passive_client(
    core: (&str, &str),
    full: (&str, &str),
    block: bool,
) -> (NetClient, Arc<MemorySink>) {
    let mut c = NetConfig {
        retries: 0,
        ..cfg()
    };
    for h in [
        "web.archive.test",
        "example.test",
        "www.example.test",
        "secret.example.test",
        "third.test",
    ] {
        c.host_overrides
            .insert(h.into(), vec!["127.0.0.1".parse().unwrap()]);
    }
    let (net, sink) = client(core.0, core.1, c);
    let (fs, errs) = Scope::from_lines(full.0, full.1);
    assert!(errs.is_empty());
    net.set_passive_guard(fs, block);
    (net, sink)
}

fn passive_host(r: &foca_net::testserver::TestRequest) -> String {
    r.headers.get("host").cloned().unwrap_or_default()
}

fn passive_server() -> impl std::future::Future<Output = TestServer> {
    TestServer::start(|r| {
        let port = passive_host(r).rsplit(':').next().unwrap_or("").to_string();
        match r.path() {
            "/to-secret" => {
                TestResponse::redirect(302, &format!("http://secret.example.test:{}/a.pdf", port))
            }
            "/to-www" => {
                TestResponse::redirect(302, &format!("http://www.example.test:{}/a.pdf", port))
            }
            "/to-third" => {
                TestResponse::redirect(302, &format!("http://third.test:{}/a.pdf", port))
            }
            _ => TestResponse::ok("pdf"),
        }
    })
}

#[tokio::test]
async fn passive_redirect_to_excluded_host_is_blocked() {
    let srv = passive_server().await;
    let port = srv.url().rsplit(':').next().unwrap().to_string();
    // standard profile: a target in scope is allowed, an exclusion never is
    let (net, sink) = passive_client(
        ("example.test", "secret.example.test"),
        ("example.test", "secret.example.test"),
        false,
    );
    let e = net
        .get_text(
            &format!("http://web.archive.test:{port}/to-secret"),
            "download",
            Access::Passive,
        )
        .await
        .unwrap_err();
    assert!(
        matches!(e, NetError::OutOfScope { ref host, .. } if host == "secret.example.test"),
        "{e:?}"
    );
    let e = net
        .get_text(
            &format!("http://secret.example.test:{port}/direct"),
            "wayback",
            Access::Passive,
        )
        .await
        .unwrap_err();
    assert!(matches!(e, NetError::OutOfScope { .. }), "{e:?}");
    let hosts: Vec<String> = srv.requests().iter().map(passive_host).collect();
    assert!(hosts.iter().all(|h| !h.starts_with("secret.")), "{hosts:?}");
    let log = sink.records();
    assert_eq!(
        log.iter()
            .filter(|r| r.blocked && r.host == "secret.example.test")
            .count(),
        2
    );
}

#[tokio::test]
async fn passive_level_never_reaches_target_hosts() {
    let srv = passive_server().await;
    let port = srv.url().rsplit(':').next().unwrap().to_string();
    // passive profile: the network scope is empty and the full scope guards passive requests
    let (net, _sink) = passive_client(("", ""), ("example.test", "secret.example.test"), true);
    for u in [
        format!("http://web.archive.test:{port}/to-www"),
        format!("http://example.test:{port}/x"),
    ] {
        let e = net
            .get_text(&u, "download", Access::Passive)
            .await
            .unwrap_err();
        assert!(matches!(e, NetError::OutOfScope { .. }), "{u}: {e:?}");
    }
    assert!(srv
        .requests()
        .iter()
        .all(|r| !passive_host(r).contains("example.test")));
    // a legitimate passive source works
    let t = net
        .get_text(
            &format!("http://web.archive.test:{port}/ok"),
            "wayback",
            Access::Passive,
        )
        .await
        .unwrap();
    assert_eq!(t, "pdf");
}

#[tokio::test]
async fn passive_hop_to_target_on_std_is_logged_as_target() {
    let srv = passive_server().await;
    let port = srv.url().rsplit(':').next().unwrap().to_string();
    let (net, sink) = passive_client(("example.test", ""), ("example.test", ""), false);
    let t = net
        .get_text(
            &format!("http://web.archive.test:{port}/to-www"),
            "download",
            Access::Passive,
        )
        .await
        .unwrap();
    assert_eq!(t, "pdf");
    let log = sink.records();
    let hop = log.iter().find(|r| r.host == "www.example.test").unwrap();
    assert!(hop.active && hop.access == "target", "{hop:?}");
    let first = log.iter().find(|r| r.host == "web.archive.test").unwrap();
    assert!(!first.active && first.access == "passive");
}

#[tokio::test]
async fn passive_allow_list_limits_redirect_hops() {
    let srv = passive_server().await;
    let port = srv.url().rsplit(':').next().unwrap().to_string();
    let (net, _) = passive_client(("", ""), ("example.test", ""), true);
    let req = NetRequest::get(
        &format!("http://web.archive.test:{port}/to-third"),
        "download",
        Access::Passive,
    )
    .unwrap()
    .passive_allow(Arc::new(vec!["archive.test".into()]));
    let e = net.send(req).await.err().unwrap();
    assert!(
        matches!(e, NetError::OutOfScope { ref host, .. } if host == "third.test"),
        "{e:?}"
    );
    assert_eq!(srv.hits("/a.pdf"), 0);
}

#[tokio::test]
async fn local_only_blocks_external_hosts_and_logs_them() {
    let srv = TestServer::start(|_| TestResponse::ok("ok")).await;
    let dir = std::env::temp_dir().join(format!("foca-local-only-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let log = dir.join("external.log");
    let _ = std::fs::remove_file(&log);
    let c = NetConfig {
        local_only: Some(log.clone()),
        ..cfg()
    };
    let (net, sink) = client("", "", c);
    // the local test bench is allowed
    let t = net
        .get_text(&format!("{}/x", srv.url()), "wayback", Access::Passive)
        .await
        .unwrap();
    assert_eq!(t, "ok");
    // an external host is denied before any network access, logged, and written to the file
    let e = net
        .get_text("https://web.archive.org/cdx", "wayback", Access::Passive)
        .await
        .unwrap_err();
    assert!(matches!(e, NetError::OutOfScope { .. }), "{e:?}");
    let recs = sink.records();
    assert!(
        recs.iter()
            .any(|r| r.host == "web.archive.org" && r.blocked),
        "{recs:?}"
    );
    assert_eq!(
        std::fs::read_to_string(&log).unwrap().trim(),
        "web.archive.org"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn local_host_classification() {
    let mut ov = HashMap::new();
    ov.insert(
        "example.org".to_string(),
        vec!["127.0.0.1".parse().unwrap()],
    );
    ov.insert(
        "mixed.org".to_string(),
        vec!["127.0.0.1".parse().unwrap(), "8.8.8.8".parse().unwrap()],
    );
    for h in [
        "localhost",
        "127.0.0.1",
        "[::1]",
        "example.test",
        "www.example.test.",
        "example.org",
    ] {
        assert!(foca_net::client::is_local_host(h, &ov), "{h}");
    }
    for h in [
        "web.archive.org",
        "8.8.8.8",
        "mixed.org",
        "test.com",
        "example.testing",
    ] {
        assert!(!foca_net::client::is_local_host(h, &ov), "{h}");
    }
}

#[tokio::test]
async fn cross_origin_redirect_strips_auth_headers_and_resolver_blocks_target_ip() {
    let dst = TestServer::start(|r| {
        let auth = r.headers.get("authorization").cloned().unwrap_or_default();
        let key = r.headers.get("x-api-key").cloned().unwrap_or_default();
        TestResponse::ok(format!("auth={auth};key={key}"))
    })
    .await;
    let dst_port = dst.url().rsplit(':').next().unwrap().to_string();
    let dst_other = format!("http://other.sink.test:{dst_port}/cb");
    let src = TestServer::start(move |_| TestResponse::redirect(302, &dst_other)).await;

    let mut c = cfg();
    c.retries = 0;
    c.host_overrides
        .insert("api.source.test".into(), vec!["127.0.0.1".parse().unwrap()]);
    c.host_overrides
        .insert("other.sink.test".into(), vec!["127.0.0.1".parse().unwrap()]);
    let src_port = src.url().rsplit(':').next().unwrap().to_string();
    let mut req = NetRequest::get(
        &format!("http://api.source.test:{src_port}/go"),
        "brave",
        Access::Passive,
    )
    .unwrap();
    req.headers
        .push(("Authorization".into(), "Bearer supersecret".into()));
    req.headers.push(("X-API-Key".into(), "key-123".into()));
    let (net, _) = client("", "", c);
    let body = net
        .send(req)
        .await
        .unwrap()
        .text_limited(4096)
        .await
        .unwrap();
    assert_eq!(body, "auth=;key=");

    // ScopedResolver blocks IP target in passive mode when guard_blocks_targets is active
    let target_srv = TestServer::start(|_| TestResponse::ok("secret")).await;
    let target_port = target_srv.url().rsplit(':').next().unwrap().to_string();
    let mut c2 = cfg();
    c2.retries = 0;
    c2.host_overrides.insert(
        "rebind.evil.test".into(),
        vec!["127.0.0.1".parse().unwrap()],
    );
    let (net2, _) = client("", "", c2);
    let (gs, _) = Scope::from_lines("127.0.0.1", "");
    net2.set_passive_guard(gs, true);
    let err = net2
        .get_text(
            &format!("http://rebind.evil.test:{target_port}/"),
            "wayback",
            Access::Passive,
        )
        .await
        .unwrap_err();
    assert!(matches!(err, NetError::OutOfScope { .. }), "{err:?}");
    assert!(target_srv.requests().is_empty());
}
