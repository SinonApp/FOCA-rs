//! Port scanning against local listeners: open/closed ports, banners, logging, scope (zero
//! connections outside the scope) and cancellation.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use foca_core::Scope;
use foca_net::ports::{
    connect_succeeds, device_intercepts_tcp, mass_open, pick_canaries, scan_ports, PortResult,
    PortScanConfig, UNRELIABLE_CANARY,
};
use foca_net::{MemorySink, NetClient, NetConfig, NetError};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

fn client(targets: &str, excludes: &str, active: bool) -> (NetClient, Arc<MemorySink>) {
    let (mut scope, errs) = Scope::from_lines(targets, excludes);
    assert!(errs.is_empty(), "{errs:?}");
    scope.active_phase = active;
    let sink = Arc::new(MemorySink::new());
    let cfg = NetConfig {
        global_rps: Some(1.0), // the client-wide rate limit is not used by the port scan
        ..Default::default()
    };
    (NetClient::new(cfg, scope, sink.clone()).unwrap(), sink)
}

/// Spawns a listener that sends `greet` (if any) on each connection, then answers any request with `reply`.
async fn listener(
    greet: Option<&'static [u8]>,
    reply: Option<&'static [u8]>,
) -> (u16, Arc<AtomicUsize>) {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    let hits = Arc::new(AtomicUsize::new(0));
    let h = hits.clone();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = l.accept().await {
            h.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                if let Some(g) = greet {
                    let _ = s.write_all(g).await;
                }
                let mut b = [0u8; 1024];
                if let Ok(n) = s.read(&mut b).await {
                    if n > 0 {
                        if let Some(r) = reply {
                            let _ = s.write_all(r).await;
                        }
                    }
                }
            });
        }
    });
    (port, hits)
}

async fn free_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    l.local_addr().unwrap().port()
}

fn cfg(ports: Vec<u16>) -> PortScanConfig {
    PortScanConfig {
        ports,
        timeout: if cfg!(windows) {
            Duration::from_secs(4)
        } else {
            Duration::from_millis(800)
        },
        banner_timeout: Duration::from_millis(700),
        rps: None,
        ..Default::default()
    }
}

#[tokio::test]
async fn open_closed_banners_and_journal() {
    let (ssh, _) = listener(Some(b"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13\r\n"), None).await;
    let (ftp, _) = listener(Some(b"220 (vsFTPd 3.0.5)\r\n"), None).await;
    let (http, _) = listener(
        None,
        Some(b"HTTP/1.1 200 OK\r\nServer: nginx/1.24.0 (Ubuntu)\r\nContent-Length: 0\r\n\r\n"),
    )
    .await;
    let (mysql, _) = listener(
        Some(b"\x4a\x00\x00\x00\x0a8.0.36-0ubuntu0.22.04.1\x00\x08\x00\x00\x00\x1b\x00evil\x07"),
        None,
    )
    .await;
    let closed = free_port().await;
    let (net, sink) = client("127.0.0.1", "", true);
    let r = scan_ports(&net, "127.0.0.1", &cfg(vec![ssh, ftp, http, mysql, closed]))
        .await
        .unwrap();
    assert_eq!(r.scanned, 5);
    assert_eq!(r.closed, 1);
    assert_eq!(r.ip.as_deref(), Some("127.0.0.1"));
    let by = |p: u16| {
        r.open
            .iter()
            .find(|x| x.port == p)
            .unwrap_or_else(|| panic!("{p}: {r:?}"))
    };
    assert_eq!(r.open.len(), 4, "{r:?}");
    let s = by(ssh);
    assert_eq!(
        (
            s.service.as_str(),
            s.product.as_deref(),
            s.version.as_deref()
        ),
        ("ssh", Some("OpenSSH"), Some("9.6p1"))
    );
    assert!(!s.banner.as_deref().unwrap().contains('\r'));
    let f = by(ftp);
    assert_eq!(
        (
            f.service.as_str(),
            f.product.as_deref(),
            f.version.as_deref()
        ),
        ("ftp", Some("vsftpd"), Some("3.0.5"))
    );
    let h = by(http);
    assert_eq!(
        (
            h.service.as_str(),
            h.product.as_deref(),
            h.version.as_deref()
        ),
        ("http", Some("nginx"), Some("1.24.0"))
    );
    assert!(h
        .banner
        .as_deref()
        .unwrap()
        .contains("Server: nginx/1.24.0"));
    let m = by(mysql);
    assert_eq!(
        (
            m.service.as_str(),
            m.product.as_deref(),
            m.version.as_deref()
        ),
        ("mysql", Some("MySQL"), Some("8.0.36"))
    );
    assert!(m
        .banner
        .as_deref()
        .unwrap()
        .chars()
        .all(|c| !c.is_control()));
    // log: every attempt is an active record of the ports module
    let recs = sink.records();
    let tcp: Vec<_> = recs
        .iter()
        .filter(|x| x.module == "ports" && !x.url.contains("canary"))
        .collect();
    assert_eq!(tcp.len(), 5, "{recs:?}");
    assert!(r.unreliable.is_none(), "{r:?}");
    assert_eq!((r.canaries, r.canaries_open), (3, 0));
    let can = recs.iter().filter(|x| x.url.contains("canary")).count();
    assert_eq!(can, 3, "canaries are logged too");
    assert!(tcp.iter().all(|x| x.active && x.access == "active"));
    assert_eq!(tcp.iter().filter(|x| x.status == Some(0)).count(), 4);
    // the result serializes
    let j = serde_json::to_value(&r.open[0]).unwrap();
    assert!(j["port"].is_u64() && j["service"].is_string() && j["tls"].is_boolean());
}

#[tokio::test]
async fn out_of_scope_and_excluded_make_zero_connections() {
    let (port, hits) = listener(Some(b"SSH-2.0-x\r\n"), None).await;
    // not a target
    let (net, sink) = client("example.org", "", true);
    let e = scan_ports(&net, "127.0.0.1", &cfg(vec![port]))
        .await
        .unwrap_err();
    assert!(e.is_scope_denial(), "{e:?}");
    assert!(
        sink.records().iter().all(|r| r.blocked),
        "{:?}",
        sink.records()
    );
    // excluded
    let (net, _) = client("127.0.0.1", "127.0.0.1", true);
    let e = scan_ports(&net, "127.0.0.1", &cfg(vec![port]))
        .await
        .unwrap_err();
    assert!(e.is_scope_denial(), "{e:?}");
    // not in the active stage
    let (net, _) = client("127.0.0.1", "", false);
    let e = scan_ports(&net, "127.0.0.1", &cfg(vec![port]))
        .await
        .unwrap_err();
    assert!(matches!(e, NetError::ActiveDenied(_)), "{e:?}");
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(
        hits.load(Ordering::SeqCst),
        0,
        "connections outside the scope"
    );
}

#[tokio::test]
async fn cancel_stops_scan() {
    let (net, _) = client("127.0.0.1", "", true);
    net.cancel();
    let r = scan_ports(&net, "127.0.0.1", &cfg((20000..20100).collect())).await;
    match r {
        Err(NetError::Cancelled) => {}
        Ok(s) => assert!(s.cancelled && s.scanned < 100, "{s:?}"),
        Err(e) => panic!("{e:?}"),
    }
}

/// An accept-everything network (local VPN, AdGuard, proxy): silent listeners on all probed ports
/// and on the canaries mark the scan unreliable, and the main scan is skipped.
#[tokio::test]
async fn accept_all_network_is_unreliable() {
    let mut ports = Vec::new();
    for _ in 0..6 {
        ports.push(listener(None, None).await.0);
    }
    let canaries = vec![listener(None, None).await.0, listener(None, None).await.0];
    let (net, sink) = client("127.0.0.1", "", true);
    let mut c = cfg(ports.clone());
    c.canaries = Some(canaries.clone());
    let r = scan_ports(&net, "127.0.0.1", &c).await.unwrap();
    assert_eq!(r.unreliable.as_deref(), Some(UNRELIABLE_CANARY), "{r:?}");
    assert!(r.open.is_empty() && r.scanned == 0, "{r:?}");
    assert_eq!((r.canaries, r.canaries_open), (2, 2));
    // only the canaries are logged
    assert_eq!(
        sink.records()
            .iter()
            .filter(|x| x.module == "ports")
            .count(),
        2
    );
}

/// One open canary out of three (something really listens on a high port): the scan proceeds.
#[tokio::test]
async fn single_open_canary_is_not_enough() {
    let (ssh, _) = listener(Some(b"SSH-2.0-OpenSSH_9.6p1\r\n"), None).await;
    let can = vec![
        listener(None, None).await.0,
        free_port().await,
        free_port().await,
    ];
    let (net, _) = client("127.0.0.1", "", true);
    let mut c = cfg(vec![ssh]);
    c.canaries = Some(can);
    let r = scan_ports(&net, "127.0.0.1", &c).await.unwrap();
    assert!(r.unreliable.is_none(), "{r:?}");
    assert_eq!(r.open.len(), 1);
}

/// Second safeguard: canaries are closed, but more than 40% of ports are open and all are silent.
#[test]
fn mass_open_heuristic() {
    let silent = |p| PortResult {
        port: p,
        service: "unknown".into(),
        banner: None,
        product: None,
        version: None,
        tls: false,
        cert_names: vec![],
        confirmed: false,
        detail: None,
    };
    let open: Vec<_> = (1..=60).map(silent).collect();
    assert!(mass_open(100, &open));
    assert!(!mass_open(100, &open[..30]), "30% is not mass-open");
    assert!(!mass_open(10, &open[..8]), "too few ports scanned");
    let talk: Vec<_> = (1..=60)
        .map(|p| PortResult {
            banner: Some("x".into()),
            ..silent(p)
        })
        .collect();
    assert!(
        !mass_open(100, &talk),
        "ports with banners are real services"
    );
}

#[tokio::test]
async fn intercept_probe() {
    let (open, _) = listener(None, None).await;
    let closed = free_port().await;
    let a = |p: u16| format!("127.0.0.1:{p}").parse().unwrap();
    assert!(connect_succeeds(&[a(closed), a(open)], Duration::from_millis(500)).await);
    assert!(!connect_succeeds(&[a(closed)], Duration::from_millis(500)).await);
    let (net, sink) = client("example.com", "", true);
    assert!(
        device_intercepts_tcp(
            &net,
            &[format!("127.0.0.1:{open}")],
            Duration::from_millis(500)
        )
        .await
    );
    assert!(
        !device_intercepts_tcp(
            &net,
            &[format!("127.0.0.1:{closed}")],
            Duration::from_millis(500)
        )
        .await
    );
    assert_eq!(sink.records().len(), 2, "the network check is logged");
    let p = pick_canaries(3, &[]);
    assert_eq!(p.len(), 3);
    assert!(p.iter().all(|x| *x >= 49152));
}

/// The first connection is accepted and closed at once without a banner, and the retry is
/// refused (tarpit, VPN or load balancer): the port is not open.
#[tokio::test]
async fn banner_retry_refused_means_not_open() {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        if let Ok((s, _)) = l.accept().await {
            drop(s);
        }
        drop(l); // the retry is refused
    });
    let (net, sink) = client("127.0.0.1", "", true);
    let mut c = cfg(vec![port]);
    c.canaries = Some(vec![]);
    let r = scan_ports(&net, "127.0.0.1", &c).await.unwrap();
    assert!(r.open.is_empty(), "{r:?}");
    assert_eq!(r.closed, 1);
    assert!(sink
        .records()
        .iter()
        .any(|x| x.url.contains("banner-retry")));
}
