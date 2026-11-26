//! The browser profile actually goes out on the wire: every header, in order, in Title-Case.

use std::sync::Arc;

use foca_core::Scope;
use foca_net::ua::{BrowserProfile, UaMode, UaVersions};
use foca_net::{Access, MemorySink, NetClient, NetConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// Accepts one connection, returns the raw request (up to the blank line) and answers 200.
async fn capture(mode: UaMode) -> (BrowserProfile, String) {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let srv = tokio::spawn(async move {
        let (mut s, _) = l.accept().await.unwrap();
        let mut buf = Vec::new();
        let mut b = [0u8; 1024];
        while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
            let n = s.read(&mut b).await.unwrap();
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&b[..n]);
        }
        s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
            .await
            .unwrap();
        String::from_utf8_lossy(&buf).to_string()
    });
    let now = time::OffsetDateTime::now_utc();
    let p = BrowserProfile::for_mode(&mode, now, &UaVersions::default());
    let mut cfg = NetConfig {
        global_rps: None,
        retries: 0,
        ..Default::default()
    };
    p.apply(&mut cfg);
    let net = NetClient::new(cfg, Scope::default(), Arc::new(MemorySink::new())).unwrap();
    let t = net
        .get_text(&format!("http://{addr}/x"), "test", Access::Passive)
        .await
        .unwrap();
    assert_eq!(t, "ok");
    (p, srv.await.unwrap())
}

fn names(raw: &str) -> Vec<String> {
    raw.lines()
        .skip(1)
        .filter_map(|l| l.split_once(':').map(|(k, _)| k.to_string()))
        .collect()
}

#[tokio::test]
async fn chrome_profile_headers_on_wire_in_order() {
    let (p, raw) = capture(UaMode::Chrome).await;
    let wire = names(&raw);
    // every profile header was sent, in the same order, in Title-Case
    let mut pos = Vec::new();
    for (k, v) in &p.headers {
        let i = wire
            .iter()
            .position(|w| w.eq_ignore_ascii_case(k))
            .unwrap_or_else(|| panic!("missing {k} in {raw}"));
        assert!(
            raw.contains(&format!("{}: {v}", wire[i])),
            "{k}: {v}\n{raw}"
        );
        pos.push(i);
    }
    assert!(pos.windows(2).all(|w| w[0] < w[1]), "order {wire:?}");
    assert!(wire.iter().any(|w| w == "User-Agent"), "{wire:?}");
    assert!(
        raw.contains("Sec-Ch-Ua: \"") && raw.contains("Chrome/"),
        "{raw}"
    );
}

#[tokio::test]
async fn firefox_has_no_client_hints_and_honest_is_bare() {
    let (_, raw) = capture(UaMode::Firefox).await;
    assert!(raw.contains("User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:"));
    assert!(!raw.to_ascii_lowercase().contains("sec-ch-ua"), "{raw}");
    let (_, raw) = capture(UaMode::Honest).await;
    let lower = raw.to_ascii_lowercase();
    assert!(lower.contains("user-agent: foca-rs/"), "{raw}");
    assert!(
        !lower.contains("sec-fetch") && !lower.contains("sec-ch-ua"),
        "{raw}"
    );
}
