//! X.509/TLS inspector against local servers: rustls with test certificates, a fake legacy
//! TLS server answering raw hellos, fake STARTTLS servers; access policy per profile; CT
//! history, abandoned hosts and the organization pivot on fixtures.

use std::net::IpAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use foca_core::Scope;
use foca_net::ct::{self, CtEndpoints};
use foca_net::testserver::{TestResponse, TestServer};
use foca_net::tls::audit::{audit_chain, AuditConfig, TrustStatus};
use foca_net::tls::handshake::{
    inspect, inspect_no_sni, inspect_standard, no_sni_issue, starttls_inspect,
};
use foca_net::tls::legacy::{probe_legacy, LegacyConfig, TlsVersion, WeakClass};
use foca_net::tls::starttls::StartTls;
use foca_net::tls::{InspectOptions, TlsInspection};
use foca_net::{Access, MemorySink, NetClient, NetConfig, NetError};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::TlsAcceptor;

const ROOT: &[u8] = include_bytes!("fixtures/tls/root.der");
const INT: &[u8] = include_bytes!("fixtures/tls/int.der");
const GOOD: &[u8] = include_bytes!("fixtures/tls/good.der");
const GOOD_KEY: &[u8] = include_bytes!("fixtures/tls/good.key.der");
const EXPIRED: &[u8] = include_bytes!("fixtures/tls/expired.der");
const EXPIRED_KEY: &[u8] = include_bytes!("fixtures/tls/expired.key.der");
const SELF: &[u8] = include_bytes!("fixtures/tls/self.der");
const SELF_KEY: &[u8] = include_bytes!("fixtures/tls/self.key.der");
const WEAK: &[u8] = include_bytes!("fixtures/tls/weak.der");
const CRTSH_HISTORY: &str = include_str!("fixtures/crtsh_history.json");
const CRTSH_ORG: &str = include_str!("fixtures/crtsh_org.json");
const CERTSPOTTER_FULL: &str = include_str!("fixtures/certspotter_full.json");

/// 2026-06-01: inside the validity of the long-lived fixtures, after `expired.test`.
const NOW: i64 = 1_780_272_000;

const HOSTS: &[&str] = &["good.test", "expired.test", "self.test", "other.test"];

fn net(targets: &str, active: bool) -> (NetClient, Arc<MemorySink>) {
    let (mut scope, errs) = Scope::from_lines(targets, "");
    assert!(errs.is_empty(), "{errs:?}");
    scope.active_phase = active;
    let sink = Arc::new(MemorySink::new());
    let lo: IpAddr = "127.0.0.1".parse().unwrap();
    let cfg = NetConfig {
        global_rps: None,
        source_rps: Default::default(),
        host_overrides: HOSTS.iter().map(|h| (h.to_string(), vec![lo])).collect(),
        ..Default::default()
    };
    (NetClient::new(cfg, scope, sink.clone()).unwrap(), sink)
}

fn audit_cfg() -> AuditConfig {
    AuditConfig {
        now: NOW,
        extra_roots: vec![ROOT.to_vec()],
        ..Default::default()
    }
}

fn opts() -> InspectOptions {
    InspectOptions {
        timeout: std::time::Duration::from_secs(5),
        ..Default::default()
    }
}

fn codes(v: &[foca_net::tls::Issue]) -> Vec<String> {
    v.iter().map(|i| i.code.clone()).collect()
}

fn acceptor(chain: &[&[u8]], key: &[u8], ocsp: bool) -> TlsAcceptor {
    let prov = Arc::new(tokio_rustls::rustls::crypto::ring::default_provider());
    let certs: Vec<CertificateDer<'static>> = chain
        .iter()
        .map(|c| CertificateDer::from(c.to_vec()))
        .collect();
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.to_vec()));
    let b = ServerConfig::builder_with_provider(prov)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth();
    let mut cfg = if ocsp {
        b.with_single_cert_with_ocsp(certs, key, b"\x30\x03\x0a\x01\x00".to_vec())
            .unwrap()
    } else {
        b.with_single_cert(certs, key).unwrap()
    };
    cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    TlsAcceptor::from(Arc::new(cfg))
}

struct Server {
    port: u16,
    accepts: Arc<AtomicUsize>,
    sni: Arc<Mutex<Vec<Option<String>>>>,
}

impl Server {
    /// SNI of the first accepted session (the server task records it after the handshake).
    async fn seen_sni(&self) -> Option<String> {
        for _ in 0..100 {
            if let Some(s) = self.sni.lock().unwrap().first() {
                return s.clone();
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        panic!("no TLS session recorded");
    }
}

/// TLS server; `pre` runs the plaintext part (STARTTLS) before the TLS accept.
async fn tls_server(acc: TlsAcceptor, pre: Option<StartTls>) -> Server {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    let accepts = Arc::new(AtomicUsize::new(0));
    let sni = Arc::new(Mutex::new(Vec::new()));
    let (a, s) = (accepts.clone(), sni.clone());
    tokio::spawn(async move {
        while let Ok((mut tcp, _)) = l.accept().await {
            a.fetch_add(1, Ordering::SeqCst);
            let acc = acc.clone();
            let s = s.clone();
            tokio::spawn(async move {
                if let Some(p) = pre {
                    if !fake_starttls(&mut tcp, p).await {
                        return;
                    }
                }
                if let Ok(t) = acc.accept(tcp).await {
                    s.lock()
                        .unwrap()
                        .push(t.get_ref().1.server_name().map(str::to_string));
                    let (mut r, _) = tokio::io::split(t);
                    let mut b = [0u8; 16];
                    let _ = r.read(&mut b).await;
                }
            });
        }
    });
    Server { port, accepts, sni }
}

async fn line(s: &mut TcpStream) -> String {
    let mut out = Vec::new();
    let mut b = [0u8; 1];
    while s.read_exact(&mut b).await.is_ok() {
        out.push(b[0]);
        if b[0] == b'\n' {
            break;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

async fn fake_starttls(s: &mut TcpStream, p: StartTls) -> bool {
    match p {
        StartTls::Smtp => {
            let _ = s
                .write_all(b"220-mx.good.test ESMTP\r\n220 ready\r\n")
                .await;
            if !line(s).await.starts_with("EHLO") {
                return false;
            }
            let _ = s
                .write_all(
                    b"250-mx.good.test\r\n250-PIPELINING\r\n250-STARTTLS\r\n250 8BITMIME\r\n",
                )
                .await;
            if line(s).await.trim() != "STARTTLS" {
                return false;
            }
            s.write_all(b"220 2.0.0 go ahead\r\n").await.is_ok()
        }
        StartTls::Imap => {
            let _ = s
                .write_all(b"* OK [CAPABILITY IMAP4rev1 STARTTLS] ready\r\n")
                .await;
            let l = line(s).await;
            let tag = l.split_whitespace().next().unwrap_or("").to_string();
            if !l.contains("STARTTLS") {
                return false;
            }
            s.write_all(format!("{tag} OK begin TLS\r\n").as_bytes())
                .await
                .is_ok()
        }
        StartTls::Pop3 => {
            let _ = s.write_all(b"+OK POP3 ready\r\n").await;
            if line(s).await.trim() != "STLS" {
                return false;
            }
            s.write_all(b"+OK begin TLS\r\n").await.is_ok()
        }
        StartTls::Ftp => {
            let _ = s.write_all(b"220 FTP ready\r\n").await;
            if line(s).await.trim() != "AUTH TLS" {
                return false;
            }
            s.write_all(b"234 AUTH TLS ok\r\n").await.is_ok()
        }
        StartTls::Postgres => {
            let mut b = [0u8; 8];
            if s.read_exact(&mut b).await.is_err() || b != [0, 0, 0, 8, 4, 0xd2, 0x16, 0x2f] {
                return false;
            }
            s.write_all(b"S").await.is_ok()
        }
        StartTls::Rdp => {
            let mut b = [0u8; 19];
            if s.read_exact(&mut b).await.is_err() || b[0] != 3 || b[5] != 0xe0 || b[11] != 1 {
                return false;
            }
            // X.224 CC + RDP_NEG_RSP selecting PROTOCOL_SSL
            let cc = [
                3, 0, 0, 19, 14, 0xd0, 0, 0, 0x12, 0x34, 0, 2, 0, 8, 0, 1, 0, 0, 0,
            ];
            s.write_all(&cc).await.is_ok()
        }
    }
}

#[tokio::test]
async fn standard_handshake_reads_chain_alpn_ocsp() {
    let srv = tls_server(acceptor(&[GOOD, INT], GOOD_KEY, true), None).await;
    let (net, sink) = net("good.test", false);
    let r = inspect_standard(&net, "good.test", srv.port, &opts())
        .await
        .unwrap();
    assert_eq!(r.chain.len(), 2);
    let leaf = r.leaf().unwrap();
    assert_eq!(leaf.subject.o.as_deref(), Some("Good Test LLC"));
    assert_eq!(
        r.chain[1].subject.cn.as_deref(),
        Some("FOCA Test Issuing CA")
    );
    assert_eq!(r.alpn.as_deref(), Some("h2"));
    assert!(r.ocsp_stapled);
    assert_eq!(r.version.as_deref(), Some("TLSv1_3"));
    assert!(r.cipher.is_some() && r.error.is_none());
    assert_eq!(r.sni.as_deref(), Some("good.test"));
    assert_eq!(r.ip.as_deref(), Some("127.0.0.1"));
    assert_eq!(srv.seen_sni().await.as_deref(), Some("good.test"));
    let a = r.audit(&audit_cfg()).unwrap();
    assert_eq!(a.trust, TrustStatus::Trusted);
    assert_eq!(codes(&r.issues(&audit_cfg())), vec!["cert_internal_pki"]);
    let recs = sink.records();
    assert_eq!(recs.len(), 1);
    assert_eq!(
        (recs[0].module.as_str(), recs[0].access.as_str()),
        ("tls", "target")
    );
    // serialization drops the raw chain but keeps the parsed one
    let j = serde_json::to_value(&r).unwrap();
    assert!(j.get("chain_der").is_none() && j["chain"][0]["sha256"].is_string());
}

/// ALPN/OCSP issues come only from a completed handshake that offered `h2`/`http/1.1` and
/// `status_request`: a server without ALPN is reported, an h2 server is not, and a result built
/// from a raw legacy hello (nothing offered) or a STARTTLS session never raises them.
#[tokio::test]
async fn alpn_and_ocsp_issues_need_a_modern_handshake() {
    let h2 = tls_server(acceptor(&[GOOD, INT], GOOD_KEY, true), None).await;
    let mut plain_cfg = {
        let prov = Arc::new(tokio_rustls::rustls::crypto::ring::default_provider());
        ServerConfig::builder_with_provider(prov)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![
                    CertificateDer::from(GOOD.to_vec()),
                    CertificateDer::from(INT.to_vec()),
                ],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(GOOD_KEY.to_vec())),
            )
            .unwrap()
    };
    plain_cfg.alpn_protocols.clear();
    let plain = tls_server(TlsAcceptor::from(Arc::new(plain_cfg)), None).await;
    let (net, _) = net("good.test", false);
    let cfg = audit_cfg();

    let r = inspect_standard(&net, "good.test", h2.port, &opts())
        .await
        .unwrap();
    assert!(r.alpn_offered && r.modern_handshake());
    let c = codes(&r.issues(&cfg));
    assert!(!c.contains(&"tls_no_alpn".into()), "{c:?}");
    assert!(!c.contains(&"tls_no_ocsp_stapling".into()), "{c:?}");

    let r = inspect_standard(&net, "good.test", plain.port, &opts())
        .await
        .unwrap();
    assert_eq!(r.alpn, None);
    let c = codes(&r.issues(&cfg));
    assert!(c.contains(&"tls_no_alpn".into()), "{c:?}");
    assert!(c.contains(&"tls_no_ocsp_stapling".into()), "{c:?}");

    // the same server seen through a probe that offered no ALPN: nothing to say about ALPN/OCSP
    let no_alpn = InspectOptions {
        alpn: Vec::new(),
        ..opts()
    };
    let r = inspect_standard(&net, "good.test", h2.port, &no_alpn)
        .await
        .unwrap();
    assert!(!r.alpn_offered);
    let c = codes(&r.issues(&cfg));
    assert!(!c.contains(&"tls_no_alpn".into()), "{c:?}");
    assert!(!c.contains(&"tls_no_ocsp_stapling".into()), "{c:?}");

    // a legacy-probe record (raw hello, chain sent in clear) and a failed handshake
    let mut legacy = inspect_standard(&net, "good.test", h2.port, &opts())
        .await
        .unwrap();
    legacy.alpn = None;
    legacy.ocsp_stapled = false;
    legacy.alpn_offered = false;
    let c = codes(&legacy.issues(&cfg));
    assert!(
        !c.iter()
            .any(|x| x == "tls_no_alpn" || x == "tls_no_ocsp_stapling"),
        "{c:?}"
    );
    let mut failed = legacy.clone();
    failed.alpn_offered = true;
    failed.version = None;
    failed.error = Some("handshake timeout".into());
    let c = codes(&failed.issues(&cfg));
    assert!(
        !c.iter()
            .any(|x| x == "tls_no_alpn" || x == "tls_no_ocsp_stapling"),
        "{c:?}"
    );
    // stored records from older versions have no `alpn_offered`: read as not offered
    let mut j = serde_json::to_value(&legacy).unwrap();
    j.as_object_mut().unwrap().remove("alpn_offered");
    let back: TlsInspection = serde_json::from_value(j).unwrap();
    assert!(!back.alpn_offered);
}

#[tokio::test]
async fn expired_self_signed_and_mismatch() {
    let exp = tls_server(acceptor(&[EXPIRED, INT], EXPIRED_KEY, false), None).await;
    let slf = tls_server(acceptor(&[SELF], SELF_KEY, false), None).await;
    let (net, _) = net("good.test\nexpired.test\nself.test", false);
    let r = inspect_standard(&net, "expired.test", exp.port, &opts())
        .await
        .unwrap();
    let c = codes(&r.issues(&audit_cfg()));
    assert!(c.contains(&"cert_expired".into()), "{c:?}");
    assert!(c.contains(&"tls_no_ocsp_stapling".into()), "{c:?}");
    let r = inspect_standard(&net, "self.test", slf.port, &opts())
        .await
        .unwrap();
    let c = codes(&r.issues(&audit_cfg()));
    assert!(c.contains(&"cert_self_signed".into()), "{c:?}");
    assert!(!c.contains(&"cert_hostname_mismatch".into()));
    let r = inspect_standard(&net, "good.test", slf.port, &opts())
        .await
        .unwrap();
    let c = codes(&r.issues(&audit_cfg()));
    assert!(c.contains(&"cert_hostname_mismatch".into()), "{c:?}");
}

#[tokio::test]
async fn no_sni_is_active_and_sends_no_sni() {
    let srv = tls_server(acceptor(&[GOOD, INT], GOOD_KEY, false), None).await;
    let (passive_phase, _) = net("good.test\n127.0.0.1", false);
    let e = inspect_no_sni(&passive_phase, "127.0.0.1", srv.port, &opts())
        .await
        .unwrap_err();
    assert!(matches!(e, NetError::ActiveDenied(_)), "{e:?}");
    assert_eq!(srv.accepts.load(Ordering::SeqCst), 0);

    let (net, sink) = net("good.test\n127.0.0.1", true);
    let r = inspect_no_sni(&net, "127.0.0.1", srv.port, &opts())
        .await
        .unwrap();
    assert!(r.sni.is_none());
    assert_eq!(srv.seen_sni().await, None, "server saw no SNI");
    assert_eq!(
        no_sni_issue(&r, "good.test").unwrap().code,
        "tls_origin_confirmed"
    );
    assert_eq!(
        no_sni_issue(&r, "x.example").unwrap().code,
        "tls_default_cert"
    );
    assert!(sink
        .records()
        .iter()
        .any(|r| r.module == "tls-no-sni" && r.access == "active" && !r.blocked));
}

#[tokio::test]
async fn starttls_protocols() {
    let (net, sink) = net("good.test", true);
    for p in [
        StartTls::Smtp,
        StartTls::Imap,
        StartTls::Pop3,
        StartTls::Ftp,
        StartTls::Postgres,
        StartTls::Rdp,
    ] {
        let srv = tls_server(acceptor(&[GOOD, INT], GOOD_KEY, false), Some(p)).await;
        let r: TlsInspection = starttls_inspect(&net, "good.test", srv.port, Some(p), &opts())
            .await
            .unwrap_or_else(|e| panic!("{p:?}: {e}"));
        assert_eq!(r.starttls, Some(p));
        assert_eq!(r.leaf().unwrap().subject.cn.as_deref(), Some("good.test"));
        assert!(r.error.is_none(), "{p:?}: {:?}", r.error);
        // no ALPN/OCSP noise for mail and database ports
        assert_eq!(codes(&r.issues(&audit_cfg())), vec!["cert_internal_pki"]);
    }
    assert!(sink
        .records()
        .iter()
        .all(|r| r.module == "starttls" && r.access == "active"));
}

#[tokio::test]
async fn smtp_without_starttls_is_reported() {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = l.accept().await {
            let _ = s.write_all(b"220 old mx\r\n").await;
            let _ = line(&mut s).await;
            let _ = s.write_all(b"250-old\r\n250 SIZE 1000\r\n").await;
            let _ = line(&mut s).await;
        }
    });
    let (net, _) = net("good.test", true);
    let e = starttls_inspect(&net, "good.test", port, None, &opts()).await;
    assert!(e.is_err(), "port is not a known STARTTLS port");
    let e = starttls_inspect(&net, "good.test", port, Some(StartTls::Smtp), &opts())
        .await
        .unwrap_err();
    assert!(e.to_string().contains("STARTTLS not offered"), "{e}");
}

/// Answers a raw ClientHello like an old server: TLS 1.0 and 1.2 (no 1.1), RC4 and 3DES.
async fn legacy_server() -> (u16, Arc<AtomicUsize>) {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    let hits = Arc::new(AtomicUsize::new(0));
    let h = hits.clone();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = l.accept().await {
            h.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                let mut hdr = [0u8; 5];
                if s.read_exact(&mut hdr).await.is_err() {
                    return;
                }
                let mut body = vec![0u8; u16::from_be_bytes([hdr[3], hdr[4]]) as usize];
                if s.read_exact(&mut body).await.is_err() {
                    return;
                }
                let ver = u16::from_be_bytes([body[4], body[5]]);
                let sid = body[38] as usize;
                let cl = u16::from_be_bytes([body[39 + sid], body[40 + sid]]) as usize;
                let offered: Vec<u16> = body[41 + sid..41 + sid + cl]
                    .chunks(2)
                    .map(|c| u16::from_be_bytes([c[0], c[1]]))
                    .collect();
                let pick = [0x002f, 0x0005, 0x000a]
                    .into_iter()
                    .find(|c| offered.contains(c));
                let (Some(cipher), true) = (pick, ver == 0x0301 || ver == 0x0303) else {
                    let _ = s.write_all(&[21, 3, 1, 0, 2, 2, 70]).await;
                    return;
                };
                let mut sh = ver.to_be_bytes().to_vec();
                sh.extend_from_slice(&[7u8; 32]);
                sh.push(0);
                sh.extend_from_slice(&u16::to_be_bytes(cipher));
                sh.push(0);
                let mut hs = vec![2, 0, 0, sh.len() as u8];
                hs.extend_from_slice(&sh);
                let n = WEAK.len();
                let mut cert = vec![11];
                cert.extend_from_slice(&((n + 6) as u32).to_be_bytes()[1..]);
                cert.extend_from_slice(&((n + 3) as u32).to_be_bytes()[1..]);
                cert.extend_from_slice(&(n as u32).to_be_bytes()[1..]);
                cert.extend_from_slice(WEAK);
                hs.extend_from_slice(&cert);
                hs.extend_from_slice(&[14, 0, 0, 0]);
                let mut rec = vec![22, 3, 1];
                rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
                rec.extend_from_slice(&hs);
                let _ = s.write_all(&rec).await;
                let mut b = [0u8; 16];
                let _ = s.read(&mut b).await;
            });
        }
    });
    (port, hits)
}

#[tokio::test]
async fn legacy_versions_and_weak_ciphers() {
    let (port, hits) = legacy_server().await;
    let (net, sink) = net("good.test", true);
    let cfg = LegacyConfig {
        versions: vec![TlsVersion::Tls10, TlsVersion::Tls11],
        ..Default::default()
    };
    let rep = probe_legacy(&net, "good.test", port, &cfg).await.unwrap();
    assert!(rep.versions[0].supported);
    assert_eq!(
        rep.versions[0].cipher.as_deref(),
        Some("TLS_RSA_WITH_AES_128_CBC_SHA")
    );
    assert!(!rep.versions[1].supported);
    assert_eq!(rep.versions[1].alert, Some(70));
    let weak: Vec<(u16, WeakClass)> = rep.weak_suites.iter().map(|w| (w.id, w.class)).collect();
    assert_eq!(
        weak,
        vec![(0x0005, WeakClass::Rc4), (0x000a, WeakClass::TripleDes)]
    );
    assert_eq!(rep.weak_suites[0].version, "TLSv1.2");
    // the certificate came in clear with the TLS 1.0 flight
    assert_eq!(rep.certs, vec![WEAK.to_vec()]);
    let a = audit_chain(&rep.certs, Some("good.test"), &audit_cfg()).unwrap();
    assert!(codes(&a.issues).contains(&"cert_weak_key".into()));
    assert_eq!(
        codes(&rep.issues),
        vec!["tls_legacy_version", "tls_weak_cipher", "tls_weak_cipher"]
    );
    // 2 version hellos + 2 accepted weak rounds + 1 final round
    assert_eq!(hits.load(Ordering::SeqCst), 5);
    assert!(sink
        .records()
        .iter()
        .all(|r| r.module == "tls-legacy" && r.access == "active"));
}

#[tokio::test]
async fn policy_passive_standard_active() {
    let srv = tls_server(acceptor(&[GOOD, INT], GOOD_KEY, false), None).await;
    let (legacy_port, legacy_hits) = legacy_server().await;

    // passive: never connects, whatever the scope
    let (net_p, sink_p) = net("good.test", false);
    let e = inspect(
        &net_p,
        "tls",
        "good.test",
        srv.port,
        Access::Passive,
        &opts(),
    )
    .await
    .unwrap_err();
    assert!(e.is_scope_denial(), "{e:?}");
    assert!(sink_p.records().is_empty());

    // standard: only in-scope hosts
    let e = inspect_standard(&net_p, "other.test", srv.port, &opts())
        .await
        .unwrap_err();
    assert!(matches!(e, NetError::OutOfScope { .. }), "{e:?}");
    let recs = sink_p.records();
    assert!(recs.len() == 1 && recs[0].blocked);

    // active probes outside the active stage
    assert!(matches!(
        probe_legacy(&net_p, "good.test", legacy_port, &LegacyConfig::default())
            .await
            .unwrap_err(),
        NetError::ActiveDenied(_)
    ));
    assert!(matches!(
        starttls_inspect(&net_p, "good.test", srv.port, Some(StartTls::Smtp), &opts())
            .await
            .unwrap_err(),
        NetError::ActiveDenied(_)
    ));
    // active probes in the active stage, but out of scope
    let (net_a, _) = net("good.test", true);
    assert!(
        probe_legacy(&net_a, "other.test", legacy_port, &LegacyConfig::default())
            .await
            .unwrap_err()
            .is_scope_denial()
    );

    assert_eq!(srv.accepts.load(Ordering::SeqCst), 0);
    assert_eq!(legacy_hits.load(Ordering::SeqCst), 0);
}

#[test]
fn ct_timeline_and_abandoned_hosts() {
    let now = 1_793_491_200; // 2026-11-01
    let certs = ct::parse_crtsh_certs(CRTSH_HISTORY).unwrap();
    assert_eq!(certs.len(), 8, "precert and final certificate merged");
    let tl = ct::cert_timeline(&certs, "acme.test");
    let www = tl.iter().find(|t| t.host == "www.acme.test").unwrap();
    assert_eq!(www.cert_count, 3);
    assert_eq!(www.ca_changes, 1);
    assert_eq!(www.issuers[0].issuer, "Sectigo Limited");
    assert_eq!(www.issuers[1].issuer, "Let's Encrypt");
    assert_eq!(www.issuers[1].certs, 2);
    assert_eq!(
        www.first_seen,
        ct::parse_ct_time("2023-02-01T00:00:00").unwrap()
    );
    assert!(tl.iter().any(|t| t.host == "*.cdn.acme.test"));
    let ab = ct::abandoned_hosts(&tl, now, 30);
    let hosts: Vec<&str> = ab.iter().map(|a| a.host.as_str()).collect();
    // shop: expired 3 days ago (grace); edge.cdn: covered by a valid wildcard
    assert_eq!(hosts, vec!["old.acme.test", "vpn.acme.test"]);
    assert_eq!(ab[0].last_issuer.as_deref(), Some("Let's Encrypt"));
    assert!(ab[0].days_since_expiry > 600);
    // a dead zone gives no abandoned-subdomain signal
    assert!(ct::abandoned_hosts(&tl, now + 400 * 86_400, 30).is_empty());
}

#[test]
fn certspotter_full_metadata() {
    let (v, last) = ct::parse_certspotter_certs(CERTSPOTTER_FULL).unwrap();
    assert_eq!(last.as_deref(), Some("9002"));
    assert_eq!(v[0].org.as_deref(), Some("Good Test LLC"));
    assert_eq!(v[0].common_name.as_deref(), Some("good.test"));
    assert_eq!(v[0].issuer_org.as_deref(), Some("FOCA Test PKI"));
    assert!(v[0].serial.is_some() && v[0].spki_sha256.is_some());
    assert_eq!(v[1].issuer_org.as_deref(), Some("Let's Encrypt"));
    assert_eq!(v[1].revoked, Some(true));
    assert!(v[1].org.is_none());
    let tl = ct::cert_timeline(&v, "good.test");
    assert_eq!(tl.len(), 3);
}

#[tokio::test]
async fn org_pivot_returns_out_of_scope_candidates_and_never_visits_them() {
    let srv = TestServer::start(|r| match (r.path(), r.query("O").as_deref()) {
        ("/", Some("Acme Corp")) => TestResponse::ok(CRTSH_ORG),
        _ => TestResponse::status(404),
    })
    .await;
    let (net, sink) = net("acme.test", false);
    let ep = CtEndpoints {
        crtsh: srv.url(),
        ..Default::default()
    };
    let c = ct::crtsh_org_pivot(&net, &ep, "Acme Corp").await.unwrap();
    let doms: Vec<&str> = c.iter().map(|x| x.domain.as_str()).collect();
    assert_eq!(doms, vec!["acme-holding.test", "acmegroup.com.ua"]);
    assert_eq!(c[0].cert_count, 2);
    assert_eq!(
        c[0].names,
        vec!["acme-holding.test", "portal.acme-holding.test"]
    );
    assert_eq!(
        c[1].names,
        vec!["acmegroup.com.ua", "shop.acmegroup.com.ua"]
    );
    // one passive request to crt.sh, nothing to the candidates
    let recs = sink.records();
    assert_eq!(recs.len(), 1);
    assert_eq!(recs[0].host, "127.0.0.1");
    assert_eq!(
        (recs[0].module.as_str(), recs[0].access.as_str()),
        ("crt-org", "passive")
    );
    assert_eq!(srv.requests().len(), 1);
    assert!(ct::crtsh_org_pivot(&net, &ep, " ").await.is_err());
}

#[tokio::test]
async fn full_ct_metadata_over_http() {
    let srv = TestServer::start(|r| match r.path() {
        "/" => TestResponse::ok(CRTSH_HISTORY),
        "/v1/issuances" if r.query("after").is_none() => TestResponse::ok(CERTSPOTTER_FULL),
        _ => TestResponse::ok("[]"),
    })
    .await;
    let (net, _) = net("acme.test", false);
    let ep = CtEndpoints {
        crtsh: srv.url(),
        certspotter: srv.url(),
    };
    let v = ct::crtsh_certs(&net, &ep, "acme.test").await.unwrap();
    assert_eq!(v.len(), 8);
    let v = ct::certspotter_certs(&net, &ep, "good.test", None, 3, true)
        .await
        .unwrap();
    assert_eq!(v.len(), 2);
    let q = &srv.requests()[1];
    assert!(q.path().ends_with("/v1/issuances"));
}

// ---------- live (allowed targets only) ----------

#[tokio::test]
#[ignore = "network: testfire.net"]
async fn live_testfire_tls() {
    let (net, _) = net("testfire.net", true);
    let r = match inspect_standard(&net, "testfire.net", 443, &InspectOptions::default()).await {
        Ok(r) => r,
        // the host is often unreachable on 443 from datacenter networks
        Err(e) => return eprintln!("testfire.net:443 unavailable: {e}"),
    };
    let leaf = r.leaf().unwrap();
    eprintln!(
        "{:?} {:?} {:?} {:?}",
        r.version, r.cipher, leaf.subject, leaf.issuer.o
    );
    eprintln!("{:?}", r.issues(&AuditConfig::default()));
    let rep = probe_legacy(&net, "testfire.net", 443, &LegacyConfig::default())
        .await
        .unwrap();
    eprintln!("{:?} {:?}", rep.versions, rep.weak_suites);
}
