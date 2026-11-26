//! Infrastructure modules inside the scan pipeline, offline: profiles (passive touches
//! nothing, standard runs no active checks), the TLS/X.509 inspector on a local stand (expired,
//! self-signed, internal PKI via CDP/AIA, SHA-1/RSA-1024 and TLS 1.0 from a raw legacy server),
//! foreign SAN names kept out of the project hosts, a wildcard zone with zero false hosts, and
//! the SaaS / Microsoft 365 passive map.

use std::collections::HashMap;
use std::sync::Arc;

use crate::common::{open_with, Env};
use foca_engine::MemoryKeys;
use foca_net::bruteforce::testdns::FakeDns;
use foca_net::dns::StaticDns;
use foca_net::testserver::{TestRequest, TestResponse, TestServer};
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio_rustls::rustls::server::{ClientHello, ResolvesServerCert};
use tokio_rustls::rustls::sign::CertifiedKey;
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::TlsAcceptor;

const INT: &[u8] = include_bytes!("../../../foca-net/tests/fixtures/tls/int.der");
const GOOD: &[u8] = include_bytes!("../../../foca-net/tests/fixtures/tls/good.der");
const GOOD_KEY: &[u8] = include_bytes!("../../../foca-net/tests/fixtures/tls/good.key.der");
const EXPIRED: &[u8] = include_bytes!("../../../foca-net/tests/fixtures/tls/expired.der");
const EXPIRED_KEY: &[u8] = include_bytes!("../../../foca-net/tests/fixtures/tls/expired.key.der");
const SELF: &[u8] = include_bytes!("../../../foca-net/tests/fixtures/tls/self.der");
const SELF_KEY: &[u8] = include_bytes!("../../../foca-net/tests/fixtures/tls/self.key.der");
const WEAK: &[u8] = include_bytes!("../../../foca-net/tests/fixtures/tls/weak.der");

const TENANT: &str = "6babcaad-604b-40ac-a9d7-9fd97c0b779f";

/// Third-party sources: crt.sh answers nothing, Microsoft knows example.test, the rest is 404.
fn handler(r: &TestRequest) -> TestResponse {
    let p = r.path();
    if p == "/" && r.query("output").is_some() {
        return TestResponse::ok(b"[]".to_vec());
    }
    if p == "/example.test/v2.0/.well-known/openid-configuration" {
        return TestResponse::ok(
            format!(r#"{{"issuer":"https://login.microsoftonline.com/{TENANT}/v2.0","tenant_region_scope":"EU"}}"#)
                .into_bytes(),
        );
    }
    if p == "/getuserrealm.srf" {
        return TestResponse::ok(
            br#"{"NameSpaceType":"Managed","DomainName":"example.test","FederationBrandName":"Example"}"#
                .to_vec(),
        );
    }
    if p == "/collinfo.json" {
        return TestResponse::ok(b"[]".to_vec());
    }
    TestResponse::status(404)
}

#[derive(Debug)]
struct Sni {
    by_name: HashMap<String, Arc<CertifiedKey>>,
    default: Arc<CertifiedKey>,
}

impl ResolvesServerCert for Sni {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(
            hello
                .server_name()
                .and_then(|n| self.by_name.get(n))
                .cloned()
                .unwrap_or_else(|| self.default.clone()),
        )
    }
}

fn certified(chain: &[&[u8]], key: &[u8]) -> Arc<CertifiedKey> {
    let prov = tokio_rustls::rustls::crypto::ring::default_provider();
    let key = prov
        .key_provider
        .load_private_key(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.to_vec())))
        .unwrap();
    let certs = chain
        .iter()
        .map(|c| CertificateDer::from(c.to_vec()))
        .collect();
    Arc::new(CertifiedKey::new(certs, key))
}

/// TLS server choosing the certificate by SNI: expired.test, self.test, anything else good.test.
async fn tls_server() -> u16 {
    let prov = Arc::new(tokio_rustls::rustls::crypto::ring::default_provider());
    let mut by_name = HashMap::new();
    by_name.insert(
        "expired.test".into(),
        certified(&[EXPIRED, INT], EXPIRED_KEY),
    );
    by_name.insert("self.test".into(), certified(&[SELF], SELF_KEY));
    let sni = Sni {
        by_name,
        default: certified(&[GOOD, INT], GOOD_KEY),
    };
    let cfg = ServerConfig::builder_with_provider(prov)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(sni));
    let acc = TlsAcceptor::from(Arc::new(cfg));
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((tcp, _)) = l.accept().await {
            let acc = acc.clone();
            tokio::spawn(async move {
                if let Ok(t) = acc.accept(tcp).await {
                    let (mut r, _) = tokio::io::split(t);
                    let mut b = [0u8; 16];
                    let _ = r.read(&mut b).await;
                }
            });
        }
    });
    port
}

/// Raw legacy server: accepts TLS 1.0 (and a TLS 1.2 hello offering weak suites) with RC4/DES
/// suites and sends the SHA-1 / RSA-1024 certificate in clear; rejects everything else.
async fn legacy_server() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = l.accept().await {
            tokio::spawn(async move {
                let mut hdr = [0u8; 5];
                if s.read_exact(&mut hdr).await.is_err() || hdr[0] != 22 {
                    return;
                }
                let mut body = vec![0u8; u16::from_be_bytes([hdr[3], hdr[4]]) as usize];
                if s.read_exact(&mut body).await.is_err() || body.len() < 42 {
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
    port
}

const TLS_HOSTS: &[&str] = &[
    "good.test",
    "expired.test",
    "self.test",
    "weak.test",
    "other.test",
];

async fn tls_env() -> (Env, u16, u16) {
    let dir = tempfile::tempdir().unwrap();
    let server = TestServer::start(handler).await;
    let (p1, p2) = (tls_server().await, legacy_server().await);
    let keys = Arc::new(MemoryKeys::new());
    let zone: String = TLS_HOSTS
        .iter()
        .map(|h| format!("{h} A 127.0.0.1\n"))
        .collect();
    let (engine, events, pause_at) = open_with(dir.path(), &server.url(), keys.clone(), |c| {
        c.dns = Some(Arc::new(StaticDns::from_zone_text(&zone)));
        c.alive_ports = vec![p1, p2];
        c.tls_ports = vec![p1, p2];
        for h in TLS_HOSTS {
            c.net
                .host_overrides
                .insert(h.to_string(), vec!["127.0.0.1".parse().unwrap()]);
        }
    });
    let e = Env {
        dir,
        server,
        engine,
        events,
        pause_at,
        keys,
    };
    e.call("settings_set", json!({ "patch": { "net": { "rps": 0 } } }))
        .await;
    (e, p1, p2)
}

async fn project(e: &Env, targets: &[&str]) -> String {
    let t: Vec<Value> = targets
        .iter()
        .map(|v| json!({ "v": v, "type": "domain" }))
        .collect();
    let p = e
        .call(
            "project_create",
            json!({ "name": targets[0], "client": "К", "targets": t, "excludes": [] }),
        )
        .await;
    p["id"].as_str().unwrap().to_string()
}

async fn scan(e: &Env, id: &str, profile: &str, extra: Value) {
    let mut a = json!({ "project": id, "profile": profile, "sources": ["crt"] });
    if let (Some(o), Value::Object(x)) = (a.as_object_mut(), extra) {
        o.extend(x);
    }
    e.call("scan_start", a).await;
    e.wait().await;
}

fn cert<'a>(infra: &'a Value, key: &str) -> &'a Value {
    infra["cert"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| {
            let mut k = format!("{}:{}", c["host"].as_str().unwrap(), c["port"]);
            if c["mode"] != "tls" {
                k = format!("{k}/{}", c["mode"].as_str().unwrap());
            }
            k == key
        })
        .unwrap_or_else(|| panic!("no certificate record {key}: {}", infra["cert"]))
}

fn codes(c: &Value) -> Vec<String> {
    c["issues"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i["code"].as_str().unwrap().to_string())
        .collect()
}

fn hosts(s: &Value) -> Vec<String> {
    s["hosts"]
        .as_array()
        .unwrap()
        .iter()
        .map(|h| h["name"].as_str().unwrap().to_string())
        .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn standard_profile_audits_certificates_without_active_checks() {
    let (e, p1, _p2) = tls_env().await;
    let id = project(&e, &["good.test", "expired.test", "self.test"]).await;
    scan(&e, &id, "std", json!({})).await;
    let infra = e.call("infra_get", json!({ "project": id })).await;
    let good = cert(&infra, &format!("good.test:{p1}"));
    let gc = codes(good);
    assert!(gc.contains(&"cert_internal_pki".into()), "{gc:?}");
    assert!(gc.contains(&"cert_unknown_ca".into()), "{gc:?}");
    // CDP/AIA: the AD domain behind the LDAP path
    assert!(
        good["pki"]
            .as_array()
            .unwrap()
            .iter()
            .any(|h| h["ad_domain"] == "corp.local"),
        "{}",
        good["pki"]
    );
    assert_eq!(good["chain"][0]["subject"]["o"], "Good Test LLC");
    let exp = codes(cert(&infra, &format!("expired.test:{p1}")));
    assert!(exp.contains(&"cert_expired".into()), "{exp:?}");
    let sel = codes(cert(&infra, &format!("self.test:{p1}")));
    assert!(sel.contains(&"cert_self_signed".into()), "{sel:?}");
    // findings reach the project list with the localized-by-rule title, one per host
    let s = e.snap(&id).await;
    let titles: Vec<&str> = s["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|f| f["title"].as_str())
        .collect();
    assert!(
        titles.contains(&"Просроченный TLS-сертификат на expired.test"),
        "{titles:?}"
    );
    // one finding per host: the probed port is listed in the description
    let expired = s["findings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["provenance"]["rule"] == "infra.cert_expired")
        .unwrap();
    assert!(
        expired["description"]
            .as_str()
            .unwrap()
            .ends_with(&format!("\nПорты: {p1}")),
        "{expired}"
    );
    // standard: no legacy/STARTTLS/no-SNI/NSEC probe, but standard TLS handshakes were made
    let log = e
        .call("request_log_get", json!({ "project": id, "limit": 100000 }))
        .await;
    let log = log.as_array().unwrap();
    let active: Vec<&Value> = log
        .iter()
        .filter(|r| {
            r["access"] == "active"
                || ["tls-legacy", "starttls", "tls-no-sni", "nsec"]
                    .contains(&r["module"].as_str().unwrap_or(""))
        })
        .collect();
    assert!(active.is_empty(), "active checks in standard: {active:?}");
    assert!(
        log.iter().any(|r| r["module"] == "tls"),
        "no TLS handshakes"
    );
    // the source reports its count, and brute force ran (standard)
    let ev = e.events();
    assert!(ev
        .iter()
        .any(|x| x["type"] == "source" && x["id"] == "tls" && x["status"] == "ok"));
    assert!(infra["dns_enum"]
        .as_array()
        .unwrap()
        .iter()
        .any(|d| d["wordlist"] == "top-1500" && d["brute"]["tried"].as_u64() > Some(1000)));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn full_profile_finds_legacy_tls_weak_cert_and_keeps_foreign_san_out() {
    let (e, p1, p2) = tls_env().await;
    // other.test is served the good.test certificate: its SAN names are foreign to the scope
    let id = project(&e, &["other.test", "weak.test"]).await;
    scan(
        &e,
        &id,
        "full",
        json!({ "subdomains": { "wordlist": "custom", "custom": ["www"] } }),
    )
    .await;
    let infra = e.call("infra_get", json!({ "project": id })).await;
    let other = codes(cert(&infra, &format!("other.test:{p1}")));
    assert!(
        other.contains(&"cert_hostname_mismatch".into()),
        "{other:?}"
    );
    // TLS 1.0 + weak suites + SHA-1/RSA-1024 certificate from the raw legacy server
    let weak = cert(&infra, &format!("weak.test:{p2}/legacy"));
    let wc = codes(weak);
    for c in [
        "tls_legacy_version",
        "tls_weak_cipher",
        "cert_weak_signature",
        "cert_weak_key",
    ] {
        assert!(wc.contains(&c.into()), "{c}: {wc:?}");
    }
    assert!(weak["legacy"]["versions"]
        .as_array()
        .unwrap()
        .iter()
        .any(|v| v["supported"] == true));
    // foreign SAN names: candidates outside the scope, never project hosts
    let s = e.snap(&id).await;
    let hs = hosts(&s);
    assert!(!hs.iter().any(|h| h.ends_with("good.test")), "{hs:?}");
    let oos = e.call("oos_list", json!({ "project": id })).await;
    assert!(
        oos.as_array()
            .unwrap()
            .iter()
            .any(|o| o["host"] == "good.test" && o["source"] == "san"),
        "{oos}"
    );
    // active probes were logged as active
    let log = e
        .call("request_log_get", json!({ "project": id, "limit": 100000 }))
        .await;
    assert!(log
        .as_array()
        .unwrap()
        .iter()
        .any(|r| r["module"] == "tls-legacy" && r["access"] == "active"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn passive_profile_maps_saas_and_tenant_without_touching_the_target() {
    let dir = tempfile::tempdir().unwrap();
    let server = TestServer::start(handler).await;
    let keys = Arc::new(MemoryKeys::new());
    let zone = "
example.test A 127.0.0.1
example.test TXT \"v=spf1 include:spf.protection.outlook.com ~all\"
example.test TXT \"MS=ms12345678\"
example.test TXT \"google-site-verification=abc123\"
example.test TXT \"atlassian-domain-verification=xyz\"
example.test MX 10 example-test.mail.protection.outlook.com
_dmarc.example.test TXT \"v=DMARC1; p=none\"
www.example.test A 127.0.0.1
";
    let (engine, events, pause_at) = open_with(dir.path(), &server.url(), keys.clone(), |c| {
        c.dns = Some(Arc::new(StaticDns::from_zone_text(zone)));
    });
    let e = Env {
        dir,
        server,
        engine,
        events,
        pause_at,
        keys,
    };
    let id = project(&e, &["example.test"]).await;
    scan(&e, &id, "passive", json!({})).await;
    let infra = e.call("infra_get", json!({ "project": id })).await;
    let saas = &infra["saas"][0];
    let ids: Vec<&str> = saas["hits"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|h| h["id"].as_str())
        .collect();
    for want in ["microsoft365", "google", "atlassian"] {
        assert!(ids.contains(&want), "{want}: {ids:?}");
    }
    assert_eq!(infra["tenant"][0]["openid"]["tenant_id"], TENANT);
    assert!(!infra["mail_policy"].as_array().unwrap().is_empty());
    // nothing touched the target: every logged request is passive and none goes to example.test
    let log = e
        .call("request_log_get", json!({ "project": id, "limit": 100000 }))
        .await;
    let bad: Vec<&Value> = log
        .as_array()
        .unwrap()
        .iter()
        .filter(|r| {
            r["access"] != "passive"
                || r["host"]
                    .as_str()
                    .is_some_and(|h| h.ends_with("example.test"))
        })
        .collect();
    assert!(bad.is_empty(), "passive scan touched the target: {bad:?}");
    assert!(infra["cert"].as_array().unwrap().is_empty());
    assert!(infra["dns_enum"].as_array().unwrap().is_empty());
    let ev = e.events();
    assert!(!ev
        .iter()
        .any(|x| x["type"] == "source" && (x["id"] == "subdomains" || x["id"] == "tls")));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn wildcard_zone_yields_no_false_hosts() {
    let dir = tempfile::tempdir().unwrap();
    let server = TestServer::start(handler).await;
    let keys = Arc::new(MemoryKeys::new());
    let (engine, events, pause_at) = open_with(dir.path(), &server.url(), keys.clone(), |c| {
        let dns = FakeDns::new()
            .host("example.test", &["127.0.0.1"], 300)
            .host("www.example.test", &["127.0.0.1"], 300)
            .host("vpn.dev.example.test", &["127.0.0.3"], 300)
            .wildcard("example.test", &[&["127.0.0.9"]], 60)
            .wildcard("dev.example.test", &[&["127.0.0.8"]], 60);
        c.dns = Some(Arc::new(dns));
    });
    let e = Env {
        dir,
        server,
        engine,
        events,
        pause_at,
        keys,
    };
    let id = project(&e, &["example.test"]).await;
    let words = [
        "www",
        "api",
        "nothing-here",
        "dev",
        "vpn.dev",
        "admin.dev",
        "mail",
    ];
    scan(
        &e,
        &id,
        "std",
        json!({ "subdomains": { "wordlist": "custom", "custom": words } }),
    )
    .await;
    let s = e.snap(&id).await;
    let hs = hosts(&s);
    assert!(hs.contains(&"www.example.test".to_string()), "{hs:?}");
    assert!(hs.contains(&"vpn.dev.example.test".to_string()), "{hs:?}");
    for bad in ["api", "nothing-here", "dev", "admin.dev", "mail"] {
        let h = format!("{bad}.example.test");
        assert!(!hs.contains(&h), "false host {h}: {hs:?}");
    }
    let infra = e.call("infra_get", json!({ "project": id })).await;
    let levels = &infra["dns_enum"][0]["brute"]["wildcard_levels"];
    assert!(
        levels
            .as_array()
            .unwrap()
            .iter()
            .any(|l| l == "example.test"),
        "{levels}"
    );
    let www = s["hosts"]
        .as_array()
        .unwrap()
        .iter()
        .find(|h| h["name"] == "www.example.test")
        .unwrap();
    assert_eq!(www["source"], "bruteforce", "{www}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn wordlist_off_skips_brute_force_only() {
    let dir = tempfile::tempdir().unwrap();
    let server = TestServer::start(handler).await;
    let keys = Arc::new(MemoryKeys::new());
    let (engine, events, pause_at) = open_with(dir.path(), &server.url(), keys.clone(), |c| {
        let dns = FakeDns::new()
            .host("example.test", &["127.0.0.1"], 300)
            .host("www.example.test", &["127.0.0.1"], 300);
        c.dns = Some(Arc::new(dns));
    });
    let e = Env {
        dir,
        server,
        engine,
        events,
        pause_at,
        keys,
    };
    let id = project(&e, &["example.test"]).await;
    scan(
        &e,
        &id,
        "std",
        json!({ "subdomains": { "wordlist": "off" } }),
    )
    .await;
    let infra = e.call("infra_get", json!({ "project": id })).await;
    let rec = &infra["dns_enum"][0];
    assert_eq!(rec["wordlist"], "off", "{rec}");
    assert_eq!(rec["brute"]["skipped"], "off", "{rec}");
}
