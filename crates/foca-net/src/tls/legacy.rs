//! Legacy protocol and weak cipher probes with a hand-built `ClientHello` (rustls cannot offer
//! TLS 1.0/1.1, SSL 3.0 or weak suites). Only the server's first flight is read; the connection
//! is closed right after the `ServerHello` (and certificate, when sent in clear). Active only.

use std::time::Duration;

use foca_core::Severity;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};

use super::starttls::{self, StartTls};
use super::{refuse_passive, Issue};
use crate::client::{Access, NetClient};
use crate::NetError;

/// Request log module.
pub const MODULE: &str = "tls-legacy";

/// Max bytes of the server's first flight that are buffered.
const MAX_FLIGHT: usize = 64 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TlsVersion {
    #[serde(rename = "SSLv3")]
    Ssl3,
    #[serde(rename = "TLSv1.0")]
    Tls10,
    #[serde(rename = "TLSv1.1")]
    Tls11,
    #[serde(rename = "TLSv1.2")]
    Tls12,
}

impl TlsVersion {
    pub fn wire(self) -> u16 {
        match self {
            TlsVersion::Ssl3 => 0x0300,
            TlsVersion::Tls10 => 0x0301,
            TlsVersion::Tls11 => 0x0302,
            TlsVersion::Tls12 => 0x0303,
        }
    }

    pub fn from_wire(v: u16) -> Option<Self> {
        Some(match v {
            0x0300 => TlsVersion::Ssl3,
            0x0301 => TlsVersion::Tls10,
            0x0302 => TlsVersion::Tls11,
            0x0303 => TlsVersion::Tls12,
            _ => return None,
        })
    }

    pub fn label(self) -> &'static str {
        match self {
            TlsVersion::Ssl3 => "SSLv3",
            TlsVersion::Tls10 => "TLSv1.0",
            TlsVersion::Tls11 => "TLSv1.1",
            TlsVersion::Tls12 => "TLSv1.2",
        }
    }
}

/// Weak suite classes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum WeakClass {
    Null,
    Anon,
    Export,
    Des,
    Rc4,
    TripleDes,
}

/// Weak suites offered by the weak cipher probe: (id, name, class).
pub const WEAK_SUITES: &[(u16, &str, WeakClass)] = &[
    (0x0001, "TLS_RSA_WITH_NULL_MD5", WeakClass::Null),
    (0x0002, "TLS_RSA_WITH_NULL_SHA", WeakClass::Null),
    (0x003b, "TLS_RSA_WITH_NULL_SHA256", WeakClass::Null),
    (0xc006, "TLS_ECDHE_ECDSA_WITH_NULL_SHA", WeakClass::Null),
    (0xc010, "TLS_ECDHE_RSA_WITH_NULL_SHA", WeakClass::Null),
    (0x0018, "TLS_DH_anon_WITH_RC4_128_MD5", WeakClass::Anon),
    (0x001b, "TLS_DH_anon_WITH_3DES_EDE_CBC_SHA", WeakClass::Anon),
    (0x0034, "TLS_DH_anon_WITH_AES_128_CBC_SHA", WeakClass::Anon),
    (0x003a, "TLS_DH_anon_WITH_AES_256_CBC_SHA", WeakClass::Anon),
    (
        0xc018,
        "TLS_ECDH_anon_WITH_AES_128_CBC_SHA",
        WeakClass::Anon,
    ),
    (
        0xc019,
        "TLS_ECDH_anon_WITH_AES_256_CBC_SHA",
        WeakClass::Anon,
    ),
    (0x0003, "TLS_RSA_EXPORT_WITH_RC4_40_MD5", WeakClass::Export),
    (
        0x0006,
        "TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5",
        WeakClass::Export,
    ),
    (
        0x0008,
        "TLS_RSA_EXPORT_WITH_DES40_CBC_SHA",
        WeakClass::Export,
    ),
    (
        0x0014,
        "TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA",
        WeakClass::Export,
    ),
    (0x0009, "TLS_RSA_WITH_DES_CBC_SHA", WeakClass::Des),
    (0x0015, "TLS_DHE_RSA_WITH_DES_CBC_SHA", WeakClass::Des),
    (0x0004, "TLS_RSA_WITH_RC4_128_MD5", WeakClass::Rc4),
    (0x0005, "TLS_RSA_WITH_RC4_128_SHA", WeakClass::Rc4),
    (0xc007, "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA", WeakClass::Rc4),
    (0xc011, "TLS_ECDHE_RSA_WITH_RC4_128_SHA", WeakClass::Rc4),
    (
        0x000a,
        "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
        WeakClass::TripleDes,
    ),
    (
        0x0016,
        "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA",
        WeakClass::TripleDes,
    ),
    (
        0xc008,
        "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA",
        WeakClass::TripleDes,
    ),
    (
        0xc012,
        "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
        WeakClass::TripleDes,
    ),
];

/// Suites offered by the version probe: what TLS 1.0/1.1 servers commonly accept.
const LEGACY_SUITES: &[u16] = &[
    0xc02b, 0xc02f, 0xc013, 0xc014, 0xc009, 0xc00a, 0x0033, 0x0039, 0x002f, 0x0035, 0x009c, 0x009d,
    0x003c, 0x003d, 0x000a, 0xc012, 0x0016, 0x0005, 0x0004, 0x00ff,
];

/// Name of a cipher suite id (weak and legacy suites; others as hex).
pub fn suite_name(id: u16) -> String {
    if let Some((_, n, _)) = WEAK_SUITES.iter().find(|(i, _, _)| *i == id) {
        return n.to_string();
    }
    match id {
        0xc02b => "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
        0xc02f => "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        0xc013 => "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
        0xc014 => "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
        0xc009 => "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
        0xc00a => "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
        0x0033 => "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
        0x0039 => "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
        0x002f => "TLS_RSA_WITH_AES_128_CBC_SHA",
        0x0035 => "TLS_RSA_WITH_AES_256_CBC_SHA",
        0x009c => "TLS_RSA_WITH_AES_128_GCM_SHA256",
        0x009d => "TLS_RSA_WITH_AES_256_GCM_SHA384",
        0x003c => "TLS_RSA_WITH_AES_128_CBC_SHA256",
        0x003d => "TLS_RSA_WITH_AES_256_CBC_SHA256",
        _ => return format!("0x{id:04x}"),
    }
    .to_string()
}

fn put_u16(v: &mut Vec<u8>, x: u16) {
    v.extend_from_slice(&x.to_be_bytes());
}

fn ext(v: &mut Vec<u8>, kind: u16, body: &[u8]) {
    put_u16(v, kind);
    put_u16(v, body.len() as u16);
    v.extend_from_slice(body);
}

/// Builds a `ClientHello` record for `version` offering `suites`. SNI is added for DNS names.
/// The random is fixed-pattern but unique per call (no cryptographic use: the handshake is
/// never completed).
pub fn client_hello(version: TlsVersion, suites: &[u16], sni: Option<&str>) -> Vec<u8> {
    let mut body = Vec::with_capacity(160);
    put_u16(&mut body, version.wire());
    let seed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    for i in 0..32u64 {
        body.push((seed.rotate_left((i * 7) as u32) ^ (i * 0x9e)) as u8);
    }
    body.push(0); // session id
    put_u16(&mut body, (suites.len() * 2) as u16);
    for s in suites {
        put_u16(&mut body, *s);
    }
    body.extend_from_slice(&[1, 0]); // compression: null
    if version != TlsVersion::Ssl3 {
        let mut exts = Vec::new();
        if let Some(h) = sni.filter(|h| h.parse::<std::net::IpAddr>().is_err() && !h.is_empty()) {
            let h = h.as_bytes();
            let mut sn = Vec::new();
            put_u16(&mut sn, (h.len() + 3) as u16);
            sn.push(0);
            put_u16(&mut sn, h.len() as u16);
            sn.extend_from_slice(h);
            ext(&mut exts, 0x0000, &sn);
        }
        // supported_groups: x25519, secp256r1, secp384r1
        ext(&mut exts, 0x000a, &[0, 6, 0, 0x1d, 0, 0x17, 0, 0x18]);
        // ec_point_formats: uncompressed
        ext(&mut exts, 0x000b, &[1, 0]);
        if version == TlsVersion::Tls12 {
            // signature_algorithms: rsa_pkcs1_sha256/sha1, ecdsa_sha256/sha1, rsa_pss_sha256
            ext(
                &mut exts,
                0x000d,
                &[
                    0, 10, 0x04, 0x01, 0x02, 0x01, 0x04, 0x03, 0x02, 0x03, 0x08, 0x04,
                ],
            );
        }
        // renegotiation_info (empty)
        ext(&mut exts, 0xff01, &[0]);
        put_u16(&mut body, exts.len() as u16);
        body.extend_from_slice(&exts);
    }
    let mut hs = vec![1u8];
    hs.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
    hs.extend_from_slice(&body);
    // record layer version: TLS 1.0 for compatibility (SSLv3 for the SSLv3 probe)
    let rec_ver = if version == TlsVersion::Ssl3 {
        0x0300
    } else {
        0x0301
    };
    let mut rec = vec![22u8];
    put_u16(&mut rec, rec_ver);
    put_u16(&mut rec, hs.len() as u16);
    rec.extend_from_slice(&hs);
    rec
}

/// The server's answer to a `ClientHello`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HelloReply {
    ServerHello {
        version: u16,
        cipher: u16,
        /// Certificates from a clear-text `Certificate` message (TLS <= 1.2), leaf first.
        certs: Vec<Vec<u8>>,
    },
    Alert {
        level: u8,
        description: u8,
    },
    /// Not TLS (HTTP error page, garbage, SSLv2).
    Other,
}

/// Parses a server's first flight. Returns `None` while more bytes are needed (the
/// `ServerHello` is incomplete, or `want_certs` and neither `Certificate` nor `ServerHelloDone`
/// has arrived yet).
pub fn parse_server_flight(b: &[u8], want_certs: bool) -> Option<HelloReply> {
    let mut hs = Vec::new();
    let mut i = 0;
    while i + 5 <= b.len() {
        let ct = b[i];
        let len = u16::from_be_bytes([b[i + 3], b[i + 4]]) as usize;
        if !(20..=23).contains(&ct) || b[i + 1] != 3 {
            return Some(HelloReply::Other);
        }
        let Some(frag) = b.get(i + 5..i + 5 + len) else {
            break;
        };
        match ct {
            21 if frag.len() >= 2 && hs.is_empty() => {
                return Some(HelloReply::Alert {
                    level: frag[0],
                    description: frag[1],
                })
            }
            22 => hs.extend_from_slice(frag),
            _ => {}
        }
        i += 5 + len;
    }
    // walk handshake messages
    let mut hello: Option<(u16, u16)> = None;
    let mut certs = Vec::new();
    let mut done = false;
    let mut j = 0;
    while j + 4 <= hs.len() {
        let t = hs[j];
        let l = u32::from_be_bytes([0, hs[j + 1], hs[j + 2], hs[j + 3]]) as usize;
        let Some(m) = hs.get(j + 4..j + 4 + l) else {
            break;
        };
        match t {
            2 => {
                // version(2) random(32) sid_len(1) sid cipher(2)
                if m.len() < 38 {
                    return Some(HelloReply::Other);
                }
                let sid = m[34] as usize;
                let c = m.get(35 + sid..37 + sid)?;
                let mut version = u16::from_be_bytes([m[0], m[1]]);
                // TLS 1.3 servers put 0x0303 here and the real version in supported_versions;
                // a hello to a legacy-only offer never negotiates 1.3, so this is enough.
                if version > 0x0303 {
                    version = 0x0304;
                }
                hello = Some((version, u16::from_be_bytes([c[0], c[1]])));
            }
            11 => {
                let mut k = 3;
                while k + 3 <= m.len() {
                    let cl = u32::from_be_bytes([0, m[k], m[k + 1], m[k + 2]]) as usize;
                    let Some(c) = m.get(k + 3..k + 3 + cl) else {
                        break;
                    };
                    certs.push(c.to_vec());
                    k += 3 + cl;
                }
                done = true;
            }
            14 => done = true,
            _ => {}
        }
        j += 4 + l;
    }
    let (version, cipher) = hello?;
    if want_certs && !done && version <= 0x0303 && b.len() < MAX_FLIGHT {
        return None;
    }
    Some(HelloReply::ServerHello {
        version,
        cipher,
        certs,
    })
}

async fn read_flight<S: AsyncRead + Unpin>(
    s: &mut S,
    want_certs: bool,
    wait: Duration,
) -> Result<HelloReply, NetError> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    let fut = async {
        loop {
            let n = s.read(&mut chunk).await?;
            if n == 0 {
                // closed: answer with what we have
                return Ok::<_, NetError>(parse_server_flight(&buf, false).unwrap_or(
                    if buf.is_empty() {
                        HelloReply::Alert {
                            level: 2,
                            description: 0,
                        }
                    } else {
                        HelloReply::Other
                    },
                ));
            }
            buf.extend_from_slice(&chunk[..n]);
            if let Some(r) = parse_server_flight(&buf, want_certs) {
                return Ok(r);
            }
            if buf.len() >= MAX_FLIGHT {
                return Ok(parse_server_flight(&buf, false).unwrap_or(HelloReply::Other));
            }
        }
    };
    tokio::time::timeout(wait, fut)
        .await
        .map_err(|_| NetError::Timeout)?
}

/// Probe settings.
#[derive(Debug, Clone)]
pub struct LegacyConfig {
    /// Versions to test (default TLS 1.0 and 1.1; add `Ssl3` for very old gear).
    pub versions: Vec<TlsVersion>,
    /// Run the weak cipher probe (TLS 1.2 hello offering only weak suites).
    pub weak_ciphers: bool,
    /// Max weak cipher rounds: each accepted suite is removed and the probe repeated.
    pub weak_rounds: usize,
    /// Send SNI.
    pub sni: bool,
    /// Upgrade first (SMTP/IMAP/... legacy TLS audit).
    pub starttls: Option<StartTls>,
    pub timeout: Duration,
}

impl Default for LegacyConfig {
    fn default() -> Self {
        LegacyConfig {
            versions: vec![TlsVersion::Tls10, TlsVersion::Tls11],
            weak_ciphers: true,
            weak_rounds: 3,
            sni: true,
            starttls: None,
            timeout: Duration::from_secs(6),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VersionProbe {
    pub version: TlsVersion,
    pub supported: bool,
    /// Suite the server picked (when supported).
    pub cipher: Option<String>,
    /// TLS alert description (70 = protocol_version, 40 = handshake_failure, 0 = closed).
    pub alert: Option<u8>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WeakSuite {
    pub id: u16,
    pub name: String,
    pub class: WeakClass,
    /// Protocol version the server answered with.
    pub version: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LegacyReport {
    pub host: String,
    pub port: u16,
    pub versions: Vec<VersionProbe>,
    pub weak_suites: Vec<WeakSuite>,
    /// Certificates the server sent in clear during a legacy handshake (leaf first): a fallback
    /// for servers rustls cannot talk to.
    #[serde(skip)]
    pub certs: Vec<Vec<u8>>,
    pub issues: Vec<Issue>,
}

async fn one_hello(
    net: &NetClient,
    host: &str,
    port: u16,
    access: &Access,
    cfg: &LegacyConfig,
    hello: Vec<u8>,
    want_certs: bool,
) -> Result<HelloReply, NetError> {
    let (mut s, _) = crate::tcp::connect(net, MODULE, host, port, access, cfg.timeout).await?;
    if let Some(p) = cfg.starttls {
        net.cancellable(starttls::upgrade(&mut s, p, cfg.timeout))
            .await??;
    }
    let run = async {
        s.write_all(&hello).await?;
        s.flush().await?;
        read_flight(&mut s, want_certs, cfg.timeout).await
    };
    net.cancellable(run).await?
}

/// Active probe: which legacy versions the server still accepts, and which weak suites.
/// One TCP connection per hello (versions + up to `weak_rounds`), each logged as `tls-legacy`.
pub async fn probe_legacy(
    net: &NetClient,
    host: &str,
    port: u16,
    cfg: &LegacyConfig,
) -> Result<LegacyReport, NetError> {
    let access = Access::active("tls-legacy");
    refuse_passive(host, &access)?;
    let sni = cfg.sni.then_some(host);
    let mut rep = LegacyReport {
        host: host.to_string(),
        port,
        versions: Vec::new(),
        weak_suites: Vec::new(),
        certs: Vec::new(),
        issues: Vec::new(),
    };
    for &v in &cfg.versions {
        let hello = client_hello(v, LEGACY_SUITES, sni);
        let mut p = VersionProbe {
            version: v,
            supported: false,
            cipher: None,
            alert: None,
            error: None,
        };
        match one_hello(net, host, port, &access, cfg, hello, rep.certs.is_empty()).await {
            Ok(HelloReply::ServerHello {
                version,
                cipher,
                certs,
            }) => {
                p.supported = version == v.wire();
                if p.supported {
                    p.cipher = Some(suite_name(cipher));
                    if rep.certs.is_empty() {
                        rep.certs = certs;
                    }
                } else {
                    p.error = Some(format!("server answered 0x{version:04x}"));
                }
            }
            Ok(HelloReply::Alert { description, .. }) => p.alert = Some(description),
            Ok(HelloReply::Other) => p.error = Some("not a TLS reply".into()),
            // scope or phase denial: nothing else will pass either
            Err(e) if e.is_scope_denial() || matches!(e, NetError::Cancelled) => return Err(e),
            Err(e) => p.error = Some(e.to_string()),
        }
        if p.supported {
            let sev = if v == TlsVersion::Ssl3 {
                Severity::High
            } else {
                Severity::Medium
            };
            rep.issues.push(Issue::new(
                "tls_legacy_version",
                sev,
                format!("{}:{port} accepts {}", host, v.label()),
            ));
        }
        rep.versions.push(p);
    }
    if cfg.weak_ciphers {
        let mut offer: Vec<u16> = WEAK_SUITES.iter().map(|(i, _, _)| *i).collect();
        for _ in 0..cfg.weak_rounds.max(1) {
            if offer.is_empty() {
                break;
            }
            let hello = client_hello(TlsVersion::Tls12, &offer, sni);
            match one_hello(net, host, port, &access, cfg, hello, false).await {
                Ok(HelloReply::ServerHello {
                    version, cipher, ..
                }) => {
                    let Some(&(id, name, class)) =
                        WEAK_SUITES.iter().find(|(i, _, _)| *i == cipher)
                    else {
                        break; // the server ignored our list
                    };
                    offer.retain(|x| *x != id);
                    rep.weak_suites.push(WeakSuite {
                        id,
                        name: name.to_string(),
                        class,
                        version: TlsVersion::from_wire(version)
                            .map(|v| v.label().to_string())
                            .unwrap_or_else(|| format!("0x{version:04x}")),
                    });
                }
                Err(e) if e.is_scope_denial() || matches!(e, NetError::Cancelled) => return Err(e),
                _ => break,
            }
        }
        for w in &rep.weak_suites {
            let sev = match w.class {
                WeakClass::Null | WeakClass::Anon | WeakClass::Export => Severity::High,
                _ => Severity::Medium,
            };
            rep.issues.push(Issue::new(
                "tls_weak_cipher",
                sev,
                format!("{host}:{port} accepts {} ({})", w.name, w.version),
            ));
        }
    }
    Ok(rep)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hello_layout() {
        let h = client_hello(TlsVersion::Tls10, &[0x002f, 0x0035], Some("a.test"));
        assert_eq!(&h[..3], &[22, 3, 1]);
        assert_eq!(u16::from_be_bytes([h[3], h[4]]) as usize, h.len() - 5);
        assert_eq!(h[5], 1);
        assert_eq!(&h[9..11], &[3, 1]);
        assert!(h.windows(6).any(|w| w == b"a.test"));
        assert!(h.len() < 200, "{}", h.len());
        let ip = client_hello(TlsVersion::Tls11, &[0x002f], Some("10.0.0.1"));
        assert!(!ip.windows(8).any(|w| w == b"10.0.0.1"), "no SNI for IPs");
        let s3 = client_hello(TlsVersion::Ssl3, &[0x000a], None);
        assert_eq!(&s3[1..3], &[3, 0]);
    }

    fn server_hello(version: u16, cipher: u16) -> Vec<u8> {
        let mut m = version.to_be_bytes().to_vec();
        m.extend_from_slice(&[0u8; 32]);
        m.push(0);
        m.extend_from_slice(&cipher.to_be_bytes());
        m.push(0);
        let mut hs = vec![2, 0, 0, m.len() as u8];
        hs.extend_from_slice(&m);
        let mut r = vec![22, 3, 1, 0, hs.len() as u8];
        r.extend_from_slice(&hs);
        r
    }

    #[test]
    fn flight_parsing() {
        let sh = server_hello(0x0301, 0x002f);
        assert_eq!(
            parse_server_flight(&sh, false),
            Some(HelloReply::ServerHello {
                version: 0x0301,
                cipher: 0x002f,
                certs: vec![]
            })
        );
        assert_eq!(
            parse_server_flight(&sh, true),
            None,
            "waits for certificate"
        );
        assert_eq!(parse_server_flight(&sh[..20], false), None);
        assert_eq!(
            parse_server_flight(&[21, 3, 1, 0, 2, 2, 70], false),
            Some(HelloReply::Alert {
                level: 2,
                description: 70
            })
        );
        assert_eq!(
            parse_server_flight(b"HTTP/1.1 400 Bad Request\r\n", false),
            Some(HelloReply::Other)
        );
        assert_eq!(suite_name(0x0005), "TLS_RSA_WITH_RC4_128_SHA");
        assert_eq!(suite_name(0x1301), "0x1301");
    }
}
