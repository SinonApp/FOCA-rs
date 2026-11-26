//! Certificate and chain audit. No network: the caller passes the chain from a handshake and,
//! for CAA, the DNS records it already resolved.

use std::sync::{Arc, OnceLock};
use std::time::Duration;

use foca_core::Severity;
use serde::{Deserialize, Serialize};
use tokio_rustls::rustls::client::danger::ServerCertVerifier;
use tokio_rustls::rustls::client::WebPkiServerVerifier;
use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use tokio_rustls::rustls::{CertificateError, Error as TlsError, RootCertStore};

use super::x509::{parse_cert, CertInfo};
use super::Issue;
use crate::NetError;

const DAY: i64 = 86_400;

/// Audit settings.
#[derive(Debug, Clone)]
pub struct AuditConfig {
    /// "Now", Unix seconds (injectable for tests and for re-auditing stored chains).
    pub now: i64,
    /// Expiry warning thresholds in days: `<= crit_days` is Medium, `<= warn_days` is Low.
    pub crit_days: i64,
    pub warn_days: i64,
    /// Trust the Mozilla root set (webpki-roots). Disable to audit against `extra_roots` only.
    pub public_roots: bool,
    /// Additional trust anchors (DER), e.g. a corporate root supplied by the user.
    pub extra_roots: Vec<Vec<u8>>,
}

impl Default for AuditConfig {
    fn default() -> Self {
        AuditConfig {
            now: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0),
            crit_days: 14,
            warn_days: 30,
            public_roots: true,
            extra_roots: Vec::new(),
        }
    }
}

/// Chain trust verdict.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "status", content = "detail")]
pub enum TrustStatus {
    /// Chains to a trusted root (validity checked at a moment inside the leaf validity window, so
    /// expiry is reported separately).
    Trusted,
    /// The leaf is self-signed and not a trust anchor.
    SelfSigned,
    /// The chain ends in an unknown (usually private) CA.
    UnknownCa,
    /// The server omitted an intermediate: the top of the presented chain is not self-signed and
    /// carries an AIA `caIssuers` URL a browser could fetch. A heuristic.
    IncompleteChain,
    /// Any other verification failure (bad signature, wrong key usage, ...).
    Invalid(String),
}

/// Result of [`audit_chain`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CertAudit {
    pub leaf: CertInfo,
    pub trust: TrustStatus,
    /// `None` when no host was given.
    pub hostname_match: Option<bool>,
    /// Days until expiry (negative when expired).
    pub days_left: i64,
    pub issues: Vec<Issue>,
}

fn public_roots() -> Arc<RootCertStore> {
    static R: OnceLock<Arc<RootCertStore>> = OnceLock::new();
    R.get_or_init(|| {
        Arc::new(RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
        })
    })
    .clone()
}

fn roots(cfg: &AuditConfig) -> Arc<RootCertStore> {
    if cfg.extra_roots.is_empty() && cfg.public_roots {
        return public_roots();
    }
    let mut s = if cfg.public_roots {
        (*public_roots()).clone()
    } else {
        RootCertStore::empty()
    };
    for r in &cfg.extra_roots {
        let _ = s.add(CertificateDer::from(r.clone()));
    }
    Arc::new(s)
}

/// A server name the leaf is valid for, so the chain check does not fail on the name (hostname
/// match is audited separately).
fn verify_name(leaf: &CertInfo, host: Option<&str>) -> ServerName<'static> {
    let candidates = host
        .map(str::to_string)
        .into_iter()
        .chain(leaf.san_dns.iter().map(|n| n.replacen("*.", "x.", 1)))
        .chain(leaf.san_ip.iter().cloned())
        .chain(leaf.subject.cn.clone());
    for c in candidates {
        if let Ok(n) = ServerName::try_from(c) {
            return n;
        }
    }
    ServerName::try_from("invalid.invalid").expect("static name")
}

fn chain_trust(
    chain: &[Vec<u8>],
    infos: &[CertInfo],
    host: Option<&str>,
    cfg: &AuditConfig,
) -> TrustStatus {
    let leaf = &infos[0];
    let prov = Arc::new(tokio_rustls::rustls::crypto::ring::default_provider());
    let verifier = match WebPkiServerVerifier::builder_with_provider(roots(cfg), prov).build() {
        Ok(v) => v,
        Err(_) => {
            // No anchors at all (public roots disabled, no extra roots).
            return if leaf.is_self_signed() {
                TrustStatus::SelfSigned
            } else {
                TrustStatus::UnknownCa
            };
        }
    };
    // Check the chain at a moment inside the leaf validity window: expiry is its own issue.
    let at = cfg
        .now
        .clamp(
            leaf.not_before + 1,
            (leaf.not_after - 1).max(leaf.not_before + 1),
        )
        .max(0);
    let end = CertificateDer::from(chain[0].clone());
    let inter: Vec<CertificateDer<'static>> = chain[1..]
        .iter()
        .map(|c| CertificateDer::from(c.clone()))
        .collect();
    let name = verify_name(leaf, host);
    let res = verifier.verify_server_cert(
        &end,
        &inter,
        &name,
        &[],
        UnixTime::since_unix_epoch(Duration::from_secs(at as u64)),
    );
    match res {
        Ok(_) => TrustStatus::Trusted,
        Err(TlsError::InvalidCertificate(e)) => match e {
            CertificateError::NotValidForName | CertificateError::NotValidForNameContext { .. } => {
                TrustStatus::Trusted
            }
            CertificateError::UnknownIssuer => {
                let top = infos.last().unwrap_or(leaf);
                if infos.len() == 1 && leaf.is_self_signed() {
                    TrustStatus::SelfSigned
                } else if top.is_self_signed() {
                    TrustStatus::UnknownCa
                } else if top
                    .ca_issuer_urls
                    .iter()
                    .any(|u| u.starts_with("http://") || u.starts_with("https://"))
                {
                    TrustStatus::IncompleteChain
                } else {
                    TrustStatus::UnknownCa
                }
            }
            other => TrustStatus::Invalid(format!("{other:?}")),
        },
        Err(e) => TrustStatus::Invalid(e.to_string()),
    }
}

/// Audits a presented chain (leaf first). `host` is the name the client asked for (SNI or the
/// IP); `None` skips the hostname check.
pub fn audit_chain(
    chain: &[Vec<u8>],
    host: Option<&str>,
    cfg: &AuditConfig,
) -> Result<CertAudit, NetError> {
    if chain.is_empty() {
        return Err(NetError::Parse("empty certificate chain".into()));
    }
    let leaf = parse_cert(&chain[0])?;
    // Intermediates that fail to parse are ignored for the heuristics but still go to webpki.
    let mut infos = vec![leaf.clone()];
    infos.extend(chain[1..].iter().filter_map(|c| parse_cert(c).ok()));
    let trust = chain_trust(chain, &infos, host, cfg);
    let days_left = (leaf.not_after - cfg.now).div_euclid(DAY);
    let mut issues = Vec::new();
    if cfg.now > leaf.not_after {
        issues.push(Issue::new(
            "cert_expired",
            Severity::High,
            format!("expired {} days ago", -days_left),
        ));
    } else if cfg.now < leaf.not_before {
        issues.push(Issue::new(
            "cert_not_yet_valid",
            Severity::Medium,
            "validity starts in the future",
        ));
    } else if days_left < cfg.crit_days {
        issues.push(Issue::new(
            "cert_expires_soon",
            Severity::Medium,
            format!("expires in {days_left} days (< {})", cfg.crit_days),
        ));
    } else if days_left < cfg.warn_days {
        issues.push(Issue::new(
            "cert_expires_soon",
            Severity::Low,
            format!("expires in {days_left} days (< {})", cfg.warn_days),
        ));
    }
    match &trust {
        TrustStatus::Trusted => {}
        TrustStatus::SelfSigned => issues.push(Issue::new(
            "cert_self_signed",
            Severity::Medium,
            leaf.subject.text.clone(),
        )),
        TrustStatus::UnknownCa => issues.push(Issue::new(
            "cert_unknown_ca",
            Severity::Medium,
            format!("issuer: {}", leaf.issuer.text),
        )),
        TrustStatus::IncompleteChain => issues.push(Issue::new(
            "cert_incomplete_chain",
            Severity::Low,
            format!("missing intermediate for {}", leaf.issuer.text),
        )),
        TrustStatus::Invalid(e) => issues.push(Issue::new(
            "cert_invalid_chain",
            Severity::Medium,
            e.clone(),
        )),
    }
    let hostname_match = host.map(|h| leaf.matches_host(h));
    if hostname_match == Some(false) {
        issues.push(Issue::new(
            "cert_hostname_mismatch",
            Severity::Medium,
            format!(
                "{} not in [{}]",
                host.unwrap_or(""),
                leaf.names().join(", ")
            ),
        ));
    }
    match leaf.sig_hash.as_str() {
        "md2" | "md5" => issues.push(Issue::new(
            "cert_weak_signature",
            Severity::High,
            leaf.sig_alg.clone(),
        )),
        "sha1" => issues.push(Issue::new(
            "cert_weak_signature",
            Severity::Medium,
            leaf.sig_alg.clone(),
        )),
        _ => {}
    }
    let weak_key = match leaf.key_type.as_str() {
        "RSA" | "DSA" => leaf.key_bits < 2048,
        "EC" => leaf.key_bits > 0 && leaf.key_bits < 224,
        _ => false,
    };
    if weak_key {
        let sev = if leaf.key_bits < 1024 {
            Severity::High
        } else {
            Severity::Medium
        };
        issues.push(Issue::new(
            "cert_weak_key",
            sev,
            format!("{} {} bits", leaf.key_type, leaf.key_bits),
        ));
    }
    Ok(CertAudit {
        leaf,
        trust,
        hostname_match,
        days_left,
        issues,
    })
}

/// Issues from the handshake itself (not the certificate).
pub fn handshake_issues(alpn: Option<&str>, ocsp_stapled: bool, trusted: bool) -> Vec<Issue> {
    let mut v = Vec::new();
    if trusted && !ocsp_stapled {
        v.push(Issue::new(
            "tls_no_ocsp_stapling",
            Severity::Info,
            "the server does not staple an OCSP response",
        ));
    }
    if alpn.is_none() {
        v.push(Issue::new(
            "tls_no_alpn",
            Severity::Info,
            "no ALPN protocol negotiated (no HTTP/2)",
        ));
    }
    v
}

/// CAA verdict for an issued certificate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "status")]
pub enum CaaCheck {
    /// No `issue`/`issuewild` records: any CA may issue.
    NoPolicy,
    /// The issuing CA is allowed.
    Allowed { ca_domain: String },
    /// The issuer is a known CA that the CAA records do not list.
    Mismatch {
        allowed: Vec<String>,
        issuer_domains: Vec<String>,
    },
    /// The issuer is not in the built-in CA table (private CA, or a CA we do not know).
    UnknownIssuer { allowed: Vec<String> },
}

/// Issuer organization substrings mapped to the CAA identifier domains the CA uses.
const CA_DOMAINS: &[(&str, &[&str])] = &[
    ("let's encrypt", &["letsencrypt.org"]),
    ("internet security research group", &["letsencrypt.org"]),
    (
        "digicert",
        &[
            "digicert.com",
            "www.digicert.com",
            "symantec.com",
            "geotrust.com",
            "thawte.com",
            "rapidssl.com",
        ],
    ),
    (
        "sectigo",
        &[
            "sectigo.com",
            "comodoca.com",
            "comodo.com",
            "trust-provider.com",
            "usertrust.com",
        ],
    ),
    ("comodo", &["comodoca.com", "comodo.com", "sectigo.com"]),
    ("google trust services", &["pki.goog", "google.com"]),
    (
        "amazon",
        &[
            "amazon.com",
            "amazontrust.com",
            "awstrust.com",
            "amazonaws.com",
        ],
    ),
    ("globalsign", &["globalsign.com"]),
    ("godaddy", &["godaddy.com", "starfieldtech.com"]),
    ("starfield", &["starfieldtech.com", "godaddy.com"]),
    ("entrust", &["entrust.net", "affirmtrust.com"]),
    ("zerossl", &["zerossl.com", "sectigo.com"]),
    ("microsoft", &["microsoft.com"]),
    ("buypass", &["buypass.com", "buypass.no"]),
    ("ssl corporation", &["ssl.com"]),
    ("ssl.com", &["ssl.com"]),
    ("certum", &["certum.pl", "certum.eu"]),
    ("asseco", &["certum.pl"]),
    ("actalis", &["actalis.it"]),
    ("harica", &["harica.gr"]),
    ("telia", &["telia.com", "teliasonera.com"]),
    ("identrust", &["identrust.com", "letsencrypt.org"]),
    (
        "cloudflare",
        &["digicert.com", "letsencrypt.org", "pki.goog", "ssl.com"],
    ),
];

/// Parses CAA record strings (`0 issue "letsencrypt.org"`, `issuewild "pki.goog; cansignhttpexchanges=yes"`)
/// into the allowed CA domains for `issue` (or `issuewild` when `wildcard`). An empty value
/// (`issue ";"`) forbids issuance and yields an empty domain.
fn caa_allowed(records: &[String], wildcard: bool) -> Option<Vec<String>> {
    let mut issue = Vec::new();
    let mut wild = Vec::new();
    for r in records {
        let mut it = r.split_whitespace().peekable();
        if it
            .peek()
            .is_some_and(|t| t.chars().all(|c| c.is_ascii_digit()))
        {
            it.next();
        }
        let Some(tag) = it.next() else { continue };
        let value: String = it.collect::<Vec<_>>().join(" ");
        let value = value.trim().trim_matches('"');
        let domain = value
            .split(';')
            .next()
            .unwrap_or("")
            .trim()
            .to_ascii_lowercase();
        match tag.to_ascii_lowercase().as_str() {
            "issue" => issue.push(domain),
            "issuewild" => wild.push(domain),
            _ => {}
        }
    }
    let set = if wildcard && !wild.is_empty() {
        wild
    } else {
        issue
    };
    (!set.is_empty()).then_some(set)
}

/// Checks the issuing CA against the CAA records of the name (the caller climbs the DNS tree
/// to the closest CAA RRset, RFC 8659).
pub fn check_caa(records: &[String], leaf: &CertInfo, wildcard: bool) -> CaaCheck {
    let Some(allowed) = caa_allowed(records, wildcard) else {
        return CaaCheck::NoPolicy;
    };
    let issuer = format!(
        "{} {}",
        leaf.issuer.o.as_deref().unwrap_or(""),
        leaf.issuer.cn.as_deref().unwrap_or("")
    )
    .to_ascii_lowercase();
    let issuer_domains: Vec<String> = CA_DOMAINS
        .iter()
        .filter(|(k, _)| issuer.contains(k))
        .flat_map(|(_, d)| d.iter().map(|s| s.to_string()))
        .collect();
    if issuer_domains.is_empty() {
        return CaaCheck::UnknownIssuer { allowed };
    }
    match allowed.iter().find(|a| issuer_domains.contains(a)) {
        Some(a) => CaaCheck::Allowed {
            ca_domain: a.clone(),
        },
        None => CaaCheck::Mismatch {
            allowed,
            issuer_domains,
        },
    }
}

impl CaaCheck {
    pub fn issue(&self) -> Option<Issue> {
        match self {
            CaaCheck::Mismatch {
                allowed,
                issuer_domains,
            } => Some(Issue::new(
                "cert_caa_mismatch",
                Severity::Low,
                format!(
                    "CAA allows [{}], issuer is [{}]",
                    allowed.join(", "),
                    issuer_domains.join(", ")
                ),
            )),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROOT: &[u8] = include_bytes!("../../tests/fixtures/tls/root.der");
    const INT: &[u8] = include_bytes!("../../tests/fixtures/tls/int.der");
    const GOOD: &[u8] = include_bytes!("../../tests/fixtures/tls/good.der");
    const EXPIRED: &[u8] = include_bytes!("../../tests/fixtures/tls/expired.der");
    const SELF: &[u8] = include_bytes!("../../tests/fixtures/tls/self.der");
    const WEAK: &[u8] = include_bytes!("../../tests/fixtures/tls/weak.der");

    // 2026-06-01
    const NOW: i64 = 1_780_272_000;

    fn cfg(roots: bool) -> AuditConfig {
        AuditConfig {
            now: NOW,
            extra_roots: if roots { vec![ROOT.to_vec()] } else { vec![] },
            ..Default::default()
        }
    }

    fn codes(a: &CertAudit) -> Vec<&str> {
        a.issues.iter().map(|i| i.code.as_str()).collect()
    }

    #[test]
    fn trusted_chain() {
        let a = audit_chain(
            &[GOOD.to_vec(), INT.to_vec()],
            Some("www.good.test"),
            &cfg(true),
        )
        .unwrap();
        assert_eq!(a.trust, TrustStatus::Trusted);
        assert_eq!(a.hostname_match, Some(true));
        assert!(a.issues.is_empty(), "{:?}", a.issues);
        let m = audit_chain(
            &[GOOD.to_vec(), INT.to_vec()],
            Some("other.test"),
            &cfg(true),
        )
        .unwrap();
        assert_eq!(m.trust, TrustStatus::Trusted);
        assert_eq!(codes(&m), vec!["cert_hostname_mismatch"]);
    }

    #[test]
    fn chain_problems() {
        // the issuing CA was not sent; the leaf carries an http caIssuers URL
        let a = audit_chain(&[GOOD.to_vec()], Some("good.test"), &cfg(true)).unwrap();
        assert_eq!(a.trust, TrustStatus::IncompleteChain);
        assert_eq!(codes(&a), vec!["cert_incomplete_chain"]);
        // private root not trusted
        let a = audit_chain(&[GOOD.to_vec(), INT.to_vec()], None, &cfg(false)).unwrap();
        assert_eq!(a.trust, TrustStatus::UnknownCa);
        let a = audit_chain(
            &[GOOD.to_vec(), INT.to_vec(), ROOT.to_vec()],
            None,
            &cfg(false),
        )
        .unwrap();
        assert_eq!(a.trust, TrustStatus::UnknownCa);
        let a = audit_chain(&[SELF.to_vec()], Some("self.test"), &cfg(true)).unwrap();
        assert_eq!(a.trust, TrustStatus::SelfSigned);
        assert_eq!(codes(&a), vec!["cert_self_signed"]);
        assert!(audit_chain(&[], None, &cfg(true)).is_err());
    }

    #[test]
    fn expiry() {
        let a = audit_chain(
            &[EXPIRED.to_vec(), INT.to_vec()],
            Some("expired.test"),
            &cfg(true),
        )
        .unwrap();
        assert_eq!(
            a.trust,
            TrustStatus::Trusted,
            "expiry is not a trust failure"
        );
        assert!(a.days_left < -300);
        assert_eq!(codes(&a), vec!["cert_expired"]);
        assert_eq!(a.issues[0].severity, Severity::High);
        let leaf = parse_cert(GOOD).unwrap();
        for (days, sev) in [(10, Severity::Medium), (20, Severity::Low)] {
            let c = AuditConfig {
                now: leaf.not_after - days * DAY - 60,
                ..cfg(true)
            };
            let a = audit_chain(&[GOOD.to_vec(), INT.to_vec()], None, &c).unwrap();
            assert_eq!(codes(&a), vec!["cert_expires_soon"]);
            assert_eq!(a.issues[0].severity, sev);
        }
        let c = AuditConfig {
            now: leaf.not_before - DAY,
            ..cfg(true)
        };
        let a = audit_chain(&[GOOD.to_vec(), INT.to_vec()], None, &c).unwrap();
        assert_eq!(codes(&a), vec!["cert_not_yet_valid"]);
    }

    #[test]
    fn weak_certificate() {
        let a = audit_chain(&[WEAK.to_vec()], Some("weak.test"), &cfg(true)).unwrap();
        assert_eq!(a.trust, TrustStatus::SelfSigned);
        assert_eq!(
            codes(&a),
            vec![
                "cert_self_signed",
                "cert_hostname_mismatch",
                "cert_weak_signature",
                "cert_weak_key"
            ]
        );
    }

    #[test]
    fn caa() {
        let mut leaf = parse_cert(GOOD).unwrap();
        assert_eq!(check_caa(&[], &leaf, false), CaaCheck::NoPolicy);
        let recs = vec![
            "0 issue \"letsencrypt.org\"".to_string(),
            "0 iodef \"mailto:sec@a.test\"".to_string(),
            "0 issuewild \"pki.goog; cansignhttpexchanges=yes\"".to_string(),
        ];
        assert!(matches!(
            check_caa(&recs, &leaf, false),
            CaaCheck::UnknownIssuer { .. }
        ));
        leaf.issuer.o = Some("Let's Encrypt".into());
        assert_eq!(
            check_caa(&recs, &leaf, false),
            CaaCheck::Allowed {
                ca_domain: "letsencrypt.org".into()
            }
        );
        let m = check_caa(&recs, &leaf, true);
        assert!(matches!(m, CaaCheck::Mismatch { .. }));
        assert_eq!(m.issue().unwrap().code, "cert_caa_mismatch");
        leaf.issuer.o = Some("Google Trust Services".into());
        assert!(matches!(
            check_caa(&recs, &leaf, true),
            CaaCheck::Allowed { .. }
        ));
        assert!(matches!(
            check_caa(&["issue \";\"".to_string()], &leaf, false),
            CaaCheck::Mismatch { .. }
        ));
    }

    #[test]
    fn handshake_level() {
        let v = handshake_issues(None, false, true);
        assert_eq!(v.len(), 2);
        assert!(handshake_issues(Some("h2"), false, false).is_empty());
    }
}
