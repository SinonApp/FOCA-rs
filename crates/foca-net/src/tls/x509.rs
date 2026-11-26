//! X.509 certificate parsing: names, SAN, fingerprints, key and signature algorithms, and the
//! CRL/AIA URLs that often leak internal PKI hosts and Active Directory paths. No network.

use std::net::IpAddr;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use x509_parser::extensions::{DistributionPointName, GeneralName, ParsedExtension};
use x509_parser::prelude::{FromDer, X509Certificate, X509Name};
use x509_parser::public_key::PublicKey;

use super::hex;
use crate::NetError;

const OID_OCSP: &str = "1.3.6.1.5.5.7.48.1";
const OID_CA_ISSUERS: &str = "1.3.6.1.5.5.7.48.2";

/// Distinguished name fields (first value of each attribute; OU may repeat).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnInfo {
    pub cn: Option<String>,
    pub o: Option<String>,
    #[serde(default)]
    pub ou: Vec<String>,
    pub l: Option<String>,
    pub st: Option<String>,
    pub c: Option<String>,
    pub email: Option<String>,
    /// RFC 4514-like rendering of the whole name.
    pub text: String,
}

/// Parsed certificate metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CertInfo {
    pub subject: DnInfo,
    pub issuer: DnInfo,
    /// Serial number, lowercase hex.
    pub serial: String,
    /// Validity bounds, Unix seconds.
    pub not_before: i64,
    pub not_after: i64,
    pub san_dns: Vec<String>,
    pub san_ip: Vec<String>,
    pub san_email: Vec<String>,
    pub san_uri: Vec<String>,
    /// SHA-256 of the whole certificate DER (the usual "fingerprint").
    pub sha256: String,
    /// SHA-256 of the SubjectPublicKeyInfo DER: stable across renewals with the same key, used to
    /// cluster servers.
    pub spki_sha256: String,
    /// Signature algorithm name (`sha256WithRSAEncryption`, `ecdsa-with-SHA256`, ...) or its OID.
    pub sig_alg: String,
    /// Digest of the signature algorithm: `md2`, `md5`, `sha1`, `sha256`, ... or `unknown`.
    pub sig_hash: String,
    /// `RSA`, `EC`, `DSA`, `Ed25519`, `Ed448` or `unknown`.
    pub key_type: String,
    pub key_bits: u32,
    pub is_ca: bool,
    /// Subject equals issuer (byte-wise); with a matching key id this is a self-signed certificate.
    pub self_issued: bool,
    pub ski: Option<String>,
    pub aki: Option<String>,
    pub crl_urls: Vec<String>,
    pub ocsp_urls: Vec<String>,
    pub ca_issuer_urls: Vec<String>,
}

fn attr(name: &X509Name<'_>, it: &str) -> Vec<String> {
    let vals: Vec<String> = match it {
        "cn" => name
            .iter_common_name()
            .filter_map(|a| a.as_str().ok())
            .map(str::to_string)
            .collect(),
        "o" => name
            .iter_organization()
            .filter_map(|a| a.as_str().ok())
            .map(str::to_string)
            .collect(),
        "ou" => name
            .iter_organizational_unit()
            .filter_map(|a| a.as_str().ok())
            .map(str::to_string)
            .collect(),
        "l" => name
            .iter_locality()
            .filter_map(|a| a.as_str().ok())
            .map(str::to_string)
            .collect(),
        "st" => name
            .iter_state_or_province()
            .filter_map(|a| a.as_str().ok())
            .map(str::to_string)
            .collect(),
        "c" => name
            .iter_country()
            .filter_map(|a| a.as_str().ok())
            .map(str::to_string)
            .collect(),
        _ => name
            .iter_email()
            .filter_map(|a| a.as_str().ok())
            .map(str::to_string)
            .collect(),
    };
    vals.into_iter()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
        .collect()
}

fn dn(name: &X509Name<'_>) -> DnInfo {
    let first = |k: &str| attr(name, k).into_iter().next();
    DnInfo {
        cn: first("cn"),
        o: first("o"),
        ou: attr(name, "ou"),
        l: first("l"),
        st: first("st"),
        c: first("c"),
        email: first("email"),
        text: name.to_string(),
    }
}

fn sig_name(oid: &str) -> (&'static str, &'static str) {
    match oid {
        "1.2.840.113549.1.1.2" => ("md2WithRSAEncryption", "md2"),
        "1.2.840.113549.1.1.4" => ("md5WithRSAEncryption", "md5"),
        "1.2.840.113549.1.1.5" => ("sha1WithRSAEncryption", "sha1"),
        "1.2.840.113549.1.1.10" => ("rsassaPss", "pss"),
        "1.2.840.113549.1.1.11" => ("sha256WithRSAEncryption", "sha256"),
        "1.2.840.113549.1.1.12" => ("sha384WithRSAEncryption", "sha384"),
        "1.2.840.113549.1.1.13" => ("sha512WithRSAEncryption", "sha512"),
        "1.2.840.113549.1.1.14" => ("sha224WithRSAEncryption", "sha224"),
        "1.2.840.10045.4.1" => ("ecdsa-with-SHA1", "sha1"),
        "1.2.840.10045.4.3.1" => ("ecdsa-with-SHA224", "sha224"),
        "1.2.840.10045.4.3.2" => ("ecdsa-with-SHA256", "sha256"),
        "1.2.840.10045.4.3.3" => ("ecdsa-with-SHA384", "sha384"),
        "1.2.840.10045.4.3.4" => ("ecdsa-with-SHA512", "sha512"),
        "1.2.840.10040.4.3" => ("dsa-with-sha1", "sha1"),
        "2.16.840.1.101.3.4.3.2" => ("dsa-with-sha256", "sha256"),
        "1.3.101.112" => ("Ed25519", "sha512"),
        "1.3.101.113" => ("Ed448", "shake256"),
        "1.2.643.7.1.1.3.2" => ("GOST R 34.10-2012-256", "streebog256"),
        "1.2.643.7.1.1.3.3" => ("GOST R 34.10-2012-512", "streebog512"),
        _ => ("", "unknown"),
    }
}

fn general_name_str(g: &GeneralName<'_>) -> Option<String> {
    match g {
        GeneralName::URI(u) => Some(u.to_string()),
        GeneralName::DNSName(d) => Some(d.to_string()),
        GeneralName::RFC822Name(e) => Some(e.to_string()),
        GeneralName::DirectoryName(n) => Some(n.to_string()),
        GeneralName::IPAddress(b) => ip_from_bytes(b).map(|i| i.to_string()),
        _ => None,
    }
}

fn ip_from_bytes(b: &[u8]) -> Option<IpAddr> {
    match b.len() {
        4 => Some(IpAddr::from(<[u8; 4]>::try_from(b).ok()?)),
        16 => Some(IpAddr::from(<[u8; 16]>::try_from(b).ok()?)),
        _ => None,
    }
}

/// SHA-256 of `b`, lowercase hex.
pub fn sha256_hex(b: &[u8]) -> String {
    hex(&Sha256::digest(b))
}

fn push_unique(v: &mut Vec<String>, s: String) {
    if !s.is_empty() && !v.contains(&s) {
        v.push(s);
    }
}

/// Parses a DER certificate.
pub fn parse_cert(der: &[u8]) -> Result<CertInfo, NetError> {
    let (_, c) =
        X509Certificate::from_der(der).map_err(|e| NetError::Parse(format!("x509: {e}")))?;
    let oid = c.signature_algorithm.algorithm.to_id_string();
    let (name, hash) = sig_name(&oid);
    let spki = c.public_key();
    let key_oid = spki.algorithm.algorithm.to_id_string();
    let (key_type, key_bits) = match spki.parsed() {
        Ok(PublicKey::RSA(k)) => ("RSA", k.key_size()),
        Ok(PublicKey::EC(k)) => ("EC", k.key_size()),
        Ok(PublicKey::DSA(k)) => ("DSA", k.len() * 8),
        _ => match key_oid.as_str() {
            "1.3.101.112" => ("Ed25519", 256),
            "1.3.101.113" => ("Ed448", 456),
            _ => ("unknown", 0),
        },
    };
    let mut info = CertInfo {
        subject: dn(c.subject()),
        issuer: dn(c.issuer()),
        serial: hex(c.raw_serial()),
        not_before: c.validity().not_before.timestamp(),
        not_after: c.validity().not_after.timestamp(),
        san_dns: Vec::new(),
        san_ip: Vec::new(),
        san_email: Vec::new(),
        san_uri: Vec::new(),
        sha256: sha256_hex(der),
        spki_sha256: sha256_hex(spki.raw),
        sig_alg: if name.is_empty() {
            oid.clone()
        } else {
            name.to_string()
        },
        sig_hash: hash.to_string(),
        key_type: key_type.to_string(),
        key_bits: key_bits as u32,
        is_ca: c.is_ca(),
        self_issued: c.subject().as_raw() == c.issuer().as_raw(),
        ski: None,
        aki: None,
        crl_urls: Vec::new(),
        ocsp_urls: Vec::new(),
        ca_issuer_urls: Vec::new(),
    };
    for ext in c.extensions() {
        match ext.parsed_extension() {
            ParsedExtension::SubjectAlternativeName(san) => {
                for g in &san.general_names {
                    match g {
                        GeneralName::DNSName(d) => {
                            push_unique(&mut info.san_dns, d.trim().to_ascii_lowercase())
                        }
                        GeneralName::IPAddress(b) => {
                            if let Some(ip) = ip_from_bytes(b) {
                                push_unique(&mut info.san_ip, ip.to_string());
                            }
                        }
                        GeneralName::RFC822Name(e) => {
                            push_unique(&mut info.san_email, e.to_string())
                        }
                        GeneralName::URI(u) => push_unique(&mut info.san_uri, u.to_string()),
                        _ => {}
                    }
                }
            }
            ParsedExtension::CRLDistributionPoints(cdp) => {
                for p in cdp.iter() {
                    if let Some(DistributionPointName::FullName(names)) = &p.distribution_point {
                        for g in names {
                            if let Some(s) = general_name_str(g) {
                                push_unique(&mut info.crl_urls, s);
                            }
                        }
                    }
                }
            }
            ParsedExtension::AuthorityInfoAccess(aia) => {
                for d in &aia.accessdescs {
                    let Some(s) = general_name_str(&d.access_location) else {
                        continue;
                    };
                    match d.access_method.to_id_string().as_str() {
                        OID_OCSP => push_unique(&mut info.ocsp_urls, s),
                        OID_CA_ISSUERS => push_unique(&mut info.ca_issuer_urls, s),
                        _ => {}
                    }
                }
            }
            ParsedExtension::SubjectKeyIdentifier(k) => info.ski = Some(hex(k.0)),
            ParsedExtension::AuthorityKeyIdentifier(a) => {
                info.aki = a.key_identifier.as_ref().map(|k| hex(k.0))
            }
            _ => {}
        }
    }
    Ok(info)
}

impl CertInfo {
    /// Self-signed: subject equals issuer and the key identifiers (when present) agree.
    pub fn is_self_signed(&self) -> bool {
        self.self_issued
            && match (&self.ski, &self.aki) {
                (Some(s), Some(a)) => s == a,
                _ => true,
            }
    }

    /// Names the certificate is valid for: SAN DNS and IP entries, or the subject CN when the
    /// certificate has no SAN (legacy behaviour, still seen on appliances).
    pub fn names(&self) -> Vec<String> {
        let mut v: Vec<String> = self
            .san_dns
            .iter()
            .chain(self.san_ip.iter())
            .cloned()
            .collect();
        if v.is_empty() {
            if let Some(cn) = &self.subject.cn {
                v.push(cn.to_ascii_lowercase());
            }
        }
        v
    }

    /// Checks `host` (DNS name or IP literal) against the certificate names (RFC 6125: the
    /// wildcard covers exactly one leftmost label).
    pub fn matches_host(&self, host: &str) -> bool {
        let h = host
            .trim()
            .trim_end_matches('.')
            .trim_start_matches('[')
            .trim_end_matches(']')
            .to_ascii_lowercase();
        if let Ok(ip) = h.parse::<IpAddr>() {
            return self
                .san_ip
                .iter()
                .any(|s| s.parse::<IpAddr>().ok() == Some(ip));
        }
        self.names().iter().any(|n| name_matches(n, &h))
    }

    /// Ready-made pivot queries for search engines that index certificates (opened by the user,
    /// never fetched by the inspector).
    pub fn pivot_queries(&self) -> Vec<(String, String)> {
        let mut v = vec![
            (
                "shodan".to_string(),
                format!("ssl.cert.fingerprint:{}", self.sha256),
            ),
            (
                "censys".to_string(),
                format!(
                    "services.tls.certificates.leaf_data.fingerprint: {}",
                    self.sha256
                ),
            ),
            (
                "crtsh".to_string(),
                format!("https://crt.sh/?q={}", self.sha256),
            ),
            (
                "crtsh_spki".to_string(),
                format!("https://crt.sh/?spkisha256={}", self.spki_sha256),
            ),
        ];
        if let Some(o) = &self.subject.o {
            v.push((
                "shodan_org".to_string(),
                format!("ssl.cert.subject.O:\"{o}\""),
            ));
        }
        v
    }
}

fn name_matches(pattern: &str, host: &str) -> bool {
    let p = pattern.trim_end_matches('.');
    if let Some(rest) = p.strip_prefix("*.") {
        match host.split_once('.') {
            Some((label, tail)) => !label.is_empty() && tail == rest && rest.contains('.'),
            None => false,
        }
    } else {
        p == host
    }
}

/// An OSINT hint from a CRL distribution point or AIA URL.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PkiHint {
    pub url: String,
    /// `crl`, `ocsp` or `ca_issuers`.
    pub source: String,
    /// URL scheme: `http`, `ldap`, `file`, ...
    pub scheme: String,
    pub host: Option<String>,
    /// The host is an internal name (single label, `.local`/`.corp`/`.lan`/..., private IP) or the
    /// URL is an LDAP path into a directory.
    pub internal: bool,
    /// The LDAP distinguished name (`CN=...,DC=corp,DC=local`), percent-decoded.
    pub ldap_dn: Option<String>,
    /// Active Directory domain built from the `DC=` components (`corp.local`).
    pub ad_domain: Option<String>,
}

const INTERNAL_SUFFIXES: &[&str] = &[
    "local",
    "lan",
    "corp",
    "internal",
    "intranet",
    "intra",
    "localdomain",
    "home",
    "private",
    "priv",
    "ad",
    "home.arpa",
];

/// Returns `true` for host names and IPs that are not routable on the public Internet.
pub fn is_internal_host(host: &str) -> bool {
    let h = host.trim().trim_end_matches('.').to_ascii_lowercase();
    let h = h.trim_start_matches('[').trim_end_matches(']');
    if h.is_empty() {
        return false;
    }
    if let Ok(ip) = h.parse::<IpAddr>() {
        return match ip {
            IpAddr::V4(v) => v.is_private() || v.is_loopback() || v.is_link_local(),
            IpAddr::V6(v) => v.is_loopback() || (v.segments()[0] & 0xfe00) == 0xfc00,
        };
    }
    !h.contains('.')
        || INTERNAL_SUFFIXES
            .iter()
            .any(|s| h == *s || h.ends_with(&format!(".{s}")))
}

fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let Some(v) = std::str::from_utf8(&b[i + 1..i + 3])
                .ok()
                .and_then(|h| u8::from_str_radix(h, 16).ok())
            {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hint(url: &str, source: &str) -> PkiHint {
    let (scheme, rest) = url.split_once("://").unwrap_or(("", url));
    let scheme = scheme.to_ascii_lowercase();
    let (authority, path) = rest.split_once('/').unwrap_or((rest, ""));
    let host = authority
        .rsplit('@')
        .next()
        .map(|a| {
            if a.starts_with('[') {
                a.split(']')
                    .next()
                    .unwrap_or("")
                    .trim_start_matches('[')
                    .to_string()
            } else {
                a.split(':').next().unwrap_or("").to_string()
            }
        })
        .map(|h| h.to_ascii_lowercase())
        .filter(|h| !h.is_empty());
    let mut ldap_dn = None;
    let mut ad_domain = None;
    if scheme == "ldap" || scheme == "ldaps" {
        let dn = percent_decode(path.split('?').next().unwrap_or(""));
        let dcs: Vec<String> = dn
            .split(',')
            .filter_map(|p| {
                let (k, v) = p.split_once('=')?;
                k.trim()
                    .eq_ignore_ascii_case("dc")
                    .then(|| v.trim().to_ascii_lowercase())
            })
            .collect();
        if !dcs.is_empty() {
            ad_domain = Some(dcs.join("."));
        }
        if !dn.is_empty() {
            ldap_dn = Some(dn);
        }
    }
    let internal =
        ldap_dn.is_some() || scheme == "file" || host.as_deref().is_some_and(is_internal_host);
    PkiHint {
        url: url.to_string(),
        source: source.to_string(),
        scheme,
        host,
        internal,
        ldap_dn,
        ad_domain,
    }
}

/// Hints from the certificate CDP and AIA URLs (all of them; check `internal` for the
/// interesting ones).
pub fn pki_hints(c: &CertInfo) -> Vec<PkiHint> {
    let mut v = Vec::new();
    for u in &c.crl_urls {
        v.push(hint(u, "crl"));
    }
    for u in &c.ocsp_urls {
        v.push(hint(u, "ocsp"));
    }
    for u in &c.ca_issuer_urls {
        v.push(hint(u, "ca_issuers"));
    }
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    const GOOD: &[u8] = include_bytes!("../../tests/fixtures/tls/good.der");
    const WEAK: &[u8] = include_bytes!("../../tests/fixtures/tls/weak.der");
    const ROOT: &[u8] = include_bytes!("../../tests/fixtures/tls/root.der");

    #[test]
    fn full_parse() {
        let c = parse_cert(GOOD).unwrap();
        assert_eq!(c.subject.cn.as_deref(), Some("good.test"));
        assert_eq!(c.subject.o.as_deref(), Some("Good Test LLC"));
        assert_eq!(c.subject.ou, vec!["IT Security"]);
        assert_eq!(c.subject.l.as_deref(), Some("Kyiv"));
        assert_eq!(c.subject.st.as_deref(), Some("Kyiv"));
        assert_eq!(c.subject.c.as_deref(), Some("UA"));
        assert_eq!(c.subject.email.as_deref(), Some("pki@good.test"));
        assert_eq!(c.issuer.cn.as_deref(), Some("FOCA Test Issuing CA"));
        assert_eq!(c.san_dns, vec!["good.test", "*.good.test"]);
        assert_eq!(c.san_ip, vec!["127.0.0.1"]);
        assert_eq!(c.san_email, vec!["admin@good.test"]);
        assert_eq!(c.san_uri, vec!["https://good.test/id"]);
        assert_eq!(c.sha256, sha256_hex(GOOD));
        assert_eq!(c.sha256.len(), 64);
        assert_eq!(c.spki_sha256.len(), 64);
        assert_eq!(c.sig_alg, "ecdsa-with-SHA256");
        assert_eq!((c.key_type.as_str(), c.key_bits), ("EC", 256));
        assert!(!c.is_ca && !c.self_issued && !c.is_self_signed());
        assert_eq!(c.not_before, 1735689600);
        assert_eq!(c.ocsp_urls, vec!["http://ocsp.corp.local/ocsp"]);
        assert_eq!(c.ca_issuer_urls.len(), 2);
        assert_eq!(c.crl_urls.len(), 2);
        assert!(c.ski.is_some() && c.aki.is_some());
        assert!(c
            .pivot_queries()
            .iter()
            .any(|(k, q)| k == "shodan" && q.contains(&c.sha256)));
    }

    #[test]
    fn weak_and_root() {
        let w = parse_cert(WEAK).unwrap();
        assert_eq!(
            (w.sig_hash.as_str(), w.key_type.as_str(), w.key_bits),
            ("sha1", "RSA", 1024)
        );
        assert!(w.is_self_signed());
        assert_eq!(w.subject.ou, vec!["Legacy"]);
        let r = parse_cert(ROOT).unwrap();
        assert!(r.is_ca && r.is_self_signed());
        assert!(parse_cert(b"\x30\x03junk").is_err());
    }

    #[test]
    fn hostname_matching() {
        let c = parse_cert(GOOD).unwrap();
        assert!(c.matches_host("good.test"));
        assert!(c.matches_host("WWW.good.test."));
        assert!(!c.matches_host("a.b.good.test"));
        assert!(!c.matches_host("evilgood.test"));
        assert!(c.matches_host("127.0.0.1"));
        assert!(!c.matches_host("127.0.0.2"));
        let w = parse_cert(WEAK).unwrap();
        assert!(w.matches_host("self.test"), "SAN wins over CN");
        assert!(!w.matches_host("weak.test"));
        assert!(!name_matches("*.test", "a.test"), "wildcard over a TLD");
    }

    #[test]
    fn pki_hints_from_cdp_aia() {
        let c = parse_cert(GOOD).unwrap();
        let h = pki_hints(&c);
        let crl = h
            .iter()
            .find(|x| x.url.starts_with("http://pki.corp"))
            .unwrap();
        assert!(crl.internal);
        assert_eq!(crl.host.as_deref(), Some("pki.corp.local"));
        let ldap = h
            .iter()
            .find(|x| x.source == "crl" && x.scheme == "ldap")
            .unwrap();
        assert_eq!(ldap.ad_domain.as_deref(), Some("corp.local"));
        assert!(ldap
            .ldap_dn
            .as_deref()
            .unwrap()
            .starts_with("CN=Corp Issuing CA,CN=PKI01,CN=CDP"));
        let public = h
            .iter()
            .find(|x| x.url.contains("pki.example.com"))
            .unwrap();
        assert!(!public.internal);
        assert!(h.iter().any(|x| x.source == "ocsp" && x.internal));
        assert!(is_internal_host("dc01") && is_internal_host("10.1.2.3"));
        assert!(!is_internal_host("8.8.8.8") && !is_internal_host("ocsp.digicert.com"));
        assert_eq!(percent_decode("a%20b%2Cc%"), "a b,c%");
    }
}
