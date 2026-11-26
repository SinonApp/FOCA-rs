//! Network spoofing & interception detector (TCP, DNS `.invalid`, TLS MITM CAs).
//!
//! Runs lightweight probes (skipped on `local_only`, configured proxies, or
//! passive-only profiles) to detect local VPN/AdGuard/firewall TCP accept-all interception,
//! DNS hijacking of RFC 2606 `.invalid` names, and corporate/antivirus TLS MITM root CAs.

use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use tokio::net::TcpStream;
use tokio_rustls::rustls::pki_types::ServerName;

use crate::client::{Access, NetClient};
use crate::dns::{DnsLookup, RType};
use crate::tcp::tls_connector;

/// Request log module name for the canary checks.
pub const MODULE: &str = "canary";

/// Unreliable scan reason: known-unused canary ports are open.
pub const UNRELIABLE_CANARY: &str = "canary";
/// Unreliable scan reason: more than 40% of ports are open and most have no banner or TLS.
pub const UNRELIABLE_MASS: &str = "mass_open";
/// Unreliable scan reason: a connection to a non-routable TEST-NET address succeeded.
pub const UNRELIABLE_INTERCEPT: &str = "intercept";

/// Addresses used to detect TCP interception by the device network (RFC 5737 TEST-NET-1/2 are not
/// routable on the internet, so a connection can only "succeed" through a local VPN or proxy).
pub const INTERCEPT_PROBES: &[&str] = &["192.0.2.1:443", "198.51.100.1:47613"];

/// Default public host used for optional TLS MITM issuer inspection.
pub const DEFAULT_TLS_PROBE: &str = "example.com:443";

/// Known local proxy / AV / corporate SSL-inspection issuer patterns (lowercase).
const MITM_ISSUER_PATTERNS: &[&str] = &[
    "adguard",
    "mitmproxy",
    "fiddler",
    "do_not_trust_fiddlerroot",
    "charles proxy",
    "charles root",
    "portswigger",
    "burp",
    "zscaler",
    "netskope",
    "fortinet",
    "fortigate",
    "palo alto",
    "pan-os",
    "sophos",
    "kaspersky",
    "eset ssl",
    "avast",
    "avg web",
    "bitdefender",
    "mcafee",
    "bluecoat",
    "blue coat",
    "symantec ssl visibility",
    "proxyman",
    "http toolkit",
    "owasp zap",
    "zed attack proxy",
    "privoxy",
    "forcepoint",
    "barracuda",
    "watchguard",
    "sonicwall",
    "check point",
    "cisco umbrella",
    "cloudflare gateway",
    "cloudflare zero trust",
];

/// Parameters for [`check_network`].
#[derive(Debug, Clone)]
pub struct CanaryConfig {
    /// Non-routable `ip:port` addresses tested for fake TCP `connect()` acceptance.
    pub probes: Vec<String>,
    /// Optional `.invalid` domain to query; when `None`, a unique `.invalid` probe name is generated.
    pub dns_probe_domain: Option<String>,
    /// Optional `host:port` target for TLS MITM issuer inspection.
    pub tls_probe_host: Option<String>,
    /// Timeout for each probe.
    pub timeout: Duration,
}

impl Default for CanaryConfig {
    fn default() -> Self {
        CanaryConfig {
            probes: INTERCEPT_PROBES.iter().map(|s| s.to_string()).collect(),
            dns_probe_domain: None,
            tls_probe_host: Some(DEFAULT_TLS_PROBE.to_string()),
            timeout: Duration::from_millis(1500),
        }
    }
}

/// Summary of network reliability probes before a scan.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CanaryReport {
    /// Device network accepted a TCP connection to a non-routable TEST-NET address.
    pub tcp_intercept: bool,
    /// DNS resolver returned IP records for an RFC 2606 `.invalid` domain.
    pub dns_hijack: bool,
    /// Unexpected IP addresses returned for the `.invalid` probe (if any).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dns_hijack_ips: Vec<String>,
    /// TLS endpoint presented a certificate issued by a known MITM / SSL-inspection CA.
    pub tls_mitm: bool,
    /// Certificate issuer label observed during the TLS probe (if available).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_issuer: Option<String>,
    /// `true` if any spoofing/interception signal was detected.
    pub unreliable: bool,
    /// Canonical machine-readable signal codes (`"tcp_intercept"`, `"dns_hijack"`, `"tls_mitm"`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub reasons: Vec<String>,
}

/// Picks random high canary ports (49152-65535) not among the requested ones.
pub fn pick_canaries(n: usize, avoid: &[u16]) -> Vec<u16> {
    let mut x = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0x9E37_79B9_7F4A_7C15)
        | 1;
    let mut out = Vec::new();
    let mut guard = 0;
    while out.len() < n && guard < 1000 {
        guard += 1;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        let p = 49152 + (x % (65535 - 49152)) as u16;
        if !avoid.contains(&p) && !out.contains(&p) {
            out.push(p);
        }
    }
    out
}

/// Returns `true` if at least one TCP connection to `addrs` completes within `timeout`.
/// No scope check and no logging; callers log the check.
pub async fn connect_succeeds(addrs: &[SocketAddr], timeout: Duration) -> bool {
    let mut set = tokio::task::JoinSet::new();
    for a in addrs.iter().copied() {
        set.spawn(async move {
            matches!(
                tokio::time::timeout(timeout, TcpStream::connect(a)).await,
                Ok(Ok(_))
            )
        });
    }
    while let Some(r) = set.join_next().await {
        if r.unwrap_or(false) {
            return true;
        }
    }
    false
}

pub(crate) async fn tcp_intercept_with_module(
    net: &NetClient,
    module: &str,
    access: &Access,
    addrs: &[String],
    timeout: Duration,
) -> bool {
    if net.has_proxy() || addrs.is_empty() {
        return false;
    }
    let mut hit = false;
    for a in addrs {
        let Ok(sa) = a.parse::<SocketAddr>() else {
            continue;
        };
        let mut rec = net.draft(
            module,
            "TCP",
            &format!("tcp://{a} (net-check: TEST-NET)"),
            &sa.ip().to_string(),
            access,
        );
        if connect_succeeds(&[sa], timeout).await {
            rec.status = Some(0);
            hit = true;
        } else {
            rec.error = Some("no-connect: expected".into());
        }
        net.record(rec);
        if hit {
            break;
        }
    }
    hit
}

/// Checks for DNS hijacking by querying a non-existent `.invalid` domain (RFC 2606).
/// Returns `(hijacked, resolved_values)`.
pub async fn check_dns_hijack<D: DnsLookup + ?Sized>(
    dns: &D,
    _net: &NetClient,
    probe_domain: Option<&str>,
) -> (bool, Vec<String>) {
    let qname = match probe_domain {
        Some(d) => d.trim().trim_end_matches('.').to_string(),
        None => {
            let n = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| (d.as_nanos() & 0xffff_ffff) as u32)
                .unwrap_or(0x5a5a_c3c3);
            format!("foca-canary-{n:08x}.invalid")
        }
    };
    // The resolver logs every lookup it sends itself (module `dns`, or the DoH HTTP request), so
    // the probe is not recorded a second time under the canary module.
    match dns.lookup(&qname, RType::A).await {
        Ok(ans) if !ans.records.is_empty() => {
            (true, ans.records.into_iter().map(|r| r.value).collect())
        }
        Ok(ans) if !ans.nxdomain => match dns.lookup(&qname, RType::AAAA).await {
            Ok(a6) if !a6.records.is_empty() => {
                (true, a6.records.into_iter().map(|r| r.value).collect())
            }
            _ => (false, Vec::new()),
        },
        _ => (false, Vec::new()),
    }
}

/// Parses a DER length; returns `(length, size of length header)`.
pub(crate) fn der_len(b: &[u8]) -> Option<(usize, usize)> {
    let f = *b.first()?;
    if f < 0x80 {
        return Some((f as usize, 1));
    }
    let n = (f & 0x7f) as usize;
    if n == 0 || n > 4 || b.len() < 1 + n {
        return None;
    }
    let mut l = 0usize;
    for x in &b[1..=n] {
        l = (l << 8) | *x as usize;
    }
    Some((l, 1 + n))
}

fn parse_tlv(b: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let tag = *b.first()?;
    let (len, hdr) = der_len(b.get(1..)?)?;
    let start = 1usize.checked_add(hdr)?;
    let end = start.checked_add(len)?;
    if end > b.len() {
        return None;
    }
    Some((tag, &b[start..end], &b[end..]))
}

fn decode_asn1_string(tag: u8, bytes: &[u8]) -> String {
    if tag == 0x1e && bytes.len().is_multiple_of(2) {
        let units: Vec<u16> = bytes
            .as_chunks::<2>()
            .0
            .iter()
            .map(|&c| u16::from_be_bytes(c))
            .collect();
        return String::from_utf16_lossy(&units).trim().to_string();
    }
    String::from_utf8_lossy(bytes).trim().to_string()
}

/// Extracts CN / O / OU attributes from the X.509 Issuer `Name` field of a DER certificate.
pub fn cert_issuer(der: &[u8]) -> Option<String> {
    const CN: &[u8] = &[0x55, 0x04, 0x03];
    const O: &[u8] = &[0x55, 0x04, 0x0a];
    const OU: &[u8] = &[0x55, 0x04, 0x0b];

    let (t_cert, cert_val, _) = parse_tlv(der)?;
    if t_cert != 0x30 {
        return None;
    }
    let (t_tbs, tbs_val, _) = parse_tlv(cert_val)?;
    if t_tbs != 0x30 {
        return None;
    }
    let (t0, _, mut rem) = parse_tlv(tbs_val)?;
    if t0 == 0xa0 {
        // v3 explicit version present; next is serialNumber
        let (t_ser, _, r) = parse_tlv(rem)?;
        if t_ser != 0x02 {
            return None;
        }
        rem = r;
    } else if t0 != 0x02 {
        return None;
    }
    // signature AlgorithmIdentifier
    let (t_sig, _, r) = parse_tlv(rem)?;
    if t_sig != 0x30 {
        return None;
    }
    // issuer Name
    let (t_iss, mut iss_rem, _) = parse_tlv(r)?;
    if t_iss != 0x30 {
        return None;
    }

    let mut parts: Vec<String> = Vec::new();
    while !iss_rem.is_empty() {
        let Some((t_set, mut set_rem, next_set)) = parse_tlv(iss_rem) else {
            break;
        };
        iss_rem = next_set;
        if t_set != 0x31 {
            continue;
        }
        while !set_rem.is_empty() {
            let Some((t_atv, atv_val, next_atv)) = parse_tlv(set_rem) else {
                break;
            };
            set_rem = next_atv;
            if t_atv != 0x30 {
                continue;
            }
            let Some((t_oid, oid, val_rem)) = parse_tlv(atv_val) else {
                continue;
            };
            if t_oid != 0x06 || (oid != CN && oid != O && oid != OU) {
                continue;
            }
            if let Some((vtag, vbytes, _)) = parse_tlv(val_rem) {
                let s = decode_asn1_string(vtag, vbytes);
                if !s.is_empty() && !parts.contains(&s) {
                    parts.push(s);
                }
            }
        }
    }
    if parts.is_empty() {
        None
    } else {
        Some(parts.join(" / "))
    }
}

/// Returns `true` if `issuer` matches a known SSL-inspection / local proxy / AV MITM CA.
pub fn classify_mitm_issuer(issuer: &str) -> bool {
    let low = issuer.to_ascii_lowercase();
    MITM_ISSUER_PATTERNS.iter().any(|p| low.contains(p))
}

fn split_host_port(hp: &str) -> Option<(String, u16)> {
    let s = hp.trim();
    if let Ok(sa) = s.parse::<SocketAddr>() {
        return Some((sa.ip().to_string(), sa.port()));
    }
    let (h, p) = s.rsplit_once(':')?;
    let port = p.parse::<u16>().ok()?;
    let host = h.trim_start_matches('[').trim_end_matches(']').to_string();
    if host.is_empty() {
        None
    } else {
        Some((host, port))
    }
}

fn is_loopback_target(hp: &str) -> bool {
    let Some((host, _)) = split_host_port(hp) else {
        return false;
    };
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback())
}

/// Inspects the peer certificate chain of `host_port` (`host:port`) for known MITM CAs.
/// Skipped when `net.has_proxy()` is true. Returns `(mitm_detected, observed_issuer)`.
pub async fn check_tls_mitm(
    net: &NetClient,
    host_port: &str,
    timeout: Duration,
) -> (bool, Option<String>) {
    if net.has_proxy() {
        return (false, None);
    }
    let Some((host, _)) = split_host_port(host_port) else {
        return (false, None);
    };
    let Some(conn) = tls_connector() else {
        return (false, None);
    };
    let sni = match host.parse::<IpAddr>() {
        Ok(ip) => ServerName::IpAddress(ip.into()),
        Err(_) => {
            let Ok(dn) = ServerName::try_from(host.clone()) else {
                return (false, None);
            };
            dn
        }
    };
    let mut rec = net.draft(
        MODULE,
        "TLS",
        &format!("tls://{host_port} (net-check: mitm)"),
        &host,
        &Access::Passive,
    );
    let fut = async {
        let tcp = TcpStream::connect(host_port)
            .await
            .map_err(|e| format!("tcp-connect: {e}"))?;
        let tls = conn
            .connect(sni, tcp)
            .await
            .map_err(|e| format!("tls-handshake: {e}"))?;
        let certs = tls
            .get_ref()
            .1
            .peer_certificates()
            .ok_or_else(|| "tls-no-certs".to_string())?;
        let mut issuers = Vec::new();
        for c in certs {
            if let Some(iss) = cert_issuer(c.as_ref()) {
                issuers.push(iss);
            }
        }
        Ok::<Vec<String>, String>(issuers)
    };
    let out = match tokio::time::timeout(timeout, fut).await {
        Ok(Ok(issuers)) => {
            rec.status = Some(0);
            if let Some(hit) = issuers.iter().find(|iss| classify_mitm_issuer(iss)) {
                rec.error = Some(format!("tls-mitm: {hit}"));
                (true, Some(hit.clone()))
            } else {
                (false, issuers.into_iter().next())
            }
        }
        Ok(Err(err)) => {
            tracing::warn!(target: "foca::net", "canary TLS probe failed for {host_port}: {err}");
            rec.error = Some(err);
            (false, None)
        }
        Err(_) => {
            rec.error = Some("tls-probe: timeout".into());
            (false, None)
        }
    };
    net.record(rec);
    out
}

/// Runs the spoofing & interception probes (`tcp_intercept`, `dns_hijack`, `tls_mitm`).
///
/// Respects `passive_only`, configured HTTP/SOCKS5 proxies (`net.has_proxy()`),
/// and `local_only` test-bench isolation (never dialing external addresses in `local_only` mode).
pub async fn check_network<D: DnsLookup + ?Sized>(
    net: &NetClient,
    dns: &D,
    passive_only: bool,
    cfg: &CanaryConfig,
) -> CanaryReport {
    let mut rep = CanaryReport::default();
    let local_only = net.is_local_only();
    let has_proxy = net.has_proxy();

    if !passive_only && !has_proxy {
        let probes: Vec<String> = if local_only {
            cfg.probes
                .iter()
                .filter(|p| is_loopback_target(p))
                .cloned()
                .collect()
        } else {
            cfg.probes.clone()
        };
        if !probes.is_empty() {
            rep.tcp_intercept =
                tcp_intercept_with_module(net, MODULE, &Access::Passive, &probes, cfg.timeout)
                    .await;
        }
    }

    if !local_only || cfg.dns_probe_domain.is_some() {
        let (hijack, ips) = check_dns_hijack(dns, net, cfg.dns_probe_domain.as_deref()).await;
        rep.dns_hijack = hijack;
        rep.dns_hijack_ips = ips;
    }

    if !passive_only && !has_proxy {
        if let Some(hp) = cfg.tls_probe_host.as_deref() {
            if !local_only || is_loopback_target(hp) {
                let (mitm, issuer) = check_tls_mitm(net, hp, cfg.timeout).await;
                rep.tls_mitm = mitm;
                rep.tls_issuer = issuer;
            }
        }
    }

    if rep.tcp_intercept {
        rep.reasons.push("tcp_intercept".into());
    }
    if rep.dns_hijack {
        rep.reasons.push("dns_hijack".into());
    }
    if rep.tls_mitm {
        rep.reasons.push("tls_mitm".into());
    }
    rep.unreliable = rep.tcp_intercept || rep.dns_hijack || rep.tls_mitm;
    rep
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::StaticDns;
    use crate::sink::MemorySink;
    use crate::NetConfig;
    use std::sync::Arc;
    use tokio::net::TcpListener;
    use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use tokio_rustls::TlsAcceptor;

    const MITM_KEY: &[u8] = &[
        48, 46, 2, 1, 0, 48, 5, 6, 3, 43, 101, 112, 4, 34, 4, 32, 155, 225, 128, 75, 129, 225, 236,
        194, 213, 26, 11, 166, 152, 36, 168, 113, 144, 223, 193, 54, 138, 88, 46, 121, 33, 225,
        141, 117, 225, 30, 211, 167,
    ];
    const MITM_CERT: &[u8] = &[
        48, 130, 1, 117, 48, 130, 1, 39, 160, 3, 2, 1, 2, 2, 20, 41, 142, 56, 125, 195, 197, 10,
        137, 182, 189, 86, 219, 156, 20, 6, 250, 53, 51, 98, 167, 48, 5, 6, 3, 43, 101, 112, 48,
        48, 49, 28, 48, 26, 6, 3, 85, 4, 3, 12, 19, 65, 100, 71, 117, 97, 114, 100, 32, 80, 101,
        114, 115, 111, 110, 97, 108, 32, 67, 65, 49, 16, 48, 14, 6, 3, 85, 4, 10, 12, 7, 65, 100,
        71, 117, 97, 114, 100, 48, 30, 23, 13, 50, 54, 49, 49, 50, 49, 50, 48, 51, 56, 49, 49, 90,
        23, 13, 51, 54, 49, 49, 49, 56, 50, 48, 51, 56, 49, 49, 90, 48, 48, 49, 28, 48, 26, 6, 3,
        85, 4, 3, 12, 19, 65, 100, 71, 117, 97, 114, 100, 32, 80, 101, 114, 115, 111, 110, 97, 108,
        32, 67, 65, 49, 16, 48, 14, 6, 3, 85, 4, 10, 12, 7, 65, 100, 71, 117, 97, 114, 100, 48, 42,
        48, 5, 6, 3, 43, 101, 112, 3, 33, 0, 176, 71, 169, 237, 47, 135, 217, 108, 133, 11, 32,
        101, 102, 193, 210, 74, 148, 77, 194, 170, 243, 101, 66, 60, 177, 132, 179, 239, 169, 177,
        77, 110, 163, 83, 48, 81, 48, 29, 6, 3, 85, 29, 14, 4, 22, 4, 20, 106, 65, 169, 160, 251,
        242, 63, 31, 69, 100, 88, 119, 228, 8, 3, 149, 54, 178, 28, 46, 48, 31, 6, 3, 85, 29, 35,
        4, 24, 48, 22, 128, 20, 106, 65, 169, 160, 251, 242, 63, 31, 69, 100, 88, 119, 228, 8, 3,
        149, 54, 178, 28, 46, 48, 15, 6, 3, 85, 29, 19, 1, 1, 255, 4, 5, 48, 3, 1, 1, 255, 48, 5,
        6, 3, 43, 101, 112, 3, 65, 0, 59, 235, 64, 28, 222, 4, 157, 190, 182, 212, 197, 50, 218,
        123, 27, 62, 205, 123, 142, 62, 63, 141, 182, 250, 165, 69, 9, 178, 175, 120, 251, 89, 82,
        139, 88, 203, 28, 76, 108, 2, 214, 192, 76, 174, 22, 164, 207, 227, 28, 142, 216, 74, 70,
        24, 31, 179, 142, 2, 166, 3, 89, 216, 238, 13,
    ];
    const LEGIT_KEY: &[u8] = &[
        48, 46, 2, 1, 0, 48, 5, 6, 3, 43, 101, 112, 4, 34, 4, 32, 205, 234, 190, 21, 199, 219, 75,
        185, 186, 45, 11, 84, 64, 114, 34, 118, 198, 152, 73, 203, 12, 215, 191, 183, 148, 147,
        222, 1, 81, 44, 244, 40,
    ];
    const LEGIT_CERT: &[u8] = &[
        48, 130, 1, 95, 48, 130, 1, 17, 160, 3, 2, 1, 2, 2, 20, 122, 30, 233, 223, 230, 7, 35, 206,
        181, 171, 46, 212, 124, 99, 44, 241, 30, 132, 113, 179, 48, 5, 6, 3, 43, 101, 112, 48, 37,
        49, 11, 48, 9, 6, 3, 85, 4, 3, 12, 2, 82, 51, 49, 22, 48, 20, 6, 3, 85, 4, 10, 12, 13, 76,
        101, 116, 39, 115, 32, 69, 110, 99, 114, 121, 112, 116, 48, 30, 23, 13, 50, 54, 49, 49, 50,
        49, 50, 48, 51, 56, 49, 49, 90, 23, 13, 51, 54, 49, 49, 49, 56, 50, 48, 51, 56, 49, 49, 90,
        48, 37, 49, 11, 48, 9, 6, 3, 85, 4, 3, 12, 2, 82, 51, 49, 22, 48, 20, 6, 3, 85, 4, 10, 12,
        13, 76, 101, 116, 39, 115, 32, 69, 110, 99, 114, 121, 112, 116, 48, 42, 48, 5, 6, 3, 43,
        101, 112, 3, 33, 0, 161, 204, 127, 172, 67, 125, 114, 248, 110, 145, 139, 78, 160, 71, 59,
        130, 9, 172, 179, 53, 54, 254, 27, 16, 103, 242, 157, 189, 14, 75, 186, 154, 163, 83, 48,
        81, 48, 29, 6, 3, 85, 29, 14, 4, 22, 4, 20, 59, 118, 211, 62, 145, 84, 48, 166, 102, 22,
        40, 133, 126, 127, 136, 113, 44, 192, 121, 18, 48, 31, 6, 3, 85, 29, 35, 4, 24, 48, 22,
        128, 20, 59, 118, 211, 62, 145, 84, 48, 166, 102, 22, 40, 133, 126, 127, 136, 113, 44, 192,
        121, 18, 48, 15, 6, 3, 85, 29, 19, 1, 1, 255, 4, 5, 48, 3, 1, 1, 255, 48, 5, 6, 3, 43, 101,
        112, 3, 65, 0, 243, 16, 197, 120, 61, 125, 45, 175, 219, 142, 224, 103, 226, 94, 194, 189,
        48, 188, 185, 134, 186, 220, 125, 206, 230, 117, 63, 181, 41, 187, 234, 3, 121, 147, 192,
        157, 35, 5, 76, 193, 60, 193, 126, 98, 243, 154, 200, 239, 186, 59, 221, 137, 251, 3, 127,
        85, 83, 103, 211, 161, 178, 219, 203, 4,
    ];

    async fn spawn_tls_server(cert: &'static [u8], key: &'static [u8]) -> SocketAddr {
        let prov = Arc::new(tokio_rustls::rustls::crypto::ring::default_provider());
        let cfg = tokio_rustls::rustls::ServerConfig::builder_with_provider(prov)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![CertificateDer::from(cert)],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key)),
            )
            .unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(cfg));
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move {
            if let Ok((s, _)) = l.accept().await {
                let _ = acceptor.accept(s).await;
            }
        });
        addr
    }

    #[test]
    fn cert_issuer_and_classifier() {
        let mitm = cert_issuer(MITM_CERT).unwrap();
        assert!(mitm.contains("AdGuard Personal CA"), "{mitm}");
        assert!(classify_mitm_issuer(&mitm));

        let legit = cert_issuer(LEGIT_CERT).unwrap();
        assert!(legit.contains("Let's Encrypt"), "{legit}");
        assert!(!classify_mitm_issuer(&legit));

        assert!(classify_mitm_issuer("mitmproxy"));
        assert!(classify_mitm_issuer("DO_NOT_TRUST_FiddlerRoot"));
        assert!(classify_mitm_issuer("Zscaler Root CA"));
        assert!(!classify_mitm_issuer("Cloudflare Inc ECC CA-3"));
        assert!(!classify_mitm_issuer(
            "DigiCert Global G2 TLS RSA SHA256 2020 CA1"
        ));
        assert!(cert_issuer(b"bad").is_none());
    }

    #[tokio::test]
    async fn dns_hijack_detects_non_nxdomain_invalid() {
        let sink = Arc::new(MemorySink::new());
        let net = NetClient::new(NetConfig::default(), Default::default(), sink.clone()).unwrap();

        // NXDOMAIN -> clean
        let clean_dns = StaticDns::default();
        let (hijack, ips) =
            check_dns_hijack(&clean_dns, &net, Some("probe.foca-test.invalid")).await;
        assert!(!hijack);
        assert!(ips.is_empty());

        // Returning an IP for .invalid -> hijacked
        let hijack_dns = StaticDns::new().add("probe.foca-test.invalid", RType::A, &["10.0.0.1"]);
        let (hijack, ips) =
            check_dns_hijack(&hijack_dns, &net, Some("probe.foca-test.invalid")).await;
        assert!(hijack);
        assert_eq!(ips, vec!["10.0.0.1"]);

        // IPv6-only hijack (NODATA on A, IP on AAAA) -> hijacked
        let v6_dns =
            StaticDns::new().add("v6.foca-test.invalid", RType::AAAA, &["::ffff:10.0.0.1"]);
        let (hijack6, ips6) = check_dns_hijack(&v6_dns, &net, Some("v6.foca-test.invalid")).await;
        assert!(hijack6);
        assert_eq!(ips6, vec!["::ffff:10.0.0.1"]);

        // StaticDns logs nothing, and the probe itself adds no record of its own.
        assert!(!sink.records().iter().any(|r| r.module == MODULE));
    }

    /// Resolver that logs its lookups like the real one does.
    struct LoggingDns(NetClient, StaticDns);

    impl DnsLookup for LoggingDns {
        fn lookup<'a>(
            &'a self,
            name: &'a str,
            t: RType,
        ) -> crate::BoxFuture<'a, Result<crate::dns::DnsAnswer, crate::NetError>> {
            Box::pin(async move {
                let mut rec = self.0.draft(
                    "dns",
                    "DNS",
                    &format!("dns://{name}/{}", t.as_str()),
                    name,
                    &Access::Passive,
                );
                let r = self.1.lookup(name, t).await;
                rec.status = Some(0);
                self.0.record(rec);
                r
            })
        }
    }

    #[tokio::test]
    async fn invalid_probe_is_logged_once() {
        let sink = Arc::new(MemorySink::new());
        let net = NetClient::new(NetConfig::default(), Default::default(), sink.clone()).unwrap();
        let dns = LoggingDns(net.clone(), StaticDns::default());
        let (hijack, _) = check_dns_hijack(&dns, &net, Some("probe.foca-test.invalid")).await;
        assert!(!hijack);
        let recs: Vec<_> = sink
            .records()
            .into_iter()
            .filter(|r| r.url.contains("probe.foca-test.invalid"))
            .collect();
        assert_eq!(recs.len(), 1, "{recs:?}");
        assert_eq!(recs[0].module, "dns");
    }

    #[tokio::test]
    async fn tls_mitm_detects_local_adguard_and_clears_legit() {
        let net = NetClient::new(
            NetConfig::default(),
            Default::default(),
            Arc::new(MemorySink::new()),
        )
        .unwrap();

        let mitm_addr = spawn_tls_server(MITM_CERT, MITM_KEY).await;
        let (mitm, iss) =
            check_tls_mitm(&net, &mitm_addr.to_string(), Duration::from_secs(2)).await;
        assert!(mitm, "{iss:?}");
        assert!(iss.unwrap().contains("AdGuard"));

        let legit_addr = spawn_tls_server(LEGIT_CERT, LEGIT_KEY).await;
        let (mitm, iss) =
            check_tls_mitm(&net, &legit_addr.to_string(), Duration::from_secs(2)).await;
        assert!(!mitm, "{iss:?}");
        assert!(iss.unwrap().contains("Let's Encrypt"));
    }

    #[tokio::test]
    async fn unified_check_network_skips_correctly_on_proxy_passive_and_local_only() {
        let dns = StaticDns::new().add("p.invalid", RType::A, &["198.18.0.1"]);

        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let tcp_addr = l.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = l.accept().await;
        });
        let tls_addr = spawn_tls_server(MITM_CERT, MITM_KEY).await;

        let cfg = CanaryConfig {
            probes: vec![tcp_addr.to_string()],
            dns_probe_domain: Some("p.invalid".into()),
            tls_probe_host: Some(tls_addr.to_string()),
            timeout: Duration::from_secs(2),
        };

        // Normal client detects all three signals
        let net = NetClient::new(
            NetConfig::default(),
            Default::default(),
            Arc::new(MemorySink::new()),
        )
        .unwrap();
        let rep = check_network(&net, &dns, false, &cfg).await;
        assert!(rep.tcp_intercept);
        assert!(rep.dns_hijack);
        assert!(rep.tls_mitm);
        assert!(rep.unreliable);
        assert_eq!(rep.reasons, vec!["tcp_intercept", "dns_hijack", "tls_mitm"]);

        // Passive mode skips TCP and TLS probes, keeps DNS check
        let rep_passive = check_network(&net, &dns, true, &cfg).await;
        assert!(!rep_passive.tcp_intercept);
        assert!(rep_passive.dns_hijack);
        assert!(!rep_passive.tls_mitm);

        // Proxy configured: skips TCP intercept & TLS MITM
        let pcfg = NetConfig {
            proxy: Some("socks5://127.0.0.1:10808".into()),
            ..Default::default()
        };
        let net_proxy =
            NetClient::new(pcfg, Default::default(), Arc::new(MemorySink::new())).unwrap();
        let rep_proxy = check_network(&net_proxy, &dns, false, &cfg).await;
        assert!(!rep_proxy.tcp_intercept);
        assert!(!rep_proxy.tls_mitm);

        // local_only skips external probes when using defaults
        let lcfg = NetConfig {
            local_only: Some(std::path::PathBuf::new()),
            ..Default::default()
        };
        let net_local =
            NetClient::new(lcfg, Default::default(), Arc::new(MemorySink::new())).unwrap();
        let rep_local = check_network(&net_local, &dns, false, &CanaryConfig::default()).await;
        assert!(!rep_local.unreliable);
    }
}
