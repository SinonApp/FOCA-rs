//! TCP port scanning modeled on RustScan, with banner grabbing via custom probes.
//!
//! Connect scan without root in adaptively sized batches, with a rate limit, a per-port
//! timeout, cancellation and a log entry for every attempt.
//!
//! * Scope: the host is checked once as active (`Access::active("ports")`: target in scope, not
//!   excluded including its resolved IPs, active stage on); connections go only to the
//!   verified IP or through the configured proxy (like [`crate::tcp`]). Out of scope means an
//!   error and zero connections.
//! * Batching: `batch` ports are probed concurrently; many timeouts (filtering or overload)
//!   halve the batch, almost none grow it by 1.5x (within `min_batch..=max_batch`).
//! * Banners: passive greeting read (SSH/FTP/SMTP/POP3/IMAP/MySQL), `PING` for Redis, `HEAD /`
//!   for HTTP ports (`Server` header); for TLS, the fact of TLS and the certificate CN/SAN
//!   (read only, the chain is not verified), plus `HEAD /` inside TLS for HTTPS.
//! * The top-100/top-1000 lists are compiled from commonly known service prevalence; they are
//!   not derived from nmap-services, whose NPSL license is incompatible with the GPL.

use std::net::IpAddr;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use regex::Regex;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::client::{Access, NetClient};
use crate::ratelimit::TokenBucket;
use crate::NetError;

/// Request log module name.
pub const MODULE: &str = "ports";

/// Top 100 TCP ports, ordered by how common the open service is on the internet.
pub const TOP_100: [u16; 100] = [
    80, 443, 22, 21, 25, 3389, 110, 143, 53, 23, 445, 139, 135, 8080, 3306, 993, 995, 587, 465,
    8443, 111, 5900, 1723, 8000, 8888, 5432, 6379, 27017, 1433, 1521, 2049, 9200, 11211, 5000,
    8008, 8081, 9000, 9090, 10000, 81, 179, 199, 389, 636, 873, 1025, 1080, 1194, 1883, 2000, 2082,
    2083, 2086, 2087, 2181, 2222, 2375, 2376, 3000, 3128, 4443, 4444, 5060, 5061, 5222, 5601, 5672,
    5800, 5985, 5986, 6000, 6443, 6667, 7001, 7443, 8001, 8009, 8082, 8086, 8181, 8880, 9001, 9092,
    9100, 9418, 9443, 15672, 25565, 49152, 50000, 113, 119, 444, 514, 515, 548, 554, 631, 990,
    3690,
];

/// Additional well-known services for the top 1000 (databases, brokers, admin panels, IoT, games, UPS, VoIP, ...).
const MORE: &[u16] = &[
    1026, 1027, 1028, 1029, 1110, 1158, 1241, 1311, 1352, 1434, 1500, 1501, 1583, 1645, 1646, 1666,
    1701, 1720, 1755, 1801, 1812, 1813, 1900, 1935, 2001, 2002, 2003, 2010, 2020, 2030, 2052, 2053,
    2077, 2078, 2095, 2096, 2100, 2103, 2121, 2161, 2301, 2323, 2368, 2379, 2380, 2381, 2399, 2483,
    2484, 2525, 2601, 2604, 2638, 2809, 2947, 3001, 3002, 3003, 3005, 3050, 3071, 3260, 3268, 3269,
    3283, 3299, 3306, 3307, 3310, 3333, 3351, 3372, 3443, 3478, 3493, 3500, 3541, 3542, 3632, 3689,
    3780, 3784, 3790, 3828, 3871, 3872, 3899, 3910, 4000, 4001, 4040, 4045, 4064, 4111, 4125, 4190,
    4242, 4369, 4430, 4433, 4500, 4505, 4506, 4567, 4646, 4662, 4711, 4712, 4730, 4786, 4840, 4848,
    4899, 4911, 5001, 5002, 5003, 5004, 5005, 5006, 5007, 5008, 5009, 5010, 5038, 5050, 5051, 5054,
    5080, 5084, 5087, 5093, 5101, 5150, 5190, 5200, 5269, 5280, 5298, 5351, 5357, 5400, 5405, 5431,
    5433, 5434, 5435, 5500, 5544, 5550, 5555, 5556, 5560, 5631, 5632, 5666, 5671, 5678, 5718, 5801,
    5802, 5810, 5815, 5822, 5825, 5901, 5902, 5903, 5904, 5906, 5910, 5911, 5938, 5984, 6001, 6002,
    6003, 6004, 6005, 6006, 6007, 6060, 6080, 6100, 6106, 6112, 6129, 6161, 6262, 6346, 6363, 6380,
    6389, 6432, 6481, 6502, 6543, 6547, 6565, 6566, 6580, 6600, 6646, 6660, 6661, 6662, 6663, 6664,
    6665, 6666, 6668, 6669, 6689, 6692, 6699, 6779, 6788, 6789, 6881, 6901, 6969, 7000, 7002, 7004,
    7007, 7019, 7025, 7070, 7071, 7077, 7080, 7100, 7144, 7199, 7200, 7201, 7210, 7272, 7402, 7474,
    7547, 7548, 7676, 7741, 7777, 7778, 7800, 7878, 7911, 7920, 7921, 7937, 7938, 7999, 8002, 8003,
    8004, 8005, 8006, 8007, 8010, 8011, 8012, 8014, 8015, 8016, 8018, 8020, 8021, 8022, 8025, 8028,
    8030, 8031, 8042, 8045, 8069, 8083, 8084, 8085, 8087, 8088, 8089, 8090, 8091, 8092, 8093, 8094,
    8095, 8096, 8097, 8098, 8099, 8100, 8112, 8123, 8139, 8140, 8161, 8180, 8182, 8192, 8193, 8194,
    8200, 8222, 8243, 8280, 8281, 8291, 8333, 8334, 8383, 8400, 8401, 8402, 8443, 8444, 8500, 8530,
    8531, 8545, 8600, 8649, 8686, 8765, 8787, 8800, 8834, 8843, 8848, 8873, 8881, 8882, 8883, 8889,
    8899, 8983, 8989, 8994, 9002, 9003, 9009, 9010, 9011, 9040, 9042, 9043, 9050, 9051, 9060, 9071,
    9080, 9081, 9091, 9093, 9099, 9101, 9102, 9103, 9110, 9111, 9151, 9160, 9191, 9200, 9207, 9220,
    9290, 9300, 9389, 9415, 9440, 9485, 9500, 9502, 9503, 9535, 9575, 9593, 9594, 9595, 9618, 9666,
    9800, 9876, 9877, 9878, 9898, 9900, 9917, 9943, 9944, 9968, 9981, 9988, 9998, 9999, 10001,
    10002, 10003, 10004, 10009, 10010, 10012, 10024, 10025, 10050, 10051, 10082, 10180, 10215,
    10243, 10250, 10255, 10443, 10566, 10616, 10617, 10621, 10626, 10628, 10629, 10778, 11110,
    11111, 11967, 12000, 12174, 12265, 12345, 13456, 13722, 13782, 13783, 14000, 14147, 14238,
    14441, 14442, 15000, 15002, 15003, 15004, 15660, 15742, 16000, 16001, 16010, 16012, 16016,
    16018, 16080, 16113, 16992, 16993, 17877, 17988, 18040, 18080, 18081, 18101, 18988, 19101,
    19283, 19315, 19350, 19780, 19801, 19842, 20000, 20005, 20031, 20221, 20222, 20828, 21571,
    22222, 22939, 23023, 23502, 24444, 24800, 25734, 25735, 26214, 27000, 27015, 27018, 27019,
    27352, 27353, 27355, 27356, 27715, 28017, 28201, 30000, 30718, 30951, 31038, 31337, 32400,
    32768, 32769, 32770, 32771, 32772, 32773, 32774, 32775, 32776, 32777, 32778, 32779, 32780,
    32781, 32782, 32783, 32784, 32785, 33354, 33899, 34571, 34572, 34573, 35500, 37777, 38292,
    40193, 40911, 41511, 42510, 44176, 44442, 44443, 44501, 45100, 48080, 49153, 49154, 49155,
    49156, 49157, 49158, 49159, 49160, 49161, 49163, 49165, 49167, 49175, 49176, 49400, 49999,
    50001, 50002, 50003, 50006, 50050, 50070, 50075, 50300, 50389, 50500, 50636, 50800, 51103,
    51493, 52673, 52822, 52848, 52869, 54045, 54328, 55055, 55056, 55555, 55600, 56737, 56738,
    57294, 57797, 58080, 60020, 60443, 61532, 61900, 62078, 63331, 64623, 64680, 65000, 65129,
    65389,
];

/// Returns the top N ports: 100 gives [`TOP_100`]; larger N adds well-known services, then
/// privileged ports 1-1024 in ascending order (up to N, without duplicates). N is capped at 1000.
pub fn top_ports(n: usize) -> Vec<u16> {
    static TOP1000: OnceLock<Vec<u16>> = OnceLock::new();
    let all = TOP1000.get_or_init(|| {
        let mut seen = std::collections::HashSet::new();
        let mut v = Vec::with_capacity(1000);
        for p in TOP_100.iter().chain(MORE.iter()).copied().chain(1..=1024) {
            if v.len() == 1000 {
                break;
            }
            if seen.insert(p) {
                v.push(p);
            }
        }
        v
    });
    all[..n.min(all.len())].to_vec()
}

/// Parses a spec such as `22,80,8000-8010`, preserving order and dropping duplicates.
///
/// # Errors
///
/// Returns a message for port 0, reversed ranges or malformed entries.
pub fn parse_ports(spec: &str) -> Result<Vec<u16>, String> {
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for part in spec.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        let (a, b) = match part.split_once('-') {
            Some((a, b)) => (a.trim(), b.trim()),
            None => (part, part),
        };
        let a: u16 = a.parse().map_err(|_| format!("не порт: {part}"))?;
        let b: u16 = b.parse().map_err(|_| format!("не порт: {part}"))?;
        if a == 0 || b < a {
            return Err(format!("неверный диапазон: {part}"));
        }
        for p in a..=b {
            if seen.insert(p) {
                out.push(p);
            }
        }
    }
    if out.is_empty() {
        return Err("пустой список портов".into());
    }
    Ok(out)
}

/// Port scan settings.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PortScanConfig {
    pub ports: Vec<u16>,
    /// Initial batch size (concurrent connections).
    pub batch: usize,
    pub min_batch: usize,
    pub max_batch: usize,
    /// Per-port connect timeout.
    pub timeout: Duration,
    /// Connection attempts per second (`None` means no limit beyond the batch size).
    pub rps: Option<f64>,
    /// Grab banners from open ports.
    pub banners: bool,
    /// Time limit for the banner (greeting, HEAD or TLS) of a single port.
    pub banner_timeout: Duration,
    /// Canary ports, known to be unused, probed before the scan. If most of them are open, the
    /// device network (local VPN, AdGuard, proxy, tarpit) accepts connections on any port and the
    /// scan is unreliable. `None` picks 3 random high ports; `Some([])` disables the check.
    #[serde(default)]
    pub canaries: Option<Vec<u16>>,
}

impl Default for PortScanConfig {
    fn default() -> Self {
        PortScanConfig {
            ports: TOP_100.to_vec(),
            batch: 50,
            min_batch: 8,
            max_batch: 200,
            timeout: Duration::from_millis(1500),
            rps: Some(100.0),
            banners: true,
            banner_timeout: Duration::from_secs(4),
            canaries: None,
        }
    }
}

impl PortScanConfig {
    /// Returns settings for the top N ports (100 or 1000) with default values.
    pub fn top(n: usize) -> Self {
        PortScanConfig {
            ports: top_ports(n),
            ..Default::default()
        }
    }
}

/// An open port.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortResult {
    pub port: u16,
    /// `ssh`, `http`, `https`, `smtp`, ... (from the banner, else from the port number; `unknown` otherwise).
    pub service: String,
    /// First line or gist of the reply: up to 200 characters, control characters removed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub banner: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub product: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// The port speaks TLS.
    #[serde(default)]
    pub tls: bool,
    /// Certificate CN and SAN names, deduplicated.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cert_names: Vec<String>,
    /// The protocol was confirmed by a service reply (Docker `GET /version` returning JSON, Redis
    /// `PING` returning `+PONG`/`-NOAUTH`, Elasticsearch `GET /` returning JSON, a MongoDB `isMaster`
    /// reply, RDP X.224, SMB negotiate, PostgreSQL SSLRequest, a MySQL/FTP/SSH greeting, ...).
    /// Without confirmation a sensitive port is reported only as unconfirmed info.
    #[serde(default)]
    pub confirmed: bool,
    /// Probe detail: `auth` (the service requires authentication), `client-cert` (TLS requires a
    /// client certificate) or `no-auth` (access without authentication).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// Port scan result for a host.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortScan {
    pub host: String,
    /// IP the connections went to (`None` when going through a proxy).
    pub ip: Option<String>,
    /// Open ports in ascending order.
    pub open: Vec<PortResult>,
    /// Number of ports scanned (fewer than requested if cancelled).
    pub scanned: usize,
    /// Connection refused (RST).
    pub closed: usize,
    /// No reply within the timeout (filtered).
    pub filtered: usize,
    pub ms: u64,
    /// Final batch size after adaptation.
    pub batch: usize,
    pub cancelled: bool,
    /// Set when the scan is unreliable: [`UNRELIABLE_CANARY`] (canaries open, the main scan was
    /// skipped) or [`UNRELIABLE_MASS`] (most ports open and almost all silent). Open ports from such
    /// a scan are not facts, and no findings are created from them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unreliable: Option<String>,
    /// Canaries probed / canaries open.
    #[serde(default)]
    pub canaries: usize,
    #[serde(default)]
    pub canaries_open: usize,
}

use crate::canary::der_len;
pub use crate::canary::{
    connect_succeeds, pick_canaries, INTERCEPT_PROBES, UNRELIABLE_CANARY, UNRELIABLE_INTERCEPT,
    UNRELIABLE_MASS,
};
use crate::tcp::tls_connector;

/// Checks whether the device network intercepts TCP by connecting to `addrs`
/// (default [`INTERCEPT_PROBES`]). Skipped when a proxy is configured.
pub async fn device_intercepts_tcp(net: &NetClient, addrs: &[String], timeout: Duration) -> bool {
    let access = Access::active(MODULE);
    crate::canary::tcp_intercept_with_module(net, MODULE, &access, addrs, timeout).await
}

/// Detects mass "open" without replies: more than 40% of scanned ports open (with at least 20
/// scanned) and more than half of them silent (no banner, no TLS), the signature of a VPN or proxy that accepts everything.
pub fn mass_open(scanned: usize, open: &[PortResult]) -> bool {
    if scanned < 20 || open.len() * 10 <= scanned * 4 {
        return false;
    }
    let silent = open.iter().filter(|p| p.banner.is_none() && !p.tls).count();
    silent * 2 > open.len()
}

/// Returns the service name for a port number (when the banner told nothing).
pub fn service_name(port: u16) -> &'static str {
    match port {
        21 => "ftp",
        990 => "ftps",
        22 | 2222 => "ssh",
        23 | 2323 => "telnet",
        25 | 587 | 2525 => "smtp",
        465 => "smtps",
        53 => "domain",
        80 | 81 | 591 | 2082 | 2086 | 3000 | 5000 | 8000 | 8008 | 8080 | 8081 | 8082 | 8088
        | 8888 | 9000 | 9090 | 10000 => "http",
        443 | 2083 | 2087 | 4443 | 7443 | 8443 | 9443 | 10443 => "https",
        110 => "pop3",
        995 => "pop3s",
        111 => "rpcbind",
        135 => "msrpc",
        139 | 445 => "smb",
        143 => "imap",
        993 => "imaps",
        389 => "ldap",
        636 => "ldaps",
        1433 => "mssql",
        1521 => "oracle",
        1723 => "pptp",
        1883 => "mqtt",
        2049 => "nfs",
        2375 | 2376 => "docker",
        3128 => "http-proxy",
        3306 => "mysql",
        3389 => "rdp",
        5432 => "postgresql",
        5672 => "amqp",
        5900..=5910 => "vnc",
        5985 | 5986 => "winrm",
        6379 => "redis",
        6443 => "kubernetes",
        6667 => "irc",
        9200 => "elasticsearch",
        11211 => "memcached",
        27017 => "mongodb",
        _ => "unknown",
    }
}

fn is_tls_port(p: u16) -> bool {
    matches!(
        p,
        443 | 465
            | 636
            | 990
            | 993
            | 995
            | 2083
            | 2087
            | 4443
            | 5986
            | 6443
            | 7443
            | 8443
            | 9443
            | 10443
    )
}

fn is_http_port(p: u16) -> bool {
    service_name(p) == "http" || p == 3128
}

/// Services that wait for the client (no greeting), so an active probe is sent immediately.
fn client_speaks_first(p: u16) -> bool {
    is_http_port(p) || p == 6379
}

/// Truncates to 200 characters, replaces control characters with spaces and collapses whitespace.
pub fn clean_banner(raw: &[u8]) -> String {
    let s = String::from_utf8_lossy(raw);
    let mut out = String::new();
    let mut sp = false;
    for c in s.chars() {
        let c = if c.is_control() || c == '\u{fffd}' {
            ' '
        } else {
            c
        };
        if c == ' ' {
            if !sp && !out.is_empty() {
                out.push(' ');
            }
            sp = true;
        } else {
            out.push(c);
            sp = false;
        }
        if out.chars().count() >= 200 {
            break;
        }
    }
    out.trim_end().to_string()
}

struct Sig {
    service: &'static str,
    re: Regex,
    /// Product: a fixed name or capture group `p`.
    product: Option<&'static str>,
}

fn sigs() -> &'static [Sig] {
    static S: OnceLock<Vec<Sig>> = OnceLock::new();
    S.get_or_init(|| {
        let s = |service, re: &str, product| Sig {
            service,
            re: Regex::new(re).expect("regex"),
            product,
        };
        vec![
            s(
                "ssh",
                r"^SSH-[\d.]+-OpenSSH[_-](?P<v>[\w.]+)",
                Some("OpenSSH"),
            ),
            s(
                "ssh",
                r"^SSH-[\d.]+-dropbear_(?P<v>[\w.]+)",
                Some("Dropbear"),
            ),
            s(
                "ssh",
                r"^SSH-[\d.]+-(?P<p>[A-Za-z][\w.\-]*?)(?:[_-](?P<v>\d[\w.]*))?(?:\s|$)",
                None,
            ),
            s(
                "ftp",
                r"^220[- ].*?\(vsFTPd (?P<v>[\d.]+)\)",
                Some("vsftpd"),
            ),
            s(
                "ftp",
                r"^220[- ].*?ProFTPD (?P<v>[\d.]+\w*)",
                Some("ProFTPD"),
            ),
            s("ftp", r"^220[- ].*?Pure-FTPd", Some("Pure-FTPd")),
            s(
                "ftp",
                r"^220[- ].*?FileZilla Server(?: version)? ?(?P<v>[\d.]+\w*)?",
                Some("FileZilla Server"),
            ),
            s(
                "ftp",
                r"^220[- ].*?Microsoft FTP Service",
                Some("Microsoft ftpd"),
            ),
            s("smtp", r"^220[- ].*?ESMTP Postfix", Some("Postfix")),
            s("smtp", r"^220[- ].*?Exim (?P<v>[\d.]+)", Some("Exim")),
            s(
                "smtp",
                r"^220[- ].*?Sendmail (?P<v>[\d.]+[\w/.]*)",
                Some("Sendmail"),
            ),
            s(
                "smtp",
                r"^220[- ].*?Microsoft ESMTP MAIL Service(?:, Version: (?P<v>[\d.]+))?",
                Some("Microsoft Exchange smtpd"),
            ),
            s("smtp", r"^220[- ].*?ESMTP", None),
            s("pop3", r"^\+OK.*?Dovecot", Some("Dovecot pop3d")),
            s("pop3", r"^\+OK", None),
            s("imap", r"^\* OK.*?Dovecot", Some("Dovecot imapd")),
            s("imap", r"^\* OK.*?Courier-IMAP", Some("Courier imapd")),
            s(
                "imap",
                r"^\* OK.*?Cyrus IMAP(?:4)? v?(?P<v>[\d.]+)?",
                Some("Cyrus imapd"),
            ),
            s("imap", r"^\* OK", None),
            s("ftp", r"^220[- ]", None),
            s(
                "redis",
                r"^(?:\+PONG|-NOAUTH|-DENIED|-ERR.*(?:auth|AUTH))",
                Some("Redis"),
            ),
        ]
    })
}

/// Identifies product and version from the service banner.
fn identify(banner: &str) -> Option<(&'static str, Option<String>, Option<String>)> {
    for s in sigs() {
        if let Some(c) = s.re.captures(banner) {
            let product = s
                .product
                .map(String::from)
                .or_else(|| c.name("p").map(|m| m.as_str().to_string()));
            let version = c
                .name("v")
                .map(|m| m.as_str().to_string())
                .filter(|v| !v.is_empty());
            return Some((s.service, product, version));
        }
    }
    None
}

/// Splits `Server: nginx/1.18.0 (Ubuntu)` into (`nginx`, `1.18.0`).
fn server_product(server: &str) -> (Option<String>, Option<String>) {
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| Regex::new(r"^\s*([^/\s()]+)(?:/([\w.\-]+))?").expect("regex"));
    match re.captures(server) {
        Some(c) => (
            c.get(1).map(|m| m.as_str().to_string()),
            c.get(2).map(|m| m.as_str().to_string()),
        ),
        None => (None, None),
    }
}

/// Parses the MySQL/MariaDB greeting: `[len:3][seq][0x0a][version\0]...`.
fn mysql_version(raw: &[u8]) -> Option<(String, String)> {
    if raw.len() < 6 || raw[4] != 0x0a {
        return None;
    }
    let end = raw[5..].iter().position(|b| *b == 0)? + 5;
    let v = std::str::from_utf8(&raw[5..end]).ok()?;
    if v.is_empty() || !v.as_bytes()[0].is_ascii_digit() {
        return None;
    }
    let product = if v.contains("MariaDB") {
        "MariaDB"
    } else {
        "MySQL"
    };
    let ver = v.trim_start_matches("5.5.5-");
    let ver = ver.split(['-', ' ']).next().unwrap_or(ver);
    Some((product.into(), ver.into()))
}

async fn read_some<S: AsyncRead + Unpin>(s: &mut S, limit: usize, wait: Duration) -> Vec<u8> {
    let mut buf = vec![0u8; limit];
    let mut got = 0;
    let deadline = tokio::time::Instant::now() + wait;
    while got < limit {
        match tokio::time::timeout_at(deadline, s.read(&mut buf[got..])).await {
            Ok(Ok(n)) if n > 0 => {
                got += n;
                // line-based protocols: the first line is enough
                if buf[..got].contains(&b'\n') && got >= 4 {
                    break;
                }
            }
            _ => break,
        }
    }
    buf.truncate(got);
    buf
}

async fn http_head<S: AsyncRead + AsyncWrite + Unpin>(
    s: &mut S,
    host: &str,
    ua: &str,
    wait: Duration,
) -> Option<Vec<u8>> {
    let req = format!(
        "HEAD / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {ua}\r\nAccept: */*\r\nConnection: close\r\n\r\n"
    );
    tokio::time::timeout(wait, s.write_all(req.as_bytes()))
        .await
        .ok()?
        .ok()?;
    let mut buf = Vec::new();
    let deadline = tokio::time::Instant::now() + wait;
    let mut b = [0u8; 2048];
    while buf.len() < 16 * 1024 && !buf.windows(4).any(|w| w == b"\r\n\r\n") {
        match tokio::time::timeout_at(deadline, s.read(&mut b)).await {
            Ok(Ok(n)) if n > 0 => buf.extend_from_slice(&b[..n]),
            _ => break,
        }
    }
    (!buf.is_empty()).then_some(buf)
}

/// Parses an HTTP response (status line and `Server` header) into the result.
fn apply_http(r: &mut PortResult, raw: &[u8], tls: bool) -> bool {
    let text = String::from_utf8_lossy(raw);
    if !text.starts_with("HTTP/") {
        return false;
    }
    r.service = if tls { "https" } else { "http" }.into();
    let server = text.lines().find_map(|l| {
        let (k, v) = l.split_once(':')?;
        k.trim()
            .eq_ignore_ascii_case("server")
            .then(|| v.trim().to_string())
    });
    let status = text.lines().next().unwrap_or("").trim().to_string();
    r.banner = Some(clean_banner(
        match &server {
            Some(s) => format!("{status} · Server: {s}"),
            None => status,
        }
        .as_bytes(),
    ));
    if let Some(s) = server {
        let (p, v) = server_product(&s);
        r.product = p;
        r.version = v;
    }
    true
}

fn apply_text(r: &mut PortResult, raw: &[u8]) {
    if raw.is_empty() {
        return;
    }
    if let Some((p, v)) = mysql_version(raw) {
        r.service = "mysql".into();
        r.product = Some(p);
        r.version = Some(v);
        r.banner = Some(clean_banner(raw));
        return;
    }
    let line = clean_banner(raw);
    if let Some((svc, p, v)) = identify(&line) {
        // "220 ..." without a product on 25/587 is SMTP, not FTP
        let svc = if svc == "ftp" && matches!(service_name(r.port), "smtp" | "smtps") {
            service_name(r.port)
        } else {
            svc
        };
        r.service = svc.into();
        r.product = p;
        r.version = v;
    }
    // Recog fills what the built-in signatures left open.
    if r.product.is_none() || r.version.is_none() {
        if let Some(h) = super::recog::match_banner(&r.service, &line) {
            // Take the version only for the same product.
            let same = match (&r.product, &h.product) {
                (None, _) => true,
                (Some(a), Some(b)) => b.to_lowercase().contains(&a.to_lowercase()),
                _ => false,
            };
            if same {
                if r.version.is_none() {
                    r.version = h.version;
                }
                if r.product.is_none() {
                    r.product = h.product;
                }
            }
        }
    }
    r.banner = Some(line);
}

// ---------- TLS: only the fact of TLS and the certificate names ----------

/// Returns the subject CN (the last CN in the TBS, since the subject follows the issuer) and SAN dNSNames.
pub fn cert_names(der: &[u8]) -> Vec<String> {
    const CN: &[u8] = &[0x06, 0x03, 0x55, 0x04, 0x03];
    const SAN: &[u8] = &[0x06, 0x03, 0x55, 0x1d, 0x11];
    let mut out: Vec<String> = Vec::new();
    let find_all = |pat: &[u8]| -> Vec<usize> {
        der.windows(pat.len())
            .enumerate()
            .filter(|(_, w)| *w == pat)
            .map(|(i, _)| i + pat.len())
            .collect()
    };
    if let Some(&i) = find_all(CN).last() {
        if let (Some(_tag), Some((l, h))) = (
            der.get(i),
            i.checked_add(1)
                .and_then(|k| der.get(k..))
                .and_then(der_len),
        ) {
            if let Some(start) = i.checked_add(1).and_then(|k| k.checked_add(h)) {
                if let Some(end) = start.checked_add(l) {
                    if let Some(v) = der.get(start..end) {
                        out.push(String::from_utf8_lossy(v).to_string());
                    }
                }
            }
        }
    }
    if let Some(mut i) = find_all(SAN).first().copied() {
        // optional `critical` BOOLEAN
        if der.get(i) == Some(&0x01) {
            i = i.saturating_add(3);
        }
        if der.get(i) == Some(&0x04) {
            if let Some((_, h)) = i
                .checked_add(1)
                .and_then(|k| der.get(k..))
                .and_then(der_len)
            {
                if let Some(next_i) = i.checked_add(1).and_then(|k| k.checked_add(h)) {
                    i = next_i;
                } else {
                    i = der.len();
                }
                if der.get(i) == Some(&0x30) {
                    if let Some((l, h)) = i
                        .checked_add(1)
                        .and_then(|k| der.get(k..))
                        .and_then(der_len)
                    {
                        if let Some(mut j) = i.checked_add(1).and_then(|k| k.checked_add(h)) {
                            let end = j.saturating_add(l).min(der.len());
                            while j < end {
                                let tag = der[j];
                                let Some((l, h)) = j
                                    .checked_add(1)
                                    .and_then(|k| der.get(k..))
                                    .and_then(der_len)
                                else {
                                    break;
                                };
                                let Some(v) = j.checked_add(1).and_then(|k| k.checked_add(h))
                                else {
                                    break;
                                };
                                if l > der.len().saturating_sub(v) {
                                    break;
                                }
                                let next_j = v + l;
                                if tag == 0x82 {
                                    if let Some(x) = der.get(v..next_j) {
                                        out.push(String::from_utf8_lossy(x).to_string());
                                    }
                                }
                                j = next_j;
                            }
                        }
                    }
                }
            }
        }
    }
    let mut seen = std::collections::HashSet::new();
    out.retain(|n| !n.is_empty() && seen.insert(n.to_ascii_lowercase()));
    out.truncate(20);
    out
}

/// Grabs a banner on an already open connection (the connection is consumed and closed).
async fn banner(mut s: TcpStream, r: &mut PortResult, host: &str, ua: &str, wait: Duration) {
    let port = r.port;
    if is_tls_port(port) {
        // TLS port: handshake, certificate names, and HEAD inside TLS for HTTPS
        if let Some(conn) = tls_connector() {
            let sni = tokio_rustls::rustls::pki_types::ServerName::try_from(host.to_string())
                .unwrap_or_else(|_| {
                    tokio_rustls::rustls::pki_types::ServerName::try_from("localhost")
                        .expect("static name")
                });
            if let Ok(Ok(mut t)) = tokio::time::timeout(wait, conn.connect(sni, s)).await {
                r.tls = true;
                if let Some(c) = t.get_ref().1.peer_certificates().and_then(|c| c.first()) {
                    r.cert_names = cert_names(c.as_ref());
                }
                if r.service == "unknown" {
                    r.service = "ssl".into();
                }
                let speaks_http = matches!(service_name(port), "https" | "kubernetes" | "winrm");
                if speaks_http {
                    if let Some(raw) = http_head(&mut t, host, ua, wait).await {
                        apply_http(r, &raw, true);
                    }
                } else {
                    let raw = read_some(&mut t, 512, wait).await;
                    apply_text(r, &raw);
                    // imaps/pop3s/smtps/ftps (implicit TLS) keep the "s" variant of the name
                    if matches!(
                        service_name(port),
                        "imaps" | "pop3s" | "smtps" | "ldaps" | "ftps"
                    ) {
                        r.service = service_name(port).into();
                    }
                }
            }
        }
        return;
    }
    if port == 6379 {
        let _ = s.write_all(b"PING\r\n").await;
        let raw = read_some(&mut s, 256, wait).await;
        apply_text(r, &raw);
        redis_confirm(r, &raw);
        return;
    }
    let Some(mut s) = probe_protocol(s, r, host, ua, wait).await else {
        return;
    };
    if !client_speaks_first(port) {
        // passively wait for a greeting
        let raw = read_some(&mut s, 512, wait.min(Duration::from_millis(2500))).await;
        if !raw.is_empty() {
            apply_text(r, &raw);
            return;
        }
    }
    // silent or an HTTP port: send HEAD /
    if let Some(raw) = http_head(&mut s, host, ua, wait).await {
        if !apply_http(r, &raw, false) {
            apply_text(r, &raw);
        }
    }
}

/// Returns `true` if the greeting confirms the protocol, i.e. the service derived from the banner
/// matches the one expected for the port (FTP "220", SSH, MySQL, Telnet, ...); an empty banner confirms nothing.
pub fn greeting_confirms(r: &PortResult) -> bool {
    let Some(b) = r.banner.as_deref() else {
        return false;
    };
    if b.is_empty() {
        return false;
    }
    let want = service_name(r.port);
    match want {
        "telnet" => true,
        "unknown" => false,
        w => r.service == w || (w == "ftps" && r.service == "ftp"),
    }
}

fn redis_confirm(r: &mut PortResult, raw: &[u8]) {
    let t = String::from_utf8_lossy(raw).to_ascii_uppercase();
    if t.starts_with("+PONG") {
        r.confirmed = true;
        r.service = "redis".into();
        r.detail = Some("no-auth".into());
    } else if t.starts_with("-NOAUTH") || t.starts_with("-DENIED") || t.starts_with("-ERR") {
        r.confirmed = true;
        r.service = "redis".into();
        r.detail = Some("auth".into());
    }
}

/// Sends an HTTP/1.1 GET for `path` and returns headers plus body, up to 16 KiB.
async fn http_get<S: AsyncRead + AsyncWrite + Unpin>(
    s: &mut S,
    host: &str,
    ua: &str,
    path: &str,
    wait: Duration,
) -> Option<String> {
    let req = format!(
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {ua}\r\nAccept: application/json\r\nConnection: close\r\n\r\n"
    );
    tokio::time::timeout(wait, s.write_all(req.as_bytes()))
        .await
        .ok()?
        .ok()?;
    let mut buf = Vec::new();
    let deadline = tokio::time::Instant::now() + wait;
    let mut b = [0u8; 4096];
    while buf.len() < 16 * 1024 {
        match tokio::time::timeout_at(deadline, s.read(&mut b)).await {
            Ok(Ok(n)) if n > 0 => buf.extend_from_slice(&b[..n]),
            _ => break,
        }
    }
    (!buf.is_empty()).then(|| String::from_utf8_lossy(&buf).into_owned())
}

/// Extracts a string or numeric JSON field `"key":"v"` from a raw reply without parsing the body.
fn json_field(text: &str, key: &str) -> Option<String> {
    let pat = format!("\"{key}\"");
    let i = text.find(&pat)? + pat.len();
    let rest = text[i..].trim_start().strip_prefix(':')?.trim_start();
    let v: String = rest
        .trim_start_matches('"')
        .chars()
        .take_while(|c| !matches!(c, '"' | ',' | '}'))
        .collect();
    (!v.is_empty()).then_some(v)
}

/// Docker Engine API: `GET /version` returns JSON with `ApiVersion`.
fn docker_confirm(r: &mut PortResult, text: &str) -> bool {
    if !text.contains("\"ApiVersion\"") {
        return false;
    }
    r.confirmed = true;
    r.service = "docker".into();
    r.product = Some("Docker".into());
    r.version = json_field(text, "Version");
    r.banner = Some(clean_banner(
        format!("Docker API {}", r.version.clone().unwrap_or_default()).as_bytes(),
    ));
    r.detail = Some("no-auth".into());
    true
}

/// Builds an SMB1 negotiate request (dialects NT LM 0.12 and SMB 2.x) inside a NetBIOS session.
fn smb_negotiate() -> Vec<u8> {
    let mut smb = vec![
        0xff, b'S', b'M', b'B', 0x72, 0, 0, 0, 0, 0x18, 0x01, 0x28, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0xff, 0xfe, 0, 0, 0, 0, 0,
    ];
    let mut d = Vec::new();
    for x in ["NT LM 0.12", "SMB 2.002", "SMB 2.???"] {
        d.push(2u8);
        d.extend_from_slice(x.as_bytes());
        d.push(0);
    }
    smb.extend_from_slice(&(d.len() as u16).to_le_bytes());
    smb.extend_from_slice(&d);
    let mut out = vec![0u8, 0, 0, 0];
    out[1..4].copy_from_slice(&(smb.len() as u32).to_be_bytes()[1..]);
    out.extend_from_slice(&smb);
    out
}

/// Builds a MongoDB OP_QUERY `admin.$cmd {isMaster: 1}` (legacy protocol, still understood by new servers).
fn mongo_is_master() -> Vec<u8> {
    let mut doc = Vec::new();
    doc.push(0x10u8); // int32
    doc.extend_from_slice(b"isMaster\0");
    doc.extend_from_slice(&1i32.to_le_bytes());
    doc.push(0);
    let mut bson = ((doc.len() + 4) as i32).to_le_bytes().to_vec();
    bson.extend_from_slice(&doc);
    let mut body = Vec::new();
    body.extend_from_slice(&0i32.to_le_bytes()); // flags
    body.extend_from_slice(b"admin.$cmd\0");
    body.extend_from_slice(&0i32.to_le_bytes()); // skip
    body.extend_from_slice(&1i32.to_le_bytes()); // return
    body.extend_from_slice(&bson);
    let mut msg = ((16 + body.len()) as i32).to_le_bytes().to_vec();
    msg.extend_from_slice(&0x4632i32.to_le_bytes()); // requestID
    msg.extend_from_slice(&0i32.to_le_bytes());
    msg.extend_from_slice(&2004i32.to_le_bytes()); // OP_QUERY
    msg.extend_from_slice(&body);
    msg
}

/// Runs active probes for sensitive protocols. Returns `None` if the port was handled (the
/// connection is consumed), or `Some(s)` if no probe applies and the connection is handed back.
async fn probe_protocol(
    mut st: TcpStream,
    r: &mut PortResult,
    host: &str,
    ua: &str,
    wait: Duration,
) -> Option<TcpStream> {
    let s = &mut st;
    let handled = match r.port {
        2375 => {
            if let Some(t) = http_get(s, host, ua, "/version", wait).await {
                if !docker_confirm(r, &t) && t.starts_with("HTTP/") {
                    apply_http(r, t.as_bytes(), false);
                }
            }
            true
        }
        2376 => {
            // Docker TLS port: accepting a client without a certificate means full access
            let conn = tls_connector()?;
            let sni = tokio_rustls::rustls::pki_types::ServerName::try_from(host.to_string())
                .unwrap_or_else(|_| {
                    tokio_rustls::rustls::pki_types::ServerName::try_from("localhost")
                        .expect("static name")
                });
            if let Ok(Ok(mut t)) = tokio::time::timeout(wait, conn.connect(sni, st)).await {
                r.tls = true;
                if let Some(c) = t.get_ref().1.peer_certificates().and_then(|c| c.first()) {
                    r.cert_names = cert_names(c.as_ref());
                }
                match http_get(&mut t, host, ua, "/version", wait).await {
                    Some(x) if docker_confirm(r, &x) => {}
                    _ => {
                        // the handshake succeeded but the request was rejected or cut off: a client certificate is required
                        r.service = "docker".into();
                        r.detail = Some("client-cert".into());
                        r.banner = Some("TLS: client certificate required".into());
                    }
                }
            }
            return None;
        }
        9200 => {
            if let Some(t) = http_get(s, host, ua, "/", wait).await {
                if t.contains("\"cluster_name\"") || t.contains("You Know, for Search") {
                    r.confirmed = true;
                    r.service = "elasticsearch".into();
                    r.product = Some("Elasticsearch".into());
                    r.version = json_field(&t, "number");
                    r.detail = Some("no-auth".into());
                    r.banner = Some(clean_banner(
                        format!("Elasticsearch {}", r.version.clone().unwrap_or_default())
                            .as_bytes(),
                    ));
                } else if t.contains("security_exception") || t.contains("realm=\"security\"") {
                    r.confirmed = true;
                    r.service = "elasticsearch".into();
                    r.product = Some("Elasticsearch".into());
                    r.detail = Some("auth".into());
                    apply_http(r, t.as_bytes(), false);
                    r.service = "elasticsearch".into();
                } else if t.starts_with("HTTP/") {
                    apply_http(r, t.as_bytes(), false);
                }
            }
            true
        }
        27017 => {
            let _ = tokio::time::timeout(wait, s.write_all(&mongo_is_master())).await;
            let raw = read_some(s, 4096, wait).await;
            // reply header: length, requestID, responseTo, opCode (1 = OP_REPLY, 2013 = OP_MSG)
            if raw.len() >= 16 {
                let op = i32::from_le_bytes([raw[12], raw[13], raw[14], raw[15]]);
                if op == 1 || op == 2013 {
                    r.confirmed = true;
                    r.service = "mongodb".into();
                    r.product = Some("MongoDB".into());
                    r.banner = Some("MongoDB (isMaster reply)".into());
                    if String::from_utf8_lossy(&raw).contains("Unauthorized") {
                        r.detail = Some("auth".into());
                    }
                }
            }
            true
        }
        3389 => {
            const X224: &[u8] = &[3, 0, 0, 19, 14, 0xe0, 0, 0, 0, 0, 0, 1, 0, 8, 0, 3, 0, 0, 0];
            let _ = tokio::time::timeout(wait, s.write_all(X224)).await;
            let raw = read_some(s, 64, wait).await;
            if raw.len() >= 4 && raw[0] == 3 && raw[1] == 0 {
                r.confirmed = true;
                r.service = "rdp".into();
                r.banner = Some("RDP (X.224)".into());
            }
            true
        }
        139 | 445 => {
            let _ = tokio::time::timeout(wait, s.write_all(&smb_negotiate())).await;
            let raw = read_some(s, 512, wait).await;
            if raw.windows(4).any(|w| w == b"\xffSMB" || w == b"\xfeSMB") {
                r.confirmed = true;
                r.service = "smb".into();
                r.banner = Some(
                    if raw.windows(4).any(|w| w == b"\xfeSMB") {
                        "SMB2/3"
                    } else {
                        "SMB1"
                    }
                    .into(),
                );
            }
            true
        }
        5432 => {
            let _ =
                tokio::time::timeout(wait, s.write_all(&[0, 0, 0, 8, 4, 0xd2, 0x16, 0x2f])).await;
            let raw = read_some(s, 8, wait).await;
            if raw.len() == 1 && (raw[0] == b'S' || raw[0] == b'N') {
                r.confirmed = true;
                r.service = "postgresql".into();
                r.product = Some("PostgreSQL".into());
                r.banner = Some(format!(
                    "PostgreSQL (SSL: {})",
                    if raw[0] == b'S' { "yes" } else { "no" }
                ));
            }
            true
        }
        _ => false,
    };
    if handled {
        None
    } else {
        Some(st)
    }
}

/// Probes a canary: connect only, no banner. `Some(true)` means open, `None` means cancelled.
async fn canary(sh: Arc<Shared>, port: u16) -> Option<bool> {
    if let Some(b) = &sh.bucket {
        if b.acquire(sh.net.cancel_token()).await.is_err() {
            return None;
        }
    }
    let url = format!("tcp://{}:{port}", sh.host);
    let mut rec = sh.net.draft(MODULE, "TCP", &url, &sh.host, &sh.access);
    rec.url = format!("{url} (canary)");
    let ips: &[IpAddr] = if sh.ips.is_empty() { &[] } else { &sh.ips[..1] };
    let r = sh
        .net
        .cancellable(crate::tcp::dial(
            &sh.net,
            &sh.host,
            ips,
            port,
            sh.cfg.timeout,
        ))
        .await;
    let out = match r {
        Err(_) => {
            rec.error = Some("cancelled".into());
            None
        }
        Ok(Ok(_)) => {
            rec.status = Some(0);
            Some(true)
        }
        Ok(Err(e)) => {
            rec.error = Some(format!("{}: {e}", e.code()));
            Some(false)
        }
    };
    sh.net.record(rec);
    out
}

enum Probe {
    Open(Box<PortResult>),
    Closed,
    Filtered,
    Cancelled,
}

struct Shared {
    net: NetClient,
    host: String,
    ips: Vec<IpAddr>,
    access: Access,
    cfg: PortScanConfig,
    bucket: Option<TokenBucket>,
    ua: String,
}

async fn probe(sh: Arc<Shared>, port: u16) -> Probe {
    if let Some(b) = &sh.bucket {
        if b.acquire(sh.net.cancel_token()).await.is_err() {
            return Probe::Cancelled;
        }
    }
    let url = format!("tcp://{}:{port}", sh.host);
    let mut rec = sh.net.draft(MODULE, "TCP", &url, &sh.host, &sh.access);
    let t = Instant::now();
    let ips: &[IpAddr] = if sh.ips.is_empty() { &[] } else { &sh.ips[..1] };
    let r = sh
        .net
        .cancellable(crate::tcp::dial(
            &sh.net,
            &sh.host,
            ips,
            port,
            sh.cfg.timeout,
        ))
        .await;
    let out = match r {
        Err(_) => {
            rec.error = Some("cancelled".into());
            Probe::Cancelled
        }
        Ok(Ok((s, ip))) => {
            rec.status = Some(0);
            if let Some(ip) = ip {
                rec.url = format!("{url} ({ip})");
            }
            let mut pr = PortResult {
                port,
                service: service_name(port).into(),
                banner: None,
                product: None,
                version: None,
                tls: false,
                cert_names: Vec::new(),
                confirmed: false,
                detail: None,
            };
            if sh.cfg.banners {
                let w = sh.cfg.banner_timeout;
                let host = sh.host.clone();
                let ua = sh.ua.clone();
                let _ = sh.net.cancellable(banner(s, &mut pr, &host, &ua, w)).await;
                // The server reset the connection without a greeting (sshd MaxStartups under load and
                // similar): retry once with a new connection, also logged.
                if pr.banner.is_none() && !pr.tls && !sh.net.is_cancelled() {
                    let mut rec2 = sh.net.draft(MODULE, "TCP", &url, &sh.host, &sh.access);
                    rec2.url = format!("{url} (banner-retry)");
                    let again = sh
                        .net
                        .cancellable(crate::tcp::dial(
                            &sh.net,
                            &sh.host,
                            ips,
                            port,
                            sh.cfg.timeout,
                        ))
                        .await;
                    // The retry did not connect (refused or timed out), so the port is not counted as open:
                    // tarpits, load balancers and VPNs behave like this after accepting the first connection.
                    let mut lost: Option<Probe> = None;
                    match again {
                        Ok(Ok((s, _))) => {
                            rec2.status = Some(0);
                            let _ = sh.net.cancellable(banner(s, &mut pr, &host, &ua, w)).await;
                        }
                        Ok(Err(NetError::Timeout)) => {
                            rec2.error = Some("timeout: filtered".into());
                            lost = Some(Probe::Filtered);
                        }
                        Ok(Err(e)) => {
                            rec2.error = Some(format!("{}: {e}", e.code()));
                            lost = Some(Probe::Closed);
                        }
                        Err(_) => rec2.error = Some("cancelled".into()),
                    }
                    sh.net.record(rec2);
                    if let Some(l) = lost {
                        rec.error = Some("unconfirmed: banner retry failed".into());
                        sh.net.record(rec);
                        return l;
                    }
                }
                if !pr.confirmed && greeting_confirms(&pr) {
                    pr.confirmed = true;
                }
                rec.bytes = pr.banner.as_ref().map(|b| b.len() as u64).unwrap_or(0);
            } else {
                drop(s);
            }
            Probe::Open(Box::new(pr))
        }
        Ok(Err(NetError::Timeout)) => {
            rec.error = Some("timeout: filtered".into());
            Probe::Filtered
        }
        Ok(Err(e)) => {
            rec.error = Some(format!("{}: {e}", e.code()));
            Probe::Closed
        }
    };
    tracing::trace!(target: "foca::net", "ports {url}: {} мс", t.elapsed().as_millis());
    sh.net.record(rec);
    out
}

/// Returns the new batch size: halved if more than half timed out, grown 1.5x if fewer than 10% did.
pub fn adapt(batch: usize, timeouts: usize, n: usize, min: usize, max: usize) -> usize {
    if timeouts * 2 > n {
        (batch / 2).max(min)
    } else if timeouts * 10 < n {
        (batch + batch / 2).min(max)
    } else {
        batch
    }
}

/// Scans the TCP ports of a host (active module).
///
/// Cancellation mid-scan is not an error: the result has `cancelled: true` and whatever was
/// scanned so far.
///
/// # Errors
///
/// Fails only on a scope or resolution denial, or on cancellation before the scan starts.
pub async fn scan_ports(
    net: &NetClient,
    host: &str,
    cfg: &PortScanConfig,
) -> Result<PortScan, NetError> {
    let t0 = Instant::now();
    let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
    let access = Access::active(MODULE);
    let ips = net
        .authorize_logged(MODULE, "TCP", &format!("tcp://{host}"), &host, &access)
        .await?;
    if ips.is_empty() && !net.has_proxy() {
        return Err(NetError::Dns(format!("{host}: нет адресов")));
    }
    let min = cfg.min_batch.max(1);
    let max = cfg.max_batch.max(min);
    let mut batch = cfg.batch.clamp(min, max);
    let sh = Arc::new(Shared {
        net: net.clone(),
        host: host.clone(),
        ips: ips.clone(),
        access,
        cfg: cfg.clone(),
        bucket: cfg
            .rps
            .filter(|r| *r > 0.0)
            .map(|r| TokenBucket::new(r, (batch as f64).min(r.max(1.0)))),
        ua: net.config().user_agent.clone(),
    });
    let mut out = PortScan {
        host: host.clone(),
        ip: if net.has_proxy() {
            None
        } else {
            ips.first().map(|i| i.to_string())
        },
        open: Vec::new(),
        scanned: 0,
        closed: 0,
        filtered: 0,
        ms: 0,
        batch,
        cancelled: false,
        unreliable: None,
        canaries: 0,
        canaries_open: 0,
    };
    let canaries = cfg
        .canaries
        .clone()
        .unwrap_or_else(|| pick_canaries(3, &cfg.ports));
    if !canaries.is_empty() {
        let mut set = tokio::task::JoinSet::new();
        for &p in &canaries {
            set.spawn(canary(sh.clone(), p));
        }
        while let Some(r) = set.join_next().await {
            match r {
                Ok(Some(open)) => {
                    out.canaries += 1;
                    out.canaries_open += open as usize;
                }
                _ => out.cancelled = true,
            }
        }
        if out.cancelled {
            out.ms = t0.elapsed().as_millis() as u64;
            return Ok(out);
        }
        if out.canaries_open * 2 > out.canaries {
            out.unreliable = Some(UNRELIABLE_CANARY.into());
            out.ms = t0.elapsed().as_millis() as u64;
            return Ok(out);
        }
    }
    let mut i = 0;
    while i < cfg.ports.len() {
        if net.is_cancelled() {
            out.cancelled = true;
            break;
        }
        let chunk = &cfg.ports[i..(i + batch).min(cfg.ports.len())];
        let mut set = tokio::task::JoinSet::new();
        for &p in chunk {
            set.spawn(probe(sh.clone(), p));
        }
        let mut timeouts = 0usize;
        let mut done = 0usize;
        while let Some(r) = set.join_next().await {
            match r {
                Ok(Probe::Open(pr)) => {
                    out.open.push(*pr);
                    done += 1;
                }
                Ok(Probe::Closed) => {
                    out.closed += 1;
                    done += 1;
                }
                Ok(Probe::Filtered) => {
                    out.filtered += 1;
                    timeouts += 1;
                    done += 1;
                }
                Ok(Probe::Cancelled) | Err(_) => out.cancelled = true,
            }
        }
        out.scanned += done;
        batch = adapt(batch, timeouts, chunk.len(), min, max);
        i += chunk.len();
        if out.cancelled {
            break;
        }
    }
    out.open.sort_by_key(|p| p.port);
    if !out.cancelled && mass_open(out.scanned, &out.open) {
        out.unreliable = Some(UNRELIABLE_MASS.into());
    }
    out.batch = batch;
    out.ms = t0.elapsed().as_millis() as u64;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pr0(port: u16) -> PortResult {
        PortResult {
            port,
            service: service_name(port).into(),
            banner: None,
            product: None,
            version: None,
            tls: false,
            cert_names: vec![],
            confirmed: false,
            detail: None,
        }
    }

    #[test]
    fn protocol_confirmation() {
        let mut d = pr0(2375);
        assert!(!docker_confirm(
            &mut d,
            "HTTP/1.1 404 Not Found\r\n\r\n<html>"
        ));
        assert!(docker_confirm(
            &mut d,
            "HTTP/1.1 200 OK\r\n\r\n{\"Platform\":{},\"Version\":\"24.0.7\",\"ApiVersion\":\"1.43\"}"
        ));
        assert!(d.confirmed && d.version.as_deref() == Some("24.0.7"));
        let mut r = pr0(6379);
        redis_confirm(&mut r, b"-NOAUTH Authentication required.\r\n");
        assert!(r.confirmed && r.detail.as_deref() == Some("auth"));
        let mut r = pr0(6379);
        redis_confirm(&mut r, b"");
        assert!(!r.confirmed, "an empty reply is not Redis");
        // a greeting confirms only its own protocol
        let mut f = pr0(21);
        f.banner = Some("220 (vsFTPd 3.0.5)".into());
        f.service = "ftp".into();
        assert!(greeting_confirms(&f));
        let mut m = pr0(3306);
        assert!(!greeting_confirms(&m), "no banner");
        m.banner = Some("HTTP/1.1 400".into());
        m.service = "http".into();
        assert!(
            !greeting_confirms(&m),
            "HTTP on the MySQL port is not MySQL"
        );
        assert_eq!(service_name(990), "ftps");
        // OP_QUERY: the header length equals the message length, opCode 2004
        let q = mongo_is_master();
        assert_eq!(
            i32::from_le_bytes([q[0], q[1], q[2], q[3]]) as usize,
            q.len()
        );
        assert_eq!(i32::from_le_bytes([q[12], q[13], q[14], q[15]]), 2004);
        let n = smb_negotiate();
        assert_eq!(
            u32::from_be_bytes([0, n[1], n[2], n[3]]) as usize,
            n.len() - 4
        );
        assert_eq!(&n[4..8], b"\xffSMB");
        assert_eq!(
            json_field("{\"number\" : \"8.11.1\",", "number").as_deref(),
            Some("8.11.1")
        );
    }

    #[test]
    fn lists() {
        assert_eq!(TOP_100.len(), 100);
        let set: std::collections::HashSet<_> = TOP_100.iter().collect();
        assert_eq!(set.len(), 100, "duplicates in TOP_100");
        let t = top_ports(1000);
        assert_eq!(t.len(), 1000);
        assert_eq!(
            t.iter().collect::<std::collections::HashSet<_>>().len(),
            1000
        );
        assert_eq!(&t[..100], &TOP_100[..]);
        assert_eq!(top_ports(100), TOP_100.to_vec());
        assert!(t.contains(&5432) && t.contains(&1) && t.contains(&3389));
    }

    #[test]
    fn batch_adapts() {
        assert_eq!(adapt(64, 40, 64, 8, 200), 32);
        assert_eq!(adapt(10, 9, 10, 8, 200), 8);
        assert_eq!(adapt(64, 0, 64, 8, 200), 96);
        assert_eq!(adapt(180, 0, 180, 8, 200), 200);
        assert_eq!(adapt(64, 10, 64, 8, 200), 64);
    }

    #[test]
    fn port_spec() {
        assert_eq!(
            parse_ports("22, 80,8000-8002,80").unwrap(),
            vec![22, 80, 8000, 8001, 8002]
        );
        assert!(parse_ports("0").is_err());
        assert!(parse_ports("90-80").is_err());
        assert!(parse_ports("x").is_err());
        assert!(parse_ports(" , ").is_err());
    }

    #[test]
    fn banners_identify() {
        let cases: &[(&str, &str, Option<&str>, Option<&str>)] = &[
            (
                "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n",
                "ssh",
                Some("OpenSSH"),
                Some("8.9p1"),
            ),
            (
                "SSH-2.0-dropbear_2022.83\r\n",
                "ssh",
                Some("Dropbear"),
                Some("2022.83"),
            ),
            (
                "220 (vsFTPd 3.0.3)\r\n",
                "ftp",
                Some("vsftpd"),
                Some("3.0.3"),
            ),
            (
                "220 ProFTPD 1.3.5e Server ready.\r\n",
                "ftp",
                Some("ProFTPD"),
                Some("1.3.5e"),
            ),
            (
                "220 mail.example.com ESMTP Postfix (Ubuntu)\r\n",
                "smtp",
                Some("Postfix"),
                None,
            ),
            (
                "220 mx ESMTP Exim 4.96 Mon, 1 Jan\r\n",
                "smtp",
                Some("Exim"),
                Some("4.96"),
            ),
            (
                "+OK Dovecot (Ubuntu) ready.\r\n",
                "pop3",
                Some("Dovecot pop3d"),
                None,
            ),
            (
                "* OK [CAPABILITY IMAP4rev1] Dovecot ready.\r\n",
                "imap",
                Some("Dovecot imapd"),
                None,
            ),
            (
                "-NOAUTH Authentication required.\r\n",
                "redis",
                Some("Redis"),
                None,
            ),
        ];
        for (raw, svc, p, v) in cases {
            let mut r = PortResult {
                port: 1,
                service: "unknown".into(),
                banner: None,
                product: None,
                version: None,
                tls: false,
                cert_names: vec![],
                confirmed: false,
                detail: None,
            };
            apply_text(&mut r, raw.as_bytes());
            assert_eq!(
                (
                    r.service.as_str(),
                    r.product.as_deref(),
                    r.version.as_deref()
                ),
                (*svc, *p, *v),
                "{raw}"
            );
            assert!(!r.banner.unwrap().contains('\r'));
        }
        let my = b"\x4a\x00\x00\x00\x0a8.0.36-0ubuntu0.22.04.1\x00\x08\x00\x00\x00";
        assert_eq!(mysql_version(my), Some(("MySQL".into(), "8.0.36".into())));
        let maria = b"\x5b\x00\x00\x00\x0a5.5.5-10.6.12-MariaDB-0ubuntu0\x00";
        assert_eq!(
            mysql_version(maria),
            Some(("MariaDB".into(), "10.6.12".into()))
        );
        assert_eq!(
            server_product("Apache/2.4.29 (Ubuntu)"),
            (Some("Apache".into()), Some("2.4.29".into()))
        );
        assert_eq!(
            server_product("cloudflare"),
            (Some("cloudflare".into()), None)
        );
    }

    #[test]
    fn banner_is_cleaned_and_cut() {
        let s = clean_banner(b"a\x00\x1b[31mb\r\n\tc");
        assert_eq!(s, "a [31mb c");
        assert_eq!(clean_banner(&[b'x'; 500]).chars().count(), 200);
    }

    #[test]
    fn san_and_cn_from_der() {
        // minimal fragment: issuer CN=CA, subject CN=a.test, SAN dNSName a.test, www.a.test
        let mut der = Vec::new();
        der.extend_from_slice(&[0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x02]);
        der.extend_from_slice(b"CA");
        der.extend_from_slice(&[0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x06]);
        der.extend_from_slice(b"a.test");
        der.extend_from_slice(&[
            0x06, 0x03, 0x55, 0x1d, 0x11, 0x04, 0x16, 0x30, 0x14, 0x82, 0x06,
        ]);
        der.extend_from_slice(b"a.test");
        der.extend_from_slice(&[0x82, 0x0a]);
        der.extend_from_slice(b"www.a.test");
        assert_eq!(cert_names(&der), vec!["a.test", "www.a.test"]);
    }

    #[test]
    fn cert_names_handles_oversized_der_length_without_panic_or_loop() {
        // SAN sequence with crafted 4-byte length = u32::MAX must exit cleanly
        let crafted = vec![
            0x06, 0x03, 0x55, 0x1d, 0x11, // SAN OID
            0x04, 0x09, // OCTET STRING len 9
            0x30, 0x07, // SEQUENCE len 7
            0x82, 0x84, 0xFF, 0xFF, 0xFF, 0xFF, // dNSName with length 0xFFFF_FFFF
            b'a',
        ];
        assert!(cert_names(&crafted).is_empty());
    }
}
