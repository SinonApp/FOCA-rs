//! DNS lookups (A/AAAA/MX/NS/TXT/SOA/CNAME/SRV/CAA/PTR/DS/DNSKEY) via hickory-resolver.
//!
//! Built without `system-config`: Android has no `/etc/resolv.conf`, and reading system
//! settings over JNI requires extra initialization. Servers come from the settings, then from
//! `/etc/resolv.conf` if present, then fall back to 1.1.1.1 / 8.8.8.8. Logic on top of DNS
//! (mail, dangling CNAMEs, subdomain liveness) goes through the [`DnsLookup`] trait and is
//! tested offline against [`StaticDns`].

pub mod axfr;
pub mod bruteforce;
pub mod doh;
pub mod mail;
pub mod nsec;
pub mod permute;
pub mod ptr;
pub mod takeover;

use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use hickory_resolver::config::{NameServerConfig, ResolverConfig, ResolverOpts};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::proto::rr::{RData, RecordType};
use hickory_resolver::TokioResolver;
use serde::{Deserialize, Serialize};

use crate::client::{Access, NetClient};
use crate::{BoxFuture, NetError};

/// DNS record type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum RType {
    A,
    AAAA,
    MX,
    NS,
    TXT,
    SOA,
    CNAME,
    SRV,
    CAA,
    PTR,
    /// Delegation signer at the parent zone (DNSSEC); the value is the raw rdata.
    DS,
    /// Zone signing keys (DNSSEC); the value is the raw rdata.
    DNSKEY,
}

impl RType {
    pub fn as_str(self) -> &'static str {
        match self {
            RType::A => "A",
            RType::AAAA => "AAAA",
            RType::MX => "MX",
            RType::NS => "NS",
            RType::TXT => "TXT",
            RType::SOA => "SOA",
            RType::CNAME => "CNAME",
            RType::SRV => "SRV",
            RType::CAA => "CAA",
            RType::PTR => "PTR",
            RType::DS => "DS",
            RType::DNSKEY => "DNSKEY",
        }
    }

    fn to_hickory(self) -> RecordType {
        match self {
            RType::A => RecordType::A,
            RType::AAAA => RecordType::AAAA,
            RType::MX => RecordType::MX,
            RType::NS => RecordType::NS,
            RType::TXT => RecordType::TXT,
            RType::SOA => RecordType::SOA,
            RType::CNAME => RecordType::CNAME,
            RType::SRV => RecordType::SRV,
            RType::CAA => RecordType::CAA,
            RType::PTR => RecordType::PTR,
            RType::DS => RecordType::DS,
            RType::DNSKEY => RecordType::DNSKEY,
        }
    }
}

/// A normalized record (names without the trailing dot, TXT strings concatenated).
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct DnsRecord {
    pub name: String,
    pub rtype: String,
    pub ttl: u32,
    pub value: String,
}

/// A lookup answer: records (possibly empty, i.e. NODATA) or NXDOMAIN.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsAnswer {
    pub records: Vec<DnsRecord>,
    pub nxdomain: bool,
}

impl DnsAnswer {
    /// Returns the values of records of type `t` (a CNAME chain in the answer is filtered out).
    pub fn values(&self, t: RType) -> Vec<String> {
        self.records
            .iter()
            .filter(|r| r.rtype == t.as_str())
            .map(|r| r.value.clone())
            .collect()
    }
}

/// Source of DNS answers.
pub trait DnsLookup: Send + Sync {
    fn lookup<'a>(&'a self, name: &'a str, t: RType) -> BoxFuture<'a, Result<DnsAnswer, NetError>>;
}

/// Lowercases a name and strips the trailing dot.
pub fn norm_name(s: &str) -> String {
    s.trim().trim_end_matches('.').to_ascii_lowercase()
}

/// Resolver settings.
#[derive(Debug, Clone)]
pub struct DnsConfig {
    /// Explicit servers (`settings.net.dns_custom`); if empty, `/etc/resolv.conf` is used, then the fallback.
    pub servers: Vec<IpAddr>,
    pub fallback: Vec<IpAddr>,
    pub timeout: Duration,
    pub attempts: usize,
    /// Path to resolv.conf (for tests).
    pub resolv_conf: Option<String>,
}

impl Default for DnsConfig {
    fn default() -> Self {
        DnsConfig {
            servers: Vec::new(),
            fallback: vec![IpAddr::from([1, 1, 1, 1]), IpAddr::from([8, 8, 8, 8])],
            timeout: Duration::from_secs(5),
            attempts: 2,
            resolv_conf: Some("/etc/resolv.conf".into()),
        }
    }
}

/// Parses `nameserver` entries from resolv.conf.
pub fn parse_resolv_conf(text: &str) -> Vec<IpAddr> {
    text.lines()
        .filter_map(|l| {
            let l = l.trim();
            let rest = l.strip_prefix("nameserver")?;
            // interface scopes (fe80::1%eth0) are not supported
            rest.split_whitespace()
                .next()?
                .split('%')
                .next()?
                .parse()
                .ok()
        })
        .collect()
}

impl DnsConfig {
    /// Returns the effective server list.
    pub fn effective_servers(&self) -> Vec<IpAddr> {
        if !self.servers.is_empty() {
            return self.servers.clone();
        }
        if let Some(p) = &self.resolv_conf {
            if let Ok(t) = std::fs::read_to_string(p) {
                let mut v = parse_resolv_conf(&t);
                let mut seen = std::collections::HashSet::new();
                v.retain(|ip| seen.insert(*ip));
                if !v.is_empty() {
                    return v;
                }
            }
        }
        self.fallback.clone()
    }
}

/// hickory-based resolver. Every query is logged (module `dns`, method `DNS`).
pub struct HickoryDns {
    resolver: TokioResolver,
    net: NetClient,
}

impl HickoryDns {
    pub fn new(cfg: &DnsConfig, net: &NetClient) -> Result<Self, NetError> {
        let servers = cfg.effective_servers();
        let ns: Vec<NameServerConfig> = servers
            .iter()
            .map(|ip| NameServerConfig::udp_and_tcp(*ip))
            .collect();
        let config = ResolverConfig::from_name_servers(ns);
        let mut opts = ResolverOpts::default();
        opts.timeout = cfg.timeout;
        opts.attempts = cfg.attempts;
        opts.ndots = 0;
        let resolver = TokioResolver::builder_with_config(config, TokioRuntimeProvider::default())
            .with_options(opts)
            .build()
            .map_err(|e| NetError::Dns(e.to_string()))?;
        Ok(HickoryDns {
            resolver,
            net: net.clone(),
        })
    }
}

fn rdata_value(d: &RData) -> String {
    match d {
        RData::TXT(t) => t
            .txt_data
            .iter()
            .map(|b| String::from_utf8_lossy(b).into_owned())
            .collect::<Vec<_>>()
            .join(""),
        RData::CNAME(c) => norm_name(&c.0.to_string()),
        RData::NS(n) => norm_name(&n.0.to_string()),
        RData::PTR(p) => norm_name(&p.0.to_string()),
        RData::MX(m) => format!("{} {}", m.preference, norm_name(&m.exchange.to_string())),
        other => other.to_string(),
    }
}

impl DnsLookup for HickoryDns {
    fn lookup<'a>(&'a self, name: &'a str, t: RType) -> BoxFuture<'a, Result<DnsAnswer, NetError>> {
        Box::pin(async move {
            let qname = format!("{}.", norm_name(name));
            let mut rec = self.net.draft(
                "dns",
                "DNS",
                &format!("dns://{}/{}", norm_name(name), t.as_str()),
                &norm_name(name),
                &Access::Passive,
            );
            let r = self
                .net
                .cancellable(self.resolver.lookup(qname.as_str(), t.to_hickory()))
                .await?;
            match r {
                Ok(l) => {
                    let records: Vec<DnsRecord> = l
                        .answers()
                        .iter()
                        .map(|r| DnsRecord {
                            name: norm_name(&r.name.to_string()),
                            rtype: r.record_type().to_string(),
                            ttl: r.ttl,
                            value: rdata_value(&r.data),
                        })
                        .collect();
                    rec.status = Some(0);
                    rec.bytes = records.len() as u64;
                    self.net.record(rec);
                    Ok(DnsAnswer {
                        records,
                        nxdomain: false,
                    })
                }
                Err(e) if e.is_nx_domain() => {
                    rec.status = Some(3);
                    rec.error = Some("NXDOMAIN".into());
                    self.net.record(rec);
                    Ok(DnsAnswer {
                        records: vec![],
                        nxdomain: true,
                    })
                }
                Err(e) if e.is_no_records_found() => {
                    rec.status = Some(0);
                    self.net.record(rec);
                    Ok(DnsAnswer::default())
                }
                Err(e) => {
                    rec.error = Some(e.to_string());
                    self.net.record(rec);
                    Err(NetError::Dns(format!("{name} {}: {e}", t.as_str())))
                }
            }
        })
    }
}

/// Static answers (tests, offline fixtures). Names without an answer yield NXDOMAIN.
#[derive(Debug, Default, Clone)]
pub struct StaticDns {
    zones: HashMap<(String, RType), Vec<String>>,
    exists: std::collections::HashSet<String>,
}

impl StaticDns {
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds one or more records.
    pub fn add(mut self, name: &str, t: RType, values: &[&str]) -> Self {
        let n = norm_name(name);
        self.exists.insert(n.clone());
        self.zones
            .entry((n, t))
            .or_default()
            .extend(values.iter().map(|v| v.to_string()));
        self
    }

    /// Parses lines of the form `name TYPE value`; `#` starts a comment.
    pub fn from_zone_text(text: &str) -> Self {
        let mut s = StaticDns::new();
        for l in text.lines() {
            let l = l.trim();
            if l.is_empty() || l.starts_with('#') {
                continue;
            }
            let mut it = l.splitn(3, char::is_whitespace);
            let (Some(n), Some(t), v) = (it.next(), it.next(), it.next()) else {
                continue;
            };
            let t = match t.to_ascii_uppercase().as_str() {
                "A" => RType::A,
                "AAAA" => RType::AAAA,
                "MX" => RType::MX,
                "NS" => RType::NS,
                "TXT" => RType::TXT,
                "SOA" => RType::SOA,
                "CNAME" => RType::CNAME,
                "SRV" => RType::SRV,
                "CAA" => RType::CAA,
                "PTR" => RType::PTR,
                "DS" => RType::DS,
                "DNSKEY" => RType::DNSKEY,
                _ => continue,
            };
            let v = v.unwrap_or("").trim().trim_matches('"');
            s = s.add(n, t, &[v]);
        }
        s
    }
}

impl DnsLookup for StaticDns {
    fn lookup<'a>(&'a self, name: &'a str, t: RType) -> BoxFuture<'a, Result<DnsAnswer, NetError>> {
        Box::pin(async move {
            let n = norm_name(name);
            if !self.exists.contains(&n) {
                return Ok(DnsAnswer {
                    records: vec![],
                    nxdomain: true,
                });
            }
            let mut records: Vec<DnsRecord> = Vec::new();
            // include the CNAME in A/AAAA/TXT answers, like a real resolver does
            if t != RType::CNAME {
                if let Some(c) = self.zones.get(&(n.clone(), RType::CNAME)) {
                    for v in c {
                        records.push(DnsRecord {
                            name: n.clone(),
                            rtype: "CNAME".into(),
                            ttl: 300,
                            value: norm_name(v),
                        });
                        if let Ok(a) = self.lookup(v, t).await {
                            records.extend(a.records);
                        }
                    }
                    return Ok(DnsAnswer {
                        records,
                        nxdomain: false,
                    });
                }
            }
            if let Some(v) = self.zones.get(&(n.clone(), t)) {
                records.extend(v.iter().map(|x| DnsRecord {
                    name: n.clone(),
                    rtype: t.as_str().into(),
                    ttl: 300,
                    value: if matches!(t, RType::CNAME | RType::NS | RType::PTR) {
                        norm_name(x)
                    } else {
                        x.clone()
                    },
                }));
            }
            Ok(DnsAnswer {
                records,
                nxdomain: false,
            })
        })
    }
}

/// Returns the PTR query name (`in-addr.arpa` / `ip6.arpa`).
pub fn reverse_name(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v) => {
            let o = v.octets();
            format!("{}.{}.{}.{}.in-addr.arpa", o[3], o[2], o[1], o[0])
        }
        IpAddr::V6(v) => {
            let mut s = String::new();
            for b in v.octets().iter().rev() {
                s.push_str(&format!("{:x}.{:x}.", b & 0xf, b >> 4));
            }
            s.push_str("ip6.arpa");
            s
        }
    }
}

/// Common SRV names (excluding internal services).
pub const COMMON_SRV: &[&str] = &[
    "_autodiscover._tcp",
    "_sip._tls",
    "_sipfederationtls._tcp",
    "_xmpp-server._tcp",
    "_caldavs._tcp",
    "_imaps._tcp",
    "_submission._tcp",
];

/// DNS summary of a domain.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsReport {
    pub domain: String,
    pub nxdomain: bool,
    /// Record type to values.
    pub records: BTreeMap<String, Vec<String>>,
    /// IP to PTR names.
    pub ptr: BTreeMap<String, Vec<String>>,
    pub srv: BTreeMap<String, Vec<String>>,
    pub mail: mail::MailReport,
    pub dangling: Vec<takeover::Dangling>,
    pub errors: Vec<String>,
}

/// Builds the summary: records, PTR, SRV, SPF/DMARC/DKIM, and dangling CNAMEs for the domain and `www`.
pub async fn dns_report(dns: &dyn DnsLookup, domain: &str) -> DnsReport {
    let d = norm_name(domain);
    let mut rep = DnsReport {
        domain: d.clone(),
        ..Default::default()
    };
    for t in [
        RType::A,
        RType::AAAA,
        RType::CNAME,
        RType::MX,
        RType::NS,
        RType::TXT,
        RType::SOA,
        RType::CAA,
    ] {
        match dns.lookup(&d, t).await {
            Ok(a) => {
                if a.nxdomain {
                    rep.nxdomain = true;
                    break;
                }
                let v = a.values(t);
                if !v.is_empty() {
                    rep.records.insert(t.as_str().into(), v);
                }
            }
            Err(e) => rep.errors.push(e.to_string()),
        }
    }
    if rep.nxdomain {
        return rep;
    }
    let mut ips: Vec<IpAddr> = Vec::new();
    for t in ["A", "AAAA"] {
        if let Some(v) = rep.records.get(t) {
            ips.extend(v.iter().filter_map(|s| s.parse::<IpAddr>().ok()));
        }
    }
    for ip in ips {
        if let Ok(a) = dns.lookup(&reverse_name(ip), RType::PTR).await {
            let v = a.values(RType::PTR);
            if !v.is_empty() {
                rep.ptr.insert(ip.to_string(), v);
            }
        }
    }
    for s in COMMON_SRV {
        let n = format!("{s}.{d}");
        if let Ok(a) = dns.lookup(&n, RType::SRV).await {
            let v = a.values(RType::SRV);
            if !v.is_empty() {
                rep.srv.insert(n, v);
            }
        }
    }
    rep.mail = mail::check_mail(dns, &d).await;
    for h in [d.clone(), format!("www.{d}")] {
        if let Some(x) = takeover::check_dangling(dns, &h).await {
            rep.dangling.push(x);
        }
    }
    rep
}

/// Resolves A and AAAA (answers that fail or carry no address give an empty list).
pub async fn lookup_ips(dns: &dyn DnsLookup, host: &str) -> Vec<IpAddr> {
    let mut out = Vec::new();
    for t in [RType::A, RType::AAAA] {
        if let Ok(a) = dns.lookup(host, t).await {
            out.extend(a.values(t).iter().filter_map(|v| v.parse::<IpAddr>().ok()));
        }
    }
    out
}

/// Checks name liveness by resolving A/AAAA, with up to `concurrency` lookups in parallel.
pub async fn resolve_alive(
    dns: Arc<dyn DnsLookup>,
    hosts: &[String],
    concurrency: usize,
) -> Vec<(String, Vec<String>)> {
    let sem = Arc::new(tokio::sync::Semaphore::new(concurrency.max(1)));
    let mut set = tokio::task::JoinSet::new();
    for (i, h) in hosts.iter().enumerate() {
        let dns = dns.clone();
        let h = h.clone();
        let sem = sem.clone();
        set.spawn(async move {
            let _p = sem.acquire_owned().await;
            let mut ips = Vec::new();
            for t in [RType::A, RType::AAAA] {
                if let Ok(a) = dns.lookup(&h, t).await {
                    if a.nxdomain {
                        break;
                    }
                    ips.extend(a.values(t));
                }
            }
            (i, h, ips)
        });
    }
    let mut out = Vec::new();
    while let Some(r) = set.join_next().await {
        if let Ok(x) = r {
            out.push(x);
        }
    }
    out.sort_by_key(|x| x.0);
    out.into_iter()
        .filter(|x| !x.2.is_empty())
        .map(|x| (x.1, x.2))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolv_conf() {
        let v = parse_resolv_conf(
            "# c\nnameserver 127.0.0.11\nsearch x\nnameserver fe80::1%eth0\noptions ndots:0\n",
        );
        assert_eq!(v.len(), 2);
        assert_eq!(v[0].to_string(), "127.0.0.11");
        let cfg = DnsConfig {
            resolv_conf: Some("/nonexistent/resolv.conf".into()),
            ..Default::default()
        };
        assert_eq!(cfg.effective_servers(), cfg.fallback);
    }

    #[test]
    fn reverse() {
        assert_eq!(
            reverse_name("192.0.2.5".parse().unwrap()),
            "5.2.0.192.in-addr.arpa"
        );
        assert!(reverse_name("2001:db8::1".parse().unwrap()).ends_with("8.b.d.0.1.0.0.2.ip6.arpa"));
    }

    #[tokio::test]
    async fn static_dns_cname_chain() {
        let d = StaticDns::new()
            .add("www.a.ua", RType::CNAME, &["web.a.ua."])
            .add("web.a.ua", RType::A, &["192.0.2.1"]);
        let a = d.lookup("WWW.a.ua.", RType::A).await.unwrap();
        assert_eq!(a.values(RType::A), vec!["192.0.2.1"]);
        assert_eq!(a.values(RType::CNAME), vec!["web.a.ua"]);
        assert!(d.lookup("nope.a.ua", RType::A).await.unwrap().nxdomain);
        let alive = resolve_alive(Arc::new(d), &["www.a.ua".into(), "nope.a.ua".into()], 2).await;
        assert_eq!(alive.len(), 1);
    }
}
