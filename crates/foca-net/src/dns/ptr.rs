//! Reverse DNS (PTR) for in-scope addresses, with shared hosting detection.
//!
//! [`ptr_lookup`] resolves PTR names of addresses that are in scope: either the address itself is
//! a target (IP, CIDR, range) or it was resolved from an in-scope host name and is not excluded.
//! [`scope_sweep_targets`] expands the IP targets of the scope (capped) for a reverse sweep of an
//! organization's network, where PTR names often reveal hosts that no wordlist would guess.
//!
//! Every address is classified ([`Hosting`]) from the PTR names, forward confirmation and the host
//! names known to resolve to it. A shared address matters beyond inventory: active checks by IP on
//! it would hit third parties, so callers should keep them to name-based requests.
//!
//! Access: PTR queries reach the reverse zone of the target's network, so the module counts as a
//! target-touching (standard profile) operation: the passive profile denies it, and excluded
//! addresses are never queried.

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;
use std::sync::Arc;

use foca_core::{Scope, Target};
use serde::{Deserialize, Serialize};

use crate::bruteforce::resolve_full;
use crate::client::{ip_excluded, is_local_host, Access, NetClient};
use crate::dns::{norm_name, reverse_name, DnsLookup, RType};
use crate::NetError;

/// Request log module name.
pub const MODULE: &str = "ptr";

/// Suffixes of default reverse names of cloud, VPS and CDN providers.
const GENERIC_SUFFIXES: &[&str] = &[
    "amazonaws.com",
    "googleusercontent.com",
    "cloudapp.azure.com",
    "cloudapp.net",
    "linodeusercontent.com",
    "members.linode.com",
    "vultrusercontent.com",
    "your-server.de",
    "contaboserver.net",
    "akamaitechnologies.com",
    "cloudfront.net",
    "digitaloceanspaces.com",
    "ovh.net",
    "kimsufi.com",
    "hosted-by-vdsina.ru",
    "scaleway.com",
    "upcloud.host",
    "hetzner.com",
    "static.cloudflare.com",
];

/// First-label markers of shared web hosting servers.
const HOSTING_MARKERS: &[&str] = &[
    "shared",
    "hosting",
    "cpanel",
    "plesk",
    "vhost",
    "webhost",
    "virtualhost",
    "isp",
    "directadmin",
];

/// Second-level labels under two-letter country TLDs that are public suffixes (`com.ua`, `co.uk`).
const SECOND_LEVEL: &[&str] = &[
    "co", "com", "net", "org", "gov", "edu", "ac", "in", "ltd", "plc", "or", "ne", "go", "mil",
    "kiev", "kyiv", "lviv", "kharkov", "odessa", "dp", "biz", "info", "gen", "nom", "msk", "spb",
];

/// An address to resolve, with the known host names that resolve to it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PtrTarget {
    pub ip: IpAddr,
    pub hosts: Vec<String>,
}

/// Hosting class of an address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Hosting {
    /// The PTR name belongs to a target domain.
    Dedicated,
    /// Several organizations share the address (virtual hosting).
    Shared,
    /// A default provider or ISP name: likely a VM or CDN node, ownership not visible.
    Generic,
    /// No PTR name and no other evidence.
    Unknown,
}

/// Settings of [`ptr_lookup`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PtrConfig {
    pub concurrency: usize,
    /// Upper bound on addresses per run.
    pub max_ips: usize,
    /// Resolve PTR names forward and check that they point back to the address (FCrDNS).
    pub forward_confirm: bool,
    /// Distinct registrable domains among known host names that make an address shared.
    pub shared_domains: usize,
}

impl Default for PtrConfig {
    fn default() -> Self {
        PtrConfig {
            concurrency: 6,
            max_ips: 1024,
            forward_confirm: true,
            shared_domains: 2,
        }
    }
}

/// PTR result for one address.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PtrEntry {
    pub ip: String,
    pub names: Vec<String>,
    /// Whether a PTR name resolves back to the address (`None` if not checked or no names).
    pub forward_confirmed: Option<bool>,
    pub hosting: Hosting,
    /// Evidence codes: `generic_ptr`, `hosting_ptr`, `foreign_ptr`, `multi_domain_ptr`,
    /// `shared_hosts`, `fcrdns_mismatch`.
    pub signals: Vec<String>,
    pub hosts: Vec<String>,
}

/// Result of [`ptr_lookup`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PtrReport {
    pub entries: Vec<PtrEntry>,
    /// Addresses not queried, with a reason code: `out_of_scope`, `excluded`, `passive`,
    /// `local_only`, `limit`.
    pub skipped: Vec<(String, String)>,
    /// PTR names inside the scope that were not among the known hosts.
    pub new_hosts: Vec<String>,
    pub errors: usize,
}

/// Groups `(host, addresses)` pairs (as returned by [`crate::dns::resolve_alive`]) by address.
pub fn group_by_ip(hosts: &[(String, Vec<String>)]) -> Vec<PtrTarget> {
    let mut m: BTreeMap<IpAddr, BTreeSet<String>> = BTreeMap::new();
    for (h, ips) in hosts {
        for ip in ips.iter().filter_map(|s| s.parse::<IpAddr>().ok()) {
            m.entry(ip).or_default().insert(norm_name(h));
        }
    }
    m.into_iter()
        .map(|(ip, hs)| PtrTarget {
            ip,
            hosts: hs.into_iter().collect(),
        })
        .collect()
}

/// Expands IP, CIDR and range targets of the scope into addresses (network and broadcast
/// addresses of IPv4 networks are skipped), at most `max`, minus exclusions.
pub fn scope_sweep_targets(scope: &Scope, max: usize) -> Vec<PtrTarget> {
    let mut out = Vec::new();
    let mut seen = BTreeSet::new();
    let mut push = |ip: IpAddr, out: &mut Vec<PtrTarget>| {
        if out.len() < max && !ip_excluded(scope, ip) && seen.insert(ip) {
            out.push(PtrTarget { ip, hosts: vec![] });
        }
    };
    for t in &scope.targets {
        if out.len() >= max {
            break;
        }
        match t {
            Target::Ip { addr } => push(*addr, &mut out),
            Target::Cidr { net } => {
                for ip in net.hosts().take(max) {
                    push(ip, &mut out);
                }
            }
            Target::IpRange { start, end } => match (start, end) {
                (IpAddr::V4(a), IpAddr::V4(b)) => {
                    let (a, b) = (u32::from(*a), u32::from(*b));
                    for x in (a..=b).take(max) {
                        push(IpAddr::V4(x.into()), &mut out);
                    }
                }
                (IpAddr::V6(a), IpAddr::V6(b)) => {
                    let (a, b) = (u128::from(*a), u128::from(*b));
                    let mut x = a;
                    while x <= b && out.len() < max {
                        push(IpAddr::V6(x.into()), &mut out);
                        x = match x.checked_add(1) {
                            Some(n) => n,
                            None => break,
                        };
                    }
                }
                _ => {}
            },
            _ => {}
        }
    }
    out
}

/// Returns the registrable domain of a name, approximately: the last two labels, or three under
/// a two-letter country TLD with a common second-level suffix (`shop.com.ua`).
pub fn base_domain(name: &str) -> String {
    let n = norm_name(name);
    let l: Vec<&str> = n.split('.').filter(|x| !x.is_empty()).collect();
    let k = if l.len() >= 3 && l[l.len() - 1].len() == 2 && SECOND_LEVEL.contains(&l[l.len() - 2]) {
        3
    } else {
        2
    };
    l[l.len().saturating_sub(k)..].join(".")
}

/// Returns `true` if the name embeds the IPv4 address (`1-2-3-4`, `4.3.2.1`, `ip-1-2-3-4`).
fn embeds_ip(name: &str, ip: IpAddr) -> bool {
    let IpAddr::V4(v4) = ip else {
        return false;
    };
    let o = v4.octets();
    let fwd = [o[0], o[1], o[2], o[3]];
    let rev = [o[3], o[2], o[1], o[0]];
    let nums: Vec<u32> = name
        .split(|c: char| !c.is_ascii_digit())
        .filter(|s| !s.is_empty())
        .filter_map(|s| s.parse().ok())
        .collect();
    let has = |seq: [u8; 4]| {
        nums.windows(4)
            .any(|w| w.iter().zip(seq.iter()).all(|(a, b)| *a == u32::from(*b)))
    };
    has(fwd) || has(rev) || name.contains(&format!("{:08x}", u32::from(v4)))
}

fn under_any(name: &str, domains: &[String]) -> bool {
    domains.iter().any(|d| {
        let d = norm_name(d);
        name == d || name.ends_with(&format!(".{d}"))
    })
}

/// Classifies an address from its PTR names, the known host names resolving to it and the
/// target domains. Returns the class and the evidence codes.
pub fn classify(
    ip: IpAddr,
    names: &[String],
    hosts: &[String],
    domains: &[String],
    shared_domains: usize,
    forward_confirmed: Option<bool>,
) -> (Hosting, Vec<String>) {
    let mut sig = Vec::new();
    let generic = names.iter().any(|n| {
        embeds_ip(n, ip)
            || GENERIC_SUFFIXES
                .iter()
                .any(|s| n == s || n.ends_with(&format!(".{s}")))
    });
    let foreign = !names.is_empty() && names.iter().all(|n| !under_any(n, domains));
    let hosting = foreign
        && names.iter().any(|n| {
            let first = n.split('.').next().unwrap_or("");
            HOSTING_MARKERS.iter().any(|m| first.contains(m))
        });
    let ptr_bases: BTreeSet<String> = names.iter().map(|n| base_domain(n)).collect();
    let host_bases: BTreeSet<String> = hosts.iter().map(|n| base_domain(n)).collect();
    let multi = ptr_bases.len() >= 2;
    let shared = host_bases.len() >= shared_domains.max(2);
    for (on, code) in [
        (generic, "generic_ptr"),
        (hosting, "hosting_ptr"),
        (foreign, "foreign_ptr"),
        (multi, "multi_domain_ptr"),
        (shared, "shared_hosts"),
        (forward_confirmed == Some(false), "fcrdns_mismatch"),
    ] {
        if on {
            sig.push(code.to_string());
        }
    }
    let class = if shared || multi || hosting {
        Hosting::Shared
    } else if names.is_empty() {
        Hosting::Unknown
    } else if generic || foreign {
        Hosting::Generic
    } else {
        Hosting::Dedicated
    };
    (class, sig)
}

fn deny_reason(net: &NetClient, scope: &Scope, t: &PtrTarget) -> Option<&'static str> {
    if ip_excluded(scope, t.ip) {
        return Some("excluded");
    }
    if net.is_local_only() && !is_local_host(&t.ip.to_string(), &net.config().host_overrides) {
        return Some("local_only");
    }
    let by_ip = scope.allows_ip(t.ip);
    let by_host: Vec<&String> = t.hosts.iter().filter(|h| scope.allows_host(h)).collect();
    if !by_ip && by_host.is_empty() {
        return Some("out_of_scope");
    }
    // passive profile: an in-scope address or host is the target and must not be touched
    let passive_denied = if by_ip {
        net.passive_access(&t.ip.to_string(), None).is_err()
    } else {
        by_host.iter().any(|h| net.passive_access(h, None).is_err())
    };
    passive_denied.then_some("passive")
}

/// Resolves PTR names of in-scope addresses and classifies them.
///
/// `domains` are the target domains (used to tell own PTR names from provider names). Addresses
/// that are not allowed are reported in [`PtrReport::skipped`] and logged as blocked, without a
/// query.
///
/// # Errors
///
/// Only on cancellation.
pub async fn ptr_lookup(
    net: &NetClient,
    dns: Arc<dyn DnsLookup>,
    targets: &[PtrTarget],
    domains: &[String],
    cfg: &PtrConfig,
) -> Result<PtrReport, NetError> {
    let scope = net.scope();
    let mut rep = PtrReport::default();
    let mut allowed = Vec::new();
    for t in targets {
        if let Some(why) = deny_reason(net, &scope, t) {
            let rn = reverse_name(t.ip);
            let mut rec = net.draft(
                MODULE,
                "PTR",
                &format!("dns://{rn}/PTR"),
                &t.ip.to_string(),
                &Access::TouchesTarget,
            );
            rec.blocked = true;
            rec.error = Some(format!("out_of_scope: {why}"));
            net.record(rec);
            rep.skipped.push((t.ip.to_string(), why.to_string()));
        } else if allowed.len() >= cfg.max_ips {
            rep.skipped.push((t.ip.to_string(), "limit".to_string()));
        } else {
            allowed.push(t.clone());
        }
    }
    let sem = Arc::new(tokio::sync::Semaphore::new(cfg.concurrency.max(1)));
    let mut set = tokio::task::JoinSet::new();
    for (i, t) in allowed.into_iter().enumerate() {
        let (dns, sem, net, cfg) = (dns.clone(), sem.clone(), net.clone(), cfg.clone());
        set.spawn(async move {
            let _p = net.cancellable(sem.acquire_owned()).await?;
            net.rate_limit(MODULE).await?;
            let a = net
                .cancellable(dns.lookup(&reverse_name(t.ip), RType::PTR))
                .await?;
            let (names, err) = match a {
                Ok(a) => {
                    let mut v: Vec<String> =
                        a.values(RType::PTR).iter().map(|x| norm_name(x)).collect();
                    v.sort();
                    v.dedup();
                    (v, false)
                }
                Err(NetError::Cancelled) => return Err(NetError::Cancelled),
                Err(_) => (vec![], true),
            };
            let mut fc = None;
            if cfg.forward_confirm && !names.is_empty() {
                let mut ok = false;
                for n in names.iter().take(3) {
                    if let Ok(Some(r)) = net.cancellable(resolve_full(dns.as_ref(), n)).await? {
                        if r.ips.iter().any(|x| x.parse::<IpAddr>().ok() == Some(t.ip)) {
                            ok = true;
                            break;
                        }
                    }
                }
                fc = Some(ok);
            }
            Ok::<_, NetError>((i, t, names, fc, err))
        });
    }
    let mut rows = Vec::new();
    while let Some(r) = set.join_next().await {
        match r {
            Ok(Ok(x)) => rows.push(x),
            Ok(Err(e)) => {
                set.abort_all();
                return Err(e);
            }
            Err(_) => rep.errors += 1,
        }
    }
    rows.sort_by_key(|x| x.0);
    let mut new_hosts = BTreeSet::new();
    for (_, t, names, fc, err) in rows {
        if err {
            rep.errors += 1;
        }
        for n in &names {
            if scope.allows_host(n) && !t.hosts.contains(n) {
                new_hosts.insert(n.clone());
            }
        }
        let (hosting, signals) = classify(t.ip, &names, &t.hosts, domains, cfg.shared_domains, fc);
        rep.entries.push(PtrEntry {
            ip: t.ip.to_string(),
            names,
            forward_confirmed: fc,
            hosting,
            signals,
            hosts: t.hosts,
        });
    }
    rep.new_hosts = new_hosts.into_iter().collect();
    Ok(rep)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bruteforce::testdns::FakeDns;
    use crate::{MemorySink, NetConfig};

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn net(targets: &str, excl: &str) -> (NetClient, Arc<MemorySink>) {
        let (scope, _) = Scope::from_lines(targets, excl);
        let sink = Arc::new(MemorySink::new());
        (
            NetClient::new(NetConfig::default(), scope, sink.clone()).unwrap(),
            sink,
        )
    }

    #[test]
    fn base_domains_and_ip_names() {
        assert_eq!(base_domain("a.b.shop.com.ua"), "shop.com.ua");
        assert_eq!(base_domain("www.example.com"), "example.com");
        assert_eq!(base_domain("x.bbc.co.uk."), "bbc.co.uk");
        assert!(embeds_ip(
            "static.4.3.2.1.clients.example.net",
            ip("1.2.3.4")
        ));
        assert!(embeds_ip(
            "ip-1-2-3-4.eu-west-1.compute.internal",
            ip("1.2.3.4")
        ));
        assert!(embeds_ip("host-01020304.isp.net", ip("1.2.3.4")));
        assert!(!embeds_ip("mail.example.com", ip("1.2.3.4")));
    }

    #[test]
    fn classification() {
        let d = s(&["ex.ua"]);
        let c = |names: &[&str], hosts: &[&str]| {
            classify(ip("192.0.2.1"), &s(names), &s(hosts), &d, 2, None).0
        };
        assert_eq!(c(&["mail.ex.ua"], &["mail.ex.ua"]), Hosting::Dedicated);
        assert_eq!(
            c(&["ec2-192-0-2-1.compute-1.amazonaws.com"], &[]),
            Hosting::Generic
        );
        assert_eq!(c(&["web12.hosting-provider.net"], &[]), Hosting::Generic);
        assert_eq!(c(&["shared7.hostco.net"], &[]), Hosting::Shared);
        assert_eq!(
            c(&["mail.ex.ua"], &["www.ex.ua", "shop.other.com"]),
            Hosting::Shared
        );
        assert_eq!(c(&["a.one.com", "b.two.net"], &[]), Hosting::Shared);
        assert_eq!(c(&[], &[]), Hosting::Unknown);
        let (_, sig) = classify(ip("192.0.2.1"), &s(&["x.ex.ua"]), &[], &d, 2, Some(false));
        assert_eq!(sig, vec!["fcrdns_mismatch"]);
    }

    #[test]
    fn sweep_targets() {
        let (scope, _) = Scope::from_lines(
            "192.0.2.0/30\n198.51.100.7\n198.51.100.10-198.51.100.12\nex.ua",
            "192.0.2.2",
        );
        let t: Vec<String> = scope_sweep_targets(&scope, 100)
            .iter()
            .map(|t| t.ip.to_string())
            .collect();
        assert_eq!(
            t,
            vec![
                "192.0.2.1",
                "198.51.100.7",
                "198.51.100.10",
                "198.51.100.11",
                "198.51.100.12"
            ]
        );
        assert_eq!(scope_sweep_targets(&scope, 2).len(), 2);
        let g = group_by_ip(&[
            ("a.ex.ua".into(), s(&["192.0.2.1"])),
            ("b.ex.ua".into(), s(&["192.0.2.1", "x"])),
        ]);
        assert_eq!(g.len(), 1);
        assert_eq!(g[0].hosts, s(&["a.ex.ua", "b.ex.ua"]));
    }

    #[tokio::test]
    async fn lookup_scope_and_classes() {
        let dns = Arc::new(
            FakeDns::new()
                .ptr("192.0.2.1", &["gw.ex.ua"])
                .host("gw.ex.ua", &["192.0.2.1"], 300)
                .ptr("192.0.2.5", &["vpn-old.ex.ua"])
                .ptr("203.0.113.9", &["shared3.bighost.net"])
                .ptr("198.51.100.1", &["x.ex.ua"]),
        );
        let (n, sink) = net("ex.ua\n192.0.2.0/29", "192.0.2.6\nsecret.ex.ua");
        let targets = vec![
            PtrTarget {
                ip: ip("192.0.2.1"),
                hosts: s(&["gw.ex.ua"]),
            },
            PtrTarget {
                ip: ip("192.0.2.5"),
                hosts: vec![],
            },
            PtrTarget {
                ip: ip("192.0.2.6"),
                hosts: vec![],
            },
            PtrTarget {
                ip: ip("203.0.113.9"),
                hosts: s(&["www.ex.ua"]),
            },
            PtrTarget {
                ip: ip("198.51.100.1"),
                hosts: s(&["secret.ex.ua"]),
            },
            PtrTarget {
                ip: ip("198.51.100.2"),
                hosts: s(&["cdn.other.org"]),
            },
        ];
        let r = ptr_lookup(
            &n,
            dns.clone(),
            &targets,
            &s(&["ex.ua"]),
            &PtrConfig::default(),
        )
        .await
        .unwrap();
        let by: BTreeMap<&str, &PtrEntry> = r.entries.iter().map(|e| (e.ip.as_str(), e)).collect();
        assert_eq!(by.len(), 3);
        assert_eq!(by["192.0.2.1"].hosting, Hosting::Dedicated);
        assert_eq!(by["192.0.2.1"].forward_confirmed, Some(true));
        assert_eq!(by["192.0.2.5"].forward_confirmed, Some(false));
        assert_eq!(by["203.0.113.9"].hosting, Hosting::Shared);
        assert_eq!(r.new_hosts, s(&["vpn-old.ex.ua"]));
        let skipped: BTreeMap<&str, &str> = r
            .skipped
            .iter()
            .map(|(a, b)| (a.as_str(), b.as_str()))
            .collect();
        assert_eq!(skipped["192.0.2.6"], "excluded");
        assert_eq!(skipped["198.51.100.1"], "out_of_scope");
        assert_eq!(skipped["198.51.100.2"], "out_of_scope");
        assert!(!dns
            .log
            .lock()
            .unwrap()
            .iter()
            .any(|l| l.starts_with("6.2.0.192") || l.starts_with("1.100.51.198")));
        assert_eq!(
            sink.records()
                .iter()
                .filter(|x| x.blocked && x.module == MODULE)
                .count(),
            3
        );
    }

    #[tokio::test]
    async fn passive_profile_and_local_only_make_no_queries() {
        let dns = Arc::new(FakeDns::new().ptr("192.0.2.1", &["gw.ex.ua"]));
        let (n, _) = net("ex.ua\n192.0.2.0/29", "");
        let (full, _) = Scope::from_lines("ex.ua\n192.0.2.0/29", "");
        n.set_passive_guard(full, true);
        let t = vec![
            PtrTarget {
                ip: ip("192.0.2.1"),
                hosts: vec![],
            },
            PtrTarget {
                ip: ip("203.0.113.1"),
                hosts: s(&["www.ex.ua"]),
            },
        ];
        let r = ptr_lookup(&n, dns.clone(), &t, &s(&["ex.ua"]), &PtrConfig::default())
            .await
            .unwrap();
        assert!(r.entries.is_empty());
        assert!(r.skipped.iter().all(|x| x.1 == "passive"));
        assert_eq!(dns.count(), 0);
        let (scope, _) = Scope::from_lines("93.184.216.0/24", "");
        let cfg = NetConfig {
            local_only: Some(std::path::PathBuf::new()),
            ..Default::default()
        };
        let n = NetClient::new(cfg, scope, Arc::new(MemorySink::new())).unwrap();
        let t = vec![PtrTarget {
            ip: ip("93.184.216.34"),
            hosts: vec![],
        }];
        let r = ptr_lookup(&n, dns.clone(), &t, &[], &PtrConfig::default())
            .await
            .unwrap();
        assert_eq!(r.skipped[0].1, "local_only");
        assert_eq!(dns.count(), 0);
    }
}
