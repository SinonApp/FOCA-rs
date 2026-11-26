//! Bulk scope extension: `scope_add_hosts { project, hosts[] }`.
//!
//! Adds out-of-scope host names (typically subdomains of the main domain found in CT/DNS) to the
//! project scope in one step. Names whose addresses belong to a CDN, a public cloud or a hosting
//! provider (built-in range table of `foca_net::cdn`, the RDAP holder, or an address shared with
//! names of other owners) are added as names only: their IPs are recorded as "no probe" and the
//! port scan never touches them: the edge or shared server belongs to someone else.

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

use foca_core::api::ScopeDto;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::analysis::rules::{self, KnownHost};

/// Project facts key: names added in bulk and the addresses excluded from active probing.
pub const K_NO_PROBE: &str = "engine.no_probe";
/// Upper bound of names per call.
pub const MAX_HOSTS: usize = 500;

/// Persistent "no probe" record.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct NoProbe {
    /// Names added through `scope_add_hosts` (their addresses are re-checked at scan time).
    pub hosts: BTreeSet<String>,
    /// Address → human-readable reason (`Cloudflare (CDN)`).
    pub ips: BTreeMap<String, String>,
}

/// An address that stays out of active probing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Excluded {
    pub host: String,
    pub ip: String,
    pub provider: String,
    /// `cdn` | `cloud` | `hosting` | `shared`
    pub kind: String,
    pub reason: String,
}

/// A name that was not added.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Skipped {
    pub host: String,
    /// `invalid` | `excluded` | `already_in_scope` | `duplicate`
    pub code: String,
    pub reason: String,
}

/// Result of planning a bulk add (pure, unit-tested).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Plan {
    pub added: Vec<String>,
    pub skipped: Vec<Skipped>,
    pub no_probe: Vec<Excluded>,
}

/// Adds `reason_msg` (see `i18n::classify`) to skipped and no-probe entries of a plan.
pub(crate) fn with_reason_msgs(mut v: Value) -> Value {
    for k in ["skipped", "no_probe"] {
        if let Some(a) = v[k].as_array_mut() {
            for x in a {
                crate::services::i18n::annotate(x, &["reason"]);
            }
        }
    }
    v
}

fn kind_label(kind: &str) -> &'static str {
    match kind {
        "cdn" => "CDN",
        "cloud" => "облако",
        "hosting" => "хостинг",
        _ => "общий хостинг",
    }
}

/// Classifies an address: CDN/cloud/hosting range table first, then the RDAP holder label, then an
/// address shared with names that are neither requested nor covered by the scope.
pub fn classify(
    sc: &ScopeDto,
    known: &[KnownHost],
    requested: &BTreeSet<String>,
    host: &str,
    ip: &str,
    cloud: Option<&str>,
) -> Option<(String, String)> {
    let addr: IpAddr = ip.parse().ok()?;
    if let Some(c) = foca_net::cdn::classify_ip(addr) {
        return Some((
            foca_net::cdn::provider_name(&c.provider).to_string(),
            c.kind.as_str().to_string(),
        ));
    }
    if let Some(c) = cloud.map(str::trim).filter(|c| !c.is_empty() && *c != "-") {
        return Some((c.to_string(), "cloud".into()));
    }
    let foreign = known.iter().any(|k| {
        let n = rules::norm_host(&k.name);
        n != host
            && k.ip.split([',', ' ']).any(|x| x.trim() == ip)
            && !requested.contains(&n)
            && !rules::check(sc, &n, known).ok
    });
    foreign.then(|| ("-".to_string(), "shared".to_string()))
}

/// Plans a bulk add: validates names, applies scope exclusions and classifies known addresses.
pub fn plan(
    sc: &ScopeDto,
    known: &[KnownHost],
    clouds: &BTreeMap<String, String>,
    hosts: &[String],
) -> Plan {
    let mut out = Plan::default();
    let requested: BTreeSet<String> = hosts.iter().map(|h| rules::norm_host(h)).collect();
    let mut seen = BTreeSet::new();
    for raw in hosts {
        let h = rules::norm_host(raw);
        let skip = |code: &str, reason: &str| Skipped {
            host: h.clone(),
            code: code.into(),
            reason: reason.into(),
        };
        if !seen.insert(h.clone()) {
            out.skipped.push(skip("duplicate", "повтор в списке"));
            continue;
        }
        match rules::entry(&h, None) {
            rules::Entry::Domain(d) if d == h && h.contains('.') => {}
            _ => {
                out.skipped.push(skip("invalid", "не имя хоста"));
                continue;
            }
        }
        let ck = rules::check(sc, &h, known);
        if ck.code == "excluded" {
            out.skipped.push(skip("excluded", &ck.reason));
            continue;
        }
        if ck.ok {
            out.skipped.push(skip("already_in_scope", "уже в скоупе"));
            continue;
        }
        let ips: Vec<String> = known
            .iter()
            .filter(|k| rules::norm_host(&k.name) == h)
            .flat_map(|k| k.ip.split([',', ' ']).map(|x| x.trim().to_string()))
            .filter(|x| rules::ip4(x).is_some() || x.parse::<IpAddr>().is_ok())
            .collect();
        for ip in ips {
            if let Some((provider, kind)) = classify(
                sc,
                known,
                &requested,
                &h,
                &ip,
                clouds.get(&h).map(String::as_str),
            ) {
                let reason = if provider == "-" {
                    format!(
                        "{}: на адресе есть сайты других владельцев",
                        kind_label(&kind)
                    )
                } else {
                    format!("{provider} ({})", kind_label(&kind))
                };
                if !out.no_probe.iter().any(|x| x.ip == ip && x.host == h) {
                    out.no_probe.push(Excluded {
                        host: h.clone(),
                        ip,
                        provider,
                        kind,
                        reason,
                    });
                }
            }
        }
        out.added.push(h);
    }
    out
}

/// Reason to skip active probing of `ip` (port scan), or `None`.
///
/// An address is skipped when it was recorded at add time, or when one of its names was added in
/// bulk and the address now classifies as CDN/cloud/hosting. An address that is itself an explicit
/// scope target is always probed.
pub fn skip_reason(np: &NoProbe, sc: &ScopeDto, ip: &str, names: &[String]) -> Option<String> {
    if sc.targets.iter().any(|t| t.v.eq_ignore_ascii_case(ip)) {
        return None;
    }
    if let Some(r) = np.ips.get(ip) {
        return Some(r.clone());
    }
    if !names
        .iter()
        .any(|n| np.hosts.contains(&rules::norm_host(n)))
    {
        return None;
    }
    let c = foca_net::cdn::classify_ip(ip.parse().ok()?)?;
    Some(format!(
        "{} ({})",
        foca_net::cdn::provider_name(&c.provider),
        kind_label(c.kind.as_str())
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use foca_core::api::ScopeTarget;

    fn scope() -> ScopeDto {
        ScopeDto {
            // a URL target covers only its own host: subdomains stay out of scope
            targets: vec![ScopeTarget {
                v: "https://example.com/".into(),
                kind: "url".into(),
            }],
            excl: vec!["vpn.example.com".into()],
            ..Default::default()
        }
    }

    fn kh(name: &str, ip: &str) -> KnownHost {
        KnownHost {
            name: name.into(),
            ip: ip.into(),
        }
    }

    #[test]
    fn plan_adds_names_and_excludes_cdn_cloud_and_shared_addresses() {
        let sc = scope();
        let known = vec![
            // Cloudflare edge (104.16.0.0/13)
            kh("cdn.example.com", "104.16.1.1"),
            // plain address, RDAP says AWS
            kh("app.example.com", "198.51.100.10"),
            // shared address with a foreign site
            kh("blog.example.com", "203.0.113.5"),
            kh("other-owner.org", "203.0.113.5"),
            // own server
            kh("dev.example.com", "192.0.2.10"),
        ];
        let clouds: BTreeMap<String, String> =
            [("app.example.com".to_string(), "AWS".to_string())].into();
        let req: Vec<String> = [
            "cdn.example.com",
            "app.example.com",
            "BLOG.example.com.",
            "dev.example.com",
            "vpn.example.com",
            "example.com",
            "dev.example.com",
            "10.0.0.1",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        let p = plan(&sc, &known, &clouds, &req);
        assert_eq!(
            p.added,
            vec![
                "cdn.example.com",
                "app.example.com",
                "blog.example.com",
                "dev.example.com"
            ]
        );
        let codes: Vec<(&str, &str)> = p
            .skipped
            .iter()
            .map(|s| (s.host.as_str(), s.code.as_str()))
            .collect();
        assert_eq!(
            codes,
            vec![
                ("vpn.example.com", "excluded"),
                ("example.com", "already_in_scope"),
                ("dev.example.com", "duplicate"),
                ("10.0.0.1", "invalid"),
            ]
        );
        let np: Vec<(&str, &str, &str)> = p
            .no_probe
            .iter()
            .map(|x| (x.host.as_str(), x.ip.as_str(), x.kind.as_str()))
            .collect();
        assert_eq!(
            np,
            vec![
                ("cdn.example.com", "104.16.1.1", "cdn"),
                ("app.example.com", "198.51.100.10", "cloud"),
                ("blog.example.com", "203.0.113.5", "shared"),
            ]
        );
        assert!(p.no_probe[0].reason.contains("Cloudflare"));
    }

    #[test]
    fn skip_reason_covers_recorded_and_late_resolved_cdn_addresses() {
        let mut sc = scope();
        let mut np = NoProbe::default();
        np.ips.insert("198.51.100.10".into(), "AWS (облако)".into());
        np.hosts.insert("cdn.example.com".into());
        let names = |n: &str| vec![n.to_string()];
        assert_eq!(
            skip_reason(&np, &sc, "198.51.100.10", &names("app.example.com")).as_deref(),
            Some("AWS (облако)")
        );
        // resolved only during the scan: classified by the range table
        let r = skip_reason(&np, &sc, "104.16.1.1", &names("cdn.example.com")).unwrap();
        assert!(r.contains("Cloudflare"), "{r}");
        // the same CDN address of a name that was not added in bulk gets no skip reason
        assert_eq!(
            skip_reason(&np, &sc, "104.16.1.1", &names("www.example.com")),
            None
        );
        // own address of a bulk name is probed
        assert_eq!(
            skip_reason(&np, &sc, "192.0.2.10", &names("cdn.example.com")),
            None
        );
        // an explicit IP target is always probed
        sc.targets.push(ScopeTarget {
            v: "198.51.100.10".into(),
            kind: "ip".into(),
        });
        assert_eq!(
            skip_reason(&np, &sc, "198.51.100.10", &names("app.example.com")),
            None
        );
    }
}
