//! Port of `FOCA_RULES` from `ui/js/sel.js` (the reference implementation): the scope rule over
//! `ScopeDto`, active stage admission, risk, "has the analysis run", and report selection. Numbers
//! and codes match the UI and the demo backend.

use foca_core::api::ScopeDto;
use serde_json::Value;

pub const NET: &[&str] = &["domain", "wild", "url", "ip", "cidr", "range", "host"];
pub const STAGE_IDS: &[&str] = &[
    "search", "download", "meta", "analysis", "network", "ports", "recon", "fuzz", "report",
];

fn low(s: &str) -> String {
    s.trim().to_lowercase()
}

pub fn ip4(s: &str) -> Option<u32> {
    let p: Vec<&str> = s.trim().split('.').collect();
    if p.len() != 4 {
        return None;
    }
    let mut v = 0u32;
    for x in p {
        if x.is_empty() || x.len() > 3 || !x.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        let n: u32 = x.parse().ok()?;
        if n > 255 {
            return None;
        }
        v = (v << 8) | n;
    }
    Some(v)
}

/// Normalizes input to a host name: lowercase, without scheme, port, path or trailing dot; `[v6]` becomes v6.
pub fn norm_host(h: &str) -> String {
    let mut s = low(h);
    if let Some(i) = s.find("://") {
        if s[..i]
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "+.-".contains(c))
            && s.chars().next().is_some_and(|c| c.is_ascii_alphabetic())
        {
            s = s[i + 3..].to_string();
        }
    }
    let s = s
        .split(|c: char| c == '/' || c == '?' || c == '#' || c.is_whitespace())
        .next()
        .unwrap_or("")
        .to_string();
    if let Some(rest) = s.strip_prefix('[') {
        return rest.split(']').next().unwrap_or("").to_string();
    }
    let mut s = s;
    if let Some(i) = s.rfind(':') {
        if !s[i + 1..].is_empty() && s[i + 1..].bytes().all(|b| b.is_ascii_digit()) {
            s.truncate(i);
        }
    }
    s.trim_end_matches('.').to_string()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Entry {
    Domain(String),
    Wild(String),
    Url(String),
    Ip(u32, u32),
    None,
}

impl Entry {
    pub fn kind(&self) -> &'static str {
        match self {
            Entry::Domain(_) => "domain",
            Entry::Wild(_) => "wild",
            Entry::Url(_) => "url",
            Entry::Ip(..) => "ip",
            Entry::None => "none",
        }
    }
    fn range(&self) -> Option<(u32, u32)> {
        match self {
            Entry::Ip(a, b) => Some((*a, *b)),
            _ => None,
        }
    }
}

fn split_range(s: &str) -> Option<(String, String)> {
    for sep in ['-', '\u{2013}', '\u{2014}'] {
        if let Some((a, b)) = s.split_once(sep) {
            let (a, b) = (a.trim(), b.trim());
            let ok = |x: &str| !x.is_empty() && x.chars().all(|c| c.is_ascii_digit() || c == '.');
            if ok(a) && ok(b) {
                return Some((a.into(), b.into()));
            }
        }
    }
    None
}

fn is_domain_like(s: &str) -> bool {
    let parts: Vec<&str> = s.split('.').collect();
    parts.len() >= 2
        && parts
            .iter()
            .all(|p| !p.is_empty() && p.chars().all(|c| c.is_alphanumeric() || c == '-'))
}

/// Parses a scope entry (a typed target, or an untyped exclusion string).
pub fn entry(v: &str, ty: Option<&str>) -> Entry {
    let s = low(v);
    let t = match ty {
        Some(t) if !t.is_empty() => t.to_string(),
        _ => if s.starts_with("http://") || s.starts_with("https://") {
            "url"
        } else if s.starts_with("*.") {
            "wild"
        } else if s.rsplit_once('/').is_some_and(|(_, n)| {
            !n.is_empty() && n.len() <= 2 && n.bytes().all(|b| b.is_ascii_digit())
        }) {
            "cidr"
        } else if split_range(&s).is_some() {
            "range"
        } else if ip4(&s).is_some() {
            "ip"
        } else if is_domain_like(&s) {
            "domain"
        } else {
            "other"
        }
        .to_string(),
    };
    match t.as_str() {
        "domain" | "host" => Entry::Domain(norm_host(&s)),
        "wild" => Entry::Wild(norm_host(s.trim_start_matches("*."))),
        "url" => Entry::Url(norm_host(&s)),
        "ip" => match ip4(&s) {
            Some(a) => Entry::Ip(a, a),
            None => Entry::None,
        },
        "cidr" => {
            let Some((b, n)) = s.split_once('/') else {
                return Entry::None;
            };
            let (Some(a), Ok(n)) = (ip4(b), n.parse::<u32>()) else {
                return Entry::None;
            };
            if n > 32 {
                return Entry::None;
            }
            let mask = if n == 0 { 0 } else { u32::MAX << (32 - n) };
            let lo = a & mask;
            Entry::Ip(lo, lo | !mask)
        }
        "range" => {
            let Some((a, mut b)) = split_range(&s) else {
                return Entry::None;
            };
            if b.len() <= 3 && b.bytes().all(|x| x.is_ascii_digit()) {
                if let Some((pre, _)) = a.rsplit_once('.') {
                    b = format!("{pre}.{b}");
                }
            }
            match (ip4(&a), ip4(&b)) {
                (Some(lo), Some(hi)) => Entry::Ip(lo, hi),
                _ => Entry::None,
            }
        }
        _ => Entry::None,
    }
}

fn is_sub(h: &str, d: &str) -> bool {
    h.len() > d.len() + 1 && h.ends_with(&format!(".{d}"))
}

pub fn covers_name(e: &Entry, h: &str) -> bool {
    match e {
        Entry::Domain(d) => h == d || is_sub(h, d),
        Entry::Wild(d) => is_sub(h, d),
        Entry::Url(u) => h == u,
        _ => false,
    }
}

pub fn covers_ip(e: &Entry, a: u32) -> bool {
    match e {
        Entry::Ip(lo, hi) => a >= *lo && a <= *hi,
        Entry::Url(u) => ip4(u) == Some(a),
        _ => false,
    }
}

/// A known project host (name and address), for the rule that a name exclusion also covers its IP.
#[derive(Debug, Clone, Default)]
pub struct KnownHost {
    pub name: String,
    pub ip: String,
}

fn host_ip(h: &KnownHost) -> Option<u32> {
    ip4(h.ip.split(' ').next().unwrap_or(""))
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct Check {
    pub ok: bool,
    pub net: bool,
    pub target: Option<String>,
    pub excluded: Option<String>,
    pub via: Option<String>,
    /// `""` | `no_host` | `excluded` | `out_of_scope` | `not_network`
    pub code: &'static str,
    pub reason: String,
}

/// Checks a host or IP (`FOCA_RULES.scope.check`).
pub fn check(sc: &ScopeDto, q: &str, hosts: &[KnownHost]) -> Check {
    if q.is_empty() || q == "-" {
        return Check {
            code: "no_host",
            reason: "нет хоста".into(),
            ..Default::default()
        };
    }
    let h = norm_host(q);
    let a = ip4(&h);
    let known = if a.is_none() {
        hosts.iter().find(|x| low(&x.name) == h)
    } else {
        None
    };
    let ka = known.and_then(host_ip);
    let hit = |e: &Entry| match a {
        Some(a) => covers_ip(e, a),
        None => covers_name(e, &h) || ka.is_some_and(|ka| covers_ip(e, ka)),
    };
    let ex: Vec<(String, Entry)> = sc
        .excl
        .iter()
        .map(|v| (v.clone(), entry(v, None)))
        .collect();
    let mut ex_hit = ex.iter().find(|(_, e)| hit(e)).cloned();
    let mut via = None;
    if ex_hit.is_none() {
        if let Some(ip) = a.or(ka) {
            for x in hosts {
                if host_ip(x) != Some(ip) || low(&x.name) == h {
                    continue;
                }
                let n = low(&x.name);
                if let Some(m) = ex.iter().find(|(_, e)| covers_name(e, &n)) {
                    ex_hit = Some(m.clone());
                    via = Some(x.name.clone());
                    break;
                }
            }
        }
    }
    if let Some((v, _)) = ex_hit {
        return Check {
            excluded: Some(v),
            reason: match &via {
                Some(x) => format!("в исключениях (это адрес {x})"),
                None => "в исключениях".into(),
            },
            via,
            code: "excluded",
            ..Default::default()
        };
    }
    let Some(t) = sc.targets.iter().find(|t| hit(&entry(&t.v, Some(&t.kind)))) else {
        return Check {
            code: "out_of_scope",
            reason: "нет в скоупе".into(),
            ..Default::default()
        };
    };
    Check {
        ok: true,
        target: Some(t.v.clone()),
        code: "",
        ..Default::default()
    }
}

/// Checks a whole scope target (`FOCA_RULES.scope.checkTarget`).
pub fn check_target(sc: &ScopeDto, v: &str, ty: &str, hosts: &[KnownHost]) -> Check {
    let e = entry(v, Some(ty));
    let with_net = |mut c: Check| {
        c.net = true;
        c
    };
    match &e {
        Entry::None => Check {
            code: "not_network",
            reason: "не сетевая цель: только внешние источники".into(),
            ..Default::default()
        },
        Entry::Domain(d) | Entry::Url(d) => with_net(check(sc, d, hosts)),
        Entry::Wild(d) => with_net(check(sc, &format!("x.{d}"), hosts)),
        Entry::Ip(lo, hi) if lo == hi && ty == "ip" => with_net(check(sc, v, hosts)),
        Entry::Ip(lo, hi) => {
            let full = sc.excl.iter().find(|x| {
                entry(x, None)
                    .range()
                    .is_some_and(|(a, b)| a <= *lo && b >= *hi)
            });
            if let Some(f) = full {
                return Check {
                    net: true,
                    excluded: Some(f.clone()),
                    code: "excluded",
                    reason: "сеть в исключениях".into(),
                    ..Default::default()
                };
            }
            let Some(t) = sc.targets.iter().find(|x| low(&x.v) == low(v)) else {
                return Check {
                    net: true,
                    code: "out_of_scope",
                    reason: "нет в скоупе".into(),
                    ..Default::default()
                };
            };
            Check {
                ok: true,
                net: true,
                target: Some(t.v.clone()),
                code: "",
                ..Default::default()
            }
        }
    }
}

pub fn sev_weight(s: &str) -> f64 {
    match s {
        "crit" => 0.25,
        "high" => 0.12,
        "warn" => 0.05,
        "low" => 0.02,
        _ => 0.0,
    }
}

pub fn sev_rank(s: &str) -> u8 {
    match s {
        "crit" => 4,
        "high" => 3,
        "warn" => 2,
        "low" => 1,
        _ => 0,
    }
}

pub fn is_live_status(s: &str) -> bool {
    s != "false" && s != "fixed"
}

/// `FOCA_RULES.riskScore` over a list of findings (JSON `{sev, status}`).
pub fn risk_score<'a>(list: impl IntoIterator<Item = &'a Value>) -> u8 {
    let mut p = 1.0f64;
    for f in list {
        if is_live_status(f["status"].as_str().unwrap_or("new")) {
            p *= 1.0 - sev_weight(f["sev"].as_str().unwrap_or("info"));
        }
    }
    (100.0 * (1.0 - p)).round() as u8
}

/// Returns the risk level using the UI rule: 90 or more with critical findings is critical, 70 or more high, 40 or more medium.
pub fn risk_level(score: Option<u8>, has_crit: bool) -> &'static str {
    match score {
        None => "none",
        Some(s) if s >= 90 && has_crit => "crit",
        Some(s) if s >= 70 => "high",
        Some(s) if s >= 40 => "mid",
        Some(_) => "low",
    }
}

/// Returns `true` if findings have been computed: there is a finished scan, or one stopped after the analysis stage.
pub fn analyzed_scans(scans: &[Value]) -> bool {
    let idx = |s: &str| STAGE_IDS.iter().position(|x| *x == s);
    scans.iter().any(|s| {
        s["status"] == "done"
            || idx(s["stage"].as_str().unwrap_or("")).is_some_and(|i| Some(i) > idx("analysis"))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use foca_core::api::ScopeTarget;

    fn sc() -> ScopeDto {
        ScopeDto {
            targets: vec![
                ScopeTarget {
                    v: "contoso.ua".into(),
                    kind: "domain".into(),
                },
                ScopeTarget {
                    v: "203.0.113.0/24".into(),
                    kind: "cidr".into(),
                },
            ],
            excl: vec!["mail.contoso.ua".into(), "10.2.0.1-10.2.0.9".into()],
            ..Default::default()
        }
    }

    #[test]
    fn scope_rules_match_js() {
        let s = sc();
        assert!(check(&s, "a.b.contoso.ua", &[]).ok);
        assert!(check(&s, "Portal.Contoso.UA.", &[]).ok);
        assert!(!check(&s, "evilcontoso.ua", &[]).ok);
        assert_eq!(check(&s, "mail.contoso.ua", &[]).code, "excluded");
        let hosts = vec![KnownHost {
            name: "mail.contoso.ua".into(),
            ip: "203.0.113.20".into(),
        }];
        let c = check(&s, "203.0.113.20", &hosts);
        assert_eq!(c.code, "excluded");
        assert_eq!(c.via.as_deref(), Some("mail.contoso.ua"));
        assert!(check(&s, "203.0.113.21", &hosts).ok);
        assert_eq!(entry("10.2.0.1-9", None), Entry::Ip(0x0A020001, 0x0A020009));
        assert!(check(&s, "https://x.contoso.ua:8443/p", &[]).ok);
        let w = ScopeDto {
            targets: vec![ScopeTarget {
                v: "*.contoso.ua".into(),
                kind: "wild".into(),
            }],
            ..Default::default()
        };
        assert!(check(&w, "www.contoso.ua", &[]).ok);
        assert!(!check(&w, "contoso.ua", &[]).ok);
        assert!(check_target(&w, "*.contoso.ua", "wild", &[]).ok);
        assert!(!check_target(&s, "ТОВ", "org", &[]).net);
    }

    #[test]
    fn every_network_target_is_checked_in_active_phase() {
        // no switches or "active" marks: a target in scope and not excluded is checked
        let s = sc();
        assert!(check(&s, "contoso.ua", &[]).ok);
        assert!(check_target(&s, "203.0.113.0/24", "cidr", &[]).ok);
        assert_eq!(check(&s, "mail.contoso.ua", &[]).code, "excluded");
    }

    #[test]
    fn risk_rule() {
        let l = vec![
            serde_json::json!({"sev": "crit", "status": "new"}),
            serde_json::json!({"sev": "high", "status": "false"}),
        ];
        assert_eq!(risk_score(&l), 25);
        assert_eq!(risk_level(Some(93), false), "high");
        assert_eq!(risk_level(Some(93), true), "crit");
        assert_eq!(risk_level(Some(40), true), "mid");
        assert_eq!(risk_level(None, true), "none");
    }
}
