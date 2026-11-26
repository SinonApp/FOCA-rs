//! Project scope: which hosts and IPs modules that contact a target may touch.
//!
//! # Matching rules
//!
//! 1. Input is normalized: host names are lowercased, stripped of a trailing dot and converted
//!    from IDN to punycode; IP literals (including `[v6]` and IPv4-mapped IPv6) are checked as IPs.
//! 2. Exclusions take precedence: a host or IP covered by any exclusion is denied, even if it
//!    is also covered by a target.
//! 3. A host is allowed if a target covers it:
//!    * `Domain(d)` covers `d` itself and all of its subdomains (`a.b.d`);
//!    * `Wildcard(*.d)` covers subdomains only, not `d` itself;
//!    * `Url` covers only the exact host of the URL (no subdomains);
//!    * `Email`, `Org` and `Asn` grant no active actions on host names (an ASN requires
//!      resolving its ranges over the network and is checked in `foca-net`).
//!
//!    Subdomain boundaries are dot-delimited: `evilcontoso.example` is not part of
//!    `contoso.example`.
//! 4. An IP is allowed if an `Ip`, `Cidr`, `IpRange` target or a `Url` with an IP host covers it.
//!    For a host name that resolved to an IP, the caller checks both rules separately.
//! 5. Active operations (AXFR, forgotten file discovery) are possible only during the active
//!    stage of a scan. The engine sets `active_phase` from the scan profile (full, or custom
//!    with active modules); it is a property of the run, not of the project, and needs no
//!    confirmation.

use std::net::IpAddr;

use serde::{Deserialize, Serialize};

use crate::target::{normalize_domain, normalize_ip, parse_ip_literal, Target, TargetError};

/// Reason an active operation was denied.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ScopeDenied {
    #[error("активная фаза не входит в профиль скана")]
    NotActivePhase,
    #[error("«{0}» исключён из скоупа")]
    Excluded(String),
    #[error("«{0}» вне скоупа")]
    OutOfScope(String),
}

/// Scope: targets, exclusions and whether the current run is in its active stage.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Scope {
    pub targets: Vec<Target>,
    pub excludes: Vec<Target>,
    /// Whether the current scan is in its active stage (full or custom profile with active modules).
    /// Set by the engine at start; not persisted in the project (the legacy `allow_active` field is ignored).
    pub active_phase: bool,
}

/// Input parse error with a 1-based line number.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LineError {
    pub line: usize,
    pub input: String,
    pub error: TargetError,
}

enum Probe {
    Host(String),
    Ip(IpAddr),
    Invalid,
}

fn probe(host: &str) -> Probe {
    let h = host.trim();
    if let Some(ip) = parse_ip_literal(h) {
        return Probe::Ip(normalize_ip(ip));
    }
    match normalize_domain(h) {
        Ok((name, _)) => Probe::Host(name),
        Err(_) => Probe::Invalid,
    }
}

impl Scope {
    /// Builds a scope from multi-line input; blank lines and `#` comments are skipped.
    pub fn from_lines(targets: &str, excludes: &str) -> (Scope, Vec<LineError>) {
        let mut errs = Vec::new();
        let t = parse_lines(targets, &mut errs);
        let e = parse_lines(excludes, &mut errs);
        (
            Scope {
                targets: t,
                excludes: e,
                active_phase: false,
            },
            errs,
        )
    }

    /// Returns `true` if the host (name or IP literal) is allowed. Invalid names are never allowed.
    pub fn allows_host(&self, host: &str) -> bool {
        match probe(host) {
            Probe::Ip(ip) => self.allows_ip(ip),
            Probe::Host(h) => {
                !self.excludes.iter().any(|t| t.covers_host(&h))
                    && self.targets.iter().any(|t| t.covers_host(&h))
            }
            Probe::Invalid => false,
        }
    }

    /// Returns `true` if the IP address is allowed.
    pub fn allows_ip(&self, ip: IpAddr) -> bool {
        let ip = normalize_ip(ip);
        !self.excludes.iter().any(|t| t.contains_ip(ip))
            && self.targets.iter().any(|t| t.contains_ip(ip))
    }

    /// Returns `true` while the scan is in its active stage.
    pub fn active_phase(&self) -> bool {
        self.active_phase
    }

    /// Performs the full check before an active request: active stage, exclusions, targets.
    ///
    /// # Errors
    ///
    /// Returns [`ScopeDenied`] describing the first rule that rejected the host.
    pub fn check_active(&self, host: &str) -> Result<(), ScopeDenied> {
        if !self.active_phase {
            return Err(ScopeDenied::NotActivePhase);
        }
        let excluded = match probe(host) {
            Probe::Ip(ip) => self.excludes.iter().any(|t| t.contains_ip(ip)),
            Probe::Host(ref h) => self.excludes.iter().any(|t| t.covers_host(h)),
            Probe::Invalid => false,
        };
        if excluded {
            return Err(ScopeDenied::Excluded(host.to_string()));
        }
        if !self.allows_host(host) {
            return Err(ScopeDenied::OutOfScope(host.to_string()));
        }
        Ok(())
    }
}

fn parse_lines(text: &str, errs: &mut Vec<LineError>) -> Vec<Target> {
    let mut out = Vec::new();
    for (i, line) in text.lines().enumerate() {
        let l = line.trim();
        if l.is_empty() || l.starts_with('#') {
            continue;
        }
        match Target::parse(l) {
            Ok(t) => {
                if !out.contains(&t) {
                    out.push(t)
                }
            }
            Err(error) => errs.push(LineError {
                line: i + 1,
                input: l.to_string(),
                error,
            }),
        }
    }
    out
}

/// Error codes of request log entries the scope policy refused before any network call.
pub const SCOPE_BLOCK_CODES: &[&str] = &[
    "blocked",
    "out_of_scope",
    "not_active_phase",
    "active_not_allowed",
];

/// Returns `true` if a request log error means "refused by the scope". Errors are stored as
/// `code: detail` (`out_of_scope: host not in scope`, PTR `out_of_scope: excluded`); the flag
/// of the network record itself is not stored, so the code is the only trace.
pub fn is_scope_block(error: Option<&str>) -> bool {
    error
        .and_then(|e| e.split(':').next())
        .is_some_and(|c| SCOPE_BLOCK_CODES.contains(&c.trim()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scope_block_reads_the_code_before_the_detail() {
        for e in [
            "blocked",
            "out_of_scope",
            "out_of_scope: out_of_scope",
            "out_of_scope: excluded",
            "out_of_scope: host ptr.example.test is not in scope",
            "not_active_phase: active requests are off",
        ] {
            assert!(is_scope_block(Some(e)), "{e}");
        }
        for e in [
            "timeout",
            "network: connection refused",
            "redirect → x",
            "NXDOMAIN",
        ] {
            assert!(!is_scope_block(Some(e)), "{e}");
        }
        assert!(!is_scope_block(None));
    }

    fn scope(t: &str, e: &str) -> Scope {
        let (s, errs) = Scope::from_lines(t, e);
        assert!(errs.is_empty(), "{errs:?}");
        s
    }

    #[test]
    fn domain_and_subdomains() {
        let s = scope("contoso.example", "");
        assert!(s.allows_host("contoso.example"));
        assert!(s.allows_host("Portal.Contoso.EXAMPLE."));
        assert!(s.allows_host("a.b.contoso.example"));
        assert!(!s.allows_host("evilcontoso.example"));
        assert!(!s.allows_host("contoso.example.evil.com"));
        assert!(!s.allows_host("ua"));
        assert!(!s.allows_host(""));
        assert!(!s.allows_host("bad..host"));
    }

    #[test]
    fn wildcard_and_url() {
        let s = scope("*.contoso.ua\nhttps://shop.example.com/x", "");
        assert!(s.allows_host("www.contoso.ua"));
        assert!(!s.allows_host("contoso.ua"));
        assert!(s.allows_host("shop.example.com"));
        assert!(!s.allows_host("a.shop.example.com"));
        assert!(!s.allows_host("example.com"));
    }

    #[test]
    fn excludes_win() {
        let s = scope(
            "contoso.ua\n10.0.0.0/8",
            "vpn.contoso.ua\n*.dev.contoso.ua\n10.1.0.0/16\n10.2.0.1-10.2.0.9",
        );
        assert!(s.allows_host("mail.contoso.ua"));
        assert!(!s.allows_host("vpn.contoso.ua"));
        assert!(!s.allows_host("x.vpn.contoso.ua"));
        assert!(s.allows_host("dev.contoso.ua"));
        assert!(!s.allows_host("ci.dev.contoso.ua"));
        assert!(s.allows_ip("10.0.0.1".parse().unwrap()));
        assert!(!s.allows_ip("10.1.2.3".parse().unwrap()));
        assert!(!s.allows_ip("10.2.0.5".parse().unwrap()));
        assert!(s.allows_ip("10.2.0.10".parse().unwrap()));
        assert!(!s.allows_ip("11.0.0.1".parse().unwrap()));
        assert!(s.allows_host("10.3.3.3"));
        assert!(!s.allows_host("[::ffff:10.1.0.1]"));
    }

    #[test]
    fn ipv6() {
        let s = scope("2001:db8::/32\n::1", "2001:db8:dead::/48");
        assert!(s.allows_ip("2001:db8::5".parse().unwrap()));
        assert!(!s.allows_ip("2001:db8:dead::1".parse().unwrap()));
        assert!(s.allows_host("[::1]"));
        assert!(!s.allows_ip("2001:db9::1".parse().unwrap()));
        assert!(!s.allows_ip("10.0.0.1".parse().unwrap()));
    }

    #[test]
    fn email_org_asn_do_not_grant() {
        let s = scope("a@contoso.ua\nContoso LLC\nAS1234", "");
        assert!(!s.allows_host("contoso.ua"));
        assert!(!s.allows_ip("1.1.1.1".parse().unwrap()));
    }

    #[test]
    fn line_errors() {
        let (s, errs) = Scope::from_lines(
            "contoso.ua\n# comment\n\n300.1.1.1\ncontoso.ua",
            "10.0.0.0/40",
        );
        assert_eq!(s.targets.len(), 1);
        assert_eq!(errs.len(), 2);
        assert_eq!(errs[0].line, 4);
    }

    #[test]
    fn active_phase_gate() {
        let mut s = scope("contoso.ua", "vpn.contoso.ua");
        assert!(!s.active_phase());
        assert_eq!(
            s.check_active("contoso.ua"),
            Err(ScopeDenied::NotActivePhase)
        );
        s.active_phase = true;
        assert!(s.active_phase());
        assert_eq!(s.check_active("www.contoso.ua"), Ok(()));
        assert!(matches!(
            s.check_active("vpn.contoso.ua"),
            Err(ScopeDenied::Excluded(_))
        ));
        assert!(matches!(
            s.check_active("evil.ua"),
            Err(ScopeDenied::OutOfScope(_))
        ));
        let j = serde_json::to_string(&s).unwrap();
        assert_eq!(serde_json::from_str::<Scope>(&j).unwrap(), s);
        // legacy 0.2.x data: the old project-level switch is ignored
        let old: Scope =
            serde_json::from_str(r#"{"targets":[],"excludes":[],"allow_active":true}"#).unwrap();
        assert!(!old.active_phase);
    }
}
