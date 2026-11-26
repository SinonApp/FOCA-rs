//! Content-Security-Policy parsing: weakness assessment and extraction of the hosts the policy
//! allows (hidden API, staging and third-party services).
//!
//! Pure analysis of an already received header or `<meta http-equiv>` value (access class
//! `passive`): nothing here sends requests. Hosts are only *reported*; the caller decides which
//! of them are in scope (new hosts) and which are mere candidates (never contacted).

use serde::{Deserialize, Serialize};

use foca_core::Severity;

/// Fetch directives that fall back to `default-src`.
const FETCH_FALLBACK: &[&str] = &[
    "script-src",
    "script-src-elem",
    "style-src",
    "img-src",
    "connect-src",
    "frame-src",
    "child-src",
    "worker-src",
    "object-src",
    "font-src",
    "media-src",
    "manifest-src",
];

/// Directives whose hosts are reported as domain candidates.
pub const DOMAIN_DIRECTIVES: &[&str] = &[
    "default-src",
    "script-src",
    "script-src-elem",
    "connect-src",
    "frame-src",
    "child-src",
    "worker-src",
    "form-action",
];

/// A parsed policy.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Csp {
    /// Directives in header order, names lowercased; repeated directives keep the first one
    /// (as browsers do).
    pub directives: Vec<(String, Vec<String>)>,
    /// `Content-Security-Policy-Report-Only`: the policy is not enforced.
    pub report_only: bool,
}

/// A policy weakness.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CspIssue {
    /// `unsafe_inline`, `unsafe_eval`, `wildcard_source`, `scheme_source`, `no_script_policy`,
    /// `missing_object_src`, `missing_base_uri`, `report_only`.
    pub id: String,
    pub directive: String,
    pub detail: String,
    pub sev: Severity,
}

/// A host allowed by the policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CspDomain {
    /// Host without the `*.` prefix, lowercased.
    pub host: String,
    /// Allowed as `*.host`.
    pub wildcard: bool,
    /// Directives that allow the host.
    pub directives: Vec<String>,
    /// `staging` (dev/test/stage/uat/internal labels), `api` (api/gateway/graphql) or empty.
    pub hint: String,
    /// Filled by the caller: the host is in the project scope.
    pub in_scope: bool,
}

/// Parses a policy value. Several policies separated by `,` (multiple headers merged) are
/// merged: the first occurrence of a directive wins.
pub fn parse(value: &str, report_only: bool) -> Csp {
    let mut csp = Csp {
        report_only,
        ..Default::default()
    };
    for part in value.split([';', ',']) {
        let mut it = part.split_ascii_whitespace();
        let Some(name) = it.next() else { continue };
        let name = name.to_ascii_lowercase();
        if csp.directives.iter().any(|(n, _)| *n == name) {
            continue;
        }
        csp.directives
            .push((name, it.map(|s| s.to_string()).collect()));
    }
    csp
}

impl Csp {
    /// Returns the sources of a directive as written.
    pub fn get(&self, name: &str) -> Option<&[String]> {
        self.directives
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_slice())
    }

    /// Returns the effective sources of a fetch directive (falls back to `default-src`).
    pub fn effective(&self, name: &str) -> Option<(String, &[String])> {
        if let Some(v) = self.get(name) {
            return Some((name.to_string(), v));
        }
        if name == "script-src-elem" {
            if let Some(v) = self.get("script-src") {
                return Some(("script-src".to_string(), v));
            }
        }
        if FETCH_FALLBACK.contains(&name) {
            return self
                .get("default-src")
                .map(|v| ("default-src".to_string(), v));
        }
        None
    }

    /// Assesses the policy.
    pub fn issues(&self) -> Vec<CspIssue> {
        let mut out = Vec::new();
        let mut push = |id: &str, directive: &str, detail: String, sev: Severity| {
            out.push(CspIssue {
                id: id.into(),
                directive: directive.into(),
                detail,
                sev,
            })
        };
        if self.report_only {
            push(
                "report_only",
                "",
                "политика в режиме Report-Only и не применяется браузером".into(),
                Severity::Low,
            );
        }
        match self.effective("script-src") {
            None => push(
                "no_script_policy",
                "script-src",
                "нет script-src и default-src: загрузка скриптов не ограничена".into(),
                Severity::Medium,
            ),
            Some((dir, src)) => {
                let dir = dir.as_str();
                let has = |k: &str| src.iter().any(|s| s.eq_ignore_ascii_case(k));
                let nonce_or_hash = src.iter().any(|s| {
                    let l = s.to_ascii_lowercase();
                    l.starts_with("'nonce-")
                        || l.starts_with("'sha256-")
                        || l.starts_with("'sha384-")
                        || l.starts_with("'sha512-")
                });
                let strict_dynamic = has("'strict-dynamic'");
                // 'unsafe-inline' is ignored by CSP2+ browsers when a nonce or hash is present.
                if has("'unsafe-inline'") && !nonce_or_hash {
                    push(
                        "unsafe_inline",
                        dir,
                        format!("{dir} разрешает 'unsafe-inline': CSP не защищает от XSS"),
                        Severity::Medium,
                    );
                }
                if has("'unsafe-eval'") {
                    push(
                        "unsafe_eval",
                        dir,
                        format!("{dir} разрешает 'unsafe-eval' (eval/new Function)"),
                        Severity::Low,
                    );
                }
                if !strict_dynamic {
                    if src.iter().any(|s| s == "*") {
                        push(
                            "wildcard_source",
                            dir,
                            format!("{dir} разрешает скрипты с любого хоста (*)"),
                            Severity::Medium,
                        );
                    }
                    let schemes: Vec<&str> = src
                        .iter()
                        .map(String::as_str)
                        .filter(|s| {
                            matches!(
                                s.to_ascii_lowercase().as_str(),
                                "http:" | "https:" | "data:" | "blob:"
                            )
                        })
                        .collect();
                    if !schemes.is_empty() {
                        push(
                            "scheme_source",
                            dir,
                            format!(
                                "{dir} разрешает целые схемы ({}): фактически любой источник",
                                schemes.join(" ")
                            ),
                            Severity::Medium,
                        );
                    }
                }
            }
        }
        let object_none = self
            .effective("object-src")
            .is_some_and(|(_, v)| v.iter().any(|s| s.eq_ignore_ascii_case("'none'")));
        if !object_none {
            push(
                "missing_object_src",
                "object-src",
                "нет object-src 'none' (ни явно, ни через default-src): плагины не запрещены"
                    .into(),
                Severity::Low,
            );
        }
        if self.get("base-uri").is_none() {
            push(
                "missing_base_uri",
                "base-uri",
                "нет base-uri: внедрённый <base> может перенаправить относительные скрипты".into(),
                Severity::Low,
            );
        }
        out
    }

    /// Returns hosts allowed by [`DOMAIN_DIRECTIVES`] (keywords, schemes and `*` skipped).
    pub fn domains(&self) -> Vec<CspDomain> {
        let mut out: Vec<CspDomain> = Vec::new();
        for (dir, src) in &self.directives {
            if !DOMAIN_DIRECTIVES.contains(&dir.as_str()) {
                continue;
            }
            for s in src {
                let Some((host, wildcard)) = source_host(s) else {
                    continue;
                };
                match out.iter_mut().find(|d| d.host == host) {
                    Some(d) => {
                        d.wildcard |= wildcard;
                        if !d.directives.contains(dir) {
                            d.directives.push(dir.clone());
                        }
                    }
                    None => out.push(CspDomain {
                        hint: host_hint(&host).into(),
                        host,
                        wildcard,
                        directives: vec![dir.clone()],
                        in_scope: false,
                    }),
                }
            }
        }
        out.sort_by(|a, b| a.host.cmp(&b.host));
        out
    }
}

/// Extracts the host of a CSP host-source (`https://*.api.example.com:443/path`).
pub fn source_host(s: &str) -> Option<(String, bool)> {
    let s = s.trim();
    if s.starts_with('\'') || s == "*" || s.ends_with(':') {
        return None;
    }
    let rest = match s.split_once("://") {
        Some((_, r)) => r,
        None => s,
    };
    let host = rest.split(['/', '?', '#']).next().unwrap_or("");
    // Strip the port; IPv6 literals are not expected in CSP host-sources.
    let host = host.rsplit_once(':').map_or(host, |(h, _)| h);
    let (host, wildcard) = match host.strip_prefix("*.") {
        Some(h) => (h, true),
        None => (host, false),
    };
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    let valid = host.contains('.')
        && host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.')
        && !host.starts_with('.')
        && !host.starts_with('-');
    valid.then_some((host, wildcard))
}

/// Classifies a host by its labels: `staging`, `api` or empty.
pub fn host_hint(host: &str) -> &'static str {
    let labels: Vec<&str> = host.split('.').collect();
    let n = labels.len().saturating_sub(2);
    let inner = &labels[..n];
    let any = |set: &[&str]| {
        inner.iter().any(|l| {
            l.split('-').any(|p| {
                set.contains(&p)
                    || set.iter().any(|s| {
                        p.starts_with(s)
                            && p.len() <= s.len() + 2
                            && p[s.len()..].chars().all(|c| c.is_ascii_digit())
                    })
            })
        })
    };
    if any(&[
        "staging", "stage", "stg", "dev", "develop", "test", "testing", "qa", "uat", "preprod",
        "pre", "sandbox", "beta", "internal", "intranet", "corp", "local", "demo",
    ]) {
        "staging"
    } else if any(&["api", "apis", "gateway", "gw", "graphql", "rest", "backend"]) {
        "api"
    } else {
        ""
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_and_assess() {
        let c = parse(
            "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.example.net *.api-stage.contoso.ua; connect-src https://api.contoso.ua wss://rt.contoso.ua:8443 https:; frame-src https://www.youtube.com",
            false,
        );
        let issues = c.issues();
        let ids2: Vec<&str> = issues.iter().map(|i| i.id.as_str()).collect();
        assert!(ids2.contains(&"unsafe_inline"), "{ids2:?}");
        assert!(ids2.contains(&"unsafe_eval"));
        assert!(ids2.contains(&"missing_object_src"));
        assert!(ids2.contains(&"missing_base_uri"));
        assert!(
            !ids2.contains(&"scheme_source"),
            "https: only in connect-src"
        );
        let d = c.domains();
        let hosts: Vec<&str> = d.iter().map(|d| d.host.as_str()).collect();
        assert_eq!(
            hosts,
            [
                "api-stage.contoso.ua",
                "api.contoso.ua",
                "cdn.example.net",
                "rt.contoso.ua",
                "www.youtube.com"
            ]
        );
        assert!(d[0].wildcard);
        assert_eq!(d[0].hint, "staging");
        assert_eq!(d[1].hint, "api");
        assert_eq!(d[4].directives, ["frame-src"]);
    }

    #[test]
    fn nonce_neutralizes_unsafe_inline_and_strict_policy_is_clean() {
        let c = parse(
            "default-src 'none'; script-src 'nonce-abc' 'unsafe-inline' 'strict-dynamic' https:; base-uri 'none'",
            false,
        );
        assert!(c.issues().is_empty(), "{:?}", c.issues());
        let c = parse("img-src *", true);
        let ids: Vec<String> = c.issues().into_iter().map(|i| i.id).collect();
        assert!(ids.contains(&"report_only".to_string()));
        assert!(ids.contains(&"no_script_policy".to_string()));
    }

    #[test]
    fn first_directive_wins_and_sources() {
        let c = parse("script-src *; script-src 'self'", false);
        assert_eq!(c.get("script-src").unwrap(), ["*"]);
        assert_eq!(source_host("'self'"), None);
        assert_eq!(source_host("data:"), None);
        assert_eq!(
            source_host("https://*.Dev.Contoso.ua:443/x"),
            Some(("dev.contoso.ua".into(), true))
        );
        assert_eq!(host_hint("dev2.contoso.ua"), "staging");
        assert_eq!(host_hint("devices.contoso.ua"), "");
        assert_eq!(host_hint("contoso.ua"), "");
    }
}
