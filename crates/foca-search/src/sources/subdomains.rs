//! Keyless passive subdomain sources (logic modeled on subfinder's
//! `pkg/subscraping/sources/*`, MIT; the code is original). All are `SourceKind::Passive`: they
//! contact third-party services only, never the target. Responses vary (JSON array, CSV, HTML,
//! text), so names are pulled out by one tolerant scanner, [`extract_hosts`], which looks for
//! `[a-z0-9.-]` runs ending in `.<domain>`. Service errors (rate limit, key required) are told
//! apart by status and response text.

use std::collections::BTreeSet;
use std::time::Duration;

use foca_net::{Access, NetError, NetRequest};

use crate::source::{DocumentSource, Found, SearchCtx, SourceKind};
use crate::BoxFuture;

/// Extracts `*.domain` names (and the domain itself) from arbitrary response text: JSON, CSV,
/// HTML. `*.` wildcards, `www.` duplicates and junk are dropped; names are lowercased.
pub fn extract_hosts(text: &str, domain: &str) -> Vec<String> {
    let domain = domain.trim().trim_end_matches('.').to_ascii_lowercase();
    let suffix = format!(".{domain}");
    // JSON escapes and URL encoding glue neighboring characters to the name
    // ("\nb.x", "%2Fa.x", "\u002fa.x"), so replace them with separators first
    let mut lower = text.to_ascii_lowercase();
    for (from, to) in [
        ("\\n", " "),
        ("\\r", " "),
        ("\\t", " "),
        ("\\/", "/"),
        ("\\u002f", "/"),
        ("\\u003d", "="),
        ("%2f", "/"),
        ("%3a", ":"),
        ("%3d", "="),
        ("%2e", "."),
    ] {
        if lower.contains(from) {
            lower = lower.replace(from, to);
        }
    }
    let mut out = BTreeSet::new();
    let is_c = |c: char| c.is_ascii_alphanumeric() || c == '-' || c == '.';
    for tok in lower.split(|c: char| !is_c(c)) {
        let t = tok.trim_matches(|c: char| c == '.' || c == '-');
        if t != domain && !(t.ends_with(&suffix) && t.len() > suffix.len()) {
            continue;
        }
        let ok = t.len() <= 253
            && t.split('.').all(|l| {
                !l.is_empty() && l.len() <= 63 && !l.starts_with('-') && !l.ends_with('-')
            });
        if ok {
            out.insert(t.to_string());
        }
    }
    out.into_iter().collect()
}

/// Recognizes how a service answers when a key is required or the quota is exhausted.
fn service_error(id: &str, status: u16, body: &str) -> Option<NetError> {
    let low = body.to_ascii_lowercase();
    let limited = status == 429
        || low.contains("api count exceeded")
        || low.contains("rate limit")
        || low.contains("too many requests")
        || low.contains("limit reached");
    if limited {
        // source status `limit` (not an error); the text comes from `source::limit_message`
        let _ = id;
        return Some(NetError::Status(429));
    }
    if status == 401 || status == 403 || low.contains("please authenticate") {
        return Some(NetError::Request(format!(
            "{id}: сервис требует ключ / отказал (HTTP {status})"
        )));
    }
    if !(200..300).contains(&status) && status != 404 {
        return Some(NetError::Status(status));
    }
    None
}

/// A passive subdomain source: a single GET, names extracted with [`extract_hosts`].
#[derive(Debug, Clone)]
pub struct HostSource {
    pub id: &'static str,
    pub name: &'static str,
    /// URL template; `{d}` is the domain.
    pub url: String,
    pub timeout: Duration,
    pub api_key: Option<String>,
}

impl HostSource {
    pub fn new(id: &'static str, name: &'static str, url: &str) -> Self {
        HostSource {
            id,
            name,
            url: url.into(),
            timeout: Duration::from_secs(40),
            api_key: None,
        }
    }

    /// Replaces the scheme and host of the template with `base` (tests).
    pub fn with_base(mut self, base: &str) -> Self {
        if let Ok(u) = url::Url::parse(&self.url.replace("{d}", "x")) {
            let origin = u.origin().ascii_serialization();
            self.url = self.url.replacen(&origin, base.trim_end_matches('/'), 1);
        }
        self
    }

    pub fn with_key(mut self, k: Option<String>) -> Self {
        self.api_key = k.map(|v| v.trim().to_string()).filter(|v| !v.is_empty());
        self
    }
}

/// Keyless subdomain sources (id, name, endpoint), ordered by speed and reliability.
pub const HOST_SOURCES: &[(&str, &str, &str)] = &[
    (
        "certspotter",
        "CertSpotter",
        "https://api.certspotter.com/v1/issuances?domain={d}&include_subdomains=true&expand=dns_names",
    ),
    ("anubis", "Anubis", "https://anubisdb.com/anubis/subdomains/{d}"),
    ("crtname", "crt.name", "https://crt.name/v1/search?apex={d}"),
    (
        "scanmalware",
        "ScanMalware",
        "https://scanmalware.com/api/v1/ct/dns/{d}?subdomain_limit=1000",
    ),
    (
        "hackertarget",
        "HackerTarget",
        "https://api.hackertarget.com/hostsearch/?q={d}",
    ),
    ("rapiddns", "RapidDNS", "https://rapiddns.io/subdomain/{d}?full=1"),
    (
        "subcenter",
        "subdomain.center",
        "https://api.subdomain.center/?domain={d}",
    ),
    (
        "thc",
        "THC ip.thc.org",
        "https://ip.thc.org/api/v1/subdomains/download?domain={d}&limit=5000",
    ),
    (
        "shodanct",
        "Shodan CT",
        "https://ctl.shodan.io/api/v1/domain/{d}/hostnames",
    ),
    (
        "otx_dns",
        "AlienVault OTX (passive DNS)",
        "https://otx.alienvault.com/api/v1/indicators/domain/{d}/passive_dns",
    ),
];

/// Returns the subdomain source with the given id.
pub fn host_source(id: &str) -> Option<HostSource> {
    HOST_SOURCES
        .iter()
        .find(|s| s.0 == id)
        .map(|s| HostSource::new(s.0, s.1, s.2))
}

impl DocumentSource for HostSource {
    fn id(&self) -> &'static str {
        self.id
    }
    fn name(&self) -> &'static str {
        self.name
    }
    fn kind(&self) -> SourceKind {
        SourceKind::Passive
    }
    fn find<'a>(
        &'a self,
        ctx: &'a SearchCtx,
        domain: &'a str,
    ) -> BoxFuture<'a, Result<Found, NetError>> {
        Box::pin(async move {
            let u = self.url.replace("{d}", domain);
            let mut req = NetRequest::get(&u, self.id, Access::Passive)?
                .header("accept", "application/json, text/plain, text/html;q=0.8")
                .timeout(ctx.req_timeout(self.timeout))
                .retries(1);
            if self.id == "otx_dns" {
                if let Some(k) = self.api_key.as_deref() {
                    req = req.header("X-OTX-API-KEY", k);
                }
            }
            let r = ctx.net.send(req).await?;
            let st = r.status();
            let body = r.text_limited(16 * 1024 * 1024).await?;
            if let Some(e) = service_error(self.id, st, &body) {
                return Err(e);
            }
            Ok(Found {
                urls: vec![],
                hosts: extract_hosts(&body, domain),
                note: None,
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hosts_from_json_csv_html_text() {
        let d = "testfire.net";
        // Anubis / subdomain.center / Shodan CT: JSON array
        let j = r#"["altoro.testfire.net","demo.testfire.net","*.Wild.TESTFIRE.net","testfire.net","evil.example.com","x.testfire.net.evil.com"]"#;
        assert_eq!(
            extract_hosts(j, d),
            vec![
                "altoro.testfire.net",
                "demo.testfire.net",
                "testfire.net",
                "wild.testfire.net"
            ]
        );
        // HackerTarget: CSV host,ip
        let c = "altoro.testfire.net,65.61.137.117\nwww.testfire.net,65.61.137.117\n";
        assert_eq!(
            extract_hosts(c, d),
            vec!["altoro.testfire.net", "www.testfire.net"]
        );
        // RapidDNS: HTML table
        let h = r#"<tr><td>demo2.testfire.net</td><td><a href="/sameip/65.61.137.117">65.61.137.117</a></td><td>A</td></tr>"#;
        assert_eq!(extract_hosts(h, d), vec!["demo2.testfire.net"]);
        // CertSpotter: dns_names; crt.sh: name_value with \n inside the JSON string
        let cs = r#"[{"dns_names":["mail.testfire.net","testfire.net"]},{"name_value":"a.testfire.net\nb.testfire.net"}]"#;
        assert_eq!(
            extract_hosts(cs, d),
            vec![
                "a.testfire.net",
                "b.testfire.net",
                "mail.testfire.net",
                "testfire.net"
            ]
        );
        // THC: plain text; a URL-encoded "/" does not stick to the name
        let t = "subdomain\ntestfire.net\nftp.testfire.net\nhttps%3A%2F%2Fftp.testfire.net%2F";
        assert_eq!(
            extract_hosts(t, d),
            vec!["ftp.testfire.net", "testfire.net"]
        );
    }

    #[test]
    fn service_errors() {
        assert!(service_error(
            "hackertarget",
            200,
            "error: API count exceeded - Increase Quota"
        )
        .is_some());
        assert!(service_error(
            "otx_dns",
            429,
            "{\"detail\": \"Anonymous access ... Please authenticate.\"}"
        )
        .is_some());
        assert!(service_error("x", 200, "[\"a.x.y\"]").is_none());
        assert!(service_error("x", 404, "").is_none());
        assert!(matches!(
            service_error("x", 503, ""),
            Some(NetError::Status(503))
        ));
    }
}
