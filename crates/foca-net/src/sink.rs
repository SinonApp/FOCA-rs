//! Outgoing request log: every network call (HTTP hop, DNS query, TCP connect, AXFR) and every
//! scope denial is recorded through [`RequestSink`].

use std::sync::Mutex;

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

/// A request log record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RequestRecord {
    #[serde(with = "time::serde::rfc3339")]
    pub time: OffsetDateTime,
    /// Source module: `wayback`, `cc`, `crt`, `crawler`, `brave`, `searx`, `dns`,
    /// `download`, `ping`, `axfr`, `rdap`, ...
    pub module: String,
    /// `GET`, `HEAD`, `DNS`, `TCP`, `AXFR`, ...
    pub method: String,
    /// URL with secret query parameters masked.
    pub url: String,
    pub host: String,
    pub status: Option<u16>,
    pub bytes: u64,
    /// The request went to a target (`TouchesTarget`/`Active`) rather than to a third-party service.
    pub active: bool,
    /// `passive` | `target` | `active`.
    pub access: String,
    /// Blocked by scope policy (no network call was made).
    pub blocked: bool,
    pub error: Option<String>,
}

/// Request log sink. Required by [`crate::NetClient`]; implementations must be fast because
/// they are called synchronously from network code.
pub trait RequestSink: Send + Sync {
    fn record(&self, rec: &RequestRecord);
}

/// In-memory log (tests, CLI).
#[derive(Debug, Default)]
pub struct MemorySink(Mutex<Vec<RequestRecord>>);

impl MemorySink {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn records(&self) -> Vec<RequestRecord> {
        match self.0.lock() {
            Ok(g) => g.clone(),
            Err(p) => p.into_inner().clone(),
        }
    }

    pub fn len(&self) -> usize {
        self.records().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl RequestSink for MemorySink {
    fn record(&self, rec: &RequestRecord) {
        match self.0.lock() {
            Ok(mut g) => g.push(rec.clone()),
            Err(p) => p.into_inner().push(rec.clone()),
        }
    }
}

/// No-op sink; an explicit opt-out for utilities, never for scans.
#[derive(Debug, Default, Clone, Copy)]
pub struct NullSink;

impl RequestSink for NullSink {
    fn record(&self, _rec: &RequestRecord) {}
}

/// Forwards records to several sinks.
pub struct TeeSink(pub Vec<std::sync::Arc<dyn RequestSink>>);

impl RequestSink for TeeSink {
    fn record(&self, rec: &RequestRecord) {
        for s in &self.0 {
            s.record(rec);
        }
    }
}

const SECRET_PARAMS: &[&str] = &[
    "key",
    "api_key",
    "apikey",
    "token",
    "access_token",
    "auth",
    "password",
    "secret",
];

/// Path segments that are credentials themselves: the Telegram bot token (`/bot<id>:<token>/`)
/// and everything after a webhook prefix (Slack `/services/…`, Discord `/api/webhooks/…`,
/// Mattermost `/hooks/…`).
const SECRET_PATH_PREFIXES: &[&str] = &["webhooks", "hooks"];

fn redact_path(host: &str, path: &str) -> Option<String> {
    let slack = host.eq_ignore_ascii_case("hooks.slack.com");
    let mut changed = false;
    let mut out: Vec<String> = Vec::new();
    let mut rest_secret = false;
    for seg in path.split('/') {
        if rest_secret && !seg.is_empty() {
            if out.last().map(String::as_str) != Some("***") {
                out.push("***".into());
            }
            changed = true;
            continue;
        }
        let bot = seg
            .strip_prefix("bot")
            .and_then(|t| t.split_once(':'))
            .is_some_and(|(id, tok)| {
                !id.is_empty() && id.bytes().all(|b| b.is_ascii_digit()) && tok.len() >= 8
            });
        if bot {
            out.push("bot***".into());
            changed = true;
            continue;
        }
        if SECRET_PATH_PREFIXES
            .iter()
            .any(|p| seg.eq_ignore_ascii_case(p))
            || (slack && seg == "services")
        {
            rest_secret = true;
        }
        out.push(seg.to_string());
    }
    changed.then(|| out.join("/"))
}

/// Masks credentials in a URL: secret query parameters (`key=...`, `token=...` and similar),
/// the Telegram bot token in the path and webhook path secrets.
pub fn redact_url(url: &str) -> String {
    let Ok(mut u) = url::Url::parse(url) else {
        return url.to_string();
    };
    let mut changed = false;
    if let Some(p) = redact_path(u.host_str().unwrap_or(""), u.path()) {
        u.set_path(&p);
        changed = true;
    }
    if !u.username().is_empty() || u.password().is_some() {
        let _ = u.set_username("");
        let _ = u.set_password(None);
        changed = true;
    }
    if u.query().is_some() {
        let pairs: Vec<(String, String)> = u
            .query_pairs()
            .map(|(k, v)| {
                let secret = SECRET_PARAMS.iter().any(|s| k.eq_ignore_ascii_case(s));
                (
                    k.into_owned(),
                    if secret {
                        "***".to_string()
                    } else {
                        v.into_owned()
                    },
                )
            })
            .collect();
        if pairs.iter().any(|(_, v)| v == "***") {
            u.query_pairs_mut().clear().extend_pairs(pairs);
            changed = true;
        }
    }
    if changed {
        u.to_string()
    } else {
        url.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_keys() {
        let r = redact_url("https://www.googleapis.com/customsearch/v1?key=SECRET&cx=1&q=a");
        assert!(!r.contains("SECRET"));
        assert!(r.contains("cx=1"));
        let same = "https://a.b/x?q=1";
        assert_eq!(redact_url(same), same);
    }

    #[test]
    fn redacts_path_credentials() {
        let r = redact_url("https://api.telegram.org/bot123456:AAE-secretTOKENvalue_x/sendMessage");
        assert_eq!(r, "https://api.telegram.org/bot***/sendMessage");
        let r = redact_url("https://hooks.slack.com/services/T000/B000/XXXXSECRET");
        assert_eq!(r, "https://hooks.slack.com/services/***");
        let r = redact_url("https://discord.com/api/webhooks/42/SECRETtoken?wait=true");
        assert_eq!(r, "https://discord.com/api/webhooks/***?wait=true");
        let r = redact_url("https://chat.example.com/hooks/SECRETkey");
        assert_eq!(r, "https://chat.example.com/hooks/***");
        let r = redact_url("https://user:SECRETpw@example.com/x");
        assert!(!r.contains("SECRET") && !r.contains("user"));
        // ordinary paths stay as they are
        let same = "https://example.com/services/bot/report.pdf";
        assert_eq!(redact_url(same), same);
    }
}
