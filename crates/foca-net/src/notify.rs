//! Alert delivery: Telegram Bot API (`sendMessage`, HTML) and webhooks (Slack / Mattermost
//! `{text}`, Discord `{content}`, generic JSON), always through [`NetClient`] (request log,
//! proxy, rate limits, cancellation).
//!
//! Safety rules:
//! * The bot token and webhook URL are [`Secret`]s (their `Debug` prints `***`). They come from the
//!   key store of the caller and are never logged: the request log masks `/bot<token>/` and
//!   webhook path secrets (see [`crate::sink::redact_url`]), and URL parse errors do not echo the URL.
//! * Message text is built only from allow-listed alert parameters passed through
//!   [`sanitize_param`], which masks anything that looks like a secret, token, e-mail address or
//!   long digit run (IDs, card and phone numbers). The generic webhook gets rendered lines, not raw
//!   parameters.
//!
//! Delivery: up to [`NotifyOptions::attempts`] tries with exponential backoff on network errors
//! and 5xx; HTTP 429 waits for `Retry-After` (header or Telegram `parameters.retry_after`) unless it
//! exceeds [`NotifyOptions::max_retry_after`]. Redirects are not followed (the body must not reach
//! another host).

use std::collections::BTreeMap;
use std::sync::OnceLock;
use std::time::Duration;

use foca_core::Severity;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{Access, Method, NetClient, NetError, NetRequest};

/// Request log module name.
pub const MODULE: &str = "notify";
/// Telegram `sendMessage` text limit (characters).
pub const TELEGRAM_LIMIT: usize = 4096;
/// Discord `content` limit.
pub const DISCORD_LIMIT: usize = 2000;
/// Limit used for Slack/Mattermost/generic text (well under their own limits).
pub const WEBHOOK_LIMIT: usize = 4000;

/// A credential value; `Debug`/`Display` never print it.
#[derive(Clone, PartialEq, Eq)]
pub struct Secret(String);

impl Secret {
    pub fn new(v: impl Into<String>) -> Self {
        Secret(v.into().trim().to_string())
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    fn expose(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Secret(***)")
    }
}

/// Webhook payload flavor.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WebhookKind {
    /// `{"text": "..."}` (Slack incoming webhooks, mrkdwn escaping).
    #[default]
    Slack,
    /// `{"text": "..."}` (Mattermost incoming webhooks).
    Mattermost,
    /// `{"content": "..."}`, 2000 characters.
    Discord,
    /// `{"text", "project", "scan_time", "count", "alerts": [{rule, severity, text}]}`.
    Generic,
}

/// A delivery channel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Channel {
    Telegram { token: Secret, chat_id: String },
    Webhook { url: Secret, kind: WebhookKind },
}

/// Message language (fallback templates are loaded from `locales/{en,ru,uk}/notify.json`;
/// an i18n lookup can override them).
pub use foca_core::Lang;

/// Optional i18n lookup: `(key, lang)` → template with `{param}` placeholders.
pub type Translate<'a> = &'a (dyn Fn(&str, Lang) -> Option<String> + Sync);

/// An alert to deliver. The JSON shape matches `foca_analysis::alerts::Alert` (extra fields are
/// ignored), so the engine can convert with `serde_json::from_value(serde_json::to_value(alert))`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct NotifyAlert {
    pub rule: String,
    pub severity: Severity,
    pub title_key: String,
    pub params: BTreeMap<String, Value>,
}

/// A notification: alerts of one scan of one project.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Notice {
    pub project: String,
    /// RFC 3339; informational (generic webhook).
    pub scan_time: String,
    pub alerts: Vec<NotifyAlert>,
    /// Alerts cut before delivery (shown as "… and N more").
    pub dropped: usize,
}

/// Delivery settings.
#[derive(Debug, Clone)]
pub struct NotifyOptions {
    /// Telegram Bot API base URL (tests point it at a local server).
    pub telegram_api: String,
    pub lang: Lang,
    /// Total tries per message (≥ 1).
    pub attempts: u32,
    /// First backoff delay, doubled per retry.
    pub backoff: Duration,
    /// A 429 asking to wait longer than this fails with [`NotifyError::RateLimited`].
    pub max_retry_after: Duration,
    /// Per-request timeout.
    pub timeout: Duration,
    /// Allow `http://` webhooks (tests, local relays); `https://` is required otherwise.
    pub allow_http: bool,
}

impl Default for NotifyOptions {
    fn default() -> Self {
        NotifyOptions {
            telegram_api: "https://api.telegram.org".into(),
            lang: Lang::Uk,
            attempts: 3,
            backoff: Duration::from_secs(2),
            max_retry_after: Duration::from_secs(60),
            timeout: Duration::from_secs(20),
            allow_http: false,
        }
    }
}

/// Delivery result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Delivery {
    pub status: u16,
    pub attempts: u32,
    /// Alerts in the message (the rest were cut by the length limit or `dropped`).
    pub sent: usize,
}

/// Delivery error. Messages never contain the token or the webhook URL.
#[derive(Debug, thiserror::Error)]
pub enum NotifyError {
    #[error("настройка уведомлений: {0}")]
    Config(&'static str),
    #[error("{0}")]
    Net(#[from] NetError),
    #[error("сервис отклонил сообщение: HTTP {status} {reason}")]
    Rejected { status: u16, reason: String },
    #[error("лимит запросов сервиса: повтор через {retry_after} с")]
    RateLimited { retry_after: u64 },
}

impl NotifyError {
    /// Short machine code for the UI: `config` | `network` | `rejected` | `rate_limited` | ….
    pub fn code(&self) -> &'static str {
        match self {
            NotifyError::Config(_) => "config",
            NotifyError::Net(e) => e.code(),
            NotifyError::Rejected { .. } => "rejected",
            NotifyError::RateLimited { .. } => "rate_limited",
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Sanitizing

/// Alert parameters allowed into message text; anything else is dropped.
pub const ALLOWED_PARAMS: &[&str] = &[
    "host",
    "port",
    "service",
    "doc",
    "count",
    "days",
    "date",
    "expired",
    "cname",
    "provider",
    "names",
    "new_names",
    "issuer",
    "risk",
    "prev",
    "delta",
    "threshold",
    "crit",
    "high",
];

const MAX_PARAM_CHARS: usize = 120;

fn patterns() -> &'static [Regex] {
    static RE: OnceLock<Vec<Regex>> = OnceLock::new();
    RE.get_or_init(|| {
        [
            // PEM blocks and private keys
            r"-----BEGIN[^-]*-----[\s\S]*?(-----END[^-]*-----|$)",
            // JWT
            r"eyJ[A-Za-z0-9_\-]{5,}\.[A-Za-z0-9_\-]{5,}\.[A-Za-z0-9_\-]*",
            // Telegram bot tokens
            r"\b\d{5,}:[A-Za-z0-9_\-]{20,}",
            // well-known key prefixes
            r"\b(AKIA|ASIA)[A-Z0-9]{12,}",
            r"\bgh[pousr]_[A-Za-z0-9]{16,}",
            r"\bgithub_pat_[A-Za-z0-9_]{20,}",
            r"\bxox[abprs]-[A-Za-z0-9\-]{8,}",
            r"\b[sr]k_(live|test)_[A-Za-z0-9]{8,}",
            r"\bAIza[A-Za-z0-9_\-]{20,}",
            r"\bglpat-[A-Za-z0-9_\-]{16,}",
            // credentials in URLs
            r"://[^/\s:@]+:[^/\s@]+@",
            // long opaque tokens (letters and digits mixed)
            r"[A-Za-z0-9+/_\-]{24,}={0,2}",
        ]
        .iter()
        .map(|p| Regex::new(p).expect("valid regex"))
        .collect()
    })
}

fn kv_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?i)\b(password|passwd|pwd|pass|secret|token|api[_\-]?key|apikey|auth|authorization|bearer|private[_\-]?key)\s*[=:]\s*\S+|\b(bearer|basic)\s+[A-Za-z0-9+/_.\-]{8,}=*",
        )
        .expect("valid regex")
    })
}

fn email_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"[A-Za-z0-9._%+\-]+@((?:[A-Za-z0-9\-]+\.)+[A-Za-z]{2,})").expect("valid regex")
    })
}

fn digits_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\+?\d[\d \-().]{6,}\d").expect("valid regex"))
}

/// Masks secrets, tokens, credentials, e-mail addresses and digit runs of 9+ digits (personal
/// IDs, card and phone numbers) in free text. Dates, ports and IPv4 addresses are kept.
pub fn mask_sensitive(s: &str) -> String {
    let mut out = kv_re()
        .replace_all(s, |c: &regex::Captures<'_>| {
            let k = c.get(1).or_else(|| c.get(2)).map_or("", |m| m.as_str());
            format!("{k}=***")
        })
        .into_owned();
    for re in patterns() {
        out = re
            .replace_all(&out, |c: &regex::Captures<'_>| {
                let m = &c[0];
                if m.starts_with("://") {
                    return "://***@".to_string();
                }
                let long_token = m.len() >= 24
                    && !m.contains('.')
                    && m.chars()
                        .all(|ch| ch.is_ascii_alphanumeric() || "+/_-=".contains(ch));
                // keep long words that are clearly not tokens (no digits or no letters)
                if long_token
                    && !(m.chars().any(|c| c.is_ascii_digit())
                        && m.chars().any(|c| c.is_ascii_alphabetic()))
                {
                    return m.to_string();
                }
                "***".to_string()
            })
            .into_owned();
    }
    out = email_re().replace_all(&out, "***@$1").into_owned();
    digits_re()
        .replace_all(&out, |c: &regex::Captures<'_>| {
            let m = &c[0];
            let digits = m.chars().filter(char::is_ascii_digit).count();
            let ipv4 = m.split('.').count() == 4
                && m.split('.')
                    .all(|p| p.parse::<u8>().is_ok() && !p.is_empty());
            if digits >= 9 && !ipv4 {
                "***".to_string()
            } else {
                m.to_string()
            }
        })
        .into_owned()
}

fn clip(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let mut t: String = s.chars().take(max.saturating_sub(1)).collect();
    t.push('…');
    t
}

/// Returns the display value of an allow-listed parameter (masked and clipped), or `None` for a
/// parameter that must not appear in messages.
pub fn sanitize_param(key: &str, value: &Value) -> Option<String> {
    if !ALLOWED_PARAMS.contains(&key) {
        return None;
    }
    let one = |v: &Value| -> String {
        match v {
            Value::Null => String::new(),
            Value::Bool(b) => b.to_string(),
            Value::Number(n) => n.to_string(),
            Value::String(s) => clip(&mask_sensitive(s), MAX_PARAM_CHARS),
            _ => String::new(),
        }
    };
    Some(match value {
        Value::Array(a) => {
            let mut parts: Vec<String> = a.iter().take(5).map(one).collect();
            if a.len() > 5 {
                parts.push(format!("+{}", a.len() - 5));
            }
            parts.join(", ")
        }
        v => one(v),
    })
}

// ---------------------------------------------------------------------------------------------
// Templates

fn locale_map(lang: Lang) -> &'static BTreeMap<String, String> {
    static EN: OnceLock<BTreeMap<String, String>> = OnceLock::new();
    static RU: OnceLock<BTreeMap<String, String>> = OnceLock::new();
    static UK: OnceLock<BTreeMap<String, String>> = OnceLock::new();
    match lang {
        Lang::En => EN.get_or_init(|| {
            serde_json::from_str(include_str!("../../../locales/en/notify.json"))
                .expect("valid locales/en/notify.json")
        }),
        Lang::Ru => RU.get_or_init(|| {
            serde_json::from_str(include_str!("../../../locales/ru/notify.json"))
                .expect("valid locales/ru/notify.json")
        }),
        Lang::Uk => UK.get_or_init(|| {
            serde_json::from_str(include_str!("../../../locales/uk/notify.json"))
                .expect("valid locales/uk/notify.json")
        }),
    }
}

fn fallback(key: &str, lang: Lang) -> Option<&'static str> {
    locale_map(lang).get(key).map(String::as_str)
}

fn fill(tpl: &str, vars: &BTreeMap<String, String>) -> String {
    let mut out = String::with_capacity(tpl.len() + 32);
    let mut rest = tpl;
    while let Some(i) = rest.find('{') {
        out.push_str(&rest[..i]);
        match rest[i..].find('}') {
            Some(j) => {
                let name = &rest[i + 1..i + j];
                out.push_str(vars.get(name).map(String::as_str).unwrap_or(""));
                rest = &rest[i + j + 1..];
            }
            None => {
                out.push_str(&rest[i..]);
                rest = "";
            }
        }
    }
    out.push_str(rest);
    // tidy empty placeholders: "()" and double spaces
    let out = out.replace(" ()", "").replace("()", "");
    let mut tidy = String::with_capacity(out.len());
    for w in out.split(' ').filter(|w| !w.is_empty()) {
        if !tidy.is_empty() {
            tidy.push(' ');
        }
        tidy.push_str(w);
    }
    tidy
}

fn template(key: &str, lang: Lang, tr: Option<Translate<'_>>) -> Option<String> {
    tr.and_then(|t| t(key, lang))
        .or_else(|| fallback(key, lang).map(str::to_string))
}

/// Renders one alert as a plain-text line (sanitized parameters only).
pub fn render_alert(a: &NotifyAlert, lang: Lang, tr: Option<Translate<'_>>) -> String {
    let vars: BTreeMap<String, String> = a
        .params
        .iter()
        .filter_map(|(k, v)| sanitize_param(k, v).map(|s| (k.clone(), s)))
        .collect();
    let mut key = if a.title_key.is_empty() {
        format!("alert.{}", a.rule)
    } else {
        a.title_key.clone()
    };
    if a.params.get("expired") == Some(&Value::Bool(true)) {
        key.push_str(".expired");
    }
    let tpl = template(&key, lang, tr)
        .or_else(|| template(key.trim_end_matches(".expired"), lang, tr))
        .unwrap_or_else(|| {
            // unknown rule: its id plus the safe parameters
            let mut s = clip(&mask_sensitive(&a.rule), 40);
            for k in vars.keys() {
                s.push_str(&format!(" {{{k}}}"));
            }
            s
        });
    fill(&tpl, &vars)
}

fn sev_mark(s: Severity) -> &'static str {
    match s {
        Severity::Critical => "🔴",
        Severity::High => "🟠",
        Severity::Medium => "🟡",
        Severity::Low => "🔵",
        Severity::Info => "⚪",
    }
}

fn header(n: &Notice, lang: Lang, tr: Option<Translate<'_>>) -> String {
    let vars = BTreeMap::from([
        ("project".to_string(), clip(&mask_sensitive(&n.project), 60)),
        (
            "count".to_string(),
            (n.alerts.len() + n.dropped).to_string(),
        ),
    ]);
    fill(
        &template("notify.header", lang, tr).unwrap_or_else(|| "FOCA-rs · {project}".into()),
        &vars,
    )
}

/// Builds the message text within `limit` characters: header, one line per alert (most severe
/// first, as given), then "… and N more". `esc` escapes text for the target markup. Returns the
/// text and the number of alerts included.
fn compose(
    n: &Notice,
    lang: Lang,
    tr: Option<Translate<'_>>,
    limit: usize,
    esc: &dyn Fn(&str) -> String,
    bold: &dyn Fn(&str) -> String,
) -> (String, usize) {
    let more = |k: usize| {
        let vars = BTreeMap::from([("count".to_string(), k.to_string())]);
        esc(&fill(
            &template("notify.more", lang, tr).unwrap_or_else(|| "… +{count}".into()),
            &vars,
        ))
    };
    let mut text = bold(&esc(&header(n, lang, tr)));
    let total = n.alerts.len() + n.dropped;
    let mut used = 0;
    for a in &n.alerts {
        let line = format!(
            "\n{} {}",
            sev_mark(a.severity),
            esc(&render_alert(a, lang, tr))
        );
        let rest = total - used - 1;
        let tail = if rest > 0 {
            more(rest).chars().count() + 1
        } else {
            0
        };
        if text.chars().count() + line.chars().count() + tail > limit {
            break;
        }
        text.push_str(&line);
        used += 1;
    }
    if used < total {
        text.push('\n');
        text.push_str(&more(total - used));
    }
    if text.chars().count() > limit {
        text = clip(&text, limit);
    }
    (text, used)
}

/// Escapes text for Telegram `parse_mode=HTML`.
pub fn escape_html(s: &str) -> String {
    let mut o = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => o.push_str("&amp;"),
            '<' => o.push_str("&lt;"),
            '>' => o.push_str("&gt;"),
            '"' => o.push_str("&quot;"),
            c => o.push(c),
        }
    }
    o
}

/// Escapes text for Slack/Mattermost mrkdwn (`&`, `<`, `>`).
pub fn escape_slack(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

/// Telegram message text (HTML, ≤ 4096 characters) and the number of alerts included.
pub fn telegram_text(n: &Notice, lang: Lang, tr: Option<Translate<'_>>) -> (String, usize) {
    compose(n, lang, tr, TELEGRAM_LIMIT, &escape_html, &|s| {
        format!("<b>{s}</b>")
    })
}

/// Webhook JSON body for `kind` and the number of alerts included.
pub fn webhook_body(
    kind: WebhookKind,
    n: &Notice,
    lang: Lang,
    tr: Option<Translate<'_>>,
) -> (Value, usize) {
    match kind {
        WebhookKind::Slack | WebhookKind::Mattermost => {
            let (t, k) = compose(n, lang, tr, WEBHOOK_LIMIT, &escape_slack, &|s| {
                format!("*{s}*")
            });
            (json!({ "text": t }), k)
        }
        WebhookKind::Discord => {
            // Discord markdown: neutralize mentions and markup characters
            let esc = |s: &str| {
                s.replace('@', "@\u{200b}")
                    .replace(['*', '_', '`', '~'], "")
            };
            let (t, k) = compose(n, lang, tr, DISCORD_LIMIT, &esc, &|s| format!("**{s}**"));
            (
                json!({ "content": t, "allowed_mentions": { "parse": [] } }),
                k,
            )
        }
        WebhookKind::Generic => {
            let (t, k) = compose(n, lang, tr, WEBHOOK_LIMIT, &|s| s.to_string(), &|s| {
                s.to_string()
            });
            let alerts: Vec<Value> = n
                .alerts
                .iter()
                .take(k)
                .map(|a| {
                    json!({
                        "rule": clip(&mask_sensitive(&a.rule), 40),
                        "severity": a.severity,
                        "text": render_alert(a, lang, tr),
                    })
                })
                .collect();
            (
                json!({
                    "text": t,
                    "project": clip(&mask_sensitive(&n.project), 60),
                    "scan_time": clip(&mask_sensitive(&n.scan_time), 40),
                    "count": n.alerts.len() + n.dropped,
                    "alerts": alerts,
                }),
                k,
            )
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Delivery

fn retry_after(resp_header: Option<&str>, body: &Value) -> Option<u64> {
    resp_header
        .and_then(|v| v.trim().parse::<u64>().ok())
        .or_else(|| body["parameters"]["retry_after"].as_u64())
}

/// Sends `notice` to `channel`. Nothing is sent for an empty notice (`Ok` with `sent = 0`,
/// `attempts = 0`).
pub async fn send(
    net: &NetClient,
    channel: &Channel,
    notice: &Notice,
    opts: &NotifyOptions,
    tr: Option<Translate<'_>>,
) -> Result<Delivery, NotifyError> {
    if notice.alerts.is_empty() && notice.dropped == 0 {
        return Ok(Delivery {
            status: 0,
            attempts: 0,
            sent: 0,
        });
    }
    let (url, body, sent, telegram) = match channel {
        Channel::Telegram { token, chat_id } => {
            let tok = token.expose();
            if tok.is_empty()
                || !tok
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || ":_-".contains(c))
            {
                return Err(NotifyError::Config("неверный токен бота"));
            }
            if chat_id.trim().is_empty() {
                return Err(NotifyError::Config("не указан chat_id"));
            }
            let (text, k) = telegram_text(notice, opts.lang, tr);
            let url = format!(
                "{}/bot{tok}/sendMessage",
                opts.telegram_api.trim_end_matches('/')
            );
            let body = json!({
                "chat_id": chat_id.trim(),
                "text": text,
                "parse_mode": "HTML",
                "disable_web_page_preview": true,
            });
            (url, body, k, true)
        }
        Channel::Webhook { url, kind } => {
            let u = url.expose();
            let ok_scheme =
                u.starts_with("https://") || (opts.allow_http && u.starts_with("http://"));
            if !ok_scheme {
                return Err(NotifyError::Config(
                    "адрес вебхука должен начинаться с https://",
                ));
            }
            let (body, k) = webhook_body(*kind, notice, opts.lang, tr);
            (u.to_string(), body, k, false)
        }
    };
    let bytes = serde_json::to_vec(&body).map_err(|_| NotifyError::Config("тело сообщения"))?;
    let attempts = opts.attempts.max(1);
    let mut wait = opts.backoff;
    for attempt in 1..=attempts {
        let last = attempt == attempts;
        // NetRequest::new would echo the URL (with the token) in its error: hide it
        let req = NetRequest::new(Method::POST, &url, MODULE, Access::Passive)
            .map_err(|_| NotifyError::Config("неверный адрес"))?
            .header("content-type", "application/json")
            .body(bytes.clone())
            .timeout(opts.timeout)
            .retries(0)
            .no_redirects();
        match net.send(req).await {
            Ok(resp) => {
                let st = resp.status();
                let ra_header = resp.header("retry-after").map(str::to_string);
                let text = resp.text_limited(64 * 1024).await.unwrap_or_default();
                let js: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
                if (200..300).contains(&st) {
                    if telegram && js["ok"] == Value::Bool(false) {
                        return Err(NotifyError::Rejected {
                            status: st,
                            reason: clip(
                                &mask_sensitive(js["description"].as_str().unwrap_or("")),
                                200,
                            ),
                        });
                    }
                    return Ok(Delivery {
                        status: st,
                        attempts: attempt,
                        sent,
                    });
                }
                if st == 429 {
                    let ra = retry_after(ra_header.as_deref(), &js);
                    let d = ra.map(Duration::from_secs).unwrap_or(wait);
                    if last || d > opts.max_retry_after {
                        return Err(NotifyError::RateLimited {
                            retry_after: ra.unwrap_or(d.as_secs()),
                        });
                    }
                    net.cancellable(tokio::time::sleep(d)).await?;
                    wait = wait.saturating_mul(2);
                    continue;
                }
                if (st >= 500 || st == 408) && !last {
                    net.cancellable(tokio::time::sleep(wait)).await?;
                    wait = wait.saturating_mul(2);
                    continue;
                }
                let reason = js["description"]
                    .as_str()
                    .or_else(|| js["message"].as_str())
                    .unwrap_or("");
                return Err(NotifyError::Rejected {
                    status: st,
                    reason: clip(&mask_sensitive(reason), 200),
                });
            }
            Err(e) if e.is_transient() && !last => {
                net.cancellable(tokio::time::sleep(wait)).await?;
                wait = wait.saturating_mul(2);
            }
            Err(e) => return Err(NotifyError::Net(e)),
        }
    }
    Err(NotifyError::Config("attempts"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testserver::{TestResponse, TestServer};
    use crate::{MemorySink, NetConfig};
    use foca_core::Scope;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    const BOT_TOKEN: &str = "123456789:AAFakeBotTokenValue_For-Tests_0123456789";
    const LEAKS: &[&str] = &[
        "AKIAIOSFODNN7EXAMPLE",
        "hunter2pass",
        "ivan.petrenko@example.com",
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.c2lnbmF0dXJl",
        "3012345678",
        "4111 1111 1111 1111",
        "ghp_abcdefghijklmnopqrstuvwxyz0123",
        "xoxb-1234567890-abcdefghij",
        "zQ8vR2mX7kL1pN4tY6wB9cD3fH5jS0aE",
        "987654321:AAAnotherBotTokenValueForTests_xyz",
        "SECRET-HIDDEN-PARAM",
    ];

    fn leaky_notice() -> Notice {
        let p = |v: Value| v;
        Notice {
            project: "Example <Corp> & Co".into(),
            scan_time: "2026-11-01T12:00:00Z".into(),
            alerts: vec![
                NotifyAlert {
                    rule: "doc_secret".into(),
                    severity: Severity::Critical,
                    title_key: "alert.doc_secret".into(),
                    params: BTreeMap::from([
                        (
                            "doc".to_string(),
                            p(json!("keys AKIAIOSFODNN7EXAMPLE password=hunter2pass <b>.xlsx")),
                        ),
                        ("host".to_string(), p(json!("www.example.com"))),
                        ("count".to_string(), p(json!(3))),
                        // not allow-listed: must never be rendered
                        ("value".to_string(), p(json!("SECRET-HIDDEN-PARAM"))),
                        ("secret".to_string(), p(json!("SECRET-HIDDEN-PARAM"))),
                    ]),
                },
                NotifyAlert {
                    rule: "doc_pii".into(),
                    severity: Severity::High,
                    title_key: "alert.doc_pii".into(),
                    params: BTreeMap::from([
                        (
                            "doc".to_string(),
                            p(json!("ivan.petrenko@example.com 3012345678 4111 1111 1111 1111")),
                        ),
                        (
                            "host".to_string(),
                            p(json!(
                                "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.c2lnbmF0dXJl"
                            )),
                        ),
                        ("count".to_string(), p(json!(2))),
                    ]),
                },
                NotifyAlert {
                    rule: "ct_new_cert".into(),
                    severity: Severity::Low,
                    title_key: "alert.ct_new_cert".into(),
                    params: BTreeMap::from([
                        (
                            "names".to_string(),
                            p(json!([
                                "ghp_abcdefghijklmnopqrstuvwxyz0123",
                                "dev.example.com",
                                "xoxb-1234567890-abcdefghij"
                            ])),
                        ),
                        (
                            "issuer".to_string(),
                            p(json!(
                                "zQ8vR2mX7kL1pN4tY6wB9cD3fH5jS0aE 987654321:AAAnotherBotTokenValueForTests_xyz"
                            )),
                        ),
                    ]),
                },
                NotifyAlert {
                    rule: "tls_expiry".into(),
                    severity: Severity::High,
                    title_key: "alert.tls_expiry".into(),
                    params: BTreeMap::from([
                        ("host".to_string(), p(json!("www.example.com"))),
                        ("days".to_string(), p(json!(8))),
                        ("date".to_string(), p(json!("2026-11-10"))),
                        ("expired".to_string(), p(json!(false))),
                    ]),
                },
            ],
            dropped: 0,
        }
    }

    fn client(sink: Arc<MemorySink>) -> NetClient {
        let cfg = NetConfig {
            retries: 0,
            global_rps: None,
            ..Default::default()
        };
        NetClient::new(cfg, Scope::default(), sink).unwrap()
    }

    fn opts(api: &str) -> NotifyOptions {
        NotifyOptions {
            telegram_api: api.into(),
            lang: Lang::En,
            backoff: Duration::from_millis(10),
            timeout: Duration::from_secs(5),
            allow_http: true,
            ..Default::default()
        }
    }

    fn assert_clean(what: &str, s: &str) {
        for l in LEAKS.iter().chain([&BOT_TOKEN]) {
            assert!(!s.contains(l), "{what} leaks {l}: {s}");
        }
        assert!(!s.contains("AAFakeBotToken"), "{what} leaks token: {s}");
    }

    #[test]
    fn sanitizer_masks_values_and_keeps_safe_text() {
        // SECRET-HIDDEN-PARAM sits in non-allow-listed params: dropped, not masked
        for l in LEAKS.iter().filter(|l| **l != "SECRET-HIDDEN-PARAM") {
            // a bare password is indistinguishable from a word; it leaks only with a label
            let l = if *l == "hunter2pass" {
                "password: hunter2pass".to_string()
            } else {
                l.to_string()
            };
            assert_clean("mask", &mask_sensitive(&format!("x {l} y")));
        }
        assert_eq!(mask_sensitive("auth.example.com"), "auth.example.com");
        assert_eq!(
            mask_sensitive("Authorization: Bearer abc.def-123456"),
            "Authorization=*** abc.def-123456"
        );
        assert_eq!(mask_sensitive("www.example.com"), "www.example.com");
        assert_eq!(mask_sensitive("2026-11-10"), "2026-11-10");
        assert_eq!(mask_sensitive("192.0.2.10:3389"), "192.0.2.10:3389");
        assert_eq!(
            mask_sensitive("Annual report 2025.pdf"),
            "Annual report 2025.pdf"
        );
        assert_eq!(
            mask_sensitive("mail ivan@example.com"),
            "mail ***@example.com"
        );
        assert!(sanitize_param("value", &json!("x")).is_none());
        assert_eq!(sanitize_param("port", &json!(443)).unwrap(), "443");
        let long = "a".repeat(500);
        assert!(sanitize_param("doc", &json!(long)).unwrap().chars().count() <= MAX_PARAM_CHARS);
        assert_eq!(
            sanitize_param("names", &json!(["a", "b", "c", "d", "e", "f", "g"])).unwrap(),
            "a, b, c, d, e, +2"
        );
    }

    #[test]
    fn templates_in_three_languages_and_i18n_override() {
        let n = leaky_notice();
        let tls = &n.alerts[3];
        assert_eq!(
            render_alert(tls, Lang::En, None),
            "TLS certificate of www.example.com expires in 8 days (2026-11-10)"
        );
        assert!(render_alert(tls, Lang::Ru, None).starts_with("TLS-сертификат"));
        assert!(render_alert(tls, Lang::Uk, None).contains("спливає"));
        let tr = |k: &str, _l: Lang| (k == "alert.tls_expiry").then(|| "{host}!".to_string());
        assert_eq!(render_alert(tls, Lang::En, Some(&tr)), "www.example.com!");
        let mut exp = tls.clone();
        exp.params.insert("expired".into(), json!(true));
        assert!(render_alert(&exp, Lang::En, None).contains("has expired"));
        assert_eq!(Lang::from_code("uk-UA"), Lang::Uk);
        assert_eq!(Lang::from_code("de"), Lang::En);
    }

    #[test]
    fn length_limits() {
        let one = leaky_notice().alerts[3].clone();
        let n = Notice {
            project: "p".into(),
            alerts: vec![one; 400],
            dropped: 7,
            ..Default::default()
        };
        let (t, k) = telegram_text(&n, Lang::En, None);
        assert!(t.chars().count() <= TELEGRAM_LIMIT);
        assert!(k < 400 && k > 10);
        assert!(t.ends_with(&format!("… and {} more", 407 - k)), "{t}");
        let (d, _) = webhook_body(WebhookKind::Discord, &n, Lang::En, None);
        assert!(d["content"].as_str().unwrap().chars().count() <= DISCORD_LIMIT);
    }

    #[tokio::test]
    async fn telegram_send_never_leaks_secrets_body_or_log() {
        let srv = TestServer::start(|_| TestResponse::ok(r#"{"ok":true,"result":{}}"#)).await;
        let sink = Arc::new(MemorySink::new());
        let net = client(sink.clone());
        let ch = Channel::Telegram {
            token: Secret::new(BOT_TOKEN),
            chat_id: "-100123".into(),
        };
        let d = send(&net, &ch, &leaky_notice(), &opts(&srv.url()), None)
            .await
            .unwrap();
        assert_eq!((d.status, d.attempts, d.sent), (200, 1, 4));
        let reqs = srv.requests();
        assert_eq!(reqs.len(), 1);
        assert_eq!(reqs[0].path(), format!("/bot{BOT_TOKEN}/sendMessage"));
        let body = String::from_utf8(reqs[0].body.clone()).unwrap();
        assert_clean("body", &body);
        let js: Value = serde_json::from_str(&body).unwrap();
        assert_eq!(js["parse_mode"], "HTML");
        assert_eq!(js["chat_id"], "-100123");
        let text = js["text"].as_str().unwrap();
        assert!(text.starts_with("<b>FOCA-rs · Example &lt;Corp&gt; &amp; Co: 4 alert(s)</b>"));
        assert!(text.contains("&lt;b&gt;.xlsx"), "{text}");
        assert!(text.contains("dev.example.com"));
        assert!(text.contains("***@example.com"));
        let log = serde_json::to_string(&sink.records()).unwrap();
        assert_clean("request log", &log);
        assert!(log.contains("/bot***/sendMessage"), "{log}");
        assert!(sink
            .records()
            .iter()
            .all(|r| r.module == MODULE && !r.active));
        assert_clean("debug", &format!("{ch:?}"));
    }

    #[tokio::test]
    async fn network_error_does_not_echo_token() {
        // a closed port: connection refused
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        drop(l);
        let sink = Arc::new(MemorySink::new());
        let net = client(sink.clone());
        let ch = Channel::Telegram {
            token: Secret::new(BOT_TOKEN),
            chat_id: "1".into(),
        };
        let mut o = opts(&format!("http://{addr}"));
        o.attempts = 2;
        let e = send(&net, &ch, &leaky_notice(), &o, None)
            .await
            .unwrap_err();
        assert_eq!(e.code(), "network");
        assert_clean("error", &e.to_string());
        assert_clean("error", &format!("{e:?}"));
        let recs = sink.records();
        assert_eq!(recs.len(), 2, "one retry");
        assert_clean("request log", &serde_json::to_string(&recs).unwrap());
    }

    #[tokio::test]
    async fn retries_429_retry_after_and_5xx() {
        let n = Arc::new(AtomicUsize::new(0));
        let c = n.clone();
        let srv = TestServer::start(move |_| match c.fetch_add(1, Ordering::SeqCst) {
            0 => TestResponse {
                status: 429,
                body: br#"{"ok":false,"error_code":429,"parameters":{"retry_after":0}}"#.to_vec(),
                ..Default::default()
            },
            1 => TestResponse::status(502),
            _ => TestResponse::ok(r#"{"ok":true}"#),
        })
        .await;
        let net = client(Arc::new(MemorySink::new()));
        let ch = Channel::Telegram {
            token: Secret::new(BOT_TOKEN),
            chat_id: "1".into(),
        };
        let d = send(&net, &ch, &leaky_notice(), &opts(&srv.url()), None)
            .await
            .unwrap();
        assert_eq!(d.attempts, 3);

        // retry_after beyond the cap: give up at once
        let srv =
            TestServer::start(|_| TestResponse::status(429).header("Retry-After", "3600")).await;
        let e = send(&net, &ch, &leaky_notice(), &opts(&srv.url()), None)
            .await
            .unwrap_err();
        assert!(matches!(e, NotifyError::RateLimited { retry_after: 3600 }));
        assert_eq!(srv.requests().len(), 1);

        // a client error is final; the description is masked
        let srv = TestServer::start(|_| TestResponse {
            status: 400,
            body: format!(
                r#"{{"ok":false,"description":"Bad Request: chat not found {BOT_TOKEN}"}}"#
            )
            .into_bytes(),
            ..Default::default()
        })
        .await;
        let e = send(&net, &ch, &leaky_notice(), &opts(&srv.url()), None)
            .await
            .unwrap_err();
        assert_eq!(e.code(), "rejected");
        assert!(e.to_string().contains("chat not found"));
        assert_clean("error", &e.to_string());
        assert_eq!(srv.requests().len(), 1);
    }

    #[tokio::test]
    async fn webhooks_slack_discord_generic() {
        let srv = TestServer::start(|_| TestResponse::ok("ok")).await;
        let sink = Arc::new(MemorySink::new());
        // real Slack host name (path masking is host-specific), routed to the test server
        let cfg = NetConfig {
            retries: 0,
            global_rps: None,
            host_overrides: std::collections::HashMap::from([(
                "hooks.slack.com".to_string(),
                vec![srv.addr.ip()],
            )]),
            ..Default::default()
        };
        let net = NetClient::new(cfg, Scope::default(), sink.clone()).unwrap();
        let slack = format!("http://hooks.slack.com:{}", srv.addr.port());
        for (kind, field, path) in [
            (
                WebhookKind::Slack,
                "text",
                "/services/T000/B000/XXXXSECRETXXXX",
            ),
            (
                WebhookKind::Mattermost,
                "text",
                "/hooks/SECRETmattermostKEY",
            ),
            (
                WebhookKind::Discord,
                "content",
                "/api/webhooks/42/SECRETdiscordTOKEN",
            ),
            (
                WebhookKind::Generic,
                "text",
                "/hooks/generic?token=SECRETgeneric",
            ),
        ] {
            let base = if kind == WebhookKind::Slack {
                slack.clone()
            } else {
                srv.url()
            };
            let ch = Channel::Webhook {
                url: Secret::new(format!("{base}{path}")),
                kind,
            };
            let d = send(&net, &ch, &leaky_notice(), &opts(""), None)
                .await
                .unwrap();
            assert_eq!(d.sent, 4);
            let r = srv.requests().pop().unwrap();
            let body = String::from_utf8(r.body).unwrap();
            assert_clean("webhook body", &body);
            let js: Value = serde_json::from_str(&body).unwrap();
            assert!(js[field].as_str().unwrap().contains("www.example.com"));
            if kind == WebhookKind::Generic {
                assert_eq!(js["alerts"].as_array().unwrap().len(), 4);
                assert!(js["alerts"][0].get("params").is_none());
            }
        }
        let log = serde_json::to_string(&sink.records()).unwrap();
        assert_clean("request log", &log);
        assert!(!log.contains("SECRET"), "{log}");
        // https is required unless explicitly relaxed
        let ch = Channel::Webhook {
            url: Secret::new("http://hooks.example.com/x"),
            kind: WebhookKind::Slack,
        };
        let e = send(&net, &ch, &leaky_notice(), &NotifyOptions::default(), None)
            .await
            .unwrap_err();
        assert_eq!(e.code(), "config");
        // nothing to send: no request at all
        let before = sink.len();
        let d = send(&net, &ch, &Notice::default(), &opts(""), None)
            .await
            .unwrap();
        assert_eq!((d.attempts, sink.len()), (0, before));
    }

    #[test]
    fn notify_locales_are_in_sync() {
        let en: Vec<_> = locale_map(Lang::En).keys().collect();
        let ru: Vec<_> = locale_map(Lang::Ru).keys().collect();
        let uk: Vec<_> = locale_map(Lang::Uk).keys().collect();
        assert_eq!(en, ru);
        assert_eq!(en, uk);
        assert!(en.len() >= 12);
    }
}
