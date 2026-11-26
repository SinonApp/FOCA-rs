//! JavaScript analysis: endpoints (`/api/…` paths, absolute URLs, `fetch`/`axios`/
//! `XMLHttpRequest`/`$.ajax`, GraphQL, source maps) and pattern-based secrets with an entropy
//! filter. Similar in spirit to jsluice/LinkFinder, implemented with regexes rather than an
//! AST.
//!
//! Secrets are never returned in clear text: only a mask (first 4 and last 2 characters) and
//! a fingerprint (first 16 hex digits of sha256) for deduplication.

use std::collections::BTreeSet;
use std::sync::OnceLock;

use foca_core::Severity;
use regex::Regex;
use serde::{Deserialize, Serialize};
use url::Url;

use crate::hash::{sha256_hex, shannon_entropy};

/// Maximum number of JS body bytes to analyze (minified bundles can be huge).
pub const MAX_JS_BYTES: usize = 8 << 20;
/// Maximum number of endpoints per file.
pub const MAX_ENDPOINTS: usize = 2000;

/// A discovered endpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Endpoint {
    /// As written in the code.
    pub raw: String,
    /// Absolute URL (relative to `base`) if it could be resolved.
    pub resolved: Option<String>,
    /// `api`, `graphql`, `path`, `url`, `sourcemap`, `websocket`.
    pub kind: String,
    /// HTTP method if visible from the call (`fetch(…,{method:'POST'})` is not parsed).
    pub method: Option<String>,
    /// `literal`, `fetch`, `axios`, `xhr`, `jquery`, `sourcemap`.
    pub source: String,
    pub line: usize,
}

/// A discovered secret (masked only).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SecretHit {
    /// `aws_access_key`, `google_api_key`, `slack_token`, `github_token`, `stripe_secret`, `jwt`,
    /// `private_key`, `telegram_bot_token`, `yandex_cloud_api_key`, `sendgrid_key`,
    /// `slack_webhook`, `mailgun_key`, `aws_secret_key`, `generic_secret`.
    pub kind: String,
    pub title: String,
    /// Mask: first 4 characters + `…` + last 2.
    pub masked: String,
    /// `sha256(value)[..16]`, used for deduplication without storing the secret.
    pub fingerprint: String,
    pub line: usize,
    /// Line fragment with the value replaced by its mask.
    pub context: String,
    pub entropy: f64,
    pub sev: Severity,
    /// Host of the absolute URL whose query string carries the value (`…/w.js?apiKey=…`): a key
    /// handed to another site's script.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub query_host: Option<String>,
    /// What the claims of a JWT say (payload decoded, signature not checked): `secret` (server
    /// roles or scopes, credentials), `client` (public client: anon role, allowed domains) or
    /// empty (not a JWT, undecodable or neutral claims).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub key_scope: String,
}

/// Analysis result for one JS file (or inline script).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct JsAnalysis {
    pub source_url: String,
    pub endpoints: Vec<Endpoint>,
    pub secrets: Vec<SecretHit>,
    /// GraphQL operation names (`query GetUser`, `mutation Login`).
    pub graphql_operations: Vec<String>,
    /// The input was truncated to [`MAX_JS_BYTES`].
    pub truncated: bool,
}

/// Masks a secret as first 4 + `…` + last 2 characters (`***` for short values).
pub fn mask_secret(s: &str) -> String {
    let c: Vec<char> = s.chars().collect();
    if c.len() < 10 {
        return "***".into();
    }
    format!(
        "{}…{}",
        c[..4].iter().collect::<String>(),
        c[c.len() - 2..].iter().collect::<String>()
    )
}

struct Lines(Vec<usize>);
impl Lines {
    fn new(s: &str) -> Self {
        Lines(
            std::iter::once(0)
                .chain(s.match_indices('\n').map(|(i, _)| i + 1))
                .collect(),
        )
    }
    fn at(&self, off: usize) -> usize {
        self.0.partition_point(|&s| s <= off)
    }
}

fn floor_char(s: &str, mut i: usize) -> usize {
    i = i.min(s.len());
    while !s.is_char_boundary(i) {
        i -= 1;
    }
    i
}

struct SecretPat {
    kind: &'static str,
    title: &'static str,
    re: Regex,
    /// Capture group holding the value (0 = whole match).
    group: usize,
    min_entropy: f64,
    sev: Severity,
}

fn secret_pats() -> &'static [SecretPat] {
    static P: OnceLock<Vec<SecretPat>> = OnceLock::new();
    P.get_or_init(|| {
        use Severity::*;
        let v: Vec<(&str, &str, &str, usize, f64, Severity)> = vec![
            ("aws_access_key", "Ключ доступа AWS", r"\b((?:AKIA|ASIA)[0-9A-Z]{16})\b", 1, 3.0, High),
            ("aws_secret_key", "Секретный ключ AWS", r#"(?i)aws.{0,20}?(?:secret|private).{0,20}?['"]([A-Za-z0-9/+=]{40})['"]"#, 1, 4.0, Critical),
            ("google_api_key", "Ключ Google API", r"\b(AIza[0-9A-Za-z_\-]{35})(?:[^0-9A-Za-z_\-]|$)", 1, 3.5, Medium),
            ("slack_token", "Токен Slack", r"\b(xox[baprs]-[0-9A-Za-z-]{10,72})\b", 1, 3.0, High),
            ("slack_webhook", "Вебхук Slack", r"(https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]{16,})", 1, 3.0, Medium),
            ("github_token", "Токен GitHub", r"\b((?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{60,90})\b", 1, 3.0, High),
            ("stripe_secret", "Секретный ключ Stripe", r"\b((?:sk|rk)_live_[0-9a-zA-Z]{24,99})\b", 1, 3.0, Critical),
            ("jwt", "JSON Web Token", r"\b(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})", 1, 3.0, Medium),
            ("private_key", "Приватный ключ (PEM)", r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----(?:[A-Za-z0-9+/=.\s]|\\[nr]){0,8192}(?:-----END [A-Z ]{0,40}-----)?", 0, 0.0, Critical),
            ("telegram_bot_token", "Токен Telegram-бота", r"\b(\d{8,10}:AA[0-9A-Za-z_-]{33})\b", 1, 3.0, High),
            ("yandex_cloud_api_key", "API-ключ Yandex Cloud", r"\b(AQVN[A-Za-z0-9_\-]{35,38})\b", 1, 3.0, High),
            ("sendgrid_key", "Ключ SendGrid", r"\b(SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43})\b", 1, 3.0, High),
            ("mailgun_key", "Ключ Mailgun", r"\b(key-[0-9a-f]{32})\b", 1, 3.0, High),
            ("generic_secret", "Возможный секрет (api_key/secret/token)", r#"(?i)\b(?:api[_-]?key|apikey|api[_-]?secret|secret[_-]?key|client[_-]?secret|access[_-]?token|auth[_-]?token|private[_-]?key|password|passwd)\b['"]?\s*[:=]\s*['"]([^'"\s]{12,128})['"]"#, 1, 3.5, Medium),
        ];
        v.into_iter()
            .map(|(kind, title, p, group, min_entropy, sev)| SecretPat {
                kind,
                title,
                re: Regex::new(p).expect("secret re"),
                group,
                min_entropy,
                sev,
            })
            .collect()
    })
}

fn placeholder(v: &str) -> bool {
    let l = v.to_ascii_lowercase();
    const BAD: &[&str] = &[
        "xxxx",
        "your",
        "example",
        "placeholder",
        "changeme",
        "dummy",
        "sample",
        "test",
        "${",
        "{{",
        "process.env",
        "<",
        "redacted",
        "insert",
        "****",
        "0000000",
    ];
    if BAD.iter().any(|b| l.contains(b)) {
        return true;
    }
    let first = v.chars().next().unwrap_or(' ');
    v.chars().all(|c| c == first)
}

/// Finds secrets in text (JS, HTML, a document). Values are masked immediately.
pub fn find_secrets(text: &str) -> Vec<SecretHit> {
    let lines = Lines::new(text);
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    let mut out_spans = Vec::new();
    let mut spans: Vec<(usize, usize, String)> = Vec::new();
    for p in secret_pats() {
        for c in p.re.captures_iter(text) {
            let Some(m) = c.get(p.group) else { continue };
            let v = m.as_str();
            let ent = shannon_entropy(v);
            if ent < p.min_entropy || (p.kind != "private_key" && placeholder(v)) {
                continue;
            }
            let fp = sha256_hex(v.as_bytes())[..16].to_string();
            let masked = if p.kind == "private_key" {
                "-----BEGIN …PRIVATE KEY----- (содержимое скрыто)".to_string()
            } else {
                mask_secret(v)
            };
            // Record span before dedup/generic skip so duplicate or skipped generic hits
            // overlapping another secret's context window still get masked.
            let span_idx = spans.len();
            spans.push((m.start(), m.end(), masked.clone()));
            if !seen.insert((p.kind, fp.clone())) {
                continue;
            }
            // Do not duplicate a value already found by a specific pattern with the generic one.
            if p.kind == "generic_secret" && out.iter().any(|h: &SecretHit| h.fingerprint == fp) {
                continue;
            }
            out_spans.push(span_idx);
            out.push(SecretHit {
                kind: p.kind.into(),
                title: p.title.into(),
                masked,
                fingerprint: fp,
                line: lines.at(m.start()),
                context: String::new(),
                entropy: (ent * 100.0).round() / 100.0,
                sev: p.sev,
                query_host: query_host(text, m.start()),
                key_scope: if p.kind == "jwt" {
                    jwt_scope(v).into()
                } else {
                    String::new()
                },
            });
        }
    }
    // Context is built after all matches are collected: neighbouring secrets may fall into the
    // window, so every value overlapping it is masked (the window grows to their boundaries).
    for (i, h) in out.iter_mut().enumerate() {
        let (st, en, _) = &spans[out_spans[i]];
        let mut a = floor_char(text, st.saturating_sub(40));
        let mut b = floor_char(text, en + 40);
        for (s2, e2, _) in &spans {
            if *s2 < b && *e2 > a {
                a = a.min(*s2);
                b = b.max(*e2);
            }
        }
        let mut inside: Vec<&(usize, usize, String)> = spans
            .iter()
            .filter(|(s2, e2, _)| *s2 >= a && *e2 <= b)
            .collect();
        inside.sort_by_key(|s| s.0);
        let mut ctx = String::new();
        let mut pos = a;
        for (s2, e2, mk) in inside {
            if *s2 < pos {
                pos = pos.max(*e2); // overlapping match: the value is already hidden
                continue;
            }
            ctx.push_str(&text[pos..*s2]);
            ctx.push_str(mk);
            pos = *e2;
        }
        ctx.push_str(&text[pos.min(b)..b]);
        h.context = ctx.replace(['\n', '\r'], " ");
    }
    out.sort_by_key(|h| h.line);
    out
}

struct EpRes {
    literal: Regex,
    fetch: Regex,
    axios: Regex,
    xhr: Regex,
    jquery: Regex,
    sourcemap: Regex,
    gql_op: Regex,
}

fn ep_res() -> &'static EpRes {
    static R: OnceLock<EpRes> = OnceLock::new();
    R.get_or_init(|| EpRes {
        literal: Regex::new(r#""([^"\\\n]{2,500})"|'([^'\\\n]{2,500})'|`([^`\\\n]{2,500})`"#)
            .expect("re"),
        fetch: Regex::new(r#"\bfetch\(\s*["'`]([^"'`\s]{1,500})["'`]"#).expect("re"),
        axios: Regex::new(
            r#"\baxios(?:\.(get|post|put|delete|patch|head|request))?\(\s*["'`]([^"'`\s]{1,500})["'`]"#,
        )
        .expect("re"),
        xhr: Regex::new(
            r#"\.open\(\s*["'](GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)["']\s*,\s*["'`]([^"'`\s]{1,500})["'`]"#,
        )
        .expect("re"),
        jquery: Regex::new(
            r#"\$\.(?:(get|post|getJSON)\(\s*|ajax\(\s*\{[^}]{0,200}?\burl\s*:\s*)["'`]([^"'`\s]{1,500})["'`]"#,
        )
        .expect("re"),
        sourcemap: Regex::new(r"//[#@]\s*sourceMappingURL=(\S+)").expect("re"),
        gql_op: Regex::new(r"\b(query|mutation|subscription)\s+([A-Za-z_]\w{1,80})\s*[({]")
            .expect("re"),
    })
}

const STATIC_EXT: &[&str] = &[
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico", ".css", ".woff", ".woff2", ".ttf",
    ".eot", ".otf", ".mp4", ".mp3", ".webm", ".avif",
];
const DYN_EXT: &[&str] = &[
    ".php", ".asp", ".aspx", ".jsp", ".json", ".action", ".do", ".cgi", ".pl", ".xml", ".ashx",
    ".asmx", ".svc",
];

fn version_seg() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"/v\d+(?:\.\d+)?/").expect("re"))
}

/// Classifies a string as an endpoint, or returns `None` for noise.
fn classify(s: &str) -> Option<&'static str> {
    let s = s.trim();
    if s.len() < 2 || s.chars().any(|c| c.is_whitespace() || c == '<' || c == '>') {
        return None;
    }
    let l = s.to_ascii_lowercase();
    let path_part = l.split(['?', '#']).next().unwrap_or("");
    if STATIC_EXT.iter().any(|e| path_part.ends_with(e)) {
        return None;
    }
    let apiish = |p: &str| {
        p.contains("/api/")
            || p.starts_with("/api")
            || p.contains("/rest/")
            || p.contains("/ajax/")
            || p.contains("/rpc")
            || version_seg().is_match(p)
    };
    if l.starts_with("ws://") || l.starts_with("wss://") {
        return Some("websocket");
    }
    if l.starts_with("http://") || l.starts_with("https://") {
        let u = Url::parse(s).ok()?;
        let host = u.host_str()?;
        if !host.contains('.') || host.ends_with("w3.org") || host == "schema.org" {
            return None;
        }
        return Some(if l.contains("graphql") {
            "graphql"
        } else if apiish(u.path()) {
            "api"
        } else {
            "url"
        });
    }
    if s.starts_with("//") || s.starts_with("/*") {
        return None;
    }
    let is_path = s.starts_with('/')
        || s.starts_with("./")
        || s.starts_with("../")
        || (s.contains('/') && DYN_EXT.iter().any(|e| path_part.ends_with(e)));
    if !is_path || !s.chars().any(|c| c.is_ascii_alphabetic()) {
        return None;
    }
    // MIME types and regexes are not paths.
    if !s.starts_with('/')
        && !s.starts_with('.')
        && s.matches('/').count() == 1
        && !DYN_EXT.iter().any(|e| path_part.ends_with(e))
    {
        return None;
    }
    if s.contains("\\") || s.contains('^') || s.contains('$') || s.contains("(?") {
        return None;
    }
    Some(if l.contains("graphql") {
        "graphql"
    } else if apiish(&l) {
        "api"
    } else {
        "path"
    })
}

/// Extracts endpoints from JS. `base` is the URL of the script itself (or the page), used to
/// resolve paths.
pub fn extract_endpoints(js: &str, base: Option<&str>) -> Vec<Endpoint> {
    let r = ep_res();
    let base = base.and_then(|b| Url::parse(b).ok());
    let lines = Lines::new(js);
    let mut out: Vec<Endpoint> = Vec::new();
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut push =
        |raw: &str, method: Option<&str>, source: &str, off: usize, force: Option<&'static str>| {
            if out.len() >= MAX_ENDPOINTS {
                return;
            }
            let kind = match force.or_else(|| classify(raw)) {
                Some(k) => k,
                // A fetch/axios argument is an endpoint even without a leading "/" (relative path).
                None if source != "literal" && !raw.contains(char::is_whitespace) => "path",
                None => return,
            };
            if !seen.insert(raw.to_string()) {
                // Refine the method of an already found literal.
                if let (Some(m), Some(e)) = (method, out.iter_mut().find(|e| e.raw == raw)) {
                    if e.method.is_none() {
                        e.method = Some(m.to_string());
                        e.source = source.to_string();
                    }
                }
                return;
            }
            let resolved = if raw.starts_with("http") || raw.starts_with("ws") {
                Some(raw.to_string())
            } else {
                base.as_ref()
                    .and_then(|b| b.join(raw).ok())
                    .map(|u| u.to_string())
            };
            out.push(Endpoint {
                raw: raw.to_string(),
                resolved,
                kind: kind.to_string(),
                method: method.map(|m| m.to_ascii_uppercase()),
                source: source.to_string(),
                line: lines.at(off),
            });
        };
    for c in r.fetch.captures_iter(js) {
        push(
            &c[1],
            None,
            "fetch",
            c.get(0).map_or(0, |m| m.start()),
            None,
        );
    }
    for c in r.axios.captures_iter(js) {
        let m = c.get(1).map(|m| m.as_str()).filter(|m| *m != "request");
        push(&c[2], m, "axios", c.get(0).map_or(0, |m| m.start()), None);
    }
    for c in r.xhr.captures_iter(js) {
        push(
            &c[2],
            Some(&c[1]),
            "xhr",
            c.get(0).map_or(0, |m| m.start()),
            None,
        );
    }
    for c in r.jquery.captures_iter(js) {
        let m = c
            .get(1)
            .map(|m| if m.as_str() == "post" { "POST" } else { "GET" });
        push(&c[2], m, "jquery", c.get(0).map_or(0, |m| m.start()), None);
    }
    for c in r.sourcemap.captures_iter(js) {
        if !c[1].starts_with("data:") {
            push(
                &c[1],
                None,
                "sourcemap",
                c.get(0).map_or(0, |m| m.start()),
                Some("sourcemap"),
            );
        }
    }
    for c in r.literal.captures_iter(js) {
        let m = c.get(1).or_else(|| c.get(2)).or_else(|| c.get(3));
        if let Some(m) = m {
            // Template literals are cut at the first substitution.
            let s = m.as_str().split("${").next().unwrap_or_default();
            if s.len() >= 2 && !s.ends_with('=') && !s.ends_with('?') {
                push(s, None, "literal", m.start(), None);
            }
        }
    }
    out.sort_by_key(|e| e.line);
    out
}

/// Runs the full JS analysis: endpoints, secrets, GraphQL operations.
pub fn analyze_js(source_url: &str, js: &str) -> JsAnalysis {
    let truncated = js.len() > MAX_JS_BYTES;
    let js = &js[..floor_char(js, MAX_JS_BYTES)];
    let base = (!source_url.is_empty()).then_some(source_url);
    let ops: BTreeSet<String> = ep_res()
        .gql_op
        .captures_iter(js)
        .map(|c| format!("{} {}", &c[1], &c[2]))
        .collect();
    JsAnalysis {
        source_url: source_url.to_string(),
        endpoints: extract_endpoints(js, base),
        secrets: find_secrets(js),
        graphql_operations: ops.into_iter().collect(),
        truncated,
    }
}

/// Returns the page's inline scripts (`<script>…</script>` without `src`) for
/// [`analyze_js`].
/// Host of the absolute URL around `pos` when the value at `pos` is a query parameter of it
/// (`https://widget.example/w.js?apiKey=<value>&domain=…`).
fn query_host(text: &str, pos: usize) -> Option<String> {
    let start = floor_char(text, pos.saturating_sub(2048));
    let before = &text[start..pos];
    // The URL runs up to the value without spaces or quotes.
    let tail_start = before
        .rfind(|c: char| c.is_whitespace() || matches!(c, '"' | '\'' | '`' | '(' | '<' | '>'))
        .map_or(0, |i| i + 1);
    let tail = &before[tail_start..];
    if !tail.ends_with('=') {
        return None;
    }
    let scheme = tail.find("https://").or_else(|| tail.find("http://"))?;
    let url = &tail[scheme..];
    if !url.contains('?') {
        return None;
    }
    Url::parse(url)
        .ok()?
        .host_str()
        .map(|h| h.trim_end_matches('.').to_ascii_lowercase())
}

/// Decodes base64url without padding (JWT segments).
fn b64url(s: &str) -> Option<Vec<u8>> {
    let val = |c: u8| -> Option<u32> {
        Some(match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'-' | b'+' => 62,
            b'_' | b'/' => 63,
            _ => return None,
        } as u32)
    };
    let bytes: Vec<u8> = s.bytes().filter(|b| *b != b'=').collect();
    let mut out = Vec::with_capacity(bytes.len() * 3 / 4);
    for chunk in bytes.chunks(4) {
        let mut acc = 0u32;
        for (i, b) in chunk.iter().enumerate() {
            acc |= val(*b)? << (18 - 6 * i);
        }
        let n = match chunk.len() {
            4 => 3,
            3 => 2,
            2 => 1,
            _ => return None,
        };
        out.extend_from_slice(&acc.to_be_bytes()[1..1 + n]);
    }
    Some(out)
}

/// Classifies a JWT by its payload claims (see [`SecretHit::key_scope`]).
fn jwt_scope(token: &str) -> &'static str {
    let Some(payload) = token.split('.').nth(1).and_then(b64url) else {
        return "";
    };
    let Ok(serde_json::Value::Object(claims)) = serde_json::from_slice(&payload) else {
        return "";
    };
    let text = |v: &serde_json::Value| v.to_string().to_ascii_lowercase();
    const SECRET_KEYS: &[&str] = &["secret", "password", "passwd", "private", "credential"];
    const SERVER_ROLES: &[&str] = &["service_role", "admin", "superuser", "root", "owner"];
    const WRITE_SCOPES: &[&str] = &["write", "admin", "delete", "manage", "full"];
    for (k, v) in &claims {
        let k = k.to_ascii_lowercase();
        if SECRET_KEYS.iter().any(|s| k.contains(s)) {
            return "secret";
        }
        let v = text(v);
        if matches!(k.as_str(), "role" | "roles" | "groups")
            && SERVER_ROLES.iter().any(|r| v.contains(r))
        {
            return "secret";
        }
        if matches!(k.as_str(), "scope" | "scp" | "permissions")
            && WRITE_SCOPES.iter().any(|r| v.contains(r))
        {
            return "secret";
        }
        if k == "typ" && v.contains("refresh") {
            return "secret";
        }
    }
    let public_role = claims
        .get("role")
        .map(text)
        .is_some_and(|r| ["anon", "public", "guest"].iter().any(|x| r.contains(x)));
    let bound = [
        "domain",
        "domains",
        "origin",
        "origins",
        "allowed_origins",
        "referer",
        "referrer",
    ]
    .iter()
    .any(|k| claims.contains_key(*k));
    if public_role || bound {
        "client"
    } else {
        ""
    }
}

pub fn inline_scripts(html: &str) -> Vec<String> {
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| Regex::new(r"(?is)<script\b([^>]*)>(.*?)</script>").expect("re"));
    re.captures_iter(html)
        .filter(|c| !c[1].to_ascii_lowercase().contains("src="))
        .map(|c| c[2].trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    fn b64(s: &str) -> String {
        const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        let b = s.as_bytes();
        let mut out = String::new();
        for c in b.chunks(3) {
            let n = (c[0] as u32) << 16
                | (*c.get(1).unwrap_or(&0) as u32) << 8
                | *c.get(2).unwrap_or(&0) as u32;
            for i in 0..c.len() + 1 {
                out.push(A[(n >> (18 - 6 * i) & 63) as usize] as char);
            }
        }
        out
    }

    /// A JWT with the given payload (header and signature are filler).
    pub(crate) fn jwt(payload: &str) -> String {
        format!(
            "{}.{}.{}",
            b64(r#"{"alg":"HS256","typ":"JWT"}"#),
            b64(payload),
            "c2lnbmF0dXJlLXZhbHVlLXg5"
        )
    }

    #[test]
    fn widget_key_in_script_url_query_is_marked() {
        let t = jwt(r#"{"domain":"example.test","iat":1700000000}"#);
        let js = format!(
            "var s=document.createElement('script');s.src='https://widget.vendor.example/w.js?apiKey={t}&domain=example.test';"
        );
        let h = find_secrets(&js);
        assert_eq!(h.len(), 1, "{h:?}");
        assert_eq!(h[0].kind, "jwt");
        assert_eq!(h[0].query_host.as_deref(), Some("widget.vendor.example"));
        assert_eq!(h[0].key_scope, "client");
        // Inline code with a server role: no URL, secret claims.
        let t = jwt(r#"{"role":"service_role","iss":"app"}"#);
        let h = find_secrets(&format!("const KEY = \"{t}\";"));
        assert_eq!(h[0].query_host, None);
        assert_eq!(h[0].key_scope, "secret");
        assert_eq!(jwt_scope("eyJhbGciOi.notbase64!.x"), "");
    }

    const APP: &str = include_str!("../tests/fixtures/app.js");

    #[test]
    fn endpoints_from_calls_and_literals() {
        let e = extract_endpoints(APP, Some("https://ex.com/static/js/app.js"));
        let find = |r: &str| {
            e.iter()
                .find(|x| x.raw == r)
                .unwrap_or_else(|| panic!("no {r}: {e:?}"))
        };
        let u = find("/api/v1/users");
        assert_eq!(u.kind, "api");
        assert_eq!(u.source, "fetch");
        assert_eq!(u.resolved.as_deref(), Some("https://ex.com/api/v1/users"));
        assert_eq!(find("/api/orders").method.as_deref(), Some("POST"));
        assert_eq!(find("/legacy/save.php").method.as_deref(), Some("POST"));
        assert_eq!(find("/search").source, "jquery");
        assert_eq!(find("https://api.ex.com/graphql").kind, "graphql");
        assert_eq!(find("wss://rt.ex.com/socket").kind, "websocket");
        assert_eq!(find("app.js.map").kind, "sourcemap");
        assert_eq!(find("/admin/export").kind, "path");
        assert_eq!(find("/api/items/").kind, "api");
        // noise
        for bad in [
            "text/html",
            "http://www.w3.org/2000/svg",
            "/img/logo.png",
            "a b",
            "use strict",
        ] {
            assert!(e.iter().all(|x| x.raw != bad), "{bad}");
        }
    }

    #[test]
    fn secrets_masked_and_filtered() {
        let s = find_secrets(APP);
        let kinds: Vec<&str> = s.iter().map(|h| h.kind.as_str()).collect();
        for k in [
            "aws_access_key",
            "google_api_key",
            "slack_token",
            "github_token",
            "stripe_secret",
            "jwt",
            "private_key",
            "generic_secret",
        ] {
            assert!(kinds.contains(&k), "{k}: {kinds:?}");
        }
        // Placeholders (YOUR_…, AKIA…EXAMPLE) and low-entropy values are dropped.
        assert!(find_secrets("k=\"AKIAIOSFODNN7EXAMPLE\"").is_empty());
        assert_eq!(
            kinds.iter().filter(|k| **k == "generic_secret").count(),
            1,
            "{s:?}"
        );
        let aws = s.iter().find(|h| h.kind == "aws_access_key").unwrap();
        assert_eq!(aws.masked, "AKIA…V6");
        let raw = [
            "AKIAZ7Q3LMN4PRS2TUV6",
            "ghp_",
            "sk_live_4eC39HqLyjWDarjtT1zdp7dc",
            "MIIEvQ",
        ];
        for h in &s {
            assert!(
                !raw[2..]
                    .iter()
                    .any(|r| h.context.contains(r) || h.masked.contains(r)),
                "{h:?}"
            );
            assert!(!h.context.contains("AKIAZ7Q3LMN4PRS2TUV6"));
        }
    }

    #[test]
    fn graphql_ops_and_inline() {
        let a = analyze_js("https://ex.com/app.js", APP);
        assert!(a.graphql_operations.contains(&"query GetUser".to_string()));
        assert!(a.graphql_operations.contains(&"mutation Login".to_string()));
        let i = inline_scripts("<script src=a.js></script><script>var a='/api/x'</script>");
        assert_eq!(i, vec!["var a='/api/x'".to_string()]);
    }

    #[test]
    fn mask_rules() {
        assert_eq!(mask_secret("short"), "***");
        assert_eq!(mask_secret("abcdefghijkl"), "abcd…kl");
    }

    #[test]
    fn duplicate_neighbour_secret_is_masked_and_stub_urls_skipped() {
        let js = r#"const a = "AKIAZ7Q3LMN4PRS2TUV6", b = "AKIAZ7Q3LMN4PRS2TUV6"; const u = `/gtm.js?id=${x}`;"#;
        let hits = find_secrets(js);
        assert_eq!(hits.len(), 1);
        assert!(!hits[0].context.contains("AKIAZ7Q3LMN4PRS2TUV6"));
        let eps = extract_endpoints(js, Some("https://ex.com"));
        assert!(!eps
            .iter()
            .any(|e| e.raw.ends_with('=') || e.raw.ends_with('?')));
    }
}
