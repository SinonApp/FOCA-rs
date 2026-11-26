//! Dorks `site:<domain> filetype:<ext>` through the embedded browser ([`crate::render`]):
//! Startpage (Google results, protected by the Anubis JavaScript proof of work "Verifying your
//! request"), keyless Brave Search and Mojeek. These engines reject plain HTTP from the core
//! (captcha, bot protection, 403), so the app's hidden WebView loads the page while this module
//! provides the script, result HTML parsing, pagination, 3-6 s pauses, scope filtering, dedup
//! and accurate statuses.
//!
//! Without a [`RenderFetch`](crate::render::RenderFetch) (CLI, `serve`, host tests) the source
//! fails with the [`NO_RENDER`] prefix, which maps to the `unavailable` status.

use std::collections::HashSet;
use std::time::Duration;

use foca_net::{Access, NetError};

use crate::dorkboard::{PageKind, CAPTCHA_WHY, VERIFY_WHY};
use crate::render::{RenderPage, RenderRequest, RenderStep, NO_RENDER};
use crate::source::{DocumentSource, Found, SearchCtx, SourceKind};
use crate::sources::dorkpool::{DorkBackend, DorkPage};
use crate::BoxFuture;

/// A search engine opened in the embedded browser.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RenderEngine {
    Startpage,
    BraveWeb,
    Mojeek,
    /// Yahoo (Bing results), in the browser; plain HTTP from the core gets 500 or rate limited.
    Yahoo,
}

/// Structural DOM / script / form / URL signals observed on a rendered search page.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CaptchaSignals {
    /// Known captcha / anti-bot widget script (`Turnstile`, `reCAPTCHA`, `hCaptcha`, `ALTCHA`, ...).
    pub widget_script: bool,
    /// Embedded challenge `<iframe>` (`recaptcha/api2/anchor`, `hcaptcha`, `turnstile`, ...).
    pub challenge_iframe: bool,
    /// Challenge `<form>` action or token `<input>` (`cf-turnstile-response`, `g-recaptcha-response`, ...).
    pub challenge_form: bool,
    /// Container element carrying captcha class/id/attribute (`cf-turnstile`, `g-recaptcha`, `data-sitekey`, ...).
    pub challenge_dom_attr: bool,
    /// URL path or host indicating a challenge / consent wall (`/captcha`, `consent.yahoo.com`, ...).
    pub challenge_url: bool,
    /// HTTP status code indicating throttling or block (403, 429, 503, 999).
    pub blocked_status: bool,
    /// Engine-specific search result containers are present in the page HTML.
    pub has_results: bool,
}

/// Captcha markers for an early exit from waiting (visible text plus URL, lowercase). These are
/// narrow phrases rather than a bare "captcha", which also appears on regular pages.
pub const CAPTCHA_ABORT: &[&str] = &[
    "/captcha",
    "altcha",
    "complete the captcha",
    "solve the captcha",
    "captcha challenge",
    "verify you are human",
    "i'm not a robot",
    "verifying you're not a bot",
    "quick check before you continue",
];

/// Returns the search engine page for a manual check in a visible WebView (sharing cookies with the
/// hidden one) for source `id`, if its error is a captcha or a failed challenge.
pub fn verify_url(id: &str, error: &str) -> Option<&'static str> {
    if !error.contains(CAPTCHA_WHY) && !error.contains(VERIFY_WHY) {
        return None;
    }
    match id {
        "startpage" => Some("https://www.startpage.com/"),
        "mojeek" => Some("https://www.mojeek.com/search?q=foca"),
        "brave_web" => Some("https://search.brave.com/"),
        "yahoo" => Some("https://search.yahoo.com/"),
        _ => None,
    }
}

/// Challenge page text used by Startpage (Anubis) and Brave.
const VERIFY_TEXT: &str = "Verifying your request";

/// Lowercase markers of a still unsolved challenge for the manual check dialog (visible text plus
/// URL): the early-exit captcha phrases plus the Startpage/Brave challenge text. After the user taps
/// Done, a page that still contains one of them is reported as not solved.
pub fn verify_markers() -> Vec<String> {
    CAPTCHA_ABORT
        .iter()
        .map(|s| s.to_string())
        .chain(std::iter::once(low(VERIFY_TEXT)))
        .collect()
}

fn low(s: &str) -> String {
    s.to_ascii_lowercase()
}

/// Returns the lowercase visible text without `<script>`/`<style>` (Brave scripts contain UI
/// strings such as "Switch to traditional CAPTCHA" even on a regular result page).
fn visible_low(html: &str) -> String {
    let mut out = String::with_capacity(html.len() / 2);
    let h = low(html);
    let mut rest = h.as_str();
    loop {
        let next = ["<script", "<style"]
            .iter()
            .filter_map(|t| rest.find(t).map(|i| (i, *t)))
            .min_by_key(|x| x.0);
        let Some((i, t)) = next else {
            out.push_str(rest);
            break;
        };
        out.push_str(&rest[..i]);
        let close = if t == "<script" {
            "</script>"
        } else {
            "</style>"
        };
        match rest[i..].find(close) {
            Some(j) => rest = &rest[i + j + close.len()..],
            None => break,
        }
    }
    out
}

fn has_any(s: &str, needles: &[&str]) -> bool {
    needles.iter().any(|n| s.contains(n))
}

/// Inspects HTML tags, attributes, URL, and HTTP status for structural captcha signals
/// without relying on natural-language English strings.
pub fn detect_captcha_signals(engine: RenderEngine, page: &RenderPage) -> CaptchaSignals {
    let h = low(&page.html);
    let url = low(&page.url);

    let has_results = match engine {
        RenderEngine::Startpage => has_sp_results(&h),
        RenderEngine::BraveWeb => h.contains("meta_url:") || h.contains("data-type=\"web\""),
        RenderEngine::Yahoo => h.contains("s-title") || h.contains("/ru=") || h.contains("algo-sr"),
        RenderEngine::Mojeek => h.contains("results-standard"),
    };

    const SCRIPT_SRCS: &[&str] = &[
        "challenges.cloudflare.com/turnstile",
        "google.com/recaptcha",
        "recaptcha/api.js",
        "hcaptcha.com",
        "js.hcaptcha.com",
        "funcaptcha.com",
        "arkoselabs.com",
        "geetest.com",
        "altcha",
        "ddos-guard",
        "/cdn-cgi/challenge-platform",
    ];
    let script_tag_hit =
        tags(&h, "script").any(|a| attr(&a, "src").is_some_and(|s| has_any(s, SCRIPT_SRCS)));
    let inline_runtime_hit = has_any(
        &h,
        &[
            "anubis_challenge",
            "/cdn-cgi/challenge-platform",
            "turnstile.render(",
            "grecaptcha.render(",
            "hcaptcha.execute(",
        ],
    );

    const IFRAME_MARKERS: &[&str] = &[
        "turnstile",
        "recaptcha",
        "hcaptcha",
        "arkoselabs",
        "funcaptcha",
        "captcha",
        "challenge",
    ];
    let challenge_iframe = tags(&h, "iframe").any(|a| {
        attr(&a, "src").is_some_and(|v| has_any(v, IFRAME_MARKERS))
            || attr(&a, "title").is_some_and(|v| has_any(v, IFRAME_MARKERS))
            || attr(&a, "id").is_some_and(|v| has_any(v, IFRAME_MARKERS))
    });

    const FORM_MARKERS: &[&str] = &[
        "captcha",
        "challenge",
        "verify",
        "consent",
        "validate",
        "botcheck",
    ];
    const INPUT_MARKERS: &[&str] = &[
        "cf-turnstile-response",
        "g-recaptcha-response",
        "h-captcha-response",
        "captcha",
        "altcha",
    ];
    let form_hit = tags(&h, "form").any(|a| {
        attr(&a, "action").is_some_and(|v| has_any(v, FORM_MARKERS))
            || attr(&a, "id").is_some_and(|v| has_any(v, FORM_MARKERS))
            || attr(&a, "class").is_some_and(|v| has_any(v, FORM_MARKERS))
    });
    let input_hit = tags(&h, "input").any(|a| {
        attr(&a, "name").is_some_and(|v| has_any(v, INPUT_MARKERS))
            || attr(&a, "id").is_some_and(|v| has_any(v, INPUT_MARKERS))
    });

    const DOM_MARKERS: &[&str] = &[
        "cf-turnstile",
        "g-recaptcha",
        "h-captcha",
        "captcha-box",
        "captcha_box",
        "anubis_challenge",
    ];
    let dom_hit = ["div", "span", "section", "altcha-widget"]
        .into_iter()
        .any(|tag| {
            tags(&h, tag).any(|a| {
                tag == "altcha-widget"
                    || attr(&a, "data-sitekey").is_some()
                    || attr(&a, "class").is_some_and(|v| has_any(v, DOM_MARKERS))
                    || attr(&a, "id").is_some_and(|v| has_any(v, DOM_MARKERS))
            })
        });

    let challenge_url = has_any(
        &url,
        &[
            "/captcha",
            "/challenge",
            "/sorry/",
            "consent.yahoo.com",
            "guce.yahoo.com",
            "/cdn-cgi/challenge-platform",
        ],
    );

    CaptchaSignals {
        widget_script: script_tag_hit || inline_runtime_hit,
        challenge_iframe,
        challenge_form: form_hit || input_hit,
        challenge_dom_attr: dom_hit,
        challenge_url,
        blocked_status: matches!(page.status, Some(403 | 429 | 503 | 999)),
        has_results,
    }
}

/// Classifies a search engine page: results, challenge, captcha or IP block.
pub fn classify(engine: RenderEngine, page: &RenderPage) -> PageKind {
    let h = low(&page.html);
    let vis = visible_low(&page.html);
    let url = low(&page.url);
    let sig = detect_captcha_signals(engine, page);

    match engine {
        RenderEngine::Startpage => {
            if h.contains("anubis_challenge") || h.contains(&low(VERIFY_TEXT)) {
                return PageKind::Verify;
            }
        }
        RenderEngine::Yahoo => {
            if url.contains("consent.yahoo.com") || url.contains("guce.yahoo.com") {
                // cookie consent wall (EU/UK): a human gets through it with the manual check button
                return PageKind::Captcha;
            }
        }
        RenderEngine::Mojeek => {
            if page.status == Some(403) {
                return PageKind::BlockedIp;
            }
        }
        RenderEngine::BraveWeb => {}
    }

    if sig.has_results {
        return PageKind::Results;
    }

    if engine == RenderEngine::Mojeek && h.contains("automated queries") {
        return PageKind::BlockedIp;
    }

    if sig.widget_script
        || sig.challenge_iframe
        || sig.challenge_form
        || sig.challenge_dom_attr
        || sig.challenge_url
    {
        return PageKind::Captcha;
    }

    let text_captcha = match engine {
        RenderEngine::Startpage => h.contains("captcha"),
        RenderEngine::Mojeek => h.contains("altcha") || vis.contains("captcha"),
        RenderEngine::BraveWeb | RenderEngine::Yahoo => vis.contains("captcha"),
    };
    if text_captcha {
        return PageKind::Captcha;
    }

    if engine == RenderEngine::BraveWeb && (vis.contains(&low(VERIFY_TEXT)) || page.wait_timeout) {
        return PageKind::Verify;
    }

    let blocked = match engine {
        RenderEngine::Yahoo => matches!(page.status, Some(403 | 429 | 500 | 503 | 999)),
        RenderEngine::Startpage | RenderEngine::BraveWeb | RenderEngine::Mojeek => {
            matches!(page.status, Some(403 | 429))
        }
    };
    if blocked {
        return PageKind::BlockedIp;
    }

    PageKind::Results
}

fn has_sp_results(h: &str) -> bool {
    h.contains("result-link") || h.contains("gl-title-link")
}

/// Yields the attributes of opening `<tag ...>` tags (lowercase name to value with `&amp;` decoded).
fn tags<'a>(html: &'a str, tag: &'a str) -> impl Iterator<Item = Vec<(String, String)>> + 'a {
    let open = format!("<{tag}");
    let mut pos = 0;
    std::iter::from_fn(move || loop {
        let i = html[pos..].find(&open)? + pos;
        let after = i + open.len();
        pos = after;
        let next = html[after..].chars().next()?;
        if !next.is_ascii_whitespace() {
            continue;
        }
        let end = find_tag_end(&html[after..])? + after;
        pos = end + 1;
        return Some(attrs(&html[after..end]));
    })
}

fn find_tag_end(s: &str) -> Option<usize> {
    let mut q: Option<char> = None;
    for (i, c) in s.char_indices() {
        match (q, c) {
            (Some(x), c) if c == x => q = None,
            (Some(_), _) => {}
            (None, '"' | '\'') => q = Some(c),
            (None, '>') => return Some(i),
            _ => {}
        }
    }
    None
}

fn attrs(s: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() {
        while i < b.len() && (b[i].is_ascii_whitespace() || b[i] == b'/') {
            i += 1;
        }
        let st = i;
        while i < b.len() && !b[i].is_ascii_whitespace() && b[i] != b'=' && b[i] != b'/' {
            i += 1;
        }
        if st == i {
            i += 1;
            continue;
        }
        let name = s[st..i].to_ascii_lowercase();
        let mut val = String::new();
        if i < b.len() && b[i] == b'=' {
            i += 1;
            if i < b.len() && (b[i] == b'"' || b[i] == b'\'') {
                let qc = b[i];
                i += 1;
                let vs = i;
                while i < b.len() && b[i] != qc {
                    i += 1;
                }
                val = s[vs..i.min(b.len())].to_string();
                i += 1;
            } else {
                let vs = i;
                while i < b.len() && !b[i].is_ascii_whitespace() {
                    i += 1;
                }
                val = s[vs..i].to_string();
            }
        }
        out.push((name, unescape(&val)));
    }
    out
}

fn unescape(s: &str) -> String {
    s.replace("&amp;", "&")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&#x2F;", "/")
}

fn attr<'a>(a: &'a [(String, String)], name: &str) -> Option<&'a str> {
    a.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str())
}

fn has_class(a: &[(String, String)], class: &str) -> bool {
    attr(a, "class").is_some_and(|c| c.split_ascii_whitespace().any(|x| x == class))
}

fn push_http(out: &mut Vec<String>, seen: &mut HashSet<String>, u: &str, skip_host: &str) {
    let u = u.trim();
    if !(u.starts_with("http://") || u.starts_with("https://")) {
        return;
    }
    let Ok(p) = url::Url::parse(u) else { return };
    let host = p.host_str().unwrap_or("").to_ascii_lowercase();
    if host == skip_host || host.ends_with(&format!(".{skip_host}")) {
        return;
    }
    let s = p.to_string();
    if seen.insert(s.clone()) {
        out.push(s);
    }
}

/// Returns Startpage result links (`a.result-link` / `data-testid="gl-title-link"`) in order.
pub fn parse_startpage(html: &str) -> Vec<String> {
    let (mut out, mut seen) = (Vec::new(), HashSet::new());
    for a in tags(html, "a") {
        let title = has_class(&a, "result-link")
            || has_class(&a, "result-title")
            || attr(&a, "data-testid") == Some("gl-title-link");
        if title {
            if let Some(h) = attr(&a, "href") {
                push_http(&mut out, &mut seen, h, "startpage.com");
            }
        }
    }
    out
}

/// Returns `true` if the Startpage page has a "Next" button.
pub fn startpage_has_next(html: &str) -> bool {
    html.contains("aria-label=\"go to page Next\"") || html.contains(">Next</button>")
}

/// Returns Brave Search result links. For some clients Brave hides direct links behind
/// `/go/v1/...`; the URL is then rebuilt from the page data `meta_url {scheme, hostname, path: "› a › b"}`
/// (a path truncated with "…" is dropped). Direct `url:"https://..."` and `a.l1[href^=http]` are used too.
pub fn parse_brave_web(html: &str) -> Vec<String> {
    let (mut out, mut seen) = (Vec::new(), HashSet::new());
    // SvelteKit data: results:[{title:"...",url:"...", ..., meta_url:{scheme:"https",netloc:"...",
    // hostname:"...",favicon:...,path:"› a  › b"}, ...}]
    let mut rest = html;
    while let Some(i) = rest.find("meta_url:{") {
        let block = &rest[i..];
        let end = block.find('}').unwrap_or(block.len());
        let m = &block[..end];
        let scheme = js_field(m, "scheme").unwrap_or_else(|| "https".into());
        let host = js_field(m, "hostname").or_else(|| js_field(m, "netloc"));
        let path = js_field(m, "path").unwrap_or_default();
        if let Some(host) = host {
            if let Some(u) = brave_url(&scheme, &host, &path) {
                push_http(&mut out, &mut seen, &u, "brave.com");
            }
        }
        // the direct url of the same result (before meta_url), unless it is a /go/ link
        let before = &rest[..i];
        if let Some(j) = before.rfind("url:\"") {
            let v = &before[j + 5..];
            if let Some(k) = v.find('"') {
                let direct = js_unescape(&v[..k]);
                if direct.starts_with("http") {
                    push_http(&mut out, &mut seen, &direct, "brave.com");
                }
            }
        }
        rest = &rest[i + 10..];
    }
    for a in tags(html, "a") {
        if has_class(&a, "l1") {
            if let Some(h) = attr(&a, "href") {
                push_http(&mut out, &mut seen, h, "brave.com");
            }
        }
    }
    out
}

fn js_field(block: &str, name: &str) -> Option<String> {
    let key = format!("{name}:\"");
    let mut from = 0;
    while let Some(i) = block[from..].find(&key) {
        let at = from + i;
        // match the whole field name (not `full_path:` when looking for `path:`)
        let ok = at == 0
            || !block.as_bytes()[at - 1].is_ascii_alphanumeric()
                && block.as_bytes()[at - 1] != b'_';
        let v = &block[at + key.len()..];
        if ok {
            let end = v.find('"')?;
            return Some(js_unescape(&v[..end]));
        }
        from = at + key.len();
    }
    None
}

fn js_unescape(s: &str) -> String {
    s.replace("\\u002F", "/")
        .replace("\\/", "/")
        .replace("&amp;", "&")
}

fn brave_url(scheme: &str, host: &str, path: &str) -> Option<String> {
    // truncated path: "…", "..." or a name cut off at a dot ("…-v14.")
    if path.contains('…') || path.contains("...") || path.trim_end().ends_with('.') {
        return None;
    }
    let segs: Vec<String> = path
        .split('›')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    let mut u = url::Url::parse(&format!("{scheme}://{host}/")).ok()?;
    u.path_segments_mut()
        .ok()?
        .extend(segs.iter().map(String::as_str));
    Some(u.to_string())
}

/// Returns Yahoo result links: direct `a.s-title[href]` on mobile, and on desktop redirects of the
/// form `r.search.yahoo.com/.../RU=<url>/RK=...` (the URL is decoded). Yahoo hosts are dropped.
pub fn parse_yahoo(html: &str) -> Vec<String> {
    let (mut out, mut seen) = (Vec::new(), HashSet::new());
    for a in tags(html, "a") {
        let Some(h) = attr(&a, "href") else { continue };
        if let Some(i) = h.find("/RU=") {
            let rest = &h[i + 4..];
            let enc = rest.split('/').next().unwrap_or("");
            let dec = crate::filter::percent_decode(enc);
            push_http(&mut out, &mut seen, &dec, "yahoo.com");
        } else if has_class(&a, "s-title") || has_class(&a, "ac-algo") {
            push_http(&mut out, &mut seen, h, "yahoo.com");
        }
    }
    out
}

/// Returns `true` if the Yahoo page has a "Next" link.
pub fn yahoo_has_next(html: &str) -> bool {
    html.contains("class=\"next\"") || html.contains(">Next<") || html.contains("aria-label=\"Next")
}

/// Returns Mojeek result links: `ul.results-standard > li > a.ob[href]` (as in searxng
/// `engines/mojeek.py`), falling back to `h2 > a[href]` inside the result list.
pub fn parse_mojeek(html: &str) -> Vec<String> {
    let (mut out, mut seen) = (Vec::new(), HashSet::new());
    let Some(start) = html.find("results-standard") else {
        return out;
    };
    let list = &html[start..];
    let list = &list[..list.find("</ul>").unwrap_or(list.len())];
    for a in tags(list, "a") {
        if has_class(&a, "ob") || has_class(&a, "title") {
            if let Some(h) = attr(&a, "href") {
                push_http(&mut out, &mut seen, h, "mojeek.com");
            }
        }
    }
    out
}

/// A dork source backed by the embedded browser.
#[derive(Debug, Clone)]
pub struct RenderDork {
    pub engine: RenderEngine,
    /// Maximum result pages per file type.
    pub max_pages: usize,
    /// Maximum file types (queries) per run.
    pub max_queries: usize,
    /// Pause between search engine requests: random within `[delay_min, delay_max]`.
    pub delay_min: Duration,
    pub delay_max: Duration,
}

/// Source names (for the scan screen and the log).
pub const RENDER_SOURCES: &[(&str, &str)] = &[
    ("startpage", "Startpage (через браузер)"),
    ("brave_web", "Brave Search (через браузер)"),
    ("yahoo", "Yahoo (через браузер)"),
    ("searx_pool", "Публичные SearXNG (через браузер)"),
];

impl RenderDork {
    pub fn new(engine: RenderEngine) -> Self {
        RenderDork {
            engine,
            max_pages: 3,
            max_queries: 8,
            // human-like pacing with jitter
            delay_min: Duration::from_secs(6),
            delay_max: Duration::from_secs(14),
        }
    }

    /// Disables pauses (tests with a fake browser).
    pub fn no_delay(mut self) -> Self {
        self.delay_min = Duration::ZERO;
        self.delay_max = Duration::ZERO;
        self
    }

    fn session(&self) -> &'static str {
        match self.engine {
            RenderEngine::Startpage => "startpage",
            RenderEngine::BraveWeb => "brave",
            RenderEngine::Mojeek => "mojeek",
            RenderEngine::Yahoo => "yahoo",
        }
    }

    fn enc(q: &str) -> String {
        url::form_urlencoded::byte_serialize(q.as_bytes()).collect()
    }

    /// Builds the browser request for page `page` (starting at 1) of query `q`.
    pub fn request(&self, q: &str, page: usize, timeout: Duration) -> RenderRequest {
        let verify = || RenderStep::Wait {
            gone: vec![VERIFY_TEXT.into()],
            present: None,
            timeout_ms: 60_000,
            abort: CAPTCHA_ABORT.iter().map(|s| s.to_string()).collect(),
        };
        match self.engine {
            RenderEngine::Startpage if page <= 1 => {
                // a direct GET /sp/search hangs on the challenge: home page, challenge, then the form (POST, field sc)
                RenderRequest::new(self.session(), Some("https://www.startpage.com/"), timeout)
                    .step(verify())
                    .step(RenderStep::Submit {
                        form: "form[action*=search]".into(),
                        field: "[name=query]".into(),
                        value: q.into(),
                    })
                    .step(verify())
            }
            RenderEngine::Startpage => RenderRequest::new(self.session(), None, timeout)
                .step(RenderStep::Click {
                    sel: "form button[type=submit], form input[type=submit]".into(),
                    text: "next".into(),
                })
                .step(verify()),
            RenderEngine::BraveWeb => {
                let off = if page > 1 {
                    format!("&offset={}", page - 1)
                } else {
                    String::new()
                };
                let u = format!(
                    "https://search.brave.com/search?q={}&source=web{off}",
                    Self::enc(q)
                );
                RenderRequest::new(self.session(), Some(&u), timeout).step(RenderStep::Wait {
                    gone: vec![VERIFY_TEXT.into(), "Verifying".into()],
                    present: None,
                    timeout_ms: 30_000,
                    abort: CAPTCHA_ABORT.iter().map(|s| s.to_string()).collect(),
                })
            }
            RenderEngine::Yahoo => {
                let off = if page > 1 {
                    format!("&b={}", (page - 1) * 10 + 1)
                } else {
                    String::new()
                };
                let u = format!("https://search.yahoo.com/search?p={}{off}", Self::enc(q));
                RenderRequest::new(self.session(), Some(&u), timeout).step(RenderStep::Wait {
                    gone: vec![],
                    present: None,
                    timeout_ms: 20_000,
                    abort: CAPTCHA_ABORT.iter().map(|s| s.to_string()).collect(),
                })
            }
            RenderEngine::Mojeek => {
                // Mojeek treats s=0 on the first page as a bot signal, so it is sent only from page two
                let off = if page > 1 {
                    format!("&s={}", (page - 1) * 10)
                } else {
                    String::new()
                };
                let u = format!("https://www.mojeek.com/search?q={}{off}", Self::enc(q));
                RenderRequest::new(self.session(), Some(&u), timeout).step(RenderStep::Wait {
                    gone: vec![],
                    present: None,
                    timeout_ms: 20_000,
                    abort: CAPTCHA_ABORT
                        .iter()
                        .chain(&["automated queries"])
                        .map(|s| s.to_string())
                        .collect(),
                })
            }
        }
    }

    fn parse(&self, html: &str) -> Vec<String> {
        match self.engine {
            RenderEngine::Startpage => parse_startpage(html),
            RenderEngine::BraveWeb => parse_brave_web(html),
            RenderEngine::Mojeek => parse_mojeek(html),
            RenderEngine::Yahoo => parse_yahoo(html),
        }
    }

    fn pause(&self) -> Duration {
        crate::sources::dorkpool::jitter(self.delay_min, self.delay_max)
    }

    fn id_of(&self) -> &'static str {
        match self.engine {
            RenderEngine::Startpage => "startpage",
            RenderEngine::BraveWeb => "brave_web",
            RenderEngine::Mojeek => "mojeek",
            RenderEngine::Yahoo => "yahoo",
        }
    }

    /// Returns the engine's home page. The engine's first request in a scan starts there, like a human
    /// would (cookies, session, `Referer` for the results); Startpage always does (form with field `sc`).
    pub fn home(&self) -> &'static str {
        match self.engine {
            RenderEngine::Startpage => "https://www.startpage.com/",
            RenderEngine::BraveWeb => "https://search.brave.com/",
            RenderEngine::Mojeek => "https://www.mojeek.com/",
            RenderEngine::Yahoo => "https://search.yahoo.com/",
        }
    }

    /// Runs the source (shared by `startpage`, `brave_web` and `mojeek` in the browser) on the shared
    /// dork board (`dorkpool::run_dorks`): type group queue, failover on captcha, budget, cache, pacing.
    pub async fn run(&self, ctx: &SearchCtx, domain: &str) -> Result<Found, NetError> {
        if ctx.render.is_none() {
            return Err(NetError::Request(NO_RENDER.into()));
        }
        crate::sources::dorkpool::run_dorks(ctx, domain, self).await
    }

    async fn fetch_page(
        &self,
        ctx: &SearchCtx,
        q: &str,
        page: usize,
        first: bool,
    ) -> Result<DorkPage, NetError> {
        let id = self.id_of();
        let Some(render) = ctx.render.clone() else {
            return Err(NetError::Request(NO_RENDER.into()));
        };
        let proxy = ctx
            .net
            .config()
            .proxy
            .clone()
            .filter(|p| !p.trim().is_empty());
        let timeout = ctx.req_timeout(Duration::from_secs(120));
        // The first visit in a scan starts at the home page (Startpage goes through it anyway; Yahoo's
        // home page from the EU is a cookie consent wall, while direct results open without it).
        if first
            && page <= 1
            && matches!(self.engine, RenderEngine::BraveWeb | RenderEngine::Mojeek)
        {
            let warm = RenderRequest::new(self.session(), Some(self.home()), timeout)
                .step(RenderStep::Wait {
                    gone: vec![VERIFY_TEXT.into()],
                    present: None,
                    timeout_ms: 30_000,
                    abort: CAPTCHA_ABORT.iter().map(|s| s.to_string()).collect(),
                })
                .through_proxy(proxy.clone())
                .logged_as(id);
            let r = render.fetch(warm).await;
            let mut rec = ctx.net.draft(
                id,
                "RENDER",
                self.home(),
                host_of(self.home()),
                &Access::Passive,
            );
            match &r {
                Ok(p) => {
                    rec.status = p.status;
                    rec.bytes = p.html.len() as u64;
                }
                Err(e) => rec.error = Some(e.clone()),
            }
            ctx.net.record(rec);
            if let Ok(p) = &r {
                let k = classify(self.engine, p);
                if k != PageKind::Results {
                    return Ok(DorkPage {
                        kind: Some(k),
                        ..Default::default()
                    });
                }
            }
            if self.delay_max > Duration::ZERO {
                tokio::time::sleep(crate::sources::dorkpool::jitter(
                    Duration::from_millis(1500),
                    Duration::from_millis(4000),
                ))
                .await;
            }
        }
        let req = self
            .request(q, page, timeout)
            .through_proxy(proxy)
            .logged_as(id);
        let shown = req
            .url
            .clone()
            .unwrap_or_else(|| format!("{q}: стр. {page}"));
        tracing::info!(target: "foca::source", "{id}: браузер {q}, стр. {page}");
        let r = render.fetch(req).await;
        let mut rec = ctx
            .net
            .draft(id, "RENDER", &shown, host_of(&shown), &Access::Passive);
        let pg = match r {
            Ok(p) => {
                rec.status = p.status;
                rec.bytes = p.html.len() as u64;
                ctx.net.record(rec);
                p
            }
            Err(e) => {
                rec.error = Some(e.clone());
                ctx.net.record(rec);
                tracing::warn!(target: "foca::source", "{id}: браузер: {e}");
                return Err(NetError::Request(format!("встроенный браузер: {e}")));
            }
        };
        let kind = classify(self.engine, &pg);
        if kind != PageKind::Results {
            return Ok(DorkPage {
                kind: Some(kind),
                ..Default::default()
            });
        }
        let has_next = pg.missing.is_none()
            && match self.engine {
                RenderEngine::Startpage => startpage_has_next(&pg.html),
                RenderEngine::Yahoo => yahoo_has_next(&pg.html),
                _ => true,
            };
        Ok(DorkPage {
            kind: Some(PageKind::Results),
            links: self.parse(&pg.html),
            has_next,
            why: None,
        })
    }
}

impl DorkBackend for RenderDork {
    fn engine_id(&self) -> &'static str {
        self.id_of()
    }
    /// Google (Startpage), Brave and Yahoo (Bing) understand `(filetype:a OR filetype:b)`; Mojeek does not.
    fn or_ok(&self) -> bool {
        self.engine != RenderEngine::Mojeek
    }
    fn max_pages(&self) -> usize {
        self.max_pages
    }
    fn pause(&self) -> Duration {
        RenderDork::pause(self)
    }
    fn fetch<'a>(
        &'a self,
        ctx: &'a SearchCtx,
        q: &'a str,
        page: usize,
        first: bool,
    ) -> BoxFuture<'a, Result<DorkPage, NetError>> {
        Box::pin(self.fetch_page(ctx, q, page, first))
    }
}

fn host_of(u: &str) -> &str {
    let s = u.split("://").nth(1).unwrap_or("");
    s.split(['/', '?', '#']).next().unwrap_or("")
}

impl DocumentSource for RenderDork {
    fn id(&self) -> &'static str {
        self.id_of()
    }
    fn name(&self) -> &'static str {
        RENDER_SOURCES
            .iter()
            .find(|s| s.0 == self.id_of())
            .map(|s| s.1)
            .unwrap_or("Mojeek (дорки)")
    }
    fn kind(&self) -> SourceKind {
        SourceKind::Passive
    }
    /// The browser is slow (challenge 5-40 s, 3-6 s pauses, several pages per type), so this source
    /// gets four times the overall source timeout.
    fn budget(&self) -> u32 {
        4
    }
    fn find<'a>(
        &'a self,
        ctx: &'a SearchCtx,
        domain: &'a str,
    ) -> BoxFuture<'a, Result<Found, NetError>> {
        Box::pin(self.run(ctx, domain))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_markers_are_lowercase_and_cover_challenges() {
        let m = verify_markers();
        assert!(m.iter().all(|s| *s == s.to_lowercase()));
        assert!(m.contains(&"verifying your request".to_string()));
        assert!(m.contains(&"altcha".to_string()));
        assert_eq!(m.len(), CAPTCHA_ABORT.len() + 1);
    }

    #[test]
    fn attrs_parse_quotes_and_entities() {
        let a: Vec<_> = tags(
            r#"<a class="x result-link" href="https://a.ua/x.pdf?a=1&amp;b=2" data-testid='gl-title-link'>t</a><abbr>"#,
            "a",
        )
        .collect();
        assert_eq!(a.len(), 1);
        assert_eq!(attr(&a[0], "href"), Some("https://a.ua/x.pdf?a=1&b=2"));
        assert!(has_class(&a[0], "result-link"));
    }

    #[test]
    fn brave_meta_url_rebuilt() {
        assert_eq!(
            brave_url(
                "https",
                "eospso.nasa.gov",
                "› sites  › default  › NASA Science.pdf"
            )
            .as_deref(),
            Some("https://eospso.nasa.gov/sites/default/NASA%20Science.pdf")
        );
        assert_eq!(brave_url("https", "a.ua", "› x  › …  › y.pdf"), None);
        assert_eq!(brave_url("https", "a.ua", "› x  › guide-v14."), None);
        assert_eq!(
            brave_url("http", "a.ua", "").as_deref(),
            Some("http://a.ua/")
        );
    }

    #[test]
    fn requests_per_engine() {
        let t = Duration::from_secs(60);
        let sp = RenderDork::new(RenderEngine::Startpage);
        let r1 = sp.request("site:a.ua filetype:pdf", 1, t);
        assert_eq!(r1.url.as_deref(), Some("https://www.startpage.com/"));
        assert!(matches!(r1.steps[1], RenderStep::Submit { .. }));
        let r2 = sp.request("site:a.ua filetype:pdf", 2, t);
        assert!(r2.url.is_none());
        assert!(matches!(r2.steps[0], RenderStep::Click { .. }));
        let b = RenderDork::new(RenderEngine::BraveWeb).request("site:a.ua filetype:pdf", 3, t);
        assert_eq!(
            b.url.as_deref(),
            Some(
                "https://search.brave.com/search?q=site%3Aa.ua+filetype%3Apdf&source=web&offset=2"
            )
        );
        let m = RenderDork::new(RenderEngine::Mojeek);
        assert_eq!(
            m.request("site:a.ua filetype:pdf", 1, t).url.as_deref(),
            Some("https://www.mojeek.com/search?q=site%3Aa.ua+filetype%3Apdf")
        );
        assert!(m.request("q", 2, t).url.unwrap().ends_with("&s=10"));
        let p = sp.pause();
        assert!(p >= Duration::from_secs(6) && p <= Duration::from_secs(14));
    }

    fn mk_page(url: &str, status: Option<u16>, html: &str) -> RenderPage {
        RenderPage {
            url: url.into(),
            status,
            html: html.into(),
            ..Default::default()
        }
    }

    #[test]
    fn structural_captcha_detects_non_english_widgets_without_captcha_words() {
        // Ukrainian/Japanese/German challenge pages with zero English "captcha" text
        let turnstile_dom = mk_page(
            "https://search.brave.com/search?q=x",
            Some(200),
            "<html><body><p>Підтвердьте, що ви людина</p><div class=\"cf-turnstile\" data-sitekey=\"0x4AAAA\"></div></body></html>",
        );
        let sig = detect_captcha_signals(RenderEngine::BraveWeb, &turnstile_dom);
        assert!(sig.challenge_dom_attr && !sig.has_results);
        assert_eq!(
            classify(RenderEngine::BraveWeb, &turnstile_dom),
            PageKind::Captcha
        );

        let recaptcha_iframe = mk_page(
            "https://www.startpage.com/sp/search",
            Some(200),
            "<html><body><p>Bitte Sicherheitsprüfung abschließen</p><iframe src=\"https://www.google.com/recaptcha/api2/anchor?k=123\"></iframe></body></html>",
        );
        assert_eq!(
            classify(RenderEngine::Startpage, &recaptcha_iframe),
            PageKind::Captcha
        );

        let hcaptcha_input = mk_page(
            "https://search.yahoo.com/search",
            Some(200),
            "<html><body><p>セキュリティ確認</p><form action=\"/check\"><input type=\"hidden\" name=\"h-captcha-response\"></form></body></html>",
        );
        assert_eq!(
            classify(RenderEngine::Yahoo, &hcaptcha_input),
            PageKind::Captcha
        );

        let turnstile_script = mk_page(
            "https://www.mojeek.com/search?q=x",
            Some(200),
            "<html><head><script src=\"https://challenges.cloudflare.com/turnstile/v0/api.js\"></script></head><body><p>Vérification en cours</p></body></html>",
        );
        assert_eq!(
            classify(RenderEngine::Mojeek, &turnstile_script),
            PageKind::Captcha
        );
    }

    #[test]
    fn real_results_with_captcha_snippet_never_false_positive() {
        let sp_serp = mk_page(
            "https://www.startpage.com/sp/search",
            Some(200),
            "<html><body><a class=\"result-link\" href=\"https://example.org/recaptcha.pdf\">How to debug Cloudflare Turnstile and reCAPTCHA widgets</a></body></html>",
        );
        let sig = detect_captcha_signals(RenderEngine::Startpage, &sp_serp);
        assert!(sig.has_results);
        assert_eq!(
            classify(RenderEngine::Startpage, &sp_serp),
            PageKind::Results
        );

        let brave_serp = mk_page(
            "https://search.brave.com/search?q=captcha",
            Some(200),
            "<html><body><div data-type=\"web\"><p>Solving g-recaptcha and h-captcha challenges in tests</p></div></body></html>",
        );
        assert_eq!(
            classify(RenderEngine::BraveWeb, &brave_serp),
            PageKind::Results
        );
    }
}
