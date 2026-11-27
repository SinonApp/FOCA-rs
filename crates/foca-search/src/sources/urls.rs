//! Keyless passive sources of document URLs: AlienVault OTX `url_list` (paginated with `page=`),
//! urlscan.io `search` (small limit), HudsonRock `urls-by-domain` (URLs from infostealer logs),
//! Arquivo.pt `textsearch` (`id_` copies from arquivo.pt), and `site:<d> filetype:<ext>` dorks
//! over the HTML results of DuckDuckGo / Bing / Mojeek (best effort, with an accurate
//! captcha/blocked status). Endpoints follow gau `pkg/providers` (MIT), theHarvester (GPL-2.0,
//! facts only), FOCA SearcherCore and go-dork (the result parsing idea); the code is original.

use std::collections::BTreeSet;
use std::time::Duration;

use foca_net::{Access, NetError, NetRequest};
use serde_json::Value;

use crate::filter::{percent_decode, url_in_domain};
use crate::source::{DocumentSource, Found, FoundUrl, SearchCtx, SourceKind};
use crate::sources::archive::Collector;
use crate::sources::render_engines::{RenderDork, RenderEngine};
use crate::sources::subdomains::extract_hosts;
use crate::BoxFuture;

/// Extracts all http(s) links from text: JSON (`\/`), HTML (`href`, `&amp;`), DuckDuckGo redirects
/// (`uddg=`) and Bing redirects (`u=a1<base64url>`).
pub fn extract_urls(text: &str) -> Vec<String> {
    let t = text.replace("\\/", "/").replace("&amp;", "&");
    let mut out = BTreeSet::new();
    let stop = |c: char| c.is_whitespace() || matches!(c, '"' | '\'' | '<' | '>' | '\\' | '`');
    let mut push = |s: &str| {
        let s = s.trim_end_matches([')', ',', ';', '.', ']']);
        if (s.starts_with("http://") || s.starts_with("https://")) && s.len() < 2048 {
            out.insert(s.to_string());
        }
    };
    for (i, _) in t.match_indices("http") {
        let rest = &t[i..];
        if rest.starts_with("http://") || rest.starts_with("https://") {
            let end = rest.find(stop).unwrap_or(rest.len());
            push(&rest[..end]);
        }
    }
    for key in ["uddg=", "?u=a1", "&u=a1"] {
        for (i, _) in t.match_indices(key) {
            let rest = &t[i + key.len()..];
            let end = rest
                .find(|c: char| c == '&' || stop(c))
                .unwrap_or(rest.len());
            let v = &rest[..end];
            if key == "uddg=" {
                push(&percent_decode(v));
            } else if let Some(d) = b64url(v) {
                push(&d);
            }
        }
    }
    out.into_iter().collect()
}

fn is_search_chrome_url(u: &str) -> bool {
    let Ok(parsed) = url::Url::parse(u) else {
        return true;
    };
    let Some(host) = parsed
        .host_str()
        .map(|h| h.trim_end_matches('.').to_ascii_lowercase())
    else {
        return true;
    };
    const NOISE_HOSTS: &[&str] = &[
        "bing.com",
        "bing.net",
        "microsoft.com",
        "msn.com",
        "live.com",
        "microsofttranslator.com",
        "duckduckgo.com",
        "mojeek.com",
        "w3.org",
        "schema.org",
        "googleapis.com",
        "gstatic.com",
        "cloudflare.com",
    ];
    if NOISE_HOSTS
        .iter()
        .any(|d| host == *d || host.ends_with(&format!(".{d}")))
    {
        return true;
    }
    let path_low = parsed.path().to_ascii_lowercase();
    [".js", ".css", ".ico", ".svg", ".woff", ".woff2"]
        .iter()
        .any(|ext| path_low.ends_with(ext))
}

/// Extracts search result URLs for a dork engine without polluting cache with search chrome/scripts.
pub fn extract_dork_urls(engine: DorkEngine, html: &str) -> Vec<String> {
    let raw = extract_urls(html);
    if engine != DorkEngine::Bing {
        return raw;
    }
    raw.into_iter()
        .filter(|u| !is_search_chrome_url(u))
        .collect()
}

fn b64url(s: &str) -> Option<String> {
    let mut bits = 0u32;
    let mut n = 0;
    let mut out = Vec::new();
    for c in s.bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'-' | b'+' => 62,
            b'_' | b'/' => 63,
            b'=' => break,
            _ => return None,
        } as u32;
        bits = (bits << 6) | v;
        n += 6;
        if n >= 8 {
            n -= 8;
            out.push((bits >> n) as u8);
            bits &= (1 << n) - 1;
        }
    }
    String::from_utf8(out).ok()
}

fn blocked_page(status: u16, body: &str) -> bool {
    let low = body.to_ascii_lowercase();
    matches!(status, 202 | 403 | 429)
        || low.contains("anomaly-modal")
        || low.contains("automated queries")
        || low.contains("unusual traffic")
        || low.contains("/challenge")
        || (low.contains("captcha") && !low.contains("b_algo"))
}

fn add_urls(col: &mut Collector, ctx: &SearchCtx, domain: &str, urls: &[String], src: &str) {
    for u in urls {
        if !url_in_domain(u, domain) {
            continue;
        }
        col.host(u, domain);
        let Some(ext) = ctx.filter.matches(u) else {
            continue;
        };
        let mut f = FoundUrl::new(u, src);
        f.hint_ext = Some(ext);
        col.push(f);
    }
}

async fn get_text(
    ctx: &SearchCtx,
    url: &str,
    module: &str,
    timeout: Duration,
    headers: &[(&str, &str)],
) -> Result<(u16, String), NetError> {
    let mut req = NetRequest::get(url, module, Access::Passive)?
        .timeout(ctx.req_timeout(timeout))
        .retries(1);
    for (k, v) in headers {
        req = req.header(k, v);
    }
    let r = ctx.net.send(req).await?;
    let st = r.status();
    let body = r.text_limited(16 * 1024 * 1024).await?;
    Ok((st, body))
}

fn limited(id: &str, st: u16, body: &str) -> Option<NetError> {
    let low = body.to_ascii_lowercase();
    if st == 503 {
        // overloaded or throttling: also the `limit` status
        return Some(NetError::Status(503));
    }
    if st == 429 || low.contains("rate limit") {
        // source status `limit` (not an error); the text comes from `source::limit_message`
        return Some(NetError::Status(429));
    }
    if low.contains("please authenticate") {
        return Some(NetError::Request(format!(
            "{id}: сервис требует ключ (HTTP {st})"
        )));
    }
    if !(200..300).contains(&st) && st != 404 {
        return Some(NetError::Status(st));
    }
    None
}

/// Kind of passive URL source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UrlKind {
    Otx,
    Urlscan,
    Hudson,
    Arquivo,
}

/// A passive URL source (OTX / urlscan / HudsonRock / Arquivo.pt).
#[derive(Debug, Clone)]
pub struct UrlSource {
    pub kind: UrlKind,
    pub base: String,
    pub max_pages: usize,
    pub api_key: Option<String>,
}

impl UrlSource {
    pub fn new(kind: UrlKind) -> Self {
        let base = match kind {
            UrlKind::Otx => "https://otx.alienvault.com",
            UrlKind::Urlscan => "https://urlscan.io",
            UrlKind::Hudson => "https://cavalier.hudsonrock.com",
            UrlKind::Arquivo => "https://arquivo.pt",
        };
        UrlSource {
            kind,
            base: base.into(),
            max_pages: 5,
            api_key: None,
        }
    }

    pub fn with_base(mut self, b: &str) -> Self {
        self.base = b.trim_end_matches('/').into();
        self
    }

    pub fn with_key(mut self, k: Option<String>) -> Self {
        self.api_key = k.map(|v| v.trim().to_string()).filter(|v| !v.is_empty());
        self
    }
}

/// Keyless URL sources (id, name).
pub const URL_SOURCES: &[(&str, &str)] = &[
    ("otx_url", "AlienVault OTX (URL)"),
    ("urlscan", "urlscan.io"),
    ("hudson", "HudsonRock (инфостилеры)"),
    ("arquivo", "Arquivo.pt"),
    ("ddg", "DuckDuckGo (дорки)"),
    ("bing", "Bing (дорки)"),
    ("mojeek", "Mojeek (дорки)"),
    ("startpage", "Startpage (через браузер)"),
    ("brave_web", "Brave Search (через браузер)"),
    ("yahoo", "Yahoo (через браузер)"),
    ("searx_pool", "Публичные SearXNG (через браузер)"),
];

/// Returns the URL or dork source with the given id.
pub fn url_source(id: &str) -> Option<Box<dyn DocumentSource>> {
    Some(match id {
        "otx_url" => Box::new(UrlSource::new(UrlKind::Otx)),
        "urlscan" => Box::new(UrlSource::new(UrlKind::Urlscan)),
        "hudson" => Box::new(UrlSource::new(UrlKind::Hudson)),
        "arquivo" => Box::new(UrlSource::new(UrlKind::Arquivo)),
        "ddg" => Box::new(Dork::new(DorkEngine::DuckDuckGo)),
        "bing" => Box::new(Dork::new(DorkEngine::Bing)),
        "mojeek" => Box::new(Dork::new(DorkEngine::Mojeek)),
        "startpage" => Box::new(RenderDork::new(RenderEngine::Startpage)),
        "brave_web" => Box::new(RenderDork::new(RenderEngine::BraveWeb)),
        "yahoo" => Box::new(RenderDork::new(RenderEngine::Yahoo)),
        "searx_pool" => Box::new(crate::sources::SearxPool::default()),
        _ => return None,
    })
}

/// Same as [`url_source`], with the base URL replaced (tests, mirrors).
pub fn url_source_with_base(id: &str, base: &str) -> Option<Box<dyn DocumentSource>> {
    Some(match id {
        "otx_url" => Box::new(UrlSource::new(UrlKind::Otx).with_base(base)),
        "urlscan" => Box::new(UrlSource::new(UrlKind::Urlscan).with_base(base)),
        "hudson" => Box::new(UrlSource::new(UrlKind::Hudson).with_base(base)),
        "arquivo" => Box::new(UrlSource::new(UrlKind::Arquivo).with_base(base)),
        "ddg" => Box::new(Dork::new(DorkEngine::DuckDuckGo).with_base(base)),
        "bing" => Box::new(Dork::new(DorkEngine::Bing).with_base(base)),
        "mojeek" => Box::new(Dork::new(DorkEngine::Mojeek).with_base(base)),
        // opened in the embedded browser, so the URL is not replaced; as with dorks `with_base`
        // (tests, mirrors), there are no pauses between requests
        "startpage" => Box::new(RenderDork::new(RenderEngine::Startpage).no_delay()),
        "brave_web" => Box::new(RenderDork::new(RenderEngine::BraveWeb).no_delay()),
        "yahoo" => Box::new(RenderDork::new(RenderEngine::Yahoo).no_delay()),
        // a self-hosted or test SearXNG instance instead of the searx.space pool
        "searx_pool" => Box::new(crate::sources::SearxPool::with_base(base)),
        _ => return None,
    })
}

/// Returns document extensions for per-type queries (Arquivo, dorks), office formats and PDF first.
fn query_exts(ctx: &SearchCtx) -> Vec<String> {
    const PRI: &[&str] = &[
        "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "odt", "ods", "rtf", "vsdx", "eml",
        "msg", "ics", "vcf",
    ];
    PRI.iter()
        .filter(|e| ctx.filter.allows_ext(e))
        .map(|e| e.to_string())
        .collect()
}

impl DocumentSource for UrlSource {
    fn id(&self) -> &'static str {
        match self.kind {
            UrlKind::Otx => "otx_url",
            UrlKind::Urlscan => "urlscan",
            UrlKind::Hudson => "hudson",
            UrlKind::Arquivo => "arquivo",
        }
    }
    fn name(&self) -> &'static str {
        URL_SOURCES
            .iter()
            .find(|s| s.0 == self.id())
            .map(|s| s.1)
            .unwrap_or("")
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
            let id = self.id();
            let mut col = Collector::new(ctx);
            let t = Duration::from_secs(40);
            match self.kind {
                UrlKind::Otx => {
                    for page in 1..=self.max_pages.max(1) {
                        if col.full() || ctx.out_of_time(Duration::from_secs(5)) {
                            break;
                        }
                        let u = format!(
                            "{}/api/v1/indicators/domain/{domain}/url_list?limit=500&page={page}",
                            self.base
                        );
                        let hdrs: Vec<(&str, &str)> = self
                            .api_key
                            .as_deref()
                            .map(|k| vec![("X-OTX-API-KEY", k)])
                            .unwrap_or_default();
                        let (st, body) = get_text(ctx, &u, id, t, &hdrs).await?;
                        if let Some(e) = limited(id, st, &body) {
                            if page == 1 {
                                return Err(e);
                            }
                            break;
                        }
                        let v: Value = serde_json::from_str(&body).unwrap_or_default();
                        let urls: Vec<String> = v["url_list"]
                            .as_array()
                            .map(|a| {
                                a.iter()
                                    .filter_map(|x| x["url"].as_str().map(String::from))
                                    .collect()
                            })
                            .unwrap_or_default();
                        for x in v["url_list"].as_array().into_iter().flatten() {
                            if let Some(h) = x["hostname"].as_str() {
                                col.host(&format!("https://{h}/"), domain);
                            }
                        }
                        add_urls(&mut col, ctx, domain, &urls, id);
                        if v["has_next"] != Value::Bool(true) || urls.is_empty() {
                            break;
                        }
                    }
                }
                UrlKind::Urlscan => {
                    let u = format!("{}/api/v1/search/?q=domain:{domain}&size=100", self.base);
                    let (st, body) = get_text(ctx, &u, id, t, &[]).await?;
                    if let Some(e) = limited(id, st, &body) {
                        return Err(e);
                    }
                    let urls = extract_urls(&body);
                    add_urls(&mut col, ctx, domain, &urls, id);
                    for h in extract_hosts(&body, domain) {
                        col.host(&format!("https://{h}/"), domain);
                    }
                }
                UrlKind::Hudson => {
                    let u = format!(
                        "{}/api/json/v2/osint-tools/urls-by-domain?domain={domain}",
                        self.base
                    );
                    let (st, body) = get_text(ctx, &u, id, t, &[]).await?;
                    if let Some(e) = limited(id, st, &body) {
                        return Err(e);
                    }
                    let urls = extract_urls(&body);
                    add_urls(&mut col, ctx, domain, &urls, id);
                    for h in extract_hosts(&body, domain) {
                        col.host(&format!("https://{h}/"), domain);
                    }
                }
                UrlKind::Arquivo => {
                    // Full-text search by file type. Arquivo's `site:` is loose, so the domain is checked locally;
                    // the `noFrame/replay/<ts>id_/<url>` copy is downloaded.
                    for ext in query_exts(ctx) {
                        if col.full() || ctx.out_of_time(Duration::from_secs(5)) {
                            break;
                        }
                        let u = format!(
                            "{}/textsearch?q=site:{domain}&type={ext}&maxItems=50",
                            self.base
                        );
                        let (st, body) = get_text(ctx, &u, id, t, &[]).await?;
                        if let Some(e) = limited(id, st, &body) {
                            return Err(e);
                        }
                        let v: Value = serde_json::from_str(&body).unwrap_or_default();
                        for it in v["response_items"].as_array().into_iter().flatten() {
                            let Some(orig) = it["originalURL"].as_str() else {
                                continue;
                            };
                            if !url_in_domain(orig, domain) {
                                continue;
                            }
                            col.host(orig, domain);
                            let Some(e) = ctx.filter.matches(orig) else {
                                continue;
                            };
                            let copy =
                                it["linkToOriginalFile"]
                                    .as_str()
                                    .map(String::from)
                                    .or_else(|| {
                                        it["tstamp"].as_str().map(|ts| {
                                            format!("{}/noFrame/replay/{ts}id_/{orig}", self.base)
                                        })
                                    });
                            let Some(copy) = copy else { continue };
                            let mut f = FoundUrl::new(&copy, id).with_original(orig);
                            f.hint_ext = Some(e);
                            f.date = it["tstamp"].as_str().map(String::from);
                            f.mime = it["mimeType"].as_str().map(String::from);
                            col.push(f);
                        }
                    }
                }
            }
            Ok(col.finish())
        })
    }
}

/// A keyless dork search engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DorkEngine {
    DuckDuckGo,
    Bing,
    Mojeek,
}

/// Dorks `site:<domain> filetype:<ext>` over HTML results (best effort): a pause between requests,
/// a browser User-Agent, one page per type; a captcha or block yields an error prefixed with [`BLOCKED`](crate::source::BLOCKED).
#[derive(Debug, Clone)]
pub struct Dork {
    pub engine: DorkEngine,
    pub base: String,
    pub delay: Duration,
    /// Maximum queries (file types) per run.
    pub max_queries: usize,
}

/// Returns the headers for search engine requests: the scan profile if one is selected
/// (`settings.net.ua`, honest included); without a profile (CLI default), a recent Firefox, since
/// search engines reject the honest UA immediately.
fn dork_headers(ctx: &SearchCtx) -> Vec<(String, String)> {
    let cfg = ctx.net.config();
    if !cfg.headers.is_empty() {
        return Vec::new();
    }
    let mode = foca_net::ua::UaMode::Firefox;
    let now = time::OffsetDateTime::now_utc();
    foca_net::ua::BrowserProfile::for_mode(&mode, now, &Default::default()).headers
}

impl Dork {
    pub fn new(engine: DorkEngine) -> Self {
        let base = match engine {
            DorkEngine::DuckDuckGo => "https://html.duckduckgo.com",
            DorkEngine::Bing => "https://www.bing.com",
            DorkEngine::Mojeek => "https://www.mojeek.com",
        };
        Dork {
            engine,
            base: base.into(),
            delay: Duration::from_millis(2500),
            max_queries: 8,
        }
    }

    pub fn with_base(mut self, b: &str) -> Self {
        self.base = b.trim_end_matches('/').into();
        self.delay = Duration::from_millis(10);
        self
    }

    /// Builds the query URL.
    pub fn query_url(&self, domain: &str, ext: &str) -> String {
        self.url_for(&format!("site:{domain} filetype:{ext}"))
    }

    /// Builds the results URL for a prepared query.
    pub fn url_for(&self, query: &str) -> String {
        let q: String = url::form_urlencoded::byte_serialize(query.as_bytes()).collect();
        match self.engine {
            DorkEngine::DuckDuckGo => format!("{}/html/?q={q}", self.base),
            DorkEngine::Bing => format!("{}/search?q={q}&count=50", self.base),
            DorkEngine::Mojeek => format!("{}/search?q={q}", self.base),
        }
    }
}

impl DocumentSource for Dork {
    fn id(&self) -> &'static str {
        match self.engine {
            DorkEngine::DuckDuckGo => "ddg",
            DorkEngine::Bing => "bing",
            DorkEngine::Mojeek => "mojeek",
        }
    }
    fn name(&self) -> &'static str {
        URL_SOURCES
            .iter()
            .find(|s| s.0 == self.id())
            .map(|s| s.1)
            .unwrap_or("")
    }
    fn kind(&self) -> SourceKind {
        SourceKind::Passive
    }
    /// Mojeek in the embedded browser fetches several pages with 3-6 s pauses.
    fn budget(&self) -> u32 {
        if self.engine == DorkEngine::Mojeek {
            3
        } else {
            1
        }
    }
    fn find<'a>(
        &'a self,
        ctx: &'a SearchCtx,
        domain: &'a str,
    ) -> BoxFuture<'a, Result<Found, NetError>> {
        Box::pin(async move {
            // Mojeek: use the embedded browser when available (plain HTTP from a data center gets 403)
            if self.engine == DorkEngine::Mojeek && ctx.render.is_some() {
                let mut r = RenderDork::new(RenderEngine::Mojeek);
                if self.delay < Duration::from_secs(1) {
                    r = r.no_delay(); // with_base: tests and mirrors
                }
                return r.run(ctx, domain).await;
            }
            crate::sources::dorkpool::run_dorks(ctx, domain, self).await
        })
    }
}

impl crate::sources::dorkpool::DorkBackend for Dork {
    fn engine_id(&self) -> &'static str {
        self.id()
    }
    /// Bing and DuckDuckGo (Bing results) understand `OR`; Mojeek does not.
    fn or_ok(&self) -> bool {
        self.engine != DorkEngine::Mojeek
    }
    fn max_pages(&self) -> usize {
        1
    }
    fn pause(&self) -> Duration {
        crate::sources::dorkpool::jitter(self.delay, self.delay * 2)
    }
    fn fetch<'a>(
        &'a self,
        ctx: &'a SearchCtx,
        q: &'a str,
        _page: usize,
        _first: bool,
    ) -> BoxFuture<'a, Result<crate::sources::dorkpool::DorkPage, NetError>> {
        Box::pin(async move {
            use crate::dorkboard::PageKind;
            use crate::sources::dorkpool::DorkPage;
            let hdrs = dork_headers(ctx);
            let (st, body) = get_text(
                ctx,
                &self.url_for(q),
                self.id(),
                Duration::from_secs(25),
                &hdrs
                    .iter()
                    .map(|(k, v)| (k.as_str(), v.as_str()))
                    .collect::<Vec<_>>(),
            )
            .await?;
            if blocked_page(st, &body) {
                let ip = body.to_ascii_lowercase().contains("automated queries");
                return Ok(DorkPage {
                    kind: Some(if ip {
                        PageKind::BlockedIp
                    } else {
                        PageKind::Captcha
                    }),
                    why: Some(if ip {
                        format!("поисковик заблокировал IP (automated queries, HTTP {st})")
                    } else {
                        format!("поисковик показал капчу (HTTP {st})")
                    }),
                    ..Default::default()
                });
            }
            Ok(DorkPage {
                kind: Some(PageKind::Results),
                links: extract_dork_urls(self.engine, &body),
                has_next: false,
                why: None,
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urls_from_ddg_bing_json() {
        let ddg = r#"<a class="result__a" href="//duckduckgo.com/l/?uddg=https%3A%2F%2Feducation.python.org%2Fstatic%2Fguides%2Fwhat_works_toolkit.pdf&amp;rut=abc">x</a>"#;
        assert!(extract_urls(ddg).contains(
            &"https://education.python.org/static/guides/what_works_toolkit.pdf".to_string()
        ));
        // Bing: u=a1 + base64url("https://www.python.org/ftp/a.pdf")
        let bing = r#"<a href="https://www.bing.com/ck/a?!&&p=x&u=a1aHR0cHM6Ly93d3cucHl0aG9uLm9yZy9mdHAvYS5wZGY&ntb=1">"#;
        assert!(extract_urls(bing).contains(&"https://www.python.org/ftp/a.pdf".to_string()));
        let j = r#"{"url": "https:\/\/demo.testfire.net\/pr\/Q3_earnings.rtf", "x": "http://other.example/a.pdf"}"#;
        let u = extract_urls(j);
        assert!(u.contains(&"https://demo.testfire.net/pr/Q3_earnings.rtf".to_string()));
        assert!(url_in_domain(&u[0], "testfire.net") || url_in_domain(&u[1], "testfire.net"));
        assert!(!url_in_domain("http://other.example/a.pdf", "testfire.net"));
        assert!(!url_in_domain(
            "http://testfire.net.evil.com/a.pdf",
            "testfire.net"
        ));

        let bing_noise = r#"
          <script src="https://r.bing.com/rs/chrome.js"></script>
          <a href="https://go.microsoft.com/fwlink/?LinkId=1">Privacy</a>
          <a href="https://www.bing.com/ck/a?!&&u=a1aHR0cHM6Ly9leGFtcGxlLmNvbS9yZXBvcnQucGRm&ntb=1">Res</a>
        "#;
        assert_eq!(
            extract_dork_urls(DorkEngine::Bing, bing_noise),
            vec!["https://example.com/report.pdf".to_string()]
        );
    }

    #[test]
    fn blocked_pages() {
        assert!(blocked_page(
            403,
            "Sorry your network appears to be sending automated queries"
        ));
        assert!(blocked_page(200, "<div class=\"anomaly-modal\">"));
        assert!(!blocked_page(
            200,
            "<li class=\"b_algo\">captcha word in result</li>"
        ));
        assert!(!blocked_page(200, "<html>results</html>"));
    }

    #[test]
    fn dork_query() {
        let d = Dork::new(DorkEngine::DuckDuckGo);
        assert_eq!(
            d.query_url("python.org", "pdf"),
            "https://html.duckduckgo.com/html/?q=site%3Apython.org+filetype%3Apdf"
        );
    }

    #[tokio::test]
    async fn otx_url_sends_key_header_only_when_present() {
        use foca_core::Scope;
        use foca_net::testserver::{TestResponse, TestServer};
        use foca_net::{MemorySink, NetClient, NetConfig};
        use std::sync::{Arc, Mutex};

        let seen: Arc<Mutex<Vec<Option<String>>>> = Arc::default();
        let s2 = seen.clone();
        let srv = TestServer::start(move |req| {
            let hdr = req
                .headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case("x-otx-api-key"))
                .map(|(_, v)| v.clone());
            s2.lock().unwrap().push(hdr);
            TestResponse::ok(br#"{"url_list":[]}"#.to_vec())
                .header("content-type", "application/json")
        })
        .await;

        let net = NetClient::new(
            NetConfig::default(),
            Scope::default(),
            Arc::new(MemorySink::new()),
        )
        .unwrap();
        let ctx = SearchCtx::new(net);

        let no_key = UrlSource::new(UrlKind::Otx).with_base(&srv.url());
        no_key.find(&ctx, "example.org").await.unwrap();

        let with_key = UrlSource::new(UrlKind::Otx)
            .with_base(&srv.url())
            .with_key(Some("otx-secret-123".into()));
        with_key.find(&ctx, "example.org").await.unwrap();

        let captured = seen.lock().unwrap().clone();
        assert_eq!(captured, vec![None, Some("otx-secret-123".into())]);
    }
}
