//! Search APIs (no HTML scraping): Brave Search API (key) and own SearXNG instances
//! (`format=json`) run as dork engines on the scan's shared board; VirusTotal, SecurityTrails and
//! GitHub Code Search (keys). Passive.

use std::sync::Mutex;
use std::time::Duration;

use foca_net::{Access, NetError, NetRequest};
use serde_json::Value;

use crate::dorkboard::PageKind;
use crate::rate::{self, Throttle, Verdict};
use crate::source::{DocumentSource, Found, FoundUrl, SearchCtx, SourceKind};
use crate::sources::dorkpool::{run_dorks, DorkBackend, DorkPage};

/// Brave Search API base.
pub const BRAVE_API: &str = "https://api.search.brave.com";
use crate::sources::subdomains::extract_hosts;
use crate::sources::urls::extract_urls;
use crate::BoxFuture;

fn in_domain(url: &str, domain: &str) -> bool {
    url::Url::parse(url)
        .ok()
        .and_then(|u| {
            u.host_str()
                .map(|h| h.trim_end_matches('.').to_ascii_lowercase())
        })
        .is_some_and(|h| h == domain || foca_core::target::is_subdomain_of(&h, domain))
}

fn push(
    found: &mut Found,
    ctx: &SearchCtx,
    domain: &str,
    url: &str,
    source: &str,
    date: Option<String>,
) {
    if !in_domain(url, domain) {
        return;
    }
    if let Some(ext) = ctx.filter.matches(url) {
        let mut f = FoundUrl::new(url, source);
        f.hint_ext = Some(ext);
        f.date = date;
        found.urls.push(f);
    }
}

/// `web.results[].url` (+ `page_age`).
pub fn parse_brave(json: &str) -> Result<Vec<(String, Option<String>)>, NetError> {
    let v: Value = serde_json::from_str(json).map_err(|e| NetError::Parse(e.to_string()))?;
    Ok(v["web"]["results"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|r| {
                    let u = r["url"].as_str()?.to_string();
                    let d = r["page_age"]
                        .as_str()
                        .or(r["age"].as_str())
                        .map(String::from);
                    Some((u, d))
                })
                .collect()
        })
        .unwrap_or_default())
}

/// `results[].url` (+ `publishedDate`).
pub fn parse_searx(json: &str) -> Result<Vec<(String, Option<String>)>, NetError> {
    let v: Value = serde_json::from_str(json).map_err(|e| NetError::Parse(e.to_string()))?;
    Ok(v["results"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|r| {
                    Some((
                        r["url"].as_str()?.to_string(),
                        r["publishedDate"].as_str().map(String::from),
                    ))
                })
                .collect()
        })
        .unwrap_or_default())
}

async fn get_body(ctx: &SearchCtx, req: NetRequest) -> Result<String, NetError> {
    let r = ctx.net.send(req).await?;
    match r.status() {
        401 | 403 => return Err(NetError::NoKey(format!("HTTP {}", r.status()))),
        _ => {}
    }
    let r = r.ensure_success()?;
    r.text_limited(8 * 1024 * 1024).await
}

/// Brave Search API (optional user key): an extra dork engine on the scan's shared board. Brave
/// has no free tier: every plan needs a card and gets a monthly credit of about 1000 queries.
/// 401/403 means the key was rejected (`nokey`), 429 slows down through the throttle and then
/// stops the engine for the scan (`limit`); a spent monthly quota stops it at once.
#[derive(Debug)]
pub struct Brave {
    pub base: String,
    pub key: Option<String>,
    /// Results per page (the API allows up to 20).
    pub count: usize,
    thr: Throttle,
}

impl Brave {
    pub fn new(key: Option<String>) -> Self {
        Brave {
            base: BRAVE_API.into(),
            key: key.map(|k| k.trim().to_string()).filter(|k| !k.is_empty()),
            count: 20,
            // the plans allow one request per second
            thr: Throttle::new(Duration::from_millis(1100)),
        }
    }

    /// Points the engine at another API base (tests, mirrors) without pacing.
    pub fn with_base(mut self, base: &str) -> Self {
        self.base = base.trim_end_matches('/').to_string();
        self.thr = Throttle::new(Duration::ZERO);
        self
    }

    fn search_url(&self, q: &str, page: usize) -> Result<String, NetError> {
        let mut u = url::Url::parse(&format!(
            "{}/res/v1/web/search",
            self.base.trim_end_matches('/')
        ))
        .map_err(|e| NetError::BadUrl(e.to_string()))?;
        u.query_pairs_mut()
            .append_pair("q", q)
            .append_pair("count", &self.count.to_string());
        if page > 1 {
            u.query_pairs_mut()
                .append_pair("offset", &(page - 1).to_string());
        }
        Ok(u.to_string())
    }

    async fn fetch_page(
        &self,
        ctx: &SearchCtx,
        q: &str,
        page: usize,
    ) -> Result<DorkPage, NetError> {
        let key = self
            .key
            .as_deref()
            .ok_or_else(|| NetError::NoKey("brave".into()))?;
        loop {
            self.thr.wait(&ctx.net).await?;
            let req = NetRequest::get(&self.search_url(q, page)?, "brave", Access::Passive)?
                .header("Accept", "application/json")
                .header("X-Subscription-Token", key)
                .timeout(ctx.req_timeout(Duration::from_secs(30)))
                .retries(0);
            let r = ctx.net.send(req).await?;
            match r.status() {
                401 | 403 => return Err(NetError::NoKey(format!("HTTP {}", r.status()))),
                s if rate::is_limit(s) => {
                    let wait = rate::retry_after(&r);
                    let body = r.text_limited(64 * 1024).await.unwrap_or_default();
                    // a spent monthly credit does not come back within the scan
                    if body.to_ascii_uppercase().contains("QUOTA") {
                        return Err(NetError::Status(429));
                    }
                    match self.thr.limited(wait) {
                        Verdict::Retry(_) => {
                            ctx.retrying("brave", 1, &format!("HTTP {s}"));
                            continue;
                        }
                        Verdict::Stop => return Err(NetError::Status(429)),
                    }
                }
                _ => {}
            }
            let body = r.ensure_success()?.text_limited(8 * 1024 * 1024).await?;
            self.thr.ok();
            let v: Value =
                serde_json::from_str(&body).map_err(|e| NetError::Parse(e.to_string()))?;
            let links: Vec<String> = parse_brave(&body)?.into_iter().map(|(u, _)| u).collect();
            return Ok(DorkPage {
                kind: Some(PageKind::Results),
                has_next: v["query"]["more_results_available"].as_bool() == Some(true),
                links,
                why: None,
            });
        }
    }
}

impl DorkBackend for Brave {
    fn engine_id(&self) -> &'static str {
        "brave"
    }
    fn or_ok(&self) -> bool {
        true
    }
    fn max_pages(&self) -> usize {
        2
    }
    fn pause(&self) -> Duration {
        Duration::ZERO
    }
    fn fetch<'a>(
        &'a self,
        ctx: &'a SearchCtx,
        q: &'a str,
        page: usize,
        _first: bool,
    ) -> BoxFuture<'a, Result<DorkPage, NetError>> {
        Box::pin(self.fetch_page(ctx, q, page))
    }
}

impl DocumentSource for Brave {
    fn id(&self) -> &'static str {
        "brave"
    }
    fn name(&self) -> &'static str {
        "Brave Search"
    }
    fn kind(&self) -> SourceKind {
        SourceKind::Passive
    }
    fn needs_key(&self) -> bool {
        true
    }
    fn has_key(&self) -> bool {
        self.key.is_some()
    }
    fn find<'a>(
        &'a self,
        ctx: &'a SearchCtx,
        domain: &'a str,
    ) -> BoxFuture<'a, Result<Found, NetError>> {
        Box::pin(async move {
            if self.key.is_none() {
                return Err(NetError::NoKey("brave".into()));
            }
            let mut f = run_dorks(ctx, domain, self).await?;
            for u in f.urls.iter_mut() {
                u.source = "brave".into();
            }
            Ok(f)
        })
    }
}

/// Splits the SearXNG setting into instance URLs (one per line, or separated by commas, spaces
/// or semicolons), without trailing slashes and duplicates.
pub fn searx_instances(raw: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for p in raw.split(|c: char| c.is_whitespace() || c == ',' || c == ';') {
        let p = p.trim().trim_end_matches('/');
        if !p.is_empty() && !out.iter().any(|o| o == p) {
            out.push(p.to_string());
        }
    }
    out
}

/// The user's own SearXNG instances (`format=json` must be enabled), asked before the public
/// pool. Each instance must be HTTPS on a public host, like other user URLs; an instance that
/// refuses JSON (403) or keeps failing is skipped for the rest of the scan.
#[derive(Debug)]
pub struct Searx {
    pub instances: Vec<String>,
    /// Accept plain HTTP and local hosts (tests; the `--test-net` bench allows them anyway).
    pub allow_local: bool,
    bad: Mutex<Vec<String>>,
    thr: Throttle,
}

impl Searx {
    pub fn new(instance: Option<String>) -> Self {
        Searx {
            instances: instance.as_deref().map(searx_instances).unwrap_or_default(),
            allow_local: false,
            bad: Mutex::new(Vec::new()),
            thr: Throttle::new(Duration::from_millis(1500)),
        }
    }

    /// Instance URLs for tests and the local bench: HTTP and loopback allowed, no pacing.
    pub fn local(instance: &str) -> Self {
        Searx {
            allow_local: true,
            thr: Throttle::new(Duration::ZERO),
            ..Searx::new(Some(instance.into()))
        }
    }

    /// Accept plain HTTP and local hosts (the `--test-net` bench).
    pub fn with_local(mut self, allow: bool) -> Self {
        self.allow_local = allow;
        self
    }

    fn usable(&self, ctx: &SearchCtx, base: &str) -> bool {
        self.allow_local || ctx.net.is_local_only() || public_https_url(base)
    }

    async fn fetch_page(
        &self,
        ctx: &SearchCtx,
        q: &str,
        page: usize,
    ) -> Result<DorkPage, NetError> {
        let mut last: Option<NetError> = None;
        for base in &self.instances {
            if self
                .bad
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .contains(base)
            {
                continue;
            }
            if !self.usable(ctx, base) {
                let host = url::Url::parse(base)
                    .ok()
                    .and_then(|u| u.host_str().map(String::from))
                    .unwrap_or_default();
                let mut rec = ctx.net.draft("searx", "GET", base, &host, &Access::Passive);
                rec.blocked = true;
                rec.error = Some(SEARX_URL_RULE.into());
                ctx.net.record(rec);
                self.bad
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .push(base.clone());
                last = Some(NetError::BadUrl(SEARX_URL_RULE.into()));
                continue;
            }
            let mut u = url::Url::parse(&format!("{base}/search"))
                .map_err(|e| NetError::BadUrl(e.to_string()))?;
            u.query_pairs_mut()
                .append_pair("q", q)
                .append_pair("format", "json")
                .append_pair("pageno", &page.to_string());
            loop {
                self.thr.wait(&ctx.net).await?;
                let req = NetRequest::get(u.as_str(), "searx", Access::Passive)?
                    .header("Accept", "application/json")
                    .timeout(ctx.req_timeout(Duration::from_secs(30)))
                    .retries(0);
                let r = match ctx.net.send(req).await {
                    Ok(r) => r,
                    Err(NetError::Cancelled) => return Err(NetError::Cancelled),
                    Err(e) => {
                        last = Some(e);
                        break;
                    }
                };
                let st = r.status();
                if rate::is_limit(st) {
                    match self.thr.limited(rate::retry_after(&r)) {
                        Verdict::Retry(_) => {
                            ctx.retrying("searx", 1, &format!("HTTP {st}"));
                            continue;
                        }
                        Verdict::Stop => return Err(NetError::Status(429)),
                    }
                }
                if !(200..300).contains(&st) {
                    // 403 is the usual answer of an instance without `format: json`
                    last = Some(NetError::Status(st));
                    break;
                }
                let body = r.text_limited(8 * 1024 * 1024).await?;
                match parse_searx(&body) {
                    Ok(v) => {
                        self.thr.ok();
                        let links: Vec<String> = v.into_iter().map(|(u, _)| u).collect();
                        return Ok(DorkPage {
                            kind: Some(PageKind::Results),
                            has_next: links.len() >= crate::sources::dorkpool::PAGE_FULL,
                            links,
                            why: None,
                        });
                    }
                    Err(e) => {
                        last = Some(e);
                        break;
                    }
                }
            }
            tracing::warn!(target: "foca::source", "searx: {base} не отвечает JSON: следующий экземпляр");
            self.bad
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(base.clone());
        }
        Err(last.unwrap_or_else(|| NetError::NoKey("searx".into())))
    }
}

impl DorkBackend for Searx {
    fn engine_id(&self) -> &'static str {
        "searx"
    }
    fn or_ok(&self) -> bool {
        true
    }
    fn max_pages(&self) -> usize {
        2
    }
    fn pause(&self) -> Duration {
        Duration::ZERO
    }
    fn fetch<'a>(
        &'a self,
        ctx: &'a SearchCtx,
        q: &'a str,
        page: usize,
        _first: bool,
    ) -> BoxFuture<'a, Result<DorkPage, NetError>> {
        Box::pin(self.fetch_page(ctx, q, page))
    }
}

impl DocumentSource for Searx {
    fn id(&self) -> &'static str {
        "searx"
    }
    fn name(&self) -> &'static str {
        "SearXNG"
    }
    fn kind(&self) -> SourceKind {
        SourceKind::Passive
    }
    fn needs_key(&self) -> bool {
        true
    }
    fn has_key(&self) -> bool {
        !self.instances.is_empty()
    }
    fn find<'a>(
        &'a self,
        ctx: &'a SearchCtx,
        domain: &'a str,
    ) -> BoxFuture<'a, Result<Found, NetError>> {
        Box::pin(async move {
            if self.instances.is_empty() {
                return Err(NetError::NoKey("searx".into()));
            }
            run_dorks(ctx, domain, self).await
        })
    }
}

/// Error text for an own SearXNG URL that is not HTTPS on a public host.
pub const SEARX_URL_RULE: &str = "Адрес SearXNG должен использовать HTTPS и публичный хост";

/// Whether a user URL is HTTPS on a public host (no localhost, private or reserved addresses).
pub fn public_https_url(raw: &str) -> bool {
    crate::sources::searx_pool::is_safe_public_instance(raw)
}

/// Result of the key or instance check in Settings.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize)]
pub struct KeyCheck {
    pub ok: bool,
    /// `ok` | `rejected` | `limit` | `json_off` | `bad_url` | `unreachable` | `error`.
    pub code: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,
    /// Requests left in the current month (Brave `X-RateLimit-Remaining`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remaining: Option<u64>,
    /// Monthly request limit (Brave `X-RateLimit-Limit`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<u64>,
    /// Results in the test answer (SearXNG).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub results: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

impl KeyCheck {
    fn new(code: &str) -> Self {
        KeyCheck {
            ok: code == "ok",
            code: code.into(),
            ..Default::default()
        }
    }
}

/// Last number of a Brave rate-limit header (`"1, 2000"`: per second, per month).
fn last_num(v: Option<&str>) -> Option<u64> {
    v?.rsplit(',').next()?.trim().parse().ok()
}

/// Checks a Brave Search API key with one query (`count=1`), reading the monthly quota headers.
pub async fn check_brave(net: &foca_net::NetClient, base: &str, key: &str) -> KeyCheck {
    let b = Brave::new(Some(key.into())).with_base(base);
    let Ok(u) = b.search_url("site:example.com", 1) else {
        return KeyCheck::new("bad_url");
    };
    let req = match NetRequest::get(&u.replace("count=20", "count=1"), "brave", Access::Passive) {
        Ok(r) => r
            .header("Accept", "application/json")
            .header("X-Subscription-Token", key.trim())
            .timeout(Duration::from_secs(20))
            .retries(0),
        Err(_) => return KeyCheck::new("bad_url"),
    };
    match net.send(req).await {
        Ok(r) => {
            let st = r.status();
            let mut k = KeyCheck::new(match st {
                200..=299 => "ok",
                401 | 403 => "rejected",
                429 => "limit",
                _ => "error",
            });
            k.status = Some(st);
            k.remaining = last_num(r.header("x-ratelimit-remaining"));
            k.limit = last_num(r.header("x-ratelimit-limit"));
            k
        }
        Err(e) => KeyCheck {
            detail: Some(e.to_string()),
            ..KeyCheck::new("unreachable")
        },
    }
}

/// Checks own SearXNG instances: each must be HTTPS on a public host and answer a JSON query.
/// Returns one result per instance.
pub async fn check_searx(
    net: &foca_net::NetClient,
    raw: &str,
    allow_local: bool,
) -> Vec<(String, KeyCheck)> {
    let mut out = Vec::new();
    for base in searx_instances(raw) {
        if !allow_local && !public_https_url(&base) {
            out.push((
                base,
                KeyCheck {
                    detail: Some(SEARX_URL_RULE.into()),
                    ..KeyCheck::new("bad_url")
                },
            ));
            continue;
        }
        let u = format!("{base}/search?q=test&format=json");
        let req = match NetRequest::get(&u, "searx", Access::Passive) {
            Ok(r) => r
                .header("Accept", "application/json")
                .timeout(Duration::from_secs(20))
                .retries(0),
            Err(_) => {
                out.push((base, KeyCheck::new("bad_url")));
                continue;
            }
        };
        let k = match net.send(req).await {
            Ok(r) => {
                let st = r.status();
                if (200..300).contains(&st) {
                    let body = r.text_limited(4 * 1024 * 1024).await.unwrap_or_default();
                    match parse_searx(&body) {
                        Ok(v) => KeyCheck {
                            status: Some(st),
                            results: Some(v.len()),
                            ..KeyCheck::new("ok")
                        },
                        Err(_) => KeyCheck {
                            status: Some(st),
                            ..KeyCheck::new("json_off")
                        },
                    }
                } else {
                    KeyCheck {
                        status: Some(st),
                        ..KeyCheck::new(match st {
                            403 => "json_off",
                            429 => "limit",
                            _ => "error",
                        })
                    }
                }
            }
            Err(e) => KeyCheck {
                detail: Some(e.to_string()),
                ..KeyCheck::new("unreachable")
            },
        };
        out.push((base, k));
    }
    out
}

/// Parses a VirusTotal API v3 response (`/domains/{d}/subdomains` or `/domains/{d}/urls`),
/// returning `(hosts, urls)` belonging to `domain`.
pub fn parse_vt(json: &str, domain: &str) -> Result<(Vec<String>, Vec<String>), NetError> {
    let v: Value = serde_json::from_str(json).map_err(|e| NetError::Parse(e.to_string()))?;
    let mut hosts = extract_hosts(json, domain);
    let mut urls = Vec::new();
    if let Some(arr) = v["data"].as_array() {
        for item in arr {
            if let Some(id) = item["id"].as_str() {
                if id.starts_with("http://") || id.starts_with("https://") {
                    if in_domain(id, domain) {
                        urls.push(id.to_string());
                    }
                } else {
                    for h in extract_hosts(id, domain) {
                        if !hosts.contains(&h) {
                            hosts.push(h);
                        }
                    }
                }
            }
            if let Some(u) = item["attributes"]["url"].as_str() {
                if in_domain(u, domain) {
                    urls.push(u.to_string());
                }
            }
        }
    }
    for u in extract_urls(json) {
        if in_domain(&u, domain) && !urls.contains(&u) {
            urls.push(u);
        }
    }
    hosts.sort();
    hosts.dedup();
    urls.sort();
    urls.dedup();
    Ok((hosts, urls))
}

/// VirusTotal API v3 passive collector.
#[derive(Debug, Clone)]
pub struct VirusTotal {
    pub base: String,
    pub key: Option<String>,
}

impl VirusTotal {
    pub fn new(key: Option<String>) -> Self {
        Self {
            base: "https://www.virustotal.com".into(),
            key: key.map(|k| k.trim().to_string()).filter(|k| !k.is_empty()),
        }
    }

    pub fn with_base(mut self, base: &str) -> Self {
        self.base = base.trim_end_matches('/').to_string();
        self
    }
}

impl DocumentSource for VirusTotal {
    fn id(&self) -> &'static str {
        "vt"
    }
    fn name(&self) -> &'static str {
        "VirusTotal"
    }
    fn kind(&self) -> SourceKind {
        SourceKind::Passive
    }
    fn needs_key(&self) -> bool {
        true
    }
    fn has_key(&self) -> bool {
        self.key.is_some()
    }
    fn find<'a>(
        &'a self,
        ctx: &'a SearchCtx,
        domain: &'a str,
    ) -> BoxFuture<'a, Result<Found, NetError>> {
        Box::pin(async move {
            let key = self
                .key
                .as_deref()
                .ok_or_else(|| NetError::NoKey("vt".into()))?;
            let mut found = Found::default();
            let base = self.base.trim_end_matches('/');
            let sub_url = format!("{base}/api/v3/domains/{domain}/subdomains?limit=40");
            let req1 = NetRequest::get(&sub_url, "vt", Access::Passive)?
                .header("Accept", "application/json")
                .header("x-apikey", key);
            let body1 = get_body(ctx, req1).await?;
            let (h1, u1) = parse_vt(&body1, domain)?;
            found.hosts.extend(h1);
            for u in u1 {
                push(&mut found, ctx, domain, &u, "vt", None);
            }

            let urls_ep = format!("{base}/api/v3/domains/{domain}/urls?limit=40");
            if let Ok(req2) = NetRequest::get(&urls_ep, "vt", Access::Passive) {
                let req2 = req2
                    .header("Accept", "application/json")
                    .header("x-apikey", key);
                if let Ok(body2) = get_body(ctx, req2).await {
                    if let Ok((h2, u2)) = parse_vt(&body2, domain) {
                        for h in h2 {
                            if !found.hosts.contains(&h) {
                                found.hosts.push(h);
                            }
                        }
                        for u in u2 {
                            push(&mut found, ctx, domain, &u, "vt", None);
                        }
                    }
                }
            }
            found.hosts.sort();
            found.hosts.dedup();
            Ok(found)
        })
    }
}

/// Parses a SecurityTrails `/v1/domain/{d}/subdomains` response (`{"subdomains":["api","dev"]}`).
pub fn parse_securitytrails(json: &str, domain: &str) -> Result<Vec<String>, NetError> {
    let v: Value = serde_json::from_str(json).map_err(|e| NetError::Parse(e.to_string()))?;
    let dom = domain.trim().trim_end_matches('.').to_ascii_lowercase();
    let mut hosts = extract_hosts(json, &dom);
    if let Some(arr) = v["subdomains"].as_array() {
        for item in arr {
            if let Some(sub) = item.as_str() {
                let sub = sub.trim().trim_matches('.').to_ascii_lowercase();
                if !sub.is_empty() {
                    let fqdn = if sub.ends_with(&format!(".{dom}")) || sub == dom {
                        sub
                    } else {
                        format!("{sub}.{dom}")
                    };
                    for h in extract_hosts(&fqdn, &dom) {
                        if !hosts.contains(&h) {
                            hosts.push(h);
                        }
                    }
                }
            }
        }
    }
    hosts.sort();
    hosts.dedup();
    Ok(hosts)
}

/// SecurityTrails passive subdomain collector.
#[derive(Debug, Clone)]
pub struct SecurityTrails {
    pub base: String,
    pub key: Option<String>,
}

impl SecurityTrails {
    pub fn new(key: Option<String>) -> Self {
        Self {
            base: "https://api.securitytrails.com".into(),
            key: key.map(|k| k.trim().to_string()).filter(|k| !k.is_empty()),
        }
    }

    pub fn with_base(mut self, base: &str) -> Self {
        self.base = base.trim_end_matches('/').to_string();
        self
    }
}

impl DocumentSource for SecurityTrails {
    fn id(&self) -> &'static str {
        "st"
    }
    fn name(&self) -> &'static str {
        "SecurityTrails"
    }
    fn kind(&self) -> SourceKind {
        SourceKind::Passive
    }
    fn needs_key(&self) -> bool {
        true
    }
    fn has_key(&self) -> bool {
        self.key.is_some()
    }
    fn find<'a>(
        &'a self,
        ctx: &'a SearchCtx,
        domain: &'a str,
    ) -> BoxFuture<'a, Result<Found, NetError>> {
        Box::pin(async move {
            let key = self
                .key
                .as_deref()
                .ok_or_else(|| NetError::NoKey("st".into()))?;
            let url = format!(
                "{}/v1/domain/{domain}/subdomains?children_only=false",
                self.base.trim_end_matches('/')
            );
            let req = NetRequest::get(&url, "st", Access::Passive)?
                .header("Accept", "application/json")
                .header("APIKEY", key);
            let body = get_body(ctx, req).await?;
            let hosts = parse_securitytrails(&body, domain)?;
            Ok(Found {
                urls: vec![],
                hosts,
                note: None,
            })
        })
    }
}

/// Parses a GitHub Code Search `/search/code` JSON response, extracting subdomains and document
/// URLs belonging to `domain` from `items[].text_matches[].fragment` and `items[]`.
pub fn parse_github_code(json: &str, domain: &str) -> Result<(Vec<String>, Vec<String>), NetError> {
    let _: Value = serde_json::from_str(json).map_err(|e| NetError::Parse(e.to_string()))?;
    let hosts = extract_hosts(json, domain);
    let urls: Vec<String> = extract_urls(json)
        .into_iter()
        .filter(|u| in_domain(u, domain))
        .collect();
    Ok((hosts, urls))
}

/// GitHub Code Search passive collector.
#[derive(Debug, Clone)]
pub struct GitHubCode {
    pub base: String,
    pub key: Option<String>,
}

impl GitHubCode {
    pub fn new(key: Option<String>) -> Self {
        Self {
            base: "https://api.github.com".into(),
            key: key.map(|k| k.trim().to_string()).filter(|k| !k.is_empty()),
        }
    }

    pub fn with_base(mut self, base: &str) -> Self {
        self.base = base.trim_end_matches('/').to_string();
        self
    }
}

impl DocumentSource for GitHubCode {
    fn id(&self) -> &'static str {
        "github"
    }
    fn name(&self) -> &'static str {
        "GitHub Code Search"
    }
    fn kind(&self) -> SourceKind {
        SourceKind::Passive
    }
    fn needs_key(&self) -> bool {
        true
    }
    fn has_key(&self) -> bool {
        self.key.is_some()
    }
    fn find<'a>(
        &'a self,
        ctx: &'a SearchCtx,
        domain: &'a str,
    ) -> BoxFuture<'a, Result<Found, NetError>> {
        Box::pin(async move {
            let key = self
                .key
                .as_deref()
                .ok_or_else(|| NetError::NoKey("github".into()))?;
            let mut u =
                url::Url::parse(&format!("{}/search/code", self.base.trim_end_matches('/')))
                    .map_err(|e| NetError::BadUrl(e.to_string()))?;
            u.query_pairs_mut()
                .append_pair("q", &format!("\"{domain}\""))
                .append_pair("per_page", "30");
            let req = NetRequest::get(u.as_str(), "github", Access::Passive)?
                .header("Accept", "application/vnd.github.text-match+json")
                .header("Authorization", &format!("Bearer {key}"));
            let body = get_body(ctx, req).await?;
            let (hosts, urls) = parse_github_code(&body, domain)?;
            let mut found = Found {
                urls: vec![],
                hosts,
                note: None,
            };
            for link in urls {
                push(&mut found, ctx, domain, &link, "github", None);
            }
            Ok(found)
        })
    }
}
