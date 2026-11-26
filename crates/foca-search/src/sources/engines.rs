//! Search APIs (no HTML scraping): Brave Search API (key) and SearXNG (instance URL,
//! `format=json`). Queries have the form `site:domain filetype:ext`. Passive.

use foca_net::{Access, NetError, NetRequest};
use serde_json::Value;

use crate::source::{DocumentSource, Found, FoundUrl, SearchCtx, SourceKind};
use crate::sources::subdomains::extract_hosts;
use crate::sources::urls::extract_urls;
use crate::BoxFuture;

/// File types used for search engine queries (intersected with the context filter).
pub const ENGINE_EXTS: &[&str] = &[
    "pdf", "docx", "doc", "xlsx", "xls", "pptx", "ppt", "odt", "rtf",
];

fn exts_for(ctx: &SearchCtx, max: usize) -> Vec<&'static str> {
    ENGINE_EXTS
        .iter()
        .copied()
        .filter(|e| ctx.filter.allows_ext(e))
        .take(max)
        .collect()
}

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

/// Brave Search API.
#[derive(Debug, Clone)]
pub struct Brave {
    pub base: String,
    pub key: Option<String>,
    /// Number of queries (file types) per domain.
    pub max_queries: usize,
}

impl Brave {
    pub fn new(key: Option<String>) -> Self {
        Brave {
            base: "https://api.search.brave.com".into(),
            key: key.filter(|k| !k.trim().is_empty()),
            max_queries: 6,
        }
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
            let key = self
                .key
                .as_deref()
                .ok_or_else(|| NetError::NoKey("brave".into()))?;
            let mut found = Found::default();
            for ext in exts_for(ctx, self.max_queries) {
                let mut u = url::Url::parse(&format!(
                    "{}/res/v1/web/search",
                    self.base.trim_end_matches('/')
                ))
                .map_err(|e| NetError::BadUrl(e.to_string()))?;
                u.query_pairs_mut()
                    .append_pair("q", &format!("site:{domain} filetype:{ext}"))
                    .append_pair("count", "20");
                let req = NetRequest::get(u.as_str(), "brave", Access::Passive)?
                    .header("Accept", "application/json")
                    .header("X-Subscription-Token", key);
                let body = get_body(ctx, req).await?;
                for (url, date) in parse_brave(&body)? {
                    push(&mut found, ctx, domain, &url, "brave", date);
                }
                if found.urls.len() >= ctx.limit {
                    break;
                }
            }
            Ok(found)
        })
    }
}

/// SearXNG (the instance must allow `format=json`).
#[derive(Debug, Clone)]
pub struct Searx {
    pub instance: Option<String>,
    pub max_queries: usize,
}

impl Searx {
    pub fn new(instance: Option<String>) -> Self {
        Searx {
            instance: instance.filter(|k| !k.trim().is_empty()),
            max_queries: 6,
        }
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
        self.instance.is_some()
    }
    fn find<'a>(
        &'a self,
        ctx: &'a SearchCtx,
        domain: &'a str,
    ) -> BoxFuture<'a, Result<Found, NetError>> {
        Box::pin(async move {
            let inst = self
                .instance
                .as_deref()
                .ok_or_else(|| NetError::NoKey("searx".into()))?;
            let mut found = Found::default();
            for ext in exts_for(ctx, self.max_queries) {
                let mut u = url::Url::parse(&format!("{}/search", inst.trim_end_matches('/')))
                    .map_err(|e| NetError::BadUrl(e.to_string()))?;
                u.query_pairs_mut()
                    .append_pair("q", &format!("site:{domain} filetype:{ext}"))
                    .append_pair("format", "json")
                    .append_pair("pageno", "1");
                let req = NetRequest::get(u.as_str(), "searx", Access::Passive)?
                    .header("Accept", "application/json");
                let body = get_body(ctx, req).await?;
                for (url, date) in parse_searx(&body)? {
                    push(&mut found, ctx, domain, &url, "searx", date);
                }
                if found.urls.len() >= ctx.limit {
                    break;
                }
            }
            Ok(found)
        })
    }
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
