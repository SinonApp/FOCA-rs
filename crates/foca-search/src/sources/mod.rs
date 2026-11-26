//! Document sources.

mod archive;
mod crawler;
pub mod dorkpool;
mod engines;
mod render_engines;
pub mod searx_pool;
mod subdomains;
mod urls;

pub use crate::dorkboard::{
    engine_journal, DorkBoard, DorkCache, EngineStat, PageKind, CAPTCHA_WHY, VERIFY_WHY,
};
pub use crate::filter::url_in_domain;
pub use crate::source::BLOCKED;
pub use archive::{
    copy_url, mime_regex, page_plan, parse_cc_ndjson, parse_cdx_json, CdxRow, CommonCrawl, CrtSh,
    Wayback, WAYBACK_FL,
};
pub use crawler::{CrawlStats, Crawler};
pub use engines::{
    parse_brave, parse_github_code, parse_searx, parse_securitytrails, parse_vt, Brave, GitHubCode,
    Searx, SecurityTrails, VirusTotal,
};
pub use render_engines::{
    classify, detect_captcha_signals, parse_brave_web, parse_mojeek, parse_startpage, parse_yahoo,
    startpage_has_next, verify_url, CaptchaSignals, RenderDork, RenderEngine, CAPTCHA_ABORT,
    RENDER_SOURCES,
};
pub use searx_pool::{parse_searx_html, parse_searx_space, SearxPool};
pub use subdomains::{extract_hosts, host_source, HostSource, HOST_SOURCES};
pub use urls::{
    extract_urls, url_source, url_source_with_base, Dork, DorkEngine, UrlKind, UrlSource,
    URL_SOURCES,
};

use crate::source::DocumentSource;

/// Keys and instance URLs for sources (from the settings / Keystore).
#[derive(Debug, Clone, Default)]
pub struct SourceKeys {
    pub brave: Option<String>,
    /// SearXNG instance URL.
    pub searx: Option<String>,
    /// VirusTotal API v3 key.
    pub vt: Option<String>,
    /// SecurityTrails API key.
    pub st: Option<String>,
    /// GitHub personal access token for Code Search API.
    pub github: Option<String>,
}

/// Builds sources from identifiers (`wayback,cc,crt,crawler,brave,searx,vt,st,github`; `crtsh` is a synonym for
/// `crt`). Unknown identifiers are returned as the second element; the retired `gcse` (Google CSE)
/// is silently skipped so old projects and settings still load.
pub fn by_ids(ids: &[String], keys: &SourceKeys) -> (Vec<Box<dyn DocumentSource>>, Vec<String>) {
    let mut out: Vec<Box<dyn DocumentSource>> = Vec::new();
    let mut unknown = Vec::new();
    for id in ids {
        match id.trim().to_ascii_lowercase().as_str() {
            "wayback" => out.push(Box::new(Wayback::default())),
            "cc" | "commoncrawl" => out.push(Box::new(CommonCrawl::default())),
            "crt" | "crtsh" => out.push(Box::new(CrtSh::default())),
            "crawler" => out.push(Box::new(Crawler::default())),
            "brave" => out.push(Box::new(Brave::new(keys.brave.clone()))),
            "searx" | "searxng" => out.push(Box::new(Searx::new(keys.searx.clone()))),
            "vt" | "virustotal" => out.push(Box::new(VirusTotal::new(keys.vt.clone()))),
            "st" | "securitytrails" => out.push(Box::new(SecurityTrails::new(keys.st.clone()))),
            "github" => out.push(Box::new(GitHubCode::new(keys.github.clone()))),
            "" | "gcse" => {}
            other => match (host_source(other), url_source(other)) {
                (Some(h), _) => out.push(Box::new(h)),
                (None, Some(u)) => out.push(u),
                _ => unknown.push(other.to_string()),
            },
        }
    }
    (out, unknown)
}

/// Default passive sources (no target contact, no keys).
pub const DEFAULT_PASSIVE: &[&str] = &["crt", "wayback", "cc"];
