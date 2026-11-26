//! Crawler for the target site (`TouchesTarget`): robots.txt, sitemap.xml and breadth-first link
//! traversal up to depth N with a page limit, restricted to hosts in scope (`NetClient`
//! additionally checks every request and redirect). Documents are not downloaded here; only
//! their URLs are collected.

use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};
use std::time::Duration;

use foca_net::{Access, NetError, NetRequest};
use serde::{Deserialize, Serialize};
use url::Url;

use crate::filter::{ext_of_url, normalize_url};
use crate::html::{extract_links, parse_sitemap, Robots};
use crate::source::{DocumentSource, Found, FoundUrl, SearchCtx, SourceKind};
use crate::BoxFuture;

const PAGE_EXTS: &[&str] = &[
    "html", "htm", "xhtml", "shtml", "php", "asp", "aspx", "jsp", "jspx", "cfm", "do", "action",
    "pl",
];

#[derive(Debug, Clone)]
pub struct Crawler {
    /// Explicit start URLs (otherwise `https://<domain>/` and the known hosts from `ctx.hosts`).
    pub start_urls: Vec<String>,
    pub max_depth: usize,
    pub max_pages: usize,
    pub respect_robots: bool,
    pub use_sitemap: bool,
    pub max_sitemaps: usize,
    pub max_page_bytes: u64,
    /// Token matched against robots.txt `User-agent` groups.
    pub agent: String,
    /// Maximum number of start hosts taken from `ctx.hosts`.
    pub max_hosts: usize,
}

impl Default for Crawler {
    fn default() -> Self {
        Crawler {
            start_urls: Vec::new(),
            max_depth: 2,
            max_pages: 200,
            respect_robots: true,
            use_sitemap: true,
            max_sitemaps: 10,
            max_page_bytes: 3 * 1024 * 1024,
            agent: "FOCA-rs".into(),
            max_hosts: 20,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrawlStats {
    pub pages: usize,
    pub sitemaps: usize,
    pub robots_skipped: usize,
    pub scope_skipped: usize,
    pub errors: usize,
}

fn origin(u: &Url) -> String {
    u.origin().ascii_serialization()
}

fn host(u: &Url) -> String {
    u.host_str().unwrap_or("").to_string()
}

/// Returns `true` for a junk link whose path embeds another URL (`/https://site/...`,
/// `/https:/site/...`, `/http%3A//...`). `base.join` produces these from hrefs like
/// `/https://...` or broken CMS links, and servers redirect to more of the same, so they are skipped.
pub(crate) fn junk_link(u: &Url) -> bool {
    let p = u.path().to_ascii_lowercase().replace("%3a", ":");
    p.contains("/http:/") || p.contains("/https:/")
}

/// Returns the visited-page key (the normalized URL, or the URL as is).
fn visit_key(u: &Url) -> String {
    normalize_url(u.as_str()).unwrap_or_else(|| u.to_string())
}

fn looks_like_page(u: &Url) -> bool {
    match ext_of_url(u.as_str()) {
        None => true,
        Some(e) => PAGE_EXTS.contains(&e.as_str()),
    }
}

/// Outcome of a single crawler request.
enum Fetch {
    /// 2xx with a body (final URL after redirects).
    Body(Url, String),
    /// The server answered, but not with 2xx HTML.
    Answered,
    /// Blocked by the scope.
    Denied,
    /// Network failure: timeout, connection refused, TLS.
    Failed,
}

async fn fetch(
    ctx: &SearchCtx,
    u: &Url,
    limit: u64,
    need_html: bool,
    timeout: Duration,
    retries: u32,
) -> Result<Fetch, NetError> {
    let req = NetRequest::get(u.as_str(), "crawler", Access::TouchesTarget)?
        .timeout(ctx.req_timeout(timeout))
        .retries(retries);
    let r = match ctx.net.send(req).await {
        Ok(r) => r,
        Err(NetError::Cancelled) => return Err(NetError::Cancelled),
        Err(e) if e.is_scope_denial() => return Ok(Fetch::Denied),
        Err(_) => return Ok(Fetch::Failed),
    };
    if !r.is_success() {
        return Ok(Fetch::Answered);
    }
    if need_html {
        let ct = r.content_type().unwrap_or("").to_ascii_lowercase();
        if !ct.is_empty() && !ct.contains("html") {
            r.abort();
            return Ok(Fetch::Answered);
        }
    }
    let final_url = r.url().clone();
    match r.text_limited(limit).await {
        Ok(t) => Ok(Fetch::Body(final_url, t)),
        Err(NetError::Cancelled) => Err(NetError::Cancelled),
        Err(_) => Ok(Fetch::Failed),
    }
}

/// Timeout for pages and auxiliary files (robots/sitemap get a single attempt).
const PAGE_TIMEOUT: Duration = Duration::from_secs(20);
const AUX_TIMEOUT: Duration = Duration::from_secs(10);
/// Timeout for probing the start page scheme: short and without retries (a closed 443, an expired
/// certificate or a refused connection falls back to http right away).
const PROBE_TIMEOUT: Duration = Duration::from_secs(8);

struct State<'a> {
    ctx: &'a SearchCtx,
    robots: HashMap<String, Option<Robots>>,
    found: Vec<FoundUrl>,
    found_set: HashSet<String>,
    stats: CrawlStats,
}

impl<'a> State<'a> {
    fn add_doc(&mut self, u: &Url) -> bool {
        let Some(ext) = self.ctx.filter.matches(u.as_str()) else {
            return false;
        };
        if !self.ctx.net.host_in_scope(&host(u)) {
            return true;
        }
        let n = normalize_url(u.as_str()).unwrap_or_else(|| u.to_string());
        if self.found_set.insert(crate::filter::dedup_key(&n)) {
            let mut f = FoundUrl::new(&n, "crawler");
            f.hint_ext = Some(ext);
            // documents downloaded in earlier scans do not count against the limit
            if !self.ctx.is_known(&f) {
                self.found.push(f);
            }
        }
        true
    }

    fn note(&mut self, f: Fetch) -> Option<(Url, String)> {
        match f {
            Fetch::Body(u, t) => Some((u, t)),
            Fetch::Answered => None,
            Fetch::Denied => {
                self.stats.scope_skipped += 1;
                None
            }
            Fetch::Failed => {
                self.stats.errors += 1;
                None
            }
        }
    }

    async fn get_text(
        &mut self,
        u: &Url,
        limit: u64,
        need_html: bool,
        timeout: Duration,
        retries: u32,
    ) -> Result<Option<(Url, String)>, NetError> {
        let f = fetch(self.ctx, u, limit, need_html, timeout, retries).await?;
        Ok(self.note(f))
    }

    async fn robots_for(&mut self, crawler: &Crawler, u: &Url) -> Result<Option<Robots>, NetError> {
        let o = origin(u);
        if let Some(r) = self.robots.get(&o) {
            return Ok(r.clone());
        }
        let ru =
            Url::parse(&format!("{o}/robots.txt")).map_err(|e| NetError::BadUrl(e.to_string()))?;
        let r = self
            .get_text(&ru, 512 * 1024, false, AUX_TIMEOUT, 0)
            .await?
            .map(|(_, t)| Robots::parse(&t, &crawler.agent));
        self.robots.insert(o, r.clone());
        Ok(r)
    }
}

impl Crawler {
    pub fn with_start(url: &str) -> Self {
        Crawler {
            start_urls: vec![url.to_string()],
            ..Default::default()
        }
    }

    /// Limits how many links deep the crawl follows from the start pages.
    pub fn with_max_depth(mut self, max_depth: usize) -> Self {
        self.max_depth = max_depth;
        self
    }

    /// Picks the host scheme: https with a short timeout, falling back to http on a network error.
    /// Returns the start page (if it is HTML) and whether the server answered at all.
    async fn pick_origin(
        &self,
        st: &mut State<'_>,
        h: &str,
    ) -> Result<Option<(Url, Option<(Url, String)>)>, NetError> {
        for scheme in ["https", "http"] {
            let Ok(u) = Url::parse(&format!("{scheme}://{h}/")) else {
                continue;
            };
            match fetch(st.ctx, &u, self.max_page_bytes, true, PROBE_TIMEOUT, 0).await? {
                Fetch::Body(fu, t) => return Ok(Some((u, Some((fu, t))))),
                Fetch::Answered => return Ok(Some((u, None))),
                Fetch::Denied => {
                    st.stats.scope_skipped += 1;
                    return Ok(None);
                }
                Fetch::Failed => st.stats.errors += 1,
            }
        }
        Ok(None)
    }

    /// Fetches the origin's robots.txt and sitemap.xml in parallel, one attempt each.
    async fn origin_aux(
        &self,
        st: &mut State<'_>,
        o: &Url,
        queue: &mut VecDeque<(Url, usize)>,
    ) -> Result<(), NetError> {
        let key = origin(o);
        let ru = o
            .join("/robots.txt")
            .map_err(|e| NetError::BadUrl(e.to_string()))?;
        let su = o
            .join("/sitemap.xml")
            .map_err(|e| NetError::BadUrl(e.to_string()))?;
        let want_robots = self.respect_robots && !st.robots.contains_key(&key);
        let ctx = st.ctx;
        let (r, s) = tokio::join!(
            async {
                if want_robots || self.use_sitemap {
                    fetch(ctx, &ru, 512 * 1024, false, AUX_TIMEOUT, 0).await
                } else {
                    Ok(Fetch::Answered)
                }
            },
            async {
                if self.use_sitemap {
                    fetch(ctx, &su, 16 * 1024 * 1024, false, AUX_TIMEOUT, 0).await
                } else {
                    Ok(Fetch::Answered)
                }
            }
        );
        let robots = st.note(r?).map(|(_, t)| Robots::parse(&t, &self.agent));
        st.robots.insert(key, robots.clone());
        if self.use_sitemap {
            let first = st.note(s?);
            let maps = robots.map(|r| r.other_sitemaps(o, &su)).unwrap_or_default();
            self.sitemaps(st, o, first.map(|(_, x)| (su.clone(), x)), maps, queue)
                .await?;
        }
        Ok(())
    }

    /// Crawls and returns the discovered documents and statistics. The time budget is the source's
    /// soft deadline (`ctx.deadline`); once it passes, whatever was collected is returned.
    pub async fn crawl(
        &self,
        ctx: &SearchCtx,
        domain: &str,
    ) -> Result<(Found, CrawlStats), NetError> {
        let mut st = State {
            ctx,
            robots: HashMap::new(),
            found: Vec::new(),
            found_set: HashSet::new(),
            stats: CrawlStats::default(),
        };
        let mut queue: VecDeque<(Url, usize)> = VecDeque::new();
        let mut visited: HashSet<String> = HashSet::new();
        let mut sitemap_origins: HashSet<String> = HashSet::new();
        let mut first_pages: Vec<(Url, String)> = Vec::new();
        if self.start_urls.is_empty() {
            let mut hosts: BTreeSet<String> = BTreeSet::new();
            hosts.insert(domain.to_ascii_lowercase());
            hosts.extend(ctx.hosts.iter().take(self.max_hosts).cloned());
            for h in hosts {
                if ctx.net.is_cancelled() {
                    return Err(NetError::Cancelled);
                }
                if ctx.out_of_time(Duration::from_secs(3)) {
                    break;
                }
                if !ctx.net.host_in_scope(&h) {
                    st.stats.scope_skipped += 1;
                    continue;
                }
                // the host was already reached as another host's redirect target (test. -> www.test.), skip it
                if ["https", "http"].iter().any(|s| {
                    Url::parse(&format!("{s}://{h}/"))
                        .is_ok_and(|u| visited.contains(&visit_key(&u)))
                }) {
                    continue;
                }
                let Some((o, page)) = self.pick_origin(&mut st, &h).await? else {
                    continue;
                };
                visited.insert(visit_key(&o));
                // robots.txt/sitemap.xml are fetched once per origin, from the final origin after redirects
                // (www. -> bare domain)
                let eff = match &page {
                    Some((fu, _)) => fu.join("/").unwrap_or_else(|_| o.clone()),
                    None => o.clone(),
                };
                if sitemap_origins.insert(origin(&eff)) {
                    self.origin_aux(&mut st, &eff, &mut queue).await?;
                }
                sitemap_origins.insert(origin(&o));
                if let Some(p) = page {
                    if visited.insert(visit_key(&p.0)) || p.0 == o {
                        st.stats.pages += 1;
                        first_pages.push(p);
                    }
                }
            }
        } else {
            for s in self.start_urls.iter().filter_map(|s| Url::parse(s).ok()) {
                queue.push_back((s, 0));
            }
        }
        for (final_url, body) in first_pages {
            self.links(&mut st, &final_url, &body, 0, &mut queue);
        }
        while let Some((u, depth)) = queue.pop_front() {
            if ctx.net.is_cancelled() {
                return Err(NetError::Cancelled);
            }
            if st.stats.pages >= self.max_pages
                || st.found.len() >= ctx.limit
                || ctx.out_of_time(Duration::from_secs(3))
            {
                break;
            }
            if !visited.insert(visit_key(&u)) {
                continue;
            }
            if !ctx.net.host_in_scope(&host(&u)) {
                st.stats.scope_skipped += 1;
                continue;
            }
            if self.respect_robots {
                if let Some(r) = st.robots_for(self, &u).await? {
                    let pq = match u.query() {
                        Some(q) => format!("{}?{q}", u.path()),
                        None => u.path().to_string(),
                    };
                    if !r.allowed(&pq) {
                        st.stats.robots_skipped += 1;
                        continue;
                    }
                }
            }
            if self.use_sitemap && sitemap_origins.insert(origin(&u)) {
                self.origin_aux(&mut st, &u, &mut queue).await?;
            }
            let Some((final_url, body)) = st
                .get_text(&u, self.max_page_bytes, true, PAGE_TIMEOUT, 1)
                .await?
            else {
                continue;
            };
            // the final URL after a redirect also counts as visited (canonical dedup)
            if final_url != u && !visited.insert(visit_key(&final_url)) {
                continue;
            }
            st.stats.pages += 1;
            self.links(&mut st, &final_url, &body, depth, &mut queue);
        }
        let mut found = Found {
            urls: st.found,
            hosts: vec![],
            note: None,
        };
        found.urls.truncate(ctx.limit);
        Ok((found, st.stats))
    }

    fn links(
        &self,
        st: &mut State<'_>,
        page: &Url,
        body: &str,
        depth: usize,
        queue: &mut VecDeque<(Url, usize)>,
    ) {
        for l in extract_links(body, page) {
            if junk_link(&l) {
                continue;
            }
            if st.add_doc(&l) {
                continue;
            }
            if depth < self.max_depth && looks_like_page(&l) {
                if st.ctx.net.host_in_scope(&host(&l)) {
                    queue.push_back((l, depth + 1));
                } else {
                    st.stats.scope_skipped += 1;
                }
            }
        }
    }

    /// Collects sitemaps: the already fetched `first` (usually /sitemap.xml), then those from robots
    /// and nested ones (sitemap index), one attempt each and at most `max_sitemaps`.
    async fn sitemaps(
        &self,
        st: &mut State<'_>,
        base: &Url,
        first: Option<(Url, String)>,
        mut maps: VecDeque<String>,
        queue: &mut VecDeque<(Url, usize)>,
    ) -> Result<(), NetError> {
        let mut seen = HashSet::new();
        let mut pending: VecDeque<(Url, String)> = first.into_iter().collect();
        loop {
            let (mu, xml) = match pending.pop_front() {
                Some(x) => x,
                None => {
                    let Some(m) = maps.pop_front() else { break };
                    if st.stats.sitemaps >= self.max_sitemaps
                        || st.ctx.out_of_time(Duration::from_secs(5))
                    {
                        break;
                    }
                    let Ok(mu) = base.join(&m) else { continue };
                    if !seen.insert(mu.to_string()) {
                        continue;
                    }
                    if !st.ctx.net.host_in_scope(&host(&mu)) {
                        st.stats.scope_skipped += 1;
                        continue;
                    }
                    let Some((_, xml)) = st
                        .get_text(&mu, 16 * 1024 * 1024, false, AUX_TIMEOUT, 0)
                        .await?
                    else {
                        continue;
                    };
                    (mu, xml)
                }
            };
            seen.insert(mu.to_string());
            st.stats.sitemaps += 1;
            let (locs, is_index) = parse_sitemap(&xml);
            for l in locs {
                if is_index {
                    maps.push_back(l);
                    continue;
                }
                let Ok(lu) = mu.join(l.trim()) else { continue };
                if junk_link(&lu) {
                    continue;
                }
                if !st.add_doc(&lu) && looks_like_page(&lu) && self.max_depth >= 1 {
                    queue.push_back((lu, 1));
                }
            }
        }
        Ok(())
    }
}

impl DocumentSource for Crawler {
    fn id(&self) -> &'static str {
        "crawler"
    }
    fn name(&self) -> &'static str {
        "Обход сайта"
    }
    fn kind(&self) -> SourceKind {
        SourceKind::TouchesTarget
    }
    fn find<'a>(
        &'a self,
        ctx: &'a SearchCtx,
        domain: &'a str,
    ) -> BoxFuture<'a, Result<Found, NetError>> {
        Box::pin(async move { self.crawl(ctx, domain).await.map(|x| x.0) })
    }
}
