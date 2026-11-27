//! Crawler for the target site (`TouchesTarget`): breadth-first link traversal restricted to
//! hosts in scope (`NetClient` additionally checks every request and redirect).
//!
//! * Seeds: the target URLs, `Sitemap:` lines of robots.txt, `/sitemap.xml` (sitemap indexes and
//!   gzip included), and the unfinished frontier of the previous scan ([`Frontier`]).
//! * Limits: depth, pages and wall time ([`Crawler::max_depth`], [`Crawler::max_pages`],
//!   [`Crawler::max_time`]); what is left goes back to the frontier for the next scan.
//! * Trap protection: links are cleaned and capped per path template ([`crate::crawl::trap`]);
//!   logout/delete-like links are never followed; `rel=nofollow` is honoured on request.
//! * Pace: a bounded number of requests per host at once on top of the client's rate limit; a
//!   429/503 halves the host's rate and repeated ones stop the host ([`crate::crawl::pace`]).
//! * JavaScript apps: a page that looks like an app shell is rendered through the platform
//!   browser ([`SearchCtx::render`]) up to [`Crawler::max_rendered`] pages; without a browser
//!   (desktop, CLI) the page is used as is.
//! * Output: document URLs as [`Found`], plus files on public external storage linked from the
//!   pages, image candidates and script files with the page that linked them ([`CrawlOutput`]).

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use foca_net::{Access, NetError, NetRequest};
use serde::{Deserialize, Serialize};
use url::Url;

use crate::crawl::images::ImageCand;
use crate::crawl::pace::{parse_retry_after, Pace, RateState};
use crate::crawl::trap::{clean_url, risky_link, TrapGuard};
use crate::filter::{ext_of_url, is_image_ext, normalize_url};
use crate::html::{parse_sitemap, scan_page, sitemap_text, PageScan, Robots};
use crate::render::{RenderRequest, RenderStep};
use crate::source::{DocumentSource, Found, FoundUrl, SearchCtx, SourceKind};
use crate::storage::{is_storage_host, parse_storage, StorageEndpoints, StorageLink};
use crate::BoxFuture;

const PAGE_EXTS: &[&str] = &[
    "html", "htm", "xhtml", "shtml", "php", "asp", "aspx", "jsp", "jspx", "cfm", "do", "action",
    "pl",
];

/// Called with the running statistics after every batch of pages.
pub type ProgressHook = Arc<dyn Fn(&CrawlStats) + Send + Sync>;

#[derive(Clone)]
pub struct Crawler {
    /// Explicit start URLs (otherwise `https://<domain>/` and the known hosts from `ctx.hosts`).
    pub start_urls: Vec<String>,
    pub max_depth: usize,
    pub max_pages: usize,
    /// Wall time of one crawl; the frontier left at the deadline is kept for the next scan.
    pub max_time: Duration,
    pub respect_robots: bool,
    pub use_sitemap: bool,
    pub max_sitemaps: usize,
    pub max_page_bytes: u64,
    /// Token matched against robots.txt `User-agent` groups.
    pub agent: String,
    /// Maximum number of start hosts taken from `ctx.hosts`.
    pub max_hosts: usize,
    /// Requests in flight per host.
    pub per_host: usize,
    /// Skip links marked `rel=nofollow` (and pages with a `nofollow` robots meta tag).
    pub honor_nofollow: bool,
    /// Pages per path template (`/events/{n}/{n}`) and distinct queries per path.
    pub per_template: usize,
    pub query_variants: usize,
    /// App-shell pages rendered through the platform browser.
    pub max_rendered: usize,
    /// Consecutive 429/503 answers that stop a host.
    pub limit_stop: u32,
    /// Starting extra interval per host before any rate limit was seen.
    pub pace_base: Duration,
    /// Collect files on public external storage linked from in-scope pages (`None`: off).
    pub storage: Option<StorageEndpoints>,
    /// Collect images as EXIF candidates in [`CrawlOutput::images`] instead of [`Found`].
    pub collect_images: bool,
    /// Ignore image links altogether (images for EXIF are off): they are neither candidates nor
    /// documents, so they never count against the document limit.
    pub skip_images: bool,
    /// Offline test harness only: the port start hosts listen on (`http(s)://<host>:<port>/`).
    pub site_port: Option<u16>,
    /// Unfinished frontiers of earlier scans, by domain ([`Crawler::with_resume`]).
    pub resume: HashMap<String, Frontier>,
    /// Results beyond document URLs; the caller keeps a clone of the `Arc`.
    pub out: Arc<Mutex<CrawlOutput>>,
    /// Running statistics ([`Crawler::with_progress`]).
    pub on_progress: Option<ProgressHook>,
}

impl std::fmt::Debug for Crawler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Crawler")
            .field("start_urls", &self.start_urls)
            .field("max_depth", &self.max_depth)
            .field("max_pages", &self.max_pages)
            .field("max_time", &self.max_time)
            .finish_non_exhaustive()
    }
}

impl Default for Crawler {
    fn default() -> Self {
        Crawler {
            start_urls: Vec::new(),
            max_depth: 5,
            max_pages: 1000,
            max_time: Duration::from_secs(20 * 60),
            respect_robots: true,
            use_sitemap: true,
            max_sitemaps: 25,
            max_page_bytes: 3 * 1024 * 1024,
            agent: "FOCA-rs".into(),
            max_hosts: 20,
            per_host: 2,
            honor_nofollow: false,
            per_template: 100,
            query_variants: 25,
            max_rendered: 30,
            limit_stop: 5,
            pace_base: Duration::ZERO,
            storage: None,
            collect_images: false,
            skip_images: false,
            site_port: None,
            resume: HashMap::new(),
            out: Arc::new(Mutex::new(CrawlOutput::default())),
            on_progress: None,
        }
    }
}

/// Why a crawl ended before its frontier was empty.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CrawlStop {
    Pages,
    Time,
    Docs,
    /// Every host left in the frontier was stopped by rate limiting.
    Limited,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct CrawlStats {
    pub pages: usize,
    pub sitemaps: usize,
    pub robots_skipped: usize,
    pub scope_skipped: usize,
    pub errors: usize,
    /// Pages waiting in the frontier.
    pub queued: usize,
    /// New document URLs found.
    pub docs: usize,
    /// Files and folders on external storage linked from the pages.
    pub storage: usize,
    pub images: usize,
    pub scripts: usize,
    /// App-shell pages rendered through the platform browser.
    pub rendered: usize,
    /// App-shell pages that needed rendering while no browser was available.
    pub render_missing: usize,
    /// Links refused by the trap guard (template or query variants saturated).
    pub trap_skipped: usize,
    /// Logout/delete-like links never followed.
    pub risky_skipped: usize,
    pub nofollow_skipped: usize,
    /// 429/503 answers.
    pub limited: usize,
    pub rate: RateState,
    pub stopped_hosts: Vec<String>,
    /// The crawl continued the frontier of an earlier scan.
    pub resumed: bool,
    /// The frontier is empty: the site was crawled within the limits.
    pub finished: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stop: Option<CrawlStop>,
}

/// Pages left to crawl, saved per project and continued by the next scan.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Frontier {
    /// `(url, depth)` in crawl order.
    pub queue: Vec<(String, usize)>,
    /// Visit keys of pages already fetched or queued.
    pub seen: Vec<String>,
    /// Pages fetched over all runs of this frontier.
    pub pages: usize,
}

impl Frontier {
    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }
}

/// A storage link with the page that showed it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinkedStorage {
    pub link: StorageLink,
    pub page: String,
}

/// Everything a crawl found besides document URLs.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrawlOutput {
    pub stats: CrawlStats,
    /// Frontier left for the next scan (empty when the crawl finished).
    pub frontier: Frontier,
    pub storage: Vec<LinkedStorage>,
    pub images: Vec<ImageCand>,
    /// `(script url, page)`.
    pub scripts: Vec<(String, String)>,
    /// Page that linked each document URL (provenance), by document URL.
    pub doc_pages: BTreeMap<String, String>,
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
    Body(Url, Vec<u8>),
    /// The server answered 429 or 503 (rate limited), with `Retry-After` if given.
    Limited(Option<Duration>),
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
) -> Result<Fetch, NetError> {
    // no client retries: a 429/503 must reach the adaptive pace at once
    let req = NetRequest::get(u.as_str(), "crawler", Access::TouchesTarget)?
        .timeout(ctx.req_timeout(timeout))
        .retries(0);
    let r = match ctx.net.send(req).await {
        Ok(r) => r,
        Err(NetError::Cancelled) => return Err(NetError::Cancelled),
        Err(e) if e.is_scope_denial() => return Ok(Fetch::Denied),
        Err(NetError::Status(429)) => return Ok(Fetch::Limited(None)),
        Err(_) => return Ok(Fetch::Failed),
    };
    if matches!(r.status(), 429 | 503) {
        let ra = parse_retry_after(r.header("retry-after"));
        r.abort();
        return Ok(Fetch::Limited(ra));
    }
    if !r.is_success() {
        r.abort();
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
    match r.bytes_limited(limit).await {
        Ok(t) => Ok(Fetch::Body(final_url, t)),
        Err(NetError::Cancelled) => Err(NetError::Cancelled),
        Err(_) => Ok(Fetch::Failed),
    }
}

/// Timeout for pages and auxiliary files (robots/sitemap get a single attempt).
const PAGE_TIMEOUT: Duration = Duration::from_secs(20);
const AUX_TIMEOUT: Duration = Duration::from_secs(10);
/// Timeout for probing the start page scheme: short (a closed 443, an expired certificate or a
/// refused connection falls back to http right away).
const PROBE_TIMEOUT: Duration = Duration::from_secs(8);
/// Time limit of one rendered page in the platform browser.
const RENDER_TIMEOUT: Duration = Duration::from_secs(45);
/// A rate-limited page goes back to the queue at most this many times.
const MAX_REQUEUE: u8 = 2;
/// Start hosts probed at once.
const SEED_PARALLEL: usize = 4;

/// A fetched start page: final URL after redirects and body.
type StartPage = (Url, Vec<u8>);

/// Outcome of probing one start host.
#[derive(Default)]
struct Probe {
    /// The origin that answered, with its start page when it is HTML.
    origin: Option<(Url, Option<StartPage>)>,
    /// Network failures (one per scheme tried).
    errors: usize,
    /// The scope refused the host.
    denied: bool,
}

/// Start hosts in crawl order: the domain, its `www.` name when known, then the other known
/// hosts as given, at most `max_hosts` besides the domain.
pub(crate) fn seed_order(domain: &str, known: &[String], max_hosts: usize) -> Vec<String> {
    let apex = domain.trim_end_matches('.').to_ascii_lowercase();
    let www = format!("www.{apex}");
    let mut known: Vec<String> = known
        .iter()
        .map(|h| h.trim_end_matches('.').to_ascii_lowercase())
        .filter(|h| *h != apex)
        .collect();
    known.dedup();
    if let Some(i) = known.iter().position(|h| *h == www) {
        let w = known.remove(i);
        known.insert(0, w);
    }
    let mut seen: HashSet<String> = HashSet::new();
    std::iter::once(apex)
        .chain(known.into_iter().take(max_hosts))
        .filter(|h| seen.insert(h.clone()))
        .collect()
}

fn text_of(body: &[u8]) -> String {
    String::from_utf8_lossy(body).into_owned()
}

struct State<'a> {
    ctx: &'a SearchCtx,
    robots: HashMap<String, Option<Robots>>,
    found: Vec<FoundUrl>,
    found_set: HashSet<String>,
    out: CrawlOutput,
    storage_set: HashSet<String>,
    image_set: HashSet<String>,
    script_set: HashSet<String>,
    queue: VecDeque<(Url, usize, u8)>,
    /// Visit keys of pages fetched or queued.
    seen: HashSet<String>,
    /// Visit keys of pages fetched in this run (redirect targets included).
    fetched: HashSet<String>,
    trap: TrapGuard,
    pace: Pace,
    deadline: Instant,
}

impl<'a> State<'a> {
    fn stats(&mut self) -> &mut CrawlStats {
        &mut self.out.stats
    }

    fn out_of_time(&self) -> bool {
        Instant::now() + Duration::from_secs(3) >= self.deadline
            || self.ctx.out_of_time(Duration::from_secs(3))
    }

    fn add_doc(&mut self, u: &Url, page: &str) -> bool {
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
                self.out.doc_pages.insert(n, page.to_string());
                self.out.stats.docs += 1;
            }
        }
        true
    }

    fn note(&mut self, f: Fetch) -> Option<(Url, Vec<u8>)> {
        match f {
            Fetch::Body(u, t) => Some((u, t)),
            Fetch::Answered | Fetch::Limited(_) => None,
            Fetch::Denied => {
                self.stats().scope_skipped += 1;
                None
            }
            Fetch::Failed => {
                self.stats().errors += 1;
                None
            }
        }
    }

    /// Queues a page link unless it was seen, is a trap or changes server state.
    fn enqueue(&mut self, u: Url, depth: usize) {
        if !looks_like_page(&u) {
            return;
        }
        if risky_link(&u) {
            self.out.stats.risky_skipped += 1;
            return;
        }
        if !self.ctx.net.host_in_scope(&host(&u)) {
            self.out.stats.scope_skipped += 1;
            return;
        }
        let key = visit_key(&u);
        if self.seen.contains(&key) {
            return;
        }
        if !self.trap.admit(&u) {
            self.out.stats.trap_skipped += 1;
            return;
        }
        self.seen.insert(key);
        self.queue.push_back((u, depth, 0));
    }

    async fn robots_for(&mut self, crawler: &Crawler, u: &Url) -> Result<Option<Robots>, NetError> {
        let o = origin(u);
        if let Some(r) = self.robots.get(&o) {
            return Ok(r.clone());
        }
        let ru =
            Url::parse(&format!("{o}/robots.txt")).map_err(|e| NetError::BadUrl(e.to_string()))?;
        let f = fetch(self.ctx, &ru, 512 * 1024, false, AUX_TIMEOUT).await?;
        let r = self
            .note(f)
            .map(|(_, t)| Robots::parse(&text_of(&t), &crawler.agent));
        self.robots.insert(o, r.clone());
        Ok(r)
    }

    fn progress(&mut self, crawler: &Crawler) {
        self.out.stats.queued = self.queue.len();
        self.out.stats.rate = self.pace.overall();
        self.out.stats.stopped_hosts = self.pace.stopped_hosts();
        self.out.stats.trap_skipped = self.out.stats.trap_skipped.max(self.trap.collapsed);
        if let Some(h) = &crawler.on_progress {
            h(&self.out.stats);
        }
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

    /// Continues the unfinished frontiers of earlier scans (by domain).
    pub fn with_resume(mut self, resume: HashMap<String, Frontier>) -> Self {
        self.resume = resume;
        self
    }

    /// Reports the running statistics after every batch of pages.
    pub fn with_progress(mut self, hook: ProgressHook) -> Self {
        self.on_progress = Some(hook);
        self
    }

    /// Picks the host scheme: https with a short timeout, falling back to http on a network error.
    /// Returns the start page (if it is HTML) and whether the server answered at all.
    async fn pick_origin(&self, ctx: &SearchCtx, h: &str) -> Result<Probe, NetError> {
        let port = self.site_port.map(|p| format!(":{p}")).unwrap_or_default();
        let mut p = Probe::default();
        for scheme in ["https", "http"] {
            let Ok(u) = Url::parse(&format!("{scheme}://{h}{port}/")) else {
                continue;
            };
            match fetch(ctx, &u, self.max_page_bytes, true, PROBE_TIMEOUT).await? {
                Fetch::Body(fu, t) => {
                    p.origin = Some((u, Some((fu, t))));
                    break;
                }
                Fetch::Answered | Fetch::Limited(_) => {
                    p.origin = Some((u, None));
                    break;
                }
                Fetch::Denied => {
                    p.denied = true;
                    break;
                }
                Fetch::Failed => p.errors += 1,
            }
        }
        Ok(p)
    }

    /// Fetches the origin's robots.txt and sitemap.xml in parallel, one attempt each.
    async fn origin_aux(&self, st: &mut State<'_>, o: &Url) -> Result<(), NetError> {
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
                    fetch(ctx, &ru, 512 * 1024, false, AUX_TIMEOUT).await
                } else {
                    Ok(Fetch::Answered)
                }
            },
            async {
                if self.use_sitemap {
                    fetch(ctx, &su, 16 * 1024 * 1024, false, AUX_TIMEOUT).await
                } else {
                    Ok(Fetch::Answered)
                }
            }
        );
        let robots = st
            .note(r?)
            .map(|(_, t)| Robots::parse(&text_of(&t), &self.agent));
        st.robots.insert(key, robots.clone());
        if self.use_sitemap {
            let first = st.note(s?);
            let maps = robots.map(|r| r.other_sitemaps(o, &su)).unwrap_or_default();
            self.sitemaps(st, o, first.map(|(_, x)| (su.clone(), x)), maps)
                .await?;
        }
        Ok(())
    }

    /// Crawls and returns the discovered documents and statistics. The time budget is the smaller
    /// of [`Crawler::max_time`] and the source's soft deadline (`ctx.deadline`); once it passes,
    /// whatever was collected is returned and the rest of the frontier is kept in [`Crawler::out`].
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
            out: CrawlOutput::default(),
            storage_set: HashSet::new(),
            image_set: HashSet::new(),
            script_set: HashSet::new(),
            queue: VecDeque::new(),
            seen: HashSet::new(),
            fetched: HashSet::new(),
            trap: TrapGuard::new(self.per_template, self.query_variants),
            pace: Pace::new(self.pace_base, self.limit_stop),
            deadline: Instant::now() + self.max_time,
        };
        let r = self.crawl_inner(&mut st, domain).await;
        // the frontier and the counters survive a cancellation, so the next scan can continue
        st.out.frontier = Frontier {
            queue: st
                .queue
                .iter()
                .map(|(u, d, _)| (u.to_string(), *d))
                .collect(),
            seen: if st.queue.is_empty() {
                Vec::new()
            } else {
                let mut v: Vec<String> = st.seen.iter().cloned().collect();
                v.sort();
                v
            },
            pages: st.out.frontier.pages + st.out.stats.pages,
        };
        st.out.stats.finished = st.queue.is_empty() && r.is_ok();
        st.progress(self);
        let stats = st.out.stats.clone();
        if let Ok(mut g) = self.out.lock() {
            *g = std::mem::take(&mut st.out);
        }
        r?;
        let mut found = Found {
            urls: st.found,
            hosts: vec![],
            note: None,
        };
        found.urls.truncate(ctx.limit);
        Ok((found, stats))
    }

    async fn seed_hosts(&self, st: &mut State<'_>, domain: &str) -> Result<(), NetError> {
        let ctx = st.ctx;
        let mut sitemap_origins: HashSet<String> = HashSet::new();
        let mut first_pages: Vec<(Url, Vec<u8>)> = Vec::new();
        let mut hosts: Vec<String> = Vec::new();
        for h in seed_order(domain, &ctx.hosts, self.max_hosts) {
            if ctx.net.host_in_scope(&h) {
                hosts.push(h);
            } else {
                st.stats().scope_skipped += 1;
            }
        }
        // start pages are probed a few hosts at once (dead CT names cost a timeout each) and
        // handled in seed order, so the domain itself and its www come first
        let mut probes: VecDeque<(String, Probe)> = VecDeque::new();
        let mut next = 0usize;
        loop {
            if ctx.net.is_cancelled() {
                return Err(NetError::Cancelled);
            }
            if st.out_of_time() {
                break;
            }
            if probes.is_empty() {
                if next >= hosts.len() {
                    break;
                }
                let chunk: Vec<String> =
                    hosts[next..].iter().take(SEED_PARALLEL).cloned().collect();
                next += chunk.len();
                let got =
                    futures_util::future::join_all(chunk.iter().map(|h| self.pick_origin(ctx, h)))
                        .await;
                for (h, p) in chunk.into_iter().zip(got) {
                    probes.push_back((h, p?));
                }
            }
            let Some((h, probe)) = probes.pop_front() else {
                break;
            };
            st.stats().errors += probe.errors;
            if probe.denied {
                st.stats().scope_skipped += 1;
            }
            // the host was already reached as another host's redirect target (test. -> www.test.), skip it
            if ["https", "http"].iter().any(|s| {
                Url::parse(&format!("{s}://{h}/")).is_ok_and(|u| st.seen.contains(&visit_key(&u)))
            }) {
                continue;
            }
            let Some((o, page)) = probe.origin else {
                continue;
            };
            st.seen.insert(visit_key(&o));
            st.fetched.insert(visit_key(&o));
            // robots.txt/sitemap.xml are fetched once per origin, from the final origin after redirects
            // (www. -> bare domain)
            let eff = match &page {
                Some((fu, _)) => fu.join("/").unwrap_or_else(|_| o.clone()),
                None => o.clone(),
            };
            if sitemap_origins.insert(origin(&eff)) {
                self.origin_aux(st, &eff).await?;
            }
            sitemap_origins.insert(origin(&o));
            if let Some(p) = page {
                st.fetched.insert(visit_key(&p.0));
                if st.seen.insert(visit_key(&p.0)) || p.0 == o {
                    st.stats().pages += 1;
                    first_pages.push(p);
                }
            }
        }
        for (final_url, body) in first_pages {
            self.page(st, &final_url, &body, 0).await?;
        }
        Ok(())
    }

    async fn crawl_inner(&self, st: &mut State<'_>, domain: &str) -> Result<(), NetError> {
        let ctx = st.ctx;
        let resume = self
            .resume
            .get(&domain.to_ascii_lowercase())
            .filter(|f| !f.is_empty());
        if let Some(f) = resume {
            st.out.stats.resumed = true;
            st.out.frontier.pages = f.pages;
            st.seen.extend(f.seen.iter().cloned());
            for (u, d) in &f.queue {
                if let Ok(u) = Url::parse(u) {
                    st.seen.insert(visit_key(&u));
                    st.queue.push_back((u, *d, 0));
                }
            }
        } else if self.start_urls.is_empty() {
            self.seed_hosts(st, domain).await?;
        } else {
            let mut origins: HashSet<String> = HashSet::new();
            for s in self.start_urls.iter().filter_map(|s| Url::parse(s).ok()) {
                if self.use_sitemap && origins.insert(origin(&s)) {
                    self.origin_aux(st, &s).await?;
                }
                if st.seen.insert(visit_key(&s)) {
                    st.queue.push_front((s, 0, 0));
                }
            }
        }
        st.progress(self);
        let per_host = self.per_host.max(1);
        while !st.queue.is_empty() {
            if ctx.net.is_cancelled() {
                return Err(NetError::Cancelled);
            }
            if st.out.stats.pages >= self.max_pages {
                st.out.stats.stop = Some(CrawlStop::Pages);
                break;
            }
            if st.found.len() >= ctx.limit {
                st.out.stats.stop = Some(CrawlStop::Docs);
                break;
            }
            if st.out_of_time() {
                st.out.stats.stop = Some(CrawlStop::Time);
                break;
            }
            let batch = self.next_batch(st, per_host).await?;
            if batch.is_empty() {
                if st.queue.is_empty() {
                    break;
                }
                // every queued host waits for its pace, or all of them are stopped
                let waits: Vec<Duration> = st
                    .queue
                    .iter()
                    .filter_map(|(u, _, _)| st.pace.wait_for(&host(u)))
                    .collect();
                let Some(w) = waits.into_iter().min() else {
                    st.out.stats.stop = Some(CrawlStop::Limited);
                    break;
                };
                let left = st.deadline.saturating_duration_since(Instant::now());
                ctx.net
                    .cancellable(tokio::time::sleep(
                        w.min(left).max(Duration::from_millis(20)),
                    ))
                    .await?;
                continue;
            }
            let room = self.max_pages.saturating_sub(st.out.stats.pages);
            let batch: Vec<(Url, usize, u8)> = batch.into_iter().take(room.max(1)).collect();
            for (u, _, _) in &batch {
                st.pace.started(&host(u));
            }
            let limit = self.max_page_bytes;
            let results = futures_util::future::join_all(
                batch
                    .iter()
                    .map(|(u, _, _)| fetch(ctx, u, limit, true, PAGE_TIMEOUT)),
            )
            .await;
            for ((u, depth, tries), r) in batch.into_iter().zip(results) {
                let h = host(&u);
                match r? {
                    Fetch::Limited(ra) => {
                        st.out.stats.limited += 1;
                        let state = st.pace.limited(&h, ra);
                        tracing::info!(target: "foca::source", "crawler: {h} ограничил частоту (429/503), темп снижен: {state:?}");
                        if state != RateState::Stopped && tries < MAX_REQUEUE {
                            st.queue.push_back((u, depth, tries + 1));
                        } else if state == RateState::Stopped {
                            // keep the page for the next scan
                            st.queue.push_back((u, depth, tries));
                        }
                    }
                    Fetch::Body(final_url, body) => {
                        st.pace.ok(&h);
                        st.fetched.insert(visit_key(&u));
                        // the final URL after a redirect also counts as visited (canonical dedup)
                        if final_url != u {
                            st.seen.insert(visit_key(&final_url));
                            if !st.fetched.insert(visit_key(&final_url)) {
                                continue;
                            }
                        }
                        st.out.stats.pages += 1;
                        self.page(st, &final_url, &body, depth).await?;
                    }
                    other => {
                        if !matches!(other, Fetch::Failed) {
                            st.pace.ok(&h);
                        }
                        st.note(other);
                    }
                }
            }
            st.progress(self);
        }
        // pages of stopped hosts stay in the frontier; the rest of the queue too
        Ok(())
    }

    /// Takes the next pages to fetch: at most `per_host` per host whose pace allows a request
    /// now, after robots.txt checks. Pages of stopped hosts stay in the queue.
    async fn next_batch(
        &self,
        st: &mut State<'_>,
        per_host: usize,
    ) -> Result<Vec<(Url, usize, u8)>, NetError> {
        let mut batch: Vec<(Url, usize, u8)> = Vec::new();
        let mut per: HashMap<String, usize> = HashMap::new();
        let mut keep: VecDeque<(Url, usize, u8)> = VecDeque::new();
        let max_batch = per_host * 4;
        while let Some((u, depth, tries)) = st.queue.pop_front() {
            if batch.len() >= max_batch {
                keep.push_back((u, depth, tries));
                break;
            }
            if st.fetched.contains(&visit_key(&u)) {
                continue;
            }
            let h = host(&u);
            let ready = st.pace.wait_for(&h).is_some_and(|w| w.is_zero());
            let n = per.get(&h).copied().unwrap_or(0);
            if !ready || n >= per_host {
                keep.push_back((u, depth, tries));
                continue;
            }
            if !st.ctx.net.host_in_scope(&h) {
                st.out.stats.scope_skipped += 1;
                continue;
            }
            if self.respect_robots {
                if let Some(r) = st.robots_for(self, &u).await? {
                    let pq = match u.query() {
                        Some(q) => format!("{}?{q}", u.path()),
                        None => u.path().to_string(),
                    };
                    if !r.allowed(&pq) {
                        st.out.stats.robots_skipped += 1;
                        continue;
                    }
                }
            }
            per.insert(h, n + 1);
            batch.push((u, depth, tries));
        }
        keep.extend(st.queue.drain(..));
        st.queue = keep;
        Ok(batch)
    }

    /// An image link while images are off: not followed and not a document.
    fn skipped_image(&self, u: &Url) -> bool {
        !self.collect_images
            && self.skip_images
            && ext_of_url(u.as_str()).is_some_and(|e| is_image_ext(&e))
    }

    /// Processes a fetched page: links, and a rendered copy when it is an app shell.
    async fn page(
        &self,
        st: &mut State<'_>,
        page: &Url,
        body: &[u8],
        depth: usize,
    ) -> Result<(), NetError> {
        let html = text_of(body);
        let scan = scan_page(&html, page);
        if scan.looks_like_app_shell() {
            match self.render(st, page).await? {
                Some(r) => self.links(st, page, &r, depth),
                None => self.links(st, page, &scan, depth),
            }
        } else {
            self.links(st, page, &scan, depth);
        }
        Ok(())
    }

    /// Renders an app-shell page through the platform browser and scans the resulting DOM.
    async fn render(&self, st: &mut State<'_>, page: &Url) -> Result<Option<PageScan>, NetError> {
        let Some(render) = st.ctx.render.clone() else {
            st.out.stats.render_missing += 1;
            return Ok(None);
        };
        if st.out.stats.rendered >= self.max_rendered || !st.ctx.net.host_in_scope(&host(page)) {
            return Ok(None);
        }
        let proxy = st
            .ctx
            .net
            .config()
            .proxy
            .clone()
            .filter(|p| !p.trim().is_empty());
        let req = RenderRequest::new("crawler", Some(page.as_str()), RENDER_TIMEOUT)
            .step(RenderStep::Wait {
                gone: vec![],
                present: None,
                timeout_ms: 20_000,
                abort: vec![],
            })
            .step(RenderStep::Sleep { ms: 1500 })
            .through_proxy(proxy)
            .logged_as("crawler");
        st.out.stats.rendered += 1;
        let r = st.ctx.net.cancellable(render.fetch(req)).await?;
        let mut rec = st.ctx.net.draft(
            "crawler",
            "RENDER",
            page.as_str(),
            &host(page),
            &Access::TouchesTarget,
        );
        let out = match r {
            Ok(p) => {
                rec.status = p.status;
                rec.bytes = p.html.len() as u64;
                let base = Url::parse(&p.url).unwrap_or_else(|_| page.clone());
                Some(scan_page(&p.html, &base))
            }
            Err(e) => {
                rec.error = Some(format!("network: {e}"));
                st.out.stats.errors += 1;
                None
            }
        };
        st.ctx.net.record(rec);
        Ok(out)
    }

    fn links(&self, st: &mut State<'_>, page: &Url, scan: &PageScan, depth: usize) {
        let page_s = page.to_string();
        for s in &scan.scripts {
            if st.ctx.net.host_in_scope(&host(s)) && st.script_set.insert(s.to_string()) {
                st.out.scripts.push((s.to_string(), page_s.clone()));
                st.out.stats.scripts += 1;
            }
        }
        for l in &scan.links {
            if junk_link(&l.url) {
                continue;
            }
            let u = clean_url(&l.url);
            if let Some(ep) = &self.storage {
                if let Some(link) = parse_storage(&u, ep) {
                    if st.storage_set.insert(link.fetch.clone()) {
                        st.out.storage.push(LinkedStorage {
                            link,
                            page: page_s.clone(),
                        });
                        st.out.stats.storage += 1;
                    }
                    continue;
                }
                if is_storage_host(&u, ep) {
                    continue;
                }
            }
            if self.skipped_image(&u) {
                continue;
            }
            if self.collect_images {
                if let Some(ext) = ext_of_url(u.as_str()).filter(|e| is_image_ext(e)) {
                    let wanted = st.ctx.filter.allows_ext(&ext) || matches!(ext.as_str(), "webp");
                    if wanted
                        && st.ctx.net.host_in_scope(&host(&u))
                        && st.image_set.insert(crate::filter::dedup_key(u.as_str()))
                    {
                        st.out.images.push(ImageCand {
                            url: u.to_string(),
                            page: page_s.clone(),
                            w: l.w,
                            h: l.h,
                        });
                        st.out.stats.images += 1;
                    }
                    continue;
                }
            }
            if st.add_doc(&u, &page_s) {
                continue;
            }
            if depth < self.max_depth && looks_like_page(&u) {
                if self.honor_nofollow && l.nofollow {
                    st.out.stats.nofollow_skipped += 1;
                    continue;
                }
                st.enqueue(u, depth + 1);
            }
        }
    }

    /// Collects sitemaps: the already fetched `first` (usually /sitemap.xml), then those from robots
    /// and nested ones (sitemap index), one attempt each and at most `max_sitemaps`.
    async fn sitemaps(
        &self,
        st: &mut State<'_>,
        base: &Url,
        first: Option<(Url, Vec<u8>)>,
        mut maps: VecDeque<String>,
    ) -> Result<(), NetError> {
        let mut seen = HashSet::new();
        let mut pending: VecDeque<(Url, Vec<u8>)> = first.into_iter().collect();
        let page_s = base.to_string();
        loop {
            let (mu, body) = match pending.pop_front() {
                Some(x) => x,
                None => {
                    let Some(m) = maps.pop_front() else { break };
                    if st.out.stats.sitemaps >= self.max_sitemaps || st.out_of_time() {
                        break;
                    }
                    let Ok(mu) = base.join(&m) else { continue };
                    if !seen.insert(mu.to_string()) {
                        continue;
                    }
                    if !st.ctx.net.host_in_scope(&host(&mu)) {
                        st.stats().scope_skipped += 1;
                        continue;
                    }
                    let f = fetch(st.ctx, &mu, 16 * 1024 * 1024, false, AUX_TIMEOUT).await?;
                    let Some((_, body)) = st.note(f) else {
                        continue;
                    };
                    (mu, body)
                }
            };
            seen.insert(mu.to_string());
            let Some(xml) = sitemap_text(&body) else {
                st.stats().errors += 1;
                continue;
            };
            st.stats().sitemaps += 1;
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
                let lu = clean_url(&lu);
                if self.skipped_image(&lu) {
                    continue;
                }
                if !st.add_doc(&lu, &page_s) && self.max_depth >= 1 {
                    st.enqueue(lu, 1);
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
    fn own_timeout(&self) -> Option<Duration> {
        // the crawl has its own wall time; a minute on top lets it hand back the frontier
        Some(self.max_time + Duration::from_secs(60))
    }
    fn find<'a>(
        &'a self,
        ctx: &'a SearchCtx,
        domain: &'a str,
    ) -> BoxFuture<'a, Result<Found, NetError>> {
        Box::pin(async move { self.crawl(ctx, domain).await.map(|x| x.0) })
    }
}

#[cfg(test)]
mod tests {
    use super::seed_order;

    #[test]
    fn seeds_start_with_the_domain_and_its_www() {
        let known: Vec<String> = [
            "admin.example.test",
            "api.example.test",
            "www.example.test",
            "example.test",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        assert_eq!(
            seed_order("Example.test.", &known, 20),
            vec![
                "example.test",
                "www.example.test",
                "admin.example.test",
                "api.example.test"
            ]
        );
        // the cap keeps www even when many names sort before it
        assert_eq!(
            seed_order("example.test", &known, 1),
            vec!["example.test", "www.example.test"]
        );
        assert_eq!(seed_order("example.test", &[], 20), vec!["example.test"]);
    }
}
