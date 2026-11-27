//! Fuzzing executor: per-context calibration, gentle limits (workers, rate, jitter, budget,
//! `max_time`), pause/stop, auto-stop when the site shows signs of throttling, response
//! classification and follow-up candidates (mutations, backups of hits, listings,
//! .DS_Store, recursion). All requests go through [`NetClient`] with `Access::Active` (scope,
//! exclusions, redirects, log). There are no evasion attempts: no address or User-Agent
//! rotation and no path obfuscation.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use foca_net::{Access, CancellationToken, NetClient, NetError, NetRequest, TokenBucket};
use tokio::sync::watch;
use tokio::task::JoinSet;
use url::Url;

use crate::calibrate::{count_lines, count_words, Baseline, Sample};
use crate::config::{FuzzConfig, Measured};
use crate::dsstore::{looks_like_ds_store, parse_ds_store, safe_candidate, DsLimits};
use crate::evidence::{evidence, truncate_chars};
use crate::listing::{is_listing, parse_listing};
use crate::mutate::{mutate_name, split_ext};
use crate::plan::{
    backup_variants, content_jobs, initial_jobs, is_doc_ext, CtxKey, Expect, FuzzTask, Job,
    JobSink, DOC_NAMES,
};
use crate::rand;
use crate::types::{
    FilterReason, Filtered, FuzzEvent, FuzzHit, FuzzReport, FuzzStats, HitKind, Module, Risk,
    StopReason, FILTERED_CAP,
};

/// Module name in the request log.
pub const LOG_MODULE: &str = "fuzz";

/// Event handler.
pub type EventFn = Arc<dyn Fn(&FuzzEvent) + Send + Sync>;

/// Control handle for a running fuzzer: stop and pause (cloned into the UI or engine).
#[derive(Clone, Debug)]
pub struct FuzzControl {
    cancel: CancellationToken,
    pause: Arc<watch::Sender<bool>>,
}

impl Default for FuzzControl {
    fn default() -> Self {
        Self::new()
    }
}

impl FuzzControl {
    pub fn new() -> Self {
        FuzzControl {
            cancel: CancellationToken::new(),
            pause: Arc::new(watch::channel(false).0),
        }
    }

    /// Creates a handle bound to an external cancellation token (the engine's scan stop).
    pub fn with_cancel(cancel: CancellationToken) -> Self {
        FuzzControl {
            cancel,
            pause: Arc::new(watch::channel(false).0),
        }
    }

    pub fn cancel(&self) {
        self.cancel.cancel();
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancel.is_cancelled()
    }

    pub fn pause(&self) {
        self.pause.send_replace(true);
    }

    pub fn resume(&self) {
        self.pause.send_replace(false);
    }

    pub fn is_paused(&self) -> bool {
        *self.pause.borrow()
    }

    pub fn token(&self) -> &CancellationToken {
        &self.cancel
    }
}

/// The fuzzer.
pub struct Fuzzer {
    net: NetClient,
    cfg: FuzzConfig,
    ctl: FuzzControl,
    events: Option<EventFn>,
    wordlist_dir: Option<std::path::PathBuf>,
    pool: Option<Arc<AtomicU64>>,
}

/// Origin and explicit `Host` of a root page.
type RootKey = (String, Option<String>);

/// Candidates that must get the catch-all page before the host is stopped.
const CATCH_ALL_STOP: u32 = 50;

struct Shared {
    net: NetClient,
    cfg: FuzzConfig,
    bucket: TokenBucket,
    stop: CancellationToken,
    pause: watch::Receiver<bool>,
    requests: AtomicU64,
    /// Requests of every fuzzer sharing the budget (several hosts at once), capped by
    /// `cfg.max_requests` like the run's own counter.
    pool: Option<Arc<AtomicU64>>,
    deadline: Instant,
    /// Root page per origin and `Host`, fetched once for all contexts.
    roots: tokio::sync::Mutex<HashMap<RootKey, Option<Sample>>>,
}

#[derive(Debug)]
struct Fetched {
    status: u16,
    size: u64,
    body: Vec<u8>,
    location: Option<String>,
    content_type: Option<String>,
    /// The response carries `Retry-After`.
    retry_after: bool,
    /// A WAF/CDN challenge page (`cf-mitigated`, "Attention Required", challenge scripts).
    challenge: bool,
}

#[derive(Debug)]
enum FetchErr {
    Cancelled,
    Budget,
    MaxTime,
    /// The request was not sent because of the scope policy (no network call was made).
    Denied(String),
    Net(String),
}

enum TaskOut {
    Calib {
        ctx: CtxKey,
        /// Calibration probes (URL and response), noted in the request log.
        probes: Vec<Filtered>,
        samples: Vec<Sample>,
        bad: u32,
        err: Option<FetchErr>,
        /// The root page of the context's origin (first fetch only counts as a request).
        root: Option<Sample>,
        root_requests: u64,
        /// Extra canaries of other path classes (a static file, a nested directory), asked once
        /// per origin when the context's own canaries all got the same 2xx page.
        cross: Vec<Sample>,
    },
    Job {
        job: Job,
        res: Result<Fetched, FetchErr>,
    },
    /// Control request to a random path that answered "not found" at calibration.
    Control {
        url: Url,
        detail: String,
        res: Result<Fetched, FetchErr>,
    },
}

/// How a response counts toward the throttling detector.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Signal {
    Ok,
    /// 403 or 5xx on a single path: Apache denies every `.ht*` file, apps fail on odd paths.
    /// Counts as a block only after a control request confirms it.
    Soft,
    /// 429, 503 with `Retry-After` or a challenge page.
    Hard,
    /// No HTTP answer at all: connection refused, timeout, DNS or TLS failure.
    Net,
}

enum Trip {
    Stop(String),
    /// Only network errors and no HTTP answer in the run: the host is unreachable, not limiting.
    Unreachable(String),
    /// The run of bad answers holds path-specific ones: confirm with a control request.
    Confirm(String),
}

/// Detects that the site is throttling requests.
struct Breaker {
    consecutive: u32,
    window: VecDeque<Signal>,
    cfg: crate::config::AutoStop,
    control_pending: bool,
    /// The latest network error, for the unreachable stop reason.
    last_net: String,
}

impl Breaker {
    fn observe(&mut self, s: Signal) -> Option<Trip> {
        if s == Signal::Ok {
            self.consecutive = 0;
        } else {
            self.consecutive += 1;
        }
        self.window.push_back(s);
        while self.window.len() > self.cfg.window.max(1) as usize {
            self.window.pop_front();
        }
        let detail = self.tripped()?;
        if self.only_net() {
            return Some(Trip::Unreachable(format!(
                "{} сетевых ошибок без ответа HTTP: {}",
                self.window.iter().filter(|b| **b == Signal::Net).count(),
                self.last_net
            )));
        }
        if !self.window.contains(&Signal::Soft) {
            return Some(Trip::Stop(detail));
        }
        if self.control_pending {
            return None;
        }
        self.control_pending = true;
        Some(Trip::Confirm(detail))
    }

    /// Records a network error and counts it.
    fn net_error(&mut self, e: &str) -> Option<Trip> {
        self.last_net = e.to_string();
        self.observe(Signal::Net)
    }

    /// Every bad signal in the window is a network error: nothing hinted at a rate limit.
    fn only_net(&self) -> bool {
        self.window
            .iter()
            .filter(|b| **b != Signal::Ok)
            .all(|b| *b == Signal::Net)
    }

    fn tripped(&self) -> Option<String> {
        if self.cfg.consecutive > 0 && self.consecutive >= self.cfg.consecutive {
            return Some(format!(
                "{} ответов подряд 429/403/5xx или сетевых ошибок",
                self.consecutive
            ));
        }
        if self.window.len() >= self.cfg.window.max(1) as usize {
            let n = self.window.iter().filter(|b| **b != Signal::Ok).count();
            if n as f64 / self.window.len() as f64 >= self.cfg.ratio {
                return Some(format!(
                    "{n} из последних {} ответов: 429/403/5xx или ошибки",
                    self.window.len()
                ));
            }
        }
        None
    }

    /// Applies the control result: path-specific answers are forgotten when the control path
    /// still answers normally.
    fn controlled(&mut self, blocked: bool) {
        self.control_pending = false;
        if !blocked {
            for s in self.window.iter_mut() {
                if *s == Signal::Soft {
                    *s = Signal::Ok;
                }
            }
            self.consecutive = 0;
        }
    }
}

/// Returns `true` for a WAF/CDN challenge or block page.
fn challenge_page(cf_mitigated: bool, status: u16, body: &[u8]) -> bool {
    if cf_mitigated {
        return true;
    }
    if !matches!(status, 403 | 429 | 503) {
        return false;
    }
    let head = String::from_utf8_lossy(&body[..body.len().min(16 * 1024)]).to_ascii_lowercase();
    [
        "attention required! | cloudflare",
        "<title>just a moment...</title>",
        "cf-chl-",
        "/cdn-cgi/challenge-platform/",
        "cf-browser-verification",
        "_incapsula_resource",
        "request unsuccessful. incapsula",
    ]
    .iter()
    .any(|m| head.contains(m))
}

impl Shared {
    async fn fetch(&self, url: &Url, host: Option<&str>) -> Result<Fetched, FetchErr> {
        let mut pause = self.pause.clone();
        loop {
            if self.stop.is_cancelled() {
                return Err(FetchErr::Cancelled);
            }
            if !*pause.borrow_and_update() {
                break;
            }
            tokio::select! {
                _ = self.stop.cancelled() => return Err(FetchErr::Cancelled),
                r = pause.changed() => if r.is_err() { break; },
            }
        }
        if Instant::now() >= self.deadline {
            return Err(FetchErr::MaxTime);
        }
        if self.requests.fetch_add(1, Ordering::SeqCst) >= self.cfg.max_requests {
            self.requests.fetch_sub(1, Ordering::SeqCst);
            return Err(FetchErr::Budget);
        }
        if let Some(pool) = &self.pool {
            if pool.fetch_add(1, Ordering::SeqCst) >= self.cfg.max_requests {
                pool.fetch_sub(1, Ordering::SeqCst);
                self.requests.fetch_sub(1, Ordering::SeqCst);
                return Err(FetchErr::Budget);
            }
        }
        self.bucket
            .acquire(&self.stop)
            .await
            .map_err(|_| FetchErr::Cancelled)?;
        let j = self.cfg.jitter.as_millis() as u64;
        if j > 0 {
            let d = Duration::from_millis(rand::below(j + 1));
            tokio::select! {
                _ = self.stop.cancelled() => return Err(FetchErr::Cancelled),
                _ = tokio::time::sleep(d) => {}
            }
        }
        let mut req = NetRequest::get(url.as_str(), LOG_MODULE, Access::active("fuzz"))
            .map_err(|e| FetchErr::Net(e.to_string()))?
            .retries(0)
            .timeout(self.cfg.request_timeout);
        if let Some(h) = host {
            req = req.header("Host", h);
        }
        if !self.cfg.follow_redirects {
            req = req.no_redirects();
        }
        let net = self.net.with_cancel(self.stop.clone());
        let mut resp = match net.send(req).await {
            Ok(r) => r,
            Err(NetError::Cancelled) => return Err(FetchErr::Cancelled),
            Err(e) if e.is_scope_denial() || matches!(e, NetError::ActiveDenied(_)) => {
                return Err(FetchErr::Denied(e.to_string()))
            }
            Err(e) => return Err(FetchErr::Net(format!("{}: {e}", e.code()))),
        };
        let status = resp.status();
        let retry_after = resp.header("retry-after").is_some();
        let cf_mitigated = resp.header("cf-mitigated").is_some();
        let location = resp.header("location").map(str::to_string);
        let content_type = resp.content_type().map(str::to_string);
        let declared = resp.content_length();
        let mut body = Vec::new();
        let limit = self.cfg.body_limit as usize;
        let mut truncated = false;
        loop {
            match resp.chunk().await {
                Ok(Some(c)) => {
                    let room = limit.saturating_sub(body.len());
                    if c.len() >= room {
                        body.extend_from_slice(&c[..room]);
                        truncated = true;
                        break;
                    }
                    body.extend_from_slice(&c);
                }
                Ok(None) => break,
                Err(NetError::Cancelled) => return Err(FetchErr::Cancelled),
                Err(e) => return Err(FetchErr::Net(format!("{}: {e}", e.code()))),
            }
        }
        // Do not read the rest of the body (files are never downloaded in full).
        resp.abort();
        let size = match declared {
            Some(n) => n,
            None if truncated => body.len() as u64,
            None => body.len() as u64,
        };
        let challenge = challenge_page(cf_mitigated, status, &body);
        Ok(Fetched {
            status,
            size,
            body,
            location,
            content_type,
            retry_after,
            challenge,
        })
    }

    /// Returns the root page sample for the context's origin and `Host`, fetching it once.
    /// A same-origin redirect of the root is followed one hop.
    async fn root_page(&self, ctx: &CtxKey) -> (Option<Sample>, Option<Filtered>) {
        let key = (ctx.origin.clone(), ctx.vhost.clone());
        let mut roots = self.roots.lock().await;
        if let Some(r) = roots.get(&key) {
            return (r.clone(), None);
        }
        let Ok(mut url) = Url::parse(&format!("{}/", ctx.origin)) else {
            roots.insert(key, None);
            return (None, None);
        };
        let mut res = self.fetch(&url, ctx.vhost.as_deref()).await;
        if let Ok(f) = &res {
            let next = f
                .location
                .as_deref()
                .filter(|_| is_redirect(f.status))
                .and_then(|l| url.join(l).ok())
                .filter(|u| origin_eq(u, &url) && u.path() != "/");
            if let Some(u) = next {
                url = u;
                res = self.fetch(&url, ctx.vhost.as_deref()).await;
            }
        }
        let Ok(f) = res else {
            // A failed root fetch is retried by the next context.
            return (None, None);
        };
        let body = String::from_utf8_lossy(&f.body);
        let sample = Sample::with_type(
            f.status,
            f.size,
            &body,
            f.location.as_deref(),
            "",
            f.content_type.as_deref(),
        );
        roots.insert(key, Some(sample.clone()));
        let probe = Filtered {
            url: url.to_string(),
            status: f.status,
            size: f.size,
            content_type: f.content_type.clone(),
            reason: FilterReason::Calibration,
        };
        (Some(sample), Some(probe))
    }

    async fn calibrate(&self, ctx: &CtxKey, samples_n: usize, cross_probe: bool) -> TaskOut {
        let mut samples = Vec::new();
        let mut probes = Vec::new();
        let mut bad = 0;
        let (root, root_probe) = if ctx.ext == "vhost" {
            (None, None)
        } else {
            self.root_page(ctx).await
        };
        let root_requests = u64::from(root_probe.is_some());
        probes.extend(root_probe);
        for i in 0..samples_n {
            let tok = rand::token(match i % 3 {
                0 => 16,
                1 => 24,
                _ => 10,
            });
            let (url, host, word) = if ctx.ext == "vhost" {
                let d = ctx.vhost.clone().unwrap_or_default();
                let Ok(u) = Url::parse(&format!("{}/", ctx.origin)) else {
                    break;
                };
                (u, Some(format!("{tok}.{d}")), tok.clone())
            } else {
                let word = if ctx.ext == "/" {
                    format!("{tok}/")
                } else {
                    format!("{}{tok}{}", ctx.dot_prefix(), ctx.ext)
                };
                let Ok(u) = Url::parse(&format!("{}{}{}", ctx.origin, ctx.dir, word)) else {
                    break;
                };
                (u, ctx.vhost.clone(), word)
            };
            match self.fetch(&url, host.as_deref()).await {
                Ok(f) => {
                    if f.status == 429 {
                        bad += 1;
                    }
                    probes.push(Filtered {
                        url: url.to_string(),
                        status: f.status,
                        size: f.size,
                        content_type: f.content_type.clone(),
                        reason: FilterReason::Calibration,
                    });
                    let body = String::from_utf8_lossy(&f.body);
                    samples.push(Sample::with_type(
                        f.status,
                        f.size,
                        &body,
                        f.location.as_deref(),
                        &word,
                        f.content_type.as_deref(),
                    ));
                }
                Err(FetchErr::Net(e)) => {
                    bad += 1;
                    if bad as usize >= samples_n {
                        return TaskOut::Calib {
                            ctx: ctx.clone(),
                            probes,
                            samples,
                            bad,
                            err: Some(FetchErr::Net(e)),
                            root,
                            root_requests,
                            cross: Vec::new(),
                        };
                    }
                }
                Err(e) => {
                    return TaskOut::Calib {
                        ctx: ctx.clone(),
                        probes,
                        samples,
                        bad,
                        err: Some(e),
                        root,
                        root_requests,
                        cross: Vec::new(),
                    }
                }
            }
        }
        // Every canary got the same 2xx page: ask other path classes too. A site that also
        // answers a random static file and a random nested path with it serves one page for
        // any address (only then the host is stopped early; an app shell with real 404s for
        // static files is fuzzed as usual).
        let mut cross = Vec::new();
        let catch_all_like =
            samples.len() >= 2 && bad == 0 && samples.iter().all(|s| s.same_catch_all(&samples[0]));
        if cross_probe && ctx.ext != "vhost" && catch_all_like {
            let words = [
                format!("{}.txt", rand::token(12)),
                format!("{}/{}.json", rand::token(10), rand::token(8)),
            ];
            for word in words {
                let Ok(url) = Url::parse(&format!("{}/{word}", ctx.origin.trim_end_matches('/')))
                else {
                    continue;
                };
                let Ok(f) = self.fetch(&url, ctx.vhost.as_deref()).await else {
                    break;
                };
                probes.push(Filtered {
                    url: url.to_string(),
                    status: f.status,
                    size: f.size,
                    content_type: f.content_type.clone(),
                    reason: FilterReason::Calibration,
                });
                let body = String::from_utf8_lossy(&f.body);
                cross.push(Sample::with_type(
                    f.status,
                    f.size,
                    &body,
                    f.location.as_deref(),
                    &word,
                    f.content_type.as_deref(),
                ));
            }
        }
        TaskOut::Calib {
            ctx: ctx.clone(),
            probes,
            samples,
            bad,
            err: None,
            root,
            root_requests,
            cross,
        }
    }
}

/// Picks a random path in a calibrated context that answered "not found" (plain names first).
fn control_target(cal: &HashMap<CtxKey, CalState>) -> Option<(Url, Option<String>)> {
    let mut ctxs: Vec<&CtxKey> = cal
        .iter()
        .filter(|(k, v)| k.ext != "vhost" && matches!(v, CalState::Ready(b) if b.answers_missing()))
        .map(|(k, _)| k)
        .collect();
    ctxs.sort_by_key(|k| (k.dot, !k.ext.is_empty(), k.dir.len(), k.ext.clone()));
    let k = ctxs.first()?;
    let tok = rand::token(16);
    let word = if k.ext == "/" {
        format!("{tok}/")
    } else {
        format!("{}{tok}{}", k.dot_prefix(), k.ext)
    };
    let u = Url::parse(&format!("{}{}{}", k.origin, k.dir, word)).ok()?;
    Some((u, k.vhost.clone()))
}

enum CalState {
    Pending(Vec<Job>),
    Ready(Baseline),
}

struct Run<'a> {
    task: &'a FuzzTask,
    events: Option<EventFn>,
    stats: FuzzStats,
    hits: Vec<FuzzHit>,
    filtered: Vec<Filtered>,
    documents: Vec<String>,
    doc_seen: HashSet<String>,
    hit_seen: HashSet<(String, Option<String>)>,
    stop: Option<StopReason>,
    breaker: Breaker,
    /// Set when the breaker asks for a control request (holds the trip detail).
    want_control: Option<String>,
    /// Normalized hashes of 2xx HTML pages served for random paths, per origin and `Host`:
    /// such a page is "not found" in every context of the site.
    not_found_pages: HashMap<RootKey, HashSet<u64>>,
    /// Origins that answer any address with one page: the page and how many candidates got it.
    catch_all: HashMap<RootKey, (Sample, u32)>,
    /// Origins whose other path classes were already probed for a catch-all page.
    cross_asked: HashSet<RootKey>,
    progress_tick: u64,
}

impl Run<'_> {
    /// Records a discarded response for the request log notes (size, type, reason).
    fn filter(&mut self, url: &Url, f: &Fetched, reason: FilterReason) {
        if self.filtered.len() < FILTERED_CAP {
            self.filtered.push(Filtered {
                url: url.to_string(),
                status: f.status,
                size: f.size,
                content_type: f.content_type.clone(),
                reason,
            });
        }
    }

    fn emit(&self, e: FuzzEvent) {
        if let Some(f) = &self.events {
            f(&e);
        }
    }

    fn progress(&mut self, force: bool) {
        self.progress_tick += 1;
        if force || self.progress_tick.is_multiple_of(10) {
            self.emit(FuzzEvent::Progress {
                stats: self.stats.clone(),
            });
        }
    }

    fn add_document(&mut self, url: &str) {
        if self.doc_seen.insert(url.to_string()) {
            self.documents.push(url.to_string());
        }
    }

    fn add_hit(&mut self, hit: FuzzHit) -> bool {
        if !self.hit_seen.insert((hit.url.clone(), hit.host.clone())) {
            return false;
        }
        self.stats.found += 1;
        self.emit(FuzzEvent::Hit { hit: hit.clone() });
        self.hits.push(hit);
        true
    }

    fn set_stop(&mut self, s: StopReason) {
        if self.stop.is_none() {
            self.stop = Some(s);
        }
    }
}

fn is_redirect(st: u16) -> bool {
    matches!(st, 301 | 302 | 303 | 307 | 308)
}

fn is_html(ct: Option<&str>) -> bool {
    ct.is_some_and(|c| c.to_ascii_lowercase().contains("text/html"))
}

fn title_of(body: &str) -> Option<String> {
    let l = body.to_ascii_lowercase();
    let s = l.find("<title>")? + 7;
    let e = l[s..].find("</title>")? + s;
    body.get(s..e).map(|t| truncate_chars(t.trim(), 120))
}

fn looks_html(body: &str) -> bool {
    let t = body.trim_start_matches('\u{feff}').trim_start();
    let head: String = t.chars().take(64).collect::<String>().to_ascii_lowercase();
    head.starts_with("<!doctype html") || head.starts_with("<html") || head.starts_with("<head")
}

/// Returns `true` if the body can be the file the name promises. An HTML page is never a data
/// or config file (SPA hosts and custom error pages answer such paths with their template),
/// JSON must start like JSON, XML must not be HTML, a CSV needs a separator in its first line.
/// Names that may legitimately be pages (`.php`, `.html.bak`, extensionless paths) pass.
fn body_fits_name(name: &str, ctype: Option<&str>, body: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    let rest = lower.strip_prefix('.').unwrap_or(&lower);
    let (_, ext) = split_ext(rest);
    let ext = ext.trim_start_matches('.').trim_end_matches('~');
    let html = is_html(ctype) || (ctype.is_none() && looks_html(body));
    let page_name = [".htm", ".php", ".asp", ".jsp", ".cfm", ".cgi", ".pl", ".do"]
        .iter()
        .any(|p| lower.contains(p));
    if ext.is_empty() {
        // `/server-status`, `/phpinfo`: pages; dotfiles (`.htaccess`, `.git/config`) are not.
        return !(html && lower.starts_with('.'));
    }
    if html && !page_name {
        return false;
    }
    let t = body.trim_start_matches('\u{feff}').trim_start();
    match ext {
        "json" | "map" => t.starts_with('{') || t.starts_with('['),
        "xml" | "config" | "plist" => t.starts_with('<') && !looks_html(t),
        "csv" | "tsv" => {
            let first = t.lines().next().unwrap_or("");
            !looks_html(t) && [',', ';', '\t'].iter().any(|c| first.contains(*c))
        }
        "yml" | "yaml" | "ini" | "conf" | "cfg" | "properties" | "toml" | "log" | "sql" | "txt"
        | "md" => !looks_html(t),
        _ => true,
    }
}

fn source_like(name: &str) -> bool {
    let (_, e) = split_ext(name);
    matches!(
        e.to_ascii_lowercase().as_str(),
        ".php"
            | ".asp"
            | ".aspx"
            | ".jsp"
            | ".config"
            | ".conf"
            | ".inc"
            | ".py"
            | ".rb"
            | ".pl"
            | ".cgi"
            | ".env"
            | ".ini"
            | ".yml"
            | ".yaml"
            | ".json"
            | ".xml"
            | ".sql"
    )
}

impl Fuzzer {
    pub fn new(net: NetClient, cfg: FuzzConfig) -> Fuzzer {
        Fuzzer {
            net,
            cfg,
            ctl: FuzzControl::new(),
            events: None,
            wordlist_dir: None,
            pool: None,
        }
    }

    /// Shares the request budget with other fuzzers: every request of every fuzzer holding the
    /// same counter counts toward `cfg.max_requests`, so hosts brute-forced at once never spend
    /// more than one budget together.
    pub fn with_shared_budget(mut self, pool: Arc<AtomicU64>) -> Self {
        self.pool = Some(pool);
        self
    }

    pub fn with_control(mut self, ctl: FuzzControl) -> Self {
        self.ctl = ctl;
        self
    }

    pub fn with_events(mut self, f: EventFn) -> Self {
        self.events = Some(f);
        self
    }

    /// Sets the directory with downloaded large wordlists (for CMS lists from the registry).
    pub fn with_wordlist_dir(mut self, d: std::path::PathBuf) -> Self {
        self.wordlist_dir = Some(d);
        self
    }

    pub fn control(&self) -> FuzzControl {
        self.ctl.clone()
    }

    pub fn config(&self) -> &FuzzConfig {
        &self.cfg
    }

    /// Runs the fuzzing task.
    pub async fn run(&self, task: &FuzzTask) -> FuzzReport {
        let cfg = &self.cfg;
        let mut run = Run {
            task,
            events: self.events.clone(),
            stats: FuzzStats::default(),
            hits: Vec::new(),
            filtered: Vec::new(),
            documents: Vec::new(),
            doc_seen: HashSet::new(),
            hit_seen: HashSet::new(),
            stop: None,
            breaker: Breaker {
                consecutive: 0,
                window: VecDeque::new(),
                cfg: cfg.autostop.clone(),
                control_pending: false,
                last_net: String::new(),
            },
            want_control: None,
            not_found_pages: HashMap::new(),
            catch_all: HashMap::new(),
            cross_asked: HashSet::new(),
            progress_tick: 0,
        };
        let scope = self.net.scope();
        // Pre-check: active requests to the root must be allowed (active phase, targets,
        // exclusions).
        let base_host = task.base.host_str().unwrap_or("").to_string();
        if let Err(d) = scope.check_active(&base_host) {
            let stop = StopReason::Denied {
                detail: d.to_string(),
            };
            run.emit(FuzzEvent::Finished {
                stop: stop.clone(),
                stats: run.stats.clone(),
            });
            return FuzzReport {
                hits: Vec::new(),
                filtered: Vec::new(),
                documents: Vec::new(),
                stats: run.stats,
                stop,
            };
        }
        let mut sink = JobSink::new(cfg, Some(&scope));
        if let Err(e) = initial_jobs(task, &mut sink, self.wordlist_dir.as_deref()) {
            let stop = StopReason::Denied { detail: e };
            return FuzzReport {
                hits: Vec::new(),
                filtered: Vec::new(),
                documents: Vec::new(),
                stats: run.stats,
                stop,
            };
        }
        let mut queue: VecDeque<Job> = VecDeque::new();
        sink.flush_into(&mut queue, &mut run.stats.skipped_excluded);
        run.stats.planned = queue.len() as u64;
        run.emit(FuzzEvent::Started {
            planned: run.stats.planned,
        });

        let stop_tok = self.ctl.token().child_token();
        let shared = Arc::new(Shared {
            net: self.net.clone(),
            cfg: cfg.clone(),
            bucket: TokenBucket::new(cfg.rate, 1.0),
            stop: stop_tok.clone(),
            pause: self.ctl.pause.subscribe(),
            requests: AtomicU64::new(0),
            pool: self.pool.clone(),
            deadline: Instant::now() + cfg.max_time,
            roots: tokio::sync::Mutex::new(HashMap::new()),
        });
        let mut cal: HashMap<CtxKey, CalState> = HashMap::new();
        let mut running: JoinSet<TaskOut> = JoinSet::new();
        let threads = cfg.threads.max(1);
        let mut was_paused = false;

        loop {
            if run.stop.is_none() {
                if self.ctl.is_cancelled() {
                    run.set_stop(StopReason::Cancelled);
                } else if Instant::now() >= shared.deadline {
                    run.set_stop(StopReason::MaxTime);
                }
            }
            if run.stop.is_some() {
                stop_tok.cancel();
                while running.join_next().await.is_some() {}
                break;
            }
            let paused = self.ctl.is_paused();
            if paused != was_paused {
                was_paused = paused;
                run.emit(if paused {
                    FuzzEvent::Paused
                } else {
                    FuzzEvent::Resumed
                });
            }
            while running.len() < threads {
                let Some(job) = queue.pop_front() else {
                    break;
                };
                match cal.get_mut(&job.ctx) {
                    Some(CalState::Ready(_)) => {
                        let sh = shared.clone();
                        running.spawn(async move {
                            let res = sh.fetch(&job.url, job.host.as_deref()).await;
                            TaskOut::Job { job, res }
                        });
                    }
                    Some(CalState::Pending(v)) => v.push(job),
                    None => {
                        let root_key = (job.ctx.origin.clone(), job.ctx.vhost.clone());
                        if run.catch_all.contains_key(&root_key) && job.ctx.ext != "vhost" {
                            // the whole origin serves one page: its signature filters this
                            // context too, new canaries would only spend the budget
                            cal.insert(job.ctx.clone(), CalState::Ready(Baseline::default()));
                            queue.push_front(job);
                        } else if cfg.calibrate && cfg.calibration_samples > 0 {
                            let ctx = job.ctx.clone();
                            cal.insert(ctx.clone(), CalState::Pending(vec![job]));
                            let sh = shared.clone();
                            let n = cfg.calibration_samples;
                            let cross = run.cross_asked.insert(root_key);
                            running.spawn(async move { sh.calibrate(&ctx, n, cross).await });
                        } else {
                            cal.insert(job.ctx.clone(), CalState::Ready(Baseline::default()));
                            queue.push_front(job);
                        }
                    }
                }
            }
            if running.is_empty() {
                if queue.is_empty() {
                    break;
                }
                continue;
            }
            let out = tokio::select! {
                o = running.join_next() => o,
                _ = self.ctl.token().cancelled() => { continue; }
                _ = tokio::time::sleep_until(tokio::time::Instant::from_std(shared.deadline)) => { continue; }
            };
            let Some(Ok(out)) = out else {
                continue;
            };
            match out {
                TaskOut::Calib {
                    ctx,
                    probes,
                    samples,
                    bad,
                    err,
                    root,
                    root_requests,
                    cross,
                } => {
                    let room = FILTERED_CAP.saturating_sub(run.filtered.len());
                    run.filtered.extend(probes.into_iter().take(room));
                    let n =
                        samples.len() as u64 + u64::from(bad) + root_requests + cross.len() as u64;
                    // one page for any address, and it is the home page itself: a distinct "not
                    // found" page with status 200 is only a soft 404 and fuzzing goes on
                    // (no canary answered: nothing to compare)
                    if let (Some(first), Some(r)) = (samples.first(), root.as_ref()) {
                        let home = first.same_catch_all(r) || first.same_page_as(r);
                        if home
                            && !cross.is_empty()
                            && cross.iter().all(|s| s.same_catch_all(first))
                        {
                            run.catch_all
                                .entry((ctx.origin.clone(), ctx.vhost.clone()))
                                .or_insert_with(|| (first.clone(), 0));
                        }
                    }
                    run.stats.requests += n;
                    run.stats.calibration_requests += n;
                    for s in &samples {
                        let sig = if s.status == 429 {
                            Signal::Hard
                        } else {
                            Signal::Ok
                        };
                        match run.breaker.observe(sig) {
                            Some(Trip::Stop(d) | Trip::Confirm(d)) => {
                                run.set_stop(StopReason::Blocked { detail: d })
                            }
                            Some(Trip::Unreachable(d)) => {
                                run.set_stop(StopReason::Unreachable { detail: d })
                            }
                            None => {}
                        }
                    }
                    if let Some(e) = err {
                        match e {
                            FetchErr::Cancelled => {}
                            FetchErr::Budget => run.set_stop(StopReason::Budget),
                            FetchErr::MaxTime => run.set_stop(StopReason::MaxTime),
                            FetchErr::Denied(d) => {
                                run.stats.skipped_excluded += 1;
                                tracing::debug!(target: "foca::fuzz", "калибровка {}: {d}", ctx.label());
                            }
                            FetchErr::Net(e) => {
                                run.stats.errors += u64::from(bad);
                                for _ in 0..bad {
                                    match run.breaker.net_error(&e) {
                                        Some(Trip::Stop(d) | Trip::Confirm(d)) => {
                                            run.set_stop(StopReason::Blocked { detail: d })
                                        }
                                        Some(Trip::Unreachable(d)) => {
                                            run.set_stop(StopReason::Unreachable { detail: d })
                                        }
                                        None => {}
                                    }
                                }
                            }
                        }
                    }
                    if ctx.ext != "vhost" {
                        let pages = run
                            .not_found_pages
                            .entry((ctx.origin.clone(), ctx.vhost.clone()))
                            .or_default();
                        for s in samples.iter().filter(|s| (200..300).contains(&s.status)) {
                            pages.insert(s.norm_hash);
                        }
                    }
                    let base = Baseline::new(samples).with_root(root);
                    run.emit(FuzzEvent::Calibrated {
                        context: ctx.label(),
                        samples: base.samples.len(),
                        summary: base.summary(),
                    });
                    if let Some(CalState::Pending(jobs)) =
                        cal.insert(ctx.clone(), CalState::Ready(base))
                    {
                        for j in jobs.into_iter().rev() {
                            queue.push_front(j);
                        }
                    }
                }
                TaskOut::Job { job, res } => {
                    let baseline = match cal.get(&job.ctx) {
                        Some(CalState::Ready(b)) => b.clone(),
                        _ => Baseline::default(),
                    };
                    self.handle(&mut run, job, res, &baseline, &mut sink);
                    sink.flush_into(&mut queue, &mut run.stats.skipped_excluded);
                    run.progress(false);
                }
                TaskOut::Control { url, detail, res } => {
                    run.stats.requests += 1;
                    run.stats.calibration_requests += 1;
                    let blocked = match &res {
                        Ok(f) => f.challenge || matches!(f.status, 403 | 429 | 503),
                        Err(_) => false,
                    };
                    // the control path got no HTTP answer at all: the host stopped answering
                    if let Err(FetchErr::Net(e)) = &res {
                        run.breaker.controlled(true);
                        run.set_stop(StopReason::Unreachable {
                            detail: format!("{detail}; контрольный запрос {}: {e}", url.path()),
                        });
                        continue;
                    }
                    let mut note = None;
                    if let Ok(f) = &res {
                        run.filter(&url, f, FilterReason::Calibration);
                        note = Some(f.status);
                    }
                    run.breaker.controlled(blocked);
                    if blocked {
                        let st = note.map_or_else(|| "ошибка".to_string(), |s| format!("HTTP {s}"));
                        run.set_stop(StopReason::Blocked {
                            detail: format!("{detail}; контрольный запрос {}: {st}", url.path()),
                        });
                    } else {
                        tracing::debug!(target: "foca::fuzz", "контрольный запрос {url}: {note:?}, ответы 403/5xx относятся к отдельным путям");
                    }
                }
            }
            if let Some(detail) = run.want_control.take() {
                match control_target(&cal) {
                    Some((url, host)) if run.stop.is_none() => {
                        let sh = shared.clone();
                        running.spawn(async move {
                            let res = sh.fetch(&url, host.as_deref()).await;
                            TaskOut::Control { url, detail, res }
                        });
                    }
                    Some(_) => {}
                    None => run.set_stop(StopReason::Blocked { detail }),
                }
            }
        }
        run.stats.requests = run
            .stats
            .requests
            .max(shared.requests.load(Ordering::SeqCst));
        let stop = run.stop.clone().unwrap_or(StopReason::Completed);
        let mut hits = std::mem::take(&mut run.hits);
        hits.sort_by(|a, b| b.risk.cmp(&a.risk).then_with(|| a.url.cmp(&b.url)));
        run.progress(true);
        run.emit(FuzzEvent::Finished {
            stop: stop.clone(),
            stats: run.stats.clone(),
        });
        FuzzReport {
            hits,
            filtered: std::mem::take(&mut run.filtered),
            documents: std::mem::take(&mut run.documents),
            stats: run.stats,
            stop,
        }
    }

    /// Filters a candidate that got the origin's catch-all page and stops the host once
    /// [`CATCH_ALL_STOP`] candidates got it: nothing on such a site can be told apart.
    fn catch_all_hit(&self, run: &mut Run<'_>, job: &Job, sample: &Sample) -> bool {
        if job.expect == Expect::Vhost {
            return false;
        }
        let key = (job.ctx.origin.clone(), job.ctx.vhost.clone());
        let Some((sig, n)) = run.catch_all.get_mut(&key) else {
            return false;
        };
        if !sample.same_catch_all(sig) {
            return false;
        }
        *n += 1;
        if *n >= CATCH_ALL_STOP {
            let detail = format!("HTTP {}, ~{} KB", sig.status, sig.size.div_ceil(1024));
            run.set_stop(StopReason::CatchAll { detail });
        }
        true
    }

    fn handle(
        &self,
        run: &mut Run<'_>,
        job: Job,
        res: Result<Fetched, FetchErr>,
        baseline: &Baseline,
        follow: &mut JobSink<'_>,
    ) {
        let f = match res {
            Ok(f) => f,
            Err(FetchErr::Cancelled) => return,
            Err(FetchErr::Budget) => {
                run.set_stop(StopReason::Budget);
                return;
            }
            Err(FetchErr::MaxTime) => {
                run.set_stop(StopReason::MaxTime);
                return;
            }
            Err(FetchErr::Denied(_)) => {
                run.stats.skipped_excluded += 1;
                return;
            }
            Err(FetchErr::Net(e)) => {
                run.stats.errors += 1;
                run.stats.requests += 1;
                tracing::debug!(target: "foca::fuzz", "{}: {e}", job.url);
                match run.breaker.net_error(&e) {
                    Some(Trip::Stop(d) | Trip::Confirm(d)) => {
                        run.set_stop(StopReason::Blocked { detail: d })
                    }
                    Some(Trip::Unreachable(d)) => {
                        run.set_stop(StopReason::Unreachable { detail: d })
                    }
                    None => {}
                }
                return;
            }
        };
        run.stats.requests += 1;
        run.stats.checked += 1;
        let st = f.status;
        let sig = if f.challenge || st == 429 || (st == 503 && f.retry_after) {
            Signal::Hard
        } else if (st == 403 && !baseline.has_status(403))
            || (st >= 500 && !baseline.has_status(st))
        {
            Signal::Soft
        } else {
            Signal::Ok
        };
        match run.breaker.observe(sig) {
            Some(Trip::Stop(d)) => {
                run.set_stop(StopReason::Blocked { detail: d });
                return;
            }
            Some(Trip::Unreachable(d)) => {
                run.set_stop(StopReason::Unreachable { detail: d });
                return;
            }
            Some(Trip::Confirm(d)) => run.want_control = Some(d),
            None => {}
        }
        if st == 429 {
            run.stats.filtered_rules += 1;
            run.filter(&job.url, &f, FilterReason::RateLimited);
            return;
        }
        let body = String::from_utf8_lossy(&f.body).into_owned();
        let sample = Sample::with_type(
            st,
            f.size,
            &body,
            f.location.as_deref(),
            &job.word,
            f.content_type.as_deref(),
        );
        let m = Measured {
            status: st,
            size: f.size,
            words: count_words(&body),
            lines: count_lines(&body),
            body: &body,
        };
        if !self.cfg.filters.accepts(&m) {
            run.stats.filtered_rules += 1;
            run.filter(&job.url, &f, FilterReason::Rules);
            return;
        }
        // The site root itself is a directory job (recursion), never its own soft 404.
        let soft = if job.url.path() == "/" {
            baseline.matches_samples(&sample)
        } else {
            baseline.matches(&sample)
                || (job.expect != Expect::Vhost
                    && (200..300).contains(&st)
                    && run
                        .not_found_pages
                        .get(&(job.ctx.origin.clone(), job.ctx.vhost.clone()))
                        .is_some_and(|p| p.contains(&sample.norm_hash)))
        };
        let catch_all = self.catch_all_hit(run, &job, &sample);
        let soft = soft || catch_all;
        if soft {
            run.stats.filtered_calibration += 1;
            run.filter(&job.url, &f, FilterReason::Soft404);
            return;
        }
        let mk = |kind: HitKind, risk: Risk, evidence: String| FuzzHit {
            url: job.url.to_string(),
            host: job.host.clone(),
            status: st,
            size: f.size,
            words: m.words,
            lines: m.lines,
            kind,
            risk,
            module: job.module,
            evidence,
            redirect: f.location.clone(),
            content_type: f.content_type.clone(),
            extra: Vec::new(),
            artifact: None,
        };
        // The raw body goes to the artifact parser only; the hit keeps the masked summary.
        let with_artifact = |mut h: FuzzHit, path: &str| {
            if let Some(a) = crate::evidence::artifact_summary(path, &f.body) {
                if matches!(
                    a.sev,
                    foca_core::Severity::Critical | foca_core::Severity::High
                ) {
                    h.risk = Risk::High;
                }
                // Actuator bodies hold configuration values: show only the parsed summary.
                if a.kind.starts_with("apidoc_actuator") {
                    h.evidence = a.lines.join("\n");
                }
                h.artifact = Some(a);
            }
            h
        };
        let ok2 = (200..300).contains(&st);
        let exts = &run.task.doc_extensions;

        // A "directory without trailing slash" redirect: check the directory.
        if is_redirect(st) && job.expect != Expect::Vhost {
            if let Some(loc) = f.location.as_deref().and_then(|l| job.url.join(l).ok()) {
                let want = format!("{}/", job.url.path().trim_end_matches('/'));
                if loc.path() == want && origin_eq(&loc, &job.url) {
                    follow.push(
                        loc,
                        job.host.clone(),
                        &job.word,
                        job.module,
                        Expect::Directory,
                        job.depth,
                    );
                    return;
                }
            }
            if matches!(job.expect, Expect::Generic | Expect::Cms) {
                let ev = format!("редирект → {}", f.location.as_deref().unwrap_or(""));
                run.add_hit(mk(
                    if job.module == Module::Cms {
                        HitKind::CmsPath
                    } else {
                        HitKind::Content
                    },
                    Risk::Info,
                    ev,
                ));
            } else {
                run.stats.filtered_rules += 1;
            }
            return;
        }

        match job.expect {
            Expect::Directory => {
                if ok2 && is_listing(&body) {
                    let links = parse_listing(&job.url, &body, self.cfg.listing_max_links);
                    let docs: Vec<String> = links
                        .files
                        .iter()
                        .filter(|u| is_doc_ext(u, exts) || is_doc_ext(u, &archive_exts()))
                        .cloned()
                        .collect();
                    let mut hit = mk(
                        HitKind::DirListing,
                        Risk::Medium,
                        format!(
                            "листинг каталога: файлов {}, подкаталогов {}{}",
                            links.files.len(),
                            links.dirs.len(),
                            if links.truncated {
                                " (усечено)"
                            } else {
                                ""
                            }
                        ),
                    );
                    hit.extra = links
                        .files
                        .iter()
                        .chain(links.dirs.iter())
                        .cloned()
                        .collect();
                    run.add_hit(hit);
                    for d in &docs {
                        run.add_document(d);
                    }
                    if job.depth < self.cfg.listing_depth {
                        for d in &links.dirs {
                            if let Ok(u) = Url::parse(d) {
                                let w = u
                                    .path()
                                    .trim_end_matches('/')
                                    .rsplit('/')
                                    .next()
                                    .unwrap_or("")
                                    .to_string();
                                follow.push(
                                    u,
                                    job.host.clone(),
                                    &w,
                                    Module::DirListing,
                                    Expect::Directory,
                                    job.depth + 1,
                                );
                            }
                        }
                    }
                    if run.task.has(Module::Backups) {
                        for fu in links.files.iter().filter(|u| source_like(u)) {
                            if let Ok(u) = Url::parse(fu) {
                                for (v, n) in backup_variants(&u) {
                                    follow.push(v, None, &n, Module::Backups, Expect::Backup, 0);
                                }
                            }
                        }
                    }
                    return;
                }
                if !(ok2 || matches!(st, 401 | 403)) {
                    run.stats.filtered_rules += 1;
                    return;
                }
                let ev = match st {
                    401 | 403 => format!("каталог существует (HTTP {st}, листинг закрыт)"),
                    _ => format!(
                        "каталог существует{}",
                        title_of(&body)
                            .map(|t| format!(": «{t}»"))
                            .unwrap_or_default()
                    ),
                };
                // The site root is not a directory finding.
                if job.url.path() != "/" {
                    run.add_hit(mk(HitKind::Directory, Risk::Info, ev));
                }
                // Follow up inside the discovered directory.
                if run.task.has(Module::Docs) && job.module == Module::Docs {
                    for n in DOC_NAMES {
                        for e in exts {
                            let name = format!("{n}.{e}");
                            if let Ok(u) = job.url.join(&name) {
                                follow.push(u, None, &name, Module::Docs, Expect::Document, 1);
                            }
                        }
                    }
                }
                if run.task.has(Module::Exposed) && job.url.path() != "/" {
                    if let Ok(u) = job.url.join(".DS_Store") {
                        follow.push(u, None, ".DS_Store", Module::Exposed, Expect::Exposed, 0);
                    }
                }
                if job.module == Module::Content && job.depth < self.cfg.recursion_depth {
                    if let Some(c) = &run.task.content {
                        if c.template.host.is_none() && c.template.url.ends_with("/FUZZ") {
                            let _ = content_jobs(c, Some(&job.url), follow, job.depth + 1);
                        }
                    }
                }
            }
            Expect::Document | Expect::Named => {
                let name = job.url.path().rsplit('/').next().unwrap_or("").to_string();
                if !ok2 {
                    run.stats.filtered_rules += 1;
                    return;
                }
                let doc = is_doc_ext(&name, exts);
                if doc && is_html(f.content_type.as_deref())
                    || !body_fits_name(&name, f.content_type.as_deref(), &body)
                {
                    // A "document" served as an HTML page is the site template, not a file.
                    run.stats.filtered_rules += 1;
                    return;
                }
                let (kind, risk) = if doc {
                    (HitKind::Document, Risk::Info)
                } else if backup_like(&name) {
                    (HitKind::Backup, Risk::High)
                } else {
                    (HitKind::Content, Risk::Info)
                };
                let ev = if doc {
                    format!(
                        "{}, {} байт",
                        f.content_type.as_deref().unwrap_or("тип не указан"),
                        f.size
                    )
                } else {
                    evidence(&f.body, f.content_type.as_deref())
                };
                if run.add_hit(mk(kind, risk, ev)) {
                    if doc {
                        run.add_document(job.url.as_str());
                    }
                    self.after_file(run, &job, &name, follow);
                }
            }
            Expect::Backup | Expect::DbBackup => {
                if !ok2 {
                    run.stats.filtered_rules += 1;
                    return;
                }
                let name = job.url.path().rsplit('/').next().unwrap_or("").to_string();
                let archive = is_doc_ext(&name, &archive_exts());
                if (job.expect == Expect::DbBackup || archive) && is_html(f.content_type.as_deref())
                    || !body_fits_name(&name, f.content_type.as_deref(), &body)
                {
                    run.stats.filtered_rules += 1;
                    return;
                }
                let (kind, risk) = if job.expect == Expect::DbBackup {
                    (HitKind::DbBackup, Risk::High)
                } else if source_like(name.trim_end_matches('~')) || archive {
                    (HitKind::Backup, Risk::High)
                } else {
                    (HitKind::Backup, Risk::Medium)
                };
                run.add_hit(mk(kind, risk, evidence(&f.body, f.content_type.as_deref())));
            }
            Expect::Exposed => {
                if !ok2 {
                    run.stats.filtered_rules += 1;
                    return;
                }
                let path = job.url.path().to_string();
                let lower = path.to_ascii_lowercase();
                let name = lower.rsplit('/').next().unwrap_or("").to_string();
                if lower.ends_with("/.git/head") {
                    let t = body.trim();
                    let hex40 = t.len() == 40 && t.chars().all(|c| c.is_ascii_hexdigit());
                    if !(t.starts_with("ref: refs/") || hex40) {
                        run.stats.filtered_rules += 1;
                        return;
                    }
                    let first = truncate_chars(t.lines().next().unwrap_or(""), 120);
                    run.add_hit(mk(
                        HitKind::GitRepo,
                        Risk::High,
                        format!("HEAD: {first} (репозиторий не выгружался)"),
                    ));
                    return;
                }
                if name == ".ds_store" {
                    if !looks_like_ds_store(&f.body) {
                        run.stats.filtered_rules += 1;
                        return;
                    }
                    let lim = DsLimits {
                        max_input: self.cfg.body_limit as usize,
                        max_names: self.cfg.dsstore_max_names,
                        ..Default::default()
                    };
                    let parsed = parse_ds_store(&f.body, lim);
                    let (names, ev) = match parsed {
                        Ok(n) => {
                            let shown: Vec<&str> =
                                n.names.iter().take(10).map(String::as_str).collect();
                            let ev = format!(
                                "имён файлов: {}{}: {}",
                                n.names.len(),
                                if n.truncated { " (усечено)" } else { "" },
                                shown.join(", ")
                            );
                            (n.names, ev)
                        }
                        Err(e) => (Vec::new(), format!(".DS_Store не разобран: {e}")),
                    };
                    let mut hit = mk(HitKind::DsStore, Risk::Medium, truncate_chars(&ev, 400));
                    hit.extra = names.clone();
                    run.add_hit(hit);
                    for n in names.iter().filter(|n| safe_candidate(n)) {
                        if let Ok(u) = job.url.join(n) {
                            let (_, ext) = split_ext(n);
                            let expect = if ext.is_empty() {
                                // Most likely a directory.
                                follow.push(u.clone(), None, n, Module::Exposed, Expect::Named, 0);
                                if let Ok(d) = job.url.join(&format!("{n}/")) {
                                    follow.push(d, None, n, Module::Exposed, Expect::Directory, 0);
                                }
                                continue;
                            } else {
                                Expect::Named
                            };
                            follow.push(u, None, n, Module::Exposed, expect, 0);
                        }
                    }
                    return;
                }
                if name == ".env" || name.ends_with(".env") {
                    let looks_env = body.lines().take(50).any(|l| {
                        let l = l.trim();
                        l.split_once('=').is_some_and(|(k, _)| {
                            !k.is_empty()
                                && k.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
                        })
                    });
                    if !looks_env || is_html(f.content_type.as_deref()) {
                        run.stats.filtered_rules += 1;
                        return;
                    }
                    run.add_hit(with_artifact(
                        mk(
                            HitKind::Exposed,
                            Risk::High,
                            evidence(&f.body, f.content_type.as_deref()),
                        ),
                        &path,
                    ));
                    return;
                }
                if !body_fits_name(&name, f.content_type.as_deref(), &body) {
                    run.stats.filtered_rules += 1;
                    return;
                }
                let (kind, risk) = if backup_like(&name) {
                    (HitKind::Backup, Risk::High)
                } else if source_like(&name) || name.starts_with('.') {
                    (HitKind::Exposed, Risk::Medium)
                } else {
                    (HitKind::Exposed, Risk::Low)
                };
                let hit = with_artifact(
                    mk(kind, risk, evidence(&f.body, f.content_type.as_deref())),
                    &path,
                );
                if run.add_hit(hit) {
                    let n = path.rsplit('/').next().unwrap_or("").to_string();
                    self.after_file(run, &job, &n, follow);
                }
            }
            Expect::Vhost => {
                let title = title_of(&body);
                let ev = format!(
                    "Host: {} → HTTP {st}{}",
                    job.host.as_deref().unwrap_or(""),
                    title.map(|t| format!(", «{t}»")).unwrap_or_default()
                );
                run.add_hit(mk(HitKind::Vhost, Risk::Low, ev));
            }
            Expect::Generic | Expect::Cms => {
                let name = job.url.path().rsplit('/').next().unwrap_or("").to_string();
                let kind = if job.module == Module::Cms {
                    HitKind::CmsPath
                } else if is_doc_ext(&name, exts) && ok2 && !is_html(f.content_type.as_deref()) {
                    HitKind::Document
                } else {
                    HitKind::Content
                };
                let ev = if matches!(st, 401 | 403) {
                    format!("существует, доступ закрыт (HTTP {st})")
                } else if kind == HitKind::Document {
                    format!(
                        "{}, {} байт",
                        f.content_type.as_deref().unwrap_or("тип не указан"),
                        f.size
                    )
                } else {
                    evidence(&f.body, f.content_type.as_deref())
                };
                if run.add_hit(mk(kind, Risk::Info, ev)) && ok2 {
                    if kind == HitKind::Document {
                        run.add_document(job.url.as_str());
                    }
                    self.after_file(run, &job, &name, follow);
                }
            }
        }
    }

    /// Schedules follow-ups for a found file: name mutations (docs) and backups (backups).
    fn after_file(&self, run: &mut Run<'_>, job: &Job, name: &str, follow: &mut JobSink<'_>) {
        if name.is_empty() {
            return;
        }
        let exts = &run.task.doc_extensions;
        if run.task.has(Module::Docs) && is_doc_ext(name, exts) && job.depth < 2 {
            for m in mutate_name(name, self.cfg.max_mutations) {
                if let Ok(u) = job.url.join(&m) {
                    follow.push(u, None, &m, Module::Docs, Expect::Document, job.depth + 1);
                }
            }
        }
        if run.task.has(Module::Backups) && job.expect != Expect::Backup {
            for (v, n) in backup_variants(&job.url) {
                follow.push(v, None, &n, Module::Backups, Expect::Backup, 0);
            }
        }
    }
}

/// Returns `true` if the name looks like a backup (`.bak`, `.old`, `~`, `.swp`, …).
fn backup_like(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    l.ends_with('~')
        || [
            ".bak", ".old", ".orig", ".save", ".swp", ".backup", "_bak", ".copy", ".tmp",
        ]
        .iter()
        .any(|s| l.ends_with(s))
}

fn origin_eq(a: &Url, b: &Url) -> bool {
    a.scheme() == b.scheme()
        && a.host_str() == b.host_str()
        && a.port_or_known_default() == b.port_or_known_default()
}

fn archive_exts() -> Vec<String> {
    [
        "zip", "tar.gz", "tgz", "7z", "rar", "gz", "bz2", "tar", "sql", "bak", "dump",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}
