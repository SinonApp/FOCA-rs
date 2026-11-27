//! Document source trait and execution of a set of sources.

use std::collections::{BTreeSet, HashSet};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use foca_net::{NetClient, NetError};
use serde::{Deserialize, Serialize};

use crate::dorkboard::DorkBoard;
use crate::filter::{dedup_key, ext_of_url, image_quota, is_image_ext, ExtFilter};
use crate::BoxFuture;

/// Error prefix for "captcha / blocked" (`run_sources` sets the `blocked` status).
pub const BLOCKED: &str = "капча / заблокировано";

/// Whether a source touches the target.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceKind {
    /// Third-party services only (archives, search APIs, CT logs).
    Passive,
    /// Requests to target hosts (crawler), restricted to hosts in scope.
    TouchesTarget,
}

/// A discovered document URL.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FoundUrl {
    /// URL to download (for Wayback, the archive.org copy `.../web/<ts>id_/<orig>`).
    pub url: String,
    /// Original URL on the target site, if different from `url`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub original: Option<String>,
    /// Source identifier (`wayback`, `cc`, `crawler`, `brave`, `searx`, ...).
    pub source: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hint_ext: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
    /// Date (of the snapshot, index or publication) as reported by the source.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub date: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mime: Option<String>,
}

impl FoundUrl {
    pub fn new(url: &str, source: &str) -> Self {
        FoundUrl {
            url: url.to_string(),
            original: None,
            source: source.to_string(),
            hint_ext: crate::filter::ext_of_url(url),
            size: None,
            date: None,
            mime: None,
        }
    }

    pub fn with_original(mut self, o: &str) -> Self {
        self.hint_ext = crate::filter::ext_of_url(o).or(self.hint_ext);
        self.original = Some(o.to_string());
        self
    }

    /// Returns the document URL on the target site (for path analysis and deduplication).
    pub fn target_url(&self) -> &str {
        self.original.as_deref().unwrap_or(&self.url)
    }
}

/// Result of a single source.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Found {
    pub urls: Vec<FoundUrl>,
    /// Discovered hosts (subdomains) for the crawler and the DNS stage.
    pub hosts: Vec<String>,
    /// Note on a partial success (status `ok`, text in `SourceReport.error`), for example that some
    /// indexes were unavailable.
    pub note: Option<String>,
}

/// Search context.
#[derive(Clone)]
pub struct SearchCtx {
    pub net: NetClient,
    pub filter: ExtFilter,
    /// Maximum number of URLs per source.
    pub limit: usize,
    /// Known target hosts (from crt.sh/DNS), used as extra crawler start points.
    pub hosts: Vec<String>,
    /// Soft deadline of the source: paginated sources check it before each page and return what they
    /// have collected, so a partial result survives the source's overall timeout.
    pub deadline: Option<Instant>,
    /// Documents already known to the project (`filter::target_key`). Sources skip them before
    /// applying their limit; otherwise a rescan would get the same first N and find nothing new.
    pub known: Arc<HashSet<String>>,
    /// Retry notification inside a source (`id`, retry number, reason), used for the "retry N" label
    /// on the scan screen (a `source` event with status `running` and a `retry` field).
    pub on_retry: Option<RetryHook>,
    /// Browser engine (a hidden WebView on Android) for search engines with JavaScript challenges.
    /// `None` in the CLI, `serve` and host tests, where such sources report that a WebView is required.
    pub render: Option<Arc<dyn crate::render::RenderFetch>>,
    /// True during autonomous headless background runs (e.g. Android WorkManager): WebView-only
    /// sources report `skipped_headless` instead of `unavailable`.
    pub headless: bool,
    /// Shared dork board of the scan (queue, failover, budget, cache); `None` lets the engine use its own.
    pub dorks: Option<Arc<DorkBoard>>,
    /// Pause state of the scan (`Some(reason)` while paused); long sources that touch the target
    /// hold their requests while it is set ([`SearchCtx::with_pause`]).
    pause: Option<tokio::sync::watch::Receiver<Option<String>>>,
}

/// Retry callback: `(source id, retry number starting at 1, reason)`.
pub type RetryHook = Arc<dyn Fn(&str, u32, &str) + Send + Sync>;

impl SearchCtx {
    /// Reports a source request retry to the subscriber, if any.
    pub fn retrying(&self, id: &str, n: u32, why: &str) {
        if let Some(h) = &self.on_retry {
            h(id, n, why);
        }
    }

    pub fn new(net: NetClient) -> Self {
        SearchCtx {
            net,
            filter: ExtFilter::default(),
            limit: 500,
            hosts: Vec::new(),
            deadline: None,
            known: Arc::new(HashSet::new()),
            on_retry: None,
            render: None,
            headless: false,
            dorks: None,
            pause: None,
        }
    }

    /// Follows the scan's pause state (`Some(reason)` while paused).
    pub fn with_pause(mut self, pause: tokio::sync::watch::Receiver<Option<String>>) -> Self {
        self.pause = Some(pause);
        self
    }

    /// Returns `true` while the scan is paused.
    pub fn is_paused(&self) -> bool {
        self.pause.as_ref().is_some_and(|p| p.borrow().is_some())
    }

    /// Returns the time left until the soft deadline (`None` if there is no deadline).
    pub fn time_left(&self) -> Option<Duration> {
        self.deadline
            .map(|d| d.saturating_duration_since(Instant::now()))
    }

    /// Returns `true` if the document is already known to the project.
    pub fn is_known(&self, u: &FoundUrl) -> bool {
        !self.known.is_empty()
            && self
                .known
                .contains(&crate::filter::target_key(u.target_url()))
    }

    /// Returns `true` if less than `min` remains until the deadline.
    pub fn out_of_time(&self, min: Duration) -> bool {
        self.time_left().is_some_and(|t| t < min)
    }

    /// Returns the timeout for a single request: `want`, capped by the soft deadline (at least 5 s).
    pub fn req_timeout(&self, want: Duration) -> Duration {
        match self.time_left() {
            Some(t) => want.min(t).max(Duration::from_secs(5)),
            None => want,
        }
    }
}

/// A document source.
pub trait DocumentSource: Send + Sync {
    /// Identifier (as in `ui/js/demo-backend.js`).
    fn id(&self) -> &'static str;
    fn name(&self) -> &'static str;
    fn kind(&self) -> SourceKind;
    /// Whether the source requires an API key or an instance URL.
    fn needs_key(&self) -> bool {
        false
    }
    /// Whether the key is set (always `true` for keyless sources).
    fn has_key(&self) -> bool {
        true
    }
    /// Multiplier for the source's overall timeout (higher for slow paginated archives).
    fn budget(&self) -> u32 {
        1
    }
    /// A source with its own wall-time limit (the crawler) replaces the overall timeout with it.
    fn own_timeout(&self) -> Option<Duration> {
        None
    }
    fn find<'a>(
        &'a self,
        ctx: &'a SearchCtx,
        domain: &'a str,
    ) -> BoxFuture<'a, Result<Found, NetError>>;
}

/// Source status in a scan (`docs/API.md`: `ok | nokey | error | off`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceStatus {
    Ok,
    Nokey,
    Error,
    Off,
    /// Did not finish within the source's overall timeout (`SourceCtl::timeout`); the stage moves on without it.
    Timeout,
    /// Skipped by the user (`scan_skip_source`).
    Skipped,
    /// Captcha or block by the search engine (keyless dorks); the source works on a best-effort basis.
    Blocked,
    /// Needs an embedded browser (WebView) that is not available: CLI, `serve`, host tests (Android only).
    Unavailable,
    /// Skipped in autonomous headless background mode where no Android WebView can be attached.
    SkippedHeadless,
    /// The service rate-limited the requests (HTTP 429 or 503 after `Retry-After` retries and
    /// slowing down, see [`crate::rate::Throttle`]).
    Limit,
}

/// Returns the text for the `limit` status (HTTP 429): what happened and what to do.
pub fn limit_message(id: &str) -> String {
    let base =
        "сервис ограничил частоту запросов (HTTP 429): повторы с паузой не помогли; повторите \
                скан позже или с другой сети";
    if id.starts_with("otx") {
        format!("{base}. Лимит OTX общий для «OTX passive DNS» и «OTX (URL)»: второй в этом скане не опрашивается")
    } else {
        base.to_string()
    }
}

/// Returns the `limit` text for a final HTTP 429 or 503 (overloaded or throttling service).
pub fn limit_message_status(id: &str, status: u16) -> String {
    if status == 503 {
        "сервис перегружен или ограничил частоту запросов (HTTP 503): повторы с паузой не помогли; \
         источник остановлен до следующего скана"
            .into()
    } else {
        limit_message(id)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceReport {
    pub id: String,
    pub name: String,
    pub status: SourceStatus,
    pub n: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SearchResult {
    pub sources: Vec<SourceReport>,
    /// URLs filtered by extension and deduplicated.
    pub urls: Vec<FoundUrl>,
    pub hosts: Vec<String>,
    /// Which sources found each host name (`host -> [id, ...]`).
    #[serde(default)]
    pub host_sources: std::collections::BTreeMap<String, Vec<String>>,
}

/// Source control during a scan: an overall timeout per source and "skip source".
#[derive(Clone)]
pub struct SourceCtl {
    /// Hard limit for a source as a whole (all pages, retries and backoff included).
    pub timeout: Duration,
    /// Ids of sources the user asked to skip (checked while running).
    pub skip: Arc<Mutex<HashSet<String>>>,
    /// Number of passive sources queried concurrently (1 means sequentially).
    pub parallel: usize,
}

impl Default for SourceCtl {
    fn default() -> Self {
        SourceCtl {
            timeout: Duration::from_secs(90),
            skip: Arc::new(Mutex::new(HashSet::new())),
            parallel: 1,
        }
    }
}

impl SourceCtl {
    pub fn skipped(&self, id: &str) -> bool {
        self.skip.lock().map(|g| g.contains(id)).unwrap_or(false)
    }
}

/// Runs the sources sequentially (order is the dedup priority). Hosts found by crt.sh are passed
/// to later sources (the crawler) through `ctx.hosts`. `on_source` is called after each source
/// (for the scan's `source` event). No timeout is applied; see [`run_sources_ctl`].
pub async fn run_sources(
    sources: &[Box<dyn DocumentSource>],
    ctx: &SearchCtx,
    domain: &str,
    on_source: impl FnMut(&SourceReport),
) -> Result<SearchResult, NetError> {
    let ctl = SourceCtl {
        timeout: Duration::from_secs(24 * 3600),
        ..Default::default()
    };
    run_sources_ctl(sources, ctx, domain, &ctl, |_, _| {}, on_source).await
}

/// Result of a single source run.
struct OneRun {
    rep: SourceReport,
    found: Option<Found>,
    cancelled: bool,
    ms: u128,
}

/// Returns the hard deadline of a source: the overall timeout times `budget` (three times longer for slow archives).
pub fn source_timeout(s: &dyn DocumentSource, ctl: &SourceCtl) -> Duration {
    s.own_timeout()
        .unwrap_or_else(|| ctl.timeout * s.budget().max(1))
}

async fn run_one(
    s: &dyn DocumentSource,
    mut ctx: SearchCtx,
    domain: &str,
    ctl: &SourceCtl,
) -> OneRun {
    let mut rep = SourceReport {
        id: s.id().into(),
        name: s.name().into(),
        status: SourceStatus::Ok,
        n: 0,
        error: None,
    };
    let t0 = Instant::now();
    let timeout = source_timeout(s, ctl);
    tracing::info!(target: "foca::source", "{}: старт ({domain}), таймаут {} с", s.id(), timeout.as_secs());
    // the soft deadline is a little earlier than the hard timeout so the source can return what it has
    let margin = (timeout / 8).clamp(Duration::from_secs(1), Duration::from_secs(10));
    ctx.deadline = Some(Instant::now() + timeout.saturating_sub(margin));
    let id = s.id();
    let skip = async {
        loop {
            tokio::time::sleep(Duration::from_millis(200)).await;
            if ctl.skipped(id) {
                return;
            }
        }
    };
    let r = tokio::select! {
        r = tokio::time::timeout(timeout, s.find(&ctx, domain)) => r.map_err(|_| ()),
        _ = skip => Err(()),
    };
    let mut found = None;
    let mut cancelled = false;
    match r {
        Ok(Ok(f)) => {
            rep.error = f.note.clone();
            found = Some(f);
        }
        Ok(Err(NetError::Cancelled)) => cancelled = true,
        Ok(Err(NetError::NoKey(_))) => rep.status = SourceStatus::Nokey,
        Ok(Err(NetError::Request(m))) if m.starts_with(crate::render::NO_RENDER) => {
            if ctx.headless {
                rep.status = SourceStatus::SkippedHeadless;
                rep.error = Some("недоступно в фоновом режиме (нет WebView)".into());
            } else {
                rep.status = SourceStatus::Unavailable;
                rep.error = Some(m);
            }
        }
        Ok(Err(NetError::Status(st @ (429 | 503)))) => {
            rep.status = SourceStatus::Limit;
            rep.error = Some(limit_message_status(id, st));
        }
        Ok(Err(NetError::Request(m))) if m.starts_with(BLOCKED) => {
            rep.status = SourceStatus::Blocked;
            rep.error = Some(m);
        }
        Ok(Err(e)) => {
            rep.status = SourceStatus::Error;
            rep.error = Some(e.to_string());
        }
        Err(()) if ctl.skipped(id) => {
            rep.status = SourceStatus::Skipped;
            rep.error = Some("пропущен пользователем".into());
        }
        Err(()) => {
            rep.status = SourceStatus::Timeout;
            rep.error = Some(format!("нет ответа за {} с", timeout.as_secs()));
        }
    }
    // Race: the skip was accepted (`scan_skip_source` returned ok:true) but the source failed before
    // polling the flag. The final status must agree with the command's answer.
    if found.is_none() && !cancelled && ctl.skipped(id) && rep.status != SourceStatus::Skipped {
        rep.status = SourceStatus::Skipped;
        rep.error = Some("пропущен пользователем".into());
    }
    OneRun {
        rep,
        found,
        cancelled,
        ms: t0.elapsed().as_millis(),
    }
}

/// Like [`run_sources`], but every source has an overall timeout `ctl.timeout` (status `timeout`;
/// a multiple of `DocumentSource::budget` for slow archives) and can be skipped (`ctl.skip`,
/// status `skipped`), so a hung source does not hold up the stage. Passive sources run in
/// parallel (`ctl.parallel` at a time), then sources that touch the target (the crawler) run
/// sequentially with the hosts found by the passive ones. List order is the URL dedup priority.
/// `on_start(id, timeout)` signals that a source started (a `source` event with status
/// `running`); `timeout` is its effective hard deadline (`ctl.timeout × budget`), which the UI
/// uses to show the remaining time.
pub async fn run_sources_ctl(
    sources: &[Box<dyn DocumentSource>],
    ctx: &SearchCtx,
    domain: &str,
    ctl: &SourceCtl,
    mut on_start: impl FnMut(&str, Duration),
    mut on_source: impl FnMut(&SourceReport),
) -> Result<SearchResult, NetError> {
    use futures_util::stream::{FuturesUnordered, StreamExt};
    let mut res = SearchResult::default();
    let mut hosts: BTreeSet<String> = ctx.hosts.iter().cloned().collect();
    let mut done: Vec<Option<OneRun>> = (0..sources.len()).map(|_| None).collect();
    let pre = |s: &dyn DocumentSource| -> Option<SourceStatus> {
        if s.needs_key() && !s.has_key() {
            Some(SourceStatus::Nokey)
        } else if ctl.skipped(s.id()) {
            Some(SourceStatus::Skipped)
        } else {
            None
        }
    };
    let instant = |s: &dyn DocumentSource, st: SourceStatus| OneRun {
        rep: SourceReport {
            id: s.id().into(),
            name: s.name().into(),
            status: st,
            n: 0,
            error: None,
        },
        found: None,
        cancelled: false,
        ms: 0,
    };
    // 1) passive sources, in parallel
    let mut queue: std::collections::VecDeque<usize> = (0..sources.len())
        .filter(|&i| sources[i].kind() == SourceKind::Passive)
        .collect();
    let par = ctl.parallel.max(1);
    let mut running = FuturesUnordered::new();
    loop {
        while running.len() < par {
            let Some(i) = queue.pop_front() else { break };
            let s = sources[i].as_ref();
            if let Some(st) = pre(s) {
                let one = instant(s, st);
                on_source(&one.rep);
                done[i] = Some(one);
                continue;
            }
            if ctx.net.is_cancelled() {
                return Err(NetError::Cancelled);
            }
            on_start(s.id(), source_timeout(s, ctl));
            let c = ctx.clone();
            running.push(async move { (i, run_one(s, c, domain, ctl).await) });
        }
        let Some((i, mut one)) = running.next().await else {
            break;
        };
        if one.cancelled || ctx.net.is_cancelled() {
            return Err(NetError::Cancelled);
        }
        finish_one(&mut one, ctx);
        on_source(&one.rep);
        if let Some(f) = &one.found {
            hosts.extend(f.hosts.iter().cloned());
        }
        done[i] = Some(one);
    }
    // 2) sources that touch the target, sequentially, with the discovered hosts
    for i in (0..sources.len()).filter(|&i| sources[i].kind() != SourceKind::Passive) {
        let s = sources[i].as_ref();
        if ctx.net.is_cancelled() {
            return Err(NetError::Cancelled);
        }
        let mut one = match pre(s) {
            Some(st) => instant(s, st),
            None => {
                on_start(s.id(), source_timeout(s, ctl));
                let mut c = ctx.clone();
                c.hosts = hosts.iter().cloned().collect();
                run_one(s, c, domain, ctl).await
            }
        };
        if one.cancelled || ctx.net.is_cancelled() {
            return Err(NetError::Cancelled);
        }
        finish_one(&mut one, ctx);
        on_source(&one.rep);
        if let Some(f) = &one.found {
            hosts.extend(f.hosts.iter().cloned());
        }
        done[i] = Some(one);
    }
    // summary in the original order (dedup priority)
    let mut all = Vec::new();
    for one in done.into_iter().flatten() {
        if let Some(f) = one.found {
            for h in &f.hosts {
                let v = res.host_sources.entry(h.clone()).or_default();
                if !v.contains(&one.rep.id) {
                    v.push(one.rep.id.clone());
                }
            }
            all.extend(f.urls);
        }
        res.sources.push(one.rep);
    }
    res.urls = dedupe(all);
    res.hosts = hosts.into_iter().collect();
    Ok(res)
}

/// Filters a source's URLs (extension, already known, limit), updates counters and logs.
fn finish_one(one: &mut OneRun, ctx: &SearchCtx) {
    if let Some(f) = one.found.as_mut() {
        let urls: Vec<FoundUrl> = std::mem::take(&mut f.urls)
            .into_iter()
            .filter(|u| ctx.filter.matches(u.target_url()).is_some())
            .filter(|u| !ctx.is_known(u))
            .take(ctx.limit)
            .collect();
        one.rep.n = urls.len() + if urls.is_empty() { f.hosts.len() } else { 0 };
        f.urls = urls;
    }
    let ms = one.ms;
    let rep = &one.rep;
    match rep.status {
        SourceStatus::Error | SourceStatus::Timeout => tracing::warn!(target: "foca::source",
            "{}: {:?} за {ms} мс {}", rep.id, rep.status, rep.error.as_deref().unwrap_or("")),
        _ => {
            tracing::info!(target: "foca::source", "{}: {:?}, найдено {} за {ms} мс", rep.id, rep.status, rep.n)
        }
    }
}

/// Deduplicates found URLs by the document's original URL; the first one wins and order is preserved.
pub fn dedupe(items: Vec<FoundUrl>) -> Vec<FoundUrl> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for it in items {
        let key = dedup_key(it.original.as_deref().unwrap_or(&it.url));
        if seen.insert(key) {
            out.push(it);
        }
    }
    out
}

/// Takes documents first (up to `limit`) and images within a separate [`image_quota`]; order
/// within each group is preserved and the total never exceeds `limit`.
pub fn take_balanced(items: Vec<FoundUrl>, limit: usize) -> Vec<FoundUrl> {
    let (mut docs, imgs): (Vec<FoundUrl>, Vec<FoundUrl>) =
        items.into_iter().partition(|u| !found_is_image(u));
    docs.truncate(limit);
    let room = limit.saturating_sub(docs.len()).min(image_quota(limit));
    docs.extend(imgs.into_iter().take(room));
    docs
}

fn found_is_image(u: &FoundUrl) -> bool {
    u.hint_ext
        .clone()
        .or_else(|| ext_of_url(u.target_url()))
        .is_some_and(|e| is_image_ext(&e))
}

/// Picks downloads fairly: documents round-robin across sources (so Wayback cannot eat the whole
/// limit before the crawler or CC), then images round-robin, up to [`image_quota`].
pub fn pick_fair(items: Vec<FoundUrl>, limit: usize) -> Vec<FoundUrl> {
    use std::collections::VecDeque;
    fn groups(v: Vec<FoundUrl>) -> Vec<VecDeque<FoundUrl>> {
        let mut out: Vec<(String, VecDeque<FoundUrl>)> = Vec::new();
        for u in v {
            match out.iter_mut().find(|g| g.0 == u.source) {
                Some(g) => g.1.push_back(u),
                None => out.push((u.source.clone(), VecDeque::from([u]))),
            }
        }
        out.into_iter().map(|g| g.1).collect()
    }
    fn round_robin(mut g: Vec<VecDeque<FoundUrl>>, n: usize, out: &mut Vec<FoundUrl>) {
        let mut taken = 0;
        while taken < n && g.iter().any(|q| !q.is_empty()) {
            for q in g.iter_mut() {
                if taken >= n {
                    break;
                }
                if let Some(u) = q.pop_front() {
                    out.push(u);
                    taken += 1;
                }
            }
        }
    }
    let (docs, imgs): (Vec<FoundUrl>, Vec<FoundUrl>) =
        items.into_iter().partition(|u| !found_is_image(u));
    let mut out = Vec::new();
    round_robin(groups(docs), limit, &mut out);
    let room = limit.saturating_sub(out.len()).min(image_quota(limit));
    round_robin(groups(imgs), room, &mut out);
    out
}
