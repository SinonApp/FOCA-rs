//! Common Crawl Index (CDX API of every crawl snapshot): a quick pass over the latest snapshots
//! and a deep sweep over the last N years or all snapshots.
//!
//! The public index is unreliable: snapshots answer 400/404/502/504 at random between good
//! answers, and a fast sweep fails on half of them. So every index call is paced
//! ([`CommonCrawl::pace`], at least 3 s against the real service), 5xx/timeouts are retried with
//! backoff, 404 means "no captures", 429/503 slow the sweep down and finally stop it
//! ([`crate::rate::Throttle`]). `showNumPages` skips empty snapshots before any page is fetched.
//! The same URL seen in many snapshots is kept once with its first and last capture time.
//!
//! With a cache directory the sweep is resumable: finished snapshots and their hits are stored
//! per domain and file type filter. A rescan within [`CommonCrawl::cache_ttl`] sends no request
//! for finished snapshots; older snapshots never change, so their results are kept for
//! [`CommonCrawl::resume_ttl`] and a stopped deep sweep continues where it left off.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use foca_net::{Access, NetError, NetRequest};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::rate::{self, Throttle, Verdict};
use crate::source::{DocumentSource, Found, FoundUrl, SearchCtx, SourceKind};
use crate::sources::archive::Collector;
use crate::BoxFuture;

/// Host of the public index (pacing and backoff defaults apply only to it).
pub const CC_INDEX_HOST: &str = "https://index.commoncrawl.org";

/// Parses Common Crawl Index NDJSON.
pub fn parse_cc_ndjson(text: &str) -> Vec<BTreeMap<String, String>> {
    text.lines()
        .filter_map(|l| serde_json::from_str::<BTreeMap<String, Value>>(l.trim()).ok())
        .map(|m| {
            m.into_iter()
                .map(|(k, v)| {
                    let s = match v {
                        Value::String(s) => s,
                        other => other.to_string(),
                    };
                    (k, s)
                })
                .collect()
        })
        .collect()
}

/// How many crawl snapshots to query.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CcDepth {
    /// The newest N snapshots that answer (quick, the default; N is `CommonCrawl::max_indexes`).
    Latest(usize),
    /// Every snapshot of the last N years (counted from the newest snapshot).
    Years(u32),
    /// Every snapshot.
    All,
}

impl Default for CcDepth {
    fn default() -> Self {
        CcDepth::Latest(3)
    }
}

impl CcDepth {
    /// Reads the setting `search.cc_depth` (`latest` | `years` | `all`) with `search.cc_years`.
    pub fn parse(mode: &str, years: u64) -> CcDepth {
        match mode.trim() {
            "all" => CcDepth::All,
            "years" => CcDepth::Years(years.clamp(1, 20) as u32),
            _ => CcDepth::Latest(3),
        }
    }

    /// A deep sweep (years or all snapshots) that runs beside the other sources.
    pub fn deep(&self) -> bool {
        !matches!(self, CcDepth::Latest(_))
    }
}

/// One crawl snapshot from `collinfo.json`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CcIndex {
    pub id: String,
    pub api: String,
    pub year: Option<i32>,
}

impl CcIndex {
    fn label(&self) -> &str {
        self.api.rsplit('/').next().unwrap_or(&self.api)
    }
}

fn year_of(id: &str, to: Option<&str>) -> Option<i32> {
    let from_id = id
        .split('-')
        .find(|p| p.len() == 4 && p.bytes().all(|b| b.is_ascii_digit()))
        .and_then(|p| p.parse().ok());
    from_id.or_else(|| to.and_then(|t| t.get(..4)).and_then(|y| y.parse().ok()))
}

/// Parses `collinfo.json` into snapshots, newest first (the order of the file).
pub fn parse_collinfo(v: &Value) -> Vec<CcIndex> {
    v.as_array()
        .map(|a| {
            a.iter()
                .filter_map(|x| {
                    let api = x["cdx-api"].as_str()?.to_string();
                    let id = x["id"].as_str().unwrap_or(&api).to_string();
                    let year = year_of(&id, x["to"].as_str().or(x["from"].as_str()));
                    Some(CcIndex { id, api, year })
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Picks the snapshots for a depth: Latest keeps `tries` newest (fallbacks for unavailable ones),
/// Years keeps those not older than the newest snapshot's year minus N-1, All keeps everything.
pub fn select_indexes(all: &[CcIndex], depth: CcDepth, tries: usize) -> Vec<CcIndex> {
    match depth {
        CcDepth::Latest(n) => all.iter().take(tries.max(n).max(1)).cloned().collect(),
        CcDepth::All => all.to_vec(),
        CcDepth::Years(y) => {
            let newest = all.iter().filter_map(|i| i.year).max();
            match newest {
                Some(top) => {
                    let from = top - y.max(1) as i32 + 1;
                    all.iter()
                        .filter(|i| i.year.is_none_or(|yr| yr >= from))
                        .cloned()
                        .collect()
                }
                None => all.to_vec(),
            }
        }
    }
}

/// A document URL seen in one or more snapshots.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CcHit {
    pub url: String,
    /// Earliest capture timestamp (`YYYYMMDDhhmmss`).
    pub first: String,
    /// Latest capture timestamp.
    pub last: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mime: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub length: Option<u64>,
    pub ext: String,
}

/// Persistent sweep state of one domain and filter.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct CcState {
    /// Finished snapshots (answered, possibly empty): id -> unix time.
    pub done: BTreeMap<String, i64>,
    /// Hits by dedup key.
    pub hits: BTreeMap<String, CcHit>,
}

impl CcState {
    /// Adds a capture; the same URL from another snapshot widens its first/last range.
    pub fn add(&mut self, url: &str, ts: &str, mime: Option<&str>, length: Option<u64>, ext: &str) {
        let key = crate::filter::dedup_key(url);
        match self.hits.get_mut(&key) {
            Some(h) => {
                if ts < h.first.as_str() {
                    h.first = ts.to_string();
                }
                if ts > h.last.as_str() {
                    h.last = ts.to_string();
                    h.url = url.to_string();
                    h.mime = mime.map(String::from).or(h.mime.take());
                    h.length = length.or(h.length);
                }
            }
            None => {
                self.hits.insert(
                    key,
                    CcHit {
                        url: url.to_string(),
                        first: ts.to_string(),
                        last: ts.to_string(),
                        mime: mime.map(String::from),
                        length,
                        ext: ext.to_string(),
                    },
                );
            }
        }
    }

    /// Whether snapshot `id` was finished recently enough to skip it.
    fn fresh(&self, id: &str, newest: bool, now: i64, cc: &CommonCrawl) -> bool {
        self.done.get(id).is_some_and(|t| {
            let age = now.saturating_sub(*t).max(0) as u64;
            let ttl = if newest { cc.cache_ttl } else { cc.resume_ttl };
            age < ttl.as_secs()
        })
    }

    /// Drops finished marks older than the resume window, then hits beyond `cap` (oldest last
    /// capture first).
    fn prune(&mut self, now: i64, cc: &CommonCrawl) {
        let keep = cc.resume_ttl.as_secs() as i64;
        self.done.retain(|_, t| now.saturating_sub(*t) < keep);
        if self.done.is_empty() {
            self.hits.clear();
        }
        if self.hits.len() > cc.max_cached {
            let mut v: Vec<(String, String)> = self
                .hits
                .iter()
                .map(|(k, h)| (h.last.clone(), k.clone()))
                .collect();
            v.sort();
            let cut = self.hits.len() - cc.max_cached;
            for (_, k) in v.into_iter().take(cut) {
                self.hits.remove(&k);
            }
        }
    }
}

/// In-process cache of collinfo.json for one day.
static COLLINFO: Mutex<Vec<(String, Instant, Vec<CcIndex>)>> = Mutex::new(Vec::new());
const COLLINFO_TTL: Duration = Duration::from_secs(24 * 3600);

/// Common Crawl Index source (`cc`). URLs point at the target site; with the passive profile the
/// engine downloads their Wayback copies (`id_`), and a CC URL that is dead now falls back to its
/// Wayback copy at download time.
#[derive(Debug, Clone)]
pub struct CommonCrawl {
    pub collinfo: String,
    /// Explicit CDX API endpoint of an index (otherwise snapshots come from collinfo).
    pub index_api: Option<String>,
    /// Quick mode: snapshots that must answer.
    pub max_indexes: usize,
    /// Quick mode: snapshots to try when the newest are unavailable.
    pub max_tries: usize,
    /// Pages per snapshot (one page is about 15k index lines).
    pub max_pages: usize,
    pub depth: CcDepth,
    /// Minimum spacing between index calls; `None` is 3 s against the public index, none otherwise.
    pub pace: Option<Duration>,
    /// Retries of one call after 5xx/400/timeout.
    pub retries: u32,
    /// First backoff after a failed call (doubles each retry); `None` is 5 s against the public
    /// index, 20 ms otherwise.
    pub backoff: Option<Duration>,
    /// Directory of the per-domain sweep cache (`None`: no cache, nothing resumes).
    pub cache_dir: Option<PathBuf>,
    /// The newest snapshot is re-checked after this time.
    pub cache_ttl: Duration,
    /// Older (immutable) snapshots stay finished this long.
    pub resume_ttl: Duration,
    /// Hits kept per domain in the cache.
    pub max_cached: usize,
}

impl Default for CommonCrawl {
    fn default() -> Self {
        CommonCrawl {
            collinfo: format!("{CC_INDEX_HOST}/collinfo.json"),
            index_api: None,
            max_indexes: 3,
            max_tries: 5,
            max_pages: 3,
            depth: CcDepth::default(),
            pace: None,
            retries: 3,
            backoff: None,
            cache_dir: None,
            cache_ttl: Duration::from_secs(24 * 3600),
            resume_ttl: Duration::from_secs(30 * 24 * 3600),
            max_cached: 20_000,
        }
    }
}

/// Outcome of one paced index call.
enum Got {
    Body(String),
    NoCaptures,
    Failed(String),
    Stop,
}

impl CommonCrawl {
    pub fn with_collinfo(url: &str) -> Self {
        CommonCrawl {
            collinfo: url.into(),
            ..Default::default()
        }
    }

    /// Sets the depth; deep sweeps page further through each snapshot.
    pub fn with_depth(mut self, depth: CcDepth) -> Self {
        self.depth = depth;
        if let CcDepth::Latest(n) = depth {
            self.max_indexes = n.max(1);
        }
        if depth.deep() {
            self.max_pages = self.max_pages.max(10);
        }
        self
    }

    /// Minimum spacing between index calls (the public index never goes below 3 s anyway).
    pub fn with_pace(mut self, pace: Duration) -> Self {
        self.pace = Some(pace);
        self
    }

    /// Directory of the per-domain sweep cache; without it nothing resumes.
    pub fn with_cache_dir(mut self, dir: PathBuf) -> Self {
        self.cache_dir = Some(dir);
        self
    }

    /// A sweep over years or all snapshots (runs beside the other sources).
    pub fn is_deep(&self) -> bool {
        self.depth.deep()
    }

    fn official(&self) -> bool {
        self.index_api
            .as_deref()
            .unwrap_or(&self.collinfo)
            .starts_with(CC_INDEX_HOST)
    }

    /// Effective spacing between index calls.
    pub fn pace(&self) -> Duration {
        self.pace.unwrap_or(if self.official() {
            Duration::from_secs(3)
        } else {
            Duration::ZERO
        })
    }

    fn backoff(&self) -> Duration {
        self.backoff.unwrap_or(if self.official() {
            Duration::from_secs(5)
        } else {
            Duration::from_millis(20)
        })
    }

    fn tries(&self) -> usize {
        self.max_tries.max(self.max_indexes).max(1)
    }

    /// Returns every snapshot from collinfo (cached for a day), newest first.
    pub async fn all_indexes(&self, ctx: &SearchCtx) -> Result<Vec<CcIndex>, NetError> {
        if let Some(a) = &self.index_api {
            let id = a.rsplit('/').next().unwrap_or(a).trim_end_matches("-index");
            return Ok(vec![CcIndex {
                id: id.to_string(),
                api: a.clone(),
                year: year_of(id, None),
            }]);
        }
        if let Ok(g) = COLLINFO.lock() {
            if let Some((_, t, v)) = g.iter().find(|x| x.0 == self.collinfo) {
                if t.elapsed() < COLLINFO_TTL && !v.is_empty() {
                    return Ok(v.clone());
                }
            }
        }
        let v: Value = ctx
            .net
            .get_json(
                NetRequest::get(&self.collinfo, "cc", Access::Passive)?
                    .timeout(ctx.req_timeout(Duration::from_secs(30)))
                    .retries(1),
            )
            .await?;
        let all = parse_collinfo(&v);
        if all.is_empty() {
            return Err(NetError::Parse("collinfo.json: нет cdx-api".into()));
        }
        if let Ok(mut g) = COLLINFO.lock() {
            g.retain(|x| x.0 != self.collinfo);
            g.push((self.collinfo.clone(), Instant::now(), all.clone()));
        }
        Ok(all)
    }

    /// Returns the CDX API endpoints to query for the configured depth, newest first.
    pub async fn indexes(&self, ctx: &SearchCtx) -> Result<Vec<String>, NetError> {
        let all = self.all_indexes(ctx).await?;
        Ok(select_indexes(&all, self.depth, self.tries())
            .into_iter()
            .map(|i| i.api)
            .collect())
    }

    /// Returns the CDX API endpoint of the latest index.
    pub async fn latest_index(&self, ctx: &SearchCtx) -> Result<String, NetError> {
        self.indexes(ctx)
            .await?
            .into_iter()
            .next()
            .ok_or_else(|| NetError::Parse("collinfo.json: нет cdx-api".into()))
    }

    /// Builds an index query: the page count (`page: None`) or one page filtered on the server by
    /// status and the file type regex of the URL.
    pub fn index_url(
        api: &str,
        domain: &str,
        filter: &crate::filter::ExtFilter,
        page: Option<usize>,
    ) -> Result<String, NetError> {
        let mut u = url::Url::parse(api).map_err(|e| NetError::BadUrl(e.to_string()))?;
        {
            let mut q = u.query_pairs_mut();
            q.append_pair("url", &format!("*.{domain}"))
                .append_pair("output", "json");
            match page {
                None => {
                    q.append_pair("showNumPages", "true");
                }
                Some(p) => {
                    q.append_pair("filter", "status:200")
                        .append_pair("filter", &format!("~url:{}", filter.url_regex()))
                        .append_pair("fl", "url,timestamp,mime,status,length")
                        .append_pair("page", &p.to_string());
                }
            }
        }
        Ok(u.to_string())
    }

    /// Path of the sweep cache file for a domain and the current filter.
    pub fn cache_file(&self, domain: &str, filter: &crate::filter::ExtFilter) -> Option<PathBuf> {
        use sha2::Digest;
        let dir = self.cache_dir.as_ref()?;
        let safe: String = domain
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || c == '.' || c == '-' {
                    c
                } else {
                    '_'
                }
            })
            .collect();
        let h = sha2::Sha256::digest(filter.url_regex().as_bytes());
        let tag: String = h.iter().take(4).map(|b| format!("{b:02x}")).collect();
        Some(dir.join(format!("{safe}-{tag}.json")))
    }

    /// Loads the sweep state of a domain (empty without a cache or on a broken file).
    pub fn load_state(&self, domain: &str, filter: &crate::filter::ExtFilter) -> CcState {
        self.cache_file(domain, filter)
            .and_then(|p| std::fs::read(p).ok())
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default()
    }

    fn save_state(&self, domain: &str, filter: &crate::filter::ExtFilter, st: &CcState) {
        let Some(p) = self.cache_file(domain, filter) else {
            return;
        };
        if let Some(d) = p.parent() {
            let _ = std::fs::create_dir_all(d);
        }
        if let Ok(b) = serde_json::to_vec(st) {
            let tmp = p.with_extension("tmp");
            if std::fs::write(&tmp, b).is_ok() {
                let _ = std::fs::rename(&tmp, &p);
            }
        }
    }

    /// One paced index call with retries: 404 is "no captures", 5xx/400/timeouts back off and
    /// retry, 429/503 go through the throttle.
    async fn call(&self, ctx: &SearchCtx, url: &str, thr: &Throttle) -> Result<Got, NetError> {
        let mut last = String::new();
        let mut attempt = 0u32;
        loop {
            if ctx.out_of_time(Duration::from_secs(6)) {
                return Ok(Got::Failed(if last.is_empty() {
                    "таймаут".into()
                } else {
                    last
                }));
            }
            thr.wait(&ctx.net).await?;
            let req = NetRequest::get(url, "cc", Access::Passive)?
                .timeout(ctx.req_timeout(Duration::from_secs(60)))
                .retries(0);
            match ctx.net.send(req).await {
                Ok(r) if r.status() == 404 => {
                    thr.ok();
                    return Ok(Got::NoCaptures);
                }
                Ok(r) if r.is_success() => match r.text_limited(ctx.net.config().max_body).await {
                    Ok(b) => {
                        thr.ok();
                        return Ok(Got::Body(b));
                    }
                    Err(NetError::Cancelled) => return Err(NetError::Cancelled),
                    Err(e) => last = e.to_string(),
                },
                Ok(r) if rate::is_limit(r.status()) => {
                    let st = r.status();
                    match thr.limited(rate::retry_after(&r)) {
                        Verdict::Retry(_) => {
                            ctx.retrying("cc", attempt + 1, &format!("HTTP {st}"));
                            attempt += 1;
                            continue;
                        }
                        Verdict::Stop => return Ok(Got::Stop),
                    }
                }
                Ok(r) if r.status() >= 500 || r.status() == 400 => {
                    last = format!("HTTP {}", r.status());
                }
                Ok(r) => return Ok(Got::Failed(format!("HTTP {}", r.status()))),
                Err(NetError::Cancelled) => return Err(NetError::Cancelled),
                Err(e) => last = e.to_string(),
            }
            if attempt >= self.retries {
                return Ok(Got::Failed(last));
            }
            attempt += 1;
            ctx.retrying("cc", attempt, &last);
            let d = self.backoff() * (1u32 << (attempt - 1).min(4));
            let d = match ctx.time_left() {
                Some(l) => d.min(l.saturating_sub(Duration::from_secs(6))),
                None => d,
            };
            if !d.is_zero() {
                ctx.net.cancellable(tokio::time::sleep(d)).await?;
            }
        }
    }

    /// Sweeps one snapshot: page count, then pages. `Ok(true)` when it finished (empty or all
    /// pages read), `Ok(false)` when stopped by the throttle.
    async fn sweep_index(
        &self,
        ctx: &SearchCtx,
        idx: &CcIndex,
        domain: &str,
        st: &mut CcState,
        thr: &Throttle,
    ) -> Result<Result<bool, String>, NetError> {
        let pages = match self
            .call(
                ctx,
                &Self::index_url(&idx.api, domain, &ctx.filter, None)?,
                thr,
            )
            .await?
        {
            Got::NoCaptures => return Ok(Ok(true)),
            Got::Stop => return Ok(Ok(false)),
            Got::Failed(e) => return Ok(Err(e)),
            Got::Body(b) => serde_json::from_str::<Value>(b.trim())
                .ok()
                .and_then(|v| v["pages"].as_u64())
                .unwrap_or(1) as usize,
        };
        if pages == 0 {
            return Ok(Ok(true));
        }
        for p in 0..pages.min(self.max_pages.max(1)) {
            let body = match self
                .call(
                    ctx,
                    &Self::index_url(&idx.api, domain, &ctx.filter, Some(p))?,
                    thr,
                )
                .await?
            {
                Got::Body(b) => b,
                Got::NoCaptures => break,
                Got::Stop => return Ok(Ok(false)),
                Got::Failed(e) => return Ok(Err(e)),
            };
            let rows = parse_cc_ndjson(&body);
            if rows.is_empty() {
                break;
            }
            for m in rows {
                let Some(url) = m.get("url") else { continue };
                if m.get("status").is_some_and(|s| s != "200") {
                    continue;
                }
                let Some(ext) = ctx.filter.matches(url) else {
                    continue;
                };
                let mime = m.get("mime").map(String::as_str);
                if !crate::filter::mime_fits(mime, &ext) {
                    continue;
                }
                let ts = m.get("timestamp").map(String::as_str).unwrap_or("");
                let len = m.get("length").and_then(|s| s.parse().ok());
                st.add(url, ts, mime, len, &ext);
            }
        }
        Ok(Ok(true))
    }

    /// Runs the sweep for a domain and returns the found URLs with notes.
    async fn sweep(&self, ctx: &SearchCtx, domain: &str) -> Result<Found, NetError> {
        let all = self.all_indexes(ctx).await?;
        let list = select_indexes(&all, self.depth, self.tries());
        let newest = all.first().map(|i| i.id.clone()).unwrap_or_default();
        let now = crate::dorkboard::now_s();
        let mut st = self.load_state(domain, &ctx.filter);
        st.prune(now, self);
        let thr = Throttle::new(self.pace());
        let mut errs: Vec<String> = Vec::new();
        let mut answered = 0usize;
        let mut finished = 0usize;
        let mut stopped = false;
        let mut cut_short = false;
        for idx in &list {
            if !self.depth.deep() && answered >= self.max_indexes.max(1) {
                break;
            }
            if st.fresh(&idx.id, idx.id == newest, now, self) {
                answered += 1;
                finished += 1;
                continue;
            }
            if ctx.out_of_time(Duration::from_secs(8)) {
                cut_short = true;
                break;
            }
            match self.sweep_index(ctx, idx, domain, &mut st, &thr).await? {
                Ok(true) => {
                    answered += 1;
                    finished += 1;
                    st.done.insert(idx.id.clone(), now);
                }
                Ok(false) => {
                    stopped = true;
                    break;
                }
                Err(e) => {
                    tracing::warn!(target: "foca::source", "cc: индекс {} недоступен: {e}", idx.label());
                    errs.push(format!("{}: {e}", idx.label()));
                }
            }
            // saved after every snapshot, so a killed scan resumes from here
            self.save_state(domain, &ctx.filter, &st);
        }
        self.save_state(domain, &ctx.filter, &st);
        tracing::info!(target: "foca::source", "cc: {domain}, снимков {finished}/{}, ссылок {}", list.len(), st.hits.len());
        if st.hits.is_empty() {
            if stopped {
                return Err(NetError::Status(429));
            }
            if answered == 0 && !errs.is_empty() {
                return Err(NetError::Request(format!(
                    "индексы Common Crawl недоступны ({})",
                    errs.join("; ")
                )));
            }
        }
        let mut hits: Vec<&CcHit> = st.hits.values().collect();
        hits.sort_by(|a, b| b.last.cmp(&a.last).then_with(|| a.url.cmp(&b.url)));
        let mut col = Collector::new(ctx);
        for h in hits {
            col.host(&h.url, domain);
            let mut f = FoundUrl::new(&h.url, "cc");
            f.hint_ext = Some(h.ext.clone());
            f.size = h.length;
            f.date = Some(h.last.clone());
            f.mime = h.mime.clone();
            col.push(f);
        }
        let mut f = col.finish();
        let mut notes = Vec::new();
        if !errs.is_empty() {
            notes.push(format!(
                "часть индексов недоступна ({}): данные из ответивших",
                errs.join("; ")
            ));
        }
        if stopped {
            notes.push(rate::THROTTLED_NOTE.into());
        }
        if self.depth.deep() && finished < list.len() && (stopped || cut_short || !errs.is_empty())
        {
            notes.push(format!(
                "проверено снимков {finished} из {}: остальные продолжатся в следующем скане",
                list.len()
            ));
        }
        if !notes.is_empty() {
            f.note = Some(notes.join("; "));
        }
        Ok(f)
    }
}

impl DocumentSource for CommonCrawl {
    fn id(&self) -> &'static str {
        "cc"
    }
    fn name(&self) -> &'static str {
        "Common Crawl"
    }
    fn kind(&self) -> SourceKind {
        SourceKind::Passive
    }
    /// Paced index calls (3 s apart) need more than a fast API; deep sweeps get their own budget
    /// from the engine.
    fn budget(&self) -> u32 {
        if self.depth.deep() {
            10
        } else {
            2
        }
    }
    fn find<'a>(
        &'a self,
        ctx: &'a SearchCtx,
        domain: &'a str,
    ) -> BoxFuture<'a, Result<Found, NetError>> {
        Box::pin(self.sweep(ctx, domain))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn idx(id: &str) -> CcIndex {
        CcIndex {
            id: id.into(),
            api: format!("http://cc.test/{id}-index"),
            year: year_of(id, None),
        }
    }

    #[test]
    fn depth_selects_snapshots() {
        let all: Vec<CcIndex> = [
            "CC-MAIN-2026-43",
            "CC-MAIN-2026-10",
            "CC-MAIN-2025-30",
            "CC-MAIN-2024-51",
            "CC-MAIN-2019-04",
        ]
        .iter()
        .map(|s| idx(s))
        .collect();
        assert_eq!(select_indexes(&all, CcDepth::Latest(3), 4).len(), 4);
        let y2 = select_indexes(&all, CcDepth::Years(2), 0);
        assert_eq!(y2.len(), 3, "{y2:?}");
        assert_eq!(select_indexes(&all, CcDepth::All, 0).len(), 5);
        assert_eq!(CcDepth::parse("years", 99), CcDepth::Years(20));
        assert_eq!(CcDepth::parse("bogus", 1), CcDepth::Latest(3));
        assert!(CcDepth::All.deep() && !CcDepth::default().deep());
    }

    #[test]
    fn state_dedupes_with_first_and_last_seen() {
        let mut st = CcState::default();
        st.add(
            "https://a.example/r.pdf",
            "20240101000000",
            Some("application/pdf"),
            Some(5),
            "pdf",
        );
        st.add(
            "http://a.example/r.pdf",
            "20260101000000",
            None,
            None,
            "pdf",
        );
        st.add(
            "https://a.example/r.pdf",
            "20200101000000",
            None,
            None,
            "pdf",
        );
        assert_eq!(st.hits.len(), 1);
        let h = st.hits.values().next().unwrap();
        assert_eq!(h.first, "20200101000000");
        assert_eq!(h.last, "20260101000000");
        assert_eq!(h.url, "http://a.example/r.pdf");
        assert_eq!(h.mime.as_deref(), Some("application/pdf"));
        assert_eq!(h.length, Some(5));
    }

    #[test]
    fn freshness_and_prune() {
        let cc = CommonCrawl {
            max_cached: 1,
            ..Default::default()
        };
        let mut st = CcState::default();
        st.done.insert("new".into(), 1_000_000);
        st.done.insert("old".into(), 1_000_000);
        let day = 24 * 3600;
        assert!(st.fresh("new", true, 1_000_000 + day - 1, &cc));
        assert!(!st.fresh("new", true, 1_000_000 + day, &cc));
        assert!(st.fresh("old", false, 1_000_000 + 10 * day, &cc));
        st.add(
            "https://a.example/1.pdf",
            "20200101000000",
            None,
            None,
            "pdf",
        );
        st.add(
            "https://a.example/2.pdf",
            "20250101000000",
            None,
            None,
            "pdf",
        );
        st.prune(1_000_000 + day, &cc);
        assert_eq!(st.hits.len(), 1);
        assert!(st.hits.values().all(|h| h.url.ends_with("2.pdf")));
        st.prune(1_000_000 + 31 * day, &cc);
        assert!(st.done.is_empty() && st.hits.is_empty());
    }

    #[test]
    fn official_defaults_pace_and_backoff() {
        let cc = CommonCrawl::default();
        assert_eq!(cc.pace(), Duration::from_secs(3));
        assert_eq!(cc.backoff(), Duration::from_secs(5));
        let local = CommonCrawl::with_collinfo("http://127.0.0.1:9/collinfo.json");
        assert_eq!(local.pace(), Duration::ZERO);
        let deep = CommonCrawl::default().with_depth(CcDepth::All);
        assert_eq!(deep.max_pages, 10);
        assert_eq!(deep.budget(), 10);
    }
}
