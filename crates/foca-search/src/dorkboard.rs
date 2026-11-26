//! Shared dork board of a scan: a single queue of `site:<domain> filetype:...` queries for all
//! keyless dork engines (Startpage, Brave, Mojeek, DuckDuckGo, Bing, Yahoo, SearXNG, ...).
//!
//! Having every engine run every file type for every domain (5 engines × 10 types × up to 3
//! pages) means many requests from one IP and therefore captchas, and a blocked engine's
//! remaining dorks would be lost. The board works as follows:
//!
//! - a domain's queries are grouped by file type family (`pdf`, `doc|docx|odt|rtf`,
//!   `xls|xlsx|ods`, `ppt|pptx`); an engine that supports `OR` sends a group as one query, others
//!   send one query per type;
//! - one healthy engine takes a group; links close the group, an empty result lets one more
//!   engine try it ([`MAX_TRIES`]);
//! - on a captcha or block, the engine's group goes back to the queue for others (failover); an
//!   engine that has finished its own work waits while others still hold groups in progress;
//! - per-engine request budget per scan, a 24 h result cache, and per-engine statistics for the
//!   Debug screen.
//!
//! Without a shared board (`SearchCtx::dorks == None`, e.g. single-source CLI tests) an engine
//! creates a private board and runs every group itself.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use serde::{Deserialize, Serialize};

/// Number of different engines that try a group when results are empty.
pub const MAX_TRIES: usize = 2;
/// Lifetime of cached dork results.
pub const CACHE_TTL_S: i64 = 24 * 3600;

/// What the search engine showed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum PageKind {
    /// Regular results (possibly empty).
    Results,
    /// The challenge page (proof of work) never passed.
    Verify,
    /// A captcha the browser cannot solve on its own.
    Captcha,
    /// The engine refused by IP ("automated queries", 403).
    BlockedIp,
}

/// `blocked` reason: a captcha only a human can solve (the manual check button).
pub const CAPTCHA_WHY: &str = "поисковик показал капчу";
/// `blocked` reason: the proof-of-work challenge did not pass in the embedded browser.
pub const VERIFY_WHY: &str = "проверка поисковика не пройдена";

/// Engine counters (per scan or per process lifetime).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EngineStat {
    pub requests: u32,
    /// Result pages received.
    pub answered: u32,
    /// Domain links in the results.
    pub links: u32,
    pub captchas: u32,
    /// Pages served from the cache (no request).
    pub cached: u32,
    /// Groups handed to other engines after a captcha.
    pub moved: u32,
    /// Groups taken over from other engines.
    pub taken_over: u32,
    /// Currently blocked by a captcha (until a manual check).
    pub blocked: bool,
}

#[derive(Debug, Clone)]
struct Item {
    exts: Vec<String>,
    tried: Vec<String>,
    taken_by: Option<String>,
    ok: bool,
    /// The engine that first gave the group back after a captcha (for the `taken_over` counter).
    moved_from: Option<String>,
}

/// What an engine should do next.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Take {
    /// Group `idx` with its types.
    Item(usize, Vec<String>),
    /// Nothing for this engine, but other engines still hold groups that may come back.
    Wait,
    /// All done (or the engine is blocked or out of budget).
    Done,
}

#[derive(Default)]
struct State {
    queues: HashMap<String, Vec<Item>>,
    running: HashMap<String, usize>,
    stats: BTreeMap<String, EngineStat>,
    warmed: HashSet<String>,
}

/// Dork result cache: `engine|query|page` to (time, links). Stored as a JSON file in the data directory.
type CacheMap = HashMap<String, (i64, Vec<String>)>;

#[derive(Default)]
pub struct DorkCache {
    path: Option<PathBuf>,
    map: Mutex<Option<CacheMap>>,
}

pub(crate) fn now_s() -> i64 {
    time::OffsetDateTime::now_utc().unix_timestamp()
}

impl DorkCache {
    pub fn new(path: Option<PathBuf>) -> Self {
        DorkCache {
            path,
            map: Mutex::new(None),
        }
    }

    fn with<R>(&self, f: impl FnOnce(&mut CacheMap) -> R) -> R {
        let mut g = self.map.lock().unwrap_or_else(|e| e.into_inner());
        let m = g.get_or_insert_with(|| {
            self.path
                .as_ref()
                .and_then(|p| std::fs::read(p).ok())
                .and_then(|b| serde_json::from_slice(&b).ok())
                .unwrap_or_default()
        });
        f(m)
    }

    pub fn key(engine: &str, q: &str, page: usize) -> String {
        format!("{engine}|{q}|{page}")
    }

    pub fn get(&self, key: &str, now: i64) -> Option<Vec<String>> {
        self.with(|m| match m.get(key) {
            Some((t, v)) if now - *t < CACHE_TTL_S && *t <= now => Some(v.clone()),
            _ => None,
        })
    }

    pub fn put(&self, key: &str, links: &[String], now: i64) {
        let data = self.with(|m| {
            m.retain(|_, (t, _)| now - *t < CACHE_TTL_S);
            m.insert(key.to_string(), (now, links.to_vec()));
            serde_json::to_vec(m).ok()
        });
        if let (Some(p), Some(d)) = (&self.path, data) {
            let tmp = p.with_extension("tmp");
            if std::fs::write(&tmp, d).is_ok() {
                let _ = std::fs::rename(&tmp, p);
            }
        }
    }

    pub fn clear(&self) {
        self.with(|m| m.clear());
        if let Some(p) = &self.path {
            let _ = std::fs::remove_file(p);
        }
    }
}

/// Per-process engine statistics (Debug → Search engines).
fn journal() -> &'static Mutex<BTreeMap<String, EngineStat>> {
    static J: OnceLock<Mutex<BTreeMap<String, EngineStat>>> = OnceLock::new();
    J.get_or_init(Default::default)
}

/// Returns a snapshot of the per-process engine statistics.
pub fn engine_journal() -> BTreeMap<String, EngineStat> {
    journal().lock().unwrap_or_else(|e| e.into_inner()).clone()
}

fn bump(id: &str, f: impl Fn(&mut EngineStat)) {
    let mut j = journal().lock().unwrap_or_else(|e| e.into_inner());
    f(j.entry(id.to_string()).or_default());
}

/// Shared dork board of a scan.
pub struct DorkBoard {
    st: Mutex<State>,
    cache: DorkCache,
    /// Request budget of one engine per scan.
    pub budget: u32,
    /// Poll interval while waiting for other engines' groups.
    pub poll: Duration,
}

impl Default for DorkBoard {
    fn default() -> Self {
        DorkBoard::new(DorkCache::default())
    }
}

/// Keeps an engine registered as running while alive.
pub struct Running<'a> {
    b: &'a DorkBoard,
    id: String,
}

impl Drop for Running<'_> {
    fn drop(&mut self) {
        let mut s = self.b.lock();
        if let Some(n) = s.running.get_mut(&self.id) {
            *n = n.saturating_sub(1);
        }
        // groups taken but not finished (source timeout, cancellation) go back to the queue
        for q in s.queues.values_mut() {
            for it in q.iter_mut() {
                if it.taken_by.as_deref() == Some(self.id.as_str()) {
                    it.taken_by = None;
                }
            }
        }
    }
}

impl DorkBoard {
    pub fn new(cache: DorkCache) -> Self {
        DorkBoard {
            st: Mutex::new(State::default()),
            cache,
            budget: 24,
            poll: Duration::from_millis(1500),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.st.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn begin(&self, id: &str) -> Running<'_> {
        *self.lock().running.entry(id.to_string()).or_default() += 1;
        Running {
            b: self,
            id: id.to_string(),
        }
    }

    /// Creates the queue for a domain (done by the first engine).
    pub fn plan(&self, domain: &str, groups: &[Vec<String>]) {
        let mut s = self.lock();
        s.queues.entry(domain.to_string()).or_insert_with(|| {
            groups
                .iter()
                .map(|g| Item {
                    exts: g.clone(),
                    tried: vec![],
                    taken_by: None,
                    ok: false,
                    moved_from: None,
                })
                .collect()
        });
    }

    /// Returns the next group for engine `id`.
    pub fn take(&self, id: &str, domain: &str) -> Take {
        let mut guard = self.lock();
        let s = &mut *guard;
        let st = s.stats.entry(id.to_string()).or_default().clone();
        if st.blocked || st.requests >= self.budget {
            return Take::Done;
        }
        let running: HashSet<String> = s
            .running
            .iter()
            .filter(|(k, n)| **n > 0 && k.as_str() != id)
            .map(|(k, _)| k.clone())
            .collect();
        let Some(q) = s.queues.get_mut(domain) else {
            return Take::Done;
        };
        let open =
            |it: &Item| !it.ok && it.tried.len() < MAX_TRIES && !it.tried.iter().any(|t| t == id);
        if let Some((i, it)) = q
            .iter_mut()
            .enumerate()
            .find(|(_, it)| open(it) && it.taken_by.is_none())
        {
            it.taken_by = Some(id.to_string());
            let moved = it.moved_from.as_deref().is_some_and(|m| m != id);
            let r = Take::Item(i, it.exts.clone());
            if moved {
                s.stats.entry(id.to_string()).or_default().taken_over += 1;
                bump(id, |e| e.taken_over += 1);
            }
            return r;
        }
        let waiting = q
            .iter()
            .any(|it| open(it) && it.taken_by.as_ref().is_some_and(|t| running.contains(t)));
        if waiting {
            Take::Wait
        } else {
            Take::Done
        }
    }

    /// Marks a group as done by an engine; `links` is the number of domain links found.
    pub fn finish(&self, id: &str, domain: &str, idx: usize, links: usize) {
        let mut s = self.lock();
        if let Some(it) = s.queues.get_mut(domain).and_then(|q| q.get_mut(idx)) {
            it.taken_by = None;
            if !it.tried.iter().any(|t| t == id) {
                it.tried.push(id.to_string());
            }
            it.ok |= links > 0;
        }
    }

    /// Returns a group to the queue for other engines after a captcha, block or failure.
    pub fn give_back(&self, id: &str, domain: &str, idx: usize, blocked: bool) {
        let mut s = self.lock();
        if let Some(it) = s.queues.get_mut(domain).and_then(|q| q.get_mut(idx)) {
            it.taken_by = None;
            it.moved_from.get_or_insert_with(|| id.to_string());
        }
        let e = s.stats.entry(id.to_string()).or_default();
        e.moved += 1;
        if blocked {
            e.blocked = true;
        }
        bump(id, |e| e.moved += 1);
    }

    /// Marks an engine healthy again after a manual check.
    pub fn unblock(&self, id: &str) {
        self.lock().stats.entry(id.to_string()).or_default().blocked = false;
    }

    /// Charges one request to the budget; returns `false` when the budget is exhausted.
    pub fn spend(&self, id: &str) -> bool {
        let mut s = self.lock();
        let e = s.stats.entry(id.to_string()).or_default();
        if e.requests >= self.budget {
            return false;
        }
        e.requests += 1;
        bump(id, |e| e.requests += 1);
        true
    }

    /// Returns `true` for the engine's first request in the scan (the session starts at the home page).
    /// Returns the links `engine` gave for `query`/`page` within the cache lifetime.
    pub fn recall(&self, engine: &str, query: &str, page: usize, now: i64) -> Option<Vec<String>> {
        self.cache.get(&DorkCache::key(engine, query, page), now)
    }

    /// Remembers the links `engine` gave for `query`/`page`.
    pub fn remember(&self, engine: &str, query: &str, page: usize, links: &[String], now: i64) {
        self.cache
            .put(&DorkCache::key(engine, query, page), links, now);
    }

    pub fn first_visit(&self, id: &str) -> bool {
        self.lock().warmed.insert(id.to_string())
    }

    pub fn note(&self, id: &str, kind: PageKind, links: usize, cached: bool) {
        let mut s = self.lock();
        let e = s.stats.entry(id.to_string()).or_default();
        let f = |e: &mut EngineStat| {
            if cached {
                e.cached += 1;
            }
            match kind {
                PageKind::Results => {
                    e.answered += 1;
                    e.links += links as u32;
                }
                _ => e.captchas += 1,
            }
        };
        f(e);
        bump(id, f);
    }

    pub fn stats(&self) -> BTreeMap<String, EngineStat> {
        self.lock().stats.clone()
    }

    /// Returns the number of the domain's groups that no engine completed (for the scan summary).
    pub fn lost(&self, domain: &str) -> usize {
        self.lock().queues.get(domain).map_or(0, |q| {
            q.iter().filter(|i| !i.ok && i.tried.is_empty()).count()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn g(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn failover_returns_group_to_queue() {
        let b = DorkBoard::default();
        b.plan("a.ua", &[g(&["pdf"]), g(&["doc"])]);
        let _sp = b.begin("startpage");
        let _br = b.begin("brave");
        assert_eq!(b.take("startpage", "a.ua"), Take::Item(0, g(&["pdf"])));
        assert_eq!(b.take("brave", "a.ua"), Take::Item(1, g(&["doc"])));
        // Brave has finished its own groups; Startpage still holds pdf, so Brave waits
        b.finish("brave", "a.ua", 1, 3);
        assert_eq!(b.take("brave", "a.ua"), Take::Wait);
        // Startpage hits a captcha: pdf goes back to the queue and Brave takes it
        b.give_back("startpage", "a.ua", 0, true);
        assert_eq!(b.take("startpage", "a.ua"), Take::Done);
        assert_eq!(b.take("brave", "a.ua"), Take::Item(0, g(&["pdf"])));
        b.finish("brave", "a.ua", 0, 5);
        assert_eq!(b.take("brave", "a.ua"), Take::Done);
        let st = b.stats();
        assert!(st["startpage"].blocked);
        assert_eq!(st["startpage"].moved, 1);
        assert_eq!(st["brave"].taken_over, 1);
        assert_eq!(b.lost("a.ua"), 0);
        b.unblock("startpage");
        assert_eq!(b.take("startpage", "a.ua"), Take::Done); // everything is closed
    }

    #[test]
    fn empty_result_tried_by_second_engine_then_closed() {
        let b = DorkBoard::default();
        b.plan("a.ua", &[g(&["ppt"])]);
        assert_eq!(b.take("bing", "a.ua"), Take::Item(0, g(&["ppt"])));
        b.finish("bing", "a.ua", 0, 0);
        assert_eq!(b.take("bing", "a.ua"), Take::Done);
        assert_eq!(b.take("ddg", "a.ua"), Take::Item(0, g(&["ppt"])));
        b.finish("ddg", "a.ua", 0, 0);
        assert_eq!(b.take("yahoo", "a.ua"), Take::Done); // MAX_TRIES
    }

    #[test]
    fn dropped_runner_releases_its_group() {
        let b = DorkBoard::default();
        b.plan("a.ua", &[g(&["pdf"])]);
        {
            let _r = b.begin("mojeek");
            assert!(matches!(b.take("mojeek", "a.ua"), Take::Item(..)));
            let _o = b.begin("brave");
            assert_eq!(b.take("brave", "a.ua"), Take::Wait);
        }
        // Mojeek's source timed out, so its group is free again
        assert!(matches!(b.take("brave", "a.ua"), Take::Item(..)));
    }

    #[test]
    fn budget_limits_requests() {
        let b = DorkBoard {
            budget: 2,
            ..Default::default()
        };
        assert!(b.spend("x") && b.spend("x"));
        assert!(!b.spend("x"));
        b.plan("a.ua", &[g(&["pdf"])]);
        assert_eq!(b.take("x", "a.ua"), Take::Done);
        assert!(b.first_visit("x") && !b.first_visit("x"));
    }

    #[test]
    fn cache_ttl_and_file() {
        let dir = std::env::temp_dir().join(format!("foca-dc-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("dork-cache.json");
        let c = DorkCache::new(Some(p.clone()));
        let k = DorkCache::key("brave", "site:a.ua filetype:pdf", 1);
        c.put(&k, &g(&["https://a.ua/x.pdf"]), 1_000_000);
        assert_eq!(c.get(&k, 1_000_100).unwrap().len(), 1);
        assert!(c.get(&k, 1_000_000 + CACHE_TTL_S).is_none());
        let c2 = DorkCache::new(Some(p));
        assert!(
            c2.get(&k, 1_000_100).is_some(),
            "the cache survives a restart"
        );
        c2.clear();
        assert!(c2.get(&k, 1_000_100).is_none());
        let _ = std::fs::remove_dir_all(dir);
    }
}
