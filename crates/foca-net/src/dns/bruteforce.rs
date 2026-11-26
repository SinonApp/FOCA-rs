//! Subdomain brute force over DNS (modeled on dnsx and puredns).
//!
//! * Candidates come from an embedded wordlist ([`Wordlist::Top1500`], [`Wordlist::Top5000`]: the
//!   most frequent labels of SecLists `subdomains-top1million-5000.txt`, in popularity order) or
//!   from a user wordlist ([`parse_wordlist`]).
//! * Phase 1 resolves the candidates through the resolver pool at an adaptive rate
//!   ([`AdaptiveRate`], AIMD: additive increase after a run of successes, multiplicative decrease on
//!   timeouts and SERVFAIL). This keeps carrier-grade NAT on mobile networks and DoH providers from
//!   silently dropping queries, which would otherwise look like NXDOMAIN.
//! * Phase 2 re-resolves every positive through the trusted resolver; names that only a lying or
//!   poisoned pool resolver answered are reported as unverified instead of as hosts.
//! * [`WildcardFilter`] profiles every parent level a candidate belongs to (`*.domain`,
//!   `*.dev.domain`, ...) with random labels and compares answers by CNAME target, IP set and TTL,
//!   so a wildcard on a sub-level is caught even when the apex has none.
//!
//! Access: queries go to recursive resolvers, but they end up at the authoritative servers of the
//! target zone, so the module counts as a target-touching (standard profile) operation. The zone must
//! be in scope, the passive profile denies it before any query, and names covered by an exclusion are
//! never queried. The queries are paced by [`Pace`] alone: the global HTTP rate limit of
//! [`NetClient`] is meant for web requests and would make a wordlist run take many minutes.

use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};
use std::io::Read;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::client::{Access, NetClient};
use crate::dns::{norm_name, DnsLookup, RType};
use crate::NetError;

/// Request log module name.
pub const MODULE: &str = "bruteforce";

const TOP_GZ: &[u8] = include_bytes!("../../wordlists/subdomains-top1million-5000.txt.gz");
/// SecLists path of the embedded wordlist.
pub const TOP_SOURCE: &str = "Discovery/DNS/subdomains-top1million-5000.txt";

/// Candidate wordlist.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Wordlist {
    /// The 1500 most frequent labels (standard profile).
    Top1500,
    /// The 5000 most frequent labels (full profile).
    Top5000,
    /// A user wordlist, already parsed with [`parse_wordlist`].
    Custom(Vec<String>),
}

impl Wordlist {
    /// Stable identifier used in settings.
    pub fn id(&self) -> &'static str {
        match self {
            Wordlist::Top1500 => "top-1500",
            Wordlist::Top5000 => "top-5000",
            Wordlist::Custom(_) => "custom",
        }
    }

    /// Returns a built-in wordlist by identifier.
    pub fn builtin(id: &str) -> Option<Wordlist> {
        match id {
            "top-1500" => Some(Wordlist::Top1500),
            "top-5000" => Some(Wordlist::Top5000),
            _ => None,
        }
    }

    /// Returns the labels in priority order.
    pub fn words(&self) -> Vec<String> {
        match self {
            Wordlist::Top1500 => builtin_top(1500),
            Wordlist::Top5000 => builtin_top(5000),
            Wordlist::Custom(w) => w.clone(),
        }
    }
}

/// Returns the first `n` labels of the embedded popularity-ordered list.
pub fn builtin_top(n: usize) -> Vec<String> {
    let mut text = String::new();
    if flate2::read::GzDecoder::new(TOP_GZ)
        .read_to_string(&mut text)
        .is_err()
    {
        return Vec::new();
    }
    let mut v = parse_wordlist(&text);
    v.truncate(n);
    v
}

/// Returns `true` for a valid DNS label: 1-63 characters of `a-z`, `0-9`, `-`, `_`, without a
/// leading or trailing hyphen (the input must already be lowercase).
pub fn valid_label(l: &str) -> bool {
    !l.is_empty()
        && l.len() <= 63
        && !l.starts_with('-')
        && !l.ends_with('-')
        && l.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
}

/// Returns `true` for a valid host name of at most 253 characters made of [`valid_label`]s.
pub fn valid_host(h: &str) -> bool {
    !h.is_empty() && h.len() <= 253 && h.split('.').all(valid_label)
}

/// Parses a user wordlist: one label (or dotted label sequence such as `dev.api`) per line, `#`
/// comments, a leading `*.` and a trailing dot are dropped; invalid entries are skipped and
/// duplicates removed, keeping the original order.
pub fn parse_wordlist(text: &str) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for l in text.lines() {
        let l = l.trim();
        if l.is_empty() || l.starts_with('#') {
            continue;
        }
        let w = norm_name(l.trim_start_matches("*."));
        if w.len() <= 200 && valid_host(&w) && seen.insert(w.clone()) {
            out.push(w);
        }
    }
    out
}

/// Pace of DNS queries.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Pace {
    /// Starting rate, queries per second.
    pub initial_rps: f64,
    /// The rate never goes below this value.
    pub min_rps: f64,
    /// The rate never goes above this value.
    pub max_rps: f64,
    /// Queries in flight at most.
    pub concurrency: usize,
    /// Rate added after `increase_every` consecutive successful queries.
    pub step: f64,
    pub increase_every: u32,
    /// Rate multiplier applied on every timeout or server failure (`0 < backoff < 1`).
    pub backoff: f64,
}

impl Pace {
    /// Wi-Fi or wired network with a plain UDP resolver.
    pub fn wifi() -> Pace {
        Pace {
            initial_rps: 30.0,
            min_rps: 5.0,
            max_rps: 120.0,
            concurrency: 16,
            step: 5.0,
            increase_every: 20,
            backoff: 0.5,
        }
    }

    /// Mobile network: carrier NAT keeps few UDP mappings and drops bursts without an error.
    pub fn mobile() -> Pace {
        Pace {
            initial_rps: 15.0,
            min_rps: 2.0,
            max_rps: 40.0,
            concurrency: 6,
            step: 2.0,
            increase_every: 25,
            backoff: 0.5,
        }
    }

    /// DNS over HTTPS (a proxy or Tor is configured): public DoH endpoints throttle bursts per client.
    pub fn doh() -> Pace {
        Pace {
            initial_rps: 10.0,
            min_rps: 2.0,
            max_rps: 25.0,
            concurrency: 4,
            step: 1.0,
            increase_every: 30,
            backoff: 0.5,
        }
    }
}

impl Default for Pace {
    fn default() -> Self {
        Pace::wifi()
    }
}

/// AIMD rate controller.
#[derive(Debug, Clone)]
pub struct AdaptiveRate {
    pace: Pace,
    rps: f64,
    streak: u32,
    lowest: f64,
}

impl AdaptiveRate {
    pub fn new(pace: Pace) -> Self {
        let rps = pace
            .initial_rps
            .clamp(pace.min_rps.max(0.1), pace.max_rps.max(0.1));
        AdaptiveRate {
            pace,
            rps,
            streak: 0,
            lowest: rps,
        }
    }

    /// Current rate, queries per second.
    pub fn rps(&self) -> f64 {
        self.rps
    }

    /// Lowest rate reached so far.
    pub fn lowest(&self) -> f64 {
        self.lowest
    }

    /// Delay between two consecutive queries at the current rate.
    pub fn interval(&self) -> Duration {
        Duration::from_secs_f64(1.0 / self.rps.max(0.1))
    }

    pub fn on_success(&mut self) {
        self.streak += 1;
        if self.streak >= self.pace.increase_every.max(1) {
            self.streak = 0;
            self.rps = (self.rps + self.pace.step).min(self.pace.max_rps.max(0.1));
        }
    }

    pub fn on_failure(&mut self) {
        self.streak = 0;
        let b = if self.pace.backoff > 0.0 && self.pace.backoff < 1.0 {
            self.pace.backoff
        } else {
            0.5
        };
        self.rps = (self.rps * b).max(self.pace.min_rps.max(0.1));
        self.lowest = self.lowest.min(self.rps);
    }
}

/// Spreads queries of all workers over time according to an [`AdaptiveRate`].
struct Pacer {
    rate: Mutex<AdaptiveRate>,
    next: Mutex<tokio::time::Instant>,
}

impl Pacer {
    fn new(pace: Pace) -> Self {
        Pacer {
            rate: Mutex::new(AdaptiveRate::new(pace)),
            next: Mutex::new(tokio::time::Instant::now()),
        }
    }

    fn rate(&self) -> std::sync::MutexGuard<'_, AdaptiveRate> {
        self.rate.lock().unwrap_or_else(|e| e.into_inner())
    }

    async fn wait(&self, net: &NetClient) -> Result<(), NetError> {
        let interval = self.rate().interval();
        let at = {
            let mut n = self.next.lock().unwrap_or_else(|e| e.into_inner());
            let at = (*n).max(tokio::time::Instant::now());
            *n = at + interval;
            at
        };
        net.cancellable(tokio::time::sleep_until(at)).await
    }
}

/// An address answer for a name: the CNAME chain, addresses and their TTL.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Resolved {
    pub name: String,
    /// A and AAAA values, sorted and deduplicated.
    pub ips: Vec<String>,
    /// CNAME targets in chain order.
    pub cnames: Vec<String>,
    /// Lowest TTL of the address records (of the CNAME records for a dangling CNAME).
    pub ttl: Option<u32>,
}

/// Resolves A and AAAA for `name`. Returns `None` for NXDOMAIN and for a name with neither
/// addresses nor a CNAME; a CNAME without addresses (dangling) is returned with empty `ips`.
///
/// # Errors
///
/// Resolver failures of the A query (timeouts, SERVFAIL); an AAAA failure after a successful A
/// query is ignored.
pub async fn resolve_full(dns: &dyn DnsLookup, name: &str) -> Result<Option<Resolved>, NetError> {
    let name = norm_name(name);
    let mut r = Resolved {
        name: name.clone(),
        ..Default::default()
    };
    let mut ips = BTreeSet::new();
    let mut cname_ttl: Option<u32> = None;
    for t in [RType::A, RType::AAAA] {
        let a = match dns.lookup(&name, t).await {
            Ok(a) => a,
            Err(e) if t == RType::AAAA && !matches!(e, NetError::Cancelled) => break,
            Err(e) => return Err(e),
        };
        if a.nxdomain {
            return Ok(None);
        }
        for rec in &a.records {
            match rec.rtype.as_str() {
                "A" | "AAAA" => {
                    ips.insert(rec.value.clone());
                    r.ttl = Some(r.ttl.map_or(rec.ttl, |x| x.min(rec.ttl)));
                }
                "CNAME" => {
                    let v = norm_name(&rec.value);
                    if !r.cnames.contains(&v) {
                        r.cnames.push(v);
                    }
                    cname_ttl = Some(cname_ttl.map_or(rec.ttl, |x| x.min(rec.ttl)));
                }
                _ => {}
            }
        }
    }
    r.ips = ips.into_iter().collect();
    if r.ips.is_empty() {
        if r.cnames.is_empty() {
            return Ok(None);
        }
        r.ttl = cname_ttl;
    }
    Ok(Some(r))
}

/// Answers synthesized by a wildcard at one level, as seen through random labels.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct WildcardProfile {
    /// The level, e.g. `dev.example.com` for `*.dev.example.com`.
    pub level: String,
    pub wildcard: bool,
    pub ips: BTreeSet<String>,
    /// First CNAME targets of the synthesized answers.
    pub cnames: BTreeSet<String>,
    pub ttls: BTreeSet<u32>,
    /// Random labels got different address sets (round-robin or a large pool).
    pub rotating: bool,
    pub probes: usize,
    /// Probes that failed with a resolver error.
    pub errors: usize,
}

impl WildcardProfile {
    fn absorb(&mut self, r: &Resolved, first_set: &mut Option<Vec<String>>) {
        self.wildcard = true;
        self.ips.extend(r.ips.iter().cloned());
        if let Some(c) = r.cnames.first() {
            self.cnames.insert(c.clone());
        }
        if let Some(t) = r.ttl {
            self.ttls.insert(t);
        }
        match first_set {
            None => *first_set = Some(r.ips.clone()),
            Some(f) if *f != r.ips => self.rotating = true,
            _ => {}
        }
    }
}

/// Returns the parent level of a name (`a.b.c` gives `b.c`).
pub fn parent_level(name: &str) -> &str {
    name.split_once('.').map_or("", |x| x.1)
}

static RNG: AtomicU64 = AtomicU64::new(0);

/// Returns a random 14-character label (`[a-z0-9]`, starting with a letter) for wildcard probes.
pub fn random_label() -> String {
    let seed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0x9e37_79b9_7f4a_7c15);
    let mut x = seed ^ RNG.fetch_add(0x9e37_79b9_7f4a_7c15, Ordering::Relaxed);
    let mut s = String::with_capacity(14);
    const ABC: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    for i in 0..14 {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        let n = if i == 0 { 26 } else { ABC.len() as u64 };
        s.push(ABC[(x % n) as usize] as char);
    }
    s
}

struct LevelState {
    profile: WildcardProfile,
    widened: bool,
}

type LevelSlot = Arc<tokio::sync::Mutex<Option<LevelState>>>;

/// Multi-level wildcard filter.
///
/// Each parent level is profiled once with `probes` random labels; a level that answers is a
/// wildcard level. A candidate under a wildcard level is a wildcard answer when:
/// * both it and the wildcard answer with a CNAME and its first CNAME target is one of the
///   wildcard's targets;
/// * neither has a CNAME and its addresses intersect the wildcard's addresses (when they do not,
///   the level is widened once with `extra_probes` more labels and checked again);
/// * the addresses stay disjoint, but the wildcard rotates addresses and the candidate has
///   exactly a wildcard TTL (a large rotating pool cannot be enumerated with a few probes).
///
/// A candidate answering with a CNAME where the wildcard has none (or vice versa) is an explicit
/// record and is kept.
pub struct WildcardFilter {
    dns: Arc<dyn DnsLookup>,
    probes: usize,
    extra_probes: usize,
    levels: Mutex<HashMap<String, LevelSlot>>,
}

impl WildcardFilter {
    pub fn new(dns: Arc<dyn DnsLookup>, probes: usize, extra_probes: usize) -> Self {
        WildcardFilter {
            dns,
            probes: probes.max(1),
            extra_probes,
            levels: Mutex::new(HashMap::new()),
        }
    }

    async fn probe(&self, level: &str, n: usize, p: &mut WildcardProfile) {
        let mut first: Option<Vec<String>> = None;
        if p.wildcard {
            first = Some(p.ips.iter().cloned().collect());
        }
        for _ in 0..n {
            let name = format!("{}.{level}", random_label());
            let mut res = Err(NetError::Timeout);
            for _ in 0..3 {
                res = resolve_full(self.dns.as_ref(), &name).await;
                if !matches!(res, Err(NetError::Timeout | NetError::Dns(_))) {
                    break;
                }
            }
            p.probes += 1;
            match res {
                Ok(Some(r)) => p.absorb(&r, &mut first),
                Ok(None) => {}
                Err(NetError::Cancelled) => return,
                Err(_) => p.errors += 1,
            }
        }
    }

    fn slot(&self, level: &str) -> LevelSlot {
        self.levels
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .entry(level.to_string())
            .or_default()
            .clone()
    }

    /// Returns the profile of a level, probing it on first use.
    pub async fn profile(&self, level: &str) -> WildcardProfile {
        let level = norm_name(level);
        let slot = self.slot(&level);
        let mut g = slot.lock().await;
        self.ensure(&level, &mut g).await.profile.clone()
    }

    async fn ensure<'g>(&self, level: &str, g: &'g mut Option<LevelState>) -> &'g mut LevelState {
        if g.is_none() {
            let mut p = WildcardProfile {
                level: level.to_string(),
                ..Default::default()
            };
            self.probe(level, self.probes, &mut p).await;
            *g = Some(LevelState {
                profile: p,
                widened: false,
            });
        }
        g.get_or_insert_with(|| LevelState {
            profile: WildcardProfile::default(),
            widened: false,
        })
    }

    fn decide(p: &WildcardProfile, r: &Resolved) -> Option<bool> {
        match (r.cnames.first(), p.cnames.is_empty()) {
            (Some(c), false) => return Some(p.cnames.contains(c)),
            (Some(_), true) | (None, false) => return Some(false),
            (None, true) => {}
        }
        if r.ips.iter().any(|ip| p.ips.contains(ip)) {
            return Some(true);
        }
        None
    }

    /// Returns `true` if the answer for `r.name` is synthesized by a wildcard at its parent level.
    pub async fn is_wildcard(&self, r: &Resolved) -> bool {
        let level = parent_level(&r.name).to_string();
        if level.is_empty() {
            return false;
        }
        let slot = self.slot(&level);
        let mut g = slot.lock().await;
        let st = self.ensure(&level, &mut g).await;
        if !st.profile.wildcard {
            return false;
        }
        if let Some(v) = Self::decide(&st.profile, r) {
            return v;
        }
        if !st.widened && self.extra_probes > 0 {
            st.widened = true;
            let mut p = std::mem::take(&mut st.profile);
            self.probe(&level, self.extra_probes, &mut p).await;
            st.profile = p;
            if let Some(v) = Self::decide(&st.profile, r) {
                return v;
            }
        }
        st.profile.rotating && r.ttl.is_some_and(|t| st.profile.ttls.contains(&t))
    }

    /// Returns the profiles of all wildcard levels seen so far, sorted by level.
    pub async fn wildcard_levels(&self) -> Vec<WildcardProfile> {
        let slots: Vec<LevelSlot> = self
            .levels
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .values()
            .cloned()
            .collect();
        let mut out = Vec::new();
        for s in slots {
            if let Some(st) = s.lock().await.as_ref() {
                if st.profile.wildcard {
                    out.push(st.profile.clone());
                }
            }
        }
        out.sort_by(|a, b| a.level.cmp(&b.level));
        out
    }
}

/// Resolvers for the two phases.
#[derive(Clone)]
pub struct Resolvers {
    /// Phase 1 resolvers, used round-robin (at least one).
    pub pool: Vec<Arc<dyn DnsLookup>>,
    /// Phase 2 resolver that confirms positives and probes wildcards; `None` reuses the
    /// phase 1 answers and the first pool resolver.
    pub trusted: Option<Arc<dyn DnsLookup>>,
}

impl Resolvers {
    /// A single resolver for both phases.
    pub fn single(dns: Arc<dyn DnsLookup>) -> Self {
        Resolvers {
            pool: vec![dns],
            trusted: None,
        }
    }

    fn reference(&self) -> Option<Arc<dyn DnsLookup>> {
        self.trusted.clone().or_else(|| self.pool.first().cloned())
    }
}

/// Brute force settings.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BruteConfig {
    pub pace: Pace,
    /// Retries of a name after resolver errors.
    pub retries: u32,
    /// Random labels per level when profiling a wildcard.
    pub wildcard_probes: usize,
    /// Extra random labels when a wildcard level needs widening.
    pub wildcard_extra_probes: usize,
    /// Upper bound on candidates per run.
    pub max_candidates: usize,
    /// Live counters shared with the caller (progress, early stop, pause).
    #[serde(skip)]
    pub progress: Option<Arc<Progress>>,
}

/// Live counters of a resolution pass (phase 1), shared with the caller: progress reports, a
/// slow-resolver estimate, early stop (results found so far are kept) and pause.
#[derive(Debug, Default)]
pub struct Progress {
    /// Candidates of the current pass.
    pub total: AtomicUsize,
    /// Candidates answered (positive, negative or given up).
    pub done: AtomicUsize,
    /// Resolver failures (timeouts, SERVFAIL), retries included.
    pub failures: AtomicUsize,
    /// Set by the caller: stop taking new candidates.
    pub stop: AtomicBool,
    /// Set by the caller: hold new queries until cleared.
    pub pause: AtomicBool,
}

impl PartialEq for Progress {
    fn eq(&self, other: &Self) -> bool {
        std::ptr::eq(self, other)
    }
}

impl Progress {
    /// Resets the counters for a new pass of `total` candidates (stop/pause flags are kept).
    pub fn start(&self, total: usize) {
        self.total.store(total, Ordering::Relaxed);
        self.done.store(0, Ordering::Relaxed);
        self.failures.store(0, Ordering::Relaxed);
    }

    /// `(done, total, failures)`.
    pub fn snapshot(&self) -> (usize, usize, usize) {
        (
            self.done.load(Ordering::Relaxed),
            self.total.load(Ordering::Relaxed),
            self.failures.load(Ordering::Relaxed),
        )
    }

    /// Share of failed queries among all queries sent so far (`0.0..=1.0`).
    pub fn failure_ratio(&self) -> f64 {
        let (done, _, failed) = self.snapshot();
        if done + failed == 0 {
            0.0
        } else {
            failed as f64 / (done + failed) as f64
        }
    }
}

impl Default for BruteConfig {
    fn default() -> Self {
        BruteConfig {
            pace: Pace::default(),
            retries: 2,
            wildcard_probes: 3,
            wildcard_extra_probes: 6,
            max_candidates: 20_000,
            progress: None,
        }
    }
}

/// A discovered host.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BruteHit {
    pub host: String,
    pub ips: Vec<String>,
    pub cnames: Vec<String>,
    pub ttl: Option<u32>,
    /// Confirmed by a separate trusted resolver in phase 2.
    pub verified: bool,
}

/// Result of a brute force run.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct BruteReport {
    pub domain: String,
    /// Names queried in phase 1.
    pub tried: usize,
    pub hits: Vec<BruteHit>,
    /// Wildcard levels found while filtering.
    pub wildcard_levels: Vec<WildcardProfile>,
    /// Names whose answer matched a wildcard (dropped).
    pub wildcard_filtered: Vec<String>,
    /// Names answered by the pool but not by the trusted resolver (dropped).
    pub unverified: Vec<String>,
    /// Names that kept failing with resolver errors.
    pub failed: Vec<String>,
    /// Candidates skipped because they are outside the zone, invalid or excluded.
    pub skipped: usize,
    /// Rate at the end of the run and the lowest rate reached, queries per second.
    pub final_rps: f64,
    pub lowest_rps: f64,
}

/// Checks that a target-touching DNS operation on `host` is allowed: the passive profile and
/// exclusions deny it, and the host must be in scope. Denials are logged.
pub(crate) async fn authorize_standard(
    net: &NetClient,
    module: &str,
    method: &str,
    url: &str,
    host: &str,
) -> Result<(), NetError> {
    if let Err(e) = net.passive_access(host, None) {
        let mut rec = net.draft(module, method, url, host, &Access::TouchesTarget);
        rec.blocked = true;
        rec.error = Some(format!("{}: {e}", e.code()));
        net.record(rec);
        return Err(e);
    }
    net.authorize_logged(module, method, url, host, &Access::TouchesTarget)
        .await
        .map(|_| ())
}

/// Builds candidate names `word.domain` from labels.
pub fn candidates(domain: &str, words: &[String]) -> Vec<String> {
    let d = norm_name(domain);
    words.iter().map(|w| format!("{w}.{d}")).collect()
}

/// Runs a brute force of `domain` with a wordlist.
///
/// # Errors
///
/// Fails before any query if the zone is not allowed (see the module docs), and on cancellation.
pub async fn bruteforce(
    net: &NetClient,
    resolvers: &Resolvers,
    domain: &str,
    wordlist: &Wordlist,
    cfg: &BruteConfig,
) -> Result<BruteReport, NetError> {
    let names = candidates(domain, &wordlist.words());
    resolve_candidates(net, resolvers, domain, names, cfg).await
}

struct Queue {
    items: VecDeque<(usize, String, u32)>,
    in_flight: usize,
}

/// Resolves names with `pool.len()` resolvers round-robin, retrying errors; returns the positive
/// answers in input order and the names that kept failing.
async fn resolve_many(
    net: &NetClient,
    pacer: &Arc<Pacer>,
    pool: &[Arc<dyn DnsLookup>],
    names: Vec<String>,
    concurrency: usize,
    retries: u32,
    progress: Option<Arc<Progress>>,
) -> Result<(Vec<Resolved>, Vec<String>, HashSet<String>), NetError> {
    let queue = Arc::new(Mutex::new(Queue {
        items: names
            .into_iter()
            .enumerate()
            .map(|(i, n)| (i, n, 0))
            .collect(),
        in_flight: 0,
    }));
    let found: Arc<Mutex<Vec<(usize, Resolved)>>> = Arc::default();
    let negative: Arc<Mutex<HashSet<String>>> = Arc::default();
    let failed: Arc<Mutex<Vec<String>>> = Arc::default();
    let turn = Arc::new(AtomicUsize::new(0));
    let pool: Arc<Vec<Arc<dyn DnsLookup>>> = Arc::new(pool.to_vec());
    let mut set = tokio::task::JoinSet::new();
    for _ in 0..concurrency.max(1) {
        let progress = progress.clone();
        let (queue, found, negative, failed, turn, pool, pacer, net) = (
            queue.clone(),
            found.clone(),
            negative.clone(),
            failed.clone(),
            turn.clone(),
            pool.clone(),
            pacer.clone(),
            net.clone(),
        );
        set.spawn(async move {
            loop {
                if let Some(p) = &progress {
                    if p.stop.load(Ordering::Relaxed) {
                        return Ok(());
                    }
                    if p.pause.load(Ordering::Relaxed) {
                        net.cancellable(tokio::time::sleep(Duration::from_millis(200)))
                            .await?;
                        continue;
                    }
                }
                let item = {
                    let mut q = queue.lock().unwrap_or_else(|e| e.into_inner());
                    match q.items.pop_front() {
                        Some(x) => {
                            q.in_flight += 1;
                            Some(x)
                        }
                        None if q.in_flight == 0 => return Ok(()),
                        None => None,
                    }
                };
                let Some((i, name, attempt)) = item else {
                    net.cancellable(tokio::time::sleep(Duration::from_millis(10)))
                        .await?;
                    continue;
                };
                let done = |q: &Arc<Mutex<Queue>>, requeue: Option<(usize, String, u32)>| {
                    let mut q = q.lock().unwrap_or_else(|e| e.into_inner());
                    q.in_flight -= 1;
                    if let Some(p) = &progress {
                        if requeue.is_some() {
                            p.failures.fetch_add(1, Ordering::Relaxed);
                        } else {
                            p.done.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                    if let Some(x) = requeue {
                        q.items.push_back(x);
                    }
                };
                if let Err(e) = pacer.wait(&net).await {
                    done(&queue, None);
                    return Err(e);
                }
                let dns = &pool[turn.fetch_add(1, Ordering::Relaxed) % pool.len()];
                match net.cancellable(resolve_full(dns.as_ref(), &name)).await {
                    Err(e) | Ok(Err(e @ NetError::Cancelled)) => {
                        done(&queue, None);
                        return Err(e);
                    }
                    Ok(Ok(r)) => {
                        pacer.rate().on_success();
                        match r {
                            Some(r) => found.lock().unwrap_or_else(|e| e.into_inner()).push((i, r)),
                            None => {
                                negative
                                    .lock()
                                    .unwrap_or_else(|e| e.into_inner())
                                    .insert(name);
                            }
                        }
                        done(&queue, None);
                    }
                    Ok(Err(e)) => {
                        if !e.is_scope_denial() {
                            pacer.rate().on_failure();
                        }
                        if attempt < retries && !e.is_scope_denial() {
                            done(&queue, Some((i, name, attempt + 1)));
                        } else {
                            failed.lock().unwrap_or_else(|e| e.into_inner()).push(name);
                            if let Some(p) = &progress {
                                p.failures.fetch_add(1, Ordering::Relaxed);
                            }
                            done(&queue, None);
                        }
                    }
                }
            }
        });
    }
    let mut err = None;
    while let Some(r) = set.join_next().await {
        if let Ok(Err(e)) = r {
            err.get_or_insert(e);
            set.abort_all();
        }
    }
    if let Some(e) = err {
        return Err(e);
    }
    let mut found = std::mem::take(&mut *found.lock().unwrap_or_else(|e| e.into_inner()));
    found.sort_by_key(|x| x.0);
    let failed = std::mem::take(&mut *failed.lock().unwrap_or_else(|e| e.into_inner()));
    let negative = std::mem::take(&mut *negative.lock().unwrap_or_else(|e| e.into_inner()));
    Ok((found.into_iter().map(|x| x.1).collect(), failed, negative))
}

/// Resolves arbitrary candidate names under `domain` (brute force, permutations): phase 1 through
/// the pool, a wildcard pre-filter, phase 2 through the trusted resolver, and the final
/// multi-level wildcard filter.
///
/// Candidates outside `domain`, invalid names and names outside the scope (including exclusions)
/// are skipped without a query.
///
/// # Errors
///
/// Fails before any query if the zone is not allowed, and on cancellation.
pub async fn resolve_candidates(
    net: &NetClient,
    resolvers: &Resolvers,
    domain: &str,
    names: Vec<String>,
    cfg: &BruteConfig,
) -> Result<BruteReport, NetError> {
    let domain = norm_name(domain);
    authorize_standard(
        net,
        MODULE,
        "DNS",
        &format!("dns-brute://{domain}"),
        &domain,
    )
    .await?;
    let Some(reference) = resolvers.reference() else {
        return Err(NetError::Dns("no resolvers".into()));
    };
    let mut rep = BruteReport {
        domain: domain.clone(),
        ..Default::default()
    };
    let suffix = format!(".{domain}");
    let mut seen = HashSet::new();
    let mut list = Vec::new();
    for n in names {
        let n = norm_name(&n);
        if !n.ends_with(&suffix) || !valid_host(&n) || !net.host_in_scope(&n) {
            rep.skipped += 1;
            continue;
        }
        if seen.insert(n.clone()) {
            if list.len() >= cfg.max_candidates {
                rep.skipped += 1;
                continue;
            }
            list.push(n);
        }
    }
    rep.tried = list.len();
    if let Some(p) = &cfg.progress {
        p.start(list.len());
    }
    let pacer = Arc::new(Pacer::new(cfg.pace.clone()));
    let filter = WildcardFilter::new(
        reference.clone(),
        cfg.wildcard_probes,
        cfg.wildcard_extra_probes,
    );
    let (phase1, failed, _) = resolve_many(
        net,
        &pacer,
        &resolvers.pool,
        list,
        cfg.pace.concurrency,
        cfg.retries,
        cfg.progress.clone(),
    )
    .await?;
    rep.failed = failed;
    // Wildcard pre-filter on the pool answers, so a wildcard zone does not cost a second full pass.
    let mut survivors = Vec::new();
    for r in phase1 {
        if net.is_cancelled() {
            return Err(NetError::Cancelled);
        }
        if filter.is_wildcard(&r).await {
            rep.wildcard_filtered.push(r.name);
        } else {
            survivors.push(r);
        }
    }
    let (confirmed, verified) = match &resolvers.trusted {
        Some(t) => {
            let names: Vec<String> = survivors.iter().map(|r| r.name.clone()).collect();
            let (ok, failed2, negative) = resolve_many(
                net,
                &pacer,
                std::slice::from_ref(t),
                names,
                cfg.pace.concurrency.min(4),
                cfg.retries,
                None,
            )
            .await?;
            let ok_names: HashSet<&str> = ok.iter().map(|r| r.name.as_str()).collect();
            for r in &survivors {
                if !ok_names.contains(r.name.as_str()) && negative.contains(&r.name) {
                    rep.unverified.push(r.name.clone());
                }
            }
            rep.failed.extend(failed2);
            (ok, true)
        }
        None => (survivors, false),
    };
    for r in confirmed {
        if net.is_cancelled() {
            return Err(NetError::Cancelled);
        }
        if filter.is_wildcard(&r).await {
            rep.wildcard_filtered.push(r.name);
            continue;
        }
        rep.hits.push(BruteHit {
            host: r.name,
            ips: r.ips,
            cnames: r.cnames,
            ttl: r.ttl,
            verified,
        });
    }
    rep.wildcard_levels = filter.wildcard_levels().await;
    let rate = pacer.rate();
    rep.final_rps = rate.rps();
    rep.lowest_rps = rate.lowest();
    Ok(rep)
}

#[doc(hidden)]
pub mod testdns {
    //! Configurable fake resolver for offline tests of DNS modules.

    use std::collections::HashMap;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    use crate::dns::{norm_name, DnsAnswer, DnsLookup, DnsRecord, RType};
    use crate::{BoxFuture, NetError};

    /// Addresses, CNAME target and TTL of a name.
    pub type Entry = (Vec<String>, Option<String>, u32);
    /// Address pools used in turn, CNAME target and TTL of a wildcard level.
    pub type WildEntry = (Vec<Vec<String>>, Option<String>, u32);

    /// A fake zone: exact names, wildcard levels (optionally rotating through address pools),
    /// injected failures and a query counter.
    #[derive(Default)]
    pub struct FakeDns {
        /// name -> (addresses, CNAME target, TTL)
        pub names: HashMap<String, Entry>,
        /// level -> (address pools used in turn, CNAME target, TTL)
        pub wildcards: HashMap<String, WildEntry>,
        /// name -> remaining failures before answering
        pub failures: Mutex<HashMap<String, usize>>,
        /// name -> PTR values (keyed by the `in-addr.arpa` name)
        pub ptr: HashMap<String, Vec<String>>,
        pub queries: AtomicUsize,
        turn: AtomicUsize,
        pub log: Mutex<Vec<String>>,
    }

    impl FakeDns {
        pub fn new() -> Self {
            Self::default()
        }

        pub fn host(mut self, name: &str, ips: &[&str], ttl: u32) -> Self {
            self.names.insert(
                norm_name(name),
                (ips.iter().map(|s| s.to_string()).collect(), None, ttl),
            );
            self
        }

        pub fn cname(mut self, name: &str, target: &str, ttl: u32) -> Self {
            self.names
                .insert(norm_name(name), (vec![], Some(norm_name(target)), ttl));
            self
        }

        pub fn wildcard(mut self, level: &str, pools: &[&[&str]], ttl: u32) -> Self {
            self.wildcards.insert(
                norm_name(level),
                (
                    pools
                        .iter()
                        .map(|p| p.iter().map(|s| s.to_string()).collect())
                        .collect(),
                    None,
                    ttl,
                ),
            );
            self
        }

        pub fn wildcard_cname(mut self, level: &str, target: &str, ttl: u32) -> Self {
            self.wildcards
                .insert(norm_name(level), (vec![], Some(norm_name(target)), ttl));
            self
        }

        pub fn fail(self, name: &str, times: usize) -> Self {
            self.failures.lock().unwrap().insert(norm_name(name), times);
            self
        }

        pub fn ptr(mut self, ip: &str, names: &[&str]) -> Self {
            let ip: std::net::IpAddr = ip.parse().unwrap();
            self.ptr.insert(
                crate::dns::reverse_name(ip),
                names.iter().map(|s| s.to_string()).collect(),
            );
            self
        }

        pub fn count(&self) -> usize {
            self.queries.load(Ordering::SeqCst)
        }

        fn entry(&self, n: &str) -> Option<Entry> {
            if let Some(e) = self.names.get(n) {
                return Some(e.clone());
            }
            // a wildcard matches only if no closer existing name is an ancestor
            let mut cur = n;
            while let Some((_, parent)) = cur.split_once('.') {
                if let Some((pools, c, ttl)) = self.wildcards.get(parent) {
                    let ips = if pools.is_empty() {
                        vec![]
                    } else {
                        pools[self.turn.fetch_add(1, Ordering::SeqCst) % pools.len()].clone()
                    };
                    return Some((ips, c.clone(), *ttl));
                }
                if self.names.contains_key(parent) {
                    return None;
                }
                cur = parent;
            }
            None
        }

        fn answer(&self, n: &str, t: RType, depth: usize) -> DnsAnswer {
            let Some((ips, cname, ttl)) = self.entry(n) else {
                return DnsAnswer {
                    records: vec![],
                    nxdomain: true,
                };
            };
            let mut records = Vec::new();
            if let Some(c) = cname {
                records.push(DnsRecord {
                    name: n.to_string(),
                    rtype: "CNAME".into(),
                    ttl,
                    value: c.clone(),
                });
                if depth < 8 {
                    let a = self.answer(&c, t, depth + 1);
                    records.extend(a.records);
                }
                return DnsAnswer {
                    records,
                    nxdomain: false,
                };
            }
            // like a real zone: an address-only name has no CNAME/TXT/MX/... data
            if t != RType::A && t != RType::AAAA {
                return DnsAnswer {
                    records,
                    nxdomain: false,
                };
            }
            for ip in ips {
                let v6 = ip.contains(':');
                if (t == RType::AAAA) == v6 {
                    records.push(DnsRecord {
                        name: n.to_string(),
                        rtype: t.as_str().into(),
                        ttl,
                        value: ip,
                    });
                }
            }
            DnsAnswer {
                records,
                nxdomain: false,
            }
        }
    }

    impl DnsLookup for FakeDns {
        fn lookup<'a>(
            &'a self,
            name: &'a str,
            t: RType,
        ) -> BoxFuture<'a, Result<DnsAnswer, NetError>> {
            Box::pin(async move {
                self.queries.fetch_add(1, Ordering::SeqCst);
                let n = norm_name(name);
                self.log.lock().unwrap().push(format!("{n} {}", t.as_str()));
                {
                    let mut f = self.failures.lock().unwrap();
                    if let Some(k) = f.get_mut(&n) {
                        if *k > 0 {
                            *k -= 1;
                            return Err(NetError::Timeout);
                        }
                    }
                }
                if t == RType::PTR {
                    return Ok(match self.ptr.get(&n) {
                        Some(v) => DnsAnswer {
                            records: v
                                .iter()
                                .map(|x| DnsRecord {
                                    name: n.clone(),
                                    rtype: "PTR".into(),
                                    ttl: 300,
                                    value: norm_name(x),
                                })
                                .collect(),
                            nxdomain: false,
                        },
                        None => DnsAnswer {
                            records: vec![],
                            nxdomain: true,
                        },
                    });
                }
                Ok(self.answer(&n, t, 0))
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::testdns::FakeDns;
    use super::*;
    use crate::sink::MemorySink;
    use crate::NetConfig;
    use foca_core::Scope;

    pub(crate) fn net_for(targets: &str, excludes: &str) -> (NetClient, Arc<MemorySink>) {
        let (scope, _) = Scope::from_lines(targets, excludes);
        let mut cfg = NetConfig::default();
        for t in targets.lines() {
            cfg.host_overrides
                .insert(t.trim().into(), vec!["127.0.0.1".parse().unwrap()]);
        }
        let sink = Arc::new(MemorySink::new());
        (NetClient::new(cfg, scope, sink.clone()).unwrap(), sink)
    }

    fn fast() -> BruteConfig {
        BruteConfig {
            pace: Pace {
                initial_rps: 5000.0,
                min_rps: 1000.0,
                max_rps: 10000.0,
                concurrency: 8,
                ..Pace::wifi()
            },
            ..Default::default()
        }
    }

    fn words(w: &[&str]) -> Wordlist {
        Wordlist::Custom(w.iter().map(|s| s.to_string()).collect())
    }

    fn hosts(r: &BruteReport) -> Vec<&str> {
        let mut v: Vec<&str> = r.hits.iter().map(|h| h.host.as_str()).collect();
        v.sort();
        v
    }

    #[test]
    fn builtin_lists() {
        let a = Wordlist::Top1500.words();
        let b = Wordlist::Top5000.words();
        assert_eq!(a.len(), 1500);
        assert!(b.len() > 4900, "{}", b.len());
        assert_eq!(&b[..1500], &a[..]);
        assert_eq!((a[0].as_str(), a[1].as_str()), ("www", "mail"));
        assert!(a.iter().all(|w| valid_host(w)));
        assert_eq!(Wordlist::builtin("top-5000"), Some(Wordlist::Top5000));
    }

    #[test]
    fn wordlist_parsing() {
        let w = parse_wordlist("# c\nWWW\n*.dev\napi.\n-bad\nok_svc\nsp ace\n\ndev\nv1.api\n");
        assert_eq!(w, vec!["www", "dev", "api", "ok_svc", "v1.api"]);
        assert!(!valid_label(&"a".repeat(64)));
    }

    #[test]
    fn aimd() {
        let mut r = AdaptiveRate::new(Pace {
            initial_rps: 20.0,
            min_rps: 4.0,
            max_rps: 22.0,
            step: 1.0,
            increase_every: 2,
            backoff: 0.5,
            concurrency: 1,
        });
        r.on_failure();
        assert_eq!(r.rps(), 10.0);
        r.on_failure();
        r.on_failure();
        assert_eq!(r.rps(), 4.0);
        assert_eq!(r.lowest(), 4.0);
        for _ in 0..100 {
            r.on_success();
        }
        assert_eq!(r.rps(), 22.0);
        assert_eq!(r.interval(), Duration::from_secs_f64(1.0 / 22.0));
    }

    #[tokio::test]
    async fn finds_hosts_and_retries() {
        let dns = Arc::new(
            FakeDns::new()
                .host("www.zt.test", &["192.0.2.1"], 300)
                .host("mail.zt.test", &["192.0.2.2", "2001:db8::2"], 300)
                .cname("cdn.zt.test", "edge.cdn.example", 60)
                .host("edge.cdn.example", &["198.51.100.9"], 20)
                .cname("old.zt.test", "gone.herokuapp.example", 300)
                .host("vpn.zt.test", &["192.0.2.3"], 300)
                .fail("vpn.zt.test", 2),
        );
        let (net, _) = net_for("zt.test", "");
        let r = bruteforce(
            &net,
            &Resolvers::single(dns.clone()),
            "zt.test",
            &words(&["www", "mail", "cdn", "old", "vpn", "nope", "x"]),
            &fast(),
        )
        .await
        .unwrap();
        assert_eq!(
            hosts(&r),
            vec![
                "cdn.zt.test",
                "mail.zt.test",
                "old.zt.test",
                "vpn.zt.test",
                "www.zt.test"
            ]
        );
        let mail = r.hits.iter().find(|h| h.host == "mail.zt.test").unwrap();
        assert_eq!(mail.ips, vec!["192.0.2.2", "2001:db8::2"]);
        let old = r.hits.iter().find(|h| h.host == "old.zt.test").unwrap();
        assert!(old.ips.is_empty() && old.cnames == vec!["gone.herokuapp.example"]);
        let cdn = r.hits.iter().find(|h| h.host == "cdn.zt.test").unwrap();
        assert_eq!(cdn.ttl, Some(20));
        assert!(r.failed.is_empty() && r.wildcard_levels.is_empty());
        assert_eq!(r.tried, 7);
        assert!(r.lowest_rps < fast().pace.initial_rps);
    }

    #[tokio::test]
    async fn multi_level_wildcard_zero_false_positives() {
        // *.zt.test (stable), *.dev.zt.test (rotating pool), *.api.zt.test (CNAME)
        let dns = Arc::new(
            FakeDns::new()
                .wildcard("zt.test", &[&["192.0.2.80"]], 300)
                .host("www.zt.test", &["192.0.2.10"], 3600)
                .host("dev.zt.test", &["192.0.2.11"], 300)
                .wildcard(
                    "dev.zt.test",
                    &[
                        &["198.51.100.1"],
                        &["198.51.100.2"],
                        &["198.51.100.3"],
                        &["198.51.100.4"],
                        &["198.51.100.5"],
                        &["198.51.100.6"],
                        &["198.51.100.7"],
                        &["198.51.100.8"],
                        &["198.51.100.9"],
                        &["198.51.100.10"],
                        &["198.51.100.11"],
                        &["198.51.100.12"],
                        &["198.51.100.13"],
                        &["198.51.100.14"],
                    ],
                    60,
                )
                .host("git.dev.zt.test", &["192.0.2.12"], 600)
                .host("api.zt.test", &["192.0.2.13"], 300)
                .wildcard_cname("api.zt.test", "lb.api.zt.test", 300)
                .host("lb.api.zt.test", &["192.0.2.14"], 300)
                .cname("v2.api.zt.test", "apigw.cloud.example", 300)
                .host("apigw.cloud.example", &["203.0.113.5"], 300),
        );
        let (net, _) = net_for("zt.test", "");
        let mut names = candidates(
            "zt.test",
            &parse_wordlist("www\ndev\napi\nshop\nadmin\nblog"),
        );
        names.extend(candidates(
            "dev.zt.test",
            &parse_wordlist("git\nci\njenkins\nstage\nqa\nx1\nx2\nx3\nx4\nx5\nx6"),
        ));
        names.extend(candidates(
            "api.zt.test",
            &parse_wordlist("v2\nv1\nv3\nlb\nint"),
        ));
        let r = resolve_candidates(&net, &Resolvers::single(dns), "zt.test", names, &fast())
            .await
            .unwrap();
        assert_eq!(
            hosts(&r),
            vec![
                "api.zt.test",
                "dev.zt.test",
                "git.dev.zt.test",
                "lb.api.zt.test",
                "v2.api.zt.test",
                "www.zt.test"
            ],
            "filtered: {:?}",
            r.wildcard_filtered
        );
        let levels: Vec<&str> = r.wildcard_levels.iter().map(|w| w.level.as_str()).collect();
        assert_eq!(levels, vec!["api.zt.test", "dev.zt.test", "zt.test"]);
        assert!(r
            .wildcard_levels
            .iter()
            .any(|w| w.level == "dev.zt.test" && w.rotating));
        assert_eq!(r.wildcard_filtered.len(), 3 + 10 + 3);
    }

    #[tokio::test]
    async fn two_phase_verification() {
        // the pool resolver hijacks NXDOMAIN for some names, the trusted one does not
        let pool = Arc::new(
            FakeDns::new()
                .host("www.zt.test", &["192.0.2.1"], 300)
                .host("fake.zt.test", &["203.0.113.66"], 300),
        );
        let trusted = Arc::new(FakeDns::new().host("www.zt.test", &["192.0.2.1"], 300));
        let (net, _) = net_for("zt.test", "");
        let r = bruteforce(
            &net,
            &Resolvers {
                pool: vec![pool.clone()],
                trusted: Some(trusted.clone()),
            },
            "zt.test",
            &words(&["www", "fake", "none"]),
            &fast(),
        )
        .await
        .unwrap();
        assert_eq!(hosts(&r), vec!["www.zt.test"]);
        assert!(r.hits[0].verified);
        assert_eq!(r.unverified, vec!["fake.zt.test"]);
    }

    #[tokio::test]
    async fn passive_profile_and_scope_make_no_queries() {
        let dns = Arc::new(FakeDns::new().host("www.zt.test", &["192.0.2.1"], 300));
        let (net, sink) = net_for("zt.test", "");
        let (full, _) = Scope::from_lines("zt.test", "");
        net.set_passive_guard(full, true);
        let r = bruteforce(
            &net,
            &Resolvers::single(dns.clone()),
            "zt.test",
            &words(&["www"]),
            &fast(),
        )
        .await;
        assert!(matches!(r, Err(NetError::OutOfScope { .. })), "{r:?}");
        assert_eq!(dns.count(), 0);
        assert!(sink
            .records()
            .iter()
            .any(|x| x.blocked && x.module == MODULE));
        // a zone outside the scope
        let (net, _) = net_for("other.test", "");
        assert!(bruteforce(
            &net,
            &Resolvers::single(dns.clone()),
            "zt.test",
            &words(&["www"]),
            &fast()
        )
        .await
        .is_err());
        assert_eq!(dns.count(), 0);
        // excluded names are never queried
        let (net, _) = net_for("zt.test", "vpn.zt.test");
        let r = bruteforce(
            &net,
            &Resolvers::single(dns.clone()),
            "zt.test",
            &words(&["vpn", "www"]),
            &fast(),
        )
        .await
        .unwrap();
        assert_eq!(r.skipped, 1);
        assert!(!dns
            .log
            .lock()
            .unwrap()
            .iter()
            .any(|l| l.starts_with("vpn.")));
    }

    #[tokio::test]
    async fn local_only_denies_external_zone() {
        let dns = Arc::new(FakeDns::new());
        let (scope, _) = Scope::from_lines("example.org", "");
        let cfg = NetConfig {
            local_only: Some(std::path::PathBuf::new()),
            ..Default::default()
        };
        let net = NetClient::new(cfg, scope, Arc::new(MemorySink::new())).unwrap();
        let r = bruteforce(
            &net,
            &Resolvers::single(dns.clone()),
            "example.org",
            &words(&["www"]),
            &fast(),
        )
        .await;
        assert!(r.is_err());
        assert_eq!(dns.count(), 0);
    }

    #[tokio::test]
    async fn progress_counts_and_stop() {
        let dns = Arc::new(FakeDns::new().host("www.zt.test", &["10.0.0.1"], 60));
        let (net, _) = net_for("zt.test", "");
        let p = Arc::new(Progress::default());
        let cfg = BruteConfig {
            progress: Some(p.clone()),
            ..fast()
        };
        let r = bruteforce(
            &net,
            &Resolvers::single(dns.clone()),
            "zt.test",
            &words(&["www", "a", "b", "c"]),
            &cfg,
        )
        .await
        .unwrap();
        assert_eq!(r.hits.len(), 1);
        assert_eq!(p.snapshot(), (4, 4, 0));
        // a stop before the run: no candidate is queried, the run still ends cleanly
        p.stop.store(true, Ordering::Relaxed);
        let before = dns.count();
        let r = bruteforce(
            &net,
            &Resolvers::single(dns.clone()),
            "zt.test",
            &words(&["www", "x"]),
            &cfg,
        )
        .await
        .unwrap();
        assert!(r.hits.is_empty());
        assert_eq!(p.snapshot().0, 0);
        assert!(dns.count() - before <= 8, "only wildcard probes may run");
    }

    #[tokio::test]
    async fn progress_counts_failures() {
        let dns = Arc::new(FakeDns::new().fail("bad.zt.test", 10));
        let (net, _) = net_for("zt.test", "");
        let p = Arc::new(Progress::default());
        let cfg = BruteConfig {
            progress: Some(p.clone()),
            retries: 2,
            ..fast()
        };
        bruteforce(
            &net,
            &Resolvers::single(dns),
            "zt.test",
            &words(&["bad", "ok"]),
            &cfg,
        )
        .await
        .unwrap();
        let (done, total, failed) = p.snapshot();
        assert_eq!((done, total), (2, 2));
        assert_eq!(failed, 3, "two retries and the final give-up");
        assert!(p.failure_ratio() > 0.5);
    }

    #[tokio::test]
    async fn cancellation() {
        let dns = Arc::new(FakeDns::new());
        let (net, _) = net_for("zt.test", "");
        net.cancel();
        let r = bruteforce(
            &net,
            &Resolvers::single(dns),
            "zt.test",
            &Wordlist::Top1500,
            &fast(),
        )
        .await;
        assert!(matches!(r, Err(NetError::Cancelled)), "{r:?}");
    }

    /// Live check against an allowed public test target (`cargo test -- --ignored live_`).
    #[tokio::test]
    #[ignore]
    async fn live_testfire() {
        let (net, _) = net_for("testfire.net", "");
        let dns: Arc<dyn DnsLookup> =
            Arc::new(crate::dns::HickoryDns::new(&crate::dns::DnsConfig::default(), &net).unwrap());
        let r = bruteforce(
            &net,
            &Resolvers::single(dns),
            "testfire.net",
            &words(&["www", "demo", "mail", "admin"]),
            &BruteConfig {
                pace: Pace::mobile(),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        assert!(r.hits.iter().any(|h| h.host == "www.testfire.net"), "{r:?}");
    }

    #[test]
    fn random_labels_differ() {
        let a = random_label();
        let b = random_label();
        assert_ne!(a, b);
        assert!(valid_label(&a) && a.len() == 14);
        assert_eq!(parent_level("a.b.c"), "b.c");
    }
}
