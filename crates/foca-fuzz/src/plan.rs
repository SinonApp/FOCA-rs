//! Fuzzing task, per-module candidate generation and request/time estimates.

use std::collections::{BTreeMap, HashSet};
use std::time::Duration;

use foca_core::Scope;
use url::Url;

use crate::config::FuzzConfig;
use crate::mutate::{mutate_name, split_ext};
use crate::types::Module;
use crate::wordlists::{self, Wordlist};

/// Default document extensions (office formats and PDF).
pub const DOC_EXTENSIONS: &[&str] = &[
    "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "odt", "ods", "odp", "rtf", "csv",
];

/// Common document folders.
pub const DOC_DIRS: &[&str] = &[
    "docs",
    "doc",
    "documents",
    "files",
    "file",
    "download",
    "downloads",
    "uploads",
    "upload",
    "media",
    "pdf",
    "reports",
    "attachments",
    "assets/files",
    "storage",
    "public",
    "press",
    "archive",
    "userfiles",
    "data",
];

/// Common document names (without extension).
pub const DOC_NAMES: &[&str] = &[
    "report",
    "annual_report",
    "annual-report",
    "price",
    "pricelist",
    "price-list",
    "catalog",
    "catalogue",
    "presentation",
    "brochure",
    "policy",
    "privacy",
    "privacy-policy",
    "contract",
    "agreement",
    "offer",
    "requisites",
    "rekvizity",
    "info",
    "document",
];

/// Backup suffixes (as in FOCA's Backups Fuzzer plus common editors and archivers).
pub const BACKUP_SUFFIXES: &[&str] = &[
    ".bak", ".old", ".orig", "~", ".save", ".tmp", ".copy", ".1", ".swp", "_bak", ".backup",
    ".zip", ".tar.gz", ".7z", ".rar", ".gz",
];

/// Detected CMS.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Cms {
    WordPress,
    Joomla,
    Drupal,
    SharePoint,
}

impl Cms {
    pub fn parse(s: &str) -> Option<Cms> {
        match s.trim().to_ascii_lowercase().as_str() {
            "wordpress" | "wp" => Some(Cms::WordPress),
            "joomla" => Some(Cms::Joomla),
            "drupal" => Some(Cms::Drupal),
            "sharepoint" => Some(Cms::SharePoint),
            _ => None,
        }
    }

    pub fn wordlist_id(self) -> &'static str {
        match self {
            Cms::WordPress => "cms-wordpress",
            Cms::Joomla => "cms-joomla",
            Cms::Drupal => "cms-drupal",
            Cms::SharePoint => "cms-sharepoint",
        }
    }
}

/// An ffuf-style template: `FUZZ` in the URL (path or file name) or in the `Host` header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Template {
    pub url: String,
    pub host: Option<String>,
}

impl Template {
    pub fn path(url: &str) -> Template {
        Template {
            url: url.to_string(),
            host: None,
        }
    }

    /// Validates the template: exactly one `FUZZ` placeholder.
    ///
    /// # Errors
    ///
    /// Returns a message if `FUZZ` is missing or appears more than once.
    pub fn validate(&self) -> Result<(), String> {
        let n = self.url.matches("FUZZ").count()
            + self
                .host
                .as_deref()
                .map_or(0, |h| h.matches("FUZZ").count());
        if n != 1 {
            return Err("в шаблоне должно быть ровно одно ключевое слово FUZZ".into());
        }
        let probe = self.url.replace("FUZZ", "x");
        let u = Url::parse(&probe).map_err(|e| format!("URL шаблона: {e}"))?;
        if !matches!(u.scheme(), "http" | "https") {
            return Err("схема шаблона должна быть http/https".into());
        }
        if u.query().is_some()
            && self
                .url
                .split('?')
                .nth(1)
                .is_some_and(|q| q.contains("FUZZ"))
        {
            return Err("перебор параметров не поддерживается".into());
        }
        Ok(())
    }
}

/// Free-form fuzzing (content module).
#[derive(Debug, Clone)]
pub struct ContentSpec {
    pub template: Template,
    pub wordlist: Wordlist,
    /// Extensions without the dot. No empty entry is needed: the bare word is always tried.
    pub extensions: Vec<String>,
}

/// Vhost fuzzing.
#[derive(Debug, Clone)]
pub struct VhostSpec {
    /// Client domains from the scope (`contoso.ua`).
    pub domains: Vec<String>,
    pub wordlist: Wordlist,
}

/// A fuzzing task.
#[derive(Debug, Clone)]
pub struct FuzzTask {
    /// Site root (`https://contoso.ua/`).
    pub base: Url,
    pub modules: Vec<Module>,
    /// Already known URLs (crawler, passive sources), used for mutations, backups and listings.
    pub known_urls: Vec<String>,
    pub content: Option<ContentSpec>,
    pub vhost: Option<VhostSpec>,
    pub cms: Option<Cms>,
    pub doc_extensions: Vec<String>,
    /// Year for `wp-content/uploads/<year>/<month>` (defaults to the current year from the
    /// system clock).
    pub current_year: Option<i32>,
}

impl FuzzTask {
    pub fn new(base: Url, modules: Vec<Module>) -> FuzzTask {
        FuzzTask {
            base,
            modules,
            known_urls: Vec::new(),
            content: None,
            vhost: None,
            cms: None,
            doc_extensions: DOC_EXTENSIONS.iter().map(|s| s.to_string()).collect(),
            current_year: None,
        }
    }

    pub fn has(&self, m: Module) -> bool {
        self.modules.contains(&m)
    }
}

/// What a candidate is expected to be (how to interpret the response).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum Expect {
    Generic,
    Directory,
    Document,
    Backup,
    DbBackup,
    Exposed,
    /// A name from .DS_Store or a listing link; only existence is checked.
    Named,
    Vhost,
    Cms,
}

/// Calibration context.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(crate) struct CtxKey {
    pub origin: String,
    /// For vhosts the base domain (`contoso.ua`), otherwise an explicit Host or `None`.
    pub vhost: Option<String>,
    pub dir: String,
    pub ext: String,
    /// Dotfile class (`/.name`, `/.name.bak`): servers often route these differently
    /// (Apache denies `.ht*`, SPA hosts rewrite them to `index.html`).
    pub dot: bool,
}

impl CtxKey {
    pub fn label(&self) -> String {
        match &self.vhost {
            Some(d) if self.ext == "vhost" => format!("Host: *.{d} → {}", self.origin),
            _ => format!(
                "{}{}{}*{}",
                self.origin,
                self.dir,
                self.dot_prefix(),
                self.ext
            ),
        }
    }

    /// `.` for the dotfile class, otherwise empty.
    pub fn dot_prefix(&self) -> &'static str {
        if self.dot {
            "."
        } else {
            ""
        }
    }
}

/// A candidate.
#[derive(Debug, Clone)]
pub(crate) struct Job {
    pub url: Url,
    pub host: Option<String>,
    /// The variable part (used to normalize echoes in a soft 404).
    pub word: String,
    pub module: Module,
    pub expect: Expect,
    pub depth: u8,
    pub ctx: CtxKey,
}

pub(crate) fn origin_of(u: &Url) -> String {
    let mut o = format!("{}://{}", u.scheme(), u.host_str().unwrap_or(""));
    if let Some(p) = u.port() {
        o.push_str(&format!(":{p}"));
    }
    o
}

fn coarse_dir(path: &str, max_segments: usize) -> String {
    let mut out = String::from("/");
    for seg in path.trim_start_matches('/').split('/').take(max_segments) {
        if seg.is_empty() {
            break;
        }
        out.push_str(seg);
        out.push('/');
    }
    out
}

/// Returns the directory and extension class used for calibration.
pub(crate) fn ctx_for(url: &Url, host: Option<&str>, expect: Expect) -> CtxKey {
    let path = url.path();
    let mut dot = false;
    let (dir, last) = if path.ends_with('/') && path.len() > 1 {
        let t = &path[..path.len() - 1];
        let i = t.rfind('/').map(|i| i + 1).unwrap_or(1);
        (t[..i].to_string(), "/".to_string())
    } else {
        let i = path.rfind('/').map(|i| i + 1).unwrap_or(1);
        let name = &path[i..];
        let rest = match name.strip_prefix('.') {
            Some(r) if !r.is_empty() => {
                dot = true;
                r
            }
            _ => name,
        };
        let (stem, ext) = split_ext(rest);
        let ext = if stem.is_empty() {
            String::new()
        } else {
            ext.to_ascii_lowercase()
        };
        (path[..i].to_string(), ext)
    };
    // Service files and CMS paths use a coarser context; otherwise every wordlist subdirectory
    // would need its own calibration.
    let dir = match expect {
        Expect::Exposed | Expect::Cms | Expect::Generic | Expect::DbBackup => coarse_dir(&dir, 0),
        _ => dir,
    };
    CtxKey {
        origin: origin_of(url),
        vhost: host.map(str::to_string),
        dir,
        ext: last,
        dot,
    }
}

/// Candidate builder with deduplication and exclusions.
///
/// The sink lives for the whole run: candidates found while handling responses go through the
/// same deduplication and context limits as the initial plan.
pub(crate) struct JobSink<'a> {
    cfg: &'a FuzzConfig,
    scope: Option<&'a Scope>,
    seen: HashSet<(String, Option<String>)>,
    jobs: Vec<Job>,
    skipped_excluded: u64,
    /// Calibration contexts already in use (limited by `max_contexts`).
    contexts: HashSet<CtxKey>,
}

impl<'a> JobSink<'a> {
    pub fn new(cfg: &'a FuzzConfig, scope: Option<&'a Scope>) -> Self {
        JobSink {
            cfg,
            scope,
            seen: HashSet::new(),
            jobs: Vec::new(),
            skipped_excluded: 0,
            contexts: HashSet::new(),
        }
    }

    fn allowed_host(&self, h: &str) -> bool {
        match self.scope {
            Some(s) => s.check_active(h).is_ok(),
            None => true,
        }
    }

    /// Adds a candidate; returns `false` for duplicates and excluded URLs.
    pub fn push(
        &mut self,
        url: Url,
        host: Option<String>,
        word: &str,
        module: Module,
        expect: Expect,
        depth: u8,
    ) -> bool {
        if !matches!(url.scheme(), "http" | "https") {
            return false;
        }
        let key = (url.as_str().to_string(), host.clone());
        if self.seen.contains(&key) {
            return false;
        }
        self.seen.insert(key);
        if self.cfg.path_excluded(url.path()) {
            self.skipped_excluded += 1;
            return false;
        }
        let url_host = url.host_str().unwrap_or("").to_string();
        if !self.allowed_host(&url_host) || host.as_deref().is_some_and(|h| !self.allowed_host(h)) {
            self.skipped_excluded += 1;
            return false;
        }
        let ctx = if expect == Expect::Vhost {
            CtxKey {
                origin: origin_of(&url),
                vhost: host.as_deref().map(vhost_base),
                dir: String::new(),
                ext: "vhost".into(),
                dot: false,
            }
        } else {
            ctx_for(&url, host.as_deref(), expect)
        };
        // Too many contexts: fall back to the host-wide context (keeping the dotfile class) so
        // calibration does not eat the budget.
        let ctx = if expect == Expect::Vhost
            || self.contexts.contains(&ctx)
            || self.contexts.len() < self.cfg.max_contexts
        {
            ctx
        } else {
            CtxKey {
                origin: ctx.origin,
                vhost: ctx.vhost,
                dir: "/".into(),
                ext: String::new(),
                dot: ctx.dot,
            }
        };
        self.contexts.insert(ctx.clone());
        self.jobs.push(Job {
            url,
            host,
            word: word.to_string(),
            module,
            expect,
            depth,
            ctx,
        });
        true
    }

    /// Marks a URL as already known so it is never scheduled.
    pub fn mark_known(&mut self, url: &Url) {
        self.seen.insert((url.as_str().to_string(), None));
    }

    /// Moves the candidates added since the last flush to `queue` and adds the number of URLs
    /// skipped as excluded meanwhile to `skipped`.
    pub fn flush_into(&mut self, queue: &mut impl Extend<Job>, skipped: &mut u64) {
        queue.extend(self.jobs.drain(..));
        *skipped += std::mem::take(&mut self.skipped_excluded);
    }
}

/// `intranet.contoso.ua` → `contoso.ua`.
pub(crate) fn vhost_base(h: &str) -> String {
    h.split_once('.')
        .map(|(_, b)| b.to_string())
        .unwrap_or_else(|| h.to_string())
}

pub(crate) fn join(base: &Url, rel: &str) -> Option<Url> {
    base.join(rel).ok()
}

pub(crate) fn is_doc_ext(name: &str, exts: &[String]) -> bool {
    let (_, e) = split_ext(name);
    let e = e.trim_start_matches('.').to_ascii_lowercase();
    !e.is_empty() && exts.iter().any(|x| x.eq_ignore_ascii_case(&e))
}

fn last_segment(u: &Url) -> &str {
    u.path().rsplit('/').next().unwrap_or("")
}

/// Returns backup variants of a known file.
pub(crate) fn backup_variants(u: &Url) -> Vec<(Url, String)> {
    let name = last_segment(u);
    let mut out = Vec::new();
    if name.is_empty() {
        return out;
    }
    let (stem, ext) = split_ext(name);
    let mut names: Vec<String> = BACKUP_SUFFIXES
        .iter()
        .map(|s| format!("{name}{s}"))
        .collect();
    if !ext.is_empty() {
        for s in [".bak", ".old", ".zip"] {
            names.push(format!("{stem}{s}"));
        }
        names.push(format!("{stem}_old{ext}"));
        names.push(format!("{stem}_backup{ext}"));
        names.push(format!("{stem}.bak{ext}"));
    }
    names.push(format!(".{name}.swp"));
    for n in names {
        if let Some(v) = u.join(&n).ok().filter(|v| v.path() != u.path()) {
            out.push((v, n));
        }
    }
    out
}

/// Returns whole-site archive names at the root (`<domain>.zip`, `backup.tar.gz`, …).
pub(crate) fn site_archive_names(base: &Url) -> Vec<String> {
    let host = base.host_str().unwrap_or("site").to_string();
    let label = host
        .split('.')
        .find(|l| *l != "www")
        .unwrap_or("site")
        .to_string();
    let mut v = Vec::new();
    for stem in [
        "backup",
        "site",
        "www",
        "html",
        "web",
        host.as_str(),
        label.as_str(),
    ] {
        for ext in ["zip", "tar.gz", "7z"] {
            v.push(format!("{stem}.{ext}"));
        }
    }
    v.sort();
    v.dedup();
    v
}

fn this_year() -> i32 {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    1970 + (secs / 31_556_952) as i32
}

/// Builds the initial candidate set (no network access).
/// API documentation and service endpoints added to the `exposed` module on top of quickhits;
/// hits are parsed by `foca_recon::apidocs` (endpoint count, API version, auth schemes).
pub const API_DOC_PATHS: &[&str] = &[
    "swagger.json",
    "openapi.json",
    "v2/api-docs",
    "v3/api-docs",
    "api-docs",
    "swagger/v1/swagger.json",
    "api/swagger.json",
    "swagger-ui.html",
    "swagger-ui/index.html",
    ".well-known/openid-configuration",
    "actuator/env",
    "actuator/mappings",
    "actuator/health",
];

pub(crate) fn initial_jobs(
    task: &FuzzTask,
    sink: &mut JobSink<'_>,
    wl_dir: Option<&std::path::Path>,
) -> Result<(), String> {
    let base = &task.base;
    let base_origin = origin_of(base);
    let known: Vec<Url> = task
        .known_urls
        .iter()
        .filter_map(|s| Url::parse(s).ok())
        .filter(|u| origin_of(u) == base_origin)
        .collect();
    let exts = &task.doc_extensions;
    // Known URLs are not requested again.
    for u in known.iter().filter(|u| !u.path().ends_with('/')) {
        sink.mark_known(u);
    }

    if task.has(Module::DirListing) {
        sink.push(
            base.clone(),
            None,
            "",
            Module::DirListing,
            Expect::Directory,
            0,
        );
        for u in &known {
            // Parent directories of known files.
            let mut p = u.clone();
            p.set_query(None);
            p.set_fragment(None);
            let mut path = p.path().to_string();
            while let Some(i) = path[..path.len().saturating_sub(1)].rfind('/') {
                path.truncate(i + 1);
                if path == "/" {
                    break;
                }
                if let Some(d) = join(base, &path) {
                    let w = path
                        .trim_end_matches('/')
                        .rsplit('/')
                        .next()
                        .unwrap_or("")
                        .to_string();
                    sink.push(d, None, &w, Module::DirListing, Expect::Directory, 0);
                }
            }
        }
    }

    if task.has(Module::Docs) {
        // Mutations of known documents go first.
        for u in &known {
            let name = last_segment(u);
            if is_doc_ext(name, exts) {
                for m in mutate_name(name, sink.cfg.max_mutations) {
                    if let Ok(v) = u.join(&m) {
                        sink.push(v, None, &m, Module::Docs, Expect::Document, 1);
                    }
                }
            }
        }
        for d in DOC_DIRS {
            if let Some(u) = join(base, &format!("{d}/")) {
                sink.push(u, None, d, Module::Docs, Expect::Directory, 0);
            }
        }
        let y = task.current_year.unwrap_or_else(this_year);
        for year in [y, y - 1] {
            for m in 1..=12 {
                let p = format!("wp-content/uploads/{year}/{m:02}/");
                if let Some(u) = join(base, &p) {
                    sink.push(
                        u,
                        None,
                        &format!("{m:02}"),
                        Module::Docs,
                        Expect::Directory,
                        0,
                    );
                }
            }
        }
        for n in DOC_NAMES {
            for e in exts {
                let f = format!("{n}.{e}");
                if let Some(u) = join(base, &f) {
                    sink.push(u, None, &f, Module::Docs, Expect::Document, 0);
                }
            }
        }
    }

    if task.has(Module::Backups) {
        for u in &known {
            for (v, n) in backup_variants(u) {
                sink.push(v, None, &n, Module::Backups, Expect::Backup, 0);
            }
        }
        for n in site_archive_names(base) {
            if let Some(u) = join(base, &n) {
                sink.push(u, None, &n, Module::Backups, Expect::Backup, 0);
            }
        }
        let db = wordlists::builtin("db-backups").map_err(|e| e.to_string())?;
        for w in &db.words {
            if let Some(u) = join(base, w) {
                sink.push(u, None, w, Module::Backups, Expect::DbBackup, 0);
            }
        }
    }

    if task.has(Module::Exposed) {
        let q = wordlists::builtin("quickhits").map_err(|e| e.to_string())?;
        for w in &q.words {
            if let Some(u) = join(base, w) {
                let expect = if w.ends_with('/') {
                    Expect::Directory
                } else {
                    Expect::Exposed
                };
                sink.push(u, None, w, Module::Exposed, expect, 0);
            }
        }
        for w in API_DOC_PATHS {
            if q.words.iter().any(|x| x == w) {
                continue;
            }
            if let Some(u) = join(base, w) {
                sink.push(u, None, w, Module::Exposed, Expect::Exposed, 0);
            }
        }
    }

    if task.has(Module::Vhost) {
        if let Some(v) = &task.vhost {
            for d in &v.domains {
                for w in &v.wordlist.words {
                    if w.contains('/') || w.contains('.') && w.ends_with('.') {
                        continue;
                    }
                    let h = format!("{w}.{}", d.trim_start_matches("*.").trim_end_matches('.'));
                    sink.push(base.clone(), Some(h), w, Module::Vhost, Expect::Vhost, 0);
                }
            }
        }
    }

    if task.has(Module::Cms) {
        if let Some(c) = task.cms {
            let wl = wordlists::resolve(c.wordlist_id(), wl_dir).map_err(|e| e.to_string())?;
            for w in &wl.words {
                if let Some(u) = join(base, w) {
                    let expect = if w.ends_with('/') {
                        Expect::Directory
                    } else {
                        Expect::Cms
                    };
                    sink.push(u, None, w, Module::Cms, expect, 0);
                }
            }
        }
    }

    if task.has(Module::Content) {
        if let Some(c) = &task.content {
            content_jobs(c, None, sink, 0)?;
        }
    }
    Ok(())
}

/// Builds template candidates (for recursion, `prefix` is a discovered directory used with a
/// `…/FUZZ` template).
pub(crate) fn content_jobs(
    c: &ContentSpec,
    prefix: Option<&Url>,
    sink: &mut JobSink<'_>,
    depth: u8,
) -> Result<(), String> {
    c.template.validate()?;
    let tpl_url = match prefix {
        Some(p) => format!("{}FUZZ", p.as_str()),
        None => c.template.url.clone(),
    };
    for w in &c.wordlist.words {
        let mut variants = vec![w.clone()];
        if !w.ends_with('/') {
            for e in &c.extensions {
                let e = e.trim_start_matches('.');
                if !e.is_empty() {
                    variants.push(format!("{w}.{e}"));
                }
            }
        }
        for v in variants {
            let (url, host) = match &c.template.host {
                Some(h) if h.contains("FUZZ") => {
                    if v.contains('/') {
                        continue;
                    }
                    (tpl_url.clone(), Some(h.replace("FUZZ", &v)))
                }
                h => (tpl_url.replace("FUZZ", &v), h.clone()),
            };
            let Ok(u) = Url::parse(&url) else {
                continue;
            };
            let vhost_mode = c
                .template
                .host
                .as_deref()
                .is_some_and(|h| h.contains("FUZZ"));
            let expect = if vhost_mode {
                Expect::Vhost
            } else if v.ends_with('/') {
                Expect::Directory
            } else {
                Expect::Generic
            };
            sink.push(u, host, &v, Module::Content, expect, depth);
        }
    }
    Ok(())
}

/// Fuzzing volume estimate.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct Estimate {
    /// Candidates in the initial plan.
    pub candidates: u64,
    /// Calibration requests (contexts × samples).
    pub calibration: u64,
    /// Total requests, capped by the budget.
    pub requests: u64,
    /// Expected time in seconds (accounting for rate, workers, jitter and `max_time`).
    pub seconds: u64,
    pub per_module: BTreeMap<String, u64>,
    pub skipped_excluded: u64,
    /// The plan is capped by the request budget.
    pub capped_by_budget: bool,
    pub note: String,
}

/// Estimates request count and time without network access (dry run).
pub fn estimate(
    task: &FuzzTask,
    cfg: &FuzzConfig,
    scope: Option<&Scope>,
    wl_dir: Option<&std::path::Path>,
) -> Result<Estimate, String> {
    let mut sink = JobSink::new(cfg, scope);
    initial_jobs(task, &mut sink, wl_dir)?;
    let mut jobs = Vec::new();
    let mut skipped_excluded = 0;
    sink.flush_into(&mut jobs, &mut skipped_excluded);
    let mut per_module = BTreeMap::new();
    let mut ctxs = HashSet::new();
    for j in &jobs {
        *per_module.entry(j.module.id().to_string()).or_insert(0u64) += 1;
        ctxs.insert(j.ctx.clone());
    }
    let candidates = jobs.len() as u64;
    let calibration = if cfg.calibrate {
        ctxs.len() as u64 * cfg.calibration_samples as u64
    } else {
        0
    };
    let total = candidates + calibration;
    let requests = total.min(cfg.max_requests);
    let secs = request_seconds(requests, cfg).min(cfg.max_time.as_secs_f64());
    Ok(Estimate {
        candidates,
        calibration,
        requests,
        seconds: secs.ceil() as u64,
        per_module,
        skipped_excluded,
        capped_by_budget: total > cfg.max_requests,
        note: "без учёта кандидатов, появляющихся по ходу (мутации найденного, листинги, .DS_Store, рекурсия)".into(),
    })
}

/// Returns the time for `n` requests: throughput is limited by `rate` and by
/// `threads / (latency + jitter/2)`.
pub fn request_seconds(n: u64, cfg: &FuzzConfig) -> f64 {
    let latency = 0.35 + cfg.jitter.as_secs_f64() / 2.0;
    let by_threads = cfg.threads.max(1) as f64 / latency;
    let rps = cfg.rate.max(0.01).min(by_threads);
    n as f64 / rps
}

pub fn fmt_duration(d: Duration) -> String {
    let s = d.as_secs();
    if s >= 3600 {
        format!("{} ч {} мин", s / 3600, (s % 3600) / 60)
    } else if s >= 60 {
        format!("{} мин {} с", s / 60, s % 60)
    } else {
        format!("{s} с")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn task(mods: &[Module]) -> FuzzTask {
        let mut t = FuzzTask::new(Url::parse("https://contoso.ua/").unwrap(), mods.to_vec());
        t.known_urls = vec![
            "https://contoso.ua/files/report_2023.pdf".into(),
            "https://contoso.ua/index.php".into(),
            "https://other.example/x.pdf".into(),
        ];
        t.current_year = Some(2026);
        t
    }

    #[test]
    fn plan_docs_and_backups() {
        let cfg = FuzzConfig::default();
        let mut sink = JobSink::new(&cfg, None);
        initial_jobs(&task(&[Module::Docs, Module::Backups]), &mut sink, None).unwrap();
        let urls: Vec<String> = sink.jobs.iter().map(|j| j.url.to_string()).collect();
        assert!(urls.contains(&"https://contoso.ua/files/report_2024.pdf".to_string()));
        assert!(urls.contains(&"https://contoso.ua/index.php.bak".to_string()));
        assert!(urls.contains(&"https://contoso.ua/wp-content/uploads/2025/12/".to_string()));
        assert!(!urls.iter().any(|u| u.contains("other.example")));
    }

    #[test]
    fn excluded_paths_and_hosts_not_planned() {
        let cfg = FuzzConfig {
            exclude_paths: vec!["/files".into()],
            ..Default::default()
        };
        let (mut scope, _) = Scope::from_lines("contoso.ua", "dev.contoso.ua");
        scope.active_phase = true;
        let mut t = task(&[Module::Docs, Module::Vhost]);
        t.vhost = Some(VhostSpec {
            domains: vec!["contoso.ua".into()],
            wordlist: Wordlist::from_text("t", "dev\nintranet\n"),
        });
        let mut sink = JobSink::new(&cfg, Some(&scope));
        initial_jobs(&t, &mut sink, None).unwrap();
        assert!(!sink.jobs.iter().any(|j| j.url.path().starts_with("/files")));
        assert!(!sink
            .jobs
            .iter()
            .any(|j| j.host.as_deref() == Some("dev.contoso.ua")));
        assert!(sink
            .jobs
            .iter()
            .any(|j| j.host.as_deref() == Some("intranet.contoso.ua")));
        assert!(sink.skipped_excluded >= 2);
    }

    #[test]
    fn estimate_counts() {
        let cfg = FuzzConfig::default();
        let e = estimate(&task(&[Module::Exposed]), &cfg, None, None).unwrap();
        assert!(e.candidates > 2000);
        assert!(e.calibration > 0);
        assert!(e.requests <= cfg.max_requests);
        assert!(e.seconds > 0);
        assert_eq!(e.per_module.len(), 1);
    }

    #[test]
    fn templates() {
        assert!(Template::path("https://x/FUZZ").validate().is_ok());
        assert!(Template::path("https://x/a").validate().is_err());
        assert!(Template::path("https://x/a?q=FUZZ").validate().is_err());
        let t = Template {
            url: "https://1.2.3.4/".into(),
            host: Some("FUZZ.contoso.ua".into()),
        };
        assert!(t.validate().is_ok());
    }

    #[test]
    fn ctx_keys() {
        let u = Url::parse("https://h/docs/a/report.PDF").unwrap();
        let c = ctx_for(&u, None, Expect::Document);
        assert_eq!((c.dir.as_str(), c.ext.as_str()), ("/docs/a/", ".pdf"));
        let c = ctx_for(
            &Url::parse("https://h/docs/").unwrap(),
            None,
            Expect::Directory,
        );
        assert_eq!((c.dir.as_str(), c.ext.as_str()), ("/", "/"));
        let c = ctx_for(
            &Url::parse("https://h/a/b/c.php").unwrap(),
            None,
            Expect::Exposed,
        );
        assert_eq!(c.dir, "/");
        let c = ctx_for(
            &Url::parse("https://h/.env").unwrap(),
            None,
            Expect::Exposed,
        );
        assert_eq!((c.ext.as_str(), c.dot), ("", true));
        // Dotfiles form their own classes, with and without an extension.
        let c = ctx_for(
            &Url::parse("https://h/.htaccess.bak").unwrap(),
            None,
            Expect::Exposed,
        );
        assert_eq!((c.ext.as_str(), c.dot), (".bak", true));
        let c = ctx_for(
            &Url::parse("https://h/.csv").unwrap(),
            None,
            Expect::Exposed,
        );
        assert_eq!((c.ext.as_str(), c.dot), ("", true));
        let c = ctx_for(
            &Url::parse("https://h/data.csv").unwrap(),
            None,
            Expect::Exposed,
        );
        assert_eq!((c.ext.as_str(), c.dot), (".csv", false));
    }
}
