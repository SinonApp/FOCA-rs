//! Dork groups no engine could run (captcha or block on every engine) are not lost: they are
//! kept per project (facts key [`K_PENDING`]), retried within the same scan after a cool-down
//! (`settings.search.dork_retry_min`, if the scan is still running), and at the next scan, where
//! they are planned first. The retry goes slowly, one group at a time; captchas are never solved.
//! `dorks_retry` runs the retry at once (wakes the waiting in-scan retry, or starts a narrowed
//! scan of the dork engines when no scan runs).

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use foca_search::sources::{DorkBoard, DorkCache, PendingDorks};
use foca_search::{DocumentSource, ExtFilter, SearchCtx};
use foca_store::ProjectDb;
use serde_json::{json, Value};
use tokio::sync::Notify;

use super::Enqueuer;
use crate::engine::{lock, Core, DorkJob};
use crate::scan::*;

/// Facts key of the postponed dork groups of a project.
pub(crate) const K_PENDING: &str = "search.dorks_pending";

/// Keyless dork engines that can take a postponed group.
pub(crate) const RETRY_ENGINES: &[&str] = &[
    "mojeek",
    "ddg",
    "bing",
    "startpage",
    "brave_web",
    "yahoo",
    "searx_pool",
];

pub(crate) fn load(db: &ProjectDb) -> PendingDorks {
    facts::get(db, K_PENDING)
}

fn save(db: &ProjectDb, p: &PendingDorks) -> Result<(), crate::CmdError> {
    facts::put(db, K_PENDING, p)
}

fn now_ms() -> i64 {
    (time::OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000_000) as i64
}

/// Cool-down before the in-scan retry, in minutes (0 turns it off).
pub(super) fn retry_minutes(settings: &Value) -> f64 {
    settings["search"]["dork_retry_min"]
        .as_f64()
        .unwrap_or(15.0)
        .clamp(0.0, 240.0)
}

/// Updates the postponed groups after the search stage and announces the count. Groups count as
/// lost only when an engine met a captcha or block (`captcha_seen`); engines that could not run
/// at all (no WebView in the CLI) postpone nothing. Returns the number of postponed groups.
pub(super) fn after_search(
    c: &Ctx,
    board: &DorkBoard,
    doms: &[String],
    captcha_seen: bool,
) -> Result<usize, Stop> {
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    let n = {
        let db = lock(&c.db);
        let mut p = load(&db);
        for d in doms {
            let lost = if captcha_seen {
                board.lost_groups(d)
            } else {
                Vec::new()
            };
            let dropped = p.update(d, &board.ran_groups(d), &lost, now);
            if dropped > 0 {
                tracing::warn!(target: "foca::scan", "{}: отложенные дорки {d}: {dropped} групп сняты после повторов", c.scan_id);
            }
        }
        save(&db, &p)?;
        p.len()
    };
    lock(&c.st).dorks_pending = n;
    if n > 0 {
        tracing::info!(target: "foca::scan", "{}: отложено групп дорков: {n}", c.scan_id);
    }
    let project = lock(&c.st).project.clone();
    emit_pending(&c.e, &c.scan_id, &project, n, None);
    Ok(n)
}

fn emit_pending(e: &Core, scan_id: &str, project: &str, n: usize, at_ms: Option<i64>) {
    e.emit(
        json!({ "type": "dorks", "scan_id": scan_id, "project": project,
        "pending": n, "retry_at": at_ms }),
    );
}

/// Dork engines for a retry: the keyless dork engines of this scan plus own SearXNG and the
/// Brave API when they are set.
fn retry_engines(c: &Ctx) -> Vec<Box<dyn DocumentSource>> {
    let ids = lock(&c.st).source_ids.clone();
    let keys = c.e.current_keys();
    let ep = &c.e.cfg.endpoints;
    let mut out: Vec<Box<dyn DocumentSource>> = Vec::new();
    if ids.iter().any(|i| i == "searx") && keys.get("searx").is_some() {
        let s =
            foca_search::sources::Searx::new(keys.get("searx")).with_local(super::test_bench(c));
        out.push(Box::new(s));
    }
    if ids.iter().any(|i| i == "brave") && keys.get("brave").is_some() {
        let mut b = foca_search::sources::Brave::new(keys.get("brave"));
        if let Some(base) = ep.sources.get("brave") {
            b = b.with_base(base);
        }
        out.push(Box::new(b));
    }
    for id in RETRY_ENGINES {
        if !ids.iter().any(|i| i == id) {
            continue;
        }
        out.extend(match ep.sources.get(*id) {
            Some(b) => foca_search::sources::url_source_with_base(id, b),
            None => foca_search::sources::url_source(id),
        });
    }
    out
}

/// Starts the in-scan retry: it waits for the cool-down (or `dorks_retry`), then, if the scan is
/// still running, retries the postponed groups of this scan's domains one by one.
pub(super) fn spawn_retry(
    c: &Ctx,
    enq: &Enqueuer,
    known: &Arc<HashSet<String>>,
    filter: ExtFilter,
    minutes: f64,
) {
    let engines = retry_engines(c);
    if engines.is_empty() {
        return;
    }
    let Ok(net) = c.group_net("search") else {
        return;
    };
    let (project, headless, limit, pending) = {
        let st = lock(&c.st);
        (st.project.clone(), st.headless, st.limit, st.dorks_pending)
    };
    let wait = Duration::from_secs_f64(minutes * 60.0);
    let wake = Arc::new(Notify::new());
    let at_ms = now_ms() + wait.as_millis() as i64;
    lock(&c.e.dork_jobs).insert(
        project.clone(),
        DorkJob {
            scan_id: c.scan_id.clone(),
            wake: wake.clone(),
            at_ms,
        },
    );
    emit_pending(&c.e, &c.scan_id, &project, pending, Some(at_ms));
    let gap_s = c.e.store().settings_get().unwrap_or_default()["search"]["dork_retry_gap_s"]
        .as_f64()
        .unwrap_or(45.0)
        .clamp(0.0, 600.0);
    let job = RetryJob {
        e: c.e.clone(),
        project,
        scan_id: c.scan_id.clone(),
        cancel: c.cancel.clone(),
        net,
        render: c.e.current_render(),
        headless,
        domains: c.domains.clone(),
        filter,
        limit,
        known: known.clone(),
        enq: enq.clone(),
        engines,
        gap: Duration::from_secs_f64(gap_s),
    };
    tokio::spawn(async move {
        let (e, project, sid) = (job.e.clone(), job.project.clone(), job.scan_id.clone());
        job.run(wait, wake).await;
        let mut g = lock(&e.dork_jobs);
        if g.get(&project).is_some_and(|j| j.scan_id == sid) {
            g.remove(&project);
        }
    });
}

struct RetryJob {
    e: Arc<Core>,
    project: String,
    scan_id: String,
    cancel: tokio_util::sync::CancellationToken,
    net: foca_net::NetClient,
    render: Option<Arc<dyn foca_search::RenderFetch>>,
    headless: bool,
    domains: Vec<String>,
    filter: ExtFilter,
    limit: usize,
    known: Arc<HashSet<String>>,
    enq: Enqueuer,
    engines: Vec<Box<dyn DocumentSource>>,
    gap: Duration,
}

impl RetryJob {
    fn alive(&self) -> bool {
        !self.cancel.is_cancelled()
            && self.e.active_scan_id().as_deref() == Some(self.scan_id.as_str())
    }

    async fn run(self, wait: Duration, wake: Arc<Notify>) {
        tokio::select! {
            _ = tokio::time::sleep(wait) => {}
            _ = wake.notified() => {}
            _ = self.cancel.cancelled() => return,
        }
        if !self.alive() {
            return;
        }
        let db = self.enq.db().clone();
        let items: Vec<_> = load(&lock(&db))
            .0
            .into_iter()
            .filter(|p| self.domains.contains(&p.domain))
            .collect();
        tracing::info!(target: "foca::scan", "{}: повтор отложенных дорков, групп {}", self.scan_id, items.len());
        let mut found = Vec::new();
        for (i, p) in items.iter().enumerate() {
            if i > 0 && !self.gap.is_zero() {
                tokio::select! {
                    _ = tokio::time::sleep(self.gap) => {}
                    _ = self.cancel.cancelled() => return,
                }
            }
            if !self.alive() {
                break;
            }
            let board = Arc::new(DorkBoard::new(DorkCache::new(Some(
                self.e.cfg.data_dir.join("dork-cache.json"),
            ))));
            board.plan(&p.domain, std::slice::from_ref(&p.exts));
            let mut ctx = SearchCtx::new(self.net.clone());
            ctx.filter = self.filter.clone();
            ctx.limit = self.limit;
            ctx.known = self.known.clone();
            ctx.render = self.render.clone();
            ctx.headless = self.headless;
            ctx.dorks = Some(board.clone());
            for s in &self.engines {
                if !board.ran_groups(&p.domain).is_empty() {
                    break;
                }
                ctx.deadline = Some(std::time::Instant::now() + Duration::from_secs(150));
                match tokio::time::timeout(Duration::from_secs(180), s.find(&ctx, &p.domain)).await
                {
                    Ok(Ok(f)) => found.extend(f.urls),
                    Ok(Err(e)) => {
                        tracing::info!(target: "foca::scan", "{}: повтор дорков {}: {e}", self.scan_id, s.id())
                    }
                    Err(_) => {}
                }
            }
            let now = time::OffsetDateTime::now_utc().unix_timestamp();
            let db = lock(&db);
            let mut pend = load(&db);
            pend.update(
                &p.domain,
                &board.ran_groups(&p.domain),
                &board.lost_groups(&p.domain),
                now,
            );
            let _ = save(&db, &pend);
        }
        let added = self
            .enq
            .enqueue(found, &self.known)
            .map(|d| d.added)
            .unwrap_or(0);
        let n = load(&lock(&db)).len();
        tracing::info!(target: "foca::scan", "{}: повтор дорков завершён: в загрузку {added}, отложено {n}", self.scan_id);
        emit_pending(&self.e, &self.scan_id, &self.project, n, None);
    }
}
