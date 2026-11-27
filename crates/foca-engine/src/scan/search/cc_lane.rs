//! Background lane of the deep Common Crawl sweep. It starts with the search stage and runs
//! beside the rest of the scan within one time budget (`settings.search.cc_minutes`, 5 by
//! default): the search stage ends when the other sources end, documents the sweep finds later
//! go straight to the download queue and are fetched when the next stage starts, and a sweep
//! that is cut short (budget, report stage, stop) continues from its cache in the next scan.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use foca_search::sources::CommonCrawl;
use foca_search::{DocumentSource, SearchCtx, SourceCtl};
use serde_json::Value;
use tokio_util::sync::CancellationToken;

use super::{merge_hosts, running_event, save_hosts, source_done_event, Enqueuer};
use crate::scan::{documents, reanalyze_bg, Ctx, Stop};

/// Default time budget of the deep sweep per scan, in minutes.
pub(crate) const DEFAULT_MINUTES: u64 = 5;
/// How long the report stage lets a running sweep finish before it is cut for the next scan.
const REPORT_GRACE: Duration = Duration::from_secs(10);
/// Source note of a sweep cut at the report stage.
pub(crate) const LEFT_NOTE: &str =
    "глубокий обход Common Crawl не успел до отчёта: остальные снимки продолжатся в следующем скане";

/// A running deep sweep. Dropping it cancels the sweep (finished snapshots stay cached).
pub(crate) struct CcLane {
    cancel: CancellationToken,
    task: Option<tokio::task::JoinHandle<()>>,
    /// Download tasks the lane queued so far.
    queued: Arc<AtomicUsize>,
    /// Of those, the ones a later stage already fetched.
    taken: usize,
}

impl Drop for CcLane {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

/// Starts the sweep over `jobs` (domain, search context, round of the events).
pub(super) fn spawn(
    c: &Ctx,
    cc: CommonCrawl,
    settings: &Value,
    jobs: Vec<(String, SearchCtx, Value)>,
    enq: Enqueuer,
    known: Arc<HashSet<String>>,
) -> CcLane {
    let minutes = settings["search"]["cc_minutes"]
        .as_u64()
        .unwrap_or(DEFAULT_MINUTES)
        .clamp(1, 240);
    let budget = Duration::from_secs(minutes * 60);
    let cancel = c.cancel.child_token();
    let queued = Arc::new(AtomicUsize::new(0));
    let bg = c.detached();
    let (cancel2, queued2) = (cancel.clone(), queued.clone());
    let task = tokio::spawn(async move {
        let run = sweep(&bg, cc, jobs, budget, &cancel2, &enq, &known, &queued2);
        tokio::select! {
            _ = run => {}
            _ = cancel2.cancelled() => {}
        }
    });
    CcLane {
        cancel,
        task: Some(task),
        queued,
        taken: 0,
    }
}

#[allow(clippy::too_many_arguments)]
async fn sweep(
    c: &Ctx,
    cc: CommonCrawl,
    jobs: Vec<(String, SearchCtx, Value)>,
    budget: Duration,
    cancel: &CancellationToken,
    enq: &Enqueuer,
    known: &HashSet<String>,
    queued: &AtomicUsize,
) {
    let deadline = Instant::now() + budget;
    let n = jobs.len().max(1);
    let one: [Box<dyn DocumentSource>; 1] = [Box::new(cc)];
    for (k, (d, mut ctx, round)) in jobs.into_iter().enumerate() {
        let left = deadline.saturating_duration_since(Instant::now());
        if left < Duration::from_secs(6) {
            tracing::info!(target: "foca::scan", "{}: Common Crawl: бюджет {} с исчерпан, {d} продолжится в следующем скане", c.scan_id, budget.as_secs());
            break;
        }
        // the lane has its own cancellation (a child of the scan's), and keeps the scan pause
        ctx.net = ctx.net.with_cancel(cancel.clone());
        // the domains left share the rest of the budget (a deep sweep has a budget factor of 10)
        let ctl = SourceCtl {
            timeout: (left / (n - k) as u32 / 10).max(Duration::from_secs(1)),
            skip: c.skip.clone(),
            parallel: 1,
        };
        let res = foca_search::run_sources_ctl(
            &one,
            &ctx,
            &d,
            &ctl,
            |id, t| running_event(c, id, t, &round),
            |r| source_done_event(c, r, &round),
        )
        .await;
        let Ok(r) = res else {
            break;
        };
        let (mut hosts, mut src) = (BTreeSet::new(), BTreeMap::new());
        merge_hosts(&mut hosts, &mut src, &r);
        if save_hosts(c, hosts, src).is_err() {
            tracing::warn!(target: "foca::scan", "{}: Common Crawl {d}: хосты не сохранены", c.scan_id);
        }
        match enq.enqueue(r.urls, known) {
            Ok(q) => {
                queued.fetch_add(q.added, Ordering::SeqCst);
                tracing::info!(target: "foca::scan", "{}: Common Crawl {d}: в загрузку {} из {}", c.scan_id, q.added, q.found);
            }
            Err(_) => {
                tracing::warn!(target: "foca::scan", "{}: Common Crawl {d}: очередь недоступна", c.scan_id)
            }
        }
    }
}

impl CcLane {
    /// Lets the sweep finish within a short grace, then cancels it. Returns `true` when it had
    /// to be cut (its finished snapshots stay cached for the next scan).
    async fn stop(&mut self) -> bool {
        let Some(mut t) = self.task.take() else {
            return false;
        };
        if tokio::time::timeout(REPORT_GRACE, &mut t).await.is_ok() {
            return false;
        }
        self.cancel.cancel();
        let _ = tokio::time::timeout(Duration::from_secs(10), t).await;
        true
    }

    /// Takes the tasks queued since the last call; `true` when there are new ones.
    fn take_new(&mut self) -> bool {
        let n = self.queued.load(Ordering::SeqCst);
        let fresh = n > self.taken;
        self.taken = n;
        fresh
    }
}

/// At the start of stage `stage` (after the download stage): documents the lane queued since
/// the last check are downloaded now, parsed when the metadata stage is over and analysed when
/// the analysis stage is over. The report stage (`last`) stops the lane first.
pub(crate) async fn catch_up(c: &mut Ctx, stage: usize, last: bool) -> Result<(), Stop> {
    let Some(lane) = c.cc_lane.as_mut() else {
        return Ok(());
    };
    if last && lane.stop().await {
        c.source_event_x("cc", "timeout", None, Some(LEFT_NOTE), Value::Null);
    }
    let Some(lane) = c.cc_lane.as_mut() else {
        return Ok(());
    };
    let fresh = lane.take_new();
    if last {
        c.cc_lane = None;
    }
    if !fresh {
        return Ok(());
    }
    tracing::info!(target: "foca::scan", "{}: документы Common Crawl после этапа поиска: загрузка", c.scan_id);
    documents::download_queue(c, stage).await?;
    if stage > 2 {
        documents::meta_pending(c, stage).await?;
    }
    if stage > 3 {
        let new = reanalyze_bg(c).await?;
        c.findings_events(&new);
    }
    Ok(())
}
