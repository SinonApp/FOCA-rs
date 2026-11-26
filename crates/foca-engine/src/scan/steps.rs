//! Sub-step progress of long stages (network: DNS summary, name resolution, takeover checks,
//! brute force, permutations, RDAP, liveness, TLS): a `substep` event with `done`/`total`,
//! info-level log lines at the start and end of each sub-step, and the current sub-step in
//! `scan_status.substep`.

use std::future::Future;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};

use foca_net::bruteforce::Progress;
use serde_json::{json, Value};

use super::{Ctx, STAGES};
use crate::engine::lock;

/// Interval of live counters while a resolver pass runs.
const TICK: Duration = Duration::from_millis(1500);
/// Share of failed resolver queries (timeouts, SERVFAIL) from which the resolver counts as slow.
const SLOW_RATIO: f64 = 0.2;
/// Queries sent before the pace is judged.
const SLOW_MIN_QUERIES: usize = 30;
/// Time left from which a slow resolver raises the `dns.slow` warning.
const SLOW_WARN_ETA_S: u64 = 60;

/// Pace of a resolver pass: seconds left (once enough names are answered) and the slow flag.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct ResolverPace {
    pub eta_s: Option<u64>,
    pub slow: bool,
}

impl ResolverPace {
    pub(crate) fn of(done: usize, total: usize, failed: usize, elapsed: Duration) -> ResolverPace {
        let secs = elapsed.as_secs_f64();
        let eta_s = (done >= 10 && secs > 0.0).then(|| {
            let rate = done as f64 / secs;
            (total.saturating_sub(done) as f64 / rate).ceil() as u64
        });
        let sent = done + failed;
        let slow = sent >= SLOW_MIN_QUERIES && failed as f64 / sent as f64 >= SLOW_RATIO;
        ResolverPace { eta_s, slow }
    }
}

/// Reason of a subdomain pass skipped because the domain is in scope only as a URL target.
pub(crate) fn url_target_note(domain: &str) -> String {
    format!("пропущено: цель задана как URL ({domain}), поддомены вне скоупа")
}

/// A running sub-step: id, start time and planned item count.
pub(crate) struct SubStep {
    pub id: &'static str,
    t0: Instant,
    pub total: usize,
    last: Option<Instant>,
}

impl Ctx {
    fn substep_event(&self, id: &str, state: &str, done: usize, total: usize, extra: Value) {
        let ev = {
            let mut st = lock(&self.st);
            let stage = STAGES[st.stage.min(STAGES.len() - 1)].0;
            let mut ev = json!({ "type": "substep", "scan_id": self.scan_id, "stage": stage,
                "id": id, "state": state, "done": done, "total": total, "eta_s": null, "slow": false });
            if let (Some(o), Value::Object(x)) = (ev.as_object_mut(), extra) {
                o.extend(x);
            }
            let mut cur = ev.clone();
            if let Some(o) = cur.as_object_mut() {
                o.remove("type");
                o.remove("scan_id");
            }
            st.substep = (state == "running").then_some(cur);
            ev
        };
        self.e.emit(ev);
    }

    /// Starts a sub-step of `total` items: `substep` event and an info log line.
    pub(crate) fn sub_begin(&self, id: &'static str, total: usize) -> SubStep {
        tracing::info!(target: "foca::scan", "{}: шаг «{id}», старт, элементов: {total}", self.scan_id);
        self.substep_event(id, "running", 0, total, Value::Null);
        SubStep {
            id,
            t0: Instant::now(),
            total,
            last: None,
        }
    }

    /// Live counter of a running sub-step (`extra`: `eta_s`, `slow`); at most one event per
    /// second unless the count is complete.
    pub(crate) fn sub_tick(&self, s: &mut SubStep, done: usize, total: usize, extra: Value) {
        s.total = total;
        if done < total && s.last.is_some_and(|t| t.elapsed() < Duration::from_secs(1)) {
            return;
        }
        s.last = Some(Instant::now());
        self.substep_event(s.id, "running", done, total, extra);
    }

    /// Ends a sub-step (`state`: `done` | `skipped`) with its counters and duration in the log.
    pub(crate) fn sub_end(&self, s: SubStep, done: usize, state: &str, note: &str) {
        let ms = s.t0.elapsed().as_millis();
        let note = if note.is_empty() {
            String::new()
        } else {
            format!(", {note}")
        };
        tracing::info!(target: "foca::scan", "{}: шаг «{}», {state}: {done}/{} за {ms} мс{note}",
            self.scan_id, s.id, s.total);
        self.substep_event(s.id, state, done, s.total, Value::Null);
    }

    /// Reports a sub-step that does not run at all, with the reason (`reason` text plus a
    /// `reason_msg` code for the UI language).
    pub(crate) fn sub_skip(&self, id: &'static str, reason: &str) {
        tracing::info!(target: "foca::scan", "{}: шаг «{id}», {reason}", self.scan_id);
        let mut extra = json!({ "reason": reason });
        crate::services::i18n::annotate(&mut extra, &["reason"]);
        self.substep_event(id, "skipped", 0, 0, extra);
    }

    /// Reports a finished sub-step of the current stage with a summary (`reason` text plus a
    /// `reason_msg` code), e.g. why found documents did not reach the download queue.
    pub(crate) fn sub_note(&self, id: &'static str, done: usize, total: usize, note: &str) {
        let mut extra = json!({ "reason": note });
        crate::services::i18n::annotate(&mut extra, &["reason"]);
        self.substep_event(id, "done", done, total, extra);
    }

    /// Runs a resolver pass (`fut`) while reporting `progress` counters every [`TICK`]: an ETA,
    /// a slow-resolver flag (one `dns.slow` warning per scan) and the user's skip of this step
    /// (or of the whole subdomain source), which ends the pass early with the names found so far.
    pub(crate) async fn tracked<F: Future>(
        &self,
        s: &mut SubStep,
        progress: &Arc<Progress>,
        fut: F,
    ) -> F::Output {
        let t0 = Instant::now();
        progress.stop.store(false, Ordering::Relaxed);
        tokio::pin!(fut);
        loop {
            tokio::select! {
                r = &mut fut => return r,
                _ = tokio::time::sleep(TICK) => {
                    // a global pause or the user's hold of this step, its source or the stage also
                    // holds the resolver workers
                    let held = self.is_held(&[
                        format!("step:{}", s.id),
                        format!("source:{}", super::SRC_SUBDOMAINS),
                        "stage:network".to_string(),
                    ]);
                    progress
                        .pause
                        .store(self.pause.borrow().is_some() || held, Ordering::Relaxed);
                    let stage_cut = lock(&self.skip)
                        .contains(&format!("{}network", super::control::SKIP_STAGE));
                    if self.step_skipped(s.id) || self.restart_asked("step", s.id) || stage_cut {
                        progress.stop.store(true, Ordering::Relaxed);
                    }
                    let (done, total, failed) = progress.snapshot();
                    let pace = ResolverPace::of(done, total, failed, t0.elapsed());
                    if pace.slow && pace.eta_s.is_some_and(|e| e >= SLOW_WARN_ETA_S) {
                        self.warn_slow_dns(pace.eta_s.unwrap_or(0));
                    }
                    self.sub_tick(s, done, total, json!({ "eta_s": pace.eta_s, "slow": pace.slow }));
                }
            }
        }
    }

    /// The user skipped this resolver step (`scan_skip_source { id: "brute" | "permute" }`) or the
    /// whole subdomain enumeration.
    pub(crate) fn step_skipped(&self, id: &str) -> bool {
        let sk = lock(&self.skip);
        sk.contains(id) || sk.contains(super::SRC_SUBDOMAINS)
    }

    fn warn_slow_dns(&self, eta_s: u64) {
        let have: Vec<Value> =
            crate::analysis::facts::get(&lock(&self.db), &super::warn_key(&self.scan_id));
        if have.iter().any(|w| w["code"] == "dns.slow") {
            return;
        }
        let min = eta_s.div_ceil(60).max(1);
        self.warn(
            "dns.slow",
            &format!("DNS медленный (VPN?): перебор займёт ~{min} мин"),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pace_flags_a_resolver_that_times_out() {
        let p = ResolverPace::of(100, 1500, 60, Duration::from_secs(50));
        assert!(p.slow);
        assert_eq!(p.eta_s, Some(700));
        let fast = ResolverPace::of(1000, 1500, 3, Duration::from_secs(5));
        assert!(!fast.slow);
        assert_eq!(fast.eta_s, Some(3));
        // too few answers to judge
        assert_eq!(
            ResolverPace::of(5, 1500, 20, Duration::from_secs(5)).eta_s,
            None
        );
        assert!(!ResolverPace::of(5, 1500, 5, Duration::from_secs(5)).slow);
    }
}
