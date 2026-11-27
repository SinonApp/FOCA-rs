//! Hosts of one stage worked on at once (`settings.net.hosts_parallel`, 1 to 8, default 4).
//!
//! * A bounded pool of host workers polled on the stage's own task (`buffer_unordered`): no
//!   spawned tasks, so a phone never holds more than N hosts in flight. `1` keeps the old
//!   one-by-one order.
//! * Limits stay where they were: the shared `NetClient` (global requests per second, concurrent
//!   requests, scope and the passive guard) and each tool's own per-host limits.
//! * Every worker passes the stage checkpoint before it starts a host, so pause, stop and the
//!   stage Skip/Restart reach workers that have not started yet; running workers watch the same
//!   flags themselves.
//! * The `hosts` sub-step tells the UI which hosts run now: `running` (names), `done` of `total`.

use std::collections::BTreeMap;
use std::future::Future;
use std::sync::Mutex;

use futures_util::stream::{self, StreamExt};
use serde_json::{json, Value};

use super::{Ctx, Stop};
use crate::engine::lock;

/// Hosts worked on at once when the setting is missing.
pub(crate) const PARALLEL_DEFAULT: u64 = 4;

/// Hosts worked on at once per `settings` (`net.hosts_parallel`). Any value from 1 up is
/// honoured (the UI warns above its recommended range); 0 means one host at a time. Workers
/// are started lazily, so a big number never preallocates anything.
pub(crate) fn parallel_of(settings: &Value) -> usize {
    let n = settings["net"]["hosts_parallel"]
        .as_u64()
        .unwrap_or(PARALLEL_DEFAULT)
        .max(1);
    usize::try_from(n).unwrap_or(usize::MAX)
}

/// Hosts of a running stage: which run now, how many are done, and each one's own progress.
pub(crate) struct HostBoard {
    total: usize,
    state: Mutex<BoardState>,
}

struct BoardState {
    running: BTreeMap<usize, String>,
    done: usize,
    frac: Vec<f64>,
}

impl HostBoard {
    /// Share of the stage's hosts done, running ones counted by their own progress.
    pub(crate) fn fraction(&self) -> f64 {
        if self.total == 0 {
            return 1.0;
        }
        let st = lock(&self.state);
        st.frac.iter().sum::<f64>() / self.total as f64
    }

    /// Records the own progress (0 to 1) of host `i`.
    pub(crate) fn set_progress(&self, i: usize, frac: f64) {
        if let Some(f) = lock(&self.state).frac.get_mut(i) {
            *f = frac.clamp(0.0, 1.0);
        }
    }

    fn view(&self) -> (usize, Value) {
        let st = lock(&self.state);
        let running: Vec<&String> = st.running.values().collect();
        (st.done, json!({ "running": running }))
    }
}

impl Ctx {
    /// Hosts worked on at once (`settings.net.hosts_parallel`).
    pub(crate) fn hosts_parallel(&self) -> usize {
        parallel_of(&self.e.store().settings_get().unwrap_or_default())
    }

    /// Starts the `hosts` sub-step of the current stage for `total` hosts.
    pub(crate) fn host_board(&self, total: usize) -> HostBoard {
        tracing::info!(target: "foca::scan", "{}: хостов {total}, одновременно до {}", self.scan_id, self.hosts_parallel());
        let b = HostBoard {
            total,
            state: Mutex::new(BoardState {
                running: BTreeMap::new(),
                done: 0,
                frac: vec![0.0; total],
            }),
        };
        self.board_event(&b, "running");
        b
    }

    /// Ends the `hosts` sub-step (`state`: `done` | `skipped`).
    pub(crate) fn host_board_end(&self, b: HostBoard, state: &str) {
        self.board_event(&b, state);
    }

    fn board_event(&self, b: &HostBoard, state: &str) {
        let (done, extra) = b.view();
        self.substep_event("hosts", state, done, b.total, extra);
    }

    /// Runs `work(i, item)` for every host, at most [`Ctx::hosts_parallel`] at once. Each worker
    /// first passes the stage checkpoint (pause, stop, stage Skip/Restart), then shows up in
    /// `running` until it returns. Results come back in input order whatever order the hosts
    /// finished in; the first error drops the other workers and is returned.
    pub(crate) async fn each_host<T, R, F, Fut>(
        &self,
        board: &HostBoard,
        items: Vec<(String, T)>,
        work: F,
    ) -> Result<Vec<R>, Stop>
    where
        F: Fn(usize, T) -> Fut,
        Fut: Future<Output = Result<R, Stop>>,
    {
        let par = self.hosts_parallel();
        let work = &work;
        let mut runs = stream::iter(items.into_iter().enumerate())
            .map(|(i, (name, item))| async move {
                self.gate().await?;
                lock(&board.state).running.insert(i, name);
                self.board_event(board, "running");
                let r = work(i, item).await;
                {
                    let mut st = lock(&board.state);
                    st.running.remove(&i);
                    st.done += 1;
                    if let Some(f) = st.frac.get_mut(i) {
                        *f = 1.0;
                    }
                }
                self.board_event(board, "running");
                r.map(|r| (i, r))
            })
            .buffer_unordered(par);
        let mut out = Vec::new();
        while let Some(r) = runs.next().await {
            out.push(r?);
        }
        out.sort_by_key(|x| x.0);
        Ok(out.into_iter().map(|x| x.1).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parallel_setting_is_honoured_from_one_up() {
        assert_eq!(parallel_of(&json!({})), 4);
        assert_eq!(parallel_of(&json!({ "net": { "hosts_parallel": 1 } })), 1);
        assert_eq!(parallel_of(&json!({ "net": { "hosts_parallel": 0 } })), 1);
        assert_eq!(parallel_of(&json!({ "net": { "hosts_parallel": 50 } })), 50);
    }

    #[test]
    fn board_fraction_counts_running_hosts() {
        let b = HostBoard {
            total: 4,
            state: Mutex::new(BoardState {
                running: BTreeMap::new(),
                done: 0,
                frac: vec![1.0, 0.5, 0.0, 0.0],
            }),
        };
        assert!((b.fraction() - 0.375).abs() < 1e-9);
        b.set_progress(2, 2.0);
        assert!((b.fraction() - 0.625).abs() < 1e-9);
    }
}
