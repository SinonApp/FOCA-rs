//! Scan queue: several projects scanned one after another in the background with a
//! shared pause, overall progress and continuation after a process restart.
//!
//! * The queue lives in `<data>/scan_queue.json` (no database): items `{ id, project, name,
//!   profile, args, status, scan_id, … }`, the `paused` flag and its reason. Writes are atomic
//!   (tmp + rename).
//! * A driver task starts the next `pending` item through the regular `scan_start` (the same scope
//!   checks, journal and history), waits for it to end and reads the outcome from the project's
//!   scan history. Only one scan runs at a time: while any other scan runs (a manual one, a
//!   scheduled monitoring rescan, an auto-resumed one) the driver waits, and a `busy` answer
//!   from `scan_start` is retried.
//! * Outcomes: `done` → next item; `stopped/error` → the item is marked `error`, the queue goes on;
//!   any other stop (the user, VPN, battery, budget…) → the item is `stopped` and the queue pauses
//!   with that reason, so stopping the current scan never silently starts the next one;
//!   `stopped/restart` (the process was unloaded) → the same scan is resumed with
//!   `resume_from` (`auto: true`), guarded by the auto-resume setting and attempt counter.
//! * Progress: the event `{ type: "queue", … }` on the scan event channel with the current item,
//!   its index, the scan progress and the overall percentage.

use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::engine::{lock, Core};
use crate::util::arg_str;
use crate::{CmdError, CmdResult, Engine};

const FILE: &str = "scan_queue.json";
/// Items kept in the queue (finished ones included).
const MAX_ITEMS: usize = 100;
/// Driver poll interval.
const TICK: Duration = Duration::from_millis(250);

/// One queued scan.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub(crate) struct QueueItem {
    pub id: String,
    pub project: String,
    /// Project name at the time it was queued (for the UI without extra lookups).
    pub name: String,
    pub profile: String,
    /// Extra `scan_start` arguments (wizard fields), without `project`/`resume_from`.
    pub args: Value,
    /// `pending` | `running` | `done` | `stopped` | `error`.
    pub status: String,
    pub scan_id: Option<String>,
    pub progress: u8,
    /// Stop reason (`stopped`) of the scan.
    pub reason: Option<String>,
    pub error: Option<String>,
    pub added_at: String,
    pub started_at: Option<String>,
    pub finished_at: Option<String>,
}

/// The queue file.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub(crate) struct QueueState {
    pub items: Vec<QueueItem>,
    pub paused: bool,
    /// `user` (queue_pause), `restart` (auto-resume is off), `restart_loop`, or the stop reason
    /// of the item that paused the queue (`user`, `vpn`, `battery`, …).
    pub pause_reason: Option<String>,
    pub seq: u64,
}

impl QueueState {
    fn finished(s: &str) -> bool {
        matches!(s, "done" | "stopped" | "error")
    }
}

fn bad_args(m: impl Into<String>) -> CmdError {
    CmdError::new("bad_args", m)
}

/// Clears `Core::queue_driver` when the driver task ends (also on panic).
struct DriverGuard(Arc<Core>);

impl Drop for DriverGuard {
    fn drop(&mut self) {
        self.0.queue_driver.store(false, Ordering::SeqCst);
    }
}

impl Engine {
    fn queue_file(&self) -> std::path::PathBuf {
        self.inner.cfg.data_dir.join(FILE)
    }

    pub(crate) fn queue_load(&self) -> QueueState {
        std::fs::read(self.queue_file())
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default()
    }

    fn queue_save(&self, st: &QueueState) -> Result<(), CmdError> {
        let f = self.queue_file();
        if st.items.is_empty() && !st.paused {
            let _ = std::fs::remove_file(&f);
            return Ok(());
        }
        let tmp = f.with_extension("json.tmp");
        std::fs::write(&tmp, serde_json::to_vec(st)?)?;
        std::fs::rename(&tmp, &f)?;
        Ok(())
    }

    /// Loads, changes and saves the queue under the queue lock; returns the closure's result.
    fn queue_edit<T>(
        &self,
        f: impl FnOnce(&mut QueueState) -> Result<T, CmdError>,
    ) -> Result<T, CmdError> {
        let _g = lock(&self.inner.queue_lock);
        let mut st = self.queue_load();
        let r = f(&mut st)?;
        self.queue_save(&st)?;
        Ok(r)
    }

    /// Drops the queue file (`wipe_all`).
    pub(crate) fn queue_wipe(&self) {
        let _g = lock(&self.inner.queue_lock);
        let _ = std::fs::remove_file(self.queue_file());
    }

    /// The queue view (`queue_list`, the `queue` event).
    pub(crate) fn queue_view(&self, st: &QueueState) -> Value {
        let total = st.items.len();
        let done = st
            .items
            .iter()
            .filter(|i| QueueState::finished(&i.status))
            .count();
        let cur = st.items.iter().position(|i| i.status == "running");
        // live progress of the running item (never regress to 0 during async finish())
        let live = cur.and_then(|i| {
            let it = &st.items[i];
            let s = self.scan_status(Some(&it.project));
            (s["scan_id"].as_str() == it.scan_id.as_deref())
                .then(|| s["progress"].as_u64().unwrap_or(0) as u8)
        });
        let cur_progress = match cur {
            Some(i) => {
                let it = &st.items[i];
                let mut hwm = lock(&self.inner.queue_progress);
                if let Some(sid) = it.scan_id.as_deref() {
                    let prev = hwm
                        .as_ref()
                        .and_then(|(s, p)| (s == sid).then_some(*p))
                        .unwrap_or(it.progress);
                    let next = live.map_or(prev, |p| prev.max(p));
                    *hwm = Some((sid.to_string(), next));
                    next
                } else {
                    live.unwrap_or(it.progress)
                }
            }
            None => 0,
        };
        let percent = (done * 100 + cur_progress as usize)
            .checked_div(total)
            .unwrap_or(0)
            .min(100);
        let pending = st.items.iter().filter(|i| i.status == "pending").count();
        let waiting = !st.paused
            && cur.is_none()
            && pending > 0
            && self.is_scanning()
            && self.inner.queue_driver.load(Ordering::SeqCst);
        let items: Vec<Value> = st
            .items
            .iter()
            .enumerate()
            .map(|(i, it)| {
                let progress = if Some(i) == cur {
                    cur_progress
                } else if it.status == "done" {
                    100
                } else {
                    it.progress
                };
                json!({ "id": it.id, "project": it.project, "name": it.name, "profile": it.profile,
                    "status": it.status, "scan_id": it.scan_id, "progress": progress,
                    "reason": it.reason, "error": it.error, "added_at": it.added_at,
                    "started_at": it.started_at, "finished_at": it.finished_at })
            })
            .collect();
        let current = cur.map(|i| {
            let it = &st.items[i];
            json!({ "id": it.id, "project": it.project, "name": it.name, "index": i,
                "scan_id": it.scan_id, "progress": cur_progress })
        });
        json!({
            "items": items,
            "total": total,
            "done": done,
            "pending": pending,
            "index": cur.unwrap_or(done.min(total.saturating_sub(1))),
            "current": current,
            "percent": percent,
            "paused": st.paused,
            "pause_reason": st.pause_reason,
            "running": cur.is_some(),
            "waiting": waiting,
        })
    }

    fn queue_emit(&self, st: &QueueState) {
        let mut v = self.queue_view(st);
        v["type"] = json!("queue");
        self.emit(v);
    }

    /// Starts the driver if the queue has work, is not paused and no driver runs. Needs a tokio
    /// runtime (no-op outside one, e.g. in a synchronous `Engine::open` caller).
    pub(crate) fn queue_kick(&self, delay: Duration) {
        if self.is_headless() || self.inner.queue_halt.load(Ordering::SeqCst) {
            return; // a headless monitoring process never drives the queue
        }
        let st = self.queue_load();
        let running = st.items.iter().any(|i| i.status == "running");
        let pending = st.items.iter().any(|i| i.status == "pending");
        if !running && (st.paused || !pending) {
            return;
        }
        let Ok(rt) = tokio::runtime::Handle::try_current() else {
            return;
        };
        if self.inner.queue_driver.swap(true, Ordering::SeqCst) {
            return;
        }
        let me = self.clone();
        rt.spawn(async move {
            let _g = DriverGuard(me.inner.clone());
            if !delay.is_zero() {
                tokio::time::sleep(delay).await;
            }
            me.queue_drive().await;
        });
    }

    /// Outcome of a finished scan from the project history: `(status, reason)`.
    fn scan_outcome(&self, project: &str, scan_id: &str) -> Option<(String, Option<String>)> {
        let db = self.db(project).ok()?;
        let scans = lock(&db).scans().ok()?;
        let s = scans.into_iter().find(|s| s.id == scan_id)?;
        Some((s.status, s.reason))
    }

    async fn queue_drive(&self) {
        let mut last_emit = Value::Null;
        loop {
            if self.inner.queue_halt.load(Ordering::SeqCst) {
                return;
            }
            let st = self.queue_load();
            // a running item is followed to its end even while the queue is paused
            if let Some(it) = st.items.iter().find(|i| i.status == "running").cloned() {
                let Some(sid) = it.scan_id.clone() else {
                    let _ = self.queue_set(&it.id, |i| i.status = "pending".into());
                    continue;
                };
                if self.active_scan_id().as_deref() == Some(sid.as_str()) {
                    // ours: report monotonic progress
                    let v = self.queue_view(&st);
                    if v != last_emit {
                        let mut ev = v.clone();
                        ev["type"] = json!("queue");
                        self.emit(ev);
                        last_emit = v;
                    }
                    tokio::time::sleep(TICK).await;
                    continue;
                }
                if self.is_scanning() {
                    // finishing async tail (alerts/history write): wait without emitting a reset
                    tokio::time::sleep(TICK).await;
                    continue;
                }
                self.queue_settle(&it, &sid).await;
                continue;
            }
            if st.paused {
                self.queue_emit(&st);
                return;
            }
            let Some(next) = st.items.iter().find(|i| i.status == "pending").cloned() else {
                // nothing left: the final state
                self.queue_emit(&st);
                return;
            };
            if self.is_scanning() {
                // another scan (manual, monitoring) runs: wait for it, never start a second one
                let v = self.queue_view(&st);
                if v != last_emit {
                    let mut ev = v.clone();
                    ev["type"] = json!("queue");
                    self.emit(ev);
                    last_emit = v;
                }
                tokio::time::sleep(TICK).await;
                continue;
            }
            let mut args = if next.args.is_object() {
                next.args.clone()
            } else {
                json!({})
            };
            args["project"] = json!(next.project);
            args["profile"] = json!(next.profile);
            match self.scan_start(&args).await {
                Ok(v) => {
                    let sid = v["scan_id"].as_str().unwrap_or("").to_string();
                    let now = self.now_iso();
                    let _ = self.queue_set(&next.id, |i| {
                        i.status = "running".into();
                        i.scan_id = Some(sid.clone());
                        i.started_at = Some(now.clone());
                        i.progress = 0;
                    });
                    tracing::info!(target: "foca::queue", "очередь: старт {} ({})", next.project, sid);
                    self.queue_emit(&self.queue_load());
                }
                Err(e) if e.code == "busy" => tokio::time::sleep(TICK).await,
                Err(e) => {
                    tracing::warn!(target: "foca::queue", "очередь: {} не запущен: {}", next.project, e);
                    let now = self.now_iso();
                    let _ = self.queue_set(&next.id, |i| {
                        i.status = "error".into();
                        i.error = Some(e.message.clone());
                        i.finished_at = Some(now.clone());
                    });
                    self.queue_emit(&self.queue_load());
                }
            }
        }
    }

    /// The running item's scan is over: read the outcome and move on.
    async fn queue_settle(&self, it: &QueueItem, sid: &str) {
        let now = self.now_iso();
        match self.scan_outcome(&it.project, sid) {
            Some((s, _)) if s == "done" => {
                let _ = self.queue_set(&it.id, |i| {
                    i.status = "done".into();
                    i.progress = 100;
                    i.finished_at = Some(now.clone());
                });
            }
            Some((s, Some(r))) if s == "stopped" && r == "restart" => {
                // the process was unloaded mid-scan: continue the same scan
                let settings = self.store().settings_get().unwrap_or_default();
                let now_ms = (self.now().unix_timestamp_nanos() / 1_000_000) as i64;
                let attempt =
                    crate::services::resume::note_attempt(&self.inner.cfg.data_dir, sid, now_ms);
                if !crate::services::resume::enabled(&settings)
                    || attempt > crate::services::resume::MAX_ATTEMPTS
                {
                    let why = if attempt > crate::services::resume::MAX_ATTEMPTS {
                        "restart_loop"
                    } else {
                        "restart"
                    };
                    let _ = self.queue_edit(|q| {
                        q.paused = true;
                        q.pause_reason = Some(why.into());
                        if let Some(i) = q.items.iter_mut().find(|i| i.id == it.id) {
                            i.status = "stopped".into();
                            i.reason = Some("restart".into());
                            i.finished_at = Some(now.clone());
                        }
                        Ok(())
                    });
                    return;
                }
                let mut args = if it.args.is_object() {
                    it.args.clone()
                } else {
                    json!({})
                };
                args["project"] = json!(it.project);
                args["profile"] = json!(it.profile);
                args["resume_from"] = json!(sid);
                args["auto"] = json!(true);
                match self.scan_start(&args).await {
                    Ok(_) => {
                        tracing::info!(target: "foca::queue", "очередь: продолжение {sid} после перезапуска")
                    }
                    Err(e) if e.code == "busy" => tokio::time::sleep(TICK).await,
                    Err(e) => {
                        let _ = self.queue_set(&it.id, |i| {
                            i.status = "error".into();
                            i.error = Some(e.message.clone());
                            i.finished_at = Some(now.clone());
                        });
                    }
                }
            }
            Some((s, r)) if s == "stopped" && r.as_deref() == Some("error") => {
                let _ = self.queue_set(&it.id, |i| {
                    i.status = "error".into();
                    i.reason = r.clone();
                    i.error = Some("скан завершился с ошибкой".into());
                    i.finished_at = Some(now.clone());
                });
            }
            Some((s, r)) if s == "stopped" => {
                // stopped by the user or the environment: stop the queue too
                let reason = r.unwrap_or_else(|| "user".into());
                let progress = self
                    .db(&it.project)
                    .ok()
                    .map(|db| {
                        let v: Value = crate::analysis::facts::get(
                            &lock(&db),
                            &crate::analysis::facts::scan_key(sid),
                        );
                        v["progress"].as_u64().unwrap_or(0) as u8
                    })
                    .unwrap_or(0);
                let _ = self.queue_edit(|q| {
                    if reason != "queue" {
                        q.paused = true;
                        q.pause_reason = Some(reason.clone());
                    }
                    if let Some(i) = q.items.iter_mut().find(|i| i.id == it.id) {
                        i.status = "stopped".into();
                        i.reason = Some(reason.clone());
                        i.progress = progress;
                        i.finished_at = Some(now.clone());
                    }
                    Ok(())
                });
            }
            _ => {
                // the record is gone (project deleted) or the scan never reached the history
                let _ = self.queue_set(&it.id, |i| {
                    i.status = "error".into();
                    i.error = Some("запись скана не найдена".into());
                    i.finished_at = Some(now.clone());
                });
            }
        }
        self.queue_emit(&self.queue_load());
    }

    /// Drops the queue rows of a deleted scan. A running row pauses the queue, as a user stop
    /// would, so the next project does not start right after the deletion.
    pub(crate) fn queue_forget_scan(&self, scan_id: &str) {
        let _ = self.queue_edit(|q| {
            let was_running = q
                .items
                .iter()
                .any(|i| i.scan_id.as_deref() == Some(scan_id) && i.status == "running");
            q.items.retain(|i| i.scan_id.as_deref() != Some(scan_id));
            if was_running {
                q.paused = true;
                q.pause_reason = Some("user".into());
            }
            Ok(())
        });
    }

    fn queue_set(&self, id: &str, f: impl FnOnce(&mut QueueItem)) -> Result<(), CmdError> {
        self.queue_edit(|q| {
            if let Some(i) = q.items.iter_mut().find(|i| i.id == id) {
                f(i);
            }
            Ok(())
        })
    }

    /// `queue_add { projects: string[] | project, profile?, args? }`.
    pub(crate) fn queue_add(&self, a: &Value) -> CmdResult {
        let ids: Vec<String> = match a.get("projects").and_then(Value::as_array) {
            Some(v) => v
                .iter()
                .filter_map(|x| x.as_str().map(String::from))
                .collect(),
            None => arg_str(a, "project")
                .map(|p| vec![p.to_string()])
                .unwrap_or_default(),
        };
        if ids.is_empty() {
            return Err(bad_args("нужен список projects"));
        }
        let profile = crate::scan::profile_id(arg_str(a, "profile").unwrap_or("std")).to_string();
        let mut extra = a.get("args").cloned().unwrap_or_else(|| json!({}));
        if !extra.is_object() {
            return Err(bad_args("args: нужен объект"));
        }
        if let Some(o) = extra.as_object_mut() {
            for k in ["project", "id", "resume_from", "auto", "trigger", "profile"] {
                o.remove(k);
            }
        }
        let names: std::collections::HashMap<String, String> = self
            .store()
            .list_projects()?
            .into_iter()
            .map(|p| (p.id, p.name))
            .collect();
        for id in &ids {
            if !names.contains_key(id) {
                return Err(CmdError::not_found(format!("Проект {id} не найден")));
            }
        }
        let now = self.now_iso();
        let (added, skipped) = self.queue_edit(|q| {
            let mut added = Vec::new();
            let mut skipped = Vec::new();
            for id in &ids {
                // a project already waiting or running is not queued twice
                if q.items
                    .iter()
                    .any(|i| &i.project == id && matches!(i.status.as_str(), "pending" | "running"))
                {
                    skipped.push(id.clone());
                    continue;
                }
                q.seq += 1;
                let item_id = format!("q{}", q.seq);
                q.items.push(QueueItem {
                    id: item_id.clone(),
                    project: id.clone(),
                    name: names.get(id).cloned().unwrap_or_default(),
                    profile: profile.clone(),
                    args: extra.clone(),
                    status: "pending".into(),
                    added_at: now.clone(),
                    ..Default::default()
                });
                added.push(item_id);
            }
            // drop the oldest finished items beyond the limit
            while q.items.len() > MAX_ITEMS {
                match q.items.iter().position(|i| QueueState::finished(&i.status)) {
                    Some(p) => {
                        q.items.remove(p);
                    }
                    None => break,
                }
            }
            Ok((added, skipped))
        })?;
        let st = self.queue_load();
        self.queue_emit(&st);
        self.queue_kick(Duration::ZERO);
        let mut v = self.queue_view(&st);
        v["added"] = json!(added);
        v["skipped"] = json!(skipped);
        Ok(v)
    }

    /// `queue_list` → the queue view; also restarts the driver if work is left.
    pub(crate) fn queue_list(&self) -> CmdResult {
        self.queue_kick(Duration::ZERO);
        Ok(self.queue_view(&self.queue_load()))
    }

    /// The running queue item whose scan is active right now.
    fn queue_active(&self, st: &QueueState) -> Option<QueueItem> {
        let it = st.items.iter().find(|i| i.status == "running")?;
        (self.active_scan_id().as_deref() == it.scan_id.as_deref()).then(|| it.clone())
    }

    /// `queue_pause`: pauses the queue and its running scan.
    pub(crate) fn queue_pause(&self) -> CmdResult {
        self.queue_edit(|q| {
            q.paused = true;
            q.pause_reason = Some("user".into());
            Ok(())
        })?;
        let st = self.queue_load();
        if self.queue_active(&st).is_some() {
            self.pause("user");
        }
        self.queue_emit(&st);
        Ok(self.queue_view(&st))
    }

    /// `queue_resume`: resumes the queue (and its paused scan) and starts the next item.
    pub(crate) fn queue_resume(&self) -> CmdResult {
        self.queue_edit(|q| {
            q.paused = false;
            q.pause_reason = None;
            Ok(())
        })?;
        let st = self.queue_load();
        if self.queue_active(&st).is_some() {
            self.resume();
        }
        self.queue_emit(&st);
        self.queue_kick(Duration::ZERO);
        Ok(self.queue_view(&self.queue_load()))
    }

    /// `queue_remove { id }`: removes an item; the running one also stops its scan.
    pub(crate) async fn queue_remove(&self, a: &Value) -> CmdResult {
        let id = arg_str(a, "id").ok_or_else(|| bad_args("нужен id элемента"))?;
        let st = self.queue_load();
        let active = self.queue_active(&st).filter(|i| i.id == id);
        let found = self.queue_edit(|q| {
            let n = q.items.len();
            q.items.retain(|i| i.id != id);
            Ok(q.items.len() != n)
        })?;
        if !found {
            return Err(CmdError::not_found(format!(
                "элемент очереди {id} не найден"
            )));
        }
        if active.is_some() {
            self.scan_stop("queue").await?;
        }
        let st = self.queue_load();
        self.queue_emit(&st);
        self.queue_kick(Duration::ZERO);
        Ok(self.queue_view(&st))
    }

    /// `queue_clear { stop? }`: removes every item except the running one; `stop: true` also
    /// stops the running scan and empties the queue.
    pub(crate) async fn queue_clear(&self, a: &Value) -> CmdResult {
        let stop = a.get("stop").and_then(Value::as_bool).unwrap_or(false);
        let st = self.queue_load();
        let active = self.queue_active(&st);
        self.queue_edit(|q| {
            q.items.retain(|i| !stop && i.status == "running");
            if q.items.is_empty() {
                q.paused = false;
                q.pause_reason = None;
            }
            Ok(())
        })?;
        if stop && active.is_some() {
            self.scan_stop("queue").await?;
        }
        let st = self.queue_load();
        self.queue_emit(&st);
        Ok(self.queue_view(&st))
    }
}
