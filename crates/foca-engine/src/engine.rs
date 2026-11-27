//! `Engine`: the store, the cache of open projects and the running scan, with the basic services
//! every command and the scan pipeline use.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard};

use foca_core::Clock;
use foca_search::store::SharedDb;
use foca_store::Store;
use serde_json::{json, Value};
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;

use crate::services::resume::RunState;
use crate::{CmdError, EngineConfig, EventSink, KeyProvider, ReportBuilder};

pub(crate) fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    match m.lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    }
}

pub(crate) struct Run {
    pub st: Arc<Mutex<RunState>>,
    /// Sources to skip (`scan_skip_source`), read by the search stage.
    pub skip: Arc<Mutex<std::collections::HashSet<String>>>,
    pub cancel: CancellationToken,
    pub pause: watch::Sender<Option<String>>,
    pub handle: Option<tokio::task::JoinHandle<()>>,
    pub net: Option<foca_net::NetClient>,
}

/// Shared state of the engine and the services every command and the scan pipeline use: the
/// store, open project files, platform providers and the running scan.
pub struct Core {
    pub(crate) cfg: EngineConfig,
    pub(crate) clock: Arc<dyn Clock>,
    pub(crate) store: Arc<Mutex<Store>>,
    pub(crate) dbs: Mutex<HashMap<String, SharedDb>>,
    pub(crate) keys: Mutex<Arc<dyn KeyProvider>>,
    pub(crate) events: Arc<Mutex<Arc<dyn EventSink>>>,
    /// Monthly mobile data counter fed by every request sink of the engine.
    pub(crate) mobile: Arc<crate::services::mobile::MobileMeter>,
    pub(crate) render: Mutex<Option<Arc<dyn foca_search::RenderFetch>>>,
    pub(crate) signer: Mutex<Option<Arc<dyn crate::ReportSigner>>>,
    pub(crate) ocr: Mutex<Option<Arc<dyn crate::OcrProvider>>>,
    pub(crate) screenshotter: Mutex<Option<Arc<dyn crate::WebScreenshotter>>>,
    pub(crate) headless: std::sync::atomic::AtomicBool,
    pub(crate) dir_lock: Mutex<Option<foca_store::DataDirLock>>,
    pub(crate) reports: Mutex<Option<Arc<dyn ReportBuilder>>>,
    pub(crate) run: Mutex<Option<Run>>,
    /// The scan has ended but its history record (`done`/`stopped`) is still being written. The engine
    /// counts as busy; otherwise `wait_idle`/`scan_start` could see it idle before the record is written.
    pub(crate) finishing: std::sync::atomic::AtomicBool,
    /// Cancellation of the running offline import (`import_cancel`).
    pub(crate) import_cancel: Mutex<Option<CancellationToken>>,
    /// Last requests of the quick tools (`tool_log`), shared with each call's request sink.
    pub(crate) tool_log: Arc<Mutex<std::collections::VecDeque<Value>>>,
    /// Serializes edits of the scan queue file.
    pub(crate) queue_lock: Mutex<()>,
    /// A queue driver task is running.
    pub(crate) queue_driver: std::sync::atomic::AtomicBool,
    /// Set by `abandon` (simulated process unload): the queue driver stops at once.
    pub(crate) queue_halt: std::sync::atomic::AtomicBool,
    /// Monotonic progress high-water mark `(scan_id, percent)` for the active queue item.
    pub(crate) queue_progress: Mutex<Option<(String, u8)>>,
    /// In-memory session cache of cloud AI models fetched via `ai_models_list`, keyed by
    /// `"{provider}|{base_url}"`.
    pub(crate) ai_models_cache: Mutex<HashMap<String, Vec<Value>>>,
    /// Running `ai_summarize` requests by project id (one per project; `ai_cancel` fires the token).
    pub(crate) ai_jobs: Mutex<HashMap<String, CancellationToken>>,
    /// Waiting in-scan retries of postponed dorks by project (`dorks_retry` wakes them).
    pub(crate) dork_jobs: Mutex<HashMap<String, DorkJob>>,
}

/// A waiting in-scan retry of postponed dorks for one project.
pub(crate) struct DorkJob {
    pub scan_id: String,
    pub wake: Arc<tokio::sync::Notify>,
    /// When the retry starts (unix ms).
    pub at_ms: i64,
}

/// The FOCA-rs engine. Cheap to clone (`Arc` inside); one per application.
#[derive(Clone)]
pub struct Engine {
    pub(crate) inner: Arc<Core>,
}

impl std::ops::Deref for Engine {
    type Target = Core;

    fn deref(&self) -> &Core {
        &self.inner
    }
}

impl Core {
    /// Returns the currently attached render fetcher, if any.
    pub fn current_render(&self) -> Option<Arc<dyn foca_search::RenderFetch>> {
        lock(&self.render).clone()
    }

    pub(crate) fn current_keys(&self) -> Arc<dyn KeyProvider> {
        lock(&self.keys).clone()
    }

    pub(crate) fn current_signer(&self) -> Option<Arc<dyn crate::ReportSigner>> {
        lock(&self.signer).clone()
    }

    pub(crate) fn current_ocr(&self) -> Option<Arc<dyn crate::OcrProvider>> {
        lock(&self.ocr).clone()
    }

    #[allow(dead_code)]
    pub(crate) fn current_screenshotter(&self) -> Option<Arc<dyn crate::WebScreenshotter>> {
        lock(&self.screenshotter).clone()
    }

    /// Returns `true` if this engine is currently running in autonomous headless mode.
    pub fn is_headless(&self) -> bool {
        self.headless.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Returns the active scan id, if any scan is currently running.
    pub fn active_scan_id(&self) -> Option<String> {
        let g = lock(&self.run);
        g.as_ref().map(|r| lock(&r.st).scan_id.clone())
    }

    pub(crate) fn now(&self) -> time::OffsetDateTime {
        self.clock.now()
    }

    pub(crate) fn now_iso(&self) -> String {
        crate::util::iso(self.now())
    }

    pub(crate) fn store(&self) -> MutexGuard<'_, Store> {
        lock(&self.store)
    }

    pub(crate) fn emit(&self, ev: Value) {
        let sink = lock(&self.events).clone();
        sink.emit(&ev);
    }

    pub(crate) fn run_file(&self) -> PathBuf {
        self.cfg.data_dir.join("engine_run.json")
    }

    /// Returns the open project file (shared by commands and the scan).
    pub(crate) fn db(&self, id: &str) -> Result<SharedDb, CmdError> {
        if let Some(d) = lock(&self.dbs).get(id) {
            return Ok(d.clone());
        }
        let db = self.store().open_project(id)?;
        let d: SharedDb = Arc::new(Mutex::new(db));
        lock(&self.dbs).insert(id.to_string(), d.clone());
        Ok(d)
    }

    pub(crate) fn forget_db(&self, id: &str) {
        lock(&self.dbs).remove(id);
    }

    /// Returns the project from the arguments: `project` or `id`, falling back to `settings.last_project`.
    pub(crate) fn project_arg(&self, a: &Value) -> Result<String, CmdError> {
        if let Some(p) = a
            .get("project")
            .or_else(|| a.get("id"))
            .and_then(Value::as_str)
        {
            return Ok(p.to_string());
        }
        self.store()
            .settings_get()?
            .get("last_project")
            .and_then(Value::as_str)
            .map(str::to_string)
            .ok_or_else(|| CmdError::not_found("проект не указан"))
    }

    /// Writes the running scan file atomically (tmp + rename): a kill -9 mid-write must not leave
    /// truncated JSON, or the scan would vanish from the history on the next start.
    pub(crate) fn persist_run(&self, st: &RunState) {
        if let Ok(j) = serde_json::to_vec(st) {
            let f = self.run_file();
            let tmp = f.with_extension("json.tmp");
            if std::fs::write(&tmp, j).is_ok() {
                let _ = std::fs::rename(&tmp, &f);
            }
        }
    }

    pub(crate) fn running_scan(&self) -> Option<(String, String, u8)> {
        let g = lock(&self.run);
        let r = g.as_ref()?;
        let st = lock(&r.st);
        Some((st.project.clone(), st.scan_id.clone(), st.progress))
    }

    /// Returns the report file path in the private directory: `<data>/reports/<project>/<name>`.
    pub(crate) fn report_file(&self, project: &str, name: &str) -> PathBuf {
        let leaf = safe_report_leaf(name).unwrap_or("report.bin");
        self.cfg.data_dir.join("reports").join(project).join(leaf)
    }
}

impl Engine {
    /// Sets the report builder (foca-report by default with the `report` feature).
    pub fn set_report_builder(&self, b: Option<Arc<dyn ReportBuilder>>) {
        *lock(&self.inner.reports) = b;
    }

    /// Replaces the live event sink (used when the UI attaches to a running headless engine).
    pub fn set_event_sink(&self, sink: Arc<dyn EventSink>) {
        *lock(&self.inner.events) = sink;
    }

    /// Attaches or clears the interactive WebView render fetcher (e.g. during headless-to-UI handoff).
    pub fn set_render(&self, render: Option<Arc<dyn foca_search::RenderFetch>>) {
        *lock(&self.inner.render) = render;
    }

    /// Returns the engine's configured data directory.
    pub fn data_dir(&self) -> &std::path::Path {
        &self.inner.cfg.data_dir
    }

    pub fn config(&self) -> &EngineConfig {
        &self.inner.cfg
    }

    /// Reports whether the device is on a mobile or metered network (request bytes count against
    /// the monthly mobile data limit only then) and returns whether this month's limit is reached.
    pub fn mobile_network(&self, on_mobile: bool) -> bool {
        self.inner.mobile.network(on_mobile)
    }

    /// The monthly mobile data limit is set and this month's mobile traffic has reached it.
    pub fn mobile_cap_reached(&self) -> bool {
        self.inner.mobile.reached()
    }

    /// Pauses the scan from outside (`offline` / `battery` / `wifi` / `vpn` / `mobile_cap` / `user`).
    /// Emits `paused { scan_id, project, reason }` when the reason changes (not on a repeated reason).
    pub fn pause(&self, reason: &str) -> bool {
        let ev = {
            let g = lock(&self.inner.run);
            let Some(r) = g.as_ref() else { return false };
            let mut st = lock(&r.st);
            let changed = st.pause_reason.as_deref() != Some(reason);
            st.pause_reason = Some(reason.to_string());
            r.pause.send_replace(Some(reason.to_string()));
            changed.then(|| {
                json!({ "type": "paused", "scan_id": st.scan_id, "project": st.project,
                    "reason": reason, "progress": st.progress })
            })
        };
        // emit without holding engine locks (the event handler may call commands)
        if let Some(ev) = ev {
            self.emit(ev);
        }
        true
    }

    /// Resumes the scan. Emits `resumed { scan_id, project }` only if the scan was paused.
    pub fn resume(&self) -> bool {
        let ev = {
            let g = lock(&self.inner.run);
            let Some(r) = g.as_ref() else { return false };
            let mut st = lock(&r.st);
            let was = st.pause_reason.take();
            r.pause.send_replace(None);
            was.map(|w| {
                json!({ "type": "resumed", "scan_id": st.scan_id, "project": st.project,
                    "after": w, "progress": st.progress })
            })
        };
        if let Some(ev) = ev {
            self.emit(ev);
        }
        true
    }

    /// Returns `true` while a scan is running.
    pub fn is_scanning(&self) -> bool {
        lock(&self.inner.run).is_some()
            || self
                .inner
                .finishing
                .load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Waits for the running scan to finish (CLI `--wait`, tests). Returns `false` on timeout.
    pub async fn wait_idle(&self, timeout: std::time::Duration) -> bool {
        let t0 = tokio::time::Instant::now();
        while self.is_scanning() {
            if t0.elapsed() > timeout {
                return false;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        true
    }

    /// Simulates a process unload (tests): the scan is aborted without a history record and
    /// `engine_run.json` is kept, so the next `Engine::open` records `stopped/restart`.
    #[doc(hidden)]
    pub async fn abandon(&self) {
        self.inner
            .queue_halt
            .store(true, std::sync::atomic::Ordering::SeqCst);
        let run = lock(&self.inner.run).take();
        if let Some(mut r) = run {
            r.cancel.cancel();
            if let Some(h) = r.handle.take() {
                h.abort();
                let _ = h.await;
            }
        }
        lock(&self.inner.dbs).clear();
        *lock(&self.inner.events) = Arc::new(crate::MemoryEvents::new());
        lock(&self.inner.dir_lock).take();
    }

    /// Cancels and awaits the active scan (if any) without tearing down `events`,
    /// `dir_lock`, or `queue_halt` (used by `project_delete` and `wipe_all`).
    pub(crate) async fn stop_active_scan(&self) {
        let mut run = lock(&self.inner.run).take();
        if let Some(ref mut r) = run {
            r.cancel.cancel();
            if let Some(h) = r.handle.take() {
                h.abort();
                let _ = h.await;
            }
        }
        self.inner
            .finishing
            .store(false, std::sync::atomic::Ordering::SeqCst);
    }
}

pub(crate) fn safe_report_leaf(name: &str) -> Option<&str> {
    let trimmed = name.trim();
    if trimmed.is_empty()
        || trimmed.contains('/')
        || trimmed.contains('\\')
        || trimmed.contains('\0')
        || trimmed == "."
        || trimmed == ".."
    {
        return None;
    }
    let mut comps = std::path::Path::new(trimmed).components();
    match (comps.next(), comps.next()) {
        (Some(std::path::Component::Normal(os)), None) => os.to_str(),
        _ => None,
    }
}
