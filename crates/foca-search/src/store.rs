//! `foca-store` adapters (feature `store`): the download queue on top of `tasks` and the request
//! log on top of `request_log` in the project file.

use std::sync::{Arc, Mutex, MutexGuard};

use foca_core::DocStatus;
use foca_net::{RequestRecord, RequestSink};
use foca_store::{AddDoc, ProjectDb, RequestLog};

use crate::download::{Downloaded, QueuedTask, TaskQueue};
use crate::source::FoundUrl;

/// Shared access to the project database (a rusqlite `Connection` is `Send` but not `Sync`).
pub type SharedDb = Arc<Mutex<ProjectDb>>;

fn lock(db: &SharedDb) -> MutexGuard<'_, ProjectDb> {
    match db.lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    }
}

/// Project download queue.
pub struct StoreQueue {
    pub db: SharedDb,
    pub kind: String,
    pub scan_id: Option<String>,
}

impl StoreQueue {
    pub fn new(db: SharedDb, scan_id: Option<String>) -> Self {
        StoreQueue {
            db,
            kind: "download".into(),
            scan_id,
        }
    }

    /// Enqueues discovered URLs, ignoring duplicates. Returns the number of new entries.
    pub fn enqueue(&self, urls: &[FoundUrl]) -> Result<usize, String> {
        let db = lock(&self.db);
        let mut n = 0;
        for u in urls {
            if db
                .task_enqueue(&self.kind, &u.url, &u.source, self.scan_id.as_deref())
                .map_err(|e| e.to_string())?
                .is_some()
            {
                n += 1;
            }
        }
        Ok(n)
    }
}

impl TaskQueue for StoreQueue {
    fn resume(&self) -> Result<u32, String> {
        lock(&self.db).tasks_resume().map_err(|e| e.to_string())
    }

    fn claim(&self, limit: usize) -> Result<Vec<QueuedTask>, String> {
        Ok(lock(&self.db)
            .task_claim_ranked(&self.kind, limit, crate::priority::rank)
            .map_err(|e| e.to_string())?
            .into_iter()
            .map(|t| QueuedTask {
                id: t.id,
                url: t.url,
                source: t.source,
                attempts: t.attempts,
            })
            .collect())
    }

    fn done(&self, task: &QueuedTask, d: &Downloaded) -> Result<Option<u64>, String> {
        let db = lock(&self.db);
        let added = db
            .add_document(&AddDoc {
                url: Some(task.url.clone()),
                name: d.name.clone(),
                source: task.source.clone(),
                first_scan: self.scan_id.clone(),
                status: DocStatus::Downloaded,
                size: d.size,
                sha256: Some(d.sha256.clone()),
                local_path: Some(d.path.to_string_lossy().into_owned()),
                mime: d.mime.clone(),
                ..Default::default()
            })
            .map_err(|e| e.to_string())?;
        db.task_done(task.id, Some(added.id))
            .map_err(|e| e.to_string())?;
        Ok(Some(added.id))
    }

    fn failed(&self, task: &QueuedTask, err: &str, permanent: bool) -> Result<(), String> {
        // max_attempts = 0 fails the task at once; otherwise it is requeued (the downloader owns the attempt limit)
        let max = if permanent { 0 } else { u32::MAX };
        lock(&self.db)
            .task_failed(task.id, err, max)
            .map(|_| ())
            .map_err(|e| e.to_string())
    }
}

/// Outgoing request log stored in the project's `request_log`.
pub struct StoreSink {
    pub db: SharedDb,
    pub scan_id: Option<String>,
}

impl RequestSink for StoreSink {
    fn record(&self, r: &RequestRecord) {
        let time = r
            .time
            .to_offset(time::UtcOffset::UTC)
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_default();
        let error = match (&r.error, r.blocked) {
            (Some(e), _) => Some(e.clone()),
            (None, true) => Some("blocked".into()),
            _ => None,
        };
        let _ = lock(&self.db).log_request(&RequestLog {
            id: 0,
            time,
            scan_id: self.scan_id.clone(),
            module: r.module.clone(),
            method: r.method.clone(),
            url: r.url.clone(),
            host: r.host.clone(),
            status: r.status,
            bytes: r.bytes,
            active: r.active,
            error,
            ..Default::default()
        });
    }
}
