//! Project persistence for FOCA-rs.
//!
//! * One SQLite file `<id>.foca` per project (WAL mode, foreign keys enabled) plus a small
//!   `projects.db` index in the same directory holding the project list, the summaries
//!   served by `project_list` and the global settings (never secrets).
//! * Schema migrations keyed on `PRAGMA user_version` (see [`schema`]).
//! * [`ProjectDb::snapshot`] builds a snapshot in exactly the shape defined in `docs/API.md`
//!   ([`foca_core::api::Snapshot`]).
//!
//! API key values are not stored here, only their status and mask; the values themselves
//! live in the Android Keystore. Secrets found in documents are stored because the report
//! needs them, but they are masked in `Debug`/`Display` ([`foca_core::api::SecretValue`]).

mod erase;
pub mod lock;
pub mod project;
pub mod revisions;
pub mod schema;
pub mod search;
pub mod settings;
mod storage_docs;

use std::path::{Path, PathBuf};
use std::sync::Arc;

use foca_core::api::{ProjectSummary, ScopeDto, ScopeTarget};
use foca_core::{Clock, SystemClock};
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub use erase::{RequestLogFilter, ScanErase};
pub use lock::{DataDirLock, LockOwner};
pub use project::{
    AddDoc, DocAdded, DocErrorKind, FindingPatch, ProjectDb, RequestLog, Task, TaskCounts,
    TaskState, UndoEntry, PROVENANCE_KEY,
};
pub use search::{SearchHit, SearchOpts, SearchPage};

/// Storage error; [`StoreError::code`] maps it to a command error code from `docs/API.md`.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("SQLite: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("ввод-вывод: {0}")]
    Io(#[from] std::io::Error),
    #[error("не найдено: {0}")]
    NotFound(String),
    #[error("недопустимый статус: {0}")]
    BadStatus(String),
    #[error("недопустимые данные: {0}")]
    Invalid(String),
    #[error("файл новее программы: версия схемы {found}, поддерживается до {supported}")]
    Version { found: u32, supported: u32 },
}

impl StoreError {
    pub fn code(&self) -> &'static str {
        match self {
            StoreError::NotFound(_) => "not_found",
            StoreError::BadStatus(_) => "bad_status",
            StoreError::Invalid(_) => "bad_args",
            _ => "internal",
        }
    }
}

pub type Result<T> = std::result::Result<T, StoreError>;

/// Formats a timestamp as local time without an offset (`2026-11-20T12:00:00`), as the API contract expects.
pub fn iso(t: time::OffsetDateTime) -> String {
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}",
        t.year(),
        u8::from(t.month()),
        t.day(),
        t.hour(),
        t.minute(),
        t.second()
    )
}

/// Arguments of `project_create`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct NewProject {
    pub name: String,
    pub client: String,
    pub targets: Vec<String>,
    pub excludes: Vec<String>,
}

/// Partial update for `project_update`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ProjectPatch {
    pub name: Option<String>,
    pub client: Option<String>,
    pub notes: Option<String>,
    pub archived: Option<bool>,
}

/// Classifies a user-entered target for the UI, using the `foca-core` target parser.
fn target_kind(v: &str) -> &'static str {
    match foca_core::Target::parse(v) {
        Ok(foca_core::Target::Domain { .. }) => "domain",
        Ok(foca_core::Target::Wildcard { .. }) => "wild",
        Ok(foca_core::Target::Cidr { .. }) => "cidr",
        Ok(foca_core::Target::Ip { .. }) => "ip",
        Ok(foca_core::Target::IpRange { .. }) => "range",
        Ok(foca_core::Target::Url { .. }) => "url",
        Ok(foca_core::Target::Asn { .. }) => "asn",
        Ok(foca_core::Target::Email { .. }) => "person",
        Ok(foca_core::Target::Org { .. }) | Err(_) => "org",
    }
}

/// Size of the buffer used to overwrite deleted project files.
const WIPE_CHUNK: usize = 64 * 1024;

/// Key of the report logo in the index `settings` table.
const REPORT_LOGO_KEY: &str = "report.logo";

/// Overwrites `len` bytes with zeros through a fixed-size buffer, so wiping a large database
/// never allocates its whole size in memory.
fn zero_fill<W: std::io::Write>(w: &mut W, len: u64) -> std::io::Result<()> {
    let buf = [0u8; WIPE_CHUNK];
    let mut left = len;
    while left > 0 {
        let n = left.min(WIPE_CHUNK as u64) as usize;
        w.write_all(&buf[..n])?;
        left -= n as u64;
    }
    w.flush()
}

/// Overwrites a file with zeros, syncs it and removes it; a missing file is not an error. Used for
/// project databases and for document files of a deleted scan.
pub fn wipe_file(path: &std::path::Path) -> std::io::Result<()> {
    let Ok(meta) = std::fs::metadata(path) else {
        return Ok(());
    };
    let mut f = std::fs::OpenOptions::new().write(true).open(path)?;
    zero_fill(&mut f, meta.len())?;
    f.sync_all()?;
    drop(f);
    std::fs::remove_file(path)
}

/// Removes a project database together with its WAL/SHM side files, ignoring errors.
fn remove_project_files(path: &std::path::Path) {
    let _ = std::fs::remove_file(path);
    for ext in ["-wal", "-shm"] {
        let _ = std::fs::remove_file(format!("{}{ext}", path.display()));
    }
}

fn slug(name: &str) -> String {
    let t = foca_analysis::translit::primary(name);
    let mut s: String = t
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '.' || c == '-' {
                c.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect();
    while s.contains("--") {
        s = s.replace("--", "-");
    }
    let s = s
        .trim_matches(['-', '.'])
        .chars()
        .take(40)
        .collect::<String>();
    if s.is_empty() {
        "project".into()
    } else {
        s
    }
}

/// Project store: a directory containing `projects.db` and the project files.
pub struct Store {
    dir: PathBuf,
    index: Connection,
    clock: Arc<dyn Clock>,
}

impl Store {
    /// Opens the store in `dir`, creating it if necessary.
    pub fn open(dir: impl AsRef<Path>) -> Result<Store> {
        Store::open_with_clock(dir, Arc::new(SystemClock))
    }

    pub fn open_with_clock(dir: impl AsRef<Path>, clock: Arc<dyn Clock>) -> Result<Store> {
        let dir = dir.as_ref().to_path_buf();
        std::fs::create_dir_all(&dir)?;
        let index = Connection::open(dir.join("projects.db"))?;
        index.busy_timeout(std::time::Duration::from_secs(10))?;
        index.pragma_update(None, "journal_mode", "WAL")?;
        index.pragma_update(None, "synchronous", "NORMAL")?;
        index.pragma_update(None, "foreign_keys", "ON")?;
        schema::migrate(&index, schema::INDEX_MIGRATIONS)?;
        Ok(Store { dir, index, clock })
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    fn now(&self) -> String {
        iso(self.clock.now())
    }

    fn unique_id(&self, base: &str) -> Result<String> {
        let mut id = base.to_string();
        let mut k = 2;
        loop {
            let exists: Option<String> = self
                .index
                .query_row("SELECT id FROM projects WHERE id = ?1", [&id], |r| r.get(0))
                .optional()?;
            if exists.is_none() && !self.dir.join(format!("{id}.foca")).exists() {
                return Ok(id);
            }
            id = format!("{base}-{k}");
            k += 1;
        }
    }

    /// Implements `project_create`: a new empty project with no scans and `risk: null`.
    pub fn create_project(&self, req: &NewProject) -> Result<ProjectSummary> {
        let name = if req.name.trim().is_empty() {
            req.targets
                .first()
                .cloned()
                .unwrap_or_else(|| "project".into())
        } else {
            req.name.trim().to_string()
        };
        let id = self.unique_id(&slug(&name))?;
        let file = format!("{id}.foca");
        let now = self.now();
        let domain = req
            .targets
            .iter()
            .find(|t| target_kind(t) == "domain")
            .cloned()
            .unwrap_or_else(|| name.clone());
        let scope = ScopeDto {
            client: req.client.clone(),
            targets: req
                .targets
                .iter()
                .map(|t| ScopeTarget {
                    v: t.clone(),
                    kind: target_kind(t).into(),
                })
                .collect(),
            excl: req.excludes.clone(),
            ..Default::default()
        };
        let db = ProjectDb::create(
            &self.dir.join(&file),
            &id,
            &name,
            &req.client,
            &domain,
            &now,
            &scope,
            self.clock.clone(),
        )?;
        let pos: i64 = self.index.query_row(
            "SELECT COALESCE(MIN(position), 0) - 1 FROM projects",
            [],
            |r| r.get(0),
        )?;
        self.index.execute(
            "INSERT INTO projects (id, name, client, file, created_at, position) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![id, name, req.client, file, now, pos],
        )?;
        let s = db.summary()?;
        self.save_summary(&s)?;
        Ok(s)
    }

    fn save_summary(&self, s: &ProjectSummary) -> Result<()> {
        self.index.execute(
            "UPDATE projects SET name = ?2, client = ?3, archived = ?4, summary_json = ?5 WHERE id = ?1",
            params![s.id, s.name, s.client, s.archived, serde_json::to_string(s)?],
        )?;
        Ok(())
    }

    /// Refreshes the project summary in the index after a scan, analysis or triage change.
    pub fn refresh_summary(&self, db: &ProjectDb) -> Result<ProjectSummary> {
        let s = db.summary()?;
        self.save_summary(&s)?;
        Ok(s)
    }

    /// Implements `project_list`, newest first.
    ///
    /// The cached summary may come from another app version; a row that does not parse still
    /// lists the project from the index columns, so a project never drops out of the list.
    pub fn list_projects(&self) -> Result<Vec<ProjectSummary>> {
        let mut st = self.index.prepare(
            "SELECT id, name, client, created_at, archived, summary_json FROM projects \
             ORDER BY position, created_at DESC",
        )?;
        let rows = st.query_map([], |r| {
            Ok((
                ProjectSummary {
                    id: r.get(0)?,
                    name: r.get(1)?,
                    client: r.get(2)?,
                    created_at: r.get(3)?,
                    archived: r.get::<_, i64>(4)? != 0,
                    ..ProjectSummary::default()
                },
                r.get::<_, String>(5)?,
            ))
        })?;
        let mut out = Vec::new();
        for r in rows {
            let (base, json) = r?;
            let s = match serde_json::from_str::<ProjectSummary>(&json) {
                Ok(s) if s.id == base.id => s,
                _ => base,
            };
            out.push(s);
        }
        Ok(out)
    }

    fn file_of(&self, id: &str) -> Result<PathBuf> {
        let f: Option<String> = self
            .index
            .query_row("SELECT file FROM projects WHERE id = ?1", [id], |r| {
                r.get(0)
            })
            .optional()?;
        match f {
            Some(f) => Ok(self.dir.join(f)),
            None => Err(StoreError::NotFound(format!("проект {id}"))),
        }
    }

    /// Opens a project file, migrating it to the current schema.
    pub fn open_project(&self, id: &str) -> Result<ProjectDb> {
        let path = self.file_of(id)?;
        if !path.exists() {
            return Err(StoreError::NotFound(format!(
                "файл проекта {}",
                path.display()
            )));
        }
        ProjectDb::open(&path, self.clock.clone())
    }

    /// Implements `project_update`.
    pub fn update_project(&self, id: &str, patch: &ProjectPatch) -> Result<ProjectSummary> {
        let db = self.open_project(id)?;
        db.update_info(patch)?;
        self.refresh_summary(&db)
    }

    /// Imports a standalone SQLite project database into the store under a fresh unique id
    /// (never overwriting existing projects).
    pub fn import_project_db(
        &self,
        db_bytes: &[u8],
        new_name: Option<&str>,
    ) -> Result<ProjectSummary> {
        if db_bytes.len() < 16 || &db_bytes[..16] != b"SQLite format 3\0" {
            return Err(StoreError::Invalid(
                "файл проекта внутри контейнера повреждён (не SQLite)".into(),
            ));
        }
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let stage_path = self
            .dir
            .join(format!(".import-{}-{nanos}.tmp", std::process::id()));
        std::fs::write(&stage_path, db_bytes)?;
        let staged_info = match ProjectDb::open(&stage_path, self.clock.clone()) {
            Ok(db) => {
                let info = db.info();
                drop(db);
                info
            }
            Err(e) => {
                let _ = std::fs::remove_file(&stage_path);
                return Err(e);
            }
        };
        let info = match staged_info {
            Ok(i) => i,
            Err(e) => {
                let _ = std::fs::remove_file(&stage_path);
                return Err(e);
            }
        };
        let final_name = new_name
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(String::from)
            .unwrap_or_else(|| info.name.clone());
        let id = self.unique_id(&slug(&final_name))?;
        let file = format!("{id}.foca");
        let dest = self.dir.join(&file);
        if let Err(e) = std::fs::rename(&stage_path, &dest) {
            let _ = std::fs::remove_file(&stage_path);
            return Err(e.into());
        }
        // Clean up any WAL/SHM generated during staging validation
        for ext in ["-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{}{ext}", stage_path.display()));
        }
        // The summary is computed before the index row is written: a database that opens but
        // cannot be summarised must not leave a `projects` row with an empty summary behind,
        // otherwise `list_projects` fails for the whole store.
        let prepared = ProjectDb::open(&dest, self.clock.clone()).and_then(|mut db| {
            db.rewrite_identity(&id, Some(&final_name))?;
            db.summary()
        });
        let s = match prepared {
            Ok(s) => s,
            Err(e) => {
                remove_project_files(&dest);
                return Err(e);
            }
        };
        let pos: i64 = self.index.query_row(
            "SELECT COALESCE(MIN(position), 0) - 1 FROM projects",
            [],
            |r| r.get(0),
        )?;
        let now = self.now();
        if let Err(e) = self.index.execute(
            "INSERT INTO projects (id, name, client, file, created_at, archived, summary_json, position) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                id,
                s.name,
                s.client,
                file,
                now,
                s.archived,
                serde_json::to_string(&s)?,
                pos
            ],
        ) {
            remove_project_files(&dest);
            return Err(e.into());
        }
        Ok(s)
    }

    /// Implements `project_duplicate`: copies targets and scope, but no results.
    pub fn duplicate_project(&self, id: &str) -> Result<ProjectSummary> {
        let src = self.open_project(id)?;
        let info = src.info()?;
        let scope = src.scope_get()?;
        let copy = self.create_project(&NewProject {
            name: info.name.clone(),
            client: format!("{} (копия)", info.client),
            ..Default::default()
        })?;
        let db = self.open_project(&copy.id)?;
        db.scope_set(&ScopeDto {
            client: copy.client.clone(),
            ..scope
        })?;
        self.refresh_summary(&db)
    }

    /// Implements `project_delete`: the project file (with its WAL/SHM files) is overwritten with zeros and removed.
    pub fn delete_project(&self, id: &str) -> Result<()> {
        let path = self.file_of(id)?;
        for p in [
            path.clone(),
            PathBuf::from(format!("{}-wal", path.display())),
            PathBuf::from(format!("{}-shm", path.display())),
        ] {
            wipe_file(&p)?;
        }
        self.index
            .execute("DELETE FROM projects WHERE id = ?1", [id])?;
        let last = self.settings_get()?;
        if last.get("last_project").and_then(Value::as_str) == Some(id) {
            let next = self.list_projects()?.first().map(|p| p.id.clone());
            self.settings_set(&serde_json::json!({ "last_project": next }))?;
        }
        Ok(())
    }

    /// Implements `settings_get`: defaults merged with the saved patch.
    pub fn settings_get(&self) -> Result<Value> {
        let saved: Option<String> = self
            .index
            .query_row(
                "SELECT value_json FROM settings WHERE key = 'settings'",
                [],
                |r| r.get(0),
            )
            .optional()?;
        let mut s = settings::defaults();
        if let Some(j) = saved {
            settings::merge(&mut s, &serde_json::from_str(&j)?);
        }
        Ok(s)
    }

    /// Implements `settings_set` as a deep merge. Secret-like fields (`value`, `key`, `secret`,
    /// `token`) under `keys.*` are dropped; only the status and the mask are kept.
    pub fn settings_set(&self, patch: &Value) -> Result<Value> {
        let mut s = self.settings_get()?;
        let mut p = patch.clone();
        settings::strip_secrets(&mut p);
        settings::merge(&mut s, &p);
        self.index.execute(
            "INSERT INTO settings (key, value_json) VALUES ('settings', ?1)
             ON CONFLICT(key) DO UPDATE SET value_json = excluded.value_json",
            [serde_json::to_string(&s)?],
        )?;
        Ok(s)
    }

    /// Resets the global settings to their defaults and drops the report logo (used by
    /// `wipe_all`).
    pub fn settings_reset(&self) -> Result<Value> {
        self.index.execute(
            "DELETE FROM settings WHERE key IN ('settings', ?1)",
            [REPORT_LOGO_KEY],
        )?;
        self.settings_get()
    }

    /// Report logo saved in Settings → Report (`report_logo_get`): the checked image as a
    /// `data:` URL with its file name and size. Kept apart from the settings JSON so that
    /// `settings_get` stays small.
    pub fn report_logo(&self) -> Result<Option<Value>> {
        let j: Option<String> = self
            .index
            .query_row(
                "SELECT value_json FROM settings WHERE key = ?1",
                [REPORT_LOGO_KEY],
                |r| r.get(0),
            )
            .optional()?;
        Ok(match j {
            Some(j) => Some(serde_json::from_str(&j)?),
            None => None,
        })
    }

    /// Saves (`Some`) or removes (`None`) the report logo; the caller checks the image.
    pub fn set_report_logo(&self, logo: Option<&Value>) -> Result<()> {
        match logo {
            Some(v) => self.index.execute(
                "INSERT INTO settings (key, value_json) VALUES (?1, ?2)
                 ON CONFLICT(key) DO UPDATE SET value_json = excluded.value_json",
                [REPORT_LOGO_KEY, &serde_json::to_string(v)?],
            )?,
            None => self
                .index
                .execute("DELETE FROM settings WHERE key = ?1", [REPORT_LOGO_KEY])?,
        };
        Ok(())
    }

    /// Implements `key_set`: the key value goes to the Keystore outside the core; only its mask and status are stored here.
    pub fn key_set(&self, service: &str, value: &str) -> Result<Value> {
        let st = settings::key_status(value);
        let s = self.settings_set(&serde_json::json!({ "keys": { service: st } }))?;
        Ok(s["keys"][service].clone())
    }

    /// Implements `project_open`: returns the snapshot and records `settings.last_project`.
    pub fn project_open(&self, id: &str) -> Result<foca_core::api::Snapshot> {
        let db = self.open_project(id)?;
        let s = self.settings_set(&serde_json::json!({ "last_project": id }))?;
        db.snapshot(s, serde_json::json!({ "running": false }))
    }

    /// Implements `project_snapshot`.
    pub fn project_snapshot(&self, id: &str) -> Result<foca_core::api::Snapshot> {
        let db = self.open_project(id)?;
        db.snapshot(
            self.settings_get()?,
            serde_json::json!({ "running": false }),
        )
    }
}

#[cfg(test)]
mod tests;
