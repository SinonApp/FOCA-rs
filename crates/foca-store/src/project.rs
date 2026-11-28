//! Project file `<id>.foca`: documents, entities, findings with triage state, scans, the
//! request log, the resumable download queue, reports, project settings and the undo log.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use foca_analysis::rules::{RuleError, RuleSet, RulesConfig};
use foca_analysis::{analyze, Analysis, DocInput, PrevFinding, PrevState};
use foca_core::api::{
    self, Doc, DocProvenance, Finding, Note, Photo, ProjectInfo, ProjectSummary, Report, Scan,
    ScopeDto, Snapshot,
};
use foca_core::{Clock, DocStatus, Document, FindingStatus, Metadata, Scope, Severity};
use rusqlite::{params, Connection, OptionalExtension, Row};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{iso, schema, ProjectPatch, Result, StoreError};

/// Project setting key of the user search rules.
pub const RULES_KEY: &str = "analysis.rules";

/// Project setting that marks a built-in reference case (`demo_case_import`).
pub const REFERENCE_CASE_KEY: &str = "reference_case";
/// Archive the reference case is imported from; its documents carry the source
/// `zip:<archive>`, which also recognises cases created before [`REFERENCE_CASE_KEY`] existed.
pub const REFERENCE_CASE_ARCHIVE: &str = "priklad-reference-case.zip";

/// Entity kinds stored as whole JSON values after analysis.
pub const ENTITY_KINDS: &[&str] = &[
    "docs", "people", "emails", "phones", "patterns", "hosts", "pcs", "software", "os", "paths",
    "printers", "secrets", "gps", "events", "graph", "activity", "risk", "leaks",
];

/// A new document to insert.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AddDoc {
    pub url: Option<String>,
    pub name: String,
    pub source: String,
    pub found_at: Option<String>,
    pub first_scan: Option<String>,
    pub status: DocStatus,
    pub size: u64,
    pub sha256: Option<String>,
    pub local_path: Option<String>,
    pub mime: Option<String>,
}

/// Result of an insert: the document id and whether it already existed (deduplicated by SHA-256 or URL).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DocAdded {
    pub id: u64,
    pub existing: bool,
}

/// A stored document together with its project-level fields.
#[derive(Debug, Clone, PartialEq)]
pub struct StoredDoc {
    pub doc: Document,
    pub first_scan: Option<String>,
    pub deleted: bool,
    pub text: Option<String>,
    pub local_path: Option<String>,
    /// Kind of the recorded error (`documents.error_kind`), see [`DocErrorKind`].
    pub error_kind: Option<String>,
}

/// Extraction revision and app version recorded with every parsed document.
pub(crate) const EXTRACTOR: (u32, &str) = (
    foca_core::extractor::FORMAT_REV,
    foca_core::extractor::VERSION,
);

/// What failed for a document in `error`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DocErrorKind {
    /// The stored (downloaded or imported) file could not be parsed or imported.
    Parse,
    /// The file could not be fetched (network error, timeout, size limit).
    Download,
    /// The server answered the fetch with an HTTP error status.
    Http,
}

impl DocErrorKind {
    pub fn as_str(self) -> &'static str {
        match self {
            DocErrorKind::Parse => "parse",
            DocErrorKind::Download => "download",
            DocErrorKind::Http => "http",
        }
    }
}

/// Partial update for `finding_update`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct FindingPatch {
    pub sev: Option<Severity>,
    pub notes: Option<Vec<Note>>,
    pub tags: Option<Vec<String>>,
    pub photos: Option<Vec<Photo>>,
    pub status: Option<FindingStatus>,
}

/// Document provenance by download URL (`BTreeMap<String, DocProvenance>`), from the scan engine.
pub const PROVENANCE_KEY: &str = "docs.provenance";

/// An entry of the outgoing request log.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct RequestLog {
    pub id: i64,
    pub time: String,
    pub scan_id: Option<String>,
    /// Source module (`wayback`, `crawler`, `dns`, `httpmap`, ...).
    pub module: String,
    pub method: String,
    pub url: String,
    pub host: String,
    pub status: Option<u16>,
    pub bytes: u64,
    /// The request went to the target itself (active stage) rather than to a third-party service.
    pub active: bool,
    pub error: Option<String>,
    /// Module annotation of the response; for brute forcing: `soft404` | `calibration` | `filtered` | `rate_limited`.
    pub note: Option<String>,
    /// Response content type, if the module reported it.
    pub ctype: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskState {
    Queued,
    Downloading,
    Done,
    Failed,
}

impl TaskState {
    fn as_str(self) -> &'static str {
        match self {
            TaskState::Queued => "queued",
            TaskState::Downloading => "downloading",
            TaskState::Done => "done",
            TaskState::Failed => "failed",
        }
    }
    fn parse(s: &str) -> TaskState {
        match s {
            "downloading" => TaskState::Downloading,
            "done" => TaskState::Done,
            "failed" => TaskState::Failed,
            _ => TaskState::Queued,
        }
    }
}

/// A download queue task.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Task {
    pub id: i64,
    pub kind: String,
    pub url: String,
    pub scan_id: Option<String>,
    pub source: String,
    pub state: TaskState,
    pub attempts: u32,
    pub last_error: Option<String>,
    pub doc_id: Option<u64>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskCounts {
    pub queued: u32,
    pub downloading: u32,
    pub done: u32,
    pub failed: u32,
}

/// An undo log entry.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UndoEntry {
    pub id: i64,
    pub time: String,
    pub action: String,
    pub payload: Value,
    pub undone: bool,
}

fn status_str(s: DocStatus) -> &'static str {
    match s {
        DocStatus::Queued => "queued",
        DocStatus::Downloading => "downloading",
        DocStatus::Downloaded => "downloaded",
        DocStatus::Analyzed => "analyzed",
        DocStatus::Error => "error",
        DocStatus::Skipped => "skipped",
    }
}

fn parse_status(s: &str) -> DocStatus {
    match s {
        "downloading" => DocStatus::Downloading,
        "downloaded" => DocStatus::Downloaded,
        "analyzed" => DocStatus::Analyzed,
        "error" => DocStatus::Error,
        "skipped" => DocStatus::Skipped,
        _ => DocStatus::Queued,
    }
}

/// Extracts an HTTP status (`HTTP 404`, `HTTP 503 …`) from a recorded error message.
pub fn http_status_of(err: &str) -> Option<u16> {
    let i = err.find("HTTP ")?;
    let code: String = err[i + 5..]
        .chars()
        .take_while(char::is_ascii_digit)
        .collect();
    code.parse::<u16>().ok().filter(|c| (100..=599).contains(c))
}

fn ui_status(s: DocStatus) -> &'static str {
    match s {
        DocStatus::Analyzed => "analyzed",
        DocStatus::Downloaded => "downloaded",
        DocStatus::Queued | DocStatus::Downloading => "queued",
        DocStatus::Error | DocStatus::Skipped => "error",
    }
}

fn fstatus_str(s: FindingStatus) -> &'static str {
    match s {
        FindingStatus::New => "new",
        FindingStatus::Confirmed => "confirmed",
        FindingStatus::FalsePositive => "false",
        FindingStatus::Accepted => "accepted",
        FindingStatus::Fixed => "fixed",
    }
}

/// Parses a finding status from its contract string (`new|confirmed|false|accepted|fixed`).
fn parse_finding_status(s: &str) -> Result<FindingStatus> {
    s.parse().map_err(StoreError::BadStatus)
}

fn sev_str(s: Severity) -> &'static str {
    foca_analysis::util::sev_name(s)
}

fn parse_sev(s: &str) -> Severity {
    serde_json::from_value(Value::String(s.to_string())).unwrap_or(Severity::Info)
}

/// Returns the UI label of a scan profile.
pub fn profile_label(id: &str) -> &'static str {
    match id {
        "passive" => "Пассивный",
        "std" => "Стандартный",
        "full" => "Полный",
        _ => "Свой",
    }
}

/// Tag added to a fixed finding that shows up again on the live site.
pub const REOPENED_TAG: &str = "reopened";

/// Russian tags written by older versions, mapped to the stable English codes the UI translates.
const LEGACY_TAGS: &[(&str, &str)] = &[
    ("секрет", "secret"),
    ("устарело", "outdated"),
    ("форензика", "forensics"),
    ("КЕП", "qes"),
    ("PII", "pii"),
    ("вернулась", REOPENED_TAG),
    ("вне скоупа", foca_analysis::findings::OUT_OF_SCOPE_TAG),
    ("архив", "archive"),
];

/// Replaces legacy Russian tags with their codes; user tags stay as they are, duplicates go.
fn migrate_tags(tags: Vec<String>) -> Vec<String> {
    let mut out: Vec<String> = Vec::with_capacity(tags.len());
    for t in tags {
        let t = LEGACY_TAGS
            .iter()
            .find(|(old, _)| *old == t)
            .map_or(t, |(_, code)| (*code).to_string());
        if !out.contains(&t) {
            out.push(t);
        }
    }
    out
}

/// Tags the engine owns and recomputes on every analysis (scope marker, CDN edge provider): the
/// stored list follows the latest result for them, user tags are kept.
fn engine_owned_tag(t: &str) -> bool {
    t == foca_analysis::findings::OUT_OF_SCOPE_TAG || t.starts_with("cdn_edge:")
}

/// Returns `true` if the document comes from a web archive (Wayback, Common Crawl, Arquivo)
/// or was imported manually, i.e. it is not evidence from the live site.
pub fn is_archive_doc(source: &str, url: &str) -> bool {
    if matches!(source, "wayback" | "cc" | "arquivo" | "local") {
        return true;
    }
    let u = url.to_ascii_lowercase();
    let host = u
        .split("://")
        .nth(1)
        .unwrap_or("")
        .split(['/', ':', '?'])
        .next()
        .unwrap_or("");
    host.ends_with("archive.org")
        || host.ends_with("arquivo.pt")
        || host.contains("commoncrawl")
        || (u.contains("/web/") && u.contains("id_/"))
}

fn setup(conn: &Connection) -> Result<()> {
    conn.busy_timeout(std::time::Duration::from_secs(10))?;
    conn.pragma_update(None, "journal_mode", "WAL")?;
    conn.pragma_update(None, "foreign_keys", "ON")?;
    conn.pragma_update(None, "synchronous", "NORMAL")?;
    Ok(())
}

fn json<T: Serialize>(v: &T) -> Result<String> {
    Ok(serde_json::to_string(v)?)
}

fn rule_errors(e: &[RuleError]) -> String {
    e.iter()
        .map(|e| {
            if e.rule.is_empty() {
                e.message.clone()
            } else {
                format!("{}: {}", e.rule, e.message)
            }
        })
        .collect::<Vec<_>>()
        .join("; ")
}

fn in_list(ids: &[u64]) -> String {
    ids.iter()
        .map(|i| i.to_string())
        .collect::<Vec<_>>()
        .join(",")
}

/// An open project file.
pub struct ProjectDb {
    conn: Connection,
    path: PathBuf,
    id: String,
    clock: Arc<dyn Clock>,
}

impl ProjectDb {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn create(
        path: &Path,
        id: &str,
        name: &str,
        client: &str,
        domain: &str,
        now: &str,
        scope: &ScopeDto,
        clock: Arc<dyn Clock>,
    ) -> Result<ProjectDb> {
        let conn = Connection::open(path)?;
        setup(&conn)?;
        schema::migrate(&conn, schema::PROJECT_MIGRATIONS)?;
        conn.execute(
            "INSERT INTO project (id, name, client, domain, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?5, ?5)",
            params![id, name, client, domain, now],
        )?;
        conn.execute(
            "INSERT INTO scope (id, json) VALUES (1, ?1)",
            [json(scope)?],
        )?;
        Ok(ProjectDb {
            conn,
            path: path.to_path_buf(),
            id: id.to_string(),
            clock,
        })
    }

    /// Opens an existing project file, migrating it to the current schema.
    pub fn open(path: &Path, clock: Arc<dyn Clock>) -> Result<ProjectDb> {
        let conn = Connection::open(path)?;
        setup(&conn)?;
        schema::migrate(&conn, schema::PROJECT_MIGRATIONS)?;
        let id: String = conn
            .query_row("SELECT id FROM project LIMIT 1", [], |r| r.get(0))
            .optional()?
            .ok_or_else(|| StoreError::NotFound(format!("проект в {}", path.display())))?;
        Ok(ProjectDb {
            conn,
            path: path.to_path_buf(),
            id,
            clock,
        })
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Gives direct access to the connection (for debugging and migration tests).
    pub fn conn(&self) -> &Connection {
        &self.conn
    }

    pub fn schema_version(&self) -> Result<u32> {
        schema::user_version(&self.conn)
    }

    /// Exports a self-contained, WAL-consolidated snapshot of the SQLite project database
    /// using `VACUUM INTO` into a temporary file, then removes the temporary file.
    pub fn export_sqlite_bytes(&self) -> Result<Vec<u8>> {
        let mut tmp = self.path.clone();
        let pid = std::process::id();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        tmp.set_file_name(format!(".{}.export-{pid}-{nanos}.tmp", self.id));
        let _ = std::fs::remove_file(&tmp);
        let tmp_str = tmp.to_string_lossy().to_string();
        let res = self.conn.execute("VACUUM INTO ?1", [&tmp_str]);
        let bytes = match res {
            Ok(_) => std::fs::read(&tmp),
            Err(e) => {
                let _ = std::fs::remove_file(&tmp);
                return Err(StoreError::Sqlite(e));
            }
        };
        let _ = std::fs::remove_file(&tmp);
        Ok(bytes?)
    }

    /// Rewrites the project id (and optionally name) inside an imported project database.
    pub fn rewrite_identity(&mut self, new_id: &str, new_name: Option<&str>) -> Result<()> {
        let now = self.now();
        let tx = self.conn.unchecked_transaction()?;
        tx.execute(
            "UPDATE project SET id = ?1, updated_at = ?2",
            params![new_id, now],
        )?;
        if let Some(name) = new_name {
            tx.execute("UPDATE project SET name = ?1", [name])?;
        }
        tx.commit()?;
        self.id = new_id.to_string();
        Ok(())
    }

    /// Updates `documents.local_path` entries according to `mapping` (old path -> restored path),
    /// clearing any unmapped `local_path` values so imported DBs can never reference arbitrary local files.
    pub fn remap_or_clear_doc_local_paths(
        &self,
        mapping: &BTreeMap<String, String>,
    ) -> Result<usize> {
        let tx = self.conn.unchecked_transaction()?;
        let mut updated = 0usize;
        for (old, new) in mapping {
            updated += tx.execute(
                "UPDATE documents SET local_path = ?1 WHERE local_path = ?2",
                params![new, old],
            )?;
        }
        if mapping.is_empty() {
            tx.execute(
                "UPDATE documents SET local_path = NULL WHERE local_path IS NOT NULL",
                [],
            )?;
        } else {
            let mut st =
                tx.prepare("SELECT id, local_path FROM documents WHERE local_path IS NOT NULL")?;
            let rows: Vec<(i64, String)> = st
                .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
                .collect::<std::result::Result<Vec<_>, _>>()?;
            drop(st);
            let valid_targets: std::collections::BTreeSet<&str> =
                mapping.values().map(String::as_str).collect();
            for (doc_id, lp) in rows {
                if !valid_targets.contains(lp.as_str()) {
                    tx.execute(
                        "UPDATE documents SET local_path = NULL WHERE id = ?1",
                        [doc_id],
                    )?;
                }
            }
        }
        tx.commit()?;
        Ok(updated)
    }

    /// Updates `documents.local_path` entries according to `mapping` (old path -> restored path).
    pub fn remap_doc_local_paths(&self, mapping: &BTreeMap<String, String>) -> Result<usize> {
        if mapping.is_empty() {
            return Ok(0);
        }
        let tx = self.conn.unchecked_transaction()?;
        let mut updated = 0usize;
        for (old, new) in mapping {
            updated += tx.execute(
                "UPDATE documents SET local_path = ?1 WHERE local_path = ?2",
                params![new, old],
            )?;
        }
        tx.commit()?;
        Ok(updated)
    }

    pub(crate) fn now(&self) -> String {
        iso(self.clock.now())
    }

    // ---------------- Project and scope ----------------

    pub fn info(&self) -> Result<ProjectInfo> {
        Ok(self.conn.query_row(
            "SELECT id, name, client, domain, created_at, archived, notes FROM project LIMIT 1",
            [],
            |r| {
                Ok(ProjectInfo {
                    id: r.get(0)?,
                    name: r.get(1)?,
                    client: r.get(2)?,
                    domain: r.get(3)?,
                    created_at: r.get(4)?,
                    archived: r.get(5)?,
                    notes: r.get(6)?,
                })
            },
        )?)
    }

    pub fn update_info(&self, p: &ProjectPatch) -> Result<ProjectInfo> {
        let now = self.now();
        let tx = self.conn.unchecked_transaction()?;
        if let Some(v) = &p.name {
            tx.execute("UPDATE project SET name = ?1", [v])?;
        }
        if let Some(v) = &p.client {
            tx.execute("UPDATE project SET client = ?1", [v])?;
            let mut s = self.scope_get()?;
            s.client = v.clone();
            tx.execute("UPDATE scope SET json = ?1 WHERE id = 1", [json(&s)?])?;
        }
        if let Some(v) = &p.notes {
            tx.execute("UPDATE project SET notes = ?1", [v])?;
        }
        if let Some(v) = p.archived {
            tx.execute("UPDATE project SET archived = ?1", [v])?;
        }
        tx.execute("UPDATE project SET updated_at = ?1", [now])?;
        tx.commit()?;
        self.info()
    }

    pub fn scope_get(&self) -> Result<ScopeDto> {
        let j: String = self
            .conn
            .query_row("SELECT json FROM scope WHERE id = 1", [], |r| r.get(0))?;
        Ok(serde_json::from_str(&j)?)
    }

    pub fn scope_set(&self, s: &ScopeDto) -> Result<ScopeDto> {
        self.conn.execute(
            "INSERT INTO scope (id, json) VALUES (1, ?1) ON CONFLICT(id) DO UPDATE SET json = excluded.json",
            [json(s)?],
        )?;
        self.scope_get()
    }

    /// Returns the scope used by core checks (`Scope::allows_host`, active checks).
    pub fn core_scope(&self) -> Result<Scope> {
        Ok(Scope::from(&self.scope_get()?))
    }

    // ---------------- Documents ----------------

    pub(crate) fn doc_by_sha(&self, sha: &str) -> Result<Option<u64>> {
        Ok(self
            .conn
            .query_row("SELECT id FROM documents WHERE sha256 = ?1", [sha], |r| {
                r.get::<_, i64>(0)
            })
            .optional()?
            .map(|i| i as u64))
    }

    /// Adds a document. No duplicate is created for a known SHA-256 (or, without a hash, a known URL).
    pub fn add_document(&self, d: &AddDoc) -> Result<DocAdded> {
        if let Some(sha) = d.sha256.as_deref().filter(|s| !s.is_empty()) {
            if let Some(id) = self.doc_by_sha(sha)? {
                return Ok(DocAdded { id, existing: true });
            }
        } else if let Some(url) = &d.url {
            let ex: Option<i64> = self
                .conn
                .query_row(
                    "SELECT id FROM documents WHERE url = ?1 LIMIT 1",
                    [url],
                    |r| r.get(0),
                )
                .optional()?;
            if let Some(id) = ex {
                return Ok(DocAdded {
                    id: id as u64,
                    existing: true,
                });
            }
        }
        // For a web archive copy (`.../web/<ts>id_/https://site/x.pdf`) the document host is the host of the original.
        let host = d
            .url
            .as_deref()
            .map(|u| archive_original(u).unwrap_or(u))
            .and_then(foca_analysis::util::url_host);
        let ext = d
            .name
            .rsplit_once('.')
            .map(|(_, e)| e.to_lowercase())
            .unwrap_or_default();
        let found = d.found_at.clone().unwrap_or_else(|| self.now());
        let downloaded =
            matches!(d.status, DocStatus::Downloaded | DocStatus::Analyzed).then(|| self.now());
        self.conn.execute(
            "INSERT INTO documents (url, host, name, ext, local_path, sha256, status, size, mime, source, found_at, downloaded_at, first_scan)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
            params![
                d.url,
                host,
                d.name,
                ext,
                d.local_path,
                d.sha256.as_deref().filter(|s| !s.is_empty()),
                status_str(d.status),
                d.size as i64,
                d.mime,
                d.source,
                found,
                downloaded,
                d.first_scan,
            ],
        )?;
        Ok(DocAdded {
            id: self.conn.last_insert_rowid() as u64,
            existing: false,
        })
    }

    /// Marks a document as downloaded. If another document already has the same SHA-256, this
    /// record is removed as a duplicate and the existing id is returned (`existing: true`).
    pub fn set_downloaded(
        &self,
        id: u64,
        sha256: &str,
        size: u64,
        local_path: Option<&str>,
        mime: Option<&str>,
    ) -> Result<DocAdded> {
        if let Some(other) = self.doc_by_sha(sha256)?.filter(|o| *o != id) {
            let tx = self.conn.unchecked_transaction()?;
            tx.execute(
                "UPDATE tasks SET doc_id = ?1 WHERE doc_id = ?2",
                params![other as i64, id as i64],
            )?;
            tx.execute("DELETE FROM documents WHERE id = ?1", [id as i64])?;
            tx.commit()?;
            return Ok(DocAdded {
                id: other,
                existing: true,
            });
        }
        let n = self.conn.execute(
            "UPDATE documents SET sha256 = ?2, size = ?3, local_path = COALESCE(?4, local_path),
                 mime = COALESCE(?5, mime), status = 'downloaded', downloaded_at = ?6, error = NULL
             WHERE id = ?1",
            params![id as i64, sha256, size as i64, local_path, mime, self.now()],
        )?;
        if n == 0 {
            return Err(StoreError::NotFound(format!("документ {id}")));
        }
        Ok(DocAdded {
            id,
            existing: false,
        })
    }

    /// Stores the metadata and a text excerpt (up to 64 KiB) and sets the status to `analyzed`.
    pub fn set_analyzed(&self, id: u64, meta: &Metadata, text: Option<&str>) -> Result<()> {
        // Personal data is summarized and masked before it touches the database (text, FTS
        // index and metadata JSON alike).
        let (meta, text) = foca_analysis::pii::sanitize(meta, text);
        let meta = &meta;
        let text = text.as_deref();
        let excerpt = text.map(|t| {
            let mut end = t.len().min(64 * 1024);
            while !t.is_char_boundary(end) {
                end -= 1;
            }
            &t[..end]
        });
        let n = self.conn.execute(
            "UPDATE documents SET metadata_json = ?2, text_excerpt = ?3, status = 'analyzed', error = NULL,
                 extractor_rev = ?4, extractor_ver = ?5 WHERE id = ?1",
            params![id as i64, json(meta)?, excerpt, EXTRACTOR.0, EXTRACTOR.1],
        )?;
        if n == 0 {
            return Err(StoreError::NotFound(format!("документ {id}")));
        }
        Ok(())
    }

    fn row_doc(r: &Row) -> rusqlite::Result<(StoredDoc, Option<String>)> {
        let meta: Option<String> = r.get(10)?;
        let deleted: Option<String> = r.get(12)?;
        Ok((
            StoredDoc {
                doc: Document {
                    id: r.get::<_, i64>(0)? as u64,
                    url: r.get(1)?,
                    host: r.get(2)?,
                    name: r.get(3)?,
                    ext: r.get(4)?,
                    sha256: r.get::<_, Option<String>>(5)?.unwrap_or_default(),
                    status: parse_status(&r.get::<_, String>(6)?),
                    size: r.get::<_, i64>(7)? as u64,
                    source: r.get(8)?,
                    error: r.get(9)?,
                    found_at: None,
                    metadata: None,
                },
                first_scan: r.get(11)?,
                deleted: deleted.is_some(),
                text: r.get(13)?,
                local_path: r.get(14)?,
                error_kind: r.get(15)?,
            },
            meta,
        ))
    }

    /// Returns all documents, including deleted ones if `include_deleted` is set.
    pub fn documents(&self, include_deleted: bool) -> Result<Vec<StoredDoc>> {
        let sql = format!(
            "SELECT id, url, host, name, ext, sha256, status, size, source, error, metadata_json, first_scan, deleted_at, text_excerpt, local_path, error_kind
             FROM documents {} ORDER BY id",
            if include_deleted {
                ""
            } else {
                "WHERE deleted_at IS NULL"
            }
        );
        let mut st = self.conn.prepare(&sql)?;
        let rows = st.query_map([], Self::row_doc)?;
        let mut out = Vec::new();
        for r in rows {
            let (mut d, meta) = r?;
            if let Some(m) = meta {
                d.doc.metadata = Some(serde_json::from_str(&m)?);
            }
            out.push(d);
        }
        Ok(out)
    }

    pub fn document(&self, id: u64) -> Result<StoredDoc> {
        self.documents(true)?
            .into_iter()
            .find(|d| d.doc.id == id)
            .ok_or_else(|| StoreError::NotFound(format!("документ {id}")))
    }

    fn record_undo(&self, action: &str, payload: &Value) -> Result<()> {
        self.conn.execute(
            "INSERT INTO undo_log (time, action, payload_json) VALUES (?1, ?2, ?3)",
            params![self.now(), action, json(payload)?],
        )?;
        Ok(())
    }

    /// Implements `doc_delete`: soft deletion (trash) plus an undo log entry.
    pub fn delete_documents(&self, ids: &[u64]) -> Result<usize> {
        if ids.is_empty() {
            return Ok(0);
        }
        let list = in_list(ids);
        let live: Vec<u64> = {
            let mut st = self.conn.prepare(&format!(
                "SELECT id FROM documents WHERE id IN ({list}) AND deleted_at IS NULL"
            ))?;
            let v = st
                .query_map([], |r| r.get::<_, i64>(0))?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            v.into_iter().map(|i| i as u64).collect()
        };
        if live.is_empty() {
            return Ok(0);
        }
        let tx = self.conn.unchecked_transaction()?;
        tx.execute(
            &format!(
                "UPDATE documents SET deleted_at = ?1 WHERE id IN ({})",
                in_list(&live)
            ),
            [self.now()],
        )?;
        self.record_undo("doc_delete", &serde_json::json!({ "ids": live }))?;
        tx.commit()?;
        Ok(live.len())
    }

    /// Implements `doc_restore`.
    pub fn restore_documents(&self, ids: &[u64]) -> Result<usize> {
        if ids.is_empty() {
            return Ok(0);
        }
        Ok(self.conn.execute(
            &format!(
                "UPDATE documents SET deleted_at = NULL WHERE id IN ({}) AND deleted_at IS NOT NULL",
                in_list(ids)
            ),
            [],
        )?)
    }

    /// Undoes the most recent logged action. Returns `None` if there is nothing to undo.
    pub fn undo_last(&self) -> Result<Option<UndoEntry>> {
        let e = self.undo_list()?.into_iter().rev().find(|e| !e.undone);
        let Some(mut e) = e else { return Ok(None) };
        let tx = self.conn.unchecked_transaction()?;
        if e.action == "doc_delete" {
            let ids: Vec<u64> = serde_json::from_value(e.payload["ids"].clone())?;
            self.restore_documents(&ids)?;
        }
        tx.execute("UPDATE undo_log SET undone = 1 WHERE id = ?1", [e.id])?;
        tx.commit()?;
        e.undone = true;
        Ok(Some(e))
    }

    pub fn undo_list(&self) -> Result<Vec<UndoEntry>> {
        let mut st = self
            .conn
            .prepare("SELECT id, time, action, payload_json, undone FROM undo_log ORDER BY id")?;
        let rows = st.query_map([], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, bool>(4)?,
            ))
        })?;
        let mut out = Vec::new();
        for r in rows {
            let (id, time, action, p, undone) = r?;
            out.push(UndoEntry {
                id,
                time,
                action,
                payload: serde_json::from_str(&p)?,
                undone,
            });
        }
        Ok(out)
    }

    /// Permanently removes trashed documents deleted before `before` (ISO timestamp).
    pub fn purge_deleted(&self, before: &str) -> Result<usize> {
        Ok(self.conn.execute(
            "DELETE FROM documents WHERE deleted_at IS NOT NULL AND deleted_at < ?1",
            [before],
        )?)
    }

    // ---------------- Analysis and findings ----------------

    /// Loads the stored triage state to seed the next analysis.
    pub fn prev_state(&self, scan_id: Option<&str>) -> Result<PrevState> {
        let mut st = self.conn.prepare(
            "SELECT id, status, sev_override, notes_json, tags_json, photos_json, first_scan, fixed_scan, data_json FROM findings",
        )?;
        let rows = st.query_map([], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, Option<String>>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, String>(4)?,
                r.get::<_, String>(5)?,
                r.get::<_, Option<String>>(6)?,
                r.get::<_, Option<String>>(7)?,
                r.get::<_, String>(8)?,
            ))
        })?;
        let mut findings = BTreeMap::new();
        for r in rows {
            let (id, status, sev, notes, tags, photos, fs, fx, data) = r?;
            let time = serde_json::from_str::<Value>(&data)?
                .get("time")
                .and_then(Value::as_str)
                .map(str::to_string);
            findings.insert(
                id as u64,
                PrevFinding {
                    status: parse_finding_status(&status)?,
                    sev: sev.as_deref().map(parse_sev),
                    notes: serde_json::from_str(&notes)?,
                    tags: serde_json::from_str(&tags)?,
                    photos: serde_json::from_str(&photos)?,
                    first_scan: fs,
                    fixed_scan: fx,
                    time,
                },
            );
        }
        Ok(PrevState {
            findings,
            scan_id: scan_id.map(str::to_string),
            now: Some(self.clock.now()),
            rules: self.rule_set().ok().filter(|r| !r.is_empty()),
        })
    }

    /// Documents as the analysis sees them: storage files get the linking site's host.
    pub fn analysis_documents(&self) -> Result<Vec<StoredDoc>> {
        let mut docs = self.documents(true)?;
        let prov = self
            .setting(PROVENANCE_KEY)?
            .and_then(|v| serde_json::from_value(v).ok());
        let mut refs: Vec<&mut Document> = docs.iter_mut().map(|d| &mut d.doc).collect();
        crate::storage_docs::attribute_storage(&mut refs, &prov.unwrap_or_default());
        Ok(docs)
    }

    /// Runs a full analysis of the project documents and stores the result.
    pub fn run_analysis(&self, scan_id: Option<&str>) -> Result<Analysis> {
        let docs = self.analysis_documents()?;
        let prev = self.prev_state(scan_id)?;
        let inputs: Vec<DocInput> = docs
            .iter()
            .map(|d| DocInput {
                doc: &d.doc,
                text: d.text.as_deref(),
                first_scan: d.first_scan.as_deref(),
                deleted: d.deleted,
                thumb_diff: None,
            })
            .collect();
        let a = analyze(&inputs, &self.core_scope()?, &prev);
        self.apply_analysis(&a, scan_id)?;
        Ok(a)
    }

    /// Stores an analysis result: entities are replaced, findings are upserted with their triage
    /// preserved. Findings that disappear during a scan (`scan_id`) become `fixed` with `fixed_scan`;
    /// outside a scan they are retired (hidden, triage kept). A retired finding never becomes fixed.
    pub fn apply_analysis(&self, a: &Analysis, scan_id: Option<&str>) -> Result<()> {
        let now = self.now();
        let tx = self.conn.unchecked_transaction()?;
        let was_live = crate::revisions::live_finding_ids(&tx)?;
        let v = serde_json::to_value(a)?;
        for k in ENTITY_KINDS {
            if let Some(x) = v.get(*k) {
                tx.execute(
                    "INSERT INTO entities (kind, json, updated_at) VALUES (?1, ?2, ?3)
                     ON CONFLICT(kind) DO UPDATE SET json = excluded.json, updated_at = excluded.updated_at",
                    params![k, json(x)?, now],
                )?;
            }
        }
        // A rescan never resets "fixed": archive copies do not reopen the finding, and a finding seen
        // again on the live site gets the reopened tag while keeping the user's status.
        let was_fixed: BTreeSet<u64> = {
            let mut st = tx.prepare("SELECT id FROM findings WHERE status = 'fixed'")?;
            let v = st
                .query_map([], |r| r.get::<_, i64>(0))?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            v.into_iter().map(|i| i as u64).collect()
        };
        tx.execute("UPDATE findings SET present = 0", [])?;
        // Per-port copies merged into one finding: their triage moved to it, the rows go.
        for id in &a.dropped {
            tx.execute("DELETE FROM findings WHERE id = ?1", params![*id as i64])?;
        }
        for f in &a.findings {
            tx.execute(
                "INSERT INTO findings (id, sev, status, notes_json, tags_json, photos_json, provenance_json, data_json, first_scan, present, created_at, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 1, ?10, ?10)
                 ON CONFLICT(id) DO UPDATE SET
                    sev = excluded.sev,
                    provenance_json = excluded.provenance_json,
                    data_json = excluded.data_json,
                    present = 1,
                    first_scan = COALESCE(findings.first_scan, excluded.first_scan),
                    updated_at = excluded.updated_at",
                params![
                    f.id as i64,
                    sev_str(f.sev),
                    fstatus_str(f.status),
                    json(&f.notes)?,
                    json(&f.tags)?,
                    json(&f.photos)?,
                    json(&f.provenance)?,
                    json(f)?,
                    f.first_scan,
                    now,
                ],
            )?;
            // Engine-owned tags (out of scope, CDN edge) follow the latest result so a scope change
            // or a new CDN match takes effect on rescan; user tags and legacy codes are kept.
            let stored: String = tx.query_row(
                "SELECT tags_json FROM findings WHERE id = ?1",
                [f.id as i64],
                |r| r.get(0),
            )?;
            let old: Vec<String> = serde_json::from_str(&stored).unwrap_or_default();
            let mut tags: Vec<String> = migrate_tags(old.clone())
                .into_iter()
                .filter(|t| !engine_owned_tag(t))
                .collect();
            for t in f.tags.iter().filter(|t| engine_owned_tag(t)) {
                if !tags.contains(t) {
                    tags.push(t.clone());
                }
            }
            if tags != old {
                tx.execute(
                    "UPDATE findings SET tags_json = ?2 WHERE id = ?1",
                    params![f.id as i64, json(&tags)?],
                )?;
            }
        }
        if scan_id.is_some() && !was_fixed.is_empty() {
            let live_docs: BTreeSet<u64> = {
                let mut st = tx.prepare("SELECT id, source, url FROM documents")?;
                let v = st
                    .query_map([], |r| {
                        Ok((
                            r.get::<_, i64>(0)?,
                            r.get::<_, Option<String>>(1)?,
                            r.get::<_, Option<String>>(2)?,
                        ))
                    })?
                    .collect::<rusqlite::Result<Vec<_>>>()?;
                v.into_iter()
                    .filter(|(_, src, url)| {
                        !is_archive_doc(src.as_deref().unwrap_or(""), url.as_deref().unwrap_or(""))
                    })
                    .map(|(id, _, _)| id as u64)
                    .collect()
            };
            for f in a.findings.iter().filter(|f| was_fixed.contains(&f.id)) {
                let docs = Self::finding_doc_ids(f);
                let live = docs.is_empty() || !docs.is_disjoint(&live_docs);
                if !live {
                    continue;
                }
                let tags: String = tx.query_row(
                    "SELECT tags_json FROM findings WHERE id = ?1",
                    [f.id as i64],
                    |r| r.get(0),
                )?;
                let mut tags = migrate_tags(serde_json::from_str(&tags).unwrap_or_default());
                if !tags.iter().any(|t| t == REOPENED_TAG) {
                    tags.push(REOPENED_TAG.into());
                    tx.execute(
                        "UPDATE findings SET tags_json = ?2, updated_at = ?3 WHERE id = ?1",
                        params![f.id as i64, json(&tags)?, now],
                    )?;
                }
            }
        }
        if let Some(sid) = scan_id {
            // A document deleted by the user is not the same as an issue fixed by the client: a finding
            // backed by a deleted document must not become fixed.
            let by_deleted = self.findings_of_deleted_docs()?;
            let gone = a.resolved.iter().filter(|id| was_live.contains(id));
            for id in gone.filter(|id| !by_deleted.contains(id)) {
                tx.execute(
                    "UPDATE findings SET status = 'fixed', fixed_scan = ?2, updated_at = ?3
                     WHERE id = ?1 AND status NOT IN ('false', 'fixed')",
                    params![*id as i64, sid, now],
                )?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    fn row_finding(r: &Row) -> rusqlite::Result<[Option<String>; 9]> {
        Ok([
            Some(r.get(0)?),
            Some(r.get(1)?),
            r.get(2)?,
            Some(r.get(3)?),
            Some(r.get(4)?),
            Some(r.get(5)?),
            r.get(6)?,
            r.get(7)?,
            Some(r.get(8)?),
        ])
    }

    fn merge_finding(c: [Option<String>; 9]) -> Result<Finding> {
        let [data, status, sev_o, notes, tags, photos, fs, fx, sev] = c;
        let mut f: Finding = serde_json::from_str(data.as_deref().unwrap_or("{}"))?;
        f.status = parse_finding_status(status.as_deref().unwrap_or("new"))?;
        f.sev = parse_sev(sev_o.as_deref().or(sev.as_deref()).unwrap_or("info"));
        f.notes = serde_json::from_str(notes.as_deref().unwrap_or("[]"))?;
        f.tags = migrate_tags(serde_json::from_str(tags.as_deref().unwrap_or("[]"))?);
        f.photos = serde_json::from_str(photos.as_deref().unwrap_or("[]"))?;
        f.first_scan = fs.or(f.first_scan);
        f.fixed_scan = fx;
        Ok(f)
    }

    const FINDING_COLS: &'static str =
        "data_json, status, sev_override, notes_json, tags_json, photos_json, first_scan, fixed_scan, sev";

    /// Returns the evidence documents of a finding (`doc`, `rel.docs`, `provenance.docs`).
    pub fn finding_doc_ids(f: &Finding) -> BTreeSet<u64> {
        f.doc
            .iter()
            .chain(&f.rel.docs)
            .chain(&f.provenance.docs)
            .copied()
            .collect()
    }

    /// Returns findings missing from the latest analysis whose evidence includes a document
    /// deleted by the user: they disappeared because of the deletion, not because of a fix.
    /// Such findings are hidden; their triage is kept so restoring the document brings them back.
    pub fn findings_of_deleted_docs(&self) -> Result<BTreeSet<u64>> {
        let deleted: BTreeSet<u64> = {
            let mut st = self
                .conn
                .prepare("SELECT id FROM documents WHERE deleted_at IS NOT NULL")?;
            let v = st
                .query_map([], |r| r.get::<_, i64>(0))?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            v.into_iter().map(|i| i as u64).collect()
        };
        if deleted.is_empty() {
            return Ok(BTreeSet::new());
        }
        let mut st = self
            .conn
            .prepare("SELECT id, data_json FROM findings WHERE present = 0")?;
        let rows = st
            .query_map([], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?)))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows
            .into_iter()
            .filter(|(_, data)| {
                serde_json::from_str::<Finding>(data)
                    .map(|f| !Self::finding_doc_ids(&f).is_disjoint(&deleted))
                    .unwrap_or(false)
            })
            .map(|(id, _)| id as u64)
            .collect())
    }

    /// Deletes findings outright (rather than marking them fixed) when their underlying data proved
    /// unreliable, e.g. a port scan through a local VPN that accepts any connection. Returns the number deleted.
    pub fn findings_delete(&self, ids: &[u64]) -> Result<usize> {
        let mut n = 0;
        for id in ids {
            n += self
                .conn
                .execute("DELETE FROM findings WHERE id = ?1", params![*id as i64])?;
        }
        Ok(n)
    }

    /// Returns all findings with triage state, ordered by severity. Findings backed only by deleted
    /// documents and retired ones (`revisions::RETIRED`) are hidden.
    pub fn findings(&self) -> Result<Vec<Finding>> {
        let hidden = self.findings_of_deleted_docs()?;
        let mut st = self.conn.prepare(&format!(
            "SELECT {} FROM findings WHERE NOT ({})",
            Self::FINDING_COLS,
            crate::revisions::RETIRED
        ))?;
        let rows = st.query_map([], Self::row_finding)?;
        let mut out = Vec::new();
        for r in rows {
            let f = Self::merge_finding(r?)?;
            if !hidden.contains(&f.id) {
                out.push(f);
            }
        }
        out.sort_by(|a, b| a.sev.cmp(&b.sev).then(a.title.cmp(&b.title)));
        Ok(out)
    }

    pub fn finding(&self, id: u64) -> Result<Finding> {
        let c = self
            .conn
            .query_row(
                &format!("SELECT {} FROM findings WHERE id = ?1", Self::FINDING_COLS),
                [id as i64],
                Self::row_finding,
            )
            .optional()?
            .ok_or_else(|| StoreError::NotFound(format!("находка {id}")))?;
        Self::merge_finding(c)
    }

    /// Implements `finding_set_status`.
    pub fn finding_set_status(&self, id: u64, status: &str) -> Result<Finding> {
        let s = parse_finding_status(status)?;
        self.finding_update(
            id,
            &FindingPatch {
                status: Some(s),
                ..Default::default()
            },
        )
    }

    /// Implements `finding_update`: user severity override, notes, tags, photos and status.
    pub fn finding_update(&self, id: u64, p: &FindingPatch) -> Result<Finding> {
        self.finding(id)?;
        let now = self.now();
        let tx = self.conn.unchecked_transaction()?;
        if let Some(s) = p.sev {
            tx.execute(
                "UPDATE findings SET sev_override = ?2 WHERE id = ?1",
                params![id as i64, sev_str(s)],
            )?;
        }
        if let Some(v) = &p.notes {
            tx.execute(
                "UPDATE findings SET notes_json = ?2 WHERE id = ?1",
                params![id as i64, json(v)?],
            )?;
        }
        if let Some(v) = &p.tags {
            tx.execute(
                "UPDATE findings SET tags_json = ?2 WHERE id = ?1",
                params![id as i64, json(v)?],
            )?;
        }
        if let Some(v) = &p.photos {
            tx.execute(
                "UPDATE findings SET photos_json = ?2 WHERE id = ?1",
                params![id as i64, json(v)?],
            )?;
        }
        if let Some(s) = p.status {
            tx.execute(
                "UPDATE findings SET status = ?2 WHERE id = ?1",
                params![id as i64, fstatus_str(s)],
            )?;
        }
        tx.execute(
            "UPDATE findings SET updated_at = ?2 WHERE id = ?1",
            params![id as i64, now],
        )?;
        tx.commit()?;
        self.finding(id)
    }

    // ---------------- Entities ----------------

    /// Returns an entity from the latest analysis (`people`, `hosts`, ...), or `null` if absent.
    pub fn entity(&self, kind: &str) -> Result<Value> {
        let j: Option<String> = self
            .conn
            .query_row("SELECT json FROM entities WHERE kind = ?1", [kind], |r| {
                r.get(0)
            })
            .optional()?;
        Ok(match j {
            Some(j) => serde_json::from_str(&j)?,
            None => Value::Null,
        })
    }

    fn entity_vec<T: serde::de::DeserializeOwned>(&self, kind: &str) -> Result<Vec<T>> {
        match self.entity(kind)? {
            Value::Null => Ok(vec![]),
            v => Ok(serde_json::from_value(v)?),
        }
    }

    /// Stores per-person breach data (HIBP); written by the leaks module.
    pub fn set_leaks(&self, leaks: &BTreeMap<String, Value>) -> Result<()> {
        self.conn.execute(
            "INSERT INTO entities (kind, json, updated_at) VALUES ('leaks', ?1, ?2)
             ON CONFLICT(kind) DO UPDATE SET json = excluded.json, updated_at = excluded.updated_at",
            params![json(leaks)?, self.now()],
        )?;
        Ok(())
    }

    // ---------------- Scans ----------------

    /// Starts a scan by inserting a `running` record.
    pub fn scan_start(&self, id: &str, profile_id: &str, active: bool) -> Result<()> {
        self.conn.execute(
            "INSERT INTO scans (id, profile, active, status, started_at) VALUES (?1, ?2, ?3, 'running', ?4)",
            params![id, profile_id, active, self.now()],
        )?;
        Ok(())
    }

    /// Saves the full scan record (`done`/`stopped`, statistics and the snapshot used for diffs).
    pub fn scan_save(&self, s: &Scan) -> Result<()> {
        let mut stats = serde_json::to_value(s)?;
        if let Some(o) = stats.as_object_mut() {
            o.remove("snapshot");
        }
        self.conn.execute(
            "INSERT INTO scans (id, profile, active, status, reason, started_at, finished_at, stats_json, snapshot_json)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
             ON CONFLICT(id) DO UPDATE SET profile = excluded.profile, active = excluded.active,
                status = excluded.status, reason = excluded.reason, started_at = excluded.started_at,
                finished_at = excluded.finished_at, stats_json = excluded.stats_json,
                snapshot_json = excluded.snapshot_json",
            params![
                s.id,
                s.profile_id,
                s.active,
                s.status,
                s.reason,
                s.started_at,
                s.finished_at,
                json(&stats)?,
                json(&s.snapshot)?,
            ],
        )?;
        Ok(())
    }

    /// Takes a snapshot of the current results for `Scan.snapshot` (scan diffing).
    pub fn scan_snapshot(&self) -> Result<api::ScanSnapshot> {
        let docs = self.documents(false)?;
        let hosts: Vec<api::Host> = self.entity_vec("hosts")?;
        let people: Vec<api::Person> = self.entity_vec("people")?;
        Ok(api::ScanSnapshot {
            docs: docs.iter().map(|d| d.doc.id).collect(),
            people: people.into_iter().map(|p| p.login).collect(),
            hosts: hosts.into_iter().map(|h| (h.name, h.tech)).collect(),
            findings: self
                .findings()?
                .into_iter()
                .filter(|f| f.status != FindingStatus::Fixed)
                .map(|f| (f.id.to_string(), f.sev))
                .collect(),
            tech: BTreeMap::new(),
        })
    }

    pub fn scans(&self) -> Result<Vec<Scan>> {
        let mut st = self.conn.prepare(
            "SELECT id, profile, active, status, reason, started_at, finished_at, stats_json, snapshot_json FROM scans ORDER BY started_at, id",
        )?;
        let rows = st.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, bool>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, Option<String>>(4)?,
                r.get::<_, String>(5)?,
                r.get::<_, Option<String>>(6)?,
                r.get::<_, String>(7)?,
                r.get::<_, Option<String>>(8)?,
            ))
        })?;
        let mut out = Vec::new();
        for r in rows {
            let (id, profile, active, status, reason, started, finished, stats, snap) = r?;
            let mut s: Scan = serde_json::from_str(&stats).unwrap_or_default();
            s.id = id;
            s.profile = profile_label(&profile).into();
            s.profile_id = profile;
            s.active = active;
            s.status = status;
            s.reason = reason;
            s.started_at = started;
            s.finished_at = finished;
            if s.trigger.is_empty() {
                s.trigger = "manual".into();
            }
            if let Some(j) = snap {
                s.snapshot = serde_json::from_str(&j)?;
            }
            out.push(s);
        }
        Ok(out)
    }

    // ---------------- Request log ----------------

    pub fn log_request(&self, r: &RequestLog) -> Result<i64> {
        let time = if r.time.is_empty() {
            self.now()
        } else {
            r.time.clone()
        };
        self.conn.execute(
            "INSERT INTO request_log (time, scan_id, module, method, url, host, status, bytes, active, error, note, ctype)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            params![
                time,
                r.scan_id,
                r.module,
                r.method,
                r.url,
                r.host,
                r.status,
                r.bytes as i64,
                r.active,
                r.error,
                r.note,
                r.ctype,
            ],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    /// Annotates requests already logged by a module during a scan (`url` as logged): the note,
    /// plus content type and size if the log did not have them. For each URL the latest
    /// unannotated entry is updated. Returns the number of annotated entries.
    pub fn annotate_requests(
        &self,
        scan_id: Option<&str>,
        module: &str,
        items: &[(String, String, Option<String>, u64)],
    ) -> Result<usize> {
        let tx = self.conn.unchecked_transaction()?;
        let mut n = 0;
        {
            let mut st = tx.prepare(
                "UPDATE request_log SET note = ?1, ctype = COALESCE(?2, ctype),
                    bytes = CASE WHEN bytes = 0 THEN ?3 ELSE bytes END
                 WHERE id = (SELECT id FROM request_log WHERE module = ?4 AND url = ?5
                    AND (?6 IS NULL OR scan_id = ?6) AND note IS NULL ORDER BY id DESC LIMIT 1)",
            )?;
            for (url, note, ctype, size) in items {
                n += st.execute(params![note, ctype, *size as i64, module, url, scan_id])?;
            }
        }
        tx.commit()?;
        Ok(n)
    }

    /// Returns the request log, oldest first; `active_only` keeps only requests sent to targets.
    pub fn requests(&self, scan_id: Option<&str>, active_only: bool) -> Result<Vec<RequestLog>> {
        let mut st = self.conn.prepare(
            "SELECT id, time, scan_id, module, method, url, host, status, bytes, active, error, note, ctype FROM request_log
             WHERE (?1 IS NULL OR scan_id = ?1) AND (?2 = 0 OR active = 1) ORDER BY id",
        )?;
        let rows = st.query_map(params![scan_id, active_only], |r| {
            Ok(RequestLog {
                id: r.get(0)?,
                time: r.get(1)?,
                scan_id: r.get(2)?,
                module: r.get(3)?,
                method: r.get(4)?,
                url: r.get(5)?,
                host: r.get(6)?,
                status: r.get(7)?,
                bytes: r.get::<_, i64>(8)? as u64,
                active: r.get(9)?,
                error: r.get(10)?,
                note: r.get(11)?,
                ctype: r.get(12)?,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    // ---------------- Download queue ----------------

    /// Enqueues a URL. Returns `None` if it is already queued.
    pub fn task_enqueue(
        &self,
        kind: &str,
        url: &str,
        source: &str,
        scan_id: Option<&str>,
    ) -> Result<Option<i64>> {
        let now = self.now();
        let n = self.conn.execute(
            "INSERT OR IGNORE INTO tasks (kind, url, source, scan_id, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?5, ?5)",
            params![kind, url, source, scan_id, now],
        )?;
        Ok((n > 0).then(|| self.conn.last_insert_rowid()))
    }

    fn row_task(r: &Row) -> rusqlite::Result<Task> {
        Ok(Task {
            id: r.get(0)?,
            kind: r.get(1)?,
            url: r.get(2)?,
            scan_id: r.get(3)?,
            source: r.get(4)?,
            state: TaskState::parse(&r.get::<_, String>(5)?),
            attempts: r.get::<_, i64>(6)? as u32,
            last_error: r.get(7)?,
            doc_id: r.get::<_, Option<i64>>(8)?.map(|i| i as u64),
        })
    }

    const TASK_COLS: &'static str =
        "id, kind, url, scan_id, source, state, attempts, last_error, doc_id";

    /// Claims up to `limit` queued tasks in queue order: `queued` becomes `downloading` and the
    /// attempt counter is incremented.
    pub fn task_claim(&self, kind: &str, limit: usize) -> Result<Vec<Task>> {
        self.task_claim_ranked(kind, limit, |_, _| ())
    }

    /// Like [`Self::task_claim`], but picks the queued tasks with the lowest `rank(url, source)`
    /// first (ties in queue order): the download stage uses it for its priority ladder.
    pub fn task_claim_ranked<K: Ord>(
        &self,
        kind: &str,
        limit: usize,
        rank: impl Fn(&str, &str) -> K,
    ) -> Result<Vec<Task>> {
        let tx = self.conn.unchecked_transaction()?;
        let ids: Vec<i64> = {
            let mut st = tx.prepare(
                "SELECT id, url, source FROM tasks WHERE kind = ?1 AND state = 'queued' ORDER BY id",
            )?;
            let mut v = st
                .query_map(params![kind], |r| {
                    Ok((
                        r.get::<_, i64>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, String>(2)?,
                    ))
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            v.sort_by_cached_key(|(id, url, source)| (rank(url, source), *id));
            v.into_iter().take(limit).map(|(id, _, _)| id).collect()
        };
        let now = self.now();
        for id in &ids {
            tx.execute(
                "UPDATE tasks SET state = 'downloading', attempts = attempts + 1, updated_at = ?2 WHERE id = ?1",
                params![id, now],
            )?;
        }
        tx.commit()?;
        let mut out = Vec::new();
        for id in ids {
            out.push(self.task(id)?);
        }
        Ok(out)
    }

    pub fn task(&self, id: i64) -> Result<Task> {
        self.conn
            .query_row(
                &format!("SELECT {} FROM tasks WHERE id = ?1", Self::TASK_COLS),
                [id],
                Self::row_task,
            )
            .optional()?
            .ok_or_else(|| StoreError::NotFound(format!("задача {id}")))
    }

    pub fn tasks(&self, state: Option<TaskState>) -> Result<Vec<Task>> {
        let mut st = self.conn.prepare(&format!(
            "SELECT {} FROM tasks WHERE (?1 IS NULL OR state = ?1) ORDER BY id",
            Self::TASK_COLS
        ))?;
        let rows = st.query_map([state.map(TaskState::as_str)], Self::row_task)?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    /// URLs of every task, in queue order: the documents the project already knows.
    pub fn task_urls(&self) -> Result<Vec<String>> {
        let mut st = self.conn.prepare("SELECT url FROM tasks ORDER BY id")?;
        let rows = st.query_map([], |r| r.get(0))?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    pub fn task_done(&self, id: i64, doc_id: Option<u64>) -> Result<()> {
        self.conn.execute(
            "UPDATE tasks SET state = 'done', doc_id = ?2, last_error = NULL, updated_at = ?3 WHERE id = ?1",
            params![id, doc_id.map(|d| d as i64), self.now()],
        )?;
        Ok(())
    }

    /// Records a failed download: the task is requeued while attempts are below `max_attempts`, otherwise it becomes `failed`.
    pub fn task_failed(&self, id: i64, err: &str, max_attempts: u32) -> Result<TaskState> {
        let t = self.task(id)?;
        let state = if t.attempts >= max_attempts {
            TaskState::Failed
        } else {
            TaskState::Queued
        };
        self.conn.execute(
            "UPDATE tasks SET state = ?2, last_error = ?3, updated_at = ?4 WHERE id = ?1",
            params![id, state.as_str(), err, self.now()],
        )?;
        Ok(state)
    }

    /// Resumes after a crash: interrupted `downloading` tasks go back to `queued`.
    /// Returns the number of pending tasks.
    pub fn tasks_resume(&self) -> Result<u32> {
        self.conn.execute(
            "UPDATE tasks SET state = 'queued', updated_at = ?1 WHERE state = 'downloading'",
            [self.now()],
        )?;
        Ok(self.task_counts()?.queued)
    }

    pub fn task_counts(&self) -> Result<TaskCounts> {
        let mut c = TaskCounts::default();
        let mut st = self
            .conn
            .prepare("SELECT state, COUNT(*) FROM tasks GROUP BY state")?;
        let rows = st.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))?;
        for r in rows {
            let (s, n) = r?;
            let n = n as u32;
            match TaskState::parse(&s) {
                TaskState::Queued => c.queued = n,
                TaskState::Downloading => c.downloading = n,
                TaskState::Done => c.done = n,
                TaskState::Failed => c.failed = n,
            }
        }
        Ok(c)
    }

    // ---------------- Reports ----------------

    pub fn report_add(&self, r: &Report) -> Result<Report> {
        let created = if r.created_at.is_empty() {
            self.now()
        } else {
            r.created_at.clone()
        };
        self.conn.execute(
            "INSERT INTO reports (name, tpl, fmt, lang, created_at, size, opts_json, result_json) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                r.name,
                r.tpl,
                r.fmt,
                r.lang,
                created,
                r.size,
                json(&r.opts)?,
                (!r.result.is_null()).then(|| json(&r.result)).transpose()?
            ],
        )?;
        let id = self.conn.last_insert_rowid() as u64;
        Ok(Report {
            id,
            created_at: created,
            ..r.clone()
        })
    }

    /// Implements `report_list`, newest first.
    pub fn reports(&self) -> Result<Vec<Report>> {
        let mut st = self.conn.prepare(
            "SELECT id, name, tpl, fmt, lang, created_at, size, opts_json, result_json FROM reports ORDER BY id DESC",
        )?;
        let rows = st.query_map([], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, String>(4)?,
                r.get::<_, String>(5)?,
                r.get::<_, String>(6)?,
                r.get::<_, String>(7)?,
                r.get::<_, Option<String>>(8)?,
            ))
        })?;
        let mut out = Vec::new();
        for r in rows {
            let (id, name, tpl, fmt, lang, created_at, size, opts, result) = r?;
            out.push(Report {
                id: id as u64,
                name,
                tpl,
                fmt,
                lang,
                created_at,
                size,
                opts: serde_json::from_str(&opts)?,
                result: match result {
                    Some(j) => serde_json::from_str(&j)?,
                    None => Value::Null,
                },
            });
        }
        Ok(out)
    }

    pub fn report_delete(&self, id: u64) -> Result<bool> {
        Ok(self
            .conn
            .execute("DELETE FROM reports WHERE id = ?1", [id as i64])?
            > 0)
    }

    // ---------------- Project settings ----------------

    pub fn setting(&self, key: &str) -> Result<Option<Value>> {
        let j: Option<String> = self
            .conn
            .query_row(
                "SELECT value_json FROM settings WHERE key = ?1",
                [key],
                |r| r.get(0),
            )
            .optional()?;
        Ok(match j {
            Some(j) => Some(serde_json::from_str(&j)?),
            None => None,
        })
    }

    pub fn set_setting(&self, key: &str, v: &Value) -> Result<()> {
        self.conn.execute(
            "INSERT INTO settings (key, value_json) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value_json = excluded.value_json",
            params![key, json(v)?],
        )?;
        Ok(())
    }

    /// User search rules of the project (empty config when unset or unreadable).
    pub fn rules_config(&self) -> Result<RulesConfig> {
        Ok(self
            .setting(RULES_KEY)?
            .and_then(|v| serde_json::from_value(v).ok())
            .unwrap_or_default())
    }

    /// Validates (compiles) and stores the user search rules; nothing is stored on error.
    pub fn set_rules_config(&self, cfg: &RulesConfig) -> Result<RulesConfig> {
        RuleSet::compile(cfg).map_err(|e| StoreError::Invalid(rule_errors(&e)))?;
        self.set_setting(RULES_KEY, &serde_json::to_value(cfg)?)?;
        Ok(cfg.clone())
    }

    /// The compiled rule set of the project (invalid stored rules yield an empty set).
    pub fn rule_set(&self) -> Result<RuleSet> {
        Ok(RuleSet::compile(&self.rules_config()?).unwrap_or_default())
    }

    // ---------------- Infrastructure records ----------------

    /// Inserts or replaces an infrastructure record (`kind`: `saas`, `tenant`, `mail_policy`,
    /// `cert`, `ct`, `cdn`, `origin`, `role`, `ptr`, `dns_enum`, `oos`; see `docs/API.md`).
    pub fn infra_put(&self, kind: &str, key: &str, v: &Value, scan: Option<&str>) -> Result<()> {
        self.conn.execute(
            "INSERT INTO infra (kind, key, json, scan, updated_at) VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(kind, key) DO UPDATE SET json = excluded.json, scan = excluded.scan,
             updated_at = excluded.updated_at",
            params![kind, key, json(v)?, scan, self.now()],
        )?;
        Ok(())
    }

    /// Records of one kind, ordered by key.
    pub fn infra_list(&self, kind: &str) -> Result<Vec<(String, Value)>> {
        let mut st = self
            .conn
            .prepare("SELECT key, json FROM infra WHERE kind = ?1 ORDER BY key")?;
        let rows = st.query_map([kind], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
        })?;
        let mut out = Vec::new();
        for r in rows {
            let (k, j) = r?;
            out.push((k, serde_json::from_str(&j)?));
        }
        Ok(out)
    }

    /// One record, or `None`.
    pub fn infra_get(&self, kind: &str, key: &str) -> Result<Option<Value>> {
        let j: Option<String> = self
            .conn
            .query_row(
                "SELECT json FROM infra WHERE kind = ?1 AND key = ?2",
                [kind, key],
                |r| r.get(0),
            )
            .optional()?;
        Ok(match j {
            Some(j) => Some(serde_json::from_str(&j)?),
            None => None,
        })
    }

    /// Deletes one record; returns `true` if it existed.
    pub fn infra_delete(&self, kind: &str, key: &str) -> Result<bool> {
        Ok(self.conn.execute(
            "DELETE FROM infra WHERE kind = ?1 AND key = ?2",
            [kind, key],
        )? > 0)
    }

    /// All records grouped by kind: `{ kind: [record, ...] }` (records in key order).
    pub fn infra_all(&self) -> Result<BTreeMap<String, Vec<Value>>> {
        let mut st = self
            .conn
            .prepare("SELECT kind, json FROM infra ORDER BY kind, key")?;
        let rows = st.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?;
        let mut out: BTreeMap<String, Vec<Value>> = BTreeMap::new();
        for r in rows {
            let (k, j) = r?;
            out.entry(k).or_default().push(serde_json::from_str(&j)?);
        }
        Ok(out)
    }

    // ---------------- Snapshot and summary ----------------

    /// Returns documents for the UI: database rows plus fields derived from the latest analysis.
    pub fn ui_docs(&self) -> Result<Vec<Doc>> {
        let analyzed: Vec<Doc> = self.entity_vec("docs")?;
        let by_id: BTreeMap<u64, Doc> = analyzed.into_iter().map(|d| (d.id, d)).collect();
        let prov: BTreeMap<String, DocProvenance> = self
            .setting(PROVENANCE_KEY)?
            .and_then(|v| serde_json::from_value(v).ok())
            .unwrap_or_default();
        let mut out = Vec::new();
        for d in self.analysis_documents()? {
            let st = ui_status(d.doc.status);
            let mut x = match by_id.get(&d.doc.id) {
                Some(a) if a.status == st => a.clone(),
                _ => Doc {
                    id: d.doc.id,
                    ext: d.doc.ext.clone(),
                    name: d.doc.name.clone(),
                    url: d.doc.url.clone().unwrap_or_default(),
                    host: d.doc.host.clone().unwrap_or_default(),
                    title: d
                        .doc
                        .name
                        .rsplit_once('.')
                        .map(|(a, _)| a.to_string())
                        .unwrap_or_else(|| d.doc.name.clone()),
                    size: d.doc.size.div_ceil(1024),
                    status: st.into(),
                    ..Default::default()
                },
            };
            x.deleted = d.deleted;
            x.first_scan = d.first_scan.clone();
            x.provenance = d.doc.url.as_ref().and_then(|u| prov.get(u)).cloned();
            if st == "error" {
                x.error_reason = d.doc.error.clone().filter(|e| !e.trim().is_empty());
                let kind = d
                    .error_kind
                    .clone()
                    .unwrap_or_else(|| DocErrorKind::Parse.as_str().into());
                // an HTTP status is known only for an HTTP failure of the fetch, never for a
                // parse error whose message happens to mention "HTTP NNN"
                x.http_status = if kind == DocErrorKind::Http.as_str() {
                    x.error_reason.as_deref().and_then(http_status_of)
                } else {
                    None
                };
                x.error_kind = Some(kind);
            } else {
                (x.error_reason, x.http_status, x.error_kind) = (None, None, None);
            }
            out.push(x);
        }
        Ok(out)
    }

    /// Implements `project_snapshot` in exactly the `Snapshot` shape from `docs/API.md`.
    pub fn snapshot(&self, settings: Value, scan: Value) -> Result<Snapshot> {
        let leaks: BTreeMap<String, Value> = match self.entity("leaks")? {
            Value::Object(m) => m.into_iter().collect(),
            _ => BTreeMap::new(),
        };
        Ok(Snapshot {
            project: self.info()?,
            scope: self.scope_get()?,
            docs: self.ui_docs()?,
            people: self.entity_vec("people")?,
            emails: self.entity_vec("emails")?,
            phones: self.entity_vec("phones")?,
            patterns: self.entity_vec("patterns")?,
            hosts: self.entity_vec("hosts")?,
            pcs: self.entity_vec("pcs")?,
            software: self.entity_vec("software")?,
            paths: self.entity_vec("paths")?,
            printers: self.entity_vec("printers")?,
            secrets: self.entity_vec("secrets")?,
            findings: self.findings()?,
            gps: self.entity_vec("gps")?,
            events: self.entity_vec("events")?,
            scans: self.scans()?,
            reports: self.reports()?,
            leaks,
            settings,
            scan,
            recon: Value::Null,
            ports: Value::Null,
            infra: Value::Null,
        })
    }

    /// Returns the summary used by `project_list`.
    /// True for a built-in reference case: marked on import, or (older cases) holding documents
    /// imported from the reference archive.
    pub fn is_reference_case(&self) -> Result<bool> {
        if self.setting(REFERENCE_CASE_KEY)?.and_then(|v| v.as_bool()) == Some(true) {
            return Ok(true);
        }
        Ok(self.conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM documents WHERE source = ?1)",
            [format!("zip:{REFERENCE_CASE_ARCHIVE}")],
            |r| r.get(0),
        )?)
    }

    pub fn summary(&self) -> Result<ProjectSummary> {
        let info = self.info()?;
        let scans = self.scans()?;
        let findings = self.findings()?;
        let docs: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM documents WHERE deleted_at IS NULL",
            [],
            |r| r.get(0),
        )?;
        let last = scans.last();
        let live = findings
            .iter()
            .filter(|f| {
                !matches!(
                    f.status,
                    FindingStatus::FalsePositive | FindingStatus::Fixed
                )
            })
            .count();
        Ok(ProjectSummary {
            id: info.id,
            name: info.name,
            client: info.client,
            created_at: info.created_at,
            archived: info.archived,
            last_scan_at: last.map(|s| s.finished_at.clone().unwrap_or(s.started_at.clone())),
            last_profile: last.map(|s| s.profile.clone()),
            scans: scans.len() as u32,
            docs: docs as u32,
            findings: live as u32,
            risk: foca_analysis::findings::risk(&findings, !scans.is_empty() || docs > 0).score,
            scanning: scans.iter().any(|s| s.status == "running"),
            progress: 0,
            reference: self.is_reference_case()?,
        })
    }
}

/// Returns the original URL of a web archive copy, e.g. `https://web.archive.org/web/20240301000000id_/https://a.ua/x.pdf`
/// yields `https://a.ua/x.pdf`. Returns `None` for anything that is not an archive copy.
pub fn archive_original(url: &str) -> Option<&str> {
    let i = url.find("/web/")?;
    let rest = &url[i + 5..];
    let (ts, orig) = rest.split_once('/')?;
    let digits = ts.trim_end_matches(|c: char| c.is_ascii_alphabetic() || c == '_');
    if digits.is_empty() || !digits.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    (orig.starts_with("http://") || orig.starts_with("https://")).then_some(orig)
}
