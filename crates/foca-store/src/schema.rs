//! Schema and migrations keyed on `PRAGMA user_version`.
//!
//! Each migration is SQL applied inside a transaction; its version number is its index plus
//! one. Migrations are append-only: existing entries must never change.

use rusqlite::Connection;

use crate::StoreError;

/// Migrations of the project file `<id>.foca`.
pub const PROJECT_MIGRATIONS: &[&str] = &[
    // v1: base schema
    r#"
CREATE TABLE project (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    client TEXT NOT NULL DEFAULT '',
    domain TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    archived INTEGER NOT NULL DEFAULT 0,
    notes TEXT NOT NULL DEFAULT '',
    updated_at TEXT NOT NULL
);
CREATE TABLE scope (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    json TEXT NOT NULL
);
CREATE TABLE documents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url TEXT,
    host TEXT,
    name TEXT NOT NULL,
    ext TEXT NOT NULL DEFAULT '',
    local_path TEXT,
    sha256 TEXT UNIQUE,
    status TEXT NOT NULL DEFAULT 'queued',
    size INTEGER NOT NULL DEFAULT 0,
    mime TEXT,
    source TEXT NOT NULL DEFAULT '',
    found_at TEXT,
    downloaded_at TEXT,
    first_scan TEXT,
    error TEXT,
    metadata_json TEXT,
    deleted_at TEXT
);
CREATE INDEX documents_url ON documents(url);
CREATE TABLE entities (
    kind TEXT PRIMARY KEY,
    json TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE TABLE findings (
    id INTEGER PRIMARY KEY,
    sev TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'new',
    sev_override TEXT,
    notes_json TEXT NOT NULL DEFAULT '[]',
    tags_json TEXT NOT NULL DEFAULT '[]',
    photos_json TEXT NOT NULL DEFAULT '[]',
    provenance_json TEXT NOT NULL DEFAULT '{}',
    data_json TEXT NOT NULL,
    first_scan TEXT,
    fixed_scan TEXT,
    present INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE TABLE scans (
    id TEXT PRIMARY KEY,
    profile TEXT NOT NULL,
    active INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'running',
    reason TEXT,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    stats_json TEXT NOT NULL DEFAULT '{}',
    snapshot_json TEXT
);
CREATE TABLE request_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    time TEXT NOT NULL,
    scan_id TEXT,
    module TEXT NOT NULL,
    method TEXT NOT NULL,
    url TEXT NOT NULL,
    host TEXT NOT NULL,
    status INTEGER,
    bytes INTEGER NOT NULL DEFAULT 0,
    active INTEGER NOT NULL DEFAULT 0,
    error TEXT
);
CREATE INDEX request_log_time ON request_log(time);
CREATE TABLE tasks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    kind TEXT NOT NULL DEFAULT 'download',
    url TEXT NOT NULL,
    scan_id TEXT,
    source TEXT NOT NULL DEFAULT '',
    state TEXT NOT NULL DEFAULT 'queued',
    attempts INTEGER NOT NULL DEFAULT 0,
    last_error TEXT,
    doc_id INTEGER REFERENCES documents(id) ON DELETE SET NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(kind, url)
);
CREATE INDEX tasks_state ON tasks(state);
CREATE TABLE reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    tpl TEXT NOT NULL DEFAULT '',
    fmt TEXT NOT NULL DEFAULT '',
    lang TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    size TEXT NOT NULL DEFAULT '',
    opts_json TEXT NOT NULL DEFAULT '{}',
    path TEXT
);
CREATE TABLE settings (
    key TEXT PRIMARY KEY,
    value_json TEXT NOT NULL
);
CREATE TABLE undo_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    time TEXT NOT NULL,
    action TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    undone INTEGER NOT NULL DEFAULT 0
);
"#,
    // v2: document text excerpt (full-text search) and per-host request log
    r#"
ALTER TABLE documents ADD COLUMN text_excerpt TEXT;
CREATE INDEX request_log_host ON request_log(host);
"#,
    // v3: report result snapshot (`Report.result`)
    r#"
ALTER TABLE reports ADD COLUMN result_json TEXT;
"#,
    // v4: engagement contract removed; its number, dates and forbidden techniques are dropped from the scope
    r#"
UPDATE scope SET json = json_remove(json, '$.num', '$.from', '$.to', '$.forbid');
"#,
    // v5: pre-run confirmations removed; the project `allow_active` switch, per-target "active"
    // marks and the active-stage confirmation log are dropped
    r#"
UPDATE scope SET json = json_remove(json, '$.allow_active');
UPDATE scope SET json = json_set(json, '$.targets',
    json((SELECT json_group_array(json(CASE WHEN json_type(value) = 'object'
        THEN json_remove(value, '$.active') ELSE json_quote(value) END))
        FROM json_each(scope.json, '$.targets'))))
  WHERE json_type(json, '$.targets') = 'array';
DELETE FROM settings WHERE key = 'engine.active_acks';
"#,
    // v6: response annotation in the request log (soft 404 / calibration / filtered) and content type
    r#"
ALTER TABLE request_log ADD COLUMN note TEXT;
ALTER TABLE request_log ADD COLUMN ctype TEXT;
"#,
    // v7: infrastructure records of the infrastructure modules (SaaS map, M365 tenant, mail policies,
    // certificates and their audit, CT history, CDN/origin, host roles, PTR, subdomain
    // enumeration summaries, out-of-scope candidates): one JSON row per (kind, key)
    r#"
CREATE TABLE infra (
    kind TEXT NOT NULL,
    key TEXT NOT NULL,
    json TEXT NOT NULL,
    scan TEXT,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (kind, key)
);
"#,
    // v8: full-text index over document names and text (FTS5, external content: the text stays
    // in `documents.text_excerpt`; triggers keep the index in sync, soft deletion is filtered at
    // query time). Apostrophe variants are separators like the ASCII one.
    r#"
CREATE VIRTUAL TABLE doc_fts USING fts5(
    name,
    text_excerpt,
    content = 'documents',
    content_rowid = 'id',
    tokenize = "unicode61 remove_diacritics 2 separators 'ʼ’‘'"
);
CREATE TRIGGER doc_fts_ai AFTER INSERT ON documents BEGIN
    INSERT INTO doc_fts (rowid, name, text_excerpt) VALUES (new.id, new.name, new.text_excerpt);
END;
CREATE TRIGGER doc_fts_ad AFTER DELETE ON documents BEGIN
    INSERT INTO doc_fts (doc_fts, rowid, name, text_excerpt)
        VALUES ('delete', old.id, old.name, old.text_excerpt);
END;
CREATE TRIGGER doc_fts_au AFTER UPDATE OF name, text_excerpt ON documents BEGIN
    INSERT INTO doc_fts (doc_fts, rowid, name, text_excerpt)
        VALUES ('delete', old.id, old.name, old.text_excerpt);
    INSERT INTO doc_fts (rowid, name, text_excerpt) VALUES (new.id, new.name, new.text_excerpt);
END;
INSERT INTO doc_fts (doc_fts) VALUES ('rebuild');
"#,
    // v9: machine-readable kind of a document error (`parse` | `download` | `http`); rows of
    // older versions keep NULL and are read as `parse` (every earlier writer recorded a
    // parse/import failure of an already stored file)
    r#"
ALTER TABLE documents ADD COLUMN error_kind TEXT;
"#,
    // v10: the empty-value mark in stored hosts, findings and infra rows is a plain hyphen;
    // rows written by earlier versions carry U+2014 (char 8212) and are rewritten once
    r#"
UPDATE entities SET json = replace(json, '"' || char(8212) || '"', '"-"');
UPDATE findings SET data_json = replace(data_json, '"' || char(8212) || '"', '"-"');
UPDATE infra SET json = replace(json, '"' || char(8212) || '"', '"-"');
"#,
];

/// Migrations of the project index `projects.db`.
pub const INDEX_MIGRATIONS: &[&str] = &[r#"
CREATE TABLE projects (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    client TEXT NOT NULL DEFAULT '',
    file TEXT NOT NULL,
    created_at TEXT NOT NULL,
    archived INTEGER NOT NULL DEFAULT 0,
    summary_json TEXT NOT NULL DEFAULT '{}',
    position INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE settings (
    key TEXT PRIMARY KEY,
    value_json TEXT NOT NULL
);
"#];

pub fn user_version(conn: &Connection) -> Result<u32, StoreError> {
    Ok(conn.pragma_query_value(None, "user_version", |r| r.get::<_, i64>(0))? as u32)
}

/// Applies migrations up to and including version `target`.
pub fn migrate_to(conn: &Connection, migrations: &[&str], target: u32) -> Result<u32, StoreError> {
    let mut v = user_version(conn)?;
    if v as usize > migrations.len() {
        return Err(StoreError::Version {
            found: v,
            supported: migrations.len() as u32,
        });
    }
    while v < target && (v as usize) < migrations.len() {
        let tx = conn.unchecked_transaction()?;
        tx.execute_batch(migrations[v as usize])?;
        v += 1;
        tx.pragma_update(None, "user_version", v)?;
        tx.commit()?;
    }
    Ok(v)
}

pub fn migrate(conn: &Connection, migrations: &[&str]) -> Result<u32, StoreError> {
    migrate_to(conn, migrations, migrations.len() as u32)
}
