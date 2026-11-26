# foca-store

↑ [Core Crates](README.md) · [Developer Guide](../README.md) · [Architecture](../architecture.md)

- [Purpose](#purpose)
- [Modules](#modules)
- [Public API](#public-api)
- [Tests](#tests)
- [Pitfalls](#pitfalls)

Path: `crates/foca-store/` · `src/` lines: 4,898 · tests: 28 · depends on: [foca-analysis](foca-analysis.md), [foca-core](foca-core.md)

## Purpose

`foca-store` implements project persistence for FOCA-rs (`F-2`, `F-3`, `I-21`, `I-23`).

- One SQLite database `<id>.foca` per project (WAL mode, foreign keys enabled) plus a compact index database `projects.db` in the same data directory (project list, summary cards for `project_list`, and global settings without secrets).
- Forward-only schema migrations keyed on `PRAGMA user_version` (`schema.rs`).
- `ProjectDb::snapshot` builds the snapshot verbatim in `docs/API.md` format (`foca_core::api::Snapshot`).
- **Portable SQLite snapshot export & import** (backing encrypted `.foca.enc` bundles in `foca-engine::bundle`):
  - `ProjectDb::export_sqlite_bytes(&self)` (`src/project.rs`) creates a self-contained, WAL-consolidated snapshot via `VACUUM INTO` into a temporary file, reads the bytes, and immediately removes the temporary file.
  - `Store::import_project_db(&self, db_bytes, new_name)` (`src/lib.rs`) verifies the SQLite 3 header, validates the database in a staging file, assigns a fresh unique project ID so existing projects are never overwritten, rewrites project identity (`rewrite_identity`), cleans up staging WAL/SHM files, and registers the imported project in `projects.db`. Pairs with `ProjectDb::remap_doc_local_paths` when restoring attached document files.
- **Global settings (`src/settings.rs`)**:
  - Defaults include `settings.lang = "auto"` (inherited by `alerts.lang = "auto"` and reports; resolved against device BCP 47 locale via `foca_core::Lang::resolve_setting`), `ocr` (`enabled: false`, `max_pages: 10`, `max_mb: 15`), `recon.screenshots: false`, network/proxy, power, security, fuzz, ports, and alerts defaults.
  - `strip_secrets` scrubs secret-like fields under both `keys.*` and `alerts.*` (`telegram`/`webhook`) before saving.

API keys and alert bot/webhook tokens are never stored in SQLite: only status and masked preview (`KeyVault.kt` holds the actual values). Secrets extracted from scanned documents are persisted for reporting, but masked in `Debug`/`Display` (`foca_core::api::SecretValue`).

## Modules

| File | Lines | Contents |
|---|---|---|
| `src/lib.rs` | 534 | `Store` (`projects.db` index, project creation/listing/archiving, `import_project_db`, settings), `StoreError`, `iso()` |
| `src/lock.rs` | 164 | Exclusive lock on the application's data directory (`<dir>/engine.lock`) |
| `src/project.rs` | 1,961 | Project database `<id>.foca`: documents, entities, findings with triage, infra, scans, request log, tasks, undo log, project settings and user search rules, `export_sqlite_bytes`, `rewrite_identity`, `remap_doc_local_paths`, reference-case marker |
| `src/erase.rs` | 325 | `scan_delete`: erases one scan and what only it produced (documents and files, request log, queue rows, per-scan settings, infra rows, scan-only findings), keeps what a later scan listed and recomputes first/fixed scan |
| `src/schema.rs` | 250 | Forward-only SQLite schema migrations keyed on `PRAGMA user_version` (currently project schema v10: plain-hyphen empty-value mark) |
| `src/search.rs` | 488 | Full-text search over document text (`I-5`, FTS5 `doc_fts`) |
| `src/settings.rs` | 159 | Global `Settings` defaults (`settings.lang = "auto"`, `KEY_SERVICES`, `LEGACY_KEY_SERVICES`), deep `merge`, `strip_secrets`, `key_status` |
| `src/tests.rs` | 1,680 | Store unit tests against temporary directories |

## Public API

Re-exports in `src/lib.rs`:

- `lock::{DataDirLock, LockOwner}`
- `project::{AddDoc, DocAdded, FindingPatch, ProjectDb, RequestLog, Task, TaskCounts, TaskState, UndoEntry, ...}`
- `search::{SearchHit, SearchOpts, SearchPage}`

Key methods & top-level items: `Store`, `Store::import_project_db`, `ProjectDb::export_sqlite_bytes`, `ProjectDb::search_text`, `fts_query`, `fts_rebuild`, `fts_check`, `rules_config` / `set_rules_config` / `rule_set`, `ProjectDb::task_urls`, `NewProject`, `ProjectPatch`, `StoreError`, `iso()`. Target kinds of new projects are derived inside `Store::create_project`; scope conversion is `foca_core::Scope::from(&ScopeDto)`.

Full API docs: `cargo doc -p foca-store --no-deps --open`.

## Tests

`cargo test -p foca-store`: 23 unit tests in `src/`.

## Pitfalls

- Migrations are strictly append-only by `PRAGMA user_version`; never mutate existing entries. Project schema is currently v10 (v7 added `infra`, v8 added FTS5 `doc_fts`, v9 added `documents.error_kind`, v10 rewrites the stored empty-value mark to a plain hyphen); tests assert `schema_version() == 10`.
- `doc_fts` is an external-content FTS5 table backed by `documents(name, text_excerpt)` with triggers; soft-deleted documents are filtered at query time so delete/restore updates search immediately. Only the first 64 KiB (`text_excerpt`) is indexed; migration v8 rebuilds old projects on open.
- Search snippets mask secrets and PII using `foca_core::api::mask` over a ±512-byte window because snippets bypass `mask_evidence`; literal `{{` markers are neutralized with a zero-width space. User queries pass through `fts_query` (FTS operators, `:`, `NEAR` neutralized; max 16 terms).
- Invalid custom search rules (`analysis.rules`) fail with `StoreError::Invalid` without writing partial changes.
- Global settings live in `projects.db` (`settings` table, key `settings`) merged over the crate-private `settings::defaults()` (read them through `Store::settings_get`). Never write plaintext API keys or webhook URLs into `settings`.
