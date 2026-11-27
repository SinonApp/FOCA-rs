# foca-engine

↑ [Core Crates](README.md) · [Developer Guide](../README.md) · [Architecture](../architecture.md)

- [Purpose](#purpose)
- [Key 2.0 Subsystems](#key-20-subsystems)
- [Modules](#modules)
- [Public API](#public-api)
- [Tests](#tests)
- [Pitfalls](#pitfalls)

Path: `crates/foca-engine/` · `src/` lines: 25,704 · tests: 164 · depends on: [foca-analysis](foca-analysis.md), [foca-core](foca-core.md), [foca-fuzz](foca-fuzz.md), [foca-meta](foca-meta.md), [foca-net](foca-net.md), [foca-recon](foca-recon.md), [foca-search](foca-search.md), [foca-store](foca-store.md), [foca-report](foca-report.md) *(optional, feature `report`)*

## Purpose

`foca-engine` is the 9-stage scan orchestrator and IPC command facade of FOCA-rs.

- **`Engine::open`**: opens the `foca-store` data directory under an exclusive `DataDirLock`, wires up `KeyProvider` (Android `KeyVault` or in-memory), `EventSink` (`app.emit("scan://event")`), optional `RenderFetch`, `OcrProvider`, `WebScreenshotter`, and `ReportBuilder`. Any scan left unfinished by a previous process crash/kill is recorded in history as `stopped` / `restart`.
- **`Engine::invoke`**: dispatches every contract command in [docs/API.md](../../API.md) (`project_*`, `scope_*`, `scan_*`, `finding_*`, `doc_*`, `oos_*`, `settings_*`, `key_*`, `report_*`, `export_build`, `ai_*`, `pin_*`, `wipe_all`, `net_check`, `secret_reveal`, `insights_get`, `chain_get`, `hygiene_get`, `demo_case_import`, `tool_*`, `queue_*`, `i18n_bundle`, `licenses_get`, `plugins_*` / `plugin_*`, `signatures_*`, `project_export_encrypted`, `project_import_encrypted`, `logs_get`, ...) and returns `serde_json::Value` or `CmdError { code, message, targets? }`.
- **Background Scan Pipeline**: runs on a tokio task across 9 stages (`search → download → meta → analysis → network → ports → recon → fuzz → report`), emits `scan://event` updates, cancels immediately via `CancellationToken`, supports external pause/resume (`Engine::pause` / `Engine::resume`), and resumes from download queues via `resume_from`.
- **Per-item controls** (`scan/control.rs`, `scan_control`): pause/resume, skip and restart for a stage, a source or a network sub-step while the rest of the scan runs; restarts of finished stages are queued for a follow-up run. A follow-up (`scan_start { only }`, `scan/selection.rs`) runs only the stages that own the chosen items: a search source adds the document pipeline, a resolver step or TLS runs only that part of Network and DNS, a whole `stage:` item runs that stage alone. Network sub-steps report `done/total` counters and a `slow` flag (`scan/steps.rs`); dangling CNAME checks run with bounded concurrency (`scan/takeover.rs`). Stages that work host by host (liveness, TLS, ports, recon, site discovery) run up to `settings.net.hosts_parallel` hosts at once on the stage's own task (`scan/hosts.rs`): workers pass the stage checkpoint before each host, site discovery shares one request budget across workers (`Fuzzer::with_shared_budget`), and a host that limits requests stops only itself.
- **Logging**: captures `tracing` events from engine, search, and net into an in-memory ring buffer and rotating `<data>/logs/foca.log`, scrubbing secrets via `analysis/redact.rs` before export (`logs_export`).

## Key 2.0 Subsystems

- **Encrypted Project Container (`cmds/bundle.rs`)**:
  - Binary format `FOCAENC1` (`.foca.enc`): 8-byte magic + big-endian header length + UTF-8 JSON header (authenticated as AEAD AAD) + `ring::aead::CHACHA20_POLY1305` ciphertext encrypting an in-memory ZIP with `manifest.json` (`CustodyManifest`), `project.foca` (`VACUUM INTO` snapshot via `foca-store::ProjectDb::export_sqlite_bytes`), and optional `files/<rel>` copies.
  - Key derivation uses `PBKDF2-HMAC-SHA256` (`210,000` iterations, random 16-byte salt, 12-byte nonce, 16-byte KDF check tag) plus optional Android Keystore `ReportSignature` (ECDSA P-256).
  - Commands: `project_export_encrypted { project, password, include_files }` and `project_import_encrypted { path, password, new_name? }` (atomically creates a new project via `Store::import_project_db`, never overwriting existing projects). Passwords are never logged, cached, or saved.
- **IPC Localization Bundles (`services/i18n.rs`)**:
  - Embeds `locales/{en,ru,uk}/{ui,help}.json` and the per-area `locales/<lang>/ui/*.json` dictionaries via `include_str!` and serves them over IPC (`i18n_bundle { lang?, device_locale?, include_help? }`) using `foca_core::Lang::resolve_setting`, so the WebView never requires `fetch()` or a relaxed CSP. Help catalogs load lazily only when `include_help: true`.
- **Offline License Catalog (`services/licenses.rs`)**:
  - Embeds `crates/foca-engine/data/licenses.json` (generated and validated by `qa/gen-licenses.py --check`) and serves it to `/settings/licenses` via `licenses_get {}` (536+ Rust crates with direct flags, Android libraries tagged `foss`/`play`/`both`, data/assets, and 10 full open-source license texts).
- **Sandboxed Plugin Engine (`services/plugins.rs`, `scan/plugins.rs`)**:
  - Pure-Rust plugin system ([ADR-0011](../../adr/0011-port-logic-not-binaries.md)) supporting two runtimes:
    - **Declarative** (`"declarative"`): JSON/TOML rules with URL templates, regex extractors (`hosts`, `urls`, `header_finding`, `meta_pattern`), and scoped `NetClient` requests.
    - **WebAssembly** (`"wasm"`): built-in pure-Rust stack-machine interpreter enforcing `<= 16 MiB` linear memory (`256` pages), `<= 50,000` instruction fuel budget, max 2 MiB binary, zero WASI/filesystem/raw sockets, and only sandboxed host imports (`host_http_get_scoped`, `host_emit_finding`).
  - Strictly enforces [ADR-0009](../../adr/0009-passive-never-touches-target.md): in `Access::Passive`, plugins declaring `net:scoped` or `touches_target` or targeting in-scope hosts are blocked before network I/O; out-of-scope hosts are always blocked.
  - Enabled user plugins run in the network stage of real scans (`scan/plugins.rs`, source id `plugins`); a failing plugin is reported on the source and never fails the scan, and plugins held by the passive policy report `skipped`.
  - Commands: `plugins_list`, `plugin_install`, `plugin_toggle`, `plugin_remove`, `plugin_test`.
- **Signed Signature Bundles (`services/sigbundle.rs`)**:
  - Updates CISA KEV entries and secret patterns without rebuilding the APK via `foca-sig-bundle/v2` (v1 still read): KEV entries, secret patterns and whole data tables (technology, end-of-life, Retire.js, Recog, PSL, takeover, EPSS); CPE prefixes are stored but not used for matching.
  - Verifies both `SHA-256` and `Ed25519` (`ring::signature::ED25519`) before atomically installing `<data_dir>/signatures/current.json`, retaining `previous.json` for instant rollback (`signatures_status`, `signatures_import`, `signatures_rollback`).
  - `signatures_update` checks the official feed (rolling GitHub release `signatures`): 404 = `no_update`, not newer = `up_to_date`, newer = installed, failures are recorded and returned as coded errors; every check lands in `last_check.json`. Status counts come from the loaded tables. Details and the maintainer tool (`examples/sig_bundle.rs`, `scripts/build-sig-bundle.sh`): [signature bundles](../signature-bundles.md).
- **Cloud-Only AI with Live Models & Thinking Controls (`cmds/ai.rs`, `services/ai.rs`)**:
  - **No local/on-device AI**: all local AI code has been removed; AI summarization operates strictly over cloud APIs with explicit user review of redacted prompts (`ai_preview` → `ai_summarize`).
  - Supported providers: `openai`, `anthropic`, `gemini`, `deepseek`, `xai`, `mistral`, `groq`, `together`, `openrouter`, and `custom` (user-supplied HTTPS OpenAI-compatible base URL). Keys live in `KeyVault("ai")` and are never written to `request_log`; requests use `Access::Passive` through `NetClient`.
  - **`ai_models_list { provider?, base_url?, refresh?, show_all? }`**: queries the provider's live `/models` endpoint directly (with session memory cache and chat/all filtering), eliminating stale hardcoded model lists.
  - **Thinking / Reasoning Controls (`AiGenOpts`)**: supports `thinking` (`auto`, `off`, `minimal`, `low`, `medium`, `high`, `xhigh`, `max`), `thinking_budget` (0-65,536 tokens for Gemini/Anthropic), `max_tokens`, `temperature`, and `show_thoughts`, adapting wire format per provider (e.g., Anthropic adaptive vs manual `budget_tokens`, Gemini thinking config, OpenAI/DeepSeek reasoning fields) and omitting optional knobs in `auto` mode to avoid HTTP 400 errors.

## Modules

| File | Lines | Contents |
|---|---:|---|
| `src/lib.rs` | 430 | Crate root, `EngineConfig`, `Endpoints`, `CmdError`, `KeyProvider`, `EventSink`, re-exports |
| `src/facade.rs` | 275 | Entry points: open the data directory (recovers an interrupted scan as `stopped`), `invoke` dispatch |
| `src/engine.rs` | 339 | `Engine`: store, open project cache, running scan handle, basic services |
| `src/run.rs` | 761 | Scan runs: start from wizard arguments, finish (history record, alerts, report), follow-up runs |
| `src/queue.rs` | 633 | Multi-project scan queue (`queue_*`) with shared pause and overall progress |
| `src/alerts.rs` | 723 | Event alerts (`foca_analysis::alerts`), risk trend, Telegram/webhook delivery (`foca_net::notify`) |
| `src/settings.rs` | 332 | Public settings view and updates, UI language for native texts |
| `src/debug.rs` | 499 | Debug tab: core and Android logs, crashes, request log, build info, `TERMS_VERSION` |
| `src/dto.rs` | 588 | Contract-shaped JSON: snapshot, project summary, out-of-scope candidates, `Finding.standards` |
| `src/util.rs` | 262 | Argument extraction, masks, hashes, time |
| **`src/scan/`** | | Scan pipeline |
| `scan/mod.rs` | 742 | Run context shared by the stages, stage order, stage helpers |
| `scan/sources.rs` | 287 | Catalog: `STAGES`, source ids grouped by stage, profiles and modules |
| `scan/search/mod.rs` | 705 | Search stage: document search engines, archives, host sources; a deep Common Crawl sweep beside them |
| `scan/search/dorks.rs` | 356 | Dork groups lost to CAPTCHAs: per-project queue, in-scan retry after a cool-down, `dorks_pending` / `dorks_retry` |
| `scan/documents.rs` | 178 | Download queue, metadata extraction and analysis stages |
| `scan/network.rs` | 495 | Network stage: DNS, takeover checks, liveness, infrastructure modules |
| `scan/steps.rs` | 193 | Sub-step progress of long stages (`done/total`, ETA, slow-resolver flag) |
| `scan/hosts.rs` | 172 | Hosts worked on at once (`settings.net.hosts_parallel`): bounded worker pool, `hosts` sub-step |
| `scan/takeover.rs` | 214 | Dangling CNAME checks with bounded concurrency |
| `scan/infra.rs` | 1,594 | Infrastructure modules inside the stages: CT, DNS brute force/permutations, SaaS/M365, CDN, TLS/X.509 |
| `scan/plugins.rs` | 328 | Network-stage step that runs enabled sandboxed plugins |
| `scan/ports.rs` | 1,325 | TCP connect port scan over live in-scope hosts (`foca_net::scan::ports`) |
| `scan/recon.rs` | 742 | Site recon and web audit (`foca-recon`, optional screenshots) |
| `scan/fuzz.rs` | 1,130 | Site search stage (`foca-fuzz`) |
| `scan/control.rs` | 383 | Per-item controls (`scan_control`): pause/resume, skip, restart, queued follow-ups |
| `scan/selection.rs` | 160 | Narrowed follow-up runs (`scan_start { only }`): which stages, sources and resolver steps run |
| **`src/cmds/`** | | Command handlers by domain |
| `cmds/projects.rs` | 291 | Projects and scope: create/update/duplicate/delete, scope edits, bulk host add |
| `cmds/findings.rs` | 202 | Finding status, edits, photos, playbooks |
| `cmds/documents.rs` | 234 | Files, deletion, local import, secret reveal, breach checks |
| `cmds/reports.rs` | 552 | Report and export build, list, verify, delete |
| `cmds/scans.rs` | 329 | `scan_delete`: cancels a running scan, prunes per-scan engine state, wipes files, rewrites the remaining history |
| `cmds/ai.rs` | 766 | AI summary: provider requests, model lists, stored summary |
| `cmds/config.rs` | 234 | API keys, network checks, UI dictionary |
| `cmds/security.rs` | 154 | PIN and wipe-all |
| `cmds/extensions.rs` | 192 | Signature bundles and plugins |
| `cmds/bundle.rs` | 666 | Encrypted `.foca.enc` project container |
| `cmds/offline.rs` | 664 | Offline import of files, folders and ZIP (no network), FTS5 search, search rules |
| `cmds/hygiene.rs` | 387 | `hygiene_get`, `doc_clean` via `clean_and_verify`, shared-file mode |
| `cmds/toolbox.rs` | 1,163 | Quick tools without a project (`tool_file`, `tool_mail_domain`, `tool_host`, `tool_secret`, `tool_log`) |
| `cmds/demo_case.rs` | 36 | Built-in reference case (`demo_case_import`) |
| **`src/analysis/`** | | Knowledge derived from project data |
| `analysis/facts.rs` | 226 | Engine state in the project `settings` table (network facts, recon/ports/fuzz snapshots) |
| `analysis/insights.rs` | 1,079 | Insights, attack paths, link chain (`insights_get`, `chain_get`), report visuals |
| `analysis/intel.rs` | 448 | Keyless Shodan InternetDB enrichment |
| `analysis/rules.rs` | 469 | Rust mirror of `FOCA_RULES` from `ui/js/sel.js` (scope, profiles, `STAGE_IDS`) |
| `analysis/scope_bulk.rs` | 341 | `scope_add_hosts`: bulk scope extension that keeps CDN/cloud IPs out of port scans |
| `analysis/redact.rs` | 216 | Secret scrubbing for `logs_export` |
| **`src/services/`** | | Self-contained services |
| `services/i18n.rs` | 470 | Embedded UI/help dictionaries over IPC (`i18n_bundle`), core message codes |
| `services/logs.rs` | 306 | `tracing` subscriber: ring buffer and rotating `<data>/logs/foca.log` |
| `services/plugins.rs` | 1,978 | Declarative and WASM plugin runtime |
| `services/sigbundle.rs` | 1174 | Ed25519 + SHA-256 signed signature bundles with rollback |
| `services/ai.rs` | 617 | AI provider protocol: request bodies, headers, response parsing, model lists |
| `services/ocr.rs` | 248 | Optional on-device OCR pipeline (off by default) |
| `services/resume.rs` | 172 | Auto-resume state (`engine_run.json`) after the OS kills the process |
| `services/licenses.rs` | 53 | Embedded `data/licenses.json` (`licenses_get`) |
| `services/report.rs` | 95 | Bridge to `foca-report` (feature `report`) |

## Public API

Re-exports in `src/lib.rs`:

- `engine::Engine`
- `debug::TERMS_VERSION`
- `scan::sources::{DOC_SOURCE_IDS, HOST_SOURCE_IDS, INFRA_SOURCE_IDS}`
- `foca_search::{BoxFuture, RenderFetch, RenderPage, RenderRequest, RenderStep}`
- `foca_recon::screenshot::{ScreenshotRaw, ScreenshotRequest, WebScreenshotter}`
- `services::ocr::{OcrProvider, OcrRequest, OcrResult}`
- `services::report::FocaReport` *(feature `report`)*
- Public modules: `intel`, `redact`, `rules` (from `analysis`); `i18n`, `licenses`, `logs`, `ocr`, `plugins`, `resume`, `sigbundle` (from `services`)

Command catalog: [docs/API.md](../../API.md). Full API docs: `cargo doc -p foca-engine --no-deps --open`.

## Tests

`cargo test -p foca-engine`: 68 unit tests in `src/` and 96 integration tests. Integration tests are grouped into six test binaries (`tests/<group>.rs` includes `tests/<group>/*.rs`), which keeps link time down:

| Binary | Files (tests) |
|---|---|
| `tests/scan.rs` | `auto_resume` (2), `lifecycle` (10), `render_sources` (5), `rescan_sources` (5), `scan_steps` (5), `source_deadline` (1), `sources` (2), `stages` (1) |
| `tests/network.rs` | `fuzz` (5), `infra` (5), `plugins_scan` (3), `ports` (7), `recon` (2) |
| `tests/data.rs` | `bundle` (1), `demo_case` (1), `files` (1), `hygiene` (2), `offline` (5), `scope_bulk` (1), `toolbox` (7) |
| `tests/reports.rs` | `insights` (2), `report_after_scan` (5), `report_company` (1) |
| `tests/ops.rs` | `monitor` (6), `queue` (5) |
| `tests/contract_shape.rs` | demo backend ⊆ engine shapes (4) |
| `tests/debug.rs` | debug tab (2) |

Shared helpers live in `tests/common/mod.rs`; `tests/dump_demo_shapes.mjs` regenerates `tests/fixtures/demo_shapes.json`.

## Pitfalls

- Stage IDs are duplicated in several places (`scan/sources.rs STAGES`, `analysis/rules.rs STAGE_IDS`, `ui/js/sel.js`, `ui/screens/scan.js`, the demo backend, test lists): update all together ([Contributing → Adding a Scan Stage](../contributing.md#adding-a-scan-stage)), and always dispatch by stage ID rather than numeric index.
- The `db` event fires only at the end of a stage; the UI refreshes `project_snapshot` on `progress`.
- `ui/screens/scan.js` forwards only an allow-listed set of `scan_start` fields: add any new launch parameter to both `scan.js` and [docs/API.md](../../API.md).
- Scheduled monitoring refuses active profiles (`monitor_active`) without issuing a single packet.
- Embedded `locales/{en,ru,uk}/{ui,help}.json` and `data/licenses.json` are verified by unit tests in `services/i18n.rs` and `services/licenses.rs`; keep all three locale files key-synchronized and run `python qa/gen-licenses.py --check` after dependency changes.
