# FOCA-rs: UI ↔ Core Contract (Tauri Commands)

↑ [Documentation](README.md) · [Developer Guide](dev/README.md) · [Architecture](dev/architecture.md)

<details>
<summary>Table of Contents</summary>

- [General Rules](#general-rules)
- [Commands](#commands)
- [Platform Commands (Android)](#platform-commands-android)
- [Scope Rule (Shared Across UI, Demo Backend, and foca-core::scope)](#scope-rule-shared-across-ui-demo-backend-and-foca-corescope)
- [Active Phase](#active-phase)
- [Scan: Launch Rules, Retry, Resume, and App Restart](#scan-launch-rules-retry-resume-and-app-restart)
- [Site Content Discovery (Stage fuzz, Crate foca-fuzz)](#site-content-discovery-stage-fuzz-crate-foca-fuzz)
- [Site Reconnaissance (Stage recon, Crate foca-recon)](#site-reconnaissance-stage-recon-crate-foca-recon)
- [Port Scanning (Stage ports, foca_net::ports)](#port-scanning-stage-ports-foca_netports)
- [Infrastructure (1.2): Subdomains, SaaS/M365, Mail, CDN, TLS/X.509, CT, Roles](#infrastructure-12-subdomains-saasm365-mail-cdn-tlsx509-ct-roles)
- [Analytics (1.4): Correlation, Org Chart, Anomalies, KEV, Network Map, Graph, Timeline](#analytics-14-correlation-org-chart-anomalies-kev-network-map-graph-timeline)
- [Document Hygiene (1.4): A-F Grade, Sanitization, and Before/After Verification](#document-hygiene-14-a-f-grade-sanitization-and-beforeafter-verification)
- [Quick Tools and Scan Queue (1.5)](#quick-tools-and-scan-queue-15)
- [Monitoring](#monitoring)
- [Types](#types)
- [Scan Events: scan://event](#scan-events-scanevent)
  - [How screens/scan.js Runs on Events (Implemented)](#how-screensscanjs-runs-on-events-implemented)
- [UI Snapshot: F.db and Event Bus](#ui-snapshot-fdb-and-event-bus)
- [Selectors F.sel (Single Source of Truth for Metrics)](#selectors-fsel-single-source-of-truth-for-metrics)
- [Compatibility (Legacy Aliases on F.db, Remove After Screen Migration)](#compatibility-legacy-aliases-on-fdb-remove-after-screen-migration)
- [Demo Backend](#demo-backend)

</details>

This document is the single contract between the UI (`ui/`) and the Rust core. The demo backend
(`ui/js/demo-backend.js`) implements the exact same commands and payloads, allowing the UI to switch to the Rust
core without rewriting any screens.

```
screen ──► F.sel.* (selectors, read-only)   ──►  F.db (current project snapshot)
screen ──► F.api.* (commands, Promise)      ──►  window.__TAURI__.core.invoke(cmd, args)   ← Rust
                                            └─►  FOCA_DEMO_BACKEND.invoke(cmd, args)       ← browser / tests
core   ──► event "scan://event"             ──►  F.emit("scan", ev) and reload F.db        ──►  F.emit("db", {kind})
```

Files: `ui/js/api.js` (bridge, event bus, `F.db`, aliases), `ui/js/sel.js` (selectors and `FOCA_RULES`: pure rules
for scope, active phase, risk scoring, and report selection; invoked directly by the demo backend with no duplicate
copy), `ui/js/demo-backend.js` (demo backend). Normative "must / must not" wording below defines mandatory Rust core
behavior; the demo backend serves as the reference implementation, verified by `qa/data-invariants.mjs` including
dynamic flows (scan → stop → app restart → resume).
Script load order in `index.html`: `core.js → demo-backend.js → api.js → sel.js → main.js → screens/*`.
Headless data invariant verification: `node qa/data-invariants.mjs`.

## General Rules

- Command and field names use `snake_case` (serde: `#[serde(rename_all = "snake_case")]`).
- Timestamps use ISO 8601 without timezone offset in device local time: `"2026-11-19T21:14:00"`. Display formatting
  (`19.11.2026, 21:14`) is handled by `api.js` (hydration); the core never sends pre-formatted display strings.
- Entity links use IDs only (`author: "a.bondar"`, `software: "word2013"`, `doc: 12`). Object references (`doc.user`,
  `doc.sw`) are resolved by `api.js`.
- Command errors return `Err({ code, message })`; in JS this becomes `reject(Error)` with a `.code` property. Error
  codes: `not_found`, `busy`, `io`, `out_of_scope` (target outside scope or excluded; includes `targets: string[]`
  listing which targets and why), `bad_status`, `blocked`, `no_key`, `stale_preview`, `bad_pin`, `bad_confirm`,
  `unknown_command`.
- **Core texts in the UI language.** Texts the core writes for the user (source `error`/`detail`, command error
  `message`, notice `text`, out-of-scope `why`/`hint`/`blocked`, bulk-scope `reason`, retry `reason`) stay Russian for
  logs and old clients; a known one also gets `<field>_msg = { code, params }` (errors: `message_msg`). The UI renders
  `F.coreMsg(text, msg)` → `F.t("core.<code>", params, text)` from `locales/<lang>/ui/core.json`, whose RU values are
  the exact templates the core emits (`foca_engine::i18n::classify`). Parameters may be nested messages; notes joined
  with `"; "` come as `{ code: "join", parts }`. Android notifications, toasts and the `device.txt` header are rendered
  by the core itself in the resolved UI language. Timeline events in `project_snapshot.events` carry `k_msg`/`t_msg`/
  `s_msg` the same way.
- **Finding texts in the UI language.** Finding `title`/`description`/`recommendation`/`evidence`, finding `source`,
  host and person `role` and host `source` are stored in Russian. `i18n_bundle().findings` (EN/UK, `null` for RU)
  carries the report catalog (`locales/<lang>/findings.json` + `sources` of `report.json`); `ui/js/ftext.js` matches the
  text by `provenance.rule` and template, like the report translator (`foca-report` `ftext.rs`, shared test vectors in
  `crates/foca-report/tests/fixtures/ftext_vectors.json`). Unknown text (user edits, old records) is shown as stored.
- The `project` parameter on data commands is the project ID; `F.api` automatically injects the active project.
- The core never returns plaintext API keys: only `mask` (`"BSAq…ab12"`).
- **Secrets from documents and findings** in snapshots are also masked only: `secrets[].mask` (no `value` field),
  evidence snippets use `{{s:<mask>}}` and `finding.secret_refs = ["f<id>:<k>"]`. The core must only return plaintext
  via `secret_reveal` (invoked by the UI after biometric confirmation; `api.js` caches the value in memory only while
  the confirmation session `F.bioOpen()` is active and clears it on `F.onBioClose`). The PIN is stored as a hash and
  never sent to the UI.
- **`project_list` freshness**: after any mutation (finding triage, document deletion, scope change, project metadata
  edit, scan event), `api.js` reloads `project_list` and emits `F.emit("db", {kind:"projects"})` so project cards never
  go stale.

## Commands

| Command | Arguments | Response |
|---|---|---|
| `project_list` | - | `ProjectSummary[]` |
| `project_snapshot` | `{ id }` | `Snapshot` |
| `project_open` | `{ id }` | `Snapshot` (also persists `settings.last_project`, except for a reference case: it is never restored on start) |
| `project_create` | `{ name, client, targets: (string \| { v, type })[], excludes: string[] }` | `ProjectSummary` (empty project: no scans, all lists empty, `risk: null`). The `/new` wizard passes target objects with UI-detected types (person, e-mail, ASN, IP range) |
| `project_update` | `{ id, patch: { name?, client?, notes?, archived? } }` | `ProjectSummary`. `notes` stores project notes (F-1, "Project Properties"). Alternative domains are not a separate entity, they are scope targets with `type: "domain"` (managed via `scope_set`) |
| `project_duplicate` | `{ id }` | `ProjectSummary` (copies targets and scope without scan results) |
| `project_delete` | `{ id }` | `{ ok }` (secure wipe performed on the core side) |
| `project_export_encrypted` | `{ project, password, include_files?: bool = false }` | `{ name, path, size, sha256, inputs_sha256, include_files, signed, counts }`: portable encrypted archive `.foca.enc` (`PBKDF2-HMAC-SHA256` with 210,000 iterations + `ChaCha20-Poly1305` AEAD with AAD header, `CustodyManifest`, optional document files, and hardware `ReportSigner` signature; the password is never persisted or logged) |
| `project_import_encrypted` | `{ path, password, new_name? }` | `{ project: ProjectSummary, custody: CustodyManifest, verified_signature: bool\|null, files_restored }`: validates password (`bad_password`), AEAD authentication, and `CustodyManifest` hashes (`tampered_bundle`), then atomically imports as a new project without overwriting existing projects |
| `scope_get` | `{ id }` | `Scope` |
| `scope_set` | `{ id, scope: Scope }` | `Scope`. A running scan immediately observes newly added exclusions. Legacy 0.2.x fields (`allow_active`, per-target `active`) are ignored |
| `scope_add_hosts` | `{ project, hosts: string[] /* 1…500 names */, dry_run?: bool = false }` | `{ added: string[], skipped: [{ host, code: "invalid"\|"excluded"\|"already_in_scope"\|"duplicate", reason }], no_probe: [{ host, ip, provider, kind: "cdn"\|"cloud"\|"hosting"\|"shared", reason }], scope: Scope, dry_run }`, bulk scope extension for out-of-scope names (typically subdomains found in CT/DNS when the target is a URL). Each added name becomes a `type: "domain"` target. Addresses that belong to a CDN, public cloud or hosting provider (built-in ranges, RDAP holder, or an IP shared with other owners' names) are listed in `no_probe`: the name is added, but the port scan never touches that IP (project fact `engine.no_probe`). `dry_run: true` computes the same plan and returns the current, unchanged `scope` without storing anything: the UI shows it for confirmation before the real call. A running scan picks up the new scope immediately. Errors: `bad_args` (empty list or more than 500 names), `not_found` |
| `scan_start` | `{ project, profile: "passive"\|"std"\|"full"\|"custom" (or legacy Russian display name), active: bool, modules: string[], sources?: string[] /* explicit list; empty = all */, sources_off?: string[] /* wizard: all except these */, targets?: string[], resume_from?: id, from_stage?: string /* stage id: a new scan that starts at this stage (follow-up run of restarts queued by scan_control) */, only?: string[] /* follow-up of chosen items (`stage:<id>`, `source:<id>`, `step:<id>`, as in scan_control): only the stages owning them run (a search source adds download/meta/analysis; a resolver step or `tls` runs only that part of network; `stage:<id>` runs that stage alone; report always runs); other stages are skipped as not selected and sources outside the items are `off`; the answer and `started` carry `stages` (ids that run, `null` for a full scan); the history record carries `only` and `stages`; survives resume */, fuzz?: { modules?: string[], rate?: number, wordlists?: string[] } /* per-run site discovery overrides atop settings.fuzz; survive resume */, ports?: { top?: 100\|1000\|0, list?: string } /* per-run port scan overrides atop settings.ports (0 = custom list); survive resume */, limit?: number /* document download cap */, exts?: string[] /* wizard document types ("pdf", "docx"…; related extensions like jpeg/tif/docm/xlsm/pptm… expand automatically; empty/omitted = all default types): filters sources, filetype: dorks, and download queue */, crawl_depth?: 1..10 /* crawler depth */, max_size_mb?: number /* max file size limit */, ua?: "chrome"\|"chrome_android"\|"firefox"\|"safari"\|"honest"\|"custom" /* per-run UA profile override atop settings.net.ua */, optional wizard parameters stored in fact `scan_opts:<scan_id>` and restored on `resume_from` if omitted, trigger?: "manual"\|"schedule" /* scheduled monitoring rescan: active tier → error `monitor_active` */ }` | `{ scan_id, profile, profile_id, active, egress, targets, resumed }`. Validation is identical for new scans, resume, and "Start over" (see "Scan: Launch Rules"): `out_of_scope`, `busy`, `not_found` (missing `resume_from` record). No confirmation prompts: every profile starts in a single call |
| `scan_stop` | `{ reason: "user"\|"android"\|"battery"\|"wifi"\|"vpn"\|"error" }` | `{ ok }` → emits `stopped`, writes a `scans` record with `status: "stopped"`, `progress`, `stage` |
| `scan_delete` | `{ project, scan_id, dry_run?: bool = false }` | `{ ok, scan_id, dry_run, docs, findings, hosts, requests, files }`: erases one scan and everything that exists only because of it. Removed: the history record and its per-scan facts, its request log and download queue rows, documents it downloaded (rows, files and cleaned copies, wiped like `project_delete`), entities extracted from them (re-analysis), network facts and infrastructure rows only it produced, findings first seen in it that nothing else backs, its alert log entries and queue rows. Kept: anything a later scan still listed in its snapshot (documents, hosts, findings move their `first_scan` to that scan), with triage notes, tags and statuses; a finding fixed by the deleted scan moves its `fixed_scan` to the next scan, or goes back to `new` without one. The remaining history snapshots are scrubbed and the next scan's growth (`added`, `new_findings`) recomputed. A running or paused scan of the project is cancelled first (no record, run file removed, so no resume or auto-resume) and `stopped { reason: "deleted" }` is emitted; deleting another scan while one runs gives `busy`. `dry_run: true` returns what would go (findings: first seen in the scan, an upper bound) and changes nothing. Errors: `not_found`, `busy` |
| `oos_list` | `{ project }` | `Oos[]`: out-of-scope candidates (matches snapshot `oos` field). Candidates from 1.2 modules (SAN, `O=`, tenant domains, origin IP, PTR, AD FS) include `source` and `why_key`, see "Infrastructure (1.2)" |
| `infra_get` | `{ project }` | `{ saas, tenant, mail_policy, cert, ct, cdn, origin, role, ptr, dns_enum, oos }`: records from 1.2 modules (arrays keyed by kind), see "Infrastructure (1.2)" |
| `insights_get` | `{ project, layers?, min_group? }` | `{ org, correlation, anomalies, kev, netmap, graph, layers, timeline, activity, attack_paths, counts }`: 1.4 analytics + 2.0 attack paths, see "Analytics (1.4)" |
| `chain_get` | `{ project, from_id? \| node?, limit? }` | `{ start, found, chains: [{ steps: [{ node: { id, kind, label }, via, reverse }], target_kind, hops }] }`, relationship chain from a finding (`from_id` = short ID) or graph node |
| `attack_paths_get` | `{ project }` | `{ paths: [{ id, title, severity, score, likelihood, target_host, steps, finding_ids, doc_ids }], choke_points: [{ node_id, kind, label, paths_broken, priority_score, recommendation, finding_ids }], summary: { total_paths, critical_or_high, choke_points, max_score } }`, attack-path and remediation choke-point engine (`foca_analysis::attack_paths`, `2.0-M5-A`) |
| `oos_add_to_scope` | `{ project, id }` | `{ scope, oos }`, atomic: marks decision `scope` and adds target to scope. Returns `blocked` if the candidate is blocked or matches exclusions (exclusions always take precedence) |
| `oos_decide` | `{ project, id, decision: "new"\|"scope"\|"ignored" }` | `Oos[]`; for "Add to scope" the UI calls `oos_add_to_scope`, while `oos_decide` handles "Ignore" and "Return to new" |
| `scan_pause` | `{ reason? }`: defaults to `user`; UI passes `offline` on connectivity loss | `{ ok }` → emits `paused { reason }`. `ok: false` if no scan is running |
| `scan_resume` | `{ reason? }` - `user` (default) or the reason that triggered the pause (`offline`…) | `{ ok }` → emits `resumed { after, progress }`. On Android, manual resume while paused by an environment rule (battery, Wi-Fi, VPN) returns `blocked` ("Scan paused: …, will resume automatically"); resuming with a non-`user` reason does not clear a manual pause |
| `scan_skip_source` | `{ id }`, any source in the Search stage (`SEARCH_SOURCES` in `foca-engine/src/scan.rs`: `wayback`, `cc`, `crt`, keyless subdomain/URL sources, see "Search Sources", `startpage`, `brave_web`, `brave`, `searx`, `crawler`) | `{ ok }`-"Skip source" during Search: aborts an in-flight request or prevents an unstarted one from launching; emits `source` with status `skipped` and continues the stage. `ok: false` if no scan is running, the search stage has passed, or the source already finished; `not_found` if not a search source. `id: "subdomains"` / `"tls"` (1.2), valid until the end of the Ports stage: skips unstarted module or stops in-progress work between domains/hosts (keeping collected data) with status `skipped`. `id: "brute"` / `"permute"`, skips only subdomain brute force or permutations until the end of the Network stage: a running resolver pass stops within 1.5 s keeping names found so far (the sub-step ends with `state: "skipped"`), later domains skip that step, the rest of the enumeration goes on. `id: "fuzz"`: "Stop discovery": stops fuzzing before or during the Site Discovery stage (preserving already-found items and still downloading/parsing discovered documents), emits `source` `fuzz` with status `stopped`, and continues the scan |
| `scan_control` | `{ kind: "stage"\|"source"\|"step", id, action: "pause"\|"resume"\|"skip"\|"restart" }` - `id`: a stage id, a source id (search sources, `subdomains`, `tls`, `ports`, recon sources, `fuzz`) or a sub-step (`brute`, `permute`) | `{ ok, state, reason }`: per-item control of the running scan, emits `control`. pause/resume holds one item while the rest of the scan goes on (stages at their next checkpoint; `brute`/`permute`/`subdomains` hold the resolver workers; `tls` between hosts). skip marks it skipped with reason `user`: a stage drops its remaining work at the next checkpoint (or never starts if still ahead), sources/steps go through `scan_skip_source`. restart re-runs the item within the current scan while its stage is running (`state: "restarting"`: the stage starts over, a resolver pass starts again, a search source that can be rebuilt runs one more pass); otherwise (stage over or not re-runnable live) it is queued (`state: "queued"`) in `scan_status.followup` and the `done` event, and the UI offers a follow-up run (`scan_start { from_stage, sources? }`). `ok: false` + `reason`: `no_scan`, `finished` (stage over), `pending` (restart of a stage not reached yet), `unsupported` (see `scan_status.controls`); `not_found` for an unknown item |
| `scan_retry_source` | `{ id }` - `startpage` \| `mojeek` \| `brave_web` \| `yahoo` | `{ ok, reason? }`-"Retry source" after manual CAPTCHA verification: while the Search stage is active, re-queries the source after the current round (up to 2 retries per domain; clears a prior skip), emitting new `source` events (`running` → `ok`/…). `ok: false` + `reason` ("Search stage already finished: verification saved for the next scan") if idle or past Search; `not_found` for other sources |
| `fuzz_estimate` | `{ project?, modules?: string[], wordlists?: string[], rate?, threads?, max_requests?, max_time_min? }` | `{ hosts: string[], candidates, calibration, requests, seconds, capped_by_budget, per_module: { [module]: n }, skipped_excluded, rate, max_requests, max_time_min, note, note_msg: { code, params } }`, offline Site Discovery estimate (launch wizard): web URLs come from live hosts in prior scan facts eligible for active scope (before first scan: target domains as `https://domain/`), capped at `settings.fuzz.max_hosts`; `requests` reflects request budget and `seconds` reflects rate and `max_time` |
| `wordlists_list` | - | `{ items: [{ id, kind: "builtin"\|"remote"\|"custom", name, source, lines, size, sha256?, downloaded }], selected: string[] /* settings.fuzz.wordlists */, seclists_commit, modules: [{ id, name, desc }] /* fuzz modules for wizard */ }`-"Settings → Wordlists". Built-in lists (SecLists, MIT) are always available; `remote` lists are larger and downloaded on demand; `custom:<name>` are user-imported |
| `wordlists_download` | `{ id, project? }` | `{ ok, id, size, lines }`: downloads a `remote` wordlist from `raw.githubusercontent.com` (pinned SecLists commit; passive request not touching any target, logged to `project` or latest project), validating size and SHA-256 (returns `checksum`/`too_large` without saving on mismatch). Network errors return `net` |
| `wordlists_import` | `{ path /* from platform_pick_files */, name? }` | `{ ok, id: "custom:<name>.txt", name, lines, dropped, size }`: imports a custom wordlist up to 64 MB (`too_large`); sanitizes entries (drops `..`, `://`, query/encoding chars `?`/`%`, whitespace/control chars, `.git/*` except `HEAD`) and deduplicates; returns `bad_args` if no valid words remain |
| `wordlists_delete` | `{ id }` | `{ ok }`: deletes a downloaded or custom wordlist (and removes it from `settings.fuzz.wordlists`); built-in lists return `bad_args` |
| `logs_get` | `{ level?: "debug"\|"info"\|"warn"\|"error", since?: id, limit?: number /* 500 */ }` | `LogEntry[]`: engine log ("Debug" tab): stage/source start & finish with durations, HTTP statuses, retries, errors. In-memory ring buffer (4,000 entries) + rotating file `<data>/logs/foca.log` (1 MB × 3). `since` is the last received entry ID (incremental fetch) |
| `scan_status` | - | `ScanStatus`: includes `active`, `profile`, `profile_id`, `targets`, `modules`, `started_at` so after a UI restart the "Active mode" banner and profile restore accurately; also includes `stage_index`, `sources: [{id,name,status}]`, `auto` (scan was auto-resumed after process eviction: UI shows "interrupted by system: resuming"), `substep` (running sub-step of the stage, see the `substep` event, or `null`), `controls` (`{ "stage:*" \| "source:<id>" \| "step:<id>": [actions] }`: what `scan_control` supports), `held` (`["stage:network", "step:brute", …]`: items paused by the user), `followup` (restarts queued for a follow-up run), `only` (chosen items of a follow-up run, empty for a full scan) and `stages` (stage ids the run executes, `null` for a full scan; the scan screen shows the others as not selected). The UI treats a scan as running exclusively from `scan_status.running` (polled every 4 s while active and on app resume); if the core reports idle, the UI shows "Scan interrupted by system" |
| `finding_set_status` | `{ project, id, status: "new"\|"confirmed"\|"false"\|"accepted"\|"fixed" }` | `Finding` |
| `finding_update` | `{ project, id, patch: { sev?, notes?, tags?, photos?, status? } }` | `Finding`. These fields represent user triage and must never be overwritten by subsequent scans |
| `finding_photo_add` | `{ project, id, name, from?, path? }` | `Finding`: attaches photo evidence. `path` comes from `platform_pick_image` (copy in private dir): the core copies it into `<data>/files/<project>/photos/` (sanitizing the name and appending `_2` on collisions) and records the stored filename in `photos[].name`; without `path`, records metadata only |
| `finding_playbook` | `{ project, id, lang?: "uk"\|"ru"\|"en" }` | Contextual remediation playbook `{ id, host, rule, playbook_key, key_label, lang, title, summary, effort: "quick"\|"medium"\|"planned", effort_label, steps: [{ step, title, action, command?, owner }], verify, references, disclaimer }` for finding `id`. Step titles carry no number (the UI numbers them by `step`); `lang` defaults to the effective UI language. Commands are sanitized; secrets and raw `evidence` are never included |
| `doc_file` | `{ project, id }` | `{ path, name, size }`: stored document file path in the project directory (for Share / Save via `platform_share { path }`); `not_found` if not downloaded |
| `doc_import` | `{ project, paths: string[] }` | `{ imported, ids }`, imports local user files into a project with zero network access (copies file, extracts metadata, runs analysis; F-6, I-19): used by "Data → Documents → Add local files", new-project wizard, and "Pre-publication check". Paths come from `platform_pick_files` |
| `import_offline` | `{ project?, name?, domain?, paths?: string[], files?: [{ name, data /* base64 */ }], max_files? = 500 (≤ 2000), max_mb? = 512 (≤ 2048) }` | `{ project, imported, ids, duplicates, skipped: [{ name, reason: "too_many_files"\|"file_too_large"\|"total_too_large"\|"not_a_file"\|"bad_data" }], errors: [{ name, error }], cancelled, bytes }`: offline analysis (1.3) of files, folders (copies from `platform_pick_folder`), and ZIP archives with zero network requests. Without `project`, creates a new project named `name` (default: `"Offline analysis YYYY-MM-DD"` / localized) with optional `domain` target. ZIPs are unpacked in memory (`foca_meta::for_each_zip_member`, recursing one level into nested ZIPs): each member becomes a document (`source: "zip:<archive>"`) and the archive itself is stored as a document without re-parsing children. Archive member names are display labels only (basename, control chars stripped); files are stored by SHA-256. Each file is parsed in its own task under `Limits` with a 30 s timeout (`error: "timeout"`); files > 100 MiB are skipped. Followed by analysis. Emits `{ type: "import", project, stage: "parse"\|"analysis"\|"done", done, total, name }` |
| `demo_case_import` | `{ name? }` | Same result as `import_offline` plus `demo_case: true`. Built-in reference offline demo case: creates a new project `name` (default: "Reference case" in the effective UI language; scope `example.test`) and parses 12 synthetic documents from fictional "Example LLC" embedded in the core (`crates/foca-engine/assets/demo_case.zip`, ~21 KB; generator: `qa/make_demo_case.py`) through the exact `import_offline` pipeline: zero network traffic (empty request log), ~1 s. Contents: two DOCX revisions sharing RSIDs (lineage), QES-signed PDF (test QTSP), PDF with flawed redaction, PDF with multi-author revisions, XLSX with hidden sheet and data connection, LNK (UNC path, machine name, MAC), EML with `Received` chain and internal relays, JPEG with GPS and camera serial, ODT, ICS with meeting link, VCF. Produces findings (`doc.bad_redaction`, `doc.signer_identity`, `doc.lnk_*`, `mail.*`, `gps`, `doc.lineage`, `doc.hidden_content`, `doc.data_connection`, `pdf-revisions`, etc.), populates graph and network map, and supports all report templates. Repeated calls create additional projects |
| `import_cancel` | - | `{ ok }`: cancels an in-progress offline import after the current file (`cancelled: true` in `import_offline` response) |
| `docs_search` | `{ project, q, limit? = 50 (≤ 200), offset?, include_deleted? }` | `SearchPage { total, query, hits: [{ doc, name, url, snippet, in_name, masked: string[], rank, deleted }] }`: full-text search (FTS5, 1.3) over document names and extracted text. Safe query syntax: `"phrase"`, `word`, `pref*`, `-exclude`, everything else treated literally. `snippet` ≈ 180 chars: highlights wrapped in `{{h:…}}`, secrets and PII masked as `{{s:<mask>}}` (raw values are never indexed because text is stored pre-masked); `masked` lists redacted categories (`"pii:card"`, `"secret:…"`) |
| `doc_get` | `{ project, id }` | `{ doc: Doc, format, forensics: { signatures: Signature[], bad_redactions: [{ page, fill, rect, text }], hidden_content: [{ kind: "vanish"\|"row"\|"column", location, text }], pdf_revisions: PdfRevision[], scan_without_text, xmp_history: XmpEvent[], xmp_ids, pii: PiiFound[], links: [{ url /* tokens masked */, host, service, shared, internal, expires, tokens: [{ name, kind }], sev }], fields: { "<prefix>:<key>": value } /* lnk:, eml:, msg:, ics:, vcf:, media:, zip:, visio:, xl:connection:, xl:pivotCache, chart:, wpd:, pub:, indd: */, embedded: [{ name, format }] } }`: document detail card and forensic breakdown (1.3). Texts are masked (`{{s:…}}`); signer tax ID (RNOKPP) is returned only as `rnokpp_masked`. Returns `format: null, forensics: null` when no metadata is available |
| `rules_get` | `{ project }` | `{ presets: [{ id, title, description, rules: [{ id, title, pattern, sev, mask }] }], config: RulesConfig }`, custom search rules (YARA-lite, 1.3): presets `ua-gov`, `credentials`, `infra`, `crypto`, `personal` plus project-specific rules (`analysis.rules`) |
| `rules_set` | `{ project, config: RulesConfig }` (or `{ project, presets, rules }`) | `{ config, new_findings }`: saves rules and recomputes `doc.user_rule` findings. `RulesConfig = { presets: string[], rules: [{ id, title, pattern, sev, enabled, case_insensitive = true, mask = true }] }`; invalid patterns (length > 512, > 64 rules, empty match, excessive regex complexity) return `bad_args` with a message and save nothing |
| `rules_test` | `{ pattern, case_insensitive? = true, text /* ≤ 64 KiB */ }` | `{ count, hits: [{ start, end /* byte offsets in text */, value /* masked */ }] }`: tests a regex pattern against sample text without saving; returns `bad_args` on invalid pattern |
| `doc_delete` | `{ project, ids: number[] }` | `{ deleted }`: count of soft-deleted documents (sets `deleted` flag, moves file to project trash; findings belonging to a deleted document are removed rather than marked "Fixed"). Derived snapshot entities must be computed over live (non-deleted) documents only: `software`/`printers`/`paths` (excluding zero-count items), `people.docs`, `pcs.docs`, `gps`, `secrets`, `events`; text-extracted people whose source document was deleted receive `src_deleted: true`. The UI reloads the snapshot afterward so counts stay identical across restarts |
| `doc_restore` | `{ project, ids: number[] }` | `{ restored }`: count of documents restored from trash; derived snapshot entities are recomputed over live documents just like after `doc_delete` |
| `doc_clean` | `{ project, ids, options? } \| { path, name?, options? }` | `{ cleaned: [{ id /* null for external file */, name /* copy *_clean.ext */, source? /* original filename (path mode) */, path /* private cleaned copy path or null */, removed: string[], manual: [{ kind: "secret"\|"remaining"\|"invalid"\|"format", where }], clean: bool, verify: VerifyReport\|null, grade_before, grade_after /* "A".."F" or null */, size /* copy size in bytes */, at }] }`: cleans documents via `foca_meta::clean_and_verify` (OOXML, ODF, PDF, JPEG, PNG) with before/after self-verification (see "Document Hygiene"). `options` = `CleanOptions` (`remove_embedded_files`, `remove_javascript`, `remove_annotation_authors`, all `true` by default). Secrets embedded in document body text cannot be stripped via metadata cleaning (`manual`, `clean: false`); snapshot records `doc.cleaned = { at, name, manual }`. `{ path }` mode handles standalone files outside any project (Android "Share to FOCA-rs", cached internally): writes copy to `<data>/clean/shared/` without touching network or projects |
| `hygiene_get` | `{ project, ids? } \| { path, name? }` | `{ set: SetHygiene, docs: [{ id\|null, name, ext, grade, score, format, cleanable, issues }] }`: A-F hygiene grades (`foca_meta::grade_document` / `grade_set`) computed over analyzed project documents (from stored metadata) or a single external file (see "Document Hygiene") |
| `secret_reveal` | `{ project, id: number \| "f<id>:<k>" }` | `{ id, value }`: returns plaintext value of a document secret or the `k`-th evidence fragment of a finding; called only after UI biometric/PIN confirmation |
| `secret_hibp_check` | `{ project, id: number \| "f<id>:<k>" }` | `{ id, pwned: bool, count: number, prefix: string }`, strictly opt-in check of a discovered secret against HIBP Pwned Passwords (`foca_net::hibp`, k-anonymity: only the 5-char SHA-1 prefix is transmitted, logged to project `request_log` with `module: "hibp"`, and the full secret never leaves the device) |
| `settings_get` | - | `Settings` |
| `settings_set` | `{ patch }` (deep merge) | `Settings` |
| `i18n_bundle` | `{ lang?, device_locale?, include_help? }` | `{ lang: "en"\|"ru"\|"uk", ui_code: "EN"\|"RU"\|"UA", setting: "auto"\|"en"\|"ru"\|"uk", ui: { [key]: string }, findings: null \| { catalog, terms, roles, tech_cats, host_sources, sources }, help: null \| { sections, acc, screens_lead, screens, glossary, profiles_html, articles } }`: serves the active UI translation dictionary (and lazily the offline help bundle when `include_help: true`) directly from `locales/{en,ru,uk}/` embedded in the core over IPC without relaxing WebView CSP |
| `licenses_get` | `{}` | `{ schema: "foca-licenses/v1", app_license: "GPL-3.0", repository, counts, data_assets, rust_crates, android_libs, license_texts }`: auto-generated offline license inventory (generated and verified by `qa/gen-licenses.py --check`) |
| `key_set` | `{ service, value }` | `KeyStatus` (plaintext stored in Android Keystore; only masked value returned) |
| `key_delete` | `{ service }` | `KeyStatus` |
| `net_check` | - | `{ ok, out_ip, country, via }`: actual egress IP observed through the active proxy |
| `net_proxy_check` | `{ proxy? /* URL, host:port (SOCKS5) or "direct" */, addr?, type? = "socks5"\|"http", group? }` | `{ ok, latency_ms, out_ip, country, org, ip_kind: "tor"\|"datacenter"\|"vpn"\|"residential"\|"unknown", error? }`: checks a proxy (the given one, or the one from settings for `group`) for reachability, latency and exit IP class; used by "Settings → Network & proxy" |
| `report_list` | `{ project }` | `Report[]` |
| `report_build` | `{ project, template?: "full"\|"executive"\|"compliance"\|"lab", custody?: bool = false, opts: { tpl, tpl_id: "full"\|"brief"\|"data", fmt: "html"\|"pdf"\|"md"\|"csv"\|"json"\|"docx", lang, min_sev, confirmed, custody?, sections, picked?, picked_only?, secrets?, company?, logo?, ai_summary?: bool = true } }` | `Report`. `ai_summary`: include the project's report AI summary (the latest from `ai_summarize` or the one picked with `ai_summary_use`) as the labelled section "Executive summary (AI-assisted)" in HTML/MD/DOCX and the `executive` template; without a stored summary nothing is added. The summary text is not copied into `Report.opts`. Filename patterns: `Звіт_пентест_<project>_vN.<fmt>` (UA), `Отчёт_пентест_…` (RU), `Pentest_report_…` (EN); for `csv`/`json`: `Data_<project>_vN.<fmt>` with `lang: "-"`; for `docx`: self-contained OOXML document with embedded severity distribution PNG chart. `N` increments sequentially per project. `size` and `created_at` are computed by the core (not provided in `opts`). `result` is a frozen snapshot of included results (see `Report`): history previews render from `result` rather than live data, and risk is scored from included findings only. A sidecar `<name>.sha256` is always written alongside the file; when `custody: true` or a `ReportSigner` is available (on Android: `AndroidKeyStore` ECDSA P-256), `<name>.sig.json` is also created and a "Chain of Custody" section is embedded in the report |
| `report_templates` | `{ lang?: "UA"\|"RU"\|"EN" }` | `[{ id, title, description }]`, report templates localized to UI language (`lang`, falling back to `settings.ui.look.lang`, then RU), ordered: `full` (complete report, default; output unchanged), `executive` (1-page executive summary: risk score, top-5 findings in plain language, 3 immediate actions, no technical tables), `compliance` (KSZI / compliance matrix: findings × MITRE ATT&CK v20 / CWE (2025 Top 25 marked) / OWASP Top 10:2025 / WSTG v4.2 / ISO/IEC 27001:2022 / NIST SP 800-53 Rev. 5 = ND TZI 3.6-006-24 / legacy ND TZI 2.5-004-99 / ND TZI 3.7-003-05, control, measure, personal data and service summaries, auditor disclaimer), `lab` (academic lab report: objective, methodology, input data, procedure, findings table mapped to standards, conclusions, blank author/reviewer fields). Top-level optional `report_build.template` takes precedence over `opts.tpl_id`; unknown ID returns `bad_args`. `executive`/`compliance`/`lab` templates render to `html` (printable to PDF under the same CSP) and `md`; `csv`/`json` export raw data as usual. `Report.opts.tpl_id` stores the template ID and `Report.tpl` stores its localized title. Standards mapping: `crates/foca-analysis/signatures/standards.toml`, see `docs/STANDARDS.md` |
| `report_verify` | `{ project, id? \| name? }` | `{ ok, id, name, exists, actual_sha256, expected_sha256, hash_match, sidecar_present, sig_present, signature_alg, signature_valid, key_alias, key_fingerprint, signature_own_key, custody, status }`, verifies report file integrity against `.sha256` and `.sig.json` manifest (`status`: `"verified_signed"` \| `"verified_foreign"` \| `"verified_hash"` \| `"tampered"` \| `"unsigned"` \| `"missing"`; `ok` is `true` for the three `verified_*` statuses). `key_fingerprint`: lowercase hex SHA-256 of the signer's public key from the manifest (`null` without a signature). `signature_own_key`: `true` when the signature was made by this device's `ReportSigner` key, `false` when it verifies under another device's key, `null` when not checked (no signature, broken manifest, no signer available). `verified_foreign` = hash matches and the signature is valid but was made on another device (not tampering: compare `key_fingerprint` with the sender's); `verified_signed` = valid signature by the own key. A missing file returns the same keys with `null`s and `status: "missing"` |
| `report_delete` | `{ project, id }` | `{ ok }` |
| `export_build` | `{ project, kind: "findings"\|"users"\|"emails"\|"paths"\|"software"\|"hosts"\|"docs"\|"log"\|"all", fmt: "dict"\|"csv"\|"json"\|"maltego"\|"md"\|"httpx"\|"nuclei"\|"stix", opts: { dict?: "users"\|"logins"\|"context"\|"emails"\|"paths"\|"software"\|"custom", ad_domain?, delim?, bom?, pretty?, mal?, md?, secrets?, pii?, items? } }` | `{ name, path /* real path in private export directory */, saved_as /* "Download/FOCA-rs/<name>": destination after "Save to files" */, size, count, secrets, pii_redacted }`. Finding card "Share" uses `kind: "findings", fmt: "md", opts.items: [id]` → `platform_share { path }`: export files are assembled by the core (F-25/26); filename format `<project-without-tld>_<kind or dict-…>_<YYYY-MM-DD>.<ext>`. `dict: "logins"` generates login username patterns (`i.petrov`, `ipetrov`, `CORP\i.petrov` with KMU-2010 / ICAO transliteration); `dict: "context"` builds a contextual pentester wordlist from company, domains, departments, hosts, and years (no secrets); `httpx`/`nuclei` produce clean `.txt` target lists (`nuclei -l`/`httpx -l`); `stix` produces a STIX 2.1 JSON bundle (MISP / OpenCTI / SIEM, always stripped of raw secrets); the `log` kind writes `error` as `<kind>: <detail>` in the export language (`foca_core::reqlog` kinds, detail via the `reqlog` templates of `findings.json`) |
| `wordlist_preview` | `{ project, kind?: "logins"\|"context" = "logins", limit?: number = 100, ad_domain?, lowercase?: bool = true, include_years?: bool = true, include_service?: bool = false }` | `{ kind, count, total, ad_domain: string\|null, patterns: [{ id, label, count, examples }], items: string[] }`: previews login username patterns (with automatic AD domain detection `DOMAIN\user` and transliteration) or a contextual pentester wordlist; project secrets and raw tax IDs / payment cards are never included |
| `ai_models_list` | `{ provider?, base_url?, refresh?, show_all? }` | `{ provider, host, models: [{ id, label, thinking, adaptive_thinking, manual_thinking, context_window, max_output_tokens }], source: "api"\|"cache"\|"no_key"\|"offline"\|"bad_url", error, error_msg }` (`error_msg`: `{ code, params }` of a known core message or `null`, so the UI shows `error` in its language): queries the live model catalog directly from the cloud provider API (`openai`, `anthropic`, `gemini` native `v1beta`, `deepseek`, `xai`, `mistral`, `groq`, `together`, `openrouter`, `custom`), extracting model capabilities from the provider response, with `show_all: true` to list all account models unfiltered |
| `ai_preview` | `{ project, opts: { provider?, base_url?, model?, lang?: "ru"\|"uk"\|"en", redact?: { secrets, pii, client, evid } } }` | `{ id, text, lang, tokens, redacted, marks: { SECRET, EMAIL, NAME, CLIENT, INTERNAL-IP }, provider, model, host }`: returns the exact redacted prompt text that will be sent to the cloud provider. The prompt and the requested answer language follow `lang` (default: the effective UI language, `ui_lang`). Placeholders are language-neutral: `[SECRET]`, `[EMAIL]`, `[NAME]`, `[CLIENT]`, `[CLIENT-DOMAIN]` (counted as `CLIENT`), `[INTERNAL-IP]` (I-20; `marks` keys are wire literals) |
| `ai_summarize` | `{ project, preview_id, opts: { provider?, base_url?, model?, thinking?: "auto"\|"off"\|"minimal"\|"low"\|"medium"\|"high"\|"xhigh"\|"max", thinking_budget?, max_tokens?, temperature?, show_thoughts?, redact?, lang? } }` | `{ id, md, thoughts, model, provider, lang, created, tokens_in, tokens_out, tokens_thoughts, preview_id, source_badge: "Cloud API" }`, invokes the cloud API with native reasoning parameter mapping (`Anthropic` adaptive `thinking` + `output_config.effort` or `budget_tokens`; `Google Gemini` `thinkingLevel` for 3/4+ and `thinkingBudget` for 2.5; `OpenAI`/`xAI`/`Mistral`/`Groq`/`Together` `reasoning_effort`; `DeepSeek` `thinking.type`; `OpenRouter` `reasoning.effort`); in `thinking: "auto"` mode and when `temperature` is unset, unnecessary fields are omitted. One request per project at a time: a second call while one runs fails with `busy` (no second provider call); `ai_cancel` ends it with `cancelled`. A non-empty `md` is added to the project history (project setting `ai_summaries`, newest first, at most 50: `{ id, text, thoughts, provider, model, lang, created, tokens_in, tokens_out, tokens_thoughts }`) and becomes the report summary (project setting `ai_summary`), see `report_build.opts.ai_summary`; the report puts the client name and domain back in place of `[CLIENT]`/`[CLIENT-DOMAIN]` (also the Russian placeholders of summaries stored up to 2.0.0-beta.2) |
| `ai_cancel` | `{ project }` | `{ cancelled: bool }`: stops the running `ai_summarize` of the project (`false` when none runs) |
| `ai_summaries_list` | `{ project }` | `{ items, report_id, running }`: stored summaries, newest first (a summary stored before the history appears as `ai-legacy`); `report_id` is the one the report uses (`null` = none); `running`: an `ai_summarize` of this project is in flight |
| `ai_summary_use` | `{ project, summary }` | Same as `ai_summaries_list`: the chosen summary becomes the report section. Unknown id: `not_found` |
| `ai_summary_delete` | `{ project, summary }` | Same as `ai_summaries_list`: drops the summary; if the report used it, the report section is removed. Unknown id: `not_found` |
| `pin_set` | `{ pin, panic? }` | `{ ok }`; 4-8 digit PIN stored hashed (`bad_pin` on invalid input) |
| `pin_check` | `{ pin }` | `{ ok, panic, attempts_left }`; matching the panic PIN runs `wipe_all` and returns `panic: true` |
| `wipe_all` | `{ confirm: "WIPE" }` | `{ ok }`: securely wipes all projects, API keys, and settings (panic PIN / "Delete everything") |
| `tool_file` | `{ path /* file from platform_pick_files / Share cache */ \| data /* base64 */, name?, timeout_ms? = 5000 }` | `{ name, ext, size, sha256, format, metadata: { title, author, last_modified_by, company, manager, template, application, producer, os, created, modified, printed, edit_time_secs, revision, people, emails, paths, servers, printers, software, links, gps, camera }, forensics: { comments, revisions, rsids, hidden_sheets, has_macros, macro_modules, has_javascript, encrypted, incremental_updates, old_versions, attachments, embedded, signatures, pdf_revisions, hidden_content, scan_without_text, thumbnail, xmp_history, warnings }, pii: PiiFound[], bad_redactions, secrets: [{ type, mask, where, sev, rule }], findings: [{ rule, title, sev, category, description, recommendation, evidence /* {{s:mask}} */ }], grade: HygieneReport, cleanable, risk, clean_with: { cmd: "doc_clean", args: { path, name } } \| null, partial, error, elapsed_ms, requests: [] }`, Quick Tools (1.5): File without a project and with zero network access: runs the same parser pipeline as offline import (`foca_meta::extract` + `pii::sanitize` + finding analysis) without writing to project storage. Cleaning uses existing `doc_clean { path }` (`clean_with`). If budget expires, returns `partial: true, error: "timeout"` along with `size`/`sha256` |
| `tool_mail_domain` | `{ domain /* domain, e-mail, or URL */, timeout_ms? = 5000, fetch_policy? = true }` | `{ domain, risk: { level: "low"\|"medium"\|"high"\|"unknown", reasons: string[], spoofable }, mx, spf: Spf\|null, dmarc: Dmarc\|null, dkim: { selectors, checked, wildcard }, bimi, mta_sts: { record, policy, fetch: { status: "ok"\|"error"\|"timeout"\|"skipped", error? } }, tls_rpt, caa, dnssec, issues: [{ id, sev, title, detail }], partial, incomplete: string[], lookups: { done, total }, elapsed_ms, requests }`, Domain Mail Check: checks SPF / DMARC / DKIM (`foca_net::mail::DKIM_SELECTORS` dictionary + wildcard check) / BIMI / MTA-STS / TLS-RPT / CAA / DNSSEC via parallel DNS queries (DoH over proxy per `settings.net.dns_mode`); fetching the MTA-STS policy file is the sole HTTP request to `mta-sts.<domain>` (scoped strictly to that host). Spoofing risk: `high`, no enforcing DMARC (or `p=none`) without SPF `-all`, or SPF `+all`; `medium`: DMARC `pct<100`, enforcing DMARC without working SPF, or SPF `-all` without DMARC; `low`: DMARC `reject`/`quarantine` at 100% plus SPF `-all`/`~all`; `unknown`: DNS failed for root TXT or `_dmarc` (`partial: true`, missing checks listed in `incomplete`) |
| `tool_host` | `{ url \| host, timeout_ms? = 5000 }` | `{ input, host, port, host_port, url /* final URL after redirects */, status, headers: HeaderAudit\|null, header_issues: [{ id, sev, title, detail }], technologies: Technology[], favicon: { url, mmh3, sha256, md5, size, queries } \| null, tls: { port, version, cipher, alpn, ocsp_stapled, leaf: CertInfo, chain, trust, hostname_match, days_left, issues, error } \| null, steps: { page, tls, favicon: { status: "ok"\|"error"\|"timeout"\|"skipped", error? } }, partial, elapsed_ms, requests }`, Host / URL check on explicit user action: TLS certificate (`foca_net::tls::inspect_standard` + audit), single page GET (security headers `foca_recon::headers`, technologies `foca_recon::tech`), and favicon (`<link rel=icon>` or `/favicon.ico`, mmh3 for Shodan/FOFA). `NetClient` scope is restricted strictly to this host (redirects to any other host are blocked and recorded in `requests` with `blocked: true`). Without a scheme, tries `https://` then `http://` |
| `tool_secret` | `{ value, hibp_opt_in? = false, timeout_ms? = 5000 }` | `{ length, classes: { lower, upper, digit, symbol }, entropy_bits, score: 0..4, strength: "very_weak"\|"weak"\|"fair"\|"strong"\|"very_strong", crack_time: "instant"\|"minutes"\|"days"\|"years"\|"centuries", issues: ("short"\|"few_classes"\|"common_word"\|"sequence"\|"repeats"\|"digits_only"\|"year")[], detected: { rule, title, kind } \| null, mask, hibp: { status: "not_requested"\|"ok"\|"timeout"\|"error", pwned?, count?, prefix?, error? }, partial, elapsed_ms, requests }`, Password / Secret Check: the input value is never stored, logged, or echoed back (only `mask`). Without `hibp_opt_in`, runs 100% locally (0 network requests); with `hibp_opt_in: true`, sends only the 5-char SHA-1 prefix via k-anonymity (`Add-Padding: true`) |
| `tool_log` | `{ limit? = 100 }` | `[RequestRecord + { tool: "mail"\|"host"\|"secret" }]`: recent (≤ 200, in-memory) Quick Tools network requests, newest first; each tool response also returns its own calls in `requests` |
| `tool_log_clear` | - | `{ ok, removed }`: empties the Quick Tools request ring (`removed` = records it held); project request logs are not touched |
| `queue_add` | `{ projects: string[] \| project, profile?: "passive"\|"std"\|"full"\|"custom" = "std", args?: { /* scan_start fields: sources, modules, exts, limit, fuzz, ports… */ } }` | `QueueView + { added: string[] /* item IDs */, skipped: string[] /* projects already pending in queue */ }`: scan queue (1.5); returns `not_found` for unknown projects. Launches items via normal `scan_start` (identical scope checks: error marks item `error` and queue advances) |
| `queue_list` | - | `QueueView = { items: [{ id, project, name, profile, status: "pending"\|"running"\|"done"\|"stopped"\|"error", scan_id, progress, reason, error, added_at, started_at, finished_at }], total, done, pending, index, current: { id, project, name, index, scan_id, progress } \| null, percent /* overall: (done×100 + current progress)/total */, paused, pause_reason, running, waiting /* waiting for an external scan to finish */ }`; also restarts the queue worker if pending work remains |
| `queue_pause` | - | `QueueView`, global queue pause: prevents launching the next item and pauses (`user`) its own active scan |
| `queue_resume` | - | `QueueView`: unpauses the queue and its scan, or launches the next pending item |
| `queue_remove` | `{ id }` | `QueueView`; if the item is currently running, also issues `scan_stop` with `reason: "queue"` (does not pause the queue); returns `not_found` if absent |
| `queue_clear` | `{ stop? = false }` | `QueueView`, removes all non-running items; `stop: true` also stops the active item (`reason: "queue"`) and clears the entire queue |
| `alert_rules_get` | `{ project? }` | `{ enabled, min_severity, rules, tls_warn_days, tls_crit_days, risk_threshold, risk_delta, risky_ports, max_alerts, telegram: { enabled, chat_id, ready }, webhook: { enabled, kind, ready }, lang, available_rules, history }`: event-driven alert configuration and delivery history (`tg_bot` and `webhook` secrets stay in KeyVault and are never returned) |
| `alert_rules_set` | `{ project?, patch }` | Same payload as `alert_rules_get`: saves per-project or global alert rules (any accidental `token`/`url`/`secret` fields are stripped). Switching a channel on without its settings (Telegram: bot token in KeyVault + `chat_id`; webhook: URL in KeyVault) fails with `alert_not_ready` + `message_msg` |
| `alert_test` | `{ project?, channel: "telegram"\|"webhook" }` | `{ ok, channel, status: number\|null, attempts, sent, error: string\|null, error_msg? }`: sends a test notification via `foca_net::notify` using KeyVault credentials and logs to `request_log` without leaking the token or URL |
| `risk_trend_get` | `{ project, limit? = 30 }` | `{ points: [{ scan_id, time, risk, counts, total, complete }], current: number\|null, previous: number\|null, delta: number\|null, direction: "up"\|"down"\|"flat"\|"none", peak: number\|null }`, risk score history across scans (`foca_analysis::alerts::risk_trend`) |
| `signatures_status` | `{}` | `{ schema: "foca-sig-bundle/v1", version, updated_at, source: "builtin"\|"bundle", sha256, pubkey_ed25519, signature_valid, can_rollback, counts: { cpe /* software + OS signatures */, cve /* CISA KEV entries used for matching */, secrets /* loaded secret rules incl. bundle */, standards /* rule to standard references */ }, added_kev, added_cpe /* stored, not used for matching */, added_secrets, kev: { catalog, released, total /* CISA catalog size */, used, products, age_days, stale /* > 30 days */ }, software: { software, os }, std_map: { rules, refs, frameworks: [{ id, label, legacy }] }, feed_url, last_check: null \| { at /* local */, outcome: "installed"\|"up_to_date"\|"no_update"\|"failed", feed_url, version, error, error_msg?, error_code } }`: status of the signature database as loaded by the analysis (`foca_engine::sigbundle`, see [signature bundles](dev/signature-bundles.md)). Counts come from the loaded tables, never from the numbers a bundle claims |
| `signatures_import` | `{ bundle_json }` or `{ bundle }` | Same as `signatures_status`: verifies `SHA-256` and the `Ed25519` signature against the built-in key, atomically activates the bundle and keeps the previous one for rollback. Errors: `bad_args` (JSON, schema, empty rule), `bad_signature` (checksum or signature), each with `message_msg` (`core.sig.*`) |
| `signatures_update` | `{ url? }` | Same as `signatures_status`: checks the update feed (`url`, default the official feed `https://github.com/SinonApp/FOCA-rs/releases/download/signatures/signatures.bundle`; HTTPS public host or loopback HTTP). HTTP 404/410 gives `last_check.outcome: "no_update"`, a verified bundle that is not newer gives `"up_to_date"`, a newer one is installed (`"installed"`). A failure (`net`, `bad_args`, `bad_signature`) is recorded as `"failed"` and returned as the error; the active database never changes then |
| `signatures_rollback` | `{}` | Same as `signatures_status`: rolls the signature database back to `previous.json` or the built-in revision |
| `plugins_list` | `{}` | `{ items: [{ id, name, version, author, description, kind, runtime, permissions, sha256, enabled, builtin, source, url_template }], counts: { total, enabled, builtin, custom } }`, catalog of built-in and installed plugins (`F-27…F-30`, `foca_engine::plugins`) |
| `plugin_install` | `{ manifest }` | `PluginInfo` item: validates JSON/TOML manifest (including `wasm_b64` magic bytes and memory `<= 16 MiB`) and installs a user plugin |
| `plugin_toggle` | `{ id, enabled }` | `PluginInfo`: enables or disables a plugin and persists its state |
| `plugin_remove` | `{ id }` | `{ ok: true, id }`: removes a user-installed plugin (built-in plugins cannot be removed → `bad_args`) |
| `plugin_run_test` | `{ id, target?, passive?, sample_body?, fuel_limit? }` | `{ ok, id, runtime, fuel_used, hosts, urls, findings, blocked_reason, http_url }`: sandboxed test execution enforcing `Scope` and [ADR-0009](adr/0009-passive-never-touches-target.md) |
| `demo_reset` | - | demo only: restores initial seed data |
| `terms_get` | - | `{ version /* core TERMS_VERSION */, accepted, accepted_version \| null, accepted_at \| null }`: Terms of Use acceptance state (initial `/terms` screen, shown before any other screen including app lock). Persisted in core settings as `{ terms_version, accepted_at }`, omitted from `settings_get`, immutable via `settings_set`, reset by `wipe_all`; bumping `TERMS_VERSION` re-prompts |
| `terms_accept` | `{ version }` | Same as `terms_get`; returns `bad_args` if `version` does not match current |
| `logs_get` (extended) | `{ level?, since?, limit?, source?: "core"\|"android"\|"all" }` | `LogEntry[]` with `source` field. `android` parses `<data>/logs/android.log*` (Kotlin `FLog`); `all` merges entries chronologically |
| `logs_clear` | - | `{ ok, files }`: clears the core ring buffer, `foca.log*`, `android.log*`, and `crash-*.txt` (app logs; the project request log is `request_log_clear`) |
| `logs_export` | `{ device?: string /* "Device" text from UI */ }` | `{ name: "FOCA-rs_logs_<timestamp>.zip", path, size, files }`: builds a ZIP in the export folder containing `foca.log`, `android.log`, `crashes/crash-*.txt`, and `device.txt`. Secret scrubbing is mandatory: API key values from storage and secrets across all projects → `[СЕКРЕТ]`, passwords in URLs (`user:***@`), parameter/field values matching `key/token/secret/password/pwd/auth/session/cookie/sig` and `Bearer …` → `***` (`crates/foca-engine/src/analysis/redact.rs`, unit-tested). The UI then shares via `platform_share { path }` |
| `crash_list` | - | `[{ name, size, kind: "rust"\|"android", title }]`: lists `crash-*.txt` files (Rust panics and Kotlin crashes), newest first |
| `crash_get` | `{ name }` | `{ name, text }` (scrubbed of secrets); returns `bad_args` if name does not match `crash-*.txt` |
| `search_journal` | `{}` | `{ engines: { <id>: { requests, answered, links, captchas, cached, moved, taken_over, blocked } } }`: dork engine counters for the current core lifetime ("Debug → Search"): requests, answered pages, domain links found, CAPTCHAs, cached pages, groups handed off to other engines after CAPTCHA / taken over from others, currently blocked by CAPTCHA |
| `search_fingerprint` | `{}` | `{ ok, fp, issues }`: loads a local page (`RenderRequest.html`, origin `https://fingerprint.foca.invalid/`) in the embedded search WebView and returns its fingerprint (`fp.userAgent, platform, languages, webdriver, visibilityState, hidden, hasFocus, maxTouchPoints, innerWidth/innerHeight, screen, devicePixelRatio, uaMobile/uaPlatform/uaBrands/uaModel` Client Hints, `rafPerSecond`, `timezone`…) plus `issues` flagging anomalous browser traits (`; wv`, hidden, webdriver, UA/touch/width/Client Hints mismatches, stalled rAF). Outside Android returns `unsupported` |
| `search_fingerprint_page` | `{}` | `{ name, path }`: writes the same test page to `Download/FOCA-rs/FOCA-rs_fingerprint.html` (open in Chrome via `platform_share` to compare) |
| `request_log_get` | `{ project, limit? = 500, only_active? }` | `[{ id, time, scan_id, module, method, url /* scrubbed */, host, status, bytes, access: "passive"\|"target"\|"active", blocked, error, error_code, error_detail, error_detail_msg?, note /* fuzz: soft404\|calibration\|filtered\|rate_limited (1.0.1) */, ctype }]`, newest first; `error_code` is a stable kind for the UI (`timeout`, `refused`, `tls`, `dns`, `out_of_scope`, `http_status`, `network`, `cancelled`, `redirect`, `limit`, `other`, …; one classifier, `foca_core::reqlog::LogError`, shared with the report exports), `error_detail` the raw text after the code (`error` keeps the full raw string); `only_active` filters to target-touching requests only |
| `request_log_clear` | `{ project, scan_id?, days?, before?, dry_run?: bool = false }` | `{ ok, removed, kept_running, dry_run }`: deletes request log rows of the project. No filter: the whole log; `days` (≥ 1): rows older than that many days; `before`: rows logged before an ISO time in UTC (wins over `days`); `scan_id`: only that scan (filters combine). Rows of the project's running or paused scan always stay (`kept_running` counts those the filter would have taken) and `scan_id` of that scan gives `busy`. `dry_run: true` only counts. `scan_delete` removes a scan's rows through the same store code. Report "Request log" sections and the `requests-log` CSV built afterwards are shorter. Errors: `bad_args` (`days: 0`), `busy`, `not_found` |
| `search_captcha_test` | `{ engine: "startpage"\|"brave_web"\|"yahoo"\|"mojeek" }` | `{ ok, supported, engine, kind, signals, status, url, error? }`: manual diagnostic from "Debug › Search": loads one results page in the built-in browser and classifies it (results / captcha / block). Never runs before scans; `supported: false` without the Android WebView |
| `app_info` | - | `{ version, commit /* build git hash, FOCA_GIT_HASH */, data_mb, log_level }` |
| `demo_first_run` | - | demo only: resets Terms acceptance (demo menu "First run") |

## Platform Commands (Android)

Routed through the same bridge: `invoke("foca", { cmd, args })` → `src-tauri/src/bridge.rs` → Kotlin plugin
`app.sinon.focars.platform.FocaPlugin` (JS has no direct access to the plugin). In the demo backend these are stubs
with `demo: true`; demo screens display their demo bottom sheets as before. Demo tools ("Demo states" menu, "Reset demo
data", demo PIN hint, "Demo: …") are visible only when `F.isDemo` (no `window.__TAURI__`). The E2E harness `foca serve`
responds to `platform_*` with stubs (`stub: true`), while still resolving real files for Share/Save. Errors use
`{ code: "platform" | "not_found" | "bad_args", message }`.

| Command | Arguments | Response |
|---|---|---|
| `platform_share` | `{ path? /* from export_build */, project?, report? /* id from report_list */, name?, mime? }` | `{ ok, name }`: Android system Share (`ACTION_SEND`). Files are served only from private app storage: exports by filename in `exports/`, reports from `reports/<project>/<name>`; an external copy is served from `cache/share` via `FileProvider` |
| `platform_save` | same as `platform_share` | `{ ok, path: "Download/FOCA-rs/<name>", uri }`: MediaStore Downloads (Android 10+; the OS appends `" (1)"` on name collisions); on Android 7-9 opens the system "Save as" picker (`{ ok: false, cancelled: true }` on cancel) |
| `platform_pdf` | `{ project, report /* id from report_list; HTML only */ }` or `{ path }` | `{ ok, path, name, size }`-"PDF" report export without the print dialog: the HTML report is rendered in an off-screen WebView (no JS, no network) and written as an A4 PDF to `<exports>/<report stem>.pdf` (then shareable/savable via `platform_share`/`platform_save { path }`). Errors: `bad_args` (not an HTML report), `busy` (another PDF is being created), `timeout`, `platform`. `platform_print` stays the fallback. Not available outside Android (`unknown_command`) |
| `platform_open_url` | `{ url }` | `{ ok: true }`: opens an external link (e.g. "How to get a key") in the system browser. Only absolute `http`/`https` URLs with a host and without credentials are accepted (`bad_args` otherwise; checked in the bridge and again in Kotlin). Android: `ACTION_VIEW` + `FLAG_ACTIVITY_NEW_TASK`, no browser installed → `platform` error; desktop: the OS default browser |
| `platform_print` | `{ project, report /* id from report_list; HTML only */ }` or `{ path }` | `{ ok, name }`-"PDF" report export: loads the report HTML in an isolated WebView (no JS, no network) and hands it to Android's `PrintManager` (A4) so the user saves as PDF. `report_build { fmt: "pdf" }` still generates HTML. Not available outside Android (`unknown_command`): the UI reports this honestly |
| `platform_biometric` | `{ title?, subtitle? }` | `{ ok, available, error? }` - `BiometricPrompt` (`BIOMETRIC_WEAK`). When `available: false` (no sensor, not enrolled, lockout), the UI falls back to the app PIN (`pin_check`); `error: "cancel"` means user cancelled |
| `platform_secure` | `{ on }` | `{ ok, applied }` - `FLAG_SECURE`: blocks screenshots/screen recording and blanks the Recents preview. The bridge automatically applies `settings.sec.block_shots` (opt-in, missing = off) after `settings_get`/`settings_set`; the flag is persisted and applied before the first frame on next launch |
| `platform_battery_status` | - | `{ ignoring /* excluded from battery optimization */, supported, oem: "xiaomi"\|"samsung"\|"pixel", rom, manufacturer, model, android, sdk, label /* e.g. "Xiaomi 14 · HyperOS 1.0 (Android 14)" */, notifications }` |
| `platform_battery_settings` | `{ what? /* "battery" or a step key/label from /settings/battery: Apps, Battery saver, Notifications, Private DNS… */ }` | `{ opened: opened_screen_key \| null }`: launches `ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS`, MIUI autostart (`com.miui.securitycenter`), app notifications, etc.; falls back to the app info screen |
| `platform_notifications` | - | `{ enabled }`: legacy alias for `platform_request_notifications` |
| `platform_permissions_status` | - | `{ notifications, notifications_runtime /* API 33+ */, notifications_blocked /* permanently denied */, battery /* excluded from optimization */, oem, manufacturer, brand, sdk }`: powers the onboarding permissions screen (`/permissions`, immediately after Terms) and "Settings › Background Execution". Refreshed automatically on app resume (`visibilitychange`) |
| `platform_bg_status` | - | `{ oem /* xiaomi \| samsung \| huawei \| oppo \| vivo \| other */, autostart /* on \| off \| unknown (MIUI/HyperOS app-op 10008) */, battery_unrestricted, hide_recents, hide_recents_default, hide_recents_chosen }`-"Settings › Background" OEM card, the launch screen hint and the `autostart` line of Debug › Device. `foca serve` answers with a fixed desktop stub (`oem: "desktop"`, `autostart: "unknown"`, `battery_unrestricted: true`, `hide_recents: false`) |
| `platform_bg_set` | `{ hide_recents }` | Stores "Hide from Recents during scans" in the native layer (missing = OEM default); replies like `platform_bg_status` |
| `platform_verify_search` | `{ url, title? }` - `url` restricted to `https://www.startpage.com/…`, `https://www.mojeek.com/…`, `https://search.brave.com/…`, `https://search.yahoo.com/…` (otherwise `bad_args`); the bridge adds `markers` (the core's challenge phrases, `foca_engine::verify_markers()`) | `{ state, ok, closed, detail? }` after the dialog closes. Visible full-screen WebView sharing the hidden browser's profile (`CookieManager`, DOM storage, `ProxyController`, mobile UA without `; wv`, images enabled, no `X-Requested-With`) with Cancel, Done, a load progress bar and an error state with Retry (load error or no finished load within 30 s). `state`: `done` only from Done on a page without challenge markers (cookies are flushed only then), `not_solved` (Done while the captcha or challenge is still shown), `cancelled` (Cancel, Back, dismiss, the app left the foreground or its Activity was destroyed), `failed` (the page did not load). `ok` is true only for `done`; only `done` may mark the engine verified and trigger `scan_retry_source`. No automated bypass exists. Outside Android (desktop, `foca serve`): `{ ok: false, unsupported: true, error }`; demo returns `{ state: "done", ok: true, demo: true }` (QA passes `demo_state` to pick another outcome) |
| `platform_request_notifications` | - | `{ granted, action: "none"\|"requested"\|"settings" }`: requests `POST_NOTIFICATIONS` (Android 13+); if permanently denied or on Android < 13, opens app notification settings. Denial breaks nothing; a silent request on first scan remains a fallback only if the user has never answered |
| `platform_exit` | - | `{ ok }`-"Decline" on the Terms screen: calls `finishAffinity()`; in demo/harness shows a placeholder screen |
| `platform_device_info` | - | `{ manufacturer, brand, model, release, sdk, rom, abi, app_version, mem_total_mb, mem_avail_mb, disk_free_mb, service_running, battery_ignoring, notifications, tz, net, vpn }`: powers "Debug › Device" |
| `platform_pick_files` | `{ multiple? = true }` | `{ ok, cancelled, files: [{ path, name, size, mime }] }`: system file picker (Storage Access Framework, no storage permissions required); selected files are copied into private `files/picked/` and returned via `path` (passed to `doc_import`) |
| `platform_pick_folder` | `{ max_files? = 500, max_mb? = 512 }` | `{ ok, cancelled, files: [{ path, name, size, mime }], skipped, truncated, bytes }`, folder picker (1.3): `ACTION_OPEN_DOCUMENT_TREE` (no storage permissions), traverses the tree in the background (depth ≤ 6) and copies files into `files/picked/tree-<timestamp>/` within limits (file count, total size, per-file ≤ 100 MiB) with flattened, deduplicated filenames. Followed by `import_offline { paths }`, then `platform_pick_clear`. Outside Android returns a platform error; demo returns `{ ok: false, cancelled: true, demo: true }` |
| `platform_pick_clear` | - | `{ ok, removed }`: deletes all temporary picked file copies (`files/picked/`) after import (the core retains its own content-addressed SHA-256 copies) |
| `platform_pick_image` | `{ camera? }` | Same flow for photos: system Photo Picker (Android 13+, previously `ACTION_GET_CONTENT image/*`) or camera (`ACTION_IMAGE_CAPTURE`) without storage permissions; passed to `finding_photo_add { path }` |
| `platform_clipboard_read` | - | `{ ok, text, available, error? }`: primary clip text via `ClipboardManager` (`coerceToText`, capped at 256 Ki chars). The Android WebView never grants the async Clipboard API read, so the paste buttons use this. `ok: false` means the clipboard could not be read (`error`: `no_focus` when the app has no window focus, `blocked` when a clip exists but the system or ROM withholds it, `unavailable`, `platform`); `ok: true, text: ""` is an empty clipboard. Desktop, `foca serve` and the demo answer `{ ok: false, unsupported: true }` and the UI falls back to `navigator.clipboard` |
| `platform_clipboard_write` | `{ text /* up to 1 MiB */, sensitive?, clear_after_ms? /* up to 600000 */ }` | `{ ok, scheduled }`: `setPrimaryClip`. `sensitive` sets `ClipDescription.EXTRA_IS_SENSITIVE` (Android 13+ hides the value in the copy preview); `clear_after_ms` schedules the conditional auto-clear in the native layer (rules of `platform_clipboard_clear` with `expected` = this text). Missing `text`: `bad_args` |
| `platform_clipboard_clear` | `{ expected? }` | `{ ok, cleared }`: `clearPrimaryClip()` (Android 9+, an empty clip before). With `expected` the clipboard is wiped only while it still holds that value; when the system hides the clipboard (no window focus), only if the app wrote that value last and no other clip change was seen since. Only a SHA-256 of the last written value is kept in memory |
| `platform_shared_files` | - | `{ files: [{ path, name, size, mime }], skipped, truncated }`, handed out once: files received through "Share → FOCA-rs" and copied into the private cache (content URIs only, count/size limits). The UI asks at start and on the `shared` event, because the copy may finish before or after the WebView loads |

**Background scans.** On the `started` event, the bridge starts a `dataSync` foreground service (notification showing
project name, current stage, percentage, "Open" → `#/p/scan`, "Stop" → `scan_stop { reason: "user" }`, and a partial
`WAKE_LOCK`), stopping it on `done`/`stopped`. On Android 15+, hitting the 6-hour `dataSync` timeout pauses the scan
with reason `android`, resumable via "Resume".

**`net` event** (`listen("net")`, Android app only): `{ online, transport: "wifi"|"cellular"|"ethernet"|"other"|"none",
vpn, metered, battery, charging, thermal, paused /* environment pause reason */, user_paused, action: { type: "pause"|"resume"|"stop", reason } | null }`.
Environment-driven pauses are controlled exclusively by the core (`src-tauri/src/policy.rs`, driven by
`settings.power`/`settings.net`): offline → `offline`; `wifi_only` on cellular → `wifi`; battery below `batt` while not
charging (`batt_action: "stop"` stops the scan), `charge_only` while unplugged, overheating with `heat` → `thermal`
(distinct reason: "Paused: overheating"); dropping a VPN that was active during the scan with `kill_switch` → stops
with `vpn` in active mode or when `kill_action ≠ "pause"`, otherwise pauses. `api.js` renders the "Offline" banner and
pause reason; network-triggered `scan_pause`/`scan_resume` calls pass `{ reason: "offline" }` as a hint rather than a
user override. Attempting manual resume while an environment condition holds returns `blocked`.

## Scope Rule (Shared Across UI, Demo Backend, and `foca-core::scope`)

Implemented as `FOCA_RULES.scope` in `ui/js/sel.js`; the demo backend invokes it directly and `F.sel.scope.*` is a thin
wrapper. Matches `crates/foca-core/src/scope.rs`. The core must enforce this rule on every target-facing request.

1. Input is normalized: lowercase, stripped of scheme, port, path, and trailing dot; `[v6]` → bare IPv6 address.
2. **Exclusions override targets**: if a host or IP matches any exclusion, it is denied even if covered by a target.
3. Hostname matching: `domain`/`host` covers the domain itself and all subdomains; `wild` (`*.d`) covers
   **subdomains only**, never `d` itself; `url` covers only the exact host from the URL; `org`, `person`, `email`, and
   `asn` grant no host access (external sources only). Subdomain boundaries require a dot: `evilcontoso.ua` is not
   within `contoso.ua`.
4. IP matching: `ip`, `cidr`, `range` (`a: b`), and `url` with an IP literal host. Untyped exclusion strings are parsed
   with the same rules.
5. A hostname with a known IP (`hosts[].ip`) is checked by both hostname and IP (excluded by either → denied; allowed
   by either → allowed). A hostname exclusion propagates to its known IPs: `203.0.113.20` is denied if excluded
   host `mail.…` resolves to it, even when `203.0.113.0/24` is a target. `excludedIn` counts how many addresses inside a
   network target are excluded.
6. Return shape: `{ ok, target, excluded?, via?, code: ""|"no_host"|"excluded"|"out_of_scope", reason }`. The active
   phase checks targets using this exact same rule with no separate per-target permissions.

## Active Phase

There are no pre-launch confirmation gates (removed in 1.0: project `allow_active` toggle, `active_ack` checkbox,
hold-to-confirm button, confirmation screen, and confirmation log). User responsibility is acknowledged once on the
first-run Terms of Use screen. Any profile launches with a single tap on "Start".

| Tier | Modules | What It Touches |
|---|---|---|
| `external` ("Passive") | search, crt.sh, web archives, Shodan cache | Never contacts the target (out-of-scope targets are queried against external sources only) |
| `target` ("Standard", "Custom" with `dns`/`docs`/`alive`) | DNS against target NS, document downloads, TCP liveness | In-scope network targets, excluding exclusions |
| `active` ("Full", `axfr` and `fuzz`: Site Content Discovery, `kind: active` plugins) | active phase | All in-scope network targets, excluding exclusions (`Scope.active_phase` is set by the engine from the launch profile) |

The wizard strips out-of-scope and excluded targets before starting a scan (displaying a snackbar listing them); the
core returns `out_of_scope` if any are submitted directly. The optional scope field `basis` ("Authorization note")
renders an "Assessment Basis" section in reports when populated.

## Scan: Launch Rules, Retry, Resume, and App Restart

- **Targets come from the current scope.** Without `targets`, the core uses all scope targets; passing `targets` narrows
  the selection. For `target`/`active` tiers, every network target must belong to the current scope and pass the scope
  rule, otherwise `out_of_scope` is returned with the offending list. Non-network targets (organization, person, e-mail,
  ASN) are always allowed (external sources only). Under `external`, out-of-scope targets are also permitted (targets
  entered in the "New Scan" wizard are not automatically written into project scope).
- **Scans are incremental and non-destructive.** Stages append new documents, entities, findings, and hosts and enrich
  existing records (e.g. adding metadata to a previously downloaded document). Already-analyzed records are never
  overwritten with empty placeholders. User triage (`status`, `sev`, `notes`, `tags`, `photos` on findings) and
  **document deletions** (`deleted`) made before or during a scan are preserved.
- **Resume (`resume_from`)** reuses the same history record: `scan_id` equals the `stopped` record ID, and the stopped
  entry is replaced upon completion (`done`) or another stop. Progress resumes from `progress`; stages up to `stage`
  re-apply idempotently. Scope and active-phase validation are identical to a fresh scan against the current scope.
- **App restart during a scan**: an active scan must survive UI restarts via the foreground service; if the OS kills the
  process, the next startup records it in history as `stopped` with `reason: "restart"`, `progress`, and `stage`, making
  it resumable. The demo backend keeps the active scan in `STATE.run` and mirrors this behavior.
- **History records follow one rule** across generated, `done`, and `stopped` runs: `snapshot.docs` lists non-deleted
  documents at record time, `people` lists authors of analyzed documents among them, `hosts` maps host → software
  fingerprint, `findings` maps ID → severity of active findings (excluding false positives and fixed); `findings =
  |snapshot.findings|`, `new_findings` counts IDs absent from the previous record's snapshot; `added: { docs, people,
  hosts, findings }` tracks increments for this scan ("Collected so far" for stopped scans). Re-running with no changes
  yields an empty diff and identical counts.
- **Search sources.** External (passive) sources run in parallel, up to 4 concurrently, followed by target-facing
  sources (crawler: "Standard"/"Full" only) seeded with discovered subdomains. Each source has an overall timeout
  (`settings.net.source_timeout`, default 90 s; paginated slow archives get ×3, Wayback 270 s): a stalled source ends
  with `timeout`, can be skipped (`scan_skip_source`), and the stage moves on. Paginated sources (Wayback, CC, OTX,
  Arquivo, dorks) yield partial results at a soft deadline rather than discarding work. Status updates stream in
  real time. Catalog (ID → output; all keyless and `Passive`: zero requests to the target):
  - documents/URLs: `wayback` (paginated CDX `showNumPages`→`page=N`, block extension filtering, local MIME filtering,
    archived copies `web/<ts>id_/<url>`), `cc` (last 3 indexes, 24 h `collinfo.json` cache), `arquivo` (textsearch by
    type → `noFrame/replay/<ts>id_/` copies), `otx_url` (`url_list?page=`), `urlscan`, `hudson` (URLs from infostealer
    logs);
  - HTML-parsed dorks `site:<domain> filetype:<ext>`: `ddg`, `bing`, `mojeek`, best-effort ("no guarantees"),
    CAPTCHA/block → `blocked`;
  - **Shared scan dork queue (1.1)** (`foca-search::sources::dorkpool`): domain queries are grouped by document family
    (`pdf`, `doc|docx|odt|rtf`, `xls|xlsx|ods`, `ppt|pptx`); engines supporting `OR` (Startpage, Brave, Yahoo, SearXNG,
    Bing, DDG) issue a single grouped query `site:d (filetype:a OR filetype:b)`, while Mojeek queries per extension. One
    engine executes a group (if empty, one more tries, `MAX_TRIES = 2`); **on CAPTCHA/block, the group returns to the
    queue for other healthy engines to pick up** (failover), and idle engines wait while peers hold active groups.
    Budget: 24 queries per engine per scan; 24 h result cache (`<data>/dork-cache.json`, key `engine|query|page`);
    pacing 6-14 s with jitter (HTTP dorks 2.5-5 s); pagination advances only when the current page yields ≥ 6 new domain
    links and a "Next" control exists. First Brave/Mojeek request per scan warms up on the homepage. Source note (`ok` +
    `error`) summarizes handoffs/takeovers; per-engine totals are logged under `foca::scan`.
  - 1.1 additions: `yahoo` (Bing results via Yahoo in WebView; EU cookie consent wall → `blocked` with `verify_url`) and
    `searx_pool` (public SearXNG pool via WebView: `searx.space/data/instances.json`, 24 h cache, clearnet only,
    uptime ≥ 90%, search success ≥ 80%, top-12 by working engines; instances returning 403/429/rate-limit are banned for
    the scan, up to 3 instances per query; no CAPTCHAs). `url_source_with_base("searx_pool", base)` supports a custom
    instance.
  - **Embedded-browser dorks**: `startpage` (Google results via Startpage), `brave_web` (keyless Brave Search), and
    `mojeek` when a WebView is available. The core describes a scenario (`foca-search::render::RenderRequest`: open URL,
    `wait` until "Verifying your request" clears, `submit` form, `click` "Next") executed by a hidden
    `android.webkit.WebView` (Kotlin `RenderFetcher`, bridge `EngineConfig::render` → JNI `FocaDirect.render_fetch`; one
    task at a time, cookies persist across requests so completed checks survive, proxy from `settings.net` applied via
    `ProxyController`: failing closed rather than falling back to direct if unsupported). The core parses the HTML.
    Iterates selected extensions up to 3 pages each with 3-6 s pauses, stopping when no new domain links appear; scoped
    to target domain and deduplicated. Request log records `method: "RENDER"`, `access: "passive"`. Overall timeout ×4
    (`budget`); "Skip" supported. Statuses: `blocked` with `error` describing CAPTCHA / failed check / IP automated
    query block; outside Android (CLI, `foca serve`, desktop) reports `unavailable` ("requires Android WebView") and the
    scan continues. Enabled by default (`search` module). Direct Google / Google CSE is not used.
  - subdomains: `crt`, `crtname`, `scanmalware`, `certspotter`, `anubis`, `hackertarget`, `rapiddns`, `subcenter`, `thc`,
    `shodanct`, `otx_dns` → `engine.net.ct_hosts`; each host's `source` lists the discovering sources (`"crt.sh, Anubis, …"`).
  - IP enrichment: `internetdb` (Shodan InternetDB, Network & DNS stage): ports → `services`, CPE → `tech`, CVEs →
    finding (`rule: internetdb-cve`, ≥ 10 CVEs = `high`, otherwise `warn`).
  - user plugins: `plugins` (Network & DNS stage, runs when the `crt` or `dns` module is on): every enabled
    **custom** plugin (WASM or declarative; built-in manifests are skipped because they mirror core sources) runs once
    per in-scope target domain through the scan's `NetClient`, with a fuel budget and a 30 s wall-clock limit per run.
    Plugin URLs pass `authorize_plugin_url` with the full project scope and `passive` unless the scan runs at the `active` level (Full or an active custom profile), so passive and
    standard scans never let a plugin touch a target host. Up to 200 returned hosts per run are kept if in scope and
    resolvable; plugin findings are merged into network facts. Statuses: `off` (`n: 0`) without enabled custom plugins,
    `ok` (`n` = hosts + findings kept), `error` with `error: "плагины с ошибкой: <id>: <reason>; …"` when a plugin
    failed, timed out or was blocked by scope/SSRF/permission checks: a failing plugin never fails the scan.
    A target-touching plugin in a passive/standard scan is held back by policy (ADR-0009, `blocked_passive`): this is
    not an error, the note `error: "не запущены в пассивном режиме (обращаются к цели): <id>, …"` is appended, and
    when every plugin was held back the status is `skipped` (the only way this source reports `skipped`; it is not
    listed in `env.incomplete_sources`).
  Disabling a source sets `settings.sources.<id>.enabled: false` ("Settings → Sources"): in `scan_start` it immediately
  reports `off` and is skipped. The core persists each source's latest outcome in `settings.source_status.<id> = { status, n, error, at }`.
- **Downloads**: only documents new to the project enter the download queue (deduplicated against project tasks
  before applying `limit`, so rescans fetch subsequent items), round-robined across sources, with images capped at a
  separate quota (one third of `limit`). Under the Passive profile, target-hosted URLs (from CC, OTX, dorks) are fetched
  via Wayback copies `web/<ts>id_/<url>` (matching snapshot/index timestamp or closest to 2025) so the target is never
  touched.
- **Custom profile** honors `modules`: sources are enabled by `wayback` (`wayback`, `cc`, `arquivo`), `search` (APIs,
  dorks, `arquivo`), `crt`/`dns` (subdomains, InternetDB), and `docs` (crawler); Network stage enables DNS summary
  (`dns`), subdomains/RDAP/InternetDB (`dns` or `crt`), TCP liveness (`alive`), and zone transfer (`axfr`).
- **AXFR** issues only AXFR queries for an in-scope zone name directly to its authoritative NS servers (often hosted on
  third-party DNS infrastructure, classified as `Access::ZoneInfra`: zone passes `check_active`, NS must not match
  exclusions by name or IP). Request log records `access: active`, URL `dns+tcp://<ns>:53/<zone>/AXFR#ns-target-zone`.
- **DNS over proxy**: `settings.net.dns_mode: "system"|"doh"|"auto"` (default `auto` = DoH whenever a proxy is active).
  DoH uses JSON RFC 8484 (`cloudflare-dns.com`, `dns.google`) routed through the same proxy/Tor; no direct DNS leaks
  occur when a proxy is enabled (fail-closed: DoH failure returns a DNS error). IP-based scope exclusion lookups also
  route through DoH when proxied.
- **Risk score** remains `null` ("no data") until at least one scan completes or stops after the Analysis stage.

## Site Content Discovery (Stage `fuzz`, Crate `foca-fuzz`)

Analogous to the original FOCA's "Backups Fuzzer": searches a client's website for forgotten documents, backups,
exposed service files, and open directory listings so the owner can remove them. Content discovery and soft-404
auto-calibration concepts come from ffuf, and wordlists from SecLists (both MIT).

- **When:** active phase only: "Full" (`fuzz` enabled by default) or "Custom" with `fuzz` selected; obeys the exact
  same rules as all other active modules (in-scope targets excluding exclusions; single-tap launch). Under "Standard"
  and "Passive", zero fuzz requests are sent and source `fuzz` reports `off`.
- **Targets:** stage `fuzz` ("Site Discovery") runs after "Network & DNS" and before "Report". Targets are live web
  hosts from network facts (ports 80/443/8080/8443 and TCP liveness ports) plus URL targets, strictly in scope;
  exclusions take precedence (hosts/IPs enforced by `NetClient` across every redirect hop and `Host:` vhost candidate;
  paths filtered by `settings.fuzz.exclude_paths`). Processes at most `max_hosts` targets, `settings.net.hosts_parallel`
  of them at once (1 = one after another).
- **Polite pacing:** 4 threads, 5 req/s (bounded by global `settings.net.rps`), jitter, and per-scan budgets
  `max_requests` and `max_time_min`; rate, jitter and the throttling detector are per host, the budget and time are
  one pool for all hosts running at once. Auto-stops a host on sustained 429/403/5xx/error bursts (the other hosts go
  on) → status `blocked`, warning `fuzz_blocked`, no retries. Performs no defense evasion, parameter fuzzing, payload injection, credential stuffing, or
  repository/database dumping; response body reads are capped at 64 KB.
- **Pause/stop/resume** propagate to discovery (immediate pause, request cancellation on stop); "Resume" reruns the
  stage idempotently. "Stop discovery" invokes `scan_skip_source { id: "fuzz" }`.
- **Findings** (emitted live, `module: "fuzz"`, `active: true`, `category: "web"`, short evidence with secrets masked):
  `fuzz-git` (Exposed `.git` repository, High), `fuzz-db-backup` (Database backup exposed on the internet, High),
  `fuzz-backup` (Backup file exposed on site, risk-based severity), `fuzz-exposed` (Exposed service/config file,
  risk-based severity), `fuzz-dsstore` (Exposed `.DS_Store` file, Medium, listing discovered filenames in evidence),
  `fuzz-listing` (Open directory listing, Medium), `fuzz-vhost` (Hidden virtual host, Low), `fuzz-path` (Discovered
  path, Info, emitted only when `show_paths` is enabled). Title format: `"<label>: <path>"`.
- **Documents** discovered directly or extracted from directory listings / `.DS_Store` enter the normal download queue
  (`source: "fuzz"`, deduplicated against existing project docs up to `limit`) and are downloaded and parsed within the
  same stage.
- **Request log:** every request is recorded in `request_log` with `module: "fuzz"`, `access: "active"`.
- **Report:** under "Infrastructure" → "Found on Site" subsection (severity, finding, URL, evidence).

## Site Reconnaissance (Stage `recon`, Crate `foca-recon`)

Passive/adaptive site reconnaissance: technology stack with version detection (flagging outdated versions), analytics
IDs, favicon hash (Shodan/FOFA/Censys queries), endpoints and secrets inside JS (secrets stored masked only),
`robots.txt` / `sitemap.xml` / `security.txt` from web archives, cloud storage bucket references, and domain mentions
in public code (`grep.app`).

- **When:** module `recon` is enabled in all default profiles (and in "Custom" when checked). Stage `recon` ("Site
  Recon") runs after "Network & DNS" and before "Site Discovery", covering up to 3 target domains,
  `settings.net.hosts_parallel` of them at once (source events of different sites may interleave; per-source states
  are stored in target order).
- **Access tier:** `external` (Passive) sends zero requests to the target: homepage, favicon, and up to 5 same-origin
  scripts come from Wayback (`<wayback>/web/2025id_/<url>`, original headers read from `x-archive-orig-*`);
  `target`/`active` fetch directly from the site (`TouchesTarget`, scope and exclusions enforced by `NetClient`).
  `robots.txt`/`sitemap.xml`/`security.txt` are always fetched from archives (CDX + snapshots). Bucket listing runs only
  in `active` mode (GET to the cloud provider, never to the target); otherwise buckets are listed as `unchecked`.
- **Sources** (`source` events, per-source timeout `settings.net.source_timeout`, skippable via
  `scan_skip_source { id }` until stage end): `recon` (site pages, `n` = detected technologies), `webaudit` (web audit
  of `recon` pages, `n` = findings; `off` if no page was retrieved), `wellknown` (`n` = hidden paths + sitemap URLs +
  `security.txt`), `buckets` (`n` = storage buckets), `grepapp` (optional; Vercel challenge / HTTP 429 → `blocked`
  "bot protection", scan continues).
- **Resume** after a stop reruns the stage; per-host data is replaced and findings remain idempotent (stable IDs).
- **Findings:** `module: "recon"`, rules `recon.*` (outdated versions, JS secrets, open buckets, favicon hash…), merged
  into the main findings list.
- **Storage:** project facts under `engine.recon`; exposed in snapshot as `recon` (`ReconView`, see "Types").
- **Web Audit (`webaudit`, `foca_recon::webaudit`)** runs immediately after page fetches without a separate stage.
  Access tier follows the scan profile: `external` (Passive) makes zero requests and inspects already-fetched
  archive responses (`x-archive-orig-*` headers) for security headers, CSP domains, CORS headers, and source map
  references; `target` (Standard) adds GET probes on in-scope hosts (`.map`, Swagger/OpenAPI, Spring Actuator,
  `openid-configuration`; logged under `recon.sourcemap`, `recon.apidocs`); `active` adds `OPTIONS`/`TRACE`/`PROPFIND`
  (never `PUT`/`DELETE`), reflected-Origin CORS checks, and GraphQL introspection (modules `http_options`, `http_trace`,
  `webdav_propfind`, `cors_origin`, `graphql_introspection`). Hosts extracted from CSP/source maps/API docs: in-scope
  hosts join the host list; out-of-scope hosts enter `oos_list` (`source: "csp"`, `why_key: "oos.why.csp"`) with zero
  requests sent to them. Findings use `recon.web.*` (`module: "webaudit"`), and snapshots expose `recon.web[]`:
  `{ host, level, requests, errors, headers: [{ url, issues: [{ id, sev, title, detail }] }], csp_domains: [{ host, wildcard, directives, in_scope, hint }], hosts, candidates, source_maps: [{ url, script, via, sources, has_content, packages, local_paths, secrets, truncated }], api_docs: [{ kind, url, title, spec_version, api_version, endpoints, operations, auth, unauthenticated }], cors, methods }` (raw secret and cookie values are never stored).

## Port Scanning (Stage `ports`, `foca_net::ports`)

- **When:** module `ports` runs exclusively at the active tier: "Full" (default) or "Custom" with `ports` selected
  (selecting `ports` elevates the scan to active, like `axfr`/`fuzz`). In "Passive" and "Standard" the stage is skipped
  with zero connection attempts and source `ports` reports `off`. Stage `ports` ("Ports") runs after "Network & DNS" and
  before "Site Recon".
- **Hosts:** resolved hosts from network facts (excluding dangling CNAMEs) that are in scope and not excluded (by
  hostname or IP, double-checked by `NetClient` via `Access::active("ports")`); deduplicated to one scan per unique IP
  (other hostnames sharing the IP inherit the result); target domains prioritized first; capped at `max_hosts` (20);
  `settings.net.hosts_parallel` hosts (default 4) are scanned at once, each with its own timeout, so a host that times
  out ends only itself.
- **Ports:** `settings.ports = { top: 100|1000|0, list: "22,80,8000-8100", max_hosts: 20, banners: true }` overridden by
  `scan_start { ports }`; `top: 0` uses custom `list`. Setting `settings.net.rps: 0` disables the connection rate cap.
- **Source `ports`** (`source` events): `running` (one per host as it starts) carries `host`, `ip`, `hosts`, `host_index`, `spec`, `timeout_s`
  (per-host timeout = `settings.net.source_timeout`, minimum 30 s); completes with `ok | skipped | timeout | error` and
  `n` = open port count; skippable via `scan_skip_source { id: "ports" }` until stage end. Resuming skips hosts already
  scanned in the same scan.
- **Unreliable scan detection (1.0.1).** On-device local VPNs/proxies (AdGuard, v2rayNG, corporate firewalls, tarpits)
  accept TCP connections on every port. Safeguards: (1) once per stage, probe unroutable TEST-NET addresses
  (`192.0.2.1:443`, `198.51.100.1:47613`; skipped when an explicit proxy is configured): if a connection succeeds, the
  network intercepts TCP and host scanning is aborted; (2) before each host, probe 3 random canary ports in 49152-65535
  (logged with `(canary)`): if more than half open, skip scanning that host; (3) post-scan heuristic: if > 40% of tested
  ports (with ≥ 20 tested) are open and > 50% of open ports return neither a banner nor TLS. Outcome: open ports are not
  written to `services`/`Host.ports`, no port findings are created, and prior port findings for that host are
  **deleted** (not marked `fixed`); `PortsScan.unreliable = "intercept" | "canary" | "mass_open"`; source status becomes
  **`unreliable`** with `unreliable: { hosts, intercept }` and an error message that tells the user to
  disable the local VPN or exclude FOCA-rs; UI displays an "Unreliable" pill + "What to do" button (Help →
  `ports-unreliable`), and reports display a notice in the "Open Ports" subsection (RU/UK/EN). On a subsequent reliable
  rescan, ports that are no longer open leave facts (analysis marks them `fixed`), and prior mass-open artifacts are
  purged. Hidden testbench settings: `settings.ports.canaries: number[]` (`[]` disables canaries),
  `settings.ports.intercept_probe: string[]` (`[]` disables TEST-NET probe).
- **Protocol confirmation.** If the secondary banner-grab connection fails (`refused` → closed, `timeout` → filtered),
  the port is not treated as open. `HostPort.confirmed` / `PortResult.confirmed` indicates protocol confirmation via
  response (Docker `GET /version` → JSON `ApiVersion`; port 2376 → TLS + same request, else `detail: "client-cert"`;
  Redis `PING` → `+PONG` (`detail: "no-auth"`) / `-NOAUTH` (`auth`); Elasticsearch `GET /` → JSON `cluster_name` or
  `security_exception` (`auth`); MongoDB `isMaster` reply; RDP X.224; SMB negotiate; PostgreSQL SSLRequest;
  FTP/SSH/MySQL/Telnet protocol banner). Unconfirmed ports produce an Info finding (`ports-unconfirmed`) rather than
  High/Critical, with `HostPort.sensitive = null`; `detail: "auth"` lowers severity to `warn`; port 990 is classified as
  `ftps` (implicit TLS), not FTP; `ports-admin` detects exposed management panels from banners (`pve-api-daemon` →
  Proxmox VE API, Webmin, MikroTik, iLO, iDRAC…). Only one finding is emitted per `IP:port` (attached to the primary
  hostname, with aliases listed in the description); duplicate findings on alias hostnames are removed. Port scanner log
  annotations use English tokens: `(canary)`, `(banner-retry)`, `(net-check: TEST-NET)`, `timeout: filtered`,
  `unconfirmed: banner retry failed`.
- **Results:** persisted in host facts (`NetHost.ports_scan`), enriching `services` with banners/versions over empty or
  InternetDB placeholders; exposed in snapshots as `Host.ports` (`HostPort[]`) and `Host.ports_scan` (`PortsScan`) (see
  "Types").
- **Findings** (`module: "ports"`, `active: true`): `ports-exposed` (internet-exposed service `host:port`: Telnet 23,
  RDP 3389, SMB 445, MySQL 3306, PostgreSQL 5432, Redis 6379, MongoDB 27017, Elasticsearch 9200 = `high`; FTP 21 =
  `warn`; Docker API 2375 and unauthenticated Redis replying `PONG` = `crit`, with remediation); `ports-outdated`
  (outdated web server version from `Server` header using `foca-recon` rules, `warn`).
- **Request log:** every connection attempt is logged to `request_log` with `module: "ports"`, `method: "TCP"`,
  `access: "active"`.
- **Report:** under "Infrastructure" after the hosts table → "Open Ports" (host, port, service, version/banner, source
  "scan"/"InternetDB cache", notes); JSON export includes `ports`. The core passes port data to reports via
  `Snapshot.ports` (report snapshot only; omitted from UI snapshot).

## Infrastructure (1.2): Subdomains, SaaS/M365, Mail, CDN, TLS/X.509, CT, Roles

Integrated into existing stages (stage count unchanged): "Network & DNS" (`network`), "Ports" (`ports`), and "Site
Recon" (`recon`). Stored in the project database's `infra` table (migration v7: `kind, key, json, scan, updated_at`),
queried via `infra_get`, and passed to reports in `Snapshot.infra` (report snapshot only). Findings appear in the main
list with `provenance.rule = "infra.<code>"` or `mail-<id>`.

| Module (`modules[]` in Custom profile) | Passive | Standard | Full |
|---|---|---|---|
| `infra`: SaaS detection via TXT/MX/CNAME, M365 tenant lookup (Microsoft endpoints only), BIMI/MTA-STS(DNS)/TLS-RPT/CAA/DNSSEC, CT timeline / abandoned subdomains / `O=` pivot (when `crt` is enabled), CDN/cloud detection via IP/CNAME, origin candidates (DNS), host roles | ✓ | ✓ | ✓ |
| `subdomains` (source `subdomains`): `top-1500` bruteforce, permutations (subdomains + document tokens), PTR on in-scope IPs | - | ✓ | ✓ (`top-5000`) |
| `tls` (source `tls`): TLS handshake on open TLS ports of live in-scope hosts (`EngineConfig.tls_ports`, default 443/8443/4443/9443/10443, plus `https` services); MTA-STS policy fetch | - | ✓ | ✓ |
| `nsec`: NSEC zone walking (same tier as AXFR) | - | - | ✓ |
| Active TLS (after Ports stage): TLS 1.0/1.1 & weak ciphers, STARTTLS on open 25/587/143/110/21/5432/3389, no-SNI probes on in-scope IPs (excluding shared hosting) and in-scope origin candidates | - | - | ✓ |
| `recon` on open non-standard web ports 8080/8443/3000/9000/5601/9200 of in-scope hosts (recorded as `host:port` site in `recon`) | - | - | ✓ |

- **Bruteforce pacing:** dedicated presets (`Pace::wifi`, or `Pace::doh` over proxy), never exceeding `settings.net.rps`
  when explicitly lowered below 5. Wordlist selection:
  `scan_start { subdomains: { wordlist: "off"|"top-1500"|"top-5000"|"custom", custom: string[]|string } }` (`off` skips
  bruteforce while keeping permutations, PTR, and NSEC active, recording `{ skipped: "off" }` in `dns_enum.brute`) ←
  `settings.subdomains` ← profile default. Persisted across resume via fact `subdomains_opts:<scan_id>`.
- **Headless (background monitoring):** bruteforce and permutations do not run (`subdomains` reports
  `skipped_headless`), and TLS inspection is capped at 5 hosts. A background core runs scans headless unless
  `scan_start` passes `headless: false` explicitly (used to resume an interrupted scan without the UI).
- **DNS hijack canary:** if DNS hijacking is detected (`canary.dns_hijack`), bruteforce is skipped (`subdomains` →
  `skipped`, `error: "canary.dns_hijack"`).
- **Scope:** in-scope hostnames discovered via bruteforce/permutations/PTR/NSEC/SAN join the project hosts with
  `source`: `bruteforce` | `permute` | `doc_token:<doc>` | `ptr` | `nsec` | `tls_san` | `m365`. External names (SAN,
  `O=`, tenant domains, out-of-scope origin IPs, PTR names, out-of-scope AD FS) go exclusively to `oos` (`source`:
  `san`|`org_pivot`|`tenant_domain`|`origin_ip`|`ptr`|`federation`) with zero requests sent to them.
- **UI snapshot `Host`** gains `roles: string[]` (`dev_stage`, `admin`, …), `priority: 0..100`, `cdn: InfraCdn|null`,
  and `tls` (summary of the latest inspection).

`infra_get` records (serialized directly by `foca-net`/`foca-analysis`):

| `kind` | Key | Payload |
|---|---|---|
| `saas` | domain | `{ domain, hits: [{ id, name, category, evidence: "txt"\|"spf_include"\|"mx"\|"cname", record }], unknown: string[] }` |
| `tenant` | domain | `TenantInfo { domain, exists, openid: { tenant_id, region_scope, … }, realm: { namespace, brand, auth_url, … }, federation_host, adfs, tenant_domains, onmicrosoft, errors }` |
| `mail_policy` | domain | `{ domain, bimi, mta_sts, mta_sts_policy, tls_rpt, caa: [{ flags, tag, value }], dnssec: "signed"\|"unanchored"\|"unsigned"\|"unknown", issues: [{ id, sev, title, detail }] }` |
| `cert` | `host:port` or `host:port/<mode>` | `{ host, port, mode: "tls"\|"starttls"\|"no_sni"\|"legacy", ip, sni, starttls, version, cipher, alpn, ocsp_stapled, error, chain: CertInfo[], trust: { status, detail? }, hostname_match, days_left, issues: [{ code, severity, detail }], pki: PkiHint[], legacy?: { versions, weak_suites }, scan, at }` |
| `ct` | domain | `{ domain, certs, timeline: HostTimeline[], abandoned: AbandonedHost[], orgs: { "<O=>": n } }` |
| `cdn` | host | `{ host, ip, provider, name, kind: "cdn"\|"cloud"\|"hosting", prefix, via: "ip"\|"cname" }` |
| `origin` | domain | `OriginAnalysis { cdn, candidates: [{ ip, score, sources, class, reasons }], dropped }` |
| `role` | host | `{ host, roles, tags: [{ role, token }], priority, alive, severity }` |
| `ptr` | IP | `PtrEntry { ip, names, forward_confirmed, hosting: "dedicated"\|"shared"\|"generic"\|"unknown", signals, hosts }` |
| `dns_enum` | domain | `{ domain, wordlist, headless, brute: { tried, hits, wildcard_levels, wildcard_filtered, unverified, failed, final_rps, lowest_rps, throttled } \| { skipped } \| { error }, permute?: { generated, hits, via_docs }, nsec?: { signing, names, complete, stopped, server, queries } }` |
| `oos` | host/IP | `{ host, kind, via, why, why_key: "oos.why.<kind>" }` |

Finding rule codes (`infra.<code>`): `cert_expired`, `cert_expires_soon`, `cert_not_yet_valid`, `cert_self_signed`,
`cert_unknown_ca`, `cert_invalid_chain`, `cert_incomplete_chain`, `cert_hostname_mismatch`, `cert_weak_signature`,
`cert_weak_key`, `cert_caa_mismatch`, `cert_internal_pki`, `tls_no_ocsp_stapling`, `tls_no_alpn`, `tls_legacy_version`,
`tls_weak_cipher`, `tls_origin_confirmed`, `tls_default_cert`, `dns_wildcard`, `dns_resolver_hijack`, `nsec_walkable`,
`ptr_shared_hosting`, `ptr_fcrdns_mismatch`, `saas_inventory`, `m365_tenant`, `m365_federated_adfs`, `origin_exposed`,
`ct_abandoned_subdomain`, `host_role_exposed`; mail policy findings (`low` and above) use `mail-<id>`. Rule catalog:
`foca_analysis::infra::RULES`; localized texts: `foca-report/src/ftext.rs`.

## Analytics (1.4): Correlation, Org Chart, Anomalies, KEV, Network Map, Graph, Timeline

Computed on demand from stored documents and `infra` records (CDP/AIA extracted from 1.2 TLS audits → `PkiInput`) during
re-analysis and `insights_get` (pure functions in `foca_analysis::insights`, executing in milliseconds with no new DB
tables or schema migrations required).

- **Findings** (`module: "analysis"`, triage preserved across recomputations): `doc.anomaly.<code>` (Low/Info, forensics
  tag, confidence ≥ 50; codes in `foca_analysis::anomalies`), `sw.kev` (matched by software/OS/technology: "Possibly
  vulnerable software (CISA KEV)" or "Likely vulnerable software (CISA KEV)" for EOL versions with post-EOL CVEs;
  `cve[]` lists matching KEV CVEs, tagged `possible`/`likely`; KEV does not encode version ranges), `doc.lineage`
  (copies/derivatives of the same document, Info; Low when authors differ), `org.structure` (Info, `T1591.004`),
  `net.internal_map` (Info; Low when servers + known domain are present). Reports localize finding texts to UK/EN/RU by
  rule ID.
- **People:** optional fields `Person.dept` (dictionary key `finance|hr|legal|it|…` → i18n `org.dept.<key>`, or share
  name), `Person.dept_conf` (0-95), `Person.title` (title extracted from certificate).
- **`insights_get { project, layers?, min_group? }`** → `org` (`OrgChart`: `organizations`, `departments[{ id, key, labels, known, members[{ login, confidence, evidence[{ source, value, doc, weight }] }], candidates, docs, confidence }]`, `people[{ login, name, roles{role:n}, primary_role, title, department, dept_confidence, organizations }]`), `correlation` (`links[{ from, to, kind: copy|derived_from|same_lineage, confidence, basis, reason, evidence }]`, `lineages[{ id, docs, root, basis, confidence }]`), `anomalies[{ doc, code, sev, confidence, title, detail, fields }]`, `kev[KevMatch]`, `netmap` (`nodes[{ id, kind: forest|domain|server|workstation|user, label, fqdn, roles, shares, printers, parent, confidence, sources[{ kind, value, doc }], docs }]`, `links[{ from, to, kind, docs }]`), `graph` (`GraphView`: `nodes[{ id, kind, label, layer, count, members }]`, collapsed into `group:*` when `count ≥ min_group` (default 3), `edges[{ from, to, kind, weight }]`, `layer_counts`, `hidden`), `layers` (applied layers; default is all except `software`; valid values: `people|docs|pcs|servers|pki_domains|software`), `timeline[{ lane: documents|software|certificates, year, label }]`, `activity` (`hours[24]`, `weekdays[7]`, `matrix[7][24]` where `0 = Monday`, `total`, `out_of_hours`, `tz`, `tz_counts`), `attack_paths`, `counts`.
- **`chain_get { project, from_id | node, limit? }`** → BFS paths toward infrastructure (domain/forest > host >
  share/printer > PC), skipping software/OS hops; starting from a finding uses its document, falling back to PC, person,
  or host. Returns `not_found` if missing.
- **Report:** `report_build` renders SVG/PNG visuals (`foca_report::Visuals`: relationship graph, network map, yearly
  timeline, 7×24 activity heatmap) via `build_report_with_visuals`, highlighting document/host nodes linked to Critical
  and High findings.

## Document Hygiene (1.4): A-F Grade, Sanitization, and Before/After Verification

- `hygiene_get` → `docs[]` = `HygieneReport` (`foca-meta::hygiene`) + `id`/`name`/`ext`:
  `{ grade: "A".."F", score: 0..100, format, cleanable, issues: [{ code, severity: crit|high|warn|low|info, count, samples?: string[≤3], fix: { code, params?: {count?, kinds?, pages?}, auto } }] }`, issues sorted from most severe; `fix.auto = true` indicates the issue is resolved by "Clean". Deductions: `crit` 40 / `high` 20 / `warn` 10 / `low` 4; any `crit` issue caps the grade at `E` or worse. Issue/fix codes are defined in `crates/foca-meta/src/hygiene.rs` (UI: `ui/screens/hygiene.js`).
- `set` = `SetHygiene`: `{ grade, score /* mean */, documents, worst, by_grade: { "A": n, … }, issues: [{ code, severity, documents, fix /* fix code */ }] }`; set grade is never more than one letter grade above the worst document.
- `doc_clean.verify` = `VerifyReport`: `{ valid, error?, remaining, clean /* valid && remaining == 0 */, pages_before?, pages_after?, text_preserved?, changes: [{ field, before?, after?, change: removed|changed|kept|added, sensitive }], warnings: [{ code: signature_removed|revisions_collapsed|javascript_removed|embedded_files_removed|embedded_files_kept|annotation_authors_removed|thumbnail_removed|versions_removed|embedded_object_kept|encrypted_content_kept, count?, name? }] }`. UI verdict: `verify.clean && manual == []` → "0 metadata · valid file"; `signature_removed` shows a prominent warning (cleaned copy is unsigned).
- Encrypted PDF → entry with `manual: [{ kind: "format", where: "Encrypted PDF: …" }]`, `verify: null`.

## Quick Tools and Scan Queue (1.5)

- **Project-free**: `tool_*` commands never create a project or write to project storage; each enforces a `timeout_ms`
  budget (default 5 s, range 1-20 s). On timeout, completed sections return alongside `partial: true` and timed-out
  steps marked `timeout`; network errors (connection refused, scope block) return an explicit `error` string with no
  fabricated data. Networking runs through `NetClient` using `settings.net` (proxy, UA, `rps`); per-call requests return
  in `requests` and aggregate in `tool_log`. `tool_file` and `tool_secret` (unless `hibp_opt_in: true`) make zero
  network calls; with `hibp_opt_in: true`, only the 5-char SHA-1 prefix is sent to HIBP.
- **UI presentation**: File → hygiene grade and issues (`grade`, same view as Hygiene), masked PII/secrets, findings,
  and "Clean" button → `doc_clean` with `clean_with.args`; Mail → `risk.level` badge with `reasons`, DNS records table,
  `issues`; Host → certificate (`tls.leaf`, `days_left`, `trust`), `header_issues`, `technologies`, `favicon.mmh3` with
  `queries`, per-step `steps` statuses; Password → `strength`/`score`, `crack_time`, `issues`, `detected`.
- **Queue**: persisted atomically to `<data>/scan_queue.json` (no DB), driven by a single worker running scans strictly
  one at a time. While any external scan is active (manual, scheduled monitor, auto-resume), the queue waits
  (`waiting: true`); calling `scan_start` while a queued scan runs returns `busy` as usual. Item outcomes follow the
  scan record: `done` advances to the next item; `stopped`/`error` marks the item `error` and advances; user or
  environment stops (`user`, `vpn`, `battery`, `budget`…) mark the item `stopped` and pause the queue with that
  reason; `stopped`/`restart` (process killed) resumes the same scan via `resume_from` with `auto: true` (respecting
  `power.auto_resume` and retry counter; disabled → pauses with `restart`; crash loop → `restart_loop`). After restart,
  the core resumes the queue automatically after `EngineConfig::queue_start_delay` (2 s, yielding first to bridge
  auto-resume); headless background cores do not process the queue.
- **Event**: `{ type: "queue", …QueueView }` emitted on `scan://event` on state changes and as the active scan
  progresses.

## Monitoring

- `settings.monitor = { <project>: { mode: "off"|"daily"|"weekly", time: "HH:MM", days: [1..7], wifi, charge, profile: "passive"|"std", … } }` ("Monitoring" screen). Whenever settings change, the Android bridge syncs schedules with
  WorkManager (`monitor_schedule`): one daily periodic job per project near `time` (the worker checks day-of-week),
  constrained by `wifi` → unmetered network, `charge` → charging, and always battery-not-low.
- Worker behavior: if the core is alive (app in background), invokes
  `scan_start { project, profile: passive|std, trigger: "schedule" }`; if no core exists (process woken by WorkManager
  without a UI window), posts a notification ("Time to rescan project X") opening `/open/<id>/scan`.
- `scan_start { trigger: "schedule" }` at an active tier (`full`, or "Custom" with `axfr`/`fuzz`/`ports`) returns
  `monitor_active` without sending a single request; scheduled scan records carry `trigger: "schedule"`.
- On `done`, the bridge shows a completion notification ("Scan complete · <project>": document/new/finding counts from
  `docs`, `added.docs`, `findings`, `new_findings`), tapping opens `/open/<id>`.
- UI routes: `/open/:id` opens the project Overview; `/open/:id/scan` opens the project and launches the New Scan
  wizard.

## Types

```ts
ProjectSummary { id, name, client, created_at, archived, last_scan_at|null, last_profile|null, scans: number,
                 docs: number /* excluding deleted */, findings: number /* active: excluding false positives & fixed */,
                 risk: number|null /* null when no scans completed */, scanning: bool, progress: number,
                 reference: bool /* built-in reference case (demo_case_import): kept out of recent projects */ }

Snapshot { project, scope, docs[], people[], emails[], patterns[], hosts[], pcs[], software[], paths[], printers[],
           secrets[], findings[], gps[], events[], scans[], reports[], leaks{}, settings, scan /* ScanStatus */, oos[],
           recon /* ReconView */ }
           // derived entities are computed over live (non-deleted) documents; secrets are masked only
ReconView { at|null, scan|null, level: "external"|"target"|"active"|null,
           sources: { recon|wellknown|buckets|grepapp: { status, n|null, error|null }|null },
           sites: [{ host, url, via: "site"|"archive"|"", error|null, at,
                     favicon: { url, mmh3: number, md5, sha256, size, queries: [{ engine: "shodan"|"fofa"|"censys", q }] }|null }],
           tech: [{ name, version|null, category, outdated: string|null /* e.g. "version X is older than Y" */, confidence, host }],
           analytics: [{ kind /* ga4, ga-ua, gtm, yandex-metrika… */, id, host }],
           hidden_paths: [{ path, reason, source, host }], sitemap: [{ loc, lastmod|null, host }] /* up to 300 per site */, sitemap_total,
           security: [{ host, source, contacts[], emails[], expires|null, policy[] }],
           endpoints: [{ url, kind, method|null, source, host }] /* up to 300 per site */, endpoints_total,
           secrets: [{ kind, title, mask, source, line, sev, host }] /* no plaintext value: mask only */,
           buckets: [{ provider, label, name, url|null, status: "unchecked"|"public"|"closed"|"not_found"|"unknown", keys|null, sources[] }],
           code: { query, total, hits: [{ repo, path, url, matches, lines: [{ line, text }] }] }|null }
ScanStatus { running: bool, scan_id?, project?, profile? /* localized display name */, profile_id?, active?, level?: "external"|"target"|"active",
           progress?, stage?, paused?, targets?: string[], modules?: string[], started_at?, resumed?, egress? }

Project  { id, name, client, domain, created_at, archived, notes }
Scope    { client, contact, phone, basis /* optional "Authorization note" */,
           targets: [{ v, type: "domain"|"wild"|"cidr"|"ip"|"host"|"range"|"url"|"org"|"person"|"asn" }],
           excl: string[] /* hosts, CIDR networks, URLs */ }

Doc { id, ext, name, url, host, title /* title from metadata or page: used for out-of-scope candidate matching */,
      size /* KB */, first_scan /* scan ID */, deleted, cleaned: { at, name, manual }|null /* doc_clean */,
      status: "analyzed"|"downloaded"|"queued"|"error",
      // populated only when status = "analyzed", otherwise null/[]:
      author /* login */, last_modified_by, software /* id */, created_at, modified_at, folder, printer, company,
      camera, gps: { lat, lon, place }|null, revisions: [{ kind: "del"|"ins"|"com", who, at, text }],
      rdp: { full_address, username, gateway }|null, lnk: { machine, mac, volume_serial, target, target_dir }|null,
      flags: ("path"|"secret"|"eol"|"gps"|"revisions")[], thumb_diff: bool,
      // only when status = "error" (omitted otherwise):
      error_kind?: "parse"|"download"|"http" /* what failed: "parse" = the downloaded or imported file could not be
        parsed/imported; "download" = the fetch failed; "http" = the server answered with an HTTP error. Label the
        document by this field, not by error_reason text. Documents recorded before this field existed read as "parse" */,
      error_reason?: string /* why the document failed, as recorded (free text, Russian) */,
      http_status?: number /* only with error_kind = "http": the HTTP status that was received */ }
      // failed downloads never create a Doc: they stay in the download queue (tasks.last_error); today every Doc in
      // status "error" is a downloaded or imported file that could not be parsed (error_kind "parse"), "download" and
      // "http" are reserved for fetch failures recorded on an existing document

Person   { login, name, role, pc|null, color, src, src_kind: "meta"|"text", docs: number /* over live docs */, src_doc?, src_deleted? }
Email    { addr, login|null, name|null, found: bool, src, role: bool /* role/service address */ }
Software { id, name, ver, kind: "office"|"pdf"|"scanner"|"camera"|"image", released, eol_date|null, eol, cve, cves: [[id, cvss]], dev|null, docs }
Host     { name, ip, role, tech, cloud, services: [[port, proto, banner]], source, internal: bool, sev, first_scan,
           ports: HostPort[] /* local port scan + InternetDB cache, sorted ascending by port */, ports_scan: PortsScan|null,
           dns: [[type, value, note]] /* A, CNAME, MX, TXT (SPF/DMARC), NS, PTR, from DNS stage */, asn: string|null,
           tls: { cn, issuer, not_after /* YYYY-MM-DD */, san: string[] }|null /* external hosts with 443/tcp only */ }
HostPort { port, proto: "tcp", service, banner|null, product|null, version|null, tls: bool, cert_names: string[],
           source: "scan"|"internetdb", cached: bool /* also present in InternetDB cache */, unconfirmed: bool /* seen by InternetDB, not by local scan */,
           outdated: string|null /* outdated web server from banner */, sensitive: string|null /* "RDP", "Redis"…: exposed to internet */ }
PortsScan { scan, at, ip|null, spec /* wire label: "топ-100" | "топ-1000" | "свой: …" */, scanned, open, closed, filtered, ms, cancelled: bool, error|null }
Pc       { name, kind: "ws"|"server", users: string[], ip|null, source, docs }
Path     { path, docs, user|null, host|null }
Printer  { name, docs, host|null }
Secret   { id, type: "conn"|"pass"|"api"|"host", mask /* no plaintext: use secret_reveal */, doc, where, sev, host?, finding? }
Finding  { id, title, sev: "crit"|"high"|"warn"|"low"|"info", status, host /* or "-" */, category, source, module,
           active: bool /* produced by an active module */, time, first_scan, fixed_scan|null, tags[], cve[], cvss|null,
           mitre, description, recommendation, evidence /* secret masked as {{s:mask}} */, secret_refs: string[] /* "f<id>:<k>" for secret_reveal */, request, url, doc|null,
           notes: [{ text, who, time }], photos: [{ name, time, from }], rel: { people[], pcs[], docs[] },
           standards: { mitre[], cwe[], owasp[], wstg[], iso27001[], nist[], privacy[], ndtzi[], kszi[], cwe_top25[] } | null }
           // standards: maps provenance.rule to standards (foca-analysis signatures/standards.toml,
           // docs/STANDARDS.md); computed per response (project_snapshot, finding_*), not stored; null if unmapped;
           // nist = NIST SP 800-53 ids (same codes in ND TZI 3.6-006-24), privacy = GDPR / Law 2297-VI article keys,
           // cwe_top25 = the cwe ids that are in the 2025 CWE Top 25
           // post-rescan status: vanished finding → "fixed" (+fixed_scan), EXCEPT findings from user-deleted
           // documents: those are hidden (not "fixed") and reappear if the document is restored;
           // rescan never resets "fixed": archived copies do not alter status, while reappearance on a live site
           // (non-Wayback/CC/Arquivo doc or network finding) keeps the user's status and adds the `reopened` tag
           // engine tags: "out_of_scope": finding about a host outside the project scope (e.g. third-party data on a
           // shared address): shown as environment context, excluded from the risk score
           // (foca_analysis::findings::risk) and kept in sync by the engine on every analysis (user tags are otherwise
           // preserved); "archive": web-audit finding computed from an archived copy (Wayback) rather than the live
           // site, so it may be outdated; "cdn_edge:<provider>": probed on a CDN edge, synced like "out_of_scope";
           // other engine tags are stable English codes too ("secret", "outdated", "forensics", "qes", "pii", "kev",
           // "eol", "reopened"): the UI translates them, Russian tags of older versions are mapped to them on read
Gps      { doc, name, lat, lon, place, dev, taken_at }
Event    { y, m, ic, k, t, s, sev?, ref: { type: "doc", id } }   // derived from document timestamps
Scan     { id, profile_id: "passive"|"std"|"full"|"custom", profile: "Пассивный"|"Стандартный"|"Полный"|"Свой" /* wire display label */, active,
           trigger: "manual"|"schedule", status: "done"|"stopped",
           reason: null|"user"|"android"|"battery"|"wifi"|"vpn"|"error"|"restart",
           started_at, finished_at, minutes, progress?, stage? /* when stopped */,
           incomplete: string[] /* recon sources (recon, wellknown) that failed to respond in this scan: site data and snapshot.tech
           are carried forward from prior data (recon.sites[].incomplete) so "What changed" does not report false removals */,
           targets[], modules[], egress, sources: [{ id, name, status: "ok"|"nokey"|"error"|"off"|"timeout"|"skipped"|"blocked"|"unavailable"|"limit"|"unreliable" }],
           docs, hosts, people, findings, new_findings, added: { docs, people, hosts, findings },
           snapshot: { docs: id[], people: login[], hosts: { name: tech }, findings: { id: sev },
                       tech: { name: version /* "" if unknown; site recon */ } },
           env?: { egress, proxy_used, tcp_intercept, dns_hijack, tls_mitm, incomplete: bool,
                   incomplete_sources?: string[],
                   incomplete_reasons?: [{ id, status, http? }] } }  // see "Scan: Launch Rules…"
           // env.incomplete_sources, ids of sources whose data for this scan is not complete: final status error,
           // timeout, skipped, blocked, captcha or limit, or "ok" while the request log of this scan has a 429/5xx
           // (or rate-limit) answer for that module that was final (not marked as retried). Omitted when empty.
           // env.incomplete_reasons: the same sources with the final status ("lost" for an "ok" source that lost
           // requests) and the HTTP code of the source's last failed request; the report appendix renders them
           // as a localized "Incomplete sources" table.
           // env.incomplete: true if the scan did not finish ("done"), any source is incomplete, or the port-scan
           // canary marked the network unreliable; reports name the incomplete sources
Report   { id, name, tpl, fmt, lang, created_at, size, opts, path /* private file: <data>/reports/<project>/<name> */,
           result: { finding_ids[], fixed_ids[], counts: { crit, high, warn, low, info }, total, risk|null /* over included findings */, risk_level: "crit"|"high"|"mid"|"low"|"none" /* crit = ≥90 with critical findings (1.0.1) */, pages|null, project_risk, at_scan } }
Oos      { id, host, kind: "cname"|"ip"|"redirect"|"link"|"cdn" /* CIDR ranges are never suggested: single IP only since 1.0.1 */, via /* source host */|null, why, hint, n|null /* count interpolated into why */,
           shared?: true /* IP of an in-scope host without cloud attribution: possible shared hosting, UI warns, only the single IP enters scope */,
           own: bool /* true only with proven ownership: A-record of an in-scope domain or redirect from an in-scope host to the client's tenant */,
           blocked: string|null /* cannot enter scope: unclaimed name (dangling CNAME), shared CDN, government service */, finding|null, decision: "new"|"scope"|"ignored" }
           // derived from project hosts/findings/docs on every snapshot; user decisions are stored separately and survive rescans
Settings { net: { proxy_on, type, addr, label, orbot, out_ip, out_country, kill_switch, kill_action: "stop"|"pause", ua /* "chrome" (default: auto, latest Chrome · Windows)|"chrome_android"|"firefox"|"safari"|"honest" (FOCA-rs/<version>)|"custom"; legacy "foca" = honest, "random"/unknown = chrome */, ua_custom /* custom UA string */, ua_versions? /* core cache {chrome, firefox, fetched: unix}, versions from public APIs refreshed in background every 7 days */, ua_update? /* false = skip network version refresh (date-based estimate only) */, threads, rps, timeout, retries, dns, dns_custom, hosts_parallel /* 1-8, default 4: hosts of one scan worked on at once in liveness, TLS, ports, recon and site discovery; 1 = one after another */, source_timeout? /* seconds, 10-600, default 90: overall search source timeout */, dns_mode? /* "system"|"doh"|"auto" (default): DoH over proxy */ },
           sources?: { [id]: { enabled: bool } } /* "Settings → Sources" */, source_status?: { [id]: { status, n, error, at } } /* written by core */,
           fuzz: { modules: string[] /* docs, backups, exposed, dirlisting, vhost, cms; first four enabled by default */, rate /* req/s, 5 (0.5-20; slider 1-10) */, threads /* 4 (1-8) */, max_requests /* per-scan budget, 3000 */, max_time_min /* 20 */, max_hosts /* web targets per scan, 3 */, exclude_paths: string[] /* path prefixes never requested, e.g. "/private" */, wordlists: string[] /* IDs from wordlists_list → content module: root path words */, follow_redirects /* false */, show_paths /* false: suppress Info "Path found" findings */ } /* "Site Discovery" */,
           keys: { [service]: KeyStatus }, power: { wifi_only, lim_on, mob_limit, batt_on, batt, batt_action, heat, charge_only, period },
           sec: { pin, pin_set /* PIN configured; hash never sent to UI */, bio, autolock, hide, clip, panic, autodel, autodel_days /* after last scan */, block_shots? /* Android FLAG_SECURE: block screenshots and the recents preview; opt-in, missing = allowed */ }, work_hours: { from, to, tz }, debug: { level: "info"|"debug" /* log level, applied live */ }, last_project,
           plugins: { [id]: { on?, removed?, installed? } } /* plugin state, persists across restarts */,
           monitor: { [project]: { mode: "off"|"daily"|"weekly", time, days: number[], wifi, charge, tg, hook, what } } /* per-project monitoring */,
           ai: { provider, model, local: false, redact: { secrets, pii, client, evid } },
           ocr: { enabled: false /* disabled by default */, max_pages: 10 /* 1..50 */, max_mb: 15 /* 1..50 */ } /* optional offline OCR for scanned PDFs/images via Android ML Kit */,
           recon: { screenshots: false /* disabled by default; Standard/Full profiles only (I-13) */ },
           report?: { picked: { [project]: finding_id[] } /* "Add to report" */, draft: { [project]: ReportDraft } /* builder draft */, company?: string /* executor name for the report header/cover, used by report_build when opts.company is empty */ },
           ui?: { battery: { excluded, oem, done }, look: { theme, lang, density }, sig: { auto, updated },
                  new_draft: { targets[], pname, pclient, excl[], profile, at }|null /* new-project wizard draft */ } }
ReportDraft { tpl, fmt, lang, minSev, confirmed, pickedOnly, sec: { summary, scope, findings, fixed, people, infra, docs, log, appx }, secrets: "hide"|"partial"|"full", logo, company, secTouched } /* persisted state of reports.js */
LogEntry { id /* monotonically increasing */, t /* local ISO with ms */, level: "debug"|"info"|"warn"|"error", target /* foca::scan, foca::source, foca::net, foca::cmd */, msg }
KeyStatus { status: "ok"|"none"|"error", mask, used?, limit?, per?, error?, note?, kind?: "url" /* value is a URL (SearXNG) */, optional?: bool /* missing key renders as "not connected" rather than error */ }
// Host omits internal generator fields (tech_s1 etc. never appear in snapshots)
```

API key services: `brave`, `searx` (instance URL), `shodan`, `hibp`, `vt`, `st`, `urlscan`, `censys`, `github`, `ai`.
Google (CSE and direct search) is not used: legacy `gcse` entries in older settings are ignored (omitted from
`settings_get`, purged on reset). Scan sources: Wayback, Common Crawl, crt.sh, site crawler, Startpage and Brave Search
via embedded WebView (keyless), Brave Search API (`optional` key), SearXNG (URL), DNS/CT, Shodan cache (key). A
keyed source's scan status reflects its key status.

## Scan Events: `scan://event`

The core emits `app.emit("scan://event", payload)`; `api.js` listens via `window.__TAURI__.event.listen` (in demo mode,
`FOCA_DEMO_BACKEND.listen`) and republishes on the internal bus via `F.emit("scan", payload)`.

| `type` | Fields | UI Behavior |
|---|---|---|
| `started` | `scan_id, project, profile, profile_id, active, egress, targets, resumed, stages` (`stages`: ids of the stages a follow-up run executes, `null` for a full scan) | mini-bar, "Active mode" banner |
| `stage` | `scan_id, stage, label, index` | pipeline stage indicator |
| `progress` | `scan_id, progress, stage, done?, total?` | progress bar; `done`/`total` count files in Download and Extraction stages (the download queue itself is not in the snapshot) |
| `control` | `scan_id, project, kind, id, state` | a `scan_control` action took effect: `state` = `paused` \| `running` \| `skipped` \| `restarting` \| `queued` |
| `substep` | `scan_id, stage, id, state, done, total, eta_s, slow`, optional `reason, reason_msg` | sub-step of a long stage (network: `dns`, `resolve`, `takeover`, `brute`, `permute`, `rdap`, `liveness`, `tls`; search: `queue`; ports, recon and fuzz: `hosts`, which also carries `running: [host names]`, the hosts worked on right now, with `done` of `total` hosts finished; at most `settings.net.hosts_parallel` run at once). `state`: `running` (live counter, at most one event per second; resolver passes tick every 1.5 s) → `done` \| `skipped`. A finished or skipped sub-step may carry `reason` (core text) and `reason_msg` (`{code, params}` for the UI language): `brute`/`permute` skipped with `sub.url_target` when the domain is in scope only as a URL target; `queue` (search stage, `done`/`total` = queued/found documents) with `search.queue` counting documents dropped as out of scope, already known or of another type. `eta_s` (seconds left, or `null`) and `slow` describe the resolver pace. The running sub-step is mirrored in `scan_status.substep` (`null` otherwise). The core also writes info-level log lines at the start and end of every sub-step with counts and duration |
| `source` | `scan_id, id, name, status, n?, error?` | source status card. Statuses: `wait` (queued at scan start), `running` (active), `ok`, `error` (`error` text, e.g. `"HTTP 504"`), `timeout` (exceeded overall source timeout `settings.net.source_timeout`, default 90 s across all pages and retries), … Core-driven deadline: `running` carries `timeout_s` (effective hard budget: `source_timeout × budget`, tripled for slow archives like Wayback/Common Crawl) and `deadline_ms` (Unix ms timestamp when the core aborts the source). The UI only displays remaining `deadline_ms − Date.now()` (clamped at 0 → "finishing…", recalculated after WebView resume) and never declares "no response" on its own: only upon a `timeout` event. Retries within a source emit another `running` event with `retry: N` and `retry_reason` (deadline unchanged) → displays `"retry N"`. With multiple target domains, sources iterate in rounds: every source event carries `domain`, `round` (1…), and `rounds`; `timeout`/`error` while `round < rounds` is non-final (the source will run for the next domain). Other statuses: `skipped` (`scan_skip_source`); `blocked` (CAPTCHA/anti-bot block on keyless dorks: since 1.0.1, `startpage`/`mojeek`/`brave_web` include `verify_url` for `platform_verify_search`, showing "Verification required" + "Verify" button followed by `scan_retry_source`; CAPTCHAs are detected immediately via `abort: string[]` substrings on the browser `wait` step such as `/captcha`, `altcha`, `"solve the captcha"`…, causing Kotlin to return `RenderPage.aborted` instead of waiting for timeout; on `fuzz`, indicates rate-limit auto-stop); `unavailable` (requires Android WebView, e.g. `startpage`/`brave_web` outside Android); `ok` with `error` (partial success with note, e.g. Common Crawl trying up to 5 fallback indexes from `collinfo`, failing only if zero respond); `limit` (1.0.1: HTTP 429 persisted after retry honoring `Retry-After` ≤ 30 s within source timeout; once `otx.alienvault.com` hits a terminal 429, it is skipped for the rest of the scan via `NetConfig.shared_limit_hosts` so secondary OTX sources immediately report `limit`); `nokey`; `off`. Source `fuzz` (Site Discovery stage) also emits `checked`, `found`, `filtered` (soft-404 calibration drops), `planned`, `requests`, `host`, `hosts`, `host_index` (counters add up over all hosts running at once; `host` is the host that reported); final event carries `status: ok \| stopped \| blocked \| error \| skipped`, localized `detail`, `stop: { kind }` (a user stop, the shared budget or time first, then a host that limited requests), `blocked_hosts` (hosts stopped by 429/challenge; the others go on) and `documents` (new docs queued for download). `skipped` means no live in-scope web hosts eligible for active scanning; outside active mode `fuzz` is `off`. `n` counts documents, hostnames (for subdomain sources), or enriched IPs (for `internetdb`). Events stream live so one slow source never stalls the stage |
| `warning` | `scan_id, code, message, message_msg?` | scan-level warning (`message_msg`: `{ code, params }` for the UI language when the text is a known core message). `no_network`: no search source responded and no request of the scan got any HTTP answer (offline or dead proxy). `search_sources_limited`: no search source gave data, but at least one answered with a rate limit (429) or a captcha, so the network works. `search_sources_failed`: no search source gave data and all failed with errors while other requests got HTTP answers. `search_dorks_lost`: some dork groups went unfinished because every engine hit CAPTCHA. `dns.slow`: the resolver behind subdomain brute force/permutations fails at least 20 % of queries (timeouts, SERVFAIL: typical for a phone VPN resolver) and the pass needs more than a minute; message carries the estimate ("DNS медленный (VPN?): перебор займёт ~N мин"), once per scan; the scan screen offers "Skip brute force" (`scan_skip_source { id: "brute" }`). `search_captcha`: all queried web dork engines (`startpage`, `brave_web`, `mojeek`, `ddg`, `bing`, `yahoo`, `searx_pool`; at least two) returned CAPTCHA/block (commonly caused by shared VPN/proxy IP) |
| `paused` | `scan_id, project, reason, progress` | pause state (`user` or environment policy: `offline`, `wifi`, `battery`, `thermal`, `vpn`, `android`) |
| `resumed` | `scan_id, project, after, progress` | resumed after pause |
| `finding` | `scan_id, finding: { id, title, sev, host, rule }` | live feed entry (full finding details read from `F.db.findings` by ID) |
| `db` | `scan_id, project, kind: stage` | project data updated → `api.js` reloads snapshot → `F.emit("db", {kind:"scan"})` |
| `done` | `scan_id, project, scan, alerts_fired?, warnings?: [{ code, message }], followup` | history entry written, snapshot refreshed; `alerts_fired` counts triggered alerts; `followup` lists restarts queued via `scan_control` (`kind:id`); `warnings` lists scan warnings (see `warning`) |
| `alert` | `project, scan_id, count, dropped, alerts, deliveries` | event-driven monitoring alerts (host/port/doc diffs, TLS/CNAME/risk trend) and Telegram/Webhook delivery outcomes |
| `stopped` | `scan_id, project, reason` | navigates to the stop-reason screen |
| `queue` | `QueueView` (see `queue_list`) | scan queue state: active project, `index`/`total`, `percent`, pause flag and reason |

The demo backend populates a project progressively across stages (merging without wiping): Download adds new unparsed
documents; Metadata Extraction adds metadata, people, software, paths, printers, PCs, GPS, and secrets; Analysis adds
findings (preserving user triage); Network & DNS adds hosts.

### How `screens/scan.js` Runs on Events (Implemented)

- `F.actions["scan-start"]({ profile, active, modules, sources, targets, resume_from, open })` invokes
  `F.api.scan_start`; `out_of_scope` shows a snackbar with the reason and a link to `/p/scope`, `busy` shows "scan
  already running".
- "Resume" and "Start over" on `/p/scan-stopped` launch immediately with one tap against the current scope;
  target-touching profiles route through `F.launchRestart({ profile, modules, resume_from })` (filtering out-of-scope
  targets). The screen has no local timer engine; `F.scanDemo.ff(n)` (demo only) advances `n` core steps instantly
  (`FOCA_DEMO_BACKEND._ff`).
- `F.scan` is populated inside `F.on("scan")`: `started` → `running`/`active`/`egress`/`profile`/`project`,
  `stage`/`progress` → pipeline stages, `source` → source cards (live key status read from `settings.keys`), `finding`
  → feed ID (title and severity from `F.db.findings`), `done` → summary from `F.db.scans`, `stopped` →
  `/p/scan-stopped/:reason` (auto-reasons navigate immediately).
- Pause/stop call `F.api.scan_pause`/`scan_resume`/`scan_stop`. Pause reason (`user|offline|battery|wifi|vpn`) is stored
  in UI state (`F.scan.pauseReason`, mini-bar caption `F.scan.pauseLabel`), formatted from `F.db.settings` (battery
  threshold & action `power.batt`/`batt_action`, Wi-Fi-only, tunnel & kill switch `net.label`/`addr`/`kill_switch`/`kill_action`).
- Connectivity: `core.js` emits `F.emit("net", { online })`; losing network pauses with `offline` and auto-resumes on
  reconnect. Tunnel drop stops (`scan_stop("vpn")`) in active mode or when `kill_action: "stop"`, otherwise pauses.
- Live re-rendering of Overview and Projects uses the `live`/`onData` mechanism in `core.js` (see `ui/README-UI.md`).

## UI Snapshot: `F.db` and Event Bus

- `F.dbReady` is the initial load `Promise` (`FOCA.start` awaits it). In demo mode loading is synchronous.
- Switching projects: `F.api.project_open(id)` replaces `F.db` → `F.emit("db", {kind:"project"})` → active screen
  re-renders (via a `late` subscriber in `api.js` running after screens refresh their caches).
- Mutations (`finding_set_status`, `doc_delete`, …) update `F.db` optimistically first, emit `F.emit("db", {kind})`,
  then invoke the backend command. The screen triggering the mutation re-renders itself.
- Subscriptions: `F.on("db", fn)` / `F.on("scan", fn)`; `F.off(ev, fn)`; `F.on(ev, fn, {late:true})` runs after regular
  listeners.

## Selectors `F.sel` (Single Source of Truth for Metrics)

| Selector | Rule |
|---|---|
| `counts()` | `docs.total` excludes deleted; `downloaded`, `analyzed`, `with_findings` (analyzed with flags other than `eol`), `new` (first seen in latest scan when ≥ 2 scans exist); `people.total/meta/text`; `emails`; `hosts.total/internal`; `software`; `secrets`; `findings.{crit,high,warn,low,info}` exclude false positives and fixed, `total` excludes false positives, `open` excludes false positives and fixed, `confirmed`, `new_since_last` (first seen in latest scan) |
| `risk(list?)` | `null` / "no data" until at least one scan completes Analysis; otherwise `FOCA_RULES.riskScore` = `100·(1 − Π(1 − wᵢ))` over active findings (or `list` for report selections), weights: `crit` 0.25, `high` 0.12, `warn` 0.05, `low` 0.02; ≥ 70 high, ≥ 40 medium |
| `scope.check(h, scope?)` / `allows(h)` | Implements the Scope Rule above; `scope` may be a draft (new-project wizard), defaulting to the current project |
| `scope.checkTarget(t, scope?)` / `excludedIn(t)` | Checks whether an entire target may be contacted and counts excluded addresses within a network target (excluded CIDRs + IPs of excluded hostnames) |
| `scope.info()` | Scope plus `nTargets`, `nNet`, `nExcl`, `activeTargets` (network targets eligible for the Full profile's active phase) |
| `entity(type, id)` | Resolves `person`/`host`/`pc`/`software`/`printer`/`path`/`email`/`doc`/`finding`/`secret`; numeric indexes remain supported for software/printers/paths (legacy routes) |
| `related(type, id)` | Computes entity relationships from live data (documents → authors, software, hosts, PCs, printers, paths; findings via `rel`, `doc`, `host`); displayed fact counts equal these list lengths |
| `search(q, kinds)` | Client-side search across findings, documents, people, hosts, PCs, e-mails, software, and secrets |
| `timeline()` | Years and analyzed documents only, document-date events, and working hours from settings |
| `diff(a, b)` | Compares `scans[].snapshot`: documents/hosts/people/findings `+ − ~` (`~` on hosts marks a software fingerprint change); user-deleted documents never appear as "new" |
| `graph(type, id)` | Target node and immediate neighbors; `graphAll()` returns the full graph |
| `os()` | Infers OS from analyzed document metadata: Application/Producer (Office, Acrobat, PDF Library, Photoshop) → Windows, LibreOffice → Linux, EXIF Software → iOS/Android, MFP/camera firmware, `.lnk` → Windows, `.rdp` → Windows Server; `{ id, name, family, src[], docs, doc_ids[] }` |
| `reportPicked()` | Finding IDs marked "Add to report" (`settings.report.picked[project]`, filtered to existing findings) |
| `reportFindings(o)` | `FOCA_RULES.reportSelect` (exact same selection rule used by the core in `report_build`): `o = { confirmed, min_sev, picked_only, picked? }` → `{ main, fixed }`; `main` excludes false positives and fixed, `fixed` populates a dedicated section; sorted by severity |
| `requests()` | Scanner request summary `{ total, by_scan[], sample[] }` estimated across project scans (documents, hosts, sources, active phase) |

## Compatibility (Legacy Aliases on `F.db`, Remove After Screen Migration)

`window.DEMO.{users, software, domains, folders, printers, docs, hosts, vulns, emails, gps}`, `F.demoFindings`,
`F.demoProjects` (= `F.projects`), `F.project` (getter), `F.scanHistory`, `F.demoData` (`data.js`),
`F.state.scope` (same object as `F.db.scope`), `F.state.settings` (legacy field view over `F.db.settings`:
`keys[id].{v, st, used, lim, err}`, `net.{proxyOn, kill…}`), `F.state.reports.history`.

## Demo Backend

- Deterministic generator (seeded per project): `contoso` (342 documents, 2 scans: Standard on 12.11 and Full active on
  19.11), `logistics` (46 docs, 1 scan), `medlab` (71 docs, 1 scan, active checks disabled), `agro` (14 docs, Passive,
  web-archive documents), `dnipro` (new, zero scans).
- Invariants: software matches file extension and release date does not postdate document date; metadata, flags,
  secrets, and GPS exist only on analyzed documents; people, PCs, software, paths, and printers derive from metadata;
  findings reference existing documents, hosts, and people; active findings apply only to in-scope hosts from active
  scans; ProxyShell on excluded `mail.*` is passive from Shodan cache.
- QA hooks: `_ff(n)` advances `n` scan steps instantaneously; `_restart()` simulates process eviction: an active scan
  is lost, recorded as interrupted, and state is reloaded from storage.
- State persists in `localStorage["foca-demo-v1"]` (versioned by generator); menu `⋮` → "Demo states" → "Reset demo
  data". `qa/shoot.sh` launches a fresh browser profile per run for deterministic screenshots while retaining state across
  reloads within a single `--steps` run.
