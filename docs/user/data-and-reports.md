# Data, Findings, Reports, Bundles & Monitoring

↑ [User Guide](README.md) · [Documentation](../README.md)

- [Overview](#overview)
- [Findings, Triage & Remediation Playbooks](#findings-triage--remediation-playbooks)
- [Data, HIBP & Contextual Wordlists](#data-hibp--contextual-wordlists)
- [Project Tools & Quick Tools](#project-tools--quick-tools)
- [Reports, DOCX & Chain of Custody](#reports-docx--chain-of-custody)
- [PDF Export](#pdf-export)
- [Exports (STIX 2.1, Nuclei, httpx & More)](#exports-stix-21-nuclei-httpx--more)
- [Encrypted `.foca.enc` Project Bundles](#encrypted-focaenc-project-bundles)
- [Declarative CLI Scenarios (`foca run`)](#declarative-cli-scenarios-foca-run)
- [Headless Monitoring & Event Alerts](#headless-monitoring--event-alerts)

## Overview

`/p/overview` displays the project's overall risk level (Critical / High / Medium / Low), live counters for documents, people, hosts, and findings (tap any counter to jump to its list), recent findings, infrastructure analytics shortcuts, and the launch button for a new scan. Every count is derived from a single selector (`F.sel` in `ui/js/sel.js`) so numbers match identically across every screen and generated report.

## Findings, Triage & Remediation Playbooks

`/p/findings` (detail card: `/p/finding/:id`). Every finding carries a severity (Critical · High · Medium · Low · Info), supporting evidence, provenance, remediation guidance, and (where applicable) mapped [standards](analytics-and-hygiene.md#standards-mapping).

Core finding rule families (spanning document metadata, forensics, secrets, infrastructure, web audit, ports, and fuzzing):

| Group | Example rule IDs | Source crate |
|---|---|---|
| Documents & Forensics | `rdp-password`, `ica-password`, `internal-paths`, `internal-pcs`, `email-pattern`, `eol-software`, `eol-os`, `sw.kev`, `pdf-revisions`, `doc.bad_redaction`, `doc.modified_after_signing`, `doc.anomaly.*`, `doc.user_rule`, `pii`, `macros`, `hidden-sheets`, `gps` | `foca-analysis` |
| Secrets | `secret` (passwords, tokens, API keys, webhooks, cloud SAS URLs in document text) | `foca-analysis/src/content/secrets.rs` |
| Network, DNS & TLS | `axfr-open`, `dangling-cname`, `takeover-http`, `internetdb-cve`, mail policy & TLS/X.509 findings | `foca-engine`, `foca-net` |
| Ports | `ports-exposed`, `ports-admin`, `ports-outdated`, `ports-unconfirmed` | `foca-engine/src/scan/ports.rs` |
| Forgotten File Discovery | `fuzz-backup`, `fuzz-db-backup`, `fuzz-exposed`, `fuzz-git`, `fuzz-dsstore`, `fuzz-listing`, `fuzz-path`, `fuzz-vhost` | `foca-fuzz` → `foca-engine` |
| Site Recon & Web Audit | `recon.favicon`, `recon.outdated_tech`, `recon.js_secret`, `recon.sourcemap`, `recon.robots_hidden`, `recon.bucket_*`, `recon.code_mentions`, `recon.web.*` | `foca-recon` |

- **Triage:** Mark findings as Confirmed (included in reports), False positive (hidden from reports), or Fixed (remediated by the client). Triage states persist across rescans because finding IDs are deterministic hashes of rule + object. Findings belonging to deleted documents are never auto-marked "Fixed", and manual "Fixed" states are never overwritten on rescan.
- **Remediation Playbooks:** Tap Remediation plan (Playbook) on any finding card (`finding_playbook`) to open a localized (`EN`/`RU`/`UA`) step-by-step fix guide with effort estimates, responsible roles, copyable verification commands (raw secrets and raw evidence are never interpolated into commands), a verification checklist, and standard references.

## Data, HIBP & Contextual Wordlists

`/p/data/:seg` holds raw extracted intelligence organized into segments (`SEGS` in `ui/screens/data.js`): Documents · People · E-mail · Hosts · Certificates · Mail Policies · SaaS & CDN · Software · OS · Secrets · Paths · Printers · Site Technologies · Site · JS & API · Cloud · Public Code.

- **Detail cards:** Document cards (`/p/doc/:id`: metadata, source URL, forensics, metadata sanitization) and entity cards (`/p/entity/:type/:id`). Host cards include a Ports panel tagging each port's provenance (*active scan*, *InternetDB cache*, or *unconfirmed by scan*) plus Web audit results.
- **Secrets & HIBP k-anonymity check:** Secrets remain hidden until confirmed with biometrics or PIN (`secret_reveal`). On any secret or finding (and in Quick Tools), you can optionally trigger an opt-in HIBP Pwned Passwords check (`secret_hibp_check`): FOCA-rs computes SHA-1 locally and transmits only the first 5 hex characters to `/range/<prefix>` with `Add-Padding: true`. The full password, full hash, and hash suffix never leave your phone and never enter `request_log`.
- **Login patterns & contextual pentest wordlist:** Under Data → People → Generator (`wordlist_preview`), FOCA-rs generates corporate username patterns (11 templates + `DOMAIN\login` with KMU-2010 / ICAO transliteration) and a contextual `.txt` pentest wordlist while strictly blocking discovered secrets and PII from entering the list.
- **Local files:** Import individual files (`doc_import`) or entire folders/ZIPs completely offline via Analyze files offline (`import_offline`), see [Documents](documents.md).

## Project Tools & Quick Tools

Project overflow menu (⋮):

| Screen | Route | What it provides |
|---|---|---|
| Search | `/p/search` | Global search across all project entities + FTS5 document text |
| Link graph | `/p/graph/:type/:id` | Layered relationship graph (people ↔ documents ↔ PCs ↔ hosts ↔ PKI) & evidence chains |
| Analytics & Attack Paths | `/p/insights` | Ranked compromise chains (Attack Paths), Choke Points, org chart, and anomalies |
| Internal network map | `/p/netmap` | Reconstructed AD domain → server roles → workstations → users topology |
| GPS map | `/p/map` | Offline 3D globe (Natural Earth) plotting photos with EXIF coordinates |
| Timeline & Heatmap | `/p/timeline` | Yearly format/software/CT timeline + 7 × 24 activity heatmap |
| Diff ("What changed") | `/p/diff` | Comparison of two finished scans: appeared, disappeared, changed. Also opened by Compare in the scan history on Monitoring. Removals are hidden when a source failed in one of the scans |
| Pre-publication check | `/p/preflight` | Document hygiene A-F grading, sanitization, and "Before / After" verification |
| Monitoring | `/p/monitor` | Headless scheduled rescans, risk trend SVG chart, 9 alert rules, Telegram/Webhook delivery |
| Cloud AI Summary | `/p/ai` | Structured summary via your chosen cloud API provider (10 providers, live `/models`, Thinking controls, editable redaction preview; disabled by default) |

App-wide utilities accessible from Projects and ⋮:

- **Quick Tools (`/tools`):** Run standalone checks without creating a project: inspect a single file (100% offline), check domain mail policies (`SPF`/`DMARC`/`DKIM`/`MTA-STS`), probe a host/URL (TLS, headers, tech, favicon), or test password strength (offline unless HIBP is checked). The Log tab lists recent tool requests (kept in memory, up to 200); Clear empties it after a confirmation that shows the count.
- **Scan Queue (`/queue`):** Queue multiple projects to scan strictly sequentially with unified progress and pause/resume controls.

## Reports, DOCX & Chain of Custody

Open Reports (`/p/reports`) → New report (`/p/report-new`) → Preview (`/p/report-preview`), powered by `foca-report`:

| Setting | Options |
|---|---|
| Template | Full · Summary · Data · Executive (1 page) · KSZI / Compliance · Laboratory work ([template details](analytics-and-hygiene.md#report-templates)) |
| Format | HTML (self-contained, zero external assets/JS, A4 print layout) · PDF (A4 file rendered on the phone) · DOCX (Word) (pure-Rust OOXML with embedded PNG severity chart, zero C dependencies) · Markdown (Obsidian-compatible) · CSV (RFC 4180, UTF-8 BOM) · JSON (`report.v1` schema) |
| Language | English (`EN`) · Ukrainian (`UA`) · Russian (`RU`): defaults to active app language |
| Secrets policy | Hide (default) · Masked · Full |
| Filtering | Minimum severity, Confirmed only, toggled sections (for Full) |
| Executive summary (AI-assisted) | Adds the project's report [AI summary](settings-network.md#cloud-ai-10-providers-live-models--thinking) (the latest one, or the one picked with "To report" in the history) as a separate section labelled with its source; skipped when no summary exists. `[CLIENT]` and `[CLIENT-DOMAIN]` become the client name and domain only in the report |
| Chain of Custody & Digital Signature | Optional `custody: true` block embedding SHA-256 input digests, creating a `.sha256` sidecar and an `ECDSA P-256` signature (`.sig.json`) backed by Android Keystore (`ReportSigner.kt`). Verify any saved report from the history menu (Verify signature / SHA-256, `report_verify`). |

Risk scores and counters inside a report are always calculated strictly from the findings included in that report. Every generated report is saved in history with an immutable data snapshot and can be exported via Android's Share sheet.

### Contractor Logo

The Header block of the report builder has a Contractor logo row:

- **Choose** opens the Android file picker. PNG, JPEG and WebP files up to 2 MB are accepted; SVG and other formats are refused. A picture larger than 512 px on its long side is scaled down to 512 px. The row then shows a thumbnail with the file name, size in pixels and file size, and the button turns into **Replace**.
- The logo is saved in the app settings, not in a project: one logo is used for every project until you replace or remove it. Wiping the settings deletes it too.
- With **Logo in the report** on, the logo appears in the preview header and on its title page, on the HTML and PDF cover and in the page headers of the templates, and above the title in DOCX. A WebP logo is left out of DOCX. Markdown, CSV and JSON reports have no logo.
- **Remove** deletes the saved picture. With Logo in the report still on and no picture saved, reports show the company initials (from Contractor in the footer) instead.

### Report Preview

Preview (`/p/report-preview`) lays the report out as A4 sheets. Every finding included by the builder settings is shown: a long table continues on the next sheet with its header repeated, and nothing is cut off with a "more" line. The footer numbers the preview sheets. The preview holds the summary tables only, so the last sheet ends with a note that gives the estimated page count of the report file, which contains every section chosen in the builder. Finding titles in the preview are in the app language; in the file they are in the report language. At large font sizes the title block grows with the text, and the last sheet stays clear of the gesture bar.

## PDF Export

Choosing PDF builds the self-contained HTML report and renders it straight into an A4 PDF file on the phone (off-screen WebView without JS or network, command `platform_pdf`). The file can be shared or saved to Downloads. If rendering fails, the app falls back to Android's print dialog (`platform_print`), where you pick Save as PDF. Outside Android (browser QA) an HTML file with print styles is saved instead.

## Exports (STIX 2.1, Nuclei, httpx & More)

Quick export (`export_build`) supports:

- **Security & TI formats:** OASIS STIX 2.1 JSON bundle (for MISP, OpenCTI, and SIEM: deterministic IDs, referential integrity, forcibly masked secrets & PII), `nuclei -l` target list (`.txt` of normalized in-scope URLs/endpoints), and `httpx -l` host/origin list (`.txt`).
- **Classic formats:** Plain list, `.txt` dictionary (usernames, e-mails, paths, contextual pentest wordlist), `CSV`, `JSON`, `Maltego CSV`, `GraphML`, and `Markdown`.
- Optional inclusion of the project's `request_log` audit trail (actual count of requests sent).

## Encrypted `.foca.enc` Project Bundles

To hand over a project securely to a colleague or archive it off-device, export it as a single encrypted `.foca.enc` container from the Projects screen (`/projects`, commands `project_export_encrypted` / `project_import_encrypted`):

- **Contents (`FOCAENC1` format):** An atomic consolidated SQLite snapshot (`VACUUM INTO`), a `CustodyManifest` (SHA-256 hashes of database, inputs, and attached files, plus optional Android Keystore `ECDSA P-256` signature), and optionally all downloaded documents (`include_files`).
- **Authenticated cryptography:** Encryption keys are derived from your passphrase using `PBKDF2-HMAC-SHA256` (`210,000` iterations, random 16-byte salt) and encrypted with authenticated `ChaCha20-Poly1305` (via `ring`) with header AAD.
- **Safety guarantees:**
  - The passphrase is never saved in SQLite, `settings.json`, or logs.
  - Import clearly distinguishes an incorrect password (`bad_password`) from file corruption or tampering (`tampered_bundle`).
  - Importing always creates a new project ID and remaps local file paths: existing projects are never overwritten.

## Declarative CLI Scenarios (`foca run`)

For reproducible desktop audits, lab grading, and CI/CD pipelines, the companion Rust CLI (`foca-cli`) supports declarative TOML scenarios:

```bash
foca run scenarios/passive-osint.toml [--store ./foca-data] [--json] [--dry-run]
```

Ready-to-use templates live in `scenarios/`:

| Template | Mode | Purpose |
|---|---|---|
| `scenarios/passive-osint.toml` | `scan` (`passive`) | Zero-target-packet OSINT audit (`ADR-0009`) + HTML report with Chain of Custody |
| `scenarios/preflight-folder.toml` | `offline` | 100% offline pre-publication audit of a local folder + Executive Markdown report |
| `scenarios/kszi-audit.toml` | `offline` / scoped | Compliance / KSZI report (`uk`, Chain of Custody) with severity & risk gates |

Each scenario file defines targets, exclusions, offline `inputs`, `[rules]` presets, `[report]` format/template/language/custody, and `[gate]` thresholds (`fail_on_severity = "high"`, `max_risk = 70`) that exit non-zero when violated in CI/CD pipelines.

### One scan from the command line (`foca scan`)

`foca scan --project <id> --profile passive|std|full|custom [--wait]` runs one scan of an existing project with the same stages and rules as the app. Crawl and Common Crawl settings can be changed for that run only; without these flags the stored settings apply:

| Flag | What it sets |
|---|---|
| `--crawl-depth`, `--crawl-pages`, `--crawl-minutes` | Crawl depth, pages and minutes per scan |
| `--crawl-storage true\|false` | Files on public external storage linked from the site |
| `--crawl-doc-links true\|false` | Links inside downloaded documents |
| `--crawl-images true\|false`, `--max-images`, `--max-image-mb` | Photos for EXIF and their limits |
| `--cc-depth latest\|years\|all`, `--cc-years` | Common Crawl search depth |
| `--control` | Reads `pause`, `resume`, `stop`, `status` and `skip <source>` from stdin while the scan runs |

## Headless Monitoring & Event Alerts

`/p/monitor` schedules recurring rescans (off / daily / selected weekdays, preferred hour, optional Wi-Fi only and Charging only gates; Passive or Standard profile only: active scans are rejected on a schedule).

- **Autonomous headless execution:** Powered by Android `WorkManager` (`MonitorWorker.kt`) invoking a headless JNI Rust entry point (`DataDirLock`, SQLite WAL + `busy_timeout`, checkpointed runs up to 8 minutes with live handoff if you open the app mid-scan). Sources that require a UI WebView are cleanly marked `skipped_headless`, while archives, CT logs, DNS, TLS, and API sources complete automatically without opening the app.
- **Event alerts & risk trend:** Tracks changes between scans across 9 deduplicated alert rules (new hosts, newly opened ports, secrets/PII/GPS in documents, expiring TLS certificates, dangling CNAMEs, new CT certificates, and risk score jumps), plots an SVG risk-trend chart, and delivers notifications locally or via Telegram / Webhook (bot tokens and Webhook URLs are stored strictly in Android KeyVault and never saved in `settings.json` or exported logs).
- Review exact scan-to-scan deltas anytime on Diff ("What changed") (`/p/diff`).
