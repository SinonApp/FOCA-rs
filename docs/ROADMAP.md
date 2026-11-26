# Roadmap

↑ [Documentation](README.md) · [Русский](ru/ROADMAP.md)

- [Current Status](#current-status)
- [2.0.0-beta.1: First Public Beta](#200-beta1-first-public-beta)
- [Next](#next)
- [2.0: Platform Maturity, Security & Localization](#20-platform-maturity-security--localization)
- [1.6: Remediation, Report Trust & Interoperability](#16-remediation-report-trust--interoperability)
- [1.5: Event Monitoring, Breach Checks & Quick Tools](#15-event-monitoring-breach-checks--quick-tools)
- [1.4: Analytics, Visualization & Document Hygiene](#14-analytics-visualization--document-hygiene)
- [1.3: FOCA Format Parity & Document Forensics](#13-foca-format-parity--document-forensics)
- [1.2: Subdomains & Infrastructure Intelligence](#12-subdomains--infrastructure-intelligence)
- [1.1: Network Reliability, CAPTCHA & Headless Monitoring](#11-network-reliability-captcha--headless-monitoring)
- [Specification Status Summary](#specification-status-summary)
- [Out of Scope / Intentionally Excluded](#out-of-scope--intentionally-excluded)


FOCA-rs is Android-only ([ADR-0001](adr/0001-android-only.md)): a pure-Rust core, a Tauri v2 shell and a vanilla JS interface.

Status legend: ✅ done · ⏳ planned or needs a device check · ✖ excluded

---

## Current Status

🧪 2.0.0-beta.2: second beta with fixes from phone tests of 2.0.0-beta.1 (see the [changelog](../CHANGELOG.md)). 2.0.0-beta.1 was the first public release, published as a GitHub Pre-release (tag `v2.0.0-beta.1`). All 2.0 milestones (`2.0-M1`-`2.0-M9`) and the `1.1.1`-`1.6` series are in. Expect rough edges; problems go to [GitHub issues](https://github.com/SinonApp/FOCA-rs/issues/new/choose).

- Android package `app.sinon.focars`, two builds: `foss` (GPL-3.0 only, no Google libraries) and `play` (adds optional offline ML Kit OCR).
- The APK is signed with a new key: uninstall a previous 1.x or 2.0 preview build before installing. 2.0.0-beta.2 installs over 2.0.0-beta.1.

---

## 2.0.0-beta.1: First Public Beta

Work done after the 2.0 milestones, from phone tests and a full audit:

- ✅ **Background survival on aggressive firmwares**: a setup card for autostart and battery restrictions (Settings and the launch screen), "Hide from Recents during scans", and a headless resume of a scan the system killed (`ScanResumeWorker` → `headless/resume.rs`), with a "Continue" notification as the fallback.
- ✅ **Scan controls**: pause, skip and restart for a stage, a source or a network sub-step; restarts of finished stages are queued for "Re-run queued".
- ✅ **Network stage visibility**: sub-step counters (DNS records, name resolution, dangling CNAME check, brute force, permutations, RDAP, liveness, TLS).
- ✅ **Parallel dangling-CNAME check** with bounded concurrency.
- ✅ **Slow-DNS warning** with the expected brute-force time and a "Skip brute force" button.
- ✅ **Full RU/UK/EN interface**: every screen localized; texts sent by the core and native notifications follow the UI language.
- ✅ **Reports**: PDF saved straight to a file on the phone, an optional AI-assisted executive summary section, F-1…F-n numbering across formats, Markdown and DOCX on par with HTML.
- ✅ **Standards refresh**: OWASP Top 10:2025, MITRE ATT&CK v20, CWE Top 25 (2025) mark, NIST SP 800-53 r5 = НД ТЗІ 3.6-006-24, GDPR and Law 2297-VI for personal data; НД ТЗІ 2.5-004-99 / 3.7-003-05 marked as КСЗІ-only.
- ✅ **Out of scope**: bulk "Add to scope and scan"; CDN/cloud IPs stay out of port scans.
- ✅ **Plugins in real scans**: enabled plugins run in the network stage; a failing plugin never fails the scan.
- ✅ **App security**: lock on start, auto-lock, panic PIN, clipboard auto-clear; screenshots allowed by default with an opt-in block.
- ✅ **Beta channel**: "Beta" label, a first-run note and "Report a problem" (logs ZIP to Downloads + GitHub issue form).
- ✅ **Audit fixes**: passive guard and SSRF checks, plugin manifest verification, parser overflow and decompression-bomb limits, PII masking, report escaping.
- ✅ **Internal refactor**: crates split into focused modules (`foca-engine` `scan/`, `cmds/`, `analysis/`, `services/`; `foca-net` `dns/`, `intel/`, `scan/`, `tls/`; and others), see [developer docs](dev/architecture.md).

---

## Next

Planned for the betas after `2.0.0-beta.2`. Order may change with bug reports.

- ⏳ **More OEM background tests**: Samsung One UI, Huawei/EMUI, Oppo/ColorOS, vivo/Funtouch and stock Android 15/16, swipe-away, "clear all", battery saver, and the headless resume path.
- ⏳ **Sub-step counters beyond the network stage**: ports, site recon and site search.
- ⏳ **More per-item controls**: step-level pause and skip for the remaining network sub-steps (today only brute force and permutations) and for the ports stage.
- ⏳ **Slow-DNS warning in the field**: tune the threshold and the time estimate on phones behind AdGuard/v2ray and corporate VPNs.
- ⏳ Bug fixes from beta reports, then `2.0.0`.

---

## 2.0: Platform Maturity, Security & Localization

✅ All 9 milestones (`2.0-M1` through `2.0-M9`) implemented and verified; released as `2.0.0-beta.1`.

### 2.0-M1: Signed Signature Bundles (`I-25`) & Semantic CPE/CVE Version Ranges (`I-10`)
- ✅ **Signed Ed25519 signature bundles**: [`crates/foca-engine/src/services/sigbundle.rs`](../crates/foca-engine/src/services/sigbundle.rs) (`foca-sig-bundle/v1`, canonical `SHA-256` + `Ed25519` verification via `ring`, atomic `current.json` / `previous.json` swap and instant rollback; commands `signatures_status`, `signatures_import`, `signatures_update`, `signatures_rollback`).
- ✅ **Semantic CPE 2.3 & CVE version-range engine**: [`crates/foca-analysis/src/products/vercmp.rs`](../crates/foca-analysis/src/products/vercmp.rs) integrated with offline CISA KEV (`confirmed` vulnerable range vs. `patched` suppression vs. `possible`/`likely`).

### 2.0-M2: Keyed Passive Collectors (`I-9`) & WebView Screenshots (`I-13`)
- ✅ **Passive API-key collectors**: `VirusTotal v3`, `SecurityTrails`, and `GitHub Code Search` backed by Android `KeyVault` (`vt`, `st`, `github`), zero target packets, zero key leakage in `request_log`, honest `no_key` status.
- ✅ **Opt-in WebView screenshots & `pHash` clustering**: [`crates/foca-recon/src/screenshot.rs`](../crates/foca-recon/src/screenshot.rs) (`WebScreenshotter`, 64-bit `dHash`/`pHash`, Hamming clustering) + Android offscreen `WebScreenshotter.kt` (`settings.recon.screenshots = false` by default; blocked in `Access::Passive` and out-of-scope hosts).

### 2.0-M3: Full Format Matrix (`3.4`, `I-7`) & Binary `OLE2` / Media Cleaning (`I-2`, `F-12`)
- ✅ **Pure-Rust parsers for `EPUB`, `MP3` (ID3v1/ID3v2 + cover EXIF), `PSD` (`8BPS`/`8BIM` XMP/EXIF), and `7z`** (UTF-16LE filenames, Zip-Slip & budget guards).
- ✅ **Deep `\x01Ole10Native` extraction** and Before / After metadata cleaning for binary `OLE2` (`.doc`, `.xls`, `.ppt`, `.vsd`, `.pub`, `.ole`) and `ISO-BMFF` media (`.mp4`, `.mov`, `.heic`) without breaking `mdat` offsets.

### 2.0-M4: Sandboxed Plugin System (`F-27`-`F-30`)
- ✅ **Declarative + pure-Rust WASM plugin engine**: [`crates/foca-engine/src/services/plugins.rs`](../crates/foca-engine/src/services/plugins.rs) (`PluginManifest` JSON/TOML, `WasmSandbox` with linear memory ≤ 16 MiB and fuel ≤ 50,000, zero WASI/FS/raw sockets, `Access::Passive` and scope enforcement).
- ✅ **4 built-in reference plugins** (`certspotter-ext`, `robots-sitemap-parser`, `ua-gov-edrpou-enricher`, `custom-header-audit`), API commands (`plugins_list`, `plugin_install`, `plugin_toggle`, `plugin_remove`, `plugin_run_test`), and live `/settings/plugins` manager.

### 2.0-M5: Attack Path Engine & Remediation Choke Points
- ✅ **Attack Path Engine**: [`crates/foca-analysis/src/assess/attack_paths.rs`](../crates/foca-analysis/src/assess/attack_paths.rs) (`attack_paths_get`, integrated in `insights_get` and reports) building ranked compromise chains from leaked artifacts, logins, external entry points, and KEV findings, plus prioritized Remediation Choke Points.

### 2.0-M6: Cloud-Only AI (10 Providers) & Honest Network Targets
- ✅ **Cloud-only AI across 10 providers** (`OpenAI`, `Anthropic`, `Google Gemini`, `DeepSeek`, `xAI`, `Mistral`, `Groq`, `Together`, `OpenRouter`, `Custom OpenAI-compatible`) with live `/models` discovery (`ai_models_list`, `show_all`, capability extraction) and official native Thinking controls; complete removal of local/on-device AI (`local_summary`, `LocalAiProvider`, `settings.ai.local`).
- ✅ **Honest network targets only**: strictly `domain`, `*.domain`, `http(s)://url`, `IP`, `CIDR`, and `IP range` across UI, parser, and scan stages (`RDAP`, `InternetDB`, `alive`, `TLS`, `ports`); removed unsupported non-network target types (`email`, `person`, `org`, `asn`).

### 2.0-M7: Encrypted `.foca.enc` Container & Declarative CLI Scenarios (`F-31`)
- ✅ **Portable encrypted `.foca.enc` container**: [`crates/foca-engine/src/cmds/bundle.rs`](../crates/foca-engine/src/cmds/bundle.rs) (`FOCAENC1`, `PBKDF2-HMAC-SHA256` 210,000 iterations + `ChaCha20-Poly1305` AEAD + `CustodyManifest` + optional hardware `ECDSA P-256` signature, `project_export_encrypted` / `project_import_encrypted`).
- ✅ **Declarative CLI scenarios (`F-31`)**: [`crates/foca-cli/src/scenario.rs`](../crates/foca-cli/src/scenario.rs) (`foca run <scenario.toml> [--store DIR] [--json] [--dry-run]`), templates ([`passive-osint.toml`](../scenarios/passive-osint.toml), [`kszi-audit.toml`](../scenarios/kszi-audit.toml), [`preflight-folder.toml`](../scenarios/preflight-folder.toml)), and CI/CD severity/risk gates.

### 2.0-M8: Externalized Localization (`N-7`), Offline Licenses & Android `foss` / `play` Flavors
- ✅ **Unified `foca_core::Lang`** ([`crates/foca-core/src/lang.rs`](../crates/foca-core/src/lang.rs)) and externalized `locales/{en,ru,uk}/` dictionaries (core tables, 55 offline help articles, UI strings) served over strict-CSP IPC ([`crates/foca-engine/src/services/i18n.rs`](../crates/foca-engine/src/services/i18n.rs), `i18n_bundle`), auto device locale detection (fallback `en`), live language switcher on `/settings/appearance`, and localized Android `strings.xml` (`values`, `values-ru`, `values-uk`).
- ✅ **Automated offline license viewer & FOSS flavor split**: [`qa/gen-licenses.py`](../qa/gen-licenses.py) (`--check`), [`crates/foca-engine/src/services/licenses.rs`](../crates/foca-engine/src/services/licenses.rs) (`licenses_get`, `/settings/licenses`), and Android `distribution` product flavors: `foss` (100% GPL-3.0 / F-Droid clean, [`src/foss/.../OcrEngine.kt`](../src-tauri/gen/android/app/src/foss/java/app/sinon/focars/platform/OcrEngine.kt)) vs. `play` (opt-in Google ML Kit OCR, [`src/play/.../OcrEngine.kt`](../src-tauri/gen/android/app/src/play/java/app/sinon/focars/platform/OcrEngine.kt)).

### 2.0-M9: English-First Documentation, UI & Release Gate
- ✅ Flagship English documentation (`README.md`, `CHANGELOG.md`, `SECURITY.md`, `CONTRIBUTING.md`, `THIRD_PARTY.md`, `.github/` templates, `docs/`) alongside Russian user documentation (`README.ru.md`, `docs/ru/`).
- ✅ Final UI wiring, version bump, and full static/unit/invariant/license/docs release gate.

---

## 1.6: Remediation, Report Trust & Interoperability

✅ Completed.

- ✅ **Contextual Remediation Playbooks**: [`crates/foca-analysis/src/assess/playbooks.rs`](../crates/foca-analysis/src/assess/playbooks.rs) (`finding_playbook`, localized `uk`/`ru`/`en`, safe commands without raw secrets/evidence, verification checklists).
- ✅ **Chain of Custody & Hardware Report Signing**: [`crates/foca-report/src/sections/custody.rs`](../crates/foca-report/src/sections/custody.rs) (`CustodyRecord`, `.sha256` sidecar), hardware `ECDSA P-256` `.sig.json` signing ([`ReportSigner.kt`](../src-tauri/gen/android/app/src/main/java/app/sinon/focars/platform/ReportSigner.kt), [`src-tauri/src/bridge.rs`](../src-tauri/src/bridge.rs)), and `report_verify`.
- ✅ **Pure-Rust DOCX Report Generator (`I-18`)**: [`crates/foca-report/src/formats/docx.rs`](../crates/foca-report/src/formats/docx.rs) (`zip` + `quick-xml`, embedded severity PNG chart, all 6 templates, `uk`/`ru`/`en`, `SecretMode::Hide` default).
- ✅ **STIX 2.1, Nuclei & `httpx` Exports**: [`crates/foca-report/src/formats/stix.rs`](../crates/foca-report/src/formats/stix.rs) and [`crates/foca-report/src/export.rs`](../crates/foca-report/src/export.rs).
- ✅ **Optional Offline OCR (`I-6`)**: [`crates/foca-engine/src/services/ocr.rs`](../crates/foca-engine/src/services/ocr.rs) + [`OcrLogic.kt`](../src-tauri/gen/android/app/src/main/java/app/sinon/focars/platform/OcrLogic.kt) + `play`-flavor ML Kit [`OcrEngine.kt`](../src-tauri/gen/android/app/src/play/java/app/sinon/focars/platform/OcrEngine.kt) (`settings.ocr.enabled = false` default, FTS5 indexing, PII masking).

---

## 1.5: Event Monitoring, Breach Checks & Quick Tools

✅ Completed.

- ✅ **HIBP Passwords (k-Anonymity)**: [`crates/foca-net/src/hibp.rs`](../crates/foca-net/src/intel/hibp.rs) (pure-Rust SHA-1 RFC 3174, 5-char prefix range query with `Add-Padding: true`, opt-in `secret_hibp_check`).
- ✅ **Corporate Login Patterns & Contextual Pentest Wordlists**: [`crates/foca-analysis/src/identity/wordlist.rs`](../crates/foca-analysis/src/identity/wordlist.rs) (11 patterns + `DOMAIN\login`, KMU-2010/ICAO transliteration, strict secret/PII exclusion).
- ✅ **Event Alerts & Risk Trend**: [`crates/foca-engine/src/alerts.rs`](../crates/foca-engine/src/alerts.rs) (9 trigger rules, deduplication, `risk_trend_get`, Telegram/Webhook delivery via KeyVault `tg_bot`/`webhook`).
- ✅ **Quick Tools & Scan Queue**: `/tools` and `/queue`.

---

## 1.4: Analytics, Visualization & Document Hygiene

✅ Completed ([User Guide](user/analytics-and-hygiene.md)).

- ✅ **Layered Relationship Graph** (layers, clusters, Link Chain mode, report SVG), Internal Network Map (`/p/netmap`), Timeline & 7×24 Heatmap, Org Chart, Metadata Anomalies, and Versions & Copies.
- ✅ **Offline CISA KEV** (`I-10`, upgraded with semantic version ranges in `2.0-M1`).
- ✅ **Web Audit**: CSP/headers, source maps, OpenAPI/Swagger/Actuator, CORS & HTTP methods (never PUT/DELETE).
- ✅ **Document Hygiene**: A-F grade, full PDF rewrite stripping old revisions, ODF & OOXML cleaning, Before/After self-check, and Android Share Target ("Share → Check in FOCA-rs").
- ✅ **Standards & Report Templates**: MITRE ATT&CK, CWE, OWASP Top 10/WSTG, ISO/IEC 27001:2022, ND TZI 2.5-004-99 & 3.7-003-05 ([STANDARDS.md](STANDARDS.md)); Executive, KSZI/Compliance, and Lab templates.
- ✅ **Reference Case**: 12 synthetic offline documents for "TOV Pryklad".
- ⏳ Live on-device verification items: Share Target URI grant from third-party messengers and paginated PDF print breaks require physical Android device testing.

---

## 1.3: FOCA Format Parity & Document Forensics

✅ Completed ([User Guide](user/documents.md)).

- ✅ Formats: InDesign, WordPerfect/Works, Visio, Publisher, LNK, EML/MSG, ICS/VCF, MP4/MOV/HEIC, recursive ZIP (extended with EPUB, MP3, PSD, 7z in `2.0-M3`).
- ✅ XMP edit history, recursive attachment parsing under shared budget, PDF deleted-text revision diffs, bad-redaction detection, hidden text/sheets/rows, data connections.
- ✅ Digital signatures (PDF CAdES/RFC 3161, OOXML XML-DSig, VBA) and Ukrainian QES (КЕП).
- ✅ PII masking before DB write, SQLite FTS5 full-text search (`I-5`), custom regex rule sets, offline folder/ZIP import via Android SAF, and parser fuzzing (~1.10B inputs, 0 panics).
- ⏳ Known nuances: Word style-inherited hidden text (outside run `w:vanish`) and legacy OLE `.doc`/`.xls` embedded signatures are not parsed; redaction geometry check is heuristic; FTS5 indexes the first 64 KiB per document; QES certificate-chain/OCSP revocation validation is offline-only.

---

## 1.2: Subdomains & Infrastructure Intelligence

✅ Completed.

- ✅ Subdomain brute-force (top-1500 / top-5000 / custom, adaptive AIMD pace, multi-level wildcard filter), `alterx`/`gotator`-style permutations with document metadata provenance, in-scope PTR sweeps, and NSEC walking (Full only).
- ✅ Passive SaaS fingerprinting, Microsoft 365 / Entra ID tenant discovery, mail/DNS policies (`BIMI`, `MTA-STS`, `TLS-RPT`, `CAA`, `DNSSEC`), offline CDN/cloud IP ranges & origin candidates, X.509/TLS & STARTTLS inspector, CT history, abandoned hosts, `O=` sibling pivots, host roles & priorities.
- ⏳ Known nuances: historical IP lookups from Wayback/OTX are not yet fed into origin candidates; legacy TLS 1.0/1.1 raw probes run on direct TLS ports (not over STARTTLS).

---

## 1.1: Network Reliability, CAPTCHA & Headless Monitoring

✅ Completed (`1.1.0`, `1.1.1`, `1.1.2`).

- ✅ Shared dork queue with search-engine failover, Yahoo & public SearXNG pool, honest mobile WebView, one-tap manual CAPTCHA verification, structural CAPTCHA detector (`detect_captcha_signals`), and `app.sinon.focars` package ID.
- ✅ Network tampering detector (`foca-net::canary`: TCP/DNS/TLS), protocol-verified host liveness (`tcp_alive_checked`), `v2rayNG` proxy preset + proxy checker + per-group HTTP proxy routing, optional OTX key, `ScanEnv` incomplete-snapshot protection, and stabilized E2E suite ([testing/README.md](testing/README.md)).
- ✅ Autonomous headless background monitoring (`1.1.2`): JNI runner via Android WorkManager (≤ 8 min checkpoint budget), `DataDirLock`/WAL safety, `skipped_headless` status, and live handoff into the UI.

---

## Specification Status Summary

In FOCA-rs 2.0.0-beta.2:

- ✅ **Implemented across the full Android-applicable scope**: projects & honest scope (`F-1`-`F-3`, `I-23`), search & download (`F-4`-`F-9`, `I-9`, `I-21`), document formats & forensics (`3.4`, `F-10`-`F-12`, `I-1`-`I-7`), DNS/RDAP/subdomains/AXFR/mail/TLS/ports (`F-13`, `F-14`, `F-16`-`F-20`, `I-11`, `I-12`), analysis, CISA KEV + CPE/CVE semver ranges, Attack Paths, graph/globe/timeline (`F-22`-`F-24`, `I-8`, `I-10`, `I-14`-`I-16`), reports, DOCX, Custody, STIX 2.1, defensive hygiene (`F-25`, `F-26`, `I-18`, `I-19`), screenshots & `pHash` (`I-13`), monitoring & alerts (`I-17`), Cloud-only AI (`I-20`), sandboxed declarative + WASM plugins (`F-27`-`F-30`), signed `Ed25519` signature bundles (`I-25`), declarative CLI `foca run scenario.toml` (`F-31`, `F-32`), and live `EN / RU / UA` localization (`N-7`).
- ⚠️ Adapted by design: FOCA Roles/Vulnerabilities tree (`F-21`) → Findings + Data segments; Rhai (`I-24`) → declarative regex rule sets & sandboxed plugins; TOML config (`F-33`) → SQLite settings + Android Keystore + CLI `scenario.toml`.

---

## Out of Scope / Intentionally Excluded

- ✖ **Desktop builds (Windows/Linux/macOS) & server daemon mode (`I-22`)**: Android-only product ([ADR-0001](adr/0001-android-only.md)); `foca-cli` remains a developer/CI companion tool.
- ✖ **Local / on-device AI models**: Removed in `2.0-M6` in favor of 10 dynamic Cloud AI API providers with live `/models` discovery and editable redaction preview.
- ✖ **Non-network scope targets (`email`, `person`, `org`, `asn`)**: Removed in `2.0-M6` to guarantee honest network targeting.
- ✖ **Keyboard shortcuts / `Ctrl+K` command palette (`I-26`)**, Not applicable on mobile (light/dark themes are supported).
- ✖ **Google Search scraping / CSE, DIARIO, FOCA Market, legacy FOCA project import**: Obsolete or unsupported ([ADR-0007](adr/0007-search-engines-via-webview.md)).
- ✖ **DNS cache snooping (`F-15`)**: Unreliable across modern public DoH and recursive resolvers.
- ✖ **Automatic CAPTCHA solving and public proxy scraping**: Explicitly rejected ([ADR-0012](adr/0012-no-captcha-solving-no-public-proxies.md)).
