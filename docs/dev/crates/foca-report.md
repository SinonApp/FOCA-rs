# foca-report

↑ [Core Crates](README.md) · [Developer Guide](../README.md) · [Architecture](../architecture.md)

- [Purpose](#purpose)
- [Modules](#modules)
- [Public API](#public-api)
- [Tests](#tests)
- [Pitfalls](#pitfalls)

Path: `crates/foca-report/` · `src/` lines: 15,117 · tests: 100 · depends on: [foca-analysis](foca-analysis.md), [foca-core](foca-core.md), [foca-meta](foca-meta.md), [foca-store](foca-store.md)

## Purpose

`foca-report` generates pentest/audit reports and structured data exports (`F-23`, `F-25`, `F-26`, `I-18`, `I-23`).

- **Report Builders (`build_report`, `build_report_with_log`, `build_report_with_visuals`)**:
  - **Formats**: self-contained A4 HTML (inline CSS, zero external assets or JS), Markdown (Obsidian-ready with YAML front matter), pure-Rust DOCX (`formats/docx.rs`, OOXML WordprocessingML), CSV (RFC 4180, UTF-8 BOM, CSV-injection safe), and JSON (`schema/report.v1.json`).
  - **Templates (`templates.rs`)**: `full` (complete audit report), `executive` (single-page management brief: risk score, top-5 findings in plain language, top-3 actions), `compliance` (findings mapped to MITRE ATT&CK v20/CWE/OWASP Top 10:2025/WSTG/ISO 27001/NIST SP 800-53 · ND TZI 3.6-006-24/privacy/legacy ND TZI/KSZI with auditor disclaimer), and `lab` (academic lab format).
  - **Static Inline SVG Diagrams (`svg/`)**: zero-dependency, deterministic inline SVGs, layered link graph (`svg/graph.rs`), internal network tree (`svg/netmap.rs`), yearly lane timeline (`svg/timeline.rs`), and 7×24 activity heat map (`svg/heatmap.rs`).
  - **AI-assisted executive summary**: `ReportOptions::ai_summary` (filled by the core from the project's stored `ai_summarize` result, options key `ai_summary_data`) renders as a labelled, escaped section with a "not verified" note in HTML/MD/DOCX and the `executive` template; `opts.ai_summary: false` turns it off.
  - **Chain of Custody (`sections/custody.rs`)**: SHA-256 verification tables and custody manifests (optionally hardware-signed with ECDSA P-256 via Android `ReportSigner.kt`).
  - Risk score and severity counters are computed strictly over the findings included in the report; `ResultSnapshot` preserves historical figures.
- **Exports (`export.rs`, `formats/stix.rs`)**: plain list, `.txt` wordlist, CSV, JSON, Maltego CSV, GraphML, Markdown, and pure-Rust OASIS STIX 2.1 JSON bundles (`ExportFormat::Stix`).
- **Unified Localization (`foca_core::Lang` + `locales/{en,ru,uk}/{report,findings}.json`)**:
  - Re-exports unified `foca_core::Lang` (`opts::Lang`: `En`, `Ru`, `Uk`).
  - `src/i18n.rs` loads all report headings, labels, severity names, diagram legends, template text, forensics/ports sections, and Chain-of-Custody text from `locales/{en,ru,uk}/report.json` via `include_str!`.
  - `src/ftext.rs` loads finding translation catalogs, technology categories, roles, scope labels, and log notes from `locales/{en,ru,uk}/findings.json` to translate core finding titles, descriptions, recommendations, and evidence into English, Ukrainian, or Russian.

### Security Model

Every string extracted from documents or targets is treated as hostile input: renderers emit strings exclusively through `safe.rs` (HTML/XML/Markdown/CSV escaping, CSV formula neutralization, safe filenames and URLs) and `svg::clean` (no `style=`, `href`, or scripts). Secrets are hidden by default (`SecretMode::Hide`, `include_secrets = false`).

Schema: `crates/foca-report/schema/report.v1.json`. Examples: `examples/out/`.

## Modules

Layout: `lib.rs` builds the report context; `sections/` prepare rows per report section; `formats/` write HTML, Markdown, DOCX, STIX and CSV/JSON from it; `svg/` draws the static visuals; the remaining root modules are shared data, options, i18n and escaping.

| File | Lines | Contents |
|---|---|---|
| `src/data.rs` | 624 | Finding selection (`FOCA_RULES.reportSelect` parity), report-scoped risk, `ResultSnapshot` |
| `src/export.rs` | 1,276 | Table exports: list, `.txt` wordlist, CSV, JSON, Maltego CSV, GraphML, Markdown |
| `src/formats/docx.rs` | 1,370 | Pure-Rust `.docx` (OOXML WordprocessingML) report generator |
| `src/formats/html.rs` | 1,168 | Self-contained A4 HTML report (inline CSS, no JS, no external resources) |
| `src/formats/md.rs` | 853 | Obsidian-compatible Markdown report with YAML front matter and safe escaping |
| `src/formats/stix.rs` | 463 | Pure-Rust OASIS STIX 2.1 JSON bundle generator (`ExportFormat::Stix`) |
| `src/formats/tabular.rs` | 267 | RFC 4180 CSV (with BOM and formula escaping) and JSON v1 report renderers |
| `src/ftext.rs` | 621 | Finding/role/term translation engine loaded from `locales/{en,ru,uk}/findings.json` |
| `src/i18n.rs` | 1,186 | Localized report strings loaded from `locales/{en,ru,uk}/report.json` (`foca_core::Lang`) |
| `src/lib.rs` | 661 | Top-level `build_report*`, `report_templates`, `ReportArtifact`, `ReportSummary`, and re-exports |
| `src/mask.rs` | 322 | Secret (`{{s:…}}`) and PII redaction before rendering |
| `src/opts.rs` | 751 | Report/export option parsing (re-exports `foca_core::Lang` as `Lang`) |
| `src/page.rs` | 7 | HTML page shell shared by the full report and extra templates: print stylesheet and Content-Security-Policy |
| `src/recon_view.rs` | 120 | Website recon view of `snapshot.recon`: input of the website section and the per-host software summary |
| `src/safe.rs` | 334 | HTML/XML/Markdown/CSV escaping, CSV injection protection, safe filenames and links |
| `src/sections/custody.rs` | 330 | Chain of Custody manifests and SHA-256 verification helpers |
| `src/sections/forensics.rs` | 230 | Document forensics subsection (signatures, KEP, revisions, bad redactions) |
| `src/sections/infra.rs` | 346 | Infrastructure subsections (`snapshot.infra`: certs, mail policies, SaaS, M365, CDN) |
| `src/sections/ports.rs` | 295 | Port scan table subsection |
| `src/sections/recon.rs` | 460 | Site reconnaissance and technology subsection |
| `src/svg/graph.rs` | 709 | Layered link graph SVG (simplified Sugiyama layout with clusters) |
| `src/svg/heatmap.rs` | 530 | 7×24 weekday × hour activity heat map SVG |
| `src/svg/mod.rs` | 396 | Static inline SVG coordinator (`Visuals`) and sanitization (`svg::clean`) |
| `src/svg/netmap.rs` | 419 | Internal AD/network hierarchy tree SVG |
| `src/svg/timeline.rs` | 395 | Yearly multi-lane chronology SVG |
| `src/table.rs` | 79 | Table building blocks shared by sections and format writers (HTML/Markdown markup, DOCX tables) |
| `src/templates.rs` | 890 | `executive`, `compliance` (KSZI / ISO 27001 / OWASP), and `lab` templates in EN/RU/UK |

## Public API

Re-exports in `src/lib.rs`:

- `data::{Counts, LogSummary, Overview, RequestEntry, ResultSnapshot}`
- `export::{export, export_with_log, Artifact}`
- `opts::{DictKind, ExportFormat, ExportKind, ExportOptions, Lang, Logo, MdLayout, ReportFormat, ReportOptions, SecretMode, Sections, Template}`
- `svg::Visuals`

Top-level functions & constants: `build_report()`, `build_report_with_log()`, `build_report_with_visuals()`, `report_templates()`, `normalized_opts()`, `size_label()`, `next_version()`, `report_file_name()`, `tpl_label()`, `SCHEMA_VERSION`, `REPORT_SCHEMA`, `GENERATOR`.

Full API docs: `cargo doc -p foca-report --no-deps --open`.

## Tests

`cargo test -p foca-report`: 36 unit tests in `src/` + 43 integration tests in `tests/`:

| File | Tests |
|---|---|
| `tests/report.rs` | 481 |
| `tests/svg.rs` | 291 |

## Pitfalls

- Always pass untrusted metadata strings through `safe.rs` (and `svg::clean` for SVG labels).
- Golden fixtures: regenerate with `UPDATE_GOLDEN=1 cargo test -p foca-report --test report`; `generator: "FOCA-rs <ver>"` in `tests/golden/*` and `examples/out/*` must be updated on every version bump.
- PDF export renders self-contained HTML and delegates printing to Android's print framework (`platform_print`).
- When adding a new finding rule, add matching entries to `locales/{en,ru,uk}/findings.json` so English and Ukrainian reports translate properly instead of falling back to raw core text.
