# FOCA-rs Documentation

**English | [Русский](ru/README.md)** · ↑ [Repository Root](../README.md)

FOCA-rs 2.0.0-beta.3 is an Android application (Tauri v2 + Rust core) for authorized OSINT, document metadata forensics, attack-path analysis, and compliance reporting. All documentation uses relative links, so it reads the same on GitHub and in Obsidian; Russian user documentation is maintained separately in [docs/ru/README.md](ru/README.md).

## User Documentation

| Document | Contents |
|---|---|
| [User Guide Index](user/README.md) | Overview and navigation for end users |
| [Getting Started, Projects & Scope](user/getting-started.md) | APK installation (`foss`/`play`), terms, projects, honest network targets & exclusions, legal use |
| [Scan Profiles](user/scan-profiles.md) | Passive / Standard / Full / Custom network behavior and 9 scan stages |
| [Sources](user/sources.md) | Keyless and optional API-key sources, access level, and profile matrix |
| [Data, Findings, Reports & Monitoring](user/data-and-reports.md) | Findings triage, Attack Paths, playbooks, reports (HTML/PDF/DOCX/MD/JSON/CSV), Chain of Custody, exports, monitoring |
| [Documents & Forensics](user/documents.md) | Supported formats (20+), digital signatures & Ukrainian QES (КЕП), redaction checks, PII masking, FTS5 search, custom rules, offline import |
| [Analytics, Web Audit & Document Hygiene](user/analytics-and-hygiene.md) | Reference case, layered graph, internal network map, timeline/heatmap, CISA KEV, web audit, hygiene & Before/After cleaning, Share Target |
| [Own SearXNG instance](user/searxng.md) | Self-hosted SearXNG for dorks, JSON output, connecting it in Settings → API keys, Brave Search API key |
| [Settings & Network](user/settings-network.md) | Browser UA profiles, proxy/Tor/v2rayNG, VPN/AdGuard port canaries, CAPTCHA verification, Cloud AI, plugins, localization, offline licenses |
| [FAQ & Troubleshooting](user/faq.md) | Xiaomi/HyperOS background limits, 0 documents, CAPTCHA handling, diagnostic logs |
| [Glossary](user/glossary.md) | Key OSINT, metadata, forensics, and security terms |

## Developer Documentation

| Document | Contents |
|---|---|
| [Developer Overview](dev/README.md) | Developer documentation index |
| [Architecture](dev/architecture.md) | 11-crate dependency graph, scan stages, Rust ⇄ Kotlin ⇄ JS bridge, per-project storage |
| [Crates Reference](dev/crates/README.md) | Per-crate guide: responsibilities, modules, APIs, tests, and pitfalls |
| [Android & Kotlin](dev/android.md) | Foreground services, `RenderFetcher`, `WebScreenshotter`, `VerifyDialog`, `KeyVault`, `WorkManager`, `foss`/`play` flavors |
| [User Interface](dev/ui.md) | Route map, vanilla JS architecture, strict-CSP IPC localization (`i18n_bundle`), mobile layout rules |
| [UI ⇄ Core IPC API](API.md) | Complete command contract, DTOs, events, and scope rules |
| [Building & Testing](dev/build.md) | Rust/Android SDK/NDK setup, `assembleFossRelease` / `assemblePlayRelease`, APK signing, release gate |
| [Contributing Guide](dev/contributing.md) | Commit conventions and step-by-step guides to add a source, finding rule, screen, or scan stage |

## Testing & QA

| Document | Contents |
|---|---|
| [Testing & QA Guide](testing/README.md) | `run-all.sh`, `real-e2e.sh`, `shoot.sh`, data invariants, `gen-licenses.py`, allowed live test targets |
| [Test Scenarios](testing/scenarios.md) | Real-core E2E scenarios and demo-backend scenario tables |

## Architecture Decisions, Standards & Research

| Document | Contents |
|---|---|
| [Architecture Decision Records (ADR)](adr/README.md) | ADR 0001-0012: Android-only, vanilla JS, SQLite per project, `panic=unwind`, native bridge, WebView search, rootless TCP ports, strict Passive guarantee, optional keys, clean-room Rust logic, no auto-CAPTCHA / public proxies |
| [Security Standards Mapping](STANDARDS.md) | Declarative finding-to-standard mapping (`standards.toml`): MITRE ATT&CK v20, CWE (Top 25 flag), OWASP Top 10:2025 & WSTG v4.2, ISO/IEC 27001:2022, NIST SP 800-53 / ND TZI 3.6-006-24, GDPR / Law 2297-VI, legacy ND TZI 2.5-004-99 & 3.7-003-05 |
| [Research Notes](research/README.md) | Free/open OSINT sources, CAPTCHA behavior analysis, and live verification notes |

## History & Planning

| Document | Contents |
|---|---|
| [Roadmap](ROADMAP.md) | What shipped in the 2.0 betas, what comes next, what is out of scope |
| [Changelog](../CHANGELOG.md) | Release-by-release changes |

## Repository Directories

| Directory | Guide |
|---|---|
| `crates/` | [Rust Core (11 crates)](../crates/README.md) |
| `src-tauri/` | [Tauri v2 Bridge & Android Project](../src-tauri/README.md) |
| `ui/` | [Vanilla JS Mobile UI](../ui/README.md) |
| `qa/` | [QA Scripts, Invariants & E2E Harness](../qa/README.md) |
| `tests/` | [Reference Document Corpus & Fixtures](../tests/README.md) |
