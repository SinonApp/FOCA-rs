# Developer Guide

↑ [Documentation](../README.md) · [Repository Root](../../README.md)

| Document | Summary |
|---|---|
| [Architecture](architecture.md) | 11 workspace crates and dependency graph, 9 scan stages, data flow, Rust ↔ Kotlin ↔ JS bridge, SQLite per project, embedded i18n |
| [Core Crates](crates/README.md) | Per-crate reference: purpose, modules, public API, tests, and pitfalls |
| [Android & Kotlin](android.md) | `foss` vs `play` product flavors, `OcrEngine.kt` split, `ScanService`, headless WorkManager monitoring, `RenderFetcher`, `VerifyDialog`, `KeyVault`, `ReportSigner`, localized string resources |
| [User Interface (UI)](ui.md) | Vanilla JS `ui/` layout, route map, `F.i18n` / `F.t` / lazy help, `/settings/licenses`, Cloud-only AI, honest network targets, UI principles |
| [UI ↔ Core Contract](../API.md) | Tauri IPC commands, DTO types, events, scope rules, and active phase (`docs/API.md`) |
| [Build & Test](build.md) | Core, UI, E2E harness, `foss` / `play` APK builds, license compliance check, APK signing (no passwords), version bump, release process, low-RAM tips |
| [Contributing](contributing.md) | Branches and commits, working in parallel, how to add a source, finding rule, screen, scan stage or command |

Related: [Testing](../testing/README.md) · [Architecture Decisions (ADR)](../adr/README.md) · [Research](../research/README.md) · [Roadmap](../ROADMAP.md).

Quick start:

```sh
cargo test                          # workspace core crates
python qa/gen-licenses.py --check   # verify licenses.json, GPL-3.0 compatibility, and foss purity
node qa/data-invariants.mjs         # demo backend data invariants
qa/run-all.sh static                # node --check, Prettier/ESLint, invariants, i18n keys, docs links, JNI check
```
