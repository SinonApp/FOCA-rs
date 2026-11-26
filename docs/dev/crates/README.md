# Core Crates

↑ [Developer Guide](../README.md) · [Architecture](../architecture.md)

11 crates in `crates/` (Cargo workspace, `default-members = crates/*`), listed bottom-up by dependency order. Line counts cover `src/**/*.rs`; test counts include unit and integration `#[test]` / `#[tokio::test]` cases.

| Crate | Purpose | `src/` Lines | Tests |
|---|---|---|---|
| [foca-core](foca-core.md) | Data model, targets, scope, contract DTOs, forensics structs, unified `Lang` | 3,172 | 26 |
| [foca-meta](foca-meta.md) | Document metadata extraction, forensics, hygiene grading & verified cleaning | 17,493 | 83 |
| [foca-net](foca-net.md) | Network layer: `NetClient`, DNS/DoH, CT, RDAP, mail, TLS, ports, HIBP, notifications | 19,383 | 169 |
| [foca-search](foca-search.md) | Discovery sources, dork pool, WebView render scripts, crawler, downloader | 8,092 | 73 |
| [foca-store](foca-store.md) | SQLite per project (schema v10 + FTS5), migrations, snapshot export/import, settings | 4,898 | 28 |
| [foca-analysis](foca-analysis.md) | People, software/KEV, secrets, PII, findings, insights, attack paths, playbooks, alerts, risk | 20,852 | 119 |
| [foca-recon](foca-recon.md) | Site reconnaissance, web audit, and isolated WebView screenshots | 7,761 | 57 |
| [foca-fuzz](foca-fuzz.md) | Content discovery for forgotten files and backups on authorized targets | 4,633 | 48 |
| [foca-report](foca-report.md) | HTML/MD/DOCX/CSV/JSON reports, inline SVGs, Chain of Custody, STIX 2.1, EN/RU/UK | 15,117 | 100 |
| [foca-engine](foca-engine.md) | 9-stage scan engine, `Engine::invoke` facade, plugins, sigbundles, `.foca.enc`, Cloud AI, i18n/licenses | 25,704 | 164 |
| [foca-cli](foca-cli.md) | Desktop CLI `foca`, declarative scenarios (`foca run`), and `serve` / `testnet` harnesses | 4,343 | 14 |
| **Total** | | 131,448 | 881 |

Dependency graph: [architecture.md](../architecture.md#crates-and-dependencies). The Android/Tauri application bridge (`src-tauri`, crate `foca-rs`) is documented in [android.md](../android.md).

Each crate page covers: purpose, module table, public API, tests, and pitfalls.
