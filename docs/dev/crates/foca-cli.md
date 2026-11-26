# foca-cli

↑ [Core Crates](README.md) · [Developer Guide](../README.md) · [Architecture](../architecture.md)

- [Purpose](#purpose)
- [Declarative Scenarios (`foca run`)](#declarative-scenarios-foca-run)
- [Modules](#modules)
- [Public API](#public-api)
- [Tests](#tests)
- [Pitfalls](#pitfalls)

Path: `crates/foca-cli/` · `src/` lines: 4,343 · tests: 14 · depends on: [foca-analysis](foca-analysis.md), [foca-core](foca-core.md), [foca-engine](foca-engine.md), [foca-fuzz](foca-fuzz.md), [foca-meta](foca-meta.md), [foca-net](foca-net.md), [foca-recon](foca-recon.md), [foca-report](foca-report.md), [foca-search](foca-search.md), [foca-store](foca-store.md)

## Purpose

`foca` is a desktop CLI for exercising the Rust core, running declarative CI/CD audit scenarios, and driving the browser E2E harness (the primary end-user product remains the Android app, see [ADR-0001](../../adr/0001-android-only.md)).

### Commands

- `foca extract <file...> [--json] [--text]`: extract document metadata and optional plain text;
- `foca target <str...> [--json]`: parse target strings;
- `foca clean <in> <out>`: strip document metadata;
- `foca analyze <dir|files...> [--scope d1,d2] [--json] [--reveal-secrets]`: extract and analyze local files (people, software, hosts, secrets, findings, risk); secret values are masked unless `--reveal-secrets` is given, files over the parser size limit are skipped and symbolic link cycles are walked once;
- `foca project new|list|import`: manage projects in the store (`--store`, defaults to `$FOCA_HOME` or `./foca-data`);
- `foca dns <domain> [--whois] [--json]`: DNS records, SPF/DMARC/DKIM, dangling CNAMEs, RDAP/RIPEstat;
- `foca subdomains <domain> [--resolve] [--json]`: CT subdomains (`crt.sh`, CertSpotter);
- `foca search <domain> [--sources wayback,cc,crt] [--limit N] [--json]`: document search (passive sources by default);
- `foca download <url...> --project id`: scoped, logged, resumable download into a project;
- `foca report --project id [--format html|md|csv|json] [--lang ru|uk|en] [--out file]`: build project report;
- `foca export --project id --kind users --format dict [--out file]`: export tables (`list`, `dict`, `csv`, `json`, `maltego`, `graphml`, `md`, `stix`);
- `foca scan --project id --profile passive --wait [--limit N]`: run a full scan via `foca-engine` with identical launch rules and `scan://event` stream;
- `foca run <scenario.toml> [--store dir] [--json] [--dry-run]`: execute a declarative audit scenario (`F-31`);
- `foca fuzz` / `foca ports` / `foca recon`: standalone fuzzing, TCP port scanning, and site recon commands;
- `foca serve --data dir [--port 8787] [--test-net net.json]`: HTTP/SSE E2E harness (`POST /invoke`, SSE `/events`, static `ui/`);
- `foca testnet --port 8788 --write-config net.json`: offline local "internet" (CDX, crt.sh, `tests/corpus` documents) for `serve`.

## Declarative Scenarios (`foca run`)

Implemented in `src/scenario.rs` (`F-31`), `foca run` runs reproducible offline or passive/standard/full audits through the real `foca-engine`, builds optional reports (including Chain of Custody), and enforces CI/CD exit-code gates:

```sh
foca run scenarios/kszi-audit.toml --dry-run       # validate TOML schema without running
foca run scenarios/preflight-folder.toml --json    # offline folder audit + JSON summary
foca run scenarios/passive-osint.toml --store ./audit --json
```

Built-in scenario templates in `scenarios/`:

| File | Mode | Summary |
|---|---|---|
| `scenarios/kszi-audit.toml` | `offline` | KSZI / compliance audit with `credentials` + `pii_ua` presets, Ukrainian HTML compliance report with Chain of Custody, gate `fail_on_severity = "high"` & `max_risk = 70` |
| `scenarios/passive-osint.toml` | `scan` (`passive`) | Zero-target-packet passive OSINT ([ADR-0009](../../adr/0009-passive-never-touches-target.md)), English full HTML report with custody, gate `fail_on_severity = "crit"` |
| `scenarios/preflight-folder.toml` | `offline` | 100% offline pre-publication folder check (`./docs-to-publish`), English Markdown executive report, gate `fail_on_severity = "high"` |

Supported `[gate]` thresholds return a non-zero exit code when breached:
- `fail_on_severity`: `low` | `warn`/`medium` | `high` | `crit`/`critical`
- `max_risk`: `0..=100` (fails when project risk strictly exceeds `max_risk`)

## Modules

| File | Lines | Contents |
|---|---|---|
| `src/fuzz.rs` | 497 | `foca fuzz`: authorized site content discovery CLI wrapper |
| `src/log.rs` | 172 | `RUST_LOG` tracing subscriber printing diagnostics to `stderr` |
| `src/main.rs` | 1,082 | CLI entry point and `Cmd` subcommand enum (`clap`) |
| `src/net.rs` | 416 | Network subcommands: `dns`, `subdomains`, `search`, `download` |
| `src/ports.rs` | 153 | `foca ports <host> [--top 100|1000] [--ports …]`: TCP port scan and banners |
| `src/recon.rs` | 256 | `foca recon <url/domain>`: project-less site reconnaissance |
| `src/scan.rs` | 161 | `foca scan`: scan runner via `foca-engine` |
| `src/scenario.rs` | 621 | Declarative audit scenarios (`foca run <scenario.toml> [--json] [--dry-run]`, `F-31`) |
| `src/serve.rs` | 631 | `foca serve`: HTTP/SSE E2E harness exposing `Engine::invoke` + static `ui/` |
| `src/testnet.rs` | 354 | `foca testnet`: offline mock "internet" for E2E tests |

## Public API

Subcommands of `foca` (`enum Cmd` in `src/main.rs`): `serve`, `testnet`, `extract`, `target`, `clean`, `analyze`, `dns`, `subdomains`, `search`, `download`, `report`, `export`, `scan`, `run`, `fuzz`, `ports`, `recon`, `project new|list|import`.

Command help: `cargo run -p foca-cli -- --help`.

## Tests

`cargo test -p foca-cli`: 6 unit tests in `src/` (including `scenario.rs`, `fuzz.rs`, `log.rs`, `serve.rs`).

## Pitfalls

- Desktop tool and E2E/CI harness, not the mobile product ([ADR-0001](../../adr/0001-android-only.md)).
- `RUST_LOG` output requires the tracing subscriber configured in `log.rs`.
- `foca serve` runs without WebView CSP, stubs `platform_*` calls, and provides no embedded browser (WebView search-engine dork sources report `unavailable`).
- On shared machines, isolate E2E runs with custom `E2E_DIR`, `E2E_PORT`, and `E2E_NET_PORT`.
