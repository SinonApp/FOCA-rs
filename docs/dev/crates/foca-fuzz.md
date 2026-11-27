# foca-fuzz

↑ [Core Crates](README.md) · [Developer Guide](../README.md) · [Architecture](../architecture.md)

- [Purpose](#purpose)
- [Modules](#modules)
- [Public API](#public-api)
- [Tests](#tests)
- [Pitfalls](#pitfalls)

Path: `crates/foca-fuzz/` · `src/` lines: 4,633 · tests: 48 · depends on: [foca-analysis](foca-analysis.md), [foca-core](foca-core.md), [foca-net](foca-net.md), [foca-recon](foca-recon.md)

## Purpose

`foca-fuzz` discovers forgotten publicly accessible documents, backup archives, directory listings, and exposed service files on an authorized audit target (inspired by classic FOCA's Backups Fuzzer, ffuf soft-404 auto-calibration, and MIT-licensed SecLists wordlists, see `THIRD_PARTY.md`).

- **Active profile only**: every request goes through `foca_net::NetClient` with `Access::Active`, enforcing project scope, host/IP exclusions, path exclusions (`FuzzConfig::exclude_paths`), per-hop redirect validation, and full request logging.
- **Polite default limits**: 4 workers, 5 req/s, jitter, request budget, and `max_time`. Fuzzers of several hosts running at once can share one budget (`Fuzzer::with_shared_budget`): every request of every holder counts toward `max_requests`.
- **Automatic backoff stop**: halts on bursts of HTTP 429/403/5xx ("target rate-limited requests: fuzzing stopped"). Network errors without any HTTP answer (refused, timeout, DNS or TLS failure) stop the host with the reason `unreachable` and the `fuzz_unreachable` warning instead. Zero WAF/rate-limit evasion (no IP/UA rotation, no path obfuscation), no parameter/payload fuzzing, no credential brute-forcing, and no bulk repository/database dumping.
- **Minimal masked evidence**: records availability and a short masked snippet capped by `FuzzConfig::body_limit`, full files are never downloaded.

Built-in gzipped wordlists live in `crates/foca-fuzz/wordlists/` (SecLists, MIT). Site test fixture: `tests/fixtures/fuzz-site/`.

## Modules

| File | Lines | Contents |
|---|---|---|
| `src/calibrate.rs` | 326 | Response fingerprinting and soft-404 auto-calibration (`ffuf -ac` concept, MIT) |
| `src/config.rs` | 375 | Fuzzing configuration: polite limits, auto-stop thresholds, filters, and matchers |
| `src/dsstore.rs` | 287 | Safe Finder `.DS_Store` ("Bud1") parser extracting filenames only |
| `src/evidence.rs` | 241 | Short masked evidence builder (capped reads, secrets scrubbed) |
| `src/lib.rs` | 46 | Crate root and re-exports |
| `src/listing.rs` | 144 | Open directory listing detector (Apache, nginx, IIS, lighttpd, Python `http.server`) |
| `src/mutate.rs` | 186 | Filename variant generator from discovered documents (years ±1..2, versions `v1→v2`, numbering `001→002`) |
| `src/plan.rs` | 923 | Fuzzing task builder, per-module candidate generation, and request/time estimation |
| `src/rand.rs` | 62 | Dependency-free random token generator for calibration probes |
| `src/runner.rs` | 1,221 | Fuzzing executor: per-context calibration, concurrency/rate/budget limits, auto-stop, and event callbacks |
| `src/types.rs` | 293 | Result, hit, event, filter-reason, and stop-reason types |
| `src/wordlists.rs` | 529 | Built-in gzipped wordlists (SecLists, MIT) and registry for optional larger lists |

## Public API

Re-exports in `src/lib.rs`:

- `config::{AutoStop, Filters, FuzzConfig, StatusRange}`
- `plan::{estimate, Cms, ContentSpec, Estimate, FuzzTask, Template, VhostSpec, DOC_EXTENSIONS}`
- `runner::{EventFn, FuzzControl, Fuzzer, LOG_MODULE}`
- `types::{FilterReason, Filtered, FuzzEvent, FuzzHit, FuzzReport, FuzzStats, HitKind, Module, Risk, StopReason}`
- `wordlists::Wordlist`

Full API docs: `cargo doc -p foca-fuzz --no-deps --open`.

## Tests

`cargo test -p foca-fuzz`: 30 unit tests in `src/` + 18 integration tests in `tests/`:

| File | Tests |
|---|---|
| `tests/apidocs.rs` | 67 |
| `tests/behaviour.rs` | 377 |
| `tests/dsstore.rs` | 83 |
| `tests/fuzz_site.rs` | 201 |

## Pitfalls

- Requires `Access::Active`: rejected before hitting the network in `passive` and `std` profiles.
- Auto-stop on 429/403/5xx is intentional safety behavior; never add evasion workarounds.
- Files are never downloaded in full (`body_limit`), and all captured snippets are masked.
- In E2E tests, set `net.rps: 0` so the default 5 req/s global rate limit does not slow down scenarios.
