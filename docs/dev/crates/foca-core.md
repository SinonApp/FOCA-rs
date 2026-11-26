# foca-core

↑ [Core Crates](README.md) · [Developer Guide](../README.md) · [Architecture](../architecture.md)

- [Purpose](#purpose)
- [Modules](#modules)
- [Public API](#public-api)
- [Tests](#tests)
- [Pitfalls](#pitfalls)

Path: `crates/foca-core/` · `src/` lines: 3,172 · tests: 26 · depends on:,

## Purpose

`foca-core` defines the shared data model of FOCA-rs: projects, targets and scope rules, documents and their metadata/forensics records, entities, findings, scan events, contract DTOs, unified localization language (`foca_core::Lang`), and an injectable time source (`Clock`).

The crate has zero Android, UI, or network dependencies and is shared across every other crate, the Android bridge, and the CLI.

### Unified `foca_core::Lang` (`src/lang.rs`)

`foca_core::Lang` unifies language handling across UI bundles (`foca-engine::i18n`), reports and finding translations (`foca-report`), remediation playbooks (`foca-analysis::playbooks`), and alert notifications (`foca-net::notify`), replacing the three duplicated language enums from 1.x:

- Variants: `Lang::En` (`#[default]`), `Lang::Ru`, and `Lang::Uk` (with `#[serde(alias = "ua")]`).
- `Lang::parse(s)` parses explicit codes (`en`, `ru`, `uk`, `ua`, and BCP 47 tags like `uk-UA`, `ru_RU`, `en-GB`), returning `None` for `"auto"` or unsupported locales.
- `Lang::from_bcp47(tag)` normalizes device BCP 47 tags: `uk*`/`ua*` → `Lang::Uk`, `ru*` → `Lang::Ru`, everything else → `Lang::En`.
- `Lang::resolve_setting(setting, device_locale)` resolves user settings (`"auto"` vs explicit language) against `device_info.locale` / `navigator.language`.
- `Lang::code()` returns canonical BCP 47 codes (`"en"` / `"ru"` / `"uk"`); `Lang::ui()` returns uppercase UI badges (`"EN"` / `"RU"` / `"UA"`).

## Modules

| File | Lines | Contents |
|---|---|---|
| `src/api.rs` | 722 | Project snapshot DTOs matching `docs/API.md` verbatim (read directly into `F.db` by the UI) |
| `src/b64.rs` | 76 | Minimal padded base64 (RFC 4648) for byte serialization without extra dependencies |
| `src/clock.rs` | 66 | Injectable `Clock` trait (`SystemClock`, `ManualClock`) for deterministic core tests |
| `src/forensics.rs` | 243 | Document forensics records attached to `Metadata` (XMP history/IDs, PDF revisions, bad redactions, hidden content, digital signatures & Ukrainian QES/KEP fields) |
| `src/lang.rs` | 153 | Unified interface, report, playbook, and alert language (`Lang`: `en` / `ru` / `uk`) |
| `src/lib.rs` | 25 | Crate root and re-exports |
| `src/metadata.rs` | 506 | Single-document extraction result (`Metadata`, `DocFormat`) returned by `foca-meta::extract` |
| `src/model.rs` | 456 | Core domain model: project, document, entities, findings, severities, statuses, scan events |
| `src/scope.rs` | 272 | Project scope enforcement (`I-23`): determines which hosts/IPs target-touching and active modules may contact |
| `src/severity.rs` | 36 | Finding severity shared by findings, forensics records and API views (wire names `crit`, `high`, `warn`, `low`, `info`; `critical` and `medium` accepted on input) |
| `src/target.rs` | 617 | Parsing of project target strings (`Domain`, wildcard `*.Domain`, URL, IP, CIDR, IP range, etc.) |

## Public API

Re-exports in `src/lib.rs`:

- `clock::{Clock, ManualClock, SystemClock}`
- `forensics::*`
- `lang::Lang`
- `metadata::*`
- `model::*`
- `scope::{LineError, Scope, ScopeDenied}`
- `target::{normalize_domain, Target, TargetError}`

Conversions: `Scope::from(&api::ScopeDto)` builds the checkable scope (unparsable targets are dropped); `FindingStatus` implements `FromStr` for the contract strings (`new|confirmed|false|accepted|fixed`, plus the `false_positive` alias).

Full API docs: `cargo doc -p foca-core --no-deps --open`.

## Tests

`cargo test -p foca-core`: 25 unit tests in `src/`.

## Pitfalls

- `api.rs` matches [docs/API.md](../../API.md) verbatim: whenever you add a snapshot field, update `api.rs`, `docs/API.md`, `ui/js/demo-backend.js`, and regenerate `crates/foca-engine/tests/fixtures/demo_shapes.json` (`node crates/foca-engine/tests/dump_demo_shapes.mjs`), or `contract_shape.rs` will fail.
- Core logic must read wall-clock time only via `Clock` so tests can inject `ManualClock`.
- Non-network identifiers (organizations, person names, e-mails, ASNs) never grant host-access permissions in `scope.rs`; the UI launch wizard restricts user input to honest network targets (`Domain`, `*.Domain`, URL, IP, CIDR, IP range).
