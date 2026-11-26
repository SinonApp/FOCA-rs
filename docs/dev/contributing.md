# Contributing to FOCA-rs

↑ [Developer Guide](README.md) · [Documentation](../README.md)

- [Branches and Commits](#branches-and-commits)
- [Working in Parallel](#working-in-parallel)
- [Rust Guidelines](#rust-guidelines)
- [UI Guidelines](#ui-guidelines)
- [Adding a Source](#adding-a-source)
- [Adding a Finding Rule](#adding-a-finding-rule)
- [Adding a Screen](#adding-a-screen)
- [Adding a Scan Stage](#adding-a-scan-stage)
- [Adding a Command or Snapshot Field](#adding-a-command-or-snapshot-field)
- [Documentation](#documentation)

## Branches and Commits

- Work happens on `develop`; `main` holds releases and is updated by merging `develop` at release time (tags `vX.Y.Z`, pre-releases like `v2.0.0-beta.1`). Both must build and pass `qa/run-all.sh`.
- Open pull requests against `develop`.
- Use Conventional Commits in English with a crate or layer scope:
  `feat(ports): add TCP port scan stage`, `fix(ui): ...`, `docs(adr): ...`. Mark breaking changes with `!` (`feat(core)!: ...`). The subject says what changed, in the imperative, without task or ticket codes.
- Keep commits focused and stage only your own files (`git add <paths>`, never `git add -A`, and never `stash`/`reset` someone else's work).

## Working in Parallel

- Agree on file ownership before several people change the same files; in a shared `Cargo.lock`, stage only your own dependency entries.
- `qa/run-all.sh --real` compiles `foca-cli` and serves `ui/` directly from the working tree: do not mutate `ui/` or crates while another run is in flight.
- Isolate your own E2E harness using `E2E_DIR=… E2E_PORT=… E2E_NET_PORT=… FOCA_BIN=…` so parallel runs do not kill each other's servers.
- When chaining tests and commit in a single command, commit only when the test exit code is `0`.

## Rust Guidelines

- `cargo fmt --all -- --check` and `cargo clippy --workspace --all-targets -- -D warnings` must pass with zero warnings.
- Use `thiserror` in library crates and `anyhow` in binaries (`foca-cli`). Never `panic!` or `unwrap()` on untrusted input.
- Every parser requires tests against reference corpus files in `tests/corpus/` as well as malformed/adversarial inputs.
- All network calls must go through `foca_net::NetClient` with the accurate `Access` class (enforcing scope, request logging, and rate limits).
- Port algorithms cleanly into Rust rather than bundling third-party binaries ([ADR-0011](../adr/0011-port-logic-not-binaries.md)); record attribution in `THIRD_PARTY.md`.
- Whenever you add, upgrade, or remove a Cargo or Gradle dependency, run `python qa/gen-licenses.py` and verify `python qa/gen-licenses.py --check` (GPL-3.0 compatibility + `foss` purity).

## UI Guidelines

- Follow [ui.md](ui.md) and [ui/README-UI.md](../../ui/README-UI.md).
- Run `npm run format:check`, `npm run lint`, and `node qa/data-invariants.mjs`.
- Put new user-facing strings into the per-area dictionaries `locales/{en,ru,uk}/ui/<area>.json` (`analysis`, `core`, `scan`, `settings`, `tools`, `workspace`; shared keys stay in `locales/<lang>/ui.json`). All three languages keep identical non-empty key sets. Access them via `F.t("key", params, "Russian fallback")`, never at script load time; `node qa/check-i18n.mjs` checks both.
- A user-visible text produced by the core needs its Russian template in `locales/<lang>/ui/core.json`, so the UI can show it in the current language (`F.coreMsg`).
- Before committing UI changes, run `qa/shoot.sh` on affected routes: require `errors: []` and `overflow 0` across 360 / 393 / 412 px × font scale 1 / 1.3 / 2 × light and dark themes.

## Adding a Source

1. **Source implementation**, `crates/foca-search/src/sources/`: document URL sources go in `urls.rs` (or a dedicated module implementing `DocumentSource` from `source.rs`); subdomain sources go in `subdomains.rs` (`HOST_SOURCES`); WebView search engines go in `render_engines.rs` and connect to `dorkpool.rs`. Export in `sources/mod.rs` (`by_ids`). Use `Access::Passive` unless the source contacts the target directly.
2. **Tests**: add an offline fixture under `crates/foca-search/tests/fixtures/` and a test in `tests/sources.rs` (or `tests/render_sources.rs`); optionally add an `#[ignore]` live test in `tests/live.rs`.
3. **Engine registration**, `crates/foca-engine/src/scan/sources.rs`: add an entry to `SOURCES` (id, name, optional key service, optional flag, touches-target flag), add the ID to `SEARCH_SOURCES` and `DOC_SOURCE_IDS` / `HOST_SOURCE_IDS`; for WebView engines update `WEB_ENGINES`, and for manual CAPTCHA retries update `RETRY_SOURCES`. Verify with `crates/foca-engine/tests/scan/rescan_sources.rs`.
4. **UI**, update `ui/screens/sources.js` (`SRC`: id, name, group, access, description), demo `SOURCES` in `ui/js/demo-backend.js`, and if an API key is used, `ui/screens/settings.js` (API Keys).
5. **Test harness**: if needed for E2E, add a mock response in `foca testnet` (`crates/foca-cli/src/testnet.rs`).
6. **Docs**: add a row to [docs/user/sources.md](../user/sources.md), record service terms in `THIRD_PARTY.md`, update `CHANGELOG.md`, and update [docs/API.md](../API.md) for any new fields.

## Adding a Finding Rule

1. **Emission**: document findings in `crates/foca-analysis/src/assess/findings.rs` (`Draft::new("<rule-id>", key, title, sev)` with category, MITRE mapping, and recommendation) or `forensic.rs`; network/port/fuzz findings in `crates/foca-engine/src/scan/mod.rs`, `scan/ports.rs`, `scan/fuzz.rs`; recon findings in `crates/foca-recon/src/` (`ReconFinding`, `recon.*` IDs).
2. **Stable IDs**: finding IDs are hashes of rule + object key, never change an existing key unnecessarily or user triage state will be lost.
3. **Localization & playbooks**: add templates to `locales/{en,ru,uk}/findings.json` (loaded by `crates/foca-report/src/ftext.rs`) so English, Ukrainian, and Russian reports translate cleanly; add a standards mapping in `crates/foca-analysis/signatures/standards.toml` and remediation steps in `locales/{en,ru,uk}/playbooks.json` when applicable.
4. **Tests**: add a rule unit test in the owning crate, and refresh golden reports if intentionally changed (`UPDATE_GOLDEN=1 cargo test -p foca-report --test report`).
5. **Demo data**: update `ui/js/demo-backend.js` if the rule should appear in screenshot QA.

## Adding a Screen

1. Create `ui/screens/<name>.js` (plus `<name>.css` with a screen-specific class prefix) and include both in `ui/index.html`.
2. Register the route via `F.route("/p/<path>", { title, sub, tab, render(params), mount(page, params), back, nav })`.
3. Read data exclusively through `F.api.*` and `F.sel.*`; wrap lists in `F.withStates` (empty / loading / error).
4. Add the route to `qa/routes.txt`; add a scenario in `qa/scenarios/<name>/steps.mjs` and wire it into `qa/run-all.sh`.
5. Add localized strings to `locales/{en,ru,uk}/ui/<area>.json`, offline help entries to `locales/{en,ru,uk}/help.json`, and update the route map in [ui.md](ui.md).

## Adding a Scan Stage

Stage IDs are duplicated across the stack: update all 8 locations in one commit:

1. `crates/foca-engine/src/scan/sources.rs` - `STAGES`; pipeline dispatch in `scan/mod.rs` (match by stage ID, never index);
2. `crates/foca-engine/src/analysis/rules.rs` - `STAGE_IDS`;
3. `ui/js/sel.js` - `STAGE_IDS`;
4. `ui/screens/scan.js` - `STAGES`;
5. `ui/js/demo-backend.js` - `STAGES`;
6. `crates/foca-engine/tests/scan/stages.rs` and `tests/scan/lifecycle.rs`: stage list constants;
7. E2E-09 (`qa/scenarios/real-core/09-kill-recover.mjs`) checks `progress > 100/<stage count>`;
8. Documentation: [architecture.md](architecture.md#scan-stages), [docs/user/scan-profiles.md](../user/scan-profiles.md), and [docs/API.md](../API.md).

Because `resume_from` matches stages by ID, inserting a stage in the middle is safe.

## Adding a Command or Snapshot Field

- Define the DTO in `crates/foca-core/src/api.rs` (exact match to [docs/API.md](../API.md)) and document it in [docs/API.md](../API.md).
- Any new `scan_start` parameter must also be added to the parameter allow-list in `ui/screens/scan.js`, otherwise it will be silently dropped before reaching the engine.
- Implement the command in `ui/js/demo-backend.js` too (commands the demo lacks are not contract-checked) and regenerate `crates/foca-engine/tests/fixtures/demo_shapes.json` (`node crates/foca-engine/tests/dump_demo_shapes.mjs`); bump `GEN_VERSION` in `demo-backend.js` when snapshot shapes change.

## Documentation

- Documentation layout: [docs/README.md](../README.md). Every page starts with an `↑` breadcrumb line and a table of contents, using relative links only.
- Verify links and anchors: `python3 qa/check-docs-links.py` (included in `qa/run-all.sh static`): must report `0` broken links.
- Record significant architectural decisions as a new ADR in `docs/adr/` (see [ADR index](../adr/README.md)).
- User-facing changes also update the in-app help (`locales/{en,ru,uk}/help.json`, keep the three languages in step), the user guide in `docs/user/` (and `docs/ru/user/`), and `CHANGELOG.md`.
