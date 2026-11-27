# Contributing to FOCA-rs

Thanks for helping. This page is the short version; the full workflow and step-by-step guides (adding a source,
finding rule, screen, scan stage or command) are in [docs/dev/contributing.md](docs/dev/contributing.md).

## Reporting bugs and ideas

- Bugs and feature requests: [GitHub issues](https://github.com/SinonApp/FOCA-rs/issues/new/choose). In the app,
  **Settings → About → Report a problem** saves a logs ZIP to `Download/FOCA-rs` and opens the issue form.
- Security problems: privately, see [SECURITY.md](SECURITY.md).
- Never attach documents or reports from real targets. Reproduce with synthetic files or the built-in reference case.

## Branches and commits

- All work happens on `main`; releases are tags on `main` (`vX.Y.Z`, pre-releases like `v2.0.0-beta.4`). Open pull requests against `main`.
- [Conventional Commits](https://www.conventionalcommits.org/) in English, scoped to the crate or layer:
  `feat(engine): …`, `fix(ui): …`, `docs(user): …`, `refactor(foca-net): …`. Imperative subject, no task codes.
- One logical change per commit. Stage your own paths (`git add <paths>`), not `git add -A`.

## Build

Prerequisites and Android builds are in [docs/dev/build.md](docs/dev/build.md). In short:

```sh
cargo test --workspace --exclude foca-rs     # Rust core, no Android SDK needed
npm ci                                       # Prettier, ESLint, Tauri CLI
bash qa/android-build.sh apk                 # unsigned arm64 foss + play APKs (Android SDK, NDK 29, JDK 21)
```

## Checks before a pull request

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --exclude foca-rs --no-fail-fast
npm run format:check && npm run lint
node qa/data-invariants.mjs
node qa/check-i18n.mjs
python3 qa/check-docs-links.py
python3 qa/gen-licenses.py --check            # after any dependency, asset or data change: run without --check first
qa/run-all.sh                                 # full UI suite on the demo backend (~15 min)
```

For UI changes, also run `qa/shoot.sh` on the routes you touched and check `errors: []` and no overflow at 360 and
393 px, font scale 1 and 2. Details: [docs/testing/README.md](docs/testing/README.md).

## Code rules

- Rust: no `panic!` or `unwrap()` on untrusted input; all network traffic goes through `foca_net::NetClient` with the
  right `Access` class, so scope, rate limits and the request log apply.
- Port algorithms to Rust instead of bundling third-party binaries
  ([ADR-0011](docs/adr/0011-port-logic-not-binaries.md)) and credit them in [THIRD_PARTY.md](THIRD_PARTY.md).
- Keep `src/main` and `src/foss` free of proprietary dependencies; Google ML Kit belongs to the `play` flavor only.
- UI strings go to `locales/{en,ru,uk}/ui/<area>.json`, help to `locales/{en,ru,uk}/help.json`; keep all three
  languages in step.
- User-facing changes update the help, the user guide (`docs/user/`, `docs/ru/user/`) and `CHANGELOG.md`.

## License

FOCA-rs is GPL-3.0. By contributing you agree that your contribution is licensed under the same terms.
