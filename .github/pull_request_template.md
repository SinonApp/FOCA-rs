## Summary

<!-- What changes and why. Link the issue: Fixes #123 -->

## Checklist

- [ ] Tests pass: `cargo test --workspace --exclude foca-rs`, plus `cargo fmt --all -- --check` and `cargo clippy --workspace --all-targets -- -D warnings` for Rust changes
- [ ] UI changes: `npm run format:check`, `npm run lint`, `bash qa/run-all.sh` (or `qa/shoot.sh` on the affected routes: no errors, no overflow)
- [ ] New or changed UI and report texts exist in all three languages: `locales/en`, `locales/ru`, `locales/uk` (`node qa/check-i18n.mjs`)
- [ ] Dependencies, bundled data or fonts changed: licenses regenerated with `python3 qa/gen-licenses.py` and the diff reviewed
- [ ] Docs and `CHANGELOG.md` updated if users will notice; `python3 qa/check-docs-links.py` passes
- [ ] No secrets, client names or real scan results in code, tests, screenshots or logs
