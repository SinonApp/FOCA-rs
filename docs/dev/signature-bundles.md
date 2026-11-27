# Signature bundles and the update feed

↑ [Developer Guide](README.md)

The analysis matches documents against data compiled into the app from
`crates/foca-analysis/signatures/`:

| File | What the app loads |
|---|---|
| `kev.tsv.gz` | CISA Known Exploited Vulnerabilities snapshot. The header (`# cisa-kev catalog=… released=… total=… kept=…`) gives the CISA catalog size; only the `kept` entries whose product maps to a group in `kev_products.toml` are stored and used for matching. There is no NVD data. Refresh with `update_kev.py`. |
| `kev_products.toml` | Product groups that link detected software names to KEV entries. |
| `software.toml` | Software (`[[software]]`) and OS (`[[os]]`) detection signatures. |
| `secrets.toml` | Built-in secret detection rules (`[[rule]]`). |
| `standards.toml` | Finding rule to standards mapping (OWASP Top 10:2025, MITRE ATT&CK v20, CWE with the 2025 Top 25 flag, NIST SP 800-53 Rev. 5 = НД ТЗІ 3.6-006-24, ISO/IEC 27001:2022, OWASP WSTG v4.2, GDPR and Law 2297-VI, legacy НД ТЗІ 2.5-004-99 / 3.7-003-05 for КСЗІ). |

`signatures_status` reports these numbers as loaded at runtime (`crates/foca-engine/src/services/sigbundle.rs`):
`kev.used` of `kev.total`, `kev.released` and `kev.age_days` (stale after 30 days), software and OS
signature counts, secret rules (built-in plus bundle rules) and the standards mapping
(`std_map.rules`, `std_map.refs`, `std_map.frameworks` labelled from the data). The numbers a bundle
claims in its own `counts` field are never shown.

## Bundle format (`foca-sig-bundle/v1`)

A bundle is one JSON object:

```json
{
  "schema": "foca-sig-bundle/v1",
  "version": "2026.11.27",
  "released_at": "2026-11-27",
  "counts": { "cpe": 73, "cve": 930, "secrets": 24, "standards": 438 },
  "kev_catalog": { "version": "2026.11.27", "released": "2026-11-27", "total": 1801 },
  "kev_additions": [{ "cve": "CVE-…", "product_key": "php", "vendor": "PHP", "product": "PHP",
                      "date_added": "2026-11-26", "ransomware": false, "name": "…", "fixed_in": null }],
  "cpe_additions": [],
  "secret_additions": [{ "id": "…", "title": "…", "pattern": "…" }],
  "sha256": "<hex of the canonical payload>",
  "signature_ed25519": "<hex, 64 bytes>"
}
```

- `sha256` and `signature_ed25519` cover the canonical payload: the compact JSON of `schema`,
  `version`, `released_at`, `counts`, `kev_catalog` (omitted when absent), `kev_additions`,
  `cpe_additions`, `secret_additions` in that order (`sigbundle::canonical_payload`).
- The signature is checked against the Ed25519 public key compiled into the app
  (`OFFICIAL_ED25519_PUBKEY`). A bundle signed with any other key is rejected with `bad_signature`.
- KEV additions extend the built-in catalog (deduplicated by CVE). Secret additions are compiled by
  the rules engine before installation and merged into the project rule set.
- `cpe_additions` are stored but not used for matching (a CPE prefix has no detection pattern), so
  the status does not count them.
- Installation is atomic: `<data>/signatures/current.json`, the replaced bundle moves to
  `previous.json` for `signatures_rollback`.

## Update feed

`signatures_update {}` downloads `sigbundle::DEFAULT_FEED_URL`:

```
https://github.com/SinonApp/FOCA-rs/releases/download/signatures/signatures.bundle
```

It is the `signatures.bundle` asset of a rolling GitHub release with the tag `signatures`. A rolling
tag is used instead of `releases/latest/download/…` because GitHub skips pre-releases there, and app
builds are published as pre-releases.

| Feed answer | `last_check.outcome` | Effect |
|---|---|---|
| HTTP 404 / 410 | `no_update` | Nothing is published yet. The active database stays. |
| Verified bundle, version not newer than the active one | `up_to_date` | Nothing changes. |
| Verified newer bundle | `installed` | The bundle becomes `current.json`. |
| Network error, bad JSON, bad signature | `failed` | The command returns the coded error (`net`, `bad_args`, `bad_signature`, with `message_msg`); the active database stays. |

Every check is stored in `<data>/signatures/last_check.json` and returned as `last_check` by
`signatures_status`, so the screen shows when the last check ran and what it found. Versions are
compared by their numeric parts (`2026.11.27` > `2026.11.20`).

## Publishing a bundle (maintainers)

The signing key is not in the repository. Keep the 32-byte Ed25519 seed offline as a file with 64
hex characters (mode 600).

1. Refresh the data and commit it: `python3 crates/foca-analysis/signatures/update_kev.py`, then the
   usual tests (`cargo test -p foca-analysis`).
2. Build and sign the bundle from that tree:

   ```sh
   scripts/build-sig-bundle.sh /path/to/sig-seed.hex dist/signatures.bundle
   ```

   The script runs `cargo run -p foca-engine --release --example sig_bundle -- build …`. The bundle
   holds every kept KEV entry of `kev.tsv.gz` plus the snapshot header (`kev_catalog`); the version
   defaults to the KEV catalog version (`--version` overrides it). Built-in secret rules are not
   copied into the bundle: they already ship with the app. The tool refuses a key whose public key
   differs from the one built into the app (`--allow-foreign-key` is for test bundles only).
3. Check it: `cargo run -p foca-engine --example sig_bundle -- verify dist/signatures.bundle`.
4. Upload `signatures.bundle` to the `signatures` release (create it once as a normal release, not a
   pre-release; replace the asset on every update), for example
   `gh release upload signatures dist/signatures.bundle --clobber`.

### New signing key

The key was rotated in 2.0.0-beta.3: the earlier private key was not available, so beta.3 ships a
new built-in public key. Builds up to 2.0.0-beta.2 reject bundles signed with the new key with
`bad_signature` and keep their built-in databases.

If the private key for the built-in public key is lost, generate a new one and ship it with the next
app release (older builds keep rejecting bundles signed with the new key):

```sh
cargo run -p foca-engine --example sig_bundle -- gen-key /path/to/sig-seed.hex
```

The tool prints the public key bytes to paste into `OFFICIAL_ED25519_PUBKEY` in
`crates/foca-engine/src/services/sigbundle.rs`.

## Tests

- `cargo test -p foca-engine --lib sigbundle`: install and rollback with a test key, tampered and
  foreign signatures, counts from the loaded tables, KEV age, feed outcomes (`no_update` on 404,
  `installed` once, `up_to_date`, recorded failures) and a bundle built from the repository data.
- `cargo test -p foca-engine --test ops signatures`: the command against a local feed server (404,
  foreign signature, refused URL) including `message_msg` codes.
- `crates/foca-engine/tests/contract_shape.rs`: demo backend shapes and the demo copy of the numbers
  (`demo_signature_numbers_match_core_status`).
- `qa/scenarios/signatures-screen/steps.mjs`: the screen at 393 px and 360 px with font scale 2.
