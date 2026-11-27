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
| `secrets_gitleaks.toml` | gitleaks default rules (MIT) converted to the `secrets.toml` format with allowlists and stopwords; our rules run first and win on the same value. |
| `kev_enrich.tsv.gz` | FIRST EPSS score and percentile plus CISA Vulnrichment CVSS, CWE and SSVC for every kept KEV entry. |
| `sources.lock.json` | Pinned upstream version (commit, tag or snapshot date), input SHA-256, license, attribution text, output hashes and counts (including skipped items) of every ingested source. |

Upstream tables that live next to the module that uses them:

| Table | Source (license) | Used by |
|---|---|---|
| `crates/foca-recon/data/webappanalyzer.json.gz` | enthec/webappanalyzer (GPL-3.0) | `foca-recon::tech`: headers, cookies, meta, HTML, script and URL rules, `implies`/`requires`/`excludes`, CPE; merged by name with the hand rules in `tech.json` (hand fields win). |
| `crates/foca-net/data/saas_dns.json` | webappanalyzer DNS rules (GPL-3.0) | `foca-net::intel::saas`: services the hand tables do not know. |
| `crates/foca-recon/data/endoflife.tsv.gz` | endoflife.date (MIT) | `foca-recon::tech`: release cycles past end of life at the snapshot date. |
| `crates/foca-recon/data/retire.json.gz` | Retire.js (Apache-2.0) | `foca-recon::retire`: JS library versions and vulnerable ranges (`recon.vuln_js_lib`). |
| `crates/foca-net/data/recog.tsv.gz` | Rapid7 Recog (BSD-2-Clause) | `foca-net::recog`: banner product, version and OS in the port scan. |
| `crates/foca-recon/data/favicons_md5.tsv` | Rapid7 Recog (BSD-2-Clause) | `foca-recon::favicon`: product of a favicon by MD5. |
| `crates/foca-net/data/public_suffix_list.dat.gz` | Public Suffix List (MPL-2.0, unmodified) | `foca-net::dns::psl`: registrable domains for CT and PTR grouping. |
| `crates/foca-net/data/takeover.json` | can-i-take-over-xyz (CC-BY-4.0, fields reduced) | `foca-net::takeover`: dangling CNAME providers and claimability. |

## Ingest scripts

`crates/foca-analysis/signatures/tools/update_<source>.py` (Python 3.11+, PyYAML for
endoflife.date) download one source at the version pinned in the script (`COMMIT`, `TAG`,
`EPSS_DATE`), check the SHA-256 of every input against `sources.lock.json`, convert, and record the
outcome in the lock file. A changed upstream file stops the script; `--repin` accepts new hashes
after a deliberate version bump. Downloads are cached in `$FOCA_SIG_CACHE` (default
`~/.cache/foca-sig`). Every regex is compiled with the Rust `regex` crate through
`cargo run -p foca-analysis --example regex_check`; patterns it rejects (lookarounds, backreferences,
over the size limit) are skipped and counted in the lock file. Order: `update_webappanalyzer.py`
before `update_endoflife.py` (the join reads its output), `update_kev.py` before
`update_kev_enrich.py`. Then run `python3 qa/gen-licenses.py` and the tests.

Not ingested: original Wappalyzer (proprietary), nmap-service-probes (NPSL), trufflehog (AGPL),
secrets-patterns-db (mixed license), can-i-take-over-dns (no license), nuclei takeover templates
(no CNAME suffixes in the templates).

`signatures_status` reports these numbers as loaded at runtime (`crates/foca-engine/src/services/sigbundle.rs`):
`kev.used` of `kev.total`, `kev.released` and `kev.age_days` (stale after 30 days), software and OS
signature counts, secret rules (built-in plus gitleaks plus bundle rules), the standards mapping
(`std_map.rules`, `std_map.refs`, `std_map.frameworks` labelled from the data) and `tables`: one
entry per ingested table with the records the module really loaded, the upstream pin, the license and
`source` (`builtin` or `bundle`). The numbers a bundle claims in its own `counts` field are never
shown.

## Bundle format (`foca-sig-bundle/v2`)

A bundle is one JSON object:

```json
{
  "schema": "foca-sig-bundle/v2",
  "version": "2026.11.27",
  "released_at": "2026-11-27",
  "counts": { "cpe": 73, "cve": 930, "secrets": 24, "standards": 438 },
  "kev_catalog": { "version": "2026.11.27", "released": "2026-11-27", "total": 1801 },
  "kev_additions": [{ "cve": "CVE-…", "product_key": "php", "vendor": "PHP", "product": "PHP",
                      "date_added": "2026-11-26", "ransomware": false, "name": "…", "fixed_in": null }],
  "cpe_additions": [],
  "secret_additions": [{ "id": "…", "title": "…", "pattern": "…" }],
  "tables": { "psl": { "version": "88b076a1fb2a", "sha256": "<hex>", "data": "<base64>" } },
  "sha256": "<hex of the canonical payload>",
  "signature_ed25519": "<hex, 64 bytes>"
}
```

- `sha256` and `signature_ed25519` cover the canonical payload: the compact JSON of `schema`,
  `version`, `released_at`, `counts`, `kev_catalog` (omitted when absent), `kev_additions`,
  `cpe_additions`, `secret_additions`, `tables` (omitted when empty) in that order
  (`sigbundle::canonical_payload`).
- `tables` (v2 only) maps a table id of `sigbundle::TABLES` (`webappanalyzer`, `endoflife`,
  `saas_dns`, `gitleaks`, `kev_enrich`, `retire`, `recog`, `favicons_md5`, `psl`, `takeover`) to
  the table file exactly as committed in the repository (gzip or text), base64-encoded, with its
  SHA-256 and upstream pin. Before installation every table is decoded, its SHA-256 checked and
  parsed by its module; an unknown id, a hash mismatch or a parse error rejects the whole bundle.
  After installation (and at engine start) the tables replace the built-in ones in the running
  modules; a table the bundle does not carry keeps the built-in data, and a rollback to the
  built-in database restores all built-in tables.
- `foca-sig-bundle/v1` bundles stay readable: they carry no `tables`, their canonical payload is
  unchanged, so their signatures still verify. A v1 bundle with `tables` is rejected.
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

1. Refresh the data and commit it: `python3 crates/foca-analysis/signatures/update_kev.py` and the
   ingest scripts whose pins you bumped (see [Ingest scripts](#ingest-scripts)), then
   `python3 qa/gen-licenses.py` and the usual tests (`cargo test -p foca-analysis -p foca-recon -p foca-net`).
2. Build and sign the bundle from that tree:

   ```sh
   scripts/build-sig-bundle.sh /path/to/sig-seed.hex dist/signatures.bundle
   ```

   The script runs `cargo run -p foca-engine --release --example sig_bundle -- build …`. The bundle
   holds every kept KEV entry of `kev.tsv.gz` plus the snapshot header (`kev_catalog`) and all data
   tables of `sigbundle::TABLES` (about 0.7 MB of base64 in total); the version
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
  `installed` once, `up_to_date`, recorded failures), a bundle built from the repository data, v2
  tables (round trip, tampered, unknown and unparsable tables) and v1 compatibility.
- Per-table unit tests in their modules: `foca-recon` `tech` (merge, version templates, end-of-life
  cycles, startup time), `retire`, `favicon`; `foca-net` `recog`, `psl`, `takeover`, `saas`;
  `foca-analysis` `secrets` (gitleaks rules and allowlists) and `kev` (enrichment).
- `cargo test -p foca-engine --test ops signatures`: the command against a local feed server (404,
  foreign signature, refused URL) including `message_msg` codes.
- `crates/foca-engine/tests/contract_shape.rs`: demo backend shapes and the demo copy of the numbers
  (`demo_signature_numbers_match_core_status`).
- `qa/scenarios/signatures-screen/steps.mjs`: the screen at 393 px and 360 px with font scale 2.
