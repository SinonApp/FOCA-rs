# Signature bundles and the update feed

↑ [Developer Guide](README.md)

The analysis matches documents against data compiled into the app from
`crates/foca-analysis/signatures/`:

| File | What the app loads |
|---|---|
| `kev.tsv.gz` | CISA Known Exploited Vulnerabilities snapshot. The header (`# cisa-kev catalog=… released=… total=… kept=…`) gives the CISA catalog size; only the `kept` entries whose product maps to a group in `kev_products.toml` are stored and used for matching. There is no NVD data. Refresh with `update_kev.py`. |
| `kev_products.toml` | Product groups that link detected software names to KEV entries. |
| `software.toml` | Software (`[[software]]`) and OS (`[[os]]`) detection signatures, with the NVD `cpe` keys of each product and `side` (`server` for generators that run on the site's servers such as wkhtmltopdf, TCPDF, iText, Ghostscript, Crystal Reports, 1C and SSRS; `workstation` for desktop software such as Office, Acrobat and LibreOffice). |
| `nvd_cve.tsv.gz` | Offline CVE table from the NVD CVE JSON 2.0 feeds (public domain): CVSS, CWE, KEV flag, EPSS and affected version ranges of every CVE that names a detectable product (see [Offline CVE table](#offline-cve-table-nvd)). Refresh with `tools/update_nvd.py`. |
| `secrets.toml` | Built-in secret detection rules (`[[rule]]`). |
| `standards.toml` | Finding rule to standards mapping (OWASP Top 10:2025, MITRE ATT&CK v20, CWE with the 2025 Top 25 flag, NIST SP 800-53 Rev. 5 = НД ТЗІ 3.6-006-24, ISO/IEC 27001:2022, OWASP WSTG v4.2, GDPR and Law 2297-VI, legacy НД ТЗІ 2.5-004-99 / 3.7-003-05 for КСЗІ). |
| `secrets_gitleaks.toml` | gitleaks default rules (MIT) converted to the `secrets.toml` format with allowlists and stopwords; our rules run first and win on the same value. |
| `kev_enrich.tsv.gz` | FIRST EPSS score and percentile plus CISA Vulnrichment CVSS, CWE and SSVC for every kept KEV entry. |
| `sources.lock.json` | Pinned upstream version (commit, tag or snapshot date), input SHA-256, license, attribution text, output hashes and counts (including skipped items) of every ingested source. |

Upstream tables that live next to the module that uses them:

| Table | Source (license) | Used by |
|---|---|---|
| `crates/foca-recon/data/webappanalyzer.json.gz` | enthec/webappanalyzer (GPL-3.0) | `foca-recon::tech`: headers, cookies, meta, HTML, script and URL rules, `implies`/`requires`/`excludes`, CPE; merged by name with the hand rules in `tech.json` (hand fields win). Since 2.0.0-beta.4 also JS file content (`sc`), text (`t`), CSS (`y`), TLS issuer (`ci`), robots (`ro`), browser-only JS globals (`g`), DOM (`d`), request hosts (`q`) and WordPress slugs (`ps`): extra keys that older loaders ignore, so the same table id stays readable by 2.0.0-beta.3 (test `table_still_parses_with_the_beta3_loader`). |
| `crates/foca-net/data/saas_dns.json` | webappanalyzer DNS rules (GPL-3.0) | `foca-net::intel::saas`: services the hand tables do not know. |
| `crates/foca-recon/data/endoflife.tsv.gz` | endoflife.date (MIT) | `foca-recon::tech`: release cycles past end of life at the snapshot date. |
| `crates/foca-recon/data/retire.json.gz` | Retire.js (Apache-2.0) | `foca-recon::retire`: JS library versions and vulnerable ranges (`recon.vuln_js_lib`). |
| `crates/foca-net/data/recog.tsv.gz` | Rapid7 Recog (BSD-2-Clause) | `foca-net::recog`: banner product, version and OS in the port scan. |
| `crates/foca-recon/data/favicons_md5.tsv` | Rapid7 Recog (BSD-2-Clause) | `foca-recon::favicon`: product of a favicon by MD5. |
| `crates/foca-net/data/public_suffix_list.dat.gz` | Public Suffix List (MPL-2.0, unmodified) | `foca-net::dns::psl`: registrable domains for CT and PTR grouping. |
| `crates/foca-net/data/takeover.json` | can-i-take-over-xyz (CC-BY-4.0, fields reduced) | `foca-net::takeover`: dangling CNAME providers, claimability and the HTTP body fingerprints matched by the network stage. |

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
`update_kev_enrich.py`, `update_webappanalyzer.py` and `update_kev.py` before `update_nvd.py`.
Then run `python3 qa/gen-licenses.py` and the tests.

Not ingested: original Wappalyzer (proprietary), nmap-service-probes (NPSL), trufflehog (AGPL),
secrets-patterns-db (mixed license), can-i-take-over-dns (no license), nuclei takeover templates
(no CNAME suffixes in the templates).

`signatures_status` reports these numbers as loaded at runtime (`crates/foca-engine/src/services/sigbundle.rs`):
`kev.used` of `kev.total`, `kev.released` and `kev.age_days` (stale after 30 days), software and OS
signature counts, secret rules (built-in plus gitleaks plus bundle rules), the standards mapping
(`std_map.rules`, `std_map.refs`, `std_map.frameworks` labelled from the data) and `tables`: one
entry per ingested table with the records the module really loaded, the upstream pin, the license and
`source` (`builtin` or `bundle`). The numbers a bundle claims in its own `counts` field are never
shown. `nvd` gives the snapshot date and CVE counts per group of the CVE table in use.

## Offline CVE table (NVD)

`tools/update_nvd.py` reads the yearly NVD CVE JSON 2.0 feeds
(`https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-<year>.json.gz`, 2002 to the current year) one
CVE at a time (about 330 MB of RAM, the feeds take about 250 MB on disk in `$FOCA_NVD_CACHE` and are
deleted after a run unless `--keep-cache` is given). It keeps a CVE when a `vulnerable=true` CPE
match of its configurations names:

- a CPE of a webappanalyzer technology,
- a `cpe` key of a `software.toml` signature (document software and OS),
- any CPE whose `target_sw` is `wordpress`, `drupal` or `joomla` (plugins, themes, modules; keyed
  `vendor:product@<cms>` so the app also finds them by plugin slug),
- a CPE identifier of an endoflife.date product.

Per CVE it stores the id, the published year, one CVSS base score and its version (v3.1, then v4.0,
v3.0, v2; NVD primary scores first), CWE numbers, the KEV flag from `kev.tsv.gz` and the EPSS score
of the pinned FIRST file; per product the affected ranges (`*`, `=version`, `[a,b)`, `(a,b]`, open
sides allowed). There is no size cut: every CVSS level, year and plugin stays. The snapshot date
and the SHA-256 of every yearly feed are pinned in `sources.lock.json` (`nvd`); a new snapshot needs
`--repin`. Unit tests on a fixture feed: `python3 crates/foca-analysis/signatures/tools/test_update_nvd.py`.

Snapshot 2026-11-27: 108019 CVEs, 9248 products, 547884 ranges, 1.28 MB gzip (9.3 MB as text).
CVEs per group (one CVE can be in several): site technologies 71087, plugins 17245, document
software 30418, OS 24315; 609 are in KEV.

The matcher (`foca_analysis::cve`) parses the table lazily on first use (about 0.4 s in a debug
build, resident size close to the 9.3 MB text) and indexes it by product; a lookup takes a few
milliseconds. Input: CPE `vendor:product` keys and/or a plugin slug with its CMS, plus the version.
Output (`CveSummary`): matched CVEs sorted by KEV, CVSS and EPSS, counts by severity, max CVSS,
KEV count, max EPSS, and the number of known CVEs of the product. Approximations:

- versions compare component by component: numbers numerically, `alpha`/`beta`/`rc`/`dev` before
  the release, a trailing letter (`1.0.2k`) after it, build metadata after `+` ignored, a leading
  `v` or `m` (`m120`) dropped, the first token starting with a digit is the version
  (`Apache/2.4.58 (Unix)` gives `2.4.58`);
- an NVD entry without version limits (`*`, `-`) matches every version only when no queried key of
  the CVE (`apple:macos` and `apple:mac_os_x` count as one product) has a range or an exact version;
  such CVEs are listed as "range not specified in NVD" (`unbounded`) and never raise the severity,
  the KEV count or the CVSS maximum; an exact-version CPE without range keys is always an exact match;
- Microsoft Office versions from documents are editions: `12` = 2007, `14` = 2010, `15` = 2013,
  `16` = 2016 plus Microsoft 365 Apps (NVD cannot tell 2016, 2019, LTSC and 365 apart in `16.0`);
  the service pack is unknown, so every CVE of the edition matches;
- the CPE update field (service pack), `target_hw` and other `target_sw` values are ignored;
- an OS from metadata without a patch level (Windows 7, Android) has no version: count only.

Findings (`sw.cve`, engine `analysis/cves.rs`): only for a known version; the severity is the
highest CVSS band, one step higher when a matched CVE is in KEV; workstation software and OS are
reconnaissance and capped at medium. Document software is judged by the version of its newest
document (`last_doc`). When a KEV or EOL finding already covers the product, the CVE data is merged
into it, and products without a version only add the line "N known CVEs, version not determined".

## Bundle format (`foca-sig-bundle/v3` and `/v2`)

A bundle is one JSON object:

```json
{
  "schema": "foca-sig-bundle/v3",
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
- `tables` (v2 and v3) maps a table id of `sigbundle::TABLES` to the table file exactly as committed
  in the repository (gzip or text), base64-encoded, with its SHA-256 and upstream pin. v2 bundles
  carry only `sigbundle::V2_TABLE_IDS` (`webappanalyzer`, `endoflife`, `saas_dns`, `gitleaks`,
  `kev_enrich`, `retire`, `recog`, `favicons_md5`, `psl`, `takeover`) in the formats 2.0.0-beta.3
  parses; v3 bundles carry every table, including `nvd_cve`. Before installation every known table
  is decoded, its SHA-256 checked and parsed by its module; a hash mismatch or a parse error rejects
  the whole bundle. A table id this build does not know (from a newer build) is skipped and listed
  in `signatures_status.skipped_tables`. The published 2.0.0-beta.3 reader rejects any id outside
  its list, so new tables never go into the v2 bundle; a table whose format changes beyond what the
  beta.3 parser accepts ships under a new id.
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

## Update feeds

There are two feeds, each the asset of a rolling GitHub release (a rolling tag is used instead of
`releases/latest/download/…` because GitHub skips pre-releases there, and app builds are published
as pre-releases):

| Feed | Schema | Read by |
|---|---|---|
| `https://github.com/SinonApp/FOCA-rs/releases/download/signatures-v3/signatures-v3.bundle` (`sigbundle::DEFAULT_FEED_URL`) | `foca-sig-bundle/v3`, every table | 2.0.0-beta.4 and newer |
| `https://github.com/SinonApp/FOCA-rs/releases/download/signatures/signatures.bundle` (`sigbundle::FALLBACK_FEED_URL`) | `foca-sig-bundle/v2`, beta.3 tables only | 2.0.0-beta.3, and newer builds while the v3 feed has nothing published |

`signatures_update {}` downloads the v3 feed first and falls back to the v2 feed when the v3 feed
answers HTTP 404/410; `last_check.feed_url` names the feed that answered. With an explicit `url` only
that URL is checked.

| Feed answer | `last_check.outcome` | Effect |
|---|---|---|
| HTTP 404 / 410 | `no_update` | Nothing is published yet. The active database stays. |
| Verified bundle, version not newer than the active one | `up_to_date` | Nothing changes. |
| Verified newer bundle | `installed` | The bundle becomes `current.json`. |
| Network error, bad JSON, bad signature | `failed` | The command returns the coded error (`net`, `bad_args`, `bad_signature`, with `message_msg`); the active database stays. |

Every check is stored in `<data>/signatures/last_check.json` and returned as `last_check` by
`signatures_status`, so the screen shows when the last check ran and what it found. Versions are
compared by their numeric parts (`2026.11.27` > `2026.11.20`), the release date breaks a tie.

### Built-in data against an installed bundle

The active database is the newer of the built-in one (version and release date of the KEV snapshot
compiled into the build) and the installed `current.json`. After an app update the embedded data
can be newer than a bundle downloaded by the previous version: that bundle is ignored
(`signatures_status.ignored_bundle` names it, `source` stays `builtin`), deleted at engine start
(`prune_shadowed`, together with an older `previous.json`), skipped by a rollback, and a manual
import of a bundle that is not newer fails with `sig_older`. Feed checks compare with the active
database, so the same old bundle at the feed is `up_to_date`. Tests:
`app_update_with_newer_builtin_wins_over_an_older_installed_bundle`,
`newer_bundle_still_wins_over_builtin`, `builtin_and_bundle_order_by_version_then_release_date`,
`importing_a_bundle_older_than_builtin_is_refused`, `rollback_skips_a_previous_bundle_older_than_builtin`.

### Automatic check in the app

`signatures_update { auto: true }` is the scheduled check. The UI sends it when it is ready (terms
accepted, past the lock screen; 15 s after start under Tauri) and whenever the app returns to the
foreground (at most every 10 minutes); the engine decides
(`crates/foca-engine/src/services/sigauto.rs`):

| Condition | Answer |
|---|---|
| `settings.signatures.auto` = `off` | `skipped: disabled` |
| Before `checked + 1 day` (`daily`, default) or `+ 7 days` (`weekly`) | `skipped: not_due` |
| Before the retry time after a failure (3 h) or a rate limit (HTTP 403/429 from the download host: 12 h) | `skipped: backoff` |
| Metered network and `settings.signatures.wifi_only` (default `true`) | `skipped: metered` |
| A scan is running | `skipped: scan` |
| Otherwise | the feed check as above, through the engine network client (proxy settings apply) |

A verified newer bundle is installed silently and the UI shows a short notice; a failure is
recorded in `last_check` and returned as `outcome: "failed"` (no error dialog). Manual checks reset
the schedule too. The schedule lives in `<data>/signatures/auto.json` (`checked_epoch`,
`retry_at`); `signatures_status.auto` gives `mode`, `wifi_only`, `checked_at` and `next_at` for the
screen. Feed URLs come from `Endpoints::sig_feed` / `sig_feed_fallback` (tests point them at the
local server).

## Publishing a bundle (maintainers)

The signing key is not in the repository. Keep the 32-byte Ed25519 seed offline as a file with 64
hex characters (mode 600).

1. Refresh the data and commit it: `python3 crates/foca-analysis/signatures/update_kev.py` and the
   ingest scripts whose pins you bumped (see [Ingest scripts](#ingest-scripts)), then
   `python3 qa/gen-licenses.py` and the usual tests (`cargo test -p foca-analysis -p foca-recon -p foca-net`).
2. Build and sign the bundle from that tree:

   ```sh
   scripts/build-sig-bundle.sh /path/to/sig-seed.hex dist/signatures-v3.bundle --schema both
   ```

   `--schema both` writes `dist/signatures-v3.bundle` (v3, every table) and
   `dist/signatures.bundle` (v2, only the tables 2.0.0-beta.3 knows); `--schema v3` (default) or
   `--schema v2` writes one of them.

   The script runs `cargo run -p foca-engine --release --example sig_bundle -- build …`. The bundle
   holds every kept KEV entry of `kev.tsv.gz` plus the snapshot header (`kev_catalog`) and all data
   tables of the schema (the v3 bundle is about 2.4 MB of base64 with the CVE table); the version
   defaults to the KEV catalog version (`--version` overrides it). Built-in secret rules are not
   copied into the bundle: they already ship with the app. The tool refuses a key whose public key
   differs from the one built into the app (`--allow-foreign-key` is for test bundles only).
3. Check them: `cargo run -p foca-engine --example sig_bundle -- verify dist/signatures-v3.bundle`
   (the script already verifies both).
4. Upload each bundle to its release (create each once with `make_latest: false`, so it never
   displaces the app release; replace the asset on every update):
   `gh release upload signatures-v3 dist/signatures-v3.bundle --clobber` and
   `gh release upload signatures dist/signatures.bundle --clobber`. Never upload a v3 bundle to the
   `signatures` release: beta.3 rejects it.

### Scheduled refresh (GitHub Actions)

`.github/workflows/signatures.yml` runs every Monday at 04:17 UTC and on demand
(`workflow_dispatch`, inputs `publish` and `pinned`). Jobs:

1. **refresh** (`contents: read`): checks out `main`, sets up Python 3.12 (PyYAML) and stable Rust,
   then moves the live feed pins with `tools/bump_live_pins.py` (newest published EPSS date in
   `update_kev_enrich.py` and `update_nvd.py`, today's NVD snapshot and feed year in
   `update_nvd.py`) and runs, in this order:
   `update_kev.py` (CISA KEV, not pinned), the pinned sources only with `pinned: true`
   (`update_webappanalyzer.py`, `update_endoflife.py`, `update_gitleaks.py`, `update_retire.py`,
   `update_recog.py`, `update_psl.py`, `update_takeover.py`, without `--repin`, so their hashes
   must still match), `update_kev_enrich.py --repin`, `update_nvd.py --repin`, then
   `qa/gen-licenses.py`. Tests: `tools/test_update_nvd.py`, `cargo test -p foca-analysis`,
   `cargo test -p foca-engine --lib sigbundle`, `qa/gen-licenses.py --check`. The changed files go
   to the next jobs as a patch artifact. A source whose code-like pin should move is bumped by hand
   in a pull request (edit `COMMIT`/`TAG`, run the script with `--repin`, commit the outputs).
2. **sign** (environment `signing`, `contents: write`; runs only when the repository variable
   `SIGNING_ENABLED` is `true`, and is skipped by a manual run with `publish: false`): applies the
   patch, writes the secret `SIG_SEED` to a temporary file with
   mode 600 (deleted on exit, never printed), runs
   `scripts/build-sig-bundle.sh <seed> signatures-v3.bundle --schema both --version <YYYY.MM.DD> --released <YYYY-MM-DD>`,
   verifies both bundles against the key built into the app and their schemas (no `nvd_cve` in the
   v2 bundle), then replaces the assets with `gh release upload signatures-v3 … --clobber` and
   `gh release upload signatures … --clobber`.
3. **pull-request** (`contents: write`, `pull-requests: write`): applies the patch and opens or
   updates the pull request `signatures/data-refresh` with
   `peter-evans/create-pull-request`. Nothing is pushed to `main`.

All third-party actions are pinned by commit SHA; the workflow has `permissions: {}` at the top
and a `signature-data` concurrency group (runs queue, never cancel each other).

One-time setup by a maintainer with admin rights:

1. Settings → Environments → New environment `signing`. Under "Deployment branches and tags"
   choose "Selected branches and tags" and add `main`. Required reviewers are optional: with
   reviewers, every scheduled run waits for an approval before signing.
2. In the `signing` environment add the secret `SIG_SEED`: the 64 hex characters of the Ed25519
   seed file (the same seed `scripts/build-sig-bundle.sh` reads; its public key must equal
   `OFFICIAL_ED25519_PUBKEY`, the build tool refuses any other). With the GitHub CLI:
   `gh secret set SIG_SEED --env signing < /path/to/sig-seed.hex`.
3. The releases `signatures` and `signatures-v3` must exist (created once with
   `make_latest: false`).
4. Settings → Actions → General → Workflow permissions: allow GitHub Actions to create pull
   requests, or the last job fails.
5. Settings → Secrets and variables → Actions → Variables: add `SIGNING_ENABLED` = `true`. Until it
   is set, the scheduled run only refreshes and tests the data and opens the pull request; the
   bundles are then signed and uploaded locally with `scripts/build-sig-bundle.sh` and
   `gh release upload --clobber`.

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
  tables (round trip, tampered and unparsable tables), unknown table ids skipped, the NVD table round
  trip, v1 compatibility and `v2_compat_bundle_stays_readable_by_beta3` (the v2 bundle passes a copy
  of the beta.3 acceptance rules: schema, table id list, hashes, signature, parsers; the v3 bundle
  does not).
- `cargo test -p foca-analysis --lib cve`: version comparison table, ranges, matcher (ranges, exact,
  no version, plugins by slug, Office editions), finding severity, the embedded table with load and
  lookup timing; `cargo test -p foca-engine --lib cves`: findings (server and workstation, KEV
  raise, no-version info line, merge with KEV and EOL findings).
- Per-table unit tests in their modules: `foca-recon` `tech` (merge, version templates, end-of-life
  cycles, startup time), `retire`, `favicon`; `foca-net` `recog`, `psl`, `takeover`, `saas`;
  `foca-analysis` `secrets` (gitleaks rules and allowlists), `kev` (enrichment) and `cve`.
- `cargo test -p foca-engine --test ops signatures`: the command against a local feed server (404,
  foreign signature, refused URL) including `message_msg` codes, and the automatic check schedule
  (metered, due, not due, off).
- `cargo test -p foca-engine --lib sigauto`: scheduling (due and not due, daily and weekly, off,
  metered with Wi-Fi only, during a scan, failure retry, rate limit backoff, state file).
- `crates/foca-engine/tests/contract_shape.rs`: demo backend shapes and the demo copy of the numbers
  (`demo_signature_numbers_match_core_status`).
- `qa/scenarios/signatures-screen/steps.mjs`: the screen at 393 px and 360 px with font scale 2.
- `qa/scenarios/update-prompt/steps.mjs`: the automatic update card (off/daily/weekly, Wi-Fi only,
  next check) and the start-up app update dialog.
