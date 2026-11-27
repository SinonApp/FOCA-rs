# Third-Party Code, Datasets & Licenses (THIRD_PARTY)

FOCA-rs is distributed under the **GNU General Public License v3.0 ([GPL-3.0](LICENSE))**. Below are the third-party libraries, datasets, algorithms, and external services referenced or used by the project. All bundled open-source dependencies are verified for GPL-3.0 compatibility.

## Automated License Inventory & Offline Viewer (`/settings/licenses`)

- **Generator & CI verifier**: [`qa/gen-licenses.py`](qa/gen-licenses.py) automatically generates [`crates/foca-engine/data/licenses.json`](crates/foca-engine/data/licenses.json) from:
  - `cargo metadata --locked` (all transitive and direct Rust crates in `Cargo.lock`: 536 crates / 43 direct as of 2.0.0),
  - `src-tauri/gen/android/app/build.gradle.kts` (all Android runtime libraries, tagged by flavor `both` / `foss` / `play`),
  - bundled assets and datasets (`Inter` font, `Fluent Emoji`, `Natural Earth`, `SecLists`, `CISA KEV`, Cloud/CDN IP lists, standards identifiers, and clean-room algorithm attributions),
  - the pinned signature data sources of `crates/foca-analysis/signatures/sources.lock.json` (license allow-list; each attribution must appear in [NOTICE](NOTICE) and each source in this file), and
  - full license texts for 13 licenses (`GPL-3.0`, `MIT`, `Apache-2.0`, `BSD-2-Clause`, `BSD-3-Clause`, `ISC`, `MPL-2.0`, `SIL OFL 1.1`, `CDLA-Permissive-2.0`, `Unicode-3.0`, `CC-BY-4.0`, `CC0-1.0`, EPSS usage terms).
- **CI enforcement**: `python qa/gen-licenses.py --check` fails the build if `licenses.json` is stale, if any Rust crate carries a GPL-3.0-incompatible SPDX license expression, or if any proprietary Google ML Kit dependency/import leaks into the `main` or `foss` Android source sets.
- **In-app viewer**: The full inventory and license texts are available offline inside the app at **Settings → About → Licenses & Third-Party Components** (`/settings/licenses`, served over IPC via `licenses_get`).

## Android `play`-Only Isolation (Google ML Kit)

- **`com.google.mlkit:text-recognition:16.0.1`**: proprietary library governed by the [Google APIs Terms of Service](https://developers.google.com/terms).
- **Strict flavor isolation**: Declared exclusively via `playImplementation(...)` in [`src-tauri/gen/android/app/build.gradle.kts`](src-tauri/gen/android/app/build.gradle.kts), with Kotlin code confined to `src/play/java/app/sinon/focars/platform/OcrEngine.kt`.
- **`foss` flavor purity**: The `foss` build flavor (`./gradlew assembleFossRelease`) ships a clean stub (`src/foss/.../OcrEngine.kt` returning `unavailable_in_foss_build`) and contains **zero** Google ML Kit binaries, dependencies, or imports, keeping `foss` 100% GPL-3.0 / F-Droid compliant.
- All common AndroidX and Material libraries (`androidx.webkit`, `androidx.appcompat`, `androidx.activity`, `com.google.android.material`, `androidx.lifecycle`, `androidx.core`, `androidx.biometric`, `androidx.work`) are licensed under **Apache-2.0**.

## Bundled Fonts & Artwork

- **Inter Font**, [SIL OFL 1.1](https://rsms.me/inter/) (© Rasmus Andersson): `ui/fonts/Inter-Regular.ttf`, `ui/fonts/Inter-SemiBold.ttf`.
- **Fluent Emoji (App Icon)**, [MIT](https://github.com/microsoft/fluentui-emoji) (© Microsoft Corporation): `ui/icon.png` and Android launcher icons.

## FOCA (ElevenPaths / Telefónica Tech): GPL-3.0

- Repository: https://github.com/ElevenPaths/FOCA
- Borrowed concepts: the "Backups Fuzzer" workflow (`FOCA/FormBackupsFuzzer.cs`: probing backup files adjacent to discovered URLs) and directory/document discovery workflows. Implemented from scratch in Rust (`crates/foca-fuzz`, `crates/foca-meta`, `crates/foca-search`); no original code was copied.

## ffuf: MIT

- Repository: https://github.com/ffuf/ffuf (Copyright (c) 2021 Joona Hoikkala)
- Borrowed concepts (clean-room Rust reimplementation in `crates/foca-fuzz`): `FUZZ` keyword placement in path/filename/`Host` header; wordlist × extension expansion (`-e`); status/size/word/line/regex matchers and filters (`-mc/-ms/-mw/-ml/-mr`, `-fc/-fs/-fw/-fl/-fr`) with default matcher status set; soft-404 auto-calibration (`-ac`) using random non-existent probes grouped by directory/extension/vhost; bounded recursion.

## SecLists: MIT

- Repository: https://github.com/danielmiessler/SecLists, pinned commit `1a89b46c204032247592a1626e29f841cb0fe2a5` (Copyright (c) 2018 Daniel Miessler; license text bundled at `crates/foca-fuzz/wordlists/SECLISTS-LICENSE`).
- Bundled in `crates/foca-fuzz/wordlists/` (gzip-compressed unmodified; at load time, entries with path-traversal/obfuscation, non-ASCII characters, or `.git/*` except `.git/HEAD` are filtered):

  | SecLists Path | Bundled File |
  |---|---|
  | `Discovery/Web-Content/common.txt` | `common.txt.gz` |
  | `Discovery/Web-Content/quickhits.txt` | `quickhits.txt.gz` |
  | `Discovery/Web-Content/Common-DB-Backups.txt` | `Common-DB-Backups.txt.gz` |
  | `Discovery/Web-Content/raft-small-files.txt` | `raft-small-files.txt.gz` |
  | `Discovery/Web-Content/raft-small-directories.txt` | `raft-small-directories.txt.gz` |
  | `Discovery/Web-Content/dsstorewordlist.txt` | `dsstorewordlist.txt.gz` |
  | `Discovery/DNS/subdomains-top1million-5000.txt` | `subdomains-top1million-5000.txt.gz` |
  | `Fuzzing/extensions-most-common.fuzz.txt` | `extensions-most-common.fuzz.txt.gz` |
  | `Fuzzing/extensions-compressed.fuzz.txt` | `extensions-compressed.fuzz.txt.gz` |
  | `Fuzzing/file-extensions-lower-case.txt` | `file-extensions-lower-case.txt.gz` |
  | `Discovery/Web-Content/CMS/wordpress.fuzz.txt` | `cms-wordpress.fuzz.txt.gz` |
  | `Discovery/Web-Content/CMS/Sharepoint.txt` | `cms-sharepoint.txt.gz` |
  | `Discovery/Web-Content/CMS/joomla-plugins.fuzz.txt` | `cms-joomla-plugins.fuzz.txt.gz` |
  | `Discovery/Web-Content/CMS/drupal-themes.fuzz.txt` | `cms-drupal-themes.fuzz.txt.gz` |

- `crates/foca-net/wordlists/subdomains-top1million-5000.txt.gz`: copy of `Discovery/DNS/subdomains-top1million-5000.txt` used by `foca_net::bruteforce` (`top-1500` uses the first 1,500 lines; `top-5000` uses the full list); license text bundled at `crates/foca-net/wordlists/SECLISTS-LICENSE`.
- Larger wordlists are not embedded: `foca_fuzz::wordlists::REGISTRY` lists on-demand download URLs pinned to the same commit with byte sizes and SHA-256 digests.
- Deliberately excluded: `Fuzzing/XSS|LFI|SQLi|command-injection`, `Passwords/`, and parameter fuzzing lists.

## ds_store (Alastair Houghton): MIT

- Repository: https://github.com/dmgbuild/ds_store, used only to generate test fixtures `tests/fixtures/fuzz-site/www/.DS_Store` and `tests/fixtures/fuzz-site/dsstore/big.DS_Store`.
- The parser in `crates/foca-fuzz/src/dsstore.rs` was written from scratch from the format specification (Mark Mentovai, "DS_Store File Format").

## Signature Data Sources (pinned, `crates/foca-analysis/signatures/sources.lock.json`)

Converted at build time by `crates/foca-analysis/signatures/tools/update_<source>.py` from a pinned
upstream version (commit, tag or snapshot date, with SHA-256 of every input). Only the fields FOCA-rs
uses are kept; regexes the Rust `regex` crate rejects are skipped and counted in the lock file.
Attribution lines are repeated in [NOTICE](NOTICE). A signed signature bundle (`foca-sig-bundle/v2`)
can replace these tables at runtime.

| Source | License | Pinned | Shipped as | Used for |
|---|---|---|---|---|
| [enthec/webappanalyzer](https://github.com/enthec/webappanalyzer) | GPL-3.0 | `7dba7bf3e8b4` | `crates/foca-recon/data/webappanalyzer.json.gz`, `crates/foca-net/data/saas_dns.json` | Web technology detection (7604 technologies, 466 with CPE), SaaS by DNS (147 rules) |
| [gitleaks](https://github.com/gitleaks/gitleaks) (© 2019 Zachary Rice) | MIT | `v8.30.1` | `crates/foca-analysis/signatures/secrets_gitleaks.toml` | Secret rules (197 of 222; 20 covered by our tuned rules, 5 path-only) |
| [endoflife.date](https://github.com/endoflife-date/endoflife.date) (© 2020 endoflife.date contributors) | MIT | `32423d8113b6` | `crates/foca-recon/data/endoflife.tsv.gz` | End-of-life dates (117 products, 2179 cycles past EOL at 2026-11-27) |
| [FIRST EPSS](https://www.first.org/epss) (`epss.empiricalsecurity.com/epss_scores-2026-11-26.csv.gz`) | Free use, attribution requested | `2026-11-26` | `crates/foca-analysis/signatures/kev_enrich.tsv.gz` | EPSS score and percentile of KEV CVEs; reports credit FIRST in the footer |
| [cisagov/vulnrichment](https://github.com/cisagov/vulnrichment) | CC0-1.0 | `2872f0a7d9f8` | `crates/foca-analysis/signatures/kev_enrich.tsv.gz` | CVSS, CWE and SSVC of KEV CVEs |
| [RetireJS/retire.js](https://github.com/RetireJS/retire.js) (© 2018 Erlend Oftedal) | Apache-2.0 | `da66c52a5a5a` | `crates/foca-recon/data/retire.json.gz` | JS library versions and vulnerable ranges (76 libraries, 819 ranges) |
| [rapid7/recog](https://github.com/rapid7/recog) (© 2014-2015 Rapid7) | BSD-2-Clause | `f1191e24332c` | `crates/foca-net/data/recog.tsv.gz`, `crates/foca-recon/data/favicons_md5.tsv` | Service banners (1062 fingerprints), favicon MD5 (645 hashes) |
| [publicsuffix/list](https://github.com/publicsuffix/list) | MPL-2.0 | `88b076a1fb2a` | `crates/foca-net/data/public_suffix_list.dat.gz` (unmodified) | Registrable domains |
| [EdOverflow/can-i-take-over-xyz](https://github.com/EdOverflow/can-i-take-over-xyz) | CC-BY-4.0 | `5bd4e1283791` | `crates/foca-net/data/takeover.json` (fields reduced and renamed) | Dangling CNAME providers (26 services) |

Evaluated and not used: original Wappalyzer (proprietary since 2023), nmap-service-probes (NPSL,
GPL-incompatible), trufflehog (AGPL-3.0), secrets-patterns-db (mixed license with an AGPL part),
can-i-take-over-dns (no license), nuclei-templates `http/takeovers` (MIT, but no CNAME suffixes to
drive a DNS check).

## Wappalyzer / webappanalyzer: GPL-3.0 (Schema Concept), MurmurHash3: Public Domain

- `crates/foca-recon/data/tech.json`: ~130 hand-authored technology fingerprinting rules; the rule schema (`headers`/`meta`/`cookies`/`html`/`scripts`/`implies`, version capture group) follows Wappalyzer/webappanalyzer (https://github.com/enthec/webappanalyzer, GPL-3.0); original patterns were not copied. The webappanalyzer fingerprints themselves now ship as data (GPL-3.0, see [Signature Data Sources](#signature-data-sources-pinned-cratesfoca-analysissignaturessourceslockjson)) and are merged with these hand rules by name.
- MurmurHash3 x86_32 (Austin Appleby, public domain) and MD5 (RFC 1321) are implemented from scratch in `crates/foca-recon/src/hash.rs`; JS endpoint/secret extraction ideas were inspired by jsluice (MIT) and LinkFinder (MIT) with clean-room Rust code.

## Document, URL & Subdomain Sources (`crates/foca-search`)

From GPL-2.0-only or unlicensed projects, only factual endpoint URLs and response schemas were referenced; all code is original Rust.

| Project | License | Concept / Facts Referenced | Location in FOCA-rs |
|---|---|---|---|
| [lc/gau](https://github.com/lc/gau) `pkg/providers/{wayback,commoncrawl,otx,urlscan}` | MIT, © Corben Leo | CDX pagination (`showNumPages` → `page=N`), Common Crawl index traversal via `collinfo.json`, OTX `url_list?page=`, urlscan `search` | `sources/archive.rs`, `sources/urls.rs` |
| [xnl-h4ck3r/waymore](https://github.com/xnl-h4ck3r/waymore) | MIT, © xnl-h4ck3r | Fetching archived document snapshots via `web.archive.org/web/<ts>id_/<url>` (zero target contact), 429/503/504 retries, local MIME filtering | `sources/archive.rs`, engine `scan.rs` |
| [projectdiscovery/subfinder](https://github.com/projectdiscovery/subfinder) `pkg/subscraping/sources/*` | MIT, © ProjectDiscovery | Keyless subdomain source endpoints (`anubis`, `crtname`, `scanmalware`, `hackertarget`, `rapiddns`, `subdomaincenter`, `thc`, `shodanct`, `certspotter`, `alienvault`) | `sources/subdomains.rs` |
| [ElevenPaths/FOCA](https://github.com/ElevenPaths/FOCA) `SearcherCore/Searcher/*WebSearcher.cs` | GPL-3.0, © ElevenPaths (Telefónica) | Keyless `site:<domain> filetype:<ext>` search-engine dorking concept | `sources/urls.rs` (`Dork`) |
| [dwisiswant0/go-dork](https://github.com/dwisiswant0/go-dork) | MIT, © Dwi Siswanto | DuckDuckGo/Bing result redirect unwrapping (`uddg=`, `u=a1<base64>`) | `sources/urls.rs` (`extract_urls`) |
| [laramies/theHarvester](https://github.com/laramies/theHarvester) `theHarvester/discovery/` | GPL-2.0: **facts only** | Endpoints for Arquivo.pt `textsearch`, Shodan InternetDB, subdomain.center, THC; no code ported | `sources/urls.rs`, `foca-engine/src/intel.rs` |

Public external services queried by passive/optional collectors include: `web.archive.org`, `index.commoncrawl.org`, `crt.sh`, `api.certspotter.com`, `anubisdb.com`, `api.hackertarget.com`, `rapiddns.io`, `api.subdomain.center`, `ip.thc.org`, `ctl.shodan.io`, `otx.alienvault.com`, `urlscan.io`, `cavalier.hudsonrock.com`, `arquivo.pt`, `internetdb.shodan.io`, `html.duckduckgo.com`, `www.bing.com`, `www.mojeek.com`, `www.virustotal.com`, `api.securitytrails.com`, `api.github.com`, `api.pwnedpasswords.com` (opt-in k-anonymity), `cloudflare-dns.com`, `dns.google` (DoH over proxy), and user-configured Cloud AI provider APIs. Returned data remains subject to each provider's terms of service. HTML dorking works on a best-effort basis (CAPTCHA → `blocked` / manual verification).

## Notable Cargo Libraries

The complete list of all 536 Rust crates is tracked in [`crates/foca-engine/data/licenses.json`](crates/foca-engine/data/licenses.json) and viewable offline at `/settings/licenses`. Notable examples include:

| Crate | License | Purpose |
|---|---|---|
| [jpeg-decoder](https://crates.io/crates/jpeg-decoder) 0.3 (default-features = false) | MIT OR Apache-2.0 | EXIF thumbnail vs. full photo comparison (1/8-scale decoding) in `foca-meta/src/thumbcmp.rs` |

## Natural Earth: Public Domain

[Natural Earth](https://www.naturalearthdata.com/) `ne_110m_admin_0_countries` and `ne_50m_admin_0_countries` ([nvkelso/natural-earth-vector](https://github.com/nvkelso/natural-earth-vector), public domain: "No permission is needed to use Natural Earth"). Simplified and quantized by `ui/data/ne-build.py` into offline assets `ui/data/ne110.js` and `ui/data/ne50.js` for the 3D GPS globe (`/p/map`). Attribution `© Natural Earth` is displayed on the map.

## Cloud & CDN IP Ranges: Published Network Facts

`crates/foca-net/data/cloud_ranges.txt.gz` (~10.5k CIDR prefixes, 40 KB) is built by `crates/foca-net/data/gen_cloud_ranges.py` from official published lists: Cloudflare (`cloudflare.com/ips-v4`, `/ips-v6`), AWS (`ip-ranges.amazonaws.com/ip-ranges.json`, CloudFront separated), Microsoft Azure (`ServiceTags_Public_*.json`, tags `AzureCloud` and `AzureFrontDoor.Frontend`), Google Cloud (`gstatic.com/ipranges/cloud.json`), Fastly (`api.fastly.com/public-ip-list`), DigitalOcean (`digitalocean.com/geo/google.csv`), plus announced prefixes for AS20940/16625/32787 (Akamai) and AS24940/213230 (Hetzner) from RIPEstat (`stat.ripe.net`, RIPE NCC data). These are factual routing allocations aggregated and compressed for offline lookup in `foca-net::cdn`. Microsoft 365 tenant discovery (`foca-net::m365`) queries public Microsoft endpoints (`login.microsoftonline.com` and `autodiscover-s.outlook.com`).

## CISA Known Exploited Vulnerabilities (KEV): Public Domain (U.S. Government Work)

`crates/foca-analysis/signatures/kev.tsv.gz` (~16 KB) is a filtered offline snapshot of the CISA KEV catalog (`https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`, `catalogVersion: 2026.11.20`, `dateReleased: 2026-11-20`, snapshot taken 2026-11-22): 924 of 1,790 entries matching software products detected by FOCA-rs (`signatures/kev_products.toml`), retaining only `cveID`, `vendorProject`, `product`, `dateAdded`, `knownRansomwareCampaignUse`, and `vulnerabilityName`. As a work of the U.S. federal government (17 U.S.C. § 105), it carries no copyright restrictions; CISA does not endorse or support FOCA-rs. Refresh via `python3 crates/foca-analysis/signatures/update_kev.py` or signed `Ed25519` signature bundles.

## Security Standards (`crates/foca-analysis/signatures/standards.toml`): Factual Identifiers & Links

- Only factual identifiers and control titles are mapped (no proprietary standard text is copied):
  - **MITRE ATT&CK v20** and **CWE** incl. the 2025 CWE Top 25 list (© The MITRE Corporation, https://attack.mitre.org/, https://cwe.mitre.org/),
  - **OWASP Top 10:2025** and **WSTG v4.2** (CC BY-SA 4.0, https://owasp.org/Top10/2025/, https://github.com/OWASP/wstg),
  - **ISO/IEC 27001:2022 Annex A** (control numbers and titles),
  - **NIST SP 800-53 Rev. 5** control ids and titles (work of the U.S. federal government, https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final) and the matching measure names of **ND TZI 3.6-006-24 (НД ТЗІ 3.6-006-24)** (SSSCIP / ДССЗЗІ, https://cip.gov.ua/),
  - article numbers of **GDPR** (Regulation (EU) 2016/679) and the **Law of Ukraine No. 2297-VI** "On Personal Data Protection",
  - **ND TZI 2.5-004-99 (НД ТЗІ 2.5-004-99)** and **ND TZI 3.7-003-05 (НД ТЗІ 3.7-003-05)** (legacy normative documents of SSSCIP / ДССЗЗІ for systems certified under КСЗІ, https://tzi.com.ua/).
- Verification details: [docs/STANDARDS.md](docs/STANDARDS.md).
