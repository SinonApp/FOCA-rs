# Changelog

All notable changes to this project are documented in this file.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/).

---

## 2.0.0-beta.4 (unreleased)

### Added
- **More site technologies**: the webappanalyzer table keeps 7604 of 7715 technologies (was 5623). Detection now also reads the contents of fetched JavaScript files, the visible page text, inline and fetched stylesheets, the TLS certificate issuer and robots.txt, with version templates as before.
- **Browser signals on Android**: in Standard and Full the home page of each site is rendered once in the hidden browser and one read-only script (1.5 s budget) reads JavaScript globals such as `jQuery.fn.jquery`, DOM selectors and the hosts the page requests. App-shell pages the crawler renders answer the same script. Settings → Site crawl → "Home pages via browser" caps renders per scan (default 10). Passive renders nothing; the CLI and desktop note in the scan log that browser-only signals were not checked.
- **Plugins, themes and modules**: WordPress plugins and themes (also `mu-plugins` and renamed content folders), Drupal modules and themes, Joomla components, modules, plugins and templates, Magento and PrestaShop modules are found by their file paths, with the version from `?ver=` (the WordPress core version is ignored). Each carries its CMS, slug and a CPE guess for vulnerability matching. Full reads `readme.txt` of up to 30 WordPress plugins for the version.
- **Technologies screen**: each technology shows which signals found it (headers, HTML, JS file, CSS, TLS, robots.txt, JS or DOM in the browser, plugin path, readme), and plugins are grouped under their CMS with versions.

## 2.0.0-beta.3: 2026-11-27

Third beta. It fixes the projects that disappeared after an upgrade, makes Pause, the stage and captcha controls do what they say, and finds more documents: a new site crawler, files on public storage linked from the site, a deeper Common Crawl sweep and postponed searches. It also adds scan deletion, several hosts at once, a saved AI summary history and a real signature database update with more detection data.

> **Installs over 2.0.0-beta.2 and 2.0.0-beta.1 and keeps your projects.** All betas are signed with the same key. Coming from 1.x or a 2.0 preview build, you still need to uninstall first (see the beta.1 note below).

### Fixed
- **Projects missing after an upgrade**: projects created with beta.2 vanished from the Projects list after upgrading to a newer build. The data was never lost: the project index could not be read, and the files stayed intact. The list now reads old index rows and keeps a project whose database fails to open, showing the error only when you open it. A permanent upgrade test opens a beta.2 data folder and checks that every project, its counts, flags and settings are still there.
- **Stage controls**: Pause, Skip and Restart on a stage now reach a running subdomain brute force instead of waiting for it to finish. A paused stage shows Pause instead of Running, and skipped or paused items are worded more clearly.
- **Follow-up runs**: re-running selected items runs only the stages those items belong to. Before, it also ran every later stage (network, ports, site recon, brute force).
- **False "no network"**: when every chosen search source hit a rate limit or a captcha, the scan no longer says the network is down. It names the real reason instead.
- **Request log in exports**: errors in the request log CSV and in the report are written in the export language, not in Russian.
- **Reports in English and Ukrainian**: missing security headers and camera labels no longer show Russian words.
- **MTA-STS**: a policy file that the scope did not allow us to fetch is reported as not checked, not as an unreachable policy (Medium).
- **Captcha check**: the verification dialog has Cancel and Done, a load progress bar, and an error with Retry when the page fails to load or does not finish within 30 seconds. Only Done on a page without a challenge marks the engine verified. Cancel, Back or leaving the app keep it blocked, and Prepare search engines counts only engines that were actually solved.
- **Clipboard on Android**: Paste from clipboard works (the WebView never allowed reading it). Copying a secret marks it as sensitive, and the 30-second auto-clear wipes only the value the app wrote. The paste buttons tell an empty clipboard from one the app could not read.
- **Floating Pause button**: after leaving a scrolled screen, the scan screen no longer shows the floating Pause on top of the stage list while the Pause and Stop row is visible.
- **Settings icon**: settings use a real cog, so the icon no longer looks like the theme sun.
- **Signature database screen**: Check for updates now checks a real update feed instead of only showing the status. The numbers come from the loaded tables: CISA KEV entries in use out of the total, the KEV catalog date with a hint when it is more than 30 days old, software and OS signatures, secret rules and standards references. The fake auto-update switch is gone, and the Ed25519 label and dates no longer wrap.
- **Pause stops traffic at once**: requests waiting for their turn, the site crawl and the port scan now hold until you resume. Before, requests already queued still went out during a pause. Requests in flight finish, and Stop cancels the held ones.
- **Unreachable is not rate-limited**: in forgotten file discovery, a host that does not answer at all (refused connection, timeout, DNS or TLS failure) stops as unreachable with its own warning, instead of "the site limited requests".
- **File names from Google Drive**: files with non-Latin names keep their names instead of `gdrive-<id>.bin`, and a file without a usable name gets its extension from its content.
- **Network map at large fonts**: long AD domain names wrap instead of pushing the screen wider than the phone.
- **Report preview to the end**: the preview stopped after a few sheets with "… N more" under each table and a footer like "p. 5 / 115", so it looked as if it could not be scrolled further. Every included finding is now shown, long tables continue on the next sheets, the footer counts the preview sheets, and a closing note gives the page estimate of the file. The sheets no longer form a nested scroll area, the title block grows with large fonts instead of spilling over, and the last footer clears the gesture bar.
- **Form spacing**: a full-width button under a field keeps a gap, so Check key in the API key sheet is no longer glued to the field.

### Changed
- **Reference cases** stay out of Recent projects and have their own section on the Projects screen. The app no longer reopens a reference case on start.
- **AI summary**: one request per project at a time. Send shows a spinner and a Cancel button, and repeated taps no longer start extra paid requests. Every summary is saved in the project (up to 50), so you can open, copy, delete one or pick which one goes into the report. The summary is written in the interface language, placeholders are language-neutral (`[CLIENT]`, `[SECRET]`, `[EMAIL]`), and the report puts the client name and domain back.
- **Pickers**: all drop-down lists (AI provider, model and reasoning level, findings host filter, timeline years, webhook format, plugin settings, User-Agent in the scan wizard) open a themed panel instead of the grey Android dialog.
- **No hard caps on manual numbers**: speed, threads, hosts at once, timeouts, retries, brute-force budgets, wizard download limits, crawl limits, OCR caps and the mobile data limit accept any valid value, and the typed value really applies (a wizard document limit above 200 or a brute-force rate above 20/s used to be cut). `0` means no limit where that makes sense. Past the recommended range the field shows a warning, and risky values (very high speed or threads, no speed limit, unlimited mobile data) ask for a one-time confirmation.
- **One adaptive pace**: paginated sources and search engines share one throttle. It honours `Retry-After`, doubles the pause on 429 or 503 and stops a source after repeated limits with a note on the scan screen.
- **Clear app logs** in Debug is labelled as such and says the request log stays.
- **Signature key rotated**: signature bundles are now signed with a new key. Older builds reject bundles from the new feed and keep their built-in databases.
- **Dependencies**: sha2 0.11, toml 1.2, rusqlite 0.43, url, zip and anyhow updates, and newer GitHub Actions.

### Added
- **Custom report logo**: Choose in the report builder opens the system file picker; PNG, JPEG and WebP up to 2 MB are accepted (SVG is refused), pictures larger than 512 px are scaled down, and the builder shows the thumbnail with file name and size. The logo is saved in the settings and appears in the preview header and title page, on the HTML/PDF cover and template headers, and above the title in DOCX. Remove brings back the company initials. New commands `report_logo_get`, `report_logo_set`, `report_logo_clear`.
- **Delete a scan**: from the scan history, a stopped scan or a paused one. A hold-to-confirm sheet shows what goes away first: the scan record, its request log, documents only it downloaded and findings that no other scan backs. Data a later scan also saw stays.
- **Hosts at once** (Settings → Network and the scan wizard, default 4, warning above 8): liveness, TLS, ports, site recon and site search work on several hosts together. The scan screen shows how many hosts are running and done. Rate limits stay per host, and a host that answers 429 stops alone.
- **Clear the request log**: Debug → Requests and the request log export in Reports can clear the whole log, entries older than 7, 30 or 90 days, or one scan, with counts shown before you confirm. A running or paused scan keeps its entries.
- **Clear the quick tools log**: Quick tools → Log has a Clear button.
- **Signature update feed**: the app checks the official feed, verifies the bundle signature and installs a newer one. Each check is saved and shown as "Last checked".
- **Monthly mobile data limit is enforced** (off by default, turn it on in Traffic & power): the app counts what it really transfers over mobile or metered networks per calendar month and shows it in Traffic & power. When a scan reaches the limit it pauses with a notification and a banner, and resumes by itself on Wi-Fi or after you raise the limit.
- **Subdomain takeover by HTTP fingerprint**: in the Standard and Full profiles, a subdomain whose CNAME points at a live resource of a known service (26 services from can-i-take-over-xyz) is fetched once, and the answer is matched against the service's "unclaimed resource" text. A match is reported as "Possible subdomain takeover (service X)" with the CNAME and the matched text as evidence. The Passive profile never contacts the subdomain; the DNS-only dangling CNAME check stays.
- **Site crawler**: in the Standard and Full profiles the crawl starts from the home pages and the site's sitemaps (robots.txt `Sitemap:` lines, `/sitemap.xml`, indexes and `.gz`). Depth, pages and time per scan are set in Settings → Site crawl or per scan in the wizard (defaults 5, 1000 pages, 20 minutes), and the next scan continues an unfinished crawl. Calendars, endless filters and session parameters are capped by URL template, logout and delete links are never opened, and `www` and bare-domain mirrors are crawled once. On Android, app-shell pages (React, Flutter) are rendered in the hidden browser, up to 30 per scan; the CLI and desktop show a warning that links came from the HTML alone.
- **Files on public storage linked from the site**: links from in-scope pages to Google Drive, Google Docs, Sheets and Slides, OneDrive, Dropbox and SharePoint are downloaded as target documents, within the scan's document limit. Only the linked items are fetched (a public folder: up to 200 files), private files are marked as private, and the request log marks these requests. Google exports are never used to name authors, because Google writes their metadata.
- **Where a document came from**: the document card shows the page that linked it, the document the link was found in, the storage provider and a Google export note.
- **Links inside documents**: web links in downloaded documents (URI links in PDF) that point to in-scope documents or linked storage files are downloaded too, up to 2 steps deep.
- **Photos for EXIF** have their own limits (300 images and 200 MB per scan by default) and no longer take room from the document limit. With images off, image links are skipped.
- **Deep Common Crawl**: choose the latest snapshot, the last N years or all snapshots (Settings → Sources, or per scan in the wizard). The sweep is slow on purpose (at least 3 seconds between index calls, backoff on errors), runs in the background of the scan for up to 5 minutes, caches results on the device and continues in the next scan. A Common Crawl URL that is dead now falls back to its Wayback copy.
- **Postponed searches**: when every search engine shows a captcha, the searches no engine could run are kept for the project and retried slowly later in the scan and first at the next scan. The scan screen shows how many are postponed and a Retry now button. Captchas are never solved automatically.
- **Own SearXNG and Brave Search API**: you can add your own SearXNG instances (asked before the public pool, with a setup guide) and an optional Brave Search API key. The API keys sheet checks both and shows the Brave monthly quota.
- **More detection data in the signature database**: technology fingerprints from webappanalyzer (about 5,600 technologies), gitleaks secret rules, end-of-life dates from endoflife.date, EPSS, CVSS and CWE for known exploited vulnerabilities (FIRST EPSS, CISA Vulnrichment), vulnerable JavaScript libraries from Retire.js, Recog banner and favicon fingerprints, the Public Suffix List for grouping subdomains, and takeover fingerprints from can-i-take-over-xyz. All sources are pinned, credited in NOTICE and the Licenses screen, and can be updated with a signed bundle (format v2; v1 bundles still install).
- **CLI**: `foca scan` takes crawl and Common Crawl options per run (`--crawl-depth`, `--crawl-pages`, `--crawl-minutes`, `--crawl-storage`, `--crawl-doc-links`, `--crawl-images`, `--max-images`, `--max-image-mb`, `--cc-depth`, `--cc-years`), and `--control` reads pause, resume, stop, status and skip commands from stdin.

## 2.0.0-beta.2: 2026-11-26

Second beta. It fixes what phone tests of 2.0.0-beta.1 turned up: false findings from the fuzzer and TLS checks, duplicate findings, Russian text in English and Ukrainian reports, and several interface problems.

> **Installs over 2.0.0-beta.1.** Both betas are signed with the same key, so Android updates beta.1 in place and keeps your projects. Coming from 1.x or a 2.0 preview build, you still need to uninstall first (see the beta.1 note below).

### Fixed
- **Fuzzer**: sites that answer every unknown path with their start page (single-page apps) no longer produce "exposed file" and "backup" findings. The fuzzer now recognises these soft 404 pages per path type.
- **Fuzzer**: a run of 403 answers on `.ht*` files (the Apache default) no longer stops the fuzzer with "site limited requests". A 403 or 5xx run is checked with one control request before the fuzzer gives up.
- **TLS**: "ALPN missing" and "OCSP stapling missing" are reported only from a full handshake, not from the legacy-protocol probe that does not offer them.
- **Duplicate findings**: the same TLS, certificate or site finding seen on several ports of one host is merged into one finding that lists the ports.
- **Third-party widget keys** in script URLs (public keys of maps, chat or analytics widgets) are reported as Info instead of a leaked secret.
- **Reports in English and Ukrainian** no longer contain Russian sentences (KEV, InternetDB, mail policy details and other generated texts). A test now renders every finding type in both languages and fails on Russian text.
- **Report language** follows the interface language when it is set to "System".
- **Blocked by scope**: requests the scope refused are counted as blocked in the request journal and in the report.
- **Settings → Appearance**: the language picker highlights the language actually in use.
- **Onboarding**: the Next button stays on screen on narrow phones, the last slide has a Start button, and Back no longer jumps forward.
- **Background execution**: the firmware steps show the detected autostart and battery state instead of a manual checklist, and the Xiaomi battery and pop-up links open the matching system screens instead of notification settings.
- **Alerts**: incomplete Telegram or webhook channels are refused with a field-level message before saving or testing, and delivery errors are reported clearly.
- **Counts read naturally** in all three languages ("1 document", "21 documents", Ukrainian and Russian plural forms).
- **Scan screen**: the floating Pause button appears only after the Pause/Stop row scrolls away, so it no longer covers the stage list.
- **Snackbar** stays clear of open sheets and closes on tap; help buttons and weekday chips are at least 44 px; several crowded rows and footers have more room.

### Changed
- **URL targets**: when the target is a URL, subdomain brute force and permutations are skipped because subdomains are out of scope. The scan screen and the report now say so instead of showing an empty step.
- **CDN edges**: TLS findings on a CDN edge are worded as a CDN setting to change in the provider's dashboard.
- **System language option**: the language setting has an explicit "System" choice that shows which language it resolves to. The core resolves it too, so playbooks, alerts, notifications, report defaults and the reference case name follow the device language.
- **Tags** on findings are stable English codes shown in the interface language. Tags saved by beta.1 are converted on read; your own tags stay as they are.
- **Request journal** entries carry an error kind (timeout, connection refused, TLS, DNS, out of scope, HTTP status) shown in the interface language.
- **Stored projects** are upgraded to schema v10 on first open: the empty-value placeholder in hosts and findings becomes a plain hyphen.
- **Demo project and test data** use only documentation domains and addresses (`example.com`, `203.0.113.0/24`) and fictional names. In an English interface the demo company shows English document titles and Latin names.
- **Documentation**: shorter and plainer texts, internal working notes removed from the repository.

### Added
- **Incompleteness reasons** per source in the report appendix: what went wrong with each source that returned partial data, for example a captcha, a rate limit (HTTP 429) or a service that was down (HTTP 502).
- **Out-of-scope documents** found by search are dropped before the download queue and counted on the scan screen.
- **Paste a list of targets** in New target: one per line, with a count and a preview of lines that are not valid targets.

## 2.0.0-beta.1: 2026-11-26

First public release of 2.0, published as a **beta** (GitHub Pre-release, tag `v2.0.0-beta.1`). Some things may still break: please report problems through [GitHub issues](https://github.com/SinonApp/FOCA-rs/issues/new/choose); the app's **Report a problem** button prepares the logs for you.

> **APK signed with a new key: uninstall the previous version before installing.** Android will not update 1.x or 2.0 preview builds in place. Export projects you want to keep as encrypted `.foca.enc` files first, then import them after the reinstall.

This release also contains the 1.1.1-1.6 development series, which was never published separately (see below).

### Added
- **Plugins**: declarative (JSON/TOML) and WASM plugins in a sandbox (memory and instruction limits, no file or socket access, scope and passive rules enforced). Four built-in plugins. Enabled plugins run in the "Network and DNS" stage of real scans; a failing plugin never fails the scan.
- **Attack paths and choke points**: ranked chains from leaked documents, logins and secrets to external entry points, with the fixes that break the most chains. Shown in analytics and in HTML, DOCX and Markdown reports.
- **Cloud AI summary** with ten providers (OpenAI, Anthropic, Google Gemini, DeepSeek, xAI, Mistral, Groq, Together, OpenRouter, any OpenAI-compatible API), a live model list from the provider and reasoning ("Thinking") settings. Secrets, names, e-mails and the client name are replaced with placeholders, and you review the prompt before it is sent.
- **AI-assisted executive summary** as an optional section in the report builder.
- **PDF export to a file**: the report is rendered into an A4 PDF on the phone, without the print dialog.
- **Encrypted project export/import** (`.foca.enc`, PBKDF2 + ChaCha20-Poly1305) for handing a project to a colleague.
- **Declarative CLI scenarios**: `foca run scenario.toml` with severity and risk gates for CI.
- **Signed signature databases**: Ed25519-signed updates of KEV, CPE rules and secret patterns with rollback.
- **More document formats**: EPUB, MP3 (ID3), PSD, 7z and embedded OLE objects; metadata cleaning for binary Office (`.doc`, `.xls`, `.ppt`, `.vsd`, `.pub`) and MP4/MOV/HEIC.
- **Passive collectors with API keys**: VirusTotal, SecurityTrails, GitHub Code Search.
- **Opt-in screenshots of web services** with similarity clustering (off by default; never in Passive or out of scope).
- **Interface in English, Ukrainian and Russian**, following the phone language by default, with a switch in Settings → Appearance. Texts from the core, notifications and toasts follow the chosen language.
- **Two Android builds**: `foss` (GPL-3.0 only, no Google libraries) and `play` (adds optional offline OCR via ML Kit), plus an offline licenses screen.
- **Background setup for aggressive firmwares**: a card with autostart and battery checks in Settings → Background execution and on the launch screen, and **Hide from Recents during scans**.
- **Scan resume without opening the app**: after the system kills the app mid-scan, the scan continues in the background (Android 12+: needs unrestricted battery), otherwise a "Continue" notification appears.
- **Scan controls**: pause, skip and restart for a stage, a source or a network sub-step; restarts of finished stages are queued for **Re-run queued**.
- **Network stage progress**: the current step with counters (DNS, resolution, dangling CNAME check, brute force, permutations, RDAP, liveness, TLS), and a slow-DNS warning with **Skip brute force**.
- **Bulk out-of-scope handling**: select candidates or "All subdomains of …", then **Add to scope and scan**.
- **App lock**: PIN asked at launch, auto-lock, panic PIN that wipes all data, clipboard clearing after 30 seconds.
- **Beta channel**: a "Beta" label, a first-run note and **Report a problem** (logs ZIP to `Download/FOCA-rs` and the GitHub issue form).
- **Standards on finding cards and in reports**: NIST SP 800-53 r5 (same codes as НД ТЗІ 3.6-006-24), GDPR and Law of Ukraine 2297-VI for personal data, a CWE Top 25 (2025) mark.
- External links (for example "How to get a key") open in the system browser.

### Changed
- **Targets are network targets only**: domains, `*.domain`, URLs, IP addresses, CIDR networks and IP ranges. E-mail addresses, person and organization names and ASNs are no longer accepted as targets; IP targets go straight into RDAP, InternetDB, liveness, TLS and port checks.
- **Standards refreshed** to OWASP Top 10:2025 and MITRE ATT&CK v20; НД ТЗІ 2.5-004-99 and 3.7-003-05 are marked as applying to КСЗІ-certified systems only. Reports print the edition of each standard.
- **Screenshots are allowed by default**; blocking them is now an opt-in switch in Settings → Security.
- **Reports**: findings are numbered F-1…F-n in the same order in HTML, Markdown and DOCX; Markdown and DOCX now carry the same sections as HTML (ports, infrastructure, website, chronology, host software); out-of-scope findings no longer raise the risk level.
- **Documentation** is English-first, with Russian user docs in `docs/ru/`. Internal plans and logs were removed from the repository.

### Removed
- **On-device AI**: the local model and its settings are gone; old `provider: "local"` settings migrate to a cloud provider.

### Fixed
- Web audit findings built from archived (Wayback) headers are no longer presented as findings on the live site.
- CISA KEV: fewer false "likely" matches on supported branches and OS backports; duplicate KEV findings merged per product.
- Port scans no longer probe CDN/cloud or shared addresses found during the scan; liveness, TLS and site search skip them too.
- The document list names what failed (download, HTTP status or parsing) instead of a fixed 403.
- Report preview and the Before/After screen scroll to the end; long labels no longer clip on narrow screens.
- Back navigation restores the scroll position; navigation stays behind the PIN lock until you unlock.
- Captcha check opens with the engine name in your language and a passed check applies on the next run.
- Android: the PDF print driver, Kotlin build of both flavors, scan service double start, and the captcha bar under the status bar.
- Many smaller fixes in CSV/Markdown escaping, report dates, device info in exported logs and plugin toggles.

### Security
- The passive profile cannot reach target hosts through DNS, redirects or plugins; SSRF checks cover the web screenshotter and plugins.
- Plugin manifests are verified (SHA-256 and Ed25519); scope and SSRF bypasses and WASM memory exhaustion in the plugin runtime are closed.
- Redirects drop authorization headers; proxy, TCP and DER parsing are hardened.
- Parser limits against 7z/EPUB/PDF decompression bombs and integer overflows on 32-bit builds.
- Secret markers are masked in every field of `foca analyze --json`; untrusted values are escaped in the UI, SVG labels and action attributes.
- Telegram tokens, webhook secrets and URL credentials are masked in the request log and error messages.
- A report signature made with another device's key is reported as such, not as tampering.

### Performance
- Dangling CNAME checks run in parallel with a concurrency limit.
- Report template matching is memoized to avoid exponential backtracking.

### Internal
- Crates split into focused modules (for example `foca-engine` → `scan/`, `cmds/`, `analysis/`, `services/`; `foca-net` → `dns/`, `intel/`, `scan/`, `tls/`), with no change in behaviour. Engine integration tests are grouped into a few test binaries.
- Core messages carry codes so the interface can translate them; a static i18n check (`qa/check-i18n.mjs`) runs in the suite.
- CI builds unsigned `foss` and `play` APKs and checks Kotlin, JNI symbols and licenses.

---

## [1.1.1-1.6]: development series (shipped in 2.0.0-beta.1)

### 1.6: Remediation, Report Trust & Interoperability
#### Added
- **Contextual Remediation Playbooks (`finding_playbook`)**: localized (`uk`/`ru`/`en`) step-by-step remediation plans in `foca-analysis::playbooks` covering `standards.toml` codes, infrastructure rules, and finding categories, with owner roles, effort estimates, safe commands (never interpolating raw secrets or evidence), and verification checklists.
- **Chain of Custody & Hardware Report Signing (`report_verify`)**: `CustodyRecord` manifest (`foca-report::custody`, opt-in via `opts.custody = true`), automatic `.sha256` sidecar, and `.sig.json` signature backed by hardware `ECDSA P-256` keys in Android Keystore (`ReportSigner.kt`, `NativeSigner`).
- **Pure-Rust DOCX Report Generator (`I-18`)**: `foca-report::docx` (`zip` + `quick-xml`) with an embedded severity distribution PNG chart (`word/media/chart_sev.png`), all 6 templates (`full`, `brief`, `data`, `executive`, `compliance`, `lab`), `uk`/`ru`/`en` localization, and `SecretMode::Hide` by default.
- **STIX 2.1, Nuclei & `httpx` Exports**: OASIS STIX 2.1 JSON bundle (`foca-report::stix`) with deterministic IDs and forced secret/PII masking, plus in-scope target `.txt` lists for `nuclei -l` and `httpx -l`.
- **Optional Offline OCR (`I-6`)**: `OcrProvider` trait (`foca-engine::ocr`, disabled by default via `settings.ocr.enabled = false`) and Android ML Kit Text Recognition + `PdfRenderer` (isolated to the `play` flavor in 2.0.0) with FTS5 indexing and PII masking.

### 1.5: Event Monitoring, Breach Checks & Quick Tools
#### Added
- **HIBP Passwords via k-Anonymity (`secret_hibp_check`)**: pure-Rust SHA-1 (RFC 3174) in `foca-net::hibp`, sending only the 5-character hash prefix to `https://api.pwnedpasswords.com/range/{prefix}` with `Add-Padding: true`, opt-in from findings, secrets, and Quick Tools.
- **Corporate Login Patterns & Contextual Pentest Wordlist (`wordlist_preview`)**: `foca-analysis::wordlist` (11 login patterns, KMU-2010 / ICAO transliteration, `DOMAIN\login` and `login@domain`, contextual wordlist strictly excluding project secrets and PII).
- **Event Alerts & Risk Trend (`alert_rules_get`, `alert_rules_set`, `alert_test`, `risk_trend_get`)**: `foca-engine::alerts` (9 diff-based trigger rules, deduplication, Telegram & Webhook delivery with tokens/URLs stored exclusively in Android KeyVault `tg_bot`/`webhook`), plus risk-trend SVG chart on the Monitoring screen.
- **Quick Tools & Scan Queue**: `/tools` (`tool_file`, `tool_mail_domain`, `tool_host`, `tool_secret`, `tool_log`) and `/queue` (`queue_add`, `queue_list`, `queue_pause`, `queue_resume`, `queue_remove`, `queue_clear`).

### 1.4: Analytics, Visualization & Document Hygiene
#### Added
- **Layered Relationship Graph** (People → Documents → Workstations → Servers → PKI/Domains): layer toggles with counts, expandable same-type node clusters, and **Link Chain** mode tracing a file or finding to its server and domain.
- **Internal Network Map (`/p/netmap`)**: AD domain → servers by role → workstations → users reconstructed from UNC paths, LNK shortcuts, printers, `Received` headers, RDP/ICA, and CDP/AIA URLs, with provenance and confidence per node.
- **Year-by-Year Timeline & 7×24 Activity Heatmap** (formats, software, CT certificates, working hours vs. off-hours share), **Org Chart** with justifications, **Metadata Anomalies**, and **Document Versions & Copies**.
- **Offline CISA KEV**: offline product lookup across document metadata and host technologies with clear confidence caveats.
- **Web Audit** (recon source `webaudit`): passive (0 target requests); standard (GET source maps and API documentation); full (CORS, OPTIONS/TRACE/PROPFIND, GraphQL: never sends PUT/DELETE); CSP domains routed to in-scope hosts or out-of-scope candidates.
- **Document Hygiene**: A-F grade per set and per file with remediation steps; full PDF rewrite stripping old revisions; ODF, Office XML-DSig, and data-connection cleanup; **Before / After** screen with `"0 metadata · valid file"` self-check; pre-publication check wired to the Rust core.
- **Android Share Target ("Share → Check in FOCA-rs")**: inspect files shared from Telegram, e-mail, or browsers offline without creating a project and share the cleaned copy onward.
- **Report Templates & Security Standards**: Executive (1-page), KSZI / Compliance, and Lab templates (`uk`/`ru`/`en`) with inline SVG diagrams; MITRE ATT&CK, CWE, OWASP Top 10:2021 & WSTG v4.2, ISO/IEC 27001:2022, ND TZI 2.5-004-99 and 3.7-003-05 chips and compliance tables with auditor disclaimer.
- **Reference Case**: one-tap offline import of 12 synthetic documents for the fictional company "TOV Pryklad".
#### Fixed
- OOXML cleaning previously left XML/VBA signatures, external data connection strings, PivotTable `refreshedBy`, and external chart workbook paths intact.
- Completed parser fuzzing campaign (~1.10 billion inputs across 16 formats, PDF, and OOXML): 0 panics, 0 hangs.

### 1.3: FOCA Format Parity & Document Forensics
#### Added
- **New Formats**: Windows LNK shortcuts, EML/MSG e-mails (Reply-To, `Received` chain, `X-Originating-IP`, Microsoft 365 tenant, X.500, attachments), ICS calendars, VCF contacts, Visio, Publisher, InDesign, WordPerfect/Works, MP4/MOV/HEIC media (device, serial number, GPS), and recursive ZIP archives (with Zip-Slip protection).
- **Document Forensics**: PDF/Office/VBA digital signatures and Ukrainian QES (КЕП: signer, organization, `ЄДРПОУ`, masked `РНОКПП`, CA/ACSK, TSA timestamp, post-signing edits), PDF revisions with removed-text diff, bad-redaction detection, hidden text (`w:vanish`) and hidden rows/columns/sheets, data connections, XMP edit history, and scanned PDFs without text layer (~25 new finding codes).
- **Personal Data (PII) Masking**: checksum-validated detection (`РНОКПП`, `ЄДРПОУ`, IBAN, payment cards, passports, ID cards, phones, classification markings) **masked before writing to the database**; cloud share links and URL tokens.
- **Full-Text Document Search (SQLite FTS5)**: phrase, exclusion, and prefix search with secrets and PII masked in snippets.
- **Custom Search Rules**: 5 built-in presets and user regex rules with live sample tester and instant finding recalculation.
- **Offline Folder / Files / ZIP Analysis**: Android SAF picker with progress, cancellation, resource limits, and zero network requests.
- Fuzz artifact parsing (`.env`, `.git/config`, `.ovpn`, `package.json`, `composer.json`) into masked summaries.
#### Fixed
- PDF text extraction previously included raw binary PKCS#7 signature blobs.
- Crafted 65535×65535 JPEG inputs previously consumed ~19 s and ~500 MB RAM: now rejected immediately.
- Section header "All" buttons widened to meet the 44 px minimum tap target.

### 1.2: Subdomains & Infrastructure Intelligence
#### Added
- **Subdomain Brute-Force & Permutations**: top-1500 (Standard), top-5000 (Full), custom wordlist, or off, with adaptive AIMD pacing and multi-level wildcard filtering; `alterx`/`gotator`-style permutations from discovered names and document metadata tokens; in-scope PTR sweeps; NSEC walking (Full only).
- **DNS Infrastructure Profiling**: organizational SaaS map (TXT/SPF/MX/CNAME), passive Microsoft 365 / Entra ID tenant discovery, mail/DNS policies (`BIMI`, `MTA-STS`, `TLS-RPT`, `CAA`, `DNSSEC`), offline CDN/cloud IP prefix classification with origin candidates, CT certificate history, abandoned hosts, `O=` sibling domain pivots, host roles, and priority scoring.
- **X.509 / TLS Inspector**: chain verification, expiry, CA/CAA audit, internal PKI hints; Full profile adds legacy TLS 1.0/1.1, weak ciphers, STARTTLS (`SMTP`/`IMAP`/`POP3`/`FTP`/`PostgreSQL`/`RDP`), and no-SNI origin probing.
- 29 new `infra.*` and `mail-*` finding codes, report sections (`TLS Certificates`, `Mail Policies`, `SaaS & Cloud`, `Out-of-Scope Candidates`), and `scan_skip_source` support for `subdomains`/`tls`.
#### Fixed
- Proxy address field remained hidden when Orbot profile was enabled via API without the Orbot UI flag.
- Aligned launch wizard Standard profile modules with core engine defaults (`infra`, `subdomains`, `tls`).

### 1.1.2: Autonomous Background Monitoring
- Headless JNI engine execution via Android WorkManager (≤ 8 min checkpoint budget, resumed afterwards) and live handoff when the UI opens during a background run.
- Data safety: exclusive `engine.lock` (`DataDirLock`), SQLite WAL + `busy_timeout`; WebView sources report `skipped_headless` in background mode (without marking snapshots incomplete).
- Last scheduled run diagnostics card on the Monitoring screen.

### 1.1.1: Network Reliability & Canaries
- Network tampering detector (`foca-net::canary`: TCP/DNS/TLS canaries) and protocol-verified host liveness (`tcp_alive_checked`) preventing VPN/proxy false positives.
- `v2rayNG` proxy preset (`127.0.0.1:10808`), proxy checker with exit IP classification (`ip_kind`), per-HTTP-group proxy routing, and Android WebView `localhost` bypass.
- Structural CAPTCHA detector (`detect_captcha_signals`), manual CAPTCHA test button, optional AlienVault OTX key, `ScanEnv` incomplete-snapshot protection in diffs and reports, and canonical `i18n::core_message` diagnostic keys.

---

## [1.1.0] - 2026-11-21

Summary: CAPTCHA resilience for keyless dorking (shared search-engine queue with failover and one-tap manual verification), Yahoo and public SearXNG pool sources, **new Android package ID `app.sinon.focars`**, and audience-organized documentation (`docs/user`, `docs/dev`, `docs/testing`, `docs/adr`).

> **Important:** Because the Android package ID changed to `app.sinon.focars`, 1.1.0 installs as a **separate application** alongside 1.0.x (projects, settings, and keys are not migrated automatically).

CAPTCHA investigation ([research report](docs/research/captcha.md)): residential ISP IP reputation is the primary trigger; the engine now avoids leaking automation signals and preserves dorks across healthy engines.

### Added
- **Dork Failover**: shared scan dork queue across search engines, an engine hitting CAPTCHA hands remaining queries to healthy engines; `OR`-grouped filetype queries, per-engine query budgets, 24 h result cache, 6-14 s jittered pacing.
- **Yahoo (via WebView)** and **public SearXNG pool (via WebView)** from `searx.space` (uptime ≥ 90 %, skipping rate-limited instances).
- Single **"Verify (N)"** button on the Scan screen for queued CAPTCHA checks and **"Settings → Network → Warm up search engines"** to save cookies ahead of time.
- **Debug → Search**: built-in browser fingerprint page + per-engine telemetry log.
### Changed
- Built-in WebView matches standard mobile Chrome on the device (`X-Requested-With` disabled, real mobile UA without `; wv`, images enabled, attached to app window). No automatic CAPTCHA solving.
- Android package renamed to `app.sinon.focars` with `qa/check-jni.sh` verifying package and `Java_*` JNI exports.
- Documentation organized into `docs/user`, `docs/dev`, `docs/testing`, `docs/adr`, and `docs/history`, validated by `qa/check-docs-links.py`.
### Tests
- `foca serve --test-net` became 100% offline with `NetConfig.local_only` blocking external hosts in `qa/real-e2e.sh`.

---

## [1.0.1] - 2026-11-21

Field fixes from real-device testing (AdGuard local VPN + v2rayNG).

### Fixed
- **False-positive open ports under local VPN/proxy**: 3 canary ports per host, TEST-NET intercept probe (`192.0.2.1`, `198.51.100.1`), and > 40% silent-open heuristic marking unreliable port scans cleanly and removing stale false findings.
- **Port banner verification**: High/Critical severity only on protocol-verified services (Docker, Redis, Elasticsearch, MongoDB, RDP, SMB, PostgreSQL, FTP/SSH/MySQL); FTPS (990) and Docker TLS (2376) handled accurately; admin-panel banner detection; one finding per IP:port.
- **WebView CAPTCHA handling**: instant detection, visible verification WebView sharing the cookie jar, `scan_retry_source` retry without automatic bypass.
- **HTTP 429 & Common Crawl resilience**: `Retry-After` backoff, per-scan OTX cooldown on 429, fallback across up to 5 Common Crawl indexes on 504/timeout.
- **Scope safety**: out-of-scope IP promotion limited to single IPs (never auto-expanding `/24` on shared hosting); separate target vs. third-party request logs in reports.
- **Crawler, reports, fuzzing, software & people polish**: redirect-aware deduplication, local device timestamps with timezone offset in reports, soft-404 annotations in request logs, clean CPE product names, historical EOL severity adjustment, and generic-word filtering for service accounts.

---

## [1.0.0] - 2026-11-21

First full release: website reconnaissance (favicon hash, technologies, JS endpoints/secrets, robots/sitemap, cloud buckets), coherent browser client profiles, TCP port scanner, scheduled WorkManager monitoring with notifications, redesigned wizard and offline Help, 3D GPS globe, and resolution of 16 security/logic review findings.

### Added
- **TCP Port Scanning** (`foca-net::ports`, active profile only, top-100/top-1000/custom lists, banner probes, service findings, CLI `foca ports`).
- **Scheduled Monitoring**: Android WorkManager rescans (Passive/Standard only: active profiles rejected by core `monitor_active`) and completion notifications.
- **Website Reconnaissance** (`foca-recon`: 131 tech rules, MurmurHash3 favicon hash, JS endpoints & masked secrets, Wayback robots/sitemap/security.txt, cloud buckets, `grep.app`, CLI `foca recon`, `snapshot.recon` in [docs/API.md](docs/API.md)).
- **Coherent Browser Profiles**: Auto Chrome/Windows, Chrome/Android, Firefox, Safari, Honest FOCA-rs, Custom with ordered Title-Case headers and GREASE `Sec-CH-UA`.
- **Keyless WebView Dorking**: Startpage, Brave Search, and Mojeek via hidden Android WebView (`RenderFetcher.kt`, `foca-search::render`).
- Repository structure, documentation, CI, and Rust core ([docs/ROADMAP.md](docs/ROADMAP.md)).
### Changed
- Replaced hardcoded User-Agents with coherent scan profiles; moved keyed search sources to the optional keyed section.
### Fixed
- Process-death recovery (HyperOS/MIUI swipe-kill): atomic scan checkpointing, core-confirmed `scan_status`, automatic resume without duplicates, Xiaomi background-lock hints.
- First-run footer buttons, snackbar/FAB spacing, DOCX reviewer role attribution (`word/people.xml`).
### Removed
- Google Custom Search (`gcse` source and key).

---

## [0.2.0] - 2026-11-20: Full Mobile UI Design (Demo Backend)
### Added
- Complete mobile UI (projects, target/scope wizard, scan progress, swipeable findings, entity cards, reports/export, settings, lock screen, graph, globe map, timeline, monitoring, plugins, AI summary, onboarding, tablet layout).
- Native Android system-bar insets, theme bar synchronization, and 130% `textZoom` cap.
### Changed
- Android-only product scope; unified design language and terminology.

## [0.1.3] - 2026-11-19
- Seal app icon, mobile layout fixes, and `textZoom` handling.

## [0.1.2] - 2026-11-19
### Fixed
- Startup crash caused by 16-bit PNG launcher icons (converted to 8-bit RGBA).

## [0.1.1] - 2026-11-19
- Crash report screen and multi-ABI packaging (`arm64` / `armv7` / `x86_64`).

## [0.1.0] - 2026-11-19
- Initial UI prototype.
