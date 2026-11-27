# Sources

↑ [User Guide](README.md) · [Documentation](../README.md)

- [Source Table](#source-table)
- [Source Statuses](#source-statuses)
- [API Keys](#api-keys)
- [Source Additions through 2.0](#source-additions-through-20)

FOCA-rs 2.0 includes 42 built-in sources: 39 entries in `SOURCES` (`crates/foca-engine/src/scan/sources.rs`, 37 visible in Settings → Sources across five groups plus a collapsed With API key section, and 2 enabled by profile modules: `dns` and `fuzz`), plus 3 passive keyed collectors wired in 2.0 (`vt` VirusTotal v3, `st` SecurityTrails, and `github` GitHub Code Search). Additional passive or scoped sources can also be installed as [sandboxed plugins](settings-network.md#sandboxed-plugins).

Google is not used directly as a source ([ADR-0007](../adr/0007-search-engines-via-webview.md)); Google results are accessed only indirectly through Startpage.

Columns: Access, whether an API key or embedded browser is needed; Contacts target: whether the source sends packets to target infrastructure (Passive = never); Profiles: where the source runs by default.

## Source Table

| ID | Source | Group | Access | Contacts target | Profiles | What it provides |
|---|---|---|---|---|---|---|
| `startpage` | Startpage (built-in browser) | Search engines | Keyless, built-in browser (Android only) | Passive | All | Google results via Startpage (`site:domain filetype:pdf…`); hidden WebView solves JS proof-of-work automatically |
| `brave_web` | Brave Search (built-in browser) | Search engines | Keyless, built-in browser (Android only) | Passive | All | Independent Brave Search index without an API key via built-in browser |
| `yahoo` | Yahoo (built-in browser) | Search engines | Keyless, built-in browser (Android only) | Passive | All | Bing results via Yahoo (`site:`, `filetype:`, `OR`); EU networks may prompt cookie consent ("Complete verification") |
| `searx_pool` | Public SearXNG pool (built-in browser) | Search engines | Keyless, built-in browser (Android only) | Passive | All | Pool of healthy public SearXNG instances (`searx.space`, uptime ≥ 90%) with health checks; rate-limited instances are rotated out |
| `mojeek` | Mojeek (dorks) | Search engines | Keyless | Passive | All | Uses built-in browser when available; best-effort (datacenter IPs often trigger ALTCHA) |
| `ddg` | DuckDuckGo (dorks) | Search engines | Keyless | Passive | All | `site:domain filetype:pdf…`: best-effort, may trigger CAPTCHA |
| `bing` | Bing (dorks) | Search engines | Keyless | Passive | All | Best-effort, may trigger CAPTCHA |
| `wayback` | Wayback Machine | Archives | Keyless | Passive | All | Historical document URLs and raw archived snapshots (`web.archive.org`, never touches target) |
| `cc` | Common Crawl | Archives | Keyless | Passive | All | Latest 3 web crawl snapshots, or a deep sweep over the last N years or all snapshots (Settings → Sources → Search depth, or the wizard): paced, retried, resumable, see [Deep Common Crawl](#deep-common-crawl) |
| `arquivo` | Arquivo.pt | Archives | Keyless | Passive | All | Portuguese web archive with file-type search |
| `crt` | crt.sh | Subdomains | Keyless | Passive | All | Subdomains from Certificate Transparency (CT) logs |
| `crtname` | crt.name | Subdomains | Keyless (higher limit with key) | Passive | All | CT mirror index for subdomains |
| `scanmalware` | ScanMalware | Subdomains | Keyless | Passive | All | Subdomains from CT/DNS feeds |
| `certspotter` | CertSpotter | Subdomains | Keyless (higher limit with key) | Passive | All | CT logs (low rate limit without key) |
| `anubis` | Anubis | Subdomains | Keyless | Passive | All | Subdomain aggregator |
| `hackertarget` | HackerTarget | Subdomains | Keyless (higher limit with key) | Passive | All | Subdomains (~50 free queries/day without key) |
| `rapiddns` | RapidDNS | Subdomains | Keyless | Passive | All | Passive DNS subdomain records |
| `subcenter` | subdomain.center | Subdomains | Keyless (higher limit with key) | Passive | All | Subdomain aggregator |
| `thc` | THC (`ip.thc.org`) | Subdomains | Keyless | Passive | All | Subdomain & reverse DNS intelligence |
| `shodanct` | Shodan CT | Subdomains | Keyless | Passive | All | CT-derived subdomains from Shodan |
| `otx_dns` | OTX Passive DNS | Subdomains | Keyless (higher limit with key) | Passive | All | AlienVault OTX passive DNS; frequently rate-limited without an optional OTX key |
| `subdomains` | Subdomain brute-force & permutations | Subdomains | Keyless | Target (DNS to target NS) | Standard (top 1,500), Full (top 5,000) | Wordlist brute-force, permutations from discovered names & document metadata, PTR on in-scope IPs; Full adds NSEC walking |
| `otx_url` | AlienVault OTX (URLs) | Recon | Keyless | Passive | All | Known historical URLs for the domain |
| `urlscan` | urlscan.io | Recon | Keyless | Passive | All | URLs from public web scans (low unauthenticated limit) |
| `internetdb` | Shodan InternetDB | Recon | Keyless | Passive | All | Passive cache of open ports, CPEs, and CVEs by IP |
| `hudson` | HudsonRock | Recon | Keyless | Passive | All | Domain URLs surfaced in infostealer intelligence logs |
| `recon` | Site recon: tech, favicon, JS | Recon | Keyless | Passive (archived) / Target (live) | All | Technology versions, analytics IDs, favicon hash, JS endpoints & masked secrets; optional WebView screenshots (`pHash`) in Standard/Full |
| `webaudit` | Web audit: headers, CSP, source maps, APIs | Recon | Keyless | Passive: cached/archived responses only; Standard: `GET`; Full: + `OPTIONS`/`TRACE`/`PROPFIND`, CORS | All | Security headers, CSP domains (in-scope → hosts, external → out-of-scope candidates), cookies, `.js.map`, Swagger/OpenAPI/Actuator/`openid-configuration` (`PUT`/`DELETE` never sent) |
| `wellknown` | `robots.txt` / `sitemap.xml` / `security.txt` | Recon | Keyless | Passive | All | Retrieved from Wayback snapshots in Passive: hidden paths, sitemap URLs, security contacts |
| `buckets` | Cloud storage buckets | Recon | Keyless | Passive (discovery) / Active (listing) | All | S3/GCS/Azure links extracted from pages and documents; open-listing probes run only in Full |
| `grepapp` | grep.app (public code) | Recon | Keyless | Passive | All | Domain mentions across public code repositories (best-effort; bot protection may apply) |
| `ports` | TCP port scan | Recon | Keyless | Target (Active) | Full | Open TCP ports, service banners, and versions on live in-scope hosts (with VPN canary protection) |
| `tls` | TLS/X.509 inspector | Recon | Keyless | Target | Standard, Full | Certificate validity, chain, SANs, CAA, internal PKI; Full adds TLS 1.0/1.1, weak ciphers, STARTTLS, and direct-IP checks without SNI |
| `crawler` | Site crawler | Crawler | Keyless | Target | Standard, Full | Crawls target websites from their pages and sitemaps; collects documents, photos for EXIF and files on public external storage the site links to |
| `brave` | Brave Search API | With API key | Key required | Passive | All (if key set) | Official Brave Search API as one more dork engine. No free tier: Brave needs a card and every plan gets a $5 monthly credit (about 1000 queries); 429/quota stops it for the scan |
| `searx` | Custom SearXNG | With API key | URL required | Passive | All (if URL set) | Your own SearXNG instances (HTTPS, public host, JSON enabled; configured in API Keys), asked before the public pool, see [Own SearXNG instance](searxng.md) |
| `shodan` | Shodan (banner cache) | With API key | Key required | Passive | All (if key set) | Ports and service banners from Shodan's database without touching the target |
| `vt` | VirusTotal v3 | With API key | Key required | Passive | All (if key set) | Passive subdomains and historical URLs via `/api/v3/domains/{domain}` (`x-apikey`, never logged) |
| `st` | SecurityTrails | With API key | Key required | Passive | All (if key set) | Passive subdomain history via `/v1/domain/{domain}/subdomains` (`APIKEY`, never logged) |
| `github` | GitHub Code Search | With API key | Key required | Passive | All (if key set) | Public code mentions (`.env`, `.ovpn`, `.pdf`, configs) via GitHub Search API (`Authorization: Bearer`, never logged) |
| `plugins` | Sandboxed plugins (WASM & declarative) | Network | Keyless (as the plugin defines) | Passive in Passive/Standard (target hosts blocked); Full allows `net:scoped` plugins in scope | All (if a custom plugin is enabled) | Runs every enabled custom plugin once per target domain: extra hosts and findings; a failing plugin ends the source as `error` without failing the scan, see [Sandboxed Plugins](settings-network.md#sandboxed-plugins) |
| `dns` | Authoritative DNS / CT | Network | Keyless | Target (DNS to target NS) | Standard, Full | DNS records, SPF/DMARC/DKIM, dangling CNAMEs: stage Network & DNS |
| `fuzz` | Forgotten file discovery | Active | Keyless | Target (Active) | Full | Wordlist path/backup/vhost discovery (`foca-fuzz`) |

Target-touching sources (`crawler`, `ports`, `subdomains`, `tls`, `fuzz`) are automatically excluded from Passive scans. You can skip `subdomains` and `tls` during a run with Skip source up through the Ports stage. DNS-based infrastructure checks (`infra`: SaaS map, Microsoft 365 tenant, mail policies, CDN/cloud ranges, CT history) run in all profiles via the device resolver and public Microsoft endpoints without contacting target servers. Any source disabled in Settings → Sources is never queried.

## Site Crawler

The crawler runs only in the Standard and Full profiles. It starts from the target home pages, the `Sitemap:` lines of robots.txt and `/sitemap.xml` (sitemap indexes and `.gz` included).

- **Limits** (Settings → Site crawl, or the wizard's Advanced block for one scan): depth 5, 1000 pages and 20 minutes per scan by default. When a limit stops the crawl, the next scan continues from the pages not crawled yet ("Continue an unfinished crawl").
- **Traps**: calendars, endless filters and session parameters are crawled by URL template with a cap; tracking parameters are stripped; logout and delete links are never opened; `rel=nofollow` is honoured when enabled.
- **Mirrors**: a start host that redirects to another start host or serves the same start page (typically `www` and the bare domain) is crawled once: only paths new to it are fetched.
- **Pace**: the crawler uses the network rate limit. A 429 or 503 answer halves the pace for that host and waits for `Retry-After`; when it keeps happening the host is no longer crawled in this scan and the scan screen says so. FOCA-rs does not get around bot protection or captchas. While the scan is paused the crawl waits; its time limit keeps running, so a long pause ends the crawl and the next scan continues it.
- **App sites** (React, Flutter and similar): when a page is an app shell with almost no links, Android renders it in the hidden built-in browser (up to 30 pages per scan) and the links come from the rendered page. Desktop and CLI builds use the HTML as is, and the scan shows a warning with the number of such pages.
- **Files on public external storage**: links from in-scope pages to Google Drive, Google Docs/Sheets/Slides, OneDrive, Dropbox and SharePoint count as target documents. Exactly those items are downloaded (a public folder: up to 200 files, 1000 in total), these files share the scan's document limit with the other sources, nothing else on the storage host is browsed, and the request log marks these requests as `linked_storage`. Private files are recorded as private, not as errors. Google Docs/Sheets/Slides come as exports (PDF, DOCX, XLSX): their metadata is written by Google, so analysis never attributes authors from them. Turn this off with "Files on external storage linked from the site".
- **Photos for EXIF**: up to 300 images and 200 MB per scan (never above the traffic limit), camera formats first; icons and thumbnails are skipped. Images from every source count against these limits, not against the document limit. With "Photos for EXIF" off, image links are skipped unless the run's document types ask for images.
- **Links inside documents**: web links in downloaded documents (for PDF, URI annotations) that point to in-scope documents or linked storage files are downloaded too, up to 2 steps deep, within the document limit.
- **Provenance**: every document found this way shows where it came from in its card: the page that linked it, the document the link was found in, the storage provider and a Google export note.

## Source Statuses

Displayed on the Scan screen and in Settings → Sources:

| Status | Meaning |
|---|---|
| `ok` / Responded | Data collected (`· found N`) |
| `error` / No response | Network failure or timeout; the scan continues without this source |
| `captcha` / Blocked | Search engine showed a challenge or blocked the IP, see [CAPTCHA & Manual Verification](settings-network.md#captcha--manual-verification) |
| `verify` / Needs verification | CAPTCHA in built-in browser: tap Complete verification and the source retries automatically |
| `rate_limited` / Rate limit | HTTP 429 or 503 (e.g., OTX): the source honours `Retry-After`, slows down, and after repeated limits stops for this scan; what it collected is kept |
| `skipped` / Skipped | Skipped manually (Skip source) or disabled in settings |
| `no_key` / No API key | Keyed source without a configured key: skipped cleanly without failing the scan |
| `unavailable` / Built-in browser required | WebView sources (`startpage`, `brave_web`, `yahoo`, `searx_pool`) outside Android (CLI, `foca serve`) |
| `skipped_headless` | WebView source skipped during an autonomous headless background monitoring run (no UI window) |
| `unreliable` / Unreliable | Port scan interfered with by a local VPN/proxy, see [VPN & Port Scans](settings-network.md#vpn-adguard--unreliable-port-scans) |

## Deep Common Crawl

The public Common Crawl index is unreliable: snapshots answer 400/404/502/504 at random between good answers, and a fast sweep over all of them fails on about half. FOCA-rs therefore:

- asks the index at most once every 3 seconds (`settings.search.cc_pace_s`, never lower against the public index) and retries 5xx/400/timeouts with a growing pause;
- treats 404 as "no captures" and uses `showNumPages` to skip empty snapshots before fetching pages;
- filters by status and file type on the server, then keeps every URL once with its first and last capture;
- gives a snapshot one retry after a connection failure (refused, TLS drop) and stops the sweep for this scan after three unreachable snapshots in a row;
- stops a sweep over N years once the six newest answered snapshots hold no capture of the domain (older crawls would not either); "all snapshots" still checks every one;
- runs a deep sweep (last N years or all snapshots) in the background: it starts with the Search stage, but the stage ends when the other sources end. The sweep keeps going during the next stages within `settings.search.cc_minutes` (default 5 per scan); documents it finds later are downloaded when the next stage starts, and whatever is still left 10 seconds after the report starts continues in the next scan;
- caches results per domain on the device: a rescan within 24 hours sends no request for finished snapshots, and an unfinished deep sweep continues in the next scan;
- falls back to the Wayback copy when a Common Crawl URL is dead now.

## Postponed searches

When every search engine shows a CAPTCHA, the dorks that no engine could run are kept for the project and retried by themselves: slowly, one by one, after `settings.search.dork_retry_min` minutes (default 15) while the scan is still running, and at the next scan, where they run first. The scan screen shows "N searches postponed, will retry" and a **Retry now** button. CAPTCHAs are never solved automatically.

## API Keys

API keys are strictly optional ([ADR-0010](../adr/0010-api-keys-optional.md)): everything works out of the box except the dedicated keyed sources (Brave Search API, Custom SearXNG ([setup](searxng.md)), Shodan, VirusTotal v3, SecurityTrails, GitHub Code Search), optional higher-tier quotas (such as OTX), and optional Cloud AI / Telegram & Webhook alerts.

Keys are entered only under Settings → API Keys (`/settings/keys`), stored encrypted in Android Keystore (`AES-256-GCM`, `KeyVault.kt`), scrubbed from `request_log` and exported diagnostic archives, and never written to project databases or reports.

## Source Additions through 2.0

- **1.1:** Yahoo and the public SearXNG pool (via embedded browser), shared dork queue with cross-engine failover, `OR`-grouping, 24-hour cache, and unified Complete verification (N).
- **1.2:** Subdomain brute-force & permutations (`subdomains`), TLS/X.509 inspector (`tls`), SearXNG pool health checks, and DNS infrastructure intelligence (`infra`).
- **1.4:** Access-level-aware Web Audit (`webaudit`).
- **2.0 beta:** Deep resumable Common Crawl sweep with a per-domain cache and Wayback fallback, postponed dorks after CAPTCHAs ("Retry now"), own SearXNG instances before the public pool, Brave Search API as a dork engine, unified 429/503 slow-down in search sources, site crawler (`crawler`) with files on public external storage and links inside documents.
- **2.0:** Native passive API collectors for VirusTotal v3 (`vt`), SecurityTrails (`st`), and GitHub Code Search (`github`), opt-in WebView screenshots with `pHash` clustering, and extensible sandboxed plugins (`/settings/plugins`). See [ROADMAP](../ROADMAP.md).
