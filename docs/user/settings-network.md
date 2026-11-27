# Settings, Network, Cloud AI & Plugins

↑ [User Guide](README.md) · [Documentation](../README.md)

- [Settings Map](#settings-map)
- [Browser Profile (User-Agent)](#browser-profile-user-agent)
- [Proxy, Tor, v2rayNG, Kill Switch & DNS](#proxy-tor-v2rayng-kill-switch--dns)
- [Speed: Concurrency, RPS & Timeouts](#speed-concurrency-rps--timeouts)
- [Subdomain Enumeration & Network Limits](#subdomain-enumeration--network-limits)
- [VPN, AdGuard & Unreliable Port Scans](#vpn-adguard--unreliable-port-scans)
- [CAPTCHA & Manual Verification](#captcha--manual-verification)
- [Cloud AI: 10 Providers, Live `/models` & Thinking](#cloud-ai-10-providers-live-models--thinking)
- [Sandboxed Plugins](#sandboxed-plugins)
- [Signed Signature Updates, Language, Licenses & Android Builds](#signed-signature-updates-language-licenses--android-builds)

## Settings Map

`/settings` (full schema in `Settings`, see [docs/API.md](../API.md)):

| Section | Route | What you configure |
|---|---|---|
| API Keys | `/settings/keys` | Brave Search API, SearXNG URL, Shodan, OTX, VirusTotal v3, SecurityTrails, GitHub Code Search, Cloud AI key, Telegram/Webhook tokens (all in Android KeyVault) |
| Sources | `/settings/sources` | Toggle sources by group, inspect last poll status |
| Plugins | `/settings/plugins` | Manage built-in & custom sandboxed plugins (declarative JSON/TOML & WASM), passive dry-run test |
| Wordlists | `/settings/wordlists` | Path discovery & subdomain wordlists (built-in, SecLists downloads, custom), fuzzing rate & budget |
| Network & Proxy | `/settings/network` | HTTP/SOCKS5 proxy, Tor (Orbot), v2rayNG preset, proxy health checker, per-group proxy routing, kill switch, browser profile, concurrency/RPS/timeouts, DNS, custom ports |
| Site crawl | `/settings/crawl` | Crawl limits (depth `5`, `1000` pages, `20` min per scan by default), App pages through the browser (`30`), Continue an unfinished crawl, Honour rel=nofollow, Files on external storage linked from the site, Photos for EXIF (`300` images, `200 MB`), Links inside documents (depth `2`), see [Site Crawler](sources.md#site-crawler) |
| Traffic & Power | `/settings/power` | Wi-Fi only, mobile data cap, battery threshold, thermal pause, charging only |
| Background Execution | `/settings/battery` | Notifications and battery status, an autostart/battery card on aggressive firmwares, Hide from Recents during scans, vendor-specific guides (Xiaomi/HyperOS, Samsung, Huawei, etc.) |
| Security | `/settings/security` | PIN asked at launch, auto-lock, biometrics, secrets after fingerprint, panic PIN (wipes all data), clipboard clear after 30 s (only what the app copied), Block screenshots (opt-in, `FLAG_SECURE`), auto-delete projects |
| Appearance & Language | `/settings/appearance` | Live interface language (Auto (System) / English / Русский / Українська), dark/light theme, font density |
| Signature Databases & OCR | `/settings/signatures` | What the analysis matches against (CISA KEV, software and OS signatures, secret rules, standards), catalog age, update check, offline import, rollback + optional on-device ML Kit OCR (`play` flavor only) |
| Cloud AI | `/settings/ai` | 10 cloud AI providers, live `/models` discovery, Thinking (reasoning) parameters, redaction toggles |
| Debug & diagnostics | `/settings/debug` | Core log, request log, crash reports, Share logs; Clear app logs (core, Android, crashes) and Clear request log (project: all, older than 7/30/90 days, or one finished scan); Search tab with WebView fingerprint check & per-engine stats |
| About, Licenses & Terms | `/settings/about`, `/settings/licenses`, `/settings/terms` | App version & build flavor (`foss`/`play`), auto-generated offline license inventory, Terms of Use |

Drop-down lists across the app (AI provider, model and reasoning level, findings host filter, timeline years, webhook format, plugin settings, User-Agent in the scan wizard) open a panel in the app theme instead of the grey Android dialog.

## Browser Profile (User-Agent)

`settings.net.ua` (also overridable per scan in the launch wizard): `chrome` (default: recent Chrome on Windows), `chrome_android`, `firefox`, `safari`, `honest` (`FOCA-rs/<version>`), or `custom`. Profiles are coherent across User-Agent, Client Hints, and header order (`foca-net::ua`); Chrome/Firefox version strings refresh from public release APIs every 7 days (disable via `ua_update: false`). The embedded search-engine browser uses the phone's own WebView UA stripped of the `; wv` marker (`UaForm.kt`).

## Proxy, Tor, v2rayNG, Kill Switch & DNS

- **HTTP / SOCKS5 / Tor / v2rayNG:** Configure custom HTTP or SOCKS5 proxies (`settings.net.type/addr`), Tor via Orbot (`127.0.0.1:9050`), or an external local v2rayNG proxy (`127.0.0.1:10808`). Use the built-in Check proxy tool (`proxy_check`) to verify connectivity, exit IP class (`ip_kind`), and latency. You can also route specific HTTP source groups through the proxy. The embedded WebView routes through the same proxy (`ProxyController`, with `localhost` bypass); if Android cannot apply the proxy to WebView, requests fail closed rather than leaking directly.
- **Kill switch:** If your VPN or proxy drops mid-scan, the scan immediately stops or pauses (`kill_action: stop|pause`) so your real IP is never exposed. Enforced by Rust policy (`src-tauri/src/policy.rs`) reacting to Kotlin network callbacks (`DeviceMonitor.kt`).
- **DNS:** `dns_mode` supports `auto` (default: routes via DoH through the proxy when a proxy is enabled), `system`, or `doh`. When Android's system Private DNS is enabled, direct UDP DNS queries and `AXFR` may be blocked.
- FOCA-rs never scrapes or auto-selects public/free proxy lists: only proxies explicitly configured by you are used ([ADR-0012](../adr/0012-no-captcha-solving-no-public-proxies.md)).

## Speed: Concurrency, RPS & Timeouts

| Preset | Concurrency | Req/s | Timeout | Recommended for |
|---|---|---|---|---|
| Gentle | 2 | 3 | 30 s | Mobile data, Tor, rate-sensitive targets |
| Normal | 6 | 8 | 15 s | Wi-Fi, most assessments |
| Fast | 16 | 20 | 10 s | Owned servers or fast dedicated proxy |

Manual values have no upper cap: any whole number is saved as typed (concurrency and timeout from `1`, retries from `0`, RPS `0` = no limit). Above the recommended range (concurrency `16`, RPS `20`, hosts at once `8`, timeout below `5 s` or above `120 s`, retries `5`) the field shows a warning, and very high concurrency, RPS or hosts at once, or RPS without a limit, ask for a one-time confirmation. The per-source search timeout defaults to `90 s`. The 429 and bot-challenge slowdowns stay active at any speed. Full table: [API: Limits of manual values](../API.md#limits-of-manual-values).

**Traffic and power** (`/settings/power`): the monthly mobile data cap accepts any size, and `0` or the switch off means no limit. The core counts the bytes it transfers over mobile or metered networks per calendar month in device local time and shows the figure under the limit; when a scan reaches the cap it pauses with reason `mobile_cap`, posts a notification and resumes by itself on Wi-Fi or once the limit is raised. Without a cap and with "Wi-Fi only for heavy modules" off, the screen warns that a scan can use up all mobile data and asks to confirm once. The battery threshold has a manual field next to the slider for any value from `1` to `100 %`. "Wi-Fi only" and "Charging only" stay optional switches. Forgotten file discovery (`foca-fuzz`) uses its own conservative limits under Wordlists (defaults: `5 req/s`, `4` threads, `3,000` request budget, `20 min` cap).

**Hosts at once** (from `1`, default `4`, warning above `8`, also in the launch wizard) sets how many hosts of one scan are worked on at the same time: subdomains and hosts found during the scan, or several targets of a project. It applies to liveness and TLS checks, the port scan, website reconnaissance and site discovery. `1` goes one host after another, as before; over Tor or mobile data `1-2` is kinder to the connection. It does not raise any limit: the global RPS and concurrency above still cap the whole scan, site discovery keeps its rate per host, and its request budget and time are shared by all hosts. If one host answers 429 or shows a bot challenge, only that host stops. Pause, Stop and Skip reach every running host at once, and the scan screen shows *"Hosts: 3 running, 2 done of 7"* with the names of the hosts in progress.

## Subdomain Enumeration & Network Limits

Subdomain brute-force (Standard / Full) runs on an adaptive pace (switching to a conservative DoH preset behind proxies) capped by your global RPS when set below 5. If your ISP or network throttles DNS, FOCA-rs backs off automatically and marks Data → Hosts with *"network throttled DNS"*. If DNS hijacking is detected by the network canary (`dns_hijack`), brute-forcing is skipped automatically (status Skipped) to avoid false hosts. Choose the wordlist in the launch wizard (`off` / `top-1500` / `top-5000` / `custom`; defaults live in `settings.subdomains`).

## VPN, AdGuard & Unreliable Port Scans

Local Android VPN apps (AdGuard in VPN mode, v2rayNG, NetGuard), corporate firewalls, and intercepting proxies terminate every outgoing TCP handshake locally: making nearly every port look "open" even when closed on the target.

Built-in network canary protection (`foca-net::canary` and `foca-net::ports`):

1. Before scanning a host, probes 3 guaranteed-unused canary ports;
2. Once per stage, checks unroutable `TEST-NET` addresses (`192.0.2.1`, `198.51.100.1`);
3. After scanning, checks the heuristic *"> 40% open while almost all remain silent"*;
4. Protocol-level liveness verification (`tcp_alive_checked`) prevents VPN spoofing of alive hosts, alongside DNS and TLS canaries.

When tampering is detected, the TCP port scan source is marked Unreliable, bogus ports are discarded, no port findings are generated, reports display an explicit notice, and stale false port findings are purged. Passive Shodan InternetDB records remain intact.

**Fix:** Temporarily disable the local VPN during port scanning or exclude FOCA-rs from it (AdGuard: *App management → FOCA-rs → Route traffic through AdGuard: Off*; v2rayNG: *Settings → Per-app proxy*), then rescan. Using an explicit SOCKS5 proxy under Settings → Network is fully supported (TEST-NET probes are skipped and canaries run through the proxy).

## CAPTCHA & Manual Verification

Search engines rate-limit automated queries. A CAPTCHA / blocked status never halts the scan: remaining sources proceed normally.

- Startpage, Brave Search, Yahoo, public SearXNG instances (and Mojeek when available) run inside a hidden Android WebView that handles JS proof-of-work challenges automatically and uses structural CAPTCHA detection (`detect_captcha_signals`).
- When a human challenge appears, the source switches to Needs verification with a Complete verification button opening a visible full-screen WebView (`VerifyDialog.kt`) sharing the same cookie jar. Solve the check manually and the source retries within the same scan (`scan_retry_source`). The window has Cancel and Done at the top: the engine counts as passed only when the page shows no challenge after Done. Cancel, Back or leaving the app keep it blocked; if the page does not load within 30 s, the window shows an error with Retry.
- **Automatic CAPTCHA solvers are never included** ([ADR-0012](../adr/0012-no-captcha-solving-no-public-proxies.md)).
- Shared dork queue: failed queries automatically fail over to healthy engines, similar queries collapse into `OR` groups, results are cached for 24 hours, and randomized delays (6-14 s) pace requests.
- Multiple blocked engines consolidate into a single Complete verification (N) button; you can also pre-authenticate cookies ahead of time via Settings → Network → Warm up search engines, or run a manual check with Test CAPTCHA (`search_captcha_test`).
- If every web search engine returns CAPTCHA, the cause is almost always IP reputation (CGNAT, VPN, or datacenter proxy). Verify in regular Chrome on the same network; switch to mobile data, use the Gentle preset, or configure your own proxy. Web archives and CT logs never display CAPTCHAs.
- Inspect the built-in browser fingerprint and per-engine metrics under Settings → Debug → Search (including exporting `Download/FOCA-rs/FOCA-rs_fingerprint.html` to compare side-by-side in Chrome).

## Cloud AI: 10 Providers, Live `/models` & Thinking

FOCA-rs 2.0 provides an optional Cloud AI Summary (`/settings/ai` and `/p/ai`) backed strictly by cloud API providers: there are no local/on-device LLM models and no hardcoded stale model lists.

- **10 supported cloud providers:**
  1. **OpenAI** (`api.openai.com`)
  2. **Anthropic** (`api.anthropic.com`: native `/v1/messages`)
  3. **Google Gemini** (`generativelanguage.googleapis.com`: native `v1beta :generateContent`)
  4. **DeepSeek** (`api.deepseek.com`)
  5. **xAI (Grok)** (`api.x.ai`)
  6. **Mistral AI** (`api.mistral.ai`)
  7. **Groq** (`api.groq.com`)
  8. **Together AI** (`api.together.xyz`)
  9. **OpenRouter** (`openrouter.ai`)
  10. **Custom OpenAI-compatible API** (any custom `base_url`)
- **Live `/models` discovery (`ai_models_list`):** Tap Refresh models to fetch your account's currently available models directly from the provider's API via `NetClient` (respecting your proxy/Orbot settings, with zero API key leakage in `request_log`). FOCA-rs parses each model's capabilities (`thinking`, `adaptive_thinking`, `manual_thinking`, context window, max output tokens), hides utility/deprecated models by default (toggle Show all API models to view everything), and allows manual model ID entry when offline or before setting a key.
- **Thinking (Reasoning) & generation controls:**
  - Reasoning level: `auto` (provider default: omits extra fields to avoid HTTP 400 errors on non-reasoning models), `off`, `minimal`, `low`, `medium`, `high`, `xhigh`, `max`.
  - Optional `thinking_budget`, `max_tokens`, `temperature`, and Show reasoning trace (Thinking) (renders a collapsible reasoning section in `/p/ai`).
  - Automatically mapped to native provider schemas: Anthropic adaptive `thinking` + `output_config.effort` (or manual `budget_tokens` without `temperature`), Google Gemini `thinkingLevel` / `thinkingBudget` + `includeThoughts`, OpenAI/xAI/Mistral/Groq/Together `reasoning_effort`, DeepSeek `thinking.type`, and OpenRouter `reasoning.effort`.
- **Privacy & redaction preview:** Before anything leaves the phone, secrets, PII, e-mail addresses, and the client name are automatically replaced with `[SECRET]`, `[NAME]`, `[EMAIL]`, `[CLIENT]` and `[CLIENT-DOMAIN]` (the same in every language), and you can inspect the entire prompt in the preview. Your AI API key lives exclusively in Android KeyVault.
- **Language:** the request and the answer use the interface language (with "System", the device language).
- **One request at a time:** "Send" stays locked until the answer arrives and the core rejects a second request for the same project; a running request can be cancelled.
- **History:** every summary is saved with the project; `/p/ai` shows the latest one and the history (date, model, language), and any of them can be copied, deleted or picked for the report. The report puts the client name and domain back in place of `[CLIENT]` and `[CLIENT-DOMAIN]`.

## Sandboxed Plugins

Manage plugins under Settings → Plugins (`/settings/plugins`). Plugins let you extend FOCA-rs with custom passive sources, HTTP header audits, metadata extractors, and finding rules without recompiling the app:

- **Two pure-Rust execution engines:**
  1. **Declarative JSON/TOML manifests** (`plugin.json` / `plugin.toml`) defining passive HTTP collectors, regex/JSONPath extractors, and metadata/header rules.
  2. **Pure-Rust WASM sandbox** (`WasmSandbox`): strict `≤ 16 MiB` linear memory limit and `50,000`-instruction `fuel` cap (infinite loops abort in `< 50 ms`).
- **Hard security boundaries:**
  - Zero WASI filesystem access, zero raw sockets, zero access to `KeyVault`, credentials, or other projects.
  - All plugin network calls pass through the host's `host_http_get_scoped` → `NetClient`, enforcing project scope, exclusions, proxy/Orbot routing, RPS limits, request logging, and [ADR-0009](../adr/0009-passive-never-touches-target.md) (any plugin attempt to contact a target host during a Passive scan is hard-blocked).
- **4 built-in reference plugins:** `certspotter-ext` (CT passive source), `robots-sitemap-parser`, `ua-gov-edrpou-enricher`, and `custom-header-audit`: toggleable out of the box and usable as templates. Install custom JSON/TOML manifests and verify them safely with Test in sandbox (Passive) (`plugin_run_test`).
- **In real scans:** enabled plugins run during the Network and DNS stage. A failing plugin is shown on the scan screen and never fails the scan; plugins that contact the target are skipped in Passive.
- **Unsigned plugins:** before enabling one, the app lists the access it requests. Enable it only if you trust the author.

## Signed Signature Updates, Language, Licenses & Android Builds

- **Signature databases (`/settings/signatures`):** the screen shows what the analysis really uses:
  - **CISA KEV** (known exploited vulnerabilities): how many catalog entries are used for matching out of the full CISA catalog (only entries for software FOCA-rs can detect are kept; there is no NVD data), the catalog date and its age. A catalog older than 30 days gets a hint to check for updates.
  - **Software and OS** detection signatures, **secret rules** (built-in plus rules from an installed bundle) and the **standards** mapping (number of references, finding rules and the families: OWASP Top 10:2025, MITRE ATT&CK v20, CWE with the 2025 Top 25, НД ТЗІ 3.6-006-24 / NIST SP 800-53, ISO/IEC 27001:2022, OWASP WSTG, GDPR, Law 2297-VI and the legacy КСЗІ documents).
  - **Check for updates** downloads the official signed bundle from the project's GitHub release. If nothing has been published yet, the screen says so ("no newer database published yet") and keeps the current database; it never reports an update that did not happen. A newer bundle is installed only after its `Ed25519` signature matches the key built into the app. The time and result of the last check stay on the screen.
  - **Detection data** beside KEV, each from a pinned upstream version and credited in [NOTICE](../../NOTICE) and on the Licenses screen: technology fingerprints from webappanalyzer, gitleaks secret rules, end-of-life dates from endoflife.date, EPSS, CVSS and CWE for KEV matches (FIRST EPSS, CISA Vulnrichment), vulnerable JavaScript libraries from Retire.js, Recog banner and favicon fingerprints, the Public Suffix List (registrable domains for grouping subdomains) and subdomain takeover fingerprints from can-i-take-over-xyz. The screen lists the record count of each loaded table. A `foca-sig-bundle/v2` bundle can replace these tables; v1 bundles still install.
  - **Signing key**: 2.0.0-beta.3 signs bundles with a new key. Builds up to 2.0.0-beta.2 reject bundles from the new feed and keep their built-in databases.
  - **Import bundle** installs a bundle file offline with the same checks, **Rollback** returns to the previous bundle or the built-in database. Format and publishing: [signature bundles](../dev/signature-bundles.md).
- **Live localization (`EN / RU / UA` + Auto):** Under Settings → Appearance (`/settings/appearance`), switch between Auto (System), English, Русский, and Українська instantaneously: all UI screens, offline help (`locales/{en,ru,uk}/help.json`), finding descriptions, playbooks, notifications, and default report language update live without leaving strict offline CSP boundaries (`i18n_bundle` IPC). Non-RU/UA device locales default cleanly to English.
- **Offline License Inventory (`/settings/licenses`):** Open Settings → About → Licenses & third-party components to inspect the CI-verified inventory of all 536+ Rust crates (with direct dependencies highlighted), Android libraries, datasets & assets (`Inter` SIL OFL 1.1, `Natural Earth`, `SecLists`, `CISA KEV`, security standards), and full texts of all open-source licenses: searchable and filterable completely offline.
- **Android build flavors (`foss` vs `play`):** Check your installed flavor on `/settings/about`:
  - **`foss`**: 100% pure `GPL-3.0` build (F-Droid / direct release) with zero proprietary Google libraries; offline OCR is excluded (`unavailable_in_foss_build`).
  - **`play`**: adds optional 100% on-device OCR via `com.google.mlkit:text-recognition` with Google APIs ToS attribution shown in `/settings/licenses`.
