# User Interface (UI)

↑ [Developer Guide](README.md) · [Architecture](architecture.md)

- [Structure](#structure)
- [Localization (`F.i18n`, `F.t`, Lazy Help)](#localization-fi18n-ft-lazy-help)
- [Screen and Route Map](#screen-and-route-map)
- [Key 2.0 UI Capabilities](#key-20-ui-capabilities)
- [Design Principles](#design-principles)
- [Verification](#verification)

For the `window.FOCA` internal API reference, CSS classes, and UI contributor conventions, see [ui/README-UI.md](../../ui/README-UI.md). For the rationale behind vanilla JS with no bundler, see [ADR-0002](../adr/0002-vanilla-js-ui.md).

## Structure

| File | Role |
|---|---|
| `ui/index.html` | Application shell loading scripts and stylesheets directly without a bundler |
| `ui/js/core.js` | UI core: router (`F.route(pattern, def)`, `F.go`, `F.back`), bottom sheets, snackbars, `F.withStates`, tabs, and `F.i18n` / `F.t` localization runtime |
| `ui/js/main.js` | Overview (`/p/overview`), project search (`/p/search`), `/open/:id` deep links, bottom navigation |
| `ui/js/api.js` | `F.api.*`, single data boundary: Tauri `invoke("foca")` in-app, demo backend in browser, or `qa/tauri-shim.js` over `foca serve` |
| `ui/js/demo-backend.js` | Deterministic in-browser mock backend implementing the same commands (including `i18n_bundle` and `licenses_get`) for `qa/shoot.sh` |
| `ui/js/demo-loader.js` | Loads `demo-backend.js` (0.5 MB) only in a plain browser; inside Tauri the app starts without it |
| `ui/js/sel.js` | `F.sel` selectors (single source of truth for numbers) and `FOCA_RULES` (reference spec mirrored in `foca-engine/src/rules.rs`) |
| `ui/js/icons.js` | Inline SVG icon registry |
| `ui/screens/*.js` + `*.css` | Feature screens (each stylesheet uses a screen-scoped class prefix) |
| `ui/data/`, `ui/fonts/` | Offline Natural Earth world boundaries (`ne110.js`, `ne50.js`), Inter font (`Inter-Regular.ttf`, `Inter-SemiBold.ttf`) |

Codebase footprint: ~37.9k lines JS (27 files) and ~11.1k lines CSS (16 files), implementing 61 routes across 17 route-registering modules.

## Localization (`F.i18n`, `F.t`, Lazy Help)

FOCA-rs supports live switching between English (`en`), Russian (`ru`), Ukrainian (`uk` / UI badge `UA`), and System (auto) without relaxing the strict WebView CSP (`connect-src ipc: http://ipc.localhost`):

- **IPC bundle loading (`i18n_bundle`)**: `locales/{en,ru,uk}/{ui,help}.json` and the per-area dictionaries `locales/<lang>/ui/*.json` (merged into one UI dictionary) are compiled into `foca-engine` (`crates/foca-engine/src/services/i18n.rs`). On boot, `ui/js/api.js` reads `settings.lang` (default `"auto"`), queries Android's BCP 47 locale via `device_info.locale` (falling back to `navigator.language`), and calls `F.api.i18n_bundle({ lang, device_locale, include_help: false })`.
- **`F.i18n` & `F.t`**: `ui/js/core.js` exposes `F.i18n` (`lang()`, `setting()`, `uiCode()`, `load()`, `loadHelp()`, `setLang()`, `applyBundle()`, `detectDeviceLocale()`) and `F.t(key, params, fallback)` with placeholder interpolation and pluralization (`1/2/5` for RU/UK, `1/2` for EN).
- **Core messages**: texts the core sends (source statuses, toasts, out-of-scope reasons) carry a message code; `F.coreMsg(text, msg)` renders them in the current language, with the Russian text as fallback.
- **Finding texts**: finding titles, descriptions, recommendations, evidence, finding sources and host/person roles come from the core in Russian. `ui/js/ftext.js` (`F.ftext`) renders them from `i18n_bundle().findings` (the report catalog) by `provenance.rule`; `ui/js/api.js` exposes them through getters, so lists, cards, search and in-app exports follow a language switch. `node qa/check-ftext.mjs` checks the port against the vectors shared with `foca-report`.
- **Static check**: `node qa/check-i18n.mjs` fails on a missing key in any language and on `F.t` evaluated at script load (module-level tables must be functions or getters).
- **Lazy offline Help**: help articles, screen index, and glossary live in `locales/{en,ru,uk}/help.json` rather than hardcoded JS arrays. `ui/screens/help.js` calls `F.i18n.loadHelp()` (`i18n_bundle { ..., include_help: true }`) only when `/help` or `/help/:id` is actually opened, keeping startup light.

<a id="карта-экранов-и-маршрутов"></a>
## Screen and Route Map

Generated from `F.route(...)` calls in the codebase. Bottom navigation tabs: Overview · Findings · Data · Reports; the `⋮` overflow menu opens secondary tools and settings. Routes exercised by screenshot QA are listed in `qa/routes.txt`.

| Route | File | Screen |
|---|---|---|
| `/open/:id` | `ui/js/main.js` | Open project → Overview (notification deep link) |
| `/open/:id/scan` | `ui/js/main.js` | Open project → Scan launch wizard |
| `/p/overview` | `ui/js/main.js` | Project overview |
| `/p/search` | `ui/js/main.js` | Global project search |
| `/p/data` | `ui/screens/data.js` | Data (default segment) |
| `/p/data/:seg` | `ui/screens/data.js` | Data segment (`certs`, `mailpol`, `saas`, and host cert card via `ui/screens/infra.js` / `infra_get`) |
| `/p/entity/:type/:id` | `ui/screens/data.js` | Person / host / computer / software detail card |
| `/settings/debug` | `ui/screens/debug.js` | Debug console |
| `/settings/debug/:seg` | `ui/screens/debug.js` | Debug tab |
| `/p/doc/:id` | `ui/screens/docs.js` | Document detail (Forensics sections from `F.fx.docBlocks` in `ui/screens/forensics.js`, `doc_get`) |
| `/p/docs-search` | `ui/screens/forensics.js` | Full-text search across document text (`docs_search`) |
| `/p/rules` | `ui/screens/forensics.js` | Project custom search rules (`rules_get` / `set` / `test`) |
| `/import` | `ui/screens/forensics.js` | Offline file/folder/ZIP inspection (`platform_pick_folder`, `import_offline`, `demo_case_import`) |
| `/p/findings` | `ui/screens/findings.js` | Findings list |
| `/p/finding/:id` | `ui/screens/findings.js` | Finding detail (standards mapping, contextual `finding_playbook`, triage) |
| `/help` | `ui/screens/help.js` | Offline Help index (lazily loads `locales/*/help.json` via `i18n_bundle`) |
| `/help/:id` | `ui/screens/help.js` | Help article |
| `/clean/result` | `ui/screens/hygiene.js` | Metadata cleaning "Before / After" diff, verdict, warnings, share clean copy |
| `/shared` | `ui/screens/hygiene.js` | Project-less file inspection from Android Share Target (`platform_shared_files`, `shared` event) |
| `/p/graph` | `ui/screens/insights.js` | Layered entity graph, clusters, link chain (`insights_get`, `chain_get`), and Attack Paths / Remediation Choke Points |
| `/p/netmap` | `ui/screens/insights.js` | Internal network tree (`insights_get().netmap`) |
| `/p/attack-paths` | `ui/screens/insights.js` | Ranked attack paths and remediation choke points (`attack_paths_get`) |
| `/new` | `ui/screens/launch.js` | New scan wizard (honest network targets only) |
| `/p/scope` | `ui/screens/launch.js` | Project scope editor |
| `/terms` | `ui/screens/onboard.js` | First-run Terms of Use |
| `/settings/terms` | `ui/screens/onboard.js` | Terms of Use (from Settings) |
| `/permissions` | `ui/screens/onboard.js` | Android permissions onboarding |
| `/projects` | `ui/screens/projects.js` | Projects list (including `.foca.enc` encrypted export/import & demo case) |
| `/p/reports` | `ui/screens/reports.js` | Reports & exports |
| `/p/report-new` | `ui/screens/reports.js` | New report wizard (`report_templates`, HTML/MD/DOCX/CSV/JSON, Chain of Custody, signing) |
| `/p/report-preview` | `ui/screens/reports.js` | Report preview |
| `/p/scan` | `ui/screens/scan.js` | Live scan progress |
| `/p/scan-stopped` | `ui/screens/scan.js` | Scan stopped summary |
| `/p/scan-stopped/:reason` | `ui/screens/scan.js` | Scan stopped (with reason) |
| `/p/out-of-scope` | `ui/screens/scan.js` | Out-of-scope candidates |
| `/settings` | `ui/screens/settings.js` | Settings home |
| `/settings/keys` | `ui/screens/settings.js` | API keys (Android Keystore) |
| `/settings/network` | `ui/screens/settings.js` | Network, proxy presets/groups, UA, speed, DNS, ports, search-engine preparation |
| `/settings/power` | `ui/screens/settings.js` | Traffic & power limits |
| `/settings/security` | `ui/screens/settings.js` | PIN, biometrics, screen protection, auto-wipe |
| `/lock` | `ui/screens/settings.js` | Lock screen (PIN / biometric) |
| `/settings/battery` | `ui/screens/settings.js` | Background execution & battery optimization |
| `/settings/appearance` | `ui/screens/settings.js` | Theme, typography, and live language switcher (`EN` / `RU` / `UA` / `System (auto)`) |
| `/settings/update` | `ui/screens/update.js` | In-app update: check GitHub releases, notes (escaped, `F.safeMd`), signed download with progress, install permission and PackageInstaller handoff, schema warning, check settings |
| `/settings/about` | `ui/screens/settings.js` | About FOCA-rs (app version, build flavor `foss`/`play`, changelog, link to licenses) |
| `/settings/licenses` | `ui/screens/settings.js` | Offline Third-Party Licenses & Components (`licenses_get {}`) |
| `/settings/signatures` | `ui/screens/settings.js` | Signed signature bundles (`sigbundle`), rollback, and offline ML Kit OCR settings |
| `/settings/sources` | `ui/screens/sources.js` | Discovery sources catalog |
| `/tools` | `ui/screens/toolbox.js` | Quick Toolbox (project-less one-shot file, mail domain, host, secret, and log checks) |
| `/queue` | `ui/screens/toolbox.js` | Batch scan queue (`queue_*`) |
| `/p/graph/:type/:id` | `ui/screens/v2.js` | Entity-focused relation graph |
| `/p/map` | `ui/screens/v2.js` | 3D canvas GPS globe |
| `/p/timeline` | `ui/screens/v2.js` | Yearly activity lanes & 7×24 heat map (`F.ins`) |
| `/p/monitor` | `ui/screens/v2.js` | Scheduled monitoring & Telegram/Webhook alert configuration |
| `/p/diff` | `ui/screens/v2.js` | Scan diff ("What changed") |
| `/settings/plugins` | `ui/screens/v2.js` | Sandboxed plugin manager (`plugins_list`, `plugin_install`, `plugin_toggle`, `plugin_remove`) |
| `/settings/plugin/:id` | `ui/screens/v2.js` | Plugin details & sandboxed test runner (`plugin_test`) |
| `/settings/ai` | `ui/screens/v2.js` | Cloud-only AI provider, live model discovery, Thinking controls & redaction rules |
| `/p/ai` | `ui/screens/v2.js` | AI summary preview, redaction review, generation & collapsible Thinking output |
| `/welcome` | `ui/screens/v2.js` | Welcome walkthrough |
| `/p/preflight` | `ui/screens/v2.js` | Pre-publication hygiene check (A-F grades, fix steps, `hygiene_get`, `doc_clean`) |
| `/settings/wordlists` | `ui/screens/wordlists.js` | Wordlist management |

## Key 2.0 UI Capabilities

- **Offline Third-Party Licenses (`/settings/licenses`)**: opened from Settings → About → Licenses & Components. Powered by IPC `licenses_get {}` (`crates/foca-engine/data/licenses.json`), organized into 4 tabs (Data & Assets, Rust Crates with a direct-dependencies filter, Android Libraries with `foss`/`play` flavor tags, and License Texts covering all 10 full open-source license texts) plus instant text search and license-type filtering.
- **Cloud-Only AI (`/settings/ai`, `/p/ai`)**: FOCA-rs ships no local/on-device AI. The UI supports cloud providers only (`openai`, `anthropic`, `gemini`, `deepseek`, `xai`, `mistral`, `groq`, `together`, `openrouter`, and `custom` OpenAI-compatible HTTPS URL), fetches the live model catalog directly from the provider API via `ai_models_list` (with manual model ID override and an optional "Show all API models" toggle), exposes Thinking / Reasoning effort (`auto`, `off`, `minimal`, `low`, `medium`, `high`, `xhigh`, `max`), optional thinking token budget (Gemini/Anthropic), `max_tokens`, `temperature`, and collapsible Thinking output (`show_thoughts`), and requires reviewing the redacted prompt (`[SECRET]`, `[NAME]`, `[EMAIL]`, `[CLIENT]`) before sending.
- **Beta label and report flow (`ui/screens/beta.js`)**: pre-release builds (`-alpha`/`-beta`/`-rc` in the version) show a "Beta" chip next to the version in Settings and About, and `/projects` shows a one-time dismissible note (stored as `settings.ui.beta_note_done`). *Report a problem* (note and About) saves the logs ZIP from `F.collectLogs()` (the same builder as Debug › Log › Share) to `Download/FOCA-rs/` and opens the GitHub issue chooser via `open_url`; the issue forms live in `.github/ISSUE_TEMPLATE/`. Scenario: `qa/scenarios/beta-note/steps.mjs`.
- **Honest Network Targets (`/new`, `/p/scope`, `/projects`)**: launch and scope inputs accept strictly what the engine actually scans, `Domain`, **`*.Domain`, `http(s)://URL`, `IP`, `CIDR`, and `IP range`**. Legacy non-scannable target promises (e-mail addresses, person names, organizations, ASN) have been removed from the wizard and placeholders; typing an e-mail address shows a hint to enter its domain instead. Client/organization name remains a project metadata field (`client`), and e-mail domain extraction remains available in Toolbox (`/tools`).

## Design Principles

- **One-handed mobile ergonomics**: primary actions sit at the bottom (FAB or sticky `.foot`); bottom sheets replace modal dialogs.
- **Large-font accessibility**: layout uses `rem` units and is verified across font scales `1`, `1.3`, and `2`; labels never clip and buttons wrap cleanly.
- **Accessible alternatives for every gesture**: swipe actions on findings duplicate card buttons; long-press duplicates the menu "Select" item.
- **Safe destructive flows**: deletions offer Undo via snackbar; irreversible wipe operations require press-and-hold confirmation.
- **Secrets hidden by default**: revealing a secret always requires explicit user confirmation.
- **Active mode visibility**: a persistent red banner at the top indicates an active-phase scan.
- **Unified state handling**: every list screen uses `F.withStates` (empty / loading / error).
- **API keys live exclusively in Settings**: scan wizard and source screens never nag with "Add key" badges; paid sources without keys stay hidden during scans and auto-enable once a key is saved in Settings → API Keys (`F.sourceKeyAdded`).
- **Direct numeric entry**: `F.numField({ id, label, unit, min, max, step, rec: [a, b], note, help, get, set, whyMin, whyMax })` (`ui/screens/help.js`) combines `inputmode="numeric"` typing with `±` buttons and a recommended-range pill; values apply on blur/Enter and display inline validation reasons instead of silently reverting.
- **Offline Help links**: settings with numeric thresholds provide `F.helpBtn(id, label)` linking into `/help/:id`.
- **3D GPS Globe (`/p/map`)**: canvas globe with button fallbacks (`±` zoom and clickable point list), honoring `prefers-reduced-motion` and repainting only on state changes.

## Verification

- Syntax, formatting, and linting (also run in CI):
  ```sh
  for f in ui/js/*.js ui/screens/*.js; do node --check "$f"; done
  npm run format:check
  npm run lint
  node qa/data-invariants.mjs
  ```
- Visual/layout check:
  ```sh
  qa/shoot.sh --routes "<routes>" --out <dir> --w 393 --fs 1.3 --theme light
  ```
  Verify `errors: []` and `overflow 0` across 360 / 393 / 412 px × font scale 1 / 1.3 / 2 × light/dark themes. Full suite: `qa/run-all.sh` (see [docs/testing/README.md](../testing/README.md)).
- Any new numeric setting must include a localized article in `locales/{en,ru,uk}/help.json` and a corresponding `F.helpBtn`.
