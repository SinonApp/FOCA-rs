# Getting Started, Projects & Scope

↑ [User Guide](README.md) · [Documentation](../README.md)

- [Installation & Android Build Flavors](#installation--android-build-flavors)
- [First Launch](#first-launch)
- [Projects](#projects)
- [Scope: Honest Network Targets & Exclusions](#scope-honest-network-targets--exclusions)
- [Your First Scan in 3 Steps](#your-first-scan-in-3-steps)
- [Legal Boundaries](#legal-boundaries)

## Installation & Android Build Flavors

- **Requirements:** Android 7.0+ (`minSdk 24`, built against `targetSdk 36`). Release APKs target 64-bit ARM devices (`arm64-v8a`), which covers virtually all modern Android phones.
- **Two Android flavors (`foss` and `play`):**
  - **`foss`**: 100% free and open-source `GPL-3.0` build for F-Droid and direct GitHub releases. Contains zero proprietary Google dependencies; optional on-device photo/scan OCR is disabled (`unavailable_in_foss_build`), while every other OSINT, document forensics, cleaning, analytics, AI, and reporting feature works identically.
  - **`play`**: adds optional offline OCR for scanned PDFs and images via `com.google.mlkit:text-recognition` (100% on-device, disabled by default, with explicit Google APIs Terms of Service attribution in `/settings/licenses`).
- **Sideloading & signature verification:** When installing an APK outside an app store, allow installation from that source when prompted by Android. The package ID is `app.sinon.focars`. Updates install over the existing app as long as the signing key matches, see [docs/dev/build.md](../dev/build.md) for signature verification instructions.
- **2.0.0-beta.1 uses a new signing key.** Uninstall any earlier FOCA-rs build (1.x or a 2.0 preview) before installing it. To keep projects, export them first as encrypted `.foca.enc` files and import them after the reinstall. 2.0.0-beta.2 and 2.0.0-beta.3 use the same key and install over beta.1 or beta.2 with your projects kept.
- **Beta:** 2.0 is published as a GitHub Pre-release. A "Beta" label sits next to the version, and the projects screen shows a note with Report a problem, which saves a logs ZIP to `Download/FOCA-rs` and opens the GitHub issue form. The same button is in Settings → About.
- **Permissions (from `AndroidManifest.xml`):** Internet & network state, notifications (`POST_NOTIFICATIONS`), `dataSync` foreground service (background scanning), `WAKE_LOCK`, battery-optimization exemption prompt, and biometrics (revealing masked secrets and app lock). FOCA-rs does not request access to contacts, location, or broad device storage (local files are selected explicitly through Android's Storage Access Framework).

## First Launch

On first launch, FOCA-rs automatically detects your phone's system language (`Locale.getDefault()`): Ukrainian (`uk`) and Russian (`ru`) map to their respective locales, while English (`en`) and all other system languages default to English. You can switch languages live at any time under Settings → Appearance (`/settings/appearance`).

1. **Welcome** (`/welcome`): brief overview of the app.
2. **Terms of Use** (`/terms`): you must accept the terms before accessing the rest of the app (core commands `terms_get` / `terms_accept`). Review them later under Settings → Terms of Use.
3. **Permissions** (`/permissions`): notifications and background execution; you can skip these and grant them later.
4. **Projects** (`/projects`): starts empty; there are no pre-populated demo projects until you choose to open the offline reference case.

## Projects

Each project represents one assessment (one organization or client engagement). All project data is stored in an isolated SQLite database (`<id>.foca`, with FTS5 full-text index) inside the app's private data directory (see [ADR-0004](../adr/0004-sqlite-per-project.md)); Android cloud backup is disabled for this directory. Deleting a project removes its database and all downloaded documents.

From the Projects screen (`/projects`), you can create, open, duplicate, delete, or transfer projects using encrypted `.foca.enc` bundles (see [Encrypted `.foca.enc` bundles](data-and-reports.md#encrypted-focaenc-project-bundles)). Each project card shows its overall risk score and counters from the latest scan. Reference cases are not listed under Recent projects: they have their own Reference cases section on the same screen, and the app never reopens one on start. Open the reference case also finds an existing one.

To delete a single scan, open it in the scan history on the Scan screen (or the card of a stopped or paused scan), tap Delete scan and hold Delete. The scan is erased with everything only it produced: downloaded documents and their files (wiped), findings, hosts and the request log. Anything a later scan also listed stays, with your notes, tags and statuses; a paused scan is stopped first and can no longer be resumed.

Inside a project, the bottom bar provides Overview · Findings · Data · Reports. The overflow menu (⋮) opens projects, scope, search rules, project tools (link graph, attack paths, internal network map, GPS map, timeline, diff, monitoring, pre-publication check, AI summary), quick tools, scan queue, settings, and offline help.

## Scope: Honest Network Targets & Exclusions

Scope defines exactly what FOCA-rs is allowed to assess and what it must never touch. Starting in 2.0, FOCA-rs accepts only network targets that the engine can actually query:

| Target input | Type | What it covers |
|---|---|---|
| `example.com` | `domain` | The domain and all of its subdomains |
| `*.example.com` | `wild` | Subdomains of `example.com` only |
| `https://app.example.com` | `url` | The host/origin extracted from the URL (`http://` or `https://`) |
| `203.0.113.10` | `ip` | Single IPv4/IPv6 address (RDAP, Shodan InternetDB, TCP liveness, TLS, ports) |
| `203.0.113.0/24` | `cidr` | Network block in CIDR notation (expanded safely within limits, skipping network/broadcast addresses) |
| `203.0.113.1-203.0.113.50` | `range` | Inclusive IP address range |

- **No non-network targets:** E-mail addresses, person names, organization names, and ASNs are not scan targets and are rejected by the launch wizard. If you paste an e-mail address such as `user@example.com`, the wizard prompts you to add its domain (`example.com`) instead. Organization/client names belong in the project's Client metadata field, and e-mail domain policies can be inspected directly via Quick Tools (`/tools`).
- **Exclusions override targets:** Any host, IP, or CIDR listed under exclusions receives zero requests in every profile: enforced inside `foca-net` on every redirect hop and every resolved IP address.
- **Out-of-scope candidates:** Hosts discovered during a scan that fall outside the authorized scope land on Out of Scope (`/p/out-of-scope`). Add one with Add to scope, or tick several (or All subdomains of …) and tap Add to scope and scan. IP addresses are suggested only as single IPs (never auto-expanded to `/24`) with a shared-hosting warning; shared CDN/hosting IPs, names with a dangling CNAME and excluded names cannot be added.
- The exact same scope rule is shared across the UI, demo backend, and Rust core, see [docs/API.md](../API.md).

## Your First Scan in 3 Steps

1. Go to Projects → New project (`/new`) and enter one or more network targets (for example, `example.com`). You can also attach local files from your phone for completely offline metadata analysis.
2. Pick a scan profile. Start with Passive: it never sends a single packet to the target site ([all profiles](scan-profiles.md)).
3. Tap Start. The scan launches immediately and runs in the background with a live progress notification (`Scanning… N%`). Discovered artifacts appear in real time on the Scan screen (`/p/scan`).

No API keys are required out of the box: search engines, web archives, Certificate Transparency logs, subdomain aggregators, and passive reconnaissance all work without keys ([sources](sources.md)).

To explore FOCA-rs before scanning any real target, tap Open reference case on the Projects screen: 12 synthetic documents belonging to the fictional company ТОВ «Приклад» (Pryklad LLC) are analyzed locally without a single network request ([details](analytics-and-hygiene.md#reference-case)).

On Xiaomi, Samsung, Huawei, Oppo and vivo firmwares the launch screen may show Keep the firmware from stopping the scan with autostart and battery checks. Fix them before a long scan; see [FAQ → Scan Stops in the Background](faq.md#scan-stops-in-the-background-xiaomi-hyperos).

## Legal Boundaries

This is general guidance, not legal advice; laws in your jurisdiction may differ.

- **Passive** reads only public third-party sources (search engines, web archives, CT logs, RDAP, Shodan InternetDB). Zero requests reach target hosts: guaranteed at the core level ([ADR-0009](../adr/0009-passive-never-touches-target.md)).
- **Standard** downloads public documents from target hosts, runs DNS queries against target nameservers, crawls pages, and inspects TLS certificates: make sure you own the target or have explicit permission.
- **Full** adds the active phase (AXFR zone transfer, NSEC walking, TCP port scanning, website path fuzzing, CORS/HTTP method probes): run only with written authorization from the system owner. Unauthorized access is a criminal offense in most jurisdictions (for example, Article 361 of the Criminal Code of Ukraine). See [SECURITY.md](../../SECURITY.md).
- Handle discovered secrets and personal data (PII) responsibly: secrets remain hidden behind biometric/PIN confirmation, PII is masked before storage, and reports hide secrets by default.
