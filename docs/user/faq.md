# FAQ & Troubleshooting

↑ [User Guide](README.md) · [Documentation](../README.md)

- [Scan Stops in the Background (Xiaomi, HyperOS)](#scan-stops-in-the-background-xiaomi-hyperos)
- [0 Documents Found](#0-documents-found)
- [Scan Is Taking Very Long](#scan-is-taking-very-long)
- [Source Reports "CAPTCHA"](#source-reports-captcha)
- [Almost Every Port Shows as "Open"](#almost-every-port-shows-as-open)
- [Why Can't I Enter an E-mail, Person, Organization, or ASN as a Target?](#why-cant-i-enter-an-e-mail-person-organization-or-asn-as-a-target)
- [Where Is Local AI? Why Does Model Selection Query the Provider API?](#where-is-local-ai-why-does-model-selection-query-the-provider-api)
- [What Is the Difference Between `foss` and `play` Builds? Why Is OCR Unavailable?](#what-is-the-difference-between-foss-and-play-builds-why-is-ocr-unavailable)
- [How Do I Change the App Language?](#how-do-i-change-the-app-language)
- [Are Plugins Safe?](#are-plugins-safe)
- [How to Report a Problem and Send Logs](#how-to-report-a-problem-and-send-logs)
  - [Clearing logs](#clearing-logs)
- [The App Crashed](#the-app-crashed)
- [Update Fails to Install](#update-fails-to-install)

## Scan Stops in the Background (Xiaomi, HyperOS)

Android, especially Xiaomi/HyperOS, closes background apps. On Xiaomi, swiping FOCA-rs out of Recents ends the whole process, scan included.

1. Open Settings → Background execution (`/settings/battery`). On firmwares known to kill apps there is a card with two checks and buttons to the right system screens: Autostart must be on, and Battery: no restrictions must be granted. The launch screen shows the same card while something is missing.
2. Turn on Hide from Recents during scans: while a scan runs and the app is in the background, its card is not in Recents and cannot be swiped away. Return through the scan notification. Alternatively lock the card in Recents (drag it down or tap the padlock).
3. Allow notifications: Android treats the persistent scan notification as a sign of running work.

Steps the app can read (autostart on Xiaomi, battery restrictions, notifications) show their real state and tick themselves. The firmware guide asks only for what the scan needs: on Xiaomi autostart, Battery saver: No restrictions and, only if hiding from Recents is off, a locked card; on Samsung Battery: Unrestricted and Never sleeping apps. No pop-up or "Open new windows while running in the background" permission is needed: notifications work without it and the app never opens a window from the background.

If the system kills the app anyway, progress is saved. FOCA-rs tries to resume the scan in the background a little later; on Android 12+ this needs the battery restriction removed, otherwise a Continue notification appears. You can always open the app and resume from where the scan stopped. Pressing Back on the root screen minimizes the app rather than closing it ([ADR-0006](../adr/0006-native-bridge.md)).

## 0 Documents Found

- Verify the target: check domain spelling and omit `www.` if public files live across the apex domain or subdomains; add all relevant domains of the organization.
- Open Settings → Sources to ensure source groups are enabled. The Scan screen shows what each individual source returned.
- Check Launch wizard → Advanced → Document types.
- Search engines may have triggered a CAPTCHA, see below.
- Finding zero documents on a well-hardened site is a normal result: nothing leaked publicly. Subdomains, DNS/TLS intelligence, hosts, and infrastructure findings are still collected.

## Scan Is Taking Very Long

- Tap Skip source next to any slow responder (including `subdomains` and `tls`); every search source also stops automatically after its configured timeout (default `90 s`).
- Stages, sources and the brute-force steps have their own pause, skip and restart buttons on the scan screen ([details](scan-profiles.md#pause-stop--resume)).
- **Network and DNS** shows its current step with a counter. If DNS is slow (often behind a VPN), a warning gives the expected time and a Skip brute force button.
- Paginated web archives (Wayback Machine, Common Crawl) are typically the slowest; partial results are saved as they arrive.
- **Full** takes the longest due to website path discovery; you can stop fuzzing independently while preserving all discovered data.
- Routing through Tor multiplies latency several times: this is expected.
- Lower the per-target document limit under Launch wizard → Advanced → Limits.

## Source Reports "CAPTCHA"

See [CAPTCHA & Manual Verification](settings-network.md#captcha--manual-verification): tap Complete verification, switch to the Gentle speed preset, change networks (avoid shared CGNAT/VPN exit IPs), or use your own proxy. Automatic CAPTCHA solving is intentionally not supported ([ADR-0012](../adr/0012-no-captcha-solving-no-public-proxies.md)).

## Almost Every Port Shows as "Open"

A local Android VPN (AdGuard in VPN mode, v2rayNG, NetGuard) is intercepting and accepting TCP connections locally. FOCA-rs detects this with network canaries and marks the port scan Unreliable, see [VPN, AdGuard & Unreliable Port Scans](settings-network.md#vpn-adguard--unreliable-port-scans).

## Why Can't I Enter an E-mail, Person, Organization, or ASN as a Target?

Starting in 2.0, FOCA-rs enforces honest network targets only: `domain` (`example.com`), `*.domain`, `http(s)://url`, `ip`, `cidr`, and `ip-range`. Earlier versions allowed typing e-mails, person names, organizations, or ASNs even though the engine did not run dedicated people/org search pipelines against them.

- If you have an e-mail address like `user@example.com`, enter the domain `example.com` (the wizard suggests this automatically).
- Store the company or client name in the project's Client metadata field.
- To check a domain's mail policies quickly without creating a project, use Quick Tools (`/tools`).

## Where Is Local AI? Why Does Model Selection Query the Provider API?

FOCA-rs 2.0 uses Cloud AI only across 10 cloud providers (OpenAI, Anthropic, Google Gemini, DeepSeek, xAI, Mistral, Groq, Together, OpenRouter, and custom OpenAI-compatible endpoints) and does not bundle local/on-device LLM weights.

Instead of shipping hardcoded model names that quickly go stale, Settings → Cloud AI (`/settings/ai`) queries the selected provider's live `/models` endpoint with your API key, detects reasoning/context capabilities automatically, and exposes native Thinking controls. If you are offline or have not entered a key yet, you can still type any model ID manually. Before any prompt is sent, secrets, PII, e-mails, and the client name are automatically redacted in an editable preview. See [Cloud AI](settings-network.md#cloud-ai-10-providers-live-models--thinking).

## What Is the Difference Between `foss` and `play` Builds? Why Is OCR Unavailable?

To keep the main FOCA-rs distribution 100% compliant with `GPL-3.0` and F-Droid inclusion rules, Android builds are split into two flavors:

- **`foss`**: 100% free and open-source build with zero proprietary Google libraries. Optional offline OCR for scanned PDFs/images is excluded (`unavailable_in_foss_build`); all other OSINT, document forensics, cleaning, analytics, AI, plugin, and reporting features are identical.
- **`play`**: adds optional 100% on-device OCR via `com.google.mlkit:text-recognition` (disabled by default; enable in Settings → Signature databases & OCR), with explicit Google APIs ToS attribution.

Check your build flavor under Settings → About (`/settings/about`) and view every library and full license text offline under Settings → About → Licenses (`/settings/licenses`).

## How Do I Change the App Language?

On first launch, FOCA-rs follows your phone's system locale (`uk*` → Ukrainian, `ru*` → Russian, `en*` and all other locales → English). You can change it live at any time under Settings → Appearance (`/settings/appearance`) between Auto (System), English, Русский, and Українська.

## Are Plugins Safe?

Yes: plugins run inside a strict pure-Rust sandbox ([Sandboxed Plugins](settings-network.md#sandboxed-plugins)). Neither declarative manifests nor WASM plugins have access to the filesystem, raw sockets, `KeyVault`, API keys, or other projects. WASM execution is capped at `16 MiB` of memory and `50,000` fuel instructions, and all HTTP requests pass through `NetClient`, which blocks any target-host access during Passive scans ([ADR-0009](../adr/0009-passive-never-touches-target.md)) and enforces scope exclusions.

## How to Report a Problem and Send Logs

2.0 is a beta. The quickest way to report a problem is Report a problem in Settings → About or in the beta note on the projects screen: it saves a logs ZIP to `Download/FOCA-rs` and opens the GitHub issue form, where you describe what happened and attach the ZIP. Security issues go through a private advisory instead ([SECURITY.md](../../SECURITY.md)).

To collect logs only:

1. Open Settings → Debug & diagnostics (`/settings/debug`).
2. If the issue is reproducible, switch log verbosity to `debug` and reproduce the problem.
3. Tap Share logs: FOCA-rs packs a ZIP containing the core log (`<data>/logs/foca.log`, rotated `1 MB × 3`), Kotlin log (`android.log`), crash reports, and device/version/flavor metadata.
4. Send the archive via e-mail or issue tracker.

API keys, tokens, and passwords are automatically scrubbed from exported logs (`crates/foca-engine/src/analysis/redact.rs`). Per-project network request history is viewable on the Requests tab of the same screen.

### Clearing logs

- **Clear app logs** (Debug screen, Actions) deletes the core and Android logs and crash reports. Projects and their request logs stay.
- **Clear request log** (Debug screen, Requests tab, or the Request log export sheet in Reports) deletes the open project's request records: the whole log, records older than 7, 30 or 90 days, or one finished scan. The sheet shows how many records go; hold the button to confirm. Records of a scan that is still running are kept, and a running scan cannot be cleared on its own. Reports built afterwards have a shorter Request log section; findings and documents are not touched.
- **Quick tools → Log → Clear** empties the quick tools request journal (in memory, it also resets when the app restarts).

## The App Crashed

On the next launch, `LauncherActivity` presents the captured crash report (Kotlin exception or Rust panic from `rust_panic.txt`) so you can share it. A parser crash on a malformed document never terminates the app: panics are caught per file and recorded as a document error ([ADR-0005](../adr/0005-panic-strategy.md)).

## Update Fails to Install

Android installs an update over an existing app only when both APKs are signed with the exact same signing key. If Android reports a package conflict, the new APK was signed by a different certificate (for instance, switching between a GitHub release APK and an F-Droid-signed build). 2.0.0-beta.1 was signed with a new key, so a 1.x or 2.0 preview build has to be uninstalled first (export projects as `.foca.enc` beforehand if you need them). 2.0.0-beta.2, 2.0.0-beta.3, 2.0.0-beta.4 and 2.0.0-beta.4.1 use the same key as beta.1 and install over it; your projects stay. See [docs/dev/build.md](../dev/build.md) for signature verification details.
