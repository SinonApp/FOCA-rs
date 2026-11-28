# Android & Kotlin Layer

↑ [Developer Guide](README.md) · [Architecture](architecture.md)

- [Package Identity and Product Flavors (`foss` vs `play`)](#package-identity-and-product-flavors-foss-vs-play)
- [Kotlin File Map](#kotlin-file-map)
- [`src-tauri` Rust Bridge](#src-tauri-rust-bridge)
- [Two Kotlin Invocation Paths: Plugin and `FocaDirect`](#two-kotlin-invocation-paths-plugin-and-focadirect)
- [Flavor-Split OCR (`OcrEngine.kt`)](#flavor-split-ocr-ocrenginekt)
- [Device Info (`locale` & `flavor`) and Android String Resources](#device-info-locale--flavor-and-android-string-resources)
- [Background Scanning: `ScanService` and Recovery](#background-scanning-scanservice-and-recovery)
- [`RenderFetcher`, `VerifyDialog`, and `WebScreenshotter`](#renderfetcher-verifydialog-and-webscreenshotter)
- [`KeyVault` and `ReportSigner`](#keyvault-and-reportsigner)
- [Monitoring: WorkManager, Headless Execution, and Notifications](#monitoring-workmanager-headless-execution-and-notifications)
- [Logs and Crash Handling](#logs-and-crash-handling)
- [Share Target: "Check in FOCA-rs"](#share-target-check-in-foca-rs)
- [Unit Tests and Compile Checks](#unit-tests-and-compile-checks)

## Package Identity and Product Flavors (`foss` vs `play`)

Application package: `app.sinon.focars`, `minSdk 24`, `targetSdk 36`, `compileSdk 37`. The manifest declares `LauncherActivity` (exported entry point + Share Target), `MainActivity` (Tauri WebView), `.platform.ScanService` (`dataSync` foreground service), and `FileProvider`.

The package name is defined in one canonical place, `identifier` in `src-tauri/tauri.conf.json`: `tauri-build` derives JNI symbol names (`Java_app_sinon_focars_…`) from it, and `tauri android build` generates `app/src/main/java/app/sinon/focars/generated`. If you ever rename the package, update together: `identifier` in `tauri.conf.json`, `namespace` and `applicationId` in `app/build.gradle.kts`, Kotlin directories and `package` declarations (`main`, `foss`, `play`, `test`), `proguard-rules.pro` keep rules, and class names in `src-tauri/src/native.rs` / `headless.rs`; delete the old `generated/` directory. Verify consistency with `bash qa/check-jni.sh` (included in `qa/run-all.sh static`).

### Distribution Flavors (`build.gradle.kts`)

`src-tauri/gen/android/app/build.gradle.kts` defines `flavorDimensions += "distribution"` with two product flavors:

| Flavor | `BuildConfig.HAS_MLKIT_OCR` | ML Kit Dependency | OCR Behavior | Distribution Target |
|---|---|---|---|---|
| `foss` | `false` | None (100% open-source) | Stub returns `unavailable_in_foss_build` | F-Droid / GPL-3.0 pure releases |
| `play` | `true` | `playImplementation("com.google.mlkit:text-recognition:16.0.1")` | Offline on-device OCR for scanned PDFs & images | Full Android release with optional ML Kit OCR |

All other features (metadata extraction, forensics, hygiene cleaning, OSINT discovery, TLS/network/port/recon/fuzz modules, reports, plugins, encrypted `.foca.enc` bundles) behave identically in both flavors. `python qa/gen-licenses.py --check` enforces that zero `com.google.mlkit` references exist anywhere in `src/main/` or `src/foss/`.

## Kotlin File Map

Source roots under `src-tauri/gen/android/app/src/`:

| File | Lines | Role |
|---|---|---|
| `main/.../LauncherActivity.kt` | 70 | Entry point without loading Rust/WebView: displays crash screen if a previous crash exists, otherwise launches `MainActivity` and forwards Share intents |
| `main/.../MainActivity.kt` | 239 | Tauri WebView host, native insets/theme, Back handling (`moveTaskToBack` at root), window recreation while a scan is alive |
| `main/.../CrashLog.kt` | 116 | Captures Java/Kotlin uncaught exceptions and Rust panics to files; holds fallback app version string |
| `main/.../platform/FocaPlugin.kt` | 736 | Tauri plugin `foca-native`: handles `platform_*` commands (`device_info`, share/save/print, biometric, secure screen, battery, permissions, folder/file picker, `verify_search`, shared inbox) |
| `main/.../platform/FocaDirect.kt` | 153 | Direct JNI entry point from Rust + headless monitor JNI bridge (`scan_service_*`, `scan_done_notify`, `monitor_schedule`, `render_fetch`, `report_sign`/`report_sig_verify`, `ocr_recognize`, `web_screenshot`, `toast`) |
| `main/.../platform/SelfUpdate.kt` | 230 | In-app update install: `update_permission` ("Install unknown apps"), APK certificate/package/versionCode check, PackageInstaller session, `UpdateReceiver` (confirmation intent, failures to `FocaBus`), download notification (`update_notify`, channel `app_update`); off when `BuildConfig.SELF_UPDATE` is false |
| `main/.../platform/UpdateLogic.kt` | 60 | Pure update checks: certificate set match, verdict order, cache path confinement, percent (JUnit-tested) |
| `main/.../platform/FocaBus.kt` | 39 | Device event channel into Rust (`Native::watch`) |
| `main/.../platform/DeviceMonitor.kt` | 139 | Monitors network (Wi-Fi/mobile/VPN/metered), battery level/charging, and thermal state → `FocaBus` |
| `main/.../platform/ScanService.kt` | 341 | Foreground service (`dataSync`): persistent scan progress notification with Open/Stop actions, `WAKE_LOCK`, Android 15+ timeout handling |
| `main/.../platform/RecoveryLogic.kt` | 105 | Pure `onStartCommand` recovery logic (JUnit-tested) |
| `main/.../platform/RenderFetcher.kt` | 382 | Hidden WebView for search-engine dorks (executes core `RenderRequest` steps) |
| `main/.../platform/RenderLogic.kt` | 72 | Pure hidden-browser profile logic (JUnit-tested) |
| `main/.../platform/UaForm.kt` | 40 | Builds honest WebView User-Agent string without `; wv` marker (JUnit-tested) |
| `main/.../platform/VerifyDialog.kt` | 75 | Full-screen visible WebView sharing `CookieManager` for manual CAPTCHA/verification |
| `main/.../platform/WebScreenshotter.kt` | 124 | Isolated offscreen WebView snapshotter (cookies disabled, no cache, JS off) returning thumbnail PNG + 9×8 luminance grid for 64-bit `dHash` |
| `main/.../platform/KeyVault.kt` | 85 | API keys & alert secrets: AES-256-GCM with AndroidKeyStore/StrongBox key and service name as AAD |
| `main/.../platform/ReportSigner.kt` | 112 | Hardware-backed ECDSA P-256 (`secp256r1`) report and `.foca.enc` bundle signing/verification via AndroidKeyStore |
| `main/.../platform/MonitorWorker.kt` | 248 | WorkManager worker for scheduled rescans (runs live via `FocaBus`, headlessly via `FocaDirect.runHeadlessMonitor`, or posts reminder notification) |
| `main/.../platform/MonitorLogic.kt` | 82 | Pure schedule computation logic (JUnit-tested) |
| `main/.../platform/OcrLogic.kt` | 66 | Pure path-confinement, MIME, page-clamping, bitmap downscaling, and UTF-8 truncation helpers for OCR (JUnit-tested) |
| `play/.../platform/OcrEngine.kt` | 118 | `play` flavor offline OCR via Google ML Kit Text Recognition (`PdfRenderer` + `BitmapFactory`) |
| `foss/.../platform/OcrEngine.kt` | 16 | `foss` flavor stub returning `unavailable_in_foss_build` with zero ML Kit dependencies |
| `main/.../platform/ShareInbox.kt` | 127 | Copies incoming `content://` Share intents into `files/shared_in/in-<ts>/` |
| `main/.../platform/ShareLogic.kt` | 82 | Pure Share Target validation and size/count limit logic (JUnit-tested) |
| `main/.../platform/BackLogic.kt` | 25 | Routes Back presses to `FOCA.back()`; minimizes app only when UI returns `"root"` (JUnit-tested) |
| `main/.../platform/PlatformLogic.kt` | 250 | Shared pure platform helpers: OEM ROM detection, path/filename sanitization (JUnit-tested) |
| `main/.../platform/FLog.kt` | 95 | Rotating `android.log` logger (1 MB × 3) |
| `main/.../platform/AppLocale.kt` | 38 | Native texts in the app language: the UI reports its language through `FocaNative.setLang`; strings resolve via `AppLocale.wrap(ctx)` |
| `main/.../platform/RecentsGuard.kt` | 104 | Hides the task from Recents (`setExcludeFromRecents`) while a scan runs in the background; unhides on resume, scan end and cold start |
| `main/.../platform/RecentsLogic.kt` | 97 | Pure "hide from Recents" decisions and OEM defaults (native pref `hide_recents`, missing = OEM default; JUnit-tested) |
| `main/.../platform/ScanResumeWorker.kt` | 98 | Delayed one-time work after the system kills the app mid-scan: restarts `ScanService` and resumes headlessly, or posts the "Continue" notification |
| `main/java/android/print/PdfPrintDriver.java` | - | Writes an HTML report to a PDF file through the package-private `android.print` callbacks (Java + ProGuard keep rule; backs `platform_pdf`) |

## `src-tauri` Rust Bridge

`src-tauri/src/` (crate `foca-rs`, cdylib `libfoca_rs_lib.so`):

| File | Role |
|---|---|
| `bridge.rs` | Single Tauri command `foca(cmd, args)`, `scan://event` / `net` / `shared` events, foreground service lifecycle, `NativeRender`, `NativeOcr`, `NativeScreenshotter`, `NativeSigner`, and attaching to a running headless engine |
| `headless.rs` | Headless background monitoring runner invoked by `MonitorWorker` over JNI (`nativeRunHeadlessMonitor` / `nativeCancelHeadlessMonitor`) when no Activity/Tauri `AppHandle` is active; enforces `passive`/`std` profiles, ≤ 8 min budget, shared `DataDirLock`, and seamless UI handoff (`attach_live_engine`) |
| `native.rs` | Android Kotlin plugin wrapper (`run_mobile_plugin`) + desktop stubs; JNI `direct_call` into `FocaDirect.call` |
| `policy.rs` | Pause/stop policy for network, VPN kill-switch, battery, thermal, and Android `dataSync` limits: pure logic with unit tests |
| `recovery.rs` | Background execution and unload recovery state machine: pure logic tested standalone via `rustc --test` |
| `monitor.rs` | Localized notification text for completed scans and schedule derivation from `settings.monitor` |
| `applog.rs` | Android `logcat` (tag `FOCA`) + `tracing` integration under target `foca::app` |
| `headless/resume.rs` | Resumes a scan killed by the system without the UI (`FocaDirect.resumeInterruptedScan` from `ScanResumeWorker`): same auto-resume rules as the app, full scan, hand-over to the UI on attach |
| `devstate.rs` | Pause policy inputs from settings and Kotlin device events; shared by the bridge and the headless runner |
| `scan_note.rs` | Contents of the scan foreground notification; shared by the bridge and the headless runner |

See [ADR-0006](../adr/0006-native-bridge.md) and [docs/API.md](../API.md) for the `platform_*` command contract.

## Two Kotlin Invocation Paths: Plugin and `FocaDirect`

- **Tauri Plugin (`FocaPlugin` via `run_mobile_plugin`)**: runs on the Android main thread and requires a live `Activity`. Rust must call it only from background threads (Tauri commands run in `spawn_blocking`). Used for UI-bound operations (file pickers, biometric prompt, print/share sheets, `VerifyDialog`, `device_info`).
- **Direct JNI (`FocaDirect.call` via `ndk_context`)**: works without an `Activity` and without occupying the main thread. Used for `ScanService`, notifications, `RenderFetcher`, `WebScreenshotter`, `OcrEngine`, `ReportSigner`, `MonitorWorker.schedule`, and toasts. Any blocking Kotlin call that posts work to the main `Looper` (such as offscreen WebView rendering) must go through `FocaDirect` from a background thread: calling it through `FocaPlugin` deadlocks the main thread.

## Flavor-Split OCR (`OcrEngine.kt`)

Optional on-device offline OCR (`settings.ocr.enabled`, disabled by default) is split cleanly across Gradle flavor source sets:

- **`src/play/java/app/sinon/focars/platform/OcrEngine.kt`**: uses `com.google.mlkit:text-recognition` (`TextRecognition.getClient(TextRecognizerOptions.DEFAULT_OPTIONS)`). Renders scanned PDF pages via `android.graphics.pdf.PdfRenderer` or decodes images via `BitmapFactory` using bounds computed by `OcrLogic`, enforces app-private path confinement (`OcrLogic.isSafeLocalPath`), caps pages (`1..50`) and UTF-8 output (`64 KiB`), recycles every `Bitmap` immediately, and runs synchronously on the calling JNI thread (`FocaDirect.call("ocr_recognize")`) with zero network access.
- **`src/foss/java/app/sinon/focars/platform/OcrEngine.kt`**: provides the exact same `object OcrEngine { fun recognize(ctx: Context, a: JSObject): JSObject }` symbol, returning `{ "ok": false, "error": "unavailable_in_foss_build", "flavor": "foss" }`.

## Device Info (`locale` & `flavor`) and Android String Resources

`FocaPlugin.device_info` returns runtime environment metadata consumed by the UI and debug screen, including:

- **`locale`**: `java.util.Locale.getDefault().toLanguageTag()` (e.g., `en-US`, `uk-UA`, `ru-RU`, `de-DE`). At startup, `ui/js/api.js` passes `device_info.locale` to `i18n_bundle { lang, device_locale }`, where `foca_core::Lang::resolve_setting` maps `uk*`/`ua*` → `uk`, `ru*` → `ru`, and all other locales → `en` whenever `settings.lang` is `"auto"`.
- **`flavor`**: `BuildConfig.FLAVOR.ifEmpty { "foss" }` (`"foss"` or `"play"`). Displayed in Settings → About / Debug and used to indicate whether ML Kit OCR is compiled into the APK.

Native Android user-facing strings (app name, Share Target label, foreground service description, notification channels, Open/Stop actions, monitoring status/errors, and `VerifyDialog` prompt) live in standard Android resource qualifiers:

- `src-tauri/gen/android/app/src/main/res/values/strings.xml`: English (default fallback for all unsupported locales);
- `src-tauri/gen/android/app/src/main/res/values-ru/strings.xml`: Russian;
- `src-tauri/gen/android/app/src/main/res/values-uk/strings.xml`: Ukrainian.

## Background Scanning: `ScanService` and Recovery

- `ScanService` starts during `scan_start` while the UI is in the foreground (Android 12+ forbids starting foreground services from the background), updates progress on scan events, and stops on `done`/`stopped`. On Android 15+, the 6-hour `dataSync` timeout pauses the scan with reason `android`.
- Tauri normally terminates the process when the last `Activity` is destroyed. To keep scans alive: pressing Back at the root screen calls `moveTaskToBack(true)`, `ExitRequested` during an active scan calls `prevent_exit()`, and a newly opened `MainActivity` sends `ui/created` so the bridge reattaches the WebView window.
- If the OS still kills the process (e.g., aggressive OEM battery managers), `engine_run.json` triggers `scan_start { resume_from }` on next launch (`settings.power.auto_resume`, loop guard: max 3 retries in 10 minutes).
- Aggressive firmwares (HyperOS/MIUI, One UI, EMUI, ColorOS, Funtouch): `platform_bg_status` reports the OEM, autostart (`on`/`off`/`unknown`, MIUI app-op 10008) and battery state for the setup card in "Settings → Background execution" and on the launch screen. `RecentsGuard` hides the task from Recents while a scan runs in the background (`platform_bg_set { hide_recents }`), so a swipe or "clear all" cannot kill it. A separate `:scan` process and a `VpnService` were rejected: HyperOS kills both processes, and a VPN would take the only VPN slot from the user's AdGuard/v2ray.
- Resume without the UI: a swipe-kill (`ScanService.onTaskRemoved`, 15 s delay) or a sticky restart without the core queues `ScanResumeWorker`. In a new process it starts `ScanService` and calls `FocaDirect.resumeInterruptedScan` → `headless::resume` (same rules as on app launch; the run continues as a full scan, `headless: false`). `FocaBus` hands network/power events and the notification Stop action to that core (`nativeHeadlessEvent`) for the usual pause policy; opening the app attaches the UI to the running engine (`attach_live_engine`, single data-dir lock). When Android refuses the background service start (Android 12+ unless the app is exempt from battery optimisation) or the core does not resume, the worker posts "Scan interrupted: Continue" instead.

## `RenderFetcher`, `VerifyDialog`, and `WebScreenshotter`

- **`RenderFetcher`**: runs `foca-search::render::RenderRequest` scripts (`wait`, `submit`, Next pagination), one job at a time, reusing one WebView per session and shared `CookieManager` cookies. Applies `settings.net` proxy via AndroidX `ProxyController` (fails closed if unsupported) and tears down idle WebViews after 10 minutes. Uses an honest mobile browser profile without `X-Requested-With`.
- **`VerifyDialog`**: full-screen visible WebView sharing the same `CookieManager`. `platform_verify_search { url }` allow-lists only supported search engines (`startpage.com`, `mojeek.com`, `search.brave.com`, `search.yahoo.com`). Completing verification lets the user retry the source (`scan_retry_source`).
- **`WebScreenshotter`**: isolated offscreen WebView for `foca-recon::screenshot` (`I-13`, opt-in via `settings.recon.screenshots`). Disables cookies, JavaScript, file/content access, and caching, draws the page into a bounded bitmap, computes a 9×8 grayscale luminance grid for 64-bit `dHash` perceptual deduplication, encodes a PNG thumbnail, and destroys the WebView immediately.

## `KeyVault` and `ReportSigner`

- **`KeyVault`**: backs `foca-engine::KeyProvider`. Encrypts each API key or alert secret with AES-256-GCM using a key stored in `AndroidKeyStore` (StrongBox when available), stores ciphertext in private `SharedPreferences`, and binds the service name as AEAD AAD so ciphertext cannot be transplanted across services. Rust caches values in process memory; SQLite stores only status and mask.
- **`ReportSigner`**: generates/uses a non-exportable `AndroidKeyStore` ECDSA P-256 (`secp256r1`, alias `focars_report_sign_p256`) keypair for `SHA256withECDSA` signing and verification of Chain-of-Custody report manifests (`.sig.json`) and `.foca.enc` bundles via `FocaDirect.call("report_sign" | "report_sig_verify")`.

## Monitoring: WorkManager, Headless Execution, and Notifications

| Notification Channel | Importance | Purpose |
|---|---|---|
| `scan` | `LOW` | Persistent progress notification while a scan is running |
| `scan_done` | `DEFAULT` | Scan completed summaries and scheduled monitoring results/reminders |

`settings.monitor` → `monitor_schedule` schedules a daily `PeriodicWorkRequest` near the configured time with unmetered network (`wifi`), charging (`charge`), and non-low-battery constraints:

1. If the UI/engine process is already alive (`FocaBus` attached), `MonitorWorker` sends `{ kind: "monitor" }` → `scan_start { trigger: "schedule" }` and awaits completion.
2. If no Activity is open, `MonitorWorker` calls `FocaDirect.runHeadlessMonitor(...)` → `src-tauri/src/headless.rs`, which runs a `passive` or `std` scan inside a bounded ≤ 8 minute budget, skips WebView-only dorks as `skipped_headless`, fires alerts, and posts the diff summary notification. If the user opens the app while headless monitoring is running, `bridge.rs` seamlessly attaches to the live engine.

## Logs and Crash Handling

`<dataDir>/logs/` contains `foca.log` (Rust rotating log), `android.log` (Kotlin `FLog`, 1 MB × 3), and `crash-*.txt` (last 5 stack traces / Rust panic backtraces); `files/rust_panic.txt` triggers `LauncherActivity`'s crash report screen on next startup. On launch, previous process exit reasons (`ApplicationExitInfo`) are recorded. All logs mirror to `logcat` under tag `FOCA`.

## Share Target: "Check in FOCA-rs"

- Only `LauncherActivity` is exported, so `ACTION_SEND` and `ACTION_SEND_MULTIPLE` intent filters (documents, images, ZIP, EML: never `*/*`) live on `LauncherActivity` and forward via `ShareInbox.forward` to `MainActivity` (`singleTask`) with `ClipData` and `FLAG_GRANT_READ_URI_PERMISSION`.
- `ShareInbox.take` (`onCreate` / `onNewIntent`) copies only `content://` URIs into `files/shared_in/in-<ts>/` (max 20 files, 256 MB total, 100 MB per file, flattened filenames; pure logic verified by `ShareLogicTest`).
- Delivery to the UI works both before and after WebView load via `platform_shared_files` on boot and `FocaBus` `shared` events → `app.emit("shared")`.

## Unit Tests and Compile Checks

- **Kotlin JUnit** (`src-tauri/gen/android/app/src/test/.../platform/*Test.kt`, 11 files, 60 `@Test` cases covering `BackLogic`, `MonitorLogic`, `OcrLogic`, `PlatformLogic`, `RecentsLogic`, `RecoveryLogic`, `RenderLogic`, `ReportSigner`, `ShareLogic`, `SsrfGuard`, `UaForm`):
  ```sh
  cd src-tauri/gen/android && ./gradlew :app:testUniversalFossDebugUnitTest -PtargetList=aarch64 -ParchList=arm64 -PabiList=arm64-v8a -x rustBuildArm64Debug -x rustBuildUniversalDebug
  ```
- **Kotlin compile of both flavors + JUnit in one step**: `bash qa/check-kotlin.sh` (Gradle: `compileUniversal{Foss,Play}ReleaseKotlin` + `testUniversalFossDebugUnitTest`, prints `OK (N tests)`; on a clean checkout it first runs `qa/android-build.sh kotlin` to generate the Tauri Gradle files).
- **JNI symbol verification**: `bash qa/check-jni.sh`.
- **Rust bridge pure logic on desktop**:
  ```sh
  cargo test -p foca-rs --lib     # policy, recovery, headless resume (simulate the kill with engine.abandon())
  ```
- WebView rendering, notifications, Keystore hardware signing, and background `ScanService` behavior must be verified on a physical Android device.
