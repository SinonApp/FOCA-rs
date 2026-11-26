# ADR-0006: Native Bridge: Single `foca` Command, In-App Kotlin Plugin

↑ [Decisions (ADR)](README.md) · [Documentation](../README.md)

- Status: accepted
- Decision:
  - The UI calls one Tauri command, `foca(cmd, args)` (`src-tauri/src/bridge.rs`): `platform_*` commands route to
    Kotlin, and everything else routes to `foca_engine::Engine::invoke` inside `spawn_blocking` + `block_on`. The
    capability grants only `allow-foca` and `core:event:allow-listen/unlisten`; CSP permits no external origins
    (`connect-src ipc:`).
  - The Kotlin plugin `app.sinon.focars.platform.FocaPlugin` lives directly in the app module (`gen/android/app`) and is
    registered by the built-in `foca-native` plugin (`register_android_plugin`), rather than a separate crate with a
    Gradle library: the foreground service, `FileProvider`, and permissions must be declared in the app manifest anyway,
    and a separate crate would add a `tauri-plugin` build dependency and `tauri.settings.gradle` generation for no
    benefit. The plugin has no ACL permissions: it is unreachable from JS and callable only from Rust.
  - Device events (network/VPN/battery/thermal/Stop button/`dataSync` timeout) flow from Kotlin to Rust over a
    `tauri::ipc::Channel` created in Rust (`Native::watch`); the channel is process-scoped (`FocaBus`) and works even
    without an Activity.
  - Pause decisions are made in Rust (`policy.rs`, pure logic covered by unit tests), not in JS: the WebView is frozen
    in the background, while a scan must pause immediately on VPN drop. The UI receives the `net` event and only renders
    state.
  - API keys: the engine's `KeyProvider` delegates to Kotlin `KeyVault` (AES-256-GCM, key stored in
    AndroidKeyStore/StrongBox, AAD = service name, ciphertext in private SharedPreferences); Rust maintains an in-memory
    value cache for the process lifetime.
- Constraint: `run_mobile_plugin` calls are blocking and execute on Android's main thread, Rust may invoke them only
  from background threads (commands already run in `spawn_blocking`; events run in the `foca-bridge` worker).

## Addendum: Background Scans, Recovery, and Logs

- **Why scans disappeared when minimizing.** Tauri binds to a single Activity: when it is destroyed (not a configuration
  change), tao emits `Destroyed`, the window is removed, and with an empty window list Tauri exits the process
  (`ExitRequested` → `process::exit`): a normal exit, so no crash screen appears. Because `MainActivity` is not the
  launcher Activity (`LauncherActivity` opens it), pressing system Back on the root screen did not minimize it but
  **closed** it (Android 12+ minimizes only the root launcher Activity) → process exit → lost scan. Swiping from Recents
  and OS Activity eviction trigger the same path.
- **Decision.** (1) System Back on root calls `moveTaskToBack(true)`; (2) `RunEvent::ExitRequested { code: None }` while
  a scan is running calls `prevent_exit()` (`recovery::keep_process_alive`), keeping the process with the engine and
  foreground service alive; a newly created `MainActivity` posts `ui/created` over `FocaBus`, and the bridge recreates
  the window from config (`WebviewWindowBuilder::from_config`, letting tao pick the available Activity); if the window
  fails to appear within 8 s, the process restarts; (3) the foreground service starts immediately in `scan_start` (while
  the UI is visible, since Android 12+ forbids starting an FGS from the background) and again on the `started` event;
  (4) service updates/stops and toasts go through direct JNI (`FocaDirect.call` via `ndk_context`), requiring neither an
  Activity nor the main thread, otherwise the service could not be stopped once the Activity is destroyed; (5) `Plugin`
  retrieves the live Activity from `PluginManager` rather than holding onto the one it was constructed with.
- **If the process is killed anyway** (HyperOS/MIUI without autostart, out-of-memory): `foca_engine::resume::interrupted_scan`
  reads `engine_run.json` prior to `Engine::open`; on the next launch, the scan resumes via `scan_start { resume_from }`
  when `settings.power.auto_resume` is enabled (default `true`) and it is not the 4th consecutive attempt within 10
  minutes (`auto_resume.json`, crash-loop guard). Shows a toast ("Scan was interrupted by the system: resuming") and
  emits `notice { kind: "auto_resumed" | "interrupted", scan_id, project, text }` to the UI. The service returns
  `START_STICKY` while a scan is active: if Android restarts it in a new process (no engine exists there: Rust boots
  only from an Activity), it displays a notification ("Scan interrupted by the system: tap to resume").
- **Logs** (`<dataDir>/logs/`, where `dataDir` = `/data/user/0/app.sinon.focars`): `foca.log`, Rust (engine and bridge,
  target `foca::app`; via `foca_engine::logs` subscriber, also exposed by `logs_get`), `android.log`: Kotlin (`FLog`,
  1 MB × 3), `crash-*.txt`: Rust panics with backtrace (last 5; `files/rust_panic.txt` triggers the crash screen). All
  entries are mirrored to logcat with tag `FOCA`. Logs record Activity/Service lifecycle, service start/stop and failure
  reasons, policy decisions, network/power state, plugin calls with durations, and on every startup the exit reasons of
  previous processes (`ApplicationExitInfo`: `CRASH` / `LOW_MEMORY` / `OTHER` (OEM shell) / `EXIT_SELF`…).
