//! UI ↔ engine bridge: a single Tauri command `foca(cmd, args)`, the `scan://event` and `net`
//! events, the pause policy driven by device state, the scan foreground service and platform
//! commands.
//!
//! ```text
//! JS invoke("foca",{cmd,args}) ─► foca() ─► spawn_blocking ─► Bridge::dispatch
//!        ├─ platform_* ───────────────► Native (Kotlin FocaPlugin)
//!        ├─ scan_pause/scan_resume ───► Policy (user + environment) ─► Engine::pause/resume
//!        └─ everything else ──────────► Engine::invoke (block_on)
//! Engine ─EventSink─► app.emit("scan://event") + worker ─► scan_service_* (notification, WAKE_LOCK)
//! Kotlin Monitor ─Channel─► worker ─► Policy ─► pause/resume/scan_stop ─► app.emit("net", …)
//! ```
//!
//! Background operation and recovery (Android, see `recovery.rs`):
//! - the foreground service starts right away in `scan_start` (the UI is on screen, so starting
//!   is allowed) and again on the `started` event if it did not start;
//! - destroying the Activity during a scan does not end the process ([`on_run_event`]); the new
//!   Activity sends `ui/created`, the Tauri window is recreated and the UI reloads;
//! - if the process is killed anyway, [`foca_engine::resume`] continues the scan on the next
//!   launch (`power.auto_resume`, on by default), showing a toast and sending a `notice` event
//!   to the UI.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, OnceLock};
use std::time::Duration;

use foca_engine::{CmdError, Engine, EngineConfig, EventSink, KeyProvider, MemoryKeys};
use serde_json::{json, Value};
use tauri::{AppHandle, Emitter, Manager, RunEvent};

use crate::native::{Native, NoNative};
use crate::policy::{Action, Env, Policy, PolicySettings};
use crate::recovery::{self, ResumeDecision};
use crate::scan_note::{reason_label, ServiceState};

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

fn err(code: &str, msg: impl Into<String>) -> CmdError {
    CmdError::new(code, msg)
}

/// A value that becomes available later (the engine opens in the background after the
/// WebView starts).
struct Slot<T> {
    v: Mutex<Option<Result<T, CmdError>>>,
    cv: Condvar,
}

impl<T: Clone> Slot<T> {
    fn new() -> Self {
        Slot {
            v: Mutex::new(None),
            cv: Condvar::new(),
        }
    }
    fn set(&self, r: Result<T, CmdError>) {
        *lock(&self.v) = Some(r);
        self.cv.notify_all();
    }
    fn get(&self) -> Option<T> {
        lock(&self.v)
            .as_ref()
            .and_then(|r| r.as_ref().ok().cloned())
    }
    fn wait(&self, t: Duration) -> Result<T, CmdError> {
        let g = lock(&self.v);
        let (g, _) = self
            .cv
            .wait_timeout_while(g, t, |v| v.is_none())
            .unwrap_or_else(|p| p.into_inner());
        match g.as_ref() {
            Some(r) => r.clone(),
            None => Err(err("busy", "ядро ещё открывается: повторите через секунду")),
        }
    }
}

enum Msg {
    Scan(Value),
    Device(Value),
    Settings(Value),
}

struct PolicyState {
    policy: Policy,
    env: Env,
    settings: PolicySettings,
    secure: Option<bool>,
}

pub struct Bridge {
    app: AppHandle,
    native: Arc<dyn Native>,
    engine: Slot<Engine>,
    policy: Mutex<PolicyState>,
    svc: Mutex<ServiceState>,
    tx: Mutex<Sender<Msg>>,
    data_dir: OnceLock<PathBuf>,
    /// `scan_start` arguments of a scan interrupted when the previous process was killed (read
    /// before `Engine::open`).
    pending_resume: Mutex<Option<Value>>,
    /// The Activity was destroyed during a scan while the process was kept alive; the window
    /// must be recreated.
    window_lost: AtomicBool,
    /// The engine was handed over by a background core with a scan already running.
    attached: AtomicBool,
    /// Last monitoring schedule handed to WorkManager (avoids calling Kotlin when nothing
    /// changed).
    monitor_sent: Mutex<String>,
}

/// Tauri state: `State<'_, Shared>`.
pub type Shared = Arc<Bridge>;

// API keys: Android Keystore via Kotlin (AES-GCM, ciphertext in SharedPreferences).

struct NativeKeys {
    native: Arc<dyn Native>,
    cache: Mutex<HashMap<String, Option<String>>>,
}

impl KeyProvider for NativeKeys {
    fn get(&self, service: &str) -> Option<String> {
        if let Some(v) = lock(&self.cache).get(service) {
            return v.clone();
        }
        match self
            .native
            .call("keystore_get", json!({ "service": service }))
        {
            Ok(v) => {
                let val = v.get("value").and_then(Value::as_str).map(str::to_string);
                lock(&self.cache).insert(service.to_string(), val.clone());
                val
            }
            Err(e) => {
                awarn!("keystore_get {service}: {e}");
                None
            }
        }
    }
    fn set(&self, service: &str, value: &str) -> Result<(), String> {
        self.native.call(
            "keystore_set",
            json!({ "service": service, "value": value }),
        )?;
        lock(&self.cache).insert(service.to_string(), Some(value.to_string()));
        Ok(())
    }
    fn delete(&self, service: &str) -> Result<(), String> {
        self.native
            .call("keystore_delete", json!({ "service": service }))?;
        lock(&self.cache).insert(service.to_string(), None);
        Ok(())
    }
}

// Hidden WebView for search engines with a JS challenge (Startpage, Brave, Mojeek): Kotlin
// RenderFetcher.

struct NativeRender {
    native: Arc<dyn Native>,
}

impl foca_engine::RenderFetch for NativeRender {
    fn fetch<'a>(
        &'a self,
        req: foca_engine::RenderRequest,
    ) -> foca_engine::BoxFuture<'a, Result<foca_engine::RenderPage, String>> {
        let native = self.native.clone();
        Box::pin(async move {
            let args = serde_json::to_value(&req).map_err(|e| e.to_string())?;
            // The call blocks the thread until the script finishes (seconds to minutes), so keep it off
            // the engine runtime.
            let r = tauri::async_runtime::spawn_blocking(move || native.call("render_fetch", args))
                .await
                .map_err(|e| format!("render_fetch: {e}"))??;
            serde_json::from_value(r).map_err(|e| format!("ответ render_fetch: {e}"))
        })
    }
}

struct NativeSigner {
    native: Arc<dyn Native>,
}

impl foca_engine::ReportSigner for NativeSigner {
    fn sign(&self, payload: &[u8]) -> Result<foca_engine::ReportSignature, String> {
        let r = self.native.call(
            "report_sign",
            json!({ "payload_b64": foca_core::b64::encode(payload) }),
        )?;
        Ok(foca_engine::ReportSignature {
            alg: r
                .get("alg")
                .and_then(Value::as_str)
                .unwrap_or("ECDSA-P256-SHA256")
                .to_string(),
            key_alias: r
                .get("key_alias")
                .and_then(Value::as_str)
                .unwrap_or("focars_report_sign_p256")
                .to_string(),
            sig_b64: r
                .get("sig_b64")
                .and_then(Value::as_str)
                .ok_or_else(|| "нет sig_b64 в ответе report_sign".to_string())?
                .to_string(),
            pubkey_b64: r
                .get("pubkey_b64")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string(),
        })
    }

    fn verify(&self, payload: &[u8], sig: &foca_engine::ReportSignature) -> Result<bool, String> {
        let r = self.native.call(
            "report_sig_verify",
            json!({
                "payload_b64": foca_core::b64::encode(payload),
                "sig_b64": sig.sig_b64,
                "pubkey_b64": sig.pubkey_b64,
            }),
        )?;
        Ok(r.get("valid").and_then(Value::as_bool).unwrap_or(false))
    }

    fn verify_detail(
        &self,
        payload: &[u8],
        sig: &foca_engine::ReportSignature,
    ) -> Result<foca_engine::SignatureCheck, String> {
        let r = self.native.call(
            "report_sig_verify",
            json!({
                "payload_b64": foca_core::b64::encode(payload),
                "sig_b64": sig.sig_b64,
                "pubkey_b64": sig.pubkey_b64,
            }),
        )?;
        let b = |k: &str| r.get(k).and_then(Value::as_bool);
        // `valid` = own key; `foreign_valid` = valid under another device's embedded key.
        let own = b("valid").unwrap_or(false);
        let foreign = b("foreign_valid").unwrap_or(false);
        Ok(foca_engine::SignatureCheck {
            valid: own || foreign,
            own_key: b("own_key").unwrap_or(own),
        })
    }
}

struct NativeOcr {
    native: Arc<dyn Native>,
}

impl foca_engine::OcrProvider for NativeOcr {
    fn recognize(&self, req: foca_engine::OcrRequest) -> Result<foca_engine::OcrResult, String> {
        let args = serde_json::to_value(&req).map_err(|e| e.to_string())?;
        let r = self.native.call("ocr_recognize", args)?;
        Ok(foca_engine::OcrResult {
            text: r
                .get("text")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string(),
            pages: r.get("pages").and_then(Value::as_u64).unwrap_or(1) as u32,
            engine: r
                .get("engine")
                .and_then(Value::as_str)
                .unwrap_or("mlkit")
                .to_string(),
        })
    }
}

struct NativeScreenshotter {
    native: Arc<dyn Native>,
}

impl foca_engine::WebScreenshotter for NativeScreenshotter {
    fn capture(
        &self,
        req: &foca_engine::ScreenshotRequest,
    ) -> Result<foca_engine::ScreenshotRaw, String> {
        let args = serde_json::to_value(req).map_err(|e| e.to_string())?;
        let r = self.native.call("web_screenshot", args)?;
        let luma_9x8 = r
            .get("luma_9x8")
            .and_then(Value::as_array)
            .map(|arr| {
                arr.iter()
                    .filter_map(Value::as_u64)
                    .map(|v| v.min(255) as u8)
                    .collect()
            })
            .unwrap_or_default();
        Ok(foca_engine::ScreenshotRaw {
            width: r.get("width").and_then(Value::as_u64).unwrap_or(360) as u32,
            height: r.get("height").and_then(Value::as_u64).unwrap_or(640) as u32,
            luma_9x8,
            image_b64: r
                .get("image_b64")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string(),
            title: r
                .get("title")
                .and_then(Value::as_str)
                .map(str::to_string)
                .filter(|s| !s.is_empty()),
        })
    }
}

// Engine events → WebView + worker.

struct Sink {
    app: AppHandle,
    tx: Mutex<Sender<Msg>>,
}

impl EventSink for Sink {
    fn emit(&self, event: &Value) {
        if let Err(e) = self.app.emit("scan://event", event) {
            awarn!("emit scan://event: {e}");
        }
        // The engine may hold its own locks during emit, so heavy work (JNI, pause) is left to the
        // worker.
        let _ = lock(&self.tx).send(Msg::Scan(event.clone()));
    }
}

// Initialization.

/// Called from `setup`: registers the state and starts the worker and the engine opening in
/// the background.
pub fn init(app: AppHandle, native_slot: Arc<OnceLock<Arc<dyn Native>>>) -> Shared {
    let native: Arc<dyn Native> = native_slot
        .get()
        .cloned()
        .unwrap_or_else(|| Arc::new(NoNative));
    let (tx, rx) = channel();
    let b = Arc::new(Bridge {
        app: app.clone(),
        native,
        engine: Slot::new(),
        policy: Mutex::new(PolicyState {
            policy: Policy::new(),
            env: Env::default(),
            settings: PolicySettings::default(),
            secure: None,
        }),
        svc: Mutex::new(ServiceState::default()),
        tx: Mutex::new(tx),
        data_dir: OnceLock::new(),
        pending_resume: Mutex::new(None),
        window_lost: AtomicBool::new(false),
        attached: AtomicBool::new(false),
        monitor_sent: Mutex::new(String::new()),
    });
    alog!(
        "мост: нативный слой {}",
        if b.native.real() {
            "Android (FocaPlugin)"
        } else {
            "заглушка (нет плагина)"
        }
    );
    app.manage(b.clone());

    let w = b.clone();
    let _ = std::thread::Builder::new()
        .name("foca-bridge".into())
        .spawn(move || w.worker(rx));

    let o = b.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let t0 = std::time::Instant::now();
        let r = o.open_engine();
        match &r {
            Err(e) => aerr!("Engine::open: {e}"),
            Ok(_) => alog!("движок открыт за {} мс", t0.elapsed().as_millis()),
        }
        o.engine.set(r);
        o.after_open();
    });
    b
}

impl Bridge {
    fn open_engine(&self) -> Result<Engine, CmdError> {
        let data_dir = self
            .app
            .path()
            .app_data_dir()
            .map_err(|e| err("internal", format!("app_data_dir: {e}")))?;
        std::fs::create_dir_all(&data_dir)?;
        crate::applog::set_dir(&data_dir.join("logs"));
        let _ = self.data_dir.set(data_dir.clone());
        let sink: Arc<dyn EventSink> = Arc::new(Sink {
            app: self.app.clone(),
            tx: Mutex::new(lock(&self.tx).clone()),
        });
        let ui_render: Option<Arc<dyn foca_engine::RenderFetch>> = self.native.real().then(|| {
            Arc::new(NativeRender {
                native: self.native.clone(),
            }) as Arc<dyn foca_engine::RenderFetch>
        });
        let ui_signer: Option<Arc<dyn foca_engine::ReportSigner>> = self.native.real().then(|| {
            Arc::new(NativeSigner {
                native: self.native.clone(),
            }) as Arc<dyn foca_engine::ReportSigner>
        });
        let ui_ocr: Option<Arc<dyn foca_engine::OcrProvider>> = self.native.real().then(|| {
            Arc::new(NativeOcr {
                native: self.native.clone(),
            }) as Arc<dyn foca_engine::OcrProvider>
        });
        let ui_screenshotter: Option<Arc<dyn foca_engine::WebScreenshotter>> =
            self.native.real().then(|| {
                Arc::new(NativeScreenshotter {
                    native: self.native.clone(),
                }) as Arc<dyn foca_engine::WebScreenshotter>
            });
        let keys: Arc<dyn KeyProvider> = if self.native.real() {
            Arc::new(NativeKeys {
                native: self.native.clone(),
                cache: Mutex::new(HashMap::new()),
            })
        } else {
            // Desktop (development): keys live only in process memory and are never written to disk in
            // clear text.
            Arc::new(MemoryKeys::new())
        };
        if let Some(engine) = crate::headless::attach_live_engine(
            &data_dir,
            keys.clone(),
            sink.clone(),
            ui_render.clone(),
            ui_signer.clone(),
            ui_ocr.clone(),
            ui_screenshotter.clone(),
        ) {
            alog!("мост: подключён к живому фоновому ядру (headless handoff)");
            self.attached.store(true, Ordering::SeqCst);
            return Ok(engine);
        }
        // Read the previous process's scan BEFORE Engine::open, which turns it into stopped/restart.
        let interrupted = foca_engine::resume::interrupted_scan(&data_dir);
        if let Some(a) = &interrupted {
            awarn!(
                "прошлый процесс выгружен во время скана {} (проект {})",
                a["resume_from"].as_str().unwrap_or("?"),
                a["project"].as_str().unwrap_or("?")
            );
        }
        *lock(&self.pending_resume) = interrupted;
        let mut cfg = EngineConfig::new(&data_dir);
        // Exports and reports stay in the private directory; they leave it only via share or save
        // to files.
        cfg.export_dir = data_dir.join("exports");
        // `time` cannot determine the local zone on Android (current_local_offset → Err), so ask the
        // system.
        if let Ok(info) = self.native.call("device_info", json!({})) {
            if let Some(secs) = info.get("utc_offset").and_then(Value::as_i64) {
                if let Ok(off) = time::UtcOffset::from_whole_seconds(secs as i32) {
                    cfg.utc_offset = off;
                }
            }
        }
        cfg.render = ui_render;
        cfg.signer = ui_signer;
        cfg.ocr = ui_ocr;
        cfg.screenshotter = ui_screenshotter;
        let engine = Engine::open(cfg, keys, sink)?;
        crate::headless::mark_ui_open(true);
        Ok(engine)
    }

    /// Runs after the engine opens: subscribes to the device monitor, feeds settings into the
    /// policy and starts the service for a running scan.
    fn after_open(self: &Arc<Self>) {
        let tx = lock(&self.tx).clone();
        let tx = Mutex::new(tx);
        if let Err(e) = self.native.watch(Box::new(move |v| {
            let _ = lock(&tx).send(Msg::Device(v));
        })) {
            aerr!("native watch: {e}, события сети/питания/сервиса не придут");
        }
        let Some(engine) = self.engine.get() else {
            return;
        };
        let settings =
            tauri::async_runtime::block_on(engine.invoke("settings_get", json!({}))).ok();
        if let Some(s) = &settings {
            self.send(Msg::Settings(s.clone()));
        }
        self.auto_resume(&engine, settings.as_ref());
        if engine.is_scanning() {
            if let Ok(st) = tauri::async_runtime::block_on(engine.invoke("scan_status", json!({})))
            {
                if let Some(pid) = st["project"].as_str().filter(|s| !s.is_empty()) {
                    self.service_begin(pid);
                }
                if self.attached.load(Ordering::SeqCst) {
                    // The background core started this scan: the policy never saw `started`.
                    let active = st["active"].as_bool().unwrap_or(false);
                    let actions = {
                        let mut g = lock(&self.policy);
                        let PolicyState {
                            policy,
                            env,
                            settings,
                            ..
                        } = &mut *g;
                        crate::devstate::sync_mobile(env, &engine);
                        policy.scan_started(active, env, settings)
                    };
                    self.apply(actions);
                }
            }
        }
    }

    /// Resumes a scan interrupted when Android killed the app in the background.
    fn auto_resume(self: &Arc<Self>, engine: &Engine, settings: Option<&Value>) {
        let Some(mut args) = lock(&self.pending_resume).take() else {
            return;
        };
        // A UI opened later (it missed the `started` event) learns about the auto-resume from
        // `scan_status.auto` and tells the user the scan was interrupted by the system and is
        // continuing.
        args["auto"] = json!(true);
        let scan_id = args["resume_from"].as_str().unwrap_or("").to_string();
        let project = args["project"].as_str().unwrap_or("").to_string();
        let enabled = settings.is_none_or(foca_engine::resume::enabled);
        let now_ms = (time::OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000_000) as i64;
        let attempt = match (enabled, self.data_dir()) {
            (true, Some(d)) => foca_engine::resume::note_attempt(d, &scan_id, now_ms),
            _ => 1,
        };
        let decision =
            recovery::auto_resume_decision(enabled, attempt, foca_engine::resume::MAX_ATTEMPTS);
        alog!("автопродолжение скана {scan_id}: {decision:?} (попытка {attempt})");
        let notice = |kind: &str, text: &str| {
            let mut p =
                json!({ "kind": kind, "scan_id": scan_id, "project": project, "text": text });
            foca_engine::i18n::annotate(&mut p, &["text"]);
            if let Err(e) = self.app.emit("notice", p) {
                awarn!("emit notice: {e}");
            }
        };
        match decision {
            ResumeDecision::Resume => {
                match tauri::async_runtime::block_on(engine.invoke("scan_start", args)) {
                    Ok(_) => {
                        let text = "Скан был прерван системой: продолжаю";
                        // The app has just been opened (Rust starts from the Activity's onCreate), so starting the
                        // foreground service is allowed.
                        self.service_begin(&project);
                        self.toast(text);
                        notice("auto_resumed", text);
                    }
                    Err(e) => {
                        awarn!("автопродолжение {scan_id}: {e}");
                        notice(
                            "interrupted",
                            &format!("Скан был прерван системой. Продолжить не удалось: {e}"),
                        );
                    }
                }
            }
            ResumeDecision::Disabled => notice(
                "interrupted",
                "Скан был прерван системой: продолжите его на экране скана",
            ),
            ResumeDecision::TooMany => notice(
                "interrupted",
                "Скан несколько раз подряд прерывался: продолжите его вручную",
            ),
        }
    }

    /// Language of texts the shell shows natively (toasts, notifications, system dialogs).
    fn lang(&self) -> foca_core::Lang {
        self.engine
            .get()
            .map_or(foca_core::Lang::Ru, |e| e.ui_lang())
    }

    /// Translates a Russian core text into the UI language.
    fn tr(&self, text: &str) -> String {
        foca_engine::i18n::localize(self.lang(), text)
    }

    fn toast(&self, text: &str) {
        let text = self.tr(text);
        if let Err(e) = self.native.call("toast", json!({ "text": text })) {
            awarn!("toast: {e}");
        }
    }

    /// Recreates the Tauri window for a new Activity after the previous one was destroyed during
    /// a scan.
    fn recreate_window(&self) {
        let open = self.app.webview_windows().len();
        let lost = self.window_lost.load(Ordering::SeqCst);
        if !recovery::should_recreate_window(lost, open) {
            adbg!("ui/created: окно не нужно (потеряно={lost}, открыто={open})");
            return;
        }
        let Some(cfg) = self.app.config().app.windows.first().cloned() else {
            aerr!("ui/created: нет конфигурации окна");
            return;
        };
        let t0 = std::time::Instant::now();
        match tauri::WebviewWindowBuilder::from_config(&self.app, &cfg).and_then(|b| b.build()) {
            Ok(_) => {
                self.window_lost.store(false, Ordering::SeqCst);
                alog!(
                    "окно пересоздано для новой Activity за {} мс",
                    t0.elapsed().as_millis()
                );
            }
            Err(e) => aerr!("пересоздание окна: {e}"),
        }
    }

    /// Returns whether a scan is running or the service is held; the process must not exit.
    fn busy(&self) -> (bool, bool) {
        let scanning = self.engine.get().is_some_and(|e| e.is_scanning());
        (scanning, lock(&self.svc).running)
    }

    fn send(&self, m: Msg) {
        let _ = lock(&self.tx).send(m);
    }

    fn engine(&self) -> Result<Engine, CmdError> {
        self.engine.wait(Duration::from_secs(20))
    }

    fn data_dir(&self) -> Option<&PathBuf> {
        self.data_dir.get()
    }

    // Commands.

    pub fn dispatch(self: &Arc<Self>, cmd: &str, args: Value) -> Result<Value, CmdError> {
        let args = if args.is_null() { json!({}) } else { args };
        if let Some(p) = cmd.strip_prefix("platform_") {
            return self.platform(p, &args);
        }
        let engine = self.engine()?;
        match cmd {
            "scan_pause" | "scan_resume" if engine.is_scanning() => self.user_pause(cmd, &args),
            "settings_get" | "settings_set" => {
                let r = tauri::async_runtime::block_on(engine.invoke(cmd, args))?;
                self.send(Msg::Settings(r.clone()));
                Ok(r)
            }
            "scan_start" => {
                let project = args
                    .get("project")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string();
                let r = tauri::async_runtime::block_on(engine.invoke(cmd, args));
                match &r {
                    // The UI is on screen (the command came from the WebView): Android 12+ allows starting a
                    // foreground service now, but not later from the background on an event.
                    Ok(v) => {
                        alog!(
                            "scan_start: {} (продолжение: {})",
                            v["scan_id"].as_str().unwrap_or("?"),
                            v["resumed"]
                        );
                        self.service_begin(&project);
                    }
                    Err(e) => alog!("scan_start отклонён: {} {}", e.code, e.message),
                }
                r
            }
            _ => tauri::async_runtime::block_on(engine.invoke(cmd, args)),
        }
    }

    /// Starts the scan service with the project title (safe to call repeatedly).
    fn service_begin(&self, project: &str) {
        if lock(&self.svc).running {
            return;
        }
        let title = self
            .project_name(project)
            .unwrap_or_else(|| project.to_string());
        {
            let mut s = lock(&self.svc);
            if s.running || !s.claim_start(title) {
                return; // already started by the worker on `started`
            }
        }
        self.service_start();
    }

    fn user_pause(self: &Arc<Self>, cmd: &str, args: &Value) -> Result<Value, CmdError> {
        let hint = args.get("reason").and_then(Value::as_str);
        let (actions, was_android) = {
            let mut st = lock(&self.policy);
            let was_android = st.policy.env_reason() == Some("android");
            let a = if cmd == "scan_pause" {
                Ok(st.policy.user_pause(hint))
            } else {
                st.policy.user_resume(hint)
            };
            (a, was_android)
        };
        match actions {
            Ok(a) => {
                let resumed = a.contains(&Action::Resume);
                self.apply(a);
                if resumed && was_android {
                    // The system removed the service (dataSync limit); the app is on screen, so start it again.
                    self.service_start();
                }
                Ok(json!({ "ok": true }))
            }
            Err(reason) => Err(err(
                "blocked",
                format!("Скан на паузе: {}, продолжится сам", reason_label(reason)),
            )),
        }
    }

    fn platform(&self, p: &str, a: &Value) -> Result<Value, CmdError> {
        let n =
            |cmd: &str, args: Value| self.native.call(cmd, args).map_err(|e| err("platform", e));
        match p {
            "share" | "save" => {
                let (path, name) = self.resolve_file(a)?;
                let mime = a
                    .get("mime")
                    .and_then(Value::as_str)
                    .map(str::to_string)
                    .unwrap_or_else(|| mime_of(&name).to_string());
                let args = json!({ "path": path.to_string_lossy(), "name": name, "mime": mime });
                n(
                    if p == "share" {
                        "share_file"
                    } else {
                        "save_to_downloads"
                    },
                    args,
                )
            }
            // Report "PDF": WebView system printing of the HTML report → "Save as PDF".
            "print" => {
                let (path, name) = self.resolve_file(a)?;
                let ext = path
                    .extension()
                    .and_then(|e| e.to_str())
                    .map(|e| e.to_ascii_lowercase())
                    .unwrap_or_default();
                if ext != "html" && ext != "htm" {
                    return Err(err(
                        "bad_args",
                        "печать в PDF доступна только для HTML-отчёта",
                    ));
                }
                n(
                    "print_html",
                    json!({ "path": path.to_string_lossy(), "name": name }),
                )
            }
            // Report "PDF" as a file: the HTML report is rendered off-screen and written to
            // `<exports>/<report stem>.pdf` without the print dialog ("print" stays the fallback).
            "pdf" => {
                let (path, name) = self.resolve_file(a)?;
                let ext = path
                    .extension()
                    .and_then(|e| e.to_str())
                    .map(|e| e.to_ascii_lowercase())
                    .unwrap_or_default();
                if ext != "html" && ext != "htm" {
                    return Err(err("bad_args", "PDF доступен только для HTML-отчёта"));
                }
                let export_dir = self.engine()?.config().export_dir.clone();
                std::fs::create_dir_all(&export_dir).map_err(|e| err("platform", e.to_string()))?;
                let stem = path
                    .file_stem()
                    .map(|s| s.to_string_lossy().into_owned())
                    .unwrap_or_else(|| "foca-report".into());
                let out = export_dir.join(format!("{stem}.pdf"));
                n(
                    "pdf_html",
                    json!({
                        "path": path.to_string_lossy(),
                        "name": name,
                        "out": out.to_string_lossy(),
                    }),
                )
            }
            "biometric" => n(
                "biometric_prompt",
                json!({
                    "title": a.get("title").and_then(Value::as_str).map_or_else(|| self.tr("Подтвердите личность"), str::to_string),
                    "subtitle": a.get("subtitle").and_then(Value::as_str).unwrap_or(""),
                }),
            ),
            "secure" => {
                let on = a.get("on").and_then(Value::as_bool).unwrap_or(true);
                lock(&self.policy).secure = Some(on);
                n("set_secure", json!({ "on": on }))
            }
            "battery_status" => n("battery_optimization_status", json!({})),
            "battery_settings" => n(
                "open_battery_settings",
                json!({ "what": a.get("what").and_then(Value::as_str).unwrap_or("battery") }),
            ),
            "notifications" | "request_notifications" => n("request_notifications", json!({})),
            "permissions_status" => n("permissions_status", json!({})),
            // Settings › Background: hide-from-Recents toggle, OEM autostart and battery status.
            "bg_status" => n("bg_status", json!({})),
            "bg_set" => n("bg_set", a.clone()),
            // Manual verification: a visible search engine WebView sharing the hidden browser's profile
            // (a human solves the Startpage/Mojeek/Brave captcha); the reply comes after the window
            // closes: `{ state: done | cancelled | failed | not_solved, ok, closed, detail? }`, only
            // `done` (Done on a page without challenge markers) means the engine accepts us.
            "verify_search" => {
                let url = a.get("url").and_then(Value::as_str).unwrap_or("");
                let ok = [
                    "https://www.startpage.com/",
                    "https://www.mojeek.com/",
                    "https://search.brave.com/",
                    "https://search.yahoo.com/",
                ]
                .iter()
                .any(|p| url.starts_with(p));
                if !ok {
                    return Err(err(
                        "bad_args",
                        "адрес проверки: только Startpage, Mojeek, Brave или Yahoo",
                    ));
                }
                n(
                    "render_verify",
                    json!({
                        "url": url,
                        "title": a.get("title").and_then(Value::as_str).map_or_else(|| self.tr("Проверка поисковика"), str::to_string),
                        "markers": foca_engine::verify_markers(),
                    }),
                )
            }
            // External link (e.g. "How to get a key"): http/https only, opened by the system browser.
            "open_url" => {
                let url = checked_http_url(a.get("url").and_then(Value::as_str).unwrap_or(""))
                    .map_err(|e| err("bad_args", e))?;
                if self.native.real() {
                    n("open_url", json!({ "url": url }))
                } else {
                    open_url_desktop(&url).map_err(|e| err("platform", e))?;
                    Ok(json!({ "ok": true }))
                }
            }
            // "Decline" on the terms screen.
            "exit" => n("app_exit", json!({})),
            // Debug tab → Device: Android version, model, ABI, memory, storage, service, battery,
            // notifications.
            "device_info" => {
                let mut v = n("device_info", json!({}))?;
                v["net"] = json!(lock(&self.policy).env.online);
                v["vpn"] = json!(lock(&self.policy).env.vpn);
                Ok(v)
            }
            // File (SAF) and photo (photo picker / camera) selection, copied into the private directory:
            // { ok, cancelled, files: [{ path, name, size, mime }] }
            "pick_files" => n("pick_files", a.clone()),
            // Offline import: a folder via the SAF tree picker, copied with limits into the
            // private directory: { ok, cancelled, files: [{ path, name, size, mime }], skipped,
            // truncated, bytes }; then import_offline { paths } and pick_clear.
            "pick_folder" => n("pick_folder", a.clone()),
            "pick_clear" => n("pick_clear", json!({})),
            // "Share → FOCA-rs" (ACTION_SEND/ACTION_SEND_MULTIPLE): files copied with limits into the private
            // directory, handed out once: { files: [{ path, name, size, mime }], skipped, truncated }; the UI
            // grades and cleans them (hygiene_get / doc_clean { path }) without a project.
            "shared_files" => n("shared_files", json!({})),
            "pick_image" => n("pick_image", a.clone()),
            // Clipboard through ClipboardManager: the Android WebView never grants the async
            // Clipboard API read. Desktop answers `unsupported` and the UI uses navigator.clipboard.
            "clipboard_read" => n("clipboard_read", json!({})),
            "clipboard_write" => n(
                "clipboard_write",
                clipboard_write_args(a).map_err(|e| err("bad_args", e))?,
            ),
            "clipboard_clear" => n(
                "clipboard_clear",
                match a.get("expected").and_then(Value::as_str) {
                    Some(x) => json!({ "expected": x }),
                    None => json!({}),
                },
            ),
            _ => Err(err("unknown_command", format!("platform_{p}"))),
        }
    }

    /// Resolves a file for share/save, only from the app's private data directory.
    /// `{ path }` is a path from `export_build` (absolute, `Download/FOCA-rs/<name>` or a file
    /// name); `{ project, report }` is a report file from history (the `path` field of the
    /// `Report` record).
    fn resolve_file(&self, a: &Value) -> Result<(PathBuf, String), CmdError> {
        let engine = self.engine()?;
        let data_dir = self
            .data_dir()
            .cloned()
            .ok_or_else(|| err("internal", "папка данных неизвестна"))?;
        let export_dir = engine.config().export_dir.clone();
        let mut raw = a.get("path").and_then(Value::as_str).map(str::to_string);
        if raw.is_none() {
            if let Some(rid) = a.get("report") {
                let list = tauri::async_runtime::block_on(engine.invoke(
                    "report_list",
                    json!({ "project": a.get("project").cloned().unwrap_or(Value::Null) }),
                ))?;
                let rec = list
                    .as_array()
                    .and_then(|l| l.iter().find(|r| r.get("id") == Some(rid)).cloned())
                    .ok_or_else(|| err("not_found", "отчёт не найден"))?;
                // foca-engine stores reports in `<data>/reports/<project>/<name>`.
                let project = a.get("project").and_then(Value::as_str).unwrap_or("");
                raw = rec
                    .get("path")
                    .and_then(Value::as_str)
                    .map(str::to_string)
                    .or_else(|| {
                        rec.get("name")
                            .and_then(Value::as_str)
                            .map(|n| format!("reports/{project}/{n}"))
                    });
            }
        }
        let raw = raw.ok_or_else(|| err("bad_args", "нужен path или report"))?;
        let path = find_file(&raw, &data_dir, &export_dir)
            .ok_or_else(|| err("not_found", format!("файл не найден: {raw}")))?;
        let name = a
            .get("name")
            .and_then(Value::as_str)
            .map(str::to_string)
            .or_else(|| path.file_name().map(|n| n.to_string_lossy().into_owned()))
            .unwrap_or_else(|| "foca-export".into());
        Ok((path, name))
    }

    // Worker: engine and device events.

    fn worker(self: Arc<Self>, rx: Receiver<Msg>) {
        while let Ok(m) = rx.recv() {
            let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| match m {
                Msg::Scan(ev) => self.on_scan_event(&ev),
                Msg::Device(ev) => self.on_device(&ev),
                Msg::Settings(s) => self.on_settings(&s),
            }));
            if r.is_err() {
                aerr!("foca-bridge: паника в обработчике события (подробности: crash-*.txt)");
            }
        }
    }

    fn on_scan_event(self: &Arc<Self>, ev: &Value) {
        let ty = ev.get("type").and_then(Value::as_str).unwrap_or("");
        match ty {
            "started" => {
                let active = ev.get("active").and_then(Value::as_bool).unwrap_or(false);
                let project = ev
                    .get("project")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string();
                alog!(
                    "скан начат: {} проект {project} (активный: {active}, продолжение: {})",
                    ev["scan_id"].as_str().unwrap_or("?"),
                    ev["resumed"]
                );
                let title = self.project_name(&project).unwrap_or(project);
                let already = !lock(&self.svc).claim_start(title);
                if already {
                    self.service_update();
                } else {
                    self.service_start();
                }
                let actions = {
                    let mut st = lock(&self.policy);
                    let PolicyState {
                        policy,
                        env,
                        settings,
                        ..
                    } = &mut *st;
                    if let Some(engine) = self.engine.get() {
                        crate::devstate::sync_mobile(env, &engine);
                    }
                    policy.scan_started(active, env, settings)
                };
                self.apply(actions);
            }
            // The engine's monthly mobile data counter crossed `power.mob_limit`.
            "mobile_cap" => {
                alog!(
                    "лимит мобильного трафика: {} из {} МБ",
                    ev["used_mb"],
                    ev["limit_mb"]
                );
                let actions = {
                    let mut st = lock(&self.policy);
                    let PolicyState {
                        policy,
                        env,
                        settings,
                        ..
                    } = &mut *st;
                    if let Some(engine) = self.engine.get() {
                        crate::devstate::sync_mobile(env, &engine);
                    }
                    policy.on_env(env, settings)
                };
                let action = actions.last().cloned();
                self.apply(actions);
                if action.is_some() {
                    self.emit_net(action);
                }
            }
            "stage" => {
                if let Some(l) = ev.get("label").and_then(Value::as_str) {
                    lock(&self.svc).set_stage(l);
                    self.service_update();
                }
            }
            "progress" => {
                let changed = lock(&self.svc).apply_progress(ev);
                if changed {
                    self.service_update();
                }
            }
            "done" | "stopped" => {
                alog!(
                    "скан {}: {} {}",
                    ev["scan_id"].as_str().unwrap_or("?"),
                    ty,
                    ev["reason"].as_str().unwrap_or("")
                );
                lock(&self.policy).policy.scan_ended();
                self.service_stop();
                if ty == "done" {
                    self.notify_done(ev);
                } else {
                    self.release_monitor(ev["project"].as_str().unwrap_or(""));
                }
            }
            _ => {}
        }
    }

    fn on_device(self: &Arc<Self>, ev: &Value) {
        let kind = ev.get("kind").and_then(Value::as_str).unwrap_or("");
        match kind {
            // Scheduled rescan (WorkManager, MonitorWorker): the core is alive, so start without a
            // window.
            "monitor" => {
                self.monitor_scan(ev);
                return;
            }
            // New shared files: the UI asks for them with platform_shared_files.
            "shared" => {
                alog!("share: файлов {}", ev["n"]);
                if let Err(e) = self.app.emit("shared", ev.clone()) {
                    awarn!("emit shared: {e}");
                }
                return;
            }
            "ui" => {
                alog!("ui: {}", ev["action"].as_str().unwrap_or("?"));
                if ev["action"] == "created" {
                    self.recreate_window();
                }
                return;
            }
            "net" | "power" => adbg!("устройство: {ev}"),
            _ => alog!("устройство: {ev}"),
        }
        let actions = {
            let mut st = lock(&self.policy);
            if kind != "service" && !crate::devstate::apply_device(&mut st.env, ev) {
                return;
            }
            if let Some(engine) = self.engine.get() {
                crate::devstate::sync_mobile(&mut st.env, &engine);
            }
            let PolicyState {
                policy,
                env,
                settings,
                ..
            } = &mut *st;
            if kind == "service" {
                match ev.get("action").and_then(Value::as_str) {
                    Some("timeout") => policy.on_fgs_timeout(),
                    _ => vec![],
                }
            } else {
                policy.on_env(env, settings)
            }
        };
        if kind == "service" {
            match ev.get("action").and_then(Value::as_str) {
                Some("stop") => {
                    // "Stop" in the notification.
                    if let Some(engine) = self.engine.get() {
                        let r = tauri::async_runtime::block_on(
                            engine.invoke("scan_stop", json!({ "reason": "user" })),
                        );
                        if r.is_err() || !engine.is_scanning() {
                            self.service_stop();
                        }
                    } else {
                        self.service_stop();
                    }
                }
                Some("timeout") => lock(&self.svc).running = false,
                Some("destroyed") => lock(&self.svc).running = false,
                _ => {}
            }
        }
        let action = actions.last().cloned();
        self.apply(actions);
        if kind == "net" || kind == "power" || action.is_some() {
            self.emit_net(action);
        }
    }

    fn on_settings(self: &Arc<Self>, s: &Value) {
        let ps = crate::devstate::policy_settings(s);
        // "Block screenshots" is opt-in: a missing `sec.block_shots` means screenshots are allowed.
        let hide = s
            .get("sec")
            .and_then(|x| x.get("block_shots"))
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let (actions, secure_changed) = {
            let mut st = lock(&self.policy);
            st.settings = ps;
            let secure_changed = st.secure != Some(hide);
            if secure_changed {
                st.secure = Some(hide);
            }
            let PolicyState {
                policy,
                env,
                settings,
                ..
            } = &mut *st;
            // a raised or removed limit lifts the mobile data cap
            if let Some(engine) = self.engine.get() {
                crate::devstate::sync_mobile(env, &engine);
            }
            (policy.on_env(env, settings), secure_changed)
        };
        if secure_changed {
            // "Block screenshots" (Settings → Security) maps to FLAG_SECURE.
            if let Err(e) = self.native.call("set_secure", json!({ "on": hide })) {
                awarn!("set_secure: {e}");
            }
        }
        let action = actions.last().cloned();
        self.apply(actions);
        if action.is_some() {
            self.emit_net(action);
        }
        self.monitor_sync(s);
    }

    fn apply(&self, actions: Vec<Action>) {
        if actions.is_empty() {
            return;
        }
        let Some(engine) = self.engine.get() else {
            return;
        };
        alog!("политика: {actions:?}");
        for a in actions {
            match a {
                Action::Pause(r) => {
                    engine.pause(r);
                    lock(&self.svc).paused = Some(r.to_string());
                    if r == "mobile_cap" {
                        self.notify_mobile_cap(&engine);
                    }
                }
                Action::Resume => {
                    engine.resume();
                    lock(&self.svc).paused = None;
                }
                Action::Stop(r) => {
                    if let Err(e) = tauri::async_runtime::block_on(
                        engine.invoke("scan_stop", json!({ "reason": r })),
                    ) {
                        awarn!("scan_stop {r}: {e}");
                    }
                }
            }
        }
        self.service_update();
    }

    /// Emits the `net` event for the UI: network and power state plus what the policy did.
    fn emit_net(&self, action: Option<Action>) {
        let st = lock(&self.policy);
        let e = &st.env;
        let act = action.map(|a| match a {
            Action::Pause(r) => json!({ "type": "pause", "reason": r }),
            Action::Resume => json!({ "type": "resume" }),
            Action::Stop(r) => json!({ "type": "stop", "reason": r }),
        });
        let payload = json!({
            "online": e.online,
            "transport": e.transport.as_str(),
            "vpn": e.vpn,
            "metered": e.metered,
            "battery": e.battery,
            "charging": e.charging,
            "thermal": e.thermal,
            "paused": st.policy.env_reason(),
            "user_paused": st.policy.user_paused(),
            "action": act,
        });
        drop(st);
        if let Err(e) = self.app.emit("net", payload) {
            awarn!("emit net: {e}");
        }
    }

    // Scan foreground service.

    fn service_payload(&self) -> Value {
        lock(&self.svc).payload(self.lang())
    }

    fn service_start(&self) {
        let p = self.service_payload();
        match self.native.call("scan_service_start", p) {
            Ok(v) => {
                let running = v.get("running").and_then(Value::as_bool).unwrap_or(true);
                lock(&self.svc).running = running;
                if running {
                    alog!("сервис скана запущен");
                } else {
                    // ForegroundServiceStartNotAllowedException and the like: without the service Android will
                    // kill the process in the background, and the scan resumes on the next launch.
                    aerr!(
                        "сервис скана НЕ запущен: {}",
                        v.get("error").and_then(Value::as_str).unwrap_or("?")
                    );
                }
            }
            Err(e) => aerr!("scan_service_start: {e}"),
        }
    }

    fn service_update(&self) {
        if !lock(&self.svc).running {
            return;
        }
        let p = self.service_payload();
        if let Err(e) = self.native.call("scan_service_update", p) {
            awarn!("scan_service_update: {e}");
        }
    }

    fn service_stop(&self) {
        lock(&self.svc).running = false;
        alog!("сервис скана: стоп");
        if let Err(e) = self.native.call("scan_service_stop", json!({})) {
            awarn!("scan_service_stop: {e}");
        }
    }

    // Monitoring: scan result, WorkManager schedule, scheduled scan.

    /// Posts the "scan finished · <project>" notification with a summary; tapping it opens the
    /// project.
    /// Posts the "mobile data limit reached" notification (the scan stays paused until Wi-Fi or a
    /// raised limit).
    fn notify_mobile_cap(&self, engine: &Engine) {
        let usage = tauri::async_runtime::block_on(engine.invoke("mobile_usage", json!({})))
            .unwrap_or_default();
        let note = crate::scan_note::mobile_cap_note(self.lang(), &usage);
        alog!("уведомление: {}", note["text"].as_str().unwrap_or(""));
        if let Err(e) = self.native.call("status_notify", note) {
            awarn!("status_notify: {e}");
        }
    }

    fn notify_done(&self, ev: &Value) {
        let project = ev["project"].as_str().unwrap_or("").to_string();
        let name = self
            .project_name(&project)
            .unwrap_or_else(|| project.clone());
        let (title, text) = crate::monitor::done_summary(self.lang(), &name, &ev["scan"]);
        alog!("итог скана: {title}, {text}");
        if let Err(e) = self.native.call(
            "scan_done_notify",
            json!({ "project": project, "title": title, "text": text }),
        ) {
            awarn!("scan_done_notify: {e}");
        }
    }

    /// Pushes a new WorkManager schedule after `settings.monitor` changes.
    fn monitor_sync(&self, s: &Value) {
        let Some(m) = s.get("monitor") else { return };
        let key = m.to_string();
        if *lock(&self.monitor_sent) == key {
            return;
        }
        let items = crate::monitor::schedule_items(m, |id| self.project_name(id));
        match self.native.call("monitor_schedule", items) {
            Ok(v) => {
                alog!("мониторинг: расписание {v}");
                *lock(&self.monitor_sent) = key;
            }
            Err(e) => awarn!("monitor_schedule: {e}"),
        }
    }

    fn release_monitor(&self, project: &str) {
        if project.is_empty() {
            return;
        }
        let _ = self.native.call(
            "scan_done_notify",
            json!({ "project": project, "silent": true }),
        );
    }

    /// Runs a scheduled project scan (passive/standard only; skipped if another scan is running).
    fn monitor_scan(self: &Arc<Self>, ev: &Value) {
        let project = ev["project"].as_str().unwrap_or("").to_string();
        let profile = crate::monitor::safe_profile(ev["profile"].as_str());
        let Some(engine) = self.engine.get() else {
            awarn!("мониторинг: ядро не открыто, скан {project} пропущен");
            self.release_monitor(&project);
            return;
        };
        if engine.is_scanning() {
            alog!("мониторинг: идёт другой скан, плановый {project} пропущен");
            self.release_monitor(&project);
            return;
        }
        let budget_sec = ev["budget_sec"]
            .as_u64()
            .unwrap_or(crate::headless::DEFAULT_BUDGET_SEC);
        let r = tauri::async_runtime::block_on(engine.invoke(
            "scan_start",
            json!({
                "project": project,
                "profile": profile,
                "trigger": "schedule",
                "budget_sec": budget_sec,
            }),
        ));
        match r {
            Ok(_) => alog!("мониторинг: плановый скан {project} ({profile}) запущен"),
            Err(e) => {
                awarn!("мониторинг: скан {project} не запущен: {e}");
                self.release_monitor(&project);
            }
        }
    }

    fn project_name(&self, id: &str) -> Option<String> {
        let engine = self.engine.get()?;
        let list = tauri::async_runtime::block_on(engine.invoke("project_list", json!({}))).ok()?;
        list.as_array()?
            .iter()
            .find(|p| p.get("id").and_then(Value::as_str) == Some(id))
            .and_then(|p| p.get("name").and_then(Value::as_str))
            .map(str::to_string)
    }
}

/// Handles Tauri run loop events: window logging and keeping the process alive when the
/// Activity is destroyed during a scan.
pub fn on_run_event(app: &AppHandle, ev: RunEvent) {
    match ev {
        RunEvent::Ready => alog!("Tauri: готов"),
        RunEvent::Resumed => alog!("Tauri: Activity снова на экране"),
        RunEvent::WindowEvent { label, event, .. } => match event {
            tauri::WindowEvent::Destroyed => alog!("окно {label}: Destroyed (Activity уничтожена)"),
            tauri::WindowEvent::Focused(f) => adbg!("окно {label}: фокус {f}"),
            _ => {}
        },
        RunEvent::ExitRequested { code, api, .. } => {
            let (scanning, service) = app
                .try_state::<Shared>()
                .map(|b| b.busy())
                .unwrap_or((false, false));
            if recovery::keep_process_alive(code, scanning, service) {
                api.prevent_exit();
                if let Some(b) = app.try_state::<Shared>() {
                    b.window_lost.store(true, Ordering::SeqCst);
                }
                awarn!(
                    "выход процесса отменён: Activity закрыта, а скан идёт (скан={scanning}, сервис={service}); \
                     окно пересоздастся при следующем открытии"
                );
            } else {
                alog!("выход процесса (код {code:?}, скан={scanning}, сервис={service})");
            }
        }
        RunEvent::Exit => alog!("Tauri: цикл событий завершён, процесс выходит"),
        _ => {}
    }
}

/// Tauri command: the single UI entry point. Errors are `{ code, message, targets? }`.
#[tauri::command]
pub async fn foca(
    state: tauri::State<'_, Shared>,
    cmd: String,
    args: Option<Value>,
) -> Result<Value, CmdError> {
    let b = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || b.dispatch(&cmd, args.unwrap_or(Value::Null)))
        .await
        .map_err(CmdError::internal)?
}

pub fn mime_of(name: &str) -> &'static str {
    let ext = name.rsplit('.').next().unwrap_or("").to_ascii_lowercase();
    match ext.as_str() {
        "pdf" => "application/pdf",
        "html" | "htm" => "text/html",
        "md" => "text/markdown",
        "txt" | "dict" | "lst" => "text/plain",
        "csv" => "text/csv",
        "json" => "application/json",
        "graphml" | "xml" => "application/xml",
        "mtgx" | "zip" | "foca" => "application/zip",
        "docx" => "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "xlsx" => "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "pptx" => "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        "odt" => "application/vnd.oasis.opendocument.text",
        "ods" => "application/vnd.oasis.opendocument.spreadsheet",
        "odp" => "application/vnd.oasis.opendocument.presentation",
        "odg" => "application/vnd.oasis.opendocument.graphics",
        "jpg" | "jpeg" => "image/jpeg",
        "png" => "image/png",
        _ => "application/octet-stream",
    }
}

/// Finds an export or report file strictly inside safe output subdirectories of the app data dir.
pub fn find_file(raw: &str, data_dir: &Path, export_dir: &Path) -> Option<PathBuf> {
    let mut allowed_roots: Vec<PathBuf> = ["exports", "reports", "clean", "files"]
        .iter()
        .filter_map(|sub| data_dir.join(sub).canonicalize().ok())
        .collect();
    if let Ok(ed) = export_dir.canonicalize() {
        if !allowed_roots.contains(&ed) {
            allowed_roots.push(ed);
        }
    }
    let p = Path::new(raw);
    let mut cands: Vec<PathBuf> = vec![];
    if p.is_absolute() {
        cands.push(p.to_path_buf());
    } else {
        cands.push(data_dir.join(p));
    }
    if let Some(name) = p.file_name() {
        cands.push(export_dir.join(name));
        cands.push(data_dir.join("exports").join(name));
        cands.push(data_dir.join("reports").join(name));
    }
    cands
        .into_iter()
        .filter_map(|c| c.canonicalize().ok())
        .find(|c| c.is_file() && allowed_roots.iter().any(|r| c.starts_with(r)))
}

#[cfg(test)]
mod service_tests {
    use super::ServiceState;

    #[test]
    fn service_start_is_claimed_once() {
        let mut s = ServiceState::default();
        // `scan_start` pre-starts the service; the `started` event arrives while the native
        // call is still in flight and must not issue a second start.
        assert!(s.claim_start("a".into()));
        assert!(s.running);
        assert!(!s.claim_start("a".into()));
        assert_eq!(s.title, "a");
        // After a failed start or a stop the next scan claims it again.
        s.running = false;
        assert!(s.claim_start("b".into()));
    }
}

/// Validates a link for `platform_open_url`: absolute `http`/`https` URL with a host, no
/// credentials, no whitespace or control characters, at most 2048 bytes.
fn checked_http_url(raw: &str) -> Result<String, String> {
    let raw = raw.trim();
    if raw.is_empty()
        || raw.len() > 2048
        || raw.chars().any(|c| c.is_whitespace() || c.is_control())
    {
        return Err("некорректная ссылка".into());
    }
    let lower = raw.to_ascii_lowercase();
    let rest = lower
        .strip_prefix("https://")
        .or_else(|| lower.strip_prefix("http://"))
        .ok_or_else(|| "открываются только ссылки http/https".to_string())?;
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    if authority.is_empty() || authority.contains('@') || authority.starts_with(':') {
        return Err("некорректная ссылка".into());
    }
    Ok(raw.to_string())
}

/// Opens a validated link in the default browser (desktop builds). The URL is passed as a single
/// argument, never through a shell.
fn open_url_desktop(url: &str) -> Result<(), String> {
    #[cfg(target_os = "windows")]
    let mut cmd = {
        let mut c = std::process::Command::new("rundll32");
        c.args(["url.dll,FileProtocolHandler", url]);
        c
    };
    #[cfg(target_os = "macos")]
    let mut cmd = {
        let mut c = std::process::Command::new("open");
        c.arg(url);
        c
    };
    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    let mut cmd = {
        let mut c = std::process::Command::new("xdg-open");
        c.arg(url);
        c
    };
    cmd.spawn()
        .map(|_| ())
        .map_err(|e| format!("не удалось открыть браузер: {e}"))
}

/// Largest text `platform_clipboard_write` accepts (bytes) and the longest auto-clear delay.
const CLIP_MAX_BYTES: usize = 1024 * 1024;
const CLIP_MAX_CLEAR_MS: u64 = 10 * 60 * 1000;

/// Validates `platform_clipboard_write { text, sensitive?, clear_after_ms? }` for the plugin.
fn clipboard_write_args(a: &Value) -> Result<Value, String> {
    let text = a
        .get("text")
        .and_then(Value::as_str)
        .ok_or_else(|| "нет текста для буфера обмена".to_string())?;
    if text.len() > CLIP_MAX_BYTES {
        return Err("слишком длинный текст для буфера обмена".into());
    }
    let sensitive = a.get("sensitive").and_then(Value::as_bool).unwrap_or(false);
    let ms = a
        .get("clear_after_ms")
        .and_then(Value::as_u64)
        .unwrap_or(0)
        .min(CLIP_MAX_CLEAR_MS);
    Ok(json!({ "text": text, "sensitive": sensitive, "clear_after_ms": ms }))
}

#[cfg(test)]
mod clipboard_tests {
    use serde_json::json;

    #[test]
    fn clipboard_write_args_are_checked_and_clamped() {
        let v = super::clipboard_write_args(
            &json!({ "text": "k", "sensitive": true, "clear_after_ms": 30000 }),
        )
        .unwrap();
        assert_eq!(
            v,
            json!({ "text": "k", "sensitive": true, "clear_after_ms": 30000 })
        );
        let v = super::clipboard_write_args(&json!({ "text": "", "clear_after_ms": u64::MAX }))
            .unwrap();
        assert_eq!(v["sensitive"], false);
        assert_eq!(v["clear_after_ms"], super::CLIP_MAX_CLEAR_MS);
        assert!(super::clipboard_write_args(&json!({})).is_err());
        assert!(super::clipboard_write_args(&json!({ "text": 5 })).is_err());
        let big = "x".repeat(super::CLIP_MAX_BYTES + 1);
        assert!(super::clipboard_write_args(&json!({ "text": big })).is_err());
    }

    #[test]
    fn desktop_clipboard_is_reported_unsupported() {
        use crate::native::{Native, NoNative};
        for cmd in ["clipboard_read", "clipboard_write", "clipboard_clear"] {
            let v = NoNative.call(cmd, json!({})).unwrap();
            assert_eq!(v["unsupported"], true, "{cmd}");
            assert_eq!(v["ok"], false, "{cmd}");
        }
    }
}

#[cfg(test)]
mod open_url_tests {
    #[test]
    fn open_url_accepts_only_plain_http_links() {
        assert!(super::checked_http_url("https://example.com/keys?x=1").is_ok());
        assert!(super::checked_http_url("http://example.com").is_ok());
        for bad in [
            "",
            "javascript:alert(1)",
            "file:///etc/passwd",
            "intent://x#Intent;end",
            "https://",
            "https://user:pw@example.com/",
            "https://exa mple.com/",
            "ftp://example.com/",
        ] {
            assert!(super::checked_http_url(bad).is_err(), "{bad}");
        }
    }
}
