//! Headless background monitoring runner and Android JNI entry point.
//!
//! Invoked by Android `WorkManager` (`MonitorWorker` → `FocaDirect.runHeadlessMonitor`) when
//! the UI / `MainActivity` / Tauri `AppHandle` are not alive in the process:
//! - enforces safe monitoring profiles (`passive` | `std` only);
//! - acquires the shared `DataDirLock` inside `Engine::open` so a UI launched mid-scan attaches
//!   to the live engine (`attach_live_engine`) instead of opening a second concurrent instance;
//! - skips WebView-only dork sources as `skipped_headless`;
//! - caps execution to a ≤ 8 minute budget with soft cancellation + `resume_from` checkpoint;
//! - reports `done_summary` diff counts back to Kotlin for `MonitorWorker.notifyDone`.
//!
//! [`resume`] reuses the same live session to continue a scan interrupted by a process kill.

#![cfg_attr(not(any(target_os = "android", test)), allow(dead_code))]

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
use std::time::{Duration, Instant};

use foca_engine::{Engine, EngineConfig, EventSink, KeyProvider, RenderFetch};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

mod resume;

/// Default WorkManager background execution budget (8 minutes, safely under the 10-minute system ceiling).
pub const DEFAULT_BUDGET_SEC: u64 = 480;
pub const MIN_BUDGET_SEC: u64 = 30;
pub const MAX_BUDGET_SEC: u64 = 480;

/// Clamps requested monitoring budget seconds into `[30, 480]`.
pub fn clamp_budget_sec(sec: u64) -> u64 {
    sec.clamp(MIN_BUDGET_SEC, MAX_BUDGET_SEC)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeadlessOutcome {
    pub ok: bool,
    pub status: String,
    pub project: String,
    pub name: String,
    pub profile: String,
    pub scan_id: Option<String>,
    pub title: String,
    pub text: String,
    pub added_docs: u64,
    pub added_findings: u64,
    pub alerts_fired: u64,
    pub elapsed_ms: u64,
    pub ui_attached: bool,
    pub error: Option<String>,
}

struct LiveSession {
    data_dir: PathBuf,
    engine: Engine,
    ui_sink: Arc<Mutex<Option<Arc<dyn EventSink>>>>,
    claimed_by_ui: AtomicBool,
}

static LIVE: OnceLock<Mutex<Option<Arc<LiveSession>>>> = OnceLock::new();
static UI_OPEN: AtomicBool = AtomicBool::new(false);
static HEADLESS_RUNNING: AtomicBool = AtomicBool::new(false);
static CANCEL_FLAG: AtomicBool = AtomicBool::new(false);
static RUNTIME: OnceLock<tokio::runtime::Runtime> = OnceLock::new();

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

fn live_slot() -> &'static Mutex<Option<Arc<LiveSession>>> {
    LIVE.get_or_init(|| Mutex::new(None))
}

fn runtime() -> Result<&'static tokio::runtime::Runtime, String> {
    if let Some(rt) = RUNTIME.get() {
        return Ok(rt);
    }
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .thread_name("foca-headless")
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime: {e}"))?;
    let _ = RUNTIME.set(rt);
    Ok(RUNTIME
        .get()
        .expect("tokio runtime initialized immediately before get"))
}

fn canonical_dir(dir: &Path) -> PathBuf {
    std::fs::canonicalize(dir).unwrap_or_else(|_| dir.to_path_buf())
}

/// Requests cancellation of any in-flight headless monitoring scan (called from `Worker.onStopped`).
pub fn request_cancel() {
    CANCEL_FLAG.store(true, Ordering::SeqCst);
}

/// Marks whether the UI `Bridge` owns an open engine in this process.
pub fn mark_ui_open(open: bool) {
    UI_OPEN.store(open, Ordering::SeqCst);
}

/// Attaches the UI `Bridge` to an already-live headless engine on `data_dir`, forwarding future
/// events and upgrading the headless engine with full interactive UI capabilities without opening a
/// second `Engine`.
#[allow(clippy::too_many_arguments)]
pub fn attach_live_engine(
    data_dir: &Path,
    keys: Arc<dyn KeyProvider>,
    ui_sink: Arc<dyn EventSink>,
    ui_render: Option<Arc<dyn RenderFetch>>,
    ui_signer: Option<Arc<dyn foca_engine::ReportSigner>>,
    ui_ocr: Option<Arc<dyn foca_engine::OcrProvider>>,
    ui_screenshotter: Option<Arc<dyn foca_engine::WebScreenshotter>>,
) -> Option<Engine> {
    let want_dir = canonical_dir(data_dir);
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        if let Some(session) = lock(live_slot()).as_ref().cloned() {
            if session.data_dir == want_dir {
                session.claimed_by_ui.store(true, Ordering::SeqCst);
                UI_OPEN.store(true, Ordering::SeqCst);
                *lock(&session.ui_sink) = Some(ui_sink);
                session.engine.attach_ui_platform(
                    keys,
                    None,
                    ui_render,
                    ui_signer,
                    ui_ocr,
                    ui_screenshotter,
                );
                resume::hand_over();
                alog!("headless handoff: UI подключился к живому фоновому ядру");
                return Some(session.engine.clone());
            }
        }
        if !HEADLESS_RUNNING.load(Ordering::SeqCst) || Instant::now() >= deadline {
            return None;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
}

struct FanoutSink {
    tx: Mutex<mpsc::Sender<Value>>,
    ui_sink: Arc<Mutex<Option<Arc<dyn EventSink>>>>,
}

impl EventSink for FanoutSink {
    fn emit(&self, event: &Value) {
        let _ = lock(&self.tx).send(event.clone());
        let ui = lock(&self.ui_sink).clone();
        if let Some(sink) = ui {
            sink.emit(event);
        }
    }
}

struct RunningGuard<'a>(&'a AtomicBool);
impl Drop for RunningGuard<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::SeqCst);
    }
}

struct LiveClearGuard(Arc<LiveSession>);
impl Drop for LiveClearGuard {
    fn drop(&mut self) {
        let mut g = lock(live_slot());
        if g.as_ref().is_some_and(|s| Arc::ptr_eq(s, &self.0)) {
            *g = None;
        }
    }
}

fn outcome_err(
    project: &str,
    name: &str,
    profile: &str,
    status: &str,
    err: String,
) -> HeadlessOutcome {
    HeadlessOutcome {
        ok: false,
        status: status.to_string(),
        project: project.to_string(),
        name: name.to_string(),
        profile: profile.to_string(),
        scan_id: None,
        title: format!("Мониторинг · {name}"),
        text: err.clone(),
        added_docs: 0,
        added_findings: 0,
        alerts_fired: 0,
        elapsed_ms: 0,
        ui_attached: false,
        error: Some(err),
    }
}

/// Returns the project's display name, or its id when the list cannot be read.
fn project_name(rt: &tokio::runtime::Runtime, engine: &Engine, project: &str) -> String {
    rt.block_on(engine.invoke("project_list", json!({})))
        .ok()
        .and_then(|v| {
            v.as_array().and_then(|arr| {
                arr.iter()
                    .find(|p| p.get("id").and_then(Value::as_str) == Some(project))
                    .and_then(|p| p.get("name").and_then(Value::as_str))
                    .map(str::to_string)
            })
        })
        .unwrap_or_else(|| project.to_string())
}

/// Runs a single scheduled scan headlessly on `cfg.data_dir`, returning summary outcome JSON data.
pub fn run_headless_with(
    mut cfg: EngineConfig,
    keys: Arc<dyn KeyProvider>,
    project: &str,
    profile: &str,
    budget: Duration,
    cancel: Arc<AtomicBool>,
) -> HeadlessOutcome {
    let t0 = Instant::now();
    let safe_prof = crate::monitor::safe_profile(Some(profile));
    if HEADLESS_RUNNING
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        return outcome_err(
            project,
            project,
            safe_prof,
            "busy",
            "Фоновый мониторинг уже выполняется".into(),
        );
    }
    let _running = RunningGuard(&HEADLESS_RUNNING);

    if UI_OPEN.load(Ordering::SeqCst) {
        return outcome_err(
            project,
            project,
            safe_prof,
            "busy",
            "Приложение уже активно: плановый скан запущен через основное окно".into(),
        );
    }

    let rt = match runtime() {
        Ok(rt) => rt,
        Err(e) => return outcome_err(project, project, safe_prof, "error", e),
    };

    cfg.headless = true;
    cfg.render = None;

    let (tx, rx) = mpsc::channel::<Value>();
    let ui_sink: Arc<Mutex<Option<Arc<dyn EventSink>>>> = Arc::new(Mutex::new(None));
    let sink: Arc<dyn EventSink> = Arc::new(FanoutSink {
        tx: Mutex::new(tx),
        ui_sink: ui_sink.clone(),
    });

    let data_dir = canonical_dir(&cfg.data_dir);
    let engine = match Engine::open(cfg, keys, sink) {
        Ok(e) => e,
        Err(e) => {
            let st = if e.code == "busy" { "busy" } else { "error" };
            awarn!("headless Engine::open {project}: {e}");
            return outcome_err(project, project, safe_prof, st, e.message);
        }
    };

    let session = Arc::new(LiveSession {
        data_dir,
        engine: engine.clone(),
        ui_sink,
        claimed_by_ui: AtomicBool::new(false),
    });
    *lock(live_slot()) = Some(session.clone());
    let live_guard = LiveClearGuard(session.clone());

    let name = project_name(rt, &engine, project);

    let budget_ms = budget.as_millis().max(1) as u64;
    let start = rt.block_on(engine.invoke(
        "scan_start",
        json!({
            "project": project,
            "profile": safe_prof,
            "trigger": "schedule",
            "headless": true,
            "budget_ms": budget_ms,
        }),
    ));

    let scan_id = match start {
        Ok(v) => v.get("scan_id").and_then(Value::as_str).map(str::to_string),
        Err(e) => {
            let st = if e.code == "busy" { "busy" } else { "error" };
            let _ = rt.block_on(engine.invoke(
                "settings_set",
                json!({
                    "patch": {
                        "monitor_status": {
                            project: {
                                "status": st,
                                "profile": safe_prof,
                                "headless": true,
                                "error": e.message,
                            }
                        }
                    }
                }),
            ));
            let ui_attached = session.claimed_by_ui.load(Ordering::SeqCst);
            drop(live_guard);
            drop(session);
            drop(engine);
            let mut out = outcome_err(project, &name, safe_prof, st, e.message);
            out.ui_attached = ui_attached;
            out.elapsed_ms = t0.elapsed().as_millis() as u64;
            return out;
        }
    };

    let hard_ceiling = budget + Duration::from_secs(15);
    let mut cancel_sent = false;
    let mut terminal: Option<Value> = None;

    loop {
        if !cancel_sent && (cancel.load(Ordering::SeqCst) || CANCEL_FLAG.load(Ordering::SeqCst)) {
            cancel_sent = true;
            awarn!("headless {project}: получена отмена, останавливаю скан с сохранением точки");
            let _ = rt.block_on(engine.invoke("scan_stop", json!({ "reason": "workmanager" })));
        }
        match rx.recv_timeout(Duration::from_millis(150)) {
            Ok(ev) => {
                let ty = ev.get("type").and_then(Value::as_str).unwrap_or("");
                if ty == "done" || ty == "stopped" {
                    terminal = Some(ev);
                    break;
                }
            }
            Err(RecvTimeoutError::Timeout) => {
                if t0.elapsed() >= hard_ceiling {
                    awarn!(
                        "headless {project}: превышен общий потолок ожидания, аварийная остановка"
                    );
                    let _ = rt.block_on(engine.invoke("scan_stop", json!({ "reason": "budget" })));
                    while let Ok(ev) = rx.try_recv() {
                        if matches!(ev["type"].as_str(), Some("done" | "stopped")) {
                            terminal = Some(ev);
                            break;
                        }
                    }
                    if terminal.is_none() {
                        terminal = Some(json!({ "type": "stopped", "reason": "budget" }));
                    }
                    break;
                }
            }
            Err(RecvTimeoutError::Disconnected) => break,
        }
    }

    let elapsed_ms = t0.elapsed().as_millis() as u64;
    let ui_attached = session.claimed_by_ui.load(Ordering::SeqCst);

    let outcome = match terminal {
        Some(ev) if ev["type"] == "done" => {
            let scan = &ev["scan"];
            let (title, text) = crate::monitor::done_summary(engine.ui_lang(), &name, scan);
            let added_docs = scan["added"]["docs"].as_u64().unwrap_or(0);
            let added_findings = scan["added"]["findings"]
                .as_u64()
                .max(scan["new_findings"].as_u64())
                .unwrap_or(0);
            let alerts_fired = ev["alerts_fired"]
                .as_u64()
                .or_else(|| scan["alerts_fired"].as_u64())
                .unwrap_or(0);
            alog!("headless мониторинг {project} завершён за {elapsed_ms} мс: +{added_docs} док., +{added_findings} находок, алертов={alerts_fired}");
            HeadlessOutcome {
                ok: true,
                status: "done".into(),
                project: project.into(),
                name,
                profile: safe_prof.into(),
                scan_id,
                title,
                text,
                added_docs,
                added_findings,
                alerts_fired,
                elapsed_ms,
                ui_attached,
                error: None,
            }
        }
        Some(ev) if ev["type"] == "stopped" => {
            let reason = ev["reason"].as_str().unwrap_or("stopped");
            match reason {
                "budget" => HeadlessOutcome {
                    ok: false,
                    status: "budget".into(),
                    project: project.into(),
                    name: name.clone(),
                    profile: safe_prof.into(),
                    scan_id,
                    title: format!("Плановый скан приостановлен · {name}"),
                    text: "Достигнут лимит фоновой работы (8 мин): контрольная точка сохранена, продолжите в приложении.".into(),
                    added_docs: 0,
                    added_findings: 0,
                    alerts_fired: 0,
                    elapsed_ms,
                    ui_attached,
                    error: None,
                },
                "workmanager" | "user" => HeadlessOutcome {
                    ok: false,
                    status: "cancelled".into(),
                    project: project.into(),
                    name: name.clone(),
                    profile: safe_prof.into(),
                    scan_id,
                    title: format!("Плановый скан остановлен · {name}"),
                    text: "Фоновое выполнение прервано системой: прогресс сохранён, продолжите с контрольной точки.".into(),
                    added_docs: 0,
                    added_findings: 0,
                    alerts_fired: 0,
                    elapsed_ms,
                    ui_attached,
                    error: None,
                },
                other => {
                    let msg = ev["message"]
                        .as_str()
                        .unwrap_or("ошибка планового скана")
                        .to_string();
                    let mut out = outcome_err(project, &name, safe_prof, "error", format!("{other}: {msg}"));
                    out.scan_id = scan_id;
                    out.elapsed_ms = elapsed_ms;
                    out.ui_attached = ui_attached;
                    out
                }
            }
        }
        _ => {
            let mut out = outcome_err(
                project,
                &name,
                safe_prof,
                "error",
                "Фоновый скан не прислал итоговое событие".into(),
            );
            out.scan_id = scan_id;
            out.elapsed_ms = elapsed_ms;
            out.ui_attached = ui_attached;
            out
        }
    };

    drop(live_guard);
    drop(session);
    drop(engine);
    outcome
}

#[cfg(target_os = "android")]
mod android_jni {
    use std::collections::HashMap;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use foca_engine::{EngineConfig, KeyProvider};
    use jni::objects::{GlobalRef, JClass, JObject, JString, JValue};
    use jni::sys::{jboolean, jint, jstring};
    use jni::{JNIEnv, JavaVM};
    use serde_json::json;

    use super::{
        clamp_budget_sec, outcome_err, run_headless_with, CANCEL_FLAG, DEFAULT_BUDGET_SEC,
    };

    struct JniKeyVault {
        vm: JavaVM,
        ctx: GlobalRef,
        cache: Mutex<HashMap<String, Option<String>>>,
    }

    impl KeyProvider for JniKeyVault {
        fn get(&self, service: &str) -> Option<String> {
            {
                let g = self.cache.lock().unwrap_or_else(|p| p.into_inner());
                if let Some(v) = g.get(service) {
                    return v.clone();
                }
            }
            let Ok(mut env) = self.vm.attach_current_thread() else {
                return None;
            };
            let res: Result<Option<String>, jni::errors::Error> = env.with_local_frame(16, |env| {
                let obj = self.ctx.as_obj();
                let loader = env
                    .call_method(obj, "getClassLoader", "()Ljava/lang/ClassLoader;", &[])?
                    .l()?;
                let cls_name = env.new_string("app.sinon.focars.platform.FocaDirect")?;
                let cls_obj = env
                    .call_method(
                        &loader,
                        "loadClass",
                        "(Ljava/lang/String;)Ljava/lang/Class;",
                        &[JValue::Object(&cls_name)],
                    )?
                    .l()?;
                let cls = JClass::from(cls_obj);
                let jsvc = env.new_string(service)?;
                let out = env
                    .call_static_method(
                        &cls,
                        "keystoreGet",
                        "(Landroid/content/Context;Ljava/lang/String;)Ljava/lang/String;",
                        &[JValue::Object(obj), JValue::Object(&jsvc)],
                    )?
                    .l()?;
                if out.is_null() {
                    return Ok(None);
                }
                let s: String = env.get_string(&JString::from(out))?.into();
                Ok(Some(s))
            });
            match res {
                Ok(val) => {
                    self.cache
                        .lock()
                        .unwrap_or_else(|p| p.into_inner())
                        .insert(service.to_string(), val.clone());
                    val
                }
                Err(e) => {
                    if env.exception_check().unwrap_or(false) {
                        let _ = env.exception_describe();
                        let _ = env.exception_clear();
                    }
                    awarn!("headless KeyVault.get({service}): {e}");
                    None
                }
            }
        }

        fn set(&self, _service: &str, _value: &str) -> Result<(), String> {
            Err("headless mode cannot modify keystore entries".into())
        }

        fn delete(&self, _service: &str) -> Result<(), String> {
            Err("headless mode cannot delete keystore entries".into())
        }
    }

    fn clear_exc(env: &mut JNIEnv) {
        if env.exception_check().unwrap_or(false) {
            let _ = env.exception_describe();
            let _ = env.exception_clear();
        }
    }

    #[no_mangle]
    pub extern "system" fn Java_app_sinon_focars_platform_FocaDirect_nativeRunHeadlessMonitor<
        'local,
    >(
        mut env: JNIEnv<'local>,
        _class: JClass<'local>,
        ctx: JObject<'local>,
        data_dir: JString<'local>,
        project: JString<'local>,
        profile: JString<'local>,
        budget_sec: jint,
        utc_offset_sec: jint,
    ) -> jstring {
        let extract = (|| -> Result<(String, String, String, JavaVM, GlobalRef), String> {
            let d: String = env
                .get_string(&data_dir)
                .map_err(|e| format!("dataDir: {e}"))?
                .into();
            let p: String = env
                .get_string(&project)
                .map_err(|e| format!("project: {e}"))?
                .into();
            let pr: String = env
                .get_string(&profile)
                .map_err(|e| format!("profile: {e}"))?
                .into();
            let vm = env.get_java_vm().map_err(|e| format!("JavaVM: {e}"))?;
            let gref = env
                .new_global_ref(&ctx)
                .map_err(|e| format!("GlobalRef: {e}"))?;
            Ok((d, p, pr, vm, gref))
        })();

        let json_out = match extract {
            Ok((data_dir_s, project_s, profile_s, vm, global_ctx)) => {
                crate::applog::install_panic_hook();
                let dir = PathBuf::from(&data_dir_s);
                crate::applog::set_dir(&dir.join("logs"));
                CANCEL_FLAG.store(false, Ordering::SeqCst);

                let sec = if budget_sec > 0 {
                    clamp_budget_sec(budget_sec as u64)
                } else {
                    DEFAULT_BUDGET_SEC
                };
                let p_for_panic = project_s.clone();
                let pr_for_panic = profile_s.clone();

                let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
                    let mut cfg = EngineConfig::new(&dir);
                    cfg.export_dir = dir.join("exports");
                    if let Ok(off) = time::UtcOffset::from_whole_seconds(utc_offset_sec) {
                        cfg.utc_offset = off;
                    }
                    cfg.headless = true;
                    let keys: Arc<dyn KeyProvider> = Arc::new(JniKeyVault {
                        vm,
                        ctx: global_ctx,
                        cache: Mutex::new(HashMap::new()),
                    });
                    let cancel = Arc::new(AtomicBool::new(false));
                    run_headless_with(
                        cfg,
                        keys,
                        &project_s,
                        &profile_s,
                        Duration::from_secs(sec),
                        cancel,
                    )
                }));
                let mut outcome = match r {
                    Ok(o) => o,
                    Err(_) => outcome_err(
                        &p_for_panic,
                        &p_for_panic,
                        crate::monitor::safe_profile(Some(&pr_for_panic)),
                        "error",
                        "Паника в headless-ядре (подробности в logs/crash-*.txt)".into(),
                    ),
                };
                // notification texts in the UI language (known core messages only)
                let lang = foca_engine::i18n::last_ui_lang().unwrap_or(foca_core::Lang::Ru);
                outcome.title = foca_engine::i18n::localize(lang, &outcome.title);
                outcome.text = foca_engine::i18n::localize(lang, &outcome.text);
                serde_json::to_string(&outcome).unwrap_or_else(|e| {
                    json!({ "ok": false, "status": "error", "error": e.to_string() }).to_string()
                })
            }
            Err(e) => {
                clear_exc(&mut env);
                json!({ "ok": false, "status": "error", "error": e }).to_string()
            }
        };

        jstring_out(&mut env, &json_out)
    }

    /// Scan service calls of the headless resume, through `FocaDirect.call`.
    struct JniNative {
        vm: JavaVM,
        ctx: GlobalRef,
    }

    impl crate::native::Native for JniNative {
        fn call(&self, cmd: &str, args: serde_json::Value) -> Result<serde_json::Value, String> {
            crate::native::direct::call_with(&self.vm, self.ctx.as_obj(), cmd, &args)
        }
        fn real(&self) -> bool {
            true
        }
        fn watch(
            &self,
            _on_event: Box<dyn Fn(serde_json::Value) + Send + Sync>,
        ) -> Result<(), String> {
            Ok(())
        }
    }

    fn jstring_out(env: &mut JNIEnv, s: &str) -> jstring {
        match env.new_string(s) {
            Ok(s) => s.into_raw(),
            Err(_) => {
                clear_exc(env);
                std::ptr::null_mut()
            }
        }
    }

    /// Resumes a scan interrupted by a process kill (`ScanResumeWorker`, after it started the scan
    /// service). Returns [`super::resume::ResumeOutcome`] as JSON.
    #[no_mangle]
    pub extern "system" fn Java_app_sinon_focars_platform_FocaDirect_nativeResumeInterruptedScan<
        'local,
    >(
        mut env: JNIEnv<'local>,
        _class: JClass<'local>,
        ctx: JObject<'local>,
        data_dir: JString<'local>,
        utc_offset_sec: jint,
    ) -> jstring {
        let extract = (|| -> Result<(String, JavaVM, JavaVM, GlobalRef, GlobalRef), String> {
            let d: String = env
                .get_string(&data_dir)
                .map_err(|e| format!("dataDir: {e}"))?
                .into();
            let vm = env.get_java_vm().map_err(|e| format!("JavaVM: {e}"))?;
            let vm2 = env.get_java_vm().map_err(|e| format!("JavaVM: {e}"))?;
            let g1 = env
                .new_global_ref(&ctx)
                .map_err(|e| format!("GlobalRef: {e}"))?;
            let g2 = env
                .new_global_ref(&ctx)
                .map_err(|e| format!("GlobalRef: {e}"))?;
            Ok((d, vm, vm2, g1, g2))
        })();
        let out = match extract {
            Ok((dir_s, vm, vm2, g1, g2)) => {
                crate::applog::install_panic_hook();
                let dir = PathBuf::from(&dir_s);
                crate::applog::set_dir(&dir.join("logs"));
                let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
                    let mut cfg = EngineConfig::new(&dir);
                    cfg.export_dir = dir.join("exports");
                    if let Ok(off) = time::UtcOffset::from_whole_seconds(utc_offset_sec) {
                        cfg.utc_offset = off;
                    }
                    let keys: Arc<dyn KeyProvider> = Arc::new(JniKeyVault {
                        vm,
                        ctx: g1,
                        cache: Mutex::new(HashMap::new()),
                    });
                    super::resume::start(cfg, keys, Arc::new(JniNative { vm: vm2, ctx: g2 }))
                }));
                match r {
                    Ok(o) => serde_json::to_string(&o).unwrap_or_default(),
                    Err(_) => json!({ "status": "error", "error": "panic" }).to_string(),
                }
            }
            Err(e) => {
                clear_exc(&mut env);
                json!({ "status": "error", "error": e }).to_string()
            }
        };
        jstring_out(&mut env, &out)
    }

    /// Device events and notification actions while no UI is attached; `true` when a headless
    /// resume took the event.
    #[no_mangle]
    pub extern "system" fn Java_app_sinon_focars_platform_FocaDirect_nativeHeadlessEvent<'local>(
        mut env: JNIEnv<'local>,
        _class: JClass<'local>,
        json: JString<'local>,
    ) -> jboolean {
        let Ok(s) = env.get_string(&json).map(String::from) else {
            clear_exc(&mut env);
            return 0;
        };
        let ev: serde_json::Value = serde_json::from_str(&s).unwrap_or_default();
        let took = std::panic::catch_unwind(|| super::resume::on_event(&ev)).unwrap_or(false);
        u8::from(took)
    }

    #[no_mangle]
    pub extern "system" fn Java_app_sinon_focars_platform_FocaDirect_nativeCancelHeadlessMonitor<
        'local,
    >(
        _env: JNIEnv<'local>,
        _class: JClass<'local>,
    ) {
        super::request_cancel();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use foca_engine::{MemoryEvents, MemoryKeys};
    use foca_net::dns::StaticDns;
    use foca_net::testserver::{TestResponse, TestServer};

    pub(super) static TEST_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    pub(super) fn guard() -> MutexGuard<'static, ()> {
        TEST_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|p| p.into_inner())
    }

    pub(super) fn offline_cfg(dir: &Path, base: &str) -> EngineConfig {
        let mut cfg = EngineConfig::new(dir);
        cfg.endpoints.wayback = base.into();
        cfg.endpoints.crtsh = base.into();
        cfg.endpoints.cc_collinfo = format!("{base}/collinfo.json");
        cfg.endpoints.ip_echo = format!("{base}/ip");
        cfg.endpoints.ip_geo = format!("{base}/geo/{{ip}}");
        for id in foca_engine::HOST_SOURCE_IDS
            .iter()
            .chain(foca_engine::DOC_SOURCE_IDS)
            .chain(&["internetdb", "grepapp"])
        {
            cfg.endpoints.sources.insert(id.to_string(), base.into());
        }
        cfg.dns = Some(Arc::new(StaticDns::from_zone_text(
            "example.test A 127.0.0.1\n",
        )));
        cfg.passive_download_hosts = vec!["127.0.0.1".into()];
        let port = base.rsplit(':').next().unwrap().parse::<u16>().unwrap();
        cfg.alive_ports = vec![port];
        cfg.net.retries = 0;
        cfg.lock_wait = Duration::from_millis(100);
        cfg
    }

    pub(super) fn seed_project(dir: &Path, base: &str) -> String {
        let rt = runtime().unwrap();
        let en = Engine::open(
            offline_cfg(dir, base),
            Arc::new(MemoryKeys::new()),
            Arc::new(MemoryEvents::new()),
        )
        .unwrap();
        let p = rt
            .block_on(en.invoke(
                "project_create",
                json!({
                    "name": "headless.unit",
                    "targets": [{ "v": "example.test", "type": "domain", "active": false }],
                    "excludes": []
                }),
            ))
            .unwrap();
        // Keep passive scheduled scans offline-fast: enable only `crt` in settings.
        let mut off_patch = serde_json::Map::new();
        for id in [
            "wayback",
            "cc",
            "crtname",
            "scanmalware",
            "certspotter",
            "anubis",
            "hackertarget",
            "rapiddns",
            "subcenter",
            "thc",
            "shodanct",
            "otx_dns",
            "arquivo",
            "otx_url",
            "urlscan",
            "hudson",
            "ddg",
            "bing",
            "mojeek",
            "startpage",
            "brave_web",
            "yahoo",
            "searx_pool",
            "internetdb",
            "recon",
            "wellknown",
            "buckets",
            "grepapp",
        ] {
            off_patch.insert(id.into(), json!({ "enabled": false }));
        }
        rt.block_on(en.invoke("settings_set", json!({ "patch": { "sources": off_patch } })))
            .unwrap();
        p["id"].as_str().unwrap().to_string()
    }

    pub(super) async fn mock_server(delay_ms: u64) -> TestServer {
        TestServer::start(move |r| {
            let p = r.path().to_string();
            if p == "/" && r.query("output").is_some() {
                let resp = TestResponse::ok(br#"[]"#.to_vec());
                return if delay_ms > 0 {
                    resp.delay(Duration::from_millis(delay_ms))
                } else {
                    resp
                };
            }
            if p == "/collinfo.json" {
                return TestResponse::ok(b"[]".to_vec());
            }
            TestResponse::status(404)
        })
        .await
    }

    #[test]
    fn clamp_budget_enforces_bounds() {
        assert_eq!(clamp_budget_sec(0), MIN_BUDGET_SEC);
        assert_eq!(clamp_budget_sec(10), MIN_BUDGET_SEC);
        assert_eq!(clamp_budget_sec(180), 180);
        assert_eq!(clamp_budget_sec(900), MAX_BUDGET_SEC);
    }

    #[test]
    fn headless_run_completes_updates_status_and_releases_lock() {
        let _g = guard();
        mark_ui_open(false);
        CANCEL_FLAG.store(false, Ordering::SeqCst);

        let rt = runtime().unwrap();
        let srv = rt.block_on(mock_server(0));
        let dir = tempfile::tempdir().unwrap();
        let pid = seed_project(dir.path(), &srv.url());

        let outcome = run_headless_with(
            offline_cfg(dir.path(), &srv.url()),
            Arc::new(MemoryKeys::new()),
            &pid,
            "full", // active profile coerced safely to passive
            Duration::from_secs(60),
            Arc::new(AtomicBool::new(false)),
        );
        assert!(outcome.ok, "{outcome:?}");
        assert_eq!(outcome.status, "done");
        assert_eq!(outcome.profile, "passive");
        assert!(!outcome.ui_attached);
        assert!(outcome.scan_id.is_some());

        // Lock released on exit: UI Engine::open must succeed immediately.
        let ui_en = Engine::open(
            offline_cfg(dir.path(), &srv.url()),
            Arc::new(MemoryKeys::new()),
            Arc::new(MemoryEvents::new()),
        )
        .expect("DataDirLock released after headless finish");
        let st = rt
            .block_on(ui_en.invoke("settings_get", json!({})))
            .unwrap();
        assert_eq!(st["monitor_status"][&pid]["status"], "done");
    }

    #[test]
    fn ui_attach_live_engine_receives_events_without_double_open() {
        let _g = guard();
        mark_ui_open(false);
        CANCEL_FLAG.store(false, Ordering::SeqCst);

        let rt = runtime().unwrap();
        let srv = rt.block_on(mock_server(400));
        let dir = tempfile::tempdir().unwrap();
        let pid = seed_project(dir.path(), &srv.url());

        let dir_bg = dir.path().to_path_buf();
        let url_bg = srv.url();
        let pid_bg = pid.clone();
        let handle = std::thread::spawn(move || {
            run_headless_with(
                offline_cfg(&dir_bg, &url_bg),
                Arc::new(MemoryKeys::new()),
                &pid_bg,
                "passive",
                Duration::from_secs(60),
                Arc::new(AtomicBool::new(false)),
            )
        });

        // Wait until live session appears in `LIVE`
        for _ in 0..100 {
            if lock(live_slot()).is_some() {
                break;
            }
            std::thread::sleep(Duration::from_millis(15));
        }

        let ui_events = Arc::new(MemoryEvents::new());
        let attached = attach_live_engine(
            dir.path(),
            Arc::new(MemoryKeys::new()),
            ui_events.clone(),
            None,
            None,
            None,
            None,
        )
        .expect("UI must attach to running headless engine");
        assert!(!attached.is_headless());

        let outcome = handle.join().unwrap();
        mark_ui_open(false);
        assert!(outcome.ok, "{outcome:?}");
        assert!(
            outcome.ui_attached,
            "expected ui_attached=true: {outcome:?}"
        );
        assert!(
            ui_events.events().iter().any(|e| e["type"] == "done"),
            "attached UI sink must receive terminal event: {:?}",
            ui_events.events()
        );
    }

    #[test]
    fn request_cancel_stops_active_headless_scan() {
        let _g = guard();
        mark_ui_open(false);
        CANCEL_FLAG.store(false, Ordering::SeqCst);

        let rt = runtime().unwrap();
        let srv = rt.block_on(mock_server(600));
        let dir = tempfile::tempdir().unwrap();
        let pid = seed_project(dir.path(), &srv.url());

        let dir_bg = dir.path().to_path_buf();
        let url_bg = srv.url();
        let pid_bg = pid.clone();
        let handle = std::thread::spawn(move || {
            run_headless_with(
                offline_cfg(&dir_bg, &url_bg),
                Arc::new(MemoryKeys::new()),
                &pid_bg,
                "passive",
                Duration::from_secs(60),
                Arc::new(AtomicBool::new(false)),
            )
        });

        for _ in 0..100 {
            if let Some(session) = lock(live_slot()).as_ref() {
                if session.engine.is_scanning() {
                    break;
                }
            }
            std::thread::sleep(Duration::from_millis(15));
        }
        request_cancel();

        let outcome = handle.join().unwrap();
        CANCEL_FLAG.store(false, Ordering::SeqCst);
        assert!(!outcome.ok, "{outcome:?}");
        assert_eq!(outcome.status, "cancelled");
    }
}
