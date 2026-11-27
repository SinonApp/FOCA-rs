//! Resumes a scan interrupted by a process kill without the UI.
//!
//! Android calls [`start`] from `ScanResumeWorker` (through `FocaDirect.resumeInterruptedScan`)
//! after it has started the scan foreground service in a process without an Activity. The runner
//! applies the same rules as the bridge on app open (`power.auto_resume`, attempt counter), opens
//! a background engine and resumes the run as a full scan (`headless: false`, so no background
//! limits apply). The scan then keeps running on the headless runtime:
//! - device events and notification actions arrive through [`on_event`] and go through the same
//!   pause policy as in the UI;
//! - the notification is updated and the service stopped through [`Native`] calls;
//! - when the UI opens, `attach_live_engine` takes the engine over ([`hand_over`]) and the runner
//!   leaves the service, notification and policy to the bridge.

use std::sync::atomic::Ordering;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use foca_engine::{Engine, EngineConfig, EventSink, KeyProvider};
use serde::Serialize;
use serde_json::{json, Value};

use super::{
    canonical_dir, live_slot, lock, project_name, runtime, FanoutSink, LiveClearGuard, LiveSession,
    RunningGuard, HEADLESS_RUNNING, UI_OPEN,
};
use crate::native::Native;
use crate::policy::{Action, Env, Policy, PolicySettings};
use crate::recovery::{self, ResumeDecision};
use crate::scan_note::ServiceState;

/// Result handed back to Kotlin.
///
/// `status`: `resumed` (the scan runs in this process), `none` (nothing to resume), `disabled`
/// (setting off), `too_many` (crash-loop guard), `busy` (the UI or another background run owns
/// the data) or `error`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ResumeOutcome {
    pub status: String,
    pub project: String,
    pub scan_id: String,
    pub attempt: u32,
    pub error: Option<String>,
}

impl ResumeOutcome {
    fn new(status: &str) -> Self {
        ResumeOutcome {
            status: status.into(),
            project: String::new(),
            scan_id: String::new(),
            attempt: 0,
            error: None,
        }
    }
}

/// State of the running headless resume.
struct Control {
    engine: Engine,
    native: Arc<dyn Native>,
    policy: Policy,
    env: Env,
    settings: PolicySettings,
    svc: ServiceState,
    /// The UI took the engine over; the bridge owns the service and the policy now.
    handed_over: bool,
}

static CONTROL: OnceLock<Mutex<Option<Control>>> = OnceLock::new();

fn control() -> &'static Mutex<Option<Control>> {
    CONTROL.get_or_init(|| Mutex::new(None))
}

/// Opens a background engine and resumes the interrupted scan, if any. Returns at once; the scan
/// keeps running on the headless runtime.
pub fn start(
    mut cfg: EngineConfig,
    keys: Arc<dyn KeyProvider>,
    native: Arc<dyn Native>,
) -> ResumeOutcome {
    if HEADLESS_RUNNING
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        return ResumeOutcome::new("busy");
    }
    let running = RunningGuard(&HEADLESS_RUNNING);
    if UI_OPEN.load(Ordering::SeqCst) {
        return ResumeOutcome::new("busy");
    }
    // Read the previous process's run BEFORE Engine::open, which turns it into stopped/restart.
    let Some(mut args) = foca_engine::resume::interrupted_scan(&cfg.data_dir) else {
        alog!("resume: прерванного скана нет");
        return ResumeOutcome::new("none");
    };
    let mut out = ResumeOutcome::new("error");
    out.project = args["project"].as_str().unwrap_or("").to_string();
    out.scan_id = args["resume_from"].as_str().unwrap_or("").to_string();
    let rt = match runtime() {
        Ok(rt) => rt,
        Err(e) => {
            out.error = Some(e);
            return out;
        }
    };

    cfg.headless = true;
    cfg.render = None;
    let (tx, rx) = mpsc::channel::<Value>();
    let ui_sink = Arc::new(Mutex::new(None));
    let sink: Arc<dyn EventSink> = Arc::new(FanoutSink {
        tx: Mutex::new(tx),
        ui_sink: ui_sink.clone(),
    });
    let data_dir = canonical_dir(&cfg.data_dir);
    let engine = match Engine::open(cfg, keys, sink) {
        Ok(e) => e,
        Err(e) => {
            awarn!("resume: Engine::open: {e}");
            out.status = if e.code == "busy" { "busy" } else { "error" }.into();
            out.error = Some(e.message);
            return out;
        }
    };

    let settings = rt
        .block_on(engine.invoke("settings_get", json!({})))
        .unwrap_or_else(|_| json!({}));
    let enabled = foca_engine::resume::enabled(&settings);
    let now_ms = (time::OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000_000) as i64;
    out.attempt = if enabled {
        foca_engine::resume::note_attempt(&data_dir, &out.scan_id, now_ms)
    } else {
        1
    };
    let decision =
        recovery::auto_resume_decision(enabled, out.attempt, foca_engine::resume::MAX_ATTEMPTS);
    alog!(
        "resume: фоновое автопродолжение скана {}: {decision:?} (попытка {})",
        out.scan_id,
        out.attempt
    );
    match decision {
        ResumeDecision::Resume => {}
        ResumeDecision::Disabled => {
            out.status = "disabled".into();
            return out;
        }
        ResumeDecision::TooMany => {
            out.status = "too_many".into();
            return out;
        }
    }

    let session = Arc::new(LiveSession {
        data_dir,
        engine: engine.clone(),
        ui_sink,
        claimed_by_ui: std::sync::atomic::AtomicBool::new(false),
    });
    *lock(live_slot()) = Some(session.clone());
    let live = LiveClearGuard(session);

    let active = args["active"].as_bool().unwrap_or(false);
    args["auto"] = json!(true);
    args["headless"] = json!(false);
    if let Err(e) = rt.block_on(engine.invoke("scan_start", args)) {
        awarn!("resume: scan_start {}: {e}", out.scan_id);
        out.status = if e.code == "busy" { "busy" } else { "error" }.into();
        out.error = Some(e.message);
        return out;
    }

    let mut c = Control {
        engine: engine.clone(),
        native,
        policy: Policy::new(),
        env: Env::default(),
        settings: crate::devstate::policy_settings(&settings),
        svc: ServiceState::default(),
        handed_over: false,
    };
    c.svc.claim_start(project_name(rt, &engine, &out.project));
    crate::devstate::sync_mobile(&mut c.env, &c.engine);
    let actions = c.policy.scan_started(active, &c.env, &c.settings);
    *lock(control()) = Some(c);
    apply(actions);
    service_update();

    let spawned = std::thread::Builder::new()
        .name("foca-resume".into())
        .spawn(move || {
            let end = watch(&rx, &engine);
            finish(&live, end.as_ref());
            drop(running);
        });
    if let Err(e) = spawned {
        aerr!("resume: поток наблюдения не запущен: {e}");
        lock(control()).take();
        out.error = Some(e.to_string());
        return out;
    }
    out.status = "resumed".into();
    out
}

/// Feeds a device event (`net`, `power`) or a notification action (`service`) to the running
/// headless resume. Returns `false` when no headless resume owns the scan.
pub fn on_event(ev: &Value) -> bool {
    let (engine, actions, stop) = {
        let mut g = lock(control());
        let Some(c) = g.as_mut().filter(|c| !c.handed_over) else {
            return false;
        };
        let mut stop = false;
        let actions = match ev.get("kind").and_then(Value::as_str).unwrap_or("") {
            "service" => match ev.get("action").and_then(Value::as_str) {
                Some("stop") => {
                    stop = true;
                    vec![]
                }
                Some("timeout") => {
                    c.svc.running = false;
                    c.policy.on_fgs_timeout()
                }
                Some("destroyed") => {
                    c.svc.running = false;
                    vec![]
                }
                _ => vec![],
            },
            _ if crate::devstate::apply_device(&mut c.env, ev) => {
                crate::devstate::sync_mobile(&mut c.env, &c.engine);
                c.policy.on_env(&c.env, &c.settings)
            }
            _ => return true,
        };
        (c.engine.clone(), actions, stop)
    };
    if stop {
        alog!("resume: «Стоп» из уведомления, останавливаю фоновый скан");
        if let Ok(rt) = runtime() {
            if let Err(e) = rt.block_on(engine.invoke("scan_stop", json!({ "reason": "user" }))) {
                awarn!("resume: scan_stop: {e}");
            }
        }
    }
    apply(actions);
    service_update();
    true
}

/// The UI attached to the engine: lift pauses this runner set, so the bridge policy decides
/// afresh, and stop driving the service.
pub fn hand_over() {
    let mut g = lock(control());
    let Some(c) = g.as_mut() else {
        return;
    };
    c.handed_over = true;
    if c.policy.env_reason().is_some() {
        c.engine.resume();
    }
    alog!("resume: UI подключился, сервис и политику ведёт мост");
}

fn apply(actions: Vec<Action>) {
    if actions.is_empty() {
        return;
    }
    let engine = {
        let mut g = lock(control());
        let Some(c) = g.as_mut() else {
            return;
        };
        for a in &actions {
            match a {
                Action::Pause(r) => {
                    c.engine.pause(r);
                    c.svc.paused = Some(r.to_string());
                    if *r == "mobile_cap" {
                        notify_mobile_cap(c);
                    }
                }
                Action::Resume => {
                    c.engine.resume();
                    c.svc.paused = None;
                }
                Action::Stop(_) => {}
            }
        }
        c.engine.clone()
    };
    alog!("resume: политика {actions:?}");
    for a in actions {
        if let Action::Stop(r) = a {
            if let Ok(rt) = runtime() {
                if let Err(e) = rt.block_on(engine.invoke("scan_stop", json!({ "reason": r }))) {
                    awarn!("resume: scan_stop {r}: {e}");
                }
            }
        }
    }
}

/// Posts the "mobile data limit reached" notification.
fn notify_mobile_cap(c: &Control) {
    let usage = runtime()
        .ok()
        .and_then(|rt| rt.block_on(c.engine.invoke("mobile_usage", json!({}))).ok())
        .unwrap_or_default();
    let note = crate::scan_note::mobile_cap_note(c.engine.ui_lang(), &usage);
    if let Err(e) = c.native.call("status_notify", note) {
        awarn!("resume: status_notify: {e}");
    }
}

/// Feeds the engine's `mobile_cap` event (monthly mobile data limit crossed) to the policy.
fn on_mobile_cap() {
    let actions = {
        let mut g = lock(control());
        let Some(c) = g.as_mut().filter(|c| !c.handed_over) else {
            return;
        };
        crate::devstate::sync_mobile(&mut c.env, &c.engine);
        c.policy.on_env(&c.env, &c.settings)
    };
    apply(actions);
}

/// Pushes the current notification text to the scan service.
fn service_update() {
    let (native, payload) = {
        let g = lock(control());
        let Some(c) = g.as_ref().filter(|c| !c.handed_over && c.svc.running) else {
            return;
        };
        (c.native.clone(), c.svc.payload(c.engine.ui_lang()))
    };
    if let Err(e) = native.call("scan_service_update", payload) {
        awarn!("resume: scan_service_update: {e}");
    }
}

/// Follows scan events until the run ends; returns the terminal event.
fn watch(rx: &Receiver<Value>, engine: &Engine) -> Option<Value> {
    loop {
        match rx.recv_timeout(Duration::from_millis(500)) {
            Ok(ev) => {
                if on_scan_event(&ev) {
                    return Some(ev);
                }
            }
            Err(RecvTimeoutError::Timeout) => {
                if !engine.is_scanning() {
                    return rx.try_iter().find(on_scan_event);
                }
            }
            Err(RecvTimeoutError::Disconnected) => return None,
        }
    }
}

/// Updates the notification from a scan event; returns `true` on the terminal event.
fn on_scan_event(ev: &Value) -> bool {
    let ty = ev.get("type").and_then(Value::as_str).unwrap_or("");
    let terminal = ty == "done" || ty == "stopped";
    {
        let mut g = lock(control());
        let Some(c) = g.as_mut() else {
            return terminal;
        };
        match ty {
            "stage" => {
                if let Some(l) = ev.get("label").and_then(Value::as_str) {
                    c.svc.stage = l.to_string();
                }
            }
            "progress" => {
                let p = ev["progress"].as_u64().unwrap_or(0).min(100) as u8;
                if p == c.svc.progress {
                    return false;
                }
                c.svc.progress = p;
            }
            "mobile_cap" => {
                drop(g);
                on_mobile_cap();
            }
            "done" | "stopped" => {
                alog!(
                    "resume: фоновый скан {}: {ty} {}",
                    ev["scan_id"].as_str().unwrap_or("?"),
                    ev["reason"].as_str().unwrap_or("")
                );
                return true;
            }
            _ => return false,
        }
    }
    service_update();
    false
}

/// Ends the run: stops the service and posts the result unless the UI took over.
fn finish(live: &LiveClearGuard, end: Option<&Value>) {
    let Some(c) = lock(control()).take() else {
        return;
    };
    if c.handed_over || live.0.claimed_by_ui.load(Ordering::SeqCst) {
        return;
    }
    if let Err(e) = c.native.call("scan_service_stop", json!({})) {
        awarn!("resume: scan_service_stop: {e}");
    }
    let Some(ev) = end.filter(|ev| ev["type"] == "done") else {
        return;
    };
    let (title, text) = crate::monitor::done_summary(c.engine.ui_lang(), &c.svc.title, &ev["scan"]);
    let project = ev["project"].as_str().unwrap_or("");
    if let Err(e) = c.native.call(
        "scan_done_notify",
        json!({ "project": project, "title": title, "text": text }),
    ) {
        awarn!("resume: scan_done_notify: {e}");
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::{guard, mock_server, offline_cfg, seed_project};
    use super::super::{attach_live_engine, mark_ui_open};
    use super::*;
    use foca_engine::{MemoryEvents, MemoryKeys};
    use std::path::Path;

    /// Records native calls instead of talking to Android.
    #[derive(Default)]
    struct Calls(Mutex<Vec<(String, Value)>>);

    impl Native for Calls {
        fn call(&self, cmd: &str, args: Value) -> Result<Value, String> {
            lock(&self.0).push((cmd.to_string(), args));
            Ok(json!({ "ok": true }))
        }
        fn real(&self) -> bool {
            true
        }
        fn watch(&self, _on_event: Box<dyn Fn(Value) + Send + Sync>) -> Result<(), String> {
            Ok(())
        }
    }

    impl Calls {
        fn names(&self) -> Vec<String> {
            lock(&self.0).iter().map(|(c, _)| c.clone()).collect()
        }
    }

    /// Starts a slow passive scan and drops the engine mid-run, like a process kill.
    fn interrupted(dir: &Path, base: &str) -> (String, String) {
        let pid = seed_project(dir, base);
        let rt = runtime().unwrap();
        let en = Engine::open(
            offline_cfg(dir, base),
            Arc::new(MemoryKeys::new()),
            Arc::new(MemoryEvents::new()),
        )
        .unwrap();
        let r = rt
            .block_on(en.invoke(
                "scan_start",
                json!({ "project": pid, "profile": "passive", "sources": ["crt"] }),
            ))
            .unwrap();
        rt.block_on(en.abandon());
        drop(en);
        (pid, r["scan_id"].as_str().unwrap().to_string())
    }

    fn wait_idle() {
        for _ in 0..800 {
            if !HEADLESS_RUNNING.load(Ordering::SeqCst) {
                return;
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        panic!("headless resume did not finish");
    }

    #[test]
    fn nothing_to_resume_without_run_file() {
        let _g = guard();
        mark_ui_open(false);
        let rt = runtime().unwrap();
        let srv = rt.block_on(mock_server(0));
        let dir = tempfile::tempdir().unwrap();
        seed_project(dir.path(), &srv.url());
        let calls = Arc::new(Calls::default());
        let out = start(
            offline_cfg(dir.path(), &srv.url()),
            Arc::new(MemoryKeys::new()),
            calls.clone(),
        );
        assert_eq!(out.status, "none", "{out:?}");
        assert!(!HEADLESS_RUNNING.load(Ordering::SeqCst));
        assert!(calls.names().is_empty());
    }

    #[test]
    fn resumes_interrupted_scan_as_full_run_and_stops_service() {
        let _g = guard();
        mark_ui_open(false);
        let rt = runtime().unwrap();
        let srv = rt.block_on(mock_server(300));
        let dir = tempfile::tempdir().unwrap();
        let (pid, scan_id) = interrupted(dir.path(), &srv.url());

        let calls = Arc::new(Calls::default());
        let out = start(
            offline_cfg(dir.path(), &srv.url()),
            Arc::new(MemoryKeys::new()),
            calls.clone(),
        );
        assert_eq!(out.status, "resumed", "{out:?}");
        assert_eq!(out.scan_id, scan_id);
        assert_eq!(out.project, pid);
        assert_eq!(out.attempt, 1);
        // A second start while the scan runs is refused by the single-run lock.
        let again = start(
            offline_cfg(dir.path(), &srv.url()),
            Arc::new(MemoryKeys::new()),
            calls.clone(),
        );
        assert_eq!(again.status, "busy");
        let st = {
            let g = lock(live_slot());
            let en = g.as_ref().expect("live session").engine.clone();
            drop(g);
            rt.block_on(en.invoke("scan_status", json!({}))).unwrap()
        };
        assert_eq!(st["auto"], true);
        assert_eq!(st["resumed"], true);
        let run: Value =
            serde_json::from_slice(&std::fs::read(dir.path().join("engine_run.json")).unwrap())
                .unwrap();
        assert_eq!(run["headless"], false, "resumed as a full run: {run}");
        wait_idle();

        let names = calls.names();
        assert!(
            names.contains(&"scan_service_update".to_string()),
            "{names:?}"
        );
        assert!(
            names.contains(&"scan_service_stop".to_string()),
            "{names:?}"
        );
        assert!(names.contains(&"scan_done_notify".to_string()), "{names:?}");
        let en = Engine::open(
            offline_cfg(dir.path(), &srv.url()),
            Arc::new(MemoryKeys::new()),
            Arc::new(MemoryEvents::new()),
        )
        .expect("data dir lock released after the resumed scan");
        let snap = rt
            .block_on(en.invoke("project_snapshot", json!({ "id": pid })))
            .unwrap();
        let scans = snap["scans"].as_array().unwrap();
        assert_eq!(scans.len(), 1, "same history record");
        assert_eq!(scans[0]["status"], "done");
    }

    #[test]
    fn respects_auto_resume_setting() {
        let _g = guard();
        mark_ui_open(false);
        let rt = runtime().unwrap();
        let srv = rt.block_on(mock_server(300));
        let dir = tempfile::tempdir().unwrap();
        let pid = seed_project(dir.path(), &srv.url());
        {
            let en = Engine::open(
                offline_cfg(dir.path(), &srv.url()),
                Arc::new(MemoryKeys::new()),
                Arc::new(MemoryEvents::new()),
            )
            .unwrap();
            rt.block_on(en.invoke(
                "settings_set",
                json!({ "patch": { "power": { "auto_resume": false } } }),
            ))
            .unwrap();
            rt.block_on(en.invoke(
                "scan_start",
                json!({ "project": pid, "profile": "passive", "sources": ["crt"] }),
            ))
            .unwrap();
            rt.block_on(en.abandon());
        }
        let calls = Arc::new(Calls::default());
        let out = start(
            offline_cfg(dir.path(), &srv.url()),
            Arc::new(MemoryKeys::new()),
            calls.clone(),
        );
        assert_eq!(out.status, "disabled", "{out:?}");
        assert!(!HEADLESS_RUNNING.load(Ordering::SeqCst));
        assert!(calls.names().is_empty());
    }

    #[test]
    fn battery_policy_pauses_and_ui_takes_over() {
        let _g = guard();
        mark_ui_open(false);
        let rt = runtime().unwrap();
        let srv = rt.block_on(mock_server(400));
        let dir = tempfile::tempdir().unwrap();
        interrupted(dir.path(), &srv.url());
        let calls = Arc::new(Calls::default());
        let out = start(
            offline_cfg(dir.path(), &srv.url()),
            Arc::new(MemoryKeys::new()),
            calls.clone(),
        );
        assert_eq!(out.status, "resumed", "{out:?}");
        {
            let mut g = lock(control());
            let c = g.as_mut().unwrap();
            c.settings.batt_on = true;
            c.settings.batt = 20;
        }
        assert!(on_event(
            &json!({ "kind": "power", "battery": 10, "charging": false })
        ));
        let en = lock(live_slot()).as_ref().unwrap().engine.clone();
        let st = rt.block_on(en.invoke("scan_status", json!({}))).unwrap();
        assert_eq!(st["pause_reason"], "battery", "{st}");

        let ui_events = Arc::new(MemoryEvents::new());
        attach_live_engine(
            dir.path(),
            Arc::new(MemoryKeys::new()),
            ui_events.clone(),
            None,
            None,
            None,
            None,
        )
        .expect("UI attaches to the resumed scan");
        // The runner lifts its own pause and stops handling events after the handover.
        let st = rt.block_on(en.invoke("scan_status", json!({}))).unwrap();
        assert_eq!(st["paused"], false, "{st}");
        assert!(!on_event(&json!({ "kind": "power", "battery": 5 })));
        drop(en);
        wait_idle();
        mark_ui_open(false);
        assert!(ui_events.events().iter().any(|e| e["type"] == "done"));
        assert!(
            !calls.names().contains(&"scan_service_stop".to_string()),
            "the bridge owns the service after the handover: {:?}",
            calls.names()
        );
    }

    #[test]
    fn mobile_cap_pauses_on_mobile_data_until_wifi() {
        let _g = guard();
        mark_ui_open(false);
        let rt = runtime().unwrap();
        let srv = rt.block_on(mock_server(400));
        let dir = tempfile::tempdir().unwrap();
        interrupted(dir.path(), &srv.url());
        // 2 MB of mobile data already used this month
        let now = time::OffsetDateTime::now_utc();
        std::fs::write(
            dir.path().join("mobile_usage.json"),
            json!({
                "month": format!("{:04}-{:02}", now.year(), u8::from(now.month())),
                "bytes": 2 * 1024 * 1024
            })
            .to_string(),
        )
        .unwrap();
        let calls = Arc::new(Calls::default());
        let out = start(
            offline_cfg(dir.path(), &srv.url()),
            Arc::new(MemoryKeys::new()),
            calls.clone(),
        );
        assert_eq!(out.status, "resumed", "{out:?}");
        let en = lock(live_slot()).as_ref().unwrap().engine.clone();
        // a 1 MB monthly limit
        rt.block_on(en.invoke(
            "settings_set",
            json!({ "patch": { "power": { "lim_on": true, "mob_limit": 1 } } }),
        ))
        .unwrap();
        // "Wi-Fi only" (on by default) would win over the cap on mobile data
        lock(control()).as_mut().unwrap().settings.wifi_only = false;
        // Wi-Fi: the cap does not apply
        assert!(on_event(
            &json!({ "kind": "net", "online": true, "transport": "wifi", "metered": false })
        ));
        let st = rt.block_on(en.invoke("scan_status", json!({}))).unwrap();
        assert_eq!(st["paused"], false, "{st}");
        // mobile data: paused with `mobile_cap` and a notification with the usage
        assert!(on_event(
            &json!({ "kind": "net", "online": true, "transport": "cellular", "metered": true })
        ));
        let st = rt.block_on(en.invoke("scan_status", json!({}))).unwrap();
        assert_eq!(st["pause_reason"], "mobile_cap", "{st}");
        let note = lock(&calls.0)
            .iter()
            .find(|(c, _)| c == "status_notify")
            .map(|(_, a)| a.clone())
            .expect("status_notify posted");
        assert_eq!(note["tag"], "mobile_cap");
        assert!(note["text"].as_str().unwrap().contains("2"), "{note}");
        // back on Wi-Fi: resumed by itself
        assert!(on_event(
            &json!({ "kind": "net", "online": true, "transport": "wifi", "metered": false })
        ));
        let st = rt.block_on(en.invoke("scan_status", json!({}))).unwrap();
        assert_eq!(st["paused"], false, "{st}");
        drop(en);
        wait_idle();
        mark_ui_open(false);
    }
}
