//! Native layer: the Kotlin plugin `app.sinon.focars.platform.FocaPlugin` (Android) or a stub
//! (desktop).
//!
//! The plugin is built into the app itself
//! (`src-tauri/gen/android/app/src/main/java/.../platform/`) rather than shipped as a separate
//! crate with a Gradle module: the service, FileProvider and permissions live in the app
//! manifest anyway, and JS has no access to the plugin (no ACL permissions), so the UI goes
//! through the `foca` command only. `run_mobile_plugin` calls block and execute on the Android
//! main thread, so they must only be made from background threads (spawn_blocking, the bridge
//! worker). Every call is logged with its duration (`foca::app`, debug; slow or failed calls at
//! warn).

use std::sync::{Arc, OnceLock};

use serde_json::{json, Value};
use tauri::plugin::TauriPlugin;
use tauri::Runtime;

/// Kotlin plugin commands (a single entry point keeps the bridge independent of the runtime).
pub trait Native: Send + Sync {
    fn call(&self, cmd: &str, args: Value) -> Result<Value, String>;
    /// Returns `true` if a real native layer (Android) is present.
    fn real(&self) -> bool;
    /// Subscribes to device events (network, battery, scan service, UI lifecycle).
    fn watch(&self, on_event: Box<dyn Fn(Value) + Send + Sync>) -> Result<(), String>;
}

/// Desktop, or before the plugin is registered.
pub struct NoNative;

impl Native for NoNative {
    fn call(&self, cmd: &str, args: Value) -> Result<Value, String> {
        match cmd {
            "biometric_prompt" => {
                Ok(json!({ "ok": false, "available": false, "error": "unsupported" }))
            }
            "set_secure" => Ok(json!({ "ok": true, "applied": false })),
            "battery_optimization_status" => Ok(json!({ "ignoring": true, "supported": false })),
            "device_info" => Ok(json!({ "utc_offset": Value::Null })),
            "scan_service_start" | "scan_service_update" | "scan_service_stop" => {
                Ok(json!({ "ok": true, "running": false }))
            }
            "toast" => Ok(json!({ "ok": false })),
            // Monitoring: no notifications or WorkManager on desktop.
            "scan_done_notify" | "monitor_schedule" => Ok(json!({ "ok": false })),
            "permissions_status" => {
                Ok(json!({ "notifications": true, "battery": true, "oem": "pixel", "stub": true }))
            }
            "request_notifications" => {
                Ok(json!({ "enabled": true, "granted": true, "action": "none" }))
            }
            "app_exit" => Ok(json!({ "ok": true })),
            "bg_status" | "bg_set" => Ok(json!({
                "oem": "other", "autostart": "unknown", "battery_unrestricted": true,
                "hide_recents": false, "hide_recents_default": false, "stub": true
            })),
            _ => {
                let _ = args;
                Err(format!("{cmd}: доступно только в приложении Android"))
            }
        }
    }
    fn real(&self) -> bool {
        false
    }
    fn watch(&self, _on_event: Box<dyn Fn(Value) + Send + Sync>) -> Result<(), String> {
        Ok(())
    }
}

#[cfg(target_os = "android")]
pub struct AndroidNative<R: Runtime>(pub tauri::plugin::PluginHandle<R>);

#[cfg(target_os = "android")]
impl<R: Runtime> AndroidNative<R> {
    fn plugin_call(&self, cmd: &str, args: Value) -> Result<Value, String> {
        self.0
            .run_mobile_plugin::<Value>(cmd, args)
            .map_err(|e| e.to_string())
    }
}

/// Calls the plugin and logs the duration (debug; errors or calls over 1 s at warn).
#[cfg(target_os = "android")]
fn timed(cmd: &str, via: &str, f: impl FnOnce() -> Result<Value, String>) -> Result<Value, String> {
    let t0 = std::time::Instant::now();
    let r = f();
    let ms = t0.elapsed().as_millis();
    match &r {
        Err(e) => awarn!("native {cmd} ({via}): ошибка за {ms} мс: {e}"),
        Ok(_) if ms > 1000 => awarn!("native {cmd} ({via}): медленно, {ms} мс"),
        Ok(_) => adbg!("native {cmd} ({via}): {ms} мс"),
    }
    r
}

/// Calls `app.sinon.focars.platform.FocaDirect.call(Context, cmd, json)` directly over JNI,
/// without an Activity or the main thread. tao stores the application context and JavaVM in
/// `ndk_context` on the first onCreate.
#[cfg(target_os = "android")]
pub(crate) mod direct {
    use jni::objects::{JClass, JObject, JString, JValue};
    use jni::JavaVM;
    use serde_json::Value;

    pub fn call(cmd: &str, args: &Value) -> Result<Value, String> {
        let ctx = ndk_context::android_context();
        if ctx.vm().is_null() || ctx.context().is_null() {
            return Err("нет контекста Android".into());
        }
        // SAFETY: the JavaVM pointer and the global Application reference from ndk_context live for
        // the whole process.
        let vm = unsafe { JavaVM::from_raw(ctx.vm().cast()) }.map_err(|e| e.to_string())?;
        let context = unsafe { JObject::from_raw(ctx.context().cast()) };
        call_with(&vm, &context, cmd, args)
    }

    /// Same as [`call`] with an explicit VM and context (the headless core has no ndk_context).
    pub fn call_with(
        vm: &JavaVM,
        context: &JObject,
        cmd: &str,
        args: &Value,
    ) -> Result<Value, String> {
        let mut env = vm.attach_current_thread().map_err(|e| e.to_string())?;
        let json = args.to_string();
        let r: Result<String, jni::errors::Error> = env.with_local_frame(16, |env| {
            let loader = env
                .call_method(context, "getClassLoader", "()Ljava/lang/ClassLoader;", &[])?
                .l()?;
            let name = env.new_string("app.sinon.focars.platform.FocaDirect")?;
            let cls = env
                .call_method(
                    &loader,
                    "loadClass",
                    "(Ljava/lang/String;)Ljava/lang/Class;",
                    &[JValue::Object(&name)],
                )?
                .l()?;
            let cls = JClass::from(cls);
            let jcmd = env.new_string(cmd)?;
            let jjson = env.new_string(&json)?;
            let out = env
                .call_static_method(
                    &cls,
                    "call",
                    "(Landroid/content/Context;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;",
                    &[
                        JValue::Object(context),
                        JValue::Object(&jcmd),
                        JValue::Object(&jjson),
                    ],
                )?
                .l()?;
            let s: String = env.get_string(&JString::from(out))?.into();
            Ok(s)
        });
        let s = match r {
            Ok(s) => s,
            Err(e) => {
                // A Java exception must not be left pending on the thread.
                if env.exception_check().unwrap_or(false) {
                    let _ = env.exception_describe();
                    let _ = env.exception_clear();
                }
                return Err(format!("JNI: {e}"));
            }
        };
        let v: Value = serde_json::from_str(&s).map_err(|e| format!("ответ FocaDirect: {e}"))?;
        match v.get("error").and_then(Value::as_str) {
            Some(e) if cmd != "scan_service_start" => Err(e.to_string()),
            _ => Ok(v),
        }
    }
}

#[cfg(target_os = "android")]
impl<R: Runtime> Native for AndroidNative<R> {
    fn call(&self, cmd: &str, args: Value) -> Result<Value, String> {
        match cmd {
            // Monitoring (scan result and WorkManager schedule), report signing and on-device OCR are JNI only:
            // there may be no Activity when a scheduled scan runs in the background.
            "scan_done_notify" | "monitor_schedule" | "report_sign" | "report_sig_verify"
            | "ocr_recognize" | "web_screenshot" => timed(cmd, "jni", || direct::call(cmd, &args)),
            // These work without an Activity (it may have been destroyed during a scan): direct JNI.
            "scan_service_update" | "scan_service_stop" | "toast" | "keystore_get" => {
                match timed(cmd, "jni", || direct::call(cmd, &args)) {
                    Ok(v) => Ok(v),
                    Err(_) => timed(cmd, "plugin", || self.plugin_call(cmd, args)),
                }
            }
            // Hidden search engine WebView: the script waits on the Android main thread, so it must be
            // JNI from a background thread; going through the plugin (which runs on the main thread)
            // would deadlock.
            "render_fetch" => {
                let t0 = std::time::Instant::now();
                let r = direct::call(cmd, &args);
                let ms = t0.elapsed().as_millis();
                match &r {
                    Ok(_) => alog!("native render_fetch (jni): {ms} мс"),
                    Err(e) => awarn!("native render_fetch (jni): ошибка за {ms} мс: {e}"),
                }
                r
            }
            // Start via the plugin (it asks the Activity for the notification permission), falling back
            // to JNI.
            "scan_service_start" => {
                match timed(cmd, "plugin", || self.plugin_call(cmd, args.clone())) {
                    Ok(v) => Ok(v),
                    Err(_) => timed(cmd, "jni", || direct::call(cmd, &args)),
                }
            }
            _ => timed(cmd, "plugin", || self.plugin_call(cmd, args)),
        }
    }
    fn real(&self) -> bool {
        true
    }
    fn watch(&self, on_event: Box<dyn Fn(Value) + Send + Sync>) -> Result<(), String> {
        use tauri::ipc::{Channel, InvokeResponseBody};
        let channel: Channel<Value> = Channel::new(move |body: InvokeResponseBody| {
            if let Ok(v) = body.deserialize::<Value>() {
                on_event(v);
            }
            Ok(())
        });
        timed("watch", "plugin", || {
            self.plugin_call("watch", json!({ "channel": channel }))
        })
        .map(|_| ())
    }
}

/// Built-in `foca-native` plugin: on Android it registers the Kotlin class and stores the
/// handle in `slot`.
pub fn plugin<R: Runtime>(slot: Arc<OnceLock<Arc<dyn Native>>>) -> TauriPlugin<R> {
    tauri::plugin::Builder::<R>::new("foca-native")
        .setup(move |_app, _api| {
            #[cfg(target_os = "android")]
            {
                match _api.register_android_plugin("app.sinon.focars.platform", "FocaPlugin") {
                    Ok(h) => {
                        alog!("foca-native: Kotlin-плагин FocaPlugin зарегистрирован");
                        let _ = slot.set(Arc::new(AndroidNative(h)));
                    }
                    // Without the plugin there is no foreground service, and a background scan will be killed
                    // by the system.
                    Err(e) => aerr!(
                        "foca-native: register_android_plugin: {e}, сервиса скана и ключей не будет"
                    ),
                }
            }
            #[cfg(not(target_os = "android"))]
            let _ = &slot;
            Ok(())
        })
        .build()
}
