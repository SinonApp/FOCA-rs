#[macro_use]
mod applog;
mod bridge;
mod devstate;
mod headless;
mod monitor;
mod native;
mod policy;
mod recovery;
mod scan_note;

use std::sync::{Arc, OnceLock};

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    applog::install_panic_hook();
    alog!(
        "FOCA-rs {}: старт Rust (поток {:?})",
        env!("CARGO_PKG_VERSION"),
        std::thread::current().name()
    );
    let native_slot: Arc<OnceLock<Arc<dyn native::Native>>> = Arc::new(OnceLock::new());
    let slot = native_slot.clone();
    let app = tauri::Builder::default()
        .plugin(native::plugin(native_slot))
        .invoke_handler(tauri::generate_handler![bridge::foca])
        .setup(move |app| {
            bridge::init(app.handle().clone(), slot.clone());
            Ok(())
        })
        .build(tauri::generate_context!())
        .unwrap_or_else(|e| {
            aerr!("сборка приложения Tauri: {e}");
            panic!("error while building FOCA-rs: {e}")
        });
    // Lifecycle: keep Tauri from ending the process when the Activity is destroyed during a scan
    // (see recovery.rs) and log window events.
    app.run(bridge::on_run_event);
}
