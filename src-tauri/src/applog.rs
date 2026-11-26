//! Application log: logcat (tag `FOCA`) plus `tracing` with the `foca::app` target. The
//! foca-engine subscriber writes it to `<data>/logs/foca.log` (rotated) and to the ring buffer
//! behind the `logs_get` command (Debug tab). On Android `eprintln!` reaches logcat only under
//! the `RustStdoutStderr` tag (through tao's pipe) and never reaches the file, so the bridge
//! uses only the `alog!`/`awarn!`/`aerr!` macros.
//!
//! Rust panics: the hook writes the message and backtrace to logcat, to
//! `<data>/logs/crash-<time>.txt` and to `<files>/rust_panic.txt`, which the `LauncherActivity`
//! crash screen shows on the next launch.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Lv {
    Debug,
    Info,
    Warn,
    Error,
}

static LOG_DIR: OnceLock<PathBuf> = OnceLock::new();

/// Sets the log directory `<data>/logs` (known once `app_data_dir` is available).
pub fn set_dir(dir: &Path) {
    let _ = std::fs::create_dir_all(dir);
    let _ = LOG_DIR.set(dir.to_path_buf());
}

fn log_dir() -> Option<PathBuf> {
    LOG_DIR
        .get()
        .cloned()
        .or_else(|| std::env::var_os("FOCA_LOG_DIR").map(PathBuf::from))
}

pub fn log(lv: Lv, msg: &str) {
    logcat(lv, msg);
    match lv {
        Lv::Debug => tracing::debug!(target: "foca::app", "{msg}"),
        Lv::Info => tracing::info!(target: "foca::app", "{msg}"),
        Lv::Warn => tracing::warn!(target: "foca::app", "{msg}"),
        Lv::Error => tracing::error!(target: "foca::app", "{msg}"),
    }
}

#[macro_export]
macro_rules! adbg { ($($t:tt)*) => { $crate::applog::log($crate::applog::Lv::Debug, &format!($($t)*)) } }
#[macro_export]
macro_rules! alog { ($($t:tt)*) => { $crate::applog::log($crate::applog::Lv::Info, &format!($($t)*)) } }
#[macro_export]
macro_rules! awarn { ($($t:tt)*) => { $crate::applog::log($crate::applog::Lv::Warn, &format!($($t)*)) } }
#[macro_export]
macro_rules! aerr { ($($t:tt)*) => { $crate::applog::log($crate::applog::Lv::Error, &format!($($t)*)) } }

#[cfg(target_os = "android")]
fn logcat(lv: Lv, msg: &str) {
    use std::ffi::CString;
    use std::os::raw::{c_char, c_int};
    #[link(name = "log")]
    extern "C" {
        fn __android_log_write(prio: c_int, tag: *const c_char, text: *const c_char) -> c_int;
    }
    let prio = match lv {
        Lv::Debug => 3,
        Lv::Info => 4,
        Lv::Warn => 5,
        Lv::Error => 6,
    };
    // logcat truncates entries at ~4 KB, so long messages (backtraces) are sent in line chunks.
    let mut chunk = String::new();
    let flush = |s: &str| {
        if let Ok(t) = CString::new(s.replace('\0', " ")) {
            // SAFETY: both strings are valid C strings for the duration of the call.
            unsafe {
                __android_log_write(prio, c"FOCA".as_ptr(), t.as_ptr());
            }
        }
    };
    for line in msg.lines() {
        if chunk.len() + line.len() > 3000 && !chunk.is_empty() {
            flush(&chunk);
            chunk.clear();
        }
        if !chunk.is_empty() {
            chunk.push('\n');
        }
        chunk.push_str(line);
    }
    if !chunk.is_empty() || msg.is_empty() {
        flush(&chunk);
    }
}

#[cfg(not(target_os = "android"))]
fn logcat(lv: Lv, msg: &str) {
    if lv != Lv::Debug {
        eprintln!("[FOCA {lv:?}] {msg}");
    }
}

/// Number of `crash-*.txt` files to keep.
const CRASH_KEEP: usize = 5;

fn write_crash_file(text: &str) {
    let Some(dir) = log_dir() else { return };
    let _ = std::fs::create_dir_all(&dir);
    let now = time::OffsetDateTime::now_utc();
    let name = format!(
        "crash-{:04}{:02}{:02}-{:02}{:02}{:02}-{:03}.txt",
        now.year(),
        u8::from(now.month()),
        now.day(),
        now.hour(),
        now.minute(),
        now.second(),
        now.millisecond()
    );
    let _ = std::fs::write(dir.join(name), text);
    if let Ok(rd) = std::fs::read_dir(&dir) {
        let names = rd
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        for n in crate::recovery::crash_files_to_prune(names, CRASH_KEEP) {
            let _ = std::fs::remove_file(dir.join(n));
        }
    }
}

/// Installs the panic hook: logcat, the log file and `rust_panic.txt` for the crash screen. A
/// panic in a tokio task or a bridge worker does not bring the process down
/// (`panic = "unwind"`, ADR-0005), but it leaves a trace.
pub fn install_panic_hook() {
    static INSTALLED: OnceLock<()> = OnceLock::new();
    if INSTALLED.set(()).is_err() {
        return;
    }
    let prev = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let bt = std::backtrace::Backtrace::force_capture();
        let thread = std::thread::current()
            .name()
            .unwrap_or("безымянный")
            .to_string();
        let text = format!(
            "FOCA-rs {} · Rust panic в потоке «{thread}»\n{info}\n\n{bt}",
            env!("CARGO_PKG_VERSION")
        );
        logcat(Lv::Error, &text);
        tracing::error!(target: "foca::app", "panic в потоке «{thread}»: {info}");
        write_crash_file(&text);
        if let Ok(dir) = std::env::var("FOCA_CRASH_DIR") {
            let _ = std::fs::write(Path::new(&dir).join("rust_panic.txt"), &text);
        }
        prev(info);
    }));
}
