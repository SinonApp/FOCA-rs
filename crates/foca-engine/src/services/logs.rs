//! Engine log: a `tracing` subscriber writing to an in-memory ring buffer and to
//! `<data>/logs/foca.log` with rotation (`foca.log.1`, `.2`). The command
//! `logs_get { level?, since?, limit? }` returns `[{ id, t, level, target, msg }]` (Debug tab).
//!
//! The subscriber is global (one per process): [`install`] sets it unless the app installed its
//! own, and [`set_file`] is called from `Engine::open` with the data directory. Our own targets
//! (`foca*`) log at DEBUG, third-party crates (reqwest, hickory, rustls) at WARN.

use std::collections::VecDeque;
use std::fmt::Write as _;
use std::io::Write as _;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};

use serde::Serialize;
use tracing_core::field::{Field, Visit};
use tracing_core::span::{Attributes, Id, Record};
use tracing_core::{Event, Level, Metadata, Subscriber};

const RING: usize = 4000;

/// Debug level for our own targets (`settings.debug.level`); when off, INFO is used.
static DEBUG: AtomicBool = AtomicBool::new(false);

/// Changes the log level at runtime: `"debug"` is verbose, anything else means INFO.
pub fn set_level(level: &str) {
    DEBUG.store(level == "debug", Ordering::Relaxed);
}

/// Clears the ring buffer ("Clear logs").
pub fn clear() {
    logger()
        .ring
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .clear();
}
const FILE_MAX: u64 = 1024 * 1024;
const FILES_KEEP: usize = 2;

#[derive(Debug, Clone, Serialize)]
pub struct LogEntry {
    pub id: u64,
    /// Local device time, ISO without an offset, with milliseconds.
    pub t: String,
    pub level: &'static str,
    pub target: String,
    pub msg: String,
}

struct FileSink {
    path: PathBuf,
    file: Option<std::fs::File>,
    size: u64,
}

impl FileSink {
    fn write(&mut self, line: &str) {
        if self.file.is_none() {
            if let Some(d) = self.path.parent() {
                let _ = std::fs::create_dir_all(d);
            }
            self.file = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&self.path)
                .ok();
            self.size = std::fs::metadata(&self.path).map(|m| m.len()).unwrap_or(0);
        }
        if self.size + line.len() as u64 > FILE_MAX {
            self.file = None;
            for i in (1..FILES_KEEP).rev() {
                let _ = std::fs::rename(self.rot(i), self.rot(i + 1));
            }
            let _ = std::fs::rename(&self.path, self.rot(1));
            self.size = 0;
            self.file = std::fs::File::create(&self.path).ok();
        }
        if let Some(f) = self.file.as_mut() {
            if f.write_all(line.as_bytes()).is_ok() {
                self.size += line.len() as u64;
            }
        }
    }
    fn rot(&self, i: usize) -> PathBuf {
        let mut s = self.path.clone().into_os_string();
        s.push(format!(".{i}"));
        s.into()
    }
}

struct Logger {
    ring: Mutex<VecDeque<LogEntry>>,
    file: Mutex<Option<FileSink>>,
    seq: AtomicU64,
    /// Local time offset in seconds.
    off: Mutex<i32>,
}

fn logger() -> &'static Logger {
    static L: OnceLock<Logger> = OnceLock::new();
    L.get_or_init(|| Logger {
        ring: Mutex::new(VecDeque::with_capacity(RING)),
        file: Mutex::new(None),
        seq: AtomicU64::new(0),
        off: Mutex::new(0),
    })
}

fn level_str(l: &Level) -> &'static str {
    match *l {
        Level::ERROR => "error",
        Level::WARN => "warn",
        Level::INFO => "info",
        Level::DEBUG => "debug",
        Level::TRACE => "trace",
    }
}

fn level_rank(s: &str) -> u8 {
    match s {
        "error" => 4,
        "warn" => 3,
        "info" => 2,
        "debug" => 1,
        _ => 0,
    }
}

/// Writes a log line (used by the subscriber and directly).
pub fn push(level: &'static str, target: &str, msg: String) {
    let lg = logger();
    let off = *lg.off.lock().unwrap_or_else(|p| p.into_inner());
    let now = time::OffsetDateTime::now_utc()
        .to_offset(time::UtcOffset::from_whole_seconds(off).unwrap_or(time::UtcOffset::UTC));
    let t = format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}",
        now.year(),
        u8::from(now.month()),
        now.day(),
        now.hour(),
        now.minute(),
        now.second(),
        now.millisecond()
    );
    let id = lg.seq.fetch_add(1, Ordering::Relaxed) + 1;
    let e = LogEntry {
        id,
        t,
        level,
        target: target.to_string(),
        msg,
    };
    if let Ok(mut f) = lg.file.lock() {
        if let Some(f) = f.as_mut() {
            f.write(&format!("{} {:5} {} {}\n", e.t, e.level, e.target, e.msg));
        }
    }
    let mut r = lg.ring.lock().unwrap_or_else(|p| p.into_inner());
    if r.len() >= RING {
        r.pop_front();
    }
    r.push_back(e);
}

/// Sets the log file (`<data>/logs/foca.log`) and the local time offset.
pub fn set_file(data_dir: &std::path::Path, utc_offset: time::UtcOffset) {
    let lg = logger();
    *lg.off.lock().unwrap_or_else(|p| p.into_inner()) = utc_offset.whole_seconds();
    *lg.file.lock().unwrap_or_else(|p| p.into_inner()) = Some(FileSink {
        path: data_dir.join("logs").join("foca.log"),
        file: None,
        size: 0,
    });
}

/// Returns log entries: `level` is the minimum level, `since` the id of the last entry already
/// received, `limit` the number of most recent entries to return (500 by default).
pub fn get(level: Option<&str>, since: Option<u64>, limit: Option<usize>) -> Vec<LogEntry> {
    let min = level.map(level_rank).unwrap_or(0);
    let r = logger().ring.lock().unwrap_or_else(|p| p.into_inner());
    let v: Vec<LogEntry> = r
        .iter()
        .filter(|e| level_rank(e.level) >= min && since.is_none_or(|s| e.id > s))
        .cloned()
        .collect();
    let n = limit.unwrap_or(500).max(1);
    v[v.len().saturating_sub(n)..].to_vec()
}

struct MsgVisitor(String, String);

impl Visit for MsgVisitor {
    fn record_debug(&mut self, f: &Field, v: &dyn std::fmt::Debug) {
        if f.name() == "message" {
            let _ = write!(self.0, "{v:?}");
        } else {
            let _ = write!(self.1, " {}={v:?}", f.name());
        }
    }
    fn record_str(&mut self, f: &Field, v: &str) {
        if f.name() == "message" {
            self.0.push_str(v);
        } else {
            let _ = write!(self.1, " {}={v}", f.name());
        }
    }
}

/// A tracing subscriber without spans (events only).
pub struct RingSubscriber;

impl Subscriber for RingSubscriber {
    fn enabled(&self, m: &Metadata<'_>) -> bool {
        let own = m.target().starts_with("foca");
        if own {
            *m.level()
                <= if DEBUG.load(Ordering::Relaxed) {
                    Level::DEBUG
                } else {
                    Level::INFO
                }
        } else {
            *m.level() <= Level::WARN
        }
    }
    // the level of our own targets changes at runtime (settings.debug.level), so the decision is not cached
    fn register_callsite(
        &self,
        m: &'static Metadata<'static>,
    ) -> tracing_core::subscriber::Interest {
        if m.target().starts_with("foca") {
            tracing_core::subscriber::Interest::sometimes()
        } else if self.enabled(m) {
            tracing_core::subscriber::Interest::always()
        } else {
            tracing_core::subscriber::Interest::never()
        }
    }
    fn new_span(&self, _: &Attributes<'_>) -> Id {
        Id::from_u64(1)
    }
    fn record(&self, _: &Id, _: &Record<'_>) {}
    fn record_follows_from(&self, _: &Id, _: &Id) {}
    fn event(&self, e: &Event<'_>) {
        let mut v = MsgVisitor(String::new(), String::new());
        e.record(&mut v);
        let m = e.metadata();
        push(level_str(m.level()), m.target(), v.0 + &v.1);
    }
    fn enter(&self, _: &Id) {}
    fn exit(&self, _: &Id) {}
}

/// Installs the global subscriber unless the app already installed one. Repeated calls are no-ops.
pub fn install() {
    static ONCE: OnceLock<()> = OnceLock::new();
    ONCE.get_or_init(|| {
        let _ = tracing::subscriber::set_global_default(RingSubscriber);
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ring_file_rotation_and_filters() {
        let d = tempfile::tempdir().unwrap();
        install();
        set_file(d.path(), time::UtcOffset::UTC);
        set_level("debug");
        let before = get(None, None, Some(1)).last().map(|e| e.id).unwrap_or(0);
        tracing::info!(target: "foca::test", n = 3, "привет");
        tracing::debug!(target: "foca::test", "отладка");
        tracing::info!(target: "hyper::x", "чужое info не пишется");
        let got = get(None, Some(before), None);
        assert!(
            got.iter()
                .any(|e| e.msg == "привет n=3" && e.level == "info"),
            "{got:?}"
        );
        assert!(got.iter().any(|e| e.level == "debug"));
        assert!(!got.iter().any(|e| e.target.starts_with("hyper")));
        assert!(get(Some("info"), Some(before), None)
            .iter()
            .all(|e| e.level != "debug"));
        // switch to INFO at runtime: debug entries are no longer written
        set_level("info");
        let mid = get(None, None, Some(1)).last().map(|e| e.id).unwrap_or(0);
        tracing::debug!(target: "foca::test", "не должно попасть");
        assert!(get(None, Some(mid), None)
            .iter()
            .all(|e| e.level != "debug"));
        set_level("debug");
        let big = "x".repeat(4096);
        for _ in 0..300 {
            push("info", "foca::test", big.clone());
        }
        let log = d.path().join("logs");
        assert!(log.join("foca.log").is_file() && log.join("foca.log.1").is_file());
        assert!(std::fs::metadata(log.join("foca.log")).unwrap().len() <= FILE_MAX);
        assert_eq!(get(None, None, Some(5)).len(), 5);
    }
}
