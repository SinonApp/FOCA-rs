//! Monthly mobile data counter.
//!
//! Counts the response bytes of every request the core makes while the device is on a mobile or
//! metered network (the app tells the engine with [`crate::Engine::mobile_network`]). The counter is
//! kept per calendar month in device local time and persisted in `<data_dir>/mobile_usage.json`.
//! When it reaches `settings.power.mob_limit` (MB, with `power.lim_on`; 0 = no limit) the engine
//! emits one `mobile_cap` event; the app's pause policy turns it into a `mobile_cap` pause that
//! lifts on Wi-Fi or when the limit is raised.

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use foca_core::Clock;
use foca_net::{RequestRecord, RequestSink};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use time::OffsetDateTime;

use crate::EventSink;

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

pub(crate) const MB: u64 = 1024 * 1024;

/// Unsaved bytes after which the counter is written to disk.
const SAVE_EVERY: u64 = 64 * 1024;

/// File name of the persisted counter in the data directory.
pub(crate) const FILE: &str = "mobile_usage.json";

/// Bytes counted in one calendar month (`YYYY-MM`, device local time).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Usage {
    pub month: String,
    pub bytes: u64,
}

impl Usage {
    /// Returns the counter for `month`: the same one, or zero when the month changed.
    fn for_month(self, month: &str) -> Usage {
        if self.month == month {
            self
        } else {
            Usage {
                month: month.to_string(),
                bytes: 0,
            }
        }
    }
}

/// `YYYY-MM` of a local time.
pub(crate) fn month_key(t: OffsetDateTime) -> String {
    format!("{:04}-{:02}", t.year(), u8::from(t.month()))
}

/// The monthly limit in bytes from the settings object; 0 means no limit.
pub(crate) fn limit_bytes(s: &Value) -> u64 {
    if s["power"]["lim_on"].as_bool() != Some(true) {
        return 0;
    }
    s["power"]["mob_limit"]
        .as_u64()
        .unwrap_or(0)
        .saturating_mul(MB)
}

struct State {
    usage: Usage,
    saved: u64,
    /// The `mobile_cap` event was emitted for the current month and limit.
    fired: bool,
}

/// The process-wide counter, shared by every request sink of the engine.
pub(crate) struct MobileMeter {
    path: PathBuf,
    clock: Arc<dyn Clock>,
    events: Arc<Mutex<Arc<dyn EventSink>>>,
    metered: AtomicBool,
    limit: AtomicU64,
    st: Mutex<State>,
}

impl MobileMeter {
    /// Loads the counter from `path` (a missing or broken file starts from zero).
    pub fn open(
        path: PathBuf,
        clock: Arc<dyn Clock>,
        events: Arc<Mutex<Arc<dyn EventSink>>>,
    ) -> MobileMeter {
        let usage: Usage = std::fs::read(&path)
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default();
        let saved = usage.bytes;
        MobileMeter {
            path,
            clock,
            events,
            metered: AtomicBool::new(false),
            limit: AtomicU64::new(0),
            st: Mutex::new(State {
                usage,
                saved,
                fired: false,
            }),
        }
    }

    /// Records the network type; returns whether this month's limit is reached.
    pub fn network(&self, on_mobile: bool) -> bool {
        self.metered.store(on_mobile, Ordering::Relaxed);
        self.reached()
    }

    pub fn metered(&self) -> bool {
        self.metered.load(Ordering::Relaxed)
    }

    /// Sets the limit in bytes (0 = none). A raised limit re-arms the event.
    pub fn set_limit(&self, bytes: u64) {
        self.limit.store(bytes, Ordering::Relaxed);
        let mut st = self.current();
        if bytes == 0 || st.usage.bytes < bytes {
            st.fired = false;
        }
    }

    pub fn limit(&self) -> u64 {
        self.limit.load(Ordering::Relaxed)
    }

    /// Locks the state rolled over to the current month.
    fn current(&self) -> std::sync::MutexGuard<'_, State> {
        let month = month_key(self.clock.now());
        let mut st = lock(&self.st);
        if st.usage.month != month {
            st.usage = std::mem::take(&mut st.usage).for_month(&month);
            st.fired = false;
            self.save(&mut st);
        }
        st
    }

    fn save(&self, st: &mut State) {
        if let Ok(b) = serde_json::to_vec(&st.usage) {
            if std::fs::write(&self.path, b).is_ok() {
                st.saved = st.usage.bytes;
            }
        }
    }

    /// This month's counter.
    pub fn usage(&self) -> Usage {
        self.current().usage.clone()
    }

    /// The limit is set and this month's mobile traffic has reached it.
    pub fn reached(&self) -> bool {
        let limit = self.limit();
        limit > 0 && self.current().usage.bytes >= limit
    }

    /// Counts `n` bytes when the device is on a mobile network; emits `mobile_cap` once when the
    /// counter crosses the limit.
    pub fn add(&self, n: u64) {
        if n == 0 || !self.metered() {
            return;
        }
        let limit = self.limit();
        let ev = {
            let mut st = self.current();
            st.usage.bytes = st.usage.bytes.saturating_add(n);
            let hit = limit > 0 && st.usage.bytes >= limit && !st.fired;
            if hit {
                st.fired = true;
            }
            if hit || st.usage.bytes - st.saved.min(st.usage.bytes) >= SAVE_EVERY {
                self.save(&mut st);
            }
            hit.then(|| {
                json!({ "type": "mobile_cap", "month": st.usage.month,
                    "used_mb": mb(st.usage.bytes), "limit_mb": limit / MB })
            })
        };
        if let Some(ev) = ev {
            tracing::info!(target: "foca::engine", "лимит мобильного трафика достигнут: {ev}");
            let sink = lock(&self.events).clone();
            sink.emit(&ev);
        }
    }

    /// The `mobile_usage` command result.
    pub fn status(&self) -> Value {
        let limit = self.limit();
        let u = self.usage();
        json!({
            "month": u.month,
            "bytes": u.bytes,
            "used_mb": mb(u.bytes),
            "limit_mb": limit / MB,
            "reached": limit > 0 && u.bytes >= limit,
            "metered": self.metered(),
        })
    }
}

/// Megabytes rounded to one decimal.
fn mb(bytes: u64) -> f64 {
    (bytes as f64 / MB as f64 * 10.0).round() / 10.0
}

/// Request sink wrapper that feeds the response bytes to the counter.
pub(crate) struct MeterSink {
    pub meter: Arc<MobileMeter>,
    pub inner: Arc<dyn RequestSink>,
}

impl RequestSink for MeterSink {
    fn record(&self, rec: &RequestRecord) {
        self.inner.record(rec);
        if !rec.blocked {
            self.meter.add(rec.bytes);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MemoryEvents;
    use foca_core::ManualClock;
    use time::macros::datetime;

    fn meter(dir: &std::path::Path, clock: Arc<ManualClock>) -> (MobileMeter, Arc<MemoryEvents>) {
        let ev = Arc::new(MemoryEvents::new());
        let sink: Arc<dyn EventSink> = ev.clone();
        let m = MobileMeter::open(dir.join(FILE), clock, Arc::new(Mutex::new(sink)));
        (m, ev)
    }

    fn caps(ev: &MemoryEvents) -> Vec<Value> {
        ev.events()
            .into_iter()
            .filter(|e| e["type"] == "mobile_cap")
            .collect()
    }

    #[test]
    fn counts_only_on_mobile_and_persists() {
        let dir = tempfile::tempdir().unwrap();
        let clock = Arc::new(ManualClock::new(datetime!(2026-11-20 10:00 UTC)));
        let (m, _) = meter(dir.path(), clock.clone());
        m.add(5 * MB);
        assert_eq!(m.usage().bytes, 0, "Wi-Fi traffic is not counted");
        m.network(true);
        m.add(3 * MB);
        m.add(100);
        assert_eq!(
            m.usage(),
            Usage {
                month: "2026-11".into(),
                bytes: 3 * MB + 100
            }
        );
        // reopened from disk: the last saved value (saving happens every 64 KiB)
        let (m2, _) = meter(dir.path(), clock);
        assert_eq!(m2.usage().bytes, 3 * MB);
    }

    #[test]
    fn month_rollover_resets_counter() {
        let dir = tempfile::tempdir().unwrap();
        let clock = Arc::new(ManualClock::new(datetime!(2026-11-30 22:00 UTC)));
        let (m, _) = meter(dir.path(), clock.clone());
        m.network(true);
        m.add(2 * MB);
        assert_eq!(m.usage().month, "2026-11");
        clock.set(datetime!(2026-12-01 00:30 UTC));
        assert_eq!(
            m.usage(),
            Usage {
                month: "2026-12".into(),
                bytes: 0
            }
        );
        let saved: Usage =
            serde_json::from_slice(&std::fs::read(dir.path().join(FILE)).unwrap()).unwrap();
        assert_eq!(saved.month, "2026-12");
    }

    #[test]
    fn month_key_uses_local_time() {
        // 23:30 UTC on Nov 30 is already December at UTC+2.
        let t = datetime!(2026-11-30 23:30 UTC).to_offset(time::macros::offset!(+2));
        assert_eq!(month_key(t), "2026-12");
        assert_eq!(month_key(datetime!(2026-01-05 00:00 UTC)), "2026-01");
    }

    #[test]
    fn cap_event_fires_once_and_rearms() {
        let dir = tempfile::tempdir().unwrap();
        let clock = Arc::new(ManualClock::new(datetime!(2026-11-20 10:00 UTC)));
        let (m, ev) = meter(dir.path(), clock.clone());
        m.network(true);
        m.set_limit(2 * MB);
        m.add(MB);
        assert!(!m.reached());
        m.add(MB);
        assert!(m.reached());
        m.add(MB);
        let c = caps(&ev);
        assert_eq!(c.len(), 1, "{c:?}");
        assert_eq!(c[0]["limit_mb"], 2);
        assert_eq!(c[0]["used_mb"], 2.0);
        // a raised limit lifts the cap and re-arms the event
        m.set_limit(4 * MB);
        assert!(!m.reached());
        m.add(MB);
        assert_eq!(caps(&ev).len(), 2);
        // no limit: never reached
        m.set_limit(0);
        assert!(!m.reached());
        // a new month starts below the cap
        m.set_limit(MB);
        assert!(m.reached());
        clock.set(datetime!(2026-12-02 10:00 UTC));
        assert!(!m.reached());
    }

    #[test]
    fn limit_from_settings() {
        assert_eq!(
            limit_bytes(&json!({ "power": { "lim_on": true, "mob_limit": 500 } })),
            500 * MB
        );
        assert_eq!(
            limit_bytes(&json!({ "power": { "lim_on": false, "mob_limit": 500 } })),
            0
        );
        assert_eq!(
            limit_bytes(&json!({ "power": { "lim_on": true, "mob_limit": 0 } })),
            0
        );
    }

    #[test]
    fn sink_skips_blocked_requests() {
        let dir = tempfile::tempdir().unwrap();
        let clock = Arc::new(ManualClock::new(datetime!(2026-11-20 10:00 UTC)));
        let (m, _) = meter(dir.path(), clock.clone());
        let m = Arc::new(m);
        m.network(true);
        let mem = Arc::new(foca_net::MemorySink::new());
        let s = MeterSink {
            meter: m.clone(),
            inner: mem.clone(),
        };
        let mut rec = RequestRecord {
            time: clock.now(),
            module: "crawler".into(),
            method: "GET".into(),
            url: "https://example.test/".into(),
            host: "example.test".into(),
            status: Some(200),
            bytes: 1000,
            active: true,
            access: "target".into(),
            blocked: false,
            error: None,
        };
        s.record(&rec);
        rec.blocked = true;
        s.record(&rec);
        assert_eq!(mem.len(), 2);
        assert_eq!(m.usage().bytes, 1000);
    }
}
