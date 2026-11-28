//! Schedule of the automatic signature database check.
//!
//! The UI asks for an automatic check at app start and when the app comes back to the
//! foreground (`signatures_update { auto: true }`); this module decides whether one is due.
//! Settings live in `settings.signatures`: `auto` (`off`, `daily` or `weekly`, default `daily`)
//! and `wifi_only` (default `true`). The schedule state is `<data>/signatures/auto.json`: the
//! last attempt and, after a failure or a rate limit, the earliest retry.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::Value;

const DAY: i64 = 24 * 60 * 60;
/// Retry after a failed check (network error, bad answer), unless the interval is shorter.
pub const FAIL_RETRY_SECS: i64 = 3 * 60 * 60;
/// Wait after the download host limited requests (HTTP 429/403), unless it named a longer wait.
pub const RATE_LIMIT_SECS: i64 = 12 * 60 * 60;

/// How often the database is checked automatically.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Off,
    Daily,
    Weekly,
}

impl Mode {
    fn parse(s: Option<&str>) -> Mode {
        match s {
            Some("off") => Mode::Off,
            Some("weekly") => Mode::Weekly,
            _ => Mode::Daily,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Mode::Off => "off",
            Mode::Daily => "daily",
            Mode::Weekly => "weekly",
        }
    }

    fn interval(self) -> Option<i64> {
        match self {
            Mode::Off => None,
            Mode::Daily => Some(DAY),
            Mode::Weekly => Some(7 * DAY),
        }
    }
}

/// `settings.signatures` as the scheduler reads it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AutoSettings {
    pub mode: Mode,
    pub wifi_only: bool,
}

impl AutoSettings {
    /// Reads `settings.signatures`; missing keys take the defaults (daily, Wi-Fi only).
    pub fn from_settings(s: &Value) -> AutoSettings {
        let sec = &s["signatures"];
        AutoSettings {
            mode: Mode::parse(sec["auto"].as_str()),
            wifi_only: sec["wifi_only"].as_bool().unwrap_or(true),
        }
    }
}

/// Persistent schedule state.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AutoState {
    /// Epoch seconds of the last check (manual or automatic, any outcome).
    #[serde(default)]
    pub checked_epoch: i64,
    /// Earliest next attempt after a failure or a rate limit; 0 after a successful check.
    #[serde(default)]
    pub retry_at: i64,
}

/// What the device and the engine look like at the moment of an automatic check.
#[derive(Debug, Clone, Copy, Default)]
pub struct Conditions {
    /// The current network is metered (mobile data).
    pub metered: bool,
    /// A scan is running: the check waits so it never competes with the heavy stages.
    pub scanning: bool,
}

fn path(data_dir: &Path) -> PathBuf {
    data_dir.join("signatures").join("auto.json")
}

pub fn read(data_dir: &Path) -> AutoState {
    std::fs::read(path(data_dir))
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default()
}

pub fn write(data_dir: &Path, st: &AutoState) {
    let p = path(data_dir);
    if let Some(dir) = p.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    if let Ok(raw) = serde_json::to_vec_pretty(st) {
        let _ = std::fs::write(p, raw);
    }
}

/// Epoch second of the next automatic check, `None` when automatic checks are off.
pub fn next_check(set: &AutoSettings, st: &AutoState) -> Option<i64> {
    let every = set.mode.interval()?;
    if st.retry_at > 0 {
        return Some(st.retry_at);
    }
    Some(if st.checked_epoch > 0 {
        st.checked_epoch + every
    } else {
        0
    })
}

/// Why an automatic check must not run now, `None` when it is due.
pub fn skip_reason(
    set: &AutoSettings,
    st: &AutoState,
    now: i64,
    cond: Conditions,
) -> Option<&'static str> {
    let Some(next) = next_check(set, st) else {
        return Some("disabled");
    };
    if now < next {
        return Some(if st.retry_at > 0 {
            "backoff"
        } else {
            "not_due"
        });
    }
    if set.wifi_only && cond.metered {
        return Some("metered");
    }
    if cond.scanning {
        return Some("scan");
    }
    None
}

/// Result class of one check, for the schedule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// Installed, up to date or nothing published (HTTP 404): the next check after the interval.
    Done,
    /// Network error, bad answer or bad signature: retry sooner.
    Failed,
    /// The host limited requests; `Some(secs)` when it said how long to wait.
    RateLimited(Option<i64>),
}

/// Records a finished check in the schedule state.
pub fn record(st: &mut AutoState, set: &AutoSettings, now: i64, outcome: Outcome) {
    st.checked_epoch = now;
    let every = set.mode.interval().unwrap_or(DAY);
    st.retry_at = match outcome {
        Outcome::Done => 0,
        Outcome::Failed => now + FAIL_RETRY_SECS.min(every),
        Outcome::RateLimited(wait) => now + wait.unwrap_or(0).max(RATE_LIMIT_SECS),
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const NOW: i64 = 1_800_000_000;

    fn daily() -> AutoSettings {
        AutoSettings::from_settings(&json!({}))
    }

    #[test]
    fn defaults_are_daily_on_wifi_only() {
        let s = daily();
        assert_eq!(s.mode, Mode::Daily);
        assert!(s.wifi_only);
        let s = AutoSettings::from_settings(
            &json!({ "signatures": { "auto": "weekly", "wifi_only": false } }),
        );
        assert_eq!((s.mode, s.wifi_only), (Mode::Weekly, false));
        let off = AutoSettings::from_settings(&json!({ "signatures": { "auto": "off" } }));
        assert_eq!(off.mode.as_str(), "off");
        // Unknown values fall back to the default instead of turning the checks off.
        let odd = AutoSettings::from_settings(&json!({ "signatures": { "auto": "hourly" } }));
        assert_eq!(odd.mode, Mode::Daily);
    }

    #[test]
    fn first_check_is_due_then_waits_for_the_interval() {
        let set = daily();
        let mut st = AutoState::default();
        let ok = Conditions::default();
        assert_eq!(skip_reason(&set, &st, NOW, ok), None, "never checked: due");
        record(&mut st, &set, NOW, Outcome::Done);
        assert_eq!(skip_reason(&set, &st, NOW + 60, ok), Some("not_due"));
        assert_eq!(skip_reason(&set, &st, NOW + DAY - 1, ok), Some("not_due"));
        assert_eq!(skip_reason(&set, &st, NOW + DAY, ok), None);
        assert_eq!(next_check(&set, &st), Some(NOW + DAY));
        let weekly = AutoSettings {
            mode: Mode::Weekly,
            wifi_only: true,
        };
        assert_eq!(skip_reason(&weekly, &st, NOW + DAY, ok), Some("not_due"));
        assert_eq!(skip_reason(&weekly, &st, NOW + 7 * DAY, ok), None);
    }

    #[test]
    fn off_metered_and_scanning_skip() {
        let st = AutoState::default();
        let off = AutoSettings {
            mode: Mode::Off,
            wifi_only: true,
        };
        assert_eq!(
            skip_reason(&off, &st, NOW, Conditions::default()),
            Some("disabled")
        );
        assert_eq!(next_check(&off, &st), None);
        let mobile = Conditions {
            metered: true,
            scanning: false,
        };
        assert_eq!(skip_reason(&daily(), &st, NOW, mobile), Some("metered"));
        let any_net = AutoSettings {
            mode: Mode::Daily,
            wifi_only: false,
        };
        assert_eq!(skip_reason(&any_net, &st, NOW, mobile), None);
        let scan = Conditions {
            metered: false,
            scanning: true,
        };
        assert_eq!(skip_reason(&daily(), &st, NOW, scan), Some("scan"));
    }

    #[test]
    fn failures_retry_sooner_and_rate_limits_back_off() {
        let set = daily();
        let ok = Conditions::default();
        let mut st = AutoState::default();
        record(&mut st, &set, NOW, Outcome::Failed);
        assert_eq!(st.retry_at, NOW + FAIL_RETRY_SECS);
        assert_eq!(skip_reason(&set, &st, NOW + 60, ok), Some("backoff"));
        assert_eq!(skip_reason(&set, &st, NOW + FAIL_RETRY_SECS, ok), None);

        record(&mut st, &set, NOW, Outcome::RateLimited(None));
        assert_eq!(st.retry_at, NOW + RATE_LIMIT_SECS);
        assert_eq!(skip_reason(&set, &st, NOW + 3600, ok), Some("backoff"));
        // A longer wait named by the server wins.
        record(&mut st, &set, NOW, Outcome::RateLimited(Some(2 * DAY)));
        assert_eq!(next_check(&set, &st), Some(NOW + 2 * DAY));
        // Success clears the backoff.
        record(&mut st, &set, NOW + 2 * DAY, Outcome::Done);
        assert_eq!(st.retry_at, 0);
        assert_eq!(next_check(&set, &st), Some(NOW + 3 * DAY));
    }

    #[test]
    fn state_roundtrips_on_disk() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(read(dir.path()), AutoState::default());
        let st = AutoState {
            checked_epoch: NOW,
            retry_at: NOW + 10,
        };
        write(dir.path(), &st);
        assert_eq!(read(dir.path()), st);
    }
}
