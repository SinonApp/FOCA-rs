//! Auto-resume of a scan interrupted by a process unload (Android killed the app in the background).
//!
//! Sequence in the application:
//! 1. [`interrupted_scan`], called before [`crate::Engine::open`], reads the previous process's
//!    `engine_run.json` and returns the `scan_start { resume_from, ... }` arguments.
//! 2. `Engine::open` turns that file into a `stopped` / `reason: "restart"` history record.
//! 3. If [`enabled`] (setting `power.auto_resume`, on by default) and [`next_attempt`] has not
//!    exceeded [`MAX_ATTEMPTS`], the app calls `scan_start` with those arguments.
//!
//! The attempt counter ([`note_attempt`], file `auto_resume.json`) prevents a crash loop where the
//! scan kills the process, auto-resumes and crashes again: at most three in a row per scan within 10 minutes.

use std::path::Path;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

/// State of the running scan (what survives a process restart in `engine_run.json`).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub(crate) struct RunState {
    pub scan_id: String,
    pub project: String,
    pub profile_id: String,
    pub active: bool,
    pub level: String,
    pub stage: usize,
    pub progress: u8,
    pub started_at: String,
    pub targets: Vec<String>,
    pub modules: Vec<String>,
    pub sources: Vec<foca_core::api::ScanSource>,
    pub source_ids: Vec<String>,
    pub egress: String,
    pub resumed: bool,
    /// The resume was started by the app itself (auto-resume after the process was unloaded).
    pub auto: bool,
    pub limit: usize,
    pub pause_reason: Option<String>,
    /// `manual` | `schedule` (a scheduled monitoring rescan: passive or standard profile only).
    pub trigger: String,
    /// Wizard parameters of this run: document types (empty means all defaults), crawl depth,
    /// file size limit (MB) and UA profile (on top of `settings.net.ua`).
    pub exts: Vec<String>,
    pub crawl_depth: Option<usize>,
    /// Common Crawl depth of this run (`latest` | `years` | `all`, over `settings.search`).
    pub cc_depth: Option<String>,
    pub cc_years: Option<u64>,
    pub max_size_mb: Option<u64>,
    pub ua: Option<String>,
    pub canary: Option<foca_net::canary::CanaryReport>,
    pub headless: bool,
    /// Running sub-step of the current stage (`id`, `state`, `done`, `total`, ...), if any.
    pub substep: Option<serde_json::Value>,
    /// Restarts queued for a follow-up run (`kind:id`, see `scan_control`).
    pub followup: Vec<String>,
    /// Chosen items of a narrowed run (`scan_start { only }`); empty for a normal scan.
    pub only: Vec<String>,
    /// Dork groups postponed after captchas everywhere (project total after the search stage).
    pub dorks_pending: usize,
}

/// File name of the running scan state (`Engine::run_file`).
pub(crate) const RUN_FILE: &str = "engine_run.json";
const ATTEMPTS_FILE: &str = "auto_resume.json";
/// Consecutive auto-resumes of one scan after which the user decides.
pub const MAX_ATTEMPTS: u32 = 3;
/// Attempts further apart than this window (ms) reset the count.
pub const ATTEMPT_WINDOW_MS: i64 = 10 * 60 * 1000;

/// Returns the `scan_start` arguments to resume the scan that was running when the previous
/// process was unloaded, or `None` if none was running (or the file is corrupt). Call before `Engine::open`.
pub fn interrupted_scan(data_dir: &Path) -> Option<Value> {
    let b = std::fs::read(data_dir.join(RUN_FILE)).ok()?;
    let st: RunState = serde_json::from_slice(&b).ok()?;
    if st.scan_id.is_empty() || st.project.is_empty() {
        return None;
    }
    let mut a = json!({
        "project": st.project,
        "resume_from": st.scan_id,
        "profile": st.profile_id,
        "active": st.active,
        "targets": st.targets,
        "modules": st.modules,
        "limit": st.limit,
    });
    if !st.source_ids.is_empty() {
        a["sources"] = json!(st.source_ids);
    }
    Some(a)
}

/// Reads the "resume interrupted scans automatically" setting (`power.auto_resume`, on by default).
pub fn enabled(settings: &Value) -> bool {
    settings
        .get("power")
        .and_then(|p| p.get("auto_resume"))
        .and_then(Value::as_bool)
        .unwrap_or(true)
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Attempt {
    pub scan_id: String,
    pub n: u32,
    /// Unix time of the last attempt, ms.
    pub at_ms: i64,
}

/// Returns the number of this auto-resume attempt for `scan_id` (pure logic, see [`note_attempt`]).
pub fn next_attempt(prev: Option<&Attempt>, scan_id: &str, now_ms: i64) -> Attempt {
    let n = match prev {
        Some(p) if p.scan_id == scan_id && (now_ms - p.at_ms).abs() <= ATTEMPT_WINDOW_MS => p.n + 1,
        _ => 1,
    };
    Attempt {
        scan_id: scan_id.to_string(),
        n,
        at_ms: now_ms,
    }
}

/// Records an attempt and returns its number (1, 2, ...); resume only if `n <= MAX_ATTEMPTS`.
pub fn note_attempt(data_dir: &Path, scan_id: &str, now_ms: i64) -> u32 {
    let f = data_dir.join(ATTEMPTS_FILE);
    let prev: Option<Attempt> = std::fs::read(&f)
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok());
    let a = next_attempt(prev.as_ref(), scan_id, now_ms);
    if let Ok(j) = serde_json::to_vec(&a) {
        let _ = std::fs::write(&f, j);
    }
    a.n
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attempts_count_per_scan_within_window() {
        let a1 = next_attempt(None, "s1", 1_000);
        assert_eq!(a1.n, 1);
        let a2 = next_attempt(Some(&a1), "s1", 2_000);
        assert_eq!(a2.n, 2);
        // a different scan starts over
        assert_eq!(next_attempt(Some(&a2), "s2", 3_000).n, 1);
        // after more than 10 minutes the count starts over
        assert_eq!(
            next_attempt(Some(&a2), "s1", 2_000 + ATTEMPT_WINDOW_MS + 1).n,
            1
        );
    }

    #[test]
    fn setting_defaults_to_on() {
        assert!(enabled(&json!({})));
        assert!(enabled(&json!({ "power": { "batt": 15 } })));
        assert!(!enabled(&json!({ "power": { "auto_resume": false } })));
    }

    #[test]
    fn note_attempt_persists() {
        let d = tempfile::tempdir().unwrap();
        assert_eq!(note_attempt(d.path(), "x", 10), 1);
        assert_eq!(note_attempt(d.path(), "x", 20), 2);
        assert_eq!(note_attempt(d.path(), "x", 30), 3);
        assert_eq!(note_attempt(d.path(), "y", 40), 1);
    }

    #[test]
    fn no_run_file_no_resume() {
        let d = tempfile::tempdir().unwrap();
        assert!(interrupted_scan(d.path()).is_none());
        std::fs::write(d.path().join(RUN_FILE), b"{oops").unwrap();
        assert!(interrupted_scan(d.path()).is_none());
    }
}
