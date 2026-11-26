//! Pure logic for background operation and recovery after the process is killed (no
//! dependencies; tests run on desktop:
//! `rustc --edition 2021 --test src-tauri/src/recovery.rs -o /tmp/recovery && /tmp/recovery`).
//!
//! Why this is needed on Android: Tauri is bound to a single Activity. When the Activity is
//! destroyed for a reason other than a configuration change (system Back on the root screen,
//! swiping it from Recents, the system reclaiming memory), tao sends `Destroyed`, the window is
//! removed, and with no windows left Tauri ends the process (`ExitRequested` →
//! `process::exit`), taking the engine and the running scan with it. This is a normal exit,
//! not a crash, so no crash screen appears.

/// Returns `true` if Tauri must not end the process: an implicit exit (code `None`, the last
/// window closed) while a scan is running or the foreground service is held. An explicit exit
/// (code set) is left alone.
pub fn keep_process_alive(code: Option<i32>, scanning: bool, service_running: bool) -> bool {
    code.is_none() && (scanning || service_running)
}

/// Returns `true` if the Tauri window must be recreated for a new Activity: the process
/// survived the destruction of the previous Activity (the exit was cancelled) and no windows
/// are open.
pub fn should_recreate_window(window_lost: bool, open_windows: usize) -> bool {
    window_lost && open_windows == 0
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResumeDecision {
    /// Resume the interrupted scan (`scan_start { resume_from }`).
    Resume,
    /// The "resume interrupted scans automatically" setting is off.
    Disabled,
    /// Too many consecutive auto-resumes: likely a crash loop, so the user decides.
    TooMany,
}

pub fn auto_resume_decision(enabled: bool, attempt: u32, max_attempts: u32) -> ResumeDecision {
    if !enabled {
        ResumeDecision::Disabled
    } else if attempt > max_attempts {
        ResumeDecision::TooMany
    } else {
        ResumeDecision::Resume
    }
}

/// Returns the `crash-*.txt` names to delete so that the `keep` newest remain (names embed
/// the time as `YYYYMMDD-HHMMSS-mmm`, so string order equals time order).
pub fn crash_files_to_prune(mut names: Vec<String>, keep: usize) -> Vec<String> {
    names.retain(|n| n.starts_with("crash-") && n.ends_with(".txt"));
    names.sort();
    let n = names.len().saturating_sub(keep);
    names.truncate(n);
    names
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keeps_process_only_for_implicit_exit_during_scan() {
        assert!(keep_process_alive(None, true, false));
        assert!(keep_process_alive(None, false, true));
        assert!(!keep_process_alive(None, false, false));
        // An explicit exit (AppPlugin.exit, restart) is never blocked.
        assert!(!keep_process_alive(Some(0), true, true));
    }

    #[test]
    fn recreate_window_only_when_lost_and_none_open() {
        assert!(should_recreate_window(true, 0));
        assert!(!should_recreate_window(true, 1));
        assert!(!should_recreate_window(false, 0));
    }

    #[test]
    fn auto_resume_respects_setting_and_attempts() {
        assert_eq!(auto_resume_decision(true, 1, 3), ResumeDecision::Resume);
        assert_eq!(auto_resume_decision(true, 3, 3), ResumeDecision::Resume);
        assert_eq!(auto_resume_decision(true, 4, 3), ResumeDecision::TooMany);
        assert_eq!(auto_resume_decision(false, 1, 3), ResumeDecision::Disabled);
    }

    #[test]
    fn prune_keeps_newest_crash_files() {
        let names = vec![
            "crash-20261120-100000-000.txt".to_string(),
            "foca.log".into(),
            "crash-20261120-090000-000.txt".into(),
            "crash-20261121-080000-000.txt".into(),
        ];
        assert_eq!(
            crash_files_to_prune(names.clone(), 2),
            vec!["crash-20261120-090000-000.txt".to_string()]
        );
        assert!(crash_files_to_prune(names, 5).is_empty());
    }
}
