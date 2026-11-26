//! Monitoring: the "scan finished" notification text, the rescan schedule from
//! `settings.monitor` for WorkManager (Kotlin `MonitorWorker`) and the scheduled scan
//! profile. Pure functions, tested with `cargo test` without Android.

use foca_core::Lang;
use serde_json::{json, Value};

/// Returns the scheduled scan profile: passive or standard only (active scans are manual).
pub fn safe_profile(p: Option<&str>) -> &'static str {
    match p {
        Some("std") => "std",
        _ => "passive",
    }
}

/// Builds the notification title and text for the `done` event (`scan` is the scan record
/// with `added`) in `lang`: document count, new documents since the last scan, finding count.
pub fn done_summary(lang: Lang, name: &str, scan: &Value) -> (String, String) {
    use foca_engine::i18n::{core_text, plural};
    let n = |v: &Value| v.as_u64().unwrap_or(0);
    let docs = n(&scan["docs"]);
    let added = n(&scan["added"]["docs"]);
    let findings = n(&scan["findings"]);
    let new_f = n(&scan["new_findings"]).max(n(&scan["added"]["findings"]));
    let first = scan["added"].is_null();
    let mut parts = vec![plural(lang, docs, "docs")];
    if !first && added > 0 {
        parts.push(core_text(
            lang,
            "notify.new_since",
            &json!({ "n": plural(lang, added, "new") }),
        ));
    }
    let mut f = plural(lang, findings, "findings");
    if new_f > 0 && new_f < findings {
        f.push(' ');
        f.push_str(&core_text(
            lang,
            "notify.new_findings",
            &json!({ "n": new_f }),
        ));
    }
    parts.push(f);
    let key = if scan["trigger"] == "schedule" {
        "notify.done_title_schedule"
    } else {
        "notify.done_title"
    };
    (
        core_text(lang, key, &json!({ "name": name })),
        core_text(
            lang,
            "notify.done_text",
            &json!({ "parts": parts.join(", ") }),
        ),
    )
}

/// Builds the `monitor_schedule` payload: `settings.monitor = { <project>: { mode, time,
/// days, wifi, charge, profile? } }` → `[{ project, name, mode, time, days, wifi, charge,
/// profile }]` (only `daily`/`weekly`; the profile is passive or standard).
pub fn schedule_items(monitor: &Value, name_of: impl Fn(&str) -> Option<String>) -> Value {
    let mut out = Vec::new();
    if let Some(m) = monitor.as_object() {
        for (pid, v) in m {
            let mode = v["mode"].as_str().unwrap_or("off");
            if mode != "daily" && mode != "weekly" {
                continue;
            }
            let days: Vec<u64> = v["days"]
                .as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(Value::as_u64)
                        .filter(|d| (1..=7).contains(d))
                        .collect()
                })
                .unwrap_or_default();
            out.push(json!({
                "project": pid,
                "name": name_of(pid).unwrap_or_else(|| pid.clone()),
                "mode": mode,
                "time": v["time"].as_str().unwrap_or("03:00"),
                "days": if days.is_empty() { vec![1] } else { days },
                "wifi": v["wifi"].as_bool().unwrap_or(true),
                "charge": v["charge"].as_bool().unwrap_or(false),
                "profile": safe_profile(v["profile"].as_str()),
            }));
        }
    }
    json!({ "items": out })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn summary_text() {
        let s = json!({ "docs": 42, "findings": 3, "new_findings": 1,
            "added": { "docs": 5, "findings": 1 } });
        let (t, x) = done_summary(Lang::Ru, "Contoso", &s);
        assert_eq!(t, "Скан завершён · Contoso");
        assert_eq!(
            x,
            "Готово: 42 документа, 5 новых с прошлого скана, 3 находки (новых: 1)"
        );
        let (_, x) = done_summary(Lang::Ru, "A", &json!({ "docs": 1, "findings": 0 }));
        assert_eq!(x, "Готово: 1 документ, 0 находок");
        let (t, x) = done_summary(
            Lang::Ru,
            "A",
            &json!({ "docs": 11, "findings": 21, "trigger": "schedule",
                "added": { "docs": 0, "findings": 0 } }),
        );
        assert!(t.starts_with("Плановый скан"));
        assert_eq!(x, "Готово: 11 документов, 21 находка");
        let (t, x) = done_summary(Lang::En, "Contoso", &s);
        assert_eq!(t, "Scan finished · Contoso");
        assert_eq!(
            x,
            "Done: 42 documents, 5 new since the last scan, 3 findings (1 new)"
        );
        let (t, x) = done_summary(Lang::Uk, "Contoso", &s);
        assert_eq!(t, "Скан завершено · Contoso");
        assert_eq!(
            x,
            "Готово: 42 документи, 5 нових з минулого скану, 3 знахідки (нових: 1)"
        );
    }

    #[test]
    fn schedule_only_on_and_never_active() {
        let m = json!({
            "a": { "mode": "weekly", "time": "04:30", "days": [1, 5, 9], "wifi": false, "charge": true, "profile": "full" },
            "b": { "mode": "off" },
            "c": { "mode": "daily", "profile": "std" }
        });
        let v = schedule_items(&m, |id| (id == "a").then(|| "Проект A".to_string()));
        let it = v["items"].as_array().unwrap();
        assert_eq!(it.len(), 2);
        assert_eq!(it[0]["name"], "Проект A");
        assert_eq!(it[0]["days"], json!([1, 5]));
        assert_eq!(
            it[0]["profile"], "passive",
            "active profile falls back to passive"
        );
        assert_eq!(it[0]["wifi"], false);
        assert_eq!(it[1]["profile"], "std");
        assert_eq!(it[1]["time"], "03:00");
        assert_eq!(safe_profile(Some("custom")), "passive");
    }
}
