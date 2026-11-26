//! The source deadline comes from the core (`source` running event: `timeout_s`, `deadline_ms`,
//! `round`/`rounds`); slow archives (Wayback) get three times the base deadline.

use crate::common;
use serde_json::Value;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn running_event_carries_effective_deadline() {
    let e = common::env(0).await;
    let id = e.project("Дедлайн источника").await;
    e.passive_scan(&id).await;
    let ev = e.events();
    let run = |sid: &str| -> Value {
        ev.iter()
            .find(|x| x["type"] == "source" && x["id"] == sid && x["status"] == "running")
            .unwrap_or_else(|| panic!("no running event for {sid}"))
            .clone()
    };
    let crt = run("crt");
    let wb = run("wayback");
    let base = crt["timeout_s"].as_u64().expect("timeout_s");
    assert!(base > 0);
    assert_eq!(wb["timeout_s"].as_u64().unwrap(), base * 3, "{wb}");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    let dl = wb["deadline_ms"].as_u64().unwrap();
    assert!(
        dl > now.saturating_sub(120_000) && dl <= now + base * 3 * 1000 + 1000,
        "{wb}"
    );
    assert_eq!(wb["round"], 1);
    assert_eq!(wb["rounds"], 1);
    // the final status carries round/rounds too
    let fin = ev
        .iter()
        .find(|x| {
            x["type"] == "source"
                && x["id"] == "wayback"
                && x["status"] != "running"
                && x["status"] != "wait"
        })
        .unwrap();
    assert_eq!(fin["rounds"], 1, "{fin}");
}
