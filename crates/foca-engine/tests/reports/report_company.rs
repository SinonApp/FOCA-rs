//! The report executor (header/cover) defaults to `settings.report.company`; an explicit name in the
//! report options wins, and without either nothing is invented.

use crate::common;
use serde_json::json;

fn read(rep: &serde_json::Value) -> String {
    std::fs::read_to_string(rep["path"].as_str().expect("report_build → path")).unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn report_company_defaults_to_settings() {
    let e = common::env(0).await;
    let id = e.project("example.test").await;
    let opts = |company: Option<&str>| {
        let mut o = json!({ "tpl_id": "full", "fmt": "html", "lang": "RU", "logo": true });
        if let Some(c) = company {
            o["company"] = json!(c);
        }
        json!({ "project": id, "opts": o })
    };
    let none = read(&e.call("report_build", opts(None)).await);
    assert!(!none.contains("Тестовий Виконавець"));
    e.call(
        "settings_set",
        json!({ "patch": { "report": { "company": "ТОВ «Тестовий Виконавець»" } } }),
    )
    .await;
    let from_settings = read(&e.call("report_build", opts(None)).await);
    assert!(
        from_settings.contains("Тестовий Виконавець"),
        "executor from settings.report.company"
    );
    let blank = read(&e.call("report_build", opts(Some("  "))).await);
    assert!(
        blank.contains("Тестовий Виконавець"),
        "blank option falls back"
    );
    let explicit = read(&e.call("report_build", opts(Some("Інша Компанія"))).await);
    assert!(explicit.contains("Інша Компанія"));
    assert!(
        !explicit.contains("Тестовий Виконавець"),
        "explicit name wins"
    );
}
