//! AI summary: one request per project, cancel, stored history, prompt language and
//! language-neutral placeholders that the report turns back into the client name.

use std::time::Duration;

use crate::common;
use serde_json::{json, Value};

const SLOW: &str = "/ai/slow/chat/completions";

async fn setup(e: &common::Env) -> String {
    let id = e.project("example.test").await;
    e.call(
        "key_set",
        json!({ "service": "ai", "value": "sk-test-slow-0000" }),
    )
    .await;
    e.call(
        "settings_set",
        json!({ "patch": { "ai": { "provider": "custom", "base_url": format!("{}/ai/slow", e.server.url()), "model": "slow-model" } } }),
    )
    .await;
    id
}

fn slow_calls(e: &common::Env) -> Vec<Value> {
    e.server
        .requests()
        .into_iter()
        .filter(|r| r.path() == SLOW)
        .map(|r| serde_json::from_slice(&r.body).unwrap())
        .collect()
}

async fn list(e: &common::Env, id: &str) -> Value {
    e.call("ai_summaries_list", json!({ "project": id })).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ai_summary_runs_once_per_project_and_is_kept_in_history() {
    let e = common::env(0).await;
    let id = setup(&e).await;
    let args = json!({ "project": id, "opts": {} });
    // a double tap: the second call while the first runs is rejected, the provider is paid once
    let (a, b) = tokio::join!(e.engine.invoke("ai_summarize", args.clone()), async {
        tokio::time::sleep(Duration::from_millis(150)).await;
        e.engine.invoke("ai_summarize", args.clone()).await
    });
    let first = a.expect("first request");
    assert_eq!(b.expect_err("second request").code, "busy");
    assert_eq!(slow_calls(&e).len(), 1);

    let h = list(&e, &id).await;
    let items = h["items"].as_array().unwrap();
    assert_eq!(items.len(), 1, "{h}");
    assert_eq!(items[0]["id"], first["id"]);
    assert_eq!(items[0]["model"], "slow-model");
    assert_eq!(items[0]["provider"], "custom");
    assert!(items[0]["created"].as_str().is_some_and(|c| !c.is_empty()));
    assert!(items[0]["tokens_in"].is_u64() && items[0]["lang"].is_string());
    assert_eq!(h["report_id"], first["id"]);
    assert_eq!(h["running"], false);

    // cancel: the running request ends with `cancelled` and stores nothing
    let eng = e.engine.clone();
    let a2 = args.clone();
    let task = tokio::spawn(async move { eng.invoke("ai_summarize", a2).await });
    let mut running = false;
    for _ in 0..200 {
        if list(&e, &id).await["running"] == true {
            running = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert!(running, "the request never showed as running");
    let c = e.call("ai_cancel", json!({ "project": id })).await;
    assert_eq!(c["cancelled"], true);
    assert_eq!(
        task.await.unwrap().expect_err("cancelled").code,
        "cancelled"
    );
    let h = list(&e, &id).await;
    assert_eq!(h["items"].as_array().unwrap().len(), 1);
    assert_eq!(h["running"], false);
    let none = e.call("ai_cancel", json!({ "project": id })).await;
    assert_eq!(none["cancelled"], false);

    // a second summary goes first; the first one can be picked for the report again
    let second = e.call("ai_summarize", args.clone()).await;
    let h = list(&e, &id).await;
    assert_eq!(h["items"][0]["id"], second["id"]);
    assert_eq!(h["items"][1]["id"], first["id"]);
    assert_eq!(h["report_id"], second["id"]);
    let h = e
        .call(
            "ai_summary_use",
            json!({ "project": id, "summary": first["id"] }),
        )
        .await;
    assert_eq!(h["report_id"], first["id"]);

    // the report names the client where the provider saw [CLIENT]/[CLIENT-DOMAIN]
    let rep = e
        .call(
            "report_build",
            json!({ "project": id, "opts": { "fmt": "md", "lang": "en" } }),
        )
        .await;
    let md = std::fs::read_to_string(rep["path"].as_str().unwrap()).unwrap();
    assert!(md.contains("Executive summary (AI-assisted)"), "{md}");
    assert!(md.contains("leaks passwords on www.example.test"), "{md}");
    assert!(md.contains("Приклад»"), "{md}");
    assert!(!md.contains("[CLIENT"), "{md}");

    // deleting the report summary drops the report section; unknown ids are errors
    let h = e
        .call(
            "ai_summary_delete",
            json!({ "project": id, "summary": first["id"] }),
        )
        .await;
    assert_eq!(h["items"].as_array().unwrap().len(), 1);
    assert_eq!(h["report_id"], Value::Null);
    let rep = e
        .call(
            "report_build",
            json!({ "project": id, "opts": { "fmt": "md", "lang": "en" } }),
        )
        .await;
    let md = std::fs::read_to_string(rep["path"].as_str().unwrap()).unwrap();
    assert!(!md.contains("Executive summary (AI-assisted)"), "{md}");
    let er = e
        .err(
            "ai_summary_delete",
            json!({ "project": id, "summary": "ai-missing" }),
        )
        .await;
    assert_eq!(er.code, "not_found");
    let er = e
        .err(
            "ai_summary_use",
            json!({ "project": id, "summary": "ai-missing" }),
        )
        .await;
    assert_eq!(er.code, "not_found");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ai_prompt_and_answer_language_follow_the_ui_language() {
    let cyr = |s: &str| s.chars().any(|c| matches!(c, '\u{0400}'..='\u{04FF}'));
    let e = common::env(0).await;
    let id = setup(&e).await;
    // "auto" follows the device locale: a Ukrainian phone gets a Ukrainian prompt, never Russian
    e.call("settings_set", json!({ "patch": { "lang": "auto" } }))
        .await;
    e.call(
        "i18n_bundle",
        json!({ "lang": "auto", "device_locale": "uk-UA", "include_help": false }),
    )
    .await;
    let p = e
        .call("ai_preview", json!({ "project": id, "opts": {} }))
        .await;
    let text = p["text"].as_str().unwrap();
    assert_eq!(p["lang"], "uk", "{p}");
    assert!(text.contains("Проєкт: [CLIENT]"), "{text}");
    assert!(text.contains("Пиши українською мовою"), "{text}");
    assert!(!text.contains("[КЛИЕНТ"), "{text}");
    let s = e
        .call(
            "ai_summarize",
            json!({ "project": id, "preview_id": p["id"], "opts": {} }),
        )
        .await;
    assert_eq!(s["lang"], "uk");
    let body = slow_calls(&e).pop().unwrap();
    let system = body["messages"][0]["content"].as_str().unwrap_or("");
    assert!(system.contains("українською"), "{body}");
    assert!(system.contains("[CLIENT]"), "{system}");
    assert_eq!(list(&e, &id).await["items"][0]["lang"], "uk");

    // an explicit language wins: English has no Cyrillic at all (client name redacted)
    let p = e
        .call(
            "ai_preview",
            json!({ "project": id, "opts": { "lang": "en" } }),
        )
        .await;
    let text = p["text"].as_str().unwrap();
    assert_eq!(p["lang"], "en");
    assert!(!cyr(text), "{text}");
    assert!(text.contains("Write in English"), "{text}");
    e.call(
        "ai_summarize",
        json!({ "project": id, "preview_id": p["id"], "opts": { "lang": "en" } }),
    )
    .await;
    let body = slow_calls(&e).pop().unwrap();
    assert!(
        !cyr(body["messages"][0]["content"].as_str().unwrap()),
        "{body}"
    );
    let p = e
        .call(
            "ai_preview",
            json!({ "project": id, "opts": { "lang": "ru" } }),
        )
        .await;
    assert!(p["text"]
        .as_str()
        .unwrap()
        .contains("Пиши на русском языке"));
    // the preview id covers the language: a stale id is refused
    let er = e
        .err(
            "ai_summarize",
            json!({ "project": id, "preview_id": p["id"], "opts": { "lang": "uk" } }),
        )
        .await;
    assert_eq!(er.code, "stale_preview");
}

async fn use_route(e: &common::Env, route: &str) {
    e.call(
        "settings_set",
        json!({ "patch": { "ai": { "provider": "custom", "base_url": format!("{}/ai/{route}", e.server.url()), "model": "reason-model" } } }),
    )
    .await;
}

/// The history regression of the phone test: reasoning answers, streamed answers and
/// reasoning-only answers. Every answer with text is saved, comes back with the history on top
/// and survives an engine restart; an answer without text is a visible error.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reasoning_and_streamed_answers_are_saved_and_survive_a_restart() {
    let e = common::env(0).await;
    let id = setup(&e).await;
    let opts = json!({ "project": id, "opts": { "show_thoughts": true } });

    use_route(&e, "reason").await;
    let r = e.call("ai_summarize", opts.clone()).await;
    assert!(
        r["md"].as_str().unwrap().contains("Exposed documents"),
        "{r}"
    );
    assert!(
        r["thoughts"].as_str().unwrap().contains("First I look"),
        "{r}"
    );
    let h = &r["history"];
    assert_eq!(h["items"][0]["id"], r["id"], "{h}");
    assert_eq!(h["report_id"], r["id"]);
    assert_eq!(h["running"], false);

    use_route(&e, "sse").await;
    let s = e.call("ai_summarize", opts.clone()).await;
    assert_eq!(s["md"], "## Streamed summary", "{s}");
    assert_eq!(s["model"], "sse-model");
    assert_eq!(s["history"]["items"][0]["id"], s["id"]);
    assert_eq!(s["history"]["items"][1]["id"], r["id"]);

    use_route(&e, "thinkonly").await;
    let er = e.err("ai_summarize", opts.clone()).await;
    assert_eq!(er.code, "empty");
    assert!(
        er.message.contains("только ход рассуждений"),
        "{}",
        er.message
    );
    let h = list(&e, &id).await;
    assert_eq!(h["items"].as_array().unwrap().len(), 2, "{h}");
    assert_eq!(h["running"], false);

    // a new engine on the same data (app restart): the history and the report pick stay
    e.engine.abandon().await;
    let (again, _, _) = common::open(e.dir.path(), &e.server.url(), e.keys.clone());
    let h = again
        .invoke("ai_summaries_list", json!({ "project": id }))
        .await
        .unwrap();
    let items = h["items"].as_array().unwrap();
    assert_eq!(items.len(), 2, "{h}");
    assert_eq!(items[0]["id"], s["id"]);
    assert_eq!(h["report_id"], s["id"]);
    assert!(items[1]["thoughts"]
        .as_str()
        .unwrap()
        .contains("First I look"));
}
