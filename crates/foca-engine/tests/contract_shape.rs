//! Checks the shape of `Engine::invoke` responses against the reference, the demo backend
//! (`ui/js/demo-backend.js`). Reference data: `tests/fixtures/demo_shapes.json`
//! (`node crates/foca-engine/tests/dump_demo_shapes.mjs`). Engine responses must contain every key
//! of the demo (extra keys are allowed) with compatible types. `null` from the engine where the demo
//! has a value is allowed (no data) but listed in the output.

mod common;

use std::collections::BTreeSet;

use common::*;
use serde_json::{json, Value};

/// Fields of every `report_verify` answer (also the "missing" one).
const VERIFY_KEYS: &[&str] = &[
    "ok",
    "id",
    "name",
    "exists",
    "actual_sha256",
    "expected_sha256",
    "hash_match",
    "sidecar_present",
    "sig_present",
    "signature_alg",
    "signature_valid",
    "key_alias",
    "key_fingerprint",
    "signature_own_key",
    "custody",
    "status",
];
const VERIFY_STATUSES: &[&str] = &[
    "verified_signed",
    "verified_foreign",
    "verified_hash",
    "tampered",
    "unsigned",
    "missing",
];
/// `Doc.error_kind` values.
const DOC_ERROR_KINDS: &[&str] = &["parse", "download", "http"];

#[derive(Default)]
struct Report {
    errors: Vec<String>,
    empty: BTreeSet<String>,
    nulls: BTreeSet<String>,
}

fn types(s: &Value) -> Vec<String> {
    s["t"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default()
}

fn ty(v: &Value) -> &'static str {
    match v {
        Value::Null => "null",
        Value::Bool(_) => "bool",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

fn check(shape: &Value, v: &Value, path: &str, r: &mut Report) {
    let t = types(shape);
    if v.is_null() {
        if !t.iter().any(|x| x == "null") {
            r.nulls.insert(path.to_string());
        }
        return;
    }
    let vt = ty(v);
    let ok = t.iter().any(|x| x == vt || (x == "map" && vt == "object"));
    if !ok {
        // the demo returns null (no data) and the engine a value: compatible if the demo only has null
        if t == ["null"] {
            return;
        }
        r.errors.push(format!("{path}: тип {vt}, у демо {t:?}"));
        return;
    }
    match vt {
        "object" if t.iter().any(|x| x == "map") => {
            if let Some(vs) = shape.get("values").filter(|x| !x.is_null()) {
                for (k, x) in v.as_object().unwrap() {
                    check(vs, x, &format!("{path}.{k}"), r);
                }
            }
        }
        "object" => {
            if let Some(keys) = shape.get("keys").and_then(Value::as_object) {
                let o = v.as_object().unwrap();
                for (k, ks) in keys {
                    match o.get(k) {
                        Some(x) => check(ks, x, &format!("{path}.{k}"), r),
                        None => r.errors.push(format!("{path}: нет ключа «{k}»")),
                    }
                }
            }
        }
        "array" => {
            let a = v.as_array().unwrap();
            if let Some(items) = shape.get("items").filter(|x| !x.is_null()) {
                if a.is_empty() {
                    r.empty.insert(path.to_string());
                }
                for x in a {
                    check(items, x, &format!("{path}[]"), r);
                }
            }
        }
        _ => {}
    }
}

#[test]
fn contract_shape_matches_demo_backend() {
    std::thread::Builder::new()
        .name("contract_shape".into())
        .stack_size(16 * 1024 * 1024)
        .spawn(|| {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(4)
                .thread_stack_size(16 * 1024 * 1024)
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(contract_shape_matches_demo_backend_inner());
        })
        .unwrap()
        .join()
        .unwrap();
}

async fn contract_shape_matches_demo_backend_inner() {
    let demo: Value = serde_json::from_str(
        &std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/demo_shapes.json"),
        )
        .unwrap(),
    )
    .unwrap();
    let e = env(0).await;
    let mut got: Vec<(String, Value)> = Vec::new();
    macro_rules! c {
        ($name:expr, $cmd:expr, $args:expr) => {{
            let v = e.call($cmd, $args).await;
            got.push(($name.to_string(), v.clone()));
            v
        }};
    }
    c!("project_list", "project_list", json!({}));
    let id = e.project("example.test").await;
    // a corpus project: offline local import plus a passive scan against the local server
    let mut paths = Vec::new();
    for d in std::fs::read_dir(corpus_dir()).unwrap().flatten() {
        if !d.path().is_dir() {
            continue;
        }
        for f in std::fs::read_dir(d.path()).unwrap().flatten() {
            let p = f.path().to_string_lossy().into_owned();
            if !p.ends_with(".json") && !p.ends_with(".py") && !p.ends_with(".md") {
                paths.push(p);
            }
        }
    }
    let imp = e
        .call("doc_import", json!({ "project": id, "paths": paths }))
        .await;
    assert!(imp["imported"].as_u64().unwrap() > 20);
    // Offline import into a new project, search, rules, forensic details.
    c!(
        "import_offline",
        "import_offline",
        json!({ "name": "offline.test", "paths": [paths[0].clone()] })
    );
    c!("demo_case_import", "demo_case_import", json!({}));
    c!("import_cancel", "import_cancel", json!({}));
    c!(
        "docs_search",
        "docs_search",
        json!({ "project": id, "q": "budget" })
    );
    let s0 = e.snap(&id).await;
    let d0 = s0["docs"][0]["id"].clone();
    c!("doc_get", "doc_get", json!({ "project": id, "id": d0 }));
    c!("rules_get", "rules_get", json!({ "project": id }));
    c!(
        "rules_set",
        "rules_set",
        json!({ "project": id, "config": { "presets": ["credentials"], "rules": [{ "id": "r1", "title": "Проект", "pattern": "проект\\s+\\w+", "sev": "low", "enabled": true, "case_insensitive": true, "mask": false }] } })
    );
    c!(
        "rules_test",
        "rules_test",
        json!({ "pattern": "\\d{4}", "text": "код 1234 і 5678" })
    );
    e.passive_scan(&id).await;
    // triage, so that notes, photos and statuses exist
    let s = e.snap(&id).await;
    let fid = s["findings"][0]["id"].clone();
    let fid2 = s["findings"][1]["id"].clone();
    c!(
        "finding_set_status",
        "finding_set_status",
        json!({ "project": id, "id": fid, "status": "confirmed" })
    );
    c!(
        "finding_update",
        "finding_update",
        json!({ "project": id, "id": fid2, "patch": { "notes": [{ "text": "t", "who": "Вы", "time": "20.11" }] } })
    );
    c!(
        "finding_photo_add",
        "finding_photo_add",
        json!({ "project": id, "id": fid2, "name": "a.jpg" })
    );
    c!(
        "finding_playbook",
        "finding_playbook",
        json!({ "project": id, "id": fid2, "lang": "uk" })
    );
    let docs: Vec<Value> = s["docs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|d| d["id"].clone())
        .collect();
    c!(
        "doc_delete",
        "doc_delete",
        json!({ "project": id, "ids": [docs[0]] })
    );
    c!(
        "doc_restore",
        "doc_restore",
        json!({ "project": id, "ids": [docs[0]] })
    );
    let enc_exp = c!(
        "project_export_encrypted",
        "project_export_encrypted",
        json!({ "project": id, "password": "ContractPassword!2026", "include_files": true })
    );
    let enc_imp = c!(
        "project_import_encrypted",
        "project_import_encrypted",
        json!({
            "path": enc_exp["path"],
            "password": "ContractPassword!2026",
            "new_name": "Imported Contract"
        })
    );
    e.call("project_delete", json!({ "id": enc_imp["project"]["id"] }))
        .await;
    let docx = s["docs"]
        .as_array()
        .unwrap()
        .iter()
        .find(|d| d["ext"] == "docx")
        .unwrap()["id"]
        .clone();
    c!(
        "doc_clean",
        "doc_clean",
        json!({ "project": id, "ids": [docx, docs[1]] })
    );
    c!("hygiene_get", "hygiene_get", json!({ "project": id }));
    let shared = corpus_dir().join("forensics/signed.pdf");
    let shared = shared.to_string_lossy();
    c!(
        "hygiene_get_file",
        "hygiene_get",
        json!({ "path": shared, "name": "a.pdf" })
    );
    c!(
        "doc_clean_file",
        "doc_clean",
        json!({ "path": shared, "name": "a.pdf" })
    );
    let sec = s["secrets"][0]["id"].clone();
    c!(
        "secret_reveal",
        "secret_reveal",
        json!({ "project": id, "id": sec })
    );
    c!(
        "secret_hibp_check",
        "secret_hibp_check",
        json!({ "project": id, "id": sec })
    );
    let fref = s["findings"]
        .as_array()
        .unwrap()
        .iter()
        .find_map(|f| {
            f["secret_refs"]
                .as_array()
                .filter(|r| !r.is_empty())
                .map(|r| r[0].clone())
        })
        .unwrap();
    c!(
        "secret_reveal_ref",
        "secret_reveal",
        json!({ "project": id, "id": fref })
    );
    let rep = c!(
        "report_build",
        "report_build",
        json!({ "project": id, "opts": { "tpl": "Полный отчёт пентеста", "tpl_id": "full", "fmt": "html", "lang": "RU", "min_sev": "low", "confirmed": false, "sections": { "summary": true, "findings": true } } })
    );
    c!(
        "report_build",
        "report_build",
        json!({ "project": id, "opts": { "tpl_id": "brief", "fmt": "md", "lang": "UA" } })
    );
    c!(
        "report_build",
        "report_build",
        json!({ "project": id, "template": "lab", "opts": { "fmt": "html", "lang": "UA" } })
    );
    c!(
        "report_templates",
        "report_templates",
        json!({ "lang": "UA" })
    );
    c!("report_list", "report_list", json!({ "project": id }));
    let rep_cust = c!(
        "report_build",
        "report_build",
        json!({ "project": id, "custody": true, "opts": { "tpl_id": "full", "fmt": "html", "lang": "UK" } })
    );
    let ver = c!(
        "report_verify",
        "report_verify",
        json!({ "project": id, "id": rep["id"] })
    );
    let ver_cust = c!(
        "report_verify",
        "report_verify",
        json!({ "project": id, "id": rep_cust["id"] })
    );
    // engine → demo direction for report_verify: every documented field is always present
    for v in [&ver, &ver_cust] {
        for k in VERIFY_KEYS {
            assert!(v.get(*k).is_some(), "report_verify lacks «{k}»: {v}");
        }
        let st = v["status"].as_str().unwrap_or("");
        assert!(VERIFY_STATUSES.contains(&st), "report_verify status {st}");
    }
    c!(
        "report_delete",
        "report_delete",
        json!({ "project": id, "id": rep["id"] })
    );
    c!(
        "export_build",
        "export_build",
        json!({ "project": id, "kind": "users", "fmt": "dict", "opts": { "dict": "users" } })
    );
    e.call(
        "export_build",
        json!({ "project": id, "kind": "users", "fmt": "dict", "opts": { "dict": "logins", "ad_domain": "CORP" } }),
    )
    .await;
    e.call(
        "export_build",
        json!({ "project": id, "kind": "all", "fmt": "dict", "opts": { "dict": "context" } }),
    )
    .await;
    c!(
        "wordlist_preview",
        "wordlist_preview",
        json!({ "project": id, "kind": "logins", "ad_domain": "CORP", "limit": 50 })
    );
    e.call(
        "wordlist_preview",
        json!({ "project": id, "kind": "context", "limit": 50 }),
    )
    .await;
    c!(
        "alert_rules_get",
        "alert_rules_get",
        json!({ "project": id })
    );
    c!(
        "alert_rules_set",
        "alert_rules_set",
        json!({ "project": id, "patch": { "enabled": false, "min_severity": "warn" } })
    );
    c!(
        "alert_test",
        "alert_test",
        json!({ "project": id, "channel": "webhook" })
    );
    c!("risk_trend_get", "risk_trend_get", json!({ "project": id }));
    c!("signatures_status", "signatures_status", json!({}));
    // the local server has no bundle: the check ends with `no_update` and fills `last_check`
    c!(
        "signatures_update",
        "signatures_update",
        json!({ "url": format!("{}/sig-feed/signatures.bundle", e.server.url()) })
    );
    c!("signatures_rollback", "signatures_rollback", json!({}));
    c!("plugins_list", "plugins_list", json!({}));
    c!(
        "plugin_install",
        "plugin_install",
        json!({ "manifest": { "id": "demo-check", "name": "Demo Check", "version": "1.0.0", "author": "QA", "kind": "analyzer", "runtime": "declarative", "permissions": ["meta:read"], "declarative": { "extract_kind": "meta_pattern", "pattern": "TEST-[0-9]+" } } })
    );
    c!(
        "plugin_toggle",
        "plugin_toggle",
        json!({ "id": "demo-check", "enabled": false })
    );
    c!(
        "plugin_run_test",
        "plugin_run_test",
        json!({ "id": "ua-gov-edrpou-enricher", "target": "example.ua", "passive": true, "sample_body": "EDRPOU 12345678" })
    );
    c!(
        "plugin_remove",
        "plugin_remove",
        json!({ "id": "demo-check" })
    );
    e.call(
        "settings_set",
        json!({ "patch": { "ai": { "provider": "deepseek", "model": "deepseek-chat" } } }),
    )
    .await;
    e.call(
        "key_set",
        json!({ "service": "ai", "value": "sk-test-0000000000" }),
    )
    .await;
    c!(
        "i18n_bundle",
        "i18n_bundle",
        json!({ "lang": "auto", "device_locale": "uk-UA", "include_help": false })
    );
    c!(
        "i18n_bundle",
        "i18n_bundle",
        json!({ "lang": "en", "include_help": true })
    );
    c!("licenses_get", "licenses_get", json!({}));
    c!(
        "ai_models_list",
        "ai_models_list",
        json!({ "provider": "openai" })
    );
    let ap = c!(
        "ai_preview",
        "ai_preview",
        json!({ "project": id, "opts": {} })
    );
    let sm = c!(
        "ai_summarize",
        "ai_summarize",
        json!({ "project": id, "preview_id": ap["id"], "opts": {} })
    );
    c!(
        "ai_summaries_list",
        "ai_summaries_list",
        json!({ "project": id })
    );
    c!(
        "ai_summary_use",
        "ai_summary_use",
        json!({ "project": id, "summary": sm["id"] })
    );
    c!("ai_cancel", "ai_cancel", json!({ "project": id }));
    c!(
        "ai_summary_delete",
        "ai_summary_delete",
        json!({ "project": id, "summary": sm["id"] })
    );
    c!("project_snapshot", "project_snapshot", json!({ "id": id }));
    c!("project_open", "project_open", json!({ "id": id }));
    c!("project_list", "project_list", json!({}));
    c!("scope_get", "scope_get", json!({ "id": id }));
    let np = c!(
        "project_create",
        "project_create",
        json!({ "name": "shape.test", "client": "К", "targets": [{ "v": "shape.test", "type": "domain", "active": false }], "excludes": [] })
    );
    c!(
        "project_update",
        "project_update",
        json!({ "id": np["id"], "patch": { "notes": "n" } })
    );
    let dup = c!(
        "project_duplicate",
        "project_duplicate",
        json!({ "id": np["id"] })
    );
    c!(
        "project_delete",
        "project_delete",
        json!({ "id": dup["id"] })
    );
    c!(
        "scope_set",
        "scope_set",
        json!({ "id": id, "scope": { "contact": "x" } })
    );
    c!("infra_get", "infra_get", json!({ "project": id }));
    c!("insights_get", "insights_get", json!({ "project": id }));
    c!(
        "insights_get",
        "insights_get",
        json!({ "project": id, "layers": ["people", "docs"], "min_group": 2 })
    );
    c!(
        "chain_get",
        "chain_get",
        json!({ "project": id, "node": "doc:1" })
    );
    c!(
        "attack_paths_get",
        "attack_paths_get",
        json!({ "project": id })
    );
    let oos = c!("oos_list", "oos_list", json!({ "project": id }));
    if let Some(cand) = oos
        .as_array()
        .unwrap()
        .iter()
        .find(|o| o["blocked"].is_null())
    {
        c!(
            "oos_decide",
            "oos_decide",
            json!({ "project": id, "id": cand["id"], "decision": "ignored" })
        );
        e.call(
            "oos_decide",
            json!({ "project": id, "id": cand["id"], "decision": "new" }),
        )
        .await;
        c!(
            "oos_add_to_scope",
            "oos_add_to_scope",
            json!({ "project": id, "id": cand["id"] })
        );
    }
    c!(
        "scope_add_hosts",
        "scope_add_hosts",
        json!({ "project": id, "hosts": ["intranet.other.test", "example.test"], "dry_run": true })
    );
    c!("settings_get", "settings_get", json!({}));
    c!(
        "settings_set",
        "settings_set",
        json!({ "patch": { "net": { "rps": 5 } } })
    );
    c!(
        "key_set",
        "key_set",
        json!({ "service": "brave", "value": "BSAqxxxxxxab12" })
    );
    c!("key_delete", "key_delete", json!({ "service": "censys" }));
    c!("net_check", "net_check", json!({}));
    c!("scan_status_idle", "scan_status", json!({}));
    // scan: responses and events
    e.clear_events();
    *e.pause_at.lock().unwrap() = Some("download".into());
    c!(
        "scan_start",
        "scan_start",
        json!({ "project": id, "profile": "passive", "sources": ["crt", "wayback"] })
    );
    e.wait_paused("download").await;
    c!("scan_status", "scan_status", json!({}));
    c!("scan_pause", "scan_pause", json!({}));
    c!("scan_resume", "scan_resume", json!({}));
    *e.pause_at.lock().unwrap() = Some("meta".into());
    e.wait_paused("meta").await;
    c!("scan_stop", "scan_stop", json!({ "reason": "user" }));
    *e.pause_at.lock().unwrap() = None;
    let stp = e.snap(&id).await["scans"]
        .as_array()
        .unwrap()
        .last()
        .cloned()
        .unwrap();
    check_demo_sources(&stp);
    c!(
        "scan_start",
        "scan_start",
        json!({ "project": id, "profile": "passive", "resume_from": stp["id"], "sources": ["crt", "wayback"] })
    );
    e.wait().await;
    c!("project_snapshot", "project_snapshot", json!({ "id": id }));
    c!(
        "scan_control",
        "scan_control",
        json!({ "kind": "stage", "id": "network", "action": "pause" })
    );
    let events = e.events();
    // Quick tools (no project) and the scan queue (paused first, so nothing starts)
    let contract = corpus_dir().join("ooxml/contract.docx");
    c!(
        "tool_file",
        "tool_file",
        json!({ "path": contract.to_string_lossy() })
    );
    c!(
        "tool_secret",
        "tool_secret",
        json!({ "value": "Qwerty2024!", "hibp_opt_in": true })
    );
    c!(
        "tool_mail_domain",
        "tool_mail_domain",
        json!({ "domain": "example.test" })
    );
    let site = foca_net::testserver::TestServer::start(|r| match r.path() {
        "/" => foca_net::testserver::TestResponse::ok(
            b"<html><head><link rel=\"icon\" href=\"/i.png\"></head></html>".to_vec(),
        )
        .header("server", "nginx/1.18.0"),
        "/i.png" => foca_net::testserver::TestResponse::ok(vec![0x89, b'P', b'N', b'G', 1]),
        _ => foca_net::testserver::TestResponse::status(404),
    })
    .await;
    c!(
        "tool_host",
        "tool_host",
        json!({ "url": format!("{}/", site.url()) })
    );
    c!("tool_log", "tool_log", json!({}));
    c!("tool_log_clear", "tool_log_clear", json!({}));
    c!("queue_pause", "queue_pause", json!({}));
    let qa = c!(
        "queue_add",
        "queue_add",
        json!({ "projects": [id], "profile": "passive" })
    );
    c!("queue_list", "queue_list", json!({}));
    c!(
        "queue_remove",
        "queue_remove",
        json!({ "id": qa["items"][0]["id"] })
    );
    c!("queue_clear", "queue_clear", json!({}));
    c!("queue_resume", "queue_resume", json!({}));
    c!("pin_set", "pin_set", json!({ "pin": "2580" }));
    c!("pin_check", "pin_check", json!({ "pin": "0000" }));
    // a document that failed to parse carries a machine-readable error_kind (no HTTP status)
    let pe = e.project("broken.test").await;
    e.call(
        "import_offline",
        json!({ "project": pe, "files": [{ "name": "broken.docx",
            "data": foca_core::b64::encode(b"PK\x03\x04 broken") }] }),
    )
    .await;
    let se = e.snap(&pe).await;
    let errs: Vec<&Value> = se["docs"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|d| d["status"] == "error")
        .collect();
    assert!(!errs.is_empty(), "no error document: {}", se["docs"]);
    for d in errs {
        let k = d["error_kind"].as_str().unwrap_or("");
        assert!(DOC_ERROR_KINDS.contains(&k), "error_kind {k}: {d}");
        assert!(
            d.get("http_status").is_none() || k == "http",
            "http_status only for http errors: {d}"
        );
    }
    // clearing the request log: a count, then the deletion of rows older than 30 days
    c!(
        "request_log_clear",
        "request_log_clear",
        json!({ "project": id, "dry_run": true })
    );
    c!(
        "request_log_clear",
        "request_log_clear",
        json!({ "project": id, "days": 30 })
    );
    // deleting one scan: what it would remove, then the deletion (everything is wiped next)
    c!(
        "scan_delete",
        "scan_delete",
        json!({ "project": id, "scan_id": stp["id"], "dry_run": true })
    );
    c!(
        "scan_delete",
        "scan_delete",
        json!({ "project": id, "scan_id": stp["id"] })
    );
    c!("wipe_all", "wipe_all", json!({ "confirm": "WIPE" }));

    let mut r = Report::default();
    let mut seen = BTreeSet::new();
    for (name, v) in &got {
        let shape = &demo["commands"][name];
        assert!(!shape.is_null(), "no reference for {name}");
        seen.insert(name.clone());
        check(shape, v, name, &mut r);
    }
    let all: BTreeSet<String> = demo["commands"]
        .as_object()
        .unwrap()
        .keys()
        .cloned()
        .collect();
    let missing: Vec<&String> = all.difference(&seen).collect();
    assert!(
        missing.is_empty(),
        "commands without a shape check: {missing:?}"
    );
    for (t, shape) in demo["events"].as_object().unwrap() {
        let evs: Vec<&Value> = events.iter().filter(|x| x["type"] == t.as_str()).collect();
        assert!(!evs.is_empty(), "the engine did not emit event {t}");
        for ev in evs {
            check(shape, ev, &format!("event:{t}"), &mut r);
        }
    }
    eprintln!("== contract_shape: пустые массивы у движка (элементы не проверены):");
    for p in &r.empty {
        eprintln!("   {p}");
    }
    eprintln!("== contract_shape: null у движка там, где у демо значение:");
    for p in &r.nulls {
        eprintln!("   {p}");
    }
    assert!(
        r.errors.is_empty(),
        "shape mismatches:\n{}",
        r.errors.join("\n")
    );
}

#[test]
fn checker_detects_missing_keys_and_types() {
    let shape = json!({ "t": ["object"], "keys": {
        "a": { "t": ["number"] },
        "b": { "t": ["array"], "items": { "t": ["object"], "keys": { "x": { "t": ["string"] } } } },
        "m": { "t": ["map"], "values": { "t": ["object"], "keys": { "status": { "t": ["string"] } } } } } });
    let mut r = Report::default();
    check(
        &shape,
        &json!({ "a": "1", "b": [{ "y": 1 }], "m": { "k": {} } }),
        "x",
        &mut r,
    );
    assert_eq!(r.errors.len(), 3, "{:?}", r.errors);
    let mut r = Report::default();
    check(
        &shape,
        &json!({ "a": null, "b": [], "m": {}, "extra": 1 }),
        "x",
        &mut r,
    );
    assert!(r.errors.is_empty());
    assert!(r.nulls.contains("x.a") && r.empty.contains("x.b"));
}

/// The demo signature screen shows the same numbers and standard families as the core status
/// (`DEMO_SIG_BUILTIN`, `DEMO_SIG_FRAMEWORKS` in demo-backend.js).
#[test]
fn demo_signature_numbers_match_core_status() {
    let src = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../ui/js/demo-backend.js"),
    )
    .unwrap();
    let start = src
        .find("const DEMO_SIG_BUILTIN = {")
        .expect("DEMO_SIG_BUILTIN");
    let body = &src[start..start + src[start..].find("};").unwrap()];
    let field = |k: &str| -> String {
        let at = body
            .find(&format!("{k}: "))
            .unwrap_or_else(|| panic!("{k}"))
            + k.len()
            + 2;
        let rest = &body[at..];
        rest[..rest.find(',').unwrap()]
            .trim_matches('"')
            .to_string()
    };
    let dir = tempfile::tempdir().unwrap();
    let st = foca_engine::sigbundle::status(dir.path(), time::macros::date!(2026 - 11 - 27));
    assert_eq!(field("version"), st.kev.catalog);
    assert_eq!(field("released"), st.kev.released);
    for (k, v) in [
        ("total", st.kev.total),
        ("used", st.kev.used),
        ("products", st.kev.products),
        ("software", st.software.software),
        ("os", st.software.os),
        ("secrets", st.counts.secrets),
        ("std_rules", st.std_map.rules),
        ("std_refs", st.std_map.refs),
    ] {
        assert_eq!(field(k), v.to_string(), "{k}");
    }
    let start = src
        .find("const DEMO_SIG_FRAMEWORKS = [")
        .expect("DEMO_SIG_FRAMEWORKS");
    let fw = &src[start..start + src[start..].find("];").unwrap()];
    let demo: Vec<String> = fw
        .lines()
        .skip(1)
        .filter_map(|l| l.trim().strip_prefix('['))
        .map(|l| l.split('"').nth(3).unwrap_or_default().to_string())
        .collect();
    let core: Vec<String> = st
        .std_map
        .frameworks
        .iter()
        .map(|f| f.label.clone())
        .collect();
    assert_eq!(demo, core);
    assert!(
        src.contains(foca_engine::sigbundle::DEFAULT_FEED_URL),
        "demo feed URL"
    );
}

/// The demo backend keeps a copy of the standards of its finding rules (`DEMO_STANDARDS`); every
/// entry must match `signatures/standards.toml` of the core.
#[test]
fn demo_standards_match_core_mapping() {
    let src = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../ui/js/demo-backend.js"),
    )
    .unwrap();
    let start = src
        .find("const DEMO_STANDARDS = {")
        .expect("DEMO_STANDARDS");
    let body = &src[start..start + src[start..].find("};").unwrap()];
    let std = foca_analysis::standards::Standards::builtin();
    let mut n = 0;
    for line in body.lines().skip(1) {
        let line = line.trim().trim_end_matches(',');
        let Some((rule, enc)) = line.split_once(": ") else {
            continue;
        };
        let (rule, enc) = (rule.trim_matches('"'), enc.trim_matches('"'));
        let r = std
            .for_rule(rule)
            .unwrap_or_else(|| panic!("{rule}: not in standards.toml"));
        let want = [
            &r.mitre,
            &r.cwe,
            &r.owasp,
            &r.wstg,
            &r.iso27001,
            &r.nist,
            &r.privacy,
            &r.ndtzi,
            &r.kszi,
        ]
        .map(|v| v.join(" "))
        .join("|");
        assert_eq!(enc, want, "{rule}");
        n += 1;
    }
    assert!(n >= 20, "only {n} demo rules parsed");
    let top = &src[src.find("const CWE_TOP25 =").expect("CWE_TOP25")..];
    let top = &top[top.find('"').unwrap() + 1..];
    let top: Vec<String> = top[..top.find('"').unwrap()]
        .split(' ')
        .map(|n| format!("CWE-{n}"))
        .collect();
    assert_eq!(
        top,
        foca_analysis::standards::CWE_TOP25_2025,
        "demo CWE_TOP25"
    );
}

/// The demo `SOURCES` table mirrors the engine source list (passive ids must exist in the core scan
/// record; the plugin step is listed in both).
fn check_demo_sources(scan: &Value) {
    let src = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../ui/js/demo-backend.js"),
    )
    .unwrap();
    let start = src.find("const SOURCES = [").expect("demo SOURCES");
    let body = &src[start..start + src[start..].find("];").unwrap()];
    let core: Vec<&str> = scan["sources"]
        .as_array()
        .expect("scan sources")
        .iter()
        .filter_map(|s| s["id"].as_str())
        .collect();
    assert!(
        core.contains(&"plugins"),
        "core scan lists the plugins source"
    );
    let mut demo = Vec::new();
    for line in body.lines().filter(|l| l.contains("{ id: \"")) {
        let id = line.split('"').nth(1).unwrap();
        demo.push(id.to_string());
        if !line.contains("active: true") {
            assert!(
                core.contains(&id),
                "demo source {id} is unknown to the core"
            );
        }
    }
    assert!(
        demo.iter().any(|d| d == "plugins"),
        "demo lists the plugins source"
    );
}

fn repo_file(rel: &str) -> String {
    std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join(rel),
    )
    .unwrap()
}

/// The demo backend and docs/API.md keep up with core fields the shape check cannot see (it only
/// checks demo keys ⊆ engine keys): report_verify fields/statuses, Doc.error_kind and the
/// settings keys read by the core.
#[test]
fn demo_and_api_doc_list_core_fields() {
    let demo = repo_file("ui/js/demo-backend.js");
    let start = demo.find("report_verify: (").expect("demo report_verify");
    let body = &demo[start..start + demo[start..].find("\n    },").unwrap()];
    for k in VERIFY_KEYS {
        assert!(
            body.contains(&format!("{k}:")) || body.contains(&format!("{k},")),
            "demo report_verify lacks «{k}»"
        );
    }
    let api = repo_file("docs/API.md");
    let row = api
        .lines()
        .find(|l| l.starts_with("| `report_verify`"))
        .expect("report_verify row");
    for k in VERIFY_KEYS {
        assert!(row.contains(k), "API.md report_verify lacks «{k}»");
    }
    for s in VERIFY_STATUSES {
        assert!(
            row.contains(&format!("\"{s}\"")),
            "API.md report_verify lacks status {s}"
        );
    }
    let doc = &api[api.find("Doc { id,").expect("Doc block")..];
    let doc = &doc[..doc.find("\nPerson").unwrap()];
    assert!(
        doc.contains("error_kind?: \"parse\"|\"download\"|\"http\""),
        "API.md Doc lacks error_kind"
    );
    let settings = &api[api.find("Settings { net:").expect("Settings block")..];
    let settings = &settings[..settings.find("\nReportDraft").unwrap()];
    for k in ["block_shots", "company?"] {
        assert!(settings.contains(k), "API.md Settings lacks «{k}»");
    }
}
