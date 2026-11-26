//! Engine insights: web audit in the recon stage (passive profile = no requests to the
//! target, CSP hosts split into scope hosts and candidates), insight findings and people's org
//! chart fields, `insights_get` / `chain_get`, and report diagrams.

use crate::common::*;
use serde_json::{json, Value};

const WEB_MODULES: &[&str] = &[
    "recon.sourcemap",
    "recon.apidocs",
    "cors_origin",
    "http_options",
    "http_trace",
    "webdav_propfind",
    "graphql_introspection",
];

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn passive_web_audit_insights_chain_and_report_diagrams() {
    let e = env(0).await;
    let id = e.project("example.test").await;
    e.call(
        "scan_start",
        json!({ "project": id, "profile": "passive",
            "sources": ["crt", "wayback", "cc", "recon", "webaudit"] }),
    )
    .await;
    e.wait().await;
    let s = e.snap(&id).await;
    let r = &s["recon"];
    assert_eq!(r["sources"]["webaudit"]["status"], "ok", "{r}");
    let web = &r["web"][0];
    assert_eq!(web["level"], "passive", "{web}");
    assert_eq!(web["requests"], 0, "passive audit sends nothing: {web}");
    // CSP hosts: in scope → host list, outside → candidates only
    assert!(web["hosts"]
        .as_array()
        .unwrap()
        .iter()
        .any(|h| h == "api.example.test"));
    assert!(web["candidates"]
        .as_array()
        .unwrap()
        .iter()
        .any(|h| h == "cdn.partner-cdn.test"));
    let hosts = s["hosts"].as_array().unwrap();
    assert!(
        hosts.iter().any(|h| h["name"] == "api.example.test"),
        "{hosts:?}"
    );
    assert!(!hosts.iter().any(|h| h["name"] == "cdn.partner-cdn.test"));
    let oos = e.call("oos_list", json!({ "project": id })).await;
    assert!(
        oos.to_string().contains("cdn.partner-cdn.test"),
        "CSP candidate in oos: {oos}"
    );
    let findings = s["findings"].as_array().unwrap();
    let rules: Vec<&str> = findings
        .iter()
        .filter_map(|f| f["provenance"]["rule"].as_str())
        .collect();
    // The passive profile audits the archived copy: archive headers say nothing about the live
    // server, so no header findings; CSP-derived domains stay, marked as archive data.
    assert_eq!(web["from_archive"], true, "{web}");
    assert!(rules.contains(&"recon.web.csp_domains"), "{rules:?}");
    for unwanted in [
        "recon.web.csp_unsafe_inline",
        "recon.web.version_disclosure",
    ] {
        assert!(
            !rules.contains(&unwanted),
            "{unwanted} from archive headers: {rules:?}"
        );
    }
    // insight findings: KEV with cautious wording, org chart, internal network map
    for want in ["sw.kev", "org.structure", "net.internal_map"] {
        assert!(rules.contains(&want), "{want} missing: {rules:?}");
    }
    for f in findings
        .iter()
        .filter(|f| f["provenance"]["rule"] == "sw.kev")
    {
        let t = f["title"].as_str().unwrap();
        assert!(
            t.starts_with("Вероятно уязвимое ПО") || t.ends_with("сверьте версию"),
            "{t}"
        );
        assert!(f["description"]
            .as_str()
            .unwrap()
            .contains("сверьте версию"));
        assert!(!f["cve"].as_array().unwrap().is_empty());
    }
    let people = s["people"].as_array().unwrap();
    assert!(
        people
            .iter()
            .any(|p| p["dept"].is_string() && p["dept_conf"].is_number()),
        "org chart departments in people: {people:?}"
    );
    // no request of the web audit modules and nothing active in the passive profile
    let log = e
        .call("request_log_get", json!({ "project": id, "limit": 5000 }))
        .await;
    let rows: Vec<Value> = log
        .get("items")
        .or_else(|| log.get("rows"))
        .and_then(Value::as_array)
        .cloned()
        .or_else(|| log.as_array().cloned())
        .unwrap_or_default();
    assert!(!rows.is_empty(), "{log}");
    for r in &rows {
        let m = r["module"].as_str().unwrap_or("");
        assert!(
            !WEB_MODULES.contains(&m),
            "web audit request in passive: {r}"
        );
        assert_ne!(r["active"], true, "active request in passive: {r}");
        let host = r["host"].as_str().unwrap_or("");
        assert!(
            !host.ends_with("example.test") && !host.ends_with("partner-cdn.test"),
            "request to the target in passive: {r}"
        );
    }

    // insights_get
    let ins = e.call("insights_get", json!({ "project": id })).await;
    for k in [
        "org",
        "correlation",
        "anomalies",
        "kev",
        "netmap",
        "graph",
        "timeline",
        "activity",
        "counts",
        "layers",
    ] {
        assert!(ins.get(k).is_some(), "insights_get.{k}: {ins}");
    }
    let m = ins["activity"]["matrix"].as_array().unwrap();
    assert_eq!(m.len(), 7);
    assert!(m.iter().all(|r| r.as_array().unwrap().len() == 24));
    assert!(
        ins["graph"]["nodes"].as_array().unwrap().len() > 1,
        "{}",
        ins["graph"]
    );
    assert!(
        ins["counts"]["departments"].as_u64().unwrap() > 0,
        "{}",
        ins["counts"]
    );
    assert!(ins["netmap"]["nodes"].as_array().unwrap().len() > 1);
    assert!(ins["timeline"]
        .as_array()
        .unwrap()
        .iter()
        .any(|e| e["lane"] == "documents"));
    let only_people = e
        .call(
            "insights_get",
            json!({ "project": id, "layers": ["people", "docs"] }),
        )
        .await;
    assert!(only_people["graph"]["nodes"]
        .as_array()
        .unwrap()
        .iter()
        .all(|n| n["layer"] == "people" || n["layer"] == "docs"));

    // chain_get from a document finding and from a node
    let fd = findings
        .iter()
        .find(|f| f["doc"].is_number())
        .expect("a document finding");
    let ch = e
        .call("chain_get", json!({ "project": id, "from_id": fd["id"] }))
        .await;
    assert_eq!(ch["start"], format!("doc:{}", fd["doc"]), "{ch}");
    assert_eq!(ch["found"], true, "{ch}");
    assert!(ch["chains"].is_array());
    let by_node = e
        .call("chain_get", json!({ "project": id, "node": ch["start"] }))
        .await;
    assert_eq!(by_node["chains"], ch["chains"]);
    let bad = e
        .err("chain_get", json!({ "project": id, "from_id": 999999 }))
        .await;
    assert_eq!(bad.code, "not_found");

    // report diagrams: chronology and the activity heat map from the documents
    let rep = e
        .call(
            "report_build",
            json!({ "project": id, "opts": { "fmt": "html", "lang": "EN", "min_sev": "all",
                "confirmed": false } }),
        )
        .await;
    let html = std::fs::read_to_string(rep["path"].as_str().unwrap()).unwrap();
    assert!(html.contains("id=\"timeline\""), "chronology section");
    assert!(html.contains("id=\"activity\""), "activity section");
    assert!(html.contains("<svg"), "inline SVG");

    // attack_paths_get + cloud-only AI with live `ai_models_list` discovery
    let ap_rep = e.call("attack_paths_get", json!({ "project": id })).await;
    assert!(ap_rep["paths"].is_array());
    assert!(ap_rep["choke_points"].is_array());
    assert!(ap_rep["summary"]["total_paths"].is_u64());

    e.call("key_delete", json!({ "service": "ai" })).await;
    let before_reqs = e
        .call("request_log_get", json!({ "project": id, "limit": 5000 }))
        .await
        .as_array()
        .map_or(0, Vec::len);
    let no_key_models = e
        .call("ai_models_list", json!({ "provider": "openai" }))
        .await;
    assert_eq!(no_key_models["source"], "no_key");
    assert_eq!(no_key_models["models"].as_array().map_or(99, Vec::len), 0);

    let prev = e
        .call("ai_preview", json!({ "project": id, "opts": {} }))
        .await;
    assert_ne!(prev["provider"], "local");
    let er_no_key = e
        .err(
            "ai_summarize",
            json!({ "project": id, "preview_id": prev["id"], "opts": { "local": true } }),
        )
        .await;
    assert_eq!(
        er_no_key.code, "no_key",
        "local AI must be gone: missing key returns no_key"
    );

    let ai_secret = "sk-test-secret-9999";
    e.call("key_set", json!({ "service": "ai", "value": ai_secret }))
        .await;

    // Live model discovery across OpenAI, Anthropic, Gemini, OpenRouter, DeepSeek, Custom
    let openai_m = e
        .call("ai_models_list", json!({ "provider": "openai" }))
        .await;
    assert_eq!(openai_m["source"], "api");
    let openai_ids: Vec<&str> = openai_m["models"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|m| m["id"].as_str())
        .collect();
    assert!(openai_ids.contains(&"gpt-4.1-mini"), "{openai_ids:?}");
    assert!(
        !openai_ids.contains(&"text-embedding-3-small"),
        "non-chat embedding model must be filtered for openai"
    );

    // Second call uses in-memory cache; refresh=true re-queries API
    let cached_m = e
        .call("ai_models_list", json!({ "provider": "openai" }))
        .await;
    assert_eq!(cached_m["source"], "cache");
    let refreshed_m = e
        .call(
            "ai_models_list",
            json!({ "provider": "openai", "refresh": true }),
        )
        .await;
    assert_eq!(refreshed_m["source"], "api");

    let ant_m = e
        .call("ai_models_list", json!({ "provider": "anthropic" }))
        .await;
    assert_eq!(ant_m["source"], "api");
    assert_eq!(ant_m["models"][0]["id"], "claude-opus-5-5");
    assert_eq!(ant_m["models"][0]["thinking"], true);
    assert_eq!(ant_m["models"][0]["adaptive_thinking"], true);
    assert_eq!(ant_m["models"][0]["context_window"], 1_000_000);
    let ant_ids: Vec<&str> = ant_m["models"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|m| m["id"].as_str())
        .collect();
    assert!(
        !ant_ids.contains(&"claude-legacy-retired"),
        "retired models must be excluded by default"
    );
    let ant_all = e
        .call(
            "ai_models_list",
            json!({ "provider": "anthropic", "show_all": true }),
        )
        .await;
    assert_eq!(ant_all["models"].as_array().unwrap().len(), 3);

    let gem_m = e
        .call("ai_models_list", json!({ "provider": "gemini" }))
        .await;
    let gem_ids: Vec<&str> = gem_m["models"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|m| m["id"].as_str())
        .collect();
    assert!(gem_ids.contains(&"gemini-4-hydrogen"), "{gem_ids:?}");
    assert!(gem_ids.contains(&"gemini-2.5-flash"), "{gem_ids:?}");
    assert_eq!(gem_m["models"][0]["thinking"], true);
    assert!(
        !gem_ids.contains(&"gemini-embedding-001")
            && !gem_ids.contains(&"gemini-2.5-flash-preview-tts"),
        "non-chat gemini utility models must be filtered: {gem_ids:?}"
    );

    let custom_url = format!("{}/ai/custom", e.server.url());
    let cust_m = e
        .call(
            "ai_models_list",
            json!({ "provider": "custom", "base_url": custom_url }),
        )
        .await;
    assert_eq!(cust_m["models"][0]["id"], "custom-llm-70b");

    // Provider-specific model catalog formats & chat capability filtering
    let tog_m = e
        .call("ai_models_list", json!({ "provider": "together" }))
        .await;
    assert_eq!(
        tog_m["models"].as_array().unwrap().len(),
        1,
        "together top-level array must filter type != chat: {tog_m}"
    );
    assert_eq!(
        tog_m["models"][0]["id"],
        "meta-llama/Llama-3.3-70B-Instruct-Turbo"
    );

    let or_m = e
        .call("ai_models_list", json!({ "provider": "openrouter" }))
        .await;
    assert_eq!(
        or_m["models"].as_array().unwrap().len(),
        1,
        "openrouter must filter out image-only output_modalities: {or_m}"
    );
    assert_eq!(or_m["models"][0]["id"], "anthropic/claude-sonnet-4-5");

    let mis_m = e
        .call("ai_models_list", json!({ "provider": "mistral" }))
        .await;
    assert_eq!(mis_m["models"].as_array().unwrap().len(), 1);
    assert_eq!(mis_m["models"][0]["id"], "mistral-large-latest");

    let groq_m = e
        .call("ai_models_list", json!({ "provider": "groq" }))
        .await;
    assert_eq!(groq_m["models"].as_array().unwrap().len(), 1);
    assert_eq!(groq_m["models"][0]["id"], "llama-3.3-70b-versatile");

    let xai_m = e.call("ai_models_list", json!({ "provider": "xai" })).await;
    assert_eq!(xai_m["models"][0]["id"], "grok-4.6");

    // Anthropic /v1/messages adapter end-to-end (adaptive thinking + output_config.effort, no temperature)
    e.call(
        "settings_set",
        json!({ "patch": { "ai": { "provider": "anthropic", "model": "claude-opus-5-5", "thinking": "high", "temperature": 0.7, "show_thoughts": true } } }),
    )
    .await;
    let prev_ant = e
        .call("ai_preview", json!({ "project": id, "opts": {} }))
        .await;
    let sum_ant = e
        .call(
            "ai_summarize",
            json!({ "project": id, "preview_id": prev_ant["id"], "opts": {} }),
        )
        .await;
    assert!(sum_ant.get("local").is_none(), "must not emit local field");
    assert_eq!(sum_ant["provider"], "anthropic");
    assert_eq!(sum_ant["model"], "claude-opus-5-5");
    assert_eq!(sum_ant["tokens_in"], 210);
    assert_eq!(sum_ant["source_badge"], "Cloud API");
    assert_eq!(sum_ant["thoughts"], "internal");
    assert!(!sum_ant["md"].as_str().unwrap_or("").contains("internal"));
    assert!(sum_ant["md"]
        .as_str()
        .unwrap_or("")
        .contains("## Ключевые риски"));

    // The stored summary reaches the report as a labelled section; `ai_summary: false` drops it.
    let read = |rep: &serde_json::Value| {
        std::fs::read_to_string(rep["path"].as_str().expect("report path")).unwrap()
    };
    let rep = e
        .call(
            "report_build",
            json!({ "project": id, "opts": { "fmt": "md", "lang": "en" } }),
        )
        .await;
    let md = read(&rep);
    assert!(md.contains("## Executive summary (AI-assisted)"), "{md}");
    assert!(md.contains("Секреты в документах"), "{md}");
    assert!(md.contains("anthropic · claude-opus-5-5"), "{md}");
    let rep = e
        .call(
            "report_build",
            json!({ "project": id, "opts": { "fmt": "md", "lang": "en", "ai_summary": false } }),
        )
        .await;
    let md = read(&rep);
    assert!(!md.contains("Executive summary (AI-assisted)"), "{md}");

    let ant_req = e
        .server
        .requests()
        .into_iter()
        .find(|r| r.path() == "/ai/anthropic/messages")
        .expect("anthropic /messages request");
    assert_eq!(
        ant_req.headers.get("x-api-key").map(String::as_str),
        Some(ai_secret)
    );
    assert_eq!(
        ant_req.headers.get("anthropic-version").map(String::as_str),
        Some("2023-06-01")
    );
    let ant_body: Value = serde_json::from_slice(&ant_req.body).unwrap();
    assert!(
        ant_body.get("temperature").is_none(),
        "temperature must be omitted when Anthropic thinking is enabled"
    );
    assert_eq!(ant_body["max_tokens"], 16_384);
    assert_eq!(ant_body["thinking"]["type"], "adaptive");
    assert_eq!(ant_body["thinking"]["display"], "summarized");
    assert_eq!(ant_body["output_config"]["effort"], "high");

    // Google Gemini 4 native v1beta :generateContent (thinkingLevel, never thinkingBudget)
    e.call(
        "settings_set",
        json!({ "patch": { "ai": { "provider": "gemini", "model": "gemini-4-hydrogen", "thinking": "low", "temperature": null, "show_thoughts": true } } }),
    )
    .await;
    let prev_gem4 = e
        .call("ai_preview", json!({ "project": id, "opts": {} }))
        .await;
    let sum_gem4 = e
        .call(
            "ai_summarize",
            json!({ "project": id, "preview_id": prev_gem4["id"], "opts": {} }),
        )
        .await;
    assert_eq!(sum_gem4["model"], "gemini-4-hydrogen");
    assert_eq!(sum_gem4["thoughts"], "internal thought");
    assert_eq!(sum_gem4["tokens_thoughts"], 42);
    let gem4_req = e
        .server
        .requests()
        .into_iter()
        .find(|r| r.path() == "/ai/gemini/models/gemini-4-hydrogen:generateContent")
        .expect("native gemini 4 :generateContent request");
    let gem4_body: Value = serde_json::from_slice(&gem4_req.body).unwrap();
    assert_eq!(
        gem4_body["generationConfig"]["thinkingConfig"]["thinkingLevel"],
        "low"
    );
    assert!(
        gem4_body["generationConfig"]["thinkingConfig"]
            .get("thinkingBudget")
            .is_none(),
        "thinkingLevel and thinkingBudget are mutually exclusive"
    );
    assert_eq!(
        gem4_body["generationConfig"]["thinkingConfig"]["includeThoughts"],
        true
    );

    // Google Gemini 2.5 native v1beta :generateContent (thinkingBudget, hides thoughts when show_thoughts=false)
    e.call(
        "settings_set",
        json!({ "patch": { "ai": { "provider": "gemini", "model": "gemini-2.5-flash", "thinking": "medium", "thinking_budget": 2048, "show_thoughts": false } } }),
    )
    .await;
    let prev_gem = e
        .call("ai_preview", json!({ "project": id, "opts": {} }))
        .await;
    let sum_gem = e
        .call(
            "ai_summarize",
            json!({ "project": id, "preview_id": prev_gem["id"], "opts": {} }),
        )
        .await;
    assert_eq!(sum_gem["provider"], "gemini");
    assert_eq!(sum_gem["model"], "gemini-2.5-flash");
    assert_eq!(sum_gem["tokens_in"], 190);
    assert_eq!(sum_gem["tokens_out"], 33);
    assert_eq!(sum_gem["thoughts"], "");
    assert_eq!(
        sum_gem["md"],
        "## Ключевые риски\n1. Нативная сводка Gemini."
    );
    let gem_req = e
        .server
        .requests()
        .into_iter()
        .find(|r| r.path() == "/ai/gemini/models/gemini-2.5-flash:generateContent")
        .expect("native gemini :generateContent request");
    assert_eq!(
        gem_req.headers.get("x-goog-api-key").map(String::as_str),
        Some(ai_secret)
    );
    let gem25_body: Value = serde_json::from_slice(&gem_req.body).unwrap();
    assert_eq!(
        gem25_body["generationConfig"]["thinkingConfig"]["thinkingBudget"],
        2048
    );
    assert!(
        gem25_body["generationConfig"]["thinkingConfig"]
            .get("thinkingLevel")
            .is_none(),
        "Gemini 2.5 uses thinkingBudget only"
    );

    let after_reqs = e
        .call("request_log_get", json!({ "project": id, "limit": 5000 }))
        .await;
    let log_json = serde_json::to_string(&after_reqs).unwrap();
    assert!(
        !log_json.contains(ai_secret),
        "AI key leaked in request_log"
    );
    assert_eq!(
        after_reqs.as_array().map_or(0, Vec::len),
        before_reqs,
        "AI calls must use NullSink without polluting target request_log"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "live network test; run with FOCA_LIVE_GEMINI_KEY set"]
async fn live_gemini_end_to_end_from_env() {
    let key = std::env::var("FOCA_LIVE_GEMINI_KEY")
        .expect("set FOCA_LIVE_GEMINI_KEY to run live Gemini test");
    let dir = tempfile::tempdir().unwrap();
    let cfg = foca_engine::EngineConfig::new(dir.path());
    let sink: std::sync::Arc<dyn foca_engine::EventSink> =
        std::sync::Arc::new(foca_engine::FnEvents(|_: &Value| {}));
    let engine = foca_engine::Engine::open(
        cfg,
        std::sync::Arc::new(foca_engine::MemoryKeys::new()),
        sink,
    )
    .unwrap();
    let demo = engine
        .invoke("demo_case_import", json!({}))
        .await
        .expect("demo_case_import");
    let id = demo["project"].as_str().unwrap().to_string();
    engine
        .invoke("key_set", json!({ "service": "ai", "value": key }))
        .await
        .unwrap();

    let models_res = engine
        .invoke("ai_models_list", json!({ "provider": "gemini" }))
        .await
        .unwrap();
    assert_eq!(models_res["source"], "api", "{models_res}");
    let ids: Vec<String> = models_res["models"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|m| m["id"].as_str().map(String::from))
        .collect();
    println!("LIVE_GEMINI_FILTERED_COUNT={}", ids.len());
    println!("LIVE_GEMINI_SAMPLE={:?}", &ids[..ids.len().min(20)]);
    assert!(ids.iter().any(|m| m == "gemini-2.5-flash"));
    assert!(!ids
        .iter()
        .any(|m| m.contains("embedding") || m.ends_with("-tts")));

    let target_model = if ids.iter().any(|m| m == "gemini-4-hydrogen") {
        "gemini-4-hydrogen"
    } else {
        "gemini-2.5-flash"
    };
    engine
        .invoke(
            "settings_set",
            json!({ "patch": { "ai": { "provider": "gemini", "model": target_model } } }),
        )
        .await
        .unwrap();
    let prev = engine
        .invoke("ai_preview", json!({ "project": id, "opts": {} }))
        .await
        .unwrap();
    println!(
        "LIVE_PREVIEW_TOKENS={} REDACTED={} MARKS={}",
        prev["tokens"], prev["redacted"], prev["marks"]
    );
    assert!(prev["redacted"].as_u64().unwrap_or(0) > 0);

    let sum = match engine
        .invoke(
            "ai_summarize",
            json!({ "project": id, "preview_id": prev["id"], "opts": {} }),
        )
        .await
    {
        Ok(ok) => ok,
        Err(err) if target_model == "gemini-4-hydrogen" && err.message.contains("503") => {
            println!("LIVE_NOTE: gemini-4-hydrogen transient 503 ({err}), falling back to gemini-2.5-flash");
            engine
                .invoke(
                    "ai_summarize",
                    json!({
                        "project": id,
                        "preview_id": prev["id"],
                        "opts": { "provider": "gemini", "model": "gemini-2.5-flash" }
                    }),
                )
                .await
                .unwrap()
        }
        Err(err) => panic!("live ai_summarize failed: {err}"),
    };
    println!(
        "LIVE_SUM_PROVIDER={} MODEL={} TOKENS_IN={} TOKENS_OUT={}",
        sum["provider"], sum["model"], sum["tokens_in"], sum["tokens_out"]
    );
    println!("LIVE_SUM_MD:\n{}", sum["md"].as_str().unwrap_or(""));
    assert_eq!(sum["provider"], "gemini");
    assert_eq!(sum["source_badge"], "Cloud API");
    assert!(sum.get("local").is_none());
    assert!(!sum["md"].as_str().unwrap_or("").trim().is_empty());

    let log_json = serde_json::to_string(
        &engine
            .invoke("request_log_get", json!({ "project": id, "limit": 5000 }))
            .await
            .unwrap(),
    )
    .unwrap();
    assert!(
        !log_json.contains(&key),
        "live AI key leaked into request_log"
    );
}
