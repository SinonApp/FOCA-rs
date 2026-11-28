//! Shared harness for integration tests: a local source server (Wayback CDX, crt.sh, document
//! copies from `tests/corpus`), static DNS, and an engine on a temporary directory.
#![allow(dead_code)]

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use foca_engine::{Engine, EngineConfig, EventSink, FnEvents, MemoryKeys};
use foca_net::dns::StaticDns;
use foca_net::testserver::{TestResponse, TestServer};
use serde_json::{json, Value};
use time::macros::datetime;

pub fn corpus_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/corpus")
}

/// Documents "stored in the web archive" of example.test.
pub const DOCS: &[&str] = &[
    "ooxml/contract.docx",
    "ooxml/schedule.xlsx",
    "ooxml/strategy.pptx",
    "pdf/report.pdf",
    "images/photo.jpg",
    "remote/SRV-TS01.rdp",
    "odf/letter.odt",
    "ole/legacy.doc",
];

pub const ZONE: &str = "
example.test A 127.0.0.1
example.test MX 10 mail.example.test
example.test TXT \"v=spf1 ip4:127.0.0.1 ~all\"
example.test NS ns1.example.test
_dmarc.example.test TXT \"v=DMARC1; p=none\"
www.example.test A 127.0.0.1
mail.example.test A 127.0.0.2
ns1.example.test A 127.0.0.1
old.example.test CNAME ghost-app.azurewebsites.net
";

pub type Events = Arc<Mutex<Vec<Value>>>;
pub type PauseAt = Arc<Mutex<Option<String>>>;

pub struct Env {
    pub dir: tempfile::TempDir,
    pub server: TestServer,
    pub engine: Engine,
    pub events: Arc<Mutex<Vec<Value>>>,
    /// Stage at which the event handler pauses the scan itself (a deterministic stop).
    pub pause_at: Arc<Mutex<Option<String>>>,
    pub keys: Arc<MemoryKeys>,
}

pub async fn server(delay_ms: u64) -> TestServer {
    let mut files: HashMap<String, Vec<u8>> = HashMap::new();
    for d in DOCS {
        let name = d.rsplit('/').next().unwrap().to_string();
        files.insert(name, std::fs::read(corpus_dir().join(d)).unwrap());
    }
    TestServer::start(move |r| {
        let p = r.path().to_string();
        if let Some(r) = recon_route(&p, r.query("url").as_deref()) {
            return r;
        }
        if p == "/cdx/search/cdx" {
            let mut rows = vec![json!(["timestamp", "original", "mimetype", "length", "statuscode"])];
            for d in DOCS {
                let name = d.rsplit('/').next().unwrap();
                rows.push(json!(["20240301000000", format!("https://example.test/upload/{name}"), "application/octet-stream", "1000", "200"]));
            }
            return TestResponse::ok(serde_json::to_vec(&rows).unwrap());
        }
        if p == "/" && r.query("output").is_some() {
            return TestResponse::ok(
                br#"[{"name_value":"www.example.test\nmail.example.test\nold.example.test"},{"name_value":"dev.example.test"}]"#.to_vec(),
            );
        }
        if p.starts_with("/web/") {
            let name = p.rsplit('/').next().unwrap_or("");
            if let Some(b) = files.get(name) {
                let mut resp = TestResponse::ok(b.clone());
                if delay_ms > 0 && r.method == "GET" {
                    resp = resp.delay(Duration::from_millis(delay_ms));
                }
                return resp;
            }
        }
        if p == "/collinfo.json" {
            return TestResponse::ok(b"[]".to_vec());
        }
        if let Some(prefix) = p.strip_prefix("/range/") {
            if prefix.len() == 5 {
                // Dummy padded HIBP k-anonymity range response (decoy :0 + one synthetic count)
                return TestResponse::ok(
                    b"00000000000000000000000000000000000:0\n1E4C9B93F3F0682250B6CF8331B7EE68FD8:12345\n"
                        .to_vec(),
                );
            }
        }
        if p == "/ip" {
            return TestResponse::ok(br#"{"ip":"203.0.113.7"}"#.to_vec());
        }
        if p.starts_with("/geo/") {
            return TestResponse::ok(br#"{"ip":"203.0.113.7","country":"DE"}"#.to_vec());
        }
        if p == "/ai/anthropic/models" {
            let has_key = r.headers.get("x-api-key").is_some_and(|v| !v.is_empty());
            let has_ver = r
                .headers
                .get("anthropic-version")
                .is_some_and(|v| !v.is_empty());
            if !has_key || !has_ver {
                return TestResponse::status(401);
            }
            return TestResponse::ok(
                br#"{"data":[{"id":"claude-opus-5-5","display_name":"Claude Opus 5.5","lifecycle":"active","max_input_tokens":1000000,"max_tokens":64000,"capabilities":{"thinking":{"supported":true,"types":{"adaptive":{"supported":true},"enabled":{"supported":false}}}}},{"id":"claude-sonnet-4-5","display_name":"Claude Sonnet 4.5","lifecycle":"active","capabilities":{"thinking":{"supported":true,"types":{"adaptive":{"supported":false},"enabled":{"supported":true}}}}},{"id":"claude-legacy-retired","display_name":"Retired","lifecycle":"retired"}]}"#.to_vec(),
            );
        }
        if p == "/ai/anthropic/messages" {
            let has_key = r.headers.get("x-api-key").is_some_and(|v| !v.is_empty());
            let has_ver = r
                .headers
                .get("anthropic-version")
                .is_some_and(|v| !v.is_empty());
            if !has_key || !has_ver {
                return TestResponse::status(401);
            }
            return TestResponse::ok(
                r###"{"model":"claude-opus-5-5","content":[{"type":"thinking","thinking":"internal"},{"type":"text","text":"## Ключевые риски\n1. Секреты в документах."}],"usage":{"input_tokens":210,"output_tokens":44}}"###.as_bytes().to_vec(),
            );
        }
        if p == "/ai/gemini/models" {
            let has_key = r.headers.get("x-goog-api-key").is_some_and(|v| !v.is_empty());
            if !has_key {
                return TestResponse::status(401);
            }
            return TestResponse::ok(
                br#"{"models":[{"name":"models/gemini-4-hydrogen","displayName":"Gemini 4 Hydrogen","thinking":true,"inputTokenLimit":1048576,"outputTokenLimit":65536,"supportedGenerationMethods":["generateContent","countTokens"]},{"name":"models/gemini-2.5-flash","displayName":"Gemini 2.5 Flash","thinking":true,"supportedGenerationMethods":["generateContent","countTokens"]},{"name":"models/gemini-embedding-001","displayName":"Gemini Embedding 001","supportedGenerationMethods":["embedContent"]},{"name":"models/gemini-2.5-flash-preview-tts","displayName":"Gemini 2.5 Flash TTS","supportedGenerationMethods":["generateContent"]}]}"#.to_vec(),
            );
        }
        if p == "/ai/gemini/models/gemini-2.5-flash:generateContent"
            || p == "/ai/gemini/models/gemini-4-hydrogen:generateContent"
        {
            let has_key = r.headers.get("x-goog-api-key").is_some_and(|v| !v.is_empty());
            if !has_key {
                return TestResponse::status(401);
            }
            let ver = if p.contains("gemini-4-hydrogen") {
                "gemini-4-hydrogen"
            } else {
                "gemini-2.5-flash"
            };
            let body = format!(
                r###"{{"modelVersion":"{ver}","candidates":[{{"content":{{"parts":[{{"text":"internal thought","thought":true}},{{"text":"## Ключевые риски\n1. Нативная сводка Gemini."}}]}}}}],"usageMetadata":{{"promptTokenCount":190,"candidatesTokenCount":33,"thoughtsTokenCount":42}}}}"###
            );
            return TestResponse::ok(body.into_bytes());
        }
        if p == "/ai/together/models" {
            let has_bearer = r
                .headers
                .get("authorization")
                .is_some_and(|v| v.starts_with("Bearer ") && v.len() > 7);
            if !has_bearer {
                return TestResponse::status(401);
            }
            return TestResponse::ok(
                br#"[{"id":"meta-llama/Llama-3.3-70B-Instruct-Turbo","type":"chat","display_name":"Llama 3.3 70B"},{"id":"togethercomputer/m2-bert-80M","type":"embedding","display_name":"BERT"}]"#.to_vec(),
            );
        }
        if p == "/ai/openrouter/models" {
            let has_bearer = r
                .headers
                .get("authorization")
                .is_some_and(|v| v.starts_with("Bearer ") && v.len() > 7);
            if !has_bearer {
                return TestResponse::status(401);
            }
            return TestResponse::ok(
                br#"{"data":[{"id":"anthropic/claude-sonnet-4-5","name":"Claude Sonnet 4.5","architecture":{"output_modalities":["text"]}},{"id":"black-forest-labs/flux","name":"FLUX","architecture":{"output_modalities":["image"]}}]}"#.to_vec(),
            );
        }
        if p == "/ai/mistral/models" {
            let has_bearer = r
                .headers
                .get("authorization")
                .is_some_and(|v| v.starts_with("Bearer ") && v.len() > 7);
            if !has_bearer {
                return TestResponse::status(401);
            }
            return TestResponse::ok(
                br#"{"data":[{"id":"mistral-large-latest","capabilities":{"completion_chat":true}},{"id":"mistral-embed","capabilities":{"completion_chat":false}}]}"#.to_vec(),
            );
        }
        if p == "/ai/groq/models" {
            let has_bearer = r
                .headers
                .get("authorization")
                .is_some_and(|v| v.starts_with("Bearer ") && v.len() > 7);
            if !has_bearer {
                return TestResponse::status(401);
            }
            return TestResponse::ok(
                br#"{"data":[{"id":"llama-3.3-70b-versatile"},{"id":"whisper-large-v3"},{"id":"playai-tts"}]}"#.to_vec(),
            );
        }
        if matches!(
            p.as_str(),
            "/ai/models" | "/ai/openai/models" | "/ai/deepseek/models" | "/ai/xai/models" | "/ai/custom/models"
        ) {
            let has_bearer = r
                .headers
                .get("authorization")
                .is_some_and(|v| v.starts_with("Bearer ") && v.len() > 7);
            if !has_bearer {
                return TestResponse::status(401);
            }
            let model_id = if p.contains("/openai/") {
                "gpt-4.1-mini"
            } else if p.contains("/xai/") {
                "grok-4.6"
            } else if p.contains("/custom/") {
                "custom-llm-70b"
            } else {
                "deepseek-chat"
            };
            let body = json!({
                "data": [
                    { "id": model_id, "name": model_id },
                    { "id": "text-embedding-3-small", "name": "text-embedding-3-small" }
                ]
            });
            return TestResponse::ok(serde_json::to_vec(&body).unwrap());
        }
        // slow OpenAI-compatible endpoint (custom provider): in-flight and cancel tests
        if p == "/ai/slow/chat/completions" {
            return TestResponse::ok(
                br###"{"model":"slow-model","choices":[{"message":{"content":"## Key risks\n1. [CLIENT] leaks passwords on www.[CLIENT-DOMAIN]."}}],"usage":{"prompt_tokens":10,"completion_tokens":5}}"###.to_vec(),
            )
            .delay(Duration::from_millis(700));
        }
        // reasoning models: answer plus reasoning, reasoning only (token limit), a stream
        if p == "/ai/reason/chat/completions" {
            return TestResponse::ok(
                br###"{"model":"reason-model","choices":[{"message":{"content":"## Summary\n1. Exposed documents.","reasoning_content":"First I look at the findings."}}],"usage":{"prompt_tokens":10,"completion_tokens":40,"completion_tokens_details":{"reasoning_tokens":30}}}"###.to_vec(),
            );
        }
        if p == "/ai/thinkonly/chat/completions" {
            return TestResponse::ok(
                br###"{"model":"reason-model","choices":[{"message":{"content":"","reasoning_content":"Still thinking about the findings..."},"finish_reason":"length"}],"usage":{"prompt_tokens":10,"completion_tokens":64}}"###.to_vec(),
            );
        }
        if p == "/ai/sse/chat/completions" {
            return TestResponse::ok(
                b"data: {\"model\":\"sse-model\",\"choices\":[{\"delta\":{\"reasoning_content\":\"Hm.\"}}]}\n\ndata: {\"choices\":[{\"delta\":{\"content\":\"## Streamed\"}}]}\n\ndata: {\"choices\":[{\"delta\":{\"content\":\" summary\"}}],\"usage\":{\"prompt_tokens\":9,\"completion_tokens\":3}}\n\ndata: [DONE]\n\n".to_vec(),
            )
            .header("content-type", "text/event-stream");
        }
        if p == "/ai/chat/completions" || p.ends_with("/chat/completions") && p.starts_with("/ai/")
        {
            return TestResponse::ok(
                r###"{"model":"deepseek-chat","choices":[{"message":{"content":"## Ключевые риски\n1. Пароли в документах."}}],"usage":{"prompt_tokens":321,"completion_tokens":12}}"###.as_bytes().to_vec(),
            );
        }
        TestResponse::status(404)
    })
    .await
}

/// Offline site reconnaissance fixtures (foca-recon): an archived example.test home page, a favicon,
/// a script with an endpoint and a key, robots.txt in CDX/archive, and a grep.app 429 challenge.
pub fn recon_route(p: &str, cdx_url: Option<&str>) -> Option<TestResponse> {
    if p == "/api/search" {
        return Some(TestResponse {
            status: 429,
            ..TestResponse::ok(br#"{"error":{"code":"challenge"}}"#.to_vec())
                .header("content-type", "application/json")
        });
    }
    if p == "/cdx/search/cdx" && cdx_url.is_some_and(|u| u.ends_with("robots.txt")) {
        return Some(TestResponse::ok(
            b"test,example)/robots.txt 20250101000000 https://example.test/robots.txt text/plain 200 RBT1 120\n"
                .to_vec(),
        ));
    }
    if p == "/cdx/search/cdx"
        && cdx_url.is_some_and(|u| u.ends_with("sitemap.xml") || u.ends_with("security.txt"))
    {
        return Some(TestResponse::ok(Vec::new()));
    }
    let orig = p.strip_prefix("/web/")?.split_once("id_/")?.1;
    let path = orig
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .trim_start_matches("example.test");
    match path {
        "/" => Some(
            TestResponse::ok(
                br#"<html><head><link rel="icon" href="/favicon.ico"><script src="/js/jquery-1.8.2.min.js"></script>
<script src="/app.js"></script><script>gtag('config', 'G-ABC123XYZ9');</script></head>
<body><a href="https://contoso-backup.s3.amazonaws.com/report.pdf">pdf</a></body></html>"#
                    .to_vec(),
            )
            .header("x-archive-orig-server", "nginx/1.18.0")
            .header(
                "x-archive-orig-content-security-policy",
                "default-src 'self'; script-src 'self' 'unsafe-inline' https://api.example.test https://cdn.partner-cdn.test; connect-src https://staging-api.example.test",
            ),
        ),
        "/favicon.ico" => Some(TestResponse::ok(vec![0u8, 0, 1, 0, 1, 0, 16, 16, 0, 0, 1, 0])),
        "/app.js" => {
            let key = format!("{}{}", "AKIA", "Q7XK2M9PLR4TZW8N");
            Some(TestResponse::ok(
                format!("fetch('/api/v2/users');const k=\"{key}\";").into_bytes(),
            ))
        }
        "/robots.txt" => Some(TestResponse::ok(
            b"User-agent: *\nDisallow: /admin/\nDisallow: /backup/\n".to_vec(),
        )),
        _ => None,
    }
}

pub fn config(dir: &Path, base: &str) -> EngineConfig {
    let mut cfg = EngineConfig::new(dir);
    cfg.clock = Arc::new(foca_core::ManualClock::new(datetime!(2026-11-20 10:00 UTC)));
    cfg.utc_offset = time::UtcOffset::from_hms(2, 0, 0).unwrap();
    cfg.endpoints.wayback = base.into();
    cfg.endpoints.crtsh = base.into();
    cfg.endpoints.cc_collinfo = format!("{base}/collinfo.json");
    cfg.endpoints.rdap = foca_net::rdap::RdapEndpoints {
        ripestat: format!("{base}/ripe"),
        rdap: format!("{base}/rdap"),
    };
    cfg.endpoints
        .ai
        .insert("deepseek".into(), format!("{base}/ai"));
    cfg.endpoints
        .ai
        .insert("openai".into(), format!("{base}/ai/openai"));
    cfg.endpoints
        .ai
        .insert("anthropic".into(), format!("{base}/ai/anthropic"));
    cfg.endpoints
        .ai
        .insert("gemini".into(), format!("{base}/ai/gemini"));
    cfg.endpoints
        .ai
        .insert("xai".into(), format!("{base}/ai/xai"));
    cfg.endpoints
        .ai
        .insert("mistral".into(), format!("{base}/ai/mistral"));
    cfg.endpoints
        .ai
        .insert("groq".into(), format!("{base}/ai/groq"));
    cfg.endpoints
        .ai
        .insert("together".into(), format!("{base}/ai/together"));
    cfg.endpoints
        .ai
        .insert("openrouter".into(), format!("{base}/ai/openrouter"));
    cfg.endpoints.ip_echo = format!("{base}/ip");
    // the update check asks the local server (404 there), never api.github.com
    cfg.endpoints.github_api = format!("{base}/gh");
    // the signature feeds too (404 there: `no_update`)
    cfg.endpoints.sig_feed = format!("{base}/sig-feed/signatures-v3.bundle");
    cfg.endpoints.sig_feed_fallback = format!("{base}/sig-feed/signatures.bundle");
    cfg.endpoints.ip_geo = format!("{base}/geo/{{ip}}");
    // keyless sources point only at the local server (tests make no internet requests)
    for id in foca_engine::HOST_SOURCE_IDS
        .iter()
        .chain(foca_engine::DOC_SOURCE_IDS)
        .chain(&["internetdb", "grepapp", "hibp"])
        .chain(foca_engine::INFRA_SOURCE_IDS)
    {
        cfg.endpoints.sources.insert(id.to_string(), base.into());
    }
    cfg.dns = Some(Arc::new(StaticDns::from_zone_text(ZONE)));
    cfg.passive_download_hosts = vec!["127.0.0.1".into()];
    let port = base.rsplit(':').next().unwrap().parse::<u16>().unwrap();
    cfg.alive_ports = vec![port];
    for h in ["example.test", "www.example.test", "ns1.example.test"] {
        cfg.net
            .host_overrides
            .insert(h.into(), vec!["127.0.0.1".parse().unwrap()]);
    }
    cfg.net.global_rps = None;
    cfg.net.source_rps.clear();
    cfg.net.retries = 0;
    cfg.meta_concurrency = 2;
    cfg.dns_unthrottled = true;
    cfg
}

pub fn open(dir: &Path, base: &str, keys: Arc<MemoryKeys>) -> (Engine, Events, PauseAt) {
    open_with(dir, base, keys, |_| {})
}

/// Like [`open`], but with a tweak to the engine configuration (for example `fuzz_unthrottled`).
pub fn open_with(
    dir: &Path,
    base: &str,
    keys: Arc<MemoryKeys>,
    tweak: impl FnOnce(&mut EngineConfig),
) -> (Engine, Events, PauseAt) {
    let events: Arc<Mutex<Vec<Value>>> = Arc::new(Mutex::new(Vec::new()));
    let pause_at: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    let cell: Arc<OnceLock<Engine>> = Arc::new(OnceLock::new());
    let (ev, pa, c2) = (events.clone(), pause_at.clone(), cell.clone());
    let sink: Arc<dyn EventSink> = Arc::new(FnEvents(move |e: &Value| {
        ev.lock().unwrap().push(e.clone());
        if e["type"] == "stage" {
            let want = pa.lock().unwrap().clone();
            if want.as_deref() == e["stage"].as_str() {
                if let Some(en) = c2.get() {
                    en.pause("test");
                }
            }
        }
    }));
    let mut cfg = config(dir, base);
    tweak(&mut cfg);
    let engine = Engine::open(cfg, keys, sink).unwrap();
    let _ = cell.set(engine.clone());
    (engine, events, pause_at)
}

pub async fn env(delay_ms: u64) -> Env {
    let dir = tempfile::tempdir().unwrap();
    let server = server(delay_ms).await;
    let keys = Arc::new(MemoryKeys::new());
    let (engine, events, pause_at) = open(dir.path(), &server.url(), keys.clone());
    Env {
        dir,
        server,
        engine,
        events,
        pause_at,
        keys,
    }
}

impl Env {
    pub async fn call(&self, cmd: &str, args: Value) -> Value {
        match self.engine.invoke(cmd, args.clone()).await {
            Ok(v) => v,
            Err(e) => panic!("{cmd} {args}: {e}"),
        }
    }

    pub async fn err(&self, cmd: &str, args: Value) -> foca_engine::CmdError {
        self.engine
            .invoke(cmd, args)
            .await
            .expect_err("expected an error")
    }

    /// Creates the example.test project with mail.* excluded.
    pub async fn project(&self, name: &str) -> String {
        let p = self
            .call(
                "project_create",
                json!({ "name": name, "client": "ТОВ «Приклад»",
                    "targets": [{ "v": "example.test", "type": "domain" }],
                    "excludes": ["mail.example.test"] }),
            )
            .await;
        p["id"].as_str().unwrap().to_string()
    }

    pub async fn wait(&self) {
        assert!(
            self.engine.wait_idle(Duration::from_secs(120)).await,
            "the scan did not finish"
        );
    }

    /// Waits for the pause at a stage (the event handler sets it via `pause_at`).
    pub async fn wait_paused(&self, stage: &str) {
        for _ in 0..3000 {
            let s = self.engine.invoke("scan_status", json!({})).await.unwrap();
            if s["paused"] == true && s["stage"] == stage {
                return;
            }
            if s["running"] == false {
                panic!("the scan finished without pausing at {stage}");
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("no pause at {stage}");
    }

    pub fn events(&self) -> Vec<Value> {
        self.events.lock().unwrap().clone()
    }

    pub fn clear_events(&self) {
        self.events.lock().unwrap().clear();
    }

    pub async fn snap(&self, id: &str) -> Value {
        self.call("project_snapshot", json!({ "id": id })).await
    }

    pub async fn passive_scan(&self, id: &str) -> Value {
        let r = self
            .call(
                "scan_start",
                json!({ "project": id, "profile": "passive", "sources": ["crt", "wayback", "cc"] }),
            )
            .await;
        self.wait().await;
        r
    }
}

/// Returns counters as shown on screen: documents, parsed, people, software, secrets, open findings.
pub fn counts(s: &Value) -> Value {
    let docs = s["docs"].as_array().unwrap();
    let live: Vec<&Value> = docs.iter().filter(|d| d["deleted"] != true).collect();
    let open = s["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|f| f["status"] != "false" && f["status"] != "fixed")
        .count();
    json!({
        "docs": live.len(),
        "analyzed": live.iter().filter(|d| d["status"] == "analyzed").count(),
        "people": s["people"].as_array().unwrap().len(),
        "software": s["software"].as_array().unwrap().len(),
        "secrets": s["secrets"].as_array().unwrap().len(),
        "findings": open,
    })
}
