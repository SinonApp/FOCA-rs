//! AI provider protocol: request bodies and headers per provider, response parsing and model
//! list filtering.

use foca_net::NetRequest;
use serde_json::{json, Value};

use crate::CmdError;

pub(crate) fn attach_ai_headers(req: NetRequest, provider: &str, key: &str) -> NetRequest {
    match provider {
        "anthropic" => req
            .header("x-api-key", key)
            .header("anthropic-version", "2023-06-01"),
        "gemini" => req.header("x-goog-api-key", key),
        "openrouter" => req
            .header("Authorization", &format!("Bearer {key}"))
            .header("HTTP-Referer", "https://github.com/SinonApp/FOCA-rs")
            .header("X-OpenRouter-Title", "FOCA-rs")
            .header("X-Title", "FOCA-rs"),
        _ => req.header("Authorization", &format!("Bearer {key}")),
    }
}

#[derive(Debug, Clone)]
pub(crate) struct AiGenOpts {
    thinking: String,
    thinking_budget: u64,
    max_tokens: u64,
    temperature: Option<f64>,
    show_thoughts: bool,
}

impl AiGenOpts {
    pub(crate) fn show_thoughts(&self) -> bool {
        self.show_thoughts
    }

    pub(crate) fn from_values(opts: &Value, ai_cfg: &Value) -> Self {
        let raw_th = opts["thinking"]
            .as_str()
            .or_else(|| ai_cfg["thinking"].as_str())
            .unwrap_or("auto")
            .trim()
            .to_ascii_lowercase();
        let thinking = match raw_th.as_str() {
            "off" | "minimal" | "low" | "medium" | "high" | "xhigh" | "max" => raw_th,
            _ => "auto".to_string(),
        };
        let thinking_budget = opts["thinking_budget"]
            .as_u64()
            .or_else(|| ai_cfg["thinking_budget"].as_u64())
            .unwrap_or(0)
            .min(65_536);
        let max_tokens = opts["max_tokens"]
            .as_u64()
            .or_else(|| ai_cfg["max_tokens"].as_u64())
            .unwrap_or(0)
            .min(65_536);
        let temperature = opts
            .get("temperature")
            .and_then(|v| {
                if v.is_null() {
                    Some(None)
                } else {
                    v.as_f64().map(Some)
                }
            })
            .unwrap_or_else(|| ai_cfg.get("temperature").and_then(Value::as_f64))
            .filter(|t| t.is_finite())
            .map(|t| t.clamp(0.0, 2.0));
        let show_thoughts = opts["show_thoughts"]
            .as_bool()
            .or_else(|| ai_cfg["show_thoughts"].as_bool())
            .unwrap_or(false);
        Self {
            thinking,
            thinking_budget,
            max_tokens,
            temperature,
            show_thoughts,
        }
    }

    fn thinking_active(&self) -> bool {
        (self.thinking != "auto" && self.thinking != "off") || self.thinking_budget > 0
    }
}

pub(crate) fn build_ai_request(
    provider: &str,
    base: &str,
    model: &str,
    system_prompt: &str,
    user_text: &str,
    gen_opts: &AiGenOpts,
    model_meta: Option<&Value>,
) -> Result<(String, Value), CmdError> {
    match provider {
        "anthropic" => {
            let mut max_tokens = if gen_opts.max_tokens > 0 {
                gen_opts.max_tokens
            } else if gen_opts.thinking_active() {
                16_384
            } else {
                8_192
            };
            let mut body = serde_json::Map::new();
            body.insert("model".into(), json!(model));
            body.insert("system".into(), json!(system_prompt));
            body.insert(
                "messages".into(),
                json!([{ "role": "user", "content": user_text }]),
            );
            if gen_opts.thinking == "off" {
                body.insert("thinking".into(), json!({ "type": "disabled" }));
            } else if gen_opts.thinking_active() {
                let adaptive_supported = model_meta
                    .and_then(|m| m["adaptive_thinking"].as_bool())
                    .unwrap_or_else(|| {
                        let lc = model.to_ascii_lowercase();
                        lc.contains("4-6") || lc.contains("4.6")
                    });
                let manual_supported = model_meta
                    .and_then(|m| m["manual_thinking"].as_bool())
                    .unwrap_or(!adaptive_supported);
                let use_manual_budget =
                    !adaptive_supported || (gen_opts.thinking_budget > 0 && manual_supported);
                if use_manual_budget {
                    let fallback_budget = match gen_opts.thinking.as_str() {
                        "minimal" => 1024,
                        "low" => 2048,
                        "medium" => 4096,
                        "high" => 8192,
                        "xhigh" => 16_384,
                        "max" => 24_576,
                        _ => 4096,
                    };
                    let raw_budget = if gen_opts.thinking_budget > 0 {
                        gen_opts.thinking_budget
                    } else {
                        fallback_budget
                    };
                    let budget = raw_budget.clamp(1024, 32_768);
                    if max_tokens <= budget {
                        max_tokens = (budget + 4096).min(65_536);
                    }
                    let mut th = serde_json::Map::new();
                    th.insert("type".into(), json!("enabled"));
                    th.insert("budget_tokens".into(), json!(budget));
                    if gen_opts.show_thoughts {
                        th.insert("display".into(), json!("summarized"));
                    }
                    body.insert("thinking".into(), Value::Object(th));
                } else {
                    let mut th = serde_json::Map::new();
                    th.insert("type".into(), json!("adaptive"));
                    if gen_opts.show_thoughts {
                        th.insert("display".into(), json!("summarized"));
                    }
                    body.insert("thinking".into(), Value::Object(th));
                    if gen_opts.thinking != "auto" {
                        let effort = match gen_opts.thinking.as_str() {
                            "minimal" | "low" => "low",
                            "medium" => "medium",
                            "high" => "high",
                            "xhigh" => "xhigh",
                            "max" => "max",
                            _ => "medium",
                        };
                        body.insert("output_config".into(), json!({ "effort": effort }));
                    }
                }
            }
            body.insert("max_tokens".into(), json!(max_tokens));
            // Anthropic rejects non-default temperature when thinking is enabled.
            if let Some(t) = gen_opts.temperature {
                if !gen_opts.thinking_active() {
                    body.insert("temperature".into(), json!(t.clamp(0.0, 1.0)));
                }
            }
            Ok((format!("{base}/messages"), Value::Object(body)))
        }
        "gemini" => {
            if model.contains('/')
                || model.contains('?')
                || model.contains('#')
                || model.contains("..")
            {
                return Err(CmdError::new(
                    "bad_input",
                    "Некорректный идентификатор модели",
                ));
            }
            let mut body = serde_json::Map::new();
            body.insert(
                "systemInstruction".into(),
                json!({ "parts": [{ "text": system_prompt }] }),
            );
            body.insert(
                "contents".into(),
                json!([{ "role": "user", "parts": [{ "text": user_text }] }]),
            );
            let mut gen_cfg = serde_json::Map::new();
            if gen_opts.max_tokens > 0 {
                gen_cfg.insert("maxOutputTokens".into(), json!(gen_opts.max_tokens));
            }
            if let Some(t) = gen_opts.temperature {
                gen_cfg.insert("temperature".into(), json!(t));
            }
            // Gemini REST rule: `thinkingLevel` (Gemini 3/4+) and `thinkingBudget` (Gemini 2.5)
            // are mutually exclusive: never send both in the same `thinkingConfig`.
            let thinking_supported = model_meta.and_then(|m| m["thinking"].as_bool());
            let lc_model = model.to_ascii_lowercase();
            let is_gemini_25 = lc_model.contains("2.5");
            let is_gemini_25_pro = lc_model.contains("2.5-pro");
            let mut th_cfg = serde_json::Map::new();
            if thinking_supported != Some(false) {
                if is_gemini_25 {
                    if gen_opts.thinking == "off" {
                        if !is_gemini_25_pro {
                            th_cfg.insert("thinkingBudget".into(), json!(0));
                        }
                    } else if gen_opts.thinking_budget > 0 {
                        th_cfg.insert(
                            "thinkingBudget".into(),
                            json!(gen_opts.thinking_budget.clamp(128, 32_768)),
                        );
                    } else if gen_opts.thinking != "auto" {
                        let budget = match gen_opts.thinking.as_str() {
                            "minimal" => 512,
                            "low" => 1024,
                            "medium" => 4096,
                            "high" => 8192,
                            "xhigh" | "max" => 16_384,
                            _ => -1,
                        };
                        th_cfg.insert("thinkingBudget".into(), json!(budget));
                    }
                } else if gen_opts.thinking != "auto"
                    && (gen_opts.thinking != "off" || thinking_supported == Some(true))
                {
                    let level = match gen_opts.thinking.as_str() {
                        "off" | "minimal" => "minimal",
                        "low" => "low",
                        "medium" => "medium",
                        "high" | "xhigh" | "max" => "high",
                        _ => "medium",
                    };
                    th_cfg.insert("thinkingLevel".into(), json!(level));
                }
                if gen_opts.show_thoughts && gen_opts.thinking != "off" {
                    th_cfg.insert("includeThoughts".into(), json!(true));
                }
            }
            if !th_cfg.is_empty() {
                gen_cfg.insert("thinkingConfig".into(), Value::Object(th_cfg));
            }
            if !gen_cfg.is_empty() {
                body.insert("generationConfig".into(), Value::Object(gen_cfg));
            }
            Ok((
                format!("{base}/models/{model}:generateContent"),
                Value::Object(body),
            ))
        }
        _ => {
            let mut body = serde_json::Map::new();
            body.insert("model".into(), json!(model));
            body.insert(
                "messages".into(),
                json!([
                    { "role": "system", "content": system_prompt },
                    { "role": "user", "content": user_text },
                ]),
            );
            if gen_opts.max_tokens > 0 {
                let key = if matches!(provider, "openai" | "xai" | "groq") {
                    "max_completion_tokens"
                } else {
                    "max_tokens"
                };
                body.insert(key.into(), json!(gen_opts.max_tokens));
            }
            match provider {
                "openai" => {
                    if gen_opts.thinking != "auto" {
                        let effort = match gen_opts.thinking.as_str() {
                            "off" => "none",
                            "minimal" => "minimal",
                            "low" => "low",
                            "medium" => "medium",
                            "high" => "high",
                            "xhigh" | "max" => "xhigh",
                            _ => "medium",
                        };
                        body.insert("reasoning_effort".into(), json!(effort));
                    }
                }
                "deepseek" => {
                    if gen_opts.thinking == "off" {
                        body.insert("thinking".into(), json!({ "type": "disabled" }));
                    } else if gen_opts.thinking != "auto" {
                        body.insert("thinking".into(), json!({ "type": "enabled" }));
                    }
                }
                "xai" => {
                    if gen_opts.thinking != "auto" && gen_opts.thinking != "off" {
                        let effort = match gen_opts.thinking.as_str() {
                            "minimal" | "low" => "low",
                            "medium" => "medium",
                            "high" => "high",
                            "xhigh" | "max" => "xhigh",
                            _ => "medium",
                        };
                        body.insert("reasoning_effort".into(), json!(effort));
                    }
                }
                "mistral" => {
                    if gen_opts.thinking != "auto" {
                        let effort = match gen_opts.thinking.as_str() {
                            "off" => "none",
                            "minimal" | "low" => "low",
                            "medium" => "medium",
                            "high" | "xhigh" | "max" => "high",
                            _ => "medium",
                        };
                        body.insert("reasoning_effort".into(), json!(effort));
                    }
                }
                "groq" => {
                    if gen_opts.thinking != "auto" {
                        let effort = match gen_opts.thinking.as_str() {
                            "off" => "none",
                            "minimal" | "low" => "low",
                            "medium" => "medium",
                            "high" | "xhigh" | "max" => "high",
                            _ => "medium",
                        };
                        body.insert("reasoning_effort".into(), json!(effort));
                    }
                }
                "together" => {
                    if gen_opts.thinking == "off" {
                        body.insert(
                            "chat_template_kwargs".into(),
                            json!({ "enable_thinking": false }),
                        );
                    } else if gen_opts.thinking != "auto" {
                        let effort = match gen_opts.thinking.as_str() {
                            "minimal" | "low" => "low",
                            "medium" => "medium",
                            "high" | "xhigh" | "max" => "high",
                            _ => "medium",
                        };
                        body.insert("reasoning_effort".into(), json!(effort));
                    }
                }
                "openrouter" => {
                    if gen_opts.thinking == "off" {
                        body.insert("reasoning".into(), json!({ "enabled": false }));
                    } else if gen_opts.thinking != "auto" {
                        let effort = match gen_opts.thinking.as_str() {
                            "minimal" => "minimal",
                            "low" => "low",
                            "medium" => "medium",
                            "high" => "high",
                            "xhigh" | "max" => "xhigh",
                            _ => "medium",
                        };
                        body.insert(
                            "reasoning".into(),
                            json!({ "effort": effort, "exclude": !gen_opts.show_thoughts }),
                        );
                    }
                }
                _ => {
                    if gen_opts.thinking != "auto" && gen_opts.thinking != "off" {
                        let effort = match gen_opts.thinking.as_str() {
                            "minimal" | "low" => "low",
                            "medium" => "medium",
                            "high" | "xhigh" | "max" => "high",
                            _ => "medium",
                        };
                        body.insert("reasoning_effort".into(), json!(effort));
                    }
                }
            }
            if let Some(t) = gen_opts.temperature {
                if !((provider == "deepseek" || provider == "openai") && gen_opts.thinking_active())
                {
                    body.insert("temperature".into(), json!(t));
                }
            }
            Ok((format!("{base}/chat/completions"), Value::Object(body)))
        }
    }
}

/// Project setting with the latest AI summary (`{text, provider, model, created}`).
pub(crate) const AI_SUMMARY_KEY: &str = "ai_summary";
/// Report options key the stored summary is passed under (`foca_report::AI_SUMMARY_DATA_KEY`).
pub(crate) const AI_SUMMARY_DATA_KEY: &str = "ai_summary_data";

pub(crate) fn is_openai_chat_model(id: &str) -> bool {
    let low = id.to_ascii_lowercase();
    ![
        "embedding",
        "whisper",
        "tts-",
        "dall-e",
        "moderation",
        "babbage",
        "davinci",
        "omni-moderation",
        "sora",
        "gpt-image",
        "gpt-realtime",
        "gpt-audio",
    ]
    .iter()
    .any(|pat| low.contains(pat))
}

pub(crate) fn is_gemini_chat_model(id: &str) -> bool {
    let low = id.to_ascii_lowercase();
    if low == "aqa" {
        return false;
    }
    ![
        "embedding",
        "-tts",
        "-image",
        "nano-banana",
        "lyria",
        "transcribe",
        "native-audio",
        "-live",
        "robotics",
        "genie-",
        "computer-use",
        "decision-",
    ]
    .iter()
    .any(|pat| low.contains(pat))
}

pub(crate) fn format_ai_http_error(st: u16, body: &str) -> String {
    let parsed = serde_json::from_str::<Value>(body).ok();
    let raw_msg = parsed
        .as_ref()
        .and_then(|v| {
            v["error"]["message"]
                .as_str()
                .or_else(|| v[0]["error"]["message"].as_str())
        })
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let Some(raw) = raw_msg else {
        return format!("HTTP {st}");
    };
    let compact: String = raw.split_whitespace().collect::<Vec<_>>().join(" ");
    if compact.chars().count() > 180 {
        let head: String = compact.chars().take(180).collect();
        format!("HTTP {st}: {head}…")
    } else {
        format!("HTTP {st}: {compact}")
    }
}

pub(crate) fn keep_ai_model(provider: &str, item: &Value, clean_id: &str) -> bool {
    let low = clean_id.to_ascii_lowercase();
    match provider {
        "anthropic" => item["lifecycle"].as_str() != Some("retired"),
        "openai" => is_openai_chat_model(clean_id),
        "gemini" => {
            let supports_gen =
                item["supportedGenerationMethods"]
                    .as_array()
                    .is_none_or(|methods| {
                        methods
                            .iter()
                            .any(|m| m.as_str() == Some("generateContent"))
                    });
            supports_gen && is_gemini_chat_model(clean_id)
        }
        "groq" => {
            item["active"].as_bool() != Some(false)
                && ![
                    "whisper",
                    "playai-tts",
                    "orpheus",
                    "prompt-guard",
                    "llama-guard",
                ]
                .iter()
                .any(|pat| low.contains(pat))
        }
        "mistral" => {
            item["capabilities"]["completion_chat"].as_bool() != Some(false)
                && !low.contains("embed")
                && !low.contains("moderation")
                && !low.contains("ocr")
        }
        "together" => item["type"]
            .as_str()
            .is_none_or(|t| t.eq_ignore_ascii_case("chat")),
        "openrouter" => item["architecture"]["output_modalities"]
            .as_array()
            .is_none_or(|mods| mods.iter().any(|m| m.as_str() == Some("text"))),
        _ => true,
    }
}

pub(crate) fn extract_ai_model_caps(provider: &str, item: &Value) -> Value {
    let thinking = match provider {
        "anthropic" => item
            .pointer("/capabilities/thinking/supported")
            .and_then(Value::as_bool),
        "gemini" => item.get("thinking").and_then(Value::as_bool),
        "mistral" => item
            .pointer("/capabilities/reasoning")
            .and_then(Value::as_bool),
        "openrouter" => item["supported_parameters"].as_array().map(|arr| {
            arr.iter()
                .any(|p| matches!(p.as_str(), Some("reasoning") | Some("include_reasoning")))
        }),
        _ => None,
    };
    let adaptive_thinking = item
        .pointer("/capabilities/thinking/types/adaptive/supported")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let manual_thinking = item
        .pointer("/capabilities/thinking/types/enabled/supported")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let context_window = item["max_input_tokens"]
        .as_u64()
        .or_else(|| item["inputTokenLimit"].as_u64())
        .or_else(|| item["context_length"].as_u64())
        .or_else(|| item["max_context_length"].as_u64())
        .or_else(|| item["context_window"].as_u64())
        .filter(|&n| n > 0);
    let max_output_tokens = item["max_tokens"]
        .as_u64()
        .or_else(|| item["outputTokenLimit"].as_u64())
        .or_else(|| item["max_completion_tokens"].as_u64())
        .or_else(|| item["top_provider"]["max_completion_tokens"].as_u64())
        .filter(|&n| n > 0);
    json!({
        "thinking": thinking,
        "adaptive_thinking": adaptive_thinking,
        "manual_thinking": manual_thinking,
        "context_window": context_window,
        "max_output_tokens": max_output_tokens,
    })
}

pub(crate) fn parse_ai_models(
    provider: &str,
    text: &str,
) -> Result<(Vec<Value>, Vec<Value>), &'static str> {
    let v: Value = serde_json::from_str(text).map_err(|_| "Некорректный ответ API провайдера")?;
    let items = v
        .as_array()
        .or_else(|| v["data"].as_array())
        .or_else(|| v["models"].as_array())
        .ok_or("Неожиданный формат списка моделей")?;
    let mut all = Vec::new();
    let mut filtered = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for item in items {
        let raw_id = item["id"]
            .as_str()
            .or_else(|| item["name"].as_str())
            .unwrap_or("")
            .trim();
        if raw_id.is_empty() {
            continue;
        }
        let clean_id = if provider == "gemini" {
            raw_id.strip_prefix("models/").unwrap_or(raw_id)
        } else {
            raw_id
        };
        if clean_id.is_empty() || !seen.insert(clean_id.to_string()) {
            continue;
        }
        let label = item["display_name"]
            .as_str()
            .or_else(|| item["displayName"].as_str())
            .or_else(|| item["name"].as_str().filter(|s| !s.starts_with("models/")))
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .unwrap_or(clean_id);
        let caps = extract_ai_model_caps(provider, item);
        let entry = json!({
            "id": clean_id,
            "label": label,
            "thinking": caps["thinking"],
            "adaptive_thinking": caps["adaptive_thinking"],
            "manual_thinking": caps["manual_thinking"],
            "context_window": caps["context_window"],
            "max_output_tokens": caps["max_output_tokens"],
        });
        if keep_ai_model(provider, item, clean_id) {
            filtered.push(entry.clone());
        }
        all.push(entry);
    }
    let chat = if !filtered.is_empty() {
        filtered
    } else {
        all.clone()
    };
    Ok((chat, all))
}
