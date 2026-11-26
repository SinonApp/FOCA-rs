//! AI summary commands: provider requests, model lists and the stored summary.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use foca_core::Scope;
use foca_net::{Access, NetRequest};
use serde_json::{json, Value};

use crate::analysis::rules;
use crate::dto::evidence_secrets;
use crate::engine::lock;
use crate::services::ai::{
    attach_ai_headers, build_ai_request, format_ai_http_error, parse_ai_models, AiGenOpts,
    AI_SUMMARY_KEY,
};
use crate::util::is_loopback_host;
use crate::util::{self, arg_str};
use crate::{CmdError, CmdResult, Engine};

struct ParsedAiSummary {
    md: String,
    thoughts: String,
    model: String,
    tokens_in: u64,
    tokens_out: u64,
    tokens_thoughts: u64,
}

fn parse_ai_summary_response(
    provider: &str,
    req_model: &str,
    fallback_in: u64,
    v: &Value,
) -> ParsedAiSummary {
    let est_out = |s: &str| (s.chars().count() as f64 / 3.6) as u64;
    match provider {
        "anthropic" => {
            let blocks = v["content"].as_array();
            let md = blocks
                .map(|arr| {
                    arr.iter()
                        .filter(|b| b["type"].as_str() == Some("text"))
                        .filter_map(|b| b["text"].as_str())
                        .collect::<Vec<_>>()
                        .join("\n")
                })
                .unwrap_or_default();
            let thoughts = blocks
                .map(|arr| {
                    arr.iter()
                        .filter(|b| b["type"].as_str() == Some("thinking"))
                        .filter_map(|b| b["thinking"].as_str())
                        .collect::<Vec<_>>()
                        .join("\n")
                })
                .unwrap_or_default();
            let model = v["model"].as_str().unwrap_or(req_model).to_string();
            let tokens_in = v["usage"]["input_tokens"].as_u64().unwrap_or(fallback_in);
            let tokens_out = v["usage"]["output_tokens"]
                .as_u64()
                .unwrap_or_else(|| est_out(&md));
            ParsedAiSummary {
                md,
                thoughts,
                model,
                tokens_in,
                tokens_out,
                tokens_thoughts: 0,
            }
        }
        "gemini" => {
            let parts = v["candidates"][0]["content"]["parts"].as_array();
            let md = parts
                .map(|arr| {
                    arr.iter()
                        .filter(|p| p["thought"].as_bool() != Some(true))
                        .filter_map(|p| p["text"].as_str())
                        .collect::<Vec<_>>()
                        .join("\n")
                })
                .unwrap_or_default();
            let thoughts = parts
                .map(|arr| {
                    arr.iter()
                        .filter(|p| p["thought"].as_bool() == Some(true))
                        .filter_map(|p| p["text"].as_str())
                        .collect::<Vec<_>>()
                        .join("\n")
                })
                .unwrap_or_default();
            let model = v["modelVersion"].as_str().unwrap_or(req_model).to_string();
            let tokens_in = v["usageMetadata"]["promptTokenCount"]
                .as_u64()
                .unwrap_or(fallback_in);
            let tokens_out = v["usageMetadata"]["candidatesTokenCount"]
                .as_u64()
                .unwrap_or_else(|| est_out(&md));
            let tokens_thoughts = v["usageMetadata"]["thoughtsTokenCount"]
                .as_u64()
                .unwrap_or(0);
            ParsedAiSummary {
                md,
                thoughts,
                model,
                tokens_in,
                tokens_out,
                tokens_thoughts,
            }
        }
        _ => {
            let msg = &v["choices"][0]["message"];
            let content = &msg["content"];
            let md = if let Some(s) = content.as_str() {
                s.to_string()
            } else if let Some(arr) = content.as_array() {
                arr.iter()
                    .filter(|b| b["type"].as_str().is_none_or(|t| t == "text"))
                    .filter_map(|b| b["text"].as_str())
                    .collect::<Vec<_>>()
                    .join("\n")
            } else {
                String::new()
            };
            let thoughts = msg["reasoning_content"]
                .as_str()
                .or_else(|| msg["reasoning"].as_str())
                .unwrap_or("")
                .trim()
                .to_string();
            let model = v["model"].as_str().unwrap_or(req_model).to_string();
            let tokens_in = v["usage"]["prompt_tokens"].as_u64().unwrap_or(fallback_in);
            let tokens_out = v["usage"]["completion_tokens"]
                .as_u64()
                .unwrap_or_else(|| est_out(&md));
            let tokens_thoughts = v["usage"]["completion_tokens_details"]["reasoning_tokens"]
                .as_u64()
                .unwrap_or(0);
            ParsedAiSummary {
                md,
                thoughts,
                model,
                tokens_in,
                tokens_out,
                tokens_thoughts,
            }
        }
    }
}

impl Engine {
    pub(crate) fn ai_preview(&self, a: &Value) -> CmdResult {
        let id = self.project_arg(a)?;
        self.ai_preview_for(&id, a.get("opts").unwrap_or(&json!({})))
    }

    fn ai_preview_for(&self, id: &str, o: &Value) -> CmdResult {
        let (snap, _) = self.core_snapshot(id)?;
        let st = serde_json::to_value(&snap)?;
        let settings = self.public_settings()?;
        let ai = &settings["ai"];
        let mut red = json!({ "secrets": true, "pii": true, "client": true, "evid": false });
        if ai["redact"].is_object() {
            foca_store::settings::merge(&mut red, &ai["redact"]);
        }
        if o["redact"].is_object() {
            foca_store::settings::merge(&mut red, &o["redact"]);
        }
        let rb = |k: &str| red[k].as_bool().unwrap_or(false);
        let dom = if snap.project.domain.is_empty() {
            snap.project.name.clone()
        } else {
            snap.project.domain.clone()
        };
        let client = if snap.scope.client.is_empty() {
            snap.project.client.clone()
        } else {
            snap.scope.client.clone()
        };
        let mut marks: BTreeMap<&str, u32> = ["СЕКРЕТ", "EMAIL", "ФИО", "КЛИЕНТ", "IP-ВНУТР"]
            .iter()
            .map(|k| (*k, 0))
            .collect();
        let m = |v: &str, tag: &'static str, on: bool, marks: &mut BTreeMap<&str, u32>| -> String {
            if !on {
                return v.to_string();
            }
            *marks.entry(tag.trim_end_matches("-ДОМЕН")).or_insert(0) += 1;
            format!("[{tag}]")
        };
        let repl = |s: &str, needle: &str, tag: &str, marks: &mut BTreeMap<&str, u32>| -> String {
            if needle.is_empty() {
                return s.to_string();
            }
            let Ok(re) = regex::RegexBuilder::new(&regex::escape(needle))
                .case_insensitive(true)
                .build()
            else {
                return s.to_string();
            };
            let n = re.find_iter(s).count() as u32;
            if n > 0 {
                let k = if tag.starts_with("КЛИЕНТ") {
                    "КЛИЕНТ"
                } else {
                    "СЕКРЕТ"
                };
                *marks.entry(k).or_insert(0) += n;
            }
            re.replace_all(s, format!("[{tag}]")).into_owned()
        };
        let client_on = rb("client");
        let txt = |s: &str, marks: &mut BTreeMap<&str, u32>| -> String {
            let mut out = s.to_string();
            if client_on {
                out = repl(&out, &dom, "КЛИЕНТ-ДОМЕН", marks);
                out = repl(&out, &client, "КЛИЕНТ", marks);
            }
            out
        };
        let mut live: Vec<&Value> = st["findings"]
            .as_array()
            .map(|l| {
                l.iter()
                    .filter(|f| rules::is_live_status(f["status"].as_str().unwrap_or("")))
                    .collect()
            })
            .unwrap_or_default();
        live.sort_by(|a, b| {
            rules::sev_rank(b["sev"].as_str().unwrap_or(""))
                .cmp(&rules::sev_rank(a["sev"].as_str().unwrap_or("")))
                .then(a["id"].as_u64().cmp(&b["id"].as_u64()))
        });
        let top: Vec<&Value> = live
            .iter()
            .filter(|f| f["sev"] == "crit" || f["sev"] == "high")
            .take(6)
            .copied()
            .collect();
        let mid: Vec<&Value> = live
            .iter()
            .filter(|f| f["sev"] == "warn")
            .copied()
            .collect();
        let mut lines: Vec<String> = Vec::new();
        let c = if client.is_empty() {
            "-".to_string()
        } else {
            m(&client, "КЛИЕНТ", client_on, &mut marks)
        };
        let d = if dom.is_empty() {
            String::new()
        } else {
            format!(", домен {}", m(&dom, "КЛИЕНТ-ДОМЕН", client_on, &mut marks))
        };
        lines.push(format!("Проект: {c}{d}"));
        let live_docs = snap.docs.iter().filter(|d| !d.deleted).count();
        lines.push(match snap.scans.last() {
            Some(l) => format!(
                "Скан {}, профиль «{}»{}. Документов: {live_docs}, хостов: {}, людей: {}.",
                l.finished_at.as_deref().unwrap_or(&l.started_at),
                l.profile,
                if l.active { " (активный)" } else { "" },
                snap.hosts.len(),
                snap.people.len()
            ),
            None => "Сканов ещё не было.".into(),
        });
        lines.push(String::new());
        lines.push(if top.is_empty() {
            "Критичных и высоких находок нет.".into()
        } else {
            "Находки (критичные и высокие):".into()
        });
        for (i, f) in top.iter().enumerate() {
            let h = f["host"].as_str().unwrap_or("");
            let host = if h.is_empty() || h == "-" {
                "несколько хостов".to_string()
            } else if client_on
                && !dom.is_empty()
                && h.len().checked_sub(dom.len()).is_some_and(|prefix_len| {
                    h.is_char_boundary(prefix_len)
                        && h[prefix_len..].eq_ignore_ascii_case(&dom)
                        && (prefix_len == 0 || h.as_bytes()[prefix_len - 1] == b'.')
                })
            {
                let prefix_len = h.len() - dom.len();
                format!(
                    "{}{}",
                    &h[..prefix_len],
                    m(&dom, "КЛИЕНТ-ДОМЕН", true, &mut marks)
                )
            } else {
                h.to_string()
            };
            let secs = evidence_secrets(f["evidence"].as_str().unwrap_or(""));
            let sec = match secs.first() {
                Some(s) => format!(": {}", m(s, "СЕКРЕТ", rb("secrets"), &mut marks)),
                None => String::new(),
            };
            let t = txt(f["title"].as_str().unwrap_or(""), &mut marks);
            lines.push(format!("{}. {t}, {host}{sec}", i + 1));
        }
        if !mid.is_empty() {
            lines.push(String::new());
            let ts: Vec<String> = mid
                .iter()
                .map(|f| txt(f["title"].as_str().unwrap_or(""), &mut marks))
                .collect();
            lines.push(format!("Средние: {}.", ts.join("; ")));
        }
        let ppl: Vec<&foca_core::api::Email> = snap
            .emails
            .iter()
            .filter(|e| e.found && !e.role && e.name.is_some())
            .take(2)
            .collect();
        if !ppl.is_empty() {
            lines.push(String::new());
            let ps: Vec<String> = ppl
                .iter()
                .map(|e| {
                    format!(
                        "{} ({})",
                        m(
                            e.name.as_deref().unwrap_or(""),
                            "ФИО",
                            rb("pii"),
                            &mut marks
                        ),
                        m(&e.addr, "EMAIL", rb("pii"), &mut marks)
                    )
                })
                .collect();
            lines.push(format!("Люди: {}.", ps.join(", ")));
        }
        let srv: Vec<&foca_core::api::Pc> = snap
            .pcs
            .iter()
            .filter(|p| p.kind == "server")
            .take(3)
            .collect();
        if !srv.is_empty() {
            let ss: Vec<String> = srv
                .iter()
                .map(|p| match &p.ip {
                    Some(ip) if rules::ip4(ip).is_some() => {
                        format!(
                            "{} ({})",
                            p.name,
                            m(ip, "IP-ВНУТР", rb("secrets"), &mut marks)
                        )
                    }
                    _ => p.name.clone(),
                })
                .collect();
            lines.push(format!("Внутренние имена: {}.", ss.join(", ")));
        }
        if rb("evid") {
            if let Some(f) = top.first() {
                let ev = f["evidence"].as_str().unwrap_or("");
                if !ev.is_empty() {
                    let parts: Vec<String> = ev
                        .lines()
                        .take(3)
                        .map(|s| {
                            let mut t = txt(s, &mut marks);
                            for v in evidence_secrets(&t) {
                                let r = m(&v, "СЕКРЕТ", rb("secrets"), &mut marks);
                                t = t.replace(&format!("{{{{s:{v}}}}}"), &r);
                            }
                            t
                        })
                        .collect();
                    let tt = txt(f["title"].as_str().unwrap_or(""), &mut marks);
                    lines.push(String::new());
                    lines.push(format!("Доказательство ({tt}): {}", parts.join("; ")));
                }
            }
        }
        lines.push(String::new());
        lines.push(
            "Задача: кратко опиши ключевые риски и дай приоритетные рекомендации на русском языке."
                .into(),
        );
        let text = lines.join("\n");
        let prov_raw = o["provider"]
            .as_str()
            .or_else(|| ai["provider"].as_str())
            .unwrap_or("deepseek");
        let (provider, host) =
            match self.resolve_ai_endpoint(prov_raw, o["base_url"].as_str(), &settings) {
                Ok((p, _, h)) => (p, h),
                Err(_) => (prov_raw.trim().to_ascii_lowercase(), String::new()),
            };
        let model = o["model"]
            .as_str()
            .or_else(|| ai["model"].as_str())
            .unwrap_or("")
            .trim()
            .to_string();
        let chars = text.chars().count() as f64;
        Ok(json!({
            "id": format!("aip-{}", util::base36(util::fnv(&format!("{text}{red}")) as u64)),
            "text": text,
            "tokens": ((chars / 3.2 / 10.0).round() as u64) * 10 + 180,
            "redacted": marks["СЕКРЕТ"],
            "marks": marks,
            "redact": red,
            "provider": provider,
            "model": model,
            "host": host,
        }))
    }

    fn resolve_ai_endpoint(
        &self,
        provider_raw: &str,
        base_url_override: Option<&str>,
        settings: &Value,
    ) -> Result<(String, String, String), CmdError> {
        let raw = provider_raw.trim().to_ascii_lowercase();
        let provider = if raw.is_empty() || raw == "local" {
            "deepseek".to_string()
        } else {
            raw
        };
        if provider == "custom" {
            let u = base_url_override
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .or_else(|| {
                    settings["ai"]["base_url"]
                        .as_str()
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                })
                .unwrap_or("");
            let parsed = url::Url::parse(u).ok().filter(|url| {
                let scheme_ok = match url.scheme() {
                    "https" => true,
                    "http" => url.host_str().is_some_and(is_loopback_host),
                    _ => false,
                };
                scheme_ok
                    && url.host_str().is_some_and(|h| !h.is_empty())
                    && url.username().is_empty()
                    && url.password().is_none()
            });
            let Some(parsed) = parsed else {
                return Err(CmdError::new(
                    "bad_input",
                    "Укажите корректный URL OpenAI-совместимого API (https://… или http://localhost…)",
                ));
            };
            let host = parsed.host_str().unwrap_or("").to_string();
            let base = u.trim_end_matches('/').to_string();
            return Ok((provider, base, host));
        }
        let base = self
            .inner
            .cfg
            .endpoints
            .ai
            .get(&provider)
            .cloned()
            .ok_or_else(|| {
                CmdError::new(
                    "unavailable",
                    format!("Неизвестный ИИ-провайдер: {provider}"),
                )
            })?;
        let host = url::Url::parse(&base)
            .ok()
            .and_then(|u| u.host_str().map(String::from))
            .unwrap_or_default();
        Ok((provider, base.trim_end_matches('/').to_string(), host))
    }

    pub(crate) async fn ai_models_list(&self, a: &Value) -> CmdResult {
        let settings = self.public_settings()?;
        let prov_raw = arg_str(a, "provider")
            .or_else(|| settings["ai"]["provider"].as_str())
            .unwrap_or("deepseek");
        let base_override = arg_str(a, "base_url");
        let refresh = a["refresh"].as_bool().unwrap_or(false);
        let show_all = a["show_all"].as_bool().unwrap_or(false);
        let (provider, base, host) =
            match self.resolve_ai_endpoint(prov_raw, base_override, &settings) {
                Ok(res) => res,
                Err(e) if e.code == "bad_input" => {
                    return Ok(json!({
                        "provider": "custom",
                        "host": "",
                        "models": [],
                        "source": "bad_url",
                        "error": e.message,
                    }));
                }
                Err(e) => return Err(e),
            };
        let Some(key) = self.current_keys().get("ai").filter(|k| !k.is_empty()) else {
            return Ok(json!({
                "provider": provider,
                "host": host,
                "models": [],
                "source": "no_key",
                "error": "Укажите ключ API, чтобы загрузить список моделей от провайдера",
            }));
        };
        let cache_key = format!(
            "{provider}|{base}|{}",
            if show_all { "all" } else { "chat" }
        );
        if !refresh {
            if let Some(cached) = lock(&self.inner.ai_models_cache).get(&cache_key).cloned() {
                return Ok(json!({
                    "provider": provider,
                    "host": host,
                    "models": cached,
                    "source": "cache",
                    "error": "",
                }));
            }
        }
        let models_url = match provider.as_str() {
            "anthropic" => format!("{base}/models?limit=100"),
            "gemini" => format!("{base}/models?pageSize=1000"),
            _ => format!("{base}/models"),
        };
        let net = self.net_client(Scope::default(), Arc::new(foca_net::NullSink))?;
        let req = match NetRequest::new(foca_net::Method::GET, &models_url, "ai", Access::Passive) {
            Ok(r) => attach_ai_headers(r, &provider, &key).timeout(Duration::from_secs(20)),
            Err(e) => {
                return Ok(json!({
                    "provider": provider,
                    "host": host,
                    "models": [],
                    "source": "offline",
                    "error": crate::analysis::redact::redact(&e.to_string(), &self.known_secrets()),
                }));
            }
        };
        let r = match net.send(req).await {
            Ok(r) => r,
            Err(e) => {
                return Ok(json!({
                    "provider": provider,
                    "host": host,
                    "models": [],
                    "source": "offline",
                    "error": crate::analysis::redact::redact(&e.to_string(), &self.known_secrets()),
                }));
            }
        };
        let st = r.status();
        let text = match r.text_limited(4 * 1024 * 1024).await {
            Ok(t) => t,
            Err(e) => {
                return Ok(json!({
                    "provider": provider,
                    "host": host,
                    "models": [],
                    "source": "offline",
                    "error": crate::analysis::redact::redact(&e.to_string(), &self.known_secrets()),
                }));
            }
        };
        if st == 401 || st == 403 {
            return Ok(json!({
                "provider": provider,
                "host": host,
                "models": [],
                "source": "no_key",
                "error": format!("Ключ ИИ отклонён: HTTP {st}"),
            }));
        }
        if !(200..300).contains(&st) {
            let err_msg = crate::analysis::redact::redact(
                &format_ai_http_error(st, &text),
                &self.known_secrets(),
            );
            return Ok(json!({
                "provider": provider,
                "host": host,
                "models": [],
                "source": "offline",
                "error": err_msg,
            }));
        }
        let (chat_models, all_models) = match parse_ai_models(&provider, &text) {
            Ok(m) => m,
            Err(msg) => {
                return Ok(json!({
                    "provider": provider,
                    "host": host,
                    "models": [],
                    "source": "offline",
                    "error": msg,
                }));
            }
        };
        {
            let mut cache = lock(&self.inner.ai_models_cache);
            cache.insert(format!("{provider}|{base}|chat"), chat_models.clone());
            cache.insert(format!("{provider}|{base}|all"), all_models.clone());
        }
        let models = if show_all { all_models } else { chat_models };
        Ok(json!({
            "provider": provider,
            "host": host,
            "models": models,
            "source": "api",
            "error": "",
        }))
    }

    pub(crate) async fn ai_summarize(&self, a: &Value) -> CmdResult {
        const SYSTEM_PROMPT: &str = "Ты аналитик информационной безопасности. Отвечай в Markdown: «## Ключевые риски» и «## Рекомендации».";
        let id = self.project_arg(a)?;
        let settings = self.public_settings()?;
        let empty_opts = json!({});
        let opts = a.get("opts").unwrap_or(&empty_opts);
        let key = self
            .current_keys()
            .get("ai")
            .filter(|k| !k.is_empty())
            .ok_or_else(|| CmdError::new("no_key", "Нет ключа ИИ-провайдера"))?;
        let p = self.ai_preview_for(&id, opts)?;
        if let Some(pid) = arg_str(a, "preview_id") {
            if pid != p["id"] {
                return Err(CmdError::new(
                    "stale_preview",
                    "Данные проекта изменились: обновите предпросмотр",
                ));
            }
        }
        let (provider, base, _host) = self.resolve_ai_endpoint(
            opts["provider"]
                .as_str()
                .or_else(|| p["provider"].as_str())
                .unwrap_or("deepseek"),
            opts["base_url"].as_str(),
            &settings,
        )?;
        let cache_key_chat = format!("{provider}|{base}|chat");
        let cache_key_all = format!("{provider}|{base}|all");
        let mut model = opts["model"]
            .as_str()
            .or_else(|| p["model"].as_str())
            .unwrap_or("")
            .trim()
            .to_string();
        if model.is_empty() {
            let cache = lock(&self.inner.ai_models_cache);
            if let Some(first) = cache
                .get(&cache_key_chat)
                .or_else(|| cache.get(&cache_key_all))
                .and_then(|list| list.first())
                .and_then(|m| m["id"].as_str())
            {
                model = first.to_string();
            }
        }
        if model.is_empty() {
            return Err(CmdError::new(
                "bad_input",
                "Выберите модель в «Настройки → ИИ-сводка» (обновите список моделей от провайдера)",
            ));
        }
        let ai_cfg = &settings["ai"];
        let gen_opts = AiGenOpts::from_values(opts, ai_cfg);
        let model_meta = {
            let cache = lock(&self.inner.ai_models_cache);
            cache
                .get(&cache_key_all)
                .or_else(|| cache.get(&cache_key_chat))
                .and_then(|list| {
                    list.iter()
                        .find(|m| m["id"].as_str() == Some(model.as_str()))
                })
                .cloned()
        };
        let (url, body) = build_ai_request(
            &provider,
            &base,
            &model,
            SYSTEM_PROMPT,
            p["text"].as_str().unwrap_or(""),
            &gen_opts,
            model_meta.as_ref(),
        )?;
        let secrets = self.known_secrets();
        let net = self.net_client(Scope::default(), Arc::new(foca_net::NullSink))?;
        let req =
            NetRequest::new(foca_net::Method::POST, &url, "ai", Access::Passive).map_err(|e| {
                CmdError::new(
                    "net",
                    crate::analysis::redact::redact(&e.to_string(), &secrets),
                )
            })?;
        let req = attach_ai_headers(req, &provider, &key)
            .header("Content-Type", "application/json")
            .body(serde_json::to_vec(&body)?)
            .timeout(Duration::from_secs(180));
        let r = net.send(req).await.map_err(|e| {
            CmdError::new(
                "net",
                crate::analysis::redact::redact(&e.to_string(), &secrets),
            )
        })?;
        let st = r.status();
        let text = r.text_limited(4 * 1024 * 1024).await.map_err(|e| {
            CmdError::new(
                "net",
                crate::analysis::redact::redact(&e.to_string(), &secrets),
            )
        })?;
        if st == 401 || st == 403 {
            return Err(CmdError::new(
                "no_key",
                format!("Ключ ИИ отклонён: HTTP {st}"),
            ));
        }
        if !(200..300).contains(&st) {
            return Err(CmdError::new(
                "net",
                crate::analysis::redact::redact(&format_ai_http_error(st, &text), &secrets),
            ));
        }
        let v: Value = serde_json::from_str(&text).map_err(|e| {
            CmdError::new(
                "net",
                crate::analysis::redact::redact(&e.to_string(), &secrets),
            )
        })?;
        let fallback_in = p["tokens"].as_u64().unwrap_or(0);
        let parsed = parse_ai_summary_response(&provider, &model, fallback_in, &v);
        // The latest summary goes into reports as the optional "Executive summary
        // (AI-assisted)" section (report option `ai_summary`, default on).
        if !parsed.md.trim().is_empty() {
            let db = self.db(&id)?;
            lock(&db).set_setting(
                AI_SUMMARY_KEY,
                &json!({
                    "text": parsed.md,
                    "provider": provider,
                    "model": parsed.model,
                    "created": util::iso(self.now()),
                }),
            )?;
        }
        Ok(json!({
            "md": parsed.md,
            "thoughts": if gen_opts.show_thoughts() { parsed.thoughts } else { String::new() },
            "model": parsed.model,
            "provider": provider,
            "tokens_in": parsed.tokens_in,
            "tokens_out": parsed.tokens_out,
            "tokens_thoughts": parsed.tokens_thoughts,
            "preview_id": p["id"],
            "source_badge": "Cloud API",
        }))
    }
}
