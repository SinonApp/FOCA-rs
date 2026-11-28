//! Quick tools (Toolbox): one-shot checks that need no project and write nothing to
//! the project store.
//!
//! * `tool_file`: metadata, forensics, personal data, bad redactions, secrets and the
//!   hygiene grade of one local file; no network at all. Cleaning stays with `doc_clean { path }`.
//! * `tool_mail_domain`: SPF / DMARC / DKIM (common selectors) / BIMI / MTA-STS / TLS-RPT / CAA /
//!   DNSSEC of a domain over DNS, plus the MTA-STS policy file, and a spoofing risk verdict.
//! * `tool_host`, one host or URL on explicit user request: the TLS certificate, security headers
//!   of the page (one GET), technologies and the favicon hash. The network scope is that host only.
//! * `tool_secret`: local strength estimate of a password or token, plus opt-in
//!   HIBP Pwned Passwords check (5-char SHA-1 k-anonymity via [`foca_net::hibp`]).
//!
//! Every network request goes through `NetClient` (settings.net: proxy, UA, rate limits) with a
//! request log: the records of the call come back in `requests` and the last records stay in a
//! memory ring (`tool_log`, emptied by `tool_log_clear`). Each tool has a wall-clock budget (`timeout_ms`, 5 s by default):
//! when it runs out, the finished parts are returned with `partial: true` and the unfinished
//! steps marked `timeout`.

use std::collections::{BTreeMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use foca_core::Scope;
use foca_net::dns::{DnsLookup, RType};
use foca_net::{Access, NetClient, NetRequest, RequestRecord, RequestSink};
use serde_json::{json, Value};
use tokio_util::sync::CancellationToken;

use crate::engine::{lock, Core};
use crate::util::arg_str;
use crate::{CmdError, CmdResult};

/// Default wall-clock budget of one tool call.
const DEFAULT_BUDGET: Duration = Duration::from_millis(5000);
/// Records kept in the toolbox request ring (`tool_log`).
const LOG_RING: usize = 200;
/// Largest file accepted by `tool_file` (base64 `data` or `path`).
const MAX_FILE: u64 = 100 * 1024 * 1024;
/// Body limits of `tool_host`.
const PAGE_LIMIT: usize = 2 << 20;
const ICON_LIMIT: usize = 1 << 20;
/// Request log module of the toolbox.
const MODULE: &str = "toolbox";

fn bad_args(m: impl Into<String>) -> CmdError {
    CmdError::new("bad_args", m)
}

/// Budget from `timeout_ms` (1-20 s, 5 s by default).
fn budget(a: &Value) -> Duration {
    a.get("timeout_ms")
        .and_then(Value::as_u64)
        .map(|ms| Duration::from_millis(ms.clamp(1000, 20_000)))
        .unwrap_or(DEFAULT_BUDGET)
}

/// Remaining time until `deadline` (at least 1 ms so a timeout future still resolves).
fn left(deadline: Instant) -> Duration {
    deadline
        .saturating_duration_since(Instant::now())
        .max(Duration::from_millis(1))
}

/// The budget is (practically) used up: a failure now is the deadline, not the target.
fn expired(deadline: Instant) -> bool {
    Instant::now() + Duration::from_millis(50) >= deadline
}

/// Step record of a failed operation: `timeout` when the budget ran out, otherwise `error`.
fn failed(deadline: Instant, e: String) -> Value {
    if expired(deadline) {
        step("timeout", None)
    } else {
        step("error", Some(e))
    }
}

fn step(status: &str, error: Option<String>) -> Value {
    match error {
        Some(e) => json!({ "status": status, "error": e }),
        None => json!({ "status": status }),
    }
}

/// Request log of one tool call; also feeds the engine's toolbox ring.
struct ToolSink {
    recs: Mutex<Vec<RequestRecord>>,
    ring: Arc<Mutex<VecDeque<Value>>>,
    tool: &'static str,
}

impl RequestSink for ToolSink {
    fn record(&self, rec: &RequestRecord) {
        tracing::debug!(target: "foca::toolbox", "{} {} {} {:?}", self.tool, rec.method, rec.url, rec.status);
        lock(&self.recs).push(rec.clone());
        let mut v = serde_json::to_value(rec).unwrap_or_default();
        v["tool"] = json!(self.tool);
        let mut g = lock(&self.ring);
        if g.len() >= LOG_RING {
            g.pop_front();
        }
        g.push_back(v);
    }
}

impl ToolSink {
    fn json(&self) -> Value {
        json!(lock(&self.recs).clone())
    }
}

/// Spoofing risk of a domain from the mail analysis: `low` | `medium` | `high` | `unknown`,
/// with the reasons in plain words.
fn spoofing_risk(m: &foca_net::mail::MailReport, complete: bool) -> (&'static str, Vec<String>) {
    let mut why: Vec<String> = Vec::new();
    if !complete {
        why.push("DNS ответил не на все запросы: оценка неполная".into());
        return ("unknown", why);
    }
    let multiple = |id: &str| m.issues.iter().any(|i| i.id == id);
    let spf_all = m.spf.as_ref().and_then(|s| s.all);
    let spf_redirect = m.spf.as_ref().is_some_and(|s| s.redirect.is_some());
    let spf_broken = multiple("spf_multiple") || multiple("spf_too_many_lookups");
    let dmarc_p = m
        .dmarc
        .as_ref()
        .map(|d| d.p.as_str())
        .filter(|_| !multiple("dmarc_multiple"));
    let dmarc_pct = m.dmarc.as_ref().map(|d| d.pct).unwrap_or(100);
    let enforced = matches!(dmarc_p, Some("reject") | Some("quarantine"));
    let level = if spf_all == Some('+') {
        why.push("SPF +all разрешает отправку писем от домена любому серверу".into());
        "high"
    } else if !enforced {
        match dmarc_p {
            None => why.push("нет действующей записи DMARC: поле From можно подделать".into()),
            Some(_) => {
                why.push("DMARC p=none только собирает отчёты и не блокирует подделку".into())
            }
        }
        if spf_all == Some('-') && !spf_broken {
            why.push(
                "SPF -all отсекает чужие серверы, но без DMARC адрес в From не защищён".into(),
            );
            "medium"
        } else {
            if m.spf.is_none() {
                why.push("нет SPF-записи".into());
            }
            "high"
        }
    } else if dmarc_pct < 100 {
        why.push(format!("DMARC применяется только к {dmarc_pct}% писем"));
        "medium"
    } else if m.spf.is_none() || spf_broken || !(matches!(spf_all, Some('-' | '~')) || spf_redirect)
    {
        why.push(
            "DMARC принудительный, но SPF отсутствует или не работает: остаётся только DKIM".into(),
        );
        "medium"
    } else {
        why.push(format!(
            "DMARC p={} для всех писем и SPF {}: подделка отклоняется получателями",
            dmarc_p.unwrap_or(""),
            spf_all
                .map(|c| format!("{c}all"))
                .unwrap_or_else(|| "redirect".into())
        ));
        "low"
    };
    if m.dmarc.as_ref().and_then(|d| d.sp.as_deref()) == Some("none") && enforced {
        why.push("sp=none: поддомены не защищены DMARC".into());
    }
    if m.dkim_selectors.is_empty() && m.has_mx {
        why.push("DKIM-селекторы из словаря не найдены (это не доказывает отсутствие DKIM)".into());
    }
    if !m.has_mx {
        why.push("у домена нет MX: для него не нужна почта, политика должна запрещать всё (-all, p=reject)".into());
    }
    (level, why)
}

/// Local strength estimate of a password or secret (no network, the value is never stored or
/// logged). A simple rule set: length, character classes, entropy, common patterns.
fn secret_estimate(s: &str) -> Value {
    let chars: Vec<char> = s.chars().collect();
    let len = chars.len();
    let lower = chars.iter().any(|c| c.is_lowercase());
    let upper = chars.iter().any(|c| c.is_uppercase());
    let digit = chars.iter().any(|c| c.is_ascii_digit());
    let symbol = chars
        .iter()
        .any(|c| !c.is_alphanumeric() && !c.is_whitespace());
    let other = chars
        .iter()
        .any(|c| c.is_alphabetic() && !c.is_ascii() && !c.is_lowercase() && !c.is_uppercase());
    let mut pool = 0u32;
    if lower {
        pool += 26;
    }
    if upper {
        pool += 26;
    }
    if digit {
        pool += 10;
    }
    if symbol {
        pool += 33;
    }
    if other {
        pool += 32;
    }
    // the unique-character count caps the effective pool (aaaaaaaa is not 8 × log2(26))
    let mut uniq: Vec<char> = chars.clone();
    uniq.sort_unstable();
    uniq.dedup();
    let mut bits = if pool > 0 {
        len as f64 * (pool as f64).log2()
    } else {
        0.0
    };
    bits = bits.min(len as f64 * ((uniq.len().max(1) as f64).log2().max(1.0) + 1.0));
    let mut issues: Vec<&str> = Vec::new();
    let low = s.to_lowercase();
    const COMMON: &[&str] = &[
        "password",
        "passw0rd",
        "qwerty",
        "123456",
        "111111",
        "admin",
        "letmein",
        "welcome",
        "iloveyou",
        "monkey",
        "dragon",
        "abc123",
        "пароль",
        "йцукен",
        "secret",
        "changeme",
    ];
    if COMMON.iter().any(|c| low.contains(c)) {
        issues.push("common_word");
        bits = bits.min(20.0);
    }
    let seq = chars.windows(3).any(|w| {
        let (a, b, c) = (w[0] as i64, w[1] as i64, w[2] as i64);
        (b - a == 1 && c - b == 1) || (a - b == 1 && b - c == 1)
    });
    if seq {
        issues.push("sequence");
        bits *= 0.8;
    }
    if chars.windows(3).any(|w| w[0] == w[1] && w[1] == w[2]) {
        issues.push("repeats");
        bits *= 0.85;
    }
    if len > 0 && chars.iter().all(|c| c.is_ascii_digit()) {
        issues.push("digits_only");
    }
    if (4..=4).contains(&s.chars().filter(|c| c.is_ascii_digit()).count())
        && (1950..=2039).any(|y| s.contains(&y.to_string()))
    {
        issues.push("year");
        bits *= 0.9;
    }
    if len < 12 {
        issues.push("short");
    }
    let classes = [lower, upper, digit, symbol].iter().filter(|x| **x).count();
    if classes < 3 && len < 16 {
        issues.push("few_classes");
    }
    let bits = (bits * 10.0).round() / 10.0;
    let (score, strength) = match bits {
        b if b < 28.0 => (0, "very_weak"),
        b if b < 36.0 => (1, "weak"),
        b if b < 60.0 => (2, "fair"),
        b if b < 80.0 => (3, "strong"),
        _ => (4, "very_strong"),
    };
    // offline attack at 10^10 guesses per second (fast hash on a GPU rig)
    let secs = 2f64.powf(bits) / 2.0 / 1e10;
    let crack = match secs {
        s if s < 1.0 => "instant",
        s if s < 3600.0 => "minutes",
        s if s < 86_400.0 * 30.0 => "days",
        s if s < 86_400.0 * 365.0 * 100.0 => "years",
        _ => "centuries",
    };
    // the secret detector of document analysis: what kind of token it looks like
    let kind = foca_analysis::secrets::Rules::builtin()
        .scan(s, "ввод")
        .into_iter()
        .next()
        .map(|h| json!({ "rule": h.rule, "title": h.title, "kind": h.kind }));
    json!({
        "length": len,
        "classes": { "lower": lower, "upper": upper, "digit": digit, "symbol": symbol },
        "entropy_bits": bits,
        "score": score,
        "strength": strength,
        "crack_time": crack,
        "issues": issues,
        "detected": kind,
        "mask": crate::util::mask(s),
    })
}

/// Reads `{ path }` or `{ data /* base64 */, name }` of `tool_file`.
fn file_input(a: &Value) -> Result<(String, Vec<u8>), CmdError> {
    if let Some(raw) = arg_str(a, "path") {
        let p = std::path::Path::new(raw);
        let meta = std::fs::metadata(p)
            .map_err(|_| CmdError::not_found(format!("файл не найден: {raw}")))?;
        if !meta.is_file() {
            return Err(bad_args("путь, не файл"));
        }
        if meta.len() > MAX_FILE {
            return Err(bad_args("файл больше 100 МБ"));
        }
        let name = crate::cmds::hygiene::safe_name(arg_str(a, "name").unwrap_or(raw));
        return Ok((name, std::fs::read(p)?));
    }
    let data = arg_str(a, "data").ok_or_else(|| bad_args("нужен path или data"))?;
    if data.len() as u64 > MAX_FILE / 3 * 4 + 4 {
        return Err(bad_args("файл больше 100 МБ"));
    }
    let bytes = foca_core::b64::decode(data).ok_or_else(|| bad_args("data: не base64"))?;
    let name = crate::cmds::hygiene::safe_name(arg_str(a, "name").unwrap_or("file"));
    Ok((name, bytes))
}

fn ext_of(name: &str) -> String {
    name.rsplit_once('.')
        .map(|(_, e)| e.to_lowercase())
        .unwrap_or_default()
}

/// Everything `tool_file` reports, computed in a blocking task.
fn analyze_file(
    bytes: &[u8],
    name: &str,
    path_hint: Option<&std::path::Path>,
    ocr_cfg: &crate::services::ocr::OcrSettings,
    ocr_prov: Option<&dyn crate::OcrProvider>,
    now: time::OffsetDateTime,
) -> Result<Value, String> {
    let lim = foca_meta::Limits::default();
    let fmt = foca_meta::detect(bytes);
    let raw = crate::util::catch_panic(|| {
        foca_meta::extract(bytes, Some(name), &lim).map_err(|e| e.to_string())
    })?;
    let mut text = foca_meta::text(bytes, &lim).ok();
    if let Some(ot) = crate::services::ocr::maybe_ocr(
        ocr_cfg,
        ocr_prov,
        path_hint.unwrap_or_else(|| std::path::Path::new(name)),
        name,
        bytes,
        text.as_deref(),
    ) {
        text = Some(ot);
    }
    // personal data summary, as on import
    let meta = foca_analysis::pii::annotate(&raw, text.as_deref());
    let grade = foca_meta::grade_document(&meta);
    let doc = foca_core::Document {
        id: 1,
        name: name.to_string(),
        ext: ext_of(name),
        url: None,
        host: None,
        source: "toolbox".into(),
        size: bytes.len() as u64,
        sha256: crate::util::hex(&crate::util::sha256(bytes)),
        status: foca_core::DocStatus::Analyzed,
        error: None,
        found_at: Some(now),
        metadata: Some(meta.clone()),
    };
    let mut input = foca_analysis::DocInput::new(&doc);
    input.text = text.as_deref();
    let prev = foca_analysis::PrevState {
        now: Some(now),
        ..Default::default()
    };
    let an = crate::util::catch_panic(|| {
        Ok(foca_analysis::analyze(&[input], &Scope::default(), &prev))
    })?;
    let values: Vec<String> = an
        .secrets
        .iter()
        .map(|s| s.value.expose().to_string())
        .collect();
    let findings: Vec<Value> = an
        .findings
        .iter()
        .map(|f| {
            let ev = crate::dto::protect_evidence(&f.evidence, &values);
            json!({ "rule": f.provenance.rule, "title": f.title, "sev": f.sev,
                "category": f.category, "description": f.description,
                "recommendation": f.recommendation, "evidence": ev })
        })
        .collect();
    let secrets: Vec<Value> = an
        .secrets
        .iter()
        .map(|s| {
            json!({ "type": s.kind, "value": s.value.expose(), "where": s.location,
            "sev": s.sev, "rule": s.rule })
        })
        .collect();
    let m = &meta;
    let metadata = json!({
        "title": m.title, "subject": m.subject, "author": m.author,
        "last_modified_by": m.last_modified_by, "company": m.company, "manager": m.manager,
        "template": m.template, "application": m.application, "producer": m.producer, "os": m.os,
        "created": m.created, "modified": m.modified, "printed": m.printed,
        "edit_time_secs": m.edit_time_secs, "revision": m.revision,
        "people": m.people.len(), "emails": m.emails, "paths": m.paths.len(),
        "servers": m.servers.len(), "printers": m.printers, "software": m.software,
        "links": m.links.len(), "gps": m.gps, "camera": m.camera,
    });
    let forensics = json!({
        "comments": m.comments.len(), "revisions": m.revisions.len(), "rsids": m.rsids.len(),
        "hidden_sheets": m.hidden_sheets, "has_macros": m.has_macros,
        "macro_modules": m.macro_modules, "has_javascript": m.has_javascript,
        "encrypted": m.encrypted, "incremental_updates": m.incremental_updates,
        "old_versions": m.old_versions.len(), "attachments": m.attachments.len(),
        "embedded": m.embedded.iter().map(|e| serde_json::to_value(e).unwrap_or_default()).collect::<Vec<_>>(),
        "signatures": m.signatures, "pdf_revisions": m.pdf_revisions.len(),
        "hidden_content": m.hidden_content, "scan_without_text": m.scan_without_text,
        "thumbnail": m.thumbnail.is_some(), "xmp_history": m.xmp_history.len(),
        "warnings": m.warnings,
    });
    Ok(json!({
        "name": name,
        "ext": ext_of(name),
        "size": bytes.len(),
        "sha256": doc.sha256,
        "format": format!("{fmt:?}").to_lowercase(),
        "metadata": metadata,
        "forensics": forensics,
        "pii": m.pii,
        "bad_redactions": m.bad_redactions,
        "secrets": secrets,
        "findings": findings,
        "grade": grade,
        "cleanable": foca_meta::can_clean(fmt),
        "risk": an.risk,
    }))
}

/// Normalizes the `tool_mail_domain` input: a domain, an e-mail address or a URL.
fn mail_domain(raw: &str) -> Result<String, CmdError> {
    let s = raw.trim();
    let s = s.rsplit('@').next().unwrap_or(s);
    let s = s
        .split_once("://")
        .map(|(_, r)| r)
        .unwrap_or(s)
        .split(['/', '?', '#'])
        .next()
        .unwrap_or("");
    let s = s.rsplit_once(':').map_or(s, |(h, p)| {
        if p.chars().all(|c| c.is_ascii_digit()) {
            h
        } else {
            s
        }
    });
    let (d, _) =
        foca_core::normalize_domain(s).map_err(|e| bad_args(format!("домен «{raw}»: {e}")))?;
    if !d.contains('.') {
        return Err(bad_args(format!("домен «{raw}»: нужно имя с точкой")));
    }
    Ok(d)
}

/// Parsed `tool_host` input.
struct HostTarget {
    host: String,
    port: Option<u16>,
    /// Explicit URL (scheme and path kept); `None` tries `https://host/`, then `http://host/`.
    url: Option<url::Url>,
}

fn host_target(raw: &str) -> Result<HostTarget, CmdError> {
    let s = raw.trim();
    if s.is_empty() {
        return Err(bad_args("нужен url или host"));
    }
    let (with_scheme, explicit) = if s.contains("://") {
        (s.to_string(), true)
    } else {
        (format!("https://{s}"), false)
    };
    let u = url::Url::parse(&with_scheme).map_err(|e| bad_args(format!("адрес «{s}»: {e}")))?;
    if !matches!(u.scheme(), "http" | "https") {
        return Err(bad_args("поддерживаются только http:// и https://"));
    }
    let host = u
        .host_str()
        .map(|h| {
            h.trim_start_matches('[')
                .trim_end_matches(']')
                .to_ascii_lowercase()
        })
        .filter(|h| !h.is_empty())
        .ok_or_else(|| bad_args(format!("адрес «{s}»: нет хоста")))?;
    let mut clean = u.clone();
    let _ = clean.set_username("");
    let _ = clean.set_password(None);
    clean.set_fragment(None);
    Ok(HostTarget {
        host,
        port: u.port(),
        url: explicit.then_some(clean),
    })
}

/// A GET with a capped body that keeps non-2xx responses (their headers matter too).
async fn get_capped(
    net: &NetClient,
    url: &str,
    limit: usize,
    deadline: Instant,
) -> Result<(u16, String, Vec<(String, String)>, Vec<u8>), String> {
    let req = NetRequest::get(url, MODULE, Access::TouchesTarget)
        .map_err(|e| e.to_string())?
        .retries(0)
        .timeout(left(deadline));
    let mut r = net.send(req).await.map_err(|e| e.to_string())?;
    let status = r.status();
    let final_url = r.url().to_string();
    let headers: Vec<(String, String)> = r
        .headers()
        .iter()
        .filter_map(|(k, v)| {
            Some((
                k.as_str().to_ascii_lowercase(),
                v.to_str().ok()?.to_string(),
            ))
        })
        .collect();
    let mut body = Vec::new();
    while let Some(c) = r.chunk().await.map_err(|e| e.to_string())? {
        if body.len() + c.len() > limit {
            body.extend_from_slice(&c[..limit - body.len()]);
            r.abort();
            break;
        }
        body.extend_from_slice(&c);
    }
    Ok((status, final_url, headers, body))
}

/// `tool_log { limit? }` → the last toolbox requests, newest first.
pub(crate) fn tool_log(core: &Core, a: &Value) -> CmdResult {
    let limit = a.get("limit").and_then(Value::as_u64).unwrap_or(100) as usize;
    let g = lock(&core.tool_log);
    Ok(json!(g
        .iter()
        .rev()
        .take(limit)
        .cloned()
        .collect::<Vec<_>>()))
}

/// `tool_log_clear` empties the toolbox request ring; returns `{ ok, removed }`.
pub(crate) fn tool_log_clear(core: &Core) -> CmdResult {
    let mut g = lock(&core.tool_log);
    let removed = g.len();
    g.clear();
    Ok(json!({ "ok": true, "removed": removed }))
}

/// `tool_file { path | data, name?, timeout_ms? }`.
pub(crate) async fn tool_file(core: &Core, a: &Value) -> CmdResult {
    let t0 = Instant::now();
    let deadline = t0 + budget(a);
    let (name, bytes) = file_input(a)?;
    let now = core.now();
    let n2 = name.clone();
    let size = bytes.len();
    let sha = crate::util::hex(&crate::util::sha256(&bytes));
    let path_opt = a
        .get("path")
        .and_then(Value::as_str)
        .map(std::path::PathBuf::from);
    let ocr_cfg = crate::services::ocr::OcrSettings::from_settings(
        &core.store().settings_get().unwrap_or_default(),
    );
    let ocr_prov = core.current_ocr();
    let job = tokio::task::spawn_blocking(move || {
        analyze_file(
            &bytes,
            &n2,
            path_opt.as_deref(),
            &ocr_cfg,
            ocr_prov.as_deref(),
            now,
        )
    });
    let mut out = match tokio::time::timeout(left(deadline), job).await {
        Ok(Ok(Ok(v))) => {
            let mut v = v;
            v["partial"] = json!(false);
            v["error"] = Value::Null;
            v
        }
        Ok(Ok(Err(e))) => {
            json!({ "name": name, "ext": ext_of(&name), "size": size, "sha256": sha,
            "partial": true, "error": format!("файл не разобран: {e}") })
        }
        Ok(Err(e)) => return Err(CmdError::internal(e)),
        Err(_) => json!({ "name": name, "ext": ext_of(&name), "size": size, "sha256": sha,
            "partial": true, "error": "timeout" }),
    };
    // cleaning is the existing command on the same file
    out["clean_with"] = if a.get("path").is_some() {
        json!({ "cmd": "doc_clean", "args": { "path": a["path"], "name": name } })
    } else {
        Value::Null
    };
    out["elapsed_ms"] = json!(t0.elapsed().as_millis() as u64);
    out["requests"] = json!([]);
    Ok(out)
}

/// `tool_secret { value, hibp_opt_in?, timeout_ms? }`: local estimate; HIBP k-anonymity is opt-in.
pub(crate) async fn tool_secret(core: &Core, a: &Value) -> CmdResult {
    let t0 = Instant::now();
    let deadline = t0 + budget(a);
    let v = a
        .get("value")
        .and_then(Value::as_str)
        .ok_or_else(|| bad_args("нужно значение value"))?;
    if v.chars().count() > 4096 {
        return Err(bad_args("значение длиннее 4096 символов"));
    }
    let mut out = secret_estimate(v);
    let opt_in = a
        .get("hibp_opt_in")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    if !opt_in {
        out["hibp"] = json!({ "status": "not_requested" });
        out["requests"] = json!([]);
        out["partial"] = json!(false);
        out["elapsed_ms"] = json!(t0.elapsed().as_millis() as u64);
        return Ok(out);
    }
    let cancel = CancellationToken::new();
    let (net, sink) = tool_net(core, "secret", Scope::default(), None, &cancel)?;
    let base = core.cfg.endpoints.sources.get("hibp").map(String::as_str);
    let res = tokio::time::timeout(
        left(deadline),
        foca_net::hibp::check_pwned_password(&net, v, base, left(deadline)),
    )
    .await;
    cancel.cancel();
    let (hibp, partial) = match res {
        Ok(Ok(r)) => (
            json!({ "status": "ok", "pwned": r.pwned, "count": r.count, "prefix": r.prefix }),
            false,
        ),
        Ok(Err(e)) if expired(deadline) => {
            let _ = e;
            (json!({ "status": "timeout", "error": "timeout" }), true)
        }
        Ok(Err(e)) => (json!({ "status": "error", "error": e.to_string() }), true),
        Err(_) => (json!({ "status": "timeout", "error": "timeout" }), true),
    };
    out["hibp"] = hibp;
    out["requests"] = sink.json();
    out["partial"] = json!(partial);
    out["elapsed_ms"] = json!(t0.elapsed().as_millis() as u64);
    Ok(out)
}

/// `tool_mail_domain { domain, timeout_ms?, fetch_policy? = true }`.
pub(crate) async fn tool_mail_domain(core: &Core, a: &Value) -> CmdResult {
    let t0 = Instant::now();
    let deadline = t0 + budget(a);
    let raw = arg_str(a, "domain")
        .or_else(|| arg_str(a, "email"))
        .ok_or_else(|| bad_args("нужен domain"))?;
    let d = mail_domain(raw)?;
    // the only target host this tool may touch is the MTA-STS policy server (or its test
    // override)
    let sts_base = core.cfg.endpoints.sources.get("mta_sts").cloned();
    let mut lines = format!("mta-sts.{d}");
    if let Some(b) = &sts_base {
        lines.push('\n');
        lines.push_str(b);
    }
    let (scope, _) = Scope::from_lines(&lines, "");
    let cancel = CancellationToken::new();
    let (net, sink) = tool_net(core, "mail", scope, Some("target"), &cancel)?;
    let dns: Arc<dyn DnsLookup> = match &core.cfg.dns {
        Some(x) => x.clone(),
        None => {
            let mode = core.store().settings_get().unwrap_or_default()["net"]["dns_mode"]
                .as_str()
                .map(foca_net::doh::DnsMode::parse)
                .unwrap_or_default();
            foca_net::doh::resolver(mode, &Default::default(), &net)
                .map_err(|e| CmdError::new("net", e.to_string()))?
        }
    };
    let probe = format!(
        "foca-{:x}._domainkey.{d}",
        crate::util::fnv(&format!("{d}{:?}", t0))
    );
    let mut names: Vec<(String, String, RType)> = vec![
        ("root".into(), d.clone(), RType::TXT),
        ("dmarc".into(), format!("_dmarc.{d}"), RType::TXT),
        ("mx".into(), d.clone(), RType::MX),
        ("bimi".into(), format!("default._bimi.{d}"), RType::TXT),
        ("mta_sts".into(), format!("_mta-sts.{d}"), RType::TXT),
        ("tls_rpt".into(), format!("_smtp._tls.{d}"), RType::TXT),
        ("caa".into(), d.clone(), RType::CAA),
        ("ds".into(), d.clone(), RType::DS),
        ("dnskey".into(), d.clone(), RType::DNSKEY),
        ("dkim_probe".into(), probe, RType::TXT),
    ];
    for s in foca_net::mail::DKIM_SELECTORS {
        names.push((
            format!("dkim:{s}"),
            format!("{s}._domainkey.{d}"),
            RType::TXT,
        ));
    }
    let total = names.len();
    let mut set = tokio::task::JoinSet::new();
    for (key, name, t) in names {
        let dns = dns.clone();
        set.spawn(async move {
            let r = dns.lookup(&name, t).await;
            (key, r.map(|a| a.values(t)).map_err(|e| e.to_string()))
        });
    }
    let mut got: BTreeMap<String, Result<Vec<String>, String>> = BTreeMap::new();
    // DNS gets the budget minus a reserve for the MTA-STS policy file
    let dns_deadline = deadline - (deadline - t0) / 5;
    while let Ok(Some(r)) = tokio::time::timeout(left(dns_deadline), set.join_next()).await {
        if let Ok((k, v)) = r {
            got.insert(k, v);
        }
    }
    set.abort_all();
    let missing: Vec<String> = {
        let mut m: Vec<String> = Vec::new();
        for k in [
            "root", "dmarc", "mx", "bimi", "mta_sts", "tls_rpt", "caa", "ds", "dnskey",
        ] {
            if !got.contains_key(k) {
                m.push(k.to_string());
            }
        }
        let dk = got.keys().filter(|k| k.starts_with("dkim:")).count();
        if dk < foca_net::mail::DKIM_SELECTORS.len() {
            m.push(format!(
                "dkim ({} из {})",
                foca_net::mail::DKIM_SELECTORS.len() - dk,
                foca_net::mail::DKIM_SELECTORS.len()
            ));
        }
        m
    };
    let vals = |k: &str| -> Vec<String> {
        got.get(k)
            .and_then(|r| r.as_ref().ok())
            .cloned()
            .unwrap_or_default()
    };
    let mx = vals("mx");
    let has_mx = !mx.is_empty();
    let wildcard = vals("dkim_probe")
        .iter()
        .any(|t| foca_net::mail::dkim_has_key(t));
    let dkim: Vec<String> = if wildcard {
        Vec::new()
    } else {
        foca_net::mail::DKIM_SELECTORS
            .iter()
            .filter(|s| {
                vals(&format!("dkim:{s}"))
                    .iter()
                    .any(|t| foca_net::mail::dkim_has_key(t))
            })
            .map(|s| s.to_string())
            .collect()
    };
    let mail = foca_net::mail::analyze_mail(&d, &vals("root"), &vals("dmarc"), &dkim, has_mx);
    let has_sts = vals("mta_sts")
        .iter()
        .any(|t| t.to_ascii_lowercase().starts_with("v=stsv1"));
    let mut policy_step = step("skipped", None);
    let policy = if has_sts && a.get("fetch_policy").and_then(Value::as_bool) != Some(false) {
        match tokio::time::timeout(
            left(deadline),
            foca_net::mail::fetch_mta_sts_policy(&net, &d, sts_base.as_deref()),
        )
        .await
        {
            Ok(Ok(p)) => {
                policy_step = step("ok", None);
                Some(Ok(p))
            }
            Ok(Err(e)) if expired(deadline) => {
                let _ = e;
                policy_step = step("timeout", None);
                None
            }
            Ok(Err(e)) => {
                policy_step = step("error", Some(e.to_string()));
                Some(Err(e.to_string()))
            }
            Err(_) => {
                cancel.cancel();
                policy_step = step("timeout", None);
                None
            }
        }
    } else {
        None
    };
    let dnssec = match (got.get("ds"), got.get("dnskey")) {
        (Some(Ok(ds)), Some(Ok(key))) => match (!ds.is_empty(), !key.is_empty()) {
            (true, _) => foca_net::mail::DnssecStatus::Signed,
            (false, true) => foca_net::mail::DnssecStatus::Unanchored,
            (false, false) => foca_net::mail::DnssecStatus::Unsigned,
        },
        (Some(Ok(ds)), _) if !ds.is_empty() => foca_net::mail::DnssecStatus::Signed,
        _ => foca_net::mail::DnssecStatus::Unknown,
    };
    let inp = foca_net::mail::PolicyInputs {
        bimi_txt: vals("bimi"),
        mta_sts_txt: vals("mta_sts"),
        mta_sts_policy: policy,
        tls_rpt_txt: vals("tls_rpt"),
        caa: vals("caa"),
        mx: mx.clone(),
        dnssec,
        dmarc: mail.dmarc.clone(),
    };
    let pol = foca_net::mail::analyze_policies(&d, &inp);
    let complete = got.contains_key("root") && got.contains_key("dmarc");
    let (level, reasons) = spoofing_risk(&mail, complete);
    let mut issues: Vec<Value> = mail
        .issues
        .iter()
        .chain(pol.issues.iter())
        .map(|i| serde_json::to_value(i).unwrap_or_default())
        .collect();
    issues.sort_by_key(|i| {
        ["crit", "high", "warn", "low", "info"]
            .iter()
            .position(|s| i["sev"] == *s)
            .unwrap_or(9)
    });
    Ok(json!({
        "domain": d,
        "risk": { "level": level, "reasons": reasons, "spoofable": mail.spoofable },
        "mx": mx,
        "spf": mail.spf,
        "dmarc": mail.dmarc,
        "dkim": { "selectors": dkim, "checked": foca_net::mail::DKIM_SELECTORS.len(), "wildcard": wildcard },
        "bimi": pol.bimi,
        "mta_sts": { "record": pol.mta_sts, "policy": pol.mta_sts_policy, "fetch": policy_step },
        "tls_rpt": pol.tls_rpt,
        "caa": pol.caa,
        "dnssec": pol.dnssec,
        "issues": issues,
        "partial": !missing.is_empty() || policy_step["status"] == "timeout",
        "incomplete": missing,
        "lookups": { "done": got.len(), "total": total },
        "elapsed_ms": t0.elapsed().as_millis() as u64,
        "requests": sink.json(),
    }))
}

/// `tool_host { url | host, timeout_ms? }`: one host on explicit user request.
pub(crate) async fn tool_host(core: &Core, a: &Value) -> CmdResult {
    let t0 = Instant::now();
    let deadline = t0 + budget(a);
    let raw = arg_str(a, "url")
        .or_else(|| arg_str(a, "host"))
        .ok_or_else(|| bad_args("нужен url или host"))?;
    let tg = host_target(raw)?;
    let host_port = match tg.port {
        Some(p) => format!("{}:{p}", tg.host),
        None => tg.host.clone(),
    };
    let host_lit = if tg.host.contains(':') {
        format!("[{}]", tg.host)
    } else {
        tg.host.clone()
    };
    let authority = match tg.port {
        Some(p) => format!("{host_lit}:{p}"),
        None => host_lit.clone(),
    };
    // the scope is exactly this host: redirects elsewhere are refused and logged
    let (scope, errs) = Scope::from_lines(&format!("https://{authority}/"), "");
    if !errs.is_empty() || !scope.allows_host(&tg.host) {
        return Err(bad_args(format!("адрес «{raw}» не поддерживается")));
    }
    let cancel = CancellationToken::new();
    let (net, sink) = tool_net(core, "host", scope, Some("target"), &cancel)?;
    let candidates: Vec<String> = match &tg.url {
        Some(u) => vec![u.to_string()],
        None => vec![
            format!("https://{authority}/"),
            format!("http://{authority}/"),
        ],
    };
    let want_tls = tg.url.as_ref().is_none_or(|u| u.scheme() == "https");
    let tls_port = match &tg.url {
        Some(u) if u.scheme() == "https" => tg.port.unwrap_or(443),
        Some(_) => 443,
        None => tg.port.unwrap_or(443),
    };
    let now_unix = core.now().unix_timestamp();
    let tls_fut = async {
        if !want_tls {
            return (step("skipped", Some("адрес http://".into())), Value::Null);
        }
        let opts = foca_net::tls::InspectOptions {
            timeout: left(deadline),
            ..Default::default()
        };
        match tokio::time::timeout(
            left(deadline),
            foca_net::tls::inspect_standard(&net, &tg.host, tls_port, &opts),
        )
        .await
        {
            Ok(Ok(ins)) if !ins.chain.is_empty() => {
                let cfg = foca_net::tls::AuditConfig {
                    now: now_unix,
                    ..Default::default()
                };
                let audit = ins.audit(&cfg).ok();
                let v = json!({
                    "port": tls_port, "version": ins.version, "cipher": ins.cipher,
                    "alpn": ins.alpn, "ocsp_stapled": ins.ocsp_stapled,
                    "leaf": ins.leaf(), "chain": ins.chain.len(),
                    "trust": audit.as_ref().map(|x| serde_json::to_value(&x.trust).unwrap_or_default()),
                    "hostname_match": audit.as_ref().and_then(|x| x.hostname_match),
                    "days_left": audit.as_ref().map(|x| x.days_left),
                    "issues": audit.as_ref().map(|x| serde_json::to_value(&x.issues).unwrap_or_default()).unwrap_or(json!([])),
                    "error": ins.error,
                });
                (step("ok", None), v)
            }
            Ok(Ok(ins)) => (
                step(
                    "error",
                    Some(ins.error.unwrap_or_else(|| "сертификат не получен".into())),
                ),
                Value::Null,
            ),
            Ok(Err(e)) => (failed(deadline, e.to_string()), Value::Null),
            Err(_) => (step("timeout", None), Value::Null),
        }
    };
    let page_fut = async {
        let mut last = String::new();
        for u in &candidates {
            match tokio::time::timeout(left(deadline), get_capped(&net, u, PAGE_LIMIT, deadline))
                .await
            {
                Ok(Ok(p)) => return Ok(p),
                Ok(Err(_)) if expired(deadline) => return Err(None),
                Ok(Err(e)) => last = e,
                Err(_) => return Err(None),
            }
            if Instant::now() >= deadline {
                break;
            }
        }
        Err(Some(last))
    };
    let ((tls_step, tls), page) = tokio::join!(tls_fut, page_fut);
    let mut steps = json!({ "tls": tls_step });
    let mut out = json!({
        "input": raw, "host": tg.host, "port": tg.port, "url": Value::Null,
        "status": Value::Null, "headers": Value::Null, "header_issues": [],
        "technologies": [], "favicon": Value::Null, "tls": tls,
    });
    match page {
        Ok((status, final_url, headers, body)) => {
            steps["page"] = step("ok", None);
            let html = String::from_utf8_lossy(&body).into_owned();
            let audit = foca_recon::headers::analyze(&final_url, &headers, &html);
            let techs = foca_recon::tech::detect(&foca_recon::tech::PageInput {
                url: final_url.clone(),
                headers: headers.clone(),
                html: html.clone(),
            });
            out["url"] = json!(final_url);
            out["status"] = json!(status);
            out["header_issues"] = serde_json::to_value(&audit.issues)?;
            out["headers"] = serde_json::to_value(&audit)?;
            out["technologies"] = serde_json::to_value(&techs)?;
            // favicon: the first icon link, otherwise /favicon.ico
            let icon = foca_recon::favicon::find_icon_links(&html, &final_url)
                .into_iter()
                .map(|l| l.url)
                .find(|u| {
                    url::Url::parse(u)
                        .ok()
                        .and_then(|x| {
                            x.host_str().map(|h| {
                                h.eq_ignore_ascii_case(&host_lit)
                                    || h.eq_ignore_ascii_case(&tg.host)
                            })
                        })
                        .unwrap_or(false)
                })
                .or_else(|| {
                    url::Url::parse(&final_url)
                        .ok()?
                        .join("/favicon.ico")
                        .ok()
                        .map(|u| u.to_string())
                });
            steps["favicon"] = match icon {
                _ if Instant::now() >= deadline => step("timeout", None),
                None => step("skipped", None),
                Some(iu) => match tokio::time::timeout(
                    left(deadline),
                    get_capped(&net, &iu, ICON_LIMIT, deadline),
                )
                .await
                {
                    Ok(Ok((st, _, _, b))) => {
                        let head =
                            String::from_utf8_lossy(&b[..b.len().min(256)]).to_ascii_lowercase();
                        if (200..300).contains(&st)
                            && !b.is_empty()
                            && !head.contains("<html")
                            && !head.contains("<!doctype")
                        {
                            let h = foca_recon::favicon::favicon_hash(&b);
                            out["favicon"] = json!({ "url": iu, "mmh3": h.mmh3,
                                "sha256": h.sha256, "md5": h.md5, "size": h.size, "queries": h.queries });
                            step("ok", None)
                        } else {
                            step("error", Some(format!("HTTP {st}: не иконка")))
                        }
                    }
                    Ok(Err(e)) => failed(deadline, e),
                    Err(_) => step("timeout", None),
                },
            };
        }
        Err(Some(e)) => {
            steps["page"] = step("error", Some(e));
            steps["favicon"] = step("skipped", None);
        }
        Err(None) => {
            steps["page"] = step("timeout", None);
            steps["favicon"] = step("skipped", None);
        }
    }
    cancel.cancel();
    let partial = ["page", "tls", "favicon"]
        .iter()
        .any(|k| steps[k]["status"] == "timeout");
    out["host_port"] = json!(host_port);
    out["steps"] = steps;
    out["partial"] = json!(partial);
    out["elapsed_ms"] = json!(t0.elapsed().as_millis() as u64);
    out["requests"] = sink.json();
    Ok(out)
}

/// A client for one tool call: settings.net on top, the given scope, the toolbox log.
fn tool_net(
    core: &Core,
    tool: &'static str,
    scope: Scope,
    group: Option<&str>,
    cancel: &CancellationToken,
) -> Result<(NetClient, Arc<ToolSink>), CmdError> {
    let sink = Arc::new(ToolSink {
        recs: Mutex::new(Vec::new()),
        ring: core.tool_log.clone(),
        tool,
    });
    let net = core
        .net_client_group(scope, sink.clone(), None, group)?
        .with_cancel(cancel.clone());
    Ok((net, sink))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report(spf: Option<&str>, dmarc: Option<&str>, mx: bool) -> foca_net::mail::MailReport {
        let root: Vec<String> = spf.map(|s| vec![s.to_string()]).unwrap_or_default();
        let dm: Vec<String> = dmarc.map(|s| vec![s.to_string()]).unwrap_or_default();
        foca_net::mail::analyze_mail("example.test", &root, &dm, &["google".into()], mx)
    }

    #[test]
    fn spoofing_levels() {
        let r = report(Some("v=spf1 -all"), Some("v=DMARC1; p=reject"), true);
        assert_eq!(spoofing_risk(&r, true).0, "low");
        let r = report(
            Some("v=spf1 ~all"),
            Some("v=DMARC1; p=quarantine; pct=50"),
            true,
        );
        assert_eq!(spoofing_risk(&r, true).0, "medium");
        let r = report(Some("v=spf1 -all"), None, true);
        assert_eq!(spoofing_risk(&r, true).0, "medium");
        let r = report(Some("v=spf1 ~all"), Some("v=DMARC1; p=none"), true);
        assert_eq!(spoofing_risk(&r, true).0, "high");
        let r = report(Some("v=spf1 +all"), Some("v=DMARC1; p=reject"), true);
        assert_eq!(spoofing_risk(&r, true).0, "high");
        let r = report(None, None, false);
        let (lvl, why) = spoofing_risk(&r, true);
        assert_eq!(lvl, "high");
        assert!(why.iter().any(|w| w.contains("нет MX")));
        assert_eq!(spoofing_risk(&r, false).0, "unknown");
    }

    #[test]
    fn secret_estimates() {
        let weak = secret_estimate("password123");
        assert_eq!(weak["strength"], "very_weak");
        assert!(weak["issues"]
            .as_array()
            .unwrap()
            .contains(&json!("common_word")));
        let strong = secret_estimate("vT9#qLm2!xR7&pZw4@kN");
        assert!(strong["score"].as_u64().unwrap() >= 3, "{strong}");
        assert_eq!(secret_estimate("aaaaaaaaaaaaaaaa")["score"], 0);
        // the value itself never comes back, only its mask
        let s = secret_estimate("vT9#qLm2!xR7&pZw4@kN").to_string();
        assert!(!s.contains("qLm2"));
    }

    #[test]
    fn inputs_are_normalized() {
        assert_eq!(mail_domain("Ivan@Example.TEST").unwrap(), "example.test");
        assert_eq!(
            mail_domain("https://example.test:8443/a").unwrap(),
            "example.test"
        );
        assert!(mail_domain("localhost").is_err());
        let t = host_target("example.test").unwrap();
        assert!(t.url.is_none() && t.port.is_none());
        let t = host_target("http://user:pw@127.0.0.1:8080/x#f").unwrap();
        assert_eq!(t.host, "127.0.0.1");
        assert_eq!(t.port, Some(8080));
        assert_eq!(t.url.unwrap().as_str(), "http://127.0.0.1:8080/x");
        assert!(host_target("ftp://example.test").is_err());
    }
}
