//! Debug tab (`#/settings/debug`): core and Android logs, crashes, the project request log, build
//! version, log level, ZIP export of logs with secrets scrubbed, and terms acceptance.
//!
//! Files live in `<data>/logs/`: `foca.log*` (core, [`crate::services::logs`]), `android.log*` (Kotlin
//! `FLog`) and `crash-*.txt` (Rust panics from `src-tauri/src/applog.rs`, Kotlin crashes from `CrashLog`).

use std::io::Write as _;
use std::path::PathBuf;

use serde_json::{json, Value};

use crate::engine::{lock, Engine};
use crate::util::{arg_str, arg_u64};
use crate::{CmdError, CmdResult};

/// Version of the terms of use text (first-run screen). Changing it shows the screen again.
pub const TERMS_VERSION: &str = "1";

/// Build commit (`FOCA_GIT_HASH` at build time; empty if unknown).
pub const GIT_HASH: &str = match option_env!("FOCA_GIT_HASH") {
    Some(h) => h,
    None => "",
};

const ANDROID_LOG: &str = "android.log";

fn level_of(code: &str) -> &'static str {
    match code {
        "E" => "error",
        "W" => "warn",
        "D" | "V" => "debug",
        _ => "info",
    }
}

fn rank(l: &str) -> u8 {
    match l {
        "error" => 3,
        "warn" => 2,
        "info" => 1,
        _ => 0,
    }
}

/// Parses `android.log`: `2026-11-20T12:00:00.000 I [main] message` (plus indented stack trace lines).
pub fn parse_android(text: &str, min: u8) -> Vec<Value> {
    let mut out: Vec<Value> = Vec::new();
    for line in text.lines() {
        let mut it = line.splitn(3, ' ');
        let (t, lv, rest) = (it.next(), it.next(), it.next());
        let ok = t.is_some_and(|t| t.len() >= 19 && t.as_bytes().get(10) == Some(&b'T'))
            && lv.is_some_and(|l| l.len() == 1);
        if !ok {
            if let Some(last) = out.last_mut() {
                let m = format!(
                    "{}\n{}",
                    last["msg"].as_str().unwrap_or(""),
                    line.trim_end()
                );
                last["msg"] = json!(m);
            }
            continue;
        }
        let rest = rest.unwrap_or("");
        let (target, msg) = match rest.strip_prefix('[').and_then(|r| r.split_once("] ")) {
            Some((th, m)) => (format!("android/{th}"), m.to_string()),
            None => ("android".to_string(), rest.to_string()),
        };
        out.push(
            json!({ "t": t.unwrap_or(""), "level": level_of(lv.unwrap_or("I")), "target": target,
            "msg": msg, "source": "android" }),
        );
    }
    out.retain(|e| rank(e["level"].as_str().unwrap_or("")) >= min);
    out
}

impl Engine {
    fn logs_dir(&self) -> PathBuf {
        self.inner.cfg.data_dir.join("logs")
    }

    fn read_rotated(&self, base: &str) -> String {
        let d = self.logs_dir();
        let mut s = String::new();
        for name in [format!("{base}.2"), format!("{base}.1"), base.to_string()] {
            if let Ok(t) = std::fs::read_to_string(d.join(&name)) {
                s.push_str(&t);
            }
        }
        s
    }

    /// `logs_get { level?, since?, limit?, source?: "core"|"android"|"all" }`.
    pub(crate) fn logs_get(&self, a: &Value) -> CmdResult {
        let source = arg_str(a, "source").unwrap_or("core");
        let limit = arg_u64(a, "limit").unwrap_or(500).max(1) as usize;
        let level = arg_str(a, "level");
        let mut out: Vec<Value> = Vec::new();
        if source != "android" {
            for e in crate::services::logs::get(level, arg_u64(a, "since"), Some(limit)) {
                let mut v = serde_json::to_value(e)?;
                v["source"] = json!("core");
                out.push(v);
            }
        }
        if source != "core" {
            let min = level.map(rank).unwrap_or(0);
            let mut v = parse_android(&self.read_rotated(ANDROID_LOG), min);
            let n = v.len();
            out.extend(v.drain(n.saturating_sub(limit)..));
        }
        if source == "all" {
            out.sort_by(|x, y| x["t"].as_str().cmp(&y["t"].as_str()));
            let n = out.len();
            out.drain(..n.saturating_sub(limit));
        }
        Ok(Value::Array(out))
    }

    /// `crash_list` returns `[{ name, size, t, kind: "rust"|"android" }]`, newest first.
    pub(crate) fn crash_list(&self) -> CmdResult {
        let mut v: Vec<(String, u64)> = std::fs::read_dir(self.logs_dir())
            .map(|rd| {
                rd.flatten()
                    .filter_map(|e| {
                        let n = e.file_name().to_string_lossy().to_string();
                        (n.starts_with("crash-") && n.ends_with(".txt"))
                            .then(|| (n, e.metadata().map(|m| m.len()).unwrap_or(0)))
                    })
                    .collect()
            })
            .unwrap_or_default();
        v.sort_by(|a, b| b.0.cmp(&a.0));
        Ok(Value::Array(
            v.into_iter()
                .map(|(n, size)| {
                    let text =
                        std::fs::read_to_string(self.logs_dir().join(&n)).unwrap_or_default();
                    let kind = if text.contains("Kotlin") || text.contains("java.") {
                        "android"
                    } else {
                        "rust"
                    };
                    let first_raw = text
                        .lines()
                        .find(|l| !l.trim().is_empty())
                        .unwrap_or("")
                        .chars()
                        .take(160)
                        .collect::<String>();
                    let first = crate::analysis::redact::redact(&first_raw, &self.known_secrets());
                    json!({ "name": n, "size": size, "kind": kind, "title": first })
                })
                .collect(),
        ))
    }

    /// `crash_get { name }` returns `{ name, text }` with secrets scrubbed from the text.
    pub(crate) fn crash_get(&self, a: &Value) -> CmdResult {
        let name = arg_str(a, "name").unwrap_or("");
        if !(name.starts_with("crash-") && name.ends_with(".txt"))
            || name.contains('/')
            || name.contains('\\')
            || name.contains("..")
            || name.contains('\0')
        {
            return Err(CmdError::new("bad_args", "Неверное имя файла сбоя"));
        }
        let text = std::fs::read_to_string(self.logs_dir().join(name))
            .map_err(|_| CmdError::not_found("Файл сбоя не найден"))?;
        Ok(
            json!({ "name": name, "text": crate::analysis::redact::redact(&text, &self.known_secrets()) }),
        )
    }

    /// `logs_clear`: clears the core buffer, `foca.log*`, `android.log*` and `crash-*.txt`.
    pub(crate) fn logs_clear(&self) -> CmdResult {
        crate::services::logs::clear();
        let mut n = 0;
        if let Ok(rd) = std::fs::read_dir(self.logs_dir()) {
            for e in rd.flatten() {
                let name = e.file_name().to_string_lossy().to_string();
                let ours = name.starts_with("foca.log")
                    || name.starts_with(ANDROID_LOG)
                    || (name.starts_with("crash-") && name.ends_with(".txt"));
                if ours {
                    // open log files are truncated rather than deleted, since writers keep appending to them
                    let ok = if name == "foca.log" || name == ANDROID_LOG {
                        std::fs::write(e.path(), b"").is_ok()
                    } else {
                        std::fs::remove_file(e.path()).is_ok()
                    };
                    n += ok as u32;
                }
            }
        }
        tracing::info!(target: "foca::debug", "журналы очищены пользователем");
        Ok(json!({ "ok": true, "files": n }))
    }

    /// `request_log_get { project, limit?, only_active? }` returns `[{ id, time, scan_id, module, method, url,
    /// host, status, bytes, access: "passive"|"target"|"active", blocked, error, note, ctype }]`, newest first.
    pub(crate) fn request_log_get(&self, a: &Value) -> CmdResult {
        let id = self.project_arg(a)?;
        let db = self.db(&id)?;
        let only = a
            .get("only_active")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let limit = arg_u64(a, "limit").unwrap_or(500).max(1) as usize;
        let known = self.known_secrets();
        let log = lock(&db).requests(None, only)?;
        Ok(Value::Array(
            log.iter()
                .rev()
                .take(limit)
                .map(|r| {
                    let access = if !r.active {
                        "passive"
                    } else if crate::scan::ACTIVE_MODULES.contains(&r.module.as_str())
                        || [
                            "tls-legacy",
                            "starttls",
                            "tls-no-sni",
                            "http_options",
                            "http_trace",
                            "webdav_propfind",
                            "cors_origin",
                            "graphql_introspection",
                        ]
                        .contains(&r.module.as_str())
                    {
                        "active"
                    } else {
                        "target"
                    };
                    let mut v = json!({ "id": r.id, "time": r.time, "scan_id": r.scan_id, "module": r.module,
                        "method": r.method, "url": crate::analysis::redact::redact(&r.url, &known), "host": r.host,
                        "status": r.status, "bytes": r.bytes, "access": access,
                        "blocked": foca_core::scope::is_scope_block(r.error.as_deref())
                            || r.error.as_deref().is_some_and(|e| e.contains("скоуп") || e.contains("scope")),
                        "error": r.error, "note": r.note, "ctype": r.ctype });
                    let (code, detail) = journal_error(r.error.as_deref());
                    v["error_code"] = json!(code);
                    v["error_detail"] = json!(detail);
                    crate::i18n::annotate(&mut v, &["error_detail"]);
                    v
                })
                .collect(),
        ))
    }

    /// `app_info` returns `{ version, commit, data_dir_mb, log_level }`.
    pub(crate) fn app_info(&self) -> CmdResult {
        fn size(p: &std::path::Path) -> u64 {
            std::fs::read_dir(p)
                .map(|rd| {
                    rd.flatten()
                        .map(|e| match e.metadata() {
                            Ok(m) if m.is_dir() => size(&e.path()),
                            Ok(m) => m.len(),
                            Err(_) => 0,
                        })
                        .sum()
                })
                .unwrap_or(0)
        }
        let s = self.store().settings_get()?;
        Ok(
            json!({ "version": env!("CARGO_PKG_VERSION"), "commit": GIT_HASH,
            "data_mb": (size(&self.inner.cfg.data_dir) as f64 / 1048576.0 * 10.0).round() / 10.0,
            "log_level": s["debug"]["level"].as_str().unwrap_or("info") }),
        )
    }

    /// `logs_export { device?: string }` writes a ZIP to the export directory with core and Android
    /// logs, crashes and `device.txt`, all scrubbed of secrets. The UI then calls `platform_share { path }`.
    pub(crate) fn logs_export(&self, a: &Value) -> CmdResult {
        let known = self.known_secrets();
        let red = |t: &str| crate::analysis::redact::redact(t, &known);
        let mut files: Vec<(String, String)> = vec![
            ("foca.log".into(), red(&self.read_rotated("foca.log"))),
            ("android.log".into(), red(&self.read_rotated(ANDROID_LOG))),
        ];
        if let Ok(rd) = std::fs::read_dir(self.logs_dir()) {
            let mut names: Vec<String> = rd
                .flatten()
                .map(|e| e.file_name().to_string_lossy().to_string())
                .filter(|n| n.starts_with("crash-") && n.ends_with(".txt"))
                .collect();
            names.sort();
            for n in names {
                let t = std::fs::read_to_string(self.logs_dir().join(&n)).unwrap_or_default();
                files.push((format!("crashes/{n}"), red(&t)));
            }
        }
        let info = self.app_info()?;
        // header in the UI language (`lang` from the UI, else the resolved one)
        let lang = arg_str(a, "lang")
            .and_then(foca_core::Lang::parse)
            .unwrap_or_else(|| self.ui_lang());
        let t = |k: &str| crate::services::i18n::core_text(lang, k, &Value::Null);
        let device = format!(
            "FOCA-rs {} ({})\n{}: {}\n\n{}\n",
            info["version"].as_str().unwrap_or(""),
            if GIT_HASH.is_empty() {
                t("device.no_commit")
            } else {
                GIT_HASH.to_string()
            },
            t("device.export"),
            self.now_iso(),
            arg_str(a, "device").unwrap_or("")
        );
        files.push(("device.txt".into(), red(&device)));
        let mut w = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        let opts = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated);
        for (n, t) in &files {
            w.start_file(n.as_str(), opts)
                .map_err(|e| CmdError::new("io", e.to_string()))?;
            w.write_all(t.as_bytes())?;
        }
        let bytes = w
            .finish()
            .map_err(|e| CmdError::new("io", e.to_string()))?
            .into_inner();
        let dir = &self.inner.cfg.export_dir;
        std::fs::create_dir_all(dir)?;
        let stamp: String = self
            .now_iso()
            .chars()
            .filter(|c| c.is_ascii_digit())
            .take(14)
            .collect();
        let name = format!("FOCA-rs_logs_{stamp}.zip");
        let path = dir.join(&name);
        std::fs::write(&path, &bytes)?;
        tracing::info!(target: "foca::debug", "журналы выгружены: {name}, {} файлов", files.len());
        Ok(
            json!({ "name": name, "path": path.to_string_lossy(), "size": bytes.len(), "files": files.len() }),
        )
    }

    /// `search_journal` returns `{ engines: { id: { requests, answered, links, captchas, cached,
    /// moved, taken_over, blocked } } }`: dork engine statistics since the core started.
    pub(crate) fn search_journal(&self) -> CmdResult {
        Ok(json!({ "engines": foca_search::sources::engine_journal() }))
    }

    /// `search_fingerprint` returns `{ ok, fp, issues }`: the embedded search browser opens a local
    /// fingerprint page (UA, Client Hints, visibilityState, webdriver, dimensions, touch, languages,
    /// rAF). Outside Android (no WebView) it returns `unsupported`.
    pub(crate) async fn search_fingerprint(&self) -> CmdResult {
        let Some(render) = self.current_render() else {
            return Err(CmdError::new(
                "unsupported",
                "Отпечаток встроенного браузера доступен только в приложении на телефоне",
            ));
        };
        let req = foca_search::render::fingerprint_request(std::time::Duration::from_secs(40));
        let page = render
            .fetch(req)
            .await
            .map_err(|e| CmdError::new("platform", format!("встроенный браузер: {e}")))?;
        let fp = foca_search::render::parse_fingerprint(&page.html).ok_or_else(|| {
            CmdError::new(
                "platform",
                "страница отпечатка не ответила (JS не выполнился?)",
            )
        })?;
        let issues = fp.get("issues").cloned().unwrap_or_else(|| json!([]));
        tracing::info!(target: "foca::debug", "отпечаток поискового браузера: {}", fp.get("userAgent").and_then(serde_json::Value::as_str).unwrap_or(""));
        Ok(json!({ "ok": true, "fp": fp, "issues": issues }))
    }

    /// `search_fingerprint_page` returns `{ name, path }`: the same page saved to the export directory,
    /// to open in regular Chrome and compare with the embedded browser's fingerprint.
    pub(crate) fn search_fingerprint_page(&self) -> CmdResult {
        let dir = &self.inner.cfg.export_dir;
        std::fs::create_dir_all(dir)?;
        let name = "FOCA-rs_fingerprint.html";
        let path = dir.join(name);
        std::fs::write(&path, foca_search::render::FINGERPRINT_HTML)?;
        Ok(json!({ "name": name, "path": path.to_string_lossy() }))
    }

    /// Manual diagnostic check for a single search engine (never invoked automatically before scans).
    pub(crate) async fn search_captcha_test(&self, a: &Value) -> CmdResult {
        use foca_search::sources::{classify, detect_captcha_signals, PageKind, RenderEngine};
        let engine_id = arg_str(a, "engine").unwrap_or("startpage");
        let (eng, test_url) = match engine_id {
            "startpage" => (
                RenderEngine::Startpage,
                "https://www.startpage.com/sp/search?query=example.com",
            ),
            "brave_web" => (
                RenderEngine::BraveWeb,
                "https://search.brave.com/search?q=example.com",
            ),
            "yahoo" => (
                RenderEngine::Yahoo,
                "https://search.yahoo.com/search?p=example.com",
            ),
            "mojeek" => (
                RenderEngine::Mojeek,
                "https://www.mojeek.com/search?q=example.com",
            ),
            _ => {
                return Err(CmdError::new(
                    "bad_args",
                    format!("неизвестный поисковик: {engine_id}"),
                ));
            }
        };
        let Some(render) = self.current_render() else {
            return Ok(json!({
                "ok": false,
                "supported": false,
                "engine": engine_id,
                "kind": Value::Null,
                "signals": Value::Null,
                "status": Value::Null,
                "url": test_url,
                "error": "Тест капчи доступен только во встроенном браузере Android",
            }));
        };
        let proxy = self
            .store()
            .settings_get()
            .ok()
            .and_then(|s| crate::settings::resolve_proxy_spec(&s["net"], None));
        let req = foca_search::render::RenderRequest::new(
            engine_id,
            Some(test_url),
            std::time::Duration::from_secs(20),
        )
        .through_proxy(proxy);
        let page = render
            .fetch(req)
            .await
            .map_err(|e| CmdError::new("platform", format!("встроенный браузер: {e}")))?;
        let signals = detect_captcha_signals(eng, &page);
        let kind = match classify(eng, &page) {
            PageKind::Results => "results",
            PageKind::Verify => "verify",
            PageKind::Captcha => "captcha",
            PageKind::BlockedIp => "blocked",
        };
        Ok(json!({
            "ok": true,
            "supported": true,
            "engine": engine_id,
            "kind": kind,
            "signals": signals,
            "status": page.status,
            "url": page.url,
        }))
    }

    /// `terms_get` returns `{ version /* current text */, accepted, accepted_version, accepted_at }`.
    pub(crate) fn terms_get(&self) -> CmdResult {
        let s = self.store().settings_get()?;
        let t = &s["terms"];
        let av = t["terms_version"].as_str().unwrap_or("");
        Ok(
            json!({ "version": TERMS_VERSION, "accepted": av == TERMS_VERSION,
            "accepted_version": if av.is_empty() { Value::Null } else { json!(av) },
            "accepted_at": t["accepted_at"].clone() }),
        )
    }

    /// `terms_accept { version }`; the version must match the current one ([`TERMS_VERSION`]).
    pub(crate) fn terms_accept(&self, a: &Value) -> CmdResult {
        if arg_str(a, "version") != Some(TERMS_VERSION) {
            return Err(CmdError::new(
                "bad_args",
                "Версия условий устарела: откройте их заново",
            ));
        }
        let at = self.now_iso();
        self.store().settings_set(
            &json!({ "terms": { "terms_version": TERMS_VERSION, "accepted_at": at } }),
        )?;
        tracing::info!(target: "foca::debug", "условия использования v{TERMS_VERSION} приняты");
        self.terms_get()
    }
}

/// Error codes of `NetError::code` that prefix request journal errors (`code: detail`).
const NET_ERROR_CODES: &[&str] = &[
    "out_of_scope",
    "not_active_phase",
    "cancelled",
    "timeout",
    "http_status",
    "too_large",
    "too_many_redirects",
    "bad_url",
    "dns",
    "network",
    "proxy",
    "parse",
    "io",
    "nokey",
];

/// Splits a request journal error into a stable kind for the UI and the raw detail. Network
/// failures are narrowed by their cause: `refused`, `tls`, `dns`, `timeout`, `unreachable`.
fn journal_error(err: Option<&str>) -> (Option<&'static str>, Option<String>) {
    let Some(e) = err.map(str::trim).filter(|e| !e.is_empty()) else {
        return (None, None);
    };
    if e == "cancelled" {
        return (Some("cancelled"), None);
    }
    if let Some(st) = e.strip_prefix("retry: ") {
        return (Some("http_status"), Some(st.to_string()));
    }
    if let Some(to) = e.strip_prefix("redirect → ") {
        return (Some("redirect"), Some(to.to_string()));
    }
    let (code, detail) = match e.split_once(": ") {
        Some((c, d)) => match NET_ERROR_CODES.iter().find(|k| **k == c) {
            Some(k) => (*k, d.to_string()),
            None => ("other", e.to_string()),
        },
        None => ("other", e.to_string()),
    };
    let code = if matches!(code, "network" | "io" | "other") {
        let low = detail.to_lowercase();
        if low.contains("connection refused") || low.contains("os error 111") {
            "refused"
        } else if ["tls", "ssl", "certificate", "handshake", "close_notify"]
            .iter()
            .any(|k| low.contains(k))
        {
            "tls"
        } else if low.contains("dns error") || low.contains("failed to lookup") {
            "dns"
        } else if low.contains("timed out") || low.contains("таймаут") {
            "timeout"
        } else if low.contains("unreachable") {
            "unreachable"
        } else {
            code
        }
    } else {
        code
    };
    (Some(code), Some(detail))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn android_log_parsed_with_stack() {
        let t = "2026-11-20T12:00:00.000 I [main] старт\n2026-11-20T12:00:01.000 E [io] сбой | java.lang.X\n    at a.b(C.kt:1)\nмусор\n";
        let v = parse_android(t, 0);
        assert_eq!(v.len(), 2);
        assert_eq!(v[1]["level"], "error");
        assert_eq!(v[1]["target"], "android/io");
        assert!(v[1]["msg"].as_str().unwrap().contains("C.kt:1"));
        assert_eq!(parse_android(t, 3).len(), 1);
    }
}

#[cfg(test)]
mod journal_error_tests {
    use super::journal_error;

    #[test]
    fn journal_errors_get_stable_kinds() {
        let k = |e: &str| journal_error(Some(e));
        assert_eq!(k("timeout: таймаут").0, Some("timeout"));
        assert_eq!(
            k("out_of_scope: вне скоупа: a.example (в исключениях скоупа)"),
            (
                Some("out_of_scope"),
                Some("вне скоупа: a.example (в исключениях скоупа)".into())
            )
        );
        assert_eq!(k("http_status: HTTP 503").0, Some("http_status"));
        assert_eq!(k("retry: HTTP 429").0, Some("http_status"));
        assert_eq!(
            k("network: сеть: error sending request: tcp connect error: Connection refused (os error 111)").0,
            Some("refused")
        );
        assert_eq!(
            k("network: сеть: invalid peer certificate: UnknownIssuer").0,
            Some("tls")
        );
        assert_eq!(k("dns: DNS: no record").0, Some("dns"));
        assert_eq!(k("cancelled").0, Some("cancelled"));
        assert_eq!(k("something odd").0, Some("other"));
        assert_eq!(journal_error(None), (None, None));
    }
}
