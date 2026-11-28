//! Services derived from the user settings: the public settings view and its updates, the UI
//! language, known secret values, the PIN state, the source timeout and network clients built
//! with `settings.net`.

use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use foca_core::{Lang, Scope};
use foca_net::NetClient;
use foca_store::settings::KEY_SERVICES;
use foca_store::ProjectDb;
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};

use crate::engine::{lock, Core};
use crate::services::i18n::{lang_to_u8, last_ui_lang, normalize_setting, UI_LANG};
use crate::{CmdError, CmdResult};

/// Longest duration a manual setting can ask for: ten years. Far beyond any scan, and small
/// enough that adding it to `Instant::now()` can never overflow (the only reason for a ceiling).
pub(crate) const MAX_SETTING_SECS: u64 = 10 * 365 * 24 * 3600;

/// Seconds from a manual setting as a `Duration`, kept below [`MAX_SETTING_SECS`].
pub(crate) fn secs(n: u64) -> Duration {
    Duration::from_secs(n.min(MAX_SETTING_SECS))
}

pub(crate) fn resolve_proxy_spec(n: &Value, group: Option<&str>) -> Option<String> {
    if let Some(g) = group {
        let raw = n["groups"][g].as_str().unwrap_or("").trim();
        if !raw.is_empty() {
            if raw.eq_ignore_ascii_case("direct") {
                return None;
            }
            if raw.contains("://") {
                return Some(raw.to_string());
            }
            return Some(format!("socks5h://{raw}"));
        }
    }
    if n["proxy_on"].as_bool().unwrap_or(false) {
        let addr = n["addr"].as_str().unwrap_or("127.0.0.1:9050").trim();
        if !addr.is_empty() {
            return Some(match n["type"].as_str().unwrap_or("socks5") {
                "http" | "https" => format!("http://{addr}"),
                _ => format!("socks5h://{addr}"),
            });
        }
    }
    None
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub(crate) struct PinState {
    pub hash: Option<String>,
    pub salt: String,
    pub panic_hash: Option<String>,
    pub panic_salt: String,
    pub fail: u32,
    pub locked_until: Option<i64>,
}

/// Returns the plain secret values of the project, longest first.
pub(crate) fn secret_values(db: &ProjectDb) -> Vec<String> {
    let mut v: Vec<String> = db
        .entity("secrets")
        .ok()
        .and_then(|x| x.as_array().cloned())
        .unwrap_or_default()
        .iter()
        .filter_map(|s| s["value"].as_str().map(String::from))
        .filter(|s| s.chars().count() >= 4)
        .collect();
    v.sort_by_key(|s| std::cmp::Reverse(s.len()));
    v.dedup();
    v
}

const PIN_ITERS: u32 = 60_000;

pub(crate) fn pin_hash(pin: &str, salt: &str) -> String {
    crate::util::hex(&crate::util::pbkdf2_sha256(
        pin.as_bytes(),
        salt.as_bytes(),
        PIN_ITERS,
    ))
}

pub(crate) fn valid_pin(p: &str) -> bool {
    (4..=8).contains(&p.len()) && p.bytes().all(|b| b.is_ascii_digit())
}

impl Core {
    pub(crate) fn pin_file(&self) -> PathBuf {
        self.cfg.data_dir.join("pin.json")
    }

    pub(crate) fn save_pin(&self, p: &PinState) -> Result<(), CmdError> {
        std::fs::write(self.pin_file(), serde_json::to_vec(p)?)?;
        Ok(())
    }

    /// Returns `Settings` without secrets: core defaults plus saved values, and `sec.pin_set`.
    pub(crate) fn public_settings(&self) -> CmdResult {
        let mut keys = Map::new();
        for k in KEY_SERVICES {
            let mut st = json!({ "status": "none", "mask": "", "used": 0, "limit": 0 });
            if matches!(*k, "searx" | "webhook") {
                st["kind"] = json!("url");
            }
            keys.insert((*k).into(), st);
        }
        // Alert defaults come with the saved settings merged below.
        let mut s = json!({
            "keys": keys, "plugins": {}, "monitor": {}, "monitor_status": {},
            "ai": {
                "provider": "deepseek",
                "model": "",
                "base_url": "",
                "thinking": "auto",
                "thinking_budget": 0,
                "max_tokens": 0,
                "temperature": Value::Null,
                "show_thoughts": false,
                "redact": { "secrets": true, "pii": true, "client": true, "evid": false }
            },
            "sec": { "pin_set": false },
            "update": { "auto": true, "wifi_only": true, "prerelease": true },
        });
        let saved = self.store().settings_get()?;
        foca_store::settings::merge(&mut s, &saved);
        if let Some(ai_obj) = s.get_mut("ai").and_then(Value::as_object_mut) {
            ai_obj.remove("local");
            if ai_obj.get("provider").and_then(Value::as_str) == Some("local") {
                ai_obj.insert("provider".into(), json!("deepseek"));
            }
        }
        // keys of retired services (gcse) in old settings are ignored
        if let Some(o) = s["keys"].as_object_mut() {
            for k in foca_store::settings::LEGACY_KEY_SERVICES {
                o.remove(*k);
            }
        }
        let keys = self.current_keys();
        for k in KEY_SERVICES {
            if let Some(v) = keys.get(k).filter(|v| !v.is_empty()) {
                if s["keys"][*k]["status"] == "none" {
                    let st = foca_store::settings::key_status(&v);
                    foca_store::settings::merge(&mut s["keys"][*k], &st);
                }
            }
        }
        let pin = self.pin_state();
        if let Some(o) = s["sec"].as_object_mut() {
            for k in ["pin_hash", "panic_hash", "pin_fail", "pin_salt"] {
                o.remove(k);
            }
            o.insert("pin_set".into(), json!(pin.hash.is_some()));
            if pin.hash.is_some() {
                o.insert("pin".into(), json!(true));
            }
        }
        foca_store::settings::strip_secrets(&mut s);
        if let Some(o) = s.as_object_mut() {
            o.remove("terms"); // acceptance is served by terms_get
        }
        Ok(s)
    }

    pub(crate) fn settings_set(&self, a: &Value) -> CmdResult {
        let mut p = a.get("patch").cloned().unwrap_or(json!({}));
        if let Some(sec) = p.get_mut("sec").and_then(Value::as_object_mut) {
            for k in ["pin_hash", "panic_hash", "pin_fail", "pin_salt", "pin_set"] {
                sec.remove(k);
            }
        }
        // terms acceptance is only possible through the `terms_accept` command
        if let Some(o) = p.as_object_mut() {
            o.remove("terms");
        }
        if let Some(ai) = p.get_mut("ai").and_then(Value::as_object_mut) {
            ai.remove("local");
        }
        foca_store::settings::strip_secrets(&mut p);
        let saved = self.store().settings_set(&p)?;
        self.mobile
            .set_limit(crate::services::mobile::limit_bytes(&saved));
        if let Some(l) = p["debug"]["level"].as_str() {
            crate::services::logs::set_level(l);
        }
        self.public_settings()
    }

    pub(crate) fn pin_state(&self) -> PinState {
        std::fs::read(self.pin_file())
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default()
    }

    /// Returns known secrets to scrub: API keys from the key store and the secrets of all projects.
    pub(crate) fn known_secrets(&self) -> Vec<String> {
        let keys = self.current_keys();
        let mut v: Vec<String> = KEY_SERVICES
            .iter()
            .chain(foca_store::settings::LEGACY_KEY_SERVICES)
            .filter_map(|k| keys.get(k))
            .filter(|s| !s.trim().is_empty())
            .collect();
        let ids: Vec<String> = self
            .store()
            .list_projects()
            .map(|l| l.into_iter().map(|p| p.id).collect())
            .unwrap_or_default();
        for id in ids {
            if let Ok(db) = self.db(&id) {
                v.extend(secret_values(&lock(&db)));
            }
        }
        v
    }

    /// Effective UI language for every language-dependent result of the core (playbooks, report
    /// defaults, alerts, notifications, toasts, `device.txt`): an explicit `lang` setting wins;
    /// with `auto` the saved device locale decides (the UI reports it with every `i18n_bundle`),
    /// then the last language the UI asked for in this process, then English.
    pub fn ui_lang(&self) -> Lang {
        let s = self.store().settings_get().unwrap_or(Value::Null);
        let setting = normalize_setting(
            s["lang"]
                .as_str()
                .or_else(|| s.pointer("/ui/look/lang").and_then(Value::as_str)),
        );
        let device = s["device_locale"].as_str().filter(|d| !d.trim().is_empty());
        let l = if setting != "auto" || device.is_some() {
            Lang::resolve_setting(Some(&setting), device)
        } else if let Some(l) = last_ui_lang() {
            return l;
        } else {
            Lang::En
        };
        UI_LANG.store(lang_to_u8(l), Ordering::Relaxed);
        l
    }

    /// Returns the overall source timeout: `settings.net.source_timeout` (seconds, any value from 1
    /// up) or `cfg.source_timeout` when missing or 0.
    pub(crate) fn source_timeout(&self) -> std::time::Duration {
        let s = self.store().settings_get().unwrap_or_default();
        match s["net"]["source_timeout"].as_u64() {
            Some(n) if n > 0 => secs(n),
            _ => self.cfg.source_timeout,
        }
    }

    /// Builds a network client with `settings.net` applied on top of the engine's base configuration.
    pub(crate) fn net_client(
        &self,
        scope: Scope,
        sink: Arc<dyn foca_net::RequestSink>,
    ) -> Result<NetClient, CmdError> {
        self.net_client_ua(scope, sink, None)
    }

    /// Same as [`Self::net_client`], with this run's UA profile (from the wizard) on top of `settings.net.ua`.
    pub(crate) fn net_client_ua(
        &self,
        scope: Scope,
        sink: Arc<dyn foca_net::RequestSink>,
        ua_override: Option<&str>,
    ) -> Result<NetClient, CmdError> {
        self.net_client_group(scope, sink, ua_override, None)
    }

    /// Resolves proxy configuration for an optional traffic group (`"search"`, `"recon"`, `"target"`).
    pub(crate) fn net_client_group(
        &self,
        scope: Scope,
        sink: Arc<dyn foca_net::RequestSink>,
        ua_override: Option<&str>,
        group: Option<&str>,
    ) -> Result<NetClient, CmdError> {
        // every request of the engine feeds the monthly mobile data counter
        let sink: Arc<dyn foca_net::RequestSink> = Arc::new(crate::services::mobile::MeterSink {
            meter: self.mobile.clone(),
            inner: sink,
        });
        let mut s = self.store().settings_get()?;
        if let Some(ua) = ua_override {
            s["net"]["ua"] = json!(ua);
        }
        let n = &s["net"];
        let mut cfg = self.cfg.net.clone();
        cfg.proxy = resolve_proxy_spec(n, group);
        // one browser profile per client (per scan); versions are estimated by date plus the API cache
        if let Some(ua) = n["ua"].as_str() {
            use foca_net::ua::{BrowserProfile, UaMode, UaVersions};
            let mode = UaMode::from_setting(ua, n["ua_custom"].as_str().unwrap_or(""));
            let cache = UaVersions::from_json(&n["ua_versions"]);
            let now = self.clock.now();
            BrowserProfile::for_mode(&mode, now, &cache).apply(&mut cfg);
            // refresh the cache only with the real service endpoints (not in tests or on the test bench)
            if mode.wants_versions()
                && !cache.is_fresh(now)
                && n["ua_update"].as_bool() != Some(false)
                && self.cfg.endpoints.crtsh.starts_with("https://crt.sh")
            {
                let store = self.store.clone();
                foca_net::ua::spawn_refresh(cfg.clone(), sink.clone(), move |v| {
                    let _ = lock(&store).settings_set(&json!({ "net": { "ua_versions": v } }));
                });
            }
        }
        if let Some(r) = n["rps"].as_f64().filter(|r| *r > 0.0) {
            cfg.global_rps = Some(r);
        }
        // Manual values are honoured as typed; only the semaphore's own permit ceiling is applied
        // (a larger count would panic, and no phone gets near it).
        if let Some(t) = n["threads"].as_u64().filter(|t| *t > 0) {
            let t = usize::try_from(t).unwrap_or(usize::MAX);
            cfg.max_concurrency = t.min(tokio::sync::Semaphore::MAX_PERMITS);
        }
        if let Some(t) = n["timeout"].as_u64().filter(|t| *t > 0) {
            cfg.connect_timeout = secs(t);
        }
        // A hard limit for the whole request: without it a trickling response (1 byte per read
        // timeout) would hold a download or RDAP forever. Search sources also get the overall source timeout.
        // It never undercuts a longer connect timeout the user chose.
        if cfg.timeout.is_none() {
            cfg.timeout = Some(Duration::from_secs(300).max(cfg.connect_timeout));
        }
        if let Some(r) = n["retries"].as_u64() {
            cfg.retries = u32::try_from(r).unwrap_or(u32::MAX);
        }
        cfg.proxy_resolver = Some(Arc::new(foca_net::doh::DohProxyResolver));
        NetClient::with_clock(cfg, scope, sink, self.clock.clone())
            .map_err(|e| CmdError::new("net", e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Engine, EngineConfig, MemoryEvents, MemoryKeys};

    #[tokio::test]
    async fn manual_net_values_reach_the_client_unclamped() {
        let dir = tempfile::tempdir().unwrap();
        let e = Engine::open(
            EngineConfig::new(dir.path()),
            Arc::new(MemoryKeys::new()),
            Arc::new(MemoryEvents::default()),
        )
        .unwrap();
        // far above the old UI caps (threads 64, rps 100, timeout 120 s, retries 5)
        e.store()
            .settings_set(
                &json!({ "net": { "threads": 300, "rps": 250, "timeout": 900, "retries": 12 } }),
            )
            .unwrap();
        let sink: Arc<dyn foca_net::RequestSink> = Arc::new(foca_net::NullSink);
        let c = e.net_client(Scope::default(), sink.clone()).unwrap();
        let cfg = c.config();
        assert_eq!(cfg.max_concurrency, 300);
        assert_eq!(cfg.global_rps, Some(250.0));
        assert_eq!(cfg.connect_timeout, Duration::from_secs(900));
        assert!(cfg.timeout.unwrap() >= Duration::from_secs(900));
        assert_eq!(cfg.retries, 12);
        // rps 0 = no limit; absurd numbers stay within the crash-safety invariants
        e.store()
            .settings_set(&json!({ "net": { "threads": u64::MAX, "rps": 0, "timeout": u64::MAX, "retries": u64::MAX } }))
            .unwrap();
        let c = e.net_client(Scope::default(), sink).unwrap();
        let cfg = c.config();
        assert_eq!(cfg.max_concurrency, tokio::sync::Semaphore::MAX_PERMITS);
        assert_eq!(cfg.connect_timeout, Duration::from_secs(MAX_SETTING_SECS));
        assert_eq!(cfg.retries, u32::MAX);
        assert!(std::time::Instant::now()
            .checked_add(cfg.timeout.unwrap())
            .is_some());
    }
}
