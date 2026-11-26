//! Settings-side commands: API keys, network checks and the UI dictionary.

use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use foca_core::{Lang, Scope};
use foca_net::{Access, NetRequest};
use serde_json::{json, Value};

use crate::engine::lock;
use crate::services::i18n::{
    findings_json, help_json, lang_to_u8, normalize_setting, ui_json, UI_LANG,
};
use crate::util::{arg_str, req_str};
use crate::{CmdError, CmdResult, Engine};

impl Engine {
    pub(crate) fn key_set(&self, a: &Value) -> CmdResult {
        let svc = req_str(a, "service")?;
        let v = arg_str(a, "value").unwrap_or("").trim();
        let keys = self.current_keys();
        if v.is_empty() {
            keys.delete(svc).map_err(|e| CmdError::new("keystore", e))?;
        } else {
            keys.set(svc, v).map_err(|e| CmdError::new("keystore", e))?;
        }
        self.store().key_set(svc, v)?;
        if svc == "ai" {
            lock(&self.inner.ai_models_cache).clear();
        }
        Ok(self.public_settings()?["keys"][svc].clone())
    }

    pub(crate) fn key_delete(&self, a: &Value) -> CmdResult {
        let svc = req_str(a, "service")?;
        self.current_keys()
            .delete(svc)
            .map_err(|e| CmdError::new("keystore", e))?;
        self.store().key_set(svc, "")?;
        if svc == "ai" {
            lock(&self.inner.ai_models_cache).clear();
        }
        Ok(self.public_settings()?["keys"][svc].clone())
    }

    /// Determines the actual egress IP through the current proxy (passive requests to third-party services).
    pub(crate) async fn net_check(&self) -> CmdResult {
        let s = self.public_settings()?;
        let via = if s["net"]["proxy_on"].as_bool().unwrap_or(false) {
            s["net"]["label"].as_str().unwrap_or("прокси").to_string()
        } else {
            "Напрямую".to_string()
        };
        let net = self.net_client(Scope::default(), Arc::new(foca_net::NullSink))?;
        let ep = self.inner.cfg.endpoints.clone();
        let t0 = std::time::Instant::now();
        let r: Result<(String, Option<String>, String, bool), String> = async {
            let v: Value = net
                .get_json(
                    NetRequest::get(&ep.ip_echo, "netcheck", Access::Passive)
                        .map_err(|e| e.to_string())?,
                )
                .await
                .map_err(|e| e.to_string())?;
            let ip = v["ip"].as_str().ok_or("нет ip в ответе")?.to_string();
            let geo: Option<Value> = net
                .get_json(
                    NetRequest::get(&ep.ip_geo.replace("{ip}", &ip), "netcheck", Access::Passive)
                        .map_err(|e| e.to_string())?,
                )
                .await
                .ok();
            let country = geo.as_ref().and_then(|g| {
                g.get("country")
                    .or_else(|| g.get("country_name"))
                    .and_then(Value::as_str)
                    .map(String::from)
            });
            let org = geo
                .as_ref()
                .and_then(|g| {
                    g.get("org")
                        .or_else(|| g.get("isp"))
                        .or_else(|| g.get("asn_org"))
                        .and_then(Value::as_str)
                })
                .unwrap_or("")
                .to_string();
            let is_tor = geo
                .as_ref()
                .and_then(|g| g.get("tor").and_then(Value::as_bool))
                .unwrap_or_else(|| via.to_ascii_lowercase().contains("tor"));
            Ok((ip, country, org, is_tor))
        }
        .await;
        let latency_ms = t0.elapsed().as_millis() as u64;
        let canary = if ep.crtsh.starts_with("https://crt.sh") && !net.is_local_only() {
            let ccfg = foca_net::canary::CanaryConfig {
                timeout: Duration::from_millis(800),
                ..Default::default()
            };
            if let Some(dns) = self.inner.cfg.dns.as_ref() {
                foca_net::canary::check_network(&net, dns.as_ref(), false, &ccfg).await
            } else if let Ok(dns) =
                foca_net::doh::resolver(foca_net::doh::DnsMode::Auto, &Default::default(), &net)
            {
                foca_net::canary::check_network(&net, dns.as_ref(), false, &ccfg).await
            } else {
                foca_net::canary::CanaryReport::default()
            }
        } else {
            foca_net::canary::CanaryReport::default()
        };
        let canary_json = json!({
            "tcp_intercept": canary.tcp_intercept,
            "dns_hijack": canary.dns_hijack,
            "tls_mitm": canary.tls_mitm,
            "unreliable": canary.unreliable,
        });
        match r {
            Ok((ip, country, org, is_tor)) => {
                let ip_kind = foca_net::proxy_check::classify_ip_kind(
                    (!org.is_empty()).then_some(org.as_str()),
                    is_tor,
                );
                self.store().settings_set(
                    &json!({ "net": { "out_ip": ip, "out_country": country.clone().unwrap_or_default() } }),
                )?;
                Ok(json!({
                    "ok": true,
                    "out_ip": ip,
                    "country": country,
                    "via": via,
                    "latency_ms": latency_ms,
                    "org": org,
                    "ip_kind": ip_kind,
                    "canary": canary_json,
                }))
            }
            Err(e) => Ok(json!({
                "ok": false,
                "out_ip": null,
                "country": null,
                "via": via,
                "latency_ms": latency_ms,
                "org": "",
                "ip_kind": "unknown",
                "canary": canary_json,
                "error": e,
            })),
        }
    }

    /// Checks a user-configured proxy (or current settings proxy) for reachability, latency, and exit IP class.
    pub(crate) async fn net_proxy_check(&self, a: &Value) -> CmdResult {
        let s = self.store().settings_get()?;
        let n = &s["net"];
        let proxy_url: Option<String> =
            match arg_str(a, "proxy").map(str::trim).filter(|p| !p.is_empty()) {
                Some("direct") => None,
                Some(p) if p.contains("://") => Some(p.to_string()),
                Some(p) => Some(format!("socks5h://{p}")),
                None => match arg_str(a, "addr").map(str::trim).filter(|x| !x.is_empty()) {
                    Some(addr) => {
                        let typ = arg_str(a, "type").unwrap_or("socks5");
                        Some(match typ {
                            "http" | "https" => format!("http://{addr}"),
                            _ => format!("socks5h://{addr}"),
                        })
                    }
                    None => crate::settings::resolve_proxy_spec(n, arg_str(a, "group")),
                },
            };
        let ep = self.inner.cfg.endpoints.clone();
        let timeout_s = n["timeout"].as_u64().unwrap_or(10).clamp(2, 15);
        let res = foca_net::proxy_check::check_proxy(
            proxy_url.as_deref(),
            &ep.ip_echo,
            &ep.ip_geo,
            Duration::from_secs(timeout_s),
        )
        .await;
        Ok(serde_json::to_value(res)?)
    }

    /// `i18n_bundle { lang?, device_locale?, include_help? }`:
    /// Returns the resolved UI dictionary (and lazily the offline Help catalog when
    /// `include_help: true`) embedded directly in the Rust core.
    pub(crate) fn i18n_bundle(&self, a: &Value) -> CmdResult {
        let setting_raw = arg_str(a, "lang").map(str::to_string).or_else(|| {
            self.public_settings().ok().and_then(|s| {
                s.pointer("/lang")
                    .or_else(|| s.pointer("/ui/look/lang"))
                    .and_then(Value::as_str)
                    .map(str::to_string)
            })
        });
        let setting = normalize_setting(setting_raw.as_deref());
        let device_locale = arg_str(a, "device_locale");
        let resolved = Lang::resolve_setting(Some(&setting), device_locale);
        UI_LANG.store(lang_to_u8(resolved), Ordering::Relaxed);
        // the device locale is kept for processes without a UI (scheduled scans, notifications)
        if let Some(dl) = device_locale.filter(|d| !d.is_empty()) {
            let known = self.store().settings_get().ok();
            if known.as_ref().and_then(|s| s["device_locale"].as_str()) != Some(dl) {
                let _ = self.store().settings_set(&json!({ "device_locale": dl }));
            }
        }
        let include_help = a
            .get("include_help")
            .and_then(Value::as_bool)
            .unwrap_or(false);

        let help = if include_help {
            help_json(resolved).clone()
        } else {
            Value::Null
        };

        Ok(json!({
            "lang": resolved.code(),
            "ui_code": resolved.ui(),
            "setting": setting,
            "ui": ui_json(resolved),
            "findings": findings_json(resolved),
            "help": help,
        }))
    }

    /// `licenses_get {}`: returns the full offline third-party licenses catalog
    /// (data/assets, Rust crates with direct flags, Android libs with `foss`/`play` flavor tags,
    /// and full texts of 10 open-source licenses).
    pub(crate) fn licenses_get(&self) -> CmdResult {
        Ok(crate::services::licenses::licenses_data().clone())
    }
}
