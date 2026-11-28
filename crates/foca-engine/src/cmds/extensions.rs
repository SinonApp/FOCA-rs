//! Signature bundle and plugin commands.

use std::sync::Arc;

use foca_core::Scope;
use foca_net::Access;
use serde_json::{json, Value};

use crate::util::is_loopback_host;
use crate::util::{arg_str, req_str};
use crate::{CmdError, CmdResult, Engine};

impl Engine {
    /// Status JSON with `last_check.error_msg` for the UI language and `auto`: the automatic
    /// check settings and schedule (`mode`, `wifi_only`, `checked_at`, `next_at` in epoch
    /// seconds, `null` when off).
    fn sig_json(&self, st: crate::services::sigbundle::SigStatus) -> CmdResult {
        use crate::services::sigauto;
        let mut v = serde_json::to_value(st)?;
        if v["last_check"].is_object() {
            crate::i18n::annotate(&mut v["last_check"], &["error"]);
        }
        let set = self.sig_auto_settings();
        let sched = sigauto::read(&self.inner.cfg.data_dir);
        let next = sigauto::next_check(&set, &sched).map(|t| t.max(self.now().unix_timestamp()));
        v["auto"] = json!({
            "mode": set.mode.as_str(),
            "wifi_only": set.wifi_only,
            "checked_at": (sched.checked_epoch > 0).then_some(sched.checked_epoch),
            "next_at": next,
        });
        Ok(v)
    }

    fn sig_auto_settings(&self) -> crate::services::sigauto::AutoSettings {
        let s = self.store().settings_get().unwrap_or_default();
        crate::services::sigauto::AutoSettings::from_settings(&s)
    }

    /// `signatures_status {}` → current verified signature database metadata.
    pub(crate) fn signatures_status(&self) -> CmdResult {
        let today = self.now().date();
        self.sig_json(crate::services::sigbundle::status(
            &self.inner.cfg.data_dir,
            today,
        ))
    }

    /// `signatures_import { bundle_json }` → verifies Ed25519 + SHA-256 and atomically applies the bundle.
    pub(crate) fn signatures_import(&self, a: &Value) -> CmdResult {
        let raw = if let Some(s) = arg_str(a, "bundle_json") {
            s.to_string()
        } else if let Some(obj) = a.get("bundle") {
            serde_json::to_string(obj).map_err(|e| {
                CmdError::new(
                    "bad_args",
                    format!("Некорректный JSON пакета сигнатур: {e}"),
                )
            })?
        } else {
            return Err(CmdError::new(
                "bad_args",
                "Нужен bundle_json или bundle (foca-sig-bundle/v2)",
            ));
        };
        let today = self.now().date();
        let st = crate::services::sigbundle::import_bundle(&self.inner.cfg.data_dir, &raw, today)?;
        self.sig_json(st)
    }

    /// `signatures_update { url?, auto? }` → checks the update feed (the official one when `url`
    /// is absent): installs a newer verified bundle, reports `no_update` when nothing is
    /// published (HTTP 404) and `up_to_date` when the feed holds no newer version. The outcome is
    /// stored in `last_check`; a failed check is stored too and returned as the error.
    ///
    /// `auto: true` is the scheduled check (app start, back to the foreground): it runs only when
    /// due by `settings.signatures` (`auto` off/daily/weekly, `wifi_only`), not on a metered
    /// network with Wi-Fi only, not during a scan and not before a rate limit or failure backoff
    /// ends; otherwise it answers `outcome: "skipped"` with `skipped` (`disabled`, `not_due`,
    /// `backoff`, `metered`, `scan`). An automatic check never returns an error: a failure comes
    /// back as `outcome: "failed"` with the status.
    pub(crate) async fn signatures_update(&self, a: &Value) -> CmdResult {
        use crate::services::{sigauto, sigbundle};
        let auto = a["auto"].as_bool().unwrap_or(false);
        let data_dir = &self.inner.cfg.data_dir;
        let now = self.now().unix_timestamp();
        let set = self.sig_auto_settings();
        let mut sched = sigauto::read(data_dir);
        if auto {
            let cond = sigauto::Conditions {
                metered: self.mobile.metered(),
                scanning: self.is_scanning(),
            };
            if let Some(reason) = sigauto::skip_reason(&set, &sched, now, cond) {
                let mut v = self.sig_json(sigbundle::status(data_dir, self.now().date()))?;
                v["outcome"] = json!("skipped");
                v["skipped"] = json!(reason);
                return Ok(v);
            }
        }
        let explicit = arg_str(a, "url").map(str::trim).filter(|u| !u.is_empty());
        let feeds = &self.inner.cfg.endpoints;
        let url = explicit.unwrap_or(feeds.sig_feed.as_str());
        let mut fetched = self.fetch_sig_feed(url).await;
        if let Err(e) = &fetched {
            if e.code == "bad_args" {
                return Err(e.clone());
            }
        }
        let mut used = url;
        // The official v3 feed falls back to the v2 compatibility feed while nothing is
        // published there.
        if explicit.is_none() && matches!(&fetched, Err(e) if e.code == "not_published") {
            used = feeds.sig_feed_fallback.as_str();
            fetched = self.fetch_sig_feed(used).await;
        }
        let rate_limited = matches!(&fetched, Err(e) if e.code == "rate_limited");
        let result = sigbundle::apply_feed(
            data_dir,
            used,
            fetched,
            &sigbundle::official_pubkey_bytes(),
            self.now(),
        );
        let outcome = match &result {
            Ok(_) => sigauto::Outcome::Done,
            Err(_) if rate_limited => sigauto::Outcome::RateLimited(None),
            Err(_) => sigauto::Outcome::Failed,
        };
        sigauto::record(&mut sched, &set, now, outcome);
        sigauto::write(data_dir, &sched);
        let st = match result {
            Ok(st) => st,
            Err(e) if !auto => return Err(e),
            Err(_) => sigbundle::status(data_dir, self.now().date()),
        };
        let installed = st
            .last_check
            .as_ref()
            .map(|c| c.outcome.clone())
            .unwrap_or_default();
        tracing::info!(target: "foca::sig", "проверка базы сигнатур (auto={auto}): {installed}");
        let mut v = self.sig_json(st)?;
        v["outcome"] = json!(installed);
        Ok(v)
    }

    /// Downloads a signature feed URL (HTTPS, public host; plain HTTP only to loopback).
    async fn fetch_sig_feed(&self, url: &str) -> Result<String, CmdError> {
        let parsed = url::Url::parse(url).ok().filter(|u| {
            let scheme_ok = match u.scheme() {
                "https" => true,
                "http" => u.host_str().is_some_and(is_loopback_host),
                _ => false,
            };
            scheme_ok
                && u.host_str().is_some_and(|h| {
                    u.scheme() == "http" || !crate::util::is_private_or_metadata_host(h)
                })
                && u.username().is_empty()
                && u.password().is_none()
        });
        if parsed.is_none() {
            return Err(CmdError::new(
                "bad_args",
                "URL фида сигнатур должен использовать HTTPS и публичный хост",
            ));
        }
        match self.net_client(Scope::default(), Arc::new(foca_net::NullSink)) {
            Ok(net) => match net.get_text(url, "signatures", Access::Passive).await {
                Ok(raw) => Ok(raw),
                Err(foca_net::NetError::Status(s @ (404 | 410))) => {
                    Err(CmdError::new("not_published", format!("HTTP {s}")))
                }
                Err(e @ foca_net::NetError::Status(429 | 403)) => Err(CmdError::new(
                    "rate_limited",
                    format!("Загрузка пакета сигнатур: {e}"),
                )),
                Err(e) => Err(CmdError::new(
                    "net",
                    format!("Загрузка пакета сигнатур: {e}"),
                )),
            },
            Err(e) => Err(e),
        }
    }

    /// `signatures_rollback {}` → restores the previous verified bundle or the builtin database.
    pub(crate) fn signatures_rollback(&self) -> CmdResult {
        let today = self.now().date();
        let st = crate::services::sigbundle::rollback(&self.inner.cfg.data_dir, today)?;
        self.sig_json(st)
    }

    // ================= Sandboxed plugin engine =================

    /// `plugins_list {}` → lists builtin and custom plugins with their status and permissions.
    pub(crate) fn plugins_list(&self) -> CmdResult {
        let store = crate::services::plugins::PluginStore::new(&self.inner.cfg.data_dir);
        let items = store.list();
        let total = items.len();
        let enabled = items.iter().filter(|p| p.enabled).count();
        let builtin = items.iter().filter(|p| p.builtin).count();
        let custom = total.saturating_sub(builtin);
        Ok(json!({
            "items": items,
            "counts": {
                "total": total,
                "enabled": enabled,
                "builtin": builtin,
                "custom": custom
            }
        }))
    }

    /// `plugin_install { manifest }` → validates and installs a custom JSON/TOML plugin manifest.
    pub(crate) fn plugin_install(&self, a: &Value) -> CmdResult {
        let raw = if let Some(s) = arg_str(a, "manifest") {
            s.to_string()
        } else if let Some(obj) = a.get("manifest").filter(|v| v.is_object()) {
            serde_json::to_string(obj)
                .map_err(|e| CmdError::new("bad_args", format!("manifest JSON: {e}")))?
        } else {
            return Err(CmdError::new(
                "bad_args",
                "Нужен параметр manifest (JSON/TOML строка или объект)",
            ));
        };
        let store = crate::services::plugins::PluginStore::new(&self.inner.cfg.data_dir);
        let info = store.install(&raw)?;
        serde_json::to_value(info).map_err(Into::into)
    }

    /// `plugin_toggle { id, enabled }` → enables or disables a builtin/custom plugin.
    pub(crate) fn plugin_toggle(&self, a: &Value) -> CmdResult {
        let id = req_str(a, "id")?;
        let enabled = a["enabled"]
            .as_bool()
            .ok_or_else(|| CmdError::new("bad_args", "Нужен boolean параметр enabled"))?;
        let store = crate::services::plugins::PluginStore::new(&self.inner.cfg.data_dir);
        let info = store.toggle(id, enabled)?;
        serde_json::to_value(info).map_err(Into::into)
    }

    /// `plugin_remove { id }` → removes a custom plugin (builtin plugins cannot be deleted).
    pub(crate) fn plugin_remove(&self, a: &Value) -> CmdResult {
        let id = req_str(a, "id")?;
        let store = crate::services::plugins::PluginStore::new(&self.inner.cfg.data_dir);
        store.remove(id)?;
        Ok(json!({ "ok": true, "id": id }))
    }

    /// `plugin_run_test { id, target?, passive?, sample_body?, fuel_limit? }` → runs plugin inside
    /// the sandbox enforcing `Scope` and ADR-0009 (`Access::Passive` blocks target-host HTTP).
    pub(crate) async fn plugin_run_test(&self, a: &Value) -> CmdResult {
        let id = req_str(a, "id")?;
        let store = crate::services::plugins::PluginStore::new(&self.inner.cfg.data_dir);
        let manifest = store.get(id)?;
        let target = arg_str(a, "target")
            .filter(|s| !s.trim().is_empty())
            .unwrap_or("example.test");
        let passive = a["passive"].as_bool().unwrap_or(true);
        let scope = crate::services::plugins::default_target_scope(target);
        let sample = arg_str(a, "sample_body");
        let fuel = a["fuel_limit"]
            .as_u64()
            .unwrap_or(crate::services::plugins::DEFAULT_FUEL_LIMIT);
        let res = crate::services::plugins::run_plugin(
            &manifest, target, passive, &scope, None, sample, fuel,
        )
        .await?;
        serde_json::to_value(res).map_err(Into::into)
    }
}
