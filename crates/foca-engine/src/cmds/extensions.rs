//! Signature bundle and plugin commands.

use std::sync::Arc;

use foca_core::Scope;
use foca_net::Access;
use serde_json::{json, Value};

use crate::util::is_loopback_host;
use crate::util::{arg_str, req_str};
use crate::{CmdError, CmdResult, Engine};

impl Engine {
    /// `signatures_status {}` → current verified signature database metadata.
    pub(crate) fn signatures_status(&self) -> CmdResult {
        let st = crate::services::sigbundle::status(&self.inner.cfg.data_dir);
        serde_json::to_value(st).map_err(Into::into)
    }

    /// `signatures_import { bundle_json }` → verifies Ed25519 + SHA-256 and atomically applies the bundle.
    pub(crate) fn signatures_import(&self, a: &Value) -> CmdResult {
        let raw = if let Some(s) = arg_str(a, "bundle_json") {
            s.to_string()
        } else if let Some(obj) = a.get("bundle") {
            serde_json::to_string(obj)
                .map_err(|e| CmdError::new("bad_args", format!("bundle JSON: {e}")))?
        } else {
            return Err(CmdError::new(
                "bad_args",
                "Нужен bundle_json или bundle (foca-sig-bundle/v1)",
            ));
        };
        let st = crate::services::sigbundle::import_bundle(&self.inner.cfg.data_dir, &raw)?;
        serde_json::to_value(st).map_err(Into::into)
    }

    /// `signatures_update { url? }` → fetches a signed Ed25519 signature bundle from an HTTPS
    /// feed URL and activates it; when no feed URL is supplied, returns the current verified
    /// signature database status without offline self-signing.
    pub(crate) async fn signatures_update(&self, a: &Value) -> CmdResult {
        let Some(url) = arg_str(a, "url").map(str::trim).filter(|u| !u.is_empty()) else {
            let st = crate::services::sigbundle::status(&self.inner.cfg.data_dir);
            return serde_json::to_value(st).map_err(Into::into);
        };
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
        let net = self.net_client(Scope::default(), Arc::new(foca_net::NullSink))?;
        let raw = net
            .get_text(url, "signatures", Access::Passive)
            .await
            .map_err(|e| CmdError::new("net", format!("Загрузка бандла сигнатур: {e}")))?;
        let st = crate::services::sigbundle::import_bundle(&self.inner.cfg.data_dir, &raw)?;
        serde_json::to_value(st).map_err(Into::into)
    }

    /// `signatures_rollback {}` → restores the previous verified bundle or the builtin database.
    pub(crate) fn signatures_rollback(&self) -> CmdResult {
        let st = crate::services::sigbundle::rollback(&self.inner.cfg.data_dir)?;
        serde_json::to_value(st).map_err(Into::into)
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
