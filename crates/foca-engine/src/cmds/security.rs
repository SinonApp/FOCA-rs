//! PIN and wipe-all commands.

use serde_json::{json, Value};

use crate::engine::lock;
use crate::settings::{pin_hash, valid_pin};
use crate::util::{self, arg_str};
use crate::{CmdError, CmdResult, Engine};

const PIN_ATTEMPTS: u32 = 5;

impl Engine {
    pub(crate) fn pin_set(&self, a: &Value) -> CmdResult {
        let pin = arg_str(a, "pin")
            .map(String::from)
            .or_else(|| a.get("pin").map(|v| v.to_string()))
            .unwrap_or_default();
        if !valid_pin(&pin) {
            return Err(CmdError::new("bad_pin", "PIN: 4-8 цифр"));
        }
        let panic = arg_str(a, "panic").filter(|p| !p.is_empty());
        if panic.is_some_and(|p| !valid_pin(p) || p == pin) {
            return Err(CmdError::new(
                "bad_pin",
                "Паник-PIN: 4-8 цифр и не совпадает с PIN",
            ));
        }
        let mut st = self.pin_state();
        st.salt = util::hex(&util::random_salt());
        st.hash = Some(pin_hash(&pin, &st.salt));
        if let Some(p) = panic {
            st.panic_salt = util::hex(&util::random_salt());
            st.panic_hash = Some(pin_hash(p, &st.panic_salt));
        }
        st.fail = 0;
        st.locked_until = None;
        self.save_pin(&st)?;
        self.store()
            .settings_set(&json!({ "sec": { "pin": true } }))?;
        Ok(json!({ "ok": true }))
    }

    pub(crate) async fn pin_check(&self, a: &Value) -> CmdResult {
        let pin = arg_str(a, "pin").unwrap_or("");
        let mut st = self.pin_state();
        let Some(h) = st.hash.clone() else {
            return Ok(json!({ "ok": true, "panic": false, "attempts_left": PIN_ATTEMPTS }));
        };
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        if let Some(until) = st.locked_until {
            if now < until {
                return Ok(json!({
                    "ok": false,
                    "panic": false,
                    "attempts_left": 0,
                    "locked": true,
                    "retry_after": until.saturating_sub(now),
                }));
            }
        }
        if let Some(ph) = &st.panic_hash {
            if util::ct_eq(pin_hash(pin, &st.panic_salt).as_bytes(), ph.as_bytes()) {
                self.wipe_all(&json!({ "confirm": "WIPE" })).await?;
                return Ok(json!({ "ok": true, "panic": true, "attempts_left": PIN_ATTEMPTS }));
            }
        }
        if util::ct_eq(pin_hash(pin, &st.salt).as_bytes(), h.as_bytes()) {
            st.fail = 0;
            st.locked_until = None;
            self.save_pin(&st)?;
            return Ok(json!({ "ok": true, "panic": false, "attempts_left": PIN_ATTEMPTS }));
        }
        st.fail = st.fail.saturating_add(1);
        let mut retry_after = 0i64;
        if st.fail >= PIN_ATTEMPTS {
            let exp = (st.fail - PIN_ATTEMPTS).min(7);
            retry_after = 30i64.saturating_mul(1i64 << exp).min(3600);
            st.locked_until = Some(now.saturating_add(retry_after));
        }
        self.save_pin(&st)?;
        if retry_after > 0 {
            Ok(json!({
                "ok": false,
                "panic": false,
                "attempts_left": 0,
                "locked": true,
                "retry_after": retry_after,
            }))
        } else {
            Ok(json!({
                "ok": false,
                "panic": false,
                "attempts_left": PIN_ATTEMPTS.saturating_sub(st.fail),
            }))
        }
    }

    pub(crate) async fn wipe_all(&self, a: &Value) -> CmdResult {
        if arg_str(a, "confirm") != Some("WIPE") {
            return Err(CmdError::new("bad_confirm", "Нужно подтверждение"));
        }
        self.stop_active_scan().await;
        let _ = std::fs::remove_file(self.run_file());
        self.queue_wipe();
        lock(&self.inner.tool_log).clear();
        lock(&self.inner.ai_models_cache).clear();
        let ids: Vec<String> = self
            .store()
            .list_projects()?
            .into_iter()
            .map(|p| p.id)
            .collect();
        for id in ids {
            self.forget_db(&id);
            self.store().delete_project(&id)?;
        }
        for d in [
            "files",
            "clean",
            "reports",
            "signatures",
            "exports",
            "logs",
            "plugins",
            "wordlists",
        ] {
            let _ = std::fs::remove_dir_all(self.inner.cfg.data_dir.join(d));
        }
        if self.inner.cfg.export_dir != self.inner.cfg.data_dir
            && self
                .inner
                .cfg
                .export_dir
                .starts_with(&self.inner.cfg.data_dir)
        {
            let _ = std::fs::remove_dir_all(&self.inner.cfg.export_dir);
        }
        for f in ["dork-cache.json", "auto_resume.json"] {
            let _ = std::fs::remove_file(self.inner.cfg.data_dir.join(f));
        }
        let keys = self.current_keys();
        for k in crate::dto::KEY_SERVICES
            .iter()
            .chain(foca_store::settings::LEGACY_KEY_SERVICES)
        {
            let _ = keys.delete(k);
        }
        self.store().settings_reset()?;
        let _ = std::fs::remove_file(self.pin_file());
        Ok(json!({ "ok": true }))
    }

    // ================= Signed signature bundles =================
}
