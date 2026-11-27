//! Contents of the scan foreground service notification, shared by the UI bridge and the
//! headless resume runner.

use foca_core::Lang;
use serde_json::{json, Value};

/// Scan notification summary.
#[derive(Default)]
pub struct ServiceState {
    pub running: bool,
    pub title: String,
    pub stage: String,
    pub progress: u8,
    pub paused: Option<String>,
}

impl ServiceState {
    /// Resets the notification for a new scan and claims the service start. `running` is set
    /// immediately (before the native call), so of the two paths that may start the service:
    /// `service_begin` on `scan_start` and the worker on the `started` event: only the first
    /// gets `true` and issues `scan_service_start`; `service_start` then stores the real result.
    pub fn claim_start(&mut self, title: String) -> bool {
        let first = !self.running;
        *self = ServiceState {
            running: true,
            title,
            stage: "Поиск".into(),
            progress: 0,
            paused: None,
        };
        first
    }

    /// Builds the `scan_service_start`/`scan_service_update` arguments in the UI language.
    pub fn payload(&self, lang: Lang) -> Value {
        use foca_engine::i18n::{core_text, localize};
        let text = match &self.paused {
            Some(r) => core_text(
                lang,
                "notify.paused_text",
                &json!({ "reason": localize(lang, reason_label(r)), "progress": self.progress }),
            ),
            None => core_text(
                lang,
                "notify.stage_text",
                &json!({ "stage": localize(lang, &self.stage), "progress": self.progress }),
            ),
        };
        json!({
            "title": core_text(lang, "notify.running_title", &json!({ "title": self.title })),
            "text": text,
            "progress": self.progress,
            "paused": self.paused.is_some(),
            "route": "/p/scan",
        })
    }
}

/// The `status_notify` arguments for a scan paused by the monthly mobile data limit; `usage` is
/// the engine's `mobile_usage` result.
pub fn mobile_cap_note(lang: Lang, usage: &Value) -> Value {
    use foca_engine::i18n::core_text;
    let p = json!({ "used": usage["used_mb"], "limit": usage["limit_mb"] });
    json!({
        "tag": "mobile_cap",
        "title": core_text(lang, "notify.mobile_cap_title", &p),
        "text": core_text(lang, "notify.mobile_cap_text", &p),
        "route": "/p/scan",
    })
}

pub fn reason_label(r: &str) -> &'static str {
    match r {
        "offline" => "нет сети",
        "wifi" => "нет Wi-Fi",
        "vpn" => "обрыв туннеля",
        "battery" => "питание",
        "thermal" => "перегрев",
        "android" => "ограничение Android",
        "mobile_cap" => "лимит мобильного трафика",
        "user" => "вручную",
        _ => "пауза",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mobile_cap_note_names_usage_and_limit() {
        let n = mobile_cap_note(Lang::En, &json!({ "used_mb": 1000.4, "limit_mb": 1000 }));
        assert_eq!(n["title"], "Mobile data limit reached");
        assert_eq!(
            n["text"],
            "Mobile data limit reached: 1000.4 of 1000 MB this month. Resume on Wi-Fi or raise the limit"
        );
        assert_eq!(n["tag"], "mobile_cap");
        let ru = mobile_cap_note(Lang::Ru, &json!({ "used_mb": 12, "limit_mb": 10 }));
        assert!(ru["text"].as_str().unwrap().contains("12 из 10 МБ"), "{ru}");
    }

    #[test]
    fn paused_notification_names_mobile_cap() {
        let s = ServiceState {
            running: true,
            title: "Contoso".into(),
            stage: "Поиск".into(),
            progress: 40,
            paused: Some("mobile_cap".into()),
        };
        assert_eq!(
            s.payload(Lang::En)["text"],
            "Paused: mobile data limit · 40%"
        );
    }
}
