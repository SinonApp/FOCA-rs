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

pub fn reason_label(r: &str) -> &'static str {
    match r {
        "offline" => "нет сети",
        "wifi" => "нет Wi-Fi",
        "vpn" => "обрыв туннеля",
        "battery" => "питание",
        "thermal" => "перегрев",
        "android" => "ограничение Android",
        "user" => "вручную",
        _ => "пауза",
    }
}
