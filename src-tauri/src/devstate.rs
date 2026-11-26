//! Pause policy inputs read from JSON: `settings.power`/`settings.net` and the Kotlin device
//! monitor events (`net`, `power`). Shared by the UI bridge and the headless resume runner.

use serde_json::Value;

use crate::policy::{Env, PolicySettings, Transport};

/// Builds the policy settings from the full settings object (`settings_get`).
pub fn policy_settings(s: &Value) -> PolicySettings {
    let net = s.get("net").cloned().unwrap_or(Value::Null);
    let pw = s.get("power").cloned().unwrap_or(Value::Null);
    let b = |o: &Value, k: &str| o.get(k).and_then(Value::as_bool).unwrap_or(false);
    let st = |o: &Value, k: &str| o.get(k).and_then(Value::as_str).unwrap_or("").to_string();
    PolicySettings {
        wifi_only: b(&pw, "wifi_only"),
        batt_on: b(&pw, "batt_on"),
        batt: pw
            .get("batt")
            .and_then(|v| {
                v.as_u64()
                    .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
            })
            .unwrap_or(15)
            .min(100) as u8,
        batt_stop: st(&pw, "batt_action") == "stop",
        charge_only: b(&pw, "charge_only"),
        heat: b(&pw, "heat"),
        kill_switch: b(&net, "kill_switch"),
        kill_stop: st(&net, "kill_action") != "pause",
    }
}

/// Applies a `net` or `power` device event to `env`; returns `false` for other kinds.
pub fn apply_device(env: &mut Env, ev: &Value) -> bool {
    let b = |k: &str, d: bool| ev.get(k).and_then(Value::as_bool).unwrap_or(d);
    match ev.get("kind").and_then(Value::as_str).unwrap_or("") {
        "net" => {
            env.online = b("online", true);
            env.vpn = b("vpn", false);
            env.metered = b("metered", false);
            env.transport = Transport::parse(
                ev.get("transport")
                    .and_then(Value::as_str)
                    .unwrap_or("other"),
            );
            if !env.online {
                env.transport = Transport::None;
            }
            true
        }
        "power" => {
            env.battery = ev
                .get("battery")
                .and_then(Value::as_u64)
                .map(|v| v.min(100) as u8);
            env.charging = b("charging", false);
            env.thermal = ev
                .get("thermal")
                .and_then(Value::as_u64)
                .unwrap_or(0)
                .min(6) as u8;
            true
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn reads_power_and_net_settings() {
        let s = policy_settings(&json!({
            "power": { "batt_on": true, "batt": "20", "batt_action": "stop", "wifi_only": true },
            "net": { "kill_switch": true, "kill_action": "pause" }
        }));
        assert!(s.batt_on && s.batt_stop && s.wifi_only && s.kill_switch);
        assert_eq!(s.batt, 20);
        assert!(!s.kill_stop);
        assert_eq!(policy_settings(&json!({})), PolicySettings::default());
    }

    #[test]
    fn device_events_update_env() {
        let mut e = Env::default();
        assert!(apply_device(
            &mut e,
            &json!({ "kind": "power", "battery": 9, "charging": false })
        ));
        assert_eq!(e.battery, Some(9));
        assert!(apply_device(
            &mut e,
            &json!({ "kind": "net", "online": false, "transport": "wifi" })
        ));
        assert_eq!(e.transport, Transport::None);
        assert!(!apply_device(&mut e, &json!({ "kind": "service" })));
    }
}
