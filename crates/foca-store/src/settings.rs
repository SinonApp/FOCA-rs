//! Global settings (`Settings` from `docs/API.md`), never containing secrets.

use serde_json::{json, Value};

/// Key services listed in `docs/API.md`.
pub const KEY_SERVICES: &[&str] = &[
    "brave", "searx", "shodan", "hibp", "vt", "st", "urlscan", "censys", "github", "otx", "ai",
    "tg_bot", "webhook",
];

/// Retired key services (Google CSE): hidden from saved settings, removed from the key store
/// on reset and scrubbed from logs as secrets.
pub const LEGACY_KEY_SERVICES: &[&str] = &["gcse"];

/// Returns the default settings: proxy disabled, no keys.
pub(crate) fn defaults() -> Value {
    let mut keys = serde_json::Map::new();
    for k in KEY_SERVICES {
        keys.insert((*k).into(), json!({ "status": "none", "mask": "" }));
    }
    json!({
        "net": {
            "proxy_on": false, "preset": "orbot", "type": "socks5", "addr": "127.0.0.1:9050", "label": "Orbot (Tor)",
            "orbot": false, "groups": { "search": "", "recon": "", "target": "" },
            "out_ip": "", "out_country": "", "kill_switch": true,
            "kill_action": "stop", "ua": "chrome", "threads": 4, "rps": 5, "timeout": 15,
            "retries": 2, "dns": "system", "dns_custom": "", "hosts_parallel": 4
        },
        "keys": keys,
        "power": {
            "wifi_only": true, "lim_on": false, "mob_limit": 1000, "batt_on": true, "batt": 20,
            "batt_action": "pause", "heat": true, "charge_only": false, "period": "month",
            "auto_resume": true
        },
        "sec": {
            "pin": false, "bio": false, "autolock": "5", "hide": true, "clip": true,
            "panic": false, "autodel": false, "autodel_days": "30"
        },
        "work_hours": { "from": 8, "to": 19, "tz": "UTC+2" },
        "debug": { "level": "info" },
        "fuzz": {
            "modules": ["docs", "backups", "exposed", "dirlisting"], "rate": 5, "threads": 4,
            "max_requests": 3000, "max_time_min": 20, "max_hosts": 3, "exclude_paths": [],
            "wordlists": [], "follow_redirects": false, "show_paths": false
        },
        "ports": { "top": 100, "list": "", "max_hosts": 20, "banners": true },
        "crawl": {
            "max_depth": 5, "max_pages": 1000, "max_minutes": 20, "max_rendered": 30,
            "nofollow": false, "resume": true, "storage": true, "images": true,
            "max_images": 300, "max_image_mb": 200, "doc_links": true, "doc_link_depth": 2
        },
        "alerts": {
            "enabled": false,
            "min_severity": "warn",
            "rules": {
                "new_host": true,
                "new_port": true,
                "doc_secret": true,
                "doc_pii": true,
                "doc_gps": true,
                "tls_expiry": true,
                "dangling_cname": true,
                "ct_new_cert": true,
                "risk_rise": true
            },
            "tls_warn_days": 30,
            "tls_crit_days": 14,
            "risk_threshold": 70,
            "risk_delta": 15,
            "risky_ports": [21, 23, 445, 1433, 2375, 3306, 3389, 5432, 5900, 6379, 9200, 11211, 27017],
            "max_alerts": 50,
            "telegram": { "enabled": false, "chat_id": "" },
            "webhook": { "enabled": false, "kind": "generic" },
            "lang": "auto"
        },
        "ocr": {
            "enabled": false,
            "max_pages": 10,
            "max_mb": 15
        },
        "recon": {
            "screenshots": false
        },
        "search": {
            "cc_depth": "latest", "cc_years": 3, "cc_pace_s": 3, "cc_minutes": 5,
            "dork_retry_min": 15
        },
        "lang": "auto",
        "last_project": null
    })
}

/// Deep-merges `b` into `a`: objects are merged recursively, any other value is replaced.
pub fn merge(a: &mut Value, b: &Value) {
    match (a, b) {
        (Value::Object(a), Value::Object(b)) => {
            for (k, v) in b {
                match a.get_mut(k) {
                    Some(x) if x.is_object() && v.is_object() => merge(x, v),
                    _ => {
                        a.insert(k.clone(), v.clone());
                    }
                }
            }
        }
        (a, b) => *a = b.clone(),
    }
}

/// Removes fields under `keys.*` and `alerts.*` that look like secret values.
pub fn strip_secrets(v: &mut Value) {
    if let Some(keys) = v.get_mut("keys").and_then(Value::as_object_mut) {
        for (_, k) in keys.iter_mut() {
            if let Some(o) = k.as_object_mut() {
                for f in [
                    "value", "v", "key", "secret", "token", "api_key", "password",
                ] {
                    o.remove(f);
                }
            }
        }
    }
    if let Some(alerts) = v.get_mut("alerts").and_then(Value::as_object_mut) {
        for f in [
            "token",
            "bot_token",
            "tg_token",
            "url",
            "webhook_url",
            "secret",
        ] {
            alerts.remove(f);
        }
        for sub in ["telegram", "webhook"] {
            if let Some(o) = alerts.get_mut(sub).and_then(Value::as_object_mut) {
                for f in [
                    "token",
                    "bot_token",
                    "url",
                    "webhook_url",
                    "value",
                    "secret",
                    "key",
                ] {
                    o.remove(f);
                }
            }
        }
    }
}

/// Builds a `KeyStatus` from a key value: a mask such as `BSAq…ab12`, never the value itself.
pub fn key_status(value: &str) -> Value {
    let v = value.trim();
    let chars: Vec<char> = v.chars().collect();
    let mask = if chars.len() > 8 {
        format!(
            "{}…{}",
            chars[..4].iter().collect::<String>(),
            chars[chars.len() - 4..].iter().collect::<String>()
        )
    } else if v.is_empty() {
        String::new()
    } else {
        "••••".into()
    };
    json!({ "status": if v.is_empty() { "none" } else { "ok" }, "mask": mask })
}
