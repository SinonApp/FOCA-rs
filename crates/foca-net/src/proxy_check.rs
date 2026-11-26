//! Explicit user-configured proxy health & exit-IP classification (`SOCKS5`/`HTTP`/`v2rayNG`/`Orbot`).
//!
//! Never discovers or scrapes public proxies (ADR-0012); only tests the local or user-supplied proxy
//! endpoint against `ip_echo` / `ip_geo` and classifies the exit ASN/organization type.

use std::sync::Arc;
use std::time::{Duration, Instant};

use foca_core::Scope;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::client::{Access, NetClient, NetConfig, NetRequest};
use crate::sink::NullSink;

/// Result of checking a user proxy (or direct exit).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProxyCheckResult {
    pub ok: bool,
    pub latency_ms: u64,
    pub out_ip: Option<String>,
    pub country: Option<String>,
    pub org: String,
    pub ip_kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Classifies an exit IP organization / Tor exit flag into `"tor"`, `"datacenter"`,
/// `"vpn"`, `"residential"`, or `"unknown"`.
pub fn classify_ip_kind(org: Option<&str>, is_tor: bool) -> &'static str {
    let low = org.unwrap_or("").trim().to_ascii_lowercase();
    if is_tor || low.contains("tor exit") || low.contains("the tor project") {
        return "tor";
    }
    if low.is_empty() {
        return "unknown";
    }
    const DATACENTER: &[&str] = &[
        "amazon",
        "aws",
        "google cloud",
        "microsoft",
        "azure",
        "digitalocean",
        "hetzner",
        "ovh",
        "linode",
        "akamai",
        "vultr",
        "choopa",
        "contabo",
        "oracle cloud",
        "leaseweb",
        "cloudflare",
        "m247",
        "datacamp",
        "scaleway",
        "upcloud",
        "fly.io",
        "alicloud",
        "alibaba",
        "tencent",
        "hostinger",
        "ionos",
        "serverius",
    ];
    if DATACENTER.iter().any(|k| low.contains(k)) {
        return "datacenter";
    }
    const VPN: &[&str] = &[
        "mullvad",
        "nordvpn",
        "proton",
        "expressvpn",
        "surfshark",
        "private internet access",
        "cyberghost",
        "windscribe",
        "ivpn",
        "wireguard",
    ];
    if VPN.iter().any(|k| low.contains(k)) {
        return "vpn";
    }
    const RESIDENTIAL: &[&str] = &[
        "telecom",
        "telekom",
        "comcast",
        "verizon",
        "at&t",
        "vodafone",
        "orange",
        "kyivstar",
        "ukrtelecom",
        "lifecell",
        "triolan",
        "volia",
        "deutsche telekom",
        "virgin media",
        "rogers",
        "telstra",
        "isp",
        "broadband",
        "mobile",
        "cable",
        "fiber",
    ];
    if RESIDENTIAL.iter().any(|k| low.contains(k)) {
        return "residential";
    }
    "unknown"
}

/// Checks connectivity, latency, exit IP, country, and organization kind through `proxy_url`.
/// When `proxy_url` is `None`, checks direct connectivity. Uses `retries: 0` so dead proxies
/// fail immediately without falling back to direct connections.
pub async fn check_proxy(
    proxy_url: Option<&str>,
    ip_echo: &str,
    ip_geo: &str,
    timeout: Duration,
) -> ProxyCheckResult {
    let proxy = proxy_url
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string);
    let cfg = NetConfig {
        proxy,
        connect_timeout: timeout,
        read_timeout: timeout,
        timeout: Some(timeout.saturating_mul(2)),
        retries: 0,
        global_rps: None,
        source_rps: Default::default(),
        ..Default::default()
    };
    let client = match NetClient::new(cfg, Scope::default(), Arc::new(NullSink)) {
        Ok(c) => c,
        Err(e) => {
            return ProxyCheckResult {
                ok: false,
                ip_kind: "unknown".into(),
                error: Some(e.to_string()),
                ..Default::default()
            };
        }
    };

    let t0 = Instant::now();
    let echo_req = match NetRequest::get(ip_echo, "proxy_check", Access::Passive) {
        Ok(r) => r,
        Err(e) => {
            return ProxyCheckResult {
                ok: false,
                ip_kind: "unknown".into(),
                error: Some(e.to_string()),
                ..Default::default()
            };
        }
    };
    let echo: Value = match client.get_json(echo_req).await {
        Ok(v) => v,
        Err(e) => {
            return ProxyCheckResult {
                ok: false,
                latency_ms: t0.elapsed().as_millis() as u64,
                ip_kind: "unknown".into(),
                error: Some(e.to_string()),
                ..Default::default()
            };
        }
    };
    let latency_ms = t0.elapsed().as_millis() as u64;
    let Some(ip_raw) = echo["ip"].as_str().map(str::trim).filter(|s| !s.is_empty()) else {
        return ProxyCheckResult {
            ok: false,
            latency_ms,
            ip_kind: "unknown".into(),
            error: Some("нет ip в ответе".into()),
            ..Default::default()
        };
    };
    let Ok(ip_addr) = ip_raw.parse::<std::net::IpAddr>() else {
        return ProxyCheckResult {
            ok: false,
            latency_ms,
            ip_kind: "unknown".into(),
            error: Some("некорректный ip в ответе".into()),
            ..Default::default()
        };
    };
    let ip = ip_addr.to_string();

    let geo: Option<Value> = if !ip_geo.trim().is_empty() {
        let u = ip_geo.replace("{ip}", &ip);
        match NetRequest::get(&u, "proxy_check", Access::Passive) {
            Ok(req) => client.get_json(req).await.ok(),
            Err(_) => None,
        }
    } else {
        None
    };

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
                .or_else(|| g.get("as"))
                .and_then(Value::as_str)
        })
        .unwrap_or("")
        .to_string();
    let is_tor = geo
        .as_ref()
        .and_then(|g| g.get("tor").and_then(Value::as_bool))
        .unwrap_or(false);
    let ip_kind = classify_ip_kind((!org.is_empty()).then_some(org.as_str()), is_tor).to_string();

    ProxyCheckResult {
        ok: true,
        latency_ms,
        out_ip: Some(ip),
        country,
        org,
        ip_kind,
        error: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testserver::{TestResponse, TestServer};

    #[test]
    fn ip_kind_classification() {
        assert_eq!(classify_ip_kind(None, true), "tor");
        assert_eq!(classify_ip_kind(Some("Tor Exit Nodes LLC"), false), "tor");
        assert_eq!(
            classify_ip_kind(Some("AS24940 Hetzner Online GmbH"), false),
            "datacenter"
        );
        assert_eq!(
            classify_ip_kind(Some("Amazon.com, Inc."), false),
            "datacenter"
        );
        assert_eq!(classify_ip_kind(Some("Mullvad VPN AB"), false), "vpn");
        assert_eq!(
            classify_ip_kind(Some("Kyivstar PJSC Mobile"), false),
            "residential"
        );
        assert_eq!(classify_ip_kind(Some("Some Unknown ASN"), false), "unknown");
        assert_eq!(classify_ip_kind(None, false), "unknown");
    }

    #[tokio::test]
    async fn check_proxy_parses_echo_and_geo_and_fails_on_dead_proxy() {
        let srv = TestServer::start(|req| match req.path() {
            "/ip" => TestResponse::ok(br#"{"ip":"203.0.113.42"}"#.to_vec())
                .header("content-type", "application/json"),
            "/geo/203.0.113.42" => {
                TestResponse::ok(br#"{"country":"DE","org":"Hetzner Online GmbH"}"#.to_vec())
                    .header("content-type", "application/json")
            }
            _ => TestResponse::status(404),
        })
        .await;

        let echo = format!("{}/ip", srv.url());
        let geo = format!("{}/geo/{{ip}}", srv.url());
        let ok = check_proxy(None, &echo, &geo, Duration::from_secs(2)).await;
        assert!(ok.ok, "{ok:?}");
        assert_eq!(ok.out_ip.as_deref(), Some("203.0.113.42"));
        assert_eq!(ok.country.as_deref(), Some("DE"));
        assert_eq!(ok.org, "Hetzner Online GmbH");
        assert_eq!(ok.ip_kind, "datacenter");

        // Dead proxy port must error without bypassing to TestServer
        let dead = check_proxy(
            Some("socks5h://127.0.0.1:9"),
            &echo,
            &geo,
            Duration::from_millis(600),
        )
        .await;
        assert!(!dead.ok, "{dead:?}");
        assert!(dead.error.is_some());
        assert_eq!(srv.requests().len(), 2);
    }
}
