//! DNS over HTTPS (RFC 8484, JSON flavor `application/dns-json`) through the shared [`NetClient`].
//!
//! With a proxy or Tor configured, DNS queries go through the same proxy instead of directly to
//! 1.1.1.1/8.8.8.8, which would leak them. The mode comes from `settings.net.dns_mode`:
//! `system` (hickory over UDP/TCP 53), `doh` (always DoH) or `auto` (DoH when a proxy is set;
//! the default). Without a proxy, or in `system` mode, the hickory resolver is used. If DoH is
//! unavailable, lookups fail closed; there is no direct fallback.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use serde_json::Value;

use crate::client::{Access, NetClient, NetRequest, ProxyResolver};
use crate::dns::{
    lookup_ips, norm_name, DnsAnswer, DnsConfig, DnsLookup, DnsRecord, HickoryDns, RType,
};
use crate::{BoxFuture, NetError};

/// Public DoH endpoints with a JSON API, tried in order on error.
pub const DEFAULT_DOH: &[&str] = &[
    "https://cloudflare-dns.com/dns-query",
    "https://dns.google/resolve",
];

/// Resolver mode (`settings.net.dns_mode`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DnsMode {
    System,
    Doh,
    #[default]
    Auto,
}

impl DnsMode {
    pub fn parse(s: &str) -> DnsMode {
        match s.trim().to_ascii_lowercase().as_str() {
            "system" | "udp" => DnsMode::System,
            "doh" | "https" => DnsMode::Doh,
            _ => DnsMode::Auto,
        }
    }

    /// Returns `true` if DoH should be used for this client.
    pub fn use_doh(self, net: &NetClient) -> bool {
        match self {
            DnsMode::System => false,
            DnsMode::Doh => true,
            DnsMode::Auto => net.has_proxy(),
        }
    }
}

/// Returns the resolver for the mode: DoH through `net` (and its proxy) or hickory.
pub fn resolver(
    mode: DnsMode,
    cfg: &DnsConfig,
    net: &NetClient,
) -> Result<Arc<dyn DnsLookup>, NetError> {
    if mode.use_doh(net) {
        Ok(Arc::new(DohDns::new(net)))
    } else {
        Ok(Arc::new(HickoryDns::new(cfg, net)?))
    }
}

/// DoH resolver (Cloudflare / Google JSON API).
#[derive(Clone)]
pub struct DohDns {
    net: NetClient,
    pub endpoints: Vec<String>,
    pub timeout: Duration,
}

impl DohDns {
    pub fn new(net: &NetClient) -> Self {
        DohDns {
            net: net.clone(),
            endpoints: DEFAULT_DOH.iter().map(|s| s.to_string()).collect(),
            timeout: Duration::from_secs(10),
        }
    }

    pub fn with_endpoints(net: &NetClient, eps: &[&str]) -> Self {
        DohDns {
            endpoints: eps.iter().map(|s| s.to_string()).collect(),
            ..DohDns::new(net)
        }
    }

    async fn query(&self, ep: &str, name: &str, t: RType) -> Result<DnsAnswer, NetError> {
        let mut u = url::Url::parse(ep).map_err(|e| NetError::BadUrl(e.to_string()))?;
        u.query_pairs_mut()
            .append_pair("name", name)
            .append_pair("type", t.as_str());
        let req = NetRequest::get(u.as_str(), "dns", Access::Passive)?
            .header("accept", "application/dns-json")
            .timeout(self.timeout)
            .retries(1);
        let v: Value = self.net.get_json(req).await?;
        parse_doh_json(&v, name, t)
    }
}

fn type_name(n: u64) -> String {
    match n {
        1 => "A",
        2 => "NS",
        5 => "CNAME",
        6 => "SOA",
        12 => "PTR",
        15 => "MX",
        16 => "TXT",
        28 => "AAAA",
        33 => "SRV",
        43 => "DS",
        48 => "DNSKEY",
        257 => "CAA",
        _ => return format!("TYPE{n}"),
    }
    .into()
}

/// Normalizes TXT data from JSON DoH: Cloudflare returns quoted strings (`"a" "b"`), Google does
/// not. Quoted parts are concatenated, matching hickory (`rdata_value`).
pub fn unquote_txt(s: &str) -> String {
    let s = s.trim();
    if !s.starts_with('"') {
        return s.to_string();
    }
    let mut out = String::new();
    let mut inq = false;
    let mut esc = false;
    for c in s.chars() {
        if esc {
            out.push(c);
            esc = false;
        } else if c == '\\' && inq {
            esc = true;
        } else if c == '"' {
            inq = !inq;
        } else if inq {
            out.push(c);
        }
    }
    out
}

/// Parses a JSON DoH response into a [`DnsAnswer`], normalized the same way as hickory answers.
pub fn parse_doh_json(v: &Value, name: &str, t: RType) -> Result<DnsAnswer, NetError> {
    let status = v["Status"].as_u64().unwrap_or(2);
    match status {
        0 => {}
        3 => {
            return Ok(DnsAnswer {
                records: vec![],
                nxdomain: true,
            })
        }
        s => {
            return Err(NetError::Dns(format!(
                "{name} {}: DoH rcode {s}",
                t.as_str()
            )))
        }
    }
    let records = v["Answer"]
        .as_array()
        .map(|a| {
            a.iter()
                .map(|r| {
                    let rtype = type_name(r["type"].as_u64().unwrap_or(0));
                    let data = r["data"].as_str().unwrap_or("").trim().to_string();
                    let value = match rtype.as_str() {
                        "TXT" => unquote_txt(&data),
                        "CNAME" | "NS" | "PTR" => norm_name(&data),
                        "MX" => match data.split_once(' ') {
                            Some((p, h)) => format!("{p} {}", norm_name(h)),
                            None => data,
                        },
                        _ => data,
                    };
                    DnsRecord {
                        name: norm_name(r["name"].as_str().unwrap_or(name)),
                        rtype,
                        ttl: r["TTL"].as_u64().unwrap_or(0) as u32,
                        value,
                    }
                })
                .collect()
        })
        .unwrap_or_default();
    Ok(DnsAnswer {
        records,
        nxdomain: false,
    })
}

impl DnsLookup for DohDns {
    fn lookup<'a>(&'a self, name: &'a str, t: RType) -> BoxFuture<'a, Result<DnsAnswer, NetError>> {
        Box::pin(async move {
            let name = norm_name(name);
            let mut last = NetError::Dns(format!("{name}: нет DoH-эндпоинтов"));
            for ep in &self.endpoints {
                match self.query(ep, &name, t).await {
                    Ok(a) => return Ok(a),
                    Err(NetError::Cancelled) => return Err(NetError::Cancelled),
                    Err(e) => last = e,
                }
            }
            Err(match last {
                NetError::Dns(m) => NetError::Dns(m),
                e => NetError::Dns(format!("{name} {} через DoH: {e}", t.as_str())),
            })
        })
    }
}

/// Scope-check resolver of proxied clients: DNS over HTTPS through the same client and proxy.
#[derive(Debug, Default)]
pub struct DohProxyResolver;

impl ProxyResolver for DohProxyResolver {
    fn resolve<'a>(&'a self, net: &'a NetClient, host: &'a str) -> BoxFuture<'a, Vec<IpAddr>> {
        Box::pin(async move { lookup_ips(&DohDns::new(net), host).await })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sink::MemorySink;
    use crate::testserver::{TestResponse, TestServer};
    use crate::NetConfig;
    use foca_core::Scope;

    #[test]
    fn parse_cloudflare_and_google() {
        let cf: Value = serde_json::from_str(
            r#"{"Status":0,"Answer":[
              {"name":"example.com","type":5,"TTL":60,"data":"Web.Example.NET."},
              {"name":"web.example.net","type":1,"TTL":60,"data":"93.184.216.34"},
              {"name":"example.com","type":16,"TTL":60,"data":"\"v=spf1 -all\""},
              {"name":"example.com","type":16,"TTL":60,"data":"\"v=DKIM1; k=rsa; \" \"p=MIIB\""},
              {"name":"example.com","type":15,"TTL":60,"data":"10 mx.example.com."}]}"#,
        )
        .unwrap();
        let a = parse_doh_json(&cf, "example.com", RType::A).unwrap();
        assert_eq!(a.values(RType::A), vec!["93.184.216.34"]);
        assert_eq!(a.values(RType::CNAME), vec!["web.example.net"]);
        assert_eq!(
            a.values(RType::TXT),
            vec!["v=spf1 -all", "v=DKIM1; k=rsa; p=MIIB"]
        );
        assert_eq!(a.values(RType::MX), vec!["10 mx.example.com"]);
        let g: Value = serde_json::from_str(
            r#"{"Status":0,"Answer":[{"name":"x.","type":16,"TTL":1,"data":"v=spf1 ~all"}]}"#,
        )
        .unwrap();
        assert_eq!(
            parse_doh_json(&g, "x", RType::TXT)
                .unwrap()
                .values(RType::TXT),
            vec!["v=spf1 ~all"]
        );
        let nx: Value = serde_json::from_str(r#"{"Status":3}"#).unwrap();
        assert!(parse_doh_json(&nx, "x", RType::A).unwrap().nxdomain);
        let sf: Value = serde_json::from_str(r#"{"Status":2}"#).unwrap();
        assert!(parse_doh_json(&sf, "x", RType::A).is_err());
    }

    #[tokio::test]
    async fn doh_goes_through_netclient_with_fallback() {
        let srv = TestServer::start(|r| match r.path() {
            "/bad" => TestResponse::status(503),
            "/dns-query" => {
                assert_eq!(r.query("type").as_deref(), Some("A"));
                TestResponse::ok(
                    r#"{"Status":0,"Answer":[{"name":"a.test.","type":1,"TTL":5,"data":"192.0.2.1"}]}"#,
                )
            }
            _ => TestResponse::status(404),
        })
        .await;
        let sink = Arc::new(MemorySink::new());
        let cfg = NetConfig {
            retries: 0,
            global_rps: None,
            ..Default::default()
        };
        let net = NetClient::new(cfg, Scope::default(), sink.clone()).unwrap();
        let bad = format!("{}/bad", srv.url());
        let good = format!("{}/dns-query", srv.url());
        let d = DohDns::with_endpoints(&net, &[&bad, &good]);
        let a = d.lookup("a.test", RType::A).await.unwrap();
        assert_eq!(a.values(RType::A), vec!["192.0.2.1"]);
        assert!(sink
            .records()
            .iter()
            .all(|r| r.module == "dns" && !r.active));
    }

    /// With the proxy down, DoH fails and no direct DNS queries (UDP/53) are made at all: in `auto`
    /// mode with a proxy the resolver is DoH, whose only route is the proxy.
    #[tokio::test]
    async fn dead_proxy_means_no_direct_dns() {
        let sink = Arc::new(MemorySink::new());
        let cfg = NetConfig {
            proxy: Some("socks5h://127.0.0.1:9".into()),
            retries: 0,
            global_rps: None,
            ..Default::default()
        };
        let net = NetClient::new(cfg, Scope::default(), sink.clone()).unwrap();
        assert!(DnsMode::Auto.use_doh(&net));
        assert!(!DnsMode::System.use_doh(&net));
        let r = resolver(DnsMode::Auto, &DnsConfig::default(), &net).unwrap();
        let e = r.lookup("example.com", RType::A).await.unwrap_err();
        assert_eq!(e.code(), "dns");
        // everything that hit the network is an HTTP request to DoH (via the proxy), never a `DNS` method
        let recs = sink.records();
        assert!(!recs.is_empty());
        assert!(
            recs.iter().all(|r| r.method == "GET" && r.module == "dns"),
            "{recs:#?}"
        );
        assert!(recs.iter().all(|r| r.status.is_none()));
    }
}
