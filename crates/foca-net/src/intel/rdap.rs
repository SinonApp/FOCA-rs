//! Network and ASN by IP, and domain registration data: RIPEstat (network-info, as-overview)
//! and RDAP (rdap.org). Passive (third-party services).

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::client::{Access, NetClient, NetRequest};
use crate::NetError;

#[derive(Debug, Clone)]
pub struct RdapEndpoints {
    pub ripestat: String,
    pub rdap: String,
}

impl Default for RdapEndpoints {
    fn default() -> Self {
        RdapEndpoints {
            ripestat: "https://stat.ripe.net".into(),
            rdap: "https://rdap.org".into(),
        }
    }
}

/// Network and ASN of an address.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetInfo {
    pub ip: String,
    pub prefix: Option<String>,
    pub asns: Vec<u32>,
    pub holder: Option<String>,
    /// From RDAP: network name, range, country.
    pub net_name: Option<String>,
    pub range: Option<String>,
    pub country: Option<String>,
}

/// Parses a RIPEstat `network-info` response.
pub fn parse_ripe_network_info(json: &str) -> Result<(Option<String>, Vec<u32>), NetError> {
    let v: Value = serde_json::from_str(json).map_err(|e| NetError::Parse(e.to_string()))?;
    let d = &v["data"];
    let prefix = d["prefix"].as_str().map(String::from);
    let asns = d["asns"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|x| {
                    x.as_u64()
                        .or_else(|| x.as_str().and_then(|s| s.parse().ok()))
                })
                .map(|x| x as u32)
                .collect()
        })
        .unwrap_or_default();
    Ok((prefix, asns))
}

/// Parses a RIPEstat `as-overview` response into the holder name.
pub fn parse_ripe_as_overview(json: &str) -> Result<Option<String>, NetError> {
    let v: Value = serde_json::from_str(json).map_err(|e| NetError::Parse(e.to_string()))?;
    Ok(v["data"]["holder"].as_str().map(String::from))
}

/// Network name, range and country from RDAP.
pub type RdapIpNet = (Option<String>, Option<String>, Option<String>);

/// Parses an RDAP IP network response into (name, range, country).
pub fn parse_rdap_ip(json: &str) -> Result<RdapIpNet, NetError> {
    let v: Value = serde_json::from_str(json).map_err(|e| NetError::Parse(e.to_string()))?;
    let name = v["name"].as_str().map(String::from);
    let range = match (v["startAddress"].as_str(), v["endAddress"].as_str()) {
        (Some(a), Some(b)) => Some(format!("{a} - {b}")),
        _ => None,
    };
    let country = v["country"].as_str().map(String::from);
    Ok((name, range, country))
}

/// Domain data from RDAP.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DomainInfo {
    pub domain: String,
    pub registrar: Option<String>,
    pub registered: Option<String>,
    pub expires: Option<String>,
    pub nameservers: Vec<String>,
    pub status: Vec<String>,
}

pub fn parse_rdap_domain(json: &str) -> Result<DomainInfo, NetError> {
    let v: Value = serde_json::from_str(json).map_err(|e| NetError::Parse(e.to_string()))?;
    let mut d = DomainInfo {
        domain: v["ldhName"].as_str().unwrap_or("").to_ascii_lowercase(),
        ..Default::default()
    };
    if let Some(ev) = v["events"].as_array() {
        for e in ev {
            let date = e["eventDate"].as_str().map(String::from);
            match e["eventAction"].as_str() {
                Some("registration") => d.registered = date,
                Some("expiration") => d.expires = date,
                _ => {}
            }
        }
    }
    if let Some(ns) = v["nameservers"].as_array() {
        d.nameservers = ns
            .iter()
            .filter_map(|n| n["ldhName"].as_str())
            .map(|s| s.to_ascii_lowercase())
            .collect();
    }
    if let Some(st) = v["status"].as_array() {
        d.status = st
            .iter()
            .filter_map(|s| s.as_str())
            .map(String::from)
            .collect();
    }
    if let Some(ents) = v["entities"].as_array() {
        for e in ents {
            let is_reg = e["roles"]
                .as_array()
                .is_some_and(|r| r.iter().any(|x| x == "registrar"));
            if !is_reg {
                continue;
            }
            // vcardArray: ["vcard", [["fn", {}, "text", "Name"], ...]]
            if let Some(items) = e["vcardArray"][1].as_array() {
                for it in items {
                    if it[0] == "fn" {
                        d.registrar = it[3].as_str().map(String::from);
                    }
                }
            }
            if d.registrar.is_none() {
                d.registrar = e["handle"].as_str().map(String::from);
            }
        }
    }
    Ok(d)
}

async fn get(net: &NetClient, url: &str) -> Result<String, NetError> {
    let req = NetRequest::get(url, "rdap", Access::Passive)?
        .header("Accept", "application/rdap+json, application/json");
    let r = net.send(req).await?.ensure_success()?;
    r.text_limited(4 * 1024 * 1024).await
}

/// Looks up network, ASN and holder for an IP (RIPEstat plus RDAP; partial failures are not fatal).
pub async fn ip_info(
    net: &NetClient,
    ep: &RdapEndpoints,
    ip: std::net::IpAddr,
) -> Result<NetInfo, NetError> {
    let rs = ep.ripestat.trim_end_matches('/');
    let mut info = NetInfo {
        ip: ip.to_string(),
        ..Default::default()
    };
    let body = get(
        net,
        &format!("{rs}/data/network-info/data.json?resource={ip}"),
    )
    .await?;
    let (prefix, asns) = parse_ripe_network_info(&body)?;
    info.prefix = prefix;
    info.asns = asns;
    if let Some(a) = info.asns.first() {
        if let Ok(b) = get(
            net,
            &format!("{rs}/data/as-overview/data.json?resource=AS{a}"),
        )
        .await
        {
            info.holder = parse_ripe_as_overview(&b).ok().flatten();
        }
    }
    if let Ok(b) = get(net, &format!("{}/ip/{ip}", ep.rdap.trim_end_matches('/'))).await {
        if let Ok((n, r, c)) = parse_rdap_ip(&b) {
            info.net_name = n;
            info.range = r;
            info.country = c;
        }
    }
    Ok(info)
}

/// Fetches RDAP data for a domain.
pub async fn domain_info(
    net: &NetClient,
    ep: &RdapEndpoints,
    domain: &str,
) -> Result<DomainInfo, NetError> {
    let b = get(
        net,
        &format!(
            "{}/domain/{}",
            ep.rdap.trim_end_matches('/'),
            crate::dns::norm_name(domain)
        ),
    )
    .await?;
    parse_rdap_domain(&b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ripe() {
        let (p, a) =
            parse_ripe_network_info(r#"{"data":{"asns":["13335"],"prefix":"1.1.1.0/24"}}"#)
                .unwrap();
        assert_eq!(p.as_deref(), Some("1.1.1.0/24"));
        assert_eq!(a, vec![13335]);
        assert_eq!(
            parse_ripe_as_overview(r#"{"data":{"holder":"CLOUDFLARENET"}}"#)
                .unwrap()
                .as_deref(),
            Some("CLOUDFLARENET")
        );
    }

    #[test]
    fn rdap_domain() {
        let j = r#"{"ldhName":"EXAMPLE.COM","status":["client delete prohibited"],
          "events":[{"eventAction":"registration","eventDate":"1995-08-14T04:00:00Z"},{"eventAction":"expiration","eventDate":"2026-08-13T04:00:00Z"}],
          "nameservers":[{"ldhName":"A.IANA-SERVERS.NET"}],
          "entities":[{"roles":["registrar"],"handle":"376","vcardArray":["vcard",[["version",{},"text","4.0"],["fn",{},"text","RESERVED-Internet Assigned Numbers Authority"]]]}]}"#;
        let d = parse_rdap_domain(j).unwrap();
        assert_eq!(d.domain, "example.com");
        assert_eq!(d.nameservers, vec!["a.iana-servers.net"]);
        assert_eq!(
            d.registrar.as_deref(),
            Some("RESERVED-Internet Assigned Numbers Authority")
        );
        assert!(d.expires.unwrap().starts_with("2026"));
    }
}
