//! Microsoft 365 / Entra ID tenant discovery, passive with respect to the target.
//!
//! Only Microsoft's public endpoints are contacted ([`Access::Passive`]):
//! * OpenID discovery `login.microsoftonline.com/<domain>/v2.0/.well-known/openid-configuration`
//!   → tenant id, region scope, cloud instance (or "no tenant");
//! * `getuserrealm.srf` → managed or federated namespace, brand name, the federation (AD FS)
//!   sign-in URL;
//! * optionally Exchange Online autodiscover `GetFederationInformation` → other domains of the
//!   tenant, including `*.onmicrosoft.com` (Microsoft has been trimming this answer, so it is
//!   best-effort).
//!
//! The AD FS URL points at the target's own infrastructure and is only reported, never requested.
//! DNS adds the `*.onmicrosoft.com` name from the DKIM selector CNAMEs of Exchange Online
//! ([`onmicrosoft_from_dkim`]). Base URLs are configurable, so tests run against a local server.

use std::collections::BTreeSet;
use std::sync::OnceLock;

use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::client::{Access, Method, NetClient, NetRequest};
use crate::dns::{norm_name, DnsLookup, RType};
use crate::NetError;

const MODULE: &str = "m365";
const BODY_LIMIT: u64 = 512 * 1024;

/// Base URLs of the Microsoft endpoints.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct M365Endpoints {
    /// `https://login.microsoftonline.com`
    pub login: String,
    /// `https://autodiscover-s.outlook.com`; `None` skips the federation-information query.
    pub autodiscover: Option<String>,
}

impl Default for M365Endpoints {
    fn default() -> Self {
        M365Endpoints {
            login: "https://login.microsoftonline.com".into(),
            autodiscover: Some("https://autodiscover-s.outlook.com".into()),
        }
    }
}

/// Namespace type reported by `getuserrealm.srf`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Namespace {
    /// Cloud-only identities (passwords validated by Entra ID).
    Managed,
    /// Sign-in is redirected to an on-premises or third-party identity provider (AD FS, Okta, ...).
    Federated,
    /// The domain is not registered in any tenant.
    #[default]
    Unknown,
}

/// Fields of the OpenID discovery document that matter for reconnaissance.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpenIdInfo {
    pub tenant_id: String,
    /// `EU`, `NA`, `AS`, `WW`, ... (`tenant_region_scope`).
    pub region_scope: Option<String>,
    /// `GCC`, `DOD`, ... (`tenant_region_sub_scope`; government clouds).
    pub region_sub_scope: Option<String>,
    /// `microsoftonline.com`, `microsoftonline.us`, `partner.microsoftonline.cn`.
    pub cloud_instance: Option<String>,
}

/// Fields of the `getuserrealm.srf` answer.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserRealm {
    pub namespace: Namespace,
    pub domain: Option<String>,
    /// Organization display name configured in the tenant (`FederationBrandName`).
    pub brand: Option<String>,
    /// Federation sign-in URL (`AuthURL`), for example an AD FS endpoint.
    pub auth_url: Option<String>,
    /// `WSTrust`, `SAML20`, ... (`FederationProtocol`).
    pub protocol: Option<String>,
    pub cloud_instance: Option<String>,
}

/// Result of the tenant discovery.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TenantInfo {
    pub domain: String,
    /// The domain belongs to an Entra ID tenant.
    pub exists: bool,
    pub openid: Option<OpenIdInfo>,
    pub realm: Option<UserRealm>,
    /// Host of the federation sign-in URL (`sts.contoso.com`).
    pub federation_host: Option<String>,
    /// The federation URL looks like AD FS (`/adfs/` path).
    pub adfs: bool,
    /// Other domains of the tenant (autodiscover), lowercase, sorted.
    pub tenant_domains: Vec<String>,
    /// `*.onmicrosoft.com` names from autodiscover and DKIM CNAMEs, sorted.
    pub onmicrosoft: Vec<String>,
    /// Non-fatal errors per step: `openid: ...`, `realm: ...`, `autodiscover: ...`.
    pub errors: Vec<String>,
}

fn guid_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(r"(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b")
            .expect("static regex")
    })
}

fn str_field(v: &Value, k: &str) -> Option<String> {
    v.get(k)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

/// Parses an OpenID discovery document. Returns `None` when there is no tenant id (error answers
/// such as `AADSTS90002` included).
pub fn parse_openid(json: &str) -> Option<OpenIdInfo> {
    let v: Value = serde_json::from_str(json).ok()?;
    let tenant_id = ["issuer", "token_endpoint", "authorization_endpoint"]
        .iter()
        .filter_map(|k| v.get(*k).and_then(Value::as_str))
        .find_map(|s| guid_re().find(s))?
        .as_str()
        .to_ascii_lowercase();
    Some(OpenIdInfo {
        tenant_id,
        region_scope: str_field(&v, "tenant_region_scope"),
        region_sub_scope: str_field(&v, "tenant_region_sub_scope"),
        cloud_instance: str_field(&v, "cloud_instance_name"),
    })
}

/// Parses the JSON answer of `getuserrealm.srf?json=1`.
pub fn parse_user_realm(json: &str) -> Result<UserRealm, NetError> {
    let v: Value = serde_json::from_str(json).map_err(|e| NetError::Parse(e.to_string()))?;
    let namespace = match str_field(&v, "NameSpaceType").as_deref() {
        Some(s) if s.eq_ignore_ascii_case("managed") => Namespace::Managed,
        Some(s) if s.eq_ignore_ascii_case("federated") => Namespace::Federated,
        _ => Namespace::Unknown,
    };
    Ok(UserRealm {
        namespace,
        domain: str_field(&v, "DomainName").map(|d| norm_name(&d)),
        brand: str_field(&v, "FederationBrandName"),
        auth_url: str_field(&v, "AuthURL"),
        protocol: str_field(&v, "FederationProtocol"),
        cloud_instance: str_field(&v, "CloudInstanceName"),
    })
}

/// Extracts the domains from a `GetFederationInformation` SOAP answer.
pub fn parse_federation_domains(xml: &str) -> Vec<String> {
    static R: OnceLock<Regex> = OnceLock::new();
    let re = R.get_or_init(|| {
        Regex::new(r"<(?:\w+:)?Domain>\s*([^<\s]+)\s*</(?:\w+:)?Domain>").expect("static regex")
    });
    let set: BTreeSet<String> = re
        .captures_iter(xml)
        .map(|c| norm_name(&c[1]))
        .filter(|d| valid_domain(d))
        .collect();
    set.into_iter().collect()
}

/// Extracts `<tenant>.onmicrosoft.com` from an Exchange Online DKIM selector CNAME
/// (`selector1-contoso-com._domainkey.contoso.onmicrosoft.com`; newer tenants use
/// `…._domainkey.contoso.n-v1.dkim.mail.microsoft`, which carries the tenant name the same way).
pub fn onmicrosoft_from_dkim(cname: &str) -> Option<String> {
    let c = norm_name(cname);
    let rest = c.split_once("._domainkey.")?.1;
    if rest.ends_with(".onmicrosoft.com") {
        let tenant = rest.strip_suffix(".onmicrosoft.com")?.rsplit('.').next()?;
        return (!tenant.is_empty()).then(|| format!("{tenant}.onmicrosoft.com"));
    }
    if rest.ends_with(".dkim.mail.microsoft") {
        let tenant = rest.split('.').next()?;
        return (!tenant.is_empty()).then(|| format!("{tenant}.onmicrosoft.com"));
    }
    None
}

fn valid_domain(d: &str) -> bool {
    !d.is_empty()
        && d.len() <= 253
        && d.contains('.')
        && d.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.')
        && !d.starts_with(['.', '-'])
}

fn federation_body(domain: &str, to: &str) -> String {
    format!(
        r#"<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:a="http://www.w3.org/2005/08/addressing" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
<soap:Header>
<a:Action soap:mustUnderstand="1">http://schemas.microsoft.com/exchange/2010/Autodiscover/Autodiscover/GetFederationInformation</a:Action>
<a:To soap:mustUnderstand="1">{to}</a:To>
<a:ReplyTo><a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address></a:ReplyTo>
</soap:Header>
<soap:Body>
<GetFederationInformationRequestMessage xmlns="http://schemas.microsoft.com/exchange/2010/Autodiscover">
<Request><Domain>{domain}</Domain></Request>
</GetFederationInformationRequestMessage>
</soap:Body>
</soap:Envelope>"#
    )
}

async fn fetch(net: &NetClient, req: NetRequest) -> Result<(u16, String), NetError> {
    let r = net.send(req).await?;
    let status = r.status();
    let body = r.text_limited(BODY_LIMIT).await?;
    Ok((status, body))
}

/// Discovers the Entra ID tenant of `domain`. Every HTTP request is [`Access::Passive`] and goes
/// only to `ep`; `dns` (optional) adds `*.onmicrosoft.com` names from DKIM CNAMEs.
///
/// Fails only for an invalid domain or cancellation; per-step failures land in
/// [`TenantInfo::errors`].
pub async fn discover_tenant(
    net: &NetClient,
    dns: Option<&dyn DnsLookup>,
    ep: &M365Endpoints,
    domain: &str,
) -> Result<TenantInfo, NetError> {
    let domain = norm_name(domain);
    if !valid_domain(&domain) {
        return Err(NetError::Parse(format!("invalid domain: {domain}")));
    }
    let login = ep.login.trim_end_matches('/');
    let mut info = TenantInfo {
        domain: domain.clone(),
        ..Default::default()
    };
    let mut onms: BTreeSet<String> = BTreeSet::new();

    let url = format!("{login}/{domain}/v2.0/.well-known/openid-configuration");
    match fetch(net, NetRequest::get(&url, MODULE, Access::Passive)?).await {
        Ok((s, body)) if s == 200 || s == 400 => {
            info.openid = parse_openid(&body);
        }
        Ok((s, _)) => info.errors.push(format!("openid: HTTP {s}")),
        Err(NetError::Cancelled) => return Err(NetError::Cancelled),
        Err(e) => info.errors.push(format!("openid: {e}")),
    }

    let url = format!("{login}/getuserrealm.srf?login=nn@{domain}&json=1");
    match fetch(net, NetRequest::get(&url, MODULE, Access::Passive)?).await {
        Ok((200, body)) => match parse_user_realm(&body) {
            Ok(r) => info.realm = Some(r),
            Err(e) => info.errors.push(format!("realm: {e}")),
        },
        Ok((s, _)) => info.errors.push(format!("realm: HTTP {s}")),
        Err(NetError::Cancelled) => return Err(NetError::Cancelled),
        Err(e) => info.errors.push(format!("realm: {e}")),
    }
    if let Some(u) = info.realm.as_ref().and_then(|r| r.auth_url.as_deref()) {
        if let Ok(parsed) = url::Url::parse(u) {
            info.federation_host = parsed.host_str().map(norm_name);
            info.adfs = parsed.path().to_ascii_lowercase().contains("/adfs/");
        }
    }
    info.exists = info.openid.is_some()
        || info
            .realm
            .as_ref()
            .is_some_and(|r| r.namespace != Namespace::Unknown);

    if let (true, Some(ad)) = (info.exists, ep.autodiscover.as_deref()) {
        let to = format!("{}/autodiscover/autodiscover.svc", ad.trim_end_matches('/'));
        let req = NetRequest::new(Method::POST, &to, MODULE, Access::Passive)?
            .header("content-type", "text/xml; charset=utf-8")
            .header(
                "soapaction",
                "\"http://schemas.microsoft.com/exchange/2010/Autodiscover/Autodiscover/GetFederationInformation\"",
            )
            .body(federation_body(&domain, &to).into_bytes());
        match fetch(net, req).await {
            Ok((200, body)) => info.tenant_domains = parse_federation_domains(&body),
            Ok((s, _)) => info.errors.push(format!("autodiscover: HTTP {s}")),
            Err(NetError::Cancelled) => return Err(NetError::Cancelled),
            Err(e) => info.errors.push(format!("autodiscover: {e}")),
        }
        onms.extend(
            info.tenant_domains
                .iter()
                .filter(|d| {
                    d.ends_with(".onmicrosoft.com") && !d.ends_with(".mail.onmicrosoft.com")
                })
                .cloned(),
        );
    }

    if let Some(dns) = dns {
        for sel in ["selector1", "selector2"] {
            if let Ok(a) = dns
                .lookup(&format!("{sel}._domainkey.{domain}"), RType::CNAME)
                .await
            {
                onms.extend(
                    a.values(RType::CNAME)
                        .iter()
                        .filter_map(|c| onmicrosoft_from_dkim(c)),
                );
            }
        }
        if !onms.is_empty() {
            info.exists = true;
        }
    }
    info.onmicrosoft = onms.into_iter().collect();
    Ok(info)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use foca_core::Scope;

    use super::*;
    use crate::client::NetConfig;
    use crate::dns::StaticDns;
    use crate::sink::MemorySink;
    use crate::testserver::{TestResponse, TestServer};

    const TID: &str = "72f988bf-86f1-41af-91ab-2d7cd011db47";

    fn openid_doc() -> String {
        format!(
            r#"{{"token_endpoint":"https://login.microsoftonline.com/{TID}/oauth2/v2.0/token",
               "issuer":"https://login.microsoftonline.com/{TID}/v2.0",
               "tenant_region_scope":"EU","cloud_instance_name":"microsoftonline.com"}}"#
        )
    }

    const REALM_FED: &str = r#"{"State":3,"UserState":2,"Login":"nn@contoso.test","NameSpaceType":"Federated",
        "DomainName":"contoso.test","FederationGlobalVersion":-1,
        "AuthURL":"https://sts.contoso.test/adfs/ls/?username=nn%40contoso.test&wa=wsignin1.0",
        "FederationBrandName":"Contoso Ltd","FederationProtocol":"WSTrust",
        "CloudInstanceName":"microsoftonline.com"}"#;

    const FED_XML: &str = r#"<s:Envelope><s:Body><GetFederationInformationResponseMessage>
        <Response><Domains><Domain>contoso.test</Domain><Domain>Contoso.onmicrosoft.com</Domain>
        <Domain>contoso.mail.onmicrosoft.com</Domain><Domain>bad domain</Domain></Domains></Response>
        </GetFederationInformationResponseMessage></s:Body></s:Envelope>"#;

    fn client(sink: Arc<MemorySink>, cfg: NetConfig, scope: Scope) -> NetClient {
        NetClient::new(
            NetConfig {
                retries: 0,
                global_rps: None,
                ..cfg
            },
            scope,
            sink,
        )
        .unwrap()
    }

    #[test]
    fn parsers() {
        let o = parse_openid(&openid_doc()).unwrap();
        assert_eq!(o.tenant_id, TID);
        assert_eq!(o.region_scope.as_deref(), Some("EU"));
        let err = r#"{"error":"invalid_tenant","error_description":"AADSTS90002: Tenant 'x.test' not found."}"#;
        assert!(parse_openid(err).is_none());
        assert!(parse_openid("not json").is_none());

        let r = parse_user_realm(REALM_FED).unwrap();
        assert_eq!(r.namespace, Namespace::Federated);
        assert_eq!(r.brand.as_deref(), Some("Contoso Ltd"));
        assert_eq!(r.protocol.as_deref(), Some("WSTrust"));
        let r = parse_user_realm(r#"{"NameSpaceType":"Unknown","Login":"nn@x.test"}"#).unwrap();
        assert_eq!(r.namespace, Namespace::Unknown);

        assert_eq!(
            parse_federation_domains(FED_XML),
            vec![
                "contoso.mail.onmicrosoft.com",
                "contoso.onmicrosoft.com",
                "contoso.test"
            ]
        );
        assert_eq!(
            onmicrosoft_from_dkim("selector1-contoso-test._domainkey.contoso.onmicrosoft.com.")
                .as_deref(),
            Some("contoso.onmicrosoft.com")
        );
        assert_eq!(
            onmicrosoft_from_dkim(
                "selector1-contoso-test._domainkey.contosoltd.n-v1.dkim.mail.microsoft"
            )
            .as_deref(),
            Some("contosoltd.onmicrosoft.com")
        );
        assert!(onmicrosoft_from_dkim("google._domainkey.example.com").is_none());
    }

    fn server_handler(r: &crate::testserver::TestRequest) -> TestResponse {
        let p = r.path();
        if p == "/contoso.test/v2.0/.well-known/openid-configuration" {
            TestResponse::ok(openid_doc())
        } else if p.ends_with("/.well-known/openid-configuration") {
            TestResponse {
                status: 400,
                body: br#"{"error":"invalid_tenant","error_description":"AADSTS90002"}"#.to_vec(),
                ..Default::default()
            }
        } else if p == "/getuserrealm.srf" {
            if r.query("login").as_deref() == Some("nn@contoso.test") {
                TestResponse::ok(REALM_FED)
            } else {
                TestResponse::ok(r#"{"NameSpaceType":"Unknown"}"#)
            }
        } else if p == "/autodiscover/autodiscover.svc" {
            TestResponse::ok(FED_XML)
        } else {
            TestResponse::status(404)
        }
    }

    #[tokio::test]
    async fn discovery_against_local_server_is_passive() {
        let srv = TestServer::start(server_handler).await;
        let sink = Arc::new(MemorySink::new());
        // contoso.test is the target: the passive profile must never contact it
        let (target, _) = Scope::from_lines("contoso.test", "");
        let net = client(sink.clone(), NetConfig::default(), Scope::default());
        net.set_passive_guard(target, true);
        let ep = M365Endpoints {
            login: srv.url(),
            autodiscover: Some(srv.url()),
        };
        let dns = StaticDns::new().add(
            "selector1._domainkey.contoso.test",
            RType::CNAME,
            &["selector1-contoso-test._domainkey.contosoltd.onmicrosoft.com"],
        );
        let t = discover_tenant(&net, Some(&dns), &ep, "Contoso.TEST")
            .await
            .unwrap();
        assert!(t.exists, "{t:?}");
        assert_eq!(t.openid.as_ref().unwrap().tenant_id, TID);
        assert_eq!(t.realm.as_ref().unwrap().namespace, Namespace::Federated);
        assert_eq!(t.federation_host.as_deref(), Some("sts.contoso.test"));
        assert!(t.adfs);
        assert_eq!(
            t.onmicrosoft,
            vec!["contoso.onmicrosoft.com", "contosoltd.onmicrosoft.com"]
        );
        assert!(t.errors.is_empty(), "{:?}", t.errors);
        // three requests, all passive, all to the Microsoft endpoint, none to the AD FS host
        let recs = sink.records();
        assert_eq!(recs.len(), 3, "{recs:#?}");
        assert!(recs
            .iter()
            .all(|r| !r.active && r.module == MODULE && r.host == "127.0.0.1"));
        let soap = srv
            .requests()
            .into_iter()
            .find(|r| r.path() == "/autodiscover/autodiscover.svc")
            .unwrap();
        assert!(String::from_utf8_lossy(&soap.body).contains("<Domain>contoso.test</Domain>"));
    }

    #[tokio::test]
    async fn unknown_domain_skips_autodiscover() {
        let srv = TestServer::start(server_handler).await;
        let sink = Arc::new(MemorySink::new());
        let net = client(sink.clone(), NetConfig::default(), Scope::default());
        let ep = M365Endpoints {
            login: srv.url(),
            autodiscover: Some(srv.url()),
        };
        let t = discover_tenant(&net, None, &ep, "nobody.test")
            .await
            .unwrap();
        assert!(!t.exists);
        assert!(t.openid.is_none());
        assert_eq!(srv.hits("/autodiscover/autodiscover.svc"), 0);
        assert!(discover_tenant(&net, None, &ep, "bad/../path")
            .await
            .is_err());
    }

    #[tokio::test]
    async fn respects_local_only_and_exclusions() {
        let sink = Arc::new(MemorySink::new());
        let net = client(
            sink.clone(),
            NetConfig {
                local_only: Some(std::path::PathBuf::new()),
                ..Default::default()
            },
            Scope::default(),
        );
        let t = discover_tenant(&net, None, &M365Endpoints::default(), "contoso.test")
            .await
            .unwrap();
        assert!(!t.exists);
        assert_eq!(t.errors.len(), 2, "{:?}", t.errors);
        assert!(sink.records().iter().all(|r| r.status.is_none()));

        // an excluded endpoint host is never contacted
        let srv = TestServer::start(server_handler).await;
        let (scope, _) = Scope::from_lines("", "127.0.0.1");
        let net = client(Arc::new(MemorySink::new()), NetConfig::default(), scope);
        let ep = M365Endpoints {
            login: srv.url(),
            autodiscover: None,
        };
        let t = discover_tenant(&net, None, &ep, "contoso.test")
            .await
            .unwrap();
        assert!(!t.exists);
        assert!(srv.requests().is_empty());
    }
}
