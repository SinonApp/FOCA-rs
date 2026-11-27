//! Dangling CNAMEs: a CNAME pointing to a non-existent host at a known provider indicates a
//! subdomain takeover risk.
//!
//! Providers come from the hand table [`PROVIDERS`] and from the can-i-take-over-xyz
//! fingerprints (CC-BY-4.0, EdOverflow and contributors; fields reduced by
//! `foca-analysis/signatures/tools/update_takeover.py`), which also say whether a released name
//! can really be claimed (`vulnerable`, `edge`, `not_vulnerable`) and which HTTP body text marks
//! an unclaimed resource.

use std::sync::{Arc, RwLock};

use serde::{Deserialize, Serialize};

use crate::dns::{norm_name, DnsLookup, RType};

/// Providers where a released name can be registered again.
pub const PROVIDERS: &[(&str, &[&str])] = &[
    (
        "Azure",
        &[
            "azurewebsites.net",
            "cloudapp.net",
            "cloudapp.azure.com",
            "trafficmanager.net",
            "blob.core.windows.net",
            "azureedge.net",
            "azure-api.net",
            "azurefd.net",
            "azurecontainer.io",
            "azurestaticapps.net",
        ],
    ),
    ("AWS S3", &["s3.amazonaws.com", "s3-website"]),
    ("AWS Elastic Beanstalk", &["elasticbeanstalk.com"]),
    ("AWS CloudFront", &["cloudfront.net"]),
    ("GitHub Pages", &["github.io"]),
    (
        "Heroku",
        &["herokuapp.com", "herokudns.com", "herokussl.com"],
    ),
    ("Shopify", &["myshopify.com"]),
    ("Fastly", &["fastly.net"]),
    ("Netlify", &["netlify.app", "netlify.com"]),
    ("Vercel", &["vercel.app", "now.sh"]),
    ("Pantheon", &["pantheonsite.io"]),
    ("Zendesk", &["zendesk.com"]),
    ("Ghost", &["ghost.io"]),
    ("Surge", &["surge.sh"]),
    ("Bitbucket", &["bitbucket.io"]),
    ("WordPress.com", &["wordpress.com"]),
    ("Tumblr", &["domains.tumblr.com"]),
    ("Unbounce", &["unbouncepages.com"]),
    ("ReadMe", &["readme.io"]),
    ("Fly.io", &["fly.dev"]),
    ("Google Cloud Storage", &["storage.googleapis.com"]),
    ("Firebase", &["firebaseapp.com", "web.app"]),
    ("Webflow", &["proxy-ssl.webflow.com"]),
    ("Help Scout", &["helpscoutdocs.com"]),
    ("Cargo", &["cargocollective.com"]),
];

/// can-i-take-over-xyz fingerprints as shipped.
pub const TAKEOVER_JSON: &str = include_str!("../../data/takeover.json");

/// One service of the fingerprint table.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TakeoverService {
    pub service: String,
    /// `vulnerable`, `edge` or `not_vulnerable`.
    pub status: String,
    pub cname: Vec<String>,
    /// NXDOMAIN of the target is the takeover signal.
    pub nxdomain: bool,
    /// HTTP body text of an unclaimed resource (empty when NXDOMAIN is the signal).
    #[serde(default)]
    pub fingerprint: String,
}

#[derive(Deserialize)]
struct TakeoverFile {
    services: Vec<TakeoverService>,
}

fn parse_table(json: &str) -> Result<Vec<TakeoverService>, String> {
    let f: TakeoverFile = serde_json::from_str(json).map_err(|e| e.to_string())?;
    Ok(f.services)
}

fn slot() -> &'static RwLock<Option<Arc<Vec<TakeoverService>>>> {
    static S: RwLock<Option<Arc<Vec<TakeoverService>>>> = RwLock::new(None);
    &S
}

/// The fingerprint table in use.
pub fn services() -> Arc<Vec<TakeoverService>> {
    if let Some(t) = slot().read().ok().and_then(|g| g.clone()) {
        return t;
    }
    let mut g = slot().write().unwrap_or_else(|e| e.into_inner());
    g.get_or_insert_with(|| Arc::new(parse_table(TAKEOVER_JSON).unwrap_or_default()))
        .clone()
}

/// Replaces the fingerprint table (a signed signature bundle); returns the service count.
pub fn install(json: &str) -> Result<usize, String> {
    let t = parse_table(json)?;
    let n = t.len();
    *slot().write().unwrap_or_else(|e| e.into_inner()) = Some(Arc::new(t));
    Ok(n)
}

fn suffix_hit(t: &str, s: &str) -> bool {
    t == s || t.ends_with(&format!(".{s}"))
}

/// The fingerprint table entry for a CNAME target, if any.
pub fn service_for(target: &str) -> Option<TakeoverService> {
    let t = norm_name(target);
    services()
        .iter()
        .find(|s| s.cname.iter().any(|c| suffix_hit(&t, c)))
        .cloned()
}

/// Whether an HTTP body served for a CNAME target shows the unclaimed-resource text of its
/// provider (for a target that still resolves). Returns the service name.
pub fn body_fingerprint(target: &str, body: &str) -> Option<String> {
    let s = service_for(target)?;
    if s.status == "not_vulnerable" || s.fingerprint.is_empty() {
        return None;
    }
    // Some fingerprints are regexes (`Tunnel .*.ngrok.io not found`); plain text is a valid
    // regex too, and a pattern that does not compile is matched as text.
    let hit = match regex::Regex::new(&s.fingerprint) {
        Ok(re) => re.is_match(body),
        Err(_) => body.contains(&s.fingerprint),
    };
    hit.then_some(s.service)
}

/// Returns the provider for a CNAME target, if known (hand table first).
pub fn provider_for(target: &str) -> Option<&'static str> {
    let t = norm_name(target);
    PROVIDERS.iter().find_map(|(p, sufs)| {
        sufs.iter()
            .any(|s| t == *s || t.ends_with(&format!(".{s}")) || (s.contains('-') && t.contains(s)))
            .then_some(*p)
    })
}

/// A dangling CNAME.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Dangling {
    pub host: String,
    /// CNAME chain (the last entry does not exist).
    pub chain: Vec<String>,
    pub provider: Option<String>,
    /// `crit` for known providers (the name can be claimed), `warn` otherwise.
    pub sev: String,
    pub reason: String,
}

/// Checks a host by following its CNAME chain (up to 8 steps); if the final target is
/// NXDOMAIN, the CNAME is dangling.
pub async fn check_dangling(dns: &dyn DnsLookup, host: &str) -> Option<Dangling> {
    let host = norm_name(host);
    let mut chain = Vec::new();
    let mut cur = host.clone();
    for _ in 0..8 {
        let a = dns.lookup(&cur, RType::CNAME).await.ok()?;
        if a.nxdomain {
            break;
        }
        let next = a.values(RType::CNAME).into_iter().next()?;
        let next = norm_name(&next);
        if chain.contains(&next) {
            return None;
        }
        chain.push(next.clone());
        cur = next;
    }
    let last = chain.last()?.clone();
    let mut nx = false;
    for t in [RType::A, RType::AAAA] {
        match dns.lookup(&last, t).await {
            Ok(a) if a.nxdomain => nx = true,
            Ok(a) if !a.records.is_empty() => return None,
            Ok(_) => {}
            Err(_) => return None,
        }
    }
    if !nx {
        return None;
    }
    let hand = chain.iter().find_map(|c| provider_for(c)).map(String::from);
    let table = chain.iter().find_map(|c| service_for(c));
    // The fingerprint table may say a released name cannot be claimed at this provider.
    let not_claimable = table.as_ref().is_some_and(|s| s.status == "not_vulnerable");
    let provider = hand.or_else(|| table.as_ref().map(|s| s.service.clone()));
    let sev = if provider.is_some() && !not_claimable {
        "crit"
    } else {
        "warn"
    };
    let reason = match &provider {
        Some(p) if not_claimable => format!(
            "CNAME → {last} ({p}) не существует; по данным can-i-take-over-xyz занять имя у этого провайдера нельзя"
        ),
        Some(p) => format!("CNAME → {last} ({p}) не существует: имя можно занять у провайдера"),
        None => format!("CNAME → {last} не существует (NXDOMAIN)"),
    };
    Some(Dangling {
        host,
        chain,
        provider,
        sev: sev.into(),
        reason,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::StaticDns;

    #[test]
    fn providers() {
        assert_eq!(provider_for("contoso.azurewebsites.net."), Some("Azure"));
        assert_eq!(
            provider_for("x.s3-website-eu-west-1.amazonaws.com"),
            Some("AWS S3")
        );
        assert_eq!(provider_for("user.github.io"), Some("GitHub Pages"));
        assert_eq!(provider_for("evilgithub.io"), None);
        assert_eq!(provider_for("www.contoso.ua"), None);
    }

    #[test]
    fn fingerprint_table() {
        let s = services();
        assert!(s.len() >= 25, "{}", s.len());
        let s3 = service_for("contoso.s3.amazonaws.com.").unwrap();
        assert_eq!(s3.status, "vulnerable");
        assert_eq!(
            body_fingerprint(
                "contoso.s3.amazonaws.com",
                "<Code>NoSuchBucket</Code><Message>The specified bucket does not exist</Message>"
            ),
            Some(s3.service.clone())
        );
        assert_eq!(body_fingerprint("contoso.s3.amazonaws.com", "hello"), None);
        // Regex fingerprints and not-claimable providers.
        assert!(body_fingerprint("a.ngrok.io", "Tunnel a.ngrok.io not found").is_some());
        assert_eq!(
            service_for("x.eu-west-1.elb.amazonaws.com").unwrap().status,
            "not_vulnerable"
        );
        assert!(service_for("www.contoso.ua").is_none());
        // A provider only the table knows is reported with its name.
        let only_table = s
            .iter()
            .find(|x| x.status == "vulnerable" && x.cname.iter().all(|c| provider_for(c).is_none()))
            .expect("a table-only provider");
        assert!(service_for(&format!("x.{}", only_table.cname[0])).is_some());
    }

    #[tokio::test]
    async fn detects_dangling() {
        let d = StaticDns::new()
            .add(
                "old.contoso.ua",
                RType::CNAME,
                &["contoso.azurewebsites.net"],
            )
            .add("www.contoso.ua", RType::CNAME, &["web.contoso.ua"])
            .add("web.contoso.ua", RType::A, &["192.0.2.1"])
            .add("lost.contoso.ua", RType::CNAME, &["gone.example.net"])
            .add("contoso.ua", RType::A, &["192.0.2.2"]);
        let x = check_dangling(&d, "old.contoso.ua").await.unwrap();
        assert_eq!(x.provider.as_deref(), Some("Azure"));
        assert_eq!(x.sev, "crit");
        assert!(check_dangling(&d, "www.contoso.ua").await.is_none());
        assert!(check_dangling(&d, "contoso.ua").await.is_none());
        let y = check_dangling(&d, "lost.contoso.ua").await.unwrap();
        assert_eq!(y.sev, "warn");
        assert!(y.provider.is_none());
    }
}
