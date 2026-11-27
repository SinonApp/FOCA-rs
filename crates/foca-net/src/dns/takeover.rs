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

/// Parses a fingerprint table without installing it; returns the service count.
pub fn check(json: &str) -> Result<usize, String> {
    parse_table(json).map(|t| t.len())
}

fn suffix_hit(t: &str, s: &str) -> bool {
    t == s || t.ends_with(&format!(".{s}"))
}

/// The fingerprint table entry for a CNAME target, if any.
pub fn service_for(target: &str) -> Option<TakeoverService> {
    let t = norm_name(target);
    services().iter().find(|s| s.serves(&t)).cloned()
}

impl TakeoverService {
    /// The CNAME target (normalized) belongs to this service.
    fn serves(&self, target: &str) -> bool {
        self.cname.iter().any(|c| suffix_hit(target, c))
    }

    /// The service has an HTTP body fingerprint and a released resource can be claimed.
    pub fn has_body_check(&self) -> bool {
        self.status != "not_vulnerable" && !self.fingerprint.is_empty()
    }

    /// Returns the part of `body` that matches the unclaimed-resource fingerprint, if any.
    pub fn match_body(&self, body: &str) -> Option<String> {
        if !self.has_body_check() {
            return None;
        }
        // The table keeps the markdown escape of `|` from the upstream README.
        let pat = self.fingerprint.replace("&#124;", "|");
        // Some fingerprints are regexes (`Tunnel .*.ngrok.io not found`); plain text is a valid
        // regex too, and a pattern that does not compile is matched as text.
        match regex::Regex::new(&pat) {
            Ok(re) => re.find(body).map(|m| m.as_str().to_string()),
            Err(_) => body.contains(&pat).then_some(pat),
        }
    }
}

/// Whether an HTTP body served for a CNAME target shows the unclaimed-resource text of its
/// provider (for a target that still resolves). Returns the service name.
pub fn body_fingerprint(target: &str, body: &str) -> Option<String> {
    let s = service_for(target)?;
    s.match_body(body).map(|_| s.service)
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

/// A host whose CNAME chain points at a resolving resource of a service with an HTTP body
/// fingerprint: fetching the host tells whether the resource is unclaimed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpCandidate {
    pub host: String,
    pub chain: Vec<String>,
    pub service: TakeoverService,
}

/// What following a host's CNAME chain found: a dangling CNAME (NXDOMAIN target) or a candidate
/// for the HTTP fingerprint check.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Inspection {
    pub dangling: Option<Dangling>,
    pub http: Option<HttpCandidate>,
}

/// Checks a host by following its CNAME chain (up to 8 steps); if the final target is
/// NXDOMAIN, the CNAME is dangling.
pub async fn check_dangling(dns: &dyn DnsLookup, host: &str) -> Option<Dangling> {
    inspect(dns, host).await.dangling
}

/// Follows a host's CNAME chain once: a dangling CNAME when the final target is NXDOMAIN, an
/// HTTP fingerprint candidate when it resolves at a service the fingerprint table can check.
pub async fn inspect(dns: &dyn DnsLookup, host: &str) -> Inspection {
    let host = norm_name(host);
    let Some(chain) = cname_chain(dns, &host).await else {
        return Inspection::default();
    };
    let Some(last) = chain.last().cloned() else {
        return Inspection::default();
    };
    let mut nx = false;
    for t in [RType::A, RType::AAAA] {
        match dns.lookup(&last, t).await {
            Ok(a) if a.nxdomain => nx = true,
            Ok(a) if !a.records.is_empty() => {
                // The target resolves: only the HTTP body can tell an unclaimed resource.
                let http = chain
                    .iter()
                    .find_map(|c| service_for(c))
                    .filter(TakeoverService::has_body_check)
                    .map(|service| HttpCandidate {
                        host,
                        chain,
                        service,
                    });
                return Inspection {
                    dangling: None,
                    http,
                };
            }
            Ok(_) => {}
            Err(_) => return Inspection::default(),
        }
    }
    if !nx {
        return Inspection::default();
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
    Inspection {
        dangling: Some(Dangling {
            host,
            chain,
            provider,
            sev: sev.into(),
            reason,
        }),
        http: None,
    }
}

/// The CNAME chain of `host` (up to 8 steps); `None` without a CNAME, on a loop or a lookup
/// error.
async fn cname_chain(dns: &dyn DnsLookup, host: &str) -> Option<Vec<String>> {
    let mut chain = Vec::new();
    let mut cur = host.to_string();
    for _ in 0..8 {
        let a = dns.lookup(&cur, RType::CNAME).await.ok()?;
        if a.nxdomain {
            break;
        }
        // no further CNAME: the chain ends at an address record (or nothing)
        let Some(next) = a.values(RType::CNAME).into_iter().next() else {
            break;
        };
        let next = norm_name(&next);
        if chain.contains(&next) {
            return None;
        }
        chain.push(next.clone());
        cur = next;
    }
    (!chain.is_empty()).then_some(chain)
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

    #[tokio::test]
    async fn resolving_cname_at_known_service_is_http_candidate() {
        let d = StaticDns::new()
            .add(
                "shop.example.test",
                RType::CNAME,
                &["unclaimed-example.s3.amazonaws.com"],
            )
            .add(
                "unclaimed-example.s3.amazonaws.com",
                RType::A,
                &["192.0.2.10"],
            )
            .add(
                "api.example.test",
                RType::CNAME,
                &["x.eu-west-1.elb.amazonaws.com"],
            )
            .add("x.eu-west-1.elb.amazonaws.com", RType::A, &["192.0.2.11"])
            .add(
                "help.example.test",
                RType::CNAME,
                &["unclaimed-example.helprace.com"],
            )
            .add("unclaimed-example.helprace.com", RType::A, &["192.0.2.12"])
            .add("www.example.test", RType::CNAME, &["web.example.test"])
            .add("web.example.test", RType::A, &["192.0.2.1"]);
        let i = inspect(&d, "shop.example.test").await;
        assert!(i.dangling.is_none());
        let c = i.http.expect("S3 candidate");
        assert_eq!(c.host, "shop.example.test");
        assert_eq!(
            c.chain,
            vec!["unclaimed-example.s3.amazonaws.com".to_string()]
        );
        assert_eq!(c.service.service, "AWS/S3");
        // not claimable (ELB), no fingerprint text (Helprace), unknown target: no candidate
        for h in ["api.example.test", "help.example.test", "www.example.test"] {
            assert_eq!(inspect(&d, h).await, Inspection::default(), "{h}");
        }
    }

    #[test]
    fn match_body_returns_the_matched_text() {
        let s3 = service_for("unclaimed-example.s3.amazonaws.com").unwrap();
        assert_eq!(
            s3.match_body("<Error><Code>NoSuchBucket</Code><Message>The specified bucket does not exist</Message>")
                .as_deref(),
            Some("The specified bucket does not exist")
        );
        assert_eq!(s3.match_body("<html>shop</html>"), None);
        // the `&#124;` escape from the upstream table is an alternation
        let ghost = service_for("unclaimed-example.ghost.io").unwrap();
        assert_eq!(
            ghost
                .match_body("<h1>Failed to resolve DNS path for this host</h1>")
                .as_deref(),
            Some("Failed to resolve DNS path for this host")
        );
        let ngrok = service_for("a.ngrok.io").unwrap();
        assert!(ngrok.match_body("Tunnel a.ngrok.io not found").is_some());
        let elb = service_for("x.eu-west-1.elb.amazonaws.com").unwrap();
        assert!(!elb.has_body_check());
        assert_eq!(elb.match_body("anything"), None);
    }
}
