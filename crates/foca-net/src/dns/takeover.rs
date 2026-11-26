//! Dangling CNAMEs: a CNAME pointing to a non-existent host at a known provider indicates a
//! subdomain takeover risk.

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

/// Returns the provider for a CNAME target, if known.
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
    let provider = chain.iter().find_map(|c| provider_for(c)).map(String::from);
    let sev = if provider.is_some() { "crit" } else { "warn" };
    let reason = match &provider {
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
