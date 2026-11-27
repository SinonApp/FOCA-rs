//! SaaS and cloud fingerprinting from DNS: domain-verification TXT records, SPF includes, MX
//! hosts and a few service-specific names (`_amazonses`, `autodiscover`).
//!
//! The result is a map of the services an organization uses (Microsoft 365, Google Workspace,
//! Atlassian, DocuSign, Slack, HubSpot, Stripe, ...). All lookups go through [`DnsLookup`], so the
//! module is passive with respect to the target; matching itself is pure and table-driven.

use std::collections::BTreeSet;
use std::sync::{Arc, RwLock};

use regex::{Regex, RegexBuilder};
use serde::{Deserialize, Serialize};

use crate::dns::{norm_name, DnsLookup, RType};
use crate::mail::parse_spf;

/// What a service was recognized from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceKind {
    /// A TXT record of the domain (verification token).
    Txt,
    /// An `include:`/`redirect=` of the SPF record.
    SpfInclude,
    /// An MX host.
    Mx,
    /// A CNAME of a service-specific name (`autodiscover`, DKIM selectors).
    Cname,
}

/// A recognized service.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SaasHit {
    /// Stable service id (`microsoft365`, `google`, `atlassian`, ...).
    pub id: String,
    /// Display name (a proper noun, not localized).
    pub name: String,
    /// Category key: `email`, `productivity`, `collaboration`, `identity`, `dev`, `crm`,
    /// `marketing`, `payments`, `security`, `cloud`, `docs`, `support`, `analytics`, `ai`.
    pub category: String,
    pub evidence: EvidenceKind,
    /// The record that matched, verbatim.
    pub record: String,
}

/// TXT verification prefixes (case-insensitive `starts_with`): `(prefix, id, name, category)`.
const TXT_SIGNATURES: &[(&str, &str, &str, &str)] = &[
    ("ms=", "microsoft365", "Microsoft 365", "productivity"),
    (
        "google-site-verification=",
        "google",
        "Google",
        "productivity",
    ),
    (
        "atlassian-domain-verification=",
        "atlassian",
        "Atlassian",
        "collaboration",
    ),
    (
        "status-page-domain-verification=",
        "statuspage",
        "Atlassian Statuspage",
        "support",
    ),
    ("docusign=", "docusign", "DocuSign", "docs"),
    (
        "slack-domain-verification=",
        "slack",
        "Slack",
        "collaboration",
    ),
    (
        "hubspot-developer-verification=",
        "hubspot",
        "HubSpot",
        "marketing",
    ),
    (
        "hubspot-domain-verification=",
        "hubspot",
        "HubSpot",
        "marketing",
    ),
    ("stripe-verification=", "stripe", "Stripe", "payments"),
    (
        "apple-domain-verification=",
        "apple",
        "Apple Business",
        "productivity",
    ),
    (
        "facebook-domain-verification=",
        "meta",
        "Meta Business",
        "marketing",
    ),
    (
        "workplace-domain-verification=",
        "meta_workplace",
        "Meta Workplace",
        "collaboration",
    ),
    ("adobe-idp-site-verification=", "adobe", "Adobe", "identity"),
    (
        "adobe-sign-verification=",
        "adobe_sign",
        "Adobe Acrobat Sign",
        "docs",
    ),
    ("zoom-domain-verification", "zoom", "Zoom", "collaboration"),
    ("zoom_verify_", "zoom", "Zoom", "collaboration"),
    ("dropbox-domain-verification=", "dropbox", "Dropbox", "docs"),
    ("box-domain-verification=", "box", "Box", "docs"),
    ("citrix-verification-code=", "citrix", "Citrix", "identity"),
    (
        "cisco-ci-domain-verification=",
        "webex",
        "Cisco Webex",
        "collaboration",
    ),
    (
        "webexdomainverification.",
        "webex",
        "Cisco Webex",
        "collaboration",
    ),
    ("amazonses:", "aws_ses", "Amazon SES", "email"),
    ("yandex-verification:", "yandex", "Yandex", "productivity"),
    (
        "mailru-verification:",
        "mailru",
        "VK WorkSpace (Mail.ru)",
        "email",
    ),
    ("miro-verification=", "miro", "Miro", "collaboration"),
    (
        "notion-domain-verification=",
        "notion",
        "Notion",
        "collaboration",
    ),
    (
        "figma-domain-verification=",
        "figma",
        "Figma",
        "collaboration",
    ),
    (
        "airtable-verification=",
        "airtable",
        "Airtable",
        "collaboration",
    ),
    ("canva-site-verification=", "canva", "Canva", "marketing"),
    (
        "logmein-verification-code=",
        "goto",
        "GoTo (LogMeIn)",
        "collaboration",
    ),
    (
        "teamviewer-sso-verification=",
        "teamviewer",
        "TeamViewer",
        "identity",
    ),
    (
        "onetrust-domain-verification=",
        "onetrust",
        "OneTrust",
        "security",
    ),
    (
        "knowbe4-site-verification=",
        "knowbe4",
        "KnowBe4",
        "security",
    ),
    (
        "detectify-verification=",
        "detectify",
        "Detectify",
        "security",
    ),
    (
        "have-i-been-pwned-verification=",
        "hibp",
        "Have I Been Pwned",
        "security",
    ),
    (
        "mongodb-site-verification=",
        "mongodb",
        "MongoDB Atlas",
        "cloud",
    ),
    ("twilio-domain-verification=", "twilio", "Twilio", "dev"),
    ("postman-domain-verification=", "postman", "Postman", "dev"),
    ("gitlab-pages-verification-code=", "gitlab", "GitLab", "dev"),
    (
        "keybase-site-verification=",
        "keybase",
        "Keybase",
        "identity",
    ),
    ("sendinblue-code:", "brevo", "Brevo", "marketing"),
    ("brevo-code:", "brevo", "Brevo", "marketing"),
    (
        "mandrill_verify.",
        "mandrill",
        "Mailchimp Transactional",
        "email",
    ),
    ("protonmail-verification=", "proton", "Proton Mail", "email"),
    ("zoho-verification=", "zoho", "Zoho", "productivity"),
    (
        "globalsign-domain-verification=",
        "globalsign",
        "GlobalSign",
        "security",
    ),
    (
        "_globalsign-domain-verification=",
        "globalsign",
        "GlobalSign",
        "security",
    ),
    ("jamf-site-verification=", "jamf", "Jamf", "security"),
    (
        "smartsheet-site-validation=",
        "smartsheet",
        "Smartsheet",
        "collaboration",
    ),
    ("wrike-verification=", "wrike", "Wrike", "collaboration"),
    (
        "segment-site-verification=",
        "segment",
        "Segment",
        "analytics",
    ),
    ("ahrefs-site-verification_", "ahrefs", "Ahrefs", "analytics"),
    (
        "pinterest-site-verification=",
        "pinterest",
        "Pinterest",
        "marketing",
    ),
    ("openai-domain-verification=", "openai", "OpenAI", "ai"),
    ("loaderio=", "loaderio", "loader.io", "dev"),
    ("fastly-domain-delegation-", "fastly", "Fastly", "cloud"),
    (
        "pardot_",
        "salesforce_pardot",
        "Salesforce Pardot",
        "marketing",
    ),
];

/// SPF include suffixes: `(suffix, id, name, category)`.
const SPF_INCLUDES: &[(&str, &str, &str, &str)] = &[
    (
        "spf.protection.outlook.com",
        "microsoft365",
        "Microsoft 365",
        "productivity",
    ),
    ("_spf.google.com", "google", "Google", "productivity"),
    ("amazonses.com", "aws_ses", "Amazon SES", "email"),
    ("mailgun.org", "mailgun", "Mailgun", "email"),
    ("sendgrid.net", "sendgrid", "SendGrid", "email"),
    ("servers.mcsv.net", "mailchimp", "Mailchimp", "marketing"),
    (
        "spf.mandrillapp.com",
        "mandrill",
        "Mailchimp Transactional",
        "email",
    ),
    ("_spf.salesforce.com", "salesforce", "Salesforce", "crm"),
    (
        "exacttarget.com",
        "salesforce_mc",
        "Salesforce Marketing Cloud",
        "marketing",
    ),
    ("mktomail.com", "marketo", "Marketo", "marketing"),
    ("zendesk.com", "zendesk", "Zendesk", "support"),
    ("freshdesk.com", "freshdesk", "Freshdesk", "support"),
    ("helpscoutemail.com", "helpscout", "Help Scout", "support"),
    ("intercom.io", "intercom", "Intercom", "support"),
    ("hubspotemail.net", "hubspot", "HubSpot", "marketing"),
    ("spf.mtasv.net", "postmark", "Postmark", "email"),
    ("spf.sendinblue.com", "brevo", "Brevo", "marketing"),
    ("spf.brevo.com", "brevo", "Brevo", "marketing"),
    ("zoho.com", "zoho", "Zoho", "productivity"),
    ("zoho.eu", "zoho", "Zoho", "productivity"),
    ("spf.mailjet.com", "mailjet", "Mailjet", "email"),
    ("mimecast.com", "mimecast", "Mimecast", "security"),
    ("pphosted.com", "proofpoint", "Proofpoint", "security"),
    (
        "spf.messagelabs.com",
        "symantec_email",
        "Symantec Email Security",
        "security",
    ),
    (
        "_spf.atlassian.net",
        "atlassian",
        "Atlassian",
        "collaboration",
    ),
    ("_spf.yandex.net", "yandex", "Yandex", "productivity"),
    ("_spf.mail.ru", "mailru", "VK WorkSpace (Mail.ru)", "email"),
    ("_spf.protonmail.ch", "proton", "Proton Mail", "email"),
    ("spf.smtp2go.com", "smtp2go", "SMTP2GO", "email"),
    ("sparkpostmail.com", "sparkpost", "SparkPost", "email"),
    (
        "spf.constantcontact.com",
        "constantcontact",
        "Constant Contact",
        "marketing",
    ),
    ("spf.sendpulse.com", "sendpulse", "SendPulse", "marketing"),
    ("spf.unisender.com", "unisender", "UniSender", "marketing"),
    (
        "_spf.elasticemail.com",
        "elasticemail",
        "Elastic Email",
        "email",
    ),
    ("mlsend.com", "mailerlite", "MailerLite", "marketing"),
];

/// MX host suffixes: `(suffix, id, name, category)`.
const MX_HOSTS: &[(&str, &str, &str, &str)] = &[
    (
        "mail.protection.outlook.com",
        "microsoft365",
        "Microsoft 365",
        "productivity",
    ),
    ("aspmx.l.google.com", "google", "Google", "productivity"),
    ("googlemail.com", "google", "Google", "productivity"),
    ("smtp.google.com", "google", "Google", "productivity"),
    ("pphosted.com", "proofpoint", "Proofpoint", "security"),
    ("mimecast.com", "mimecast", "Mimecast", "security"),
    (
        "messagelabs.com",
        "symantec_email",
        "Symantec Email Security",
        "security",
    ),
    (
        "barracudanetworks.com",
        "barracuda",
        "Barracuda",
        "security",
    ),
    ("iphmx.com", "cisco_email", "Cisco Secure Email", "security"),
    (
        "trendmicro.com",
        "trendmicro",
        "Trend Micro Email Security",
        "security",
    ),
    (
        "trendmicro.eu",
        "trendmicro",
        "Trend Micro Email Security",
        "security",
    ),
    ("hydra.sophos.com", "sophos", "Sophos Email", "security"),
    (
        "fireeyecloud.com",
        "trellix",
        "Trellix Email Security",
        "security",
    ),
    ("mx.yandex.net", "yandex", "Yandex", "productivity"),
    ("mx.yandex.ru", "yandex", "Yandex", "productivity"),
    ("mxs.mail.ru", "mailru", "VK WorkSpace (Mail.ru)", "email"),
    ("protonmail.ch", "proton", "Proton Mail", "email"),
    ("zoho.com", "zoho", "Zoho", "productivity"),
    ("zoho.eu", "zoho", "Zoho", "productivity"),
    ("amazonaws.com", "aws_ses", "Amazon SES", "email"),
    ("mailgun.org", "mailgun", "Mailgun", "email"),
    ("icloud.com", "apple", "Apple iCloud Mail", "email"),
    ("secureserver.net", "godaddy", "GoDaddy Email", "email"),
    ("emailsrvr.com", "rackspace", "Rackspace Email", "email"),
    ("ovh.net", "ovh", "OVHcloud", "email"),
];

/// CNAME targets of service names: `(suffix, id, name, category)`.
const CNAME_TARGETS: &[(&str, &str, &str, &str)] = &[
    (
        "autodiscover.outlook.com",
        "microsoft365",
        "Microsoft 365",
        "productivity",
    ),
    (
        "onmicrosoft.com",
        "microsoft365",
        "Microsoft 365",
        "productivity",
    ),
    ("domainkey.google.com", "google", "Google", "productivity"),
    ("sendgrid.net", "sendgrid", "SendGrid", "email"),
    ("mailgun.org", "mailgun", "Mailgun", "email"),
    ("amazonses.com", "aws_ses", "Amazon SES", "email"),
    ("hubspotemail.net", "hubspot", "HubSpot", "marketing"),
    ("mcsv.net", "mailchimp", "Mailchimp", "marketing"),
    ("zendesk.com", "zendesk", "Zendesk", "support"),
];

fn suffix_match<'t>(
    table: &'t [(&'static str, &'static str, &'static str, &'static str)],
    host: &str,
) -> Option<&'t (&'static str, &'static str, &'static str, &'static str)> {
    let h = norm_name(host);
    table
        .iter()
        .find(|(s, ..)| h == *s || h.ends_with(&format!(".{s}")))
}

fn hit(
    row: &(&'static str, &'static str, &'static str, &'static str),
    evidence: EvidenceKind,
    record: &str,
) -> SaasHit {
    SaasHit {
        id: row.1.into(),
        name: row.2.into(),
        category: row.3.into(),
        evidence,
        record: record.to_string(),
    }
}

/// Recognizes services from TXT records of a domain: verification tokens plus the SPF record's
/// includes and redirect.
pub fn fingerprint_txt(records: &[String]) -> Vec<SaasHit> {
    let mut out = Vec::new();
    for r in records {
        let t = r.trim();
        let low = t.to_ascii_lowercase();
        if let Some(row) = TXT_SIGNATURES.iter().find(|(p, ..)| low.starts_with(p)) {
            out.push(hit(row, EvidenceKind::Txt, t));
            continue;
        }
        if let Some(spf) = parse_spf(t) {
            for inc in spf.includes.iter().chain(spf.redirect.iter()) {
                if let Some(row) = suffix_match(SPF_INCLUDES, inc) {
                    out.push(hit(row, EvidenceKind::SpfInclude, inc));
                }
            }
        }
    }
    out
}

/// Recognizes mail and mail-security providers from MX values (`10 host` or bare hosts).
pub fn fingerprint_mx(mx: &[String]) -> Vec<SaasHit> {
    mx.iter()
        .filter_map(|v| {
            let host = v.split_whitespace().last()?;
            suffix_match(MX_HOSTS, host).map(|row| hit(row, EvidenceKind::Mx, &norm_name(host)))
        })
        .collect()
}

/// Recognizes a service from a CNAME target of a service-specific name.
pub fn fingerprint_cname(target: &str) -> Option<SaasHit> {
    suffix_match(CNAME_TARGETS, target).map(|row| hit(row, EvidenceKind::Cname, &norm_name(target)))
}

/// Returns the vendor token of an unrecognized verification record (`acme-site-verification=…`
/// → `acme`), or `None` if the record does not look like a verification token.
pub fn unknown_verification(txt: &str) -> Option<String> {
    let low = txt.trim().to_ascii_lowercase();
    let key = low.split(['=', ':']).next()?;
    if key.len() == low.len() || key.len() > 64 || key.contains(' ') {
        return None;
    }
    for marker in [
        "-site-verification",
        "-domain-verification",
        "_site-verification",
        "-verification-code",
        "-verification",
        "_verification",
        "-site-validation",
        "-validation",
        "-challenge",
    ] {
        if let Some(v) = key.strip_suffix(marker) {
            let v = v.trim_matches(['_', '-', '.']);
            if !v.is_empty() {
                return Some(v.to_string());
            }
        }
    }
    None
}

/// webappanalyzer DNS rules (GPL-3.0, enthec), converted by
/// `foca-analysis/signatures/tools/update_webappanalyzer.py`: regexes over MX hosts, TXT records
/// and CNAME targets. They only add services the hand tables above do not know.
pub const UPSTREAM_DNS_JSON: &str = include_str!("../../data/saas_dns.json");

#[derive(Deserialize)]
struct UpstreamDnsFile {
    rules: Vec<UpstreamDnsDef>,
}

#[derive(Deserialize)]
struct UpstreamDnsDef {
    name: String,
    cat: String,
    dns: std::collections::BTreeMap<String, Vec<String>>,
}

struct DnsRule {
    name: String,
    cat: String,
    /// (record type, regex)
    res: Vec<(String, Regex)>,
}

fn parse_upstream_dns(json: &str) -> Result<Vec<DnsRule>, String> {
    let f: UpstreamDnsFile = serde_json::from_str(json).map_err(|e| e.to_string())?;
    Ok(f.rules
        .into_iter()
        .map(|d| DnsRule {
            res: d
                .dns
                .into_iter()
                .flat_map(|(t, ps)| ps.into_iter().map(move |p| (t.clone(), p)))
                .filter_map(|(t, p)| {
                    let re = RegexBuilder::new(&p)
                        .case_insensitive(true)
                        .size_limit(1 << 20)
                        .build()
                        .ok()?;
                    Some((t, re))
                })
                .collect(),
            name: d.name,
            cat: d.cat,
        })
        .collect())
}

fn upstream_slot() -> &'static RwLock<Option<Arc<Vec<DnsRule>>>> {
    static S: RwLock<Option<Arc<Vec<DnsRule>>>> = RwLock::new(None);
    &S
}

fn upstream_dns() -> Arc<Vec<DnsRule>> {
    if let Some(r) = upstream_slot().read().ok().and_then(|g| g.clone()) {
        return r;
    }
    let mut g = upstream_slot().write().unwrap_or_else(|e| e.into_inner());
    g.get_or_insert_with(|| Arc::new(parse_upstream_dns(UPSTREAM_DNS_JSON).unwrap_or_default()))
        .clone()
}

/// Replaces the upstream DNS rules (a signed signature bundle); returns the rule count.
pub fn install_upstream_dns(json: &str) -> Result<usize, String> {
    let rules = parse_upstream_dns(json)?;
    let n = rules.len();
    *upstream_slot().write().unwrap_or_else(|e| e.into_inner()) = Some(Arc::new(rules));
    Ok(n)
}

/// Parses upstream DNS rules without installing them; returns the rule count.
pub fn check_upstream_dns(json: &str) -> Result<usize, String> {
    parse_upstream_dns(json).map(|r| r.len())
}

/// Number of upstream DNS rules in use.
pub fn upstream_dns_count() -> usize {
    upstream_dns().len()
}

fn slug(name: &str) -> String {
    let s: String = name
        .to_ascii_lowercase()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect();
    s.trim_matches('_').to_string()
}

/// Services recognized by the upstream rules from TXT, MX and CNAME values.
pub fn fingerprint_upstream(txt: &[String], mx: &[String], cnames: &[String]) -> Vec<SaasHit> {
    let mut out = Vec::new();
    let rules = upstream_dns();
    let mx_hosts: Vec<String> = mx
        .iter()
        .filter_map(|v| v.split_whitespace().last().map(norm_name))
        .collect();
    let cn: Vec<String> = cnames.iter().map(|c| norm_name(c)).collect();
    for r in rules.iter() {
        let found = r.res.iter().find_map(|(t, re)| {
            let (vals, kind): (&[String], EvidenceKind) = match t.as_str() {
                "TXT" => (txt, EvidenceKind::Txt),
                "MX" => (&mx_hosts, EvidenceKind::Mx),
                "CNAME" => (&cn, EvidenceKind::Cname),
                _ => return None,
            };
            vals.iter()
                .find(|v| re.is_match(v.trim()))
                .map(|v| (kind, v.trim().to_string()))
        });
        if let Some((evidence, record)) = found {
            out.push(SaasHit {
                id: slug(&r.name),
                name: r.name.clone(),
                category: r.cat.clone(),
                evidence,
                record,
            });
        }
    }
    out
}

/// Map of the SaaS/cloud services of a domain.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SaasMap {
    pub domain: String,
    /// One entry per (service, evidence kind, record), in discovery order.
    pub hits: Vec<SaasHit>,
    /// Vendor tokens of verification records not in the table (`acme`).
    pub unknown: Vec<String>,
}

impl SaasMap {
    /// Distinct service ids.
    pub fn services(&self) -> BTreeSet<&str> {
        self.hits.iter().map(|h| h.id.as_str()).collect()
    }

    fn push(&mut self, h: SaasHit) {
        if !self
            .hits
            .iter()
            .any(|x| x.id == h.id && x.evidence == h.evidence && x.record == h.record)
        {
            self.hits.push(h);
        }
    }
}

/// Builds the map from already fetched records. A pure function.
pub fn analyze_saas(
    domain: &str,
    txt: &[String],
    mx: &[String],
    cnames: &[String],
    amazonses_txt: &[String],
) -> SaasMap {
    let mut m = SaasMap {
        domain: norm_name(domain),
        ..Default::default()
    };
    for h in fingerprint_txt(txt) {
        m.push(h);
    }
    for h in fingerprint_mx(mx) {
        m.push(h);
    }
    for h in cnames.iter().filter_map(|c| fingerprint_cname(c)) {
        m.push(h);
    }
    // Upstream rules only add services the hand tables did not recognize.
    for h in fingerprint_upstream(txt, mx, cnames) {
        let same = |x: &SaasHit| {
            x.name.eq_ignore_ascii_case(&h.name) || x.id == h.id || x.record == h.record
        };
        if !m.hits.iter().any(same) {
            m.push(h);
        }
    }
    if let Some(t) = amazonses_txt.iter().find(|t| !t.trim().is_empty()) {
        m.push(SaasHit {
            id: "aws_ses".into(),
            name: "Amazon SES".into(),
            category: "email".into(),
            evidence: EvidenceKind::Txt,
            record: format!("_amazonses: {}", t.trim()),
        });
    }
    let known: BTreeSet<&str> = TXT_SIGNATURES.iter().map(|r| r.0).collect();
    for t in txt {
        let low = t.trim().to_ascii_lowercase();
        if known.iter().any(|p| low.starts_with(p)) {
            continue;
        }
        if let Some(v) = unknown_verification(t) {
            if !m.unknown.contains(&v) {
                m.unknown.push(v);
            }
        }
    }
    m
}

/// Names whose CNAME reveals a service.
const CNAME_PROBES: &[&str] = &[
    "autodiscover",
    "selector1._domainkey",
    "selector2._domainkey",
    "google._domainkey",
    "s1._domainkey",
    "k1._domainkey",
    "em",
];

/// Fetches TXT, MX, `_amazonses` TXT and a few service CNAMEs, then builds the map. DNS only.
pub async fn saas_map(dns: &dyn DnsLookup, domain: &str) -> SaasMap {
    let d = norm_name(domain);
    let get = |name: String, t: RType| async move {
        dns.lookup(&name, t)
            .await
            .map(|a| a.values(t))
            .unwrap_or_default()
    };
    let txt = get(d.clone(), RType::TXT).await;
    let mx = get(d.clone(), RType::MX).await;
    let ses = get(format!("_amazonses.{d}"), RType::TXT).await;
    let mut cnames = Vec::new();
    for p in CNAME_PROBES {
        cnames.extend(get(format!("{p}.{d}"), RType::CNAME).await);
    }
    analyze_saas(&d, &txt, &mx, &cnames, &ses)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upstream_dns_rules_add_unknown_services_only() {
        assert!(upstream_dns_count() > 100, "{}", upstream_dns_count());
        // DanDomain MX is not in the hand table: the upstream rules recognize it.
        let m = analyze_saas(
            "contoso.ua",
            &[],
            &[
                "10 mx1.dandomain.dk.".to_string(),
                "10 aspmx.l.google.com.".to_string(),
            ],
            &[],
            &[],
        );
        assert!(
            m.hits
                .iter()
                .any(|h| h.name == "DanDomain email" && h.evidence == EvidenceKind::Mx),
            "{m:?}"
        );
        // A record the hand table matched is not reported twice under an upstream name.
        let google = m
            .hits
            .iter()
            .filter(|h| h.record == "aspmx.l.google.com")
            .count();
        assert_eq!(google, 1, "{m:?}");
    }
    use crate::dns::StaticDns;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn txt_tokens_and_spf() {
        let h = fingerprint_txt(&s(&[
            "MS=ms12345678",
            "google-site-verification=abc",
            "atlassian-domain-verification=xyz",
            "docusign=1b2c",
            "slack-domain-verification=q",
            "hubspot-developer-verification=w",
            "stripe-verification=e",
            "v=spf1 include:spf.protection.outlook.com include:_spf.google.com include:mail.zendesk.com redirect=_spf.salesforce.com ~all",
            "unrelated text",
        ]));
        let ids: Vec<_> = h.iter().map(|x| (x.id.as_str(), x.evidence)).collect();
        assert_eq!(
            ids,
            vec![
                ("microsoft365", EvidenceKind::Txt),
                ("google", EvidenceKind::Txt),
                ("atlassian", EvidenceKind::Txt),
                ("docusign", EvidenceKind::Txt),
                ("slack", EvidenceKind::Txt),
                ("hubspot", EvidenceKind::Txt),
                ("stripe", EvidenceKind::Txt),
                ("microsoft365", EvidenceKind::SpfInclude),
                ("google", EvidenceKind::SpfInclude),
                ("zendesk", EvidenceKind::SpfInclude),
                ("salesforce", EvidenceKind::SpfInclude),
            ]
        );
        assert_eq!(h[0].record, "MS=ms12345678");
        assert_eq!(h[9].record, "mail.zendesk.com");
    }

    #[test]
    fn mx_and_cname() {
        let h = fingerprint_mx(&s(&[
            "0 contoso-com.mail.protection.outlook.com.",
            "10 mx.evil.test",
        ]));
        assert_eq!(h.len(), 1);
        assert_eq!(h[0].id, "microsoft365");
        assert_eq!(h[0].record, "contoso-com.mail.protection.outlook.com");
        assert_eq!(
            fingerprint_cname("selector1-contoso-com._domainkey.contoso.onmicrosoft.com")
                .unwrap()
                .id,
            "microsoft365"
        );
        assert!(fingerprint_cname("www.example.com").is_none());
        // suffix match is label-aligned
        assert!(fingerprint_mx(&s(&["10 notpphosted.com"])).is_empty());
    }

    #[test]
    fn unknown_tokens() {
        assert_eq!(
            unknown_verification("acme-site-verification=1").as_deref(),
            Some("acme")
        );
        assert_eq!(
            unknown_verification("foo-domain-verification:abc").as_deref(),
            Some("foo")
        );
        assert_eq!(
            unknown_verification("bar_verification=1").as_deref(),
            Some("bar")
        );
        assert!(unknown_verification("v=spf1 -all").is_none());
        assert!(unknown_verification("hello world").is_none());
        assert!(unknown_verification("-verification=1").is_none());
    }

    #[tokio::test]
    async fn map_from_dns() {
        let z = StaticDns::new()
            .add(
                "ex.com",
                RType::TXT,
                &[
                    "MS=ms1",
                    "acme-site-verification=z",
                    "v=spf1 include:sendgrid.net -all",
                ],
            )
            .add(
                "ex.com",
                RType::MX,
                &["10 ex-com.mail.protection.outlook.com"],
            )
            .add("_amazonses.ex.com", RType::TXT, &["tok"])
            .add(
                "autodiscover.ex.com",
                RType::CNAME,
                &["autodiscover.outlook.com"],
            );
        let m = saas_map(&z, "Ex.com.").await;
        assert_eq!(m.domain, "ex.com");
        let svc: Vec<_> = m.services().into_iter().collect();
        assert_eq!(svc, vec!["aws_ses", "microsoft365", "sendgrid"]);
        assert_eq!(m.unknown, vec!["acme"]);
        // TXT, MX and CNAME evidence for Microsoft 365 are kept separately
        assert_eq!(m.hits.iter().filter(|h| h.id == "microsoft365").count(), 3);
    }
}
