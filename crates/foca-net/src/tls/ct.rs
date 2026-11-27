//! Certificate Transparency: crt.sh JSON and the CertSpotter API. Passive.
//!
//! * Subdomains ([`crtsh_subdomains`], [`certspotter_subdomains`]).
//! * Full issuance metadata ([`CtCert`]: issuer, validity, serial, fingerprints, subject O when
//!   the DER is available), the per-host certificate timeline with CA changes
//!   ([`cert_timeline`]), abandoned subdomains whose certificates stopped being renewed
//!   ([`abandoned_hosts`]), and the organization pivot ([`crtsh_org_pivot`]): sibling domains
//!   from certificates issued to the same `O=`, returned as out-of-scope candidates that are
//!   never contacted.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::client::{Access, NetClient, NetRequest};
use crate::dns::norm_name;
use crate::NetError;

/// Base URLs (tests point them at a local server).
#[derive(Debug, Clone)]
pub struct CtEndpoints {
    pub crtsh: String,
    pub certspotter: String,
}

impl Default for CtEndpoints {
    fn default() -> Self {
        CtEndpoints {
            crtsh: "https://crt.sh".into(),
            certspotter: "https://api.certspotter.com".into(),
        }
    }
}

fn accept(name: &str, domain: &str, out: &mut BTreeSet<String>) {
    let n = norm_name(name);
    let n = n.trim_start_matches("*.").to_string();
    if n.is_empty() || n.contains(char::is_whitespace) || n.contains('@') {
        return;
    }
    if n == domain || foca_core::target::is_subdomain_of(&n, domain) {
        out.insert(n);
    }
}

#[derive(Deserialize)]
struct CrtRow {
    #[serde(default)]
    name_value: String,
    #[serde(default)]
    common_name: Option<String>,
}

/// Parses a `crt.sh/?q=%.domain&output=json` response.
pub fn parse_crtsh(json: &str, domain: &str) -> Result<Vec<String>, NetError> {
    let d = norm_name(domain);
    let rows: Vec<CrtRow> =
        serde_json::from_str(json).map_err(|e| NetError::Parse(e.to_string()))?;
    let mut out = BTreeSet::new();
    for r in rows {
        for n in r.name_value.split('\n') {
            accept(n, &d, &mut out);
        }
        if let Some(c) = r.common_name {
            accept(&c, &d, &mut out);
        }
    }
    Ok(out.into_iter().collect())
}

#[derive(Deserialize)]
struct SpotRow {
    #[serde(default)]
    id: String,
    #[serde(default)]
    dns_names: Vec<String>,
}

/// Parses a CertSpotter `/v1/issuances?...&expand=dns_names` response; the second element is the id
/// of the last issuance (for `after=` pagination).
pub fn parse_certspotter(
    json: &str,
    domain: &str,
) -> Result<(Vec<String>, Option<String>), NetError> {
    let d = norm_name(domain);
    let rows: Vec<SpotRow> =
        serde_json::from_str(json).map_err(|e| NetError::Parse(e.to_string()))?;
    let mut out = BTreeSet::new();
    let last = rows.last().map(|r| r.id.clone()).filter(|s| !s.is_empty());
    for r in rows {
        for n in r.dns_names {
            accept(&n, &d, &mut out);
        }
    }
    Ok((out.into_iter().collect(), last))
}

/// Fetches subdomains from crt.sh.
pub async fn crtsh_subdomains(
    net: &NetClient,
    ep: &CtEndpoints,
    domain: &str,
) -> Result<Vec<String>, NetError> {
    let d = norm_name(domain);
    let mut u = url::Url::parse(&format!("{}/", ep.crtsh.trim_end_matches('/')))
        .map_err(|e| NetError::BadUrl(e.to_string()))?;
    u.query_pairs_mut()
        .append_pair("q", &format!("%.{d}"))
        .append_pair("output", "json");
    let req = NetRequest::get(u.as_str(), "crt", Access::Passive)?
        .timeout(std::time::Duration::from_secs(90))
        .retries(1);
    let r = net.send(req).await?.ensure_success()?;
    let body = r.text_limited(net.config().max_body).await?;
    parse_crtsh(&body, &d)
}

/// Fetches subdomains from CertSpotter (keyless, within free tier limits), up to `max_pages` pages.
pub async fn certspotter_subdomains(
    net: &NetClient,
    ep: &CtEndpoints,
    domain: &str,
    key: Option<&str>,
    max_pages: usize,
) -> Result<Vec<String>, NetError> {
    let d = norm_name(domain);
    let mut all = BTreeSet::new();
    let mut after: Option<String> = None;
    for _ in 0..max_pages.max(1) {
        let mut u = url::Url::parse(&format!(
            "{}/v1/issuances",
            ep.certspotter.trim_end_matches('/')
        ))
        .map_err(|e| NetError::BadUrl(e.to_string()))?;
        u.query_pairs_mut()
            .append_pair("domain", &d)
            .append_pair("include_subdomains", "true")
            .append_pair("expand", "dns_names");
        if let Some(a) = &after {
            u.query_pairs_mut().append_pair("after", a);
        }
        let mut req = NetRequest::get(u.as_str(), "certspotter", Access::Passive)?;
        if let Some(k) = key {
            req = req.header("Authorization", &format!("Bearer {k}"));
        }
        let r = net.send(req).await?.ensure_success()?;
        let body = r.text_limited(net.config().max_body).await?;
        let (names, last) = parse_certspotter(&body, &d)?;
        let before = all.len();
        all.extend(names);
        match last {
            Some(l) if all.len() > before || after.is_none() => after = Some(l),
            _ => break,
        }
    }
    Ok(all.into_iter().collect())
}

// ---------- full issuance metadata, timeline, abandoned hosts, organization pivot ----------

const DAY: i64 = 86_400;

/// One CT issuance with the metadata the sources expose.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CtCert {
    /// `crtsh` or `certspotter`.
    pub source: String,
    /// Source-specific id (crt.sh certificate id, CertSpotter issuance id).
    pub id: String,
    /// DNS names (SAN + CN), lowercase, wildcards kept as `*.name`.
    pub names: Vec<String>,
    pub common_name: Option<String>,
    /// Issuer DN as text (`C=US, O=Let's Encrypt, CN=R3`).
    pub issuer: Option<String>,
    /// Issuer organization (or the CA friendly name).
    pub issuer_org: Option<String>,
    /// Validity, Unix seconds.
    pub not_before: Option<i64>,
    pub not_after: Option<i64>,
    pub serial: Option<String>,
    /// Subject organization (`O=`), when the certificate DER was available.
    pub org: Option<String>,
    pub cert_sha256: Option<String>,
    pub spki_sha256: Option<String>,
    pub revoked: Option<bool>,
}

/// Parses `YYYY-MM-DDTHH:MM:SS[.fff][Z]` (crt.sh omits the zone; both sources are UTC).
pub fn parse_ct_time(s: &str) -> Option<i64> {
    let fmt = time::macros::format_description!("[year]-[month]-[day]T[hour]:[minute]:[second]");
    let t = time::PrimitiveDateTime::parse(s.get(..19)?, &fmt).ok()?;
    Some(t.assume_utc().unix_timestamp())
}

/// Value of the `O=` attribute in an RFC 4514-ish DN string.
fn dn_attr(dn: &str, key: &str) -> Option<String> {
    dn.split(',').find_map(|p| {
        let (k, v) = p.split_once('=')?;
        k.trim()
            .eq_ignore_ascii_case(key)
            .then(|| v.trim().trim_matches('"').to_string())
            .filter(|v| !v.is_empty())
    })
}

fn clean_name(n: &str) -> Option<String> {
    let n = norm_name(n);
    if n.is_empty() || n.contains(char::is_whitespace) || n.contains('@') || !n.contains('.') {
        return None;
    }
    Some(n)
}

#[derive(Deserialize)]
struct CrtFullRow {
    #[serde(default)]
    id: Option<serde_json::Value>,
    #[serde(default)]
    issuer_ca_id: Option<serde_json::Value>,
    #[serde(default)]
    issuer_name: Option<String>,
    #[serde(default)]
    common_name: Option<String>,
    #[serde(default)]
    name_value: String,
    #[serde(default)]
    not_before: Option<String>,
    #[serde(default)]
    not_after: Option<String>,
    #[serde(default)]
    serial_number: Option<String>,
}

fn json_id(v: &Option<serde_json::Value>) -> String {
    match v {
        Some(serde_json::Value::String(s)) => s.clone(),
        Some(serde_json::Value::Number(n)) => n.to_string(),
        _ => String::new(),
    }
}

/// Parses a crt.sh JSON response into issuances. A precertificate and its final certificate
/// share issuer and serial and are merged into one entry.
pub fn parse_crtsh_certs(json: &str) -> Result<Vec<CtCert>, NetError> {
    let rows: Vec<CrtFullRow> =
        serde_json::from_str(json).map_err(|e| NetError::Parse(e.to_string()))?;
    let mut seen = std::collections::HashMap::<(String, String), usize>::new();
    let mut out: Vec<CtCert> = Vec::new();
    for r in rows {
        let mut names: Vec<String> = Vec::new();
        for n in r.name_value.split('\n').chain(r.common_name.as_deref()) {
            if let Some(n) = clean_name(n) {
                if !names.contains(&n) {
                    names.push(n);
                }
            }
        }
        let serial = r.serial_number.clone().filter(|s| !s.is_empty());
        let issuer_key = {
            let id = json_id(&r.issuer_ca_id);
            if id.is_empty() {
                r.issuer_name.clone().unwrap_or_default()
            } else {
                id
            }
        };
        if let Some(sn) = &serial {
            if let Some(&i) = seen.get(&(issuer_key.clone(), sn.clone())) {
                for n in names {
                    if !out[i].names.contains(&n) {
                        out[i].names.push(n);
                    }
                }
                continue;
            }
            seen.insert((issuer_key, sn.clone()), out.len());
        }
        out.push(CtCert {
            source: "crtsh".into(),
            id: json_id(&r.id),
            names,
            common_name: r.common_name.as_deref().and_then(clean_name),
            issuer_org: r.issuer_name.as_deref().and_then(|d| dn_attr(d, "O")),
            issuer: r.issuer_name,
            not_before: r.not_before.as_deref().and_then(parse_ct_time),
            not_after: r.not_after.as_deref().and_then(parse_ct_time),
            serial,
            org: None,
            cert_sha256: None,
            spki_sha256: None,
            revoked: None,
        });
    }
    Ok(out)
}

#[derive(Deserialize)]
struct SpotIssuer {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    friendly_name: Option<String>,
}

#[derive(Deserialize)]
struct SpotFullRow {
    #[serde(default)]
    id: String,
    #[serde(default)]
    dns_names: Vec<String>,
    #[serde(default)]
    not_before: Option<String>,
    #[serde(default)]
    not_after: Option<String>,
    #[serde(default)]
    cert_sha256: Option<String>,
    #[serde(default)]
    pubkey_sha256: Option<String>,
    #[serde(default)]
    revoked: Option<bool>,
    #[serde(default)]
    issuer: Option<SpotIssuer>,
    #[serde(default)]
    cert_der: Option<String>,
}

/// Standard base64 decoder (CertSpotter `cert_der`).
fn base64_decode(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let mut acc = 0u32;
    let mut bits = 0;
    for c in s.bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' | b'-' => 62,
            b'/' | b'_' => 63,
            b'=' | b'\n' | b'\r' => continue,
            _ => return None,
        } as u32;
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    Some(out)
}

/// Parses a CertSpotter `/v1/issuances` response requested with `expand=dns_names`,
/// `expand=issuer` and optionally `expand=cert_der` (then serial and subject O come from the
/// DER). The second element is the last id for `after=` pagination.
pub fn parse_certspotter_certs(json: &str) -> Result<(Vec<CtCert>, Option<String>), NetError> {
    let rows: Vec<SpotFullRow> =
        serde_json::from_str(json).map_err(|e| NetError::Parse(e.to_string()))?;
    let last = rows.last().map(|r| r.id.clone()).filter(|s| !s.is_empty());
    let out = rows
        .into_iter()
        .map(|r| {
            let der = r.cert_der.as_deref().and_then(base64_decode);
            let parsed = der
                .as_deref()
                .and_then(|d| crate::tls::x509::parse_cert(d).ok());
            let mut names: Vec<String> = Vec::new();
            for n in &r.dns_names {
                if let Some(n) = clean_name(n) {
                    if !names.contains(&n) {
                        names.push(n);
                    }
                }
            }
            let issuer = r.issuer.as_ref().and_then(|i| i.name.clone());
            CtCert {
                source: "certspotter".into(),
                id: r.id,
                names,
                common_name: parsed.as_ref().and_then(|p| p.subject.cn.clone()),
                issuer_org: r
                    .issuer
                    .as_ref()
                    .and_then(|i| i.friendly_name.clone())
                    .or_else(|| issuer.as_deref().and_then(|d| dn_attr(d, "O"))),
                issuer,
                not_before: r.not_before.as_deref().and_then(parse_ct_time),
                not_after: r.not_after.as_deref().and_then(parse_ct_time),
                serial: parsed.as_ref().map(|p| p.serial.clone()),
                org: parsed.as_ref().and_then(|p| p.subject.o.clone()),
                cert_sha256: r.cert_sha256,
                spki_sha256: r.pubkey_sha256,
                revoked: r.revoked,
            }
        })
        .collect();
    Ok((out, last))
}

/// Fetches full issuance metadata from crt.sh (`q=%.domain`).
pub async fn crtsh_certs(
    net: &NetClient,
    ep: &CtEndpoints,
    domain: &str,
) -> Result<Vec<CtCert>, NetError> {
    let d = norm_name(domain);
    let mut u = url::Url::parse(&format!("{}/", ep.crtsh.trim_end_matches('/')))
        .map_err(|e| NetError::BadUrl(e.to_string()))?;
    u.query_pairs_mut()
        .append_pair("q", &format!("%.{d}"))
        .append_pair("output", "json");
    let req = NetRequest::get(u.as_str(), "crt", Access::Passive)?
        .timeout(std::time::Duration::from_secs(90))
        .retries(1);
    let r = net.send(req).await?.ensure_success()?;
    let body = r.text_limited(net.config().max_body).await?;
    let mut v = parse_crtsh_certs(&body)?;
    v.retain(|c| c.names.iter().any(|n| in_domain(n, &d)));
    Ok(v)
}

/// Fetches full issuance metadata from CertSpotter, up to `max_pages` pages. `with_der` adds
/// `expand=cert_der` (subject O and serial; responses get several times larger).
pub async fn certspotter_certs(
    net: &NetClient,
    ep: &CtEndpoints,
    domain: &str,
    key: Option<&str>,
    max_pages: usize,
    with_der: bool,
) -> Result<Vec<CtCert>, NetError> {
    let d = norm_name(domain);
    let mut all: Vec<CtCert> = Vec::new();
    let mut after: Option<String> = None;
    for _ in 0..max_pages.max(1) {
        let mut u = url::Url::parse(&format!(
            "{}/v1/issuances",
            ep.certspotter.trim_end_matches('/')
        ))
        .map_err(|e| NetError::BadUrl(e.to_string()))?;
        u.query_pairs_mut()
            .append_pair("domain", &d)
            .append_pair("include_subdomains", "true")
            .append_pair("expand", "dns_names")
            .append_pair("expand", "issuer");
        if with_der {
            u.query_pairs_mut().append_pair("expand", "cert_der");
        }
        if let Some(a) = &after {
            u.query_pairs_mut().append_pair("after", a);
        }
        let mut req = NetRequest::get(u.as_str(), "certspotter", Access::Passive)?;
        if let Some(k) = key {
            req = req.header("Authorization", &format!("Bearer {k}"));
        }
        let r = net.send(req).await?.ensure_success()?;
        let body = r.text_limited(net.config().max_body).await?;
        let (certs, last) = parse_certspotter_certs(&body)?;
        if certs.is_empty() {
            break;
        }
        all.extend(certs);
        match last {
            Some(l) if after.as_deref() != Some(l.as_str()) => after = Some(l),
            _ => break,
        }
    }
    Ok(all)
}

fn in_domain(name: &str, domain: &str) -> bool {
    let n = name.trim_start_matches("*.");
    n == domain || foca_core::target::is_subdomain_of(n, domain)
}

/// A CA period in a host timeline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IssuerSpan {
    pub issuer: String,
    /// First `not_before` and last `not_after` of the CA's certificates for the host.
    pub from: i64,
    pub to: i64,
    pub certs: usize,
}

/// Certificate history of one name.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostTimeline {
    /// Host name; wildcard entries keep the `*.` prefix.
    pub host: String,
    /// Earliest `not_before`: when the host first appeared in CT.
    pub first_seen: i64,
    /// Latest `not_after`.
    pub last_expiry: i64,
    pub cert_count: usize,
    /// CA periods in chronological order; consecutive certificates from the same CA merge.
    pub issuers: Vec<IssuerSpan>,
    /// Number of CA switches.
    pub ca_changes: usize,
}

/// Builds per-host timelines for `domain` and its subdomains (certificates without validity
/// dates are skipped). Sorted by host.
pub fn cert_timeline(certs: &[CtCert], domain: &str) -> Vec<HostTimeline> {
    let d = norm_name(domain);
    let mut by_host: std::collections::BTreeMap<String, Vec<&CtCert>> = Default::default();
    for c in certs {
        if c.not_before.is_none() || c.not_after.is_none() {
            continue;
        }
        for n in &c.names {
            if in_domain(n, &d) {
                by_host.entry(n.clone()).or_default().push(c);
            }
        }
    }
    by_host
        .into_iter()
        .map(|(host, mut v)| {
            v.sort_by_key(|c| (c.not_before, c.not_after));
            let mut issuers: Vec<IssuerSpan> = Vec::new();
            for c in &v {
                let (nb, na) = (c.not_before.unwrap_or(0), c.not_after.unwrap_or(0));
                let name = c
                    .issuer_org
                    .clone()
                    .or_else(|| c.issuer.clone())
                    .unwrap_or_else(|| "unknown".into());
                match issuers.last_mut() {
                    Some(s) if s.issuer == name => {
                        s.to = s.to.max(na);
                        s.certs += 1;
                    }
                    _ => issuers.push(IssuerSpan {
                        issuer: name,
                        from: nb,
                        to: na,
                        certs: 1,
                    }),
                }
            }
            HostTimeline {
                first_seen: v.iter().filter_map(|c| c.not_before).min().unwrap_or(0),
                last_expiry: v.iter().filter_map(|c| c.not_after).max().unwrap_or(0),
                cert_count: v.len(),
                ca_changes: issuers.len().saturating_sub(1),
                issuers,
                host,
            }
        })
        .collect()
}

/// A subdomain whose certificates stopped being renewed while the zone is still alive.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AbandonedHost {
    pub host: String,
    pub last_expiry: i64,
    pub days_since_expiry: i64,
    pub last_issuer: Option<String>,
    pub cert_count: usize,
}

/// Hosts whose last certificate expired more than `grace_days` before `now`, in a zone that
/// still has valid certificates, and not covered by a valid wildcard. These are takeover
/// candidates (check the DNS: a dangling CNAME to a deprovisioned service is the classic case).
/// Most recently abandoned first.
pub fn abandoned_hosts(timeline: &[HostTimeline], now: i64, grace_days: i64) -> Vec<AbandonedHost> {
    if !timeline.iter().any(|t| t.last_expiry >= now) {
        return Vec::new();
    }
    let fresh_wild: Vec<&str> = timeline
        .iter()
        .filter(|t| t.last_expiry >= now)
        .filter_map(|t| t.host.strip_prefix("*."))
        .collect();
    let mut v: Vec<AbandonedHost> = timeline
        .iter()
        .filter(|t| !t.host.starts_with("*."))
        .filter(|t| t.last_expiry < now - grace_days * DAY)
        .filter(|t| {
            let parent = t.host.split_once('.').map(|(_, p)| p).unwrap_or("");
            !fresh_wild.contains(&parent)
        })
        .map(|t| AbandonedHost {
            host: t.host.clone(),
            last_expiry: t.last_expiry,
            days_since_expiry: (now - t.last_expiry) / DAY,
            last_issuer: t.issuers.last().map(|s| s.issuer.clone()),
            cert_count: t.cert_count,
        })
        .collect();
    v.sort_by(|a, b| b.last_expiry.cmp(&a.last_expiry).then(a.host.cmp(&b.host)));
    v
}

/// A sibling domain found through certificates issued to the same organization. Always out of
/// scope: shown to the user as a candidate, never contacted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrgPivotCandidate {
    /// Approximate registrable domain (see [`registrable_domain`]).
    pub domain: String,
    /// Names seen under it (capped at 50).
    pub names: Vec<String>,
    pub cert_count: usize,
    pub first_seen: Option<i64>,
    pub last_seen: Option<i64>,
}

/// Second-level labels that act as public suffixes under a two-letter ccTLD (`com.ua`,
/// `co.uk`, ...).
const CC_SECOND_LEVEL: &[&str] = &[
    "com", "net", "org", "gov", "edu", "co", "ac", "or", "ne", "go", "mil", "in", "kiev", "kyiv",
    "biz", "info", "ltd", "plc", "nic", "gob", "gv",
];

/// Registrable domain by the Public Suffix List ([`crate::dns::psl`]). A name the list cannot
/// split (a bare public suffix) falls back to the old approximation: the last two labels, or
/// three under a ccTLD with a generic second level (`a.com.ua`, `b.co.uk`).
pub fn registrable_domain(name: &str) -> String {
    if let Some(r) = crate::dns::psl::registrable_domain(name) {
        return r;
    }
    let n = name.trim_start_matches("*.");
    let labels: Vec<&str> = n.split('.').collect();
    if labels.len() >= 3 {
        let tld = labels[labels.len() - 1];
        let sld = labels[labels.len() - 2];
        if tld.len() == 2 && CC_SECOND_LEVEL.contains(&sld) {
            return labels[labels.len() - 3..].join(".");
        }
    }
    labels[labels.len().saturating_sub(2)..].join(".")
}

/// Groups the names of an `O=` crt.sh search into sibling domain candidates, dropping every
/// name (or registrable domain) that `in_scope` accepts.
pub fn org_pivot_candidates(
    certs: &[CtCert],
    in_scope: impl Fn(&str) -> bool,
) -> Vec<OrgPivotCandidate> {
    let mut map: std::collections::BTreeMap<String, OrgPivotCandidate> = Default::default();
    for c in certs {
        let mut domains_here = BTreeSet::new();
        for n in &c.names {
            let host = n.trim_start_matches("*.");
            let reg = registrable_domain(host);
            if in_scope(host) || in_scope(&reg) {
                continue;
            }
            let e = map.entry(reg.clone()).or_insert_with(|| OrgPivotCandidate {
                domain: reg.clone(),
                names: Vec::new(),
                cert_count: 0,
                first_seen: None,
                last_seen: None,
            });
            if e.names.len() < 50 && !e.names.iter().any(|x| x == host) {
                e.names.push(host.to_string());
            }
            if domains_here.insert(reg) {
                e.cert_count += 1;
                e.first_seen = match (e.first_seen, c.not_before) {
                    (Some(a), Some(b)) => Some(a.min(b)),
                    (a, b) => a.or(b),
                };
                e.last_seen = match (e.last_seen, c.not_after) {
                    (Some(a), Some(b)) => Some(a.max(b)),
                    (a, b) => a.or(b),
                };
            }
        }
    }
    let mut v: Vec<OrgPivotCandidate> = map.into_values().collect();
    for c in &mut v {
        c.names.sort();
    }
    v.sort_by(|a, b| {
        b.cert_count
            .cmp(&a.cert_count)
            .then(a.domain.cmp(&b.domain))
    });
    v
}

/// Organization pivot: crt.sh certificates whose subject `O=` equals `org`, grouped into
/// sibling domains outside the scope. Only crt.sh is contacted (`Passive`); the candidates are
/// returned for the user to review and are never requested.
pub async fn crtsh_org_pivot(
    net: &NetClient,
    ep: &CtEndpoints,
    org: &str,
) -> Result<Vec<OrgPivotCandidate>, NetError> {
    let org = org.trim();
    if org.is_empty() {
        return Err(NetError::BadUrl("empty organization".into()));
    }
    let mut u = url::Url::parse(&format!("{}/", ep.crtsh.trim_end_matches('/')))
        .map_err(|e| NetError::BadUrl(e.to_string()))?;
    u.query_pairs_mut()
        .append_pair("O", org)
        .append_pair("output", "json");
    let req = NetRequest::get(u.as_str(), "crt-org", Access::Passive)?
        .timeout(std::time::Duration::from_secs(90))
        .retries(1);
    let r = net.send(req).await?.ensure_success()?;
    let body = r.text_limited(net.config().max_body).await?;
    let certs = parse_crtsh_certs(&body)?;
    Ok(org_pivot_candidates(&certs, |h| net.host_in_scope(h)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crtsh() {
        let j = r#"[{"name_value":"*.a.ua\nwww.a.ua","common_name":"a.ua"},{"name_value":"evil-a.ua\nmail.A.UA."},{"name_value":"x@a.ua"}]"#;
        assert_eq!(
            parse_crtsh(j, "a.ua").unwrap(),
            vec!["a.ua", "mail.a.ua", "www.a.ua"]
        );
        assert!(parse_crtsh("<html>", "a.ua").is_err());
    }

    #[test]
    fn certspotter() {
        let j = r#"[{"id":"1","dns_names":["a.ua","*.b.a.ua"]},{"id":"9","dns_names":["c.org"]}]"#;
        let (v, last) = parse_certspotter(j, "a.ua").unwrap();
        assert_eq!(v, vec!["a.ua", "b.a.ua"]);
        assert_eq!(last.as_deref(), Some("9"));
    }
    #[test]
    fn ct_time_and_base64() {
        assert_eq!(parse_ct_time("2026-09-30T23:29:20"), Some(1790810960));
        assert_eq!(parse_ct_time("2025-11-20T00:00:00Z"), Some(1763596800));
        assert_eq!(parse_ct_time("2025-11-20"), None);
        assert_eq!(base64_decode("TWFu").unwrap(), b"Man");
        assert_eq!(base64_decode("TWE=").unwrap(), b"Ma");
        assert!(base64_decode("T!").is_none());
    }

    #[test]
    fn registrable() {
        assert_eq!(registrable_domain("a.b.example.com"), "example.com");
        assert_eq!(
            registrable_domain("*.shop.example.com.ua"),
            "example.com.ua"
        );
        assert_eq!(registrable_domain("x.co.uk"), "x.co.uk");
        assert_eq!(registrable_domain("example.de"), "example.de");
    }

    #[test]
    fn crtsh_full_merges_precert() {
        let j = r#"[
          {"id":1,"issuer_ca_id":7,"issuer_name":"C=US, O=Let's Encrypt, CN=R3","common_name":"a.ua","name_value":"a.ua\nwww.a.ua","not_before":"2026-01-01T00:00:00","not_after":"2026-04-01T00:00:00","serial_number":"0a"},
          {"id":2,"issuer_ca_id":7,"issuer_name":"C=US, O=Let's Encrypt, CN=R3","common_name":"a.ua","name_value":"a.ua","not_before":"2026-01-01T00:00:00","not_after":"2026-04-01T00:00:00","serial_number":"0a"},
          {"id":3,"issuer_name":"CN=x","name_value":"x@a.ua\n*.A.UA"}
        ]"#;
        let v = parse_crtsh_certs(j).unwrap();
        assert_eq!(v.len(), 2);
        assert_eq!(v[0].names, vec!["a.ua", "www.a.ua"]);
        assert_eq!(v[0].issuer_org.as_deref(), Some("Let's Encrypt"));
        assert_eq!(v[0].not_after, parse_ct_time("2026-04-01T00:00:00"));
        assert_eq!(v[1].names, vec!["*.a.ua"]);
        assert!(v[1].not_before.is_none());
    }
}
