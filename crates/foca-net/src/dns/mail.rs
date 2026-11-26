//! Mail security analysis of a domain: SPF, DMARC and DKIM (can mail from it be spoofed?), plus
//! the transport and certificate policies BIMI, MTA-STS, TLS-RPT, CAA and the DNSSEC status.

use serde::{Deserialize, Serialize};

use crate::dns::{DnsLookup, RType};

/// A parsed SPF record.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Spf {
    pub record: String,
    /// Qualifier of `all`: `+`, `-`, `~` or `?`; `None` if there is no `all` mechanism (equivalent to `?all`).
    pub all: Option<char>,
    pub includes: Vec<String>,
    pub redirect: Option<String>,
    /// Number of mechanisms that require DNS lookups (RFC 7208 limits this to 10).
    pub dns_lookups: u32,
}

/// Parses an SPF record (`v=spf1 ...`). Returns `None` if it is not SPF.
pub fn parse_spf(txt: &str) -> Option<Spf> {
    let t = txt.trim();
    let mut parts = t.split_whitespace();
    if !parts.next()?.eq_ignore_ascii_case("v=spf1") {
        return None;
    }
    let mut spf = Spf {
        record: t.to_string(),
        ..Default::default()
    };
    for p in parts {
        let lower = p.to_ascii_lowercase();
        let (q, mech) = match lower.chars().next() {
            Some(c @ ('+' | '-' | '~' | '?')) => (c, &lower[1..]),
            _ => ('+', lower.as_str()),
        };
        let name = mech.split([':', '/', '=']).next().unwrap_or("");
        match name {
            "all" => spf.all = Some(q),
            "include" => {
                spf.dns_lookups += 1;
                if let Some(v) = mech.split_once(':').map(|x| x.1) {
                    spf.includes.push(v.to_string());
                }
            }
            "redirect" => {
                spf.dns_lookups += 1;
                spf.redirect = mech.split_once('=').map(|x| x.1.to_string());
            }
            "a" | "mx" | "ptr" | "exists" => spf.dns_lookups += 1,
            _ => {}
        }
    }
    Some(spf)
}

/// A parsed DMARC record.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Dmarc {
    pub record: String,
    pub p: String,
    pub sp: Option<String>,
    pub pct: u32,
    pub rua: Vec<String>,
}

/// Parses a DMARC record (`v=DMARC1; p=...`). Returns `None` if it is not DMARC.
pub fn parse_dmarc(txt: &str) -> Option<Dmarc> {
    let t = txt.trim();
    let mut tags = t.split(';').map(|x| x.trim()).filter(|x| !x.is_empty());
    let v = tags.next()?;
    let (k, val) = v.split_once('=')?;
    if !k.trim().eq_ignore_ascii_case("v") || !val.trim().eq_ignore_ascii_case("DMARC1") {
        return None;
    }
    let mut d = Dmarc {
        record: t.to_string(),
        pct: 100,
        ..Default::default()
    };
    for tag in tags {
        let Some((k, v)) = tag.split_once('=') else {
            continue;
        };
        let v = v.trim();
        match k.trim().to_ascii_lowercase().as_str() {
            "p" => d.p = v.to_ascii_lowercase(),
            "sp" => d.sp = Some(v.to_ascii_lowercase()),
            "pct" => d.pct = v.parse().unwrap_or(100).min(100),
            "rua" => d.rua = v.split(',').map(|x| x.trim().to_string()).collect(),
            _ => {}
        }
    }
    Some(d)
}

/// A mail security issue.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MailIssue {
    /// `spf_missing`, `spf_multiple`, `spf_pass_all`, `spf_neutral_all`, `spf_softfail`,
    /// `spf_no_all`, `spf_too_many_lookups`, `dmarc_missing`, `dmarc_multiple`, `dmarc_none`,
    /// `dmarc_pct`, `dmarc_sp_none`, `dkim_not_found`.
    pub id: String,
    /// `crit` | `high` | `warn` | `low` | `info` (same as `Severity` in `docs/API.md`).
    pub sev: String,
    pub title: String,
    pub detail: String,
}

/// Result of the mail analysis.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MailReport {
    pub has_mx: bool,
    pub spf: Option<Spf>,
    pub dmarc: Option<Dmarc>,
    /// DKIM selectors found (from a dictionary of common ones).
    pub dkim_selectors: Vec<String>,
    /// Mail from the domain can be spoofed (recipients would accept it).
    pub spoofable: bool,
    pub issues: Vec<MailIssue>,
}

fn issue(id: &str, sev: &str, title: &str, detail: String) -> MailIssue {
    MailIssue {
        id: id.into(),
        sev: sev.into(),
        title: title.into(),
        detail,
    }
}

/// Analyzes already fetched TXT records. A pure function, tested against fixtures.
pub fn analyze_mail(
    domain: &str,
    root_txt: &[String],
    dmarc_txt: &[String],
    dkim_selectors: &[String],
    has_mx: bool,
) -> MailReport {
    let spfs: Vec<Spf> = root_txt.iter().filter_map(|t| parse_spf(t)).collect();
    let dmarcs: Vec<Dmarc> = dmarc_txt.iter().filter_map(|t| parse_dmarc(t)).collect();
    let mut issues = Vec::new();
    let spf = spfs.first().cloned();
    let dmarc = dmarcs.first().cloned();

    if spfs.is_empty() {
        issues.push(issue(
            "spf_missing",
            "warn",
            "Нет SPF-записи: подделка писем от домена возможна",
            format!("Для {domain} нет TXT-записи v=spf1."),
        ));
    } else if spfs.len() > 1 {
        issues.push(issue(
            "spf_multiple",
            "warn",
            "Несколько SPF-записей (permerror): SPF не работает",
            format!("Найдено {} записей v=spf1 у {domain}.", spfs.len()),
        ));
    }
    if let Some(s) = &spf {
        match s.all {
            Some('+') => issues.push(issue(
                "spf_pass_all",
                "high",
                "SPF +all: любой сервер может отправлять письма от домена",
                s.record.clone(),
            )),
            Some('?') => issues.push(issue(
                "spf_neutral_all",
                "warn",
                "SPF ?all: нейтральная политика, подделка не блокируется",
                s.record.clone(),
            )),
            Some('~') => issues.push(issue(
                "spf_softfail",
                "low",
                "SPF с мягкой политикой ~all",
                s.record.clone(),
            )),
            None if s.redirect.is_none() => issues.push(issue(
                "spf_no_all",
                "warn",
                "SPF без механизма all: политика по умолчанию нейтральная",
                s.record.clone(),
            )),
            _ => {}
        }
        if s.dns_lookups > 10 {
            issues.push(issue(
                "spf_too_many_lookups",
                "low",
                "SPF требует больше 10 DNS-запросов (permerror)",
                format!("{} механизмов с DNS-запросами", s.dns_lookups),
            ));
        }
    }
    if dmarcs.is_empty() {
        issues.push(issue(
            "dmarc_missing",
            "warn",
            "Нет DMARC: подделка писем от домена возможна",
            format!("Для _dmarc.{domain} нет записи v=DMARC1."),
        ));
    } else if dmarcs.len() > 1 {
        issues.push(issue(
            "dmarc_multiple",
            "warn",
            "Несколько DMARC-записей: DMARC игнорируется",
            format!("{} записей v=DMARC1", dmarcs.len()),
        ));
    }
    if let Some(d) = &dmarc {
        if d.p == "none" || d.p.is_empty() {
            issues.push(issue(
                "dmarc_none",
                "warn",
                "DMARC p=none: подделка писем от домена возможна",
                d.record.clone(),
            ));
        } else if d.pct < 100 {
            issues.push(issue(
                "dmarc_pct",
                "low",
                "DMARC применяется не ко всем письмам (pct<100)",
                d.record.clone(),
            ));
        }
        if d.sp.as_deref() == Some("none") && d.p != "none" {
            issues.push(issue(
                "dmarc_sp_none",
                "low",
                "DMARC sp=none: поддомены не защищены",
                d.record.clone(),
            ));
        }
    }
    if dkim_selectors.is_empty() && has_mx {
        issues.push(issue(
            "dkim_not_found",
            "info",
            "DKIM-селекторы из словаря не найдены",
            "Проверены распространённые селекторы; это не доказывает отсутствие DKIM.".into(),
        ));
    }

    let dmarc_enforced = dmarcs.len() == 1
        && dmarc
            .as_ref()
            .is_some_and(|d| (d.p == "reject" || d.p == "quarantine") && d.pct == 100);
    let spf_ok = spfs.len() == 1
        && spf
            .as_ref()
            .is_some_and(|s| matches!(s.all, Some('-') | Some('~')) || s.redirect.is_some());
    // An enforcing DMARC policy protects even with ~all, since SPF/DKIM alignment is mandatory.
    let spoofable = !(dmarc_enforced && spf_ok);

    MailReport {
        has_mx,
        spf,
        dmarc,
        dkim_selectors: dkim_selectors.to_vec(),
        spoofable,
        issues,
    }
}

/// Common DKIM selectors (a small dictionary, not brute force).
pub const DKIM_SELECTORS: &[&str] = &[
    "default",
    "selector1",
    "selector2",
    "google",
    "k1",
    "k2",
    "mail",
    "dkim",
    "s1",
    "s2",
    "smtp",
    "mx",
    "mandrill",
    "everlytickey1",
    "zoho",
];

/// Returns `true` for a DKIM record with an actual key (non-empty `p=`). `v=DKIM1; p=` is a revoked
/// key placeholder (often a wildcard over `_domainkey`) and does not count as a found selector.
pub fn dkim_has_key(txt: &str) -> bool {
    let low = txt.to_ascii_lowercase();
    if !low.contains("v=dkim1") && !low.contains("p=") {
        return false;
    }
    txt.split(';').any(|kv| {
        let kv = kv.trim();
        kv.len() > 2 && kv[..2].eq_ignore_ascii_case("p=") && !kv[2..].trim().is_empty()
    })
}

fn wildcard_salt(domain: &str) -> u64 {
    let t = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(7);
    domain.bytes().fold(t, |h, b| h.rotate_left(5) ^ b as u64)
}

/// Fetches TXT/MX records and analyzes them.
pub async fn check_mail(dns: &dyn DnsLookup, domain: &str) -> MailReport {
    let root = dns
        .lookup(domain, RType::TXT)
        .await
        .map(|a| a.values(RType::TXT))
        .unwrap_or_default();
    let dmarc = dns
        .lookup(&format!("_dmarc.{domain}"), RType::TXT)
        .await
        .map(|a| a.values(RType::TXT))
        .unwrap_or_default();
    let has_mx = dns
        .lookup(domain, RType::MX)
        .await
        .map(|a| !a.values(RType::MX).is_empty())
        .unwrap_or(false);
    let mut dkim = Vec::new();
    if has_mx {
        // wildcard: a random selector also returns a DKIM record, so the dictionary proves nothing
        let probe = format!("foca-{:x}._domainkey.{domain}", wildcard_salt(domain));
        let wildcard = dns
            .lookup(&probe, RType::TXT)
            .await
            .map(|a| a.values(RType::TXT).iter().any(|t| dkim_has_key(t)))
            .unwrap_or(false);
        if !wildcard {
            for s in DKIM_SELECTORS {
                if let Ok(a) = dns
                    .lookup(&format!("{s}._domainkey.{domain}"), RType::TXT)
                    .await
                {
                    if a.values(RType::TXT).iter().any(|t| dkim_has_key(t)) {
                        dkim.push(s.to_string());
                    }
                }
            }
        }
    }
    analyze_mail(domain, &root, &dmarc, &dkim, has_mx)
}

/// A parsed BIMI record (`default._bimi.<domain>`, `v=BIMI1; l=...; a=...`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Bimi {
    pub record: String,
    /// SVG logo URL (`l=`).
    pub logo: Option<String>,
    /// Verified Mark Certificate URL (`a=`).
    pub authority: Option<String>,
}

fn tags(txt: &str) -> impl Iterator<Item = (String, String)> + '_ {
    txt.split(';').filter_map(|kv| {
        let (k, v) = kv.split_once('=')?;
        Some((k.trim().to_ascii_lowercase(), v.trim().to_string()))
    })
}

fn first_tag_is(txt: &str, key: &str, val: &str) -> bool {
    tags(txt)
        .next()
        .is_some_and(|(k, v)| k == key && v.eq_ignore_ascii_case(val))
}

fn non_empty(v: String) -> Option<String> {
    (!v.is_empty()).then_some(v)
}

/// Parses a BIMI record. Returns `None` if it is not `v=BIMI1`.
pub fn parse_bimi(txt: &str) -> Option<Bimi> {
    let t = txt.trim();
    if !first_tag_is(t, "v", "BIMI1") {
        return None;
    }
    let mut b = Bimi {
        record: t.to_string(),
        ..Default::default()
    };
    for (k, v) in tags(t) {
        match k.as_str() {
            "l" => b.logo = non_empty(v),
            "a" => b.authority = non_empty(v),
            _ => {}
        }
    }
    Some(b)
}

/// The MTA-STS DNS record (`_mta-sts.<domain>`, `v=STSv1; id=...`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MtaStsRecord {
    pub record: String,
    pub id: String,
}

/// Parses an MTA-STS TXT record. Returns `None` if it is not `v=STSv1`.
pub fn parse_mta_sts_record(txt: &str) -> Option<MtaStsRecord> {
    let t = txt.trim();
    if !first_tag_is(t, "v", "STSv1") {
        return None;
    }
    let id = tags(t)
        .find(|(k, _)| k == "id")
        .map(|(_, v)| v)
        .unwrap_or_default();
    Some(MtaStsRecord {
        record: t.to_string(),
        id,
    })
}

/// An MTA-STS policy file (`https://mta-sts.<domain>/.well-known/mta-sts.txt`, RFC 8461).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MtaStsPolicy {
    /// `enforce`, `testing` or `none`.
    pub mode: String,
    /// MX patterns (`mail.example.com`, `*.example.net`).
    pub mx: Vec<String>,
    pub max_age: Option<u64>,
}

/// Parses an MTA-STS policy file. Returns `None` without `version: STSv1`.
pub fn parse_mta_sts_policy(text: &str) -> Option<MtaStsPolicy> {
    let mut p = MtaStsPolicy::default();
    let mut version = false;
    for line in text.lines() {
        let Some((k, v)) = line.split_once(':') else {
            continue;
        };
        let v = v.trim();
        match k.trim().to_ascii_lowercase().as_str() {
            "version" => version = v.eq_ignore_ascii_case("STSv1"),
            "mode" => p.mode = v.to_ascii_lowercase(),
            "mx" => p.mx.push(v.to_ascii_lowercase()),
            "max_age" => p.max_age = v.parse().ok(),
            _ => {}
        }
    }
    version.then_some(p)
}

/// Returns `true` if `host` matches an MTA-STS MX pattern (a leading `*.` covers exactly one
/// label).
pub fn mta_sts_mx_matches(pattern: &str, host: &str) -> bool {
    let p = crate::dns::norm_name(pattern);
    let h = crate::dns::norm_name(host);
    match p.strip_prefix("*.") {
        Some(suffix) => h
            .split_once('.')
            .is_some_and(|(first, rest)| !first.is_empty() && rest == suffix),
        None => p == h,
    }
}

/// The SMTP TLS reporting record (`_smtp._tls.<domain>`, `v=TLSRPTv1; rua=...`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TlsRpt {
    pub record: String,
    pub rua: Vec<String>,
}

/// Parses a TLS-RPT record. Returns `None` if it is not `v=TLSRPTv1`.
pub fn parse_tls_rpt(txt: &str) -> Option<TlsRpt> {
    let t = txt.trim();
    if !first_tag_is(t, "v", "TLSRPTv1") {
        return None;
    }
    let rua = tags(t)
        .find(|(k, _)| k == "rua")
        .map(|(_, v)| {
            v.split(',')
                .map(|x| x.trim().to_string())
                .filter(|x| !x.is_empty())
                .collect()
        })
        .unwrap_or_default();
    Some(TlsRpt {
        record: t.to_string(),
        rua,
    })
}

/// A CAA record (`0 issue "letsencrypt.org"`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Caa {
    pub flags: u8,
    /// `issue`, `issuewild`, `iodef`, ... (lowercase).
    pub tag: String,
    /// Value without quotes (`letsencrypt.org; validationmethods=dns-01`).
    pub value: String,
}

impl Caa {
    /// The CA domain of an `issue`/`issuewild` value (`letsencrypt.org`); empty means "no CA".
    pub fn issuer(&self) -> &str {
        self.value.split(';').next().unwrap_or("").trim()
    }
}

/// Parses a CAA value as printed by hickory and DoH (`flags tag "value"`).
pub fn parse_caa(s: &str) -> Option<Caa> {
    let mut it = s.trim().splitn(3, char::is_whitespace);
    let flags = it.next()?.parse().ok()?;
    let tag = it.next()?.trim().to_ascii_lowercase();
    if tag.is_empty() {
        return None;
    }
    let value = it.next().unwrap_or("").trim().trim_matches('"').to_string();
    Some(Caa { flags, tag, value })
}

/// Checks whether CAA records allow a CA (identified by its CAA domain, `letsencrypt.org`) to
/// issue a certificate. `wildcard` selects `issuewild` (falling back to `issue`, RFC 8659).
/// Returns `None` when there are no `issue`/`issuewild` records (any CA may issue).
pub fn caa_allows(records: &[Caa], ca_domain: &str, wildcard: bool) -> Option<bool> {
    let ca = crate::dns::norm_name(ca_domain);
    let pick = |tag: &str| -> Vec<&Caa> { records.iter().filter(|r| r.tag == tag).collect() };
    let mut set = if wildcard {
        pick("issuewild")
    } else {
        Vec::new()
    };
    if set.is_empty() {
        set = pick("issue");
    }
    if set.is_empty() {
        return None;
    }
    Some(
        set.iter()
            .any(|r| !r.issuer().is_empty() && crate::dns::norm_name(r.issuer()) == ca),
    )
}

/// DNSSEC status of a domain, as far as DS/DNSKEY presence shows (no signature validation).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DnssecStatus {
    /// DS at the parent and DNSKEY in the zone: a signed delegation.
    Signed,
    /// DNSKEY without DS: the zone is signed but the chain of trust is not anchored.
    Unanchored,
    /// Neither DS nor DNSKEY.
    Unsigned,
    /// Lookups failed.
    #[default]
    Unknown,
}

/// Mail transport and certificate policies of a domain (BIMI, MTA-STS, TLS-RPT, CAA, DNSSEC).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MailPolicyReport {
    pub bimi: Option<Bimi>,
    pub mta_sts: Option<MtaStsRecord>,
    /// The fetched policy file, when the caller fetched it ([`fetch_mta_sts_policy`]).
    pub mta_sts_policy: Option<MtaStsPolicy>,
    pub tls_rpt: Option<TlsRpt>,
    pub caa: Vec<Caa>,
    pub dnssec: DnssecStatus,
    /// Issue ids: `bimi_dmarc_weak`, `mta_sts_missing`, `mta_sts_testing`, `mta_sts_none`,
    /// `mta_sts_policy_unreachable`, `mta_sts_mx_mismatch`, `tls_rpt_missing`, `caa_missing`,
    /// `dnssec_unsigned`, `dnssec_unanchored`.
    pub issues: Vec<MailIssue>,
}

/// Raw inputs of [`analyze_policies`].
#[derive(Debug, Clone, Default)]
pub struct PolicyInputs {
    pub bimi_txt: Vec<String>,
    pub mta_sts_txt: Vec<String>,
    /// `Some(Ok)` fetched, `Some(Err)` fetch failed, `None` not attempted.
    pub mta_sts_policy: Option<Result<MtaStsPolicy, String>>,
    pub tls_rpt_txt: Vec<String>,
    pub caa: Vec<String>,
    /// MX host names (`10 mx.example.com` or bare).
    pub mx: Vec<String>,
    pub dnssec: DnssecStatus,
    /// The domain's DMARC policy (`p=`), for the BIMI prerequisite.
    pub dmarc: Option<Dmarc>,
}

/// Analyzes already fetched policy records. A pure function, tested against fixtures.
pub fn analyze_policies(domain: &str, inp: &PolicyInputs) -> MailPolicyReport {
    let mut r = MailPolicyReport {
        bimi: inp.bimi_txt.iter().find_map(|t| parse_bimi(t)),
        mta_sts: inp.mta_sts_txt.iter().find_map(|t| parse_mta_sts_record(t)),
        tls_rpt: inp.tls_rpt_txt.iter().find_map(|t| parse_tls_rpt(t)),
        caa: inp.caa.iter().filter_map(|c| parse_caa(c)).collect(),
        dnssec: inp.dnssec,
        ..Default::default()
    };
    let has_mx = !inp.mx.is_empty();
    let mx_hosts: Vec<String> = inp
        .mx
        .iter()
        .filter_map(|m| m.split_whitespace().last())
        .map(crate::dns::norm_name)
        .filter(|h| !h.is_empty())
        .collect();

    if r.bimi.is_some() {
        let enforced = inp
            .dmarc
            .as_ref()
            .is_some_and(|d| (d.p == "reject" || d.p == "quarantine") && d.pct == 100);
        if !enforced {
            r.issues.push(issue(
                "bimi_dmarc_weak",
                "info",
                "BIMI без принудительного DMARC: логотип не будет показан",
                format!("default._bimi.{domain}"),
            ));
        }
    }
    if has_mx {
        match (&r.mta_sts, &inp.mta_sts_policy) {
            (None, _) => r.issues.push(issue(
                "mta_sts_missing",
                "info",
                "Нет MTA-STS: доставка почты на домен допускает понижение TLS",
                format!("Нет записи _mta-sts.{domain}."),
            )),
            (Some(_), Some(Err(e))) => r.issues.push(issue(
                "mta_sts_policy_unreachable",
                "warn",
                "Запись MTA-STS есть, но файл политики недоступен",
                e.clone(),
            )),
            (Some(_), Some(Ok(p))) => {
                r.mta_sts_policy = Some(p.clone());
                match p.mode.as_str() {
                    "testing" => r.issues.push(issue(
                        "mta_sts_testing",
                        "low",
                        "MTA-STS в режиме testing: политика не применяется",
                        format!("mode: {}", p.mode),
                    )),
                    "enforce" => {}
                    _ => r.issues.push(issue(
                        "mta_sts_none",
                        "low",
                        "MTA-STS отключён (mode: none)",
                        format!("mode: {}", p.mode),
                    )),
                }
                let uncovered: Vec<&str> = mx_hosts
                    .iter()
                    .filter(|h| !p.mx.iter().any(|pat| mta_sts_mx_matches(pat, h)))
                    .map(String::as_str)
                    .collect();
                if !uncovered.is_empty() {
                    r.issues.push(issue(
                        "mta_sts_mx_mismatch",
                        "warn",
                        "MX-серверы не покрыты политикой MTA-STS: доставка на них будет отклонена",
                        uncovered.join(", "),
                    ));
                }
            }
            (Some(_), None) => {}
        }
        if r.tls_rpt.is_none() {
            r.issues.push(issue(
                "tls_rpt_missing",
                "info",
                "Нет TLS-RPT: сбои TLS при доставке почты не отслеживаются",
                format!("Нет записи _smtp._tls.{domain}."),
            ));
        }
    }
    if !r
        .caa
        .iter()
        .any(|c| c.tag == "issue" || c.tag == "issuewild")
    {
        r.issues.push(issue(
            "caa_missing",
            "low",
            "Нет CAA: сертификат для домена может выпустить любой УЦ",
            format!("Нет записей CAA issue/issuewild у {domain}."),
        ));
    }
    match r.dnssec {
        DnssecStatus::Unsigned => r.issues.push(issue(
            "dnssec_unsigned",
            "low",
            "DNSSEC не включён: ответы DNS можно подделать",
            format!("Нет записей DS/DNSKEY у {domain}."),
        )),
        DnssecStatus::Unanchored => r.issues.push(issue(
            "dnssec_unanchored",
            "warn",
            "Зона подписана, но DS у родительской зоны нет: цепочка доверия разорвана",
            format!("DNSKEY есть, DS нет: {domain}."),
        )),
        _ => {}
    }
    r
}

/// Determines the DNSSEC status from DS (at the parent) and DNSKEY lookups.
pub async fn dnssec_status(dns: &dyn DnsLookup, domain: &str) -> DnssecStatus {
    let ds = dns.lookup(domain, RType::DS).await;
    let key = dns.lookup(domain, RType::DNSKEY).await;
    match (ds, key) {
        (Ok(ds), Ok(key)) => {
            let has_ds = !ds.values(RType::DS).is_empty();
            let has_key = !key.values(RType::DNSKEY).is_empty();
            match (has_ds, has_key) {
                (true, _) => DnssecStatus::Signed,
                (false, true) => DnssecStatus::Unanchored,
                (false, false) => DnssecStatus::Unsigned,
            }
        }
        (Ok(ds), Err(_)) if !ds.values(RType::DS).is_empty() => DnssecStatus::Signed,
        _ => DnssecStatus::Unknown,
    }
}

/// Fetches the policy records over DNS only (passive) and analyzes them. The MTA-STS policy file
/// lives on the target's web server: pass it in `policy` after [`fetch_mta_sts_policy`] (standard
/// profile) or leave `None` (passive profile).
pub async fn check_mail_policies(
    dns: &dyn DnsLookup,
    domain: &str,
    dmarc: Option<Dmarc>,
    policy: Option<Result<MtaStsPolicy, String>>,
) -> MailPolicyReport {
    let d = crate::dns::norm_name(domain);
    let txt = |name: String| async move {
        dns.lookup(&name, RType::TXT)
            .await
            .map(|a| a.values(RType::TXT))
            .unwrap_or_default()
    };
    let inp = PolicyInputs {
        bimi_txt: txt(format!("default._bimi.{d}")).await,
        mta_sts_txt: txt(format!("_mta-sts.{d}")).await,
        mta_sts_policy: policy,
        tls_rpt_txt: txt(format!("_smtp._tls.{d}")).await,
        caa: dns
            .lookup(&d, RType::CAA)
            .await
            .map(|a| a.values(RType::CAA))
            .unwrap_or_default(),
        mx: dns
            .lookup(&d, RType::MX)
            .await
            .map(|a| a.values(RType::MX))
            .unwrap_or_default(),
        dnssec: dnssec_status(dns, &d).await,
        dmarc,
    };
    analyze_policies(&d, &inp)
}

/// Fetches the MTA-STS policy file from `https://mta-sts.<domain>/.well-known/mta-sts.txt`
/// (`base` overrides the origin for tests). The host belongs to the target, so the request is
/// [`Access::TouchesTarget`]: it is scope-checked and must not run in the passive profile.
pub async fn fetch_mta_sts_policy(
    net: &crate::NetClient,
    domain: &str,
    base: Option<&str>,
) -> Result<MtaStsPolicy, crate::NetError> {
    let d = crate::dns::norm_name(domain);
    let url = match base {
        Some(b) => format!("{}/.well-known/mta-sts.txt", b.trim_end_matches('/')),
        None => format!("https://mta-sts.{d}/.well-known/mta-sts.txt"),
    };
    let req = crate::NetRequest::get(&url, "mail", crate::Access::TouchesTarget)?
        .no_redirects()
        .retries(0);
    let r = net.send(req).await?.ensure_success()?;
    let body = r.text_limited(64 * 1024).await?;
    parse_mta_sts_policy(&body)
        .ok_or_else(|| crate::NetError::Parse("not an MTA-STS policy".into()))
}

#[cfg(test)]
mod policy_tests {
    use std::sync::Arc;

    use foca_core::Scope;

    use super::*;
    use crate::dns::StaticDns;
    use crate::testserver::{TestResponse, TestServer};
    use crate::{MemorySink, NetClient, NetConfig};

    #[test]
    fn record_parsers() {
        let b = parse_bimi("v=BIMI1; l=https://x.test/logo.svg; a=;").unwrap();
        assert_eq!(b.logo.as_deref(), Some("https://x.test/logo.svg"));
        assert!(b.authority.is_none());
        assert!(parse_bimi("v=spf1 -all").is_none());

        assert_eq!(
            parse_mta_sts_record("v=STSv1; id=2024010101").unwrap().id,
            "2024010101"
        );
        assert!(parse_mta_sts_record("v=STSv2; id=1").is_none());

        let p = parse_mta_sts_policy("version: STSv1\r\nmode: enforce\r\nmx: mail.x.test\r\nmx: *.mx.x.test\r\nmax_age: 604800\r\n").unwrap();
        assert_eq!(p.mode, "enforce");
        assert_eq!(p.mx, vec!["mail.x.test", "*.mx.x.test"]);
        assert_eq!(p.max_age, Some(604800));
        assert!(parse_mta_sts_policy("<html>").is_none());
        assert!(mta_sts_mx_matches("*.mx.x.test", "a.mx.x.test."));
        assert!(!mta_sts_mx_matches("*.mx.x.test", "a.b.mx.x.test"));
        assert!(!mta_sts_mx_matches("*.mx.x.test", "mx.x.test"));

        let t = parse_tls_rpt("v=TLSRPTv1; rua=mailto:tls@x.test, https://r.test/").unwrap();
        assert_eq!(t.rua, vec!["mailto:tls@x.test", "https://r.test/"]);

        let c = parse_caa("0 issue \"letsencrypt.org; validationmethods=dns-01\"").unwrap();
        assert_eq!(
            (c.flags, c.tag.as_str(), c.issuer()),
            (0, "issue", "letsencrypt.org")
        );
        let caa: Vec<Caa> = [
            "0 issue \"letsencrypt.org\"",
            "0 issuewild \";\"",
            "0 iodef \"mailto:a@x.test\"",
        ]
        .iter()
        .filter_map(|s| parse_caa(s))
        .collect();
        assert_eq!(caa_allows(&caa, "letsencrypt.org", false), Some(true));
        assert_eq!(caa_allows(&caa, "digicert.com", false), Some(false));
        assert_eq!(caa_allows(&caa, "letsencrypt.org", true), Some(false));
        assert_eq!(caa_allows(&[], "letsencrypt.org", false), None);
    }

    #[test]
    fn policy_matrix() {
        let ids = |r: &MailPolicyReport| r.issues.iter().map(|i| i.id.clone()).collect::<Vec<_>>();
        let bare = analyze_policies(
            "x.test",
            &PolicyInputs {
                mx: vec!["10 mail.x.test".into()],
                dnssec: DnssecStatus::Unsigned,
                ..Default::default()
            },
        );
        assert_eq!(
            ids(&bare),
            vec![
                "mta_sts_missing",
                "tls_rpt_missing",
                "caa_missing",
                "dnssec_unsigned"
            ]
        );

        let good = analyze_policies(
            "x.test",
            &PolicyInputs {
                bimi_txt: vec!["v=BIMI1; l=https://x.test/l.svg".into()],
                mta_sts_txt: vec!["v=STSv1; id=1".into()],
                mta_sts_policy: Some(Ok(MtaStsPolicy {
                    mode: "enforce".into(),
                    mx: vec!["*.x.test".into()],
                    max_age: Some(86400),
                })),
                tls_rpt_txt: vec!["v=TLSRPTv1; rua=mailto:a@x.test".into()],
                caa: vec!["0 issue \"letsencrypt.org\"".into()],
                mx: vec!["10 mail.x.test".into()],
                dnssec: DnssecStatus::Signed,
                dmarc: parse_dmarc("v=DMARC1; p=reject"),
            },
        );
        assert!(good.issues.is_empty(), "{:?}", good.issues);
        assert!(good.mta_sts_policy.is_some());

        let weak = analyze_policies(
            "x.test",
            &PolicyInputs {
                bimi_txt: vec!["v=BIMI1; l=".into()],
                mta_sts_txt: vec!["v=STSv1; id=1".into()],
                mta_sts_policy: Some(Ok(MtaStsPolicy {
                    mode: "testing".into(),
                    mx: vec!["mail.x.test".into()],
                    max_age: None,
                })),
                tls_rpt_txt: vec!["v=TLSRPTv1; rua=mailto:a@x.test".into()],
                caa: vec!["0 iodef \"mailto:a@x.test\"".into()],
                mx: vec!["10 mail.x.test".into(), "20 backup.y.test".into()],
                dnssec: DnssecStatus::Unanchored,
                dmarc: parse_dmarc("v=DMARC1; p=none"),
            },
        );
        assert_eq!(
            ids(&weak),
            vec![
                "bimi_dmarc_weak",
                "mta_sts_testing",
                "mta_sts_mx_mismatch",
                "caa_missing",
                "dnssec_unanchored"
            ]
        );
        let unreachable = analyze_policies(
            "x.test",
            &PolicyInputs {
                mta_sts_txt: vec!["v=STSv1; id=1".into()],
                mta_sts_policy: Some(Err("HTTP 404".into())),
                mx: vec!["10 mail.x.test".into()],
                ..Default::default()
            },
        );
        assert!(ids(&unreachable).contains(&"mta_sts_policy_unreachable".to_string()));
    }

    #[tokio::test]
    async fn dns_side_and_dnssec() {
        let z = StaticDns::new()
            .add("x.test", RType::MX, &["10 mail.x.test"])
            .add("x.test", RType::CAA, &["0 issue \"letsencrypt.org\""])
            .add("x.test", RType::DS, &["2371 13 2 abcd"])
            .add("x.test", RType::DNSKEY, &["257 3 13 AAAA"])
            .add("_mta-sts.x.test", RType::TXT, &["v=STSv1; id=7"])
            .add(
                "_smtp._tls.x.test",
                RType::TXT,
                &["v=TLSRPTv1; rua=mailto:t@x.test"],
            )
            .add(
                "default._bimi.x.test",
                RType::TXT,
                &["v=BIMI1; l=https://x.test/l.svg"],
            );
        let r = check_mail_policies(&z, "X.test.", parse_dmarc("v=DMARC1; p=reject"), None).await;
        assert_eq!(r.dnssec, DnssecStatus::Signed);
        assert_eq!(r.mta_sts.as_ref().unwrap().id, "7");
        assert!(r.issues.is_empty(), "{:?}", r.issues);

        let z = StaticDns::new()
            .add("y.test", RType::A, &["192.0.2.1"])
            .add("y.test", RType::DNSKEY, &["257 3 13 AAAA"]);
        assert_eq!(dnssec_status(&z, "y.test").await, DnssecStatus::Unanchored);
        let z = StaticDns::new().add("y.test", RType::A, &["192.0.2.1"]);
        assert_eq!(dnssec_status(&z, "y.test").await, DnssecStatus::Unsigned);
    }

    #[tokio::test]
    async fn mta_sts_policy_fetch_is_target_access() {
        let srv = TestServer::start(|r| match r.path() {
            "/.well-known/mta-sts.txt" => {
                TestResponse::ok("version: STSv1\nmode: enforce\nmx: mail.x.test\nmax_age: 86400\n")
            }
            _ => TestResponse::status(404),
        })
        .await;
        let cfg = NetConfig {
            retries: 0,
            global_rps: None,
            ..Default::default()
        };
        // in scope: fetched and logged as a target request
        let sink = Arc::new(MemorySink::new());
        let (scope, _) = Scope::from_lines("127.0.0.1", "");
        let net = NetClient::new(cfg.clone(), scope, sink.clone()).unwrap();
        let p = fetch_mta_sts_policy(&net, "x.test", Some(&srv.url()))
            .await
            .unwrap();
        assert_eq!(p.mode, "enforce");
        assert!(sink
            .records()
            .iter()
            .all(|r| r.active && r.access == "target"));

        // out of scope (passive profile: nothing in scope for the target client): no request
        let net =
            NetClient::new(cfg.clone(), Scope::default(), Arc::new(MemorySink::new())).unwrap();
        assert!(fetch_mta_sts_policy(&net, "x.test", Some(&srv.url()))
            .await
            .is_err());
        // local_only test bench: an external host is refused before connecting
        let net = NetClient::new(
            NetConfig {
                local_only: Some(std::path::PathBuf::new()),
                ..cfg
            },
            Scope::from_lines("x.test", "").0,
            Arc::new(MemorySink::new()),
        )
        .unwrap();
        assert!(fetch_mta_sts_policy(&net, "example.com", None)
            .await
            .is_err());
        assert_eq!(srv.hits("/.well-known/mta-sts.txt"), 1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn dkim_key_vs_revoked_stub() {
        assert!(dkim_has_key("v=DKIM1; k=rsa; p=MIIBIjANBgkq"));
        assert!(!dkim_has_key("v=DKIM1; p="));
        assert!(!dkim_has_key("v=DKIM1; k=rsa; p= "));
        assert!(!dkim_has_key("google-site-verification=x"));
    }

    #[tokio::test]
    async fn dkim_wildcard_and_stub_not_counted() {
        use crate::dns::StaticDns;
        // example.com answers any selector with the `v=DKIM1; p=` placeholder: nothing found
        let mut z = StaticDns::new()
            .add("ex.test", RType::MX, &["10 mx.ex.test"])
            .add("ex.test", RType::TXT, &["v=spf1 -all"]);
        for s in DKIM_SELECTORS {
            z = z.add(
                &format!("{s}._domainkey.ex.test"),
                RType::TXT,
                &["v=DKIM1; p="],
            );
        }
        let r = check_mail(&z, "ex.test").await;
        assert!(r.dkim_selectors.is_empty(), "{:?}", r.dkim_selectors);
        // a real key under one selector is found
        let z = StaticDns::new()
            .add("ok.test", RType::MX, &["10 mx.ok.test"])
            .add(
                "google._domainkey.ok.test",
                RType::TXT,
                &["v=DKIM1; k=rsa; p=MIIB"],
            );
        let r = check_mail(&z, "ok.test").await;
        assert_eq!(r.dkim_selectors, vec!["google"]);
    }

    #[test]
    fn spf_parse() {
        let p = parse_spf("v=spf1 ip4:1.2.3.0/24 include:_spf.google.com mx -all").unwrap();
        assert_eq!(p.all, Some('-'));
        assert_eq!(p.includes, vec!["_spf.google.com"]);
        assert_eq!(p.dns_lookups, 2);
        assert!(parse_spf("google-site-verification=abc").is_none());
        assert_eq!(parse_spf("v=spf1 +all").unwrap().all, Some('+'));
        assert_eq!(parse_spf("v=spf1 all").unwrap().all, Some('+'));
        assert_eq!(
            parse_spf("v=spf1 redirect=_spf.x.ua")
                .unwrap()
                .redirect
                .as_deref(),
            Some("_spf.x.ua")
        );
    }

    #[test]
    fn dmarc_parse() {
        let d = parse_dmarc("v=DMARC1; p=reject; sp=none; pct=50; rua=mailto:a@x.ua").unwrap();
        assert_eq!(d.p, "reject");
        assert_eq!(d.sp.as_deref(), Some("none"));
        assert_eq!(d.pct, 50);
        assert!(parse_dmarc("v=spf1 -all").is_none());
    }

    #[test]
    fn spoofing_matrix() {
        let ok = analyze_mail(
            "a.ua",
            &s(&["v=spf1 mx -all"]),
            &s(&["v=DMARC1; p=reject"]),
            &s(&["selector1"]),
            true,
        );
        assert!(!ok.spoofable);
        assert!(ok.issues.is_empty(), "{:?}", ok.issues);

        let soft = analyze_mail(
            "a.ua",
            &s(&["v=spf1 mx ~all"]),
            &s(&["v=DMARC1; p=quarantine"]),
            &[],
            false,
        );
        assert!(!soft.spoofable);
        assert!(soft
            .issues
            .iter()
            .any(|i| i.id == "spf_softfail" && i.sev == "low"));

        let none = analyze_mail(
            "a.ua",
            &s(&["v=spf1 mx ~all"]),
            &s(&["v=DMARC1; p=none"]),
            &[],
            true,
        );
        assert!(none.spoofable);
        let ids: Vec<_> = none.issues.iter().map(|i| i.id.as_str()).collect();
        assert!(ids.contains(&"dmarc_none") && ids.contains(&"dkim_not_found"));

        let bare = analyze_mail("a.ua", &[], &[], &[], true);
        assert!(bare.spoofable);
        let ids: Vec<_> = bare.issues.iter().map(|i| i.id.as_str()).collect();
        assert!(ids.contains(&"spf_missing") && ids.contains(&"dmarc_missing"));

        let all = analyze_mail(
            "a.ua",
            &s(&["v=spf1 +all"]),
            &s(&["v=DMARC1; p=reject"]),
            &[],
            false,
        );
        assert!(all.spoofable);
        assert!(all
            .issues
            .iter()
            .any(|i| i.id == "spf_pass_all" && i.sev == "high"));

        let multi = analyze_mail(
            "a.ua",
            &s(&["v=spf1 -all", "v=spf1 mx -all"]),
            &s(&["v=DMARC1; p=reject"]),
            &[],
            false,
        );
        assert!(multi.spoofable);
        assert!(multi.issues.iter().any(|i| i.id == "spf_multiple"));

        let pct = analyze_mail(
            "a.ua",
            &s(&["v=spf1 -all"]),
            &s(&["v=DMARC1; p=reject; pct=20"]),
            &[],
            false,
        );
        assert!(pct.spoofable);
    }
}
