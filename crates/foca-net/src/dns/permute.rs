//! Smart permutations of known subdomains (modeled on alterx and gotator).
//!
//! [`permute`] turns the subdomains already found (CT logs, brute force, crawler) and host-like
//! tokens from document metadata (internal servers, printers, shares: [`tokens_from_metadata`])
//! into new candidate names, each with its provenance ([`Candidate`]): which rule produced it,
//! from which known name, and for metadata tokens from which document. Candidates are generated
//! by rule groups in priority order and capped by [`PermuteConfig::max_candidates`], so the
//! cheapest and most productive guesses survive a small budget:
//!
//! 1. metadata host tokens directly under the zone (`srv-fs01.example.com`);
//! 2. number steps (`api01` gives `api02`..`api05`, zero padding kept);
//! 3. environment swaps (`dev-api` gives `stage-api`, `api.dev` gives `api.uat`);
//! 4. cross-pollination: first labels seen anywhere placed under every known sub-level
//!    (`www`, `api` and the level `eu.example.com` give `api.eu.example.com`);
//! 5. API versions (`v1` gives `v2`, `api` gives `api-v2`, `v2.api`);
//! 6. environment prefixes and suffixes (`dev-shop`, `shop-stage`);
//! 7. number suffixes (`shop1`, `shop-2`, `shop03`);
//! 8. common role words (`admin-shop`, `shop-api`).
//!
//! Generation is pure. [`permute_and_resolve`] resolves the candidates with
//! [`crate::bruteforce::resolve_candidates`] (same access rules, pacing, two-phase verification
//! and multi-level wildcard filter) and keeps the provenance of every hit.

use std::collections::{BTreeMap, BTreeSet, HashSet};

use serde::{Deserialize, Serialize};

use crate::bruteforce::{
    self, valid_host, valid_label, BruteConfig, BruteHit, BruteReport, Resolvers,
};
use crate::dns::norm_name;
use crate::{NetClient, NetError};

/// Environment words (swapped with each other and used as affixes).
pub const ENV_WORDS: &[&str] = &[
    "dev", "test", "stage", "staging", "uat", "qa", "preprod", "prod", "demo", "beta", "old", "new",
];

/// Common role words used as affixes and new labels.
pub const ROLE_WORDS: &[&str] = &[
    "api", "admin", "app", "portal", "auth", "sso", "vpn", "git", "ci", "cdn", "static",
    "internal", "int", "mail", "db", "backup",
];

/// Suffixes of internal or non-public names in metadata (`printer.corp.local`).
const INTERNAL_SUFFIXES: &[&str] = &[
    "local",
    "lan",
    "corp",
    "internal",
    "intra",
    "intranet",
    "home",
    "localdomain",
    "ad",
    "priv",
    "private",
];

/// Generic tokens that are not host names.
const STOP_TOKENS: &[&str] = &[
    "localhost",
    "users",
    "user",
    "documents",
    "desktop",
    "share",
    "shares",
    "public",
    "home",
    "temp",
    "tmp",
    "windows",
    "program",
    "files",
    "admin",
    "administrator",
    "default",
    "unknown",
    "none",
    "null",
    "http",
    "https",
    "file",
    "www",
];

/// Where a token or candidate comes from.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TokenSource {
    /// A known subdomain of the zone.
    Subdomain,
    /// Document metadata; `name` is the document (file name or URL).
    Document { name: String },
    /// A built-in word list.
    Builtin,
}

/// A host-like token with its source.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Token {
    pub value: String,
    pub source: TokenSource,
}

/// Permutation rule that produced a candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Rule {
    DocHost,
    NumberStep,
    EnvSwap,
    CrossLevel,
    Version,
    EnvAffix,
    NumberSuffix,
    RoleAffix,
}

impl Rule {
    /// Stable identifier (for findings and report keys).
    pub fn as_str(self) -> &'static str {
        match self {
            Rule::DocHost => "doc_host",
            Rule::NumberStep => "number_step",
            Rule::EnvSwap => "env_swap",
            Rule::CrossLevel => "cross_level",
            Rule::Version => "version",
            Rule::EnvAffix => "env_affix",
            Rule::NumberSuffix => "number_suffix",
            Rule::RoleAffix => "role_affix",
        }
    }
}

/// A generated name and its provenance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Candidate {
    pub fqdn: String,
    pub rule: Rule,
    /// Known name the candidate was derived from, if any.
    pub seed: Option<String>,
    /// Token inserted by the rule, if any.
    pub token: Option<String>,
    pub source: TokenSource,
}

/// Permutation settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PermuteConfig {
    pub max_candidates: usize,
    /// Highest number used by number steps and suffixes.
    pub numbers: u32,
    pub env_words: bool,
    pub role_words: bool,
}

impl Default for PermuteConfig {
    fn default() -> Self {
        PermuteConfig {
            max_candidates: 3000,
            numbers: 5,
            env_words: true,
            role_words: true,
        }
    }
}

fn is_ip_like(s: &str) -> bool {
    s.parse::<std::net::IpAddr>().is_ok()
        || s.split(['.', '-']).filter(|p| !p.is_empty()).count() == 4
            && s.split(['.', '-']).all(|p| p.parse::<u8>().is_ok())
}

/// Normalizes a host-like token: lowercase, `_` and spaces are not allowed, 2-40 characters,
/// not purely numeric, not an IP address and not a generic word.
fn clean_token(s: &str) -> Option<String> {
    let t = s
        .trim()
        .trim_matches(['"', '\'', '[', ']'])
        .to_ascii_lowercase();
    if t.len() < 2 || t.len() > 40 || is_ip_like(&t) || t.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    if !valid_label(&t) || t.contains('_') || STOP_TOKENS.contains(&t.as_str()) {
        return None;
    }
    Some(t)
}

/// Extracts a host token from a metadata value: the server of a UNC path (`\\SRV-FS01\share`),
/// the host of a URL, the first label of an internal FQDN (`printer-hr.corp.local`) or a bare
/// host name (`SRV-DC01`). Returns `None` for free text, IP addresses, drive paths and generic
/// words.
pub fn token_from_metadata(value: &str) -> Option<String> {
    let v = value.trim();
    let host = if let Some(rest) = v.strip_prefix("\\\\").or_else(|| v.strip_prefix("//")) {
        rest.split(['\\', '/']).next().unwrap_or("")
    } else if let Some((_, rest)) = v.split_once("://") {
        let h = rest.split(['/', '?', '#']).next().unwrap_or("");
        let h = h.rsplit('@').next().unwrap_or(h);
        h.split(':').next().unwrap_or("")
    } else if v.contains(char::is_whitespace) || v.contains(['\\', '/', ':', '@']) {
        return None;
    } else {
        v
    };
    let host = norm_name(host);
    if is_ip_like(&host) {
        return None;
    }
    let labels: Vec<&str> = host.split('.').collect();
    let first = match labels.len() {
        0 => return None,
        1 => labels[0],
        _ => {
            // a public FQDN is a host of some zone, not an internal name; keep internal ones only
            let last = labels[labels.len() - 1];
            if !INTERNAL_SUFFIXES.contains(&last) {
                return None;
            }
            labels[0]
        }
    };
    clean_token(first)
}

/// Collects host tokens from `(document, metadata value)` pairs, deduplicated by value (the first
/// document wins).
pub fn tokens_from_metadata<'a, I>(items: I) -> Vec<Token>
where
    I: IntoIterator<Item = (&'a str, &'a str)>,
{
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for (doc, value) in items {
        if let Some(t) = token_from_metadata(value) {
            if seen.insert(t.clone()) {
                out.push(Token {
                    value: t,
                    source: TokenSource::Document {
                        name: doc.to_string(),
                    },
                });
            }
        }
    }
    out
}

/// Splits a label into the parts before, inside and after its last digit run
/// (`api01` gives `("api", "01", "")`).
fn last_number(label: &str) -> Option<(&str, &str, &str)> {
    let b = label.as_bytes();
    let end = b.iter().rposition(|c| c.is_ascii_digit())? + 1;
    let start = b[..end]
        .iter()
        .rposition(|c| !c.is_ascii_digit())
        .map_or(0, |i| i + 1);
    Some((&label[..start], &label[start..end], &label[end..]))
}

/// Splits a label into words on `-` (`dev-api-eu` gives `dev`, `api`, `eu`).
fn words(label: &str) -> Vec<&str> {
    label.split('-').filter(|w| !w.is_empty()).collect()
}

struct Gen<'a> {
    root: String,
    max: usize,
    seen: HashSet<String>,
    out: Vec<Candidate>,
    _p: std::marker::PhantomData<&'a ()>,
}

impl Gen<'_> {
    fn full(&self) -> bool {
        self.out.len() >= self.max
    }

    /// Adds `label` (one or more labels) under `level` (relative to the root, may be empty).
    fn push(
        &mut self,
        label: &str,
        level: &str,
        rule: Rule,
        seed: Option<&str>,
        token: Option<&str>,
        source: &TokenSource,
    ) {
        if self.full() {
            return;
        }
        let fqdn = if level.is_empty() {
            format!("{label}.{}", self.root)
        } else {
            format!("{label}.{level}.{}", self.root)
        };
        if !valid_host(&fqdn) || !self.seen.insert(fqdn.clone()) {
            return;
        }
        self.out.push(Candidate {
            fqdn,
            rule,
            seed: seed.map(str::to_string),
            token: token.map(str::to_string),
            source: source.clone(),
        });
    }
}

/// Generates candidates from known names under `root` and extra tokens (see the module docs).
/// Known names, the root and names outside the root are never returned.
pub fn permute(
    root: &str,
    known: &[String],
    tokens: &[Token],
    cfg: &PermuteConfig,
) -> Vec<Candidate> {
    let root = norm_name(root);
    let suffix = format!(".{root}");
    // known names as (first label, level relative to the root)
    let mut seeds: Vec<(String, String, String)> = Vec::new();
    let mut levels: BTreeSet<String> = BTreeSet::new();
    let mut seen = HashSet::new();
    seen.insert(root.clone());
    for k in known {
        let k = norm_name(k);
        let Some(rel) = k.strip_suffix(&suffix) else {
            continue;
        };
        if !valid_host(&k) || !seen.insert(k.clone()) {
            continue;
        }
        let (first, level) = rel.split_once('.').unwrap_or((rel, ""));
        if first.starts_with('_') || first == "*" {
            continue;
        }
        levels.insert(level.to_string());
        // every proper ancestor inside the root is a level too
        let mut l = level;
        while let Some((_, up)) = l.split_once('.') {
            levels.insert(up.to_string());
            l = up;
        }
        seeds.push((k.clone(), first.to_string(), level.to_string()));
    }
    levels.insert(String::new());
    let mut g = Gen {
        root,
        max: cfg.max_candidates,
        seen,
        out: Vec::new(),
        _p: std::marker::PhantomData,
    };
    let sub = TokenSource::Subdomain;
    let builtin = TokenSource::Builtin;
    let n = cfg.numbers.max(1);

    // 1. metadata host tokens directly under the zone, then their number steps
    for t in tokens {
        g.push(&t.value, "", Rule::DocHost, None, Some(&t.value), &t.source);
    }
    for t in tokens {
        if let Some((pre, num, post)) = last_number(&t.value) {
            for i in 1..=n {
                let l = format!("{pre}{i:0w$}{post}", w = num.len());
                if l != t.value {
                    g.push(&l, "", Rule::DocHost, None, Some(&t.value), &t.source);
                }
            }
        }
    }
    // 2. number steps of known labels
    for (k, first, level) in &seeds {
        if let Some((pre, num, post)) = last_number(first) {
            let cur: u32 = num.parse().unwrap_or(0);
            for i in (1..=n.max(cur.saturating_add(2))).filter(|i| *i != cur) {
                let l = format!("{pre}{i:0w$}{post}", w = num.len());
                g.push(&l, level, Rule::NumberStep, Some(k), None, &sub);
            }
        }
    }
    // 3. environment swaps, in the first label and in the level
    if cfg.env_words {
        for (k, first, level) in &seeds {
            let ws = words(first);
            for (i, w) in ws.iter().enumerate() {
                if ENV_WORDS.contains(w) {
                    for e in ENV_WORDS.iter().filter(|e| *e != w) {
                        let mut v = ws.clone();
                        v[i] = e;
                        g.push(&v.join("-"), level, Rule::EnvSwap, Some(k), Some(e), &sub);
                    }
                }
            }
            let lv: Vec<&str> = level.split('.').collect();
            for (i, w) in lv.iter().enumerate() {
                if ENV_WORDS.contains(w) {
                    for e in ENV_WORDS.iter().filter(|e| *e != w) {
                        let mut v = lv.clone();
                        v[i] = e;
                        g.push(first, &v.join("."), Rule::EnvSwap, Some(k), Some(e), &sub);
                    }
                }
            }
        }
    }
    // 4. cross-pollination: first labels seen anywhere, under every known level
    let firsts: Vec<String> = {
        let mut s = BTreeMap::new();
        for (_, f, _) in &seeds {
            *s.entry(f.clone()).or_insert(0usize) += 1;
        }
        let mut v: Vec<(String, usize)> = s.into_iter().collect();
        v.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        v.into_iter().map(|x| x.0).collect()
    };
    for level in levels.iter().filter(|l| !l.is_empty()) {
        for f in &firsts {
            g.push(f, level, Rule::CrossLevel, None, Some(f), &sub);
        }
        for t in tokens {
            g.push(
                &t.value,
                level,
                Rule::CrossLevel,
                None,
                Some(&t.value),
                &t.source,
            );
        }
    }
    // 5. API versions
    for (k, first, level) in &seeds {
        let ws = words(first);
        let mut has_version = false;
        for (i, w) in ws.iter().enumerate() {
            if let Some(num) = w.strip_prefix('v').and_then(|x| x.parse::<u32>().ok()) {
                has_version = true;
                for j in 1..=3u32.max(num + 1) {
                    if j != num {
                        let mut v: Vec<String> = ws.iter().map(|s| s.to_string()).collect();
                        v[i] = format!("v{j}");
                        g.push(&v.join("-"), level, Rule::Version, Some(k), None, &sub);
                    }
                }
            }
        }
        if !has_version && ws.contains(&"api") {
            for j in 1..=3 {
                g.push(
                    &format!("{first}-v{j}"),
                    level,
                    Rule::Version,
                    Some(k),
                    None,
                    &sub,
                );
                g.push(
                    &format!("v{j}.{first}"),
                    level,
                    Rule::Version,
                    Some(k),
                    None,
                    &sub,
                );
            }
        }
    }
    // 6. environment affixes
    if cfg.env_words {
        for (k, first, level) in &seeds {
            if words(first).iter().any(|w| ENV_WORDS.contains(w)) {
                continue;
            }
            for e in ENV_WORDS {
                g.push(
                    &format!("{e}-{first}"),
                    level,
                    Rule::EnvAffix,
                    Some(k),
                    Some(e),
                    &builtin,
                );
                g.push(
                    &format!("{first}-{e}"),
                    level,
                    Rule::EnvAffix,
                    Some(k),
                    Some(e),
                    &builtin,
                );
                g.push(
                    &format!("{first}.{e}"),
                    level,
                    Rule::EnvAffix,
                    Some(k),
                    Some(e),
                    &builtin,
                );
            }
        }
    }
    // 7. number suffixes
    for (k, first, level) in &seeds {
        if last_number(first).is_some() {
            continue;
        }
        for i in 1..=n.min(3) {
            g.push(
                &format!("{first}{i}"),
                level,
                Rule::NumberSuffix,
                Some(k),
                None,
                &sub,
            );
            g.push(
                &format!("{first}-{i}"),
                level,
                Rule::NumberSuffix,
                Some(k),
                None,
                &sub,
            );
            g.push(
                &format!("{first}{i:02}"),
                level,
                Rule::NumberSuffix,
                Some(k),
                None,
                &sub,
            );
        }
    }
    // 8. role words
    if cfg.role_words {
        for level in &levels {
            for w in ROLE_WORDS {
                g.push(w, level, Rule::RoleAffix, None, Some(w), &builtin);
            }
        }
        for (k, first, level) in &seeds {
            for w in ROLE_WORDS.iter().filter(|w| !words(first).contains(w)) {
                g.push(
                    &format!("{w}-{first}"),
                    level,
                    Rule::RoleAffix,
                    Some(k),
                    Some(w),
                    &builtin,
                );
                g.push(
                    &format!("{first}-{w}"),
                    level,
                    Rule::RoleAffix,
                    Some(k),
                    Some(w),
                    &builtin,
                );
            }
        }
    }
    g.out
}

/// A resolved permutation with its provenance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PermuteHit {
    pub hit: BruteHit,
    pub candidate: Candidate,
}

/// Result of [`permute_and_resolve`].
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct PermuteReport {
    pub generated: usize,
    pub hits: Vec<PermuteHit>,
    /// Resolution details (wildcard levels, filtered and unverified names, pace).
    pub resolution: BruteReport,
}

/// Generates candidates and resolves them (target-touching, standard profile; see
/// [`crate::bruteforce`] for access rules).
///
/// # Errors
///
/// Fails before any query if the zone is not allowed, and on cancellation.
pub async fn permute_and_resolve(
    net: &NetClient,
    resolvers: &Resolvers,
    root: &str,
    known: &[String],
    tokens: &[Token],
    pcfg: &PermuteConfig,
    bcfg: &BruteConfig,
) -> Result<PermuteReport, NetError> {
    let cands = permute(root, known, tokens, pcfg);
    let names: Vec<String> = cands.iter().map(|c| c.fqdn.clone()).collect();
    let mut res = bruteforce::resolve_candidates(net, resolvers, root, names, bcfg).await?;
    let mut by_name: BTreeMap<String, Candidate> =
        cands.into_iter().map(|c| (c.fqdn.clone(), c)).collect();
    let generated = by_name.len();
    let hits = std::mem::take(&mut res.hits)
        .into_iter()
        .filter_map(|h| {
            let c = by_name.remove(&h.host)?;
            Some(PermuteHit {
                hit: h,
                candidate: c,
            })
        })
        .collect::<Vec<_>>();
    res.hits = hits.iter().map(|h| h.hit.clone()).collect();
    Ok(PermuteReport {
        generated,
        hits,
        resolution: res,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bruteforce::testdns::FakeDns;
    use crate::bruteforce::Pace;
    use std::sync::Arc;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    fn names(c: &[Candidate]) -> Vec<&str> {
        c.iter().map(|x| x.fqdn.as_str()).collect()
    }

    #[test]
    fn metadata_tokens() {
        assert_eq!(
            token_from_metadata(r"\\SRV-FS01\Buh\report.xlsx").as_deref(),
            Some("srv-fs01")
        );
        assert_eq!(
            token_from_metadata("//nas02/share").as_deref(),
            Some("nas02")
        );
        assert_eq!(
            token_from_metadata("printer-hr.corp.local").as_deref(),
            Some("printer-hr")
        );
        assert_eq!(
            token_from_metadata("http://intranet.lan:8080/x").as_deref(),
            Some("intranet")
        );
        assert_eq!(token_from_metadata("SRV-DC01").as_deref(), Some("srv-dc01"));
        for bad in [
            "HP LaserJet 4250",
            r"C:\Users\ivan\doc.docx",
            "10.0.0.5",
            r"\\10.1.2.3\c$",
            "www.google.com",
            "localhost",
            "12345",
            "x",
            "svc_account",
        ] {
            assert_eq!(token_from_metadata(bad), None, "{bad}");
        }
        let t = tokens_from_metadata([
            ("a.docx", r"\\SRV-FS01\x"),
            ("b.pdf", "srv-fs01.corp.local"),
            ("b.pdf", "John Smith"),
        ]);
        assert_eq!(t.len(), 1);
        assert_eq!(
            t[0].source,
            TokenSource::Document {
                name: "a.docx".into()
            }
        );
    }

    #[test]
    fn rules_and_provenance() {
        let known = s(&[
            "api01.ex.ua",
            "dev-shop.ex.ua",
            "www.eu.ex.ua",
            "v1.api.ex.ua",
            "mail.ex.ua",
            "ex.ua",
            "other.org",
        ]);
        let tokens = tokens_from_metadata([("plan.docx", r"\\srv-fs01\buh")]);
        let c = permute("ex.ua", &known, &tokens, &PermuteConfig::default());
        let n = names(&c);
        for want in [
            "srv-fs01.ex.ua",
            "srv-fs02.ex.ua",
            "api02.ex.ua",
            "api05.ex.ua",
            "stage-shop.ex.ua",
            "mail.eu.ex.ua",
            "v2.api.ex.ua",
            "dev-mail.ex.ua",
            "mail-stage.ex.ua",
            "mail2.ex.ua",
            "admin.eu.ex.ua",
            "srv-fs01.eu.ex.ua",
        ] {
            assert!(n.contains(&want), "missing {want}");
        }
        for never in ["api01.ex.ua", "ex.ua", "mail.ex.ua", "other.org"] {
            assert!(!n.contains(&never), "{never}");
        }
        assert!(n.iter().all(|x| x.ends_with(".ex.ua")));
        let doc = c.iter().find(|x| x.fqdn == "srv-fs01.ex.ua").unwrap();
        assert_eq!(doc.rule, Rule::DocHost);
        assert_eq!(
            doc.source,
            TokenSource::Document {
                name: "plan.docx".into()
            }
        );
        let step = c.iter().find(|x| x.fqdn == "api02.ex.ua").unwrap();
        assert_eq!(
            (step.rule, step.seed.as_deref()),
            (Rule::NumberStep, Some("api01.ex.ua"))
        );
        // priority: metadata tokens come first, budget is respected
        assert_eq!(c[0].fqdn, "srv-fs01.ex.ua");
        let small = permute(
            "ex.ua",
            &known,
            &tokens,
            &PermuteConfig {
                max_candidates: 10,
                ..Default::default()
            },
        );
        assert_eq!(small.len(), 10);
        assert_eq!(names(&small), names(&c[..10]));
        let uniq: HashSet<&str> = n.iter().copied().collect();
        assert_eq!(uniq.len(), n.len());
    }

    #[tokio::test]
    async fn resolves_with_provenance() {
        let dns = Arc::new(
            FakeDns::new()
                .host("api01.zt.test", &["192.0.2.1"], 300)
                .host("api02.zt.test", &["192.0.2.2"], 300)
                .host("srv-fs01.zt.test", &["192.0.2.3"], 300),
        );
        let (scope, _) = foca_core::Scope::from_lines("zt.test", "");
        let mut cfg = crate::NetConfig::default();
        cfg.host_overrides
            .insert("zt.test".into(), vec!["127.0.0.1".parse().unwrap()]);
        let net = NetClient::new(cfg, scope, Arc::new(crate::MemorySink::new())).unwrap();
        let bcfg = BruteConfig {
            pace: Pace {
                initial_rps: 5000.0,
                max_rps: 10000.0,
                ..Pace::wifi()
            },
            ..Default::default()
        };
        let tokens = tokens_from_metadata([("plan.docx", r"\\SRV-FS01\x")]);
        let r = permute_and_resolve(
            &net,
            &bruteforce::Resolvers::single(dns.clone()),
            "zt.test",
            &s(&["api01.zt.test"]),
            &tokens,
            &PermuteConfig::default(),
            &bcfg,
        )
        .await
        .unwrap();
        let mut got: Vec<(&str, Rule)> = r
            .hits
            .iter()
            .map(|h| (h.hit.host.as_str(), h.candidate.rule))
            .collect();
        got.sort();
        assert_eq!(
            got,
            vec![
                ("api02.zt.test", Rule::NumberStep),
                ("srv-fs01.zt.test", Rule::DocHost)
            ]
        );
        assert!(r.generated > 10);
        // the passive profile makes no queries
        let before = dns.count();
        let (full, _) = foca_core::Scope::from_lines("zt.test", "");
        net.set_passive_guard(full, true);
        assert!(permute_and_resolve(
            &net,
            &bruteforce::Resolvers::single(dns.clone()),
            "zt.test",
            &s(&["api01.zt.test"]),
            &tokens,
            &PermuteConfig::default(),
            &bcfg,
        )
        .await
        .is_err());
        assert_eq!(dns.count(), before);
    }
}
