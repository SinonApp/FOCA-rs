//! Public Suffix List (MPL-2.0, Mozilla Foundation and contributors), shipped unmodified as
//! `data/public_suffix_list.dat.gz` by `foca-analysis/signatures/tools/update_psl.py`.
//!
//! [`registrable_domain`] implements the PSL algorithm (normal, wildcard and exception rules,
//! ICANN and private sections, the implicit `*` rule): `www.shop.example.com.ua` ->
//! `example.com.ua`, `user.github.io` -> `user.github.io`.

use std::collections::HashSet;
use std::io::Read;
use std::sync::{Arc, RwLock};

/// The list, gzip-compressed, byte for byte as published.
pub const PSL_GZ: &[u8] = include_bytes!("../../data/public_suffix_list.dat.gz");

/// Parsed rules (ASCII/punycode, lowercase).
#[derive(Debug, Default)]
pub struct Psl {
    rules: HashSet<String>,
    /// `*.X` rules, stored as `X`.
    wild: HashSet<String>,
    /// `!X` rules, stored as `X`.
    exc: HashSet<String>,
}

fn ascii(rule: &str) -> String {
    idna::domain_to_ascii(rule).unwrap_or_else(|_| rule.to_ascii_lowercase())
}

impl Psl {
    /// Parses the list text.
    pub fn parse(text: &str) -> Psl {
        let mut p = Psl::default();
        for line in text.lines() {
            let r = line.split_whitespace().next().unwrap_or("");
            if r.is_empty() || r.starts_with("//") {
                continue;
            }
            if let Some(x) = r.strip_prefix('!') {
                p.exc.insert(ascii(x));
            } else if let Some(x) = r.strip_prefix("*.") {
                p.wild.insert(ascii(x));
            } else {
                p.rules.insert(ascii(r));
            }
        }
        p
    }

    /// Gunzips and parses a list.
    pub fn from_gz(gz: &[u8]) -> Result<Psl, String> {
        let mut text = String::new();
        flate2::read::GzDecoder::new(gz)
            .read_to_string(&mut text)
            .map_err(|e| format!("gzip: {e}"))?;
        let p = Psl::parse(&text);
        if p.len() < 100 {
            return Err("public suffix list: too few rules".into());
        }
        Ok(p)
    }

    /// Number of rules.
    pub fn len(&self) -> usize {
        self.rules.len() + self.wild.len() + self.exc.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Number of labels of the public suffix of `labels`.
    fn suffix_len(&self, labels: &[&str]) -> usize {
        let n = labels.len();
        for i in 0..n {
            let cand = labels[i..].join(".");
            if self.exc.contains(&cand) {
                return n - i - 1;
            }
            if i + 1 < n && self.wild.contains(&labels[i + 1..].join(".")) {
                return n - i;
            }
            if self.rules.contains(&cand) {
                return n - i;
            }
        }
        1
    }

    /// Public suffix of a host name (`com.ua` for `shop.example.com.ua`).
    pub fn public_suffix(&self, name: &str) -> Option<String> {
        let n = norm(name)?;
        let labels: Vec<&str> = n.split('.').collect();
        let k = self.suffix_len(&labels);
        Some(labels[labels.len() - k..].join("."))
    }

    /// Registrable domain (public suffix plus one label); `None` for a bare public suffix, an IP
    /// address or an empty name.
    pub fn registrable_domain(&self, name: &str) -> Option<String> {
        let n = norm(name)?;
        let labels: Vec<&str> = n.split('.').collect();
        let k = self.suffix_len(&labels);
        (labels.len() > k).then(|| labels[labels.len() - k - 1..].join("."))
    }
}

fn norm(name: &str) -> Option<String> {
    let n = name
        .trim()
        .trim_start_matches("*.")
        .trim_end_matches('.')
        .to_ascii_lowercase();
    if n.is_empty() || n.parse::<std::net::IpAddr>().is_ok() || n.split('.').any(str::is_empty) {
        return None;
    }
    Some(if n.is_ascii() { n } else { ascii(&n) })
}

fn slot() -> &'static RwLock<Option<Arc<Psl>>> {
    static S: RwLock<Option<Arc<Psl>>> = RwLock::new(None);
    &S
}

/// The list in use (built-in unless a signature bundle installed a newer one).
pub fn list() -> Arc<Psl> {
    if let Some(p) = slot().read().ok().and_then(|g| g.clone()) {
        return p;
    }
    let mut g = slot().write().unwrap_or_else(|e| e.into_inner());
    g.get_or_insert_with(|| Arc::new(Psl::from_gz(PSL_GZ).unwrap_or_default()))
        .clone()
}

/// Replaces the list (a signed signature bundle); returns the rule count.
pub fn install(gz: &[u8]) -> Result<usize, String> {
    let p = Psl::from_gz(gz)?;
    let n = p.len();
    *slot().write().unwrap_or_else(|e| e.into_inner()) = Some(Arc::new(p));
    Ok(n)
}

/// Registrable domain of `name` with the list in use (see [`Psl::registrable_domain`]).
pub fn registrable_domain(name: &str) -> Option<String> {
    list().registrable_domain(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn psl_algorithm() {
        let p = list();
        assert!(p.len() > 9000, "{}", p.len());
        let r = |n: &str| p.registrable_domain(n);
        assert_eq!(r("www.example.com").as_deref(), Some("example.com"));
        assert_eq!(r("a.b.shop.com.ua").as_deref(), Some("shop.com.ua"));
        assert_eq!(r("mail.contoso.co.uk.").as_deref(), Some("contoso.co.uk"));
        assert_eq!(r("contoso.kiev.ua").as_deref(), Some("contoso.kiev.ua"));
        // Private section: each user site is its own registrable domain.
        assert_eq!(r("user.github.io").as_deref(), Some("user.github.io"));
        assert_eq!(r("x.y.user.github.io").as_deref(), Some("user.github.io"));
        // Wildcard and exception rules (`*.ck`, `!www.ck`).
        assert_eq!(r("a.b.ck").as_deref(), Some("a.b.ck"));
        assert_eq!(r("www.ck").as_deref(), Some("www.ck"));
        // Bare suffixes, IPs and unknown TLDs (implicit `*` rule).
        assert_eq!(r("com.ua"), None);
        assert_eq!(r("192.0.2.1"), None);
        assert_eq!(r("host.corp.internal").as_deref(), Some("corp.internal"));
        assert_eq!(p.public_suffix("x.shop.com.ua").as_deref(), Some("com.ua"));
        // IDN: Unicode rules are matched in punycode.
        assert_eq!(r("пример.укр").as_deref(), Some("xn--e1afmkfd.xn--j1amh"));
    }
}
