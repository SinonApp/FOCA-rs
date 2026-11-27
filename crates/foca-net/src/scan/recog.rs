//! Service banner fingerprints from Rapid7 Recog (BSD-2-Clause, Copyright (c) 2014-2015 Rapid7),
//! converted by `foca-analysis/signatures/tools/update_recog.py` into `data/recog.tsv.gz`.
//!
//! The port scanner's own signatures run first; Recog fills in the product, version and OS when
//! they found none. Banners are matched the way Recog expects them: SSH without the
//! `SSH-2.0-` prefix, FTP/SMTP/POP3/IMAP without the status code, HTTP as the `Server` value.

use std::io::Read;
use std::sync::{Arc, OnceLock, RwLock};

use regex::{Regex, RegexBuilder};

/// Converted Recog banner fingerprints (gzip TSV).
pub const RECOG_GZ: &[u8] = include_bytes!("../../data/recog.tsv.gz");

struct Fp {
    proto: String,
    icase: bool,
    src: String,
    product: String,
    version: String,
    os: String,
    cpe: String,
    re: OnceLock<Option<Regex>>,
}

impl Fp {
    fn re(&self) -> Option<&Regex> {
        self.re
            .get_or_init(|| {
                RegexBuilder::new(&self.src)
                    .case_insensitive(self.icase)
                    .size_limit(1 << 20)
                    .build()
                    .ok()
            })
            .as_ref()
    }
}

/// What a Recog fingerprint says about a banner.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RecogHit {
    pub product: Option<String>,
    pub version: Option<String>,
    pub os: Option<String>,
    pub cpe: Option<String>,
}

fn parse(gz: &[u8]) -> Result<Vec<Fp>, String> {
    let mut text = String::new();
    flate2::read::GzDecoder::new(gz)
        .read_to_string(&mut text)
        .map_err(|e| format!("gzip: {e}"))?;
    let mut out = Vec::new();
    for line in text
        .lines()
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
    {
        let f: Vec<&str> = line.split('\t').collect();
        let [proto, flags, src, product, version, os, cpe] = f[..] else {
            return Err(format!("bad row: {line}"));
        };
        out.push(Fp {
            proto: proto.into(),
            icase: flags == "i",
            src: src.into(),
            product: product.into(),
            version: version.into(),
            os: os.into(),
            cpe: cpe.into(),
            re: OnceLock::new(),
        });
    }
    Ok(out)
}

fn slot() -> &'static RwLock<Option<Arc<Vec<Fp>>>> {
    static S: RwLock<Option<Arc<Vec<Fp>>>> = RwLock::new(None);
    &S
}

fn table() -> Arc<Vec<Fp>> {
    if let Some(t) = slot().read().ok().and_then(|g| g.clone()) {
        return t;
    }
    let mut g = slot().write().unwrap_or_else(|e| e.into_inner());
    g.get_or_insert_with(|| Arc::new(parse(RECOG_GZ).unwrap_or_default()))
        .clone()
}

/// Replaces the table (a signed signature bundle); returns the fingerprint count.
pub fn install(gz: &[u8]) -> Result<usize, String> {
    let t = parse(gz)?;
    let n = t.len();
    *slot().write().unwrap_or_else(|e| e.into_inner()) = Some(Arc::new(t));
    Ok(n)
}

/// Parses a table without installing it; returns the fingerprint count.
pub fn check(gz: &[u8]) -> Result<usize, String> {
    parse(gz).map(|t| t.len())
}

/// Number of banner fingerprints in use.
pub fn count() -> usize {
    table().len()
}

/// Expands `$N` references (also inside text, `Ubuntu $2`) with capture groups.
fn expand(tpl: &str, c: &regex::Captures) -> Option<String> {
    if tpl.is_empty() {
        return None;
    }
    let mut out = String::new();
    let mut chars = tpl.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '$' && chars.peek().is_some_and(|d| d.is_ascii_digit()) {
            let mut n = 0usize;
            while let Some(d) = chars.peek().and_then(|d| d.to_digit(10)) {
                n = n * 10 + d as usize;
                chars.next();
            }
            out.push_str(c.get(n).map_or("", |m| m.as_str()));
        } else {
            out.push(ch);
        }
    }
    let v = out.split_whitespace().collect::<Vec<_>>().join(" ");
    (!v.is_empty()).then_some(v)
}

/// The banner as Recog expects it for `service`.
fn strip(service: &str, banner: &str) -> String {
    let b = banner.trim();
    let b = match service {
        // `SSH-2.0-OpenSSH_8.9p1 Ubuntu-3` -> `OpenSSH_8.9p1 Ubuntu-3`
        "ssh" if b.starts_with("SSH-") => b.splitn(3, '-').nth(2).unwrap_or(b),
        "ftp" | "smtp" | "submission" | "smtps" => b
            .get(4..)
            .filter(|_| b.len() > 4 && b.as_bytes()[..3].iter().all(u8::is_ascii_digit))
            .unwrap_or(b),
        "pop3" | "pop3s" => b.strip_prefix("+OK").unwrap_or(b),
        "imap" | "imaps" => b.strip_prefix("* OK").unwrap_or(b),
        "http" | "https" => b
            .strip_prefix("Server:")
            .or_else(|| b.strip_prefix("server:"))
            .unwrap_or(b),
        _ => b,
    };
    b.trim().to_string()
}

/// Matches a banner of `service` (`ssh`, `ftp`, `smtp`, `pop3`, `imap`, `telnet`, `http`).
pub fn match_banner(service: &str, banner: &str) -> Option<RecogHit> {
    let proto = match service {
        "submission" | "smtps" => "smtp",
        "pop3s" => "pop3",
        "imaps" => "imap",
        "https" => "http",
        s => s,
    };
    let text = strip(service, banner);
    if text.is_empty() {
        return None;
    }
    let t = table();
    t.iter().filter(|f| f.proto == proto).find_map(|f| {
        let c = f.re()?.captures(&text)?;
        let version = expand(&f.version, &c);
        let cpe = (!f.cpe.is_empty()).then(|| {
            f.cpe
                .replace("{service.version}", version.as_deref().unwrap_or("-"))
        });
        Some(RecogHit {
            product: expand(&f.product, &c),
            version,
            os: expand(&f.os, &c),
            cpe,
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_loads_and_matches_banners() {
        assert!(count() > 1000, "{}", count());
        let h = match_banner("ssh", "SSH-2.0-RomSShell_4.62").unwrap();
        assert_eq!(h.product.as_deref(), Some("Allegro Software RomSShell"));
        assert_eq!(h.version.as_deref(), Some("4.62"));
        let h = match_banner("ssh", "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6").unwrap();
        assert!(h.product.as_deref().unwrap().contains("OpenSSH"), "{h:?}");
        assert_eq!(h.version.as_deref(), Some("8.9p1"));
        assert!(h.os.as_deref().unwrap_or("").contains("Ubuntu"), "{h:?}");
        assert!(match_banner("ssh", "SSH-2.0-zzzz-unknown-zzzz").is_none());
    }

    #[test]
    fn strips_protocol_prefixes() {
        assert_eq!(
            strip("ftp", "220 ProFTPD Server ready"),
            "ProFTPD Server ready"
        );
        assert_eq!(strip("pop3", "+OK Dovecot ready."), "Dovecot ready.");
        assert_eq!(strip("http", "Server: nginx/1.18.0"), "nginx/1.18.0");
        assert_eq!(strip("ssh", "SSH-2.0-OpenSSH_9.6"), "OpenSSH_9.6");
    }
}
