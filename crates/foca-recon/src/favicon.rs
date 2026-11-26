//! Favicon: Shodan-compatible hash (`http.favicon.hash`), sha256/md5, and discovery of
//! `<link rel=icon>` in HTML.
//!
//! The functions work on bytes and HTML that were already downloaded; the caller fetches the
//! icon itself (via `foca_net::NetClient` with `Access::TouchesTarget`).

use regex::Regex;
use serde::{Deserialize, Serialize};
use std::sync::OnceLock;
use url::Url;

use crate::hash::{base64_mime, md5_hex, murmur3_32, sha256_hex};

/// Icon hashes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FaviconHash {
    /// Signed MurmurHash3 x86_32 of the MIME base64 encoding, as searched in Shodan with
    /// `http.favicon.hash:<n>`.
    pub mmh3: i32,
    pub sha256: String,
    pub md5: String,
    pub size: usize,
    /// Ready-made pivot queries (Shodan, FOFA, Censys).
    pub queries: Vec<String>,
}

/// Computes the icon hashes from its bytes.
pub fn favicon_hash(bytes: &[u8]) -> FaviconHash {
    let mmh3 = murmur3_32(base64_mime(bytes).as_bytes(), 0);
    let md5 = md5_hex(bytes);
    FaviconHash {
        mmh3,
        sha256: sha256_hex(bytes),
        queries: vec![
            format!("shodan: http.favicon.hash:{mmh3}"),
            format!("fofa: icon_hash=\"{mmh3}\""),
            format!("censys: services.http.response.favicons.md5_hash:{md5}"),
        ],
        md5,
        size: bytes.len(),
    }
}

/// An icon link found in HTML.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IconLink {
    /// Absolute URL (resolved against `base`).
    pub url: String,
    /// The `rel` value (`icon`, `shortcut icon`, `apple-touch-icon`, `mask-icon`).
    pub rel: String,
    pub sizes: Option<String>,
    pub mime: Option<String>,
}

fn link_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?is)<link\b[^>]*>").expect("re"))
}

fn attr_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"(?is)([a-z_:-]+)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))"#).expect("re")
    })
}

/// Parses the attributes of an HTML tag (names lowercased).
pub(crate) fn attrs(tag: &str) -> Vec<(String, String)> {
    attr_re()
        .captures_iter(tag)
        .map(|c| {
            let v = c
                .get(2)
                .or_else(|| c.get(3))
                .or_else(|| c.get(4))
                .map(|m| m.as_str())
                .unwrap_or_default();
            (c[1].to_ascii_lowercase(), html_unescape(v))
        })
        .collect()
}

pub(crate) fn html_unescape(s: &str) -> String {
    s.replace("&amp;", "&")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
}

/// Finds `<link rel="icon" …>` (as well as `shortcut icon`, `apple-touch-icon`, `mask-icon`).
/// If there is none, returns `/favicon.ico` relative to `base` with `rel = "default"`.
pub fn find_icon_links(html: &str, base: &str) -> Vec<IconLink> {
    let base = Url::parse(base).ok();
    let mut out: Vec<IconLink> = Vec::new();
    for m in link_re().find_iter(html) {
        let a = attrs(m.as_str());
        let get = |k: &str| a.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone());
        let Some(rel) = get("rel") else { continue };
        let rl = rel.to_ascii_lowercase();
        if !rl
            .split_whitespace()
            .any(|t| t == "icon" || t == "apple-touch-icon" || t == "mask-icon")
        {
            continue;
        }
        let Some(href) = get("href") else { continue };
        let url = match &base {
            Some(b) => match b.join(href.trim()) {
                Ok(u) => u.to_string(),
                Err(_) => continue,
            },
            None => href.trim().to_string(),
        };
        if out.iter().any(|l| l.url == url) {
            continue;
        }
        out.push(IconLink {
            url,
            rel: rl,
            sizes: get("sizes"),
            mime: get("type"),
        });
    }
    if out.is_empty() {
        if let Some(u) = base.and_then(|b| b.join("/favicon.ico").ok()) {
            out.push(IconLink {
                url: u.to_string(),
                rel: "default".into(),
                sizes: None,
                mime: None,
            });
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_known_icon_bytes() {
        let d: Vec<u8> = (0..=255u8).cycle().take(768).collect();
        let h = favicon_hash(&d);
        assert_eq!(h.mmh3, 1836528006);
        assert_eq!(h.md5, "e6899eaaf06fd702f3ed3f988eb19362");
        assert_eq!(h.size, 768);
        assert!(h.queries[0].contains("1836528006"));
    }

    #[test]
    fn finds_icon_links() {
        let html = r#"<head><link rel="stylesheet" href="/a.css">
<LINK REL='shortcut icon' href="/static/fav.ico?v=1&amp;x=2" type="image/x-icon">
<link href="apple.png" rel="apple-touch-icon" sizes="180x180"></head>"#;
        let l = find_icon_links(html, "https://ex.com/dir/page.html");
        assert_eq!(l.len(), 2);
        assert_eq!(l[0].url, "https://ex.com/static/fav.ico?v=1&x=2");
        assert_eq!(l[0].mime.as_deref(), Some("image/x-icon"));
        assert_eq!(l[1].url, "https://ex.com/dir/apple.png");
        assert_eq!(l[1].sizes.as_deref(), Some("180x180"));
        let d = find_icon_links("<html></html>", "https://ex.com/x");
        assert_eq!(d[0].url, "https://ex.com/favicon.ico");
        assert_eq!(d[0].rel, "default");
    }
}
