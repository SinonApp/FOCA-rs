//! JavaScript source maps: references in collected scripts (`//# sourceMappingURL=`, the
//! `SourceMap` / `X-SourceMap` headers, inline `data:` maps) and parsing of a map into
//! original source paths, npm packages, developer file-system paths, URLs and masked secrets.
//!
//! * [`map_refs`] and [`parse_source_map`] are pure (access class `passive`).
//! * [`fetch_map`] is a GET to an in-scope host (access class `standard`,
//!   `Access::TouchesTarget`), body capped at [`MAX_MAP_BYTES`]; out-of-scope map URLs are
//!   never requested.
//!
//! Secrets in `sourcesContent` go through [`crate::js::find_secrets`], so only masked values
//! and fingerprints are kept; the source code itself is never stored.

use std::collections::BTreeSet;
use std::sync::OnceLock;

use regex::Regex;
use serde::{Deserialize, Serialize};

use foca_net::{Access, NetClient, NetRequest};

use crate::js::{find_secrets, SecretHit};
use crate::webaudit::fetch::read_capped;

/// Maximum source map size read from the network.
pub const MAX_MAP_BYTES: u64 = 8 << 20;
/// Maximum number of `sourcesContent` bytes scanned for secrets and URLs.
pub const MAX_CONTENT_SCAN: usize = 8 << 20;
/// Maximum number of source paths kept in the report.
pub const MAX_SOURCES_KEPT: usize = 300;

/// Request log module.
pub const MODULE: &str = "recon.sourcemap";

/// A reference from a script to its map.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MapRef {
    pub script_url: String,
    /// Absolute map URL, or `data:` for an inline map.
    pub map_url: String,
    /// `comment`, `header`, `inline` or `guess` (`<script>.map`).
    pub via: String,
}

/// What a source map reveals.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct SourceMapInfo {
    pub map_url: String,
    pub script_url: String,
    pub via: String,
    pub file: Option<String>,
    pub source_root: Option<String>,
    pub sources_total: usize,
    /// Original source paths (at most [`MAX_SOURCES_KEPT`]).
    pub sources: Vec<String>,
    /// npm packages from `node_modules` paths (`name` or `name@version`).
    pub packages: Vec<String>,
    /// Paths revealing the developer machine or server layout (`/home/<user>`, `C:\Users\…`).
    pub local_paths: Vec<String>,
    /// Absolute URLs found in `sourcesContent`.
    pub urls: Vec<String>,
    /// Secrets from `sourcesContent` (masked).
    pub secrets: Vec<SecretHit>,
    /// The map embeds the original code (`sourcesContent`).
    pub has_content: bool,
    /// The map was larger than the limit or not valid JSON; `sources` were recovered leniently.
    pub truncated: bool,
}

fn header<'a>(h: &'a [(String, String)], name: &str) -> Option<&'a str> {
    h.iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.trim())
}

fn res() -> &'static (Regex, Regex, Regex, Regex) {
    static R: OnceLock<(Regex, Regex, Regex, Regex)> = OnceLock::new();
    R.get_or_init(|| {
        (
            // Only the last comment counts, as in browsers.
            Regex::new(r"(?m)(?://[#@]|/\*[#@])\s*sourceMappingURL=([^\s*]+)").expect("re"),
            Regex::new(r"node_modules/(?:\.pnpm/)?((?:@[\w.-]+/)?[\w.-]+?)(?:@(\d+\.\d+\.\d+[\w.+-]*))?(?:/|$)").expect("re"),
            Regex::new(r#"(?i)(?:^|[\s"'(=])((?:/home/|/Users/|/root/|[a-z]:[\\/](?:Users|Documents and Settings)[\\/])[^\s"'):]+)"#).expect("re"),
            Regex::new(r#"https?://[A-Za-z0-9.-]+(?::\d+)?(?:/[^\s"'`<>\\)]*)?"#).expect("re"),
        )
    })
}

/// Finds map references of a downloaded script (no requests).
pub fn map_refs(script_url: &str, body: &str, headers: &[(String, String)]) -> Vec<MapRef> {
    let mut out = Vec::new();
    let base = url::Url::parse(script_url).ok();
    let mut push = |raw: &str, via: &str| {
        let raw = raw.trim();
        if raw.is_empty() {
            return;
        }
        if raw.starts_with("data:") {
            out.push(MapRef {
                script_url: script_url.into(),
                map_url: raw.into(),
                via: "inline".into(),
            });
            return;
        }
        let abs = match &base {
            Some(b) => b.join(raw).ok().map(|u| u.to_string()),
            None => url::Url::parse(raw).ok().map(|u| u.to_string()),
        };
        if let Some(u) = abs.filter(|u| u.starts_with("http://") || u.starts_with("https://")) {
            if !out.iter().any(|r: &MapRef| r.map_url == u) {
                out.push(MapRef {
                    script_url: script_url.into(),
                    map_url: u,
                    via: via.into(),
                });
            }
        }
    };
    for h in ["sourcemap", "x-sourcemap"] {
        if let Some(v) = header(headers, h) {
            push(v, "header");
        }
    }
    // Look only at the tail: the directive is at the end of the file.
    let tail_from = body.len().saturating_sub(64 << 10);
    let tail_from = (tail_from..body.len())
        .find(|&i| body.is_char_boundary(i))
        .unwrap_or(body.len());
    if let Some(c) = res().0.captures_iter(&body[tail_from..]).last() {
        push(&c[1], "comment");
    }
    out
}

/// Returns the conventional `<script>.map` URL for a `.js` script.
pub fn guess_url(script_url: &str) -> Option<String> {
    let mut u = url::Url::parse(script_url).ok()?;
    if !u.path().to_ascii_lowercase().ends_with(".js") {
        return None;
    }
    let p = format!("{}.map", u.path());
    u.set_path(&p);
    u.set_query(None);
    u.set_fragment(None);
    Some(u.to_string())
}

/// Decodes an inline `data:application/json;base64,...` map.
pub fn decode_data_url(u: &str) -> Option<Vec<u8>> {
    let (meta, data) = u.strip_prefix("data:")?.split_once(',')?;
    if meta.ends_with(";base64") {
        b64(data)
    } else {
        Some(
            url::form_urlencoded::parse(format!("x={data}").as_bytes())
                .next()
                .map(|(_, v)| v.into_owned().into_bytes())
                .unwrap_or_default(),
        )
    }
}

fn b64(s: &str) -> Option<Vec<u8>> {
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
            b'=' | b'\r' | b'\n' | b' ' => continue,
            _ => return None,
        };
        acc = (acc << 6) | u32::from(v);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    Some(out)
}

/// Returns `true` if the body looks like a source map (rejects HTML soft-404 pages).
pub fn looks_like_map(body: &[u8]) -> bool {
    let head = String::from_utf8_lossy(&body[..body.len().min(512)]);
    let t = head.trim_start_matches('\u{feff}').trim_start();
    let t = t.strip_prefix(")]}'").map_or(t, |r| r.trim_start());
    t.starts_with('{')
        && (head.contains("\"version\"")
            || head.contains("\"sources\"")
            || head.contains("\"mappings\""))
}

/// Parses a source map. `truncated` is set when the body was cut at the limit or is not valid
/// JSON; the `sources` array is then recovered leniently.
///
/// # Errors
///
/// Returns an error if the body is not a source map.
pub fn parse_source_map(map_url: &str, body: &[u8]) -> Result<SourceMapInfo, String> {
    if !looks_like_map(body) {
        return Err("не карта исходников (не JSON source map)".into());
    }
    let text = String::from_utf8_lossy(body);
    let text = text.trim_start_matches('\u{feff}').trim_start();
    let text = text.strip_prefix(")]}'").unwrap_or(text);
    let mut info = SourceMapInfo {
        map_url: map_url.into(),
        ..Default::default()
    };
    let mut sources: Vec<String> = Vec::new();
    let mut contents: Vec<String> = Vec::new();
    match serde_json::from_str::<serde_json::Value>(text) {
        Ok(v) => {
            let mut maps = vec![&v];
            // Index maps: `sections[].map`.
            if let Some(secs) = v.get("sections").and_then(|s| s.as_array()) {
                maps.extend(secs.iter().filter_map(|s| s.get("map")));
            }
            info.file = v.get("file").and_then(|s| s.as_str()).map(str::to_string);
            info.source_root = v
                .get("sourceRoot")
                .and_then(|s| s.as_str())
                .filter(|s| !s.is_empty())
                .map(str::to_string);
            for m in maps {
                if let Some(a) = m.get("sources").and_then(|s| s.as_array()) {
                    sources.extend(a.iter().filter_map(|s| s.as_str()).map(str::to_string));
                }
                if let Some(a) = m.get("sourcesContent").and_then(|s| s.as_array()) {
                    contents.extend(a.iter().filter_map(|s| s.as_str()).map(str::to_string));
                }
            }
        }
        Err(_) => {
            info.truncated = true;
            if let Some(i) = text.find("\"sources\"") {
                let rest = &text[i + 9..];
                let end = rest.find(']').unwrap_or(rest.len());
                static S: OnceLock<Regex> = OnceLock::new();
                let re = S.get_or_init(|| Regex::new(r#""((?:[^"\\]|\\.)*)""#).expect("re"));
                sources.extend(
                    re.captures_iter(&rest[..end])
                        .map(|c| c[1].replace("\\\\", "\\")),
                );
            }
            info.has_content = text.contains("\"sourcesContent\"");
        }
    }
    info.sources_total = sources.len();
    let (_, pkg_re, local_re, url_re) = res();
    let mut pkgs = BTreeSet::new();
    let mut local = BTreeSet::new();
    for s in &sources {
        for c in pkg_re.captures_iter(s) {
            let name = c[1].to_string();
            pkgs.insert(match c.get(2) {
                Some(v) => format!("{name}@{}", v.as_str()),
                None => name,
            });
        }
        let probe = format!(" {s}");
        if let Some(c) = local_re.captures(&probe) {
            local.insert(c[1].to_string());
        }
    }
    // Keep `name@ver` and drop the bare `name` duplicate.
    let versioned: BTreeSet<String> = pkgs
        .iter()
        .filter_map(|p| {
            p.rsplit_once('@')
                .filter(|(n, _)| !n.is_empty())
                .map(|(n, _)| n.to_string())
        })
        .collect();
    let has_ver = |p: &str| p.rsplit_once('@').is_some_and(|(n, _)| !n.is_empty());
    info.packages = pkgs
        .iter()
        .filter(|p| has_ver(p) || !versioned.contains(*p))
        .take(200)
        .cloned()
        .collect();
    let mut urls = BTreeSet::new();
    let mut secrets: Vec<SecretHit> = Vec::new();
    let mut scanned = 0usize;
    info.has_content |= !contents.is_empty();
    for c in &contents {
        if scanned >= MAX_CONTENT_SCAN {
            info.truncated = true;
            break;
        }
        scanned += c.len();
        for m in url_re.find_iter(c) {
            if urls.len() < 100 {
                urls.insert(m.as_str().trim_end_matches(['.', ',', ';']).to_string());
            }
        }
        for c2 in local_re.captures_iter(c) {
            if local.len() < 50 {
                local.insert(c2[1].to_string());
            }
        }
        for s in find_secrets(c) {
            if !secrets.iter().any(|x| x.fingerprint == s.fingerprint) && secrets.len() < 50 {
                secrets.push(s);
            }
        }
    }
    info.urls = urls.into_iter().collect();
    info.local_paths = local.into_iter().take(50).collect();
    info.secrets = secrets;
    sources.truncate(MAX_SOURCES_KEPT);
    info.sources = sources;
    Ok(info)
}

/// Downloads and parses a map from an in-scope host (`Access::TouchesTarget`, GET only).
///
/// # Errors
///
/// Returns an error for network failures, non-2xx statuses and bodies that are not maps.
pub async fn fetch_map(client: &NetClient, r: &MapRef) -> Result<SourceMapInfo, String> {
    let req =
        NetRequest::get(&r.map_url, MODULE, Access::TouchesTarget).map_err(|e| e.to_string())?;
    let resp = client
        .send(req)
        .await
        .and_then(|r| r.ensure_success())
        .map_err(|e| e.to_string())?;
    let (body, cut) = read_capped(resp, MAX_MAP_BYTES)
        .await
        .map_err(|e| e.to_string())?;
    let mut info = parse_source_map(&r.map_url, &body)?;
    info.truncated |= cut;
    info.script_url = r.script_url.clone();
    info.via = r.via.clone();
    Ok(info)
}

/// Parses an inline `data:` map (no request).
///
/// # Errors
///
/// Returns an error if the data URL cannot be decoded or is not a map.
pub fn parse_inline(r: &MapRef) -> Result<SourceMapInfo, String> {
    let body = decode_data_url(&r.map_url).ok_or("data: URL не декодируется")?;
    let mut info = parse_source_map("data:", &body)?;
    info.script_url = r.script_url.clone();
    info.via = r.via.clone();
    Ok(info)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refs_from_comment_header_and_inline() {
        let r = map_refs(
            "https://contoso.ua/static/app.min.js?v=3",
            "var a=1;\n//# sourceMappingURL=app.min.js.map",
            &[("X-SourceMap".into(), "/maps/app.map".into())],
        );
        let urls: Vec<&str> = r.iter().map(|r| r.map_url.as_str()).collect();
        assert_eq!(
            urls,
            [
                "https://contoso.ua/maps/app.map",
                "https://contoso.ua/static/app.min.js.map"
            ]
        );
        assert_eq!(r[0].via, "header");
        let r = map_refs("https://a.ua/x.js", "x\n/*# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbImEuanMiXX0= */", &[]);
        assert_eq!(r[0].via, "inline");
        let i = parse_inline(&r[0]).unwrap();
        assert_eq!(i.sources, ["a.js"]);
        assert_eq!(
            guess_url("https://a.ua/js/app.js?x=1").as_deref(),
            Some("https://a.ua/js/app.js.map")
        );
        assert_eq!(guess_url("https://a.ua/app.php"), None);
    }

    #[test]
    fn parse_reveals_packages_paths_urls_and_masks_secrets() {
        let map = serde_json::json!({
            "version": 3,
            "file": "app.js",
            "sources": [
                "webpack:///./src/api/client.ts",
                "webpack:///./node_modules/lodash/lodash.js",
                "webpack:///./node_modules/.pnpm/axios@0.21.1/node_modules/axios/index.js",
                "webpack:///./node_modules/@sentry/browser/esm/index.js",
                "/home/ivan/projects/portal/src/main.ts"
            ],
            "sourcesContent": [
                "const API = 'https://api.staging.contoso.ua/v2'; const key = 'AKIAZ7Q3RT5XW2LMNPV6';",
                "", "", "", ""
            ],
            "mappings": "AAAA"
        });
        let body = serde_json::to_vec(&map).unwrap();
        let i = parse_source_map("https://contoso.ua/app.js.map", &body).unwrap();
        assert_eq!(i.sources_total, 5);
        assert!(
            i.packages.contains(&"lodash".to_string()),
            "{:?}",
            i.packages
        );
        assert!(
            i.packages.contains(&"axios@0.21.1".to_string()),
            "{:?}",
            i.packages
        );
        assert!(
            !i.packages.contains(&"axios".to_string()),
            "{:?}",
            i.packages
        );
        assert!(i.packages.contains(&"@sentry/browser".to_string()));
        assert_eq!(i.local_paths, ["/home/ivan/projects/portal/src/main.ts"]);
        assert_eq!(i.urls, ["https://api.staging.contoso.ua/v2"]);
        assert_eq!(i.secrets.len(), 1);
        assert!(i.has_content);
        let ser = serde_json::to_string(&i).unwrap();
        assert!(!ser.contains("AKIAZ7Q3RT5XW2LMNPV6"), "secret leaked");
    }

    #[test]
    fn truncated_and_soft404() {
        let body = br#"{"version":3,"sources":["src/a.ts","node_modules/vue/dist/vue.js"],"sourcesContent":["very long"#;
        let i = parse_source_map("u", body).unwrap();
        assert!(i.truncated);
        assert_eq!(i.sources_total, 2);
        assert_eq!(i.packages, ["vue"]);
        assert!(parse_source_map("u", b"<!doctype html><html>404</html>").is_err());
    }
}
