//! grep.app: searches public GitHub code for mentions of a domain (no API key required).
//!
//! `GET https://grep.app/api/search?q=<query>&page=<n>` returns JSON
//! `{facets:{repo:{buckets:[{val,count}]},lang:{…}}, hits:{total, hits:[{repo, branch, path,
//! content:{snippet:"<table>…<mark>…</mark>…"}, total_matches:"15"|"100+"}]}}`.
//! The format is pinned by `tests/fixtures/grepapp_google.json` (fields are strings; the older
//! `{"raw": …}` format is still accepted). It is a third-party service, so requests use
//! `Access::Passive` and the `grepapp` module (rate limit in `NetConfig::source_rps["grepapp"]`).
//!
//! grep.app sits behind the Vercel Security Checkpoint: from datacenter IPs the API answers
//! `429 {"error":{"code":"challenge"}}`, reported as [`GrepAppError::Challenge`].

use foca_net::{Access, NetClient, NetError, NetRequest};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::favicon::html_unescape;

pub const DEFAULT_BASE: &str = "https://grep.app";
pub const MODULE: &str = "grepapp";

/// A match within a file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrepLine {
    pub line: u32,
    /// Line text without HTML markup.
    pub text: String,
    /// The line contains a highlighted match (`<mark>`).
    pub matched: bool,
}

/// A file that mentions the query.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrepHit {
    /// `owner/name`.
    pub repo: String,
    pub branch: String,
    pub path: String,
    /// Link to the file on GitHub.
    pub url: String,
    /// Number of matches in the file (`"100+"` → 100).
    pub total_matches: u32,
    pub lines: Vec<GrepLine>,
}

/// A page of results.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrepAppResult {
    pub query: String,
    pub total: u64,
    pub hits: Vec<GrepHit>,
    /// Top repositories (name, number of files).
    pub repos: Vec<(String, u64)>,
    /// Top languages.
    pub langs: Vec<(String, u64)>,
}

#[derive(Debug)]
pub enum GrepAppError {
    /// Vercel bot-protection challenge; the API is unavailable from this IP.
    Challenge,
    Net(NetError),
    Parse(String),
}

impl std::fmt::Display for GrepAppError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GrepAppError::Challenge => write!(f, "grep.app требует прохождения челленджа (429)"),
            GrepAppError::Net(e) => write!(f, "grep.app: {e}"),
            GrepAppError::Parse(e) => write!(f, "grep.app: разбор ответа: {e}"),
        }
    }
}

impl std::error::Error for GrepAppError {}

fn s(v: &Value) -> String {
    match v {
        Value::String(x) => x.clone(),
        Value::Number(n) => n.to_string(),
        Value::Object(o) => o.get("raw").map(s).unwrap_or_default(),
        _ => String::new(),
    }
}

fn strip_tags(h: &str) -> String {
    let mut out = String::with_capacity(h.len());
    let mut in_tag = false;
    for c in h.chars() {
        match c {
            '<' => in_tag = true,
            '>' if in_tag => in_tag = false,
            _ if !in_tag => out.push(c),
            _ => {}
        }
    }
    html_unescape(&out)
}

/// Splits a grep.app HTML snippet into lines.
pub fn parse_snippet(html: &str) -> Vec<GrepLine> {
    let mut out = Vec::new();
    for part in html.split("<tr data-line=\"").skip(1) {
        let Some((num, rest)) = part.split_once('"') else {
            continue;
        };
        let pre = rest
            .split_once("<pre>")
            .map(|(_, p)| p.split("</pre>").next().unwrap_or(""))
            .unwrap_or("");
        out.push(GrepLine {
            line: num.parse().unwrap_or(0),
            text: strip_tags(pre).trim_end().to_string(),
            matched: pre.contains("<mark"),
        });
    }
    out
}

/// Parses the JSON response of `/api/search`.
///
/// # Errors
///
/// Returns a [`GrepAppError`] if the response is a challenge or has an unexpected shape.
pub fn parse_response(query: &str, v: &Value) -> Result<GrepAppResult, GrepAppError> {
    if v.pointer("/error/code").and_then(Value::as_str) == Some("challenge") {
        return Err(GrepAppError::Challenge);
    }
    let hits_v = v
        .pointer("/hits/hits")
        .and_then(Value::as_array)
        .ok_or_else(|| GrepAppError::Parse("нет hits.hits".into()))?;
    let hits = hits_v
        .iter()
        .map(|h| {
            let repo = s(&h["repo"]);
            let branch = s(&h["branch"]);
            let path = s(&h["path"]);
            let tm = s(&h["total_matches"]);
            GrepHit {
                url: format!("https://github.com/{repo}/blob/{branch}/{path}"),
                total_matches: tm.trim_end_matches('+').parse().unwrap_or(0),
                lines: parse_snippet(
                    h.pointer("/content/snippet")
                        .and_then(Value::as_str)
                        .unwrap_or(""),
                ),
                repo,
                branch,
                path,
            }
        })
        .collect();
    let buckets = |p: &str| -> Vec<(String, u64)> {
        v.pointer(p)
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .map(|b| (s(&b["val"]), b["count"].as_u64().unwrap_or(0)))
                    .collect()
            })
            .unwrap_or_default()
    };
    Ok(GrepAppResult {
        query: query.to_string(),
        total: v
            .pointer("/hits/total")
            .and_then(Value::as_u64)
            .unwrap_or(0),
        hits,
        repos: buckets("/facets/repo/buckets"),
        langs: buckets("/facets/lang/buckets"),
    })
}

/// Builds the request URL (`base` is normally [`DEFAULT_BASE`], a local server in tests).
pub fn search_url(base: &str, query: &str, page: u32) -> String {
    let mut u =
        url::Url::parse(&format!("{}/api/search", base.trim_end_matches('/'))).expect("base url");
    u.query_pairs_mut()
        .append_pair("q", query)
        .append_pair("page", &page.max(1).to_string());
    u.to_string()
}

/// Sends one grep.app request through `NetClient` (passive, logged and rate limited by the
/// client). `query` is usually the target domain (`example.com`); `page` starts at 1.
pub async fn search(
    client: &NetClient,
    base: &str,
    query: &str,
    page: u32,
) -> Result<GrepAppResult, GrepAppError> {
    let req = NetRequest::get(&search_url(base, query, page), MODULE, Access::Passive)
        .map_err(GrepAppError::Net)?
        .header("Accept", "application/json")
        .retries(0);
    let resp = client.send(req).await.map_err(GrepAppError::Net)?;
    let status = resp.status();
    let body = resp
        .bytes_limited(8 << 20)
        .await
        .map_err(GrepAppError::Net)?;
    let v: Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(_) if status == 429 => return Err(GrepAppError::Challenge),
        Err(e) if (200..300).contains(&status) => return Err(GrepAppError::Parse(e.to_string())),
        Err(_) => return Err(GrepAppError::Net(NetError::Status(status))),
    };
    if !(200..300).contains(&status) {
        return match parse_response(query, &v) {
            Err(GrepAppError::Challenge) => Err(GrepAppError::Challenge),
            _ => Err(GrepAppError::Net(NetError::Status(status))),
        };
    }
    parse_response(query, &v)
}

#[cfg(test)]
mod tests {
    use super::*;

    const FX: &str = include_str!("../tests/fixtures/grepapp_google.json");

    #[test]
    fn parses_fixture() {
        let v: Value = serde_json::from_str(FX).unwrap();
        let r = parse_response("google.com", &v).unwrap();
        assert_eq!(r.total, 291);
        assert_eq!(r.hits.len(), 3);
        let h = &r.hits[0];
        assert_eq!(h.repo, "Significant-Gravitas/AutoGPT");
        assert_eq!(h.total_matches, 82);
        assert_eq!(h.url, "https://github.com/Significant-Gravitas/AutoGPT/blob/master/autogpt_platform/backend/backend/blocks/google/sheets.py");
        assert_eq!(h.lines.len(), 2);
        assert_eq!(h.lines[1].line, 58);
        assert!(h.lines[1].matched && !h.lines[0].matched);
        assert!(h.lines[1]
            .text
            .contains(">>> extract_spreadsheet_id(\"docs.google.com/"));
        assert_eq!(r.hits[1].total_matches, 100);
        assert_eq!(r.hits[2].repo, "old/format");
        assert_eq!(r.repos[0], ("Significant-Gravitas/AutoGPT".to_string(), 51));
        assert_eq!(r.langs[0].0, "Java");
    }

    #[test]
    fn challenge_detected() {
        let v: Value =
            serde_json::from_str(r#"{"error":{"code":"challenge","message":"x"}}"#).unwrap();
        assert!(matches!(
            parse_response("a", &v),
            Err(GrepAppError::Challenge)
        ));
        assert_eq!(
            search_url("https://grep.app/", "python.org", 0),
            "https://grep.app/api/search?q=python.org&page=1"
        );
    }
}
