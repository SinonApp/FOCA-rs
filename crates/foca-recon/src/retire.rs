//! JavaScript library versions and known vulnerable ranges from the Retire.js repository
//! (Apache-2.0, Copyright 2018 Erlend Oftedal), converted by
//! `foca-analysis/signatures/tools/update_retire.py` into `data/retire.json.gz`.
//!
//! A library version is extracted from the script URL (`uri`, `filename` extractors) or its
//! content (`filecontent`); the version is then checked against the `atOrAbove` / `below`
//! ranges. Extractors that need a JS engine (`func`, `ast`) are not shipped.

use std::io::Read;
use std::sync::{Arc, OnceLock, RwLock};

use foca_core::Severity;
use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::tech::version_lt;

/// Converted Retire.js repository (gzip JSON).
pub const RETIRE_GZ: &[u8] = include_bytes!("../data/retire.json.gz");

#[derive(Deserialize)]
struct RepoFile {
    libraries: Vec<LibDef>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct LibDef {
    n: String,
    u: Vec<String>,
    f: Vec<String>,
    c: Vec<String>,
    v: Vec<VulnDef>,
}

#[derive(Deserialize, Default, Clone)]
#[serde(default)]
struct VulnDef {
    a: Option<String>,
    b: String,
    s: String,
    cve: Vec<String>,
    cwe: Vec<String>,
    ghsa: Option<String>,
    t: Option<String>,
}

struct Extractor {
    src: String,
    re: OnceLock<Option<Regex>>,
}

impl Extractor {
    fn version(&self, s: &str) -> Option<String> {
        let re = self
            .re
            .get_or_init(|| Regex::new(&self.src).ok())
            .as_ref()?;
        let c = re.captures(s)?;
        c.iter()
            .skip(1)
            .flatten()
            .map(|m| clean_version(m.as_str()))
            .find(|v| v.starts_with(|ch: char| ch.is_ascii_digit()))
    }
}

/// The greedy version class also takes build suffixes (`1.12.4.min` in `jquery-1.12.4.min.js`):
/// drop them.
fn clean_version(v: &str) -> String {
    let mut v = v.trim_end_matches(['.', '-', '_']);
    loop {
        let lower = v.to_ascii_lowercase();
        let cut = [
            "min",
            "slim",
            "pack",
            "prod",
            "production",
            "dev",
            "debug",
            "umd",
            "bundle",
        ]
        .iter()
        .find_map(|s| {
            let n = lower.len().checked_sub(s.len() + 1)?;
            (lower.ends_with(s) && matches!(&lower[n..n + 1], "." | "-" | "_")).then_some(n)
        });
        match cut {
            Some(n) => v = &v[..n],
            None => return v.to_string(),
        }
    }
}

struct Lib {
    name: String,
    uri: Vec<Extractor>,
    filename: Vec<Extractor>,
    content: Vec<Extractor>,
    vulns: Vec<VulnDef>,
}

/// A vulnerable range a detected library version falls into.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JsVuln {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub at_or_above: Option<String>,
    pub below: String,
    /// `low`, `medium`, `high` or `critical` (Retire.js severity).
    pub severity: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cves: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cwe: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ghsa: Option<String>,
    /// Upstream summary (English).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
}

/// A JavaScript library detected in a script with its version and vulnerable ranges.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JsLibrary {
    pub name: String,
    pub version: String,
    /// `uri`, `filename` or `content`.
    pub via: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub vulns: Vec<JsVuln>,
}

impl JsLibrary {
    /// Highest severity of the vulnerable ranges (`None` without any).
    pub fn severity(&self) -> Option<Severity> {
        self.vulns
            .iter()
            .map(|v| match v.severity.as_str() {
                "critical" => Severity::Critical,
                "high" => Severity::High,
                "medium" => Severity::Medium,
                _ => Severity::Low,
            })
            .max_by_key(|s| s.rank())
    }
}

fn parse(gz: &[u8]) -> Result<Vec<Lib>, String> {
    let mut text = String::new();
    flate2::read::GzDecoder::new(gz)
        .read_to_string(&mut text)
        .map_err(|e| format!("gzip: {e}"))?;
    let f: RepoFile = serde_json::from_str(&text).map_err(|e| format!("json: {e}"))?;
    let ex = |v: Vec<String>| {
        v.into_iter()
            .map(|src| Extractor {
                src,
                re: OnceLock::new(),
            })
            .collect()
    };
    Ok(f.libraries
        .into_iter()
        .map(|l| Lib {
            name: l.n,
            uri: ex(l.u),
            filename: ex(l.f),
            content: ex(l.c),
            vulns: l.v,
        })
        .collect())
}

fn slot() -> &'static RwLock<Option<Arc<Vec<Lib>>>> {
    static S: RwLock<Option<Arc<Vec<Lib>>>> = RwLock::new(None);
    &S
}

fn libs() -> Arc<Vec<Lib>> {
    if let Some(l) = slot().read().ok().and_then(|g| g.clone()) {
        return l;
    }
    let mut g = slot().write().unwrap_or_else(|e| e.into_inner());
    g.get_or_insert_with(|| Arc::new(parse(RETIRE_GZ).unwrap_or_default()))
        .clone()
}

/// Replaces the table (a signed signature bundle); returns the library count.
pub fn install(gz: &[u8]) -> Result<usize, String> {
    let l = parse(gz)?;
    let n = l.len();
    *slot().write().unwrap_or_else(|e| e.into_inner()) = Some(Arc::new(l));
    Ok(n)
}

/// (libraries, vulnerable ranges) in use.
pub fn counts() -> (usize, usize) {
    let l = libs();
    (l.len(), l.iter().map(|x| x.vulns.len()).sum())
}

/// Whether `v` is inside `[at_or_above, below)`.
fn in_range(v: &str, at_or_above: Option<&str>, below: &str) -> bool {
    version_lt(v, below) && at_or_above.is_none_or(|a| !version_lt(v, a))
}

/// Detects libraries in a script: `url` is its address (may be empty), `content` its text (may
/// be empty when only the URL is known). One entry per library, URL evidence first.
pub fn detect(url: &str, content: &str) -> Vec<JsLibrary> {
    let file = url
        .split(['?', '#'])
        .next()
        .unwrap_or("")
        .rsplit('/')
        .next()
        .unwrap_or("");
    let mut cut = content.len().min(256 * 1024);
    while !content.is_char_boundary(cut) {
        cut -= 1;
    }
    let head = &content[..cut];
    let mut out = Vec::new();
    for l in libs().iter() {
        let hit = l
            .uri
            .iter()
            .find_map(|e| (!url.is_empty()).then(|| e.version(url)).flatten())
            .map(|v| (v, "uri"))
            .or_else(|| {
                l.filename
                    .iter()
                    .find_map(|e| (!file.is_empty()).then(|| e.version(file)).flatten())
                    .map(|v| (v, "filename"))
            })
            .or_else(|| {
                l.content
                    .iter()
                    .find_map(|e| (!head.is_empty()).then(|| e.version(head)).flatten())
                    .map(|v| (v, "content"))
            });
        let Some((version, via)) = hit else { continue };
        let vulns = l
            .vulns
            .iter()
            .filter(|x| in_range(&version, x.a.as_deref(), &x.b))
            .map(|x| JsVuln {
                at_or_above: x.a.clone(),
                below: x.b.clone(),
                severity: x.s.clone(),
                cves: x.cve.clone(),
                cwe: x.cwe.clone(),
                ghsa: x.ghsa.clone(),
                summary: x.t.clone(),
            })
            .collect();
        out.push(JsLibrary {
            name: l.name.clone(),
            version,
            via: via.into(),
            vulns,
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_loads() {
        let (n, v) = counts();
        assert!(n > 60, "{n}");
        assert!(v > 700, "{v}");
    }

    #[test]
    fn detects_versions_and_vulnerable_ranges() {
        let l = detect("https://cdn.example/js/jquery-1.12.4.min.js", "");
        let jq = l.iter().find(|x| x.name == "jquery").unwrap();
        assert_eq!(jq.version, "1.12.4");
        assert_eq!(jq.via, "filename");
        assert!(jq
            .vulns
            .iter()
            .any(|v| v.cves.contains(&"CVE-2020-11022".into())));
        assert_eq!(jq.severity(), Some(Severity::Medium));
        // From the banner comment in the file content.
        let l = detect(
            "",
            "/*! jQuery v3.7.1 | (c) OpenJS Foundation */\n!function(){}",
        );
        let jq = l.iter().find(|x| x.name == "jquery").unwrap();
        assert_eq!(jq.version, "3.7.1");
        assert!(jq.vulns.is_empty(), "{:?}", jq.vulns);
        assert!(detect("https://example.com/app.js", "console.log(1)").is_empty());
    }

    #[test]
    fn build_suffixes_are_dropped() {
        assert_eq!(clean_version("1.12.4.min"), "1.12.4");
        assert_eq!(clean_version("3.4.1.slim.min"), "3.4.1");
        assert_eq!(clean_version("2.0.0-beta1"), "2.0.0-beta1");
    }

    #[test]
    fn ranges() {
        assert!(in_range("1.12.4", None, "3.5.0"));
        assert!(!in_range("3.5.0", None, "3.5.0"));
        assert!(in_range("2.1.0", Some("2.0.0"), "2.2.0"));
        assert!(!in_range("1.9.0", Some("2.0.0"), "2.2.0"));
    }
}
