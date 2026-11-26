//! Site technology detection with Wappalyzer/webappanalyzer-style rules: response headers,
//! `<meta>` (generator and others), cookies, HTML regexes and `<script src>`. JS globals and
//! the DOM are unavailable (there is no JS engine), so such rules are not supported.
//!
//! Rules live in `data/tech.json` (embedded with `include_str!`, about 130 technologies,
//! GPL-3.0, hand-written with Wappalyzer's key format). The version is the first non-empty
//! capture group. Analytics and advertising ids ([`extract_analytics_ids`]) are extracted as
//! well, as pivots for finding related sites.

use std::collections::BTreeMap;
use std::sync::OnceLock;

use regex::{Regex, RegexBuilder};
use serde::{Deserialize, Serialize};

use crate::favicon::attrs;

const RULES_JSON: &str = include_str!("../data/tech.json");

/// A technology rule (as in `data/tech.json`).
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct TechRule {
    pub name: String,
    pub cat: String,
    /// Header (lowercase) → regex for its value (empty means presence is enough).
    pub headers: BTreeMap<String, String>,
    /// `<meta name|property>` → regex for `content`.
    pub meta: BTreeMap<String, String>,
    /// Cookie name (or prefix) → regex for its value.
    pub cookies: BTreeMap<String, String>,
    pub html: Vec<String>,
    pub scripts: Vec<String>,
    pub implies: Vec<String>,
    /// Versions below this one are outdated (produces an outdated version finding).
    pub outdated_below: Option<String>,
    /// The whole branch is out of support (reason text).
    pub eol: Option<String>,
    /// End-of-life release branches (ascending): a detected version whose branch is at or below
    /// `upto` is reported as unsupported since `date`.
    pub eol_branches: Vec<EolBranch>,
    pub website: Option<String>,
}

/// An unsupported release branch: versions up to `upto` (compared on its components, so `8.1`
/// covers `8.1.31`) are out of support since `date` (ISO).
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct EolBranch {
    pub upto: String,
    pub date: String,
}

/// Returns the end-of-life note for `version` from ascending `branches`, if any.
pub fn eol_branch_note(branches: &[EolBranch], version: &str) -> Option<String> {
    let b = branches.iter().find(|b| {
        let n = b.upto.split('.').count();
        let cut: Vec<&str> = version.split(['.', '-', '_']).take(n).collect();
        !cut.is_empty() && !version_lt(&b.upto, &cut.join("."))
    })?;
    Some(format!(
        "версия {version} не поддерживается: выпуски до {} включительно сняты с поддержки {}",
        b.upto, b.date
    ))
}

#[derive(Deserialize)]
struct RulesFile {
    technologies: Vec<TechRule>,
}

struct Compiled {
    rule: TechRule,
    headers: Vec<(String, Option<Regex>)>,
    meta: Vec<(String, Option<Regex>)>,
    cookies: Vec<(String, Option<Regex>)>,
    html: Vec<Regex>,
    scripts: Vec<Regex>,
}

fn re(p: &str) -> Option<Regex> {
    if p.is_empty() {
        return None;
    }
    RegexBuilder::new(p)
        .case_insensitive(true)
        .size_limit(1 << 20)
        .build()
        .ok()
}

fn compiled() -> &'static [Compiled] {
    static C: OnceLock<Vec<Compiled>> = OnceLock::new();
    C.get_or_init(|| {
        let f: RulesFile = serde_json::from_str(RULES_JSON).expect("data/tech.json");
        let kv = |m: &BTreeMap<String, String>| {
            m.iter()
                .map(|(k, v)| (k.to_ascii_lowercase(), re(v)))
                .collect::<Vec<_>>()
        };
        f.technologies
            .into_iter()
            .map(|r| Compiled {
                headers: kv(&r.headers),
                meta: kv(&r.meta),
                cookies: r.cookies.iter().map(|(k, v)| (k.clone(), re(v))).collect(),
                html: r.html.iter().filter_map(|p| re(p)).collect(),
                scripts: r.scripts.iter().filter_map(|p| re(p)).collect(),
                rule: r,
            })
            .collect()
    })
}

/// Returns all built-in rules.
pub fn rules() -> impl Iterator<Item = &'static TechRule> {
    compiled().iter().map(|c| &c.rule)
}

/// A downloaded page: URL, response headers (as received, case-insensitive) and HTML body.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct PageInput {
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub html: String,
}

/// A detected technology.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Technology {
    pub name: String,
    pub category: String,
    pub version: Option<String>,
    /// Confidence 0-100: header/meta/cookie 100, `script src` 75, HTML regex 50 (summed, capped
    /// at 100); technologies inferred via `implies` inherit the source's confidence.
    pub confidence: u8,
    /// Evidence (`header server: nginx/1.18.0`, `script: /js/jquery-1.12.4.min.js`, …).
    pub evidence: Vec<String>,
    /// Why the version is outdated, if it is.
    pub outdated: Option<String>,
    pub website: Option<String>,
}

/// Compares versions by numeric components (`1.12.4` < `3.5.0`).
pub fn version_lt(a: &str, b: &str) -> bool {
    let p = |s: &str| -> Vec<u64> {
        s.split(['.', '-', '_'])
            .map(|x| {
                x.chars()
                    .take_while(|c| c.is_ascii_digit())
                    .collect::<String>()
                    .parse()
                    .unwrap_or(0)
            })
            .collect()
    };
    let (x, y) = (p(a), p(b));
    for i in 0..x.len().max(y.len()) {
        let (u, v) = (
            x.get(i).copied().unwrap_or(0),
            y.get(i).copied().unwrap_or(0),
        );
        if u != v {
            return u < v;
        }
    }
    false
}

fn version_of(re: &Regex, s: &str) -> Option<Option<String>> {
    let c = re.captures(s)?;
    let v = c
        .iter()
        .skip(1)
        .flatten()
        .map(|m| m.as_str().trim_matches('.').to_string())
        .find(|v| v.chars().any(|c| c.is_ascii_digit()));
    Some(v)
}

fn tag_re(name: &str) -> Regex {
    Regex::new(&format!(r"(?is)<{name}\b[^>]*>")).expect("re")
}

/// Extracts `<meta name|property|http-equiv=K content=V>` as (lowercase k, v).
pub fn extract_meta(html: &str) -> Vec<(String, String)> {
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| tag_re("meta"));
    re.find_iter(html)
        .filter_map(|m| {
            let a = attrs(m.as_str());
            let get = |k: &str| a.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone());
            let k = get("name")
                .or_else(|| get("property"))
                .or_else(|| get("http-equiv"))?;
            Some((k.to_ascii_lowercase(), get("content").unwrap_or_default()))
        })
        .collect()
}

/// Returns the `src` values of all `<script src=…>` in document order.
pub fn extract_script_srcs(html: &str) -> Vec<String> {
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| tag_re("script"));
    re.find_iter(html)
        .filter_map(|m| {
            attrs(m.as_str())
                .into_iter()
                .find(|(n, _)| n == "src")
                .map(|(_, v)| v)
        })
        .collect()
}

/// Extracts cookies from `Set-Cookie` headers (name → value).
pub fn cookies_from_headers(headers: &[(String, String)]) -> Vec<(String, String)> {
    headers
        .iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case("set-cookie"))
        .filter_map(|(_, v)| {
            let first = v.split(';').next()?;
            let (n, val) = first.split_once('=').unwrap_or((first, ""));
            Some((n.trim().to_string(), val.trim().to_string()))
        })
        .collect()
}

#[derive(Default)]
struct Acc {
    conf: u32,
    version: Option<String>,
    evidence: Vec<String>,
}

impl Acc {
    fn hit(&mut self, conf: u32, v: Option<String>, ev: String) {
        self.conf += conf;
        if self.version.is_none() {
            self.version = v;
        }
        if self.evidence.len() < 5 && !self.evidence.contains(&ev) {
            self.evidence.push(ev);
        }
    }
}

fn clip(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        format!("{}…", s.chars().take(n).collect::<String>())
    }
}

/// Detects the technologies of a page. The order is deterministic: by category, then name.
pub fn detect(page: &PageInput) -> Vec<Technology> {
    let headers: Vec<(String, String)> = page
        .headers
        .iter()
        .map(|(k, v)| (k.to_ascii_lowercase(), v.clone()))
        .collect();
    let cookies = cookies_from_headers(&headers);
    let meta = extract_meta(&page.html);
    let scripts = extract_script_srcs(&page.html);
    let mut found: BTreeMap<String, Acc> = BTreeMap::new();
    for c in compiled() {
        let mut acc = Acc::default();
        for (h, r) in &c.headers {
            for (_, v) in headers.iter().filter(|(k, _)| k == h) {
                match r {
                    None => acc.hit(100, None, format!("header {h}")),
                    Some(r) => {
                        if let Some(ver) = version_of(r, v) {
                            acc.hit(100, ver, format!("header {h}: {}", clip(v, 80)));
                        }
                    }
                }
            }
        }
        for (m, r) in &c.meta {
            for (_, v) in meta.iter().filter(|(k, _)| k == m) {
                let hit = match r {
                    None => Some(None),
                    Some(r) => version_of(r, v),
                };
                if let Some(ver) = hit {
                    acc.hit(100, ver, format!("meta {m}: {}", clip(v, 80)));
                }
            }
        }
        for (name, r) in &c.cookies {
            for (n, v) in cookies.iter().filter(|(n, _)| n.starts_with(name.as_str())) {
                let hit = match r {
                    None => Some(None),
                    Some(r) => version_of(r, v),
                };
                if let Some(ver) = hit {
                    acc.hit(100, ver, format!("cookie {n}"));
                }
            }
        }
        for r in &c.scripts {
            for s in &scripts {
                if let Some(ver) = version_of(r, s) {
                    acc.hit(75, ver, format!("script: {}", clip(s, 120)));
                }
            }
        }
        for r in &c.html {
            if let Some(m) = r.find(&page.html) {
                let ver = version_of(r, m.as_str()).flatten();
                acc.hit(50, ver, format!("html: {}", clip(m.as_str(), 80)));
            }
        }
        if acc.conf > 0 {
            found.insert(c.rule.name.clone(), acc);
        }
    }
    // Resolve `implies` transitively, guarding against cycles.
    let mut queue: Vec<String> = found.keys().cloned().collect();
    while let Some(n) = queue.pop() {
        let Some(c) = compiled().iter().find(|c| c.rule.name == n) else {
            continue;
        };
        let conf = found.get(&n).map(|a| a.conf.min(100)).unwrap_or(0);
        for imp in &c.rule.implies {
            if !found.contains_key(imp) {
                let mut a = Acc::default();
                a.hit(conf, None, format!("implied by {n}"));
                found.insert(imp.clone(), a);
                queue.push(imp.clone());
            }
        }
    }
    let mut out: Vec<Technology> = found
        .into_iter()
        .filter_map(|(name, acc)| {
            let c = compiled().iter().find(|c| c.rule.name == name)?;
            let branch_eol = acc
                .version
                .as_deref()
                .and_then(|v| eol_branch_note(&c.rule.eol_branches, v));
            let outdated = match (&c.rule.eol, &c.rule.outdated_below, &acc.version) {
                (Some(e), _, _) => Some(e.clone()),
                _ if branch_eol.is_some() => branch_eol,
                (_, Some(min), Some(v)) if version_lt(v, min) => {
                    Some(format!("версия {v} старее {min}"))
                }
                _ => None,
            };
            Some(Technology {
                category: c.rule.cat.clone(),
                version: acc.version,
                confidence: acc.conf.min(100) as u8,
                evidence: acc.evidence,
                outdated,
                website: c.rule.website.clone(),
                name,
            })
        })
        .collect();
    out.sort_by(|a, b| a.category.cmp(&b.category).then(a.name.cmp(&b.name)));
    out
}

/// An analytics or advertising id, a pivot for finding other sites of the same owner.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct AnalyticsId {
    /// `ga-ua`, `ga4`, `gtm`, `google-ads`, `adsense`, `yandex-metrika`, `facebook-pixel`, `top-mail-ru`.
    pub kind: String,
    pub id: String,
}

fn analytics_res() -> &'static [(&'static str, Regex)] {
    static R: OnceLock<Vec<(&'static str, Regex)>> = OnceLock::new();
    R.get_or_init(|| {
        [
            ("ga-ua", r"\b(UA-\d{4,10}-\d{1,4})\b"),
            (
                "ga4",
                r#"(?:gtag\(\s*['"]config['"]\s*,\s*['"]|[?&]id=|['"]measurementId['"]\s*:\s*['"])(G-[A-Z0-9]{6,12})\b"#,
            ),
            ("gtm", r"\b(GTM-[A-Z0-9]{4,8})\b"),
            ("google-ads", r"\b(AW-\d{9,11})\b"),
            ("adsense", r"\b(ca-pub-\d{10,20})\b"),
            (
                "yandex-metrika",
                r#"(?:\bym\(\s*|mc\.yandex\.ru/watch/|yaCounter|['"]?counterId['"]?\s*:\s*['"]?)(\d{5,10})\b"#,
            ),
            (
                "facebook-pixel",
                r#"fbq\(\s*['"]init['"]\s*,\s*['"](\d{10,20})['"]"#,
            ),
            ("top-mail-ru", r"top-fwz1\.mail\.ru/counter\?id=(\d{5,10})"),
        ]
        .into_iter()
        .map(|(k, p)| (k, Regex::new(p).expect("re")))
        .collect()
    })
}

/// Extracts analytics ids (UA-/G-/GTM-/AW-/ca-pub-/Yandex Metrica/Pixel) from HTML or JS,
/// deduplicated and sorted.
pub fn extract_analytics_ids(text: &str) -> Vec<AnalyticsId> {
    let mut out = std::collections::BTreeSet::new();
    for (k, r) in analytics_res() {
        for c in r.captures_iter(text) {
            out.insert(AnalyticsId {
                kind: (*k).to_string(),
                id: c[1].to_string(),
            });
        }
    }
    out.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const WP: &str = include_str!("../tests/fixtures/wp_page.html");

    fn page() -> PageInput {
        PageInput {
            url: "https://ex.com/".into(),
            headers: vec![
                ("Server".into(), "nginx/1.18.0 (Ubuntu)".into()),
                ("X-Powered-By".into(), "PHP/7.4.3".into()),
                ("Set-Cookie".into(), "_ym_uid=123; path=/".into()),
                ("CF-RAY".into(), "abc-AMS".into()),
            ],
            html: WP.into(),
        }
    }

    fn get<'a>(t: &'a [Technology], n: &str) -> &'a Technology {
        t.iter()
            .find(|x| x.name == n)
            .unwrap_or_else(|| panic!("no {n}"))
    }

    #[test]
    fn eol_branches_flag_unsupported_versions() {
        let br = vec![
            EolBranch {
                upto: "7.4".into(),
                date: "2022-11-28".into(),
            },
            EolBranch {
                upto: "8.1".into(),
                date: "2025-12-31".into(),
            },
        ];
        assert!(eol_branch_note(&br, "8.1.31")
            .unwrap()
            .contains("2025-12-31"));
        assert!(eol_branch_note(&br, "7.2").unwrap().contains("2022-11-28"));
        assert_eq!(eol_branch_note(&br, "8.2.10"), None);
        assert_eq!(eol_branch_note(&br, "8.3"), None);
        // rules table: PHP 8.1, Apache 2.2, nginx 1.18 and jQuery 2.x are reported as out of support
        for (name, ver) in [
            ("PHP", "8.1.2"),
            ("Apache HTTP Server", "2.2.34"),
            ("Nginx", "1.18.0"),
            ("jQuery", "2.2.4"),
        ] {
            let r = compiled().iter().find(|c| c.rule.name == name).unwrap();
            let note = eol_branch_note(&r.rule.eol_branches, ver);
            assert!(note.is_some(), "{name} {ver}");
        }
        let php = compiled().iter().find(|c| c.rule.name == "PHP").unwrap();
        assert_eq!(eol_branch_note(&php.rule.eol_branches, "8.2.0"), None);
    }

    #[test]
    fn rules_load_and_compile() {
        let n = rules().count();
        assert!((100..=200).contains(&n), "{n}");
        for c in compiled() {
            assert_eq!(c.html.len(), c.rule.html.len(), "{}", c.rule.name);
            assert_eq!(c.scripts.len(), c.rule.scripts.len(), "{}", c.rule.name);
            for i in &c.rule.implies {
                assert!(rules().any(|r| &r.name == i), "{} implies {i}", c.rule.name);
            }
        }
    }

    #[test]
    fn detects_wordpress_stack_with_versions() {
        let t = detect(&page());
        let wp = get(&t, "WordPress");
        assert_eq!(wp.version.as_deref(), Some("5.8.1"));
        assert_eq!(wp.confidence, 100);
        assert!(wp.outdated.is_some());
        let jq = get(&t, "jQuery");
        assert_eq!(jq.version.as_deref(), Some("1.12.4"));
        // jQuery 1.x/2.x, nginx 1.18 and PHP 7.4 are end-of-life branches: the note names the date
        let jq_note = jq.outdated.as_deref().unwrap();
        assert!(
            jq_note.contains("не поддерживается") && jq_note.contains("2016-06-09"),
            "{jq_note}"
        );
        assert_eq!(get(&t, "Nginx").version.as_deref(), Some("1.18.0"));
        assert!(get(&t, "Nginx")
            .outdated
            .as_deref()
            .unwrap()
            .contains("2021-04-20"));
        assert_eq!(get(&t, "PHP").version.as_deref(), Some("7.4.3"));
        assert!(get(&t, "PHP")
            .outdated
            .as_deref()
            .unwrap()
            .contains("2022-11-28"));
        assert!(get(&t, "MySQL").evidence[0].contains("implied"));
        get(&t, "Ubuntu");
        get(&t, "Cloudflare");
        get(&t, "Yandex.Metrika");
        get(&t, "Google Tag Manager");
        assert_eq!(get(&t, "Bootstrap").version.as_deref(), Some("4.6.0"));
        assert!(t.iter().all(|x| x.name != "Drupal"));
    }

    #[test]
    fn analytics_pivots() {
        let ids = extract_analytics_ids(WP);
        let has = |k: &str, id: &str| ids.iter().any(|a| a.kind == k && a.id == id);
        assert!(has("ga-ua", "UA-1234567-1"), "{ids:?}");
        assert!(has("ga4", "G-ABCDEF1234"));
        assert!(has("gtm", "GTM-ABC12D"));
        assert!(has("yandex-metrika", "12345678"));
        assert!(has("adsense", "ca-pub-1234567890123456"));
        assert!(has("facebook-pixel", "112233445566778"));
    }

    #[test]
    fn coyote_is_tomcat_not_apache_httpd() {
        let p = PageInput {
            url: "http://t/".into(),
            headers: vec![("Server".into(), "Apache-Coyote/1.1".into())],
            html: String::new(),
        };
        let t = detect(&p);
        assert!(t.iter().all(|x| x.name != "Apache HTTP Server"), "{t:?}");
        assert_eq!(get(&t, "Apache Tomcat").version, None);
        let p2 = PageInput {
            headers: vec![("Server".into(), "Apache/2.4.41 (Ubuntu)".into())],
            ..p
        };
        assert_eq!(
            get(&detect(&p2), "Apache HTTP Server").version.as_deref(),
            Some("2.4.41")
        );
    }

    #[test]
    fn version_compare() {
        assert!(version_lt("1.12.4", "3.5.0"));
        assert!(!version_lt("3.5.0", "3.5"));
        assert!(version_lt("2.4.41", "2.4.58"));
        assert!(!version_lt("10.0", "10.0"));
    }
}
