//! Site technology detection with Wappalyzer-style rules.
//!
//! Static signals are evaluated over data the scan already fetched: response headers, `<meta>`
//! (generator and others), cookies, HTML regexes, `<script src>`, the page URL, the bodies of
//! fetched JavaScript files, the visible page text, stylesheets (inline `<style>` and fetched
//! files), the TLS certificate issuer and robots.txt ([`SiteExtra`]). Browser signals (global
//! JavaScript variables, DOM selectors, request hosts seen during a render) need a real browser:
//! [`browser::probe_script`] builds one bounded read-only script for the hidden Android WebView
//! and [`browser::BrowserSignals`] carries its answer back into [`detect_with`].
//!
//! Two rule sets are merged by technology name:
//! * `data/tech.json`: about 130 hand-written rules (GPL-3.0, part of FOCA-rs) with tuned
//!   categories, outdated thresholds and end-of-life branches; they win on conflicts;
//! * `data/webappanalyzer.json.gz`: the webappanalyzer fingerprints (GPL-3.0, enthec), converted
//!   by `foca-analysis/signatures/tools/update_webappanalyzer.py` (regexes the Rust engine rejects
//!   are dropped there). A signed signature bundle may replace this table at runtime
//!   ([`install_upstream`]).
//!
//! Upstream regexes carry a lowercase literal that every match must contain: one Aho-Corasick
//! pass over the page finds the present literals and only those regexes are compiled (lazily,
//! once) and run. The version is the upstream version template (`\1`, `\1?a:b`) or the first
//! non-empty capture group. Analytics and advertising ids ([`extract_analytics_ids`]) are
//! extracted as well, as pivots for finding related sites.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::Read;
use std::sync::{Arc, OnceLock, RwLock};

use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};
use regex::{Regex, RegexBuilder};
use serde::{Deserialize, Serialize};

use crate::favicon::attrs;

pub mod browser;
pub mod cmsparts;

use browser::{BrowserSignals, DomRule};

const RULES_JSON: &str = include_str!("../data/tech.json");
/// Converted webappanalyzer fingerprints (gzip JSON).
pub const UPSTREAM_GZ: &[u8] = include_bytes!("../data/webappanalyzer.json.gz");
/// endoflife.date release cycles past their end of life at the snapshot (gzip TSV, written by
/// `foca-analysis/signatures/tools/update_endoflife.py`).
pub const EOL_GZ: &[u8] = include_bytes!("../data/endoflife.tsv.gz");

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
    /// CPE 2.3 name (`cpe:2.3:a:f5:nginx:*:...`), from the upstream table.
    #[serde(skip)]
    pub cpe: Option<String>,
    /// Reported only together with one of these technologies.
    #[serde(skip)]
    pub requires: Vec<String>,
    /// Detecting this technology removes these ones.
    #[serde(skip)]
    pub excludes: Vec<String>,
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

/// A pattern: regex source, optional version template, confidence (0 = field default) and the
/// prefilter literal index. The regex is compiled on first use.
#[derive(Debug)]
struct Pat {
    src: String,
    ver: Option<String>,
    conf: u8,
    lit: Option<usize>,
    re: OnceLock<Option<Regex>>,
}

impl Pat {
    fn new(src: &str) -> Pat {
        Pat {
            src: src.to_string(),
            ver: None,
            conf: 0,
            lit: None,
            re: OnceLock::new(),
        }
    }

    /// `None` for an empty pattern (presence is enough) or one that does not compile.
    fn re(&self) -> Option<&Regex> {
        self.re.get_or_init(|| re(&self.src)).as_ref()
    }

    /// An upstream pattern `[regex, version template, confidence, literal]`; the literal is
    /// interned into `lits` (its index is the Aho-Corasick pattern id).
    fn upstream(
        v: &[serde_json::Value],
        lits: &mut Vec<String>,
        seen: &mut HashMap<String, usize>,
    ) -> Pat {
        let s = |i: usize| v.get(i).and_then(|x| x.as_str()).unwrap_or("");
        let mut p = Pat::new(s(0));
        p.ver = Some(s(1)).filter(|t| !t.is_empty()).map(String::from);
        p.conf = v
            .get(2)
            .and_then(|x| x.as_u64())
            .map_or(0, |c| c.min(100) as u8);
        let lit = s(3);
        if !lit.is_empty() {
            let next = lits.len();
            let id = *seen.entry(lit.to_string()).or_insert(next);
            if id == next {
                lits.push(lit.to_string());
            }
            p.lit = Some(id);
        }
        p
    }

    /// Presence is enough (no regex for the value).
    fn presence_only(&self) -> bool {
        self.src.is_empty()
    }

    /// Whether the prefilter allows a match: no literal, or its literal is in `present`.
    fn may_match(&self, present: &HashSet<usize>) -> bool {
        self.lit.is_none_or(|l| present.contains(&l))
    }

    fn weight(&self, base: u32) -> u32 {
        if self.conf == 0 {
            base
        } else {
            base * u32::from(self.conf.min(100)) / 100
        }
    }

    /// First match in `s`: (version, matched text). Presence-only patterns never match here.
    fn find<'s>(&self, s: &'s str) -> Option<(Option<String>, &'s str)> {
        let m = self.re()?.find(s)?;
        Some((self.version(m.as_str()).flatten(), m.as_str()))
    }

    /// `Some(version)` when `s` matches (presence-only patterns always match).
    fn version(&self, s: &str) -> Option<Option<String>> {
        if self.src.is_empty() {
            return Some(None);
        }
        let re = self.re()?;
        let c = re.captures(s)?;
        Some(match &self.ver {
            Some(t) => apply_version_template(t, &c),
            None => c
                .iter()
                .skip(1)
                .flatten()
                .map(|m| m.as_str().trim_matches('.').to_string())
                .find(|v| v.chars().any(|c| c.is_ascii_digit())),
        })
    }
}

/// Expands an upstream version template: `\1` is replaced by group 1, `\1?a:b` gives `a` when
/// group 1 matched and `b` otherwise. An empty result means no version.
pub fn apply_version_template(t: &str, c: &regex::Captures) -> Option<String> {
    let group = |i: usize| c.get(i).map(|m| m.as_str()).filter(|s| !s.is_empty());
    let b = t.as_bytes();
    let mut out = String::new();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'\\' && i + 1 < b.len() && b[i + 1].is_ascii_digit() {
            let g = usize::from(b[i + 1] - b'0');
            i += 2;
            if i < b.len() && b[i] == b'?' {
                // Ternary `\N?yes:no`: both branches run up to the next `:` / end.
                let rest = &t[i + 1..];
                let (yes, no) = rest.split_once(':').unwrap_or((rest, ""));
                out.push_str(if group(g).is_some() { yes } else { no });
                break;
            }
            out.push_str(group(g).unwrap_or(""));
        } else {
            let ch = t[i..].chars().next().unwrap_or(' ');
            out.push(ch);
            i += ch.len_utf8();
        }
    }
    let v = out.trim().trim_matches('.').to_string();
    (!v.is_empty() && v.chars().any(|c| c.is_ascii_alphanumeric())).then_some(v)
}

#[derive(Default)]
struct Compiled {
    rule: TechRule,
    headers: Vec<(String, Pat)>,
    meta: Vec<(String, Pat)>,
    cookies: Vec<(String, Pat)>,
    html: Vec<Pat>,
    /// `<script src>` URLs.
    scripts: Vec<Pat>,
    url: Vec<Pat>,
    /// Bodies of fetched JavaScript files (upstream `scripts`).
    js_files: Vec<Pat>,
    /// Visible page text.
    text: Vec<Pat>,
    /// Stylesheets: inline `<style>` and fetched CSS files.
    css: Vec<Pat>,
    /// TLS certificate issuer.
    cert: Vec<Pat>,
    robots: Vec<Pat>,
    /// Browser only: global JavaScript variable paths (`jQuery.fn.jquery`).
    globals: Vec<(String, Pat)>,
    /// Browser only: DOM selectors with conditions.
    dom: Vec<DomRule>,
    /// Browser only: hosts of requests made while the page rendered.
    xhr: Vec<Pat>,
}

/// An end-of-life release cycle of a technology (endoflife.date).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EolCycle {
    pub cycle: String,
    /// End-of-life date (ISO).
    pub date: String,
}

/// Parses the endoflife.date table into technology name -> cycles.
pub fn parse_eol(gz: &[u8]) -> Result<HashMap<String, Vec<EolCycle>>, String> {
    let mut text = String::new();
    flate2::read::GzDecoder::new(gz)
        .read_to_string(&mut text)
        .map_err(|e| format!("gzip: {e}"))?;
    let mut out: HashMap<String, Vec<EolCycle>> = HashMap::new();
    for line in text
        .lines()
        .filter(|l| !l.starts_with('#') && !l.is_empty())
    {
        let f: Vec<&str> = line.split('\t').collect();
        let [tech, _product, cycle, date, ..] = f[..] else {
            return Err(format!("bad row: {line}"));
        };
        out.entry(tech.to_string()).or_default().push(EolCycle {
            cycle: cycle.to_string(),
            date: date.to_string(),
        });
    }
    Ok(out)
}

/// End-of-life note for `version` when its release cycle (the version cut to the cycle's
/// component count, `8.1.31` -> `8.1`) is in `cycles`.
pub fn eol_cycle_note(cycles: &[EolCycle], version: &str) -> Option<String> {
    let c = cycles.iter().find(|c| {
        let n = c.cycle.split('.').count();
        let cut: Vec<&str> = version.split(['.', '-', '_']).take(n).collect();
        let cut = cut.join(".");
        cut.split('.').count() == n
            && cut.chars().next().is_some_and(|ch| ch.is_ascii_digit())
            && !version_lt(&cut, &c.cycle)
            && !version_lt(&c.cycle, &cut)
    })?;
    Some(format!(
        "версия {version} не поддерживается: ветка {} снята с поддержки {} (endoflife.date)",
        c.cycle, c.date
    ))
}

/// The merged rule database.
struct Db {
    techs: Vec<Compiled>,
    /// endoflife.date cycles by technology name.
    eol: HashMap<String, Vec<EolCycle>>,
    by_name: HashMap<String, usize>,
    /// WordPress `plugin:<slug>` / `theme:<slug>` directory names -> technology index.
    wp_slugs: HashMap<String, usize>,
    /// Prefilter over the literals of every upstream html/script/url pattern.
    lits: Option<AhoCorasick>,
    hand: usize,
    upstream: usize,
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

/// Upstream table as written by the ingest script.
#[derive(Deserialize)]
struct UpstreamFile {
    #[serde(default)]
    technologies: Vec<UpstreamTech>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct UpstreamTech {
    n: String,
    c: String,
    h: BTreeMap<String, Vec<Vec<serde_json::Value>>>,
    k: BTreeMap<String, Vec<Vec<serde_json::Value>>>,
    m: BTreeMap<String, Vec<Vec<serde_json::Value>>>,
    x: Vec<Vec<serde_json::Value>>,
    s: Vec<Vec<serde_json::Value>>,
    u: Vec<Vec<serde_json::Value>>,
    sc: Vec<Vec<serde_json::Value>>,
    t: Vec<Vec<serde_json::Value>>,
    y: Vec<Vec<serde_json::Value>>,
    ci: Vec<Vec<serde_json::Value>>,
    ro: Vec<Vec<serde_json::Value>>,
    g: BTreeMap<String, Vec<Vec<serde_json::Value>>>,
    d: Vec<browser::UpstreamDom>,
    q: Vec<Vec<serde_json::Value>>,
    /// WordPress plugin/theme directories: `[kind, slug]`.
    ps: Vec<Vec<String>>,
    i: Vec<String>,
    r: Vec<String>,
    e: Vec<String>,
    cpe: Option<String>,
    w: Option<String>,
}

/// Gunzips and parses an upstream table.
pub fn parse_upstream(gz: &[u8]) -> Result<usize, String> {
    Ok(read_upstream(gz)?.len())
}

fn read_upstream(gz: &[u8]) -> Result<Vec<UpstreamTech>, String> {
    let mut text = String::new();
    flate2::read::GzDecoder::new(gz)
        .read_to_string(&mut text)
        .map_err(|e| format!("gzip: {e}"))?;
    let f: UpstreamFile = serde_json::from_str(&text).map_err(|e| format!("json: {e}"))?;
    Ok(f.technologies)
}

fn build_db(upstream: Vec<UpstreamTech>, eol: HashMap<String, Vec<EolCycle>>) -> Db {
    let f: RulesFile = serde_json::from_str(RULES_JSON).expect("data/tech.json");
    let kv = |m: &BTreeMap<String, String>, lower: bool| {
        m.iter()
            .map(|(k, v)| {
                let k = if lower {
                    k.to_ascii_lowercase()
                } else {
                    k.clone()
                };
                (k, Pat::new(v))
            })
            .collect::<Vec<_>>()
    };
    let mut techs: Vec<Compiled> = f
        .technologies
        .into_iter()
        .map(|r| Compiled {
            headers: kv(&r.headers, true),
            meta: kv(&r.meta, true),
            cookies: kv(&r.cookies, false),
            html: r.html.iter().map(|p| Pat::new(p)).collect(),
            scripts: r.scripts.iter().map(|p| Pat::new(p)).collect(),
            rule: r,
            ..Compiled::default()
        })
        .collect();
    let hand = techs.len();
    let mut by_name: HashMap<String, usize> = techs
        .iter()
        .enumerate()
        .map(|(i, c)| (c.rule.name.clone(), i))
        .collect();
    let mut lits = Vec::new();
    let mut seen = HashMap::new();
    let mut wp_slugs = HashMap::new();
    let n_up = upstream.len();
    for u in upstream {
        let idx = match by_name.get(&u.n) {
            Some(&i) => i,
            None => {
                techs.push(Compiled {
                    rule: TechRule {
                        name: u.n.clone(),
                        cat: u.c.clone(),
                        ..TechRule::default()
                    },
                    ..Compiled::default()
                });
                by_name.insert(u.n.clone(), techs.len() - 1);
                techs.len() - 1
            }
        };
        let mut pats = |m: &BTreeMap<String, Vec<Vec<serde_json::Value>>>| {
            let mut out = Vec::new();
            for (k, ps) in m {
                for p in ps {
                    out.push((k.clone(), Pat::upstream(p, &mut lits, &mut seen)));
                }
            }
            out
        };
        let (h, k, m) = (pats(&u.h), pats(&u.k), pats(&u.m));
        let globals = pats(&u.g);
        let mut list = |v: &[Vec<serde_json::Value>]| {
            v.iter()
                .map(|p| Pat::upstream(p, &mut lits, &mut seen))
                .collect::<Vec<_>>()
        };
        let (x, s, url) = (list(&u.x), list(&u.s), list(&u.u));
        let (js_files, text, css) = (list(&u.sc), list(&u.t), list(&u.y));
        let (cert, robots, xhr) = (list(&u.ci), list(&u.ro), list(&u.q));
        let dom: Vec<DomRule> =
            u.d.iter()
                .map(|d| d.compile(&mut |p| Pat::upstream(p, &mut lits, &mut seen)))
                .collect();
        for p in &u.ps {
            if let [kind, slug] = &p[..] {
                wp_slugs.entry(format!("{kind}:{slug}")).or_insert(idx);
            }
        }
        let t = &mut techs[idx];
        t.headers.extend(h);
        t.cookies.extend(k);
        t.meta.extend(m);
        t.html.extend(x);
        t.scripts.extend(s);
        t.url.extend(url);
        t.js_files.extend(js_files);
        t.text.extend(text);
        t.css.extend(css);
        t.cert.extend(cert);
        t.robots.extend(robots);
        t.globals.extend(globals);
        t.dom.extend(dom);
        t.xhr.extend(xhr);
        for i in u.i {
            if !t.rule.implies.contains(&i) && i != t.rule.name {
                t.rule.implies.push(i);
            }
        }
        t.rule.requires = u.r;
        t.rule.excludes = u.e;
        if t.rule.cpe.is_none() {
            t.rule.cpe = u.cpe;
        }
        if t.rule.website.is_none() {
            t.rule.website = u.w;
        }
    }
    let lits = (!lits.is_empty()).then(|| {
        AhoCorasickBuilder::new()
            .ascii_case_insensitive(true)
            .match_kind(MatchKind::Standard)
            .build(&lits)
            .expect("literal prefilter")
    });
    Db {
        techs,
        eol,
        by_name,
        wp_slugs,
        lits,
        hand,
        upstream: n_up,
    }
}

fn db_slot() -> &'static RwLock<Option<Arc<Db>>> {
    static DB: RwLock<Option<Arc<Db>>> = RwLock::new(None);
    &DB
}

fn db() -> Arc<Db> {
    if let Some(d) = db_slot().read().ok().and_then(|g| g.clone()) {
        return d;
    }
    let mut g = db_slot().write().unwrap_or_else(|e| e.into_inner());
    g.get_or_insert_with(|| {
        Arc::new(build_db(
            read_upstream(UPSTREAM_GZ).unwrap_or_default(),
            parse_eol(EOL_GZ).unwrap_or_default(),
        ))
    })
    .clone()
}

/// Replaces the upstream fingerprint table and/or the end-of-life table (a signed signature
/// bundle; `None` keeps the built-in one) and returns (technologies, eol cycles). The hand rules
/// stay; an invalid table leaves the current database untouched.
pub fn install_upstream(
    tech_gz: Option<&[u8]>,
    eol_gz: Option<&[u8]>,
) -> Result<(usize, usize), String> {
    let up = read_upstream(tech_gz.unwrap_or(UPSTREAM_GZ))?;
    let eol = parse_eol(eol_gz.unwrap_or(EOL_GZ))?;
    let counts = (up.len(), eol.values().map(Vec::len).sum());
    let new = Arc::new(build_db(up, eol));
    *db_slot().write().unwrap_or_else(|e| e.into_inner()) = Some(new);
    Ok(counts)
}

/// Loaded rule numbers: hand rules, upstream records and merged technologies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct TechCounts {
    pub hand: usize,
    pub upstream: usize,
    pub technologies: usize,
    pub with_cpe: usize,
    /// endoflife.date release cycles past end of life.
    pub eol_cycles: usize,
    /// Technologies with end-of-life data.
    pub eol_products: usize,
    /// Technologies with a static signal beyond headers/meta/cookies/html/script src/url: JS
    /// file content, visible text, CSS, TLS issuer or robots.txt.
    #[serde(default)]
    pub with_static_extra: usize,
    /// Technologies with a browser-only signal (JS globals, DOM, request hosts).
    #[serde(default)]
    pub with_browser: usize,
    /// WordPress plugin/theme directory slugs mapped to technology names.
    #[serde(default)]
    pub wp_slugs: usize,
}

/// A webappanalyzer technology matched by a WordPress plugin/theme directory slug.
#[derive(Debug, Clone)]
pub struct KnownPart {
    pub name: String,
    pub category: String,
    pub cpe: Option<String>,
    pub website: Option<String>,
}

/// The webappanalyzer technology of WordPress plugin/theme `slug` (`kind` = `plugin`|`theme`).
pub fn wordpress_slug(kind: &str, slug: &str) -> Option<KnownPart> {
    let d = db();
    let i = *d
        .wp_slugs
        .get(&format!("{kind}:{}", slug.to_ascii_lowercase()))?;
    let r = &d.techs[i].rule;
    Some(KnownPart {
        name: r.name.clone(),
        category: r.cat.clone(),
        cpe: r.cpe.clone(),
        website: r.website.clone(),
    })
}

/// Numbers of the rule database in use.
pub fn counts() -> TechCounts {
    let d = db();
    TechCounts {
        hand: d.hand,
        upstream: d.upstream,
        technologies: d.techs.len(),
        with_cpe: d.techs.iter().filter(|t| t.rule.cpe.is_some()).count(),
        eol_cycles: d.eol.values().map(Vec::len).sum(),
        eol_products: d.eol.len(),
        with_static_extra: d
            .techs
            .iter()
            .filter(|t| {
                !(t.js_files.is_empty()
                    && t.text.is_empty()
                    && t.css.is_empty()
                    && t.cert.is_empty()
                    && t.robots.is_empty())
            })
            .count(),
        with_browser: d
            .techs
            .iter()
            .filter(|t| !(t.globals.is_empty() && t.dom.is_empty() && t.xhr.is_empty()))
            .count(),
        wp_slugs: d.wp_slugs.len(),
    }
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
    /// CPE 2.3 name of the product (upstream table), for matching against vulnerability data.
    /// For a CMS plugin without an upstream CPE this is a guess with any vendor
    /// (`cpe:2.3:a:*:<slug>:*:*:*:*:*:wordpress:*:*`), marked by `plugin_of`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpe: Option<String>,
    /// Signal kinds that detected it: `header`, `cookie`, `meta`, `html`, `script_src`, `url`,
    /// `script` (JS file content), `text`, `css`, `cert`, `robots`, `js`, `dom`, `xhr`,
    /// `plugin_path`, `readme`, `implied`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub signals: Vec<String>,
    /// A plugin, theme or module of this CMS: `wordpress`, `drupal`, `joomla`, `magento`,
    /// `prestashop`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plugin_of: Option<String>,
    /// Directory name of the plugin/theme/module (`contact-form-7`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub slug: Option<String>,
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
    signals: std::collections::BTreeSet<&'static str>,
}

impl Acc {
    fn hit(&mut self, sig: &'static str, conf: u32, v: Option<String>, ev: String) {
        self.conf += conf;
        self.signals.insert(sig);
        if self.version.is_none() {
            self.version = v;
        }
        if self.evidence.len() < 6 && !self.evidence.contains(&ev) {
            self.evidence.push(ev);
        }
    }
}

/// Largest body of one fetched JavaScript or CSS file that signal regexes run over.
pub const MAX_SIGNAL_BODY: usize = 512 << 10;
/// Largest visible page text that `text` regexes run over.
const MAX_TEXT: usize = 256 << 10;

/// Site-wide data beyond one page that static and browser signals use. Everything here was
/// already fetched by the scan: detection sends no requests.
#[derive(Debug, Clone, Default)]
pub struct SiteExtra<'a> {
    /// Fetched JavaScript files: (URL, body).
    pub scripts: Vec<(&'a str, &'a str)>,
    /// Fetched stylesheet bodies (inline `<style>` of the page is always used).
    pub styles: Vec<&'a str>,
    /// Issuer of the site's TLS certificate (`CN=R11, O=Let's Encrypt, C=US`).
    pub cert_issuer: Option<&'a str>,
    /// robots.txt body.
    pub robots: Option<&'a str>,
    /// What the hidden browser read on the rendered page.
    pub browser: Option<&'a BrowserSignals>,
}

/// Cuts `s` to at most `max` bytes on a char boundary.
fn head(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    let mut i = max;
    while !s.is_char_boundary(i) {
        i -= 1;
    }
    &s[..i]
}

/// Inline `<style>` blocks of a page.
pub fn inline_styles(html: &str) -> Vec<&str> {
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| Regex::new(r"(?is)<style\b[^>]*>(.*?)</style>").expect("re"));
    re.captures_iter(html)
        .filter_map(|c| c.get(1).map(|m| m.as_str()))
        .collect()
}

/// Visible text of a page: tags, scripts, styles and comments removed, common entities decoded,
/// whitespace collapsed.
pub fn visible_text(html: &str) -> String {
    static DROP: OnceLock<Regex> = OnceLock::new();
    static TAG: OnceLock<Regex> = OnceLock::new();
    let drop = DROP.get_or_init(|| {
        Regex::new(r"(?is)<!--.*?-->|<(script|style|noscript|template|svg)\b[^>]*>.*?</(?:script|style|noscript|template|svg)\s*>")
            .expect("re")
    });
    let tag = TAG.get_or_init(|| Regex::new(r"(?s)<[^>]*>").expect("re"));
    let body = drop.replace_all(html, " ");
    let body = tag.replace_all(&body, " ");
    let decoded = body
        .replace("&nbsp;", " ")
        .replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&copy;", "©");
    let mut out = String::with_capacity(decoded.len().min(MAX_TEXT));
    for w in decoded.split_whitespace() {
        if out.len() + w.len() + 1 > MAX_TEXT {
            break;
        }
        if !out.is_empty() {
            out.push(' ');
        }
        out.push_str(w);
    }
    out
}

fn clip(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        format!("{}…", s.chars().take(n).collect::<String>())
    }
}

/// JavaScript file contents and visible text.
fn static_extra(
    c: &Compiled,
    acc: &mut Acc,
    js: &[(&str, &str)],
    in_js: &[HashSet<usize>],
    (text, in_text): (&str, &HashSet<usize>),
) {
    for p in &c.js_files {
        for ((url, body), present) in js.iter().zip(in_js) {
            if !p.may_match(present) {
                continue;
            }
            if let Some((ver, m)) = p.find(body) {
                let file = url.rsplit('/').next().unwrap_or(url);
                acc.hit(
                    "script",
                    p.weight(75),
                    ver,
                    format!("JS file {}: {}", clip(file, 60), clip(m, 60)),
                );
                break;
            }
        }
    }
    for p in c.text.iter().filter(|p| p.may_match(in_text)) {
        if let Some((ver, m)) = p.find(text) {
            acc.hit("text", p.weight(50), ver, format!("text: {}", clip(m, 80)));
        }
    }
}

/// Detects the technologies of a page. The order is deterministic: by category, then name.
pub fn detect(page: &PageInput) -> Vec<Technology> {
    detect_with(page, &SiteExtra::default())
}

/// [`detect`] plus site-wide signals: fetched JavaScript and CSS files, the TLS issuer,
/// robots.txt and what the hidden browser read on the rendered page.
pub fn detect_with(page: &PageInput, extra: &SiteExtra) -> Vec<Technology> {
    let db = db();
    let headers: Vec<(String, String)> = page
        .headers
        .iter()
        .map(|(k, v)| (k.to_ascii_lowercase(), v.clone()))
        .collect();
    let cookies = cookies_from_headers(&headers);
    let meta = extract_meta(&page.html);
    let scripts = extract_script_srcs(&page.html);
    // Literal prefilter: which upstream html/script/url patterns can match at all.
    let present = |text: &str| -> HashSet<usize> {
        db.lits.as_ref().map_or_else(HashSet::new, |ac| {
            ac.find_overlapping_iter(text)
                .map(|m| m.pattern().as_usize())
                .collect()
        })
    };
    let in_html = present(&page.html);
    let in_scripts = present(&scripts.join("\n"));
    let in_url = present(&page.url);
    let js_bodies: Vec<(&str, &str)> = extra
        .scripts
        .iter()
        .map(|(u, b)| (*u, head(b, MAX_SIGNAL_BODY)))
        .collect();
    let in_js: Vec<HashSet<usize>> = js_bodies.iter().map(|(_, b)| present(b)).collect();
    let text = visible_text(&page.html);
    let in_text = present(&text);
    let mut styles: Vec<&str> = inline_styles(&page.html);
    styles.extend(extra.styles.iter().map(|s| head(s, MAX_SIGNAL_BODY)));
    let css = styles.join("\n");
    let in_css = present(&css);
    let robots = extra.robots.map(|r| head(r, 64 << 10)).unwrap_or("");
    let in_robots = present(robots);
    let mut found: BTreeMap<String, Acc> = BTreeMap::new();
    for c in &db.techs {
        let mut acc = Acc::default();
        for (h, p) in &c.headers {
            for (_, v) in headers.iter().filter(|(k, _)| k == h) {
                if let Some(ver) = p.version(v) {
                    let ev = if p.presence_only() {
                        format!("header {h}")
                    } else {
                        format!("header {h}: {}", clip(v, 80))
                    };
                    acc.hit("header", p.weight(100), ver, ev);
                }
            }
        }
        for (m, p) in &c.meta {
            for (_, v) in meta.iter().filter(|(k, _)| k == m) {
                if let Some(ver) = p.version(v) {
                    acc.hit(
                        "meta",
                        p.weight(100),
                        ver,
                        format!("meta {m}: {}", clip(v, 80)),
                    );
                }
            }
        }
        for (name, p) in &c.cookies {
            for (n, v) in cookies.iter().filter(|(n, _)| n.starts_with(name.as_str())) {
                if let Some(ver) = p.version(v) {
                    acc.hit("cookie", p.weight(100), ver, format!("cookie {n}"));
                }
            }
        }
        for p in c.scripts.iter().filter(|p| p.may_match(&in_scripts)) {
            for s in &scripts {
                if let Some(ver) = p.version(s) {
                    acc.hit(
                        "script_src",
                        p.weight(75),
                        ver,
                        format!("script: {}", clip(s, 120)),
                    );
                }
            }
        }
        for p in c.html.iter().filter(|p| p.may_match(&in_html)) {
            if let Some((ver, m)) = p.find(&page.html) {
                acc.hit("html", p.weight(50), ver, format!("html: {}", clip(m, 80)));
            }
        }
        for p in c.url.iter().filter(|p| p.may_match(&in_url)) {
            if let Some(ver) = p.version(&page.url) {
                acc.hit(
                    "url",
                    p.weight(50),
                    ver,
                    format!("url: {}", clip(&page.url, 80)),
                );
            }
        }
        static_extra(c, &mut acc, &js_bodies, &in_js, (&text, &in_text));
        for p in c.css.iter().filter(|p| p.may_match(&in_css)) {
            if let Some((ver, m)) = p.find(&css) {
                acc.hit("css", p.weight(50), ver, format!("CSS: {}", clip(m, 80)));
            }
        }
        if let Some(issuer) = extra.cert_issuer {
            for p in &c.cert {
                if let Some(ver) = p.version(issuer) {
                    acc.hit(
                        "cert",
                        p.weight(100),
                        ver,
                        format!("TLS issuer: {}", clip(issuer, 80)),
                    );
                }
            }
        }
        for p in c.robots.iter().filter(|p| p.may_match(&in_robots)) {
            if let Some((ver, m)) = p.find(robots) {
                acc.hit(
                    "robots",
                    p.weight(75),
                    ver,
                    format!("robots.txt: {}", clip(m, 80)),
                );
            }
        }
        if let Some(b) = extra.browser {
            b.evaluate(c, &mut acc);
        }
        if acc.conf > 0 {
            found.insert(c.rule.name.clone(), acc);
        }
    }
    let rule = |n: &str| db.by_name.get(n).map(|&i| &db.techs[i]);
    // Resolve `implies` transitively, guarding against cycles.
    let mut queue: Vec<String> = found.keys().cloned().collect();
    while let Some(n) = queue.pop() {
        let Some(c) = rule(&n) else {
            continue;
        };
        let conf = found.get(&n).map(|a| a.conf.min(100)).unwrap_or(0);
        for imp in &c.rule.implies {
            if !found.contains_key(imp) {
                let mut a = Acc::default();
                a.hit("implied", conf, None, format!("implied by {n}"));
                found.insert(imp.clone(), a);
                queue.push(imp.clone());
            }
        }
    }
    // `excludes` and `requires` (upstream semantics): drop excluded names, then names whose
    // required companion is absent.
    let excluded: HashSet<String> = found
        .keys()
        .filter_map(|n| rule(n))
        .flat_map(|c| c.rule.excludes.iter().cloned())
        .collect();
    found.retain(|n, _| !excluded.contains(n));
    let names: HashSet<String> = found.keys().cloned().collect();
    found.retain(|n, _| {
        rule(n).is_none_or(|c| {
            c.rule.requires.is_empty() || c.rule.requires.iter().any(|r| names.contains(r))
        })
    });
    let mut out: Vec<Technology> = found
        .into_iter()
        .filter_map(|(name, acc)| {
            let c = rule(&name)?;
            let branch_eol = acc
                .version
                .as_deref()
                .and_then(|v| eol_branch_note(&c.rule.eol_branches, v));
            // Hand EOL data first, then endoflife.date, then the hand "older than" threshold.
            let cycle_eol = || {
                let v = acc.version.as_deref()?;
                eol_cycle_note(db.eol.get(&name)?, v)
            };
            let outdated = match (&c.rule.eol, &c.rule.outdated_below, &acc.version) {
                (Some(e), _, _) => Some(e.clone()),
                _ if branch_eol.is_some() => branch_eol,
                _ if cycle_eol().is_some() => cycle_eol(),
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
                cpe: c.rule.cpe.clone(),
                signals: acc.signals.iter().map(|s| (*s).to_string()).collect(),
                plugin_of: None,
                slug: None,
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
            let r = rule_of(name);
            let note = eol_branch_note(&r.eol_branches, ver);
            assert!(note.is_some(), "{name} {ver}");
        }
        let php = rule_of("PHP");
        assert_eq!(eol_branch_note(&php.eol_branches, "8.2.0"), None);
    }

    fn rule_of(name: &str) -> TechRule {
        let d = db();
        let i = d.by_name[name];
        d.techs[i].rule.clone()
    }

    #[test]
    fn rules_load_and_compile() {
        let c = counts();
        assert!((100..=200).contains(&c.hand), "{c:?}");
        assert!(c.upstream > 5000, "{c:?}");
        assert!(c.technologies > c.upstream, "{c:?}");
        assert!(c.with_cpe > 400, "{c:?}");
        let d = db();
        // Every hand pattern compiles; the upstream ones were checked by the ingest script.
        for t in &d.techs[..d.hand] {
            for p in t.html.iter().chain(&t.scripts) {
                assert!(p.re().is_some(), "{}: {p:?}", t.rule.name);
            }
            for i in &t.rule.implies {
                assert!(d.by_name.contains_key(i), "{} implies {i}", t.rule.name);
            }
        }
        // Hand rules keep their tuned fields after the merge.
        let nginx = rule_of("Nginx");
        assert_eq!(nginx.cat, "Веб-сервер");
        assert_eq!(nginx.outdated_below.as_deref(), Some("1.20"));
        assert_eq!(
            nginx.cpe.as_deref(),
            Some("cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*")
        );
        // Upstream names are aliased onto the hand ones (`IIS` -> `Microsoft IIS`).
        assert!(!d.by_name.contains_key("IIS"));
        assert!(rule_of("Microsoft IIS").cpe.is_some());
    }

    #[test]
    fn endoflife_cycles_flag_versions_past_eol() {
        let c = counts();
        assert!(c.eol_products > 100 && c.eol_cycles > 1500, "{c:?}");
        let d = db();
        let nginx = &d.eol["Nginx"];
        let n = eol_cycle_note(nginx, "1.24.0").unwrap();
        assert!(n.contains("ветка 1.24") && n.contains("2024-04-23"), "{n}");
        // `1.2` must not match the `1.24` cycle, nor a bare major version a minor cycle.
        assert!(eol_cycle_note(nginx, "1.2.9")
            .unwrap()
            .contains("ветка 1.2 "));
        assert_eq!(eol_cycle_note(nginx, "1"), None);
        assert_eq!(eol_cycle_note(&d.eol["PHP"], "8.4.1"), None);
        // In detection: hand EOL branches win, endoflife.date fills the gaps.
        let t = detect(&PageInput {
            url: "https://x.example/".into(),
            headers: vec![
                ("Server".into(), "nginx/1.24.0".into()),
                ("X-Powered-By".into(), "PHP/7.4.3".into()),
            ],
            html: String::new(),
        });
        assert!(get(&t, "Nginx")
            .outdated
            .as_deref()
            .unwrap()
            .contains("endoflife.date"));
        assert!(get(&t, "PHP")
            .outdated
            .as_deref()
            .unwrap()
            .contains("выпуски до 7.4"));
    }

    #[test]
    fn version_templates() {
        let r = Regex::new(r"nginx(?:/([\d.]+))?").unwrap();
        let c = r.captures("nginx/1.25.3").unwrap();
        assert_eq!(apply_version_template(r"\1", &c).as_deref(), Some("1.25.3"));
        assert_eq!(
            apply_version_template(r"\1?new:old", &c).as_deref(),
            Some("new")
        );
        let c = r.captures("nginx").unwrap();
        assert_eq!(apply_version_template(r"\1", &c), None);
        assert_eq!(
            apply_version_template(r"\1?new:old", &c).as_deref(),
            Some("old")
        );
    }

    #[test]
    fn upstream_rules_detect_more_stacks() {
        let p = PageInput {
            url: "https://shop.example/".into(),
            headers: vec![
                ("Server".into(), "Microsoft-IIS/8.5".into()),
                ("X-Powered-By".into(), "ASP.NET".into()),
                ("Set-Cookie".into(), "ci_session=abc; path=/".into()),
            ],
            html: concat!(
                "<html><head><meta name=\"generator\" content=\"Hugo 0.111.3\">",
                "<script src=\"https://cdn.jsdelivr.net/npm/alpinejs@3.13.3/dist/cdn.min.js\"></script>",
                "</head><body>hi</body></html>"
            )
            .into(),
        };
        let t = detect(&p);
        let iis = get(&t, "Microsoft IIS");
        assert_eq!(iis.version.as_deref(), Some("8.5"));
        assert!(iis.cpe.as_deref().unwrap().contains(":microsoft:"));
        assert_eq!(get(&t, "Hugo").version.as_deref(), Some("0.111.3"));
        assert_eq!(get(&t, "CodeIgniter").category, "Фреймворк");
        // A plain page gets nothing from the upstream rules.
        let empty = detect(&PageInput {
            url: "https://x.example/".into(),
            headers: vec![],
            html: "<html><body>hello</body></html>".into(),
        });
        assert!(empty.is_empty(), "{empty:?}");
    }

    #[test]
    fn startup_and_detect_stay_fast() {
        // The merged database is built once; measure a fresh build and one detect on a page.
        let t0 = std::time::Instant::now();
        let d = build_db(
            read_upstream(UPSTREAM_GZ).unwrap(),
            parse_eol(EOL_GZ).unwrap(),
        );
        let build = t0.elapsed();
        assert!(d.techs.len() > 5000);
        let t1 = std::time::Instant::now();
        let _ = detect(&page());
        let first = t1.elapsed();
        eprintln!("tech db build {build:?}, first detect {first:?}");
        // Generous bounds for debug builds on a loaded CI box.
        assert!(build.as_secs() < 5, "{build:?}");
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

    /// The published 2.0.0-beta.3 app loads this table from the signature bundle with the
    /// struct below (copied from `git show v2.0.0-beta.3:crates/foca-recon/src/tech.rs`): the
    /// new signal keys must stay ignorable extra fields and every record must still parse.
    #[test]
    fn table_still_parses_with_the_beta3_loader() {
        #[derive(Deserialize)]
        struct UpstreamFileB3 {
            #[serde(default)]
            technologies: Vec<UpstreamTechB3>,
        }
        #[derive(Deserialize, Default)]
        #[serde(default)]
        #[allow(dead_code)]
        struct UpstreamTechB3 {
            n: String,
            c: String,
            h: BTreeMap<String, Vec<Vec<serde_json::Value>>>,
            k: BTreeMap<String, Vec<Vec<serde_json::Value>>>,
            m: BTreeMap<String, Vec<Vec<serde_json::Value>>>,
            x: Vec<Vec<serde_json::Value>>,
            s: Vec<Vec<serde_json::Value>>,
            u: Vec<Vec<serde_json::Value>>,
            i: Vec<String>,
            r: Vec<String>,
            e: Vec<String>,
            cpe: Option<String>,
            w: Option<String>,
        }
        let mut text = String::new();
        flate2::read::GzDecoder::new(UPSTREAM_GZ)
            .read_to_string(&mut text)
            .unwrap();
        let old: UpstreamFileB3 = serde_json::from_str(&text).expect("beta.3 loader");
        let now = read_upstream(UPSTREAM_GZ).unwrap();
        assert_eq!(old.technologies.len(), now.len());
        assert!(old.technologies.iter().all(|t| !t.n.is_empty()));
        // the new signals really are in the table
        assert!(now.iter().any(|t| !t.g.is_empty()) && now.iter().any(|t| !t.sc.is_empty()));
    }
}
