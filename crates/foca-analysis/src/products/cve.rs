//! Offline NVD CVE table: affected version ranges per product and version matching.
//!
//! The table (`signatures/nvd_cve.tsv.gz`, built by `signatures/tools/update_nvd.py` from the
//! public-domain NVD CVE feeds) keeps, for every product FOCA-rs can detect (web technologies,
//! WordPress/Drupal/Joomla plugins, document software and OS), the CVEs whose NVD
//! configurations mark it vulnerable, with CVSS, CWE, KEV flag, EPSS and the affected ranges.
//! It is parsed lazily on first use and can be replaced by a signed bundle ([`install`]).
//!
//! Approximations (documented in `docs/dev/signature-bundles.md`):
//! * versions are compared component by component ([`cmp_ver`]): numeric parts numerically,
//!   pre-release tags (`alpha`, `beta`, `rc`, `dev`) sort before the release, a trailing letter
//!   (`1.0.2k`) after it, build metadata after `+` is ignored, a leading `v`/`m` is dropped;
//! * an NVD entry without version limits (`*`, `-`) matches every version only when no
//!   configuration of the CVE names the product with a range or an exact version; such
//!   matches are flagged "range not specified in NVD" and never raise the severity;
//! * Microsoft Office versions from document metadata are marketing editions: `14` = 2010,
//!   `15` = 2013, `16` = 2016 and Microsoft 365 Apps (NVD cannot tell 2016, 2019, LTSC and 365
//!   apart in `16.0`); the service pack level is unknown, so every CVE of the edition matches;
//! * the update field of a CPE (service pack) and `target_hw` are ignored, `target_sw` only
//!   tells plugins (`wordpress`, `drupal`, `joomla`) from the products themselves.

use std::cmp::Ordering;
use std::collections::HashMap;
use std::io::Read;
use std::sync::{Arc, OnceLock, RwLock};

use foca_core::api::{CveRef, CveSummary};
use foca_core::Severity;

/// Embedded snapshot.
pub const NVD_GZ: &[u8] = include_bytes!("../../signatures/nvd_cve.tsv.gz");

/// One CVE of the table.
#[derive(Debug, Clone, PartialEq)]
pub struct CveRec {
    /// Year and number of the id (`CVE-<id_year>-<id_num>`).
    pub id_year: u16,
    pub id_num: u32,
    /// Published year.
    pub year: u16,
    /// CVSS base score.
    pub cvss: Option<f32>,
    /// `31`, `40`, `30` or `2`.
    pub cvss_ver: u8,
    pub cwe: Box<[u16]>,
    pub kev: bool,
    pub epss: Option<f32>,
}

impl CveRec {
    /// `CVE-YYYY-NNNN`.
    pub fn id(&self) -> String {
        format!("CVE-{}-{:04}", self.id_year, self.id_num)
    }

    /// Qualitative severity of the score (CVSS v3/v4 scale; v2 has no critical band).
    pub fn severity(&self) -> Option<Severity> {
        let s = self.cvss?;
        Some(if s >= 9.0 && self.cvss_ver != 2 {
            Severity::Critical
        } else if s >= 7.0 {
            Severity::High
        } else if s >= 4.0 {
            Severity::Medium
        } else if s > 0.0 {
            Severity::Low
        } else {
            Severity::Info
        })
    }
}

/// An affected version range of one product.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerRange {
    All,
    Exact(String),
    /// Lower and upper bound, each `(version, inclusive)`; `None` is open.
    Between(Option<(String, bool)>, Option<(String, bool)>),
}

impl VerRange {
    fn parse(s: &str) -> Option<VerRange> {
        if s == "*" {
            return Some(VerRange::All);
        }
        if let Some(v) = s.strip_prefix('=') {
            return Some(VerRange::Exact(v.to_string()));
        }
        let lo_inc = match s.chars().next()? {
            '[' => true,
            '(' => false,
            _ => return None,
        };
        let hi_inc = match s.chars().last()? {
            ']' => true,
            ')' => false,
            _ => return None,
        };
        let (a, b) = s.get(1..s.len() - 1)?.split_once(',')?;
        let side = |v: &str, inc: bool| (!v.is_empty()).then(|| (v.to_string(), inc));
        Some(VerRange::Between(side(a, lo_inc), side(b, hi_inc)))
    }

    /// Whether `ver` lies in the range.
    pub fn contains(&self, ver: &str) -> bool {
        match self {
            VerRange::All => true,
            VerRange::Exact(v) => cmp_ver(ver, v) == Ordering::Equal,
            VerRange::Between(lo, hi) => {
                let lo_ok = lo.as_ref().is_none_or(|(v, inc)| match cmp_ver(ver, v) {
                    Ordering::Greater => true,
                    Ordering::Equal => *inc,
                    Ordering::Less => false,
                });
                let hi_ok = hi.as_ref().is_none_or(|(v, inc)| match cmp_ver(ver, v) {
                    Ordering::Less => true,
                    Ordering::Equal => *inc,
                    Ordering::Greater => false,
                });
                lo_ok && hi_ok
            }
        }
    }
}

/// Normalizes a real-world version string for comparison: first token that starts with a digit
/// (after an optional `v`/`m` prefix: `v2.1`, `m120`), build metadata after `+` dropped.
pub fn norm_ver(v: &str) -> Option<String> {
    for tok in v.split(|c: char| c.is_whitespace() || matches!(c, '/' | '(' | ')' | ',' | ';')) {
        let t = tok
            .strip_prefix(['v', 'V', 'm', 'M'])
            .filter(|r| r.starts_with(|c: char| c.is_ascii_digit()))
            .unwrap_or(tok);
        if t.starts_with(|c: char| c.is_ascii_digit()) {
            let t = t.split('+').next().unwrap_or(t);
            return Some(t.trim_end_matches(['.', '-', '_']).to_string());
        }
    }
    None
}

#[derive(Debug, PartialEq, Eq)]
enum Tok<'a> {
    Num(u64),
    Pre(u8),
    Word(&'a str),
}

const PRE: &[(&str, u8)] = &[
    ("dev", 0),
    ("snapshot", 0),
    ("nightly", 0),
    ("alpha", 1),
    ("a", 1),
    ("beta", 2),
    ("b", 2),
    ("pre", 3),
    ("preview", 3),
    ("rc", 4),
    ("cr", 4),
];

fn toks(v: &str) -> Vec<Tok<'_>> {
    let b = v.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        let s = i;
        if b[i].is_ascii_digit() {
            while i < b.len() && b[i].is_ascii_digit() {
                i += 1;
            }
            out.push(Tok::Num(v[s..i].parse().unwrap_or(u64::MAX)));
        } else if b[i].is_ascii_alphabetic() {
            while i < b.len() && b[i].is_ascii_alphabetic() {
                i += 1;
            }
            let w = &v[s..i];
            let lw = w.to_ascii_lowercase();
            match PRE.iter().find(|(p, _)| *p == lw) {
                Some((_, r)) => out.push(Tok::Pre(*r)),
                // Release markers that do not change the order.
                None if matches!(lw.as_str(), "final" | "ga" | "release" | "stable" | "r") => {}
                None => out.push(Tok::Word(w)),
            }
        } else {
            i += 1;
        }
    }
    out
}

/// Compares two version strings (see the module docs for the rules).
pub fn cmp_ver(a: &str, b: &str) -> Ordering {
    let (na, nb) = (norm_ver(a), norm_ver(b));
    let (ta, tb) = (
        toks(na.as_deref().unwrap_or(a)),
        toks(nb.as_deref().unwrap_or(b)),
    );
    let n = ta.len().max(tb.len());
    for i in 0..n {
        let o = match (ta.get(i), tb.get(i)) {
            (Some(Tok::Num(x)), Some(Tok::Num(y))) => x.cmp(y),
            (Some(Tok::Pre(x)), Some(Tok::Pre(y))) => x.cmp(y),
            (Some(Tok::Word(x)), Some(Tok::Word(y))) => {
                x.to_ascii_lowercase().cmp(&y.to_ascii_lowercase())
            }
            // A pre-release sorts before anything, a letter suffix before a further number.
            (Some(Tok::Pre(_)), Some(_)) => Ordering::Less,
            (Some(_), Some(Tok::Pre(_))) => Ordering::Greater,
            (Some(Tok::Num(_)), Some(Tok::Word(_))) => Ordering::Greater,
            (Some(Tok::Word(_)), Some(Tok::Num(_))) => Ordering::Less,
            (Some(Tok::Num(0)), None) | (None, Some(Tok::Num(0))) => Ordering::Equal,
            (Some(Tok::Pre(_)), None) => Ordering::Less,
            (None, Some(Tok::Pre(_))) => Ordering::Greater,
            (Some(_), None) => Ordering::Greater,
            (None, Some(_)) => Ordering::Less,
            (None, None) => Ordering::Equal,
        };
        if o != Ordering::Equal {
            return o;
        }
    }
    Ordering::Equal
}

/// Header fields of the table.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub struct CveMeta {
    pub snapshot: String,
    pub epss: String,
    pub cves: usize,
    pub products: usize,
    pub ranges: usize,
    /// CVEs per group: site technologies, plugins, document software, OS.
    pub site: usize,
    pub plugin: usize,
    pub doc: usize,
    pub os: usize,
}

/// The parsed table. Range lists stay as text slices of the decompressed table and are parsed
/// per lookup, which keeps the resident size near the text size.
#[derive(Debug, Default)]
pub struct CveDb {
    pub meta: CveMeta,
    text: String,
    cves: Vec<CveRec>,
    /// Product key -> (CVE index, byte range of its range list in `text`).
    products: HashMap<String, Vec<(u32, u32, u32)>>,
    /// `product@cms` (slug spelling) -> product keys.
    slugs: HashMap<String, Vec<String>>,
}

/// What to look up: CPE `vendor:product` keys and/or a plugin slug, plus the version.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CveQuery {
    pub keys: Vec<String>,
    /// `(slug, cms)`: `("contact-form-7", "wordpress")`.
    pub slug: Option<(String, String)>,
    pub version: Option<String>,
    /// Where the version was found (`header`, `html`, `js`, `plugin_path`, `readme`, `meta`).
    pub source: String,
    /// Software seen in documents: only CVEs published up to this year count (a document shows
    /// the version at the time it was made; later CVEs go to `CveSummary::later`).
    pub until_year: Option<u16>,
}

/// Normalized slug spelling (`Contact-Form 7` -> `contact_form_7`).
pub fn slug_key(s: &str) -> String {
    s.trim()
        .to_ascii_lowercase()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect()
}

/// `vendor:product` of a CPE 2.3 (`cpe:2.3:a:f5:nginx:*:...`), 2.2 (`cpe:/a:f5:nginx`) name or
/// of an already short key.
pub fn cpe_key(cpe: &str) -> Option<String> {
    let c = cpe.trim().to_ascii_lowercase();
    let parts: Vec<&str> = c.split(':').collect();
    let (v, p) = if c.starts_with("cpe:2.3:") {
        (parts.get(3)?, parts.get(4)?)
    } else if c.starts_with("cpe:/") {
        (parts.get(2)?, parts.get(3)?)
    } else if parts.len() == 2 {
        (parts.first()?, parts.get(1)?)
    } else {
        return None;
    };
    (!v.is_empty() && !p.is_empty()).then(|| format!("{v}:{p}"))
}

/// Marketing editions NVD uses for a Microsoft Office version from document metadata.
pub fn office_editions(ver: &str) -> Vec<String> {
    let lead: String = ver
        .trim()
        .chars()
        .take_while(char::is_ascii_digit)
        .collect();
    let ed: &[&str] = match lead.as_str() {
        "8" => &["97"],
        "9" => &["2000"],
        "10" => &["2002", "xp"],
        "11" => &["2003"],
        "12" => &["2007"],
        "14" => &["2010"],
        "15" => &["2013"],
        "16" => &["2016"],
        y if y.len() == 4 => return vec![y.to_string()],
        _ => &[],
    };
    ed.iter().map(|s| s.to_string()).collect()
}

fn is_office_key(k: &str) -> bool {
    k.starts_with("microsoft:")
        && matches!(
            &k[10..],
            "office"
                | "word"
                | "excel"
                | "powerpoint"
                | "outlook"
                | "visio"
                | "publisher"
                | "onenote"
                | "access"
        )
}

/// Parse error of the table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CveError(pub String);

impl std::fmt::Display for CveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl CveDb {
    /// Parses a gzip table (format in `signatures/tools/update_nvd.py`).
    pub fn parse(gz: &[u8]) -> Result<CveDb, CveError> {
        let mut text = String::new();
        flate2::read::GzDecoder::new(gz)
            .read_to_string(&mut text)
            .map_err(|e| CveError(format!("nvd table: {e}")))?;
        CveDb::parse_text(text)
    }

    fn parse_text(text: impl Into<String>) -> Result<CveDb, CveError> {
        let text: String = text.into();
        let mut db = CveDb::default();
        let mut cur: Option<(String, u32)> = None;
        let mut off = 0usize;
        for (n, raw) in text.split_inclusive('\n').enumerate() {
            let start = off;
            off += raw.len();
            let line = raw.trim_end_matches(['\n', '\r']);
            if let Some(h) = line.strip_prefix('#') {
                if !h.contains("foca-nvd v1") {
                    return Err(CveError("nvd table: unknown header".into()));
                }
                for kv in h.split_whitespace() {
                    let Some((k, v)) = kv.split_once('=') else {
                        continue;
                    };
                    let num = v.parse().unwrap_or(0);
                    match k {
                        "snapshot" => db.meta.snapshot = v.into(),
                        "epss" => db.meta.epss = v.into(),
                        "site" => db.meta.site = num,
                        "plugin" => db.meta.plugin = num,
                        "doc" => db.meta.doc = num,
                        "os" => db.meta.os = num,
                        _ => {}
                    }
                }
                continue;
            }
            let bad = || CveError(format!("nvd table: bad line {}", n + 1));
            if let Some(rest) = line.strip_prefix("C\t") {
                let f: Vec<&str> = rest.split('\t').collect();
                if f.len() != 7 {
                    return Err(bad());
                }
                let (iy, inum) = f[0].split_once('-').ok_or_else(bad)?;
                db.cves.push(CveRec {
                    id_year: iy.parse().map_err(|_| bad())?,
                    id_num: inum.parse().map_err(|_| bad())?,
                    year: f[1].parse().unwrap_or(0),
                    cvss: f[2].parse().ok(),
                    cvss_ver: f[3].parse().unwrap_or(0),
                    cwe: f[4].split(',').filter_map(|c| c.parse().ok()).collect(),
                    kev: f[5] == "K",
                    epss: f[6].parse::<u32>().ok().map(|e| e as f32 / 10000.0),
                });
            } else if let Some(rest) = line.strip_prefix("P\t") {
                let key = rest.split('\t').next().ok_or_else(bad)?.to_string();
                if let Some((prod, cms)) = key.split_once('@') {
                    let product = prod.split_once(':').map_or(prod, |x| x.1);
                    db.slugs
                        .entry(format!("{}@{cms}", slug_key(product)))
                        .or_default()
                        .push(key.clone());
                }
                db.products.entry(key.clone()).or_default();
                cur = Some((key, 0));
            } else if !line.is_empty() {
                let (key, prev) = cur.as_mut().ok_or_else(bad)?;
                let (d, rs) = line.split_once('\t').ok_or_else(bad)?;
                *prev += d.parse::<u32>().map_err(|_| bad())?;
                if *prev as usize >= db.cves.len() {
                    return Err(bad());
                }
                db.meta.ranges += rs.split(' ').count();
                let rs_start = (start + d.len() + 1) as u32;
                if let Some(v) = db.products.get_mut(key.as_str()) {
                    v.push((*prev, rs_start, rs_start + rs.len() as u32));
                }
            }
        }
        db.meta.cves = db.cves.len();
        db.meta.products = db.products.len();
        if db.cves.is_empty() {
            return Err(CveError("nvd table: no CVEs".into()));
        }
        db.text = text;
        Ok(db)
    }

    /// A record of the table by id.
    pub fn cve(&self, id: &str) -> Option<&CveRec> {
        self.cves.iter().find(|c| c.id() == id)
    }

    /// Product keys a query resolves to (CPE keys present in the table plus plugin keys).
    pub fn resolve(&self, q: &CveQuery) -> Vec<String> {
        let mut out: Vec<String> = q
            .keys
            .iter()
            .filter_map(|k| cpe_key(k))
            .filter(|k| self.products.contains_key(k))
            .collect();
        if let Some((slug, cms)) = &q.slug {
            let cms = slug_key(cms);
            for k in self
                .slugs
                .get(&format!("{}@{cms}", slug_key(slug)))
                .into_iter()
                .flatten()
            {
                if !out.contains(k) {
                    out.push(k.clone());
                }
            }
        }
        out
    }

    /// Version candidates of a query for one product key (Office editions, normalized version).
    fn candidates(k: &str, ver: Option<&str>) -> Vec<String> {
        match ver {
            Some(v) if is_office_key(k) => office_editions(v),
            // Microsoft 365 Apps carries no version in NVD: Office `16` documents map here.
            Some(v) if k == "microsoft:365_apps" => office_editions(v)
                .into_iter()
                .filter(|e| e == "2016")
                .collect(),
            Some(v) => norm_ver(v).into_iter().collect(),
            None => vec![],
        }
    }

    fn ranges_of(&self, a: u32, b: u32) -> impl Iterator<Item = (&str, VerRange)> {
        self.text[a as usize..b as usize]
            .split(' ')
            .filter_map(|r| VerRange::parse(r).map(|v| (r, v)))
    }

    /// Matches a query: resolved keys, CVE indexes of the product and the hits.
    ///
    /// A CVE hits through a bounded entry (range or exact version) that contains the version.
    /// An unbounded entry (`*`: NVD gives no version) hits only when no key of the query has a
    /// bounded entry for that CVE; such hits are flagged ([`Hit::unbounded`]).
    fn matches(&self, q: &CveQuery) -> Option<(Vec<String>, Vec<u32>, Vec<Hit>)> {
        let keys = self.resolve(q);
        if keys.is_empty() {
            return None;
        }
        let ver = query_version(q);
        // CVE index -> (matched bounded range, any bounded entry, unbounded entry)
        let mut per: std::collections::BTreeMap<u32, (Option<String>, bool, bool)> =
            std::collections::BTreeMap::new();
        for k in &keys {
            let cands = Self::candidates(k, ver);
            for (i, a, b) in self.products.get(k).into_iter().flatten() {
                let e = per.entry(*i).or_default();
                for (raw, r) in self.ranges_of(*a, *b) {
                    if r == VerRange::All {
                        e.2 |= !cands.is_empty();
                        continue;
                    }
                    e.1 = true;
                    if e.0.is_none() && cands.iter().any(|c| r.contains(c)) {
                        e.0 = Some(raw.to_string());
                    }
                }
            }
        }
        let known: Vec<u32> = per.keys().copied().collect();
        let hits = per
            .into_iter()
            .filter_map(|(i, (range, bounded, all))| match range {
                Some(r) => Some(Hit {
                    idx: i,
                    range: Some(r),
                    unbounded: false,
                }),
                None if all && !bounded => Some(Hit {
                    idx: i,
                    range: None,
                    unbounded: true,
                }),
                None => None,
            })
            .collect();
        Some((keys, known, hits))
    }

    /// Lowest version outside every matched range: the highest exclusive upper bound of the
    /// matched ranges, moved past any other range of the product that still contains it.
    /// `None` when a matched range has no exclusive upper bound or the walk does not settle.
    fn fixed_in(&self, keys: &[String], hits: &[Hit]) -> Option<String> {
        let mut target: Option<String> = None;
        for h in hits.iter().filter(|h| !h.unbounded) {
            match VerRange::parse(h.range.as_deref()?)? {
                VerRange::Exact(_) => {}
                VerRange::Between(_, Some((v, false))) => {
                    if target
                        .as_deref()
                        .is_none_or(|t| cmp_ver(&v, t) == Ordering::Greater)
                    {
                        target = Some(v);
                    }
                }
                _ => return None,
            }
        }
        let mut t = target?;
        for _ in 0..16 {
            let mut moved = false;
            for k in keys {
                for (_, a, b) in self.products.get(k).into_iter().flatten() {
                    for (_, r) in self.ranges_of(*a, *b) {
                        if r == VerRange::All || !r.contains(&t) {
                            continue;
                        }
                        match r {
                            VerRange::Between(_, Some((v, false))) => {
                                t = v;
                                moved = true;
                            }
                            VerRange::Exact(_) => {}
                            _ => return None,
                        }
                    }
                }
            }
            if !moved {
                return Some(t);
            }
        }
        None
    }

    /// Looks a product version up. `None` when the table has no CVE for the product.
    pub fn lookup(&self, q: &CveQuery) -> Option<CveSummary> {
        let (keys, known, mut hits) = self.matches(q)?;
        let ver = query_version(q);
        let before = hits.len();
        if let Some(y) = q.until_year {
            hits.retain(|h| self.cves[h.idx as usize].year <= y);
        }
        let later = (before - hits.len()) as u32;
        let version_known = ver.is_some_and(|v| norm_ver(v).is_some());
        let mut s = CveSummary {
            product: keys.join(","),
            version: ver.unwrap_or_default().to_string(),
            version_known,
            source: q.source.clone(),
            known: known.len() as u32,
            matched: hits.len() as u32,
            later,
            until_year: q.until_year,
            ..Default::default()
        };
        for h in &hits {
            let c = &self.cves[h.idx as usize];
            if h.unbounded {
                // Range not specified in NVD: listed, never counted into the severity.
                s.unbounded += 1;
                continue;
            }
            match c.severity() {
                Some(Severity::Critical) => s.critical += 1,
                Some(Severity::High) => s.high += 1,
                Some(Severity::Medium) => s.medium += 1,
                Some(Severity::Low) => s.low += 1,
                _ => {}
            }
            s.kev += u32::from(c.kev);
            s.max_cvss = max_opt(s.max_cvss, c.cvss);
            s.max_epss = max_opt(s.max_epss, c.epss);
        }
        if version_known && !hits.is_empty() {
            s.fixed_in = self.fixed_in(&keys, &hits);
        }
        sort_hits(&mut hits, &self.cves);
        s.cves = hits
            .iter()
            .map(|h| {
                let c = &self.cves[h.idx as usize];
                CveRef {
                    id: c.id(),
                    cvss: c.cvss,
                    kev: c.kev,
                    epss: c.epss,
                    unbounded: h.unbounded,
                }
            })
            .collect();
        Some(s)
    }

    /// Every matched CVE of a query with its record and matched range, in [`CveSummary::cves`]
    /// order (for the CVE list of a product).
    pub fn list(&self, q: &CveQuery) -> Vec<(CveRec, Hit)> {
        let Some((_, _, mut hits)) = self.matches(q) else {
            return vec![];
        };
        if let Some(y) = q.until_year {
            hits.retain(|h| self.cves[h.idx as usize].year <= y);
        }
        sort_hits(&mut hits, &self.cves);
        hits.into_iter()
            .map(|h| (self.cves[h.idx as usize].clone(), h))
            .collect()
    }
}

/// One row of a product's CVE list (`cve_list`, `docs/API.md`).
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct CveRow {
    pub id: String,
    pub cvss: Option<f32>,
    /// `critical` | `high` | `medium` | `low` (none without a score).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub severity: Option<&'static str>,
    pub kev: bool,
    pub epss: Option<f32>,
    /// CWE numbers (`79` for CWE-79).
    pub cwe: Vec<u16>,
    /// Published year.
    pub year: u16,
    /// Matched affected range in table syntax (`[1.1,1.20.1)`, `=2016`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub range: Option<String>,
    /// Exclusive upper bound of the matched range.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fixed: Option<String>,
    /// Range not specified in NVD.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub unbounded: bool,
}

/// One page of a product's CVE list: the matched CVEs of the version or, when the version is
/// unknown, every CVE of the product (`version_specific: false`).
#[derive(Debug, Clone, Default, PartialEq, serde::Serialize)]
pub struct CveListPage {
    pub product: String,
    pub version: String,
    pub version_specific: bool,
    pub total: usize,
    pub offset: usize,
    pub critical: u32,
    pub high: u32,
    pub medium: u32,
    pub low: u32,
    pub kev: u32,
    pub unbounded: u32,
    pub max_epss: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fixed_in: Option<String>,
    pub items: Vec<CveRow>,
}

fn sev_key(s: Option<Severity>) -> Option<&'static str> {
    match s? {
        Severity::Critical => Some("critical"),
        Severity::High => Some("high"),
        Severity::Medium => Some("medium"),
        Severity::Low => Some("low"),
        _ => None,
    }
}

impl CveDb {
    /// A page of the CVE list of a product (`offset`, at most `limit` rows), sorted KEV first,
    /// then CVSS and EPSS; counts cover the whole list.
    pub fn list_page(&self, q: &CveQuery, offset: usize, limit: usize) -> Option<CveListPage> {
        let (keys, known, mut hits) = self.matches(q)?;
        let ver = query_version(q).unwrap_or_default().to_string();
        let specific = norm_ver(&ver).is_some();
        if !specific {
            hits = known
                .iter()
                .map(|&idx| Hit {
                    idx,
                    range: None,
                    unbounded: false,
                })
                .collect();
        }
        if let Some(y) = q.until_year {
            hits.retain(|h| self.cves[h.idx as usize].year <= y);
        }
        sort_hits(&mut hits, &self.cves);
        let mut page = CveListPage {
            product: keys.join(","),
            version: ver,
            version_specific: specific,
            total: hits.len(),
            offset,
            ..Default::default()
        };
        for h in &hits {
            let c = &self.cves[h.idx as usize];
            if h.unbounded {
                page.unbounded += 1;
                continue;
            }
            match c.severity() {
                Some(Severity::Critical) => page.critical += 1,
                Some(Severity::High) => page.high += 1,
                Some(Severity::Medium) => page.medium += 1,
                Some(Severity::Low) => page.low += 1,
                _ => {}
            }
            page.kev += u32::from(c.kev);
            page.max_epss = max_opt(page.max_epss, c.epss);
        }
        if specific && !hits.is_empty() {
            page.fixed_in = self.fixed_in(&keys, &hits);
        }
        page.items = hits
            .iter()
            .skip(offset)
            .take(limit)
            .map(|h| {
                let c = &self.cves[h.idx as usize];
                CveRow {
                    id: c.id(),
                    cvss: c.cvss,
                    severity: sev_key(c.severity()),
                    kev: c.kev,
                    epss: c.epss,
                    cwe: c.cwe.to_vec(),
                    year: c.year,
                    fixed: h.fixed(),
                    range: h.range.clone(),
                    unbounded: h.unbounded,
                }
            })
            .collect();
        Some(page)
    }
}

/// One matched CVE of a query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hit {
    idx: u32,
    /// Matched affected range in table syntax (`[1.1,1.20.1)`, `=2016`); `None` when unbounded.
    pub range: Option<String>,
    /// NVD names the product without any version limit and no bounded entry exists.
    pub unbounded: bool,
}

impl Hit {
    /// Fixed version of the matched range: its exclusive upper bound.
    pub fn fixed(&self) -> Option<String> {
        match VerRange::parse(self.range.as_deref()?)? {
            VerRange::Between(_, Some((v, false))) => Some(v),
            _ => None,
        }
    }
}

fn query_version(q: &CveQuery) -> Option<&str> {
    q.version
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty() && *v != "-")
}

/// KEV first, then CVSS, EPSS, newer first; unbounded matches after the bounded ones.
fn sort_hits(hits: &mut [Hit], cves: &[CveRec]) {
    hits.sort_by(|x, y| {
        let (a, b) = (&cves[x.idx as usize], &cves[y.idx as usize]);
        x.unbounded
            .cmp(&y.unbounded)
            .then(b.kev.cmp(&a.kev))
            .then(cmp_f(b.cvss, a.cvss))
            .then(cmp_f(b.epss, a.epss))
            .then(b.year.cmp(&a.year))
            .then(a.id_year.cmp(&b.id_year))
            .then(a.id_num.cmp(&b.id_num))
    });
}

fn max_opt(a: Option<f32>, b: Option<f32>) -> Option<f32> {
    match (a, b) {
        (Some(x), Some(y)) => Some(x.max(y)),
        (x, None) => x,
        (None, y) => y,
    }
}

fn cmp_f(a: Option<f32>, b: Option<f32>) -> Ordering {
    a.unwrap_or(-1.0)
        .partial_cmp(&b.unwrap_or(-1.0))
        .unwrap_or(Ordering::Equal)
}

fn slot() -> &'static RwLock<Option<Arc<CveDb>>> {
    static S: RwLock<Option<Arc<CveDb>>> = RwLock::new(None);
    &S
}

/// The active table: an installed bundle table, else the embedded snapshot (parsed once).
pub fn db() -> Arc<CveDb> {
    if let Some(d) = slot().read().ok().and_then(|g| g.clone()) {
        return d;
    }
    static BUILTIN: OnceLock<Arc<CveDb>> = OnceLock::new();
    BUILTIN
        .get_or_init(|| Arc::new(CveDb::parse(NVD_GZ).unwrap_or_default()))
        .clone()
}

/// Validates a bundle table and returns its CVE count.
pub fn check(gz: &[u8]) -> Result<usize, CveError> {
    CveDb::parse(gz).map(|d| d.meta.cves)
}

/// Installs a bundle table, or with `None` goes back to the embedded one. Returns the CVE count
/// of the installed table (0 for the embedded one, which stays lazy).
pub fn install(gz: Option<&[u8]>) -> Result<usize, CveError> {
    let d = gz.map(CveDb::parse).transpose()?;
    let n = d.as_ref().map_or(0, |d| d.meta.cves);
    if let Ok(mut g) = slot().write() {
        *g = d.map(Arc::new);
    }
    Ok(n)
}

/// Raises a severity one step (KEV), capped at critical.
pub fn raise(s: Severity) -> Severity {
    match s {
        Severity::Info => Severity::Low,
        Severity::Low => Severity::Medium,
        Severity::Medium => Severity::High,
        _ => Severity::Critical,
    }
}

/// Severity of a CVE finding: the highest CVSS band, one step higher when any CVE is in KEV,
/// capped at medium for workstation software (`cap`).
pub fn finding_severity(s: &CveSummary, cap: Option<Severity>) -> Severity {
    let base = match s.max_cvss {
        Some(x) if x >= 9.0 && s.critical > 0 => Severity::Critical,
        Some(x) if x >= 7.0 => Severity::High,
        Some(x) if x >= 4.0 => Severity::Medium,
        Some(_) => Severity::Low,
        None => Severity::Low,
    };
    let sev = if s.kev > 0 { raise(base) } else { base };
    match cap {
        Some(c) if sev.rank() > c.rank() => c,
        _ => sev,
    }
}

mod subjects;
pub use subjects::{annotate, doc_matches, tech_matches, version_source, CveMatch, TechInput};

#[cfg(test)]
mod tests;
