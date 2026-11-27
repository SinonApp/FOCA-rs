//! robots.txt / sitemap.xml / security.txt: parsers and collection from Wayback snapshots.
//!
//! Bodies are taken from the archive (`https://web.archive.org/web/<ts>id_/<url>`,
//! `Access::Passive`) using CDX rows the engine already obtained while collecting archive
//! URLs; the target itself is never contacted. The pure functions ([`parse_robots`],
//! [`parse_sitemap`], [`parse_security_txt`], [`report_from_bodies`]) also accept
//! bodies fetched in other ways.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::OnceLock;

use foca_net::{Access, NetClient, NetRequest};
use regex::Regex;
use serde::{Deserialize, Serialize};

pub const MODULE: &str = "wayback";
pub const ARCHIVE_BASE: &str = "https://web.archive.org";

/// Kind of well-known file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WellKnownKind {
    Robots,
    Sitemap,
    SecurityTxt,
}

/// Determines the kind from the URL (`/robots.txt`, `/sitemap*.xml[.gz]`, `sitemap_index.xml`,
/// `/.well-known/security.txt`, `/security.txt`).
pub fn classify_url(url: &str) -> Option<WellKnownKind> {
    let path = url
        .split(['?', '#'])
        .next()
        .unwrap_or("")
        .to_ascii_lowercase();
    let path = path.split_once("://").map_or(path.as_str(), |(_, r)| r);
    let path = path.find('/').map_or("", |i| &path[i..]);
    let file = path.rsplit('/').next().unwrap_or("");
    if path == "/robots.txt" {
        Some(WellKnownKind::Robots)
    } else if path == "/.well-known/security.txt" || path == "/security.txt" {
        Some(WellKnownKind::SecurityTxt)
    } else if file.starts_with("sitemap") && (file.ends_with(".xml") || file.ends_with(".txt")) {
        Some(WellKnownKind::Sitemap)
    } else {
        None
    }
}

// ---------- robots.txt ----------

/// A rule group for a set of user agents.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RobotsGroup {
    pub agents: Vec<String>,
    pub allow: Vec<String>,
    pub disallow: Vec<String>,
}

/// A parsed robots.txt.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Robots {
    pub groups: Vec<RobotsGroup>,
    pub sitemaps: Vec<String>,
    pub crawl_delay: Option<f64>,
    /// The `Host:` directive (Yandex).
    pub host: Option<String>,
    /// Paths that look like hidden sections or documents.
    pub interesting: Vec<HiddenPath>,
    /// The body (first 64 KiB) for technology signals; not stored.
    #[serde(default, skip_serializing)]
    pub text: String,
}

/// A path worth attention.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct HiddenPath {
    pub path: String,
    /// `admin`, `backup`, `dev`, `config`, `api`, `document`, `vcs`, … (see [`classify_path`]).
    pub reason: String,
    /// Origin: URL of the robots.txt or its archived copy.
    pub source: String,
}

const DOC_EXT: &[&str] = &[
    "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "odt", "ods", "odp", "rtf", "csv", "txt",
    "zip", "rar", "7z", "sql", "bak", "old", "log", "xml", "json", "conf", "ini", "env",
];

/// Returns why a path is interesting, or `None`. Order matters: specific reasons come first.
pub fn classify_path(path: &str) -> Option<&'static str> {
    let l = path.to_ascii_lowercase();
    let file = l
        .split(['?', '#'])
        .next()
        .unwrap_or("")
        .trim_end_matches(['*', '$']);
    let ext = file.rsplit_once('.').filter(|(a, _)| !a.ends_with('/'));
    const RULES: &[(&str, &[&str])] = &[
        ("vcs", &["/.git", "/.svn", "/.hg", "/.env", "/.ds_store"]),
        (
            "backup",
            &[
                "backup", "/bak", ".bak", "/old/", "/old_", "_old", "/dump", "archive",
            ],
        ),
        (
            "admin",
            &[
                "admin",
                "/manager",
                "/panel",
                "/cpanel",
                "phpmyadmin",
                "/bitrix/",
                "/wp-login",
                "/login",
                "/auth",
                "/cms",
            ],
        ),
        (
            "dev",
            &[
                "/dev", "/test", "/stage", "/staging", "/beta", "/demo", "/debug", "/tmp", "/temp",
                "/sandbox",
            ],
        ),
        (
            "config",
            &[
                "config", "/install", "/setup", "/conf/", "settings", "/cgi-bin",
            ],
        ),
        (
            "private",
            &[
                "private",
                "secret",
                "internal",
                "/intranet",
                "/personal",
                "/lk/",
                "/cabinet",
                "/account",
            ],
        ),
        (
            "api",
            &[
                "/api", "/graphql", "/rest/", "/soap", "/wsdl", "/swagger", "/openapi",
            ],
        ),
        (
            "upload",
            &["upload", "/files/", "/docs/", "/documents/", "/download"],
        ),
        ("search", &["/search", "?s=", "?q="]),
    ];
    for (reason, needles) in RULES {
        if needles.iter().any(|n| l.contains(n)) {
            return Some(reason);
        }
    }
    if let Some((_, e)) = ext {
        if DOC_EXT.contains(&e) {
            return Some("document");
        }
    }
    None
}

/// Parses robots.txt. `source` is its origin (for [`HiddenPath::source`]).
pub fn parse_robots(text: &str, source: &str) -> Robots {
    let mut r = Robots::default();
    let mut cut = text.len().min(64 << 10);
    while !text.is_char_boundary(cut) {
        cut -= 1;
    }
    r.text = text[..cut].to_string();
    let mut cur: Option<RobotsGroup> = None;
    let mut last_was_agent = false;
    for raw in text.lines() {
        let line = raw.split('#').next().unwrap_or("").trim();
        let Some((k, v)) = line.split_once(':') else {
            continue;
        };
        let (k, v) = (k.trim().to_ascii_lowercase(), v.trim().to_string());
        match k.as_str() {
            "user-agent" => {
                if !last_was_agent {
                    if let Some(g) = cur.take() {
                        r.groups.push(g);
                    }
                    cur = Some(RobotsGroup::default());
                }
                cur.get_or_insert_with(RobotsGroup::default).agents.push(v);
                last_was_agent = true;
                continue;
            }
            "disallow" if !v.is_empty() => cur
                .get_or_insert_with(RobotsGroup::default)
                .disallow
                .push(v),
            "allow" if !v.is_empty() => cur.get_or_insert_with(RobotsGroup::default).allow.push(v),
            "sitemap" if !v.is_empty() => {
                // `Sitemap: https://…`: split_once cut off the scheme.
                let full = line.split_once(':').map(|x| x.1.trim()).unwrap_or("");
                if !r.sitemaps.iter().any(|s| s == full) {
                    r.sitemaps.push(full.to_string());
                }
            }
            "crawl-delay" => r.crawl_delay = v.parse().ok(),
            "host" if !v.is_empty() => r.host = Some(v),
            _ => {}
        }
        last_was_agent = false;
    }
    if let Some(g) = cur {
        r.groups.push(g);
    }
    let mut seen = BTreeSet::new();
    for g in &r.groups {
        for p in g.disallow.iter().chain(&g.allow) {
            if let Some(reason) = classify_path(p) {
                if seen.insert(p.clone()) {
                    r.interesting.push(HiddenPath {
                        path: p.clone(),
                        reason: reason.into(),
                        source: source.into(),
                    });
                }
            }
        }
    }
    r
}

// ---------- sitemap ----------

/// A URL from a sitemap.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SitemapUrl {
    pub loc: String,
    pub lastmod: Option<String>,
}

/// A parsed sitemap.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sitemap {
    /// `<sitemapindex>`: `urls` holds child sitemaps.
    pub is_index: bool,
    pub urls: Vec<SitemapUrl>,
}

fn sm_res() -> &'static (Regex, Regex, Regex) {
    static R: OnceLock<(Regex, Regex, Regex)> = OnceLock::new();
    R.get_or_init(|| {
        (
            Regex::new(r"(?is)<(?:\w+:)?(url|sitemap)\b[^>]*>(.*?)</(?:\w+:)?(?:url|sitemap)>")
                .expect("re"),
            Regex::new(
                r"(?is)<(?:\w+:)?loc>\s*(?:<!\[CDATA\[)?\s*(.*?)\s*(?:\]\]>)?\s*</(?:\w+:)?loc>",
            )
            .expect("re"),
            Regex::new(r"(?is)<(?:\w+:)?lastmod>\s*(.*?)\s*</(?:\w+:)?lastmod>").expect("re"),
        )
    })
}

/// Parses a sitemap (XML `urlset`/`sitemapindex`, or plain text with one URL per line).
/// Gzipped `.gz` files must be decompressed by the caller.
pub fn parse_sitemap(text: &str) -> Sitemap {
    let (entry, loc, lastmod) = sm_res();
    // The first ≤ 4096 bytes, cut on a char boundary (slicing inside a multi-byte char panics).
    let mut cut = text.len().min(4096);
    while !text.is_char_boundary(cut) {
        cut -= 1;
    }
    let head = &text[..cut].to_ascii_lowercase();
    let is_index = head.contains("<sitemapindex");
    let mut urls = Vec::new();
    let mut seen = BTreeSet::new();
    for c in entry.captures_iter(text) {
        let body = &c[2];
        let Some(l) = loc.captures(body) else {
            continue;
        };
        let l = crate::favicon::html_unescape(l[1].trim());
        if l.is_empty() || !seen.insert(l.clone()) {
            continue;
        }
        urls.push(SitemapUrl {
            loc: l,
            lastmod: lastmod.captures(body).map(|m| m[1].to_string()),
        });
    }
    if urls.is_empty() && !head.contains('<') {
        for l in text.lines().map(str::trim) {
            if (l.starts_with("http://") || l.starts_with("https://")) && seen.insert(l.to_string())
            {
                urls.push(SitemapUrl {
                    loc: l.to_string(),
                    lastmod: None,
                });
            }
        }
    }
    Sitemap { is_index, urls }
}

/// Returns `true` if the URL points to a document (by extension: pdf, doc(x), xls(x),
/// ppt(x), odt, …).
pub fn is_document_url(u: &str) -> bool {
    const EXT: &[&str] = &[
        "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "pps", "ppsx", "odt", "ods", "odp",
        "rtf", "csv", "svg", "indd", "wpd",
    ];
    let p = u
        .split(['?', '#'])
        .next()
        .unwrap_or("")
        .to_ascii_lowercase();
    let file = p.rsplit('/').next().unwrap_or("");
    file.rsplit_once('.').is_some_and(|(_, e)| EXT.contains(&e))
}

// ---------- security.txt ----------

/// A parsed security.txt (RFC 9116).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecurityTxt {
    pub source: String,
    pub contacts: Vec<String>,
    /// E-mail addresses from `Contact: mailto:` and bare addresses.
    pub emails: Vec<String>,
    pub expires: Option<String>,
    pub encryption: Vec<String>,
    pub policy: Vec<String>,
    pub acknowledgments: Vec<String>,
    pub hiring: Vec<String>,
    pub canonical: Vec<String>,
    pub preferred_languages: Option<String>,
    /// PGP-signed (`-----BEGIN PGP SIGNED MESSAGE-----`).
    pub signed: bool,
}

/// Parses security.txt.
pub fn parse_security_txt(text: &str, source: &str) -> SecurityTxt {
    let mut s = SecurityTxt {
        source: source.into(),
        signed: text.contains("-----BEGIN PGP SIGNED MESSAGE-----"),
        ..Default::default()
    };
    for raw in text.lines() {
        let line = raw.trim();
        if line.starts_with('#') || line.starts_with("-----") {
            continue;
        }
        let Some((k, v)) = line.split_once(':') else {
            continue;
        };
        let v = v.trim().to_string();
        if v.is_empty() {
            continue;
        }
        match k.trim().to_ascii_lowercase().as_str() {
            "contact" => {
                let e = v.strip_prefix("mailto:").unwrap_or(&v);
                if e.contains('@') && !e.contains('/') {
                    s.emails.push(e.to_string());
                }
                s.contacts.push(v);
            }
            "expires" => s.expires = Some(v),
            "encryption" => s.encryption.push(v),
            "policy" => s.policy.push(v),
            "acknowledgments" | "acknowledgements" => s.acknowledgments.push(v),
            "hiring" => s.hiring.push(v),
            "canonical" => s.canonical.push(v),
            "preferred-languages" => s.preferred_languages = Some(v),
            _ => {}
        }
    }
    s
}

// CDX and archive.

/// A Wayback CDX row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CdxRecord {
    pub timestamp: String,
    pub original: String,
    pub mime: String,
    pub status: String,
    pub digest: String,
}

/// Parses CDX API output, either text (`urlkey timestamp original mimetype statuscode digest
/// length`) or JSON (`output=json`, first row is the header). Unrecognized rows are skipped.
pub fn parse_cdx(text: &str) -> Vec<CdxRecord> {
    let t = text.trim_start();
    if t.starts_with('[') {
        let Ok(rows) = serde_json::from_str::<Vec<Vec<String>>>(t) else {
            return vec![];
        };
        let Some((head, rest)) = rows.split_first() else {
            return vec![];
        };
        let idx = |n: &str| head.iter().position(|h| h == n);
        let (Some(ts), Some(orig)) = (idx("timestamp"), idx("original")) else {
            return vec![];
        };
        let get = |r: &Vec<String>, i: Option<usize>| {
            i.and_then(|i| r.get(i)).cloned().unwrap_or_default()
        };
        return rest
            .iter()
            .map(|r| CdxRecord {
                timestamp: get(r, Some(ts)),
                original: get(r, Some(orig)),
                mime: get(r, idx("mimetype")),
                status: get(r, idx("statuscode")),
                digest: get(r, idx("digest")),
            })
            .collect();
    }
    t.lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            match f.len() {
                n if n >= 6 => Some(CdxRecord {
                    timestamp: f[1].into(),
                    original: f[2].into(),
                    mime: f[3].into(),
                    status: f[4].into(),
                    digest: f[5].into(),
                }),
                2 if f[0].len() == 14 && f[0].bytes().all(|b| b.is_ascii_digit()) => {
                    Some(CdxRecord {
                        timestamp: f[0].into(),
                        original: f[1].into(),
                        mime: String::new(),
                        status: String::new(),
                        digest: String::new(),
                    })
                }
                _ => None,
            }
        })
        .collect()
}

/// An archived copy to download.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Snapshot {
    pub kind: WellKnownKind,
    pub timestamp: String,
    pub original: String,
}

impl Snapshot {
    /// URL of the raw copy (`id_` strips the Wayback toolbar and rewriting).
    pub fn archive_url(&self, base: &str) -> String {
        format!(
            "{}/web/{}id_/{}",
            base.trim_end_matches('/'),
            self.timestamp,
            self.original
        )
    }
}

/// Selects robots/sitemap/security.txt snapshots: status 200 (or unknown) only, deduplicated
/// by digest, newest first, at most `per_url` versions per original URL.
pub fn select_snapshots(records: &[CdxRecord], per_url: usize) -> Vec<Snapshot> {
    let mut by_url: BTreeMap<(WellKnownKind, String), Vec<&CdxRecord>> = BTreeMap::new();
    for r in records {
        if !(r.status.is_empty() || r.status == "200" || r.status == "-") {
            continue;
        }
        if let Some(k) = classify_url(&r.original) {
            let key = r
                .original
                .replace("http://", "https://")
                .replace(":443/", "/")
                .replace(":80/", "/");
            by_url.entry((k, key)).or_default().push(r);
        }
    }
    let mut out = Vec::new();
    for ((kind, _), mut v) in by_url {
        v.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
        let mut digests = BTreeSet::new();
        for r in v {
            if !r.digest.is_empty() && !digests.insert(r.digest.clone()) {
                continue;
            }
            out.push(Snapshot {
                kind,
                timestamp: r.timestamp.clone(),
                original: r.original.clone(),
            });
            if out.iter().filter(|s| s.original == r.original).count() >= per_url {
                break;
            }
        }
    }
    out
}

/// Summary of the well-known files.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct WellKnownReport {
    pub robots: Vec<(String, Robots)>,
    pub sitemap_urls: Vec<SitemapUrl>,
    pub security: Vec<SecurityTxt>,
    /// Hidden sections and interesting paths (from robots.txt), deduplicated.
    pub hidden_paths: Vec<HiddenPath>,
    /// Document links (from sitemaps and robots).
    pub documents: Vec<String>,
    /// Processed sources (snapshot URLs).
    pub sources: Vec<String>,
    pub errors: Vec<String>,
}

/// Turns well-known file bodies (fetched in any way) into a report: same merging rules as
/// [`harvest_from_archive`].
pub fn report_from_bodies<'a>(
    bodies: impl IntoIterator<Item = (WellKnownKind, &'a str, &'a str)>,
) -> WellKnownReport {
    Collector::from_bodies(bodies)
}

/// Options for archive collection.
#[derive(Debug, Clone)]
pub struct HarvestOptions {
    pub archive_base: String,
    /// Versions per original URL (distinct digests).
    pub per_url: usize,
    /// Maximum number of child sitemaps (from indexes or robots) fetched from the archive.
    pub max_child_sitemaps: usize,
    /// Body size limit per snapshot.
    pub max_body: u64,
}

impl Default for HarvestOptions {
    fn default() -> Self {
        HarvestOptions {
            archive_base: ARCHIVE_BASE.into(),
            per_url: 2,
            max_child_sitemaps: 20,
            max_body: 10 << 20,
        }
    }
}

async fn fetch(client: &NetClient, url: &str, limit: u64) -> Result<String, String> {
    let req = NetRequest::get(url, MODULE, Access::Passive).map_err(|e| e.to_string())?;
    let r = client
        .send(req)
        .await
        .and_then(|r| r.ensure_success())
        .map_err(|e| format!("{url}: {e}"))?;
    r.text_limited(limit)
        .await
        .map_err(|e| format!("{url}: {e}"))
}

/// Selects robots/sitemap/security.txt snapshots from Wayback CDX rows, downloads them from
/// the archive (`Access::Passive`) and parses them. Child sitemaps are fetched as
/// `<archive>/web/<ts>id_/<url>` (Wayback picks the nearest capture). Errors of individual
/// snapshots go to `errors`; cancelling the client stops the collection.
pub async fn harvest_from_archive(
    client: &NetClient,
    cdx: &str,
    opts: &HarvestOptions,
) -> WellKnownReport {
    Collector::harvest(client, cdx, opts).await
}

/// Merges fetched files into one report: deduplicates hidden paths and sitemap URLs, picks out
/// document links and records fetch errors.
#[derive(Default)]
struct Collector {
    rep: WellKnownReport,
}

impl Collector {
    fn from_bodies<'a>(
        bodies: impl IntoIterator<Item = (WellKnownKind, &'a str, &'a str)>,
    ) -> WellKnownReport {
        let mut col = Collector::default();
        for (kind, source, body) in bodies {
            col.add_body(kind, source, body);
        }
        col.rep
    }

    async fn harvest(client: &NetClient, cdx: &str, opts: &HarvestOptions) -> WellKnownReport {
        let mut col = Collector::default();
        let snaps = select_snapshots(&parse_cdx(cdx), opts.per_url.max(1));
        let mut children: Vec<(String, String)> = Vec::new();
        for s in &snaps {
            if client.is_cancelled() {
                break;
            }
            let url = s.archive_url(&opts.archive_base);
            match fetch(client, &url, opts.max_body).await {
                Ok(body) => {
                    for c in col.add_body(s.kind, &url, &body) {
                        children.push((s.timestamp.clone(), c));
                    }
                }
                Err(e) => col.rep.errors.push(e),
            }
        }
        let mut done: BTreeSet<String> = snaps.iter().map(|s| s.original.clone()).collect();
        let mut n = 0;
        while let Some((ts, child)) = children.pop() {
            if n >= opts.max_child_sitemaps || client.is_cancelled() {
                break;
            }
            if !done.insert(child.clone()) || !child.starts_with("http") {
                continue;
            }
            n += 1;
            let url = format!(
                "{}/web/{}id_/{}",
                opts.archive_base.trim_end_matches('/'),
                ts,
                child
            );
            match fetch(client, &url, opts.max_body).await {
                Ok(body) => {
                    for c in col.add_body(WellKnownKind::Sitemap, &url, &body) {
                        children.push((ts.clone(), c));
                    }
                }
                Err(e) => col.rep.errors.push(e),
            }
        }
        col.rep
    }

    /// Adds a file body. Returns child sitemaps (from robots `Sitemap:` and sitemap indexes).
    fn add_body(&mut self, kind: WellKnownKind, source: &str, body: &str) -> Vec<String> {
        self.rep.sources.push(source.to_string());
        let mut children = Vec::new();
        match kind {
            WellKnownKind::Robots => {
                let r = parse_robots(body, source);
                for h in &r.interesting {
                    if (h.reason == "document" || is_document_url(&h.path))
                        && !self.rep.documents.contains(&h.path)
                    {
                        self.rep.documents.push(h.path.clone());
                    }
                    if !self.rep.hidden_paths.iter().any(|x| x.path == h.path) {
                        self.rep.hidden_paths.push(h.clone());
                    }
                }
                children.extend(r.sitemaps.iter().cloned());
                self.rep.robots.push((source.to_string(), r));
            }
            WellKnownKind::Sitemap => {
                let s = parse_sitemap(body);
                for u in s.urls {
                    if s.is_index {
                        children.push(u.loc);
                        continue;
                    }
                    if is_document_url(&u.loc) && !self.rep.documents.contains(&u.loc) {
                        self.rep.documents.push(u.loc.clone());
                    }
                    if !self.rep.sitemap_urls.iter().any(|x| x.loc == u.loc) {
                        self.rep.sitemap_urls.push(u);
                    }
                }
            }
            WellKnownKind::SecurityTxt => {
                let s = parse_security_txt(body, source);
                if !s.contacts.is_empty() || !s.policy.is_empty() {
                    self.rep.security.push(s);
                }
            }
        }
        children
    }
}

#[cfg(test)]
mod tests {
    /// A multi-byte character at byte 4096 must not panic.
    #[test]
    fn sitemap_head_cut_on_char_boundary() {
        let t = format!(
            "{}\u{3000}<urlset><url><loc>https://a.test/x</loc></url></urlset>",
            "a".repeat(4094)
        );
        let sm = super::parse_sitemap(&t);
        assert_eq!(sm.urls.len(), 1);
    }

    use super::*;

    const ROBOTS: &str = include_str!("../tests/fixtures/robots.txt");

    #[test]
    fn robots_parsed() {
        let r = parse_robots(ROBOTS, "src");
        assert_eq!(r.groups.len(), 2);
        assert_eq!(r.groups[0].agents, vec!["*".to_string()]);
        assert_eq!(
            r.groups[1].agents,
            vec!["Yandex".to_string(), "Googlebot".to_string()]
        );
        assert_eq!(
            r.sitemaps,
            vec!["https://ex.com/sitemap_index.xml".to_string()]
        );
        assert_eq!(r.crawl_delay, Some(2.0));
        assert_eq!(r.host.as_deref(), Some("ex.com"));
        let reason = |p: &str| {
            r.interesting
                .iter()
                .find(|h| h.path == p)
                .map(|h| h.reason.as_str())
        };
        assert_eq!(reason("/wp-admin/"), Some("admin"));
        assert_eq!(reason("/backup_2019/"), Some("backup"));
        assert_eq!(reason("/staging/"), Some("dev"));
        assert_eq!(reason("/.git/"), Some("vcs"));
        assert_eq!(reason("/files/price.xlsx"), Some("upload"));
        assert_eq!(reason("/reports/annual.pdf"), Some("document"));
        assert_eq!(reason("/about/"), None);
    }

    #[test]
    fn sitemap_index_and_urlset() {
        let idx = parse_sitemap(
            r#"<?xml version="1.0"?><sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"><sitemap><loc>https://ex.com/sitemap-posts.xml</loc><lastmod>2024-01-01</lastmod></sitemap><sitemap><loc><![CDATA[https://ex.com/sitemap-docs.xml]]></loc></sitemap></sitemapindex>"#,
        );
        assert!(idx.is_index);
        assert_eq!(idx.urls[1].loc, "https://ex.com/sitemap-docs.xml");
        let us = parse_sitemap("<urlset><url><loc>https://ex.com/a?x=1&amp;y=2</loc><lastmod>2023-05-05</lastmod></url><url><loc>https://ex.com/f/plan.DOCX</loc></url></urlset>");
        assert!(!us.is_index);
        assert_eq!(us.urls[0].loc, "https://ex.com/a?x=1&y=2");
        assert_eq!(us.urls[0].lastmod.as_deref(), Some("2023-05-05"));
        assert!(is_document_url(&us.urls[1].loc));
        let txt = parse_sitemap("https://ex.com/1\nhttps://ex.com/2\n");
        assert_eq!(txt.urls.len(), 2);
    }

    #[test]
    fn security_txt_parsed() {
        let s = parse_security_txt("-----BEGIN PGP SIGNED MESSAGE-----\n# c\nContact: mailto:security@ex.com\nContact: https://ex.com/report\nExpires: 2027-01-01T00:00:00Z\nEncryption: https://ex.com/pgp.asc\nPolicy: https://ex.com/policy\nPreferred-Languages: ru, en\n", "s");
        assert_eq!(s.emails, vec!["security@ex.com".to_string()]);
        assert_eq!(s.contacts.len(), 2);
        assert_eq!(s.expires.as_deref(), Some("2027-01-01T00:00:00Z"));
        assert!(s.signed);
        assert_eq!(s.preferred_languages.as_deref(), Some("ru, en"));
    }

    #[test]
    fn cdx_and_selection() {
        let cdx = "com,ex)/robots.txt 20200101000000 http://ex.com/robots.txt text/plain 200 AAA 100\n\
com,ex)/robots.txt 20210101000000 https://ex.com/robots.txt text/plain 200 BBB 100\n\
com,ex)/robots.txt 20220101000000 https://ex.com/robots.txt text/plain 200 BBB 100\n\
com,ex)/robots.txt 20230101000000 https://ex.com/robots.txt text/html 404 CCC 100\n\
com,ex)/sitemap.xml 20230101000000 https://ex.com/sitemap.xml text/xml 200 DDD 100\n\
com,ex)/.well-known/security.txt 20230101000000 https://ex.com/.well-known/security.txt text/plain 200 EEE 1\n\
com,ex)/index.html 20230101000000 https://ex.com/index.html text/html 200 FFF 1\n";
        let recs = parse_cdx(cdx);
        assert_eq!(recs.len(), 7);
        let s = select_snapshots(&recs, 2);
        let robots: Vec<&str> = s
            .iter()
            .filter(|x| x.kind == WellKnownKind::Robots)
            .map(|x| x.timestamp.as_str())
            .collect();
        assert_eq!(robots, vec!["20220101000000", "20200101000000"]);
        assert_eq!(s.len(), 4);
        assert_eq!(
            s[0].archive_url("https://web.archive.org"),
            "https://web.archive.org/web/20220101000000id_/https://ex.com/robots.txt"
        );
        let j = parse_cdx(
            r#"[["urlkey","timestamp","original","mimetype","statuscode","digest","length"],["k","20240101000000","https://ex.com/robots.txt","text/plain","200","X","1"]]"#,
        );
        assert_eq!(j[0].original, "https://ex.com/robots.txt");
        assert_eq!(
            classify_url("https://ex.com/sitemap-posts.xml?x"),
            Some(WellKnownKind::Sitemap)
        );
        assert_eq!(classify_url("https://ex.com/a/robots.txt"), None);
    }
}
