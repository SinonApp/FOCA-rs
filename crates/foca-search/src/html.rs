//! Lightweight HTML link extraction (no DOM, just a tag and attribute tokenizer), robots.txt and
//! sitemap.xml parsing. Heavy parsers (scraper/html5ever) are unnecessary: the crawler only needs
//! `href`/`src` and `<base>`.

use std::collections::VecDeque;

use url::Url;

/// Link-bearing attributes per tag.
const LINK_ATTRS: &[(&str, &str)] = &[
    ("a", "href"),
    ("area", "href"),
    ("link", "href"),
    ("iframe", "src"),
    ("frame", "src"),
    ("embed", "src"),
    ("object", "data"),
    ("img", "src"),
    ("source", "src"),
];

fn decode_entities(s: &str) -> String {
    s.replace("&amp;", "&")
        .replace("&#38;", "&")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
}

/// Parses the attributes inside a tag (`a href="x" class=y`).
fn parse_attrs(tag: &str) -> Vec<(String, String)> {
    let b = tag.as_bytes();
    let mut i = 0;
    let mut out = Vec::new();
    while i < b.len() {
        while i < b.len() && (b[i].is_ascii_whitespace() || b[i] == b'/') {
            i += 1;
        }
        let ks = i;
        while i < b.len() && !b[i].is_ascii_whitespace() && b[i] != b'=' && b[i] != b'/' {
            i += 1;
        }
        let key = tag[ks..i].to_ascii_lowercase();
        while i < b.len() && b[i].is_ascii_whitespace() {
            i += 1;
        }
        if i < b.len() && b[i] == b'=' {
            i += 1;
            while i < b.len() && b[i].is_ascii_whitespace() {
                i += 1;
            }
            let val = if i < b.len() && (b[i] == b'"' || b[i] == b'\'') {
                let q = b[i];
                i += 1;
                let vs = i;
                while i < b.len() && b[i] != q {
                    i += 1;
                }
                let v = &tag[vs..i.min(b.len())];
                i += 1;
                v
            } else {
                let vs = i;
                while i < b.len() && !b[i].is_ascii_whitespace() {
                    i += 1;
                }
                &tag[vs..i]
            };
            if !key.is_empty() {
                out.push((key, decode_entities(val.trim())));
            }
        } else if !key.is_empty() {
            out.push((key, String::new()));
        } else {
            i += 1;
        }
    }
    out
}

/// A link found on a page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PageLink {
    pub url: Url,
    /// Tag the link came from (`a`, `img`, `iframe`, ...).
    pub tag: String,
    /// `rel="nofollow"` on the link, or `<meta name="robots" content="nofollow">` on the page.
    pub nofollow: bool,
    /// Declared `width`/`height` of an `<img>`.
    pub w: Option<u32>,
    pub h: Option<u32>,
}

/// What a page contains, for the crawler: links, script files and app shell signs.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PageScan {
    pub links: Vec<PageLink>,
    /// External script files (`<script src>`).
    pub scripts: Vec<Url>,
    /// Number of `<script>` tags, inline ones included.
    pub script_tags: usize,
    /// Visible text length outside tags, scripts and styles (whitespace not counted).
    pub text_len: usize,
    /// A JavaScript app mount point (`id="root"`, `id="app"`, `<app-root>`, Flutter loader).
    pub app_root: bool,
}

/// Ids and markers of client-side app mount points.
const APP_ROOT_IDS: &[&str] = &[
    "root",
    "app",
    "__next",
    "__nuxt",
    "___gatsby",
    "q-app",
    "main-app",
];

impl PageScan {
    /// Links of `<a>`/`<area>` tags (navigation, as opposed to embedded resources).
    pub fn nav_links(&self) -> usize {
        self.links
            .iter()
            .filter(|l| l.tag == "a" || l.tag == "area")
            .count()
    }

    /// The page looks like a JavaScript app shell: scripts, almost no text and almost no
    /// navigation links, usually with an app mount point. Its links appear only after rendering.
    pub fn looks_like_app_shell(&self) -> bool {
        self.script_tags > 0
            && self.text_len < 400
            && self.nav_links() <= 2
            && (self.app_root || self.text_len < 80)
    }
}

fn first_src_of_srcset(v: &str) -> Option<&str> {
    v.split(',').next()?.split_whitespace().next()
}

/// Scans a page: links (absolute, without fragments, honoring `<base href>`), script files and
/// app shell signs. The contents of `<script>` and `<style>` and HTML comments are skipped.
pub fn scan_page(html: &str, page: &Url) -> PageScan {
    let mut base = page.clone();
    let mut out = PageScan::default();
    let mut page_nofollow = false;
    let lower = html.to_ascii_lowercase();
    if lower.contains("flutter_bootstrap.js")
        || lower.contains("main.dart.js")
        || lower.contains("<app-root")
        || lower.contains("ng-version=")
    {
        out.app_root = true;
    }
    let join = |base: &Url, v: &str| -> Option<Url> {
        let lv = v.to_ascii_lowercase();
        if lv.starts_with("javascript:")
            || lv.starts_with("mailto:")
            || lv.starts_with("data:")
            || lv.starts_with("tel:")
        {
            return None;
        }
        let mut u = base.join(v).ok()?;
        if !matches!(u.scheme(), "http" | "https") {
            return None;
        }
        u.set_fragment(None);
        Some(u)
    };
    let mut i = 0;
    while let Some(p) = lower[i..].find('<') {
        let start = i + p;
        out.text_len += html[i..start]
            .chars()
            .filter(|c| !c.is_whitespace())
            .count();
        if lower[start..].starts_with("<!--") {
            i = lower[start..]
                .find("-->")
                .map(|e| start + e + 3)
                .unwrap_or(lower.len());
            continue;
        }
        let Some(e) = lower[start..].find('>') else {
            i = lower.len();
            break;
        };
        let end = start + e;
        let inner = &html[start + 1..end];
        let name_end = inner
            .find(|c: char| c.is_ascii_whitespace() || c == '/' || c == '>')
            .unwrap_or(inner.len());
        let name = inner[..name_end].to_ascii_lowercase();
        i = end + 1;
        let attrs = || parse_attrs(&inner[name_end..]);
        if name == "script" || name == "style" {
            if name == "script" {
                out.script_tags += 1;
                if let Some((_, v)) = attrs().into_iter().find(|(k, _)| k == "src") {
                    if let Some(u) = join(&base, &v) {
                        out.scripts.push(u);
                    }
                }
            }
            let close = format!("</{name}");
            i = lower[i..]
                .find(&close)
                .map(|x| i + x)
                .unwrap_or(lower.len());
            continue;
        }
        if name == "base" {
            if let Some((_, v)) = attrs().into_iter().find(|(k, _)| k == "href") {
                if let Ok(b) = page.join(&v) {
                    base = b;
                }
            }
            continue;
        }
        if name == "meta" {
            let a = attrs();
            let is_robots = a
                .iter()
                .any(|(k, v)| k == "name" && v.eq_ignore_ascii_case("robots"));
            if is_robots
                && a.iter()
                    .any(|(k, v)| k == "content" && v.to_ascii_lowercase().contains("nofollow"))
            {
                page_nofollow = true;
            }
            continue;
        }
        if !out.app_root && matches!(name.as_str(), "div" | "main" | "body" | "section") {
            if let Some((_, v)) = attrs().into_iter().find(|(k, _)| k == "id") {
                out.app_root = APP_ROOT_IDS.contains(&v.as_str());
            }
        }
        let Some((_, attr)) = LINK_ATTRS.iter().find(|(t, _)| *t == name) else {
            continue;
        };
        let a = attrs();
        let num = |key: &str| {
            a.iter()
                .find(|(k, _)| k == key)
                .and_then(|(_, v)| v.trim_end_matches("px").trim().parse::<u32>().ok())
        };
        let nofollow = a.iter().any(|(k, v)| {
            k == "rel"
                && v.split_ascii_whitespace()
                    .any(|r| r.eq_ignore_ascii_case("nofollow"))
        });
        let (w, h) = if name == "img" {
            (num("width"), num("height"))
        } else {
            (None, None)
        };
        let mut push = |v: &str| {
            if let Some(u) = join(&base, v) {
                if !out.links.iter().any(|l| l.url == u && l.tag == name) {
                    out.links.push(PageLink {
                        url: u,
                        tag: name.clone(),
                        nofollow,
                        w,
                        h,
                    });
                }
            }
        };
        for (k, v) in &a {
            if v.is_empty() {
                continue;
            }
            if k == attr {
                push(v);
            } else if name == "img" && (k == "data-src" || k == "data-original") {
                // lazy loading keeps the real image here
                push(v);
            } else if (name == "img" || name == "source") && (k == "srcset" || k == "data-srcset") {
                if let Some(s) = first_src_of_srcset(v) {
                    push(s);
                }
            }
        }
    }
    out.text_len += html[i.min(html.len())..]
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '>')
        .count();
    if page_nofollow {
        for l in &mut out.links {
            l.nofollow = true;
        }
    }
    out
}

/// Returns the page's links (absolute, without fragments), honoring `<base href>`. The contents
/// of `<script>` and `<style>` and HTML comments are skipped.
pub fn extract_links(html: &str, page: &Url) -> Vec<Url> {
    scan_page(html, page)
        .links
        .into_iter()
        .map(|l| l.url)
        .collect()
}

/// A robots.txt group: user agents, rules (allow, pattern) and crawl delay.
type RobotsGroup = (Vec<String>, Vec<(bool, String)>, Option<f64>);

/// robots.txt rules that apply to our crawler.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Robots {
    /// (allow, path pattern)
    rules: Vec<(bool, String)>,
    sitemaps: Vec<String>,
    pub crawl_delay: Option<f64>,
}

impl Robots {
    /// Returns the sitemaps listed in robots.txt except the one at `known`; entries are resolved
    /// against `origin` for the comparison and kept as written.
    pub fn other_sitemaps(&self, origin: &Url, known: &Url) -> VecDeque<String> {
        self.sitemaps
            .iter()
            .filter(|m| origin.join(m).map(|x| &x != known).unwrap_or(false))
            .cloned()
            .collect()
    }

    /// Parses robots.txt, taking the group whose `User-agent` contains the given name (case-insensitive),
    /// otherwise the `*` group.
    pub fn parse(text: &str, agent: &str) -> Robots {
        let agent = agent.to_ascii_lowercase();
        let mut sitemaps = Vec::new();
        // groups: (user agents, rules, delay)
        let mut groups: Vec<RobotsGroup> = Vec::new();
        let mut in_agents = false;
        for line in text.lines() {
            let line = line.split('#').next().unwrap_or("").trim();
            let Some((k, v)) = line.split_once(':') else {
                continue;
            };
            let k = k.trim().to_ascii_lowercase();
            let v = v.trim();
            match k.as_str() {
                "user-agent" => {
                    if !in_agents {
                        groups.push((Vec::new(), Vec::new(), None));
                    }
                    in_agents = true;
                    if let Some(g) = groups.last_mut() {
                        g.0.push(v.to_ascii_lowercase());
                    }
                }
                "allow" | "disallow" => {
                    in_agents = false;
                    if let Some(g) = groups.last_mut() {
                        if !(k == "disallow" && v.is_empty()) {
                            g.1.push((k == "allow", v.to_string()));
                        }
                    }
                }
                "crawl-delay" => {
                    in_agents = false;
                    if let Some(g) = groups.last_mut() {
                        g.2 = v.parse().ok();
                    }
                }
                "sitemap" => {
                    // `Sitemap: https://...` has a colon inside the URL
                    let full = line.split_once(':').map(|x| x.1.trim()).unwrap_or("");
                    if !full.is_empty() {
                        sitemaps.push(full.to_string());
                    }
                }
                _ => {}
            }
        }
        let specific = groups.iter().find(|g| {
            g.0.iter()
                .any(|a| a != "*" && !a.is_empty() && agent.contains(a.as_str()))
        });
        let chosen = specific.or_else(|| groups.iter().find(|g| g.0.iter().any(|a| a == "*")));
        let (rules, crawl_delay) = chosen.map(|g| (g.1.clone(), g.2)).unwrap_or_default();
        Robots {
            rules,
            sitemaps,
            crawl_delay,
        }
    }

    /// Returns `true` if the path (with query) is allowed. The longest match wins; ties go to allow.
    pub fn allowed(&self, path_and_query: &str) -> bool {
        let mut best: Option<(usize, bool)> = None;
        for (allow, pat) in &self.rules {
            if pattern_match(pat, path_and_query) {
                let len = pat.len();
                match best {
                    Some((l, a)) if l > len || (l == len && a) => {}
                    _ => best = Some((len, *allow)),
                }
            }
        }
        best.map(|b| b.1).unwrap_or(true)
    }
}

/// Matches a robots pattern: a prefix with `*` (any string) and `$` (end of path).
fn pattern_match(pat: &str, s: &str) -> bool {
    let (pat, anchored) = match pat.strip_suffix('$') {
        Some(p) => (p, true),
        None => (pat, false),
    };
    let parts: Vec<&str> = pat.split('*').collect();
    let mut pos = 0;
    for (i, part) in parts.iter().enumerate() {
        if i == 0 {
            if !s.starts_with(part) {
                return false;
            }
            pos = part.len();
            continue;
        }
        if part.is_empty() {
            continue;
        }
        match s[pos..].find(part) {
            Some(f) => pos += f + part.len(),
            None => return false,
        }
    }
    if anchored {
        if parts.last().is_some_and(|p| p.is_empty()) {
            return true;
        }
        return pos == s.len() || parts.len() > 1 && s.ends_with(parts[parts.len() - 1]);
    }
    true
}

/// Returns the `<loc>` entries of a sitemap (urlset or sitemapindex); the flag is `true` for a sitemap index.
pub fn parse_sitemap(xml: &str) -> (Vec<String>, bool) {
    let is_index = xml.contains("<sitemapindex");
    let mut out = Vec::new();
    let mut rest = xml;
    while let Some(p) = rest.find("<loc>") {
        let after = &rest[p + 5..];
        let Some(e) = after.find("</loc>") else { break };
        let v = after[..e].trim();
        let v = v
            .strip_prefix("<![CDATA[")
            .and_then(|x| x.strip_suffix("]]>"))
            .unwrap_or(v);
        out.push(decode_entities(v.trim()));
        rest = &after[e + 6..];
    }
    (out, is_index)
}

/// Largest decompressed sitemap accepted (the sitemaps.org limit is 50 MB).
const MAX_SITEMAP: u64 = 50 * 1024 * 1024;

/// Decodes a fetched sitemap body: gzip (`sitemap.xml.gz`, detected by its magic bytes) or plain
/// text. Returns `None` for a broken archive.
pub fn sitemap_text(body: &[u8]) -> Option<String> {
    use std::io::Read;
    if body.starts_with(&[0x1f, 0x8b]) {
        let mut out = Vec::new();
        flate2::read::GzDecoder::new(body)
            .take(MAX_SITEMAP)
            .read_to_end(&mut out)
            .ok()?;
        return Some(String::from_utf8_lossy(&out).into_owned());
    }
    Some(String::from_utf8_lossy(body).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn links() {
        let page = Url::parse("https://a.ua/dir/page.html").unwrap();
        let html = r#"<html><head><BASE HREF="https://a.ua/base/"><style>a{background:url(x.pdf)}</style></head>
        <body><a href="doc1.pdf">1</a><a class=x href='/abs/doc2.docx#p'>2</a>
        <A HREF=rel/doc3.xlsx>3</A><!-- <a href="hidden.pdf"> --><script>var s='<a href="js.pdf">';</script>
        <img src="//cdn.a.ua/p.jpg"><a href="mailto:x@a.ua">m</a><a href="javascript:void(0)">j</a>
        <a href="https://b.ua/?a=1&amp;b=2">ext</a><iframe src="/frame.html"></iframe></body></html>"#;
        let v: Vec<String> = extract_links(html, &page)
            .iter()
            .map(|u| u.to_string())
            .collect();
        assert_eq!(
            v,
            vec![
                "https://a.ua/base/doc1.pdf",
                "https://a.ua/abs/doc2.docx",
                "https://a.ua/base/rel/doc3.xlsx",
                "https://cdn.a.ua/p.jpg",
                "https://b.ua/?a=1&b=2",
                "https://a.ua/frame.html",
            ]
        );
    }

    #[test]
    fn robots() {
        let t = "User-agent: Googlebot\nDisallow: /\n\nUser-agent: *\nDisallow: /private/\nDisallow: /*.pdf$\nAllow: /private/public.pdf$\nCrawl-delay: 2\nSitemap: https://a.ua/sitemap.xml # main\n";
        let r = Robots::parse(t, "FOCA-rs/0.5");
        assert!(r.allowed("/"));
        assert!(!r.allowed("/private/x.html"));
        assert!(!r.allowed("/docs/a.pdf"));
        assert!(r.allowed("/docs/a.pdf?x=1"));
        assert!(r.allowed("/private/public.pdf"));
        assert_eq!(r.sitemaps, vec!["https://a.ua/sitemap.xml"]);
        assert_eq!(r.crawl_delay, Some(2.0));
        let g = Robots::parse(t, "Googlebot/2.1");
        assert!(!g.allowed("/anything"));
        assert!(Robots::parse("User-agent: *\nDisallow:\n", "x").allowed("/a"));
    }

    #[test]
    fn sitemap() {
        let (v, idx) = parse_sitemap("<urlset><url><loc> https://a.ua/a.pdf </loc></url><url><loc><![CDATA[https://a.ua/?a=1&amp;b=2]]></loc></url></urlset>");
        assert!(!idx);
        assert_eq!(v, vec!["https://a.ua/a.pdf", "https://a.ua/?a=1&b=2"]);
        let (v, idx) = parse_sitemap(
            "<sitemapindex><sitemap><loc>https://a.ua/s1.xml</loc></sitemap></sitemapindex>",
        );
        assert!(idx);
        assert_eq!(v.len(), 1);
    }

    #[test]
    fn scan_page_reports_shell_nofollow_and_images() {
        let page = Url::parse("https://site.example/").unwrap();
        let shell = r#"<!doctype html><html><head><title>App</title>
            <script type="module" src="/assets/index-4f2a.js"></script></head>
            <body><noscript>You need to enable JavaScript to run this app.</noscript><div id="root"></div></body></html>"#;
        let s = scan_page(shell, &page);
        assert!(s.looks_like_app_shell());
        assert_eq!(
            s.scripts[0].as_str(),
            "https://site.example/assets/index-4f2a.js"
        );
        let flutter =
            r#"<html><body><script src="flutter_bootstrap.js" async></script></body></html>"#;
        assert!(scan_page(flutter, &page).looks_like_app_shell());
        let normal = r#"<html><body><h1>Welcome to the faculty</h1><p>News, staff and timetable for all students and visitors of the site.</p>
            <a href="/news">News</a><a href="/staff">Staff</a><a href="/files/plan.pdf" rel="nofollow noopener">Plan</a>
            <img src="/i/hall.jpg" width="1600" height="900"><img data-src="/i/lazy.jpg" src="/i/blank.gif">
            <picture><source srcset="/i/a-800.jpg 800w, /i/a-400.jpg 400w"></picture><script>var x=1;</script></body></html>"#;
        let s = scan_page(normal, &page);
        assert!(!s.looks_like_app_shell());
        assert_eq!(s.nav_links(), 3);
        let plan = s
            .links
            .iter()
            .find(|l| l.url.path() == "/files/plan.pdf")
            .unwrap();
        assert!(plan.nofollow);
        let hall = s
            .links
            .iter()
            .find(|l| l.url.path() == "/i/hall.jpg")
            .unwrap();
        assert_eq!((hall.w, hall.h), (Some(1600), Some(900)));
        assert!(s.links.iter().any(|l| l.url.path() == "/i/lazy.jpg"));
        assert!(s.links.iter().any(|l| l.url.path() == "/i/a-800.jpg"));
        assert_eq!(s.script_tags, 1);
        let meta = r#"<meta name="robots" content="noindex, nofollow"><a href="/x">x</a>"#;
        assert!(scan_page(meta, &page).links[0].nofollow);
    }

    #[test]
    fn sitemap_gzip_is_decoded() {
        use std::io::Write;
        let xml = "<urlset><url><loc>https://site.example/a</loc></url></urlset>";
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(xml.as_bytes()).unwrap();
        let gz = enc.finish().unwrap();
        assert_eq!(sitemap_text(&gz).as_deref(), Some(xml));
        assert_eq!(sitemap_text(xml.as_bytes()).as_deref(), Some(xml));
        assert_eq!(sitemap_text(&[0x1f, 0x8b, 1, 2, 3]), None);
    }
}
