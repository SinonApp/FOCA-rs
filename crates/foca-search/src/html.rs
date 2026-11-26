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

/// Returns the page's links (absolute, without fragments), honoring `<base href>`. The contents
/// of `<script>` and `<style>` and HTML comments are skipped.
pub fn extract_links(html: &str, page: &Url) -> Vec<Url> {
    let mut base = page.clone();
    let mut out = Vec::new();
    let lower = html.to_ascii_lowercase();
    let mut i = 0;
    while let Some(p) = lower[i..].find('<') {
        let start = i + p;
        if lower[start..].starts_with("<!--") {
            i = lower[start..]
                .find("-->")
                .map(|e| start + e + 3)
                .unwrap_or(lower.len());
            continue;
        }
        let Some(e) = lower[start..].find('>') else {
            break;
        };
        let end = start + e;
        let inner = &html[start + 1..end];
        let name_end = inner
            .find(|c: char| c.is_ascii_whitespace() || c == '/' || c == '>')
            .unwrap_or(inner.len());
        let name = inner[..name_end].to_ascii_lowercase();
        i = end + 1;
        if name == "script" || name == "style" {
            let close = format!("</{name}");
            i = lower[i..]
                .find(&close)
                .map(|x| i + x)
                .unwrap_or(lower.len());
            continue;
        }
        if name == "base" {
            if let Some((_, v)) = parse_attrs(&inner[name_end..])
                .into_iter()
                .find(|(k, _)| k == "href")
            {
                if let Ok(b) = page.join(&v) {
                    base = b;
                }
            }
            continue;
        }
        let Some((_, attr)) = LINK_ATTRS.iter().find(|(t, _)| *t == name) else {
            continue;
        };
        for (k, v) in parse_attrs(&inner[name_end..]) {
            if k == *attr && !v.is_empty() {
                let lv = v.to_ascii_lowercase();
                if lv.starts_with("javascript:")
                    || lv.starts_with("mailto:")
                    || lv.starts_with("data:")
                    || lv.starts_with("tel:")
                {
                    continue;
                }
                if let Ok(mut u) = base.join(&v) {
                    if matches!(u.scheme(), "http" | "https") {
                        u.set_fragment(None);
                        out.push(u);
                    }
                }
            }
        }
    }
    out
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
}
