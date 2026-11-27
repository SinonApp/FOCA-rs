//! URL normalisation and crawler trap protection.
//!
//! Sites generate endless URL spaces: calendars (`/events/2026/11/27`), pagination
//! (`?page=1..N`), filter permutations (`?color=red&size=m`), session ids in the query and
//! tracking parameters. The crawler cleans every link ([`clean_url`]), refuses links that change
//! state ([`risky_link`]: logout, delete, unsubscribe) and admits at most `per_template` pages
//! per path template and `query_variants` distinct queries per path ([`TrapGuard`]).

use std::collections::HashMap;

use url::Url;

/// Query parameters dropped from crawled links: analytics tags and session ids.
const TRACKING_PARAMS: &[&str] = &[
    "fbclid",
    "gclid",
    "dclid",
    "gbraid",
    "wbraid",
    "msclkid",
    "yclid",
    "mc_cid",
    "mc_eid",
    "_ga",
    "_gl",
    "igshid",
    "ref_src",
    "spm",
    "sessionid",
    "session_id",
    "sid",
    "phpsessid",
    "jsessionid",
    "cfid",
    "cftoken",
    "replytocom",
    "share",
];

/// Words in a path or query that mark a link which changes state on the server.
const RISKY_WORDS: &[&str] = &[
    "logout",
    "logoff",
    "signout",
    "delete",
    "remove",
    "destroy",
    "unsubscribe",
    "deactivate",
    "revoke",
];

fn tracking(key: &str) -> bool {
    let k = key.to_ascii_lowercase();
    k.starts_with("utm_") || k.starts_with("aspsessionid") || TRACKING_PARAMS.contains(&k.as_str())
}

/// Returns the link without its fragment, tracking parameters, `;jsessionid=` path parameters
/// and with the remaining query parameters sorted (so `?b=1&a=2` and `?a=2&b=1` are one page).
pub fn clean_url(u: &Url) -> Url {
    let mut out = u.clone();
    out.set_fragment(None);
    let path = out.path().to_string();
    if let Some(i) = path.to_ascii_lowercase().find(";jsessionid=") {
        out.set_path(&path[..i]);
    }
    if out.query().is_some() {
        let mut pairs: Vec<(String, String)> = out
            .query_pairs()
            .filter(|(k, _)| !tracking(k))
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect();
        pairs.sort();
        pairs.dedup();
        if pairs.is_empty() {
            out.set_query(None);
        } else {
            out.query_pairs_mut().clear().extend_pairs(pairs);
        }
    }
    out
}

/// Returns `true` for a link that may change state on the server (log out, delete, unsubscribe):
/// the crawler never follows it.
pub fn risky_link(u: &Url) -> bool {
    let text = format!("{}?{}", u.path(), u.query().unwrap_or("")).to_ascii_lowercase();
    let words: Vec<&str> = text
        .split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|w| !w.is_empty())
        .collect();
    if words.iter().any(|w| RISKY_WORDS.contains(w)) {
        return true;
    }
    // split forms: "log-out", "sign_out", "log/off"
    words
        .windows(2)
        .any(|p| matches!((p[0], p[1]), ("log" | "sign", "out") | ("log", "off")))
}

/// Replaces every run of digits with `{n}` and long hex ids with `{id}`.
fn segment_template(seg: &str) -> String {
    let hexish = seg.len() >= 16 && seg.chars().all(|c| c.is_ascii_hexdigit() || c == '-');
    if hexish && seg.chars().any(|c| c.is_ascii_digit()) {
        return "{id}".into();
    }
    let mut out = String::with_capacity(seg.len());
    let mut in_digits = false;
    for ch in seg.chars() {
        if ch.is_ascii_digit() {
            if !in_digits {
                out.push_str("{n}");
            }
            in_digits = true;
        } else {
            in_digits = false;
            out.push(ch);
        }
    }
    out
}

/// Returns the path template of a link: host, path with numbers and ids collapsed, and the sorted
/// query keys without values (`site/events/{n}/{n}?page`).
pub fn template_key(u: &Url) -> String {
    let segs: Vec<String> = u
        .path()
        .split('/')
        .map(segment_template)
        .collect::<Vec<_>>();
    let mut keys: Vec<String> = u.query_pairs().map(|(k, _)| k.into_owned()).collect();
    keys.sort();
    keys.dedup();
    format!(
        "{}{}?{}",
        u.host_str().unwrap_or(""),
        segs.join("/"),
        keys.join("&")
    )
}

/// Admission control against trap URL spaces.
#[derive(Debug, Clone)]
pub struct TrapGuard {
    per_template: usize,
    query_variants: usize,
    templates: HashMap<String, usize>,
    variants: HashMap<String, usize>,
    /// Links refused because their template or path was already saturated.
    pub collapsed: usize,
}

impl TrapGuard {
    pub fn new(per_template: usize, query_variants: usize) -> Self {
        TrapGuard {
            per_template: per_template.max(1),
            query_variants: query_variants.max(1),
            templates: HashMap::new(),
            variants: HashMap::new(),
            collapsed: 0,
        }
    }

    /// Counts a cleaned link against its template and path; `false` means the crawler should
    /// skip it. Call it once per distinct URL (after the visited check).
    pub fn admit(&mut self, u: &Url) -> bool {
        let t = self.templates.entry(template_key(u)).or_insert(0);
        if *t >= self.per_template {
            self.collapsed += 1;
            return false;
        }
        if u.query().is_some() {
            let path = format!("{}{}", u.host_str().unwrap_or(""), u.path());
            let v = self.variants.entry(path).or_insert(0);
            if *v >= self.query_variants {
                self.collapsed += 1;
                return false;
            }
            *v += 1;
        }
        *t += 1;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn u(s: &str) -> Url {
        Url::parse(s).unwrap()
    }

    #[test]
    fn clean_strips_tracking_and_sorts_query() {
        let c = clean_url(&u(
            "https://site.example/news?utm_source=x&b=2&fbclid=abc&a=1&PHPSESSID=f00#top",
        ));
        assert_eq!(c.as_str(), "https://site.example/news?a=1&b=2");
        let c = clean_url(&u("https://site.example/a;jsessionid=ABC123?utm_medium=m"));
        assert_eq!(c.as_str(), "https://site.example/a");
        assert_eq!(
            clean_url(&u("https://site.example/x?b=1&a=2")),
            clean_url(&u("https://site.example/x?a=2&b=1"))
        );
    }

    #[test]
    fn risky_links_are_detected() {
        for s in [
            "https://site.example/logout",
            "https://site.example/user/log-out",
            "https://site.example/account?action=delete&id=4",
            "https://site.example/sign_out",
            "https://site.example/mail/unsubscribe/123",
        ] {
            assert!(risky_link(&u(s)), "{s}");
        }
        for s in [
            "https://site.example/blog/logo.png",
            "https://site.example/docs/removal-policy.pdf",
            "https://site.example/catalog?page=2",
        ] {
            assert!(!risky_link(&u(s)), "{s}");
        }
    }

    #[test]
    fn templates_collapse_numbers_and_ids() {
        assert_eq!(
            template_key(&u("https://site.example/events/2026/11/27")),
            template_key(&u("https://site.example/events/2025/01/03"))
        );
        assert_eq!(
            template_key(&u("https://site.example/list?page=3&sort=a")),
            "site.example/list?page&sort"
        );
        assert_eq!(
            template_key(&u("https://site.example/item/0f3a9c2e7d5b4a1f9e8d")),
            "site.example/item/{id}?"
        );
    }

    #[test]
    fn guard_caps_templates_and_query_variants() {
        let mut g = TrapGuard::new(3, 100);
        let admitted = (1..=10)
            .filter(|d| g.admit(&u(&format!("https://site.example/cal/2026/1/{d}"))))
            .count();
        assert_eq!(admitted, 3);
        assert_eq!(g.collapsed, 7);
        let mut g = TrapGuard::new(100, 4);
        let admitted = ["red", "blue", "green", "black", "white", "pink"]
            .iter()
            .filter(|c| g.admit(&u(&format!("https://site.example/shop?color={c}"))))
            .count();
        assert_eq!(admitted, 4);
        // other paths are unaffected
        assert!(g.admit(&u("https://site.example/about")));
    }
}
