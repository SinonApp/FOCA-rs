//! Response fingerprints and soft-404 auto-calibration (the idea behind ffuf's `-ac`, MIT).
//!
//! Before fuzzing, each *context* (host + `Host` header + directory + extension class) is
//! probed with random paths that certainly do not exist. The responses form a [`Baseline`];
//! a candidate response similar to it is treated as a soft 404 and discarded. Similar means
//! the same status and either the same normalized `Location`, the same normalized body hash
//! (random tokens, numbers and echoes of the requested word replaced), the same size, the
//! same word and line counts, or word/line counts inside the narrow range of all samples.
//!
//! Single-page apps answer every path with their `index.html` (HTTP 200), sometimes only for
//! some path classes. Each baseline therefore also carries the site's root page: a 2xx HTML
//! candidate with the same normalized body, or the same title and tag skeleton at a similar
//! size, is the app shell and counts as a soft 404 too.

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::sync::OnceLock;

use regex::Regex;

/// Fingerprint of a single response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sample {
    pub status: u16,
    pub size: u64,
    pub words: u64,
    pub lines: u64,
    /// `Location` with the requested word replaced by `FUZZ`.
    pub location: Option<String>,
    /// Hash of the normalized body.
    pub norm_hash: u64,
    /// MIME type without parameters (`text/html`).
    pub ctype: Option<String>,
    /// `<title>` text, trimmed and lowercased.
    pub title: Option<String>,
    /// Hash of the opening tag names in order (0 when the body has no markup).
    pub skeleton: u64,
    /// Number of opening tags seen for `skeleton`.
    pub tags: u32,
    /// 64-bit sketch of the distinct tag names (one bit per name hash).
    pub tagset: u64,
}

/// Counts words the way ffuf does (split on whitespace).
pub fn count_words(body: &str) -> u64 {
    body.split_whitespace().count() as u64
}

/// Counts lines the way ffuf does (`\n` count + 1 for a non-empty body).
pub fn count_lines(body: &str) -> u64 {
    if body.is_empty() {
        0
    } else {
        body.matches('\n').count() as u64 + 1
    }
}

fn token_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    // Random tokens (hex/base64-like, 6+ chars), numbers, date-times.
    RE.get_or_init(|| Regex::new(r"[0-9a-f]{6,}|[A-Za-z0-9+/_\-]{24,}={0,2}|\d+").expect("re"))
}

fn ws_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\s+").expect("re"))
}

/// Returns the hash, count and name sketch of the first 400 opening tags (`<div …>` → `div`).
fn skeleton_of(body: &str) -> (u64, u32, u64) {
    let mut h = DefaultHasher::new();
    let mut n = 0u32;
    let mut set = 0u64;
    let b = body.as_bytes();
    let mut i = 0;
    while i + 1 < b.len() && n < 400 {
        if b[i] == b'<' && b[i + 1].is_ascii_alphabetic() {
            let start = i + 1;
            let mut j = start;
            while j < b.len() && (b[j].is_ascii_alphanumeric() || b[j] == b'-') {
                j += 1;
            }
            let name = body[start..j].to_ascii_lowercase();
            name.hash(&mut h);
            let mut nh = DefaultHasher::new();
            name.hash(&mut nh);
            set |= 1 << (nh.finish() % 64);
            n += 1;
            i = j;
        } else {
            i += 1;
        }
    }
    if n == 0 {
        (0, 0, 0)
    } else {
        (h.finish(), n, set)
    }
}

fn title_text(body: &str) -> Option<String> {
    let l = body.to_lowercase();
    let s = l.find("<title")?;
    let s = s + l[s..].find('>')? + 1;
    let e = s + l[s..].find("</title>")?;
    let t = ws_re().replace_all(l[s..e].trim(), " ").into_owned();
    (!t.is_empty()).then_some(t)
}

fn replace_word(s: &str, word: &str) -> String {
    if word.is_empty() {
        return s.to_string();
    }
    let mut out = s.replace(word, "FUZZ");
    let enc: String = url::form_urlencoded::byte_serialize(word.as_bytes()).collect();
    if enc != word {
        out = out.replace(&enc, "FUZZ");
    }
    out
}

/// Normalizes a body for comparison: the echoed word becomes `FUZZ`, tokens and numbers
/// become `#`, whitespace is collapsed.
pub fn normalize_body(body: &str, word: &str) -> String {
    let lower = body.to_lowercase();
    let w = word.to_lowercase();
    let s = replace_word(&lower, &w);
    // The word may also be part of a path, so replace the last segment as well.
    let s = match w.rsplit('/').find(|p| !p.is_empty()) {
        Some(seg) if seg != w => replace_word(&s, seg),
        _ => s,
    };
    let s = token_re().replace_all(&s, "#");
    ws_re().replace_all(s.trim(), " ").into_owned()
}

/// Normalizes `Location`: the word becomes `FUZZ`, the query is kept (`/login?next=/FUZZ`).
pub fn normalize_location(loc: &str, word: &str) -> String {
    let w = word.trim_matches('/');
    let mut s = replace_word(loc, word);
    if !w.is_empty() && w != word {
        s = replace_word(&s, w);
    }
    s.to_ascii_lowercase()
}

impl Sample {
    pub fn new(status: u16, size: u64, body: &str, location: Option<&str>, word: &str) -> Sample {
        Self::with_type(status, size, body, location, word, None)
    }

    /// Builds a sample with a content type: a different MIME type is never a soft-404 template.
    pub fn with_type(
        status: u16,
        size: u64,
        body: &str,
        location: Option<&str>,
        word: &str,
        content_type: Option<&str>,
    ) -> Sample {
        let mut h = DefaultHasher::new();
        normalize_body(body, word).hash(&mut h);
        let (skeleton, tags, tagset) = skeleton_of(body);
        Sample {
            status,
            size,
            words: count_words(body),
            lines: count_lines(body),
            location: location.map(|l| normalize_location(l, word)),
            norm_hash: h.finish(),
            ctype: content_type.map(|c| {
                c.split(';')
                    .next()
                    .unwrap_or("")
                    .trim()
                    .to_ascii_lowercase()
            }),
            title: title_text(body),
            skeleton,
            tags,
            tagset,
        }
    }

    /// Returns `true` if both are 2xx answers with the same page: the same normalized body, or
    /// sizes within 3% with the same title or tag sequence (a catch-all page with a token).
    pub fn same_catch_all(&self, other: &Sample) -> bool {
        if !(200..300).contains(&self.status) || !(200..300).contains(&other.status) {
            return false;
        }
        if self.norm_hash == other.norm_hash {
            return true;
        }
        let near = self.size.abs_diff(other.size) * 100 <= other.size.max(1) * 3;
        near && ((other.title.is_some() && self.title == other.title)
            || (other.tags >= 5 && self.skeleton == other.skeleton))
    }

    pub fn is_redirect(&self) -> bool {
        matches!(self.status, 301 | 302 | 303 | 307 | 308)
    }

    /// Both are redirects to the same normalized `Location`.
    fn same_location(&self, other: &Sample) -> bool {
        self.location.is_some() && self.location == other.location
    }

    fn is_html(&self) -> bool {
        match &self.ctype {
            Some(c) => c.contains("html"),
            None => self.tags >= 3,
        }
    }

    /// Returns `true` if this 2xx HTML response is the same page as `root` (the site's home
    /// page): the same normalized body; the same title with the same tag sequence or within 5%
    /// of the size; the same title and set of tag names within 25% (another build of an app
    /// shell); or the same tag sequence within 10% of the size.
    pub fn same_page_as(&self, root: &Sample) -> bool {
        if !(200..300).contains(&self.status) || !(200..300).contains(&root.status) {
            return false;
        }
        if !root.is_html() || !self.is_html() || root.size == 0 {
            return false;
        }
        if self.norm_hash == root.norm_hash {
            return true;
        }
        let near = |pct: u64| self.size.abs_diff(root.size) * 100 <= root.size * pct;
        let same_title = root.title.is_some() && self.title == root.title;
        let same_skel = root.tags >= 5 && self.skeleton == root.skeleton;
        let same_set = root.tags >= 5 && self.tagset == root.tagset;
        (same_title && (same_skel || near(5) || (same_set && near(25)))) || (same_skel && near(10))
    }
}

/// The learned soft 404 of a context.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Baseline {
    pub samples: Vec<Sample>,
    /// The site's root page for the same origin and `Host`.
    pub root: Option<Sample>,
}

impl Baseline {
    pub fn new(samples: Vec<Sample>) -> Baseline {
        Baseline {
            samples,
            root: None,
        }
    }

    /// Adds the site's root page: a candidate that is the same page counts as a soft 404.
    pub fn with_root(mut self, root: Option<Sample>) -> Baseline {
        self.root = root;
        self
    }

    /// Returns `true` if the candidate is the site's root page served for another path.
    pub fn is_root_page(&self, c: &Sample) -> bool {
        self.root.as_ref().is_some_and(|r| c.same_page_as(r))
    }

    /// Returns `true` if calibration saw a "not found" kind of answer (404/410, a redirect or a
    /// 2xx soft 404): a random path there can serve as a control request.
    pub fn answers_missing(&self) -> bool {
        !self.samples.is_empty()
            && self
                .samples
                .iter()
                .all(|s| !matches!(s.status, 401 | 403 | 429) && s.status < 500)
    }

    pub fn is_empty(&self) -> bool {
        self.samples.is_empty()
    }

    /// Returns `true` if the site answers nonexistent paths with this status (403 or 5xx for
    /// everything).
    pub fn has_status(&self, st: u16) -> bool {
        self.samples.iter().any(|s| s.status == st)
    }

    /// Returns `true` if the candidate response looks like the soft 404.
    pub fn matches(&self, c: &Sample) -> bool {
        self.is_root_page(c) || self.matches_samples(c)
    }

    /// Compares with the calibration samples only (not with the root page).
    pub fn matches_samples(&self, c: &Sample) -> bool {
        let same: Vec<&Sample> = self
            .samples
            .iter()
            .filter(|s| s.status == c.status)
            .filter(|s| match (&s.ctype, &c.ctype) {
                (Some(a), Some(b)) => a == b,
                _ => true,
            })
            .collect();
        if same.is_empty() {
            return false;
        }
        for s in &same {
            if c.is_redirect() || s.is_redirect() {
                if c.same_location(s) {
                    return true;
                }
                // Redirects with different targets (`/docs` → `/docs/`) are not a soft 404.
                continue;
            }
            if c.norm_hash == s.norm_hash || c.size == s.size {
                return true;
            }
        }
        if c.is_redirect() {
            return false;
        }
        // Like ffuf: if sample sizes vary, compare by words, then by lines.
        let (smin, smax) = minmax(same.iter().map(|s| s.size));
        let sizes_vary = smax > smin;
        if same.len() == 1 || sizes_vary {
            let all_words = same.iter().all(|s| s.words == same[0].words);
            let all_lines = same.iter().all(|s| s.lines == same[0].lines);
            if all_words && c.words == same[0].words && (all_lines || same.len() > 1) {
                return true;
            }
            if all_lines && c.lines == same[0].lines && same.len() > 1 && !all_words {
                return true;
            }
        }
        // Random body: samples with the same status differ noticeably, but their word/line counts
        // fall in a narrow range; a candidate inside that range (no margin) matches the template.
        if same.len() >= 2 {
            let (wmin, wmax) = minmax(same.iter().map(|s| s.words));
            let (lmin, lmax) = minmax(same.iter().map(|s| s.lines));
            let varies = wmax > wmin || lmax > lmin;
            if varies
                && lmax - lmin <= 3
                && wmax - wmin <= 12
                && (wmin..=wmax).contains(&c.words)
                && (lmin..=lmax).contains(&c.lines)
            {
                return true;
            }
        }
        false
    }

    /// Returns a short summary for the log and UI.
    pub fn summary(&self) -> String {
        self.samples
            .iter()
            .map(|s| match &s.location {
                Some(l) => format!("{} → {l}", s.status),
                None => format!("{} {}B/{}w/{}l", s.status, s.size, s.words, s.lines),
            })
            .collect::<Vec<_>>()
            .join("; ")
    }
}

fn minmax(it: impl Iterator<Item = u64>) -> (u64, u64) {
    let mut lo = u64::MAX;
    let mut hi = 0;
    for v in it {
        lo = lo.min(v);
        hi = hi.max(v);
    }
    if lo == u64::MAX {
        (0, 0)
    } else {
        (lo, hi)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn soft(word: &str, junk: &str) -> Sample {
        let body = format!("<html><h1>Page not found</h1><p>/{word}: request id {junk}</p></html>");
        Sample::new(200, body.len() as u64, &body, None, word)
    }

    #[test]
    fn soft404_random_body_matches() {
        let b = Baseline::new(vec![
            soft("q8f7a6s5d4f3g2h1", "a1b2c3d4"),
            soft("zzxxccvvbbnnmm1122334455", "0f0f0f0f0f0f0f0f0f0f0f"),
            soft("k3j4h5", "deadbeefcafe"),
        ]);
        assert!(b.matches(&soft("admin", "123456789abcdef")));
        assert!(b.matches(&soft("report_2024.pdf", "77")));
        let real = "%PDF-1.4\n% report\n1 0 obj << >> endobj\n%%EOF\n";
        assert!(!b.matches(&Sample::new(
            200,
            real.len() as u64,
            real,
            None,
            "report_2024.pdf"
        )));
        // A short file with a similar word/line count but a different MIME type is not a soft 404.
        let b = Baseline::new(vec![
            Sample::with_type(200, 90, "a b c\nd e f\ng h", None, "x1", Some("text/html")),
            Sample::with_type(
                200,
                95,
                "a b c\nd e f\ng h i",
                None,
                "x2",
                Some("text/html; charset=utf-8"),
            ),
        ]);
        assert!(b.matches(&Sample::with_type(
            200,
            91,
            "q w e\nr t y\nu i",
            None,
            "z",
            Some("text/html")
        )));
        assert!(!b.matches(&Sample::with_type(
            200,
            40,
            "%PDF q w\nr t y\nu i",
            None,
            "s.pdf",
            Some("application/pdf")
        )));
    }

    #[test]
    fn redirect_to_login_matches_but_dir_redirect_does_not() {
        let mk = |w: &str, loc: &str| Sample::new(302, 0, "", Some(loc), w);
        let b = Baseline::new(vec![
            mk("abc123xyz", "/login?next=/abc123xyz"),
            mk("qwe456rty", "/login?next=/qwe456rty"),
        ]);
        assert!(b.matches(&mk("backup.zip", "/login?next=/backup.zip")));
        assert!(!b.matches(&Sample::new(301, 0, "", Some("/docs/"), "docs")));
        assert!(!b.matches(&mk("docs", "/docs/")));
    }

    #[test]
    fn forbidden_everywhere_matches() {
        let body = "<html>403 Forbidden</html>";
        let b = Baseline::new(vec![
            Sample::new(403, body.len() as u64, body, None, "a1"),
            Sample::new(403, body.len() as u64, body, None, "b2"),
        ]);
        assert!(b.matches(&Sample::new(403, body.len() as u64, body, None, ".env")));
        assert!(!b.matches(&Sample::new(200, 10, "APP_ENV=x\n", None, ".env")));
        assert!(b.has_status(403));
    }

    #[test]
    fn app_shell_matches_root_page() {
        let shell = |extra: &str| {
            format!(
                "<!DOCTYPE html><html><head><title>Portal</title><base href=\"/\">\
                 <!-- {} --></head><body>{extra}<script src=\"main.dart.js\"></script>\
                 </body></html>",
                "If you are serving your web app in a path other than the root. ".repeat(12)
            )
        };
        let mk = |st: u16, body: &str, ct: &str| {
            Sample::with_type(st, body.len() as u64, body, None, "", Some(ct))
        };
        let a = shell("");
        let b = shell("<script src=\"flutter_bootstrap.js\" async></script><!-- build 2 -->");
        let root = mk(200, &a, "text/html");
        let base = Baseline::new(vec![mk(404, "nf", "text/plain")]).with_root(Some(root));
        assert!(base.matches(&mk(200, &a, "text/html; charset=utf-8")));
        assert!(base.matches(&mk(200, &b, "text/html")));
        // A CSV or a different page is not the shell.
        assert!(!base.matches(&mk(200, "a,b\n1,2\n", "text/csv")));
        let other = "<!DOCTYPE html><html><head><title>Admin login</title></head><body>\
                     <form><input name=u><input name=p></form></body></html>";
        assert!(!base.matches(&mk(200, other, "text/html")));
        assert!(!base.matches(&mk(404, &a, "text/html")));
    }

    #[test]
    fn counts() {
        assert_eq!(count_lines(""), 0);
        assert_eq!(count_lines("a\nb"), 2);
        assert_eq!(count_words(" a  b\nc "), 3);
    }
}
