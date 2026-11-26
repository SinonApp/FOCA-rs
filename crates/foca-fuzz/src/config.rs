//! Fuzzing settings: gentle limits, auto-stop, filters and matchers (as in ffuf).

use std::time::Duration;

use regex::Regex;

/// An inclusive range of status codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StatusRange(pub u16, pub u16);

impl StatusRange {
    pub fn contains(&self, s: u16) -> bool {
        self.0 <= s && s <= self.1
    }
}

/// Parses `200-299,301,403` into ranges.
///
/// # Errors
///
/// Returns a message describing the first invalid item.
fn parse_status_list(s: &str) -> Result<Vec<StatusRange>, String> {
    let mut out = Vec::new();
    for part in s.split(',').map(str::trim).filter(|p| !p.is_empty()) {
        if part.eq_ignore_ascii_case("all") {
            out.push(StatusRange(100, 599));
            continue;
        }
        let (a, b) = match part.split_once('-') {
            Some((a, b)) => (a.trim(), b.trim()),
            None => (part, part),
        };
        let a: u16 = a.parse().map_err(|_| format!("код ответа: {part}"))?;
        let b: u16 = b.parse().map_err(|_| format!("код ответа: {part}"))?;
        if a > b || !(100..=599).contains(&a) || !(100..=599).contains(&b) {
            return Err(format!("код ответа: {part}"));
        }
        out.push(StatusRange(a, b));
    }
    Ok(out)
}

/// Parses `10,20-30` into numeric ranges.
///
/// # Errors
///
/// Returns a message describing the first invalid item.
fn parse_num_list(s: &str) -> Result<Vec<(u64, u64)>, String> {
    let mut out = Vec::new();
    for part in s.split(',').map(str::trim).filter(|p| !p.is_empty()) {
        let (a, b) = match part.split_once('-') {
            Some((a, b)) => (a.trim(), b.trim()),
            None => (part, part),
        };
        let a: u64 = a.parse().map_err(|_| format!("число: {part}"))?;
        let b: u64 = b.parse().map_err(|_| format!("число: {part}"))?;
        if a > b {
            return Err(format!("диапазон: {part}"));
        }
        out.push((a, b));
    }
    Ok(out)
}

fn in_ranges(v: u64, r: &[(u64, u64)]) -> bool {
    r.iter().any(|(a, b)| *a <= v && v <= *b)
}

/// One kind of matcher or filter rule, as given on the command line (`-mc`, `-fs`, `-fr`…).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rule {
    /// Status codes that count as a hit (`200-299,403`, `all`).
    MatchStatus,
    /// Body sizes that count as a hit (`10,20-30`).
    MatchSize,
    /// Word counts that count as a hit.
    MatchWords,
    /// Line counts that count as a hit.
    MatchLines,
    /// A body regex that counts as a hit.
    MatchRegex,
    /// Status codes to discard.
    FilterStatus,
    /// Body sizes to discard.
    FilterSize,
    /// Word counts to discard.
    FilterWords,
    /// Line counts to discard.
    FilterLines,
    /// A body regex to discard.
    FilterRegex,
}

/// Matchers (what counts as a hit) and filters (what to discard), with ffuf semantics: a
/// response is a hit if it passes at least one configured matcher and no filter.
#[derive(Debug, Clone)]
pub struct Filters {
    match_status: Vec<StatusRange>,
    match_size: Vec<(u64, u64)>,
    match_words: Vec<(u64, u64)>,
    match_lines: Vec<(u64, u64)>,
    match_regex: Option<Regex>,
    filter_status: Vec<StatusRange>,
    filter_size: Vec<(u64, u64)>,
    filter_words: Vec<(u64, u64)>,
    filter_lines: Vec<(u64, u64)>,
    filter_regex: Option<Regex>,
}

impl Default for Filters {
    fn default() -> Self {
        // Same as ffuf's default `-mc`.
        let mc = [
            StatusRange(200, 299),
            StatusRange(301, 302),
            StatusRange(307, 308),
            StatusRange(401, 401),
            StatusRange(403, 403),
            StatusRange(405, 405),
        ];
        Filters {
            match_status: mc.to_vec(),
            match_size: Vec::new(),
            match_words: Vec::new(),
            match_lines: Vec::new(),
            match_regex: None,
            filter_status: Vec::new(),
            filter_size: Vec::new(),
            filter_words: Vec::new(),
            filter_lines: Vec::new(),
            filter_regex: None,
        }
    }
}

/// Response properties the filters operate on.
#[derive(Debug, Clone, Copy)]
pub struct Measured<'a> {
    pub status: u16,
    pub size: u64,
    pub words: u64,
    pub lines: u64,
    pub body: &'a str,
}

impl Filters {
    /// Builds the defaults overridden by `rules`; each rule replaces the default of its kind.
    ///
    /// # Errors
    ///
    /// Returns a message describing the first invalid rule value.
    pub fn from_rules<'a>(
        rules: impl IntoIterator<Item = (Rule, &'a str)>,
    ) -> Result<Self, String> {
        let mut f = Filters::default();
        for (rule, spec) in rules {
            f.set(rule, spec)?;
        }
        Ok(f)
    }

    fn set(&mut self, rule: Rule, spec: &str) -> Result<(), String> {
        let regex = || Regex::new(spec).map(Some).map_err(|e| e.to_string());
        match rule {
            Rule::MatchStatus => self.match_status = parse_status_list(spec)?,
            Rule::MatchSize => self.match_size = parse_num_list(spec)?,
            Rule::MatchWords => self.match_words = parse_num_list(spec)?,
            Rule::MatchLines => self.match_lines = parse_num_list(spec)?,
            Rule::MatchRegex => self.match_regex = regex()?,
            Rule::FilterStatus => self.filter_status = parse_status_list(spec)?,
            Rule::FilterSize => self.filter_size = parse_num_list(spec)?,
            Rule::FilterWords => self.filter_words = parse_num_list(spec)?,
            Rule::FilterLines => self.filter_lines = parse_num_list(spec)?,
            Rule::FilterRegex => self.filter_regex = regex()?,
        }
        Ok(())
    }

    /// Returns `true` if the response passes the matchers and filters.
    pub fn accepts(&self, m: &Measured<'_>) -> bool {
        let any_matcher = !self.match_status.is_empty()
            || !self.match_size.is_empty()
            || !self.match_words.is_empty()
            || !self.match_lines.is_empty()
            || self.match_regex.is_some();
        let matched = !any_matcher
            || self.match_status.iter().any(|r| r.contains(m.status))
            || in_ranges(m.size, &self.match_size)
            || in_ranges(m.words, &self.match_words)
            || in_ranges(m.lines, &self.match_lines)
            || self
                .match_regex
                .as_ref()
                .is_some_and(|r| r.is_match(m.body));
        if !matched {
            return false;
        }
        let filtered = self.filter_status.iter().any(|r| r.contains(m.status))
            || in_ranges(m.size, &self.filter_size)
            || in_ranges(m.words, &self.filter_words)
            || in_ranges(m.lines, &self.filter_lines)
            || self
                .filter_regex
                .as_ref()
                .is_some_and(|r| r.is_match(m.body));
        !filtered
    }
}

/// Auto-stop conditions: signs that the site is throttling requests.
#[derive(Debug, Clone)]
pub struct AutoStop {
    /// Number of consecutive "bad" responses (429, 503 with `Retry-After`, challenge pages,
    /// network errors; 403/5xx unless calibration showed them as normal). A run that holds
    /// 403/5xx stops only when a control request to a known "not found" path is refused too.
    pub consecutive: u32,
    /// Window of recent responses…
    pub window: u32,
    /// …and the share of "bad" ones in it (once the window is full).
    pub ratio: f64,
}

impl Default for AutoStop {
    fn default() -> Self {
        AutoStop {
            consecutive: 8,
            window: 30,
            ratio: 0.5,
        }
    }
}

/// Fuzzing settings. The defaults are gentle, suited to a phone and a client's site.
#[derive(Debug, Clone)]
pub struct FuzzConfig {
    /// Concurrent requests (default 4).
    pub threads: usize,
    /// Requests per second (default 5).
    pub rate: f64,
    /// Random delay of 0..jitter before each request.
    pub jitter: Duration,
    /// Total HTTP request budget (calibration included).
    pub max_requests: u64,
    /// Overall time limit.
    pub max_time: Duration,
    /// Per-request timeout.
    pub request_timeout: Duration,
    /// Recursion depth into discovered directories (content module).
    pub recursion_depth: u8,
    /// Soft-404 auto-calibration (disable only for debugging).
    pub calibrate: bool,
    /// Calibration requests per context.
    pub calibration_samples: usize,
    pub autostop: AutoStop,
    pub filters: Filters,
    /// Body bytes read for comparison and evidence (files are never downloaded in full).
    pub body_limit: u64,
    /// Follow redirects (each hop is checked against the scope by NetClient). Off by default,
    /// like ffuf.
    pub follow_redirects: bool,
    /// Excluded path prefixes (`/private`, `/admin/`); such URLs are never requested.
    pub exclude_paths: Vec<String>,
    /// Maximum number of names extracted from one .DS_Store.
    pub dsstore_max_names: usize,
    /// Maximum number of links collected from one listing.
    pub listing_max_links: usize,
    /// Depth of nested listing traversal.
    pub listing_depth: u8,
    /// Mutations per known document name.
    pub max_mutations: usize,
    /// Number of DNS wordlist entries used for vhosts by default.
    pub vhost_words: usize,
    /// Maximum number of calibration contexts (beyond it the host-wide context is used).
    pub max_contexts: usize,
}

impl Default for FuzzConfig {
    fn default() -> Self {
        FuzzConfig {
            threads: 4,
            rate: 5.0,
            jitter: Duration::from_millis(150),
            max_requests: 3000,
            max_time: Duration::from_secs(20 * 60),
            request_timeout: Duration::from_secs(20),
            recursion_depth: 1,
            calibrate: true,
            calibration_samples: 3,
            autostop: AutoStop::default(),
            filters: Filters::default(),
            body_limit: 64 * 1024,
            follow_redirects: false,
            exclude_paths: Vec::new(),
            dsstore_max_names: 2000,
            listing_max_links: 2000,
            listing_depth: 2,
            max_mutations: 24,
            vhost_words: 500,
            max_contexts: 40,
        }
    }
}

impl FuzzConfig {
    /// Returns `true` if the path is excluded (`exclude_paths`, case-insensitive prefix match by
    /// segment).
    pub fn path_excluded(&self, path: &str) -> bool {
        let p = path.to_ascii_lowercase();
        self.exclude_paths.iter().any(|x| {
            let x = x.trim().to_ascii_lowercase();
            if x.is_empty() {
                return false;
            }
            let x = if x.starts_with('/') {
                x
            } else {
                format!("/{x}")
            };
            let base = x.trim_end_matches('/');
            p == base
                || p.starts_with(&format!("{base}/"))
                || (x.ends_with('/') && p.starts_with(&x))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_lists() {
        let r = parse_status_list("200-299, 403,all").unwrap();
        assert_eq!(r.len(), 3);
        assert!(parse_status_list("abc").is_err());
        assert!(parse_status_list("300-200").is_err());
    }

    #[test]
    fn filters_semantics() {
        let f = Filters::from_rules([(Rule::FilterSize, "10")]).unwrap();
        let m = |status, size| Measured {
            status,
            size,
            words: 1,
            lines: 1,
            body: "",
        };
        assert!(f.accepts(&m(200, 11)));
        assert!(!f.accepts(&m(200, 10)));
        assert!(!f.accepts(&m(404, 11)));
        let f =
            Filters::from_rules([(Rule::MatchRegex, "secret"), (Rule::MatchStatus, "")]).unwrap();
        assert!(f.accepts(&Measured {
            status: 500,
            size: 1,
            words: 1,
            lines: 1,
            body: "a secret"
        }));
    }

    #[test]
    fn excluded_paths() {
        let c = FuzzConfig {
            exclude_paths: vec!["/private".into(), "admin/".into()],
            ..Default::default()
        };
        assert!(c.path_excluded("/private"));
        assert!(c.path_excluded("/private/data.pdf"));
        assert!(c.path_excluded("/PRIVATE/x"));
        assert!(!c.path_excluded("/privateer.pdf"));
        assert!(c.path_excluded("/admin/x"));
        assert!(!c.path_excluded("/docs/a.pdf"));
    }
}
