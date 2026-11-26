//! Semantic version parsing, comparison, and CPE 2.3 / CVE range evaluation.
//!
//! Pure-Rust comparator for dotted software and server versions (`2.4.49`, `8.3.8`,
//! `10.0.20348.2582`, `2021.007.20099`, `1.18.0ubuntu1`, `7.4.1-p2`, `1.0.2k`) plus a curated
//! table of affected version ranges (`[from_inc, to_exc)`) and minimum patched thresholds for
//! server/application products in the CISA KEV catalog.

use std::cmp::Ordering;

use serde::{Deserialize, Serialize};

/// One component of a normalized software version.
#[derive(Debug, Clone, PartialEq, Eq)]
enum VerToken {
    Num(u64),
    Alpha(String),
}

impl Ord for VerToken {
    fn cmp(&self, other: &Self) -> Ordering {
        match (self, other) {
            (VerToken::Num(a), VerToken::Num(b)) => a.cmp(b),
            (VerToken::Alpha(a), VerToken::Alpha(b)) => a.cmp(b),
            // A numeric component after a number is greater than a pre-release alpha suffix,
            // except OpenSSL-style single letter patches (`1.0.2k` > `1.0.2`).
            (VerToken::Num(_), VerToken::Alpha(_)) => Ordering::Greater,
            (VerToken::Alpha(_), VerToken::Num(_)) => Ordering::Less,
        }
    }
}

impl PartialOrd for VerToken {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Parses a version string into comparable tokens.
fn tokenize(v: &str) -> Vec<VerToken> {
    let mut out = Vec::new();
    let bytes = v.trim().as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if b.is_ascii_digit() {
            let start = i;
            while i < bytes.len() && bytes[i].is_ascii_digit() {
                i += 1;
            }
            if let Ok(n) = std::str::from_utf8(&bytes[start..i])
                .unwrap_or("0")
                .parse::<u64>()
            {
                out.push(VerToken::Num(n));
            }
        } else if b.is_ascii_alphabetic() {
            let start = i;
            while i < bytes.len() && bytes[i].is_ascii_alphabetic() {
                i += 1;
            }
            let s = std::str::from_utf8(&bytes[start..i])
                .unwrap_or("")
                .to_ascii_lowercase();
            // Skip distro separator words like "ubuntu", "deb", "el", "p" when comparing upstream patch numbers.
            if !matches!(s.as_str(), "ubuntu" | "deb" | "build" | "rel" | "p") {
                out.push(VerToken::Alpha(s));
            }
        } else {
            i += 1;
        }
    }
    // Strip trailing `.0` numeric tokens so `2.4` == `2.4.0`.
    while out.len() > 2 && matches!(out.last(), Some(VerToken::Num(0))) {
        out.pop();
    }
    out
}

/// Whether an alphabetic version token denotes a SemVer/distro pre-release tag rather than
/// a post-release patch letter (`1.0.2k`).
fn is_prerelease_tag(s: &str) -> bool {
    matches!(
        s,
        "alpha" | "a" | "beta" | "b" | "rc" | "pre" | "dev" | "snapshot" | "preview" | "nightly"
    )
}

/// Compares two software version strings (`a` vs `b`).
pub fn compare_versions(a: &str, b: &str) -> Ordering {
    let ta = tokenize(a);
    let tb = tokenize(b);
    let len = ta.len().max(tb.len());
    for idx in 0..len {
        match (ta.get(idx), tb.get(idx)) {
            (Some(x), Some(y)) => {
                let ord = x.cmp(y);
                if ord != Ordering::Equal {
                    return ord;
                }
            }
            (Some(VerToken::Num(0)), None) => continue,
            (None, Some(VerToken::Num(0))) => continue,
            (Some(VerToken::Alpha(s)), None) if is_prerelease_tag(s) => return Ordering::Less,
            (None, Some(VerToken::Alpha(s))) if is_prerelease_tag(s) => return Ordering::Greater,
            (Some(_), None) => return Ordering::Greater,
            (None, Some(_)) => return Ordering::Less,
            (None, None) => break,
        }
    }
    Ordering::Equal
}

/// Whether `ver` lies within `[from_inc, to_exc)`.
pub fn in_range(ver: &str, from_inc: &str, to_exc: &str) -> bool {
    compare_versions(ver, from_inc) != Ordering::Less
        && compare_versions(ver, to_exc) == Ordering::Less
}

/// Extracts a dotted version (`2.4.49`, `8.3.6`, `10.0.19045`) from a product display string or
/// explicit version field. Single 4-digit marketing years (`2007`, `2010`, `2016`, `365`) without a
/// dot are treated as marketing editions, not patch versions.
pub fn extract_semver(name: &str, explicit_ver: &str) -> Option<String> {
    for candidate in [explicit_ver.trim(), name.trim()] {
        if candidate.is_empty() {
            continue;
        }
        for raw_tok in
            candidate.split(|c: char| c.is_whitespace() || matches!(c, '/' | '(' | ')' | ',' | ';'))
        {
            let tok = raw_tok.trim_matches(|c: char| !c.is_ascii_alphanumeric());
            if !tok.contains('.') {
                continue;
            }
            let first = tok.chars().next().unwrap_or(' ');
            if !first.is_ascii_digit() {
                continue;
            }
            let nums = tok
                .split('.')
                .filter(|p| p.chars().next().is_some_and(|c| c.is_ascii_digit()))
                .count();
            if nums >= 2 {
                return Some(tok.to_string());
            }
        }
    }
    None
}

/// One known affected CVE version range for a product key in `kev_products.toml`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CveVersionRange {
    pub product_key: &'static str,
    pub cve: &'static str,
    pub from_inc: &'static str,
    pub to_exc: &'static str,
    /// Optional OS applicability hint (`Some("windows")`) to avoid Linux false positives.
    pub os_hint: Option<&'static str>,
}

/// Curated CVE version ranges (`[from_inc, to_exc)`) for products in `kev_products.toml`.
pub const KNOWN_CVE_RANGES: &[CveVersionRange] = &[
    // Apache HTTP Server (`apache_httpd`): CVEs present in KEV snapshot
    CveVersionRange {
        product_key: "apache_httpd",
        cve: "CVE-2019-0211",
        from_inc: "2.4.17",
        to_exc: "2.4.39",
        os_hint: None,
    },
    CveVersionRange {
        product_key: "apache_httpd",
        cve: "CVE-2021-40438",
        from_inc: "2.4.0",
        to_exc: "2.4.49",
        os_hint: None,
    },
    CveVersionRange {
        product_key: "apache_httpd",
        cve: "CVE-2021-41773",
        from_inc: "2.4.49",
        to_exc: "2.4.50",
        os_hint: None,
    },
    CveVersionRange {
        product_key: "apache_httpd",
        cve: "CVE-2021-42013",
        from_inc: "2.4.49",
        to_exc: "2.4.51",
        os_hint: None,
    },
    CveVersionRange {
        product_key: "apache_httpd",
        cve: "CVE-2024-38475",
        from_inc: "2.4.0",
        to_exc: "2.4.60",
        os_hint: None,
    },
    // Apache Tomcat (`apache_tomcat`)
    CveVersionRange {
        product_key: "apache_tomcat",
        cve: "CVE-2020-1938",
        from_inc: "9.0.0",
        to_exc: "9.0.31",
        os_hint: None,
    },
    CveVersionRange {
        product_key: "apache_tomcat",
        cve: "CVE-2020-9484",
        from_inc: "9.0.0",
        to_exc: "9.0.35",
        os_hint: None,
    },
    CveVersionRange {
        product_key: "apache_tomcat",
        cve: "CVE-2024-50379",
        from_inc: "9.0.0",
        to_exc: "9.0.98",
        os_hint: None,
    },
    CveVersionRange {
        product_key: "apache_tomcat",
        cve: "CVE-2024-50379",
        from_inc: "10.1.0",
        to_exc: "10.1.34",
        os_hint: None,
    },
    // PHP (`php`)
    CveVersionRange {
        product_key: "php",
        cve: "CVE-2019-11043",
        from_inc: "7.1.0",
        to_exc: "7.3.11",
        os_hint: None,
    },
    CveVersionRange {
        product_key: "php",
        cve: "CVE-2024-4577",
        from_inc: "8.1.0",
        to_exc: "8.1.29",
        os_hint: Some("windows"),
    },
    CveVersionRange {
        product_key: "php",
        cve: "CVE-2024-4577",
        from_inc: "8.2.0",
        to_exc: "8.2.20",
        os_hint: Some("windows"),
    },
    CveVersionRange {
        product_key: "php",
        cve: "CVE-2024-4577",
        from_inc: "8.3.0",
        to_exc: "8.3.8",
        os_hint: Some("windows"),
    },
    // Exim (`exim`)
    CveVersionRange {
        product_key: "exim",
        cve: "CVE-2019-10149",
        from_inc: "4.87",
        to_exc: "4.92",
        os_hint: None,
    },
    CveVersionRange {
        product_key: "exim",
        cve: "CVE-2020-28018",
        from_inc: "4.00",
        to_exc: "4.94.2",
        os_hint: None,
    },
    CveVersionRange {
        product_key: "exim",
        cve: "CVE-2023-42115",
        from_inc: "4.00",
        to_exc: "4.96.2",
        os_hint: None,
    },
    // OpenSSL (`openssl`)
    CveVersionRange {
        product_key: "openssl",
        cve: "CVE-2014-0160",
        from_inc: "1.0.1",
        to_exc: "1.0.1g",
        os_hint: None,
    },
    // WordPress (`wordpress`)
    CveVersionRange {
        product_key: "wordpress",
        cve: "CVE-2017-5487",
        from_inc: "4.7.0",
        to_exc: "4.7.2",
        os_hint: None,
    },
    CveVersionRange {
        product_key: "wordpress",
        cve: "CVE-2022-21661",
        from_inc: "3.7.0",
        to_exc: "5.8.3",
        os_hint: None,
    },
    // Joomla (`joomla`)
    CveVersionRange {
        product_key: "joomla",
        cve: "CVE-2023-23752",
        from_inc: "4.0.0",
        to_exc: "4.2.8",
        os_hint: None,
    },
    // Drupal (`drupal`)
    CveVersionRange {
        product_key: "drupal",
        cve: "CVE-2018-7600",
        from_inc: "7.0",
        to_exc: "7.58",
        os_hint: None,
    },
    CveVersionRange {
        product_key: "drupal",
        cve: "CVE-2018-7600",
        from_inc: "8.0.0",
        to_exc: "8.5.1",
        os_hint: None,
    },
    // Roundcube (`roundcube`)
    CveVersionRange {
        product_key: "roundcube",
        cve: "CVE-2023-43770",
        from_inc: "1.4.0",
        to_exc: "1.6.3",
        os_hint: None,
    },
    CveVersionRange {
        product_key: "roundcube",
        cve: "CVE-2024-37383",
        from_inc: "1.5.0",
        to_exc: "1.6.7",
        os_hint: None,
    },
    // GitLab (`gitlab`)
    CveVersionRange {
        product_key: "gitlab",
        cve: "CVE-2021-22205",
        from_inc: "11.9.0",
        to_exc: "13.10.3",
        os_hint: None,
    },
    CveVersionRange {
        product_key: "gitlab",
        cve: "CVE-2023-7028",
        from_inc: "16.1.0",
        to_exc: "16.7.2",
        os_hint: None,
    },
    // OwnCloud / Nextcloud (`owncloud`)
    CveVersionRange {
        product_key: "owncloud",
        cve: "CVE-2023-49103",
        from_inc: "10.0.0",
        to_exc: "10.13.1",
        os_hint: None,
    },
];

/// Outcome of evaluating a product's detected version against [`KNOWN_CVE_RANGES`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VersionEval {
    /// Detected version falls inside one or more known vulnerable ranges `[from_inc, to_exc)`.
    Confirmed {
        ver: String,
        cves: Vec<&'static str>,
        fixed_in: &'static str,
        distro_backport: bool,
    },
    /// Product has known CVE ranges and the detected version is newer than or equal to every
    /// `to_exc` threshold for that product.
    Patched { ver: String, min_safe: &'static str },
    /// No dotted version was detected or the product has no version-range entries in the table.
    Unknown,
}

/// Evaluates `product_key` and a detected software/tech name + version against [`KNOWN_CVE_RANGES`].
pub fn eval_product_version(product_key: &str, name: &str, explicit_ver: &str) -> VersionEval {
    eval_product_version_with_context(product_key, name, explicit_ver, "")
}

/// Evaluates `product_key`, version, and surrounding host tech/banner context (used to filter
/// Windows-only CVEs on Linux hosts and detect distro packages with backported security fixes).
pub fn eval_product_version_with_context(
    product_key: &str,
    name: &str,
    explicit_ver: &str,
    host_context: &str,
) -> VersionEval {
    let Some(ver) = extract_semver(name, explicit_ver) else {
        return VersionEval::Unknown;
    };
    let ctx_low = format!("{name} {explicit_ver} {host_context}").to_ascii_lowercase();
    let is_unix = [
        "ubuntu", "debian", "linux", "centos", "rhel", "red hat", "alpine", "freebsd", "openbsd",
        "netbsd", "suse", "opensuse", "fedora", "arch", "macos", "darwin", "php-fpm",
    ]
    .iter()
    .any(|t| ctx_low.contains(t));
    let is_windows = ["windows", "win32", "win64", "iis", "xampp", "wamp"]
        .iter()
        .any(|t| ctx_low.contains(t));
    let distro_backport = [
        "ubuntu", "debian", "-1ubuntu", "deb10", "deb11", "deb12", "deb13", ".el7", ".el8", ".el9",
        "centos", "rhel", "alpine", "suse",
    ]
    .iter()
    .any(|t| ctx_low.contains(t));

    let product_ranges: Vec<&CveVersionRange> = KNOWN_CVE_RANGES
        .iter()
        .filter(|r| {
            r.product_key == product_key
                && !(r.os_hint == Some("windows") && is_unix && !is_windows)
        })
        .collect();
    if product_ranges.is_empty() {
        return VersionEval::Unknown;
    }
    let mut matched_cves = Vec::new();
    let mut highest_fix = "";
    for r in &product_ranges {
        if in_range(&ver, r.from_inc, r.to_exc) {
            if !matched_cves.contains(&r.cve) {
                matched_cves.push(r.cve);
            }
            if highest_fix.is_empty()
                || compare_versions(r.to_exc, highest_fix) == Ordering::Greater
            {
                highest_fix = r.to_exc;
            }
        }
    }
    if !matched_cves.is_empty() {
        return VersionEval::Confirmed {
            ver,
            cves: matched_cves,
            fixed_in: highest_fix,
            distro_backport,
        };
    }
    // Check if the version is strictly `>= to_exc` for all applicable ranges of this product.
    let mut max_fix = product_ranges[0].to_exc;
    for r in &product_ranges[1..] {
        if compare_versions(r.to_exc, max_fix) == Ordering::Greater {
            max_fix = r.to_exc;
        }
    }
    if compare_versions(&ver, max_fix) != Ordering::Less {
        return VersionEval::Patched {
            ver,
            min_safe: max_fix,
        };
    }
    VersionEval::Unknown
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compare_versions_handles_dotted_and_vendor_suffixes() {
        assert_eq!(compare_versions("2.4.49", "2.4.50"), Ordering::Less);
        assert_eq!(compare_versions("2.4.50", "2.4.49"), Ordering::Greater);
        assert_eq!(compare_versions("2.4.0", "2.4"), Ordering::Equal);
        assert_eq!(compare_versions("8.3.6-1ubuntu2", "8.3.8"), Ordering::Less);
        assert_eq!(compare_versions("1.0.1f", "1.0.1g"), Ordering::Less);
        assert_eq!(
            compare_versions("10.0.20348.2582", "10.0.20348.1000"),
            Ordering::Greater
        );
    }

    #[test]
    fn eval_product_version_distinguishes_confirmed_patched_and_unknown() {
        assert_eq!(compare_versions("2.4.60-rc1", "2.4.60"), Ordering::Less);
        assert_eq!(compare_versions("2.4.60", "2.4.60-rc1"), Ordering::Greater);
        assert_eq!(compare_versions("1.0.2k", "1.0.2"), Ordering::Greater);

        let v1 = eval_product_version("apache_httpd", "Apache HTTP Server 2.4.49", "");
        assert_eq!(
            v1,
            VersionEval::Confirmed {
                ver: "2.4.49".into(),
                cves: vec!["CVE-2021-41773", "CVE-2021-42013", "CVE-2024-38475"],
                fixed_in: "2.4.60",
                distro_backport: false,
            }
        );

        let v_ub = eval_product_version_with_context(
            "apache_httpd",
            "Apache HTTP Server 2.4.52",
            "",
            "Apache HTTP Server 2.4.52, Ubuntu Linux",
        );
        assert_eq!(
            v_ub,
            VersionEval::Confirmed {
                ver: "2.4.52".into(),
                cves: vec!["CVE-2024-38475"],
                fixed_in: "2.4.60",
                distro_backport: true,
            }
        );

        // Windows-only PHP CGI CVE-2024-4577 must not fire on Ubuntu Linux PHP 8.1.2.
        let php_linux = eval_product_version_with_context(
            "php",
            "PHP 8.1.2",
            "",
            "Apache HTTP Server 2.4.52, Ubuntu Linux, PHP 8.1.2",
        );
        assert!(matches!(php_linux, VersionEval::Patched { .. }));

        let v2 = eval_product_version("apache_httpd", "Apache HTTP Server 2.4.62", "");
        assert_eq!(
            v2,
            VersionEval::Patched {
                ver: "2.4.62".into(),
                min_safe: "2.4.60",
            }
        );

        let v3 = eval_product_version("apache_httpd", "Apache HTTP Server", "");
        assert_eq!(v3, VersionEval::Unknown);

        // Marketing year (Word 2010) is not a dotted semver -> Unknown (handled by EOL logic).
        let v4 = eval_product_version("ms_office", "Microsoft Office Word 2010", "");
        assert_eq!(v4, VersionEval::Unknown);
    }
}
