//! Name variants of documents already found: years ±1..2, versions v1→v2, numbering
//! 001→002, `_final/_old/_draft` suffixes (added or removed). Extends FOCA's DNS prediction
//! idea to files.

use std::collections::BTreeSet;
use std::sync::OnceLock;

use regex::Regex;

const SUFFIXES: [&str; 8] = [
    "_final", "_old", "_draft", "-final", "-old", "-draft", "_new", "_copy",
];

fn year_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?:^|[^0-9])((?:19|20)[0-9]{2})(?:[^0-9]|$)").expect("re"))
}

fn version_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)(v|ver|version|rev|r)([._\-]?)([0-9]{1,3})").expect("re"))
}

fn num_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"[0-9]+").expect("re"))
}

/// Splits a name into stem and extension (`report.tar.gz` → `report`, `.tar.gz`).
pub fn split_ext(name: &str) -> (&str, &str) {
    let lower = name.to_ascii_lowercase();
    for multi in [".tar.gz", ".tar.bz2", ".tar.xz"] {
        if lower.ends_with(multi) && name.len() > multi.len() {
            return name.split_at(name.len() - multi.len());
        }
    }
    match name.rfind('.') {
        Some(i) if i > 0 => name.split_at(i),
        _ => (name, ""),
    }
}

fn replace_range(s: &str, start: usize, end: usize, with: &str) -> String {
    format!("{}{}{}", &s[..start], with, &s[end..])
}

/// Returns up to `max` variants of a file name (excluding the original).
pub fn mutate_name(name: &str, max: usize) -> Vec<String> {
    let (stem, ext) = split_ext(name);
    let mut out: BTreeSet<String> = BTreeSet::new();
    let mut ordered: Vec<String> = Vec::new();
    let mut push = |s: String, out: &mut BTreeSet<String>| {
        if s != name && !s.is_empty() && out.insert(s.clone()) {
            ordered.push(s);
        }
    };
    // Years.
    let mut year_spans = Vec::new();
    for c in year_re().captures_iter(stem) {
        let m = c.get(1).expect("group");
        year_spans.push((m.start(), m.end()));
        let y: i32 = m.as_str().parse().unwrap_or(0);
        for d in [1, -1, 2, -2] {
            let ny = y + d;
            if (1990..=2099).contains(&ny) {
                push(
                    format!(
                        "{}{ext}",
                        replace_range(stem, m.start(), m.end(), &ny.to_string())
                    ),
                    &mut out,
                );
            }
        }
    }
    // Versions.
    let mut ver_spans = Vec::new();
    for c in version_re().captures_iter(stem) {
        let m = c.get(3).expect("group");
        ver_spans.push((m.start(), m.end()));
        let v: u32 = m.as_str().parse().unwrap_or(0);
        let width = m.as_str().len();
        for nv in [v + 1, v + 2, v.saturating_sub(1)] {
            if nv != v {
                let s = format!("{nv:0width$}");
                push(
                    format!("{}{ext}", replace_range(stem, m.start(), m.end(), &s)),
                    &mut out,
                );
            }
        }
    }
    // Numbering (remaining digit groups other than years and versions).
    for m in num_re().find_iter(stem) {
        let span = (m.start(), m.end());
        if year_spans.contains(&span) || ver_spans.iter().any(|v| v.0 <= span.0 && span.1 <= v.1) {
            continue;
        }
        let digits = m.as_str();
        if digits.len() > 6 {
            continue;
        }
        let v: u64 = digits.parse().unwrap_or(0);
        let width = digits.len();
        for nv in [v + 1, v + 2, v.saturating_sub(1)] {
            if nv != v {
                let s = format!("{nv:0width$}");
                push(
                    format!("{}{ext}", replace_range(stem, m.start(), m.end(), &s)),
                    &mut out,
                );
            }
        }
    }
    // Suffixes.
    let lower = stem.to_ascii_lowercase();
    let mut had_suffix = false;
    for s in SUFFIXES {
        if lower.ends_with(s) {
            had_suffix = true;
            push(format!("{}{ext}", &stem[..stem.len() - s.len()]), &mut out);
        }
    }
    if !had_suffix {
        for s in ["_final", "_old", "_draft", "_v2", "-final"] {
            push(format!("{stem}{s}{ext}"), &mut out);
        }
    } else {
        let base = SUFFIXES
            .iter()
            .find(|s| lower.ends_with(**s))
            .map(|s| &stem[..stem.len() - s.len()])
            .unwrap_or(stem);
        for s in ["_final", "_old", "_draft"] {
            push(format!("{base}{s}{ext}"), &mut out);
        }
    }
    ordered.truncate(max);
    ordered
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn years() {
        let v = mutate_name("report_2023.pdf", 50);
        for y in [
            "report_2024.pdf",
            "report_2022.pdf",
            "report_2025.pdf",
            "report_2021.pdf",
        ] {
            assert!(v.contains(&y.to_string()), "{y} not in {v:?}");
        }
        assert!(!v.contains(&"report_2023.pdf".to_string()));
        // Year variants come first so the limit never cuts off the most valuable one.
        assert_eq!(mutate_name("report_2023.pdf", 1), vec!["report_2024.pdf"]);
    }

    #[test]
    fn versions_numbers_suffixes() {
        let v = mutate_name("spec_v1.docx", 50);
        assert!(v.contains(&"spec_v2.docx".to_string()), "{v:?}");
        assert!(v.contains(&"spec_v1_final.docx".to_string()));
        let v = mutate_name("doc_001.pdf", 50);
        assert!(v.contains(&"doc_002.pdf".to_string()), "{v:?}");
        assert!(v.contains(&"doc_000.pdf".to_string()));
        let v = mutate_name("budget_final.xlsx", 50);
        assert!(v.contains(&"budget.xlsx".to_string()), "{v:?}");
        assert!(v.contains(&"budget_draft.xlsx".to_string()));
        let v = mutate_name("plan_2024_v3.tar.gz", 50);
        assert!(v.contains(&"plan_2025_v3.tar.gz".to_string()), "{v:?}");
        assert!(v.contains(&"plan_2024_v4.tar.gz".to_string()), "{v:?}");
    }

    #[test]
    fn limits_and_no_digits() {
        assert!(mutate_name("readme", 3).len() <= 3);
        assert!(mutate_name("x.pdf", 100)
            .iter()
            .all(|n| n.ends_with(".pdf")));
        assert_eq!(split_ext(".htaccess"), (".htaccess", ""));
    }
}
