//! URL analysis before download, similar to FOCA's PathAnalysis: user names in paths, servers
//! and folders.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use url::Url;

use crate::filter::{ext_of_url, file_name_of_url, percent_decode};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UrlInfo {
    pub url: String,
    pub host: String,
    /// Decoded path folders, without the file name.
    pub dirs: Vec<String>,
    pub file: String,
    pub ext: Option<String>,
    /// User from the path (`/~ivan/`, `/users/ivan/`, `/home/ivan/`, ...).
    pub user: Option<String>,
}

/// Path segments that are usually followed by a login name.
const USER_MARKERS: &[&str] = &[
    "users",
    "user",
    "home",
    "people",
    "staff",
    "profiles",
    "profile",
    "author",
    "members",
    "member",
    "personal",
    "employees",
    "u",
];

fn plausible_login(s: &str) -> bool {
    let n = s.chars().count();
    (2..=32).contains(&n)
        && s.chars()
            .all(|c| c.is_alphanumeric() || matches!(c, '.' | '_' | '-'))
        && s.chars().any(|c| c.is_alphabetic())
        && !s.contains("..")
}

pub fn analyze_url(url: &str) -> Option<UrlInfo> {
    let u = Url::parse(url).ok()?;
    let host = u.host_str()?.to_ascii_lowercase();
    let segs: Vec<String> = u
        .path_segments()
        .map(|s| s.map(percent_decode).filter(|x| !x.is_empty()).collect())
        .unwrap_or_default();
    let file_is_last = ext_of_url(url).is_some();
    let dirs: Vec<String> = if file_is_last && !segs.is_empty() {
        segs[..segs.len() - 1].to_vec()
    } else {
        segs.clone()
    };
    let mut user = None;
    for (i, s) in dirs.iter().enumerate() {
        if let Some(x) = s.strip_prefix('~') {
            if plausible_login(x) {
                user = Some(x.to_lowercase());
                break;
            }
        }
        if USER_MARKERS.contains(&s.to_ascii_lowercase().as_str()) {
            if let Some(next) = dirs.get(i + 1) {
                if plausible_login(next) {
                    user = Some(next.to_lowercase());
                    break;
                }
            }
        }
    }
    Some(UrlInfo {
        url: url.to_string(),
        host,
        dirs,
        file: if file_is_last {
            file_name_of_url(url)
        } else {
            String::new()
        },
        ext: ext_of_url(url),
        user,
    })
}

/// Summary over a set of URLs.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct UrlSummary {
    /// Host to URL count.
    pub hosts: BTreeMap<String, usize>,
    /// User to URL count.
    pub users: BTreeMap<String, usize>,
    /// `host/dir/.../` to URL count.
    pub dirs: BTreeMap<String, usize>,
    /// Extension to URL count.
    pub exts: BTreeMap<String, usize>,
}

pub fn summarize_urls<'a>(urls: impl IntoIterator<Item = &'a str>) -> UrlSummary {
    let mut s = UrlSummary::default();
    for u in urls {
        let Some(i) = analyze_url(u) else { continue };
        *s.hosts.entry(i.host.clone()).or_default() += 1;
        if let Some(us) = &i.user {
            *s.users.entry(us.clone()).or_default() += 1;
        }
        if !i.dirs.is_empty() {
            *s.dirs
                .entry(format!("{}/{}/", i.host, i.dirs.join("/")))
                .or_default() += 1;
        }
        if let Some(e) = &i.ext {
            *s.exts.entry(e.clone()).or_default() += 1;
        }
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn users_in_paths() {
        let i = analyze_url("https://www.a.ua/~ivanov/docs/cv.pdf").unwrap();
        assert_eq!(i.user.as_deref(), Some("ivanov"));
        assert_eq!(i.dirs, vec!["~ivanov", "docs"]);
        assert_eq!(i.file, "cv.pdf");
        assert_eq!(
            analyze_url("https://a.ua/users/O.Petrenko/report.docx")
                .unwrap()
                .user
                .as_deref(),
            Some("o.petrenko")
        );
        assert_eq!(analyze_url("https://a.ua/home/x/a.pdf").unwrap().user, None);
        assert_eq!(
            analyze_url("https://a.ua/files/2024/a.pdf").unwrap().user,
            None
        );
        let s = summarize_urls([
            "https://a.ua/~ivanov/a.pdf",
            "https://a.ua/~ivanov/b.pdf",
            "https://files.a.ua/upload/c.docx",
        ]);
        assert_eq!(s.users["ivanov"], 2);
        assert_eq!(s.hosts["a.ua"], 2);
        assert_eq!(s.dirs["files.a.ua/upload/"], 1);
        assert_eq!(s.exts["pdf"], 2);
    }
}
