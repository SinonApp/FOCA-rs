//! Detection of open directory listings (Apache/nginx/IIS/lighttpd/Python http.server) and
//! collection of links to documents and subdirectories, restricted to that directory (no
//! `..` or sort links).

use std::collections::BTreeSet;
use std::sync::OnceLock;

use regex::Regex;
use url::Url;

/// Returns `true` if the body looks like a directory listing.
pub fn is_listing(body: &str) -> bool {
    let head: String = body
        .chars()
        .take(4096)
        .collect::<String>()
        .to_ascii_lowercase();
    head.contains("<title>index of /")
        || head.contains("<h1>index of /")
        || head.contains("<title>directory listing for /")
        || head.contains("[to parent directory]")
        || (head.contains(" - /") && head.contains("<pre>") && head.contains("[to parent"))
        || head.contains("<h2>index of /")
}

fn href_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r#"(?i)href\s*=\s*["']([^"'<>]+)["']"#).expect("re"))
}

/// Links from a listing.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ListingLinks {
    /// Files (absolute URLs).
    pub files: Vec<String>,
    /// Subdirectories (absolute URLs ending with `/`).
    pub dirs: Vec<String>,
    pub truncated: bool,
}

/// Collects links from a listing `body` fetched from `dir_url` (which ends with `/`).
pub fn parse_listing(dir_url: &Url, body: &str, max_links: usize) -> ListingLinks {
    let mut files = BTreeSet::new();
    let mut dirs = BTreeSet::new();
    let mut truncated = false;
    let base_path = dir_url.path().to_string();
    for c in href_re().captures_iter(body) {
        let raw = c[1].trim();
        if raw.is_empty()
            || raw.starts_with('?')
            || raw.starts_with('#')
            || raw.starts_with("javascript:")
            || raw.starts_with("mailto:")
            || raw.contains("..")
        {
            continue;
        }
        let Ok(mut u) = dir_url.join(raw) else {
            continue;
        };
        u.set_fragment(None);
        u.set_query(None);
        if u.scheme() != dir_url.scheme()
            || u.host_str() != dir_url.host_str()
            || u.port_or_known_default() != dir_url.port_or_known_default()
        {
            continue;
        }
        let p = u.path();
        // Only this directory's contents (no parent or siblings).
        if !p.starts_with(&base_path) || p == base_path {
            continue;
        }
        if files.len() + dirs.len() >= max_links {
            truncated = true;
            break;
        }
        if p.ends_with('/') {
            dirs.insert(u.to_string());
        } else {
            files.insert(u.to_string());
        }
    }
    ListingLinks {
        files: files.into_iter().collect(),
        dirs: dirs.into_iter().collect(),
        truncated,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const APACHE: &str = r#"<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
<html><head><title>Index of /docs</title></head><body><h1>Index of /docs</h1>
<table><tr><th><a href="?C=N;O=D">Name</a></th></tr>
<tr><td><a href="/">Parent Directory</a></td></tr>
<tr><td><a href="annual_report.docx">annual_report.docx</a></td></tr>
<tr><td><a href="price.xlsx">price.xlsx</a></td></tr>
<tr><td><a href="sub/">sub/</a></td></tr>
<tr><td><a href="../etc/">x</a></td></tr>
<tr><td><a href="http://evil.example/x.pdf">x</a></td></tr>
</table></body></html>"#;

    #[test]
    fn apache_listing() {
        assert!(is_listing(APACHE));
        let u = Url::parse("http://h/docs/").unwrap();
        let l = parse_listing(&u, APACHE, 100);
        assert_eq!(
            l.files,
            vec![
                "http://h/docs/annual_report.docx",
                "http://h/docs/price.xlsx"
            ]
        );
        assert_eq!(l.dirs, vec!["http://h/docs/sub/"]);
    }

    #[test]
    fn nginx_iis_python() {
        assert!(is_listing(
            "<html>\r\n<head><title>Index of /files/</title></head>\r\n<body>\r\n<h1>Index of /files/</h1><hr><pre><a href=\"../\">../</a>\r\n<a href=\"a.pdf\">a.pdf</a>"
        ));
        assert!(is_listing(
            "<html><head><title>h - /x/</title></head><body><H1>h - /x/</H1><hr>\r\n\r\n<pre><A HREF=\"/\">[To Parent Directory]</A>"
        ));
        assert!(is_listing(
            "<html><head><title>Directory listing for /</title>"
        ));
        assert!(!is_listing(
            "<html><title>Welcome</title>Index of products</html>"
        ));
    }

    #[test]
    fn limit() {
        let u = Url::parse("http://h/docs/").unwrap();
        let l = parse_listing(&u, APACHE, 1);
        assert!(l.truncated);
        assert_eq!(l.files.len() + l.dirs.len(), 1);
    }
}
