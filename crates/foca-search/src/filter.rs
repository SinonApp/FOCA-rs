//! Extension filter, URL normalization and deduplication.

use std::collections::BTreeSet;

use url::Url;

/// Default extensions (FOCA's list plus images with EXIF and connection files).
pub const DEFAULT_EXTS: &[&str] = &[
    "doc", "docx", "docm", "dot", "dotx", "xls", "xlsx", "xlsm", "xlsb", "ppt", "pptx", "pptm",
    "pps", "ppsx", "pdf", "odt", "ods", "odp", "odg", "sxw", "sxc", "sxi", "wpd", "rtf", "svg",
    "indd", "rdp", "ica", "jpg", "jpeg", "png", "tif", "tiff", "heic", "vsd", "vsdx", "pub", "wps",
    "wks", "eml", "msg", "ics", "vcf", "lnk", "mp4", "mov", "zip", "7z", "epub", "mp3", "psd",
    // executables and packages, CAD and print files, archives, media, geodata, developer files
    "exe", "dll", "msi", "jar", "war", "ear", "apk", "aab", "dwg", "dxf", "eps", "ps", "ai", "emf",
    "wmf", "tar", "gz", "tgz", "bz2", "xz", "rar", "wav", "avi", "mkv", "webm", "wmv", "wma",
    "flac", "ogg", "opus", "kml", "kmz", "gpx", "map", "ipynb",
];

/// Extension filter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtFilter {
    exts: BTreeSet<String>,
}

/// Image extensions (EXIF/XMP metadata). Sources give them a separate, smaller quota so images
/// do not crowd out documents.
pub const IMAGE_EXTS: &[&str] = &[
    "jpg", "jpeg", "png", "tif", "tiff", "heic", "gif", "svg", "webp", "mp4", "mov", "m4v", "wav",
    "avi", "mkv", "webm", "wmv", "wma", "flac", "ogg", "opus", "mp3",
];

/// Returns `true` for an image extension (as opposed to a document).
pub fn is_image_ext(ext: &str) -> bool {
    IMAGE_EXTS.contains(&ext.to_ascii_lowercase().as_str())
}

/// Returns `true` if the MIME type of an archive copy fits a file with extension `ext`. An HTML page
/// (error, placeholder, redirect) is not a document; `-`, empty, octet-stream and warc defer to the extension.
pub fn mime_fits(mime: Option<&str>, ext: &str) -> bool {
    let Some(m) = mime.map(|m| m.trim().to_ascii_lowercase()) else {
        return true;
    };
    if m.is_empty() || m == "-" || m == "unk" || m.starts_with("warc/") {
        return true;
    }
    if m.contains("html") || m.starts_with("text/css") || m.contains("javascript") {
        return false;
    }
    // fonts (.eot/.woff) from the application/vnd.* family are not documents
    if m.contains("fontobject") || m.starts_with("font/") || m.contains("font-") {
        return false;
    }
    if is_image_ext(ext) {
        return m.starts_with("image/")
            || m.starts_with("video/")
            || m.starts_with("audio/")
            || m.contains("octet-stream");
    }
    true
}

impl Default for ExtFilter {
    fn default() -> Self {
        ExtFilter::new(DEFAULT_EXTS.iter().copied())
    }
}

impl ExtFilter {
    pub fn new<I, S>(exts: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        ExtFilter {
            exts: exts
                .into_iter()
                .map(|e| {
                    e.as_ref()
                        .trim()
                        .trim_start_matches('.')
                        .to_ascii_lowercase()
                })
                .filter(|e| !e.is_empty())
                .collect(),
        }
    }

    /// Parses a list such as `pdf,docx,...`; an empty list yields the defaults.
    pub fn parse(list: &str) -> Self {
        let f = ExtFilter::new(list.split([',', ' ', ';']));
        if f.exts.is_empty() {
            ExtFilter::default()
        } else {
            f
        }
    }

    pub fn exts(&self) -> impl Iterator<Item = &str> {
        self.exts.iter().map(|s| s.as_str())
    }

    pub fn allows_ext(&self, ext: &str) -> bool {
        self.exts.contains(&ext.to_ascii_lowercase())
    }

    /// Returns the URL's extension if it passes the filter.
    pub fn matches(&self, url: &str) -> Option<String> {
        ext_of_url(url).filter(|e| self.exts.contains(e))
    }

    /// Builds a case-insensitive regex matching URLs that end in one of the extensions, for the
    /// server-side CDX (`filter=original:...`) and CC (`filter=~url:...`) filters.
    pub fn url_regex(&self) -> String {
        let alts: Vec<&str> = self.exts().collect();
        format!("(?i).*\\.({})(\\?.*)?$", alts.join("|"))
    }
}

/// Returns `true` if the URL belongs to the domain or one of its subdomains.
pub fn url_in_domain(u: &str, domain: &str) -> bool {
    url::Url::parse(u)
        .ok()
        .and_then(|x| {
            x.host_str()
                .map(|h| h.trim_end_matches('.').to_ascii_lowercase())
        })
        .is_some_and(|h| h == domain || h.ends_with(&format!(".{domain}")))
}

/// Returns the original URL of an archive copy `.../web/<ts>id_/<url>`, or `None`.
pub fn archived_original(url: &str) -> Option<&str> {
    let i = url.find("/web/")?;
    let rest = &url[i + 5..];
    let j = rest.find('/')?;
    let ts = &rest[..j];
    if ts.is_empty()
        || !ts
            .trim_end_matches('_')
            .trim_end_matches(char::is_alphabetic)
            .bytes()
            .all(|b| b.is_ascii_digit())
    {
        return None;
    }
    let o = &rest[j + 1..];
    (o.starts_with("http://") || o.starts_with("https://")).then_some(o)
}

/// Returns the dedup key of a document by its URL on the target site (the original URL for archive copies).
pub fn target_key(url: &str) -> String {
    dedup_key(archived_original(url).unwrap_or(url))
}

/// Returns the extension of the last path segment (lowercase, without query or fragment).
pub fn ext_of_url(url: &str) -> Option<String> {
    let path = match Url::parse(url) {
        Ok(u) => u.path().to_string(),
        Err(_) => url.split(['?', '#']).next().unwrap_or("").to_string(),
    };
    let last = path.rsplit('/').next()?;
    let last = percent_decode(last);
    let (stem, ext) = last.rsplit_once('.')?;
    if stem.is_empty()
        || ext.is_empty()
        || ext.len() > 5
        || !ext.chars().all(|c| c.is_ascii_alphanumeric())
    {
        return None;
    }
    Some(ext.to_ascii_lowercase())
}

/// Returns the file name from a URL (the decoded last segment).
pub fn file_name_of_url(url: &str) -> String {
    let path = Url::parse(url)
        .map(|u| u.path().to_string())
        .unwrap_or_default();
    let last = path.rsplit('/').next().unwrap_or("");
    let n = percent_decode(last);
    if n.is_empty() {
        "index".into()
    } else {
        n
    }
}

/// Decodes `%XX` escapes (invalid UTF-8 is replaced).
pub fn percent_decode(s: &str) -> String {
    url::form_urlencoded::parse(format!("x={}", s.replace('+', "%2B")).as_bytes())
        .next()
        .map(|(_, v)| v.into_owned())
        .unwrap_or_else(|| s.to_string())
}

/// Normalizes a URL: http(s) only, lowercase scheme and host (IDN to punycode), no fragment, no
/// default port, no empty `?`, no trailing dot in the host; an empty path becomes `/`.
pub fn normalize_url(input: &str) -> Option<String> {
    let mut u = Url::parse(input.trim()).ok()?;
    if !matches!(u.scheme(), "http" | "https") {
        return None;
    }
    u.set_fragment(None);
    let host = u.host_str()?.trim_end_matches('.').to_ascii_lowercase();
    if host.is_empty() {
        return None;
    }
    if u.set_host(Some(&host)).is_err() {
        return None;
    }
    if u.query() == Some("") {
        u.set_query(None);
    }
    Some(u.to_string())
}

/// Returns the dedup key: no scheme and no `www.` (http/https and www variants are one document).
pub fn dedup_key(url: &str) -> String {
    match normalize_url(url).and_then(|n| Url::parse(&n).ok()) {
        Some(u) => {
            let host = u.host_str().unwrap_or("");
            let host = host.strip_prefix("www.").unwrap_or(host);
            let port = u.port().map(|p| format!(":{p}")).unwrap_or_default();
            let q = u.query().map(|q| format!("?{q}")).unwrap_or_default();
            format!("{host}{port}{}{q}", u.path())
        }
        None => url.trim().to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::source::{dedupe, FoundUrl};

    #[test]
    fn ext_filter() {
        let f = ExtFilter::default();
        assert_eq!(
            f.matches("https://a.ua/docs/Report.PDF?x=1#p").as_deref(),
            Some("pdf")
        );
        assert_eq!(
            f.matches("https://a.ua/%D0%B7%D0%B2%D1%96%D1%82.docx")
                .as_deref(),
            Some("docx")
        );
        assert_eq!(f.matches("https://a.ua/index.php"), None);
        assert_eq!(f.matches("https://a.ua/.pdf"), None);
        assert_eq!(f.matches("https://a.ua/dir.pdf/"), None);
        let p = ExtFilter::parse("pdf, .DOCX");
        assert!(p.allows_ext("docx") && !p.allows_ext("xls"));
        assert_eq!(ExtFilter::parse(""), ExtFilter::default());
        for (u, e) in [
            ("https://a.ua/dl/setup.msi", "msi"),
            ("https://a.ua/app/Billing.DLL", "dll"),
            ("https://a.ua/lib/app.jar", "jar"),
            ("https://a.ua/m/field.apk", "apk"),
            ("https://a.ua/cad/plan.dwg", "dwg"),
            ("https://a.ua/print/logo.eps", "eps"),
            ("https://a.ua/b/site.tar", "tar"),
            ("https://a.ua/b/site.tgz", "tgz"),
            ("https://a.ua/b/x.rar", "rar"),
            ("https://a.ua/geo/depots.kmz", "kmz"),
            ("https://a.ua/geo/run.gpx", "gpx"),
            ("https://a.ua/js/app.js.map", "map"),
            ("https://a.ua/nb/report.ipynb", "ipynb"),
            ("https://a.ua/v/tour.webm", "webm"),
        ] {
            assert_eq!(f.matches(u).as_deref(), Some(e), "{u}");
        }
        assert!(is_image_ext("webm") && !is_image_ext("dwg"));
        assert!(mime_fits(Some("video/webm"), "webm"));
        assert!(mime_fits(Some("audio/x-wav"), "wav"));
        assert!(!mime_fits(Some("text/html"), "wav"));
        assert_eq!(
            file_name_of_url("https://a.ua/x/%D0%B7%D0%B2%D1%96%D1%82%201.docx"),
            "звіт 1.docx"
        );
    }

    #[test]
    fn normalize_and_dedup() {
        assert_eq!(
            normalize_url("HTTPS://WWW.A.UA.:443/x/y.pdf?#frag").as_deref(),
            Some("https://www.a.ua/x/y.pdf")
        );
        assert_eq!(normalize_url("ftp://a.ua/x"), None);
        assert_eq!(
            normalize_url("http://a.ua").as_deref(),
            Some("http://a.ua/")
        );
        assert_eq!(
            dedup_key("http://www.a.ua/x.pdf"),
            dedup_key("https://a.ua/x.pdf#z")
        );
        assert_ne!(
            dedup_key("https://a.ua/x.pdf?v=1"),
            dedup_key("https://a.ua/x.pdf?v=2")
        );
        let v = dedupe(vec![
            FoundUrl::new(
                "https://web.archive.org/web/1id_/http://a.ua/x.pdf",
                "wayback",
            )
            .with_original("http://a.ua/x.pdf"),
            FoundUrl::new("https://a.ua/x.pdf", "cc"),
            FoundUrl::new("https://a.ua/y.pdf", "cc"),
        ]);
        assert_eq!(v.len(), 2);
        assert_eq!(v[0].source, "wayback");
    }
}
