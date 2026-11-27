//! Download priority: documents with the richest metadata first, low-value images last.
//!
//! The ladder is applied when a source's finds are cut to the download limit and when the download
//! stage claims the next tasks from the queue. Inside a tier the provenance decides (site pages and
//! linked storage, then links found in documents, then search results, then archive copies), then
//! smaller files when the size is known, then discovery order.

use crate::filter::ext_of_url;

/// Office and PDF files with the richest metadata (authors, templates, printers, revisions).
const TIER1: &[&str] = &[
    "docx", "doc", "docm", "dotx", "dot", "xlsx", "xls", "xlsm", "xltx", "pptx", "ppt", "pptm",
    "ppsx", "pps", "odt", "ods", "odp", "odg", "pdf", "rtf", "msg", "eml", "vsdx", "vsd", "pub",
];

/// Other metadata-rich files: programs and packages, drawings, print files, archives, geodata,
/// notebooks, source maps, mail and contact files.
const TIER2: &[&str] = &[
    "exe", "dll", "msi", "jar", "war", "ear", "apk", "aab", "dwg", "dxf", "eps", "ai", "ps",
    "indd", "zip", "rar", "7z", "tar", "gz", "tgz", "bz2", "xz", "kml", "kmz", "gpx", "ipynb",
    "map", "vcf", "ics", "mbox", "txt", "csv", "xml", "json", "sql", "log", "bak", "conf", "cfg",
    "ini", "lnk", "rdp",
];

/// Media that may carry EXIF/XMP: camera photos, raw formats, video and audio.
const TIER3: &[&str] = &[
    "jpg", "jpeg", "tif", "tiff", "heic", "heif", "dng", "cr2", "cr3", "nef", "arw", "orf", "rw2",
    "raf", "mp4", "mov", "m4v", "avi", "mkv", "webm", "wmv", "wma", "wav", "flac", "ogg", "opus",
    "mp3", "m4a",
];

/// Low-value images and font files: site graphics rarely carry useful metadata.
const TIER4: &[&str] = &[
    "png", "gif", "svg", "webp", "ico", "bmp", "woff", "woff2", "ttf", "otf", "eot",
];

/// File names of site graphics (icons, logos, sprites, icon fonts, thumbnails).
const LOW_NAMES: &[&str] = &[
    "favicon",
    "logo",
    "sprite",
    "icon",
    "glyph",
    "fontello",
    "fontawesome",
    "thumb",
    "avatar",
    "emoji",
    "spinner",
    "loader",
    "placeholder",
    "pixel",
    "spacer",
];

/// Tier of a URL, 1 (download first) to 4 (last); `hint_ext` wins over the URL's extension.
pub fn tier(url: &str, hint_ext: Option<&str>) -> u8 {
    let ext = hint_ext
        .map(|e| e.trim_start_matches('.').to_ascii_lowercase())
        .or_else(|| ext_of_url(url));
    let name = file_name(url);
    let low_name = LOW_NAMES.iter().any(|n| name.contains(n));
    match ext.as_deref() {
        Some(e) if TIER4.contains(&e) => 4,
        Some(e) if TIER3.contains(&e) => {
            if low_name {
                4
            } else {
                3
            }
        }
        Some(e) if TIER1.contains(&e) => 1,
        Some(e) if TIER2.contains(&e) => 2,
        _ if low_name => 4,
        _ => 2,
    }
}

/// Provenance rank of a source id: 0 site pages, linked storage and site file search, 1 links
/// found inside documents, 2 search engines and URL indexes, 3 archive copies.
pub fn source_rank(source: &str) -> u8 {
    match source {
        "crawler" | "crawl" | "site" | "storage" | "fuzz" => 0,
        "doc" => 1,
        "wayback" | "cc" => 3,
        _ => 2,
    }
}

/// Queue order key of a task: tier, then provenance (ties keep the queue id order).
pub fn rank(url: &str, source: &str) -> (u8, u8) {
    (tier(url, None), source_rank(source))
}

/// Order key of a find: tier, provenance, then known size (smaller first). Sorting by it is
/// stable, so discovery order breaks the remaining ties.
pub fn found_key(
    url: &str,
    hint_ext: Option<&str>,
    source: &str,
    size: Option<u64>,
) -> (u8, u8, bool, u64) {
    (
        tier(url, hint_ext),
        source_rank(source),
        size.is_none(),
        size.unwrap_or(0),
    )
}

fn file_name(url: &str) -> String {
    let path = url.split(['?', '#']).next().unwrap_or("");
    path.rsplit('/').next().unwrap_or("").to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::source::FoundUrl;

    fn sort_found(items: &mut [FoundUrl]) {
        crate::source::sort_found(items);
    }

    #[test]
    fn mixed_items_follow_the_ladder() {
        let urls = [
            "https://a.example/assets/fontello.svg",
            "https://a.example/img/about.png",
            "https://a.example/favicon.png",
            "https://a.example/files/prices.doc",
            "https://a.example/files/koledzh.docx",
            "https://a.example/files/report.pdf",
            "https://a.example/gallery/photo.jpg",
            "https://a.example/dl/app.exe",
        ];
        let mut items: Vec<FoundUrl> = urls.iter().map(|u| FoundUrl::new(u, "crawler")).collect();
        sort_found(&mut items);
        let names: Vec<&str> = items
            .iter()
            .map(|u| u.url.rsplit('/').next().unwrap())
            .collect();
        assert_eq!(
            names,
            [
                "prices.doc",
                "koledzh.docx",
                "report.pdf",
                "app.exe",
                "photo.jpg",
                "fontello.svg",
                "about.png",
                "favicon.png"
            ]
        );
        assert_eq!(tier("https://a.example/files/report.pdf", None), 1);
        assert_eq!(tier("https://a.example/dl/app.exe", None), 2);
        assert_eq!(tier("https://a.example/gallery/photo.jpg", None), 3);
        assert_eq!(tier("https://a.example/logo.jpg", None), 4);
        assert_eq!(tier("https://a.example/d?id=7", Some("PDF")), 1);
    }

    #[test]
    fn provenance_then_size_inside_a_tier() {
        let mut a = FoundUrl::new(
            "https://web.archive.org/web/2020id_/https://a.example/x.pdf",
            "wayback",
        );
        a.size = Some(10);
        let mut b = FoundUrl::new("https://a.example/big.pdf", "crawler");
        b.size = Some(9_000_000);
        let mut c = FoundUrl::new("https://a.example/small.pdf", "crawler");
        c.size = Some(1_000);
        let d = FoundUrl::new("https://a.example/unknown.pdf", "brave");
        let e = FoundUrl::new("https://a.example/inner.pdf", "doc");
        let mut v = vec![a, b, c, d, e];
        sort_found(&mut v);
        let names: Vec<&str> = v
            .iter()
            .map(|u| u.url.rsplit('/').next().unwrap())
            .collect();
        assert_eq!(
            names,
            ["small.pdf", "big.pdf", "inner.pdf", "unknown.pdf", "x.pdf"]
        );
    }
}
