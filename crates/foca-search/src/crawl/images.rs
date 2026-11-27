//! Selective image download for EXIF: which crawled images are worth fetching.
//!
//! Photos (JPEG, HEIC, TIFF) carry camera, GPS and author metadata; PNG sometimes carries XMP or
//! text chunks; icons, logos, sprites and thumbnails carry nothing useful. Candidates are scored
//! by extension, URL patterns and the `width`/`height` attributes of the `<img>` tag, then the
//! best ones are kept up to a count cap. The byte cap is enforced by the download stage.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use crate::filter::{dedup_key, ext_of_url};

/// An image found on a crawled page.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImageCand {
    pub url: String,
    /// The in-scope page that showed or linked the image.
    pub page: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub w: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub h: Option<u32>,
}

/// URL words of decorative images.
const SKIP_WORDS: &[&str] = &[
    "icon",
    "icons",
    "favicon",
    "logo",
    "logos",
    "sprite",
    "sprites",
    "thumb",
    "thumbs",
    "thumbnail",
    "thumbnails",
    "avatar",
    "avatars",
    "emoji",
    "badge",
    "button",
    "spacer",
    "pixel",
    "placeholder",
    "loader",
    "spinner",
    "blank",
    "arrow",
    "bullet",
];

/// Smallest declared side (in pixels) of an image worth downloading.
const MIN_SIDE: u32 = 200;

/// `-150x150` style size suffixes (WordPress thumbnails) with both sides small.
fn small_size_suffix(path: &str) -> bool {
    let stem = path.rsplit('/').next().unwrap_or("");
    let stem = stem.rsplit_once('.').map(|(a, _)| a).unwrap_or(stem);
    let Some((_, dims)) = stem.rsplit_once('-') else {
        return false;
    };
    let Some((w, h)) = dims.split_once('x') else {
        return false;
    };
    match (w.parse::<u32>(), h.parse::<u32>()) {
        (Ok(w), Ok(h)) => w < 400 && h < 400,
        _ => false,
    }
}

/// Small sizes requested through the query (`?w=64`, `?width=120`, `?size=small`).
fn small_query(q: &str) -> bool {
    url::form_urlencoded::parse(q.as_bytes()).any(|(k, v)| {
        let k = k.to_ascii_lowercase();
        let small_num = v.parse::<u32>().is_ok_and(|n| n < MIN_SIDE);
        (matches!(k.as_str(), "w" | "h" | "width" | "height" | "resize") && small_num)
            || (k == "size" && matches!(&*v.to_ascii_lowercase(), "small" | "thumb" | "icon"))
    })
}

/// Returns the priority of a candidate (higher first), or `None` to skip it.
pub fn image_score(c: &ImageCand) -> Option<u32> {
    let ext = ext_of_url(&c.url)?;
    let mut score: u32 = match ext.as_str() {
        "jpg" | "jpeg" | "heic" | "heif" | "tif" | "tiff" => 30,
        "png" => 20,
        "webp" => 10,
        _ => return None,
    };
    let u = url::Url::parse(&c.url).ok()?;
    let path = u.path().to_ascii_lowercase();
    let words: Vec<&str> = path
        .split(|ch: char| !ch.is_ascii_alphanumeric())
        .filter(|w| !w.is_empty())
        .collect();
    if words.iter().any(|w| SKIP_WORDS.contains(w)) || small_size_suffix(&path) {
        return None;
    }
    if u.query().is_some_and(small_query) {
        return None;
    }
    match (c.w, c.h) {
        (Some(w), _) if w < MIN_SIDE => return None,
        (_, Some(h)) if h < MIN_SIDE => return None,
        (Some(w), Some(h)) if w.max(h) >= 1000 => score += 10,
        _ => {}
    }
    // camera file names (IMG_1234, DSC01234, PXL_2026...) usually keep their EXIF
    let file = path.rsplit('/').next().unwrap_or("");
    if ["img_", "dsc", "dscn", "pxl_", "p_", "photo"]
        .iter()
        .any(|p| file.starts_with(p))
    {
        score += 5;
    }
    Some(score)
}

/// Keeps the best `cap` candidates (deduplicated by URL), best first.
pub fn select_images(cands: Vec<ImageCand>, cap: usize) -> Vec<ImageCand> {
    let mut seen = HashSet::new();
    let mut scored: Vec<(u32, usize, ImageCand)> = cands
        .into_iter()
        .enumerate()
        .filter(|(_, c)| seen.insert(dedup_key(&c.url)))
        .filter_map(|(i, c)| image_score(&c).map(|s| (s, i, c)))
        .collect();
    // stable: equal scores keep page order
    scored.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(&b.1)));
    scored.into_iter().take(cap).map(|x| x.2).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn c(url: &str, w: Option<u32>, h: Option<u32>) -> ImageCand {
        ImageCand {
            url: url.into(),
            page: "https://site.example/".into(),
            w,
            h,
        }
    }

    #[test]
    fn decorative_and_tiny_images_are_skipped() {
        for (u, w, h) in [
            ("https://site.example/img/logo.png", None, None),
            ("https://site.example/assets/icons/mail.png", None, None),
            ("https://site.example/uploads/team-150x150.jpg", None, None),
            ("https://site.example/p.jpg?w=64", None, None),
            ("https://site.example/a.jpg", Some(48), Some(48)),
            ("https://site.example/anim.gif", None, None),
            ("https://site.example/vector.svg", None, None),
        ] {
            assert_eq!(image_score(&c(u, w, h)), None, "{u}");
        }
    }

    #[test]
    fn photos_rank_first_and_cap_applies() {
        let v = select_images(
            vec![
                c("https://site.example/banner.webp", None, None),
                c("https://site.example/chart.png", None, None),
                c("https://site.example/uploads/IMG_2041.JPG", None, None),
                c("https://site.example/uploads/IMG_2041.JPG", None, None),
                c("https://site.example/hall.jpg", Some(1600), Some(900)),
                c("https://site.example/favicon.png", None, None),
            ],
            3,
        );
        let urls: Vec<&str> = v.iter().map(|x| x.url.as_str()).collect();
        assert_eq!(
            urls,
            vec![
                "https://site.example/hall.jpg",
                "https://site.example/uploads/IMG_2041.JPG",
                "https://site.example/chart.png",
            ]
        );
    }
}
