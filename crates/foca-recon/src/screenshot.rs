//! Visual web service snapshots via isolated Android WebView and 64-bit perceptual hashing.
//!
//! Gated by [`foca_net::Access`]: never runs in [`Access::Passive`] ([ADR-0009]), never
//! touches out-of-scope hosts, and is disabled by default (`enabled = false`).

use foca_core::Scope;
use foca_net::Access;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Request passed to a [`WebScreenshotter`] implementation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScreenshotRequest {
    pub url: String,
    pub width: u32,
    pub height: u32,
    pub timeout_ms: u32,
}

impl ScreenshotRequest {
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            width: 360,
            height: 640,
            timeout_ms: 8_000,
        }
    }
}

/// Raw capture returned by the platform WebView renderer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScreenshotRaw {
    pub width: u32,
    pub height: u32,
    /// Downsampled 9×8 (72-byte) grayscale luminance grid (row-major) for 64-bit dHash.
    pub luma_9x8: Vec<u8>,
    /// Base64-encoded PNG/WEBP thumbnail (≤ 64 KiB).
    pub image_b64: String,
    pub title: Option<String>,
}

/// Platform provider capable of rendering an in-scope URL in an isolated offscreen WebView.
pub trait WebScreenshotter: Send + Sync {
    fn capture(&self, req: &ScreenshotRequest) -> Result<ScreenshotRaw, String>;
}

/// Processed screenshot record with perceptual hash and visual cluster assignment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostScreenshot {
    pub host: String,
    pub url: String,
    pub width: u32,
    pub height: u32,
    /// 16-char lowercase hex of the 64-bit perceptual hash (`dHash`).
    pub phash: String,
    #[serde(skip)]
    pub phash_u64: u64,
    /// Visual similarity cluster identifier (`cluster-1`, `cluster-2`, …).
    pub cluster_id: String,
    pub title: Option<String>,
    pub sha256: String,
    pub image_b64: String,
}

/// Computes a 64-bit horizontal gradient difference hash (`dHash`) from a 9×8 (72-byte)
/// row-major luminance grid. If `luma_9x8` has fewer than 72 bytes, it is deterministically
/// resampled from the provided bytes.
pub fn compute_dhash_64(luma_9x8: &[u8]) -> u64 {
    let mut grid = [0u8; 72];
    if luma_9x8.len() >= 72 {
        grid.copy_from_slice(&luma_9x8[..72]);
    } else if !luma_9x8.is_empty() {
        for (i, slot) in grid.iter_mut().enumerate() {
            *slot = luma_9x8[i * luma_9x8.len() / 72];
        }
    }
    let mut hash = 0u64;
    let mut bit = 0u32;
    for row in 0..8 {
        let base = row * 9;
        for col in 0..8 {
            if grid[base + col] > grid[base + col + 1] {
                hash |= 1u64 << bit;
            }
            bit += 1;
        }
    }
    hash
}

/// Downsamples an arbitrary grayscale image (`width × height`) to a 9×8 luminance grid.
pub fn downsample_gray_to_9x8(pixels: &[u8], width: usize, height: usize) -> [u8; 72] {
    let mut out = [0u8; 72];
    if width == 0 || height == 0 || pixels.len() < width * height {
        return out;
    }
    for ty in 0..8 {
        let y0 = ty * height / 8;
        let y1 = ((ty + 1) * height / 8).max(y0 + 1).min(height);
        for tx in 0..9 {
            let x0 = tx * width / 9;
            let x1 = ((tx + 1) * width / 9).max(x0 + 1).min(width);
            let mut sum = 0u64;
            let mut cnt = 0u64;
            for y in y0..y1 {
                for x in x0..x1 {
                    sum += pixels[y * width + x] as u64;
                    cnt += 1;
                }
            }
            out[ty * 9 + tx] = sum.checked_div(cnt).unwrap_or(0) as u8;
        }
    }
    out
}

/// Hamming distance between two 64-bit perceptual hashes (`0..=64`).
pub fn hamming_distance(a: u64, b: u64) -> u32 {
    (a ^ b).count_ones()
}

/// Formats a 64-bit perceptual hash as a 16-character lowercase hex string.
pub fn format_phash(h: u64) -> String {
    format!("{h:016x}")
}

/// Parses a 16-character hex perceptual hash into `u64`.
pub fn parse_phash(s: &str) -> Option<u64> {
    u64::from_str_radix(s.trim(), 16).ok()
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    let d = h.finalize();
    let mut out = String::with_capacity(64);
    for b in d {
        use std::fmt::Write;
        let _ = write!(&mut out, "{b:02x}");
    }
    out
}

/// Captures a screenshot of `url` through `provider`, enforcing:
/// 1. `enabled == true`
/// 2. `access != Access::Passive` (ADR-0009)
/// 3. Target host of `url` is allowed by `scope`.
pub fn capture_scoped(
    provider: Option<&dyn WebScreenshotter>,
    enabled: bool,
    access: Access,
    scope: &Scope,
    url: &str,
) -> Result<Option<HostScreenshot>, String> {
    if !enabled {
        return Ok(None);
    }
    if access == Access::Passive {
        return Err("Скриншоты веб-сервисов запрещены в пассивном режиме (ADR-0009)".into());
    }
    let Some(p) = provider else {
        return Ok(None);
    };
    let parsed = url::Url::parse(url).map_err(|e| format!("Некорректный URL: {e}"))?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return Err(format!(
            "Неподдерживаемая схема URL для скриншота: {}",
            parsed.scheme()
        ));
    }
    let host = parsed
        .host_str()
        .ok_or_else(|| "В URL отсутствует имя хоста".to_string())?
        .to_ascii_lowercase();
    if !scope.allows_host(&host) {
        return Err(format!("Хост {host} вне скоупа проекта"));
    }
    let req = ScreenshotRequest::new(url);
    let raw = p.capture(&req)?;
    let phash_u64 = compute_dhash_64(&raw.luma_9x8);
    let sha256 = sha256_hex(raw.image_b64.as_bytes());
    Ok(Some(HostScreenshot {
        host,
        url: url.into(),
        width: raw.width,
        height: raw.height,
        phash: format_phash(phash_u64),
        phash_u64,
        cluster_id: "cluster-1".into(),
        title: raw.title,
        sha256,
        image_b64: raw.image_b64,
    }))
}

/// Assigns visual similarity clusters (`cluster-1`, `cluster-2`, …) to `items` using single-linkage
/// clustering over [`hamming_distance`] with threshold `max_hamming` (typical `8`).
pub fn cluster_screenshots(items: &mut [HostScreenshot], max_hamming: u32) {
    let mut leaders: Vec<u64> = Vec::new();
    for item in items.iter_mut() {
        if item.phash_u64 == 0 && item.phash != "0000000000000000" {
            if let Some(v) = parse_phash(&item.phash) {
                item.phash_u64 = v;
            }
        }
        let mut found = None;
        for (idx, &leader_hash) in leaders.iter().enumerate() {
            if hamming_distance(item.phash_u64, leader_hash) <= max_hamming {
                found = Some(idx + 1);
                break;
            }
        }
        let cid = match found {
            Some(c) => c,
            None => {
                leaders.push(item.phash_u64);
                leaders.len()
            }
        };
        item.cluster_id = format!("cluster-{cid}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct MockShot {
        calls: AtomicUsize,
        luma: Vec<u8>,
    }

    impl WebScreenshotter for MockShot {
        fn capture(&self, _req: &ScreenshotRequest) -> Result<ScreenshotRaw, String> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(ScreenshotRaw {
                width: 360,
                height: 640,
                luma_9x8: self.luma.clone(),
                image_b64: "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=".into(),
                title: Some("Login Portal".into()),
            })
        }
    }

    #[test]
    fn phash_clusters_identical_pages_and_separates_distinct_layouts() {
        // Gradient A: left-to-right brightening on every row
        let mut luma_a = vec![0u8; 72];
        for r in 0..8 {
            for c in 0..9 {
                luma_a[r * 9 + c] = (c as u8) * 25;
            }
        }
        // Gradient A' with slight noise (identical gradient ordering)
        let mut luma_a2 = luma_a.clone();
        luma_a2[0] = 2;

        // Gradient B: right-to-left brightening (opposite gradient on every bit)
        let mut luma_b = vec![0u8; 72];
        for r in 0..8 {
            for c in 0..9 {
                luma_b[r * 9 + c] = ((8 - c) as u8) * 25;
            }
        }

        let ha1 = compute_dhash_64(&luma_a);
        let ha2 = compute_dhash_64(&luma_a2);
        let hb = compute_dhash_64(&luma_b);

        assert_eq!(hamming_distance(ha1, ha2), 0);
        assert_eq!(hamming_distance(ha1, hb), 64);

        let mut shots = vec![
            HostScreenshot {
                host: "admin.example.com".into(),
                url: "https://admin.example.com/".into(),
                width: 360,
                height: 640,
                phash: format_phash(ha1),
                phash_u64: ha1,
                cluster_id: String::new(),
                title: None,
                sha256: String::new(),
                image_b64: String::new(),
            },
            HostScreenshot {
                host: "sso.example.com".into(),
                url: "https://sso.example.com/".into(),
                width: 360,
                height: 640,
                phash: format_phash(ha2),
                phash_u64: ha2,
                cluster_id: String::new(),
                title: None,
                sha256: String::new(),
                image_b64: String::new(),
            },
            HostScreenshot {
                host: "grafana.example.com".into(),
                url: "https://grafana.example.com/".into(),
                width: 360,
                height: 640,
                phash: format_phash(hb),
                phash_u64: hb,
                cluster_id: String::new(),
                title: None,
                sha256: String::new(),
                image_b64: String::new(),
            },
        ];
        cluster_screenshots(&mut shots, 8);
        assert_eq!(shots[0].cluster_id, "cluster-1");
        assert_eq!(shots[1].cluster_id, "cluster-1");
        assert_eq!(shots[2].cluster_id, "cluster-2");
    }

    #[test]
    fn passive_mode_and_out_of_scope_never_invoke_screenshotter() {
        let (scope, _) = Scope::from_lines("example.com", "excluded.example.com");
        let mock = MockShot {
            calls: AtomicUsize::new(0),
            luma: vec![100; 72],
        };

        // 1. Disabled by default -> Ok(None), 0 calls.
        let r0 = capture_scoped(
            Some(&mock),
            false,
            Access::TouchesTarget,
            &scope,
            "https://app.example.com/",
        )
        .unwrap();
        assert!(r0.is_none());
        assert_eq!(mock.calls.load(Ordering::SeqCst), 0);

        // 2. Access::Passive -> Err, 0 calls (ADR-0009).
        let r1 = capture_scoped(
            Some(&mock),
            true,
            Access::Passive,
            &scope,
            "https://app.example.com/",
        );
        assert!(r1.is_err());
        assert_eq!(mock.calls.load(Ordering::SeqCst), 0);

        // 3. Excluded / out of scope -> Err, 0 calls.
        let r2 = capture_scoped(
            Some(&mock),
            true,
            Access::TouchesTarget,
            &scope,
            "https://excluded.example.com/",
        );
        assert!(r2.is_err());
        assert_eq!(mock.calls.load(Ordering::SeqCst), 0);

        // 4. In scope + TouchesTarget + enabled -> captures 1 screenshot.
        let r3 = capture_scoped(
            Some(&mock),
            true,
            Access::TouchesTarget,
            &scope,
            "https://app.example.com/",
        )
        .unwrap()
        .unwrap();
        assert_eq!(mock.calls.load(Ordering::SeqCst), 1);
        assert_eq!(r3.host, "app.example.com");
        assert_eq!(r3.phash.len(), 16);

        // 5. Non-http(s) scheme rejected even with matching host.
        let r4 = capture_scoped(
            Some(&mock),
            true,
            Access::TouchesTarget,
            &scope,
            "ftp://app.example.com/file",
        );
        assert!(r4.is_err());
        assert_eq!(mock.calls.load(Ordering::SeqCst), 1);
    }
}
