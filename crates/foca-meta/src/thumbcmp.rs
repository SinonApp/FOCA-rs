//! Pixel comparison of an EXIF thumbnail with the photo itself.
//!
//! A thumbnail left over from the original frame after cropping or redaction is a leak. A
//! heuristic such as "the photo was edited and has a thumbnail" yields a false high-severity
//! finding on almost every photo saved by Photoshop, so the images are compared directly:
//!
//! * both JPEGs are decoded with 1/8 DCT downscaling (cheap even for 24 MP images);
//! * black letterbox bars in the thumbnail (cameras fit 3:2 into 160×120) are trimmed;
//! * aspect ratios and the mean brightness difference on a 16×16 grid are compared.

/// A decoded image: luma (for trimming bars) and RGB (for comparison; color matters because
/// blue and red can have the same gray level).
struct Gray {
    w: usize,
    h: usize,
    px: Vec<u8>,
    rgb: Vec<[u8; 3]>,
}

fn decode_small(data: &[u8], want: u16) -> Option<Gray> {
    let mut d = jpeg_decoder::Decoder::new(std::io::Cursor::new(data));
    d.read_info().ok()?;
    // A forged SOF with huge dimensions makes the decoder walk millions of empty MCUs even at
    // 1/8 scale (seconds per file); real photos stay well below 100 MP.
    let full = d.info()?;
    if u64::from(full.width) * u64::from(full.height) > 100_000_000 {
        return None;
    }
    let _ = d.scale(want, want);
    let px = d.decode().ok()?;
    let info = d.info()?;
    let (w, h) = (info.width as usize, info.height as usize);
    if w == 0 || h == 0 {
        return None;
    }
    let rgb: Vec<[u8; 3]> = match info.pixel_format {
        jpeg_decoder::PixelFormat::L8 => px.iter().map(|&v| [v, v, v]).collect(),
        jpeg_decoder::PixelFormat::L16 => px.chunks(2).map(|c| [c[0], c[0], c[0]]).collect(),
        jpeg_decoder::PixelFormat::RGB24 => px.chunks(3).map(|c| [c[0], c[1], c[2]]).collect(),
        jpeg_decoder::PixelFormat::CMYK32 => px
            .chunks(4)
            .map(|c| {
                let k = 255 - c[3] as u32;
                let f = |x: u8| ((255 - x as u32) * k / 255) as u8;
                [f(c[0]), f(c[1]), f(c[2])]
            })
            .collect(),
    };
    if rgb.len() < w * h {
        return None;
    }
    let px = rgb
        .iter()
        .map(|c| ((c[0] as u32 * 299 + c[1] as u32 * 587 + c[2] as u32 * 114) / 1000) as u8)
        .collect();
    Some(Gray { w, h, px, rgb })
}

/// Trims nearly black or white uniform bars at the edges (thumbnail letterboxing).
fn trim_bars(g: &Gray) -> Gray {
    let row = |y: usize| -> (f64, u8, u8) {
        let s = &g.px[y * g.w..(y + 1) * g.w];
        let (mn, mx) = s
            .iter()
            .fold((255u8, 0u8), |(a, b), &v| (a.min(v), b.max(v)));
        (
            s.iter().map(|&v| v as f64).sum::<f64>() / g.w as f64,
            mn,
            mx,
        )
    };
    let col = |x: usize| -> (f64, u8, u8) {
        let mut sum = 0.0;
        let (mut mn, mut mx) = (255u8, 0u8);
        for y in 0..g.h {
            let v = g.px[y * g.w + x];
            sum += v as f64;
            mn = mn.min(v);
            mx = mx.max(v);
        }
        (sum / g.h as f64, mn, mx)
    };
    let bar = |(m, mn, mx): (f64, u8, u8)| (mx - mn) < 24 && !(24.0..=231.0).contains(&m);
    let (mut y0, mut y1, mut x0, mut x1) = (0, g.h, 0, g.w);
    while y0 + 4 < y1 && bar(row(y0)) {
        y0 += 1;
    }
    while y1 > y0 + 4 && bar(row(y1 - 1)) {
        y1 -= 1;
    }
    while x0 + 4 < x1 && bar(col(x0)) {
        x0 += 1;
    }
    while x1 > x0 + 4 && bar(col(x1 - 1)) {
        x1 -= 1;
    }
    let (w, h) = (x1 - x0, y1 - y0);
    let mut px = Vec::with_capacity(w * h);
    let mut rgb = Vec::with_capacity(w * h);
    for y in y0..y1 {
        px.extend_from_slice(&g.px[y * g.w + x0..y * g.w + x1]);
        rgb.extend_from_slice(&g.rgb[y * g.w + x0..y * g.w + x1]);
    }
    Gray { w, h, px, rgb }
}

/// Averages RGB over an `n×n` grid (three consecutive channels per cell).
fn grid(g: &Gray, n: usize) -> Vec<f64> {
    let mut out = vec![0.0; n * n * 3];
    for (j, cell) in out.chunks_mut(3).enumerate() {
        let (cx, cy) = (j % n, j / n);
        let (xa, xb) = (cx * g.w / n, ((cx + 1) * g.w / n).max(cx * g.w / n + 1));
        let (ya, yb) = (cy * g.h / n, ((cy + 1) * g.h / n).max(cy * g.h / n + 1));
        let mut s = [0.0f64; 3];
        let mut k = 0.0;
        for y in ya..yb.min(g.h) {
            for x in xa..xb.min(g.w) {
                for (si, ci) in s.iter_mut().zip(g.rgb[y * g.w + x]) {
                    *si += ci as f64;
                }
                k += 1.0;
            }
        }
        for (ce, si) in cell.iter_mut().zip(s) {
            *ce = if k > 0.0 { si / k } else { 0.0 };
        }
    }
    out
}

/// Mean brightness difference (0 to 255) on the 16×16 grid above which the thumbnail is considered a different frame.
pub const THUMB_DIFF_THRESHOLD: f64 = 22.0;

/// Returns the mean difference (0 to 255) and the aspect ratio difference, or `None` if decoding failed.
pub fn thumbnail_distance(photo: &[u8], thumb: &[u8]) -> Option<(f64, f64)> {
    let t = trim_bars(&decode_small(thumb, 256)?);
    let p = decode_small(photo, 256)?;
    let ar = |g: &Gray| g.w as f64 / g.h as f64;
    let ar_diff = (ar(&p) - ar(&t)).abs() / ar(&p);
    let (a, b) = (grid(&p, 16), grid(&t, 16));
    let mean = a.iter().zip(&b).map(|(x, y)| (x - y).abs()).sum::<f64>() / a.len() as f64;
    Some((mean, ar_diff))
}

/// Returns whether the thumbnail differs noticeably from the photo (cropping changes the aspect
/// ratio; redaction or a different frame produces a large mean difference). Returns `None` if
/// the images could not be compared, in which case no finding is raised.
pub fn thumbnail_differs(photo: &[u8], thumb: &[u8]) -> Option<bool> {
    let (mean, ar_diff) = thumbnail_distance(photo, thumb)?;
    Some(ar_diff > 0.12 || mean > THUMB_DIFF_THRESHOLD)
}
