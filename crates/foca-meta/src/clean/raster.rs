//! Raster image cleaning, also used for images embedded in office packages.
//!
//! JPEG: APP1 (EXIF/XMP), APP13 (IPTC/Photoshop), other metadata-bearing APPn segments and COM
//! are removed; only JFIF (APP0), ICC (APP2) and Adobe (APP14) remain; data after EOI is
//! dropped; the image data is copied without re-encoding.
//! PNG: tEXt/zTXt/iTXt (including XMP and generator prompts), eXIf, tIME and caBX (C2PA)
//! chunks are removed.

use crate::MetaError;

pub(crate) fn clean_jpeg(b: &[u8]) -> Result<Vec<u8>, MetaError> {
    let segs = crate::formats::media::image::jpeg_segments(b);
    if segs.is_empty() {
        return Err(MetaError::malformed("jpeg", "нет сегментов"));
    }
    let mut out = Vec::with_capacity(b.len());
    out.extend_from_slice(&[0xFF, 0xD8]);
    let mut tail_from = None;
    for (m, seg_start, s, e) in &segs {
        if *m == 0xDA {
            tail_from = Some(*seg_start);
            break;
        }
        let Some(seg) = b.get(*seg_start..*e) else {
            return Err(MetaError::malformed("jpeg", "обрезанный сегмент"));
        };
        let payload = b.get(*s..*e).unwrap_or(&[]);
        let keep = match m {
            // APP0: JFIF only (JFXX carries a thumbnail)
            0xE0 => payload.starts_with(b"JFIF\0"),
            // APP2: ICC profile only; APP14: Adobe (needed for color conversion)
            0xE2 => payload.starts_with(b"ICC_PROFILE\0"),
            0xEE => payload.starts_with(b"Adobe"),
            0xE1 | 0xE3..=0xED | 0xEF | 0xFE => false,
            _ => true,
        };
        if keep {
            out.extend_from_slice(seg);
        }
    }
    let Some(p) = tail_from else {
        return Err(MetaError::malformed("jpeg", "нет данных изображения (SOS)"));
    };
    // scan data up to EOI; anything after EOI (MPF images, trailers) is dropped
    let end = crate::util::find(b, &[0xFF, 0xD9], p)
        .map(|i| i + 2)
        .unwrap_or(b.len());
    out.extend_from_slice(&b[p..end]);
    if !out.ends_with(&[0xFF, 0xD9]) {
        out.extend_from_slice(&[0xFF, 0xD9]);
    }
    Ok(out)
}

/// Cleans a PNG: text chunks (tEXt/zTXt/iTXt, including XMP), eXIf and tIME are removed; all
/// other chunks are copied verbatim, so their CRCs stay valid.
pub(crate) fn clean_png(b: &[u8]) -> Result<Vec<u8>, MetaError> {
    const SIG: &[u8] = b"\x89PNG\r\n\x1a\n";
    if !b.starts_with(SIG) {
        return Err(MetaError::malformed("png", "нет сигнатуры"));
    }
    let mut out = SIG.to_vec();
    let mut p = SIG.len();
    while p + 12 <= b.len() {
        let len = u32::from_be_bytes([b[p], b[p + 1], b[p + 2], b[p + 3]]) as usize;
        let Some(end) = p
            .checked_add(12)
            .and_then(|x| x.checked_add(len))
            .filter(|e| *e <= b.len())
        else {
            return Err(MetaError::malformed("png", "обрезанный чанк"));
        };
        let ty = &b[p + 4..p + 8];
        if !matches!(
            ty,
            b"tEXt" | b"zTXt" | b"iTXt" | b"eXIf" | b"tIME" | b"caBX"
        ) {
            out.extend_from_slice(&b[p..end]);
        }
        p = end;
        if ty == b"IEND" {
            return Ok(out);
        }
    }
    Err(MetaError::malformed("png", "нет IEND"))
}
