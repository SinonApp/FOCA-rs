//! Report logo images: format, size and dimension checks for the logo saved in Settings →
//! Report (`report_logo_set`), and the pixel size the DOCX renderer needs to place it.
//!
//! Only PNG, JPEG and WebP are accepted. SVG is refused: it can carry scripts and external
//! references, and sanitising it safely is out of scope. Dimensions are read from the file
//! header without decoding the image.

use crate::opts::Logo;

/// Largest accepted logo file (the picked file and the stored image).
pub const LOGO_MAX_BYTES: usize = 2 * 1024 * 1024;
/// Longest accepted side in pixels; the UI downscales larger pictures before saving.
pub const LOGO_MAX_SIDE: u32 = 512;

/// A logo image that passed the checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogoImage {
    pub mime: &'static str,
    pub width: u32,
    pub height: u32,
}

/// Why a logo image was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LogoError {
    /// Not PNG, JPEG or WebP (SVG, GIF, anything else).
    Format,
    /// The file is larger than [`LOGO_MAX_BYTES`].
    TooLarge,
    /// The longest side is larger than [`LOGO_MAX_SIDE`].
    TooBig { width: u32, height: u32 },
    /// The header is cut off or holds a zero size.
    Corrupt,
}

impl LogoError {
    /// Stable error code for the command layer.
    pub fn code(&self) -> &'static str {
        match self {
            Self::Format => "logo_format",
            Self::TooLarge => "logo_too_large",
            Self::TooBig { .. } => "logo_too_big",
            Self::Corrupt => "logo_corrupt",
        }
    }
}

/// Checks the bytes of a logo file: signature, file size and dimensions.
pub fn inspect(bytes: &[u8]) -> Result<LogoImage, LogoError> {
    if bytes.len() > LOGO_MAX_BYTES {
        return Err(LogoError::TooLarge);
    }
    let (mime, dims) = if bytes.starts_with(b"\x89PNG\r\n\x1a\n") {
        ("image/png", png_size(bytes))
    } else if bytes.starts_with(&[0xff, 0xd8, 0xff]) {
        ("image/jpeg", jpeg_size(bytes))
    } else if bytes.len() > 12 && &bytes[..4] == b"RIFF" && &bytes[8..12] == b"WEBP" {
        ("image/webp", webp_size(bytes))
    } else {
        return Err(LogoError::Format);
    };
    let (width, height) = dims
        .filter(|(w, h)| *w > 0 && *h > 0)
        .ok_or(LogoError::Corrupt)?;
    if width.max(height) > LOGO_MAX_SIDE {
        return Err(LogoError::TooBig { width, height });
    }
    Ok(LogoImage {
        mime,
        width,
        height,
    })
}

/// Decoded bytes and checked size of an image logo, `None` for initials, no logo or an image
/// that fails the checks.
pub fn image_of(logo: &Logo) -> Option<(Vec<u8>, LogoImage)> {
    let Logo::Image { b64, .. } = logo else {
        return None;
    };
    let bytes = foca_core::b64::decode(b64)?;
    let info = inspect(&bytes).ok()?;
    Some((bytes, info))
}

fn be16(b: &[u8], at: usize) -> Option<u32> {
    let s = b.get(at..at + 2)?;
    Some(u32::from(u16::from_be_bytes([s[0], s[1]])))
}

fn be32(b: &[u8], at: usize) -> Option<u32> {
    let s = b.get(at..at + 4)?;
    Some(u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
}

fn le16(b: &[u8], at: usize) -> Option<u32> {
    let s = b.get(at..at + 2)?;
    Some(u32::from(u16::from_le_bytes([s[0], s[1]])))
}

fn le24(b: &[u8], at: usize) -> Option<u32> {
    let s = b.get(at..at + 3)?;
    Some(u32::from(s[0]) | u32::from(s[1]) << 8 | u32::from(s[2]) << 16)
}

/// PNG: the first chunk is IHDR with width and height as big-endian u32.
fn png_size(b: &[u8]) -> Option<(u32, u32)> {
    if b.get(12..16)? != b"IHDR" {
        return None;
    }
    Some((be32(b, 16)?, be32(b, 20)?))
}

/// JPEG: walks the marker segments up to the first SOFn frame header.
fn jpeg_size(b: &[u8]) -> Option<(u32, u32)> {
    let mut i = 2;
    while i + 4 <= b.len() {
        if b[i] != 0xff {
            return None;
        }
        let m = b[i + 1];
        // fill bytes and standalone markers carry no length
        if m == 0xff {
            i += 1;
            continue;
        }
        if m == 0x01 || (0xd0..=0xd7).contains(&m) {
            i += 2;
            continue;
        }
        let len = be16(b, i + 2)? as usize;
        if len < 2 {
            return None;
        }
        let sof = (0xc0..=0xcf).contains(&m) && !matches!(m, 0xc4 | 0xc8 | 0xcc);
        if sof {
            return Some((be16(b, i + 7)?, be16(b, i + 5)?));
        }
        i += 2 + len;
    }
    None
}

/// WebP: lossy (`VP8 `), lossless (`VP8L`) or extended (`VP8X`) first chunk.
fn webp_size(b: &[u8]) -> Option<(u32, u32)> {
    match b.get(12..16)? {
        b"VP8 " => {
            // frame tag (3 bytes) and start code 9d 01 2a, then 14-bit sizes
            if b.get(23..26)? != [0x9d, 0x01, 0x2a] {
                return None;
            }
            Some((le16(b, 26)? & 0x3fff, le16(b, 28)? & 0x3fff))
        }
        b"VP8L" => {
            if *b.get(20)? != 0x2f {
                return None;
            }
            let v = u32::from_le_bytes(b.get(21..25)?.try_into().ok()?);
            Some(((v & 0x3fff) + 1, ((v >> 14) & 0x3fff) + 1))
        }
        b"VP8X" => Some((le24(b, 24)? + 1, le24(b, 27)? + 1)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn png(w: u32, h: u32) -> Vec<u8> {
        let mut v = b"\x89PNG\r\n\x1a\n\0\0\0\x0dIHDR".to_vec();
        v.extend_from_slice(&w.to_be_bytes());
        v.extend_from_slice(&h.to_be_bytes());
        v.extend_from_slice(&[8, 6, 0, 0, 0]);
        v
    }

    fn jpeg(w: u16, h: u16) -> Vec<u8> {
        let mut v = vec![0xff, 0xd8, 0xff, 0xe0, 0x00, 0x04, 0x00, 0x00];
        v.extend_from_slice(&[0xff, 0xc0, 0x00, 0x11, 0x08]);
        v.extend_from_slice(&h.to_be_bytes());
        v.extend_from_slice(&w.to_be_bytes());
        v.extend_from_slice(&[3, 1, 0x22, 0, 2, 0x11, 1, 3, 0x11, 1]);
        v
    }

    fn webp(chunk: &[u8; 4], body: &[u8]) -> Vec<u8> {
        let mut v = b"RIFF\0\0\0\0WEBP".to_vec();
        v.extend_from_slice(chunk);
        v.extend_from_slice(&(body.len() as u32).to_le_bytes());
        v.extend_from_slice(body);
        v
    }

    #[test]
    fn reads_png_jpeg_and_webp_sizes() {
        assert_eq!(
            inspect(&png(512, 128)),
            Ok(LogoImage {
                mime: "image/png",
                width: 512,
                height: 128
            })
        );
        let j = inspect(&jpeg(300, 200)).unwrap();
        assert_eq!((j.mime, j.width, j.height), ("image/jpeg", 300, 200));
        // lossy: frame tag, start code, 14-bit width/height
        let lossy = webp(
            b"VP8 ",
            &[0, 0, 0, 0x9d, 0x01, 0x2a, 0x40, 0x01, 0xf0, 0x00, 0, 0],
        );
        let w = inspect(&lossy).unwrap();
        assert_eq!((w.mime, w.width, w.height), ("image/webp", 320, 240));
        // lossless: signature 0x2f, then (w-1) | (h-1) << 14
        let bits: u32 = (100 - 1) | ((50 - 1) << 14);
        let mut body = vec![0x2f];
        body.extend_from_slice(&bits.to_le_bytes());
        let w = inspect(&webp(b"VP8L", &body)).unwrap();
        assert_eq!((w.width, w.height), (100, 50));
        let ext = webp(b"VP8X", &[0, 0, 0, 0, 0xff, 0x01, 0, 0x7f, 0, 0]);
        let w = inspect(&ext).unwrap();
        assert_eq!((w.width, w.height), (512, 128));
    }

    #[test]
    fn refuses_svg_gif_oversized_and_cut_files() {
        assert_eq!(
            inspect(b"<svg xmlns=\"http://www.w3.org/2000/svg\" onload=\"alert(1)\"/>"),
            Err(LogoError::Format)
        );
        assert_eq!(inspect(b"GIF89a\x10\0\x10\0"), Err(LogoError::Format));
        assert_eq!(
            inspect(&png(1024, 300)),
            Err(LogoError::TooBig {
                width: 1024,
                height: 300
            })
        );
        assert_eq!(inspect(&png(0, 10)), Err(LogoError::Corrupt));
        assert_eq!(inspect(&png(64, 64)[..18]), Err(LogoError::Corrupt));
        assert_eq!(inspect(&[0xff, 0xd8, 0xff, 0xd9]), Err(LogoError::Corrupt));
        let mut big = png(64, 64);
        big.resize(LOGO_MAX_BYTES + 1, 0);
        assert_eq!(inspect(&big), Err(LogoError::TooLarge));
        assert_eq!(LogoError::TooLarge.code(), "logo_too_large");
    }

    #[test]
    fn image_of_skips_initials_and_bad_images() {
        assert!(image_of(&Logo::Initials).is_none());
        assert!(image_of(&Logo::None).is_none());
        let b64 = foca_core::b64::encode(&png(64, 32));
        let (bytes, info) = image_of(&Logo::Image {
            mime: "image/png".into(),
            b64,
        })
        .unwrap();
        assert_eq!((info.width, info.height, bytes.len()), (64, 32, 29));
        let b64 = foca_core::b64::encode(&png(4096, 32));
        assert!(image_of(&Logo::Image {
            mime: "image/png".into(),
            b64,
        })
        .is_none());
    }
}
