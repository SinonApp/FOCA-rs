//! GIF, WebP, JPEG XL and JPEG 2000 images.
//!
//! * GIF: comment extensions, application extensions (`XMP DataXMP`, `ICCRGBG1` ICC profile,
//!   `NETSCAPE2.0` loop count), frame count and the logical screen size.
//! * WebP (RIFF): `VP8X` feature flags and canvas size, `EXIF`, `XMP `, `ICCP`, animation frames.
//! * JPEG XL container (ISO/IEC 18181-2): `Exif`, `xml ` and `jumb` (C2PA) boxes; `brob`
//!   (Brotli) boxes are only reported.
//! * JPEG 2000 (JP2/JPX and raw J2K codestreams, also inside PDFs): `xml ` (XMP), XMP and EXIF
//!   `uuid` boxes and codestream `COM` comments (encoder names such as Kakadu).
//!
//! Layouts follow the GIF89a specification, Google's WebP container spec and ExifTool `GIF.pm`,
//! `RIFF.pm`, `Jpeg2000.pm` (GPL-1+/Artistic). Every loop is bounded by the input length and a
//! block counter.

use foca_core::{DocFormat, Metadata};

use super::{image, image_extra};
use crate::util::{clean_str, decode_text, rd_u16le, rd_u32le, truncate};
use crate::{xmp, Ctx, MetaError};

/// Maximum number of GIF blocks or container boxes visited.
const MAX_BLOCKS: usize = 200_000;
/// Maximum size of one metadata payload copied out of an image.
const MAX_PAYLOAD: usize = 8 << 20;

pub(crate) const JP2_MAGIC: [u8; 12] =
    [0, 0, 0, 12, b'j', b'P', b' ', b' ', 0x0D, 0x0A, 0x87, 0x0A];
pub(crate) const JXL_MAGIC: [u8; 12] =
    [0, 0, 0, 12, b'J', b'X', b'L', b' ', 0x0D, 0x0A, 0x87, 0x0A];
const XMP_UUID: [u8; 16] = [
    0xBE, 0x7A, 0xCF, 0xCB, 0x97, 0xA9, 0x42, 0xE8, 0x9C, 0x71, 0x99, 0x94, 0x91, 0xE3, 0xAF, 0xAC,
];
/// `JpgTiffExif->JP2` UUID of an EXIF block in JPEG 2000.
const EXIF_UUID: &[u8; 16] = b"JpgTiffExif->JP2";

/// Format of a GIF, WebP, JPEG XL or JPEG 2000 file by its magic bytes.
pub(crate) fn kind(b: &[u8]) -> Option<DocFormat> {
    if b.starts_with(b"GIF87a") || b.starts_with(b"GIF89a") {
        return Some(DocFormat::Gif);
    }
    if b.starts_with(b"RIFF") && b.get(8..12) == Some(b"WEBP") {
        return Some(DocFormat::Webp);
    }
    if b.starts_with(&JXL_MAGIC) || b.starts_with(&[0xFF, 0x0A]) {
        return Some(DocFormat::Jxl);
    }
    if b.starts_with(&JP2_MAGIC) || b.starts_with(&[0xFF, 0x4F, 0xFF, 0x51]) {
        return Some(DocFormat::Jp2);
    }
    None
}

pub fn extract(b: &[u8], format: DocFormat, ctx: &Ctx) -> Result<Metadata, MetaError> {
    let mut meta = Metadata::new(format);
    match format {
        DocFormat::Gif => gif(&mut meta, b, ctx),
        DocFormat::Webp => webp(&mut meta, b, ctx),
        DocFormat::Jxl | DocFormat::Jp2 => {
            if b.starts_with(&[0xFF, 0x4F]) {
                codestream(&mut meta, b);
            } else if b.starts_with(&[0xFF, 0x0A]) {
                meta.fields
                    .insert("jxl:container".into(), "no (bare codestream)".into());
            } else {
                boxes(&mut meta, b, ctx, 0);
            }
        }
        _ => {}
    }
    image_extra::xmp_devices(&mut meta);
    image_extra::xmp_ai(&mut meta);
    Ok(meta)
}

/// Joins GIF data sub-blocks starting at `p`; returns the data and the offset after the
/// terminator. `keep` limits how much is copied.
fn sub_blocks(b: &[u8], mut p: usize, keep: usize) -> (Vec<u8>, usize) {
    let mut out = Vec::new();
    let mut n = 0;
    while let Some(&len) = b.get(p) {
        p += 1;
        if len == 0 || n > MAX_BLOCKS {
            break;
        }
        n += 1;
        let end = (p + usize::from(len)).min(b.len());
        if out.len() < keep {
            out.extend_from_slice(&b[p..end]);
        }
        p = end;
    }
    (out, p)
}

fn gif(meta: &mut Metadata, b: &[u8], ctx: &Ctx) {
    meta.fields
        .insert("gif:version".into(), decode_text(&b[3..6.min(b.len())]));
    if let (Some(w), Some(h)) = (rd_u16le(b, 6), rd_u16le(b, 8)) {
        meta.stats.insert("width".into(), u64::from(w));
        meta.stats.insert("height".into(), u64::from(h));
    }
    let flags = b.get(10).copied().unwrap_or(0);
    let mut p = 13;
    if flags & 0x80 != 0 {
        p += 3 << ((flags & 7) + 1);
    }
    let mut frames = 0u64;
    let mut comments: Vec<String> = Vec::new();
    let mut blocks = 0;
    while let Some(&intro) = b.get(p) {
        blocks += 1;
        if blocks > MAX_BLOCKS {
            break;
        }
        match intro {
            0x21 => {
                let label = b.get(p + 1).copied().unwrap_or(0);
                match label {
                    0xFE => {
                        let (d, next) = sub_blocks(b, p + 2, 64 * 1024);
                        if let Some(c) = clean_str(&decode_text(&d)) {
                            if comments.len() < 20 {
                                comments.push(truncate(&c, 2048));
                            }
                        }
                        p = next;
                    }
                    0xFF => {
                        let id = b.get(p + 3..p + 14).unwrap_or(&[]);
                        let start = p + 2;
                        if id == b"XMP DataXMP" {
                            // XMP is stored raw (its bytes double as sub-block lengths) and
                            // ends with a 258-byte "magic trailer"
                            let data = &b[(p + 14).min(b.len())..];
                            let end = crate::util::find(data, b"<?xpacket end", 0)
                                .and_then(|e| crate::util::find(data, b"?>", e).map(|x| x + 2))
                                .or_else(|| {
                                    crate::util::find(data, b"</x:xmpmeta>", 0).map(|x| x + 12)
                                })
                                .unwrap_or(data.len().min(MAX_PAYLOAD));
                            let map = xmp::parse(&data[..end.min(MAX_PAYLOAD)], ctx);
                            xmp::apply(meta, &map, "xmp");
                            let (_, next) = sub_blocks(b, start + 12 + end, 0);
                            p = next.max(start + 12 + end);
                        } else {
                            let (d, next) = sub_blocks(b, start + 12, MAX_PAYLOAD);
                            match id {
                                b"ICCRGBG1012" => image_extra::icc(meta, &d),
                                b"NETSCAPE2.0" | b"ANIMEXTS1.0" => {
                                    if let Some(l) = rd_u16le(&d, 1) {
                                        meta.fields.insert("gif:loop_count".into(), l.to_string());
                                    }
                                }
                                _ => {
                                    let s = String::from_utf8_lossy(id).into_owned();
                                    if let Some(s) = clean_str(&s) {
                                        meta.fields.entry("gif:application".into()).or_insert(s);
                                    }
                                }
                            }
                            p = next;
                        }
                    }
                    _ => {
                        // graphic control, plain text and unknown extensions
                        let (_, next) = sub_blocks(b, p + 2, 0);
                        p = next;
                    }
                }
            }
            0x2C => {
                frames += 1;
                let lflags = b.get(p + 9).copied().unwrap_or(0);
                let mut q = p + 10;
                if lflags & 0x80 != 0 {
                    q += 3 << ((lflags & 7) + 1);
                }
                // LZW minimum code size, then the image data sub-blocks
                let (_, next) = sub_blocks(b, q + 1, 0);
                p = next;
            }
            _ => break,
        }
    }
    meta.stats.insert("frames".into(), frames);
    if !comments.is_empty() {
        let c = comments.join("\n");
        meta.description.get_or_insert(truncate(&c, 2048));
        meta.fields.insert("gif:comment".into(), truncate(&c, 4096));
    }
}

fn webp(meta: &mut Metadata, b: &[u8], ctx: &Ctx) {
    let mut p = 12;
    let mut frames = 0u64;
    let mut n = 0;
    while p + 8 <= b.len() && n < MAX_BLOCKS {
        n += 1;
        let id = &b[p..p + 4];
        let size = rd_u32le(b, p + 4).unwrap_or(0) as usize;
        let start = p + 8;
        let end = start.saturating_add(size).min(b.len());
        let d = &b[start..end];
        match id {
            b"VP8X" => {
                let f = d.first().copied().unwrap_or(0);
                let mut feats = Vec::new();
                for (bit, name) in [
                    (0x20, "icc"),
                    (0x10, "alpha"),
                    (0x08, "exif"),
                    (0x04, "xmp"),
                    (0x02, "animation"),
                ] {
                    if f & bit != 0 {
                        feats.push(name);
                    }
                }
                meta.fields.insert("webp:features".into(), feats.join(", "));
                let u24 = |o: usize| {
                    d.get(o..o + 3)
                        .map(|s| u64::from(s[0]) | u64::from(s[1]) << 8 | u64::from(s[2]) << 16)
                };
                if let (Some(w), Some(h)) = (u24(4), u24(7)) {
                    meta.stats.insert("width".into(), w + 1);
                    meta.stats.insert("height".into(), h + 1);
                }
            }
            b"EXIF" => {
                let tiff = d.strip_prefix(b"Exif\0\0").unwrap_or(d);
                if !image::apply_exif_tiff(meta, tiff.to_vec(), ctx) {
                    meta.warnings.push("WebP: EXIF not parsed".into());
                }
            }
            b"XMP " => {
                let map = xmp::parse(&d[..d.len().min(MAX_PAYLOAD)], ctx);
                xmp::apply(meta, &map, "xmp");
            }
            b"ICCP" => image_extra::icc(meta, d),
            b"ANMF" => frames += 1,
            b"VP8 " => {
                meta.fields
                    .insert("webp:compression".into(), "lossy".into());
            }
            b"VP8L" => {
                meta.fields
                    .insert("webp:compression".into(), "lossless".into());
            }
            _ => {}
        }
        p = start.saturating_add(size).saturating_add(size & 1);
    }
    if frames > 0 {
        meta.stats.insert("frames".into(), frames);
    }
}

fn be32(b: &[u8], o: usize) -> Option<u32> {
    b.get(o..o.checked_add(4)?)
        .map(|s| u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
}

/// JPEG XL / JPEG 2000 boxes (same layout as ISO BMFF).
fn boxes(meta: &mut Metadata, b: &[u8], ctx: &Ctx, depth: usize) {
    let mut p = 0usize;
    let mut n = 0;
    while p + 8 <= b.len() && n < 4096 && depth < 8 {
        n += 1;
        let Some(size32) = be32(b, p) else { break };
        let kind = &b[p + 4..p + 8];
        let (hdr, size) = match size32 {
            0 => (8, (b.len() - p) as u64),
            1 => match b.get(p + 8..p + 16) {
                Some(s) => (16, u64::from_be_bytes(s.try_into().unwrap_or([0; 8]))),
                None => break,
            },
            s => (8, u64::from(s)),
        };
        if size < hdr as u64 || size > (b.len() - p) as u64 {
            break;
        }
        let body = &b[p + hdr..p + size as usize];
        match kind {
            b"jp2h" | b"res " | b"uinf" | b"asoc" => boxes(meta, body, ctx, depth + 1),
            b"ftyp" => {
                if let Some(m) = body.get(0..4) {
                    meta.fields.insert(
                        "media:major_brand".into(),
                        decode_text(m).trim().to_string(),
                    );
                }
            }
            b"ihdr" => {
                if let (Some(h), Some(w)) = (be32(body, 0), be32(body, 4)) {
                    meta.stats.insert("width".into(), u64::from(w));
                    meta.stats.insert("height".into(), u64::from(h));
                }
            }
            b"colr" if body.first() == Some(&2) => {
                image_extra::icc(meta, body.get(3..).unwrap_or(&[]));
            }
            b"xml " => {
                let map = xmp::parse(&body[..body.len().min(MAX_PAYLOAD)], ctx);
                if map.is_empty() {
                    // GML or other XML: keep a short excerpt
                    if let Some(t) = clean_str(&decode_text(&body[..body.len().min(512)])) {
                        meta.fields.entry("jp2:xml".into()).or_insert(t);
                    }
                } else {
                    xmp::apply(meta, &map, "xmp");
                }
            }
            b"uuid" if body.starts_with(&XMP_UUID) => {
                let d = &body[16..];
                let map = xmp::parse(&d[..d.len().min(MAX_PAYLOAD)], ctx);
                xmp::apply(meta, &map, "xmp");
            }
            b"uuid" if body.starts_with(EXIF_UUID) => {
                let d = &body[16..];
                let tiff = d.strip_prefix(b"Exif\0\0").unwrap_or(d);
                image::apply_exif_tiff(meta, tiff.to_vec(), ctx);
            }
            b"Exif" => {
                // JPEG XL: u32 offset to the TIFF header
                let off = be32(body, 0).unwrap_or(0) as usize;
                let tiff = body.get(4usize.saturating_add(off)..).unwrap_or(&[]);
                if !image::apply_exif_tiff(meta, tiff.to_vec(), ctx) {
                    meta.warnings.push("JPEG XL: EXIF not parsed".into());
                }
            }
            b"jumb" => image_extra::c2pa(meta, body),
            b"brob" => {
                let inner = body.get(0..4).map(decode_text).unwrap_or_default();
                meta.warnings.push(format!(
                    "JPEG XL: Brotli-compressed '{}' box not decoded",
                    inner.trim()
                ));
            }
            b"jp2c" => codestream(meta, body),
            _ => {}
        }
        p += size as usize;
    }
}

/// JPEG 2000 codestream main header: image size (SIZ) and comments (COM).
fn codestream(meta: &mut Metadata, b: &[u8]) {
    if !b.starts_with(&[0xFF, 0x4F]) {
        return;
    }
    let mut p = 2;
    let mut n = 0;
    while p + 4 <= b.len() && n < 256 {
        n += 1;
        if b[p] != 0xFF {
            break;
        }
        let marker = b[p + 1];
        if marker == 0x90 || marker == 0x93 || marker == 0xD9 {
            break; // SOT/SOD/EOC: tile data follows
        }
        let len = usize::from(u16::from_be_bytes([b[p + 2], b[p + 3]]));
        if len < 2 {
            break;
        }
        let seg = &b[(p + 4).min(b.len())..(p + 2 + len).min(b.len())];
        match marker {
            0x51 => {
                if let (Some(w), Some(h)) = (be32(seg, 2), be32(seg, 6)) {
                    meta.stats.entry("width".into()).or_insert(u64::from(w));
                    meta.stats.entry("height".into()).or_insert(u64::from(h));
                }
            }
            0x64 => {
                // Rcom 1 = Latin text
                if seg.get(0..2) == Some(&[0, 1]) {
                    if let Some(c) = clean_str(&decode_text(&seg[2..])) {
                        let c = truncate(&c, 512);
                        if c.to_ascii_lowercase().contains("kakadu")
                            || c.contains("Created by")
                            || c.contains("OpenJPEG")
                        {
                            Metadata::add_unique(&mut meta.software, &c);
                        }
                        meta.fields.entry("jp2:comment".into()).or_insert(c);
                    }
                }
            }
            _ => {}
        }
        p += 2 + len;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx_run(b: &[u8], f: DocFormat) -> Metadata {
        let limits = crate::Limits::default();
        let budget = std::cell::Cell::new(limits.max_unzipped_total);
        let ctx = Ctx::standalone(&limits, &budget);
        extract(b, f, &ctx).unwrap()
    }

    const XMP: &str = r#"<x:xmpmeta xmlns:x="adobe:ns:meta/" x:xmptk="XMP Core 6.0.0"><rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#"><rdf:Description xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:xmp="http://ns.adobe.com/xap/1.0/" xmp:CreatorTool="GIMP 2.10"><dc:creator><rdf:Seq><rdf:li>Іван Петренко</rdf:li></rdf:Seq></dc:creator></rdf:Description></rdf:RDF></x:xmpmeta>"#;

    #[test]
    fn gif_comment_xmp_netscape() {
        let mut g = b"GIF89a\x02\x00\x02\x00\x80\x00\x00".to_vec();
        g.extend([0u8; 6]); // 2-entry global color table
        g.extend(b"\x21\xFF\x0BNETSCAPE2.0\x03\x01\x05\x00\x00");
        g.extend(b"\x21\xFE\x0Bhello world\x00");
        g.extend(b"\x21\xFF\x0BXMP DataXMP");
        g.extend(XMP.as_bytes());
        g.extend(b"<?xpacket end=\"w\"?>");
        g.push(1);
        g.extend((0..=255u8).rev());
        g.push(0);
        g.extend(b"\x2C\0\0\0\0\x02\0\x02\0\x00\x02\x02\x4C\x01\x00");
        g.push(0x3B);
        let m = ctx_run(&g, DocFormat::Gif);
        assert_eq!(m.fields["gif:comment"], "hello world");
        assert_eq!(m.fields["gif:loop_count"], "5");
        assert_eq!(m.author.as_deref(), Some("Іван Петренко"));
        assert!(m.software.iter().any(|s| s == "XMP Core 6.0.0"));
        assert_eq!(m.stats["frames"], 1);
    }

    #[test]
    fn webp_chunks() {
        let mut body = b"WEBP".to_vec();
        let mut chunk = |id: &[u8], d: &[u8]| {
            body.extend(id);
            body.extend((d.len() as u32).to_le_bytes());
            body.extend(d);
            if d.len() % 2 == 1 {
                body.push(0);
            }
        };
        chunk(b"VP8X", &[0x0C, 0, 0, 0, 99, 0, 0, 49, 0, 0]);
        chunk(b"XMP ", XMP.as_bytes());
        let mut w = b"RIFF".to_vec();
        w.extend((body.len() as u32).to_le_bytes());
        w.extend(body);
        assert_eq!(kind(&w), Some(DocFormat::Webp));
        let m = ctx_run(&w, DocFormat::Webp);
        assert_eq!(m.stats["width"], 100);
        assert_eq!(m.fields["webp:features"], "exif, xmp");
        assert_eq!(m.application.as_deref(), Some("GIMP 2.10"));
    }

    #[test]
    fn jxl_and_jp2_boxes() {
        let bx = |k: &[u8], d: &[u8]| {
            let mut v = ((d.len() + 8) as u32).to_be_bytes().to_vec();
            v.extend(k);
            v.extend(d);
            v
        };
        let mut j = JXL_MAGIC.to_vec();
        j.extend(bx(b"ftyp", b"jxl \0\0\0\0jxl "));
        j.extend(bx(b"xml ", XMP.as_bytes()));
        assert_eq!(kind(&j), Some(DocFormat::Jxl));
        assert_eq!(
            ctx_run(&j, DocFormat::Jxl).author.as_deref(),
            Some("Іван Петренко")
        );
        let mut cs = vec![0xFF, 0x4F, 0xFF, 0x64, 0, 13, 0, 1];
        cs.extend(b"Kakadu-v7");
        cs.extend([0xFF, 0x90]);
        let mut p = JP2_MAGIC.to_vec();
        p.extend(bx(b"jp2c", &cs));
        let m = ctx_run(&p, DocFormat::Jp2);
        assert!(m.software.iter().any(|s| s == "Kakadu-v7"), "{m:?}");
    }
}
