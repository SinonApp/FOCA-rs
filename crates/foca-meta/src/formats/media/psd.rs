//! Adobe Photoshop document (`.psd` / `.psb`, signature `8BPS`).
//!
//! Parses the 26-byte File Header, skips Color Mode Data, walks the Image Resource Blocks
//! (`8BIM`, see `irb.rs`: XMP, EXIF, IPTC, caption, URL, writer application, slices, path names and the
//! JPEG thumbnail) and the layer records for layer names.

use foca_core::{DocFormat, Metadata};

use super::irb;
use crate::formats::media::indesign::xmp_packets;
use crate::util::{clean_str, decode_text, truncate};
use crate::{xmp, Ctx, MetaError};

pub fn extract(b: &[u8], ctx: &Ctx) -> Result<Metadata, MetaError> {
    if b.len() < 26 || &b[0..4] != b"8BPS" {
        return Err(MetaError::malformed("psd", "bad 8BPS header"));
    }
    let version = u16::from_be_bytes([b[4], b[5]]);
    if version != 1 && version != 2 {
        return Err(MetaError::malformed("psd", "unsupported PSD/PSB version"));
    }
    let channels = u16::from_be_bytes([b[12], b[13]]);
    let height = u32::from_be_bytes([b[14], b[15], b[16], b[17]]);
    let width = u32::from_be_bytes([b[18], b[19], b[20], b[21]]);
    let depth = u16::from_be_bytes([b[22], b[23]]);
    let color_mode = u16::from_be_bytes([b[24], b[25]]);

    let mut meta = Metadata::new(DocFormat::Psd);
    meta.stats.insert("width".into(), width as u64);
    meta.stats.insert("height".into(), height as u64);
    meta.stats.insert("channels".into(), channels as u64);
    meta.stats.insert("bit_depth".into(), depth as u64);
    meta.fields.insert(
        "psd:version".into(),
        if version == 2 {
            "PSB (Large Document)".into()
        } else {
            "PSD".into()
        },
    );
    meta.fields.insert(
        "psd:color_mode".into(),
        match color_mode {
            0 => "Bitmap",
            1 => "Grayscale",
            2 => "Indexed",
            3 => "RGB",
            4 => "CMYK",
            7 => "Multichannel",
            8 => "Duotone",
            9 => "Lab",
            _ => "Other",
        }
        .into(),
    );

    // 1. Skip Color Mode Data section: [u32 len, bytes...]
    let mut pos = 26usize;
    if pos + 4 <= b.len() {
        let cm_len = u32::from_be_bytes([b[pos], b[pos + 1], b[pos + 2], b[pos + 3]]) as usize;
        pos = pos.saturating_add(4).saturating_add(cm_len);
    }

    // 2. Image Resources section: [u32 len, 8BIM blocks...]
    let mut xmp_applied = false;
    if let Some(ir_len) = b
        .get(pos..pos + 4)
        .map(|s| u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
    {
        pos += 4;
        let ir_end = pos.saturating_add(ir_len as usize).min(b.len());
        if let Some(section) = b.get(pos..ir_end) {
            xmp_applied = irb::apply(&mut meta, section, ctx, "8BIM:Thumbnail")?;
        }
        pos = ir_end;
    }
    // 3. Layer and mask information: layer names
    layer_names(&mut meta, b, pos, version == 2);

    // 4. Fallback scan for any `<x:xmpmeta>` packets if resource block 0x0424 was absent.
    if !xmp_applied {
        for p in xmp_packets(b) {
            let map = xmp::parse(p, ctx);
            if !map.is_empty() {
                xmp::apply(&mut meta, &map, "xmp");
                break;
            }
        }
    }

    Ok(meta)
}

/// Layer names from the layer records (Pascal name, or the Unicode `luni` block when present).
/// Layer record layout per the Adobe Photoshop File Formats Specification.
fn layer_names(meta: &mut Metadata, b: &[u8], pos: usize, psb: bool) {
    let lw = if psb { 8 } else { 4 };
    let rd = |o: usize, n: usize| -> Option<usize> {
        let s = b.get(o..o.checked_add(n)?)?;
        Some(s.iter().fold(0u64, |a, &c| (a << 8) | u64::from(c)) as usize)
    };
    // section length, then layer info length, then the signed layer count
    let Some(p) = pos.checked_add(lw * 2) else {
        return;
    };
    let Some(count) = b
        .get(p..p + 2)
        .map(|s| i16::from_be_bytes([s[0], s[1]]).unsigned_abs())
    else {
        return;
    };
    let mut q = p + 2;
    let mut names: Vec<String> = Vec::new();
    for _ in 0..usize::from(count).min(2000) {
        let Some(ch) = rd(q + 16, 2) else { break };
        q = q + 18 + ch.saturating_mul(2 + lw);
        // blend signature + key, opacity, clipping, flags, filler
        q += 12;
        let Some(extra) = rd(q, 4) else { break };
        let ex_start = q + 4;
        let Some(ex_end) = ex_start.checked_add(extra).filter(|e| *e <= b.len()) else {
            break;
        };
        q = ex_end;
        // layer mask data, blending ranges, then the name
        let Some(m) = rd(ex_start, 4) else { continue };
        let Some(br_at) = (ex_start + 4).checked_add(m) else {
            continue;
        };
        let Some(br) = rd(br_at, 4) else { continue };
        let name_at = br_at + 4 + br;
        let Some(&nl) = b.get(name_at) else { continue };
        let mut name = b
            .get(name_at + 1..name_at + 1 + usize::from(nl))
            .map(decode_text)
            .unwrap_or_default();
        // additional layer information blocks
        let mut a = name_at + (1 + usize::from(nl)).next_multiple_of(4);
        let mut guard = 0;
        while a + 12 <= ex_end && guard < 64 {
            guard += 1;
            if !matches!(&b[a..a + 4], b"8BIM" | b"8B64") {
                break;
            }
            let key = &b[a + 4..a + 8];
            let Some(len) = rd(a + 8, 4) else { break };
            let data_at = a + 12;
            if key == b"luni" {
                if let Some((u, _)) = irb::unicode_string(b, data_at) {
                    name = u;
                }
            }
            a = data_at.saturating_add(len.next_multiple_of(2));
        }
        if let Some(n) = clean_str(&name) {
            if n != "</Layer group>" && !names.contains(&n) && names.len() < 200 {
                names.push(truncate(&n, 256));
            }
        }
    }
    if !names.is_empty() {
        meta.stats.insert("layers".into(), u64::from(count));
        meta.fields
            .insert("psd:layer_names".into(), truncate(&names.join("; "), 4096));
    }
}
