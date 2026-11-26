//! Adobe Photoshop document (`.psd` / `.psb`, signature `8BPS`).
//!
//! Parses the 26-byte File Header, skips Color Mode Data, and walks the Image Resource Blocks
//! (`8BIM`):
//! - `0x0424` (1060): XMP packet (`<?xpacket?>` / `<x:xmpmeta>`): creator tool, history, dates,
//!   document/instance IDs;
//! - `0x0422` / `0x0423` (1058/1059): raw TIFF/EXIF block, camera, GPS, software, author;
//! - `0x040C` (1036) / `0x0409` (1033): embedded JPEG thumbnail (at byte offset 28);
//! - `0x03F0` (1008) / `0x0404` (1028): caption / IPTC strings.

use foca_core::{DocFormat, Metadata};

use crate::formats::media::indesign::xmp_packets;
use crate::util::{clean_str, decode_text, truncate};
use crate::{formats::media::image, xmp, Ctx, MetaError};

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

    // 2. Parse Image Resources section: [u32 len, 8BIM blocks...]
    let mut xmp_applied = false;
    if pos + 4 <= b.len() {
        let ir_len = u32::from_be_bytes([b[pos], b[pos + 1], b[pos + 2], b[pos + 3]]) as usize;
        pos += 4;
        let ir_end = pos.saturating_add(ir_len).min(b.len());
        let mut blocks = 0usize;

        while pos + 12 <= ir_end && blocks < ctx.max_entries() {
            if &b[pos..pos + 4] != b"8BIM" {
                break;
            }
            blocks += 1;
            let res_id = u16::from_be_bytes([b[pos + 4], b[pos + 5]]);
            let name_len = b[pos + 6] as usize;
            // Pascal string padded to even length (including the length byte itself)
            let name_total = if (1 + name_len).is_multiple_of(2) {
                1 + name_len
            } else {
                2 + name_len
            };
            let size_pos = pos + 6 + name_total;
            let Some(data_start) = size_pos.checked_add(4) else {
                break;
            };
            if data_start > ir_end {
                break;
            }
            let data_len = u32::from_be_bytes([
                b[size_pos],
                b[size_pos + 1],
                b[size_pos + 2],
                b[size_pos + 3],
            ]) as usize;
            let data_end = data_start.saturating_add(data_len).min(ir_end);
            let data = &b[data_start..data_end];
            // Data is padded to even byte boundary
            let padded_len = if data_len.is_multiple_of(2) {
                data_len
            } else {
                data_len.saturating_add(1)
            };
            pos = data_start.saturating_add(padded_len);

            match res_id {
                0x0424 => {
                    // XMP packet
                    let map = xmp::parse(data, ctx);
                    if !map.is_empty() {
                        xmp::apply(&mut meta, &map, "xmp");
                        xmp_applied = true;
                    }
                }
                0x0422 | 0x0423 => {
                    // EXIF data 1 / 3 (TIFF header `II*\0` or `MM\0*`)
                    let tiff = if data.starts_with(b"Exif\0\0") {
                        &data[6..]
                    } else {
                        data
                    };
                    if let Ok(exif_meta) = image::extract(tiff, DocFormat::Tiff, ctx) {
                        merge_exif(&mut meta, exif_meta);
                    }
                }
                0x040C | 0x0409 => {
                    // Thumbnail resource (28-byte header followed by JFIF JPEG)
                    if data.len() > 28 {
                        let jpg = &data[28..];
                        if jpg.starts_with(&[0xFF, 0xD8, 0xFF]) {
                            ctx.spend(jpg.len() as u64)?;
                            ctx.attach_child(&mut meta, jpg, "thumbnail.jpg", "8BIM:Thumbnail")?;
                        }
                    }
                }
                0x03F0 => {
                    // Caption string
                    if meta.description.is_none() {
                        if let Some(s) = clean_str(&decode_text(data)) {
                            meta.description = Some(truncate(&s, 1024));
                        }
                    }
                }
                _ => {}
            }
        }
    }

    // 3. Fallback scan for any `<x:xmpmeta>` packets if resource block 0x0424 was absent.
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

fn merge_exif(dst: &mut Metadata, src: Metadata) {
    if dst.author.is_none() {
        dst.author = src.author;
    }
    for p in src.people {
        dst.add_person(&p.name, p.role, &p.source);
    }
    if dst.application.is_none() {
        dst.application = src.application;
    }
    for s in src.software {
        Metadata::add_unique(&mut dst.software, &s);
    }
    if dst.created.is_none() {
        dst.created = src.created;
    }
    if dst.modified.is_none() {
        dst.modified = src.modified;
    }
    if dst.gps.is_none() {
        dst.gps = src.gps;
    }
    if dst.camera.is_none() {
        dst.camera = src.camera;
    }
    for (k, v) in src.fields {
        dst.fields.entry(k).or_insert(v);
    }
}
