//! MPEG Audio Layer III (`.mp3`, ID3v2.2/2.3/2.4 and ID3v1 tags).
//!
//! Extracts artist/author (`TPE1`/`TCOM`/`TEXT`), organization/label (`TPUB`/`TPE2`), album/title
//! (`TALB`/`TIT2`), encoding software (`TSSE`/`TENC`), timestamps (`TDRC`/`TYER`), comments
//! (`COMM`), and recursively parses attached cover art (`APIC`/`PIC`) via
//! [`crate::Ctx::attach_child`] so EXIF/GPS in cover photos are discovered.

use foca_core::{CommentRef, DocFormat, Metadata, PersonRole};

use crate::util::{clean_str, decode_text, truncate};
use crate::{Ctx, MetaError};

/// Returns `true` if `b` starts with a valid ID3v2 header (`ID3` + major version 2..=4) or is an
/// MPEG audio frame with a trailing 128-byte `ID3v1` (`TAG`) footer.
pub(crate) fn is_mp3(b: &[u8]) -> bool {
    if b.len() >= 10
        && &b[0..3] == b"ID3"
        && matches!(b[3], 2..=4)
        && b[4] < 0x80
        && b[6] < 0x80
        && b[7] < 0x80
        && b[8] < 0x80
        && b[9] < 0x80
    {
        return true;
    }
    if b.len() >= 132
        && b[0] == 0xFF
        && (b[1] & 0xE0) == 0xE0
        && &b[b.len() - 128..b.len() - 125] == b"TAG"
    {
        return true;
    }
    false
}

fn synchsafe_u32(b: &[u8]) -> u32 {
    if b.len() < 4 {
        return 0;
    }
    ((b[0] as u32 & 0x7F) << 21)
        | ((b[1] as u32 & 0x7F) << 14)
        | ((b[2] as u32 & 0x7F) << 7)
        | (b[3] as u32 & 0x7F)
}

fn decode_id3_string(data: &[u8]) -> Option<String> {
    if data.is_empty() {
        return None;
    }
    let enc = data[0];
    let payload = &data[1..];
    let s = match enc {
        0 => decode_text(payload),
        1 | 2 => {
            let (be, slice) = if payload.starts_with(&[0xFE, 0xFF]) {
                (true, &payload[2..])
            } else if payload.starts_with(&[0xFF, 0xFE]) {
                (false, &payload[2..])
            } else {
                (enc == 2, payload)
            };
            let units: Vec<u16> = slice
                .as_chunks::<2>()
                .0
                .iter()
                .map(|c| {
                    if be {
                        u16::from_be_bytes([c[0], c[1]])
                    } else {
                        u16::from_le_bytes([c[0], c[1]])
                    }
                })
                .take_while(|&u| u != 0)
                .collect();
            String::from_utf16_lossy(&units)
        }
        3 => String::from_utf8_lossy(payload)
            .trim_end_matches('\0')
            .to_string(),
        _ => decode_text(data),
    };
    clean_str(s.trim_matches('\0'))
}

pub fn extract(b: &[u8], ctx: &Ctx) -> Result<Metadata, MetaError> {
    if !is_mp3(b) {
        return Err(MetaError::malformed("mp3", "missing ID3v2/ID3v1 signature"));
    }
    let mut meta = Metadata::new(DocFormat::Mp3);

    if b.len() >= 10 && &b[0..3] == b"ID3" {
        let ver = b[3];
        let tag_len = synchsafe_u32(&b[6..10]) as usize;
        meta.fields
            .insert("mp3:id3_version".into(), format!("2.{ver}"));
        let end = (10 + tag_len).min(b.len());
        let mut pos = 10usize;
        let mut frames = 0usize;

        while pos < end && frames < ctx.max_entries() {
            frames += 1;
            if ver == 2 {
                let Some(hdr_end) = pos.checked_add(6) else {
                    break;
                };
                if hdr_end > end {
                    break;
                }
                let id = &b[pos..pos + 3];
                if id == [0, 0, 0] {
                    break;
                }
                let fsize = ((b[pos + 3] as usize) << 16)
                    | ((b[pos + 4] as usize) << 8)
                    | (b[pos + 5] as usize);
                pos = hdr_end;
                let Some(frame_end) = pos.checked_add(fsize) else {
                    break;
                };
                if fsize == 0 || frame_end > end {
                    break;
                }
                let fdata = &b[pos..frame_end];
                pos = frame_end;
                apply_frame(&mut meta, ctx, id, fdata)?;
            } else {
                let Some(hdr_end) = pos.checked_add(10) else {
                    break;
                };
                if hdr_end > end {
                    break;
                }
                let id = &b[pos..pos + 4];
                if id == [0, 0, 0, 0] {
                    break;
                }
                let fsize = if ver == 4 {
                    synchsafe_u32(&b[pos + 4..pos + 8]) as usize
                } else {
                    u32::from_be_bytes([b[pos + 4], b[pos + 5], b[pos + 6], b[pos + 7]]) as usize
                };
                pos = hdr_end;
                let Some(frame_end) = pos.checked_add(fsize) else {
                    break;
                };
                if fsize == 0 || frame_end > end {
                    break;
                }
                let fdata = &b[pos..frame_end];
                pos = frame_end;
                apply_frame(&mut meta, ctx, id, fdata)?;
            }
        }
    }

    // Fallback/supplement from trailing 128-byte ID3v1 tag (`TAG`)
    if b.len() >= 128 && &b[b.len() - 128..b.len() - 125] == b"TAG" {
        let tag = &b[b.len() - 128..];
        if meta.title.is_none() {
            if let Some(t) = clean_str(decode_text(&tag[3..33]).trim_matches('\0')) {
                meta.title = Some(truncate(&t, 256));
            }
        }
        if let Some(a) = clean_str(decode_text(&tag[33..63]).trim_matches('\0')) {
            let a = truncate(&a, 256);
            if meta.author.is_none() {
                meta.author = Some(a.clone());
            }
            meta.add_person(&a, PersonRole::Author, "id3v1:artist");
        }
        if meta.subject.is_none() {
            if let Some(alb) = clean_str(decode_text(&tag[63..93]).trim_matches('\0')) {
                meta.subject = Some(truncate(&alb, 256));
            }
        }
        if meta.created.is_none() {
            if let Some(yr) = clean_str(decode_text(&tag[93..97]).trim_matches('\0')) {
                meta.created = Some(truncate(&yr, 32));
            }
        }
        if meta.description.is_none() {
            if let Some(cm) = clean_str(decode_text(&tag[97..125]).trim_matches('\0')) {
                meta.description = Some(truncate(&cm, 256));
            }
        }
    }

    Ok(meta)
}

fn apply_frame(meta: &mut Metadata, ctx: &Ctx, id: &[u8], fdata: &[u8]) -> Result<(), MetaError> {
    match id {
        b"TIT2" | b"TT2" => {
            if let Some(v) = decode_id3_string(fdata) {
                meta.title = Some(truncate(&v, 512));
            }
        }
        b"TPE1" | b"TP1" | b"TCOM" | b"TCM" | b"TEXT" | b"TXT" => {
            if let Some(v) = decode_id3_string(fdata) {
                let v = truncate(&v, 512);
                if meta.author.is_none() {
                    meta.author = Some(v.clone());
                }
                meta.add_person(&v, PersonRole::Author, "id3v2:TPE1");
            }
        }
        b"TPUB" | b"TPB" | b"TPE2" | b"TP2" => {
            if let Some(v) = decode_id3_string(fdata) {
                let v = truncate(&v, 512);
                if meta.company.is_none() {
                    meta.company = Some(v);
                }
            }
        }
        b"TALB" | b"TAL" => {
            if let Some(v) = decode_id3_string(fdata) {
                meta.subject = Some(truncate(&v, 512));
            }
        }
        b"TSSE" | b"TSS" | b"TENC" | b"TEN" => {
            if let Some(v) = decode_id3_string(fdata) {
                let v = truncate(&v, 256);
                if meta.application.is_none() {
                    meta.application = Some(v.clone());
                }
                Metadata::add_unique(&mut meta.software, &v);
            }
        }
        b"TDRC" | b"TYER" | b"TYE" => {
            if let Some(v) = decode_id3_string(fdata) {
                if meta.created.is_none() {
                    meta.created = Some(truncate(&v, 64));
                }
            }
        }
        b"COMM" | b"COM" => {
            let body = if fdata.len() > 4 {
                let enc = fdata[0];
                let rest = &fdata[4..];
                let payload = if let Some(sep) = rest.iter().position(|&b| b == 0) {
                    &rest[sep + 1..]
                } else {
                    rest
                };
                let mut buf = Vec::with_capacity(1 + payload.len());
                buf.push(enc);
                buf.extend_from_slice(payload);
                decode_id3_string(&buf)
            } else {
                decode_id3_string(fdata)
            };
            if let Some(v) = body {
                let v = truncate(&v, 1024);
                if meta.description.is_none() {
                    meta.description = Some(v.clone());
                }
                meta.comments.push(CommentRef {
                    author: meta.author.clone(),
                    initials: None,
                    date: None,
                    text: v,
                    source: "id3v2:COMM".into(),
                });
            }
        }
        b"APIC" | b"PIC" => {
            if let Some(pos) = fdata
                .windows(3)
                .position(|w| w == [0xFF, 0xD8, 0xFF])
                .or_else(|| fdata.windows(8).position(|w| w == b"\x89PNG\r\n\x1a\n"))
            {
                let img = &fdata[pos..];
                ctx.spend(img.len() as u64)?;
                ctx.attach_child(meta, img, "cover.jpg", "APIC")?;
            }
        }
        _ => {}
    }
    Ok(())
}
