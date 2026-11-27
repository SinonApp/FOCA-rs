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
    if frame_len(b, 0).is_some_and(|l| frame_len(b, l).is_some()) {
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

/// Length of a valid MPEG audio Layer III frame header at `at` (two consecutive frames identify
/// an MP3 without tags).
fn frame_len(b: &[u8], at: usize) -> Option<usize> {
    let h = b.get(at..at + 4)?;
    if h[0] != 0xFF || h[1] & 0xE0 != 0xE0 {
        return None;
    }
    let version = (h[1] >> 3) & 3; // 3 = MPEG1, 2 = MPEG2, 0 = MPEG2.5
    let layer = (h[1] >> 1) & 3; // 1 = Layer III
    let br = usize::from(h[2] >> 4);
    let sr = usize::from((h[2] >> 2) & 3);
    if version == 1 || layer != 1 || br == 0 || br == 15 || sr == 3 {
        return None;
    }
    const BR1: [usize; 15] = [
        0, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320,
    ];
    const BR2: [usize; 15] = [0, 8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 144, 160];
    let rates = [44100usize, 48000, 32000][sr];
    let pad = usize::from((h[2] >> 1) & 1);
    let len = if version == 3 {
        144_000 * BR1[br] / rates + pad
    } else {
        let rate = if version == 2 { rates / 2 } else { rates / 4 };
        72_000 * BR2[br] / rate + pad
    };
    (len > 4).then_some(at + len)
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

/// Splits `encoding, description, terminator, value` (TXXX) into two strings.
fn id3_pair(f: &[u8]) -> Option<(String, String)> {
    let enc = *f.first()?;
    let rest = f.get(1..)?;
    let wide = matches!(enc, 1 | 2);
    let cut = if wide {
        rest.as_chunks::<2>()
            .0
            .iter()
            .position(|c| c == &[0, 0])
            .map(|i| (i * 2, i * 2 + 2))
    } else {
        rest.iter().position(|&c| c == 0).map(|i| (i, i + 1))
    };
    let (a, b) = cut.unwrap_or((0, 0));
    let dec = |x: &[u8]| {
        let mut v = vec![enc];
        v.extend_from_slice(x);
        decode_id3_string(&v)
    };
    let desc = dec(&rest[..a]).unwrap_or_default();
    // a UTF-16 value carries its own BOM
    let val = dec(rest.get(b..)?)?;
    Some((desc, val))
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

    // encoder tag in the first (Xing/Info) frame: `LAME3.98r`, `Lavc58.54`
    let audio_at = if b.starts_with(b"ID3") {
        10 + synchsafe_u32(&b[6..10]) as usize
    } else {
        0
    };
    if let Some(head) = b.get(audio_at..(audio_at + 4096).min(b.len())) {
        for sig in [&b"LAME"[..], b"Lavc", b"Lavf"] {
            if let Some(i) = crate::util::find(head, sig, 0) {
                let tag: String = head[i..(i + 9).min(head.len())]
                    .iter()
                    .take_while(|c| c.is_ascii_graphic())
                    .map(|&c| c as char)
                    .collect();
                if tag.len() > 4 {
                    Metadata::add_unique(&mut meta.software, &tag);
                    meta.fields.insert("mp3:encoder".into(), tag);
                }
                break;
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
        b"TCOP" | b"TCR" => {
            if let Some(v) = decode_id3_string(fdata) {
                meta.custom
                    .entry("copyright".into())
                    .or_insert_with(|| truncate(&v, 512));
            }
        }
        b"TDRL" | b"TDEN" | b"TDOR" | b"TDTG" | b"TORY" | b"TOWN" | b"TOFN" | b"TOAL" | b"TOPE"
        | b"TPE3" | b"TPE4" | b"TIT1" | b"TIT3" | b"TSRC" | b"TKEY" | b"TLAN" => {
            if let Some(v) = decode_id3_string(fdata) {
                let k = String::from_utf8_lossy(id).into_owned();
                if k == "TOWN" {
                    meta.add_person(&v, PersonRole::Owner, "id3v2:TOWN");
                }
                if (k == "TDRL" || k == "TDOR") && meta.created.is_none() {
                    meta.created = crate::util::normalize_date(&v).or(Some(truncate(&v, 64)));
                }
                meta.fields.insert(format!("id3:{k}"), truncate(&v, 512));
            }
        }
        b"TXXX" | b"TXX" => {
            // encoding, description\0, value
            if let Some((desc, val)) = id3_pair(fdata) {
                if meta.fields.len() < 300 {
                    meta.fields.insert(
                        format!("id3:TXXX:{}", truncate(&desc, 64)),
                        truncate(&val, 1024),
                    );
                }
            }
        }
        b"WXXX" | b"WXX" | b"WOAR" | b"WOAS" | b"WOAF" | b"WCOM" | b"WPUB" | b"WORS" => {
            // URL frames: Latin-1 text (WXXX: encoding + description first)
            let raw = if id.starts_with(b"WXX") {
                fdata.get(1..).map(|r| {
                    let z = r.iter().position(|&c| c == 0).map(|i| i + 1).unwrap_or(0);
                    let r = &r[z..];
                    r.strip_prefix(&[0]).unwrap_or(r)
                })
            } else {
                Some(fdata)
            };
            if let Some(u) = raw.and_then(|r| clean_str(&decode_text(r).replace('\0', ""))) {
                Metadata::add_unique(&mut meta.links, &truncate(&u, 1024));
            }
        }
        b"PRIV" => {
            let z = fdata.iter().position(|&c| c == 0).unwrap_or(fdata.len());
            if let Some(o) = clean_str(&decode_text(&fdata[..z])) {
                let cur = meta.fields.entry("id3:PRIV".into()).or_default();
                if !cur.split("; ").any(|x| x == o) && cur.len() < 1024 {
                    if !cur.is_empty() {
                        cur.push_str("; ");
                    }
                    cur.push_str(&truncate(&o, 128));
                }
            }
        }
        b"APIC" | b"PIC" => {
            // encoding, MIME (v2.2: 3-byte format), picture type, description
            if let Some(&enc) = fdata.first() {
                let rest = fdata.get(1..).unwrap_or(&[]);
                let after_mime = if id == b"PIC" {
                    3.min(rest.len())
                } else {
                    rest.iter()
                        .position(|&c| c == 0)
                        .map(|i| i + 1)
                        .unwrap_or(rest.len())
                };
                let ptype = rest.get(after_mime).copied();
                let desc_bytes = rest.get(after_mime + 1..).unwrap_or(&[]);
                let mut db = vec![enc];
                db.extend_from_slice(&desc_bytes[..desc_bytes.len().min(512)]);
                let desc = decode_id3_string(&db)
                    .map(|d| d.split('\0').next().unwrap_or("").to_string())
                    .and_then(|d| clean_str(&d));
                let label = match ptype {
                    Some(3) => "Cover (front)",
                    Some(4) => "Cover (back)",
                    Some(0) => "Other",
                    _ => "Picture",
                };
                let v = match desc {
                    Some(d) => format!("{label}: {d}"),
                    None => label.to_string(),
                };
                let cur = meta.fields.entry("id3:APIC".into()).or_default();
                if cur.len() < 1024 {
                    if !cur.is_empty() {
                        cur.push_str("; ");
                    }
                    cur.push_str(&truncate(&v, 256));
                }
            }
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

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(id: &[u8], body: &[u8]) -> Vec<u8> {
        let mut v = id.to_vec();
        v.extend((body.len() as u32).to_be_bytes());
        v.extend([0, 0]);
        v.extend(body);
        v
    }

    #[test]
    fn txxx_copyright_and_untagged_frames() {
        let mut tags = frame(b"TXXX", b"\x00Source\x00C:\\Users\\olena\\draft.docx");
        tags.extend(frame(b"TCOP", "\x03© Студія".as_bytes()));
        tags.extend(frame(b"WXXX", b"\x00\x00https://example.org/a"));
        let mut b = b"ID3\x03\x00\x00".to_vec();
        let n = tags.len() as u32;
        b.extend([
            (n >> 21) as u8 & 0x7F,
            (n >> 14) as u8 & 0x7F,
            (n >> 7) as u8 & 0x7F,
            n as u8 & 0x7F,
        ]);
        b.extend(tags);
        let limits = crate::Limits::default();
        let budget = std::cell::Cell::new(limits.max_unzipped_total);
        let ctx = Ctx::standalone(&limits, &budget);
        let m = extract(&b, &ctx).unwrap();
        assert_eq!(m.fields["id3:TXXX:Source"], "C:\\Users\\olena\\draft.docx");
        assert_eq!(m.custom["copyright"], "© Студія");
        assert!(m.links.iter().any(|l| l == "https://example.org/a"));
        // two MPEG-1 Layer III frames (128 kbit/s, 44.1 kHz) without any tag
        let mut raw = Vec::new();
        for _ in 0..2 {
            let mut f = vec![0xFF, 0xFB, 0x90, 0x00];
            f.resize(417, 0);
            raw.extend(f);
        }
        assert!(is_mp3(&raw));
    }
}
