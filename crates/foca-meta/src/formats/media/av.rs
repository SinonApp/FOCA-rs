//! Audio and video containers: RIFF (WAV/AVI: LIST INFO, Broadcast WAVE `bext`, iXML, XMP),
//! Matroska/WebM (EBML Info and Tags), ASF (WMV/WMA content descriptions and file
//! properties), FLAC and Ogg (Vorbis/Opus comments).

use foca_core::{DocFormat, Metadata, PersonRole};

use crate::util::{
    clean_str, decode_text, filetime_to_iso, rd_u16le, rd_u32be, rd_u32le, rd_u64le, truncate,
    utf16le,
};
use crate::{Ctx, MetaError};

const MAX_CHUNKS: usize = 10_000;

// ---------- RIFF ----------

pub(crate) fn riff_kind(b: &[u8]) -> Option<DocFormat> {
    if !b.starts_with(b"RIFF") {
        return None;
    }
    match b.get(8..12)? {
        b"WAVE" => Some(DocFormat::Wav),
        b"AVI " => Some(DocFormat::Avi),
        _ => None,
    }
}

pub fn extract_riff(b: &[u8], format: DocFormat, ctx: &Ctx) -> Result<Metadata, MetaError> {
    crate::guard("riff", || {
        let mut meta = Metadata::new(format);
        let mut count = 0;
        riff_chunks(&mut meta, b.get(12..).unwrap_or(&[]), 0, &mut count, ctx);
        Ok(meta)
    })
}

fn riff_chunks(meta: &mut Metadata, mut b: &[u8], depth: u8, count: &mut usize, ctx: &Ctx) {
    while b.len() >= 8 && *count < MAX_CHUNKS {
        *count += 1;
        let id = &b[..4];
        let size = rd_u32le(b, 4).unwrap_or(0) as usize;
        let data = &b[8..(8usize.saturating_add(size)).min(b.len())];
        match id {
            b"LIST" if depth < 4 && data.len() >= 4 => {
                if &data[..4] == b"INFO" {
                    info_list(meta, &data[4..]);
                } else if &data[..4] != b"movi" {
                    riff_chunks(meta, &data[4..], depth + 1, count, ctx);
                }
            }
            b"bext" => bext(meta, data),
            b"iXML" => {
                let t = decode_text(&data[..data.len().min(256 * 1024)]);
                for tag in ["PROJECT", "NOTE", "TAPE", "SCENE"] {
                    if let Some(v) = xml_tag(&t, tag) {
                        meta.fields.insert(format!("ixml:{tag}"), truncate(&v, 512));
                    }
                }
            }
            b"_PMX" | b"XMP " => {
                let map = crate::xmp::parse(&data[..data.len().min(4 << 20)], ctx);
                crate::xmp::apply(meta, &map, "xmp");
            }
            b"IDIT" => {
                if let Some(v) = clean_str(&decode_text(data)) {
                    meta.fields.insert("avi:IDIT".into(), truncate(&v, 64));
                    meta.created.get_or_insert(truncate(&v, 64));
                }
            }
            b"strn" => {
                if let Some(v) = clean_str(&decode_text(data)) {
                    meta.fields
                        .entry("avi:stream_name".into())
                        .or_insert(truncate(&v, 256));
                }
            }
            _ => {}
        }
        let next = 8usize.saturating_add(size).saturating_add(size & 1);
        if next >= b.len() {
            break;
        }
        b = &b[next..];
    }
}

fn info_list(meta: &mut Metadata, mut b: &[u8]) {
    let mut n = 0;
    while b.len() >= 8 && n < 256 {
        n += 1;
        let id = String::from_utf8_lossy(&b[..4]).into_owned();
        let size = rd_u32le(b, 4).unwrap_or(0) as usize;
        let data = &b[8..(8usize.saturating_add(size)).min(b.len())];
        if let Some(v) = clean_str(&decode_text(data).replace('\0', "")) {
            let v = truncate(&v, 512);
            match id.as_str() {
                "IART" => {
                    meta.add_person(&v, PersonRole::Author, "riff:IART");
                    meta.author.get_or_insert(v.clone());
                }
                "IENG" | "ITCH" => meta.add_person(&v, PersonRole::Creator, &format!("riff:{id}")),
                "ICMT" => meta.description = Some(v.clone()),
                "INAM" => meta.title = Some(v.clone()),
                "ISBJ" => meta.subject = Some(v.clone()),
                "IKEY" => meta.keywords = Some(v.clone()),
                "ICOP" => {
                    meta.custom.insert("copyright".into(), v.clone());
                }
                "ISFT" => {
                    Metadata::add_unique(&mut meta.software, &v);
                    meta.application.get_or_insert(v.clone());
                }
                "ICRD" => {
                    meta.created = crate::util::normalize_date(&v).or(Some(v.clone()));
                }
                _ => {}
            }
            meta.fields.insert(format!("riff:{id}"), v);
        }
        let next = 8usize.saturating_add(size).saturating_add(size & 1);
        if next >= b.len() {
            break;
        }
        b = &b[next..];
    }
}

/// Broadcast WAVE extension: description, originator, reference, origination date/time.
fn bext(meta: &mut Metadata, d: &[u8]) {
    let field = |a: usize, n: usize| {
        d.get(a..a + n)
            .and_then(|x| clean_str(&decode_text(x).replace('\0', "")))
    };
    if let Some(v) = field(0, 256) {
        meta.description.get_or_insert(v.clone());
        meta.fields.insert("bext:Description".into(), v);
    }
    if let Some(v) = field(256, 32) {
        Metadata::add_unique(&mut meta.software, &v);
        meta.fields.insert("bext:Originator".into(), v);
    }
    if let Some(v) = field(288, 32) {
        meta.fields.insert("bext:OriginatorReference".into(), v);
    }
    if let (Some(date), time) = (field(320, 10), field(330, 8)) {
        let t = time.unwrap_or_default().replace([':', '-', '.'], ":");
        let v = if t.is_empty() {
            date
        } else {
            format!("{date}T{t}")
        };
        meta.created.get_or_insert(v.clone());
        meta.fields.insert("bext:OriginationDate".into(), v);
    }
    if let Some(v) = d.get(602..).map(|x| decode_text(&x[..x.len().min(4096)])) {
        if let Some(v) = clean_str(&v.replace('\0', "")) {
            meta.fields
                .insert("bext:CodingHistory".into(), truncate(&v, 1024));
        }
    }
}

fn xml_tag(t: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    let s = t.find(&open)? + open.len();
    let e = t[s..].find(&format!("</{tag}>"))? + s;
    clean_str(&t[s..e])
}

// ---------- Matroska / WebM ----------

pub(crate) const EBML_MAGIC: [u8; 4] = [0x1A, 0x45, 0xDF, 0xA3];

/// Reads an EBML element id (marker bits kept).
fn ebml_id(b: &[u8], at: &mut usize) -> Option<u32> {
    let first = *b.get(*at)?;
    let len = first.leading_zeros() as usize + 1;
    if len > 4 {
        return None;
    }
    let mut v = 0u32;
    for i in 0..len {
        v = (v << 8) | u32::from(*b.get(*at + i)?);
    }
    *at += len;
    Some(v)
}

/// Reads an EBML size (marker removed); `None` for unknown size or bad input.
fn ebml_size(b: &[u8], at: &mut usize) -> Option<u64> {
    let first = *b.get(*at)?;
    let len = first.leading_zeros() as usize + 1;
    if len > 8 {
        return None;
    }
    let mut v = u64::from(first) & (0xFF >> len);
    let mut all_ones = v == (0xFF >> len);
    for i in 1..len {
        let c = *b.get(*at + i)?;
        all_ones &= c == 0xFF;
        v = (v << 8) | u64::from(c);
    }
    *at += len;
    (!all_ones).then_some(v)
}

pub fn extract_mkv(b: &[u8]) -> Result<Metadata, MetaError> {
    crate::guard("matroska", || {
        let mut meta = Metadata::new(DocFormat::Mkv);
        let mut count = 0;
        ebml_walk(&mut meta, b, 0, &mut count, None);
        Ok(meta)
    })
}

fn ebml_walk(
    meta: &mut Metadata,
    b: &[u8],
    depth: u8,
    count: &mut usize,
    tag: Option<&mut (String, String)>,
) {
    let mut at = 0;
    let mut pending = tag;
    while at < b.len() && *count < MAX_CHUNKS {
        *count += 1;
        let Some(id) = ebml_id(b, &mut at) else { break };
        let size = ebml_size(b, &mut at);
        let end = match size {
            Some(s) => at.saturating_add(s as usize).min(b.len()),
            // unknown size: only containers we descend into may use it
            None => b.len(),
        };
        let data = &b[at..end];
        let text = || clean_str(&String::from_utf8_lossy(&data[..data.len().min(4096)]));
        match id {
            // EBML header -> DocType
            0x1A45_DFA3 if depth == 0 => ebml_walk(meta, data, depth + 1, count, None),
            0x4282 => {
                if let Some(v) = text() {
                    meta.fields.insert("mkv:doctype".into(), v);
                }
            }
            // Segment, Info, Tags, Tag
            0x1853_8067 | 0x1549_A966 | 0x1254_C367 if depth < 4 => {
                ebml_walk(meta, data, depth + 1, count, None)
            }
            0x7373 if depth < 6 => ebml_walk(meta, data, depth + 1, count, None),
            0x67C8 if depth < 8 => {
                let mut kv = (String::new(), String::new());
                ebml_walk(meta, data, depth + 1, count, Some(&mut kv));
                simple_tag(meta, &kv.0, &kv.1);
            }
            0x45A3 => {
                if let (Some(slot), Some(v)) = (pending.as_deref_mut(), text()) {
                    slot.0 = v;
                }
            }
            0x4487 => {
                if let (Some(slot), Some(v)) = (pending.as_deref_mut(), text()) {
                    slot.1 = v;
                }
            }
            0x7BA9 => meta.title = text(),
            0x4D80 => {
                if let Some(v) = text() {
                    Metadata::add_unique(&mut meta.software, &v);
                    meta.producer = Some(v.clone());
                    meta.fields.insert("mkv:MuxingApp".into(), v);
                }
            }
            0x5741 => {
                if let Some(v) = text() {
                    Metadata::add_unique(&mut meta.software, &v);
                    meta.application = Some(v.clone());
                    meta.fields.insert("mkv:WritingApp".into(), v);
                }
            }
            0x4461 if data.len() == 8 => {
                let ns = i64::from_be_bytes(data.try_into().unwrap_or([0; 8]));
                // nanoseconds since 2001-01-01T00:00:00 UTC
                meta.created = crate::util::unix_to_iso(978_307_200 + ns / 1_000_000_000);
            }
            // Cluster: media data, never descend
            0x1F43_B675 if size.is_none() => break,
            _ => {}
        }
        if end <= at && size != Some(0) {
            break;
        }
        at = end;
    }
}

fn simple_tag(meta: &mut Metadata, k: &str, v: &str) {
    if k.is_empty() || v.is_empty() {
        return;
    }
    let v = truncate(v, 512);
    match k.to_ascii_uppercase().as_str() {
        "ARTIST" | "DIRECTOR" | "COMPOSER" => meta.add_person(&v, PersonRole::Author, "mkv:tag"),
        "ENCODER" | "ENCODED_BY" => Metadata::add_unique(&mut meta.software, &v),
        "COMMENT" | "DESCRIPTION" => {
            meta.description.get_or_insert(v.clone());
        }
        "DATE_RECORDED" | "DATE_RELEASED" | "CREATION_TIME" => {
            meta.created.get_or_insert(v.clone());
        }
        _ => {}
    }
    if meta.fields.len() < 300 {
        meta.fields.insert(format!("mkv:{}", truncate(k, 64)), v);
    }
}

// ---------- ASF ----------

pub(crate) const ASF_HEADER: [u8; 16] = [
    0x30, 0x26, 0xB2, 0x75, 0x8E, 0x66, 0xCF, 0x11, 0xA6, 0xD9, 0x00, 0xAA, 0x00, 0x62, 0xCE, 0x6C,
];
const ASF_CONTENT: [u8; 16] = [
    0x33, 0x26, 0xB2, 0x75, 0x8E, 0x66, 0xCF, 0x11, 0xA6, 0xD9, 0x00, 0xAA, 0x00, 0x62, 0xCE, 0x6C,
];
const ASF_EXT_CONTENT: [u8; 16] = [
    0x40, 0xA4, 0xD0, 0xD2, 0x07, 0xE3, 0xD2, 0x11, 0x97, 0xF0, 0x00, 0xA0, 0xC9, 0x5E, 0xA8, 0x50,
];
const ASF_FILE_PROPS: [u8; 16] = [
    0xA1, 0xDC, 0xAB, 0x8C, 0x47, 0xA9, 0xCF, 0x11, 0x8E, 0xE4, 0x00, 0xC0, 0x0C, 0x20, 0x53, 0x65,
];

pub fn extract_asf(b: &[u8]) -> Result<Metadata, MetaError> {
    crate::guard("asf", || {
        let mut meta = Metadata::new(DocFormat::Asf);
        let hsize = rd_u64le(b, 16).unwrap_or(0).min(b.len() as u64) as usize;
        let count = rd_u32le(b, 24).unwrap_or(0).min(256);
        let mut at = 30;
        for _ in 0..count {
            let Some(guid) = b.get(at..at + 16) else {
                break;
            };
            let size = rd_u64le(b, at + 16).unwrap_or(0) as usize;
            if size < 24 {
                break;
            }
            let end = at.saturating_add(size).min(hsize.max(30)).min(b.len());
            let obj = &b[at.min(end)..end];
            if guid == ASF_CONTENT {
                asf_content(&mut meta, obj);
            } else if guid == ASF_EXT_CONTENT {
                asf_ext_content(&mut meta, obj);
            } else if guid == ASF_FILE_PROPS {
                if let Some(ft) = rd_u64le(obj, 48) {
                    meta.created = filetime_to_iso(ft);
                }
            }
            at = at.saturating_add(size);
        }
        Ok(meta)
    })
}

fn asf_content(meta: &mut Metadata, o: &[u8]) {
    let lens: Vec<usize> = (0..5)
        .map(|i| rd_u16le(o, 24 + i * 2).unwrap_or(0) as usize)
        .collect();
    let mut at: usize = 34;
    let mut vals = Vec::new();
    for l in lens {
        let v = o
            .get(at..at.saturating_add(l))
            .map(utf16le)
            .and_then(|s| clean_str(&s));
        vals.push(v);
        at = at.saturating_add(l);
    }
    if let Some(Some(t)) = vals.first() {
        meta.title = Some(truncate(t, 512));
    }
    if let Some(Some(a)) = vals.get(1) {
        meta.add_person(a, PersonRole::Author, "asf:Author");
        meta.author = Some(truncate(a, 512));
    }
    if let Some(Some(c)) = vals.get(2) {
        meta.custom.insert("copyright".into(), truncate(c, 512));
    }
    if let Some(Some(d)) = vals.get(3) {
        meta.description = Some(truncate(d, 2048));
    }
}

fn asf_ext_content(meta: &mut Metadata, o: &[u8]) {
    let n = rd_u16le(o, 24).unwrap_or(0).min(256);
    let mut at = 26;
    for _ in 0..n {
        let Some(nl) = rd_u16le(o, at).map(|x| x as usize) else {
            break;
        };
        let name = o.get(at + 2..at + 2 + nl).map(utf16le).unwrap_or_default();
        at += 2 + nl;
        let (Some(ty), Some(vl)) = (rd_u16le(o, at), rd_u16le(o, at + 2)) else {
            break;
        };
        let vl = vl as usize;
        let raw = o.get(at + 4..at + 4 + vl).unwrap_or(&[]);
        at += 4 + vl;
        let value = match ty {
            0 => utf16le(raw),
            3 => rd_u32le(raw, 0).map(|v| v.to_string()).unwrap_or_default(),
            5 => rd_u16le(raw, 0).map(|v| v.to_string()).unwrap_or_default(),
            _ => continue,
        };
        let name = name.trim_end_matches('\0').to_string();
        let Some(v) = clean_str(value.trim_end_matches('\0')) else {
            continue;
        };
        let v = truncate(&v, 512);
        match name.as_str() {
            "WM/ToolName" | "WM/EncodingSettings" | "WM/EncodedBy" => {
                Metadata::add_unique(&mut meta.software, &v);
                meta.application.get_or_insert(v.clone());
            }
            "WM/AlbumArtist" | "WM/Composer" | "WM/Writer" => {
                meta.add_person(&v, PersonRole::Author, "asf:ext")
            }
            "WM/Publisher" | "WM/Provider" => {
                meta.company.get_or_insert(v.clone());
            }
            _ => {}
        }
        if meta.fields.len() < 300 {
            meta.fields
                .insert(format!("asf:{}", truncate(&name, 64)), v);
        }
    }
    let tool = meta.fields.get("asf:WM/ToolName").cloned();
    let ver = meta.fields.get("asf:WM/ToolVersion").cloned();
    if let (Some(t), Some(v)) = (tool, ver) {
        Metadata::add_unique(&mut meta.software, &format!("{t} {v}"));
    }
}

// ---------- FLAC / Ogg (Vorbis comments) ----------

pub fn extract_flac(b: &[u8]) -> Result<Metadata, MetaError> {
    crate::guard("flac", || {
        let mut meta = Metadata::new(DocFormat::Flac);
        let mut at = 4;
        for _ in 0..128 {
            let Some(&h) = b.get(at) else { break };
            let len = rd_u32be(b, at).unwrap_or(0) as usize & 0x00FF_FFFF;
            let data = b.get(at + 4..(at + 4 + len).min(b.len())).unwrap_or(&[]);
            if h & 0x7F == 4 {
                vorbis_comments(&mut meta, data);
            }
            if h & 0x80 != 0 {
                break;
            }
            at = at + 4 + len;
        }
        Ok(meta)
    })
}

pub fn extract_ogg(b: &[u8]) -> Result<Metadata, MetaError> {
    crate::guard("ogg", || {
        let mut meta = Metadata::new(DocFormat::Ogg);
        // concatenate the payload of the first pages: comment packets come second
        let mut payload = Vec::new();
        let mut at = 0;
        for _ in 0..64 {
            if b.get(at..at + 4) != Some(b"OggS") || payload.len() > (1 << 20) {
                break;
            }
            let Some(&nseg) = b.get(at + 26) else { break };
            let segs = b.get(at + 27..at + 27 + nseg as usize).unwrap_or(&[]);
            let len: usize = segs.iter().map(|&s| s as usize).sum();
            let start = at + 27 + nseg as usize;
            let Some(d) = b.get(start..(start + len).min(b.len())) else {
                break;
            };
            payload.extend_from_slice(d);
            at = start + len;
        }
        for (magic, codec) in [
            (&b"\x03vorbis"[..], "Vorbis"),
            (&b"OpusTags"[..], "Opus"),
            (&b"\x81theora"[..], "Theora"),
        ] {
            if let Some(i) = crate::util::find(&payload, magic, 0) {
                meta.fields.insert("ogg:codec".into(), codec.into());
                vorbis_comments(&mut meta, &payload[i + magic.len()..]);
                break;
            }
        }
        Ok(meta)
    })
}

fn vorbis_comments(meta: &mut Metadata, d: &[u8]) {
    let vlen = rd_u32le(d, 0).unwrap_or(0) as usize;
    if let Some(v) = d.get(4..4 + vlen.min(1024)) {
        if let Some(v) = clean_str(&String::from_utf8_lossy(v)) {
            Metadata::add_unique(&mut meta.software, &v);
            meta.fields.insert("vorbis:vendor".into(), v);
        }
    }
    let mut at = 4usize.saturating_add(vlen);
    let n = rd_u32le(d, at).unwrap_or(0).min(512);
    at += 4;
    for _ in 0..n {
        let Some(l) = rd_u32le(d, at).map(|x| x as usize) else {
            break;
        };
        let Some(c) = d.get(at + 4..(at + 4).saturating_add(l)) else {
            break;
        };
        at += 4 + l;
        let c = String::from_utf8_lossy(&c[..c.len().min(4096)]).into_owned();
        let Some((k, v)) = c.split_once('=') else {
            continue;
        };
        let Some(v) = clean_str(v) else { continue };
        let v = truncate(&v, 512);
        let key = k.to_ascii_uppercase();
        match key.as_str() {
            "ARTIST" | "PERFORMER" | "COMPOSER" => {
                meta.add_person(&v, PersonRole::Author, "vorbis:ARTIST");
                meta.author.get_or_insert(v.clone());
            }
            "TITLE" => meta.title = Some(v.clone()),
            "COMMENT" | "DESCRIPTION" => meta.description = Some(v.clone()),
            "DATE" => meta.created = Some(v.clone()),
            "ORGANIZATION" | "LABEL" => meta.company = Some(v.clone()),
            "ENCODER" | "ENCODED_BY" | "ENCODED-BY" => {
                Metadata::add_unique(&mut meta.software, &v);
                meta.application.get_or_insert(v.clone());
            }
            "COPYRIGHT" => {
                meta.custom.insert("copyright".into(), v.clone());
            }
            "METADATA_BLOCK_PICTURE" => continue,
            _ => {}
        }
        if meta.fields.len() < 300 {
            meta.fields
                .insert(format!("vorbis:{}", truncate(&key, 64)), v);
        }
    }
}
