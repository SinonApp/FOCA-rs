//! ISO base media files (MP4, QuickTime MOV, HEIF/HEIC/AVIF): brand, movie creation and
//! modification times, QuickTime `©xyz` / `com.apple.quicktime.location.ISO6709` GPS,
//! device make/model/software, camera serial numbers, iTunes-style `ilst` tags, XMP
//! (`XMP_` atom, XMP `uuid` box, HEIF `mime` item) and HEIF `Exif` items (through the EXIF
//! parser of `image.rs`).
//!
//! Box sizes are validated against the enclosing box; nesting and box count are limited.

use foca_core::{Camera, DocFormat, Gps, Metadata, PersonRole};

use crate::util::{clean_str, decode_text, truncate, utf16be};
use crate::{xmp, Ctx, MetaError};

/// Maximum box nesting.
const MAX_BOX_DEPTH: usize = 16;
/// Maximum size of an item (EXIF/XMP) copied out of a HEIF file.
const MAX_ITEM: usize = 4 << 20;
/// Mac OS Roman, bytes 0x80..=0xFF (legacy QuickTime text with a Macintosh language code).
pub(crate) const MAC_ROMAN: &str = "ÄÅÇÉÑÖÜáàâäãåçéèêëíìîïñóòôöõúùûü†°¢£§•¶ß®©™´¨≠ÆØ∞±≤≥¥µ∂∑∏π∫ªºΩæø¿¡¬√ƒ≈∆«»…\u{a0}ÀÃÕŒœ\u{2013}\u{2014}“”‘’÷◊ÿŸ⁄€‹›ﬁﬂ‡·‚„‰ÂÊÁËÈÍÎÏÌÓÔ\u{f8ff}ÒÚÛÙıˆ˜¯˘˙˚¸˝˛ˇ";

/// Decodes QuickTime international text: UTF-8 when valid, otherwise Mac OS Roman.
fn qt_text(b: &[u8]) -> String {
    if let Ok(s) = std::str::from_utf8(b) {
        return s.to_string();
    }
    let table: Vec<char> = MAC_ROMAN.chars().collect();
    b.iter()
        .map(|&c| {
            if c < 0x80 {
                c as char
            } else {
                table.get(usize::from(c - 0x80)).copied().unwrap_or('?')
            }
        })
        .collect()
}

/// Seconds between 1904-01-01 and 1970-01-01.
const MAC_EPOCH: u64 = 2_082_844_800;

const XMP_UUID: [u8; 16] = [
    0xBE, 0x7A, 0xCF, 0xCB, 0x97, 0xA9, 0x42, 0xE8, 0x9C, 0x71, 0x99, 0x94, 0x91, 0xE3, 0xAF, 0xAC,
];

fn be16(b: &[u8], off: usize) -> Option<u16> {
    b.get(off..off.checked_add(2)?)
        .map(|s| u16::from_be_bytes([s[0], s[1]]))
}

fn be32(b: &[u8], off: usize) -> Option<u32> {
    b.get(off..off.checked_add(4)?)
        .map(|s| u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
}

fn be64(b: &[u8], off: usize) -> Option<u64> {
    let s = b.get(off..off.checked_add(8)?)?;
    let mut a = [0u8; 8];
    a.copy_from_slice(s);
    Some(u64::from_be_bytes(a))
}

/// Reads a big-endian unsigned integer of `n` bytes (0, 4 or 8).
fn be_n(b: &[u8], off: usize, n: usize) -> Option<u64> {
    match n {
        0 => Some(0),
        2 => be16(b, off).map(u64::from),
        4 => be32(b, off).map(u64::from),
        8 => be64(b, off),
        _ => None,
    }
}

/// A box: type and payload (after the header).
struct BoxRef<'a> {
    kind: [u8; 4],
    body: &'a [u8],
    /// Offset of the payload in the whole file.
    start: usize,
}

/// Iterates over the boxes in `b` (`base` = offset of `b` in the file).
fn boxes(b: &[u8], base: usize) -> Vec<BoxRef<'_>> {
    let mut out = Vec::new();
    let mut off = 0usize;
    while off + 8 <= b.len() && out.len() < 4096 {
        let Some(size32) = be32(b, off) else { break };
        let mut kind = [0u8; 4];
        kind.copy_from_slice(&b[off + 4..off + 8]);
        let (hdr, size) = match size32 {
            0 => (8usize, (b.len() - off) as u64),
            1 => match be64(b, off + 8) {
                Some(s) => (16, s),
                None => break,
            },
            s => (8, u64::from(s)),
        };
        if size < hdr as u64 || size > (b.len() - off) as u64 {
            break;
        }
        let size = size as usize;
        out.push(BoxRef {
            kind,
            body: &b[off + hdr..off + size],
            start: base + off + hdr,
        });
        off += size;
    }
    out
}

struct State<'c, 'a, 'f> {
    ctx: &'c Ctx<'a>,
    /// The whole file (HEIF item offsets are absolute).
    file: &'f [u8],
    boxes: usize,
    cam: Camera,
    gps: Option<Gps>,
    /// `mdta` key names from `keys`, 1-based.
    keys: Vec<String>,
    xmp_seen: bool,
}

fn mac_time(secs: u64) -> Option<String> {
    let unix = secs.checked_sub(MAC_EPOCH)?;
    if !(315_532_800..=4_102_444_800).contains(&unix) {
        return None;
    }
    let dt = time::OffsetDateTime::from_unix_timestamp(unix as i64).ok()?;
    dt.format(&time::format_description::well_known::Rfc3339)
        .ok()
}

/// Parses an ISO 6709 string such as `+50.4501+030.5234+157.000/`.
pub(crate) fn iso6709(s: &str) -> Option<Gps> {
    let s = s.trim().trim_end_matches('/');
    let mut nums = Vec::new();
    let mut cur = String::new();
    for c in s.chars() {
        if (c == '+' || c == '-') && !cur.is_empty() {
            nums.push(std::mem::take(&mut cur));
        }
        if !(c.is_ascii_digit() || matches!(c, '+' | '-' | '.')) {
            break;
        }
        cur.push(c);
        if nums.len() >= 3 {
            break;
        }
    }
    if !cur.is_empty() && nums.len() < 3 {
        nums.push(cur);
    }
    let lat: f64 = nums.first()?.parse().ok()?;
    let lon: f64 = nums.get(1)?.parse().ok()?;
    if !(-90.0..=90.0).contains(&lat)
        || !(-180.0..=180.0).contains(&lon)
        || (lat == 0.0 && lon == 0.0)
    {
        return None;
    }
    let alt = nums.get(2).and_then(|a| a.parse().ok());
    Some(Gps { lat, lon, alt })
}

fn text_value(meta: &mut Metadata, st: &mut State, key: &str, value: String) {
    let Some(v) = clean_str(&value) else { return };
    let v = truncate(&v, 1024);
    let k = key.to_ascii_lowercase();
    let k = k.trim_start_matches("com.apple.quicktime.");
    match k {
        "©xyz" | "location.iso6709" | "©loc" => {
            if st.gps.is_none() {
                st.gps = iso6709(&v);
            }
        }
        "©mak" | "make" => {
            st.cam.make.get_or_insert(v.clone());
        }
        "©mod" | "model" => {
            st.cam.model.get_or_insert(v.clone());
        }
        "©swr" | "software" | "©too" | "©enc" => {
            meta.application.get_or_insert(v.clone());
            Metadata::add_unique(&mut meta.software, &v);
        }
        "©day" | "creationdate" => {
            if let Some(d) = crate::util::normalize_date(&v) {
                meta.fields.insert("media:creation_date".into(), d);
            }
        }
        "©nam" | "title" | "displayname" => {
            meta.title.get_or_insert(v.clone());
        }
        "©art" | "©aut" | "artist" | "author" => {
            meta.author.get_or_insert(v.clone());
            meta.add_person(&v, PersonRole::Author, &format!("media:{key}"));
        }
        "©cmt" | "©des" | "©inf" | "description" | "comment" => {
            meta.description.get_or_insert(v.clone());
        }
        "cprt" | "©cpy" | "copyright" => {
            meta.add_person(&v, PersonRole::Owner, &format!("media:{key}"));
        }
        "©snm" | "serialnumber" | "camera.serialnumber" | "came" => {
            st.cam.serial.get_or_insert(v.clone());
        }
        "lens" | "camera.lens_model" | "©lns" => {
            st.cam.lens.get_or_insert(v.clone());
        }
        _ => {}
    }
    if k.contains("serial") {
        st.cam.serial.get_or_insert(v.clone());
    }
    let shown: String = key
        .chars()
        .map(|c| if c == '\u{a9}' { '@' } else { c })
        .collect();
    meta.fields.entry(format!("media:{shown}")).or_insert(v);
}

/// Decodes the value of an `ilst` `data` box.
fn data_box_value(body: &[u8]) -> Option<String> {
    let ty = be32(body, 0)? & 0x00FF_FFFF;
    let v = body.get(8..)?;
    match ty {
        1 | 4 => Some(String::from_utf8_lossy(v).into_owned()),
        2 | 5 => Some(utf16be(v)),
        21 | 22 => match v.len() {
            1 => Some(v[0].to_string()),
            2 => be16(v, 0).map(|x| x.to_string()),
            4 => be32(v, 0).map(|x| x.to_string()),
            8 => be64(v, 0).map(|x| x.to_string()),
            _ => None,
        },
        _ => None,
    }
}

fn kind_str(k: &[u8; 4]) -> String {
    k.iter()
        .map(|&c| {
            if c == 0xA9 {
                '\u{a9}'
            } else if c.is_ascii_graphic() || c == b' ' {
                c as char
            } else {
                '?'
            }
        })
        .collect()
}

fn walk(
    meta: &mut Metadata,
    st: &mut State,
    b: &[u8],
    base: usize,
    depth: usize,
    parent: &[u8; 4],
) -> Result<(), MetaError> {
    if depth > MAX_BOX_DEPTH {
        meta.warnings.push("ISOBMFF: boxes nested too deep".into());
        return Ok(());
    }
    for bx in boxes(b, base) {
        st.boxes += 1;
        if st.boxes > st.ctx.max_entries() {
            return Err(MetaError::TooManyEntries("ISOBMFF: too many boxes".into()));
        }
        match &bx.kind {
            b"moov" | b"trak" | b"mdia" | b"minf" | b"stbl" | b"udta" | b"edts" | b"tapt" => {
                walk(meta, st, bx.body, bx.start, depth + 1, &bx.kind)?;
            }
            b"meta" => {
                // ISO `meta` is a full box; the QuickTime one is not
                let skip = if be32(bx.body, 0) == Some(0) { 4 } else { 0 };
                if let Some(inner) = bx.body.get(skip..) {
                    if parent == b"file" {
                        heif_meta(meta, st, inner, bx.start + skip)?;
                    } else {
                        walk(meta, st, inner, bx.start + skip, depth + 1, &bx.kind)?;
                    }
                }
            }
            b"keys" => {
                let n = be32(bx.body, 4).unwrap_or(0) as usize;
                let mut off = 8;
                for _ in 0..n.min(1024) {
                    let Some(sz) = be32(bx.body, off).map(|v| v as usize) else {
                        break;
                    };
                    if sz < 8 {
                        break;
                    }
                    let Some(name) = bx.body.get(off + 8..off + sz) else {
                        break;
                    };
                    st.keys.push(String::from_utf8_lossy(name).into_owned());
                    off += sz;
                }
            }
            b"ilst" => {
                for item in boxes(bx.body, bx.start) {
                    let key = match be32(&item.kind, 0) {
                        Some(i) if item.kind[0] == 0 && i >= 1 => st
                            .keys
                            .get(i as usize - 1)
                            .cloned()
                            .unwrap_or_else(|| format!("key{i}")),
                        _ => kind_str(&item.kind),
                    };
                    if let Some(d) = boxes(item.body, item.start)
                        .into_iter()
                        .find(|x| &x.kind == b"data")
                    {
                        if let Some(v) = data_box_value(d.body) {
                            text_value(meta, st, &key, v);
                        }
                    }
                }
            }
            b"mvhd" => {
                let v = bx.body.first().copied().unwrap_or(0);
                let (c, m) = if v == 1 {
                    (be64(bx.body, 4), be64(bx.body, 12))
                } else {
                    (
                        be32(bx.body, 4).map(u64::from),
                        be32(bx.body, 8).map(u64::from),
                    )
                };
                if meta.created.is_none() {
                    meta.created = c.and_then(mac_time);
                }
                if meta.modified.is_none() {
                    meta.modified = m.and_then(mac_time);
                }
                let (scale, dur) = if v == 1 {
                    (be32(bx.body, 20), be64(bx.body, 24))
                } else {
                    (be32(bx.body, 12), be32(bx.body, 16).map(u64::from))
                };
                if let (Some(s), Some(d)) = (scale, dur) {
                    if s > 0 {
                        meta.stats.insert("duration_secs".into(), d / u64::from(s));
                    }
                }
            }
            b"hdlr" if parent == b"mdia" => {
                if let Some(h) = bx.body.get(8..12) {
                    let key = match h {
                        b"vide" => Some("video_tracks"),
                        b"soun" => Some("audio_tracks"),
                        _ => None,
                    };
                    if let Some(k) = key {
                        *meta.stats.entry(k.into()).or_insert(0) += 1;
                    }
                }
                // handler name (`Core Media Video`, `GoPro AVC`, `DJI.AVC`, ...)
                if let Some(n) = bx.body.get(24..).and_then(handler_name) {
                    let k = "media:handler_names".to_string();
                    let cur = meta.fields.entry(k).or_default();
                    if !cur.split("; ").any(|x| x == n) && cur.len() < 512 {
                        if !cur.is_empty() {
                            cur.push_str("; ");
                        }
                        cur.push_str(&truncate(&n, 64));
                    }
                }
            }
            b"stsd" => sample_entries(meta, bx.body),
            b"XMP_" => apply_xmp(meta, st, bx.body),
            b"uuid" if bx.body.starts_with(&XMP_UUID) => {
                apply_xmp(meta, st, bx.body.get(16..).unwrap_or(&[]));
            }
            k if parent == b"udta" && k[0] == 0xA9 => {
                // QuickTime international text: u16 size, u16 language, text
                let key = kind_str(k);
                let s = be16(bx.body, 0).map(usize::from);
                match s.and_then(|s| bx.body.get(4..4 + s)) {
                    Some(t) if !t.is_empty() => text_value(meta, st, &key, qt_text(t)),
                    _ => {
                        if let Some(d) = boxes(bx.body, bx.start)
                            .into_iter()
                            .find(|x| &x.kind == b"data")
                        {
                            if let Some(v) = data_box_value(d.body) {
                                text_value(meta, st, &key, v);
                            }
                        } else if !bx.body.is_empty() {
                            text_value(meta, st, &key, decode_text(bx.body));
                        }
                    }
                }
            }
            // GoPro / camera vendor atoms in udta
            b"FIRM" | b"LENS" | b"CAME" | b"MUID" | b"cprt" if parent == b"udta" => {
                let key = kind_str(&bx.kind);
                let v = if &bx.kind == b"CAME" || &bx.kind == b"MUID" {
                    bx.body
                        .iter()
                        .map(|x| format!("{x:02x}"))
                        .collect::<String>()
                } else {
                    decode_text(bx.body)
                };
                text_value(meta, st, &key, truncate(&v, 256));
            }
            _ => {}
        }
    }
    Ok(())
}

/// `hdlr` name: a Pascal string in QuickTime, a C string in MP4.
fn handler_name(raw: &[u8]) -> Option<String> {
    let l = usize::from(*raw.first()?);
    let s = if l > 0 && l + 1 <= raw.len() && raw.len() <= l + 2 {
        &raw[1..1 + l]
    } else {
        raw
    };
    clean_str(&qt_text(s).replace('\0', ""))
}

/// Video sample entries: the 32-byte compressor name (`Lavc61.19.101 libx264`, `Photo - JPEG`).
fn sample_entries(meta: &mut Metadata, b: &[u8]) {
    let n = be32(b, 4).unwrap_or(0).min(16);
    let mut p = 8usize;
    for _ in 0..n {
        let Some(size) = be32(b, p).map(|s| s as usize) else {
            break;
        };
        if size < 8 {
            break;
        }
        if size >= 86 {
            if let Some(name) = b.get(p + 50..p + 82) {
                let len = usize::from(name[0]).min(31);
                if let Some(v) = clean_str(&qt_text(&name[1..1 + len])) {
                    if v.bytes().any(|c| c.is_ascii_digit()) || v.contains("Lavc") {
                        Metadata::add_unique(&mut meta.software, &v);
                    }
                    meta.fields.entry("media:compressor".into()).or_insert(v);
                }
            }
        }
        p = p.saturating_add(size);
    }
}

fn apply_xmp(meta: &mut Metadata, st: &mut State, b: &[u8]) {
    let b = &b[..b.len().min(MAX_ITEM)];
    let map = xmp::parse(b, st.ctx);
    if !map.is_empty() {
        st.xmp_seen = true;
        xmp::apply(meta, &map, "xmp");
    }
}

/// HEIF item location: `(item id, construction method, extents)`.
type Loc = (u32, u16, Vec<(u64, u64)>);

fn parse_iloc(b: &[u8]) -> Vec<Loc> {
    let mut out = Vec::new();
    let Some(&ver) = b.first() else { return out };
    let (Some(&s1), Some(&s2)) = (b.get(4), b.get(5)) else {
        return out;
    };
    let (off_size, len_size) = (usize::from(s1 >> 4), usize::from(s1 & 0xF));
    let base_size = usize::from(s2 >> 4);
    let idx_size = if ver >= 1 { usize::from(s2 & 0xF) } else { 0 };
    let mut p = 6;
    let count = if ver < 2 {
        let c = be16(b, p).map(u32::from);
        p += 2;
        c
    } else {
        let c = be32(b, p);
        p += 4;
        c
    };
    let Some(count) = count else { return out };
    for _ in 0..count.min(4096) {
        let id = if ver < 2 {
            let v = be16(b, p).map(u32::from);
            p += 2;
            v
        } else {
            let v = be32(b, p);
            p += 4;
            v
        };
        let Some(id) = id else { return out };
        let mut method = 0;
        if ver >= 1 {
            let Some(m) = be16(b, p) else { return out };
            method = m & 0xF;
            p += 2;
        }
        p += 2; // data_reference_index
        let Some(base) = be_n(b, p, base_size) else {
            return out;
        };
        p += base_size;
        let Some(n) = be16(b, p) else { return out };
        p += 2;
        let mut ext = Vec::new();
        for _ in 0..n.min(256) {
            p += idx_size;
            let (Some(o), Some(l)) = (be_n(b, p, off_size), be_n(b, p + off_size, len_size)) else {
                return out;
            };
            p += off_size + len_size;
            ext.push((base.saturating_add(o), l));
        }
        out.push((id, method, ext));
    }
    out
}

/// Parses `iinf`: `(item id, type, content type)`.
fn parse_iinf(b: &[u8], base: usize) -> Vec<(u32, [u8; 4], String)> {
    let mut out = Vec::new();
    let ver = b.first().copied().unwrap_or(0);
    let skip = if ver == 0 { 6 } else { 8 };
    for e in boxes(b.get(skip..).unwrap_or(&[]), base + skip) {
        if &e.kind != b"infe" {
            continue;
        }
        let v = e.body.first().copied().unwrap_or(0);
        if v < 2 {
            continue;
        }
        let (id, p) = if v == 2 {
            (be16(e.body, 4).map(u32::from), 6)
        } else {
            (be32(e.body, 4), 8)
        };
        let Some(id) = id else { continue };
        let p = p + 2; // protection index
        let Some(t) = e.body.get(p..p + 4) else {
            continue;
        };
        let mut kind = [0u8; 4];
        kind.copy_from_slice(t);
        // item_name\0 [content_type\0]
        let rest = e.body.get(p + 4..).unwrap_or(&[]);
        let mut parts = rest.split(|&c| c == 0);
        let _name = parts.next();
        let ctype = parts
            .next()
            .map(|c| String::from_utf8_lossy(c).into_owned())
            .unwrap_or_default();
        out.push((id, kind, ctype));
    }
    out
}

fn item_bytes(
    file: &[u8],
    idat: Option<&BoxRef>,
    method: u16,
    ext: &[(u64, u64)],
) -> Option<Vec<u8>> {
    let src: &[u8] = match method {
        0 => file,
        1 => idat?.body,
        _ => return None,
    };
    let mut out = Vec::new();
    for &(o, l) in ext {
        let o = usize::try_from(o).ok()?;
        let l = if l == 0 {
            src.len().checked_sub(o)?
        } else {
            usize::try_from(l).ok()?
        };
        if out.len().saturating_add(l) > MAX_ITEM {
            return None;
        }
        out.extend_from_slice(src.get(o..o.checked_add(l)?)?);
    }
    Some(out)
}

fn heif_meta(meta: &mut Metadata, st: &mut State, b: &[u8], base: usize) -> Result<(), MetaError> {
    let list = boxes(b, base);
    st.boxes += list.len();
    let mut items = Vec::new();
    let mut locs = Vec::new();
    let mut idat = None;
    for bx in &list {
        match &bx.kind {
            b"iinf" => items = parse_iinf(bx.body, bx.start),
            b"iloc" => locs = parse_iloc(bx.body),
            b"idat" => idat = Some(bx),
            b"iprp" => {
                for c in boxes(bx.body, bx.start) {
                    if &c.kind != b"ipco" {
                        continue;
                    }
                    for p in boxes(c.body, c.start) {
                        if &p.kind == b"colr" && matches!(p.body.get(0..4), Some(b"prof" | b"rICC"))
                        {
                            super::image_extra::icc(meta, &p.body[4..]);
                        }
                    }
                }
            }
            b"hdlr" => {
                if let Some(h) = bx.body.get(8..12) {
                    meta.fields
                        .insert("media:handler".into(), kind_str(&[h[0], h[1], h[2], h[3]]));
                }
            }
            _ => {}
        }
    }
    meta.stats.insert("items".into(), items.len() as u64);
    let file = st.file;
    for (id, kind, ctype) in &items {
        let is_exif = kind == b"Exif";
        let is_xmp = kind == b"mime" && ctype.contains("rdf+xml");
        if !is_exif && !is_xmp {
            continue;
        }
        let Some((_, method, ext)) = locs.iter().find(|(i, _, _)| i == id) else {
            continue;
        };
        let Some(data) = item_bytes(file, idat, *method, ext) else {
            meta.warnings.push(format!("HEIF: item {id} out of bounds"));
            continue;
        };
        if is_exif {
            let off = be32(&data, 0).unwrap_or(0) as usize;
            let tiff = data.get(4usize.saturating_add(off)..).unwrap_or(&[]);
            let tiff = tiff.strip_prefix(b"Exif\0\0").unwrap_or(tiff);
            if !crate::formats::media::image::apply_exif_tiff(meta, tiff.to_vec(), st.ctx) {
                meta.warnings.push("HEIF: EXIF not parsed".into());
            }
        } else {
            apply_xmp(meta, st, &data);
        }
    }
    Ok(())
}

/// Returns the format for an `ftyp` major brand and its compatible brands.
pub(crate) fn brand_format(b: &[u8]) -> Option<DocFormat> {
    if b.get(4..8)? != b"ftyp" {
        return None;
    }
    let size = be32(b, 0)? as usize;
    let major = b.get(8..12)?;
    let compat = b.get(16..size.min(b.len()).max(16)).unwrap_or(&[]);
    let heif = |x: &[u8]| {
        matches!(
            x,
            b"heic"
                | b"heix"
                | b"heim"
                | b"heis"
                | b"hevc"
                | b"hevx"
                | b"mif1"
                | b"msf1"
                | b"avif"
                | b"avis"
                | b"mif2"
        )
    };
    if major == b"qt  " {
        return Some(DocFormat::Mov);
    }
    if heif(major) {
        return Some(DocFormat::Heic);
    }
    let compat_brands: Vec<&[u8]> = compat.as_chunks::<4>().0.iter().map(|c| &c[..]).collect();
    if compat_brands.iter().any(|c| heif(c))
        && !compat_brands
            .iter()
            .any(|c| matches!(*c, b"isom" | b"mp41" | b"mp42"))
    {
        return Some(DocFormat::Heic);
    }
    Some(DocFormat::Mp4)
}

pub fn extract(b: &[u8], format: DocFormat, ctx: &Ctx) -> Result<Metadata, MetaError> {
    let mut meta = Metadata::new(format);
    if let Some(major) = b.get(8..12).filter(|_| b.get(4..8) == Some(b"ftyp")) {
        meta.fields.insert(
            "media:major_brand".into(),
            kind_str(&[major[0], major[1], major[2], major[3]]),
        );
    }
    let mut st = State {
        ctx,
        boxes: 0,
        cam: Camera::default(),
        gps: None,
        keys: Vec::new(),
        xmp_seen: false,
        file: b,
    };
    walk(&mut meta, &mut st, b, 0, 0, b"file")?;
    if st.boxes == 0 {
        return Err(MetaError::malformed("isobmff", "no boxes"));
    }
    if meta.gps.is_none() {
        meta.gps = st.gps;
    }
    super::image_extra::xmp_devices(&mut meta);
    if st.cam != Camera::default() {
        let cam = meta.camera.get_or_insert_with(Camera::default);
        cam.make = cam.make.take().or(st.cam.make);
        cam.model = cam.model.take().or(st.cam.model);
        cam.serial = cam.serial.take().or(st.cam.serial);
        cam.lens = cam.lens.take().or(st.cam.lens);
    }
    Ok(meta)
}

/// Cleans identifying metadata from an ISO-BMFF / QuickTime / HEIF container (`Mp4`, `Mov`, `Heic`)
/// in place without shifting any `mdat` chunk offsets (`stco` / `co64` remain 100% valid):
/// - zeroes creation and modification timestamps in `mvhd`, `tkhd`, `mdhd`;
/// - converts `udta`, `XMP_`, `uuid(XMP_UUID)` and movie-level `meta` boxes into `free` padding
///   boxes of the exact same byte size with zeroed bodies;
/// - in HEIF/HEIC top-level `meta`: wipes `Exif` and `mime` (`rdf+xml`) item payloads and marks
///   their `infe` entries as `free`.
pub(crate) fn clean_isobmff(bytes: &[u8]) -> Result<Vec<u8>, MetaError> {
    let mut out = bytes.to_vec();
    clean_boxes_in_place(&mut out, 0, bytes.len(), b"file", 0);
    Ok(out)
}

fn clean_boxes_in_place(buf: &mut [u8], start: usize, end: usize, parent: &[u8; 4], depth: usize) {
    if depth > MAX_BOX_DEPTH || start >= end || end > buf.len() {
        return;
    }
    let mut off = start;
    while off + 8 <= end {
        let Some(size32) = be32(buf, off) else { break };
        let mut kind = [0u8; 4];
        kind.copy_from_slice(&buf[off + 4..off + 8]);
        let (hdr, size64) = match size32 {
            0 => (8usize, (end - off) as u64),
            1 => match be64(buf, off + 8) {
                Some(s) => (16usize, s),
                None => break,
            },
            s => (8usize, u64::from(s)),
        };
        if size64 < hdr as u64 || size64 > (end - off) as u64 {
            break;
        }
        let size = size64 as usize;
        let body_start = off + hdr;
        let box_end = off + size;

        match &kind {
            b"udta" | b"XMP_" => {
                buf[off + 4..off + 8].copy_from_slice(b"free");
                buf[body_start..box_end].fill(0);
            }
            b"uuid" if buf.get(body_start..body_start + 16) == Some(&XMP_UUID) => {
                buf[off + 4..off + 8].copy_from_slice(b"free");
                buf[body_start..box_end].fill(0);
            }
            b"meta" if parent != b"file" => {
                buf[off + 4..off + 8].copy_from_slice(b"free");
                buf[body_start..box_end].fill(0);
            }
            b"meta" if parent == b"file" => {
                // HEIF/HEIC top-level meta box (FullBox: 4-byte version/flags header)
                if body_start + 4 < box_end {
                    clean_heif_top_meta(buf, body_start + 4, box_end);
                }
            }
            b"mvhd" | b"tkhd" | b"mdhd" => {
                if body_start < box_end {
                    let v = buf[body_start];
                    let ts_end = if v == 1 {
                        body_start + 20
                    } else {
                        body_start + 12
                    };
                    if ts_end <= box_end {
                        buf[body_start + 4..ts_end].fill(0);
                    }
                }
            }
            b"moov" | b"trak" | b"mdia" | b"minf" | b"stbl" | b"edts" => {
                clean_boxes_in_place(buf, body_start, box_end, &kind, depth + 1);
            }
            _ => {}
        }
        off = box_end;
    }
}

fn clean_heif_top_meta(buf: &mut [u8], meta_start: usize, meta_end: usize) {
    // Parse items and locations from immutable snapshot first
    let snap = buf[meta_start..meta_end].to_vec();
    let list = boxes(&snap, meta_start);
    let mut items = Vec::new();
    let mut locs = Vec::new();
    let mut idat_range: Option<(usize, usize)> = None;
    let mut iinf_range: Option<(usize, usize)> = None;
    for bx in &list {
        match &bx.kind {
            b"iinf" => {
                items = parse_iinf(bx.body, bx.start);
                iinf_range = Some((bx.start, bx.start + bx.body.len()));
            }
            b"iloc" => locs = parse_iloc(bx.body),
            b"idat" => idat_range = Some((bx.start, bx.start + bx.body.len())),
            _ => {}
        }
    }
    for (id, kind, ctype) in &items {
        let is_exif = kind == b"Exif";
        let is_xmp = kind == b"mime" && ctype.contains("rdf+xml");
        if !is_exif && !is_xmp {
            continue;
        }
        if let Some((_, method, ext)) = locs.iter().find(|(i, _, _)| i == id) {
            for &(o, l) in ext {
                let Ok(o) = usize::try_from(o) else { continue };
                let Ok(l) = usize::try_from(l) else { continue };
                match method {
                    0 => {
                        let s = o.min(buf.len());
                        let e = o.saturating_add(l).min(buf.len());
                        buf[s..e].fill(0);
                    }
                    1 => {
                        if let Some((is, ie)) = idat_range {
                            let s = is.saturating_add(o).min(ie);
                            let e = is.saturating_add(o).saturating_add(l).min(ie);
                            buf[s..e].fill(0);
                        }
                    }
                    _ => {}
                }
            }
        }
    }
    // Neutralize `Exif` and `mime` item types inside `iinf` so `heif_meta` skips them.
    if let Some((is, ie)) = iinf_range {
        let slice = &mut buf[is..ie];
        for pat in [*b"Exif", *b"mime"] {
            let mut p = 0;
            while p + 4 <= slice.len() {
                if slice[p..p + 4] == pat {
                    slice[p..p + 4].copy_from_slice(b"free");
                    p += 4;
                } else {
                    p += 1;
                }
            }
        }
    }
}
