//! Camera RAW files: Canon CR2/CR3/CRW, Olympus ORF, Panasonic RW2/RWL, Fujifilm RAF, Minolta
//! MRW and Sigma X3F, plus the preview JPEGs of TIFF-based RAW (NEF, ARW, DNG, PEF, ...).
//!
//! TIFF variants with their own magic (ORF, RW2) are read by the EXIF parser after the magic is
//! normalised; RAF and RW2 carry a full JPEG with EXIF; CR3 stores TIFF blocks in `CMT1..CMT4`
//! boxes; CRW is a CIFF heap; X3F has a UTF-16 property list. Preview and thumbnail JPEGs are
//! collected and compared (a thumbnail that differs from the preview hints at an edited image).
//! Layouts follow ExifTool `CanonRaw.pm`, `Canon.pm` (CR3), `FujiFilm.pm`, `MinoltaRaw.pm`,
//! `SigmaRaw.pm` and `PanasonicRaw.pm` (GPL-1+/Artistic).

use foca_core::{Camera, DocFormat, Gps, Metadata, PersonRole};

use super::image;
use super::image_extra::{self, Ifd};
use super::previews::{self, MAX_PREVIEW};
use crate::util::{clean_str, rd_u32le, truncate, utf16le};
use crate::{Ctx, MetaError};

/// Canon CR3 metadata box UUID.
const CR3_UUID: [u8; 16] = [
    0x85, 0xC0, 0xB6, 0x87, 0x82, 0x0F, 0x11, 0xE0, 0x81, 0x11, 0xF4, 0xCE, 0x46, 0x2B, 0x6A, 0x48,
];
/// Canon CR3 preview box UUID.
const CR3_PRVW_UUID: [u8; 16] = [
    0xEA, 0xF4, 0x2B, 0x5E, 0x1C, 0x98, 0x4B, 0x88, 0xB9, 0xFB, 0xB7, 0xDC, 0x40, 0x6E, 0x4D, 0x16,
];

/// RAW type by magic bytes (CR3 is recognised by its `ftyp` brand in `isobmff.rs`).
fn raw_type(b: &[u8]) -> Option<&'static str> {
    if b.starts_with(b"II*\0") && b.get(8..10) == Some(b"CR") {
        return Some("CR2");
    }
    if b.starts_with(b"IIRO") || b.starts_with(b"IIRS") || b.starts_with(b"MMOR") {
        return Some("ORF");
    }
    if b.starts_with(b"IIU\0") {
        return Some("RW2");
    }
    if b.starts_with(b"FUJIFILMCCD-RAW") {
        return Some("RAF");
    }
    if b.starts_with(b"\0MRM") {
        return Some("MRW");
    }
    if b.starts_with(b"FOVb") {
        return Some("X3F");
    }
    if b.starts_with(b"II\x1a\0\0\0HEAPCCDR") || b.starts_with(b"MM\0\0\0\x1aHEAPCCDR") {
        return Some("CRW");
    }
    if b.get(4..12) == Some(b"ftypcrx ") {
        return Some("CR3");
    }
    None
}

pub(crate) fn is_raw(b: &[u8]) -> bool {
    raw_type(b).is_some()
}

pub fn extract(b: &[u8], ctx: &Ctx) -> Result<Metadata, MetaError> {
    let ty = raw_type(b).unwrap_or("RAW");
    let mut meta = Metadata::new(DocFormat::Raw);
    match ty {
        "CR2" => {
            image::apply_exif_tiff(&mut meta, b.to_vec(), ctx);
        }
        "ORF" | "RW2" => {
            let mut t = b.to_vec();
            if t.starts_with(b"MM") {
                t[2..4].copy_from_slice(&[0, 42]);
            } else {
                t[2..4].copy_from_slice(&[42, 0]);
            }
            image::apply_exif_tiff(&mut meta, t, ctx);
        }
        "RAF" => raf(&mut meta, b, ctx)?,
        "MRW" => mrw(&mut meta, b, ctx),
        "X3F" => x3f(&mut meta, b),
        "CRW" => crw(&mut meta, b),
        "CR3" => cr3(&mut meta, b, ctx),
        _ => {}
    }
    meta.fields.insert("raw:type".into(), ty.into());
    if matches!(ty, "CR2" | "ORF" | "RW2") {
        let mut t = b.to_vec();
        if ty != "CR2" {
            if t.starts_with(b"MM") {
                t[2..4].copy_from_slice(&[0, 42]);
            } else {
                t[2..4].copy_from_slice(&[42, 0]);
            }
        }
        for jpg in previews::tiff_previews(&mut meta, &t) {
            merge_jpeg(&mut meta, jpg, ctx);
        }
    }
    previews::finish_previews(&mut meta);
    image_extra::xmp_devices(&mut meta);
    Ok(meta)
}

/// Fills empty facts of `meta` from the metadata of an embedded JPEG.
fn fill_from(meta: &mut Metadata, m: Metadata) {
    let set = |a: &mut Option<String>, b: Option<String>| {
        if a.is_none() {
            *a = b;
        }
    };
    set(&mut meta.author, m.author);
    set(&mut meta.application, m.application);
    set(&mut meta.created, m.created);
    set(&mut meta.modified, m.modified);
    set(&mut meta.description, m.description);
    set(&mut meta.title, m.title);
    if meta.gps.is_none() {
        meta.gps = m.gps;
    }
    if let Some(c) = m.camera {
        let cam = meta.camera.get_or_insert_with(Camera::default);
        set(&mut cam.make, c.make);
        set(&mut cam.model, c.model);
        set(&mut cam.serial, c.serial);
        set(&mut cam.lens, c.lens);
        set(&mut cam.lens_serial, c.lens_serial);
        set(&mut cam.owner, c.owner);
    }
    if meta.thumbnail.is_none() {
        meta.thumbnail = m.thumbnail;
    }
    for p in m.people {
        meta.add_person(&p.name, p.role, &p.source);
    }
    for s in m.software {
        Metadata::add_unique(&mut meta.software, &s);
    }
    for (k, v) in m.fields {
        meta.fields.entry(k).or_insert(v);
    }
    for (k, v) in m.xmp {
        meta.xmp.entry(k).or_insert(v);
    }
    if meta.xmp_history.is_empty() {
        meta.xmp_history = m.xmp_history;
    }
    if meta.xmp_ids.is_none() {
        meta.xmp_ids = m.xmp_ids;
    }
}

/// Parses an embedded JPEG (preview with EXIF) and merges its facts.
fn merge_jpeg(meta: &mut Metadata, jpg: &[u8], ctx: &Ctx) {
    if !jpg.starts_with(&[0xFF, 0xD8]) {
        return;
    }
    if let Ok(m) = image::extract(jpg, DocFormat::Jpeg, ctx) {
        fill_from(meta, m);
    }
}

fn be32(b: &[u8], o: usize) -> Option<u32> {
    b.get(o..o.checked_add(4)?)
        .map(|s| u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
}

/// RAF: camera model string, then the offset and length of the embedded JPEG (with EXIF and the
/// Fujifilm maker note).
fn raf(meta: &mut Metadata, b: &[u8], ctx: &Ctx) -> Result<(), MetaError> {
    if let Some(m) = b.get(0x1C..0x3C).and_then(|s| {
        let end = s.iter().position(|&c| c == 0).unwrap_or(s.len());
        clean_str(&String::from_utf8_lossy(&s[..end]))
    }) {
        meta.fields.insert("raf:model".into(), m);
    }
    if let Some(v) = b
        .get(0x3C..0x40)
        .and_then(|s| clean_str(&String::from_utf8_lossy(s)))
    {
        meta.fields.insert("raf:version".into(), v);
    }
    let (Some(off), Some(len)) = (be32(b, 84), be32(b, 88)) else {
        return Ok(());
    };
    let (off, len) = (off as usize, (len as usize).min(MAX_PREVIEW));
    if let Some(jpg) = off.checked_add(len).and_then(|e| b.get(off..e)) {
        merge_jpeg(meta, jpg, ctx);
        previews::add_preview(meta, jpg);
    }
    Ok(())
}

/// MRW: `\0MRM` header followed by blocks; `\0TTW` holds a TIFF/EXIF block.
fn mrw(meta: &mut Metadata, b: &[u8], ctx: &Ctx) {
    let end = (be32(b, 4).unwrap_or(0) as usize)
        .saturating_add(8)
        .min(b.len());
    let mut p = 8;
    let mut n = 0;
    while p + 8 <= end && n < 64 {
        n += 1;
        let id = &b[p..p + 4];
        let len = be32(b, p + 4).unwrap_or(0) as usize;
        let s = p + 8;
        let e = s.saturating_add(len).min(b.len());
        if id == b"\0TTW" {
            image::apply_exif_tiff(meta, b[s..e].to_vec(), ctx);
        }
        p = s.saturating_add(len);
    }
}

/// X3F: the directory at the end lists a `PROP` section (UTF-16 name/value pairs) and image
/// sections, one of which may be a JPEG preview.
fn x3f(meta: &mut Metadata, b: &[u8]) {
    let Some(dir) = b.len().checked_sub(4).and_then(|o| rd_u32le(b, o)) else {
        return;
    };
    let dir = dir as usize;
    if b.get(dir..dir + 4) != Some(b"SECd") {
        return;
    }
    let n = rd_u32le(b, dir + 8).unwrap_or(0).min(64) as usize;
    let mut cam = Camera::default();
    for i in 0..n {
        let e = dir + 12 + i * 12;
        let (Some(off), Some(len), Some(kind)) =
            (rd_u32le(b, e), rd_u32le(b, e + 4), b.get(e + 8..e + 12))
        else {
            break;
        };
        let (off, len) = (off as usize, len as usize);
        let Some(sec) = off.checked_add(len).and_then(|x| b.get(off..x)) else {
            continue;
        };
        match kind {
            b"PROP" if sec.starts_with(b"SECp") => {
                let num = rd_u32le(sec, 8).unwrap_or(0).min(512) as usize;
                let chars_at = 24 + num * 8;
                let chars = sec.get(chars_at..).unwrap_or(&[]);
                let text = |o: u32| -> Option<String> {
                    let s = chars.get((o as usize).checked_mul(2)?..)?;
                    let end = s
                        .as_chunks::<2>()
                        .0
                        .iter()
                        .position(|c| c == &[0, 0])
                        .unwrap_or(s.len() / 2);
                    clean_str(&utf16le(&s[..end * 2]))
                };
                for j in 0..num {
                    let (Some(k), Some(v)) = (rd_u32le(sec, 24 + j * 8), rd_u32le(sec, 28 + j * 8))
                    else {
                        break;
                    };
                    let (Some(k), Some(v)) = (text(k), text(v)) else {
                        continue;
                    };
                    let v = truncate(&v, 256);
                    match k.as_str() {
                        "CAMMANUF" => cam.make = Some(v.clone()),
                        "CAMMODEL" => cam.model = Some(v.clone()),
                        "CAMSERIAL" => cam.serial = Some(v.clone()),
                        "LENSMODEL" => cam.lens = Some(v.clone()),
                        "FIRMVERS" => Metadata::add_unique(&mut meta.software, &v),
                        "TIME" => {
                            if let Ok(t) = v.parse::<i64>() {
                                meta.created = crate::util::unix_to_iso(t);
                            }
                        }
                        _ => {}
                    }
                    if meta.fields.len() < 200 {
                        meta.fields.insert(format!("x3f:{}", truncate(&k, 32)), v);
                    }
                }
            }
            b"IMA2" | b"IMAG" if sec.starts_with(b"SECi") && rd_u32le(sec, 12) == Some(18) => {
                if let Some(jpg) = sec.get(28..).filter(|j| j.starts_with(&[0xFF, 0xD8])) {
                    previews::add_preview(meta, &jpg[..jpg.len().min(MAX_PREVIEW)]);
                }
            }
            _ => {}
        }
    }
    if cam != Camera::default() {
        meta.camera = Some(cam);
    }
}

/// CRW (CIFF): heaps of records; strings for make/model, owner, firmware and the original file
/// name, the capture time, and the JPEG thumbnail.
fn crw(meta: &mut Metadata, b: &[u8]) {
    let le = b.starts_with(b"II");
    let ifd = Ifd { base: b, le };
    let hlen = ifd.u32(2).unwrap_or(26) as usize;
    let mut cam = Camera::default();
    let mut stack = vec![(hlen.min(b.len()), b.len(), 0usize)];
    let mut visited = 0;
    while let Some((start, end, depth)) = stack.pop() {
        visited += 1;
        if visited > 64 || end < start + 4 || end > b.len() {
            continue;
        }
        let table = start + ifd.u32(end - 4).unwrap_or(0) as usize;
        let count = ifd.u16(table).unwrap_or(0).min(512) as usize;
        for i in 0..count {
            let e = table + 2 + i * 10;
            let (Some(ty), Some(size), Some(off)) = (ifd.u16(e), ifd.u32(e + 2), ifd.u32(e + 6))
            else {
                break;
            };
            if ty >> 14 != 0 {
                continue; // value stored in the entry itself
            }
            let s = start.saturating_add(off as usize);
            let Some(data) = s
                .checked_add(size as usize)
                .filter(|x| *x <= end)
                .and_then(|x| b.get(s..x))
            else {
                continue;
            };
            let kind = ty & 0x3FFF;
            let text = || {
                let z = data.iter().position(|&c| c == 0).unwrap_or(data.len());
                clean_str(&String::from_utf8_lossy(&data[..z]))
            };
            match kind {
                0x080A => {
                    let mut parts = data
                        .split(|&c| c == 0)
                        .filter_map(|p| clean_str(&String::from_utf8_lossy(p)));
                    cam.make = parts.next();
                    cam.model = parts.next();
                }
                0x0810 => cam.owner = text(),
                0x080B => {
                    if let Some(v) = text() {
                        Metadata::add_unique(&mut meta.software, &v);
                    }
                }
                0x0805 => meta.description = text(),
                0x0816 => {
                    if let Some(v) = text() {
                        meta.fields.insert("crw:OriginalFileName".into(), v);
                    }
                }
                0x180E => {
                    if let Some(t) = ifd.u32_of(data) {
                        meta.created = crate::util::unix_to_iso(i64::from(t));
                    }
                }
                0x2007 => previews::add_preview(meta, &data[..data.len().min(MAX_PREVIEW)]),
                k if matches!(k & 0x3800, 0x2800 | 0x3000) && depth < 4 => {
                    stack.push((s, s + data.len(), depth + 1))
                }
                _ => {}
            }
        }
    }
    if let Some(o) = &cam.owner {
        meta.add_person(o, PersonRole::Owner, "crw:OwnerName");
    }
    if cam != Camera::default() {
        meta.camera = Some(cam);
    }
}

fn rationals(ifd: &Ifd, v: &[u8]) -> Vec<f64> {
    v.as_chunks::<8>()
        .0
        .iter()
        .filter_map(|c| {
            let n = ifd.u32_of(&c[..4])?;
            let d = ifd.u32_of(&c[4..])?;
            (d != 0).then(|| f64::from(n) / f64::from(d))
        })
        .collect()
}

/// CR3 (ISO BMFF): `moov/uuid(Canon)` holds `CMT1` (IFD0), `CMT2` (EXIF IFD), `CMT3` (Canon maker
/// note), `CMT4` (GPS IFD) and `THMB`; a top-level `uuid` holds the `PRVW` preview.
fn cr3(meta: &mut Metadata, b: &[u8], ctx: &Ctx) {
    let mut cmts: Vec<(&[u8], &[u8])> = Vec::new();
    let mut previews: Vec<&[u8]> = Vec::new();
    let mut stack: Vec<(&[u8], usize)> = vec![(b, 0)];
    let mut n = 0;
    while let Some((buf, depth)) = stack.pop() {
        let mut p = 0;
        while p + 8 <= buf.len() && n < 4096 {
            n += 1;
            let size = be32(buf, p).unwrap_or(0) as usize;
            let kind = &buf[p + 4..p + 8];
            let (hdr, size) = match size {
                0 => (8, buf.len() - p),
                1 => {
                    let s = buf
                        .get(p + 8..p + 16)
                        .map(|s| u64::from_be_bytes(s.try_into().unwrap_or([0; 8])));
                    (16, s.unwrap_or(0) as usize)
                }
                s => (8, s),
            };
            if size < hdr || size > buf.len() - p {
                break;
            }
            let body = &buf[p + hdr..p + size];
            match kind {
                b"moov" if depth < 4 => stack.push((body, depth + 1)),
                b"uuid" if body.starts_with(&CR3_UUID) && depth < 4 => {
                    stack.push((&body[16..], depth + 1))
                }
                b"uuid" if body.starts_with(&CR3_PRVW_UUID) => {
                    if let Some(i) = crate::util::find(body, &[0xFF, 0xD8, 0xFF], 16) {
                        previews.push(&body[i..]);
                    }
                }
                b"CMT1" | b"CMT2" | b"CMT3" | b"CMT4" => cmts.push((kind, body)),
                b"THMB" => {
                    if let Some(i) = crate::util::find(body, &[0xFF, 0xD8, 0xFF], 0) {
                        previews.push(&body[i..]);
                    }
                }
                _ => {}
            }
            p += size;
        }
    }
    for (kind, t) in cmts {
        match kind {
            b"CMT1" => {
                image::apply_exif_tiff(meta, t.to_vec(), ctx);
            }
            b"CMT2" => {
                let Some((ifd, at)) = previews::first_ifd(t) else {
                    continue;
                };
                let cam = meta.camera.get_or_insert_with(Camera::default);
                for (tag, _, _, v) in ifd.entries(at) {
                    let s = || clean_str(&String::from_utf8_lossy(v).replace('\0', ""));
                    match tag {
                        0x9003 => {
                            if let Some(d) = s().and_then(|d| crate::util::normalize_date(&d)) {
                                meta.created = Some(d);
                            }
                        }
                        0xA430 => cam.owner = cam.owner.take().or_else(s),
                        0xA431 => cam.serial = cam.serial.take().or_else(s),
                        0xA434 => cam.lens = cam.lens.take().or_else(s),
                        0xA435 => cam.lens_serial = cam.lens_serial.take().or_else(s),
                        _ => {}
                    }
                }
            }
            b"CMT3" => {
                if let Some((ifd, at)) = previews::first_ifd(t) {
                    image_extra::maker_note(meta, "canon", t, at, ifd.le);
                }
            }
            b"CMT4" => {
                let Some((ifd, at)) = previews::first_ifd(t) else {
                    continue;
                };
                let (mut lat, mut lon, mut alt) = (None, None, None);
                let (mut south, mut west, mut below) = (false, false, false);
                for (tag, _, _, v) in ifd.entries(at) {
                    let dms = |v: &[u8]| {
                        let r = rationals(&ifd, v);
                        (r.len() >= 3).then(|| r[0] + r[1] / 60.0 + r[2] / 3600.0)
                    };
                    match tag {
                        1 => south = v.first() == Some(&b'S'),
                        2 => lat = dms(v),
                        3 => west = v.first() == Some(&b'W'),
                        4 => lon = dms(v),
                        5 => below = v.first() == Some(&1),
                        6 => alt = rationals(&ifd, v).first().copied(),
                        _ => {}
                    }
                }
                if let (Some(la), Some(lo)) = (lat, lon) {
                    let la = if south { -la } else { la };
                    let lo = if west { -lo } else { lo };
                    if (-90.0..=90.0).contains(&la)
                        && (-180.0..=180.0).contains(&lo)
                        && !(la == 0.0 && lo == 0.0)
                    {
                        let r = |x: f64| (x * 1e6).round() / 1e6;
                        meta.gps = Some(Gps {
                            lat: r(la),
                            lon: r(lo),
                            alt: alt.map(|a| (if below { -a } else { a } * 100.0).round() / 100.0),
                        });
                    }
                }
            }
            _ => {}
        }
    }
    if meta.camera.as_ref() == Some(&Camera::default()) {
        meta.camera = None;
    }
    if let Some(o) = meta.camera.as_ref().and_then(|c| c.owner.clone()) {
        meta.add_person(&o, PersonRole::Owner, "exif:CameraOwnerName");
    }
    for p in previews {
        previews::add_preview(meta, &p[..p.len().min(MAX_PREVIEW)]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn magic_types() {
        assert_eq!(raw_type(b"IIRO\x08\0\0\0"), Some("ORF"));
        assert_eq!(raw_type(b"IIU\0\x08\0\0\0"), Some("RW2"));
        assert_eq!(raw_type(b"II*\0\x10\0\0\0CR\x02\0"), Some("CR2"));
        assert_eq!(raw_type(b"\0\0\0\x18ftypcrx \0\0\0\x01"), Some("CR3"));
        assert_eq!(raw_type(b"II*\0\x08\0\0\0"), None);
    }

    #[test]
    fn cr3_cmt_boxes() {
        // CMT2 with a body serial and CMT4 with GPS, big-endian TIFF blocks
        fn tiff(entries: &[(u16, u16, u32, Vec<u8>)]) -> Vec<u8> {
            let mut t = b"MM\0\x2A\0\0\0\x08".to_vec();
            let n = entries.len();
            t.extend((n as u16).to_be_bytes());
            let mut data_at = 8 + 2 + n * 12 + 4;
            let mut tail: Vec<u8> = Vec::new();
            for (tag, ty, count, v) in entries {
                t.extend(tag.to_be_bytes());
                t.extend(ty.to_be_bytes());
                t.extend(count.to_be_bytes());
                if v.len() <= 4 {
                    let mut x = v.clone();
                    x.resize(4, 0);
                    t.extend(x);
                } else {
                    t.extend((data_at as u32).to_be_bytes());
                    tail.extend(v);
                    data_at += v.len();
                }
            }
            t.extend([0; 4]);
            t.extend(tail);
            t
        }
        let rat = |vals: &[(u32, u32)]| {
            vals.iter()
                .flat_map(|(a, b)| a.to_be_bytes().into_iter().chain(b.to_be_bytes()))
                .collect::<Vec<u8>>()
        };
        let cmt2 = tiff(&[(0xA431, 2, 10, b"123456789\0".to_vec())]);
        let cmt4 = tiff(&[
            (1, 2, 2, b"N\0".to_vec()),
            (2, 5, 3, rat(&[(50, 1), (27, 1), (0, 1)])),
            (3, 2, 2, b"E\0".to_vec()),
            (4, 5, 3, rat(&[(30, 1), (31, 1), (12, 1)])),
        ]);
        let bx = |k: &[u8], d: &[u8]| {
            let mut v = ((d.len() + 8) as u32).to_be_bytes().to_vec();
            v.extend(k);
            v.extend(d);
            v
        };
        let mut canon = CR3_UUID.to_vec();
        canon.extend(bx(b"CMT2", &cmt2));
        canon.extend(bx(b"CMT4", &cmt4));
        let mut f = bx(b"ftyp", b"crx \0\0\0\x01crx isom");
        f.extend(bx(b"moov", &bx(b"uuid", &canon)));
        let limits = crate::Limits::default();
        let budget = std::cell::Cell::new(limits.max_unzipped_total);
        let ctx = Ctx::standalone(&limits, &budget);
        let m = extract(&f, &ctx).unwrap();
        assert_eq!(m.camera.unwrap().serial.as_deref(), Some("123456789"));
        let g = m.gps.unwrap();
        assert!(
            (g.lat - 50.45).abs() < 1e-6 && (g.lon - 30.52).abs() < 1e-6,
            "{g:?}"
        );
        assert_eq!(m.fields["raw:type"], "CR3");
    }
}
