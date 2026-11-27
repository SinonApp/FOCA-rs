//! Embedded content of OLE2 documents: OLE objects in `ObjectPool`/`MBD*` storages (whole
//! Word/Excel/PowerPoint documents, `Package` OOXML parts, `CONTENTS` and `EmbeddedOdf`
//! payloads) parsed recursively, OfficeArt pictures (BLIP records in the Word `Data` stream,
//! the PowerPoint `Pictures` stream and the Excel drawing group) with their EXIF, and the
//! `\x01CompObj` user type (localized product name such as `Microsoft Word-Dokument`).
//!
//! Object layout follows MS-OLEDS and oletools oleobj (BSD-2); BLIP records follow MS-ODRAW
//! and Apache POI `EscherBlipRecord` (Apache-2.0).

use std::collections::HashSet;
use std::io::{Cursor, Read, Seek, Write};

use foca_core::{Attachment, DocFormat, Metadata};

use super::read_stream;
use crate::util::{clean_str, decode_codepage, rd_u16le, rd_u32le, truncate, utf16le};
use crate::{Ctx, MetaError, MAX_CHILDREN};

const MAX_ATTACHMENTS: usize = 500;
const MAX_BLIPS: usize = 500;

/// Streams whose presence makes a storage a complete document of its own.
const DOC_STREAMS: [&str; 5] = [
    "WordDocument",
    "Workbook",
    "Book",
    "PowerPoint Document",
    "VisioDocument",
];

/// A storage path and its direct children (`name`, `is_stream`, `len`).
type Storage<'a> = (&'a str, Vec<(&'a str, bool, u64)>);

/// Groups the walked entries into storages with their direct children.
fn storages(entries: &[(String, bool, u64)]) -> Vec<Storage<'_>> {
    let mut out: Vec<Storage<'_>> = vec![("", Vec::new())];
    for (p, is_stream, _) in entries {
        if !*is_stream && p != "/" && !p.is_empty() {
            out.push((p.as_str(), Vec::new()));
        }
    }
    for (p, is_stream, len) in entries {
        let Some((parent, name)) = p.rsplit_once('/') else {
            continue;
        };
        if name.is_empty() {
            continue;
        }
        if let Some(s) = out.iter_mut().find(|(sp, _)| *sp == parent) {
            s.1.push((name, *is_stream, *len));
        }
    }
    out
}

/// Whether a storage holds an embedded object (`/ObjectPool/_123`, `/MBD0001A2B3`, nested
/// `_123` storages of an object pool).
fn is_object_storage(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    let name = lower.rsplit('/').next().unwrap_or("");
    lower.starts_with("/objectpool/") && path.matches('/').count() == 2
        || (name.starts_with("mbd") && path.matches('/').count() == 1)
}

/// Parses the embedded objects of an OLE2 file and attaches them to `meta`.
pub(crate) fn embedded_objects<F: Read + Seek>(
    meta: &mut Metadata,
    cf: &mut cfb::CompoundFile<F>,
    entries: &[(String, bool, u64)],
    format: DocFormat,
    ctx: &Ctx,
) -> Result<(), MetaError> {
    for (path, children) in storages(entries) {
        let root = path.is_empty();
        if !root && !is_object_storage(path) {
            continue;
        }
        let has = |n: &str| {
            children
                .iter()
                .find(|(c, s, _)| *s && c.eq_ignore_ascii_case(n))
                .map(|(c, _, _)| *c)
        };
        let label = if root {
            "object".to_string()
        } else {
            path.trim_start_matches('/').to_string()
        };
        let before = meta.embedded.len() + meta.attachments.len();
        let mut handled = false;
        if !root {
            if let Some(t) = compobj(cf, &format!("{path}/\u{1}CompObj"), ctx)? {
                meta.fields
                    .insert(format!("ole:object:{label}:type"), truncate(&t, 256));
            }
        }
        // payload streams of OLE objects (also at the root of a standalone oleObject.bin)
        let payload_ok = !root || format == DocFormat::Ole;
        for name in ["Package", "CONTENTS", "EmbeddedOdf"] {
            if !payload_ok {
                break;
            }
            if let Some(n) = has(name) {
                handled = true;
                if meta.embedded.len() >= MAX_CHILDREN {
                    break;
                }
                if let Some(b) = read_stream(cf, &format!("{path}/{n}"), ctx)? {
                    ctx.attach_child(meta, &b, &format!("{label}/{n}"), &format!("{label}/{n}"))?;
                }
            }
        }
        // Ole10Native streams are parsed by the caller's pass
        let handled = handled || has("\u{1}Ole10Native").is_some();
        let is_doc = !root && !handled && DOC_STREAMS.iter().any(|d| has(d).is_some());
        if is_doc && meta.embedded.len() < MAX_CHILDREN && ctx.can_descend() {
            if let Some(b) = storage_to_cfb(cf, path, entries, ctx)? {
                ctx.attach_child(meta, &b, &label, &label)?;
            }
        }

        if !root
            && meta.embedded.len() + meta.attachments.len() == before
            && meta.attachments.len() < MAX_ATTACHMENTS
        {
            let size = children.iter().filter(|c| c.1).map(|c| c.2).sum();
            meta.attachments.push(Attachment {
                name: label,
                size: Some(size),
                mime: None,
            });
        }
    }
    Ok(())
}

/// Copies one storage with all its streams into a new compound file, so that an embedded
/// document can be parsed like a standalone file. Reads are charged to the shared budget.
fn storage_to_cfb<F: Read + Seek>(
    cf: &mut cfb::CompoundFile<F>,
    root: &str,
    entries: &[(String, bool, u64)],
    ctx: &Ctx,
) -> Result<Option<Vec<u8>>, MetaError> {
    let Ok(mut out) = cfb::CompoundFile::create(Cursor::new(Vec::new())) else {
        return Ok(None);
    };
    if let Ok(e) = cf.entry(root) {
        let _ = out.set_storage_clsid("/", *e.clsid());
    }
    let prefix = format!("{root}/");
    for (p, is_stream, _) in entries.iter().filter(|(p, ..)| p.starts_with(&prefix)) {
        let rel = &p[root.len()..];
        if *is_stream {
            let Some(data) = read_stream(cf, p, ctx)? else {
                continue;
            };
            if let Some((parent, _)) = rel.rsplit_once('/') {
                if !parent.is_empty() && out.create_storage_all(parent).is_err() {
                    return Ok(None);
                }
            }
            match out.create_stream(rel) {
                Ok(mut s) => {
                    if s.write_all(&data).is_err() {
                        return Ok(None);
                    }
                }
                Err(_) => return Ok(None),
            }
        } else if out.create_storage_all(rel).is_err() {
            return Ok(None);
        }
    }
    if out.flush().is_err() {
        return Ok(None);
    }
    Ok(Some(out.into_inner().into_inner()))
}

/// User type of a `\x01CompObj` stream (MS-OLEDS CompObjStream): the Unicode user type when
/// present, otherwise the ANSI one, plus the ProgID in parentheses.
pub(crate) fn compobj<F: Read + Seek>(
    cf: &mut cfb::CompoundFile<F>,
    path: &str,
    ctx: &Ctx,
) -> Result<Option<String>, MetaError> {
    let Some(b) = read_stream(cf, path, ctx)? else {
        return Ok(None);
    };
    Ok(parse_compobj(&b, 1252))
}

fn parse_compobj(b: &[u8], cp: u16) -> Option<String> {
    let mut p = 28usize;
    let ansi = |p: &mut usize| -> Option<String> {
        let n = rd_u32le(b, *p)? as usize;
        if n > 4096 {
            return None;
        }
        let raw = b.get(*p + 4..*p + 4 + n)?;
        *p += 4 + n;
        Some(decode_codepage(
            raw.split(|c| *c == 0).next().unwrap_or(raw),
            cp,
        ))
    };
    let user = ansi(&mut p);
    // clipboard format: 0 = none, 0xFFFFFFFF/0xFFFFFFFE = a format id, else a string
    match rd_u32le(b, p) {
        Some(0) => p += 4,
        Some(0xFFFF_FFFF | 0xFFFF_FFFE) => p += 8,
        Some(_) => {
            ansi(&mut p);
        }
        None => {}
    }
    let prog = ansi(&mut p);
    let mut unicode = None;
    if rd_u32le(b, p) == Some(0x71B2_39F4) {
        p += 4;
        if let Some(n) = rd_u32le(b, p).map(|n| n as usize).filter(|n| *n < 4096) {
            unicode = b.get(p + 4..p + 4 + n * 2).map(utf16le);
        }
    }
    let name = unicode
        .and_then(|u| clean_str(&u))
        .or_else(|| user.and_then(|u| clean_str(&u)))?;
    Some(match prog.and_then(|p| clean_str(&p)) {
        Some(p) => format!("{name} ({p})"),
        None => name,
    })
}

/// Picture records (OfficeArt BLIPs) found in a stream: extension and image bytes.
pub(crate) fn blips(d: &[u8]) -> Vec<(&'static str, &[u8])> {
    let mut out = Vec::new();
    let mut i = 0usize;
    while i + 8 <= d.len() && out.len() < MAX_BLIPS {
        let ty = rd_u16le(d, i + 2).unwrap_or(0);
        if !(0xF01A..=0xF02A).contains(&ty) || d[i] & 0x0F != 0 {
            i += 1;
            continue;
        }
        let inst = rd_u16le(d, i).unwrap_or(0) >> 4;
        let len = rd_u32le(d, i + 4).unwrap_or(0) as usize;
        let Some(body) = d.get(i + 8..(i + 8).saturating_add(len)) else {
            i += 1;
            continue;
        };
        // (extension, instance with one uid, header bytes after the uids)
        let (ext, one, extra) = match ty {
            0xF01A => ("emf", 0x3D4, 34),
            0xF01B => ("wmf", 0x216, 34),
            0xF01C => ("pict", 0x542, 34),
            0xF01D | 0xF02A => ("jpg", if inst & 0xFFE == 0x6E2 { 0x6E2 } else { 0x46A }, 1),
            0xF01E => ("png", 0x6E0, 1),
            0xF01F => ("bmp", 0x7A8, 1),
            0xF029 => ("tiff", 0x6E4, 1),
            _ => {
                i += 1;
                continue;
            }
        };
        if inst & !1 != one {
            i += 1;
            continue;
        }
        let skip = if inst == one { 16 } else { 32 } + extra;
        let Some(img) = body.get(skip..) else {
            i += 1;
            continue;
        };
        let valid = match ext {
            "jpg" => img.starts_with(&[0xFF, 0xD8]),
            "png" => img.starts_with(b"\x89PNG"),
            "tiff" => img.starts_with(b"II*\0") || img.starts_with(b"MM\0*"),
            _ => !img.is_empty(),
        };
        if !valid {
            i += 1;
            continue;
        }
        out.push((ext, img));
        i += 8 + len;
    }
    out
}

/// Attaches the pictures of a stream: JPEG/PNG/TIFF are parsed for their own metadata, the
/// others are listed as attachments.
pub(crate) fn attach_blips(meta: &mut Metadata, data: &[u8], ctx: &Ctx) -> Result<(), MetaError> {
    let mut seen: HashSet<u64> = HashSet::new();
    let mut n = 0usize;
    for (ext, img) in blips(data) {
        use std::hash::{Hash, Hasher};
        let mut h = std::collections::hash_map::DefaultHasher::new();
        img.hash(&mut h);
        if !seen.insert(h.finish()) {
            continue;
        }
        n += 1;
        let name = format!("image{n}.{ext}");
        let before = meta.embedded.len() + meta.attachments.len();
        if matches!(ext, "jpg" | "png" | "tiff") {
            ctx.attach_child(meta, img, &name, &name)?;
        }
        if meta.embedded.len() + meta.attachments.len() == before
            && meta.attachments.len() < MAX_ATTACHMENTS
        {
            meta.attachments.push(Attachment {
                name,
                size: Some(img.len() as u64),
                mime: Some(format!("image/{ext}")),
            });
        }
    }
    if n > 0 {
        meta.stats.insert("images".into(), n as u64);
    }
    Ok(())
}

/// Picture source paths, alternative text and shape hyperlinks from OfficeArt property
/// tables (OfficeArtFOPT records, MS-ODRAW 2.2.9) anywhere in a stream: `pibName` (0x0105),
/// `fillBlipName` (0x0187) and `lineFillBlipName` (0x01C7) keep the path of the inserted
/// picture file, `wzDescription` (0x0381) the alt text, `pihlShape` (0x0382) the link.
pub(crate) fn officeart_props(meta: &mut Metadata, d: &[u8]) {
    let mut pics: Vec<String> = Vec::new();
    let mut alt: Vec<String> = Vec::new();
    let mut i = 0usize;
    while i + 8 <= d.len() {
        if d[i] & 0x0F != 3 || rd_u16le(d, i + 2) != Some(0xF00B) {
            i += 1;
            continue;
        }
        let n = usize::from(rd_u16le(d, i).unwrap_or(0) >> 4);
        let len = rd_u32le(d, i + 4).unwrap_or(0) as usize;
        let Some(body) = d.get(i + 8..(i + 8).saturating_add(len)) else {
            i += 1;
            continue;
        };
        if n == 0 || n * 6 > len {
            i += 1;
            continue;
        }
        let mut complex = n * 6;
        let mut ok = true;
        let mut found: Vec<(u16, &[u8])> = Vec::new();
        for k in 0..n {
            let id = rd_u16le(body, k * 6).unwrap_or(0);
            let op = rd_u32le(body, k * 6 + 2).unwrap_or(0) as usize;
            if id & 0x8000 == 0 {
                continue;
            }
            let Some(c) = body.get(complex..complex.saturating_add(op)) else {
                ok = false;
                break;
            };
            complex += op;
            found.push((id & 0x3FFF, c));
        }
        if !ok {
            i += 1;
            continue;
        }
        for (id, c) in found {
            match id {
                0x0105 | 0x0187 | 0x01C7 => {
                    if let Some(v) = clean_str(&crate::util::utf16le_z(c)) {
                        if pics.len() < 200 && !pics.contains(&v) {
                            pics.push(v);
                        }
                    }
                }
                0x0381 => {
                    if let Some(v) = clean_str(&crate::util::utf16le_z(c)) {
                        if alt.len() < 200 && !alt.contains(&v) {
                            alt.push(v);
                        }
                    }
                }
                0x0382 => {
                    for l in super::biff::link_strings(c) {
                        if meta.links.len() < 2000 {
                            Metadata::add_unique(&mut meta.links, &truncate(&l, 2048));
                        }
                    }
                }
                _ => {}
            }
        }
        i += 8 + len;
    }
    if !pics.is_empty() {
        meta.fields.insert(
            "officeart:pictureSource".into(),
            truncate(&pics.join("; "), 4096),
        );
    }
    if !alt.is_empty() {
        meta.fields
            .insert("officeart:altText".into(), truncate(&alt.join("; "), 4096));
    }
}

#[cfg(test)]
pub(crate) mod tests;
