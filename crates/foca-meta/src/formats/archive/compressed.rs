//! Single-stream compressors: gzip (original file name, mtime, OS byte, comment; the stream is
//! decompressed under the shared budget and parsed recursively, so `.tar.gz` works), bzip2 and
//! xz (header facts only: no decompressor is bundled).

use std::io::Read;

use foca_core::{DocFormat, Metadata};

use crate::formats::magic::GZIP_MAGIC;
use crate::util::{clean_str, rd_u32le, truncate, unix_to_iso};
use crate::{Ctx, MetaError};

fn os_name(os: u8) -> Option<&'static str> {
    Some(match os {
        0 => "MS-DOS/Windows (FAT)",
        3 => "Unix",
        7 => "Macintosh",
        11 => "Windows NTFS",
        _ => return None,
    })
}

fn latin1_z(b: &[u8], max: usize) -> (String, usize) {
    let end = b.iter().position(|&c| c == 0).unwrap_or(b.len());
    let s: String = b[..end.min(max)].iter().map(|&c| c as char).collect();
    (s, (end + 1).min(b.len()))
}

pub fn extract_gzip(b: &[u8], name_hint: Option<&str>, ctx: &Ctx) -> Result<Metadata, MetaError> {
    crate::guard("gzip", || gzip_inner(b, name_hint, ctx))
}

fn gzip_inner(b: &[u8], name_hint: Option<&str>, ctx: &Ctx) -> Result<Metadata, MetaError> {
    if b.len() < 18 || !b.starts_with(&GZIP_MAGIC) {
        return Err(MetaError::malformed("gzip", "нет заголовка gzip"));
    }
    let mut meta = Metadata::new(DocFormat::Gzip);
    let flags = b[3];
    let mtime = rd_u32le(b, 4).unwrap_or(0);
    if let Some(t) = unix_to_iso(i64::from(mtime)) {
        meta.fields.insert("gzip:mtime".into(), t.clone());
        meta.modified = Some(t);
    }
    if let Some(os) = os_name(b[9]) {
        meta.fields.insert("gzip:os".into(), os.into());
        meta.os = Some(os.into());
    }
    let mut at = 10usize;
    if flags & 0x04 != 0 {
        let xlen = b
            .get(at..at + 2)
            .map_or(0, |x| u16::from_le_bytes([x[0], x[1]])) as usize;
        at = at.saturating_add(2 + xlen);
    }
    let mut inner_name = None;
    if flags & 0x08 != 0 {
        let (n, used) = latin1_z(b.get(at..).unwrap_or(&[]), 1024);
        at = at.saturating_add(used);
        if let Some(n) = clean_str(&n) {
            meta.fields.insert("gzip:name".into(), n.clone());
            crate::paths::add_path(&mut meta, &n, "gzip:name");
            inner_name = Some(n);
        }
    }
    if flags & 0x10 != 0 {
        let (c, _) = latin1_z(b.get(at..).unwrap_or(&[]), 4096);
        if let Some(c) = clean_str(&c) {
            meta.description = Some(truncate(&c, 2048));
        }
    }
    if !ctx.can_descend() {
        return Ok(meta);
    }
    let cap = ctx.remaining().min(ctx.max_file());
    let mut out = Vec::new();
    let mut dec = flate2::read::MultiGzDecoder::new(b);
    let res = (&mut dec).take(cap.saturating_add(1)).read_to_end(&mut out);
    if out.len() as u64 > cap {
        let _ = ctx.spend(cap);
        return Err(MetaError::ZipBomb(
            "gzip: распаковано больше бюджета".into(),
        ));
    }
    ctx.spend(out.len() as u64)?;
    if res.is_err() {
        meta.warnings.push("gzip: поток повреждён".into());
    }
    meta.stats
        .insert("uncompressed_bytes".into(), out.len() as u64);
    let child_name = inner_name
        .as_deref()
        .map(|n| n.rsplit(['/', '\\']).next().unwrap_or(n).to_string())
        .or_else(|| {
            name_hint.map(|h| {
                let h = h.rsplit(['/', '\\']).next().unwrap_or(h);
                if let Some(s) = h.strip_suffix(".tgz") {
                    format!("{s}.tar")
                } else {
                    h.trim_end_matches(".gz").to_string()
                }
            })
        })
        .unwrap_or_else(|| "data".into());
    if !out.is_empty() {
        ctx.attach_child(&mut meta, &out, &child_name, &child_name)?;
    }
    Ok(meta)
}

pub fn extract_bzip2(b: &[u8]) -> Metadata {
    let mut meta = Metadata::new(DocFormat::Bzip2);
    if let Some(&lvl) = b.get(3) {
        meta.fields
            .insert("bzip2:block_size".into(), format!("{}00k", lvl as char));
    }
    meta.warnings
        .push("bzip2: содержимое не распаковывается".into());
    meta
}

pub fn extract_xz(b: &[u8]) -> Metadata {
    let mut meta = Metadata::new(DocFormat::Xz);
    if let Some(&f) = b.get(7) {
        let check = match f & 0x0F {
            0 => "none",
            1 => "crc32",
            4 => "crc64",
            10 => "sha256",
            _ => "other",
        };
        meta.fields.insert("xz:check".into(), check.into());
    }
    meta.warnings
        .push("xz: содержимое не распаковывается".into());
    meta
}
