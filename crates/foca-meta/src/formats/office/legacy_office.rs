//! Minimal legacy office formats: WordPerfect (`.wpd`, the `\xFFWPC` header: product, file
//! type, version, encryption) and Microsoft Works (`.wps` word processor / `.wks` spreadsheet:
//! OLE2 property sets, or the Lotus-style BOF record of DOS-era spreadsheets).

use foca_core::{DocFormat, Metadata};

use crate::util::{rd_u16le, rd_u32le};
use crate::{Ctx, MetaError};

pub(crate) const WPD_MAGIC: &[u8; 4] = b"\xFFWPC";

fn wp_file_type(t: u8) -> &'static str {
    match t {
        0x0A => "document",
        0x0B => "dictionary",
        0x0C => "thesaurus",
        0x0D => "block",
        0x0E => "rectangular_block",
        0x0F => "column_block",
        0x10 => "printer_resource",
        0x11 => "setup",
        0x13 => "printer_resource_prs",
        0x15 => "graphics",
        0x16 => "macro",
        0x2C => "template",
        _ => "other",
    }
}

fn wp_version(major: u8, minor: u8) -> String {
    match major {
        0 => format!("WordPerfect 5.x (0.{minor})"),
        1 => format!("WordPerfect 5.x for Windows (1.{minor})"),
        2 => format!("WordPerfect 6+ ({major}.{minor})"),
        _ => format!("WordPerfect ({major}.{minor})"),
    }
}

pub fn extract_wpd(b: &[u8], _ctx: &Ctx) -> Result<Metadata, MetaError> {
    if !b.starts_with(WPD_MAGIC) || b.len() < 16 {
        return Err(MetaError::malformed("wpd", "bad header"));
    }
    let mut meta = Metadata::new(DocFormat::Wpd);
    let doc_ptr = rd_u32le(b, 4).unwrap_or(0);
    let (product, ftype, major, minor) = (b[8], b[9], b[10], b[11]);
    let encryption = rd_u16le(b, 12).unwrap_or(0);
    meta.fields
        .insert("wpd:product_type".into(), product.to_string());
    meta.fields
        .insert("wpd:file_type".into(), wp_file_type(ftype).into());
    let ver = wp_version(major, minor);
    meta.application = Some(ver.clone());
    Metadata::add_unique(&mut meta.software, &ver);
    if encryption != 0 {
        meta.encrypted = true;
    }
    if doc_ptr as usize > b.len() {
        meta.warnings
            .push("WPD: document pointer beyond the end of file".into());
    }
    Ok(meta)
}

/// Returns `true` for the BOF record of a Lotus-format worksheet (DOS-era Works `.wks`).
pub(crate) fn is_lotus_wks(b: &[u8]) -> bool {
    b.len() >= 6
        && b[..4] == [0x00, 0x00, 0x02, 0x00]
        && matches!(rd_u16le(b, 4), Some(0x0404..=0x0406 | 0x5404..=0x5406))
}

pub fn extract_works(b: &[u8], format: DocFormat, ctx: &Ctx) -> Result<Metadata, MetaError> {
    if is_lotus_wks(b) {
        let mut meta = Metadata::new(format);
        let v = rd_u16le(b, 4).unwrap_or(0);
        let app = match v {
            0x0404 => "Lotus 1-2-3 1A / Works for DOS",
            0x0405 => "Symphony",
            0x0406 => "Lotus 1-2-3 2.x",
            0x5404..=0x5406 => "Microsoft Works for DOS",
            _ => "Lotus-format worksheet",
        };
        meta.application = Some(app.into());
        meta.fields
            .insert("wks:bof_version".into(), format!("0x{v:04x}"));
        return Ok(meta);
    }
    crate::formats::office::ole::extract(b, format, ctx)
}

/// Classifies OLE root names of Works files.
pub(crate) fn works_format(names: &[String]) -> Option<DocFormat> {
    let has = |n: &str| names.iter().any(|x| x.eq_ignore_ascii_case(n));
    if has("MatOST") || (has("CONTENTS") && has("SPELLING")) {
        Some(DocFormat::Wps)
    } else if has("WksSSWorkBook") {
        Some(DocFormat::Wks)
    } else {
        None
    }
}
