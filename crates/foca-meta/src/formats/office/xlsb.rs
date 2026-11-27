//! Excel binary workbook (XLSB, BIFF12 records inside the OPC package): shared strings, cell
//! text and selected numbers, sheet names and visibility, defined names, comments with their
//! authors and external workbook paths.
//!
//! Record ids and structures follow MS-XLSB; the reading order mirrors calamine (MIT).

use foca_core::{CommentRef, Metadata, PersonRole};

use super::ole::biff::{interesting_number, rk_value};
use crate::util::{clean_str, rd_u16le, rd_u32le, truncate, utf16le};
use crate::zipx::SafeZip;
use crate::{Ctx, MetaError};

const MAX_TEXT: usize = 16 << 20;
const MAX_NUMBERS: usize = 20_000;
const NUMBER_SHEETS: usize = 2;
const MAX_RECORDS: usize = 4_000_000;

/// Iterates BIFF12 records: variable-length type (up to 2 bytes) and size (up to 4 bytes).
fn records(b: &[u8]) -> Vec<(u32, &[u8])> {
    let mut out = Vec::new();
    let mut p = 0usize;
    let varint = |p: &mut usize, max: usize| -> Option<u32> {
        let mut v: u32 = 0;
        for i in 0..max {
            let c = *b.get(*p)?;
            *p += 1;
            v |= u32::from(c & 0x7F) << (7 * i);
            if c & 0x80 == 0 {
                return Some(v);
            }
        }
        Some(v)
    };
    while p < b.len() && out.len() < MAX_RECORDS {
        let (Some(ty), Some(len)) = (varint(&mut p, 2), varint(&mut p, 4)) else {
            break;
        };
        let Some(data) = b.get(p..p.saturating_add(len as usize)) else {
            break;
        };
        out.push((ty, data));
        p += len as usize;
    }
    out
}

/// XLWideString: u32 character count and UTF-16LE characters. Returns the string and the
/// bytes consumed.
fn wide(d: &[u8], off: usize) -> Option<(String, usize)> {
    let n = rd_u32le(d, off)?;
    if n == 0xFFFF_FFFF {
        return Some((String::new(), 4));
    }
    let n = (n as usize).checked_mul(2)?;
    let raw = d.get(off + 4..(off + 4).checked_add(n)?)?;
    Some((utf16le(raw), 4 + n))
}

fn parse_sst(b: &[u8]) -> Vec<String> {
    records(b)
        .into_iter()
        .filter(|(t, _)| *t == 0x13)
        .take(2_000_000)
        .map(|(_, d)| wide(d, 1).map(|x| x.0).unwrap_or_default())
        .collect()
}

/// Appends the text of one worksheet part.
fn sheet_text(b: &[u8], sst: &[String], nums: bool, numbers: &mut usize, out: &mut String) {
    let mut first = true;
    for (ty, d) in records(b) {
        if out.len() >= MAX_TEXT {
            return;
        }
        let v = match ty {
            0 => {
                if !first {
                    out.push('\n');
                }
                first = false;
                continue;
            }
            7 => rd_u32le(d, 8).and_then(|i| sst.get(i as usize).cloned()),
            6 | 8 => wide(d, 8).map(|x| x.0),
            5 | 9 | 2 if nums && *numbers < MAX_NUMBERS => {
                *numbers += 1;
                let f = if ty == 2 {
                    rd_u32le(d, 8).map(rk_value)
                } else {
                    d.get(8..16)
                        .and_then(|x| x.try_into().ok())
                        .map(f64::from_le_bytes)
                };
                f.and_then(interesting_number)
            }
            _ => None,
        };
        if let Some(v) = v.filter(|v| !v.is_empty()) {
            out.push_str(&v);
            out.push('\t');
        }
    }
    out.push('\n');
}

/// Workbook part: sheet names with visibility and defined names.
fn workbook(b: &[u8], meta: &mut Metadata, out: &mut String) {
    let mut sheets = Vec::new();
    let mut names = Vec::new();
    for (ty, d) in records(b) {
        match ty {
            // BrtBundleSh: hsState, iTabID, strRelID, strName
            0x9C => {
                let state = rd_u32le(d, 0).unwrap_or(0);
                let Some((_, k)) = wide(d, 8) else { continue };
                if let Some((name, _)) = wide(d, 8 + k) {
                    if state != 0 {
                        Metadata::add_unique(&mut meta.hidden_sheets, &name);
                        if state == 2 {
                            meta.fields
                                .insert(format!("xl:veryHidden:{name}"), "true".into());
                        }
                    }
                    if sheets.len() < 4096 {
                        sheets.push(name);
                    }
                }
            }
            // BrtName: flags u32, chKey u8, itab u32, name
            0x27 => {
                if let Some((n, _)) = wide(d, 9) {
                    if let Some(n) = clean_str(&n).filter(|n| !n.starts_with("_xlnm")) {
                        if names.len() < 1000 {
                            names.push(n);
                        }
                    }
                }
            }
            _ => {}
        }
    }
    if !sheets.is_empty() {
        meta.fields
            .insert("xls:Sheets".into(), truncate(&sheets.join("; "), 2048));
        out.push_str(&sheets.join("\n"));
        out.push('\n');
    }
    if !names.is_empty() {
        meta.fields
            .insert("xls:DefinedNames".into(), truncate(&names.join("; "), 2048));
        out.push_str(&names.join("\n"));
        out.push('\n');
    }
}

/// Comments part: BrtCommentAuthor (0x278), BrtBeginComment (0x27B, author index) and
/// BrtCommentText (0x27D, RichStr).
fn comments(b: &[u8], part: &str, meta: &mut Metadata, out: &mut String) {
    let mut authors: Vec<String> = Vec::new();
    let mut cur: Option<usize> = None;
    for (ty, d) in records(b) {
        match ty {
            0x278 => {
                if let Some((a, _)) = wide(d, 0) {
                    if let Some(a) = clean_str(&a) {
                        meta.add_person(&a, PersonRole::Comment, part);
                    }
                    authors.push(a);
                }
            }
            0x27B => cur = rd_u32le(d, 0).map(|i| i as usize),
            0x27D => {
                let text = wide(d, 1).map(|x| x.0).unwrap_or_default();
                out.push_str(&text);
                out.push('\n');
                if meta.comments.len() < 2000 {
                    meta.comments.push(CommentRef {
                        author: cur.and_then(|i| authors.get(i)).and_then(|a| clean_str(a)),
                        initials: None,
                        date: None,
                        text: truncate(text.trim(), 2048),
                        source: part.to_string(),
                    });
                }
            }
            _ => {}
        }
    }
}

/// External link part: BrtSupBook (0x167) with the path of the referenced workbook.
fn external(b: &[u8], meta: &mut Metadata) {
    for (ty, d) in records(b) {
        if ty == 0x167 && rd_u16le(d, 0) == Some(0) {
            if let Some((p, _)) = wide(d, 2) {
                if let Some(p) = clean_str(&p) {
                    Metadata::add_unique(&mut meta.links, &truncate(&p, 2048));
                }
            }
        }
    }
}

/// Parses the binary parts of an XLSB package into `meta` and returns the text.
pub(crate) fn parse(
    z: &mut SafeZip,
    names: &[String],
    ctx: &Ctx,
    meta: &mut Metadata,
) -> Result<String, MetaError> {
    let mut out = String::new();
    if let Some(b) = z.read("xl/workbook.bin", ctx)? {
        workbook(&b, meta, &mut out);
    }
    let sst = match z.read("xl/sharedStrings.bin", ctx)? {
        Some(b) => parse_sst(&b),
        None => Vec::new(),
    };
    let mut sheets: Vec<&String> = names
        .iter()
        .filter(|n| n.starts_with("xl/worksheets/") && n.ends_with(".bin"))
        .collect();
    sheets.sort_by_key(|n| natural(n));
    let mut numbers = 0usize;
    for (i, n) in sheets.into_iter().take(500).enumerate() {
        if let Some(b) = z.read(n, ctx)? {
            sheet_text(&b, &sst, i < NUMBER_SHEETS, &mut numbers, &mut out);
        }
    }
    for n in names
        .iter()
        .filter(|n| n.starts_with("xl/comments") && n.ends_with(".bin"))
        .take(500)
    {
        if let Some(b) = z.read(n, ctx)? {
            comments(&b, n, meta, &mut out);
        }
    }
    for n in names
        .iter()
        .filter(|n| n.starts_with("xl/externalLinks/") && n.ends_with(".bin"))
        .take(200)
    {
        if let Some(b) = z.read(n, ctx)? {
            external(&b, meta);
        }
    }
    Ok(out)
}

/// Natural sort key (`sheet2` before `sheet10`).
fn natural(s: &str) -> (usize, String) {
    let digits: String = s.chars().filter(char::is_ascii_digit).collect();
    (digits.len(), format!("{digits:0>12}{s}"))
}

#[cfg(test)]
mod tests;
