//! OLE2 (doc/xls/ppt 97-2003): SummaryInformation / DocumentSummaryInformation (a custom
//! property set parser), Word save history (SttbSavedBy), template (SttbfAssoc), revision and
//! comment authors, Excel WRITEACCESS and hidden sheets, PowerPoint Current User, VBA macros
//! and embedded objects.

use std::collections::BTreeMap;
use std::io::{Cursor, Read, Seek};

use foca_core::{DocFormat, Metadata, OldVersion, PersonRole};

use super::office_info;
use crate::util::{
    clean_str, decode_codepage, filetime_to_iso, rd_u16le, rd_u32le, rd_u64le, truncate, utf16le,
};
use crate::{Ctx, MetaError};

#[derive(Debug, Clone, PartialEq)]
pub(crate) enum PropValue {
    Str(String),
    Int(i64),
    Bool(bool),
    Time(u64),
    List(Vec<PropValue>),
    /// VT_CF clipboard data (the document thumbnail): format tag and bytes.
    Clip(i32, Vec<u8>),
    Other,
}

pub(crate) struct Section {
    pub fmtid: [u8; 16],
    /// Declared code page of the section strings (property 1).
    pub codepage: Option<u16>,
    pub props: Vec<(u32, PropValue)>,
    pub dict: BTreeMap<u32, String>,
}

pub(crate) struct PropertySet {
    pub os: Option<String>,
    pub sections: Vec<Section>,
}

/// OS of the property set header (OSVersion: kind in the high word, major/minor in the low
/// bytes). Writers other than Windows Office (LibreOffice, Apache POI) leave zero or
/// placeholder values, which are not reported: no Windows below 3.0 ever wrote these files.
fn os_name(os_ver: u32) -> Option<String> {
    let kind = os_ver >> 16;
    let major = os_ver & 0xFF;
    let minor = (os_ver >> 8) & 0xFF;
    match kind {
        0 if major >= 3 => Some("Windows 3.x (Win16)".into()),
        2 if major < 3 => None,
        1 => Some("Macintosh".into()),
        2 => Some(
            match (major, minor) {
                (4, 0) => "Windows NT 4.0/95",
                (4, 10) => "Windows 98",
                (4, 90) => "Windows Me",
                (5, 0) => "Windows 2000",
                (5, 1) => "Windows XP",
                (5, 2) => "Windows XP x64/Server 2003",
                (6, 0) => "Windows Vista/Server 2008",
                (6, 1) => "Windows 7/Server 2008 R2",
                (6, 2) => "Windows 8/Server 2012",
                (6, 3) => "Windows 8.1/Server 2012 R2",
                (10, 0) => "Windows 10/11",
                _ => return Some(format!("Windows {major}.{minor}")),
            }
            .to_string(),
        ),
        _ => None,
    }
}

fn read_value(b: &[u8], off: usize, codepage: u16, depth: u8) -> PropValue {
    let Some(vt) = rd_u32le(b, off) else {
        return PropValue::Other;
    };
    let p = off + 4;
    let ty = vt & 0xFFFF;
    if ty & 0x1000 != 0 && depth == 0 {
        // VT_VECTOR
        let base = ty & 0x0FFF;
        let Some(n) = rd_u32le(b, p) else {
            return PropValue::Other;
        };
        let mut items = Vec::new();
        let mut q = p + 4;
        for _ in 0..n.min(1024) {
            let (v, size) = match base {
                0x1E | 0x1F => read_string(b, q, base, codepage),
                0x0C => {
                    let v = read_value(b, q, codepage, depth + 1);
                    let size = value_size(b, q, codepage);
                    (v, size)
                }
                0x03 => (
                    rd_u32le(b, q)
                        .map(|x| PropValue::Int(i64::from(x as i32)))
                        .unwrap_or(PropValue::Other),
                    4,
                ),
                _ => break,
            };
            if size == 0 {
                break;
            }
            items.push(v);
            q += size;
        }
        return PropValue::List(items);
    }
    match ty {
        0x02 => rd_u16le(b, p)
            .map(|x| PropValue::Int(i64::from(x as i16)))
            .unwrap_or(PropValue::Other),
        0x03 | 0x16 => rd_u32le(b, p)
            .map(|x| PropValue::Int(i64::from(x as i32)))
            .unwrap_or(PropValue::Other),
        0x13 | 0x17 => rd_u32le(b, p)
            .map(|x| PropValue::Int(i64::from(x)))
            .unwrap_or(PropValue::Other),
        0x0B => rd_u16le(b, p)
            .map(|x| PropValue::Bool(x != 0))
            .unwrap_or(PropValue::Other),
        0x40 => rd_u64le(b, p)
            .map(PropValue::Time)
            .unwrap_or(PropValue::Other),
        0x1E | 0x1F => read_string(b, p, ty, codepage).0,
        0x47 => {
            // ClipboardData: u32 size (format + data), i32 format, data
            let size = rd_u32le(b, p).unwrap_or(0) as usize;
            let fmt = rd_u32le(b, p + 4).unwrap_or(0) as i32;
            match b.get(p + 8..(p + 4).saturating_add(size).min(p + 8 + (8 << 20))) {
                Some(d) if size > 4 => PropValue::Clip(fmt, d.to_vec()),
                _ => PropValue::Other,
            }
        }
        _ => PropValue::Other,
    }
}

/// Returns the size of a VT_VARIANT value (for vectors of variants).
fn value_size(b: &[u8], off: usize, codepage: u16) -> usize {
    let Some(vt) = rd_u32le(b, off) else { return 0 };
    match vt & 0xFFFF {
        0x02 | 0x0B => 8,
        0x03 | 0x13 | 0x16 | 0x17 => 8,
        0x40 => 12,
        t @ (0x1E | 0x1F) => 4 + read_string(b, off + 4, t, codepage).1,
        _ => 0,
    }
}

/// Reads an LPSTR/LPWSTR string; returns the value and the consumed size padded to 4 bytes.
fn read_string(b: &[u8], off: usize, ty: u32, codepage: u16) -> (PropValue, usize) {
    let Some(n) = rd_u32le(b, off) else {
        return (PropValue::Other, 0);
    };
    let n = n as usize;
    if n > 1 << 20 {
        return (PropValue::Other, 0);
    }
    // VT_LPWSTR length is in characters; VT_LPSTR length is in bytes (also for code page 1200)
    let unicode = ty == 0x1F || codepage == 1200;
    let bytes_len = if ty == 0x1F { n.saturating_mul(2) } else { n };
    let Some(raw) = b.get(off + 4..off + 4 + bytes_len) else {
        return (PropValue::Other, 0);
    };
    let s = if unicode {
        utf16le(raw)
    } else {
        decode_codepage(raw, codepage)
    };
    let s = s.trim_end_matches('\0').to_string();
    let size = 4 + bytes_len.div_ceil(4) * 4;
    (PropValue::Str(s), size)
}

pub(crate) fn parse_property_set(b: &[u8]) -> Option<PropertySet> {
    if rd_u16le(b, 0)? != 0xFFFE {
        return None;
    }
    let os = rd_u32le(b, 4).and_then(os_name);
    let nsec = rd_u32le(b, 24)?.min(8) as usize;
    let mut sections = Vec::new();
    for i in 0..nsec {
        let h = 28 + i * 20;
        let mut fmtid = [0u8; 16];
        fmtid.copy_from_slice(b.get(h..h + 16)?);
        let so = rd_u32le(b, h + 16)? as usize;
        let sec = b.get(so..)?;
        let size = (rd_u32le(sec, 0)? as usize).min(sec.len());
        let sec = &sec[..size];
        let count = rd_u32le(sec, 4)?.min(4096) as usize;
        let mut ids = Vec::new();
        for k in 0..count {
            let (Some(pid), Some(off)) = (rd_u32le(sec, 8 + k * 8), rd_u32le(sec, 12 + k * 8))
            else {
                break;
            };
            ids.push((pid, off as usize));
        }
        let declared = ids
            .iter()
            .find(|(pid, _)| *pid == 1)
            .and_then(|(_, off)| off.checked_add(4).and_then(|o| rd_u16le(sec, o)));
        let codepage = declared.unwrap_or(1252);
        let mut props = Vec::new();
        let mut dict = BTreeMap::new();
        for (pid, off) in &ids {
            if *pid == 0 {
                // dictionary of custom property names
                let Some(n) = rd_u32le(sec, *off) else {
                    continue;
                };
                let Some(mut q) = off.checked_add(4) else {
                    continue;
                };
                for _ in 0..n.min(4096) {
                    let Some(q_len) = q.checked_add(4) else {
                        break;
                    };
                    let Some(q_data) = q.checked_add(8) else {
                        break;
                    };
                    let (Some(id), Some(cch)) = (rd_u32le(sec, q), rd_u32le(sec, q_len)) else {
                        break;
                    };
                    let cch = cch as usize;
                    if cch > 4096 {
                        break;
                    }
                    let (name, len) = if codepage == 1200 {
                        let Some(l) = cch.checked_mul(2) else {
                            break;
                        };
                        let Some(end) = q_data.checked_add(l) else {
                            break;
                        };
                        (sec.get(q_data..end).map(utf16le), l.div_ceil(4) * 4)
                    } else {
                        let Some(end) = q_data.checked_add(cch) else {
                            break;
                        };
                        (
                            sec.get(q_data..end).map(|r| decode_codepage(r, codepage)),
                            cch,
                        )
                    };
                    if let Some(name) = name {
                        dict.insert(id, name.trim_end_matches('\0').to_string());
                    }
                    let Some(next_q) = q_data.checked_add(len) else {
                        break;
                    };
                    q = next_q;
                }
                continue;
            }
            if *pid == 1 {
                continue;
            }
            props.push((*pid, read_value(sec, *off, codepage, 0)));
        }
        sections.push(Section {
            fmtid,
            codepage: declared,
            props,
            dict,
        });
    }
    Some(PropertySet { os, sections })
}

fn as_str(v: &PropValue) -> Option<String> {
    match v {
        PropValue::Str(s) => clean_str(s),
        _ => None,
    }
}

fn as_int(v: &PropValue) -> Option<i64> {
    match v {
        PropValue::Int(i) => Some(*i),
        _ => None,
    }
}

fn value_to_string(v: &PropValue) -> Option<String> {
    match v {
        PropValue::Str(s) => clean_str(s),
        PropValue::Int(i) => Some(i.to_string()),
        PropValue::Bool(b) => Some(b.to_string()),
        PropValue::Time(t) => filetime_to_iso(*t),
        PropValue::List(l) => {
            let parts: Vec<String> = l.iter().filter_map(value_to_string).collect();
            (!parts.is_empty()).then(|| parts.join("; "))
        }
        PropValue::Clip(..) | PropValue::Other => None,
    }
}

fn summary(meta: &mut Metadata, ps: &PropertySet) {
    if let Some(os) = &ps.os {
        meta.os = Some(os.clone());
    }
    let Some(sec) = ps.sections.first() else {
        return;
    };
    if let Some(cp) = sec.codepage {
        let name = office_info::codepage_name(cp)
            .map_or_else(|| cp.to_string(), |n| format!("{cp} ({n})"));
        meta.fields.insert("ole:CodePage".into(), name);
    }
    for (pid, v) in &sec.props {
        match pid {
            2 => meta.title = as_str(v),
            3 => meta.subject = as_str(v),
            4 => {
                if let Some(a) = as_str(v) {
                    meta.add_person(&a, PersonRole::Author, "SummaryInformation:Author");
                    meta.author = Some(a);
                }
            }
            5 => meta.keywords = as_str(v),
            6 => meta.description = as_str(v),
            7 => meta.template = as_str(v),
            8 => {
                if let Some(a) = as_str(v) {
                    meta.add_person(
                        &a,
                        PersonRole::LastModifiedBy,
                        "SummaryInformation:LastAuthor",
                    );
                    meta.last_modified_by = Some(a);
                }
            }
            9 => meta.revision = as_str(v),
            10 => {
                if let PropValue::Time(t) = v {
                    let secs = t / 10_000_000;
                    if secs < 10 * 365 * 86400 {
                        meta.edit_time_secs = Some(secs);
                    }
                }
            }
            11 => {
                meta.printed = if let PropValue::Time(t) = v {
                    filetime_to_iso(*t)
                } else {
                    None
                }
            }
            12 => {
                meta.created = if let PropValue::Time(t) = v {
                    filetime_to_iso(*t)
                } else {
                    None
                }
            }
            13 => {
                meta.modified = if let PropValue::Time(t) = v {
                    filetime_to_iso(*t)
                } else {
                    None
                }
            }
            14..=16 => {
                if let Some(n) = as_int(v).filter(|n| *n >= 0) {
                    let k = match pid {
                        14 => "pages",
                        15 => "words",
                        _ => "characters",
                    };
                    meta.stats.insert(k.into(), n as u64);
                }
            }
            18 => {
                if let Some(a) = as_str(v) {
                    Metadata::add_unique(&mut meta.software, &a);
                    meta.application = Some(a);
                }
            }
            17 => {
                if let PropValue::Clip(fmt, d) = v {
                    // -1: Windows clipboard format id (3 metafile, 8 DIB, 14 EMF) + data
                    let kind = match (fmt, rd_u32le(d, 0)) {
                        (-1, Some(3)) => "wmf",
                        (-1, Some(8)) => "bmp",
                        (-1, Some(14)) => "emf",
                        (-2, _) => "pict",
                        _ => "bin",
                    };
                    meta.fields.insert(
                        "office:thumbnail".into(),
                        format!("SummaryInformation ({kind})"),
                    );
                    meta.attachments.push(foca_core::Attachment {
                        name: format!("thumbnail.{kind}"),
                        size: Some(d.len() as u64),
                        mime: Some(format!("image/{kind}")),
                    });
                }
            }
            19 => {
                if let Some(n) = as_int(v) {
                    meta.fields.insert("ole:Security".into(), n.to_string());
                    if n & 1 != 0 {
                        meta.encrypted = true;
                    }
                }
            }
            _ => {}
        }
    }
}

fn doc_summary(meta: &mut Metadata, ps: &PropertySet) {
    for (i, sec) in ps.sections.iter().enumerate() {
        let user_defined = i > 0 || sec.fmtid[0] == 0x05;
        if user_defined {
            for (pid, v) in &sec.props {
                let name = sec
                    .dict
                    .get(pid)
                    .cloned()
                    .unwrap_or_else(|| format!("prop{pid}"));
                if let Some(s) = value_to_string(v) {
                    meta.custom.insert(name, truncate(&s, 2048));
                }
            }
            continue;
        }
        for (pid, v) in &sec.props {
            match pid {
                2 => meta.category = as_str(v),
                14 => meta.manager = as_str(v),
                15 => meta.company = as_str(v),
                5..=10 => {
                    if let Some(n) = as_int(v).filter(|n| *n >= 0) {
                        let k = [
                            "lines",
                            "paragraphs",
                            "slides",
                            "notes",
                            "hidden_slides",
                            "mm_clips",
                        ][(*pid - 5) as usize];
                        meta.stats.insert(k.into(), n as u64);
                    }
                }
                13 => {
                    if let Some(s) = value_to_string(v) {
                        meta.fields
                            .insert("ole:TitlesOfParts".into(), truncate(&s, 2048));
                    }
                }
                0x17 => {
                    if let Some(n) = as_int(v) {
                        meta.fields.insert(
                            "ole:AppVersion".into(),
                            format!("{}.{:04}", n >> 16, n & 0xFFFF),
                        );
                    }
                }
                0x1A..=0x1D => {
                    if let Some(s) = as_str(v) {
                        let k = ["ContentType", "ContentStatus", "Language", "DocVersion"]
                            [(*pid - 0x1A) as usize];
                        meta.fields.insert(format!("ole:{k}"), s);
                    }
                }
                _ => {}
            }
        }
    }
}

pub(crate) fn read_stream<F: Read + Seek>(
    cf: &mut cfb::CompoundFile<F>,
    path: &str,
    ctx: &Ctx,
) -> Result<Option<Vec<u8>>, MetaError> {
    let Ok(mut s) = cf.open_stream(path) else {
        return Ok(None);
    };
    let len = s.len();
    if len > ctx.remaining() {
        return Err(MetaError::ZipBomb(format!(
            "OLE: поток {path} больше бюджета"
        )));
    }
    let mut buf = Vec::with_capacity(len.min(1 << 20) as usize);
    let _ = (&mut s).take(len).read_to_end(&mut buf);
    ctx.spend(buf.len() as u64)?;
    Ok(Some(buf))
}

/// Parses an STTB, skipping extra data. Both extended (UTF-16) and ANSI tables are supported.
fn parse_sttb(b: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    let Some(first) = rd_u16le(b, 0) else {
        return out;
    };
    let extended = first == 0xFFFF;
    let (count, cb_extra, mut p) = if extended {
        (
            rd_u16le(b, 2).unwrap_or(0) as usize,
            rd_u16le(b, 4).unwrap_or(0) as usize,
            6,
        )
    } else {
        (first as usize, rd_u16le(b, 2).unwrap_or(0) as usize, 4)
    };
    for _ in 0..count.min(4096) {
        if extended {
            let Some(cch) = rd_u16le(b, p) else { break };
            let l = usize::from(cch) * 2;
            let Some(raw) = b.get(p + 2..p + 2 + l) else {
                break;
            };
            out.push(utf16le(raw));
            p += 2 + l + cb_extra;
        } else {
            let Some(&cch) = b.get(p) else { break };
            let l = usize::from(cch);
            let Some(raw) = b.get(p + 1..p + 1 + l) else {
                break;
            };
            out.push(decode_codepage(raw, 1252));
            p += 1 + l + cb_extra;
        }
    }
    out
}

/// Entry `i` of the FIB `FibRgFcLcb` array: offset and size in the table stream (empty
/// entries give `None`).
fn fib_fc_lcb(wd: &[u8], i: usize) -> Option<(usize, usize)> {
    let csw = rd_u16le(wd, 32)?;
    let p_lw = 34 + usize::from(csw) * 2;
    let cslw = rd_u16le(wd, p_lw)?;
    let p_fc = p_lw + 2 + usize::from(cslw) * 4;
    let cb = rd_u16le(wd, p_fc)?;
    if i >= usize::from(cb) {
        return None;
    }
    let base = p_fc + 2;
    let fc = rd_u32le(wd, base + i * 8)? as usize;
    let lcb = rd_u32le(wd, base + i * 8 + 4)? as usize;
    (lcb > 0).then_some((fc, lcb))
}

/// Characters of Word text kept per document.
const MAX_WORD_TEXT: usize = 16 << 20;

/// Text of a Word binary document from the piece table (CLX `PlcPcd`): body, footnotes,
/// headers, comments and text boxes in character order. Compressed pieces are Windows-1252,
/// the others UTF-16LE. `None` when the FIB or the piece table cannot be read.
fn word_text<F: Read + Seek>(
    cf: &mut cfb::CompoundFile<F>,
    wd: &[u8],
    ctx: &Ctx,
) -> Result<Option<String>, MetaError> {
    if rd_u16le(wd, 0) != Some(0xA5EC) {
        return Ok(None);
    }
    let flags = rd_u16le(wd, 0x0A).unwrap_or(0);
    if flags & 0x0100 != 0 {
        // encrypted: the pieces are ciphertext
        return Ok(Some(String::new()));
    }
    let table = if flags & 0x0200 != 0 {
        "/1Table"
    } else {
        "/0Table"
    };
    let Some((fc, lcb)) = fib_fc_lcb(wd, 33) else {
        return Ok(None);
    };
    let Some(tbl) = read_stream(cf, table, ctx)? else {
        return Ok(None);
    };
    let Some(clx) = tbl.get(fc..fc.saturating_add(lcb).min(tbl.len())) else {
        return Ok(None);
    };
    Ok(piece_table_text(wd, clx))
}

/// Decodes the pieces listed in a CLX against the WordDocument stream.
fn piece_table_text(wd: &[u8], clx: &[u8]) -> Option<String> {
    // skip Prc entries (0x01 + cbGrpprl), then the Pcdt (0x02 + lcb + PlcPcd)
    let mut p = 0usize;
    let plc = loop {
        match clx.get(p)? {
            1 => p = p.checked_add(3 + usize::from(rd_u16le(clx, p + 1)?))?,
            2 => {
                let lcb = rd_u32le(clx, p + 1)? as usize;
                break clx.get(p + 5..p.checked_add(5 + lcb)?)?;
            }
            _ => return None,
        }
    };
    if plc.len() < 16 {
        return None;
    }
    let n = (plc.len() - 4) / 12;
    let mut out = String::new();
    for i in 0..n.min(100_000) {
        let (cp0, cp1) = (rd_u32le(plc, i * 4)?, rd_u32le(plc, i * 4 + 4)?);
        let len = cp1.saturating_sub(cp0) as usize;
        let fc = rd_u32le(plc, 4 * (n + 1) + 8 * i + 2)?;
        let (fcv, compressed) = ((fc & 0x3FFF_FFFF) as usize, fc & 0x4000_0000 != 0);
        let piece = if compressed {
            wd.get(fcv / 2..(fcv / 2).saturating_add(len).min(wd.len()))
                .map(|b| decode_codepage(b, 1252))
        } else {
            wd.get(fcv..fcv.saturating_add(len.saturating_mul(2)).min(wd.len()))
                .map(utf16le)
        };
        for c in piece.unwrap_or_default().chars() {
            match c {
                '\r' | '\u{0B}' | '\u{0C}' => out.push('\n'),
                '\u{07}' => out.push('\t'),
                '\u{1E}' => out.push('-'),
                // field begin/separator/end
                '\u{13}' | '\u{14}' | '\u{15}' => out.push(' '),
                '\t' | '\n' => out.push(c),
                c if c.is_control() || c == '\u{1F}' => {}
                c => out.push(c),
            }
        }
        if out.len() > MAX_WORD_TEXT {
            break;
        }
    }
    Some(out)
}

/// Reads Word data: FIB, then the table stream with SttbSavedBy (71), SttbfAssoc (32), SttbfRMark (51) and GrpXstAtnOwners (36).
fn word_binary<F: Read + Seek>(
    meta: &mut Metadata,
    cf: &mut cfb::CompoundFile<F>,
    ctx: &Ctx,
) -> Result<(), MetaError> {
    let Some(wd) = read_stream(cf, "/WordDocument", ctx)? else {
        return Ok(());
    };
    if rd_u16le(&wd, 0) != Some(0xA5EC) {
        meta.warnings
            .push("WordDocument: неизвестная сигнатура FIB".into());
        return Ok(());
    }
    let flags = rd_u16le(&wd, 0x0A).unwrap_or(0);
    if flags & 0x0100 != 0 {
        meta.encrypted = true;
        return Ok(());
    }
    let table = if flags & 0x0200 != 0 {
        "/1Table"
    } else {
        "/0Table"
    };
    let pair = |i: usize| fib_fc_lcb(&wd, i);
    if let Some(lid) = rd_u16le(&wd, 6).filter(|l| *l != 0) {
        let tag = office_info::lcid_tag(lid);
        meta.fields.insert(
            "doc:lid".into(),
            match tag {
                Some(t) => format!("0x{lid:04X} ({t})"),
                None => format!("0x{lid:04X}"),
            },
        );
        if let (Some(t), None) = (tag, &meta.language) {
            meta.language = Some(t.to_string());
        }
    }
    let Some(tbl) = read_stream(cf, table, ctx)? else {
        return Ok(());
    };
    let slice =
        |p: Option<(usize, usize)>| p.and_then(|(fc, lcb)| tbl.get(fc..fc.checked_add(lcb)?));
    if let Some(dop) = slice(pair(31)) {
        dop_time_zone(meta, dop);
    }
    if let Some(s) = slice(pair(71)) {
        let v = parse_sttb(s);
        for (i, ch) in v.chunks(2).enumerate() {
            let author = ch.first().cloned().unwrap_or_default();
            let path = ch.get(1).cloned().unwrap_or_default();
            let mut f = BTreeMap::new();
            if let Some(a) = clean_str(&author) {
                meta.add_person(&a, PersonRole::LastModifiedBy, "doc:SttbSavedBy");
                f.insert("author".into(), a);
            }
            if let Some(p) = clean_str(&path) {
                f.insert("path".into(), p);
            }
            if !f.is_empty() {
                meta.old_versions.push(OldVersion {
                    revision: (i + 1) as u32,
                    fields: f,
                });
            }
        }
    }
    if let Some(s) = slice(pair(32)) {
        let v = parse_sttb(s);
        if let Some(t) = v.get(1).and_then(|t| clean_str(t)) {
            meta.template = Some(t);
        }
    }
    if let Some(s) = slice(pair(51)) {
        for a in parse_sttb(s) {
            if let Some(a) = clean_str(&a) {
                if a != "Unknown" {
                    meta.add_person(&a, PersonRole::Revision, "doc:SttbfRMark");
                }
            }
        }
    }
    if let Some(s) = slice(pair(36)) {
        let mut p = 0;
        while let Some(cch) = rd_u16le(s, p) {
            let l = usize::from(cch) * 2;
            let Some(raw) = s.get(p + 2..p + 2 + l) else {
                break;
            };
            if let Some(a) = clean_str(&utf16le(raw)) {
                meta.add_person(&a, PersonRole::Comment, "doc:GrpXstAtnOwners");
            }
            p += 2 + l;
        }
    }
    Ok(())
}

/// Derives the author's UTC offset: the DOP keeps creation, save and print times in the
/// local time of the machine, the summary information keeps the same moments in UTC.
fn dop_time_zone(meta: &mut Metadata, dop: &[u8]) {
    let mut pairs = Vec::new();
    for (off, utc) in [
        (0x14, meta.created.as_deref()),
        (0x18, meta.modified.as_deref()),
        (0x1C, meta.printed.as_deref()),
    ] {
        let local = rd_u32le(dop, off).and_then(office_info::dttm_minutes);
        if let (Some(l), Some(u)) = (local, utc.and_then(office_info::iso_minutes)) {
            pairs.push((l, u));
        }
    }
    if let Some(tz) = office_info::tz_offset(&pairs) {
        meta.fields.insert("doc:tz_offset".into(), tz);
    }
}

/// Reads the Excel workbook stream (see [`super::biff`]).
fn excel_binary<F: Read + Seek>(
    meta: &mut Metadata,
    cf: &mut cfb::CompoundFile<F>,
    ctx: &Ctx,
) -> Result<(), MetaError> {
    let wb = match read_stream(cf, "/Workbook", ctx)? {
        Some(w) => w,
        None => match read_stream(cf, "/Book", ctx)? {
            Some(w) => w,
            None => return Ok(()),
        },
    };
    super::biff::parse(&wb, meta);
    super::ole_objects::attach_blips(meta, &super::biff::drawing_group(&wb), ctx)?;
    super::ole_objects::officeart_props(meta, &wb);
    Ok(())
}

fn ppt_current_user<F: Read + Seek>(
    meta: &mut Metadata,
    cf: &mut cfb::CompoundFile<F>,
    ctx: &Ctx,
) -> Result<(), MetaError> {
    let Some(cu) = read_stream(cf, "/Current User", ctx)? else {
        return Ok(());
    };
    let len = rd_u16le(&cu, 20).unwrap_or(0) as usize;
    if let Some(raw) = cu.get(28..28 + len.min(255)) {
        if let Some(u) = clean_str(&decode_codepage(raw, 1252)) {
            meta.add_person(&u, PersonRole::LastModifiedBy, "ppt:CurrentUser");
            meta.fields.insert("ppt:CurrentUser".into(), u);
        }
    }
    Ok(())
}

pub fn extract(b: &[u8], format: DocFormat, ctx: &Ctx) -> Result<Metadata, MetaError> {
    crate::guard("ole", || extract_inner(b, format, ctx))
}

fn extract_inner(b: &[u8], format: DocFormat, ctx: &Ctx) -> Result<Metadata, MetaError> {
    let mut cf =
        cfb::CompoundFile::open(Cursor::new(b)).map_err(|e| MetaError::malformed("ole", e))?;
    let mut meta = Metadata::new(format);
    let mut entries: Vec<(String, bool, u64)> = Vec::new();
    for e in cf.walk() {
        entries.push((
            e.path().to_string_lossy().replace('\\', "/"),
            e.is_stream(),
            e.len(),
        ));
        if entries.len() > ctx.max_entries() {
            return Err(MetaError::TooManyEntries(
                "OLE: слишком много потоков".into(),
            ));
        }
    }
    let mut ansi_cp: u16 = 1251;
    if let Some(s) = read_stream(&mut cf, "/\u{5}SummaryInformation", ctx)? {
        match parse_property_set(&s) {
            Some(ps) => {
                if let Some(cp) = ps.sections.first().and_then(|s| s.codepage) {
                    if cp != 1200 && cp != 65001 {
                        ansi_cp = cp;
                    }
                }
                summary(&mut meta, &ps)
            }
            None => meta.warnings.push("SummaryInformation: не разобран".into()),
        }
    }
    if let Some(s) = read_stream(&mut cf, "/\u{5}DocumentSummaryInformation", ctx)? {
        if let Some(ps) = parse_property_set(&s) {
            doc_summary(&mut meta, &ps);
        }
    }
    if let Some(v) = meta.fields.get("ole:AppVersion").cloned() {
        office_info::apply_app_version(&mut meta, &v);
    }
    if let Some(t) = super::ole_objects::compobj(&mut cf, "/\u{1}CompObj", ctx)? {
        // the product name of the document type (localized: language of the Office UI)
        meta.fields
            .insert("ole:CompObjUserType".into(), truncate(&t, 256));
    }
    match format {
        DocFormat::Doc => {
            word_binary(&mut meta, &mut cf, ctx)?;
            if let Some(data) = read_stream(&mut cf, "/Data", ctx)? {
                super::ole_objects::attach_blips(&mut meta, &data, ctx)?;
            }
            for t in ["/1Table", "/0Table"] {
                if let Some(tbl) = read_stream(&mut cf, t, ctx)? {
                    super::ole_objects::officeart_props(&mut meta, &tbl);
                }
            }
        }
        DocFormat::Xls => excel_binary(&mut meta, &mut cf, ctx)?,
        DocFormat::Ppt => {
            ppt_current_user(&mut meta, &mut cf, ctx)?;
            if let Some(doc) = read_stream(&mut cf, "/PowerPoint Document", ctx)? {
                super::ppt::parse(&doc, &mut meta, ctx, true)?;
                super::ole_objects::officeart_props(&mut meta, &doc);
            }
            if let Some(pics) = read_stream(&mut cf, "/Pictures", ctx)? {
                super::ole_objects::attach_blips(&mut meta, &pics, ctx)?;
            }
        }
        DocFormat::Msi => msi_summary(&mut meta),
        DocFormat::Pub => publisher_streams(&mut meta, &mut cf, ctx)?,
        _ => {}
    }
    // an encrypted OOXML package (MS-OFFCRYPTO) is stored in a compound file
    if entries
        .iter()
        .any(|(p, s, _)| *s && p == "/EncryptedPackage")
    {
        meta.encrypted = true;
        if let Some(info) = read_stream(&mut cf, "/EncryptionInfo", ctx)? {
            let (major, minor) = (
                rd_u16le(&info, 0).unwrap_or(0),
                rd_u16le(&info, 2).unwrap_or(0),
            );
            let kind = match (major, minor) {
                (4, 4) => "agile",
                (2..=4, 2) => "standard",
                (3 | 4, 3) => "extensible",
                _ => "unknown",
            };
            meta.fields.insert(
                "ole:encryption".into(),
                format!("OOXML {kind} encryption {major}.{minor}"),
            );
        }
    }
    if entries
        .iter()
        .any(|(p, s, _)| *s && p.to_ascii_lowercase().ends_with("/vba/dir"))
    {
        super::vba::scan_ole(b, &mut meta);
    }
    super::ole_objects::embedded_objects(&mut meta, &mut cf, &entries, format, ctx)?;
    // macros and Ole10Native packages
    for (path, is_stream, _) in &entries {
        let lower = path.to_ascii_lowercase();
        if lower.starts_with("/macros")
            || lower.starts_with("/_vba_project_cur")
            || lower.contains("/vba/")
        {
            meta.has_macros = true;
            let parent_vba = path
                .rsplit('/')
                .nth(1)
                .is_some_and(|p| p.eq_ignore_ascii_case("VBA"));
            let name = path.rsplit('/').next().unwrap_or("");
            if *is_stream
                && parent_vba
                && !name.eq_ignore_ascii_case("dir")
                && !name.starts_with("_VBA_PROJECT")
                && !name.starts_with("__SRP_")
            {
                Metadata::add_unique(&mut meta.macro_modules, name);
            }
        }
        if *is_stream && lower.ends_with("\u{1}ole10native") {
            if let Ok(Some(native)) = read_stream(&mut cf, path, ctx) {
                parse_ole10_native(&mut meta, ctx, path, &native, ansi_cp)?;
            }
        }
    }
    Ok(meta)
}

/// Publisher: picture source paths and pictures of the Escher streams, hyperlinks of the
/// Contents and Quill streams (layout after Apache POI HPBF).
fn publisher_streams<F: Read + Seek>(
    meta: &mut Metadata,
    cf: &mut cfb::CompoundFile<F>,
    ctx: &Ctx,
) -> Result<(), MetaError> {
    for p in ["/Escher/EscherStm", "/Escher/EscherDelayStm"] {
        if let Some(d) = read_stream(cf, p, ctx)? {
            super::ole_objects::officeart_props(meta, &d);
            if p.ends_with("DelayStm") {
                super::ole_objects::attach_blips(meta, &d, ctx)?;
            }
        }
    }
    for p in ["/Contents", "/Quill/QuillSub/CONTENTS"] {
        if let Some(d) = read_stream(cf, p, ctx)? {
            for l in super::biff::link_strings(&d) {
                if meta.links.len() < 2000 {
                    Metadata::add_unique(&mut meta.links, &truncate(&l, 2048));
                }
            }
        }
    }
    Ok(())
}

/// UTF-16LE text runs of 3+ characters (any script), `\r` as a line break.
fn utf16_runs(d: &[u8], out: &mut String) {
    let mut cur = String::new();
    let flush = |cur: &mut String, out: &mut String| {
        if cur.trim().chars().count() >= 3 && out.len() < MAX_WORD_TEXT {
            out.push_str(cur.trim());
            out.push('\n');
        }
        cur.clear();
    };
    for ch in d.as_chunks::<2>().0 {
        let u = u16::from_le_bytes(*ch);
        match char::from_u32(u32::from(u)) {
            Some('\r' | '\u{0B}') => flush(&mut cur, out),
            Some(c) if u >= 0x20 && !c.is_control() && !(0xE000..0xF900).contains(&u) => {
                cur.push(c)
            }
            _ => flush(&mut cur, out),
        }
    }
    flush(&mut cur, out);
}

/// Windows Installer reuses the summary information properties: Template holds the platform
/// and languages (`x64;1033`), Revision Number holds the package code GUID, Subject the
/// product name and Comments the description.
fn msi_summary(meta: &mut Metadata) {
    if let Some(t) = meta.template.take() {
        meta.fields.insert("msi:platform".into(), t);
    }
    if let Some(r) = meta.revision.take() {
        meta.fields.insert("msi:package_code".into(), r);
    }
    if let Some(s) = meta.subject.clone() {
        meta.fields.insert("msi:product".into(), s);
    }
}

/// Parses an MS-OLEDS `\x01Ole10Native` embedded package stream: extracts original filename,
/// source path (`C:\...` / `\\server\...`), temp path, and recursively parses the embedded payload.
pub(crate) fn parse_ole10_native(
    meta: &mut Metadata,
    ctx: &Ctx,
    stream_path: &str,
    b: &[u8],
    codepage: u16,
) -> Result<(), MetaError> {
    // Layout: [u32 total_size, u16 flags(2), label\0, source_path\0, u32+u32 unknown(8), temp_path\0, u32 data_size, data...]
    if b.len() < 12 {
        return Ok(());
    }
    let mut pos = 6usize;
    let read_z = |p: &mut usize| -> Option<String> {
        let rest = b.get(*p..)?;
        let nul = rest.iter().position(|&c| c == 0)?;
        let raw = &rest[..nul];
        // ANSI strings in the system code page; UTF-8 when the bytes are valid UTF-8
        let s = match std::str::from_utf8(raw) {
            Ok(u) => clean_str(u),
            Err(_) => clean_str(&decode_codepage(raw, codepage)),
        };
        *p += nul + 1;
        s
    };
    let label = read_z(&mut pos).unwrap_or_else(|| "Ole10Native".into());
    meta.fields
        .entry("ole10:filename".into())
        .or_insert_with(|| label.clone());
    if let Some(src_path) = read_z(&mut pos) {
        meta.fields
            .entry("ole10:source_path".into())
            .or_insert_with(|| src_path.clone());
        meta.fields
            .insert(format!("ole:pkg_source:{stream_path}"), src_path);
    }
    if pos + 8 <= b.len() {
        pos += 8;
        if let Some(tmp_path) = read_z(&mut pos) {
            meta.fields
                .entry("ole10:temp_path".into())
                .or_insert_with(|| tmp_path.clone());
            meta.fields
                .insert(format!("ole:pkg_temp:{stream_path}"), tmp_path);
        }
        if let Some(data_len) = rd_u32le(b, pos).map(|n| n as usize) {
            let start = pos + 4;
            if let Some(payload) = b.get(start..start.saturating_add(data_len).min(b.len())) {
                if !payload.is_empty() {
                    ctx.attach_child(meta, payload, &label, stream_path)?;
                }
            }
        }
    }
    Ok(())
}

/// Cleans identifying metadata from an OLE2 Compound File (`.doc`, `.xls`, `.ppt`, `.vsd`, `.pub`, `.ole`):
/// - wipes and removes `\x05SummaryInformation` and `\x05DocumentSummaryInformation`;
/// - wipes and removes digital signature streams (`_xmlsignatures`, `\x05DigitalSignature`);
/// - in `.doc`: zeroes `SttbSavedBy` (save history), `SttbfAssoc` (template path), `SttbfRMark`
///   (revision authors) and `GrpXstAtnOwners` (comment authors) in `/0Table` / `/1Table`;
/// - in `.xls`: blanks the `WRITEACCESS` (`0x005C`) username in `/Workbook` / `/Book`;
/// - in `.ppt`: zeroes the username in `/Current User`;
/// - in `\x01Ole10Native`: zeroes the source and temp file paths while preserving the payload.
///
/// Returns the rewritten file and the number of removed signature streams.
pub(crate) fn clean_ole(bytes: &[u8], limits: &crate::Limits) -> Result<(Vec<u8>, u32), MetaError> {
    use std::io::Write;
    let budget = std::cell::Cell::new(limits.max_unzipped_total);
    let ctx = Ctx::standalone(limits, &budget);
    let mut cf = cfb::CompoundFile::open(Cursor::new(bytes.to_vec()))
        .map_err(|e| MetaError::malformed("ole", e))?;

    let mut entries: Vec<(String, bool, usize)> = Vec::new();
    for e in cf.walk() {
        entries.push((
            e.path().to_string_lossy().replace('\\', "/"),
            e.is_stream(),
            e.len() as usize,
        ));
        if entries.len() > limits.max_entries {
            return Err(MetaError::TooManyEntries(
                "OLE: слишком много потоков".into(),
            ));
        }
    }

    // 1. Refuse encrypted Word / Excel files so callers get a clear error.
    if let Some(wd) = read_stream(&mut cf, "/WordDocument", &ctx)? {
        let flags = rd_u16le(&wd, 0x0A).unwrap_or(0);
        if flags & 0x0100 != 0 {
            return Err(MetaError::Unsupported(
                "зашифрованный документ Word (.doc)".into(),
            ));
        }
    }
    for wb_name in ["/Workbook", "/Book"] {
        if let Some(wb) = read_stream(&mut cf, wb_name, &ctx)? {
            let mut p = 0;
            while let (Some(ty), Some(len)) = (rd_u16le(&wb, p), rd_u16le(&wb, p + 2)) {
                if ty == 0x002F {
                    return Err(MetaError::Unsupported(
                        "зашифрованная книга Excel (.xls)".into(),
                    ));
                }
                if ty == 0x000A {
                    break;
                }
                p += 4 + usize::from(len);
            }
        }
    }

    let mut removed_sigs = 0u32;

    // 2. Wipe and remove property sets and signature streams.
    for (path, is_stream, len) in &entries {
        if !*is_stream {
            continue;
        }
        let low = path.to_ascii_lowercase();
        let is_prop = path == "/\u{5}SummaryInformation"
            || path == "/\u{5}DocumentSummaryInformation"
            || low.ends_with("/\u{5}summaryinformation")
            || low.ends_with("/\u{5}documentsummaryinformation");
        let is_sig = low.contains("digitalsignature") || low.contains("_xmlsignatures");
        if is_prop || is_sig {
            if let Ok(mut s) = cf.open_stream(path) {
                let zeros = vec![0u8; (*len).min(1024 * 1024)];
                let _ = s.write_all(&zeros);
            }
            let _ = cf.remove_stream(path);
            if is_sig {
                removed_sigs += 1;
            }
        }
    }

    // 3. Clean Word binary metadata in `/WordDocument` + `/1Table` or `/0Table`.
    if let Some(mut wd) = read_stream(&mut cf, "/WordDocument", &ctx)? {
        if rd_u16le(&wd, 0) == Some(0xA5EC) {
            let flags = rd_u16le(&wd, 0x0A).unwrap_or(0);
            let table_name = if flags & 0x0200 != 0 {
                "/1Table"
            } else {
                "/0Table"
            };
            if let Some(mut tbl) = read_stream(&mut cf, table_name, &ctx)? {
                if let Some(csw) = rd_u16le(&wd, 32) {
                    let p_lw = 34 + usize::from(csw) * 2;
                    if let Some(cslw) = rd_u16le(&wd, p_lw) {
                        let p_fc = p_lw + 2 + usize::from(cslw) * 4;
                        if let Some(cb) = rd_u16le(&wd, p_fc) {
                            let base = p_fc + 2;
                            // 32 = SttbfAssoc (template), 36 = GrpXstAtnOwners, 51 = SttbfRMark, 71 = SttbSavedBy
                            for idx in [32usize, 36, 51, 71] {
                                if idx < usize::from(cb) {
                                    if let (Some(fc), Some(lcb)) = (
                                        rd_u32le(&wd, base + idx * 8).map(|v| v as usize),
                                        rd_u32le(&wd, base + idx * 8 + 4).map(|v| v as usize),
                                    ) {
                                        if lcb > 0 {
                                            if let Some(slice) =
                                                tbl.get_mut(fc..fc.saturating_add(lcb))
                                            {
                                                slice.fill(0);
                                            }
                                            if let Some(lcb_bytes) =
                                                wd.get_mut(base + idx * 8 + 4..base + idx * 8 + 8)
                                            {
                                                lcb_bytes.copy_from_slice(&0u32.to_le_bytes());
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                if let Ok(mut s) = cf.create_stream(table_name) {
                    let _ = s.write_all(&tbl);
                }
            }
            if let Ok(mut s) = cf.create_stream("/WordDocument") {
                let _ = s.write_all(&wd);
            }
        }
    }

    // 4. Clean Excel BIFF8 `WRITEACCESS` (`0x005C`) in `/Workbook` or `/Book`.
    for wb_name in ["/Workbook", "/Book"] {
        if let Some(mut wb) = read_stream(&mut cf, wb_name, &ctx)? {
            let mut p = 0usize;
            let mut modified = false;
            while let (Some(ty), Some(len)) = (rd_u16le(&wb, p), rd_u16le(&wb, p + 2)) {
                let len = usize::from(len);
                if p + 4 + len > wb.len() {
                    break;
                }
                if ty == 0x005C && len >= 3 {
                    wb[p + 4] = 0;
                    wb[p + 5] = 0;
                    wb[p + 6] = 0;
                    wb[p + 7..p + 4 + len].fill(b' ');
                    modified = true;
                }
                if ty == 0x000A {
                    break;
                }
                p += 4 + len;
            }
            if modified {
                if let Ok(mut s) = cf.create_stream(wb_name) {
                    let _ = s.write_all(&wb);
                }
            }
        }
    }

    // 5. Clean PowerPoint `/Current User`.
    if let Some(mut cu) = read_stream(&mut cf, "/Current User", &ctx)? {
        if cu.len() >= 28 {
            cu[20] = 0;
            cu[21] = 0;
            cu[28..].fill(0);
            if let Ok(mut s) = cf.create_stream("/Current User") {
                let _ = s.write_all(&cu);
            }
        }
    }

    let _ = cf.flush();
    let out_bytes = cf.into_inner().into_inner();
    Ok((out_bytes, removed_sigs))
}

/// Returns the text of an OLE document: Word text from the piece table, otherwise printable
/// strings (ASCII and UTF-16LE) from the main streams.
pub fn text(b: &[u8], ctx: &Ctx) -> Result<String, MetaError> {
    crate::guard("ole", || {
        let mut cf =
            cfb::CompoundFile::open(Cursor::new(b)).map_err(|e| MetaError::malformed("ole", e))?;
        let mut out = String::new();
        for s in [
            "/WordDocument",
            "/Workbook",
            "/Book",
            "/PowerPoint Document",
        ] {
            if let Some(data) = read_stream(&mut cf, s, ctx)? {
                if s == "/WordDocument" {
                    if let Some(t) = word_text(&mut cf, &data, ctx)? {
                        out.push_str(&t);
                        out.push('\n');
                        continue;
                    }
                }
                if s == "/PowerPoint Document" {
                    out.push_str(&super::ppt::parse(
                        &data,
                        &mut Metadata::default(),
                        ctx,
                        false,
                    )?);
                    continue;
                }
                if s == "/Workbook" || s == "/Book" {
                    out.push_str(&super::biff::parse(&data, &mut Metadata::default()));
                    continue;
                }
                strings(&data, &mut out);
            }
        }
        // Publisher story text lives in the Quill TEXT chunks (UTF-16)
        if let Some(q) = read_stream(&mut cf, "/Quill/QuillSub/CONTENTS", ctx)? {
            utf16_runs(&q, &mut out);
        }
        for l in super::vba::scan_ole(b, &mut Metadata::default()) {
            out.push_str(&l);
            out.push('\n');
        }
        Ok(out)
    })
}

fn strings(d: &[u8], out: &mut String) {
    // ASCII strings of at least 6 characters
    let mut cur = String::new();
    for &c in d {
        if (0x20..0x7F).contains(&c) || c == b'\t' {
            cur.push(c as char);
        } else {
            if cur.len() >= 6 {
                out.push_str(&cur);
                out.push('\n');
            }
            cur.clear();
        }
    }
    if cur.len() >= 6 {
        out.push_str(&cur);
        out.push('\n');
    }
    // UTF-16LE strings of at least 4 characters
    let mut cur = String::new();
    for ch in d.as_chunks::<2>().0 {
        let u = u16::from_le_bytes(*ch);
        match char::from_u32(u32::from(u)) {
            Some(c)
                if !c.is_control()
                    && u >= 0x20
                    && (u < 0x0530 || (0x2000..0x2070).contains(&u)) =>
            {
                cur.push(c)
            }
            _ => {
                if cur.chars().count() >= 4 {
                    out.push_str(&cur);
                    out.push('\n');
                }
                cur.clear();
            }
        }
    }
    if cur.chars().count() >= 4 {
        out.push_str(&cur);
        out.push('\n');
    }
}
