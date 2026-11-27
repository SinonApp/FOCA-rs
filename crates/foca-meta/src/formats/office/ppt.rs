//! PowerPoint 97-2003 `PowerPoint Document` stream: slide, notes and master text
//! (TextCharsAtom/TextBytesAtom), comments with author, initials and date (Comment10),
//! hyperlink targets (ExHyperlink), the number of saves (UserEditAtom chain) and embedded OLE
//! objects (ExOleObjStg, zlib-compressed compound files parsed recursively).
//!
//! Record types follow MS-PPT and Apache POI HSLF (Apache-2.0).

use std::io::Read;

use foca_core::{CommentRef, Metadata, PersonRole};

use crate::util::{clean_str, rd_u16le, rd_u32le, truncate, utf16le};
use crate::{Ctx, MetaError};

const MAX_TEXT: usize = 16 << 20;
const MAX_DEPTH: u32 = 32;
const MAX_RECORDS: usize = 2_000_000;
/// Decompressed size of one embedded object.
const MAX_OBJECT: u64 = 64 << 20;

struct Walker<'a, 'c> {
    ctx: &'a Ctx<'c>,
    meta: &'a mut Metadata,
    text: String,
    edits: u32,
    objects: u32,
    records: usize,
    paths: Vec<String>,
    want_children: bool,
}

/// Parses the main stream: fills `meta` and returns the text.
pub(crate) fn parse(
    doc: &[u8],
    meta: &mut Metadata,
    ctx: &Ctx,
    want_children: bool,
) -> Result<String, MetaError> {
    let mut w = Walker {
        ctx,
        meta,
        text: String::new(),
        edits: 0,
        objects: 0,
        records: 0,
        paths: Vec::new(),
        want_children,
    };
    w.walk(doc, 0, doc.len(), 0)?;
    if w.edits > 0 {
        w.meta.stats.insert("saves".into(), u64::from(w.edits));
    }
    if !w.paths.is_empty() {
        let v = truncate(&w.paths.join("; "), 4096);
        w.meta.fields.insert("ppt:paths".into(), v);
    }
    if w.objects > 0 {
        w.meta.stats.insert("objects".into(), u64::from(w.objects));
    }
    Ok(w.text)
}

/// Record header: (instance, is container, type, body start, body end).
fn header(d: &[u8], p: usize, end: usize) -> Option<(u16, bool, u16, usize, usize)> {
    let vi = rd_u16le(d, p)?;
    let ty = rd_u16le(d, p + 2)?;
    let len = rd_u32le(d, p + 4)? as usize;
    let start = p + 8;
    let stop = start.checked_add(len)?;
    if stop > end {
        return None;
    }
    Some((vi >> 4, vi & 0x0F == 0x0F, ty, start, stop))
}

impl Walker<'_, '_> {
    fn walk(&mut self, d: &[u8], mut p: usize, end: usize, depth: u32) -> Result<(), MetaError> {
        while p + 8 <= end {
            self.records += 1;
            if self.records > MAX_RECORDS {
                return Ok(());
            }
            let Some((inst, container, ty, s, e)) = header(d, p, end) else {
                return Ok(());
            };
            let body = &d[s..e];
            match (container, ty) {
                // master slides hold layout prompts ("Click to edit Master title style")
                (true, 0x03F8) => {}
                (true, 0x0FF0) if inst == 1 => {}
                (true, 0x2EE0) => self.comment(d, s, e),
                (true, 0x0FD7) => self.hyperlink(d, s, e),
                (true, _) if depth < MAX_DEPTH => self.walk(d, s, e, depth + 1)?,
                (false, 0x0FA0) => self.push_text(&utf16le(body)),
                (false, 0x0FA8) => {
                    let t: String = body.iter().map(|&c| c as char).collect();
                    self.push_text(&t);
                }
                (false, 0x0FF5) => self.edits += 1,
                // CStrings of media and link objects keep source file paths
                (false, 0x0FBA) => {
                    let v = utf16le(body);
                    if (v.contains(":\\") || v.starts_with("\\\\")) && self.paths.len() < 200 {
                        if let Some(v) = clean_str(&v) {
                            if !self.paths.contains(&v) {
                                self.paths.push(v);
                            }
                        }
                    }
                }
                (false, 0x1011) => self.object(body, inst)?,
                _ => {}
            }
            p = e;
        }
        Ok(())
    }

    fn push_text(&mut self, t: &str) {
        // `*` stands for a slide number or date field
        if self.text.len() >= MAX_TEXT || t.trim() == "*" {
            return;
        }
        for c in t.chars() {
            self.text.push(match c {
                '\r' | '\u{0B}' => '\n',
                c => c,
            });
        }
        self.text.push('\n');
    }

    /// CString children (instance, text) of a container.
    fn strings(d: &[u8], mut p: usize, end: usize) -> Vec<(u16, String, u16, usize)> {
        let mut out = Vec::new();
        while p + 8 <= end {
            let Some((inst, _, ty, s, e)) = header(d, p, end) else {
                break;
            };
            out.push((inst, utf16le(&d[s..e]), ty, s));
            p = e;
        }
        out
    }

    fn comment(&mut self, d: &[u8], s: usize, e: usize) {
        let mut author = None;
        let mut initials = None;
        let mut text = String::new();
        let mut date = None;
        for (inst, v, ty, at) in Self::strings(d, s, e) {
            match (ty, inst) {
                (0x0FBA, 0) => author = clean_str(&v),
                (0x0FBA, 1) => text = v,
                (0x0FBA, 2) => initials = clean_str(&v),
                // Comment10Atom: index, then a SYSTEMTIME
                (0x2EE1, _) => date = systemtime(d, at + 4),
                _ => {}
            }
        }
        if let Some(a) = &author {
            self.meta
                .add_person(a, PersonRole::Comment, "ppt:Comment10");
        }
        self.push_text(&text);
        if self.meta.comments.len() < 2000 {
            self.meta.comments.push(CommentRef {
                author,
                initials,
                date,
                text: truncate(text.trim(), 2048),
                source: "ppt:Comment10".into(),
            });
        }
    }

    fn hyperlink(&mut self, d: &[u8], s: usize, e: usize) {
        for (inst, v, ty, _) in Self::strings(d, s, e) {
            if ty == 0x0FBA && inst == 1 {
                if let Some(v) = clean_str(&v) {
                    if self.meta.links.len() < 2000 {
                        Metadata::add_unique(&mut self.meta.links, &truncate(&v, 2048));
                    }
                }
            }
        }
    }

    /// ExOleObjStg: instance 1 = u32 decompressed size + zlib stream, 0 = raw.
    fn object(&mut self, body: &[u8], inst: u16) -> Result<(), MetaError> {
        self.objects += 1;
        if !self.want_children || !self.ctx.can_descend() {
            return Ok(());
        }
        let data = if inst == 1 {
            let size = u64::from(rd_u32le(body, 0).unwrap_or(0));
            let cap = size.min(MAX_OBJECT).min(self.ctx.remaining());
            let mut out = Vec::new();
            let z = flate2::read::ZlibDecoder::new(body.get(4..).unwrap_or(&[]));
            let _ = z.take(cap).read_to_end(&mut out);
            self.ctx.spend(out.len() as u64)?;
            out
        } else {
            body.to_vec()
        };
        if data.is_empty() {
            return Ok(());
        }
        let label = format!("ExOleObjStg{}", self.objects);
        self.ctx.attach_child(self.meta, &data, &label, &label)
    }
}

/// ISO date of a SYSTEMTIME (year, month, weekday, day, hour, minute, second, ms).
fn systemtime(d: &[u8], p: usize) -> Option<String> {
    let f = |i: usize| rd_u16le(d, p + i * 2);
    let (y, mo, day, h, mi, s) = (f(0)?, f(1)?, f(3)?, f(4)?, f(5)?, f(6)?);
    if !(1980..=2200).contains(&y) || !(1..=12).contains(&mo) || !(1..=31).contains(&day) {
        return None;
    }
    Some(format!(
        "{y:04}-{mo:02}-{day:02}T{:02}:{:02}:{:02}",
        h.min(23),
        mi.min(59),
        s.min(59)
    ))
}

#[cfg(test)]
mod tests;
