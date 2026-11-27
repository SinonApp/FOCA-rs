//! Page text extraction: interprets content streams with font state (`Tf`), decodes strings
//! through each font's ToUnicode CMap or encoding, places words with the text matrices
//! (`Td`/`TD`/`Tm`/`T*`/`'`/`"` and `TJ` offsets) and follows form XObjects.

use std::collections::HashSet;
use std::rc::Rc;

use super::fonts::{Font, FontCache};
use super::syntax::{content_str, dget, dname, Dict, Lex, Obj};
use super::{page_content, pages_at, Pdf, StreamCache};
use crate::{Ctx, MetaError};

/// Content stream operators interpreted per document.
const MAX_OPS: usize = 4_000_000;
/// Nesting of form XObjects.
const MAX_FORM_DEPTH: usize = 8;
/// Characters of extracted text per document.
const MAX_TEXT: usize = 32 << 20;

#[derive(Clone, Copy, Debug, PartialEq)]
struct M([f64; 6]);

const ID: M = M([1.0, 0.0, 0.0, 1.0, 0.0, 0.0]);

impl M {
    fn mul(self, o: M) -> M {
        let [a, b, c, d, e, f] = self.0;
        let [a2, b2, c2, d2, e2, f2] = o.0;
        M([
            a * a2 + b * c2,
            a * b2 + b * d2,
            c * a2 + d * c2,
            c * b2 + d * d2,
            e * a2 + f * c2 + e2,
            e * b2 + f * d2 + f2,
        ])
    }
    fn translate(x: f64, y: f64) -> M {
        M([1.0, 0.0, 0.0, 1.0, x, y])
    }
    fn finite(self) -> bool {
        self.0.iter().all(|v| v.is_finite())
    }
    fn from_ops(ops: &[Obj]) -> Option<M> {
        let v: Vec<f64> = ops.iter().filter_map(Obj::num).collect();
        let s = v.get(v.len().checked_sub(6)?..)?;
        let m = M([s[0], s[1], s[2], s[3], s[4], s[5]]);
        m.finite().then_some(m)
    }
}

fn last_nums<const N: usize>(ops: &[Obj]) -> Option<[f64; N]> {
    let v: Vec<f64> = ops.iter().filter_map(Obj::num).collect();
    let s = v.get(v.len().checked_sub(N)?..)?;
    let mut out = [0.0; N];
    out.copy_from_slice(s);
    out.iter().all(|x| x.is_finite()).then_some(out)
}

/// Graphics and text state saved by `q`/`Q`.
#[derive(Clone)]
struct Gs {
    ctm: M,
    font: Option<Rc<Font>>,
    fs: f64,
    char_sp: f64,
    word_sp: f64,
    scale: f64,
    leading: f64,
    rise: f64,
}

/// End of the last shown string in device space.
#[derive(Clone, Copy)]
struct Pen {
    x: f64,
    y: f64,
    size: f64,
}

struct Extractor<'p, 'b> {
    pdf: &'p Pdf<'b>,
    ctx: &'p Ctx<'p>,
    out: String,
    fonts: FontCache,
    ops: usize,
    pen: Option<Pen>,
}

impl<'p, 'b> Extractor<'p, 'b> {
    /// Places a shown string relative to the previous one: a line break when the baseline
    /// moved, a space when there is a visible gap.
    fn place(&mut self, x: f64, y: f64, size: f64, text: &str) {
        if let Some(p) = self.pen {
            let size_ref = p.size.max(size).max(0.1);
            if (y - p.y).abs() > 0.5 * size_ref {
                if !self.out.ends_with('\n') {
                    self.out.push('\n');
                }
            } else {
                let gap = x - p.x;
                let need = gap > 0.15 * size_ref || gap < -1.5 * size_ref;
                if need
                    && !self.out.ends_with([' ', '\n'])
                    && !text.starts_with(char::is_whitespace)
                {
                    self.out.push(' ');
                }
            }
        }
        if self.out.len() + text.len() <= MAX_TEXT {
            self.out.push_str(text);
        }
    }

    fn show(&mut self, items: &[Obj], gs: &Gs, tm: &mut M) {
        for it in items {
            match it {
                Obj::Str(s) => {
                    let start = M([gs.fs * gs.scale, 0.0, 0.0, gs.fs, 0.0, gs.rise])
                        .mul(*tm)
                        .mul(gs.ctm);
                    let (text, adv) = match &gs.font {
                        Some(f) => {
                            let sh = f.show(s);
                            let adv = (sh.width * gs.fs
                                + gs.char_sp * sh.glyphs as f64
                                + gs.word_sp * sh.spaces as f64)
                                * gs.scale;
                            (sh.text, adv)
                        }
                        None => {
                            let t = content_str(s);
                            let n = t.chars().count() as f64;
                            (t, (0.5 * gs.fs + gs.char_sp) * n * gs.scale)
                        }
                    };
                    if !start.finite() {
                        continue;
                    }
                    let size = (start.0[2].hypot(start.0[3])).abs();
                    if !text.is_empty() {
                        self.place(start.0[4], start.0[5], size, &text);
                    }
                    let next = M::translate(adv, 0.0).mul(*tm);
                    if next.finite() {
                        *tm = next;
                    }
                    if !text.is_empty() {
                        let end = M::translate(0.0, gs.rise).mul(*tm).mul(gs.ctm);
                        self.pen = Some(Pen {
                            x: end.0[4],
                            y: end.0[5],
                            size,
                        });
                    }
                }
                Obj::Num(k) if k.is_finite() => {
                    let next = M::translate(-k / 1000.0 * gs.fs * gs.scale, 0.0).mul(*tm);
                    if next.finite() {
                        *tm = next;
                    }
                }
                _ => {}
            }
        }
    }

    fn run(
        &mut self,
        data: &[u8],
        res: Option<&Dict>,
        ctm: M,
        depth: usize,
        forms: &mut HashSet<usize>,
    ) -> Result<(), MetaError> {
        let mut gs = Gs {
            ctm,
            font: None,
            fs: 0.0,
            char_sp: 0.0,
            word_sp: 0.0,
            scale: 1.0,
            leading: 0.0,
            rise: 0.0,
        };
        let mut stack: Vec<Gs> = Vec::new();
        let (mut tm, mut tlm) = (ID, ID);
        let mut ops: Vec<Obj> = Vec::new();
        let mut lx = Lex::new(data, 0, 8);
        while let Some(tok) = lx.parse(0) {
            self.ops += 1;
            if self.ops > MAX_OPS || self.out.len() > MAX_TEXT {
                break;
            }
            let Obj::Kw(k) = tok else {
                if ops.len() < 64 {
                    ops.push(tok);
                }
                if lx.at_end() {
                    break;
                }
                continue;
            };
            match k.as_str() {
                "q" => {
                    if stack.len() < 64 {
                        stack.push(gs.clone());
                    }
                }
                "Q" => {
                    if let Some(g) = stack.pop() {
                        gs = g;
                    }
                }
                "cm" => {
                    if let Some(m) = M::from_ops(&ops) {
                        let n = m.mul(gs.ctm);
                        if n.finite() {
                            gs.ctm = n;
                        }
                    }
                }
                "BT" => {
                    tm = ID;
                    tlm = ID;
                }
                "Tf" => {
                    if let [.., Obj::Name(n), Obj::Num(sz)] = ops.as_slice() {
                        gs.font = self.fonts.get(self.pdf, res, n, self.ctx);
                        if sz.is_finite() {
                            gs.fs = sz.clamp(-10_000.0, 10_000.0);
                        }
                    }
                }
                "Tc" => {
                    if let Some([v]) = last_nums::<1>(&ops) {
                        gs.char_sp = v.clamp(-1e4, 1e4);
                    }
                }
                "Tw" => {
                    if let Some([v]) = last_nums::<1>(&ops) {
                        gs.word_sp = v.clamp(-1e4, 1e4);
                    }
                }
                "Tz" => {
                    if let Some([v]) = last_nums::<1>(&ops) {
                        gs.scale = (v / 100.0).clamp(-100.0, 100.0);
                    }
                }
                "TL" => {
                    if let Some([v]) = last_nums::<1>(&ops) {
                        gs.leading = v.clamp(-1e5, 1e5);
                    }
                }
                "Ts" => {
                    if let Some([v]) = last_nums::<1>(&ops) {
                        gs.rise = v.clamp(-1e5, 1e5);
                    }
                }
                "Td" | "TD" => {
                    if let Some([tx, ty]) = last_nums::<2>(&ops) {
                        if k == "TD" {
                            gs.leading = (-ty).clamp(-1e5, 1e5);
                        }
                        let n = M::translate(tx, ty).mul(tlm);
                        if n.finite() {
                            tlm = n;
                            tm = n;
                        }
                    }
                }
                "Tm" => {
                    if let Some(m) = M::from_ops(&ops) {
                        tm = m;
                        tlm = m;
                    }
                }
                "T*" => {
                    tlm = M::translate(0.0, -gs.leading).mul(tlm);
                    tm = tlm;
                }
                "Tj" | "'" | "\"" | "TJ" => {
                    if k == "'" || k == "\"" {
                        if k == "\"" {
                            if let [Obj::Num(aw), Obj::Num(ac), ..] =
                                &ops[ops.len().saturating_sub(3)..]
                            {
                                gs.word_sp = aw.clamp(-1e4, 1e4);
                                gs.char_sp = ac.clamp(-1e4, 1e4);
                            }
                        }
                        tlm = M::translate(0.0, -gs.leading).mul(tlm);
                        tm = tlm;
                    }
                    match ops.last() {
                        Some(Obj::Arr(a)) if k == "TJ" => {
                            let a = a.clone();
                            self.show(&a, &gs, &mut tm);
                        }
                        Some(s @ Obj::Str(_)) if k != "TJ" => {
                            let s = s.clone();
                            self.show(std::slice::from_ref(&s), &gs, &mut tm);
                        }
                        _ => {}
                    }
                }
                "Do" => {
                    if let Some(Obj::Name(n)) = ops.last() {
                        self.form(res, n, gs.ctm, depth, forms)?;
                    }
                }
                "ID" => lx.skip_inline_image(),
                _ => {}
            }
            ops.clear();
            if lx.at_end() {
                break;
            }
        }
        Ok(())
    }

    /// Runs a form XObject (bounded depth, no cycles).
    fn form(
        &mut self,
        res: Option<&Dict>,
        name: &str,
        ctm: M,
        depth: usize,
        forms: &mut HashSet<usize>,
    ) -> Result<(), MetaError> {
        if depth >= MAX_FORM_DEPTH {
            return Ok(());
        }
        let Some(xo) = res
            .and_then(|r| dget(r, "XObject"))
            .map(|x| self.pdf.resolve(x))
            .and_then(Obj::dict)
        else {
            return Ok(());
        };
        let Some(o) = dget(xo, name).map(|x| self.pdf.resolve(x)) else {
            return Ok(());
        };
        let Obj::Stream(d, s, e) = o else {
            return Ok(());
        };
        if dname(d, "Subtype") != Some("Form") {
            return Ok(());
        }
        let key = o as *const Obj as usize;
        if !forms.insert(key) {
            return Ok(());
        }
        let Some(data) = self.pdf.decode(d, *s, *e, self.ctx)? else {
            forms.remove(&key);
            return Ok(());
        };
        let m = match dget(d, "Matrix").map(|x| self.pdf.resolve(x)) {
            Some(Obj::Arr(a)) => M::from_ops(a).unwrap_or(ID),
            _ => ID,
        };
        let fres = dget(d, "Resources")
            .map(|r| self.pdf.resolve(r))
            .and_then(Obj::dict)
            .or(res);
        let r = self.run(&data, fres, m.mul(ctm), depth + 1, forms);
        forms.remove(&key);
        r
    }
}

/// Text of every page with font-aware decoding. Returns `None` when the page tree is missing,
/// so the caller can fall back to the raw content-stream scan.
pub(super) fn pages_text(pdf: &Pdf, ctx: &Ctx) -> Result<Option<String>, MetaError> {
    let pages = pages_at(pdf, usize::MAX);
    if pages.is_empty() {
        return Ok(None);
    }
    let mut ex = Extractor {
        pdf,
        ctx,
        out: String::new(),
        fonts: FontCache::default(),
        ops: 0,
        pen: None,
    };
    let mut cache = StreamCache::new();
    for p in &pages {
        let data = page_content(pdf, p, usize::MAX, ctx, &mut cache)?;
        let mut forms = HashSet::new();
        ex.run(&data, p.res, ID, 0, &mut forms)?;
        if !ex.out.ends_with('\n') && !ex.out.is_empty() {
            ex.out.push('\n');
        }
        ex.out.push('\n');
        ex.pen = None;
        if ex.ops > MAX_OPS || ex.out.len() > MAX_TEXT {
            break;
        }
    }
    Ok(Some(ex.out))
}

#[cfg(test)]
mod tests {
    /// Builds a PDF from object bodies (object `i + 1` = `objs[i]`); `{stream:...}` bodies are
    /// written as streams with a correct `/Length`.
    fn build(objs: &[(&str, Option<&[u8]>)]) -> Vec<u8> {
        let mut b = b"%PDF-1.5\n".to_vec();
        for (i, (dict, data)) in objs.iter().enumerate() {
            b.extend_from_slice(format!("{} 0 obj\n", i + 1).as_bytes());
            match data {
                Some(d) => {
                    let dict = dict.replacen("<<", &format!("<< /Length {}", d.len()), 1);
                    b.extend_from_slice(dict.as_bytes());
                    b.extend_from_slice(b"\nstream\n");
                    b.extend_from_slice(d);
                    b.extend_from_slice(b"\nendstream");
                }
                None => b.extend_from_slice(dict.as_bytes()),
            }
            b.extend_from_slice(b"\nendobj\n");
        }
        b.extend_from_slice(b"trailer << /Root 1 0 R /ID [<0011AABB> <0011AABB>] >>\n%%EOF\n");
        b
    }

    fn text(b: &[u8]) -> String {
        crate::text(b, &crate::Limits::default()).unwrap()
    }

    const TOUNICODE: &[u8] = b"/CIDInit /ProcSet findresource begin\n\
        12 dict begin begincmap\n\
        1 begincodespacerange <0000> <FFFF> endcodespacerange\n\
        4 beginbfchar <0003> <0020> <0010> <0406> <0011> <FB01> <0012> <D83DDE00> endbfchar\n\
        2 beginbfrange <0020> <003F> <0410> <0040> <0042> [<0454> <0457> <0491>] endbfrange\n\
        endcmap CMapName currentdict /CMap defineresource pop end end";

    /// Two-byte Identity-H codes mapped through bfrange (base and array forms), bfchar
    /// (space, ligature, surrogate pair).
    #[test]
    fn identity_h_with_tounicode() {
        let content = b"BT /F1 12 Tf 72 700 Td <002F0030002800220010003200030040004100420003001100030012> Tj ET\n\
            BT /F1 12 Tf 72 680 Td [<0022>-3000<0022>] TJ ET";
        let pdf = build(&[
            ("<< /Type /Catalog /Pages 2 0 R /Lang (uk-UA) /MarkInfo << /Marked true >> >>", None),
            ("<< /Type /Pages /Kids [3 0 R] /Count 1 /MediaBox [0 0 595 842] >>", None),
            ("<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 5 0 R >> >> /Contents 4 0 R >>", None),
            ("<<>>", Some(content)),
            ("<< /Type /Font /Subtype /Type0 /BaseFont /ABCDEE+Georgia /Encoding /Identity-H /DescendantFonts [6 0 R] /ToUnicode 7 0 R >>", None),
            ("<< /Type /Font /Subtype /CIDFontType2 /BaseFont /ABCDEE+Georgia /DW 500 /W [3 [250]] >>", None),
            ("<<>>", Some(TOUNICODE)),
        ]);
        let t = text(&pdf);
        assert!(t.contains("ПРИВІТ єїґ fi \u{1F600}"), "{t:?}");
        // a large TJ offset is a word gap, a new baseline is a new line
        assert!(t.contains("\nВ В"), "{t:?}");
        let m = crate::extract(&pdf, Some("a.pdf"), &crate::Limits::default()).unwrap();
        assert_eq!(m.language.as_deref(), Some("uk-UA"));
        assert_eq!(m.fields.get("pdf:paper").map(String::as_str), Some("A4"));
        assert_eq!(
            m.fields.get("pdf:page_size").map(String::as_str),
            Some("595x842 pt")
        );
        assert_eq!(m.fields.get("pdf:tagged").map(String::as_str), Some("true"));
        assert_eq!(m.fields.get("pdf:ID").map(String::as_str), Some("0011AABB"));
        assert!(!m.fields.contains_key("pdf:ID_instance"));
    }

    #[test]
    fn simple_fonts_differences_winansi_and_forms() {
        // F1: /Differences with Cyrillic afii and uni names; F2: WinAnsi; the form draws F2 text.
        let content = b"BT /F1 10 Tf 1 0 0 1 72 700 Tm (\x41\x42\x43) Tj ( \x44) Tj ET\n\
            BT /F2 10 Tf 72 680 Td (caf\xe9 \x93quoted\x94) Tj T* (next) ' ET\n\
            q 1 0 0 1 0 -100 cm /Fm1 Do Q";
        let form = b"BT /F2 10 Tf 72 500 Td (inside form) Tj ET";
        let pdf = build(&[
            ("<< /Type /Catalog /Pages 2 0 R >>", None),
            ("<< /Type /Pages /Kids [3 0 R] /Count 1 >>", None),
            ("<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 5 0 R /F2 6 0 R >> /XObject << /Fm1 7 0 R >> >> /Contents 4 0 R >>", None),
            ("<<>>", Some(content)),
            ("<< /Type /Font /Subtype /Type1 /BaseFont /Custom /Encoding << /BaseEncoding /WinAnsiEncoding /Differences [65 /afii10017 /afii10066 /uni0432 68 /afii10103] >> >>", None),
            ("<< /Type /Font /Subtype /TrueType /BaseFont /Arial /Encoding /WinAnsiEncoding >>", None),
            ("<< /Type /XObject /Subtype /Form /BBox [0 0 612 792] /Resources << /Font << /F2 6 0 R >> >> >>", Some(form)),
        ]);
        let t = text(&pdf);
        assert!(t.contains("Абв і"), "{t:?}");
        assert!(t.contains("café \u{201C}quoted\u{201D}"), "{t:?}");
        assert!(t.contains("next"), "{t:?}");
        assert!(t.contains("inside form"), "{t:?}");
        let m = crate::extract(&pdf, Some("a.pdf"), &crate::Limits::default()).unwrap();
        assert_eq!(
            m.fields.get("pdf:paper").map(String::as_str),
            Some("Letter")
        );
        assert!(m.language.is_none());
    }

    #[test]
    fn self_referencing_form_and_garbage_do_not_hang() {
        let content = b"/Fm1 Do BT /F9 12 Tf (plain) Tj ET";
        let form = b"/Fm1 Do BT (loop) Tj ET";
        let pdf = build(&[
            ("<< /Type /Catalog /Pages 2 0 R >>", None),
            ("<< /Type /Pages /Kids [3 0 R] /Count 1 >>", None),
            (
                "<< /Type /Page /Parent 2 0 R /Resources 5 0 R /Contents 4 0 R >>",
                None,
            ),
            ("<<>>", Some(content)),
            ("<< /XObject << /Fm1 6 0 R >> >>", None),
            (
                "<< /Type /XObject /Subtype /Form /Resources 5 0 R >>",
                Some(form),
            ),
        ]);
        let t = text(&pdf);
        assert!(t.contains("plain"), "{t:?}");
        assert_eq!(t.matches("loop").count(), 1, "{t:?}");
        // deterministic byte flips over the fixture: never panic
        let mut x = 0x9E37_79B9u32;
        for _ in 0..300 {
            let mut b = pdf.clone();
            for _ in 0..4 {
                x ^= x << 13;
                x ^= x >> 17;
                x ^= x << 5;
                let i = (x as usize) % b.len();
                b[i] = (x >> 8) as u8;
            }
            let _ = crate::text(&b, &crate::Limits::default());
        }
    }

    #[test]
    fn bad_redaction_text_uses_tounicode() {
        let content = b"BT /F1 12 Tf 72 700 Td <002F0030002800220010003200030040> Tj ET 0 g 70 695 200 20 re f";
        let pdf = build(&[
            ("<< /Type /Catalog /Pages 2 0 R >>", None),
            ("<< /Type /Pages /Kids [3 0 R] /Count 1 /MediaBox [0 0 612 792] >>", None),
            ("<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 5 0 R >> >> /Contents 4 0 R >>", None),
            ("<<>>", Some(content)),
            ("<< /Type /Font /Subtype /Type0 /BaseFont /X /Encoding /Identity-H /DescendantFonts [6 0 R] /ToUnicode 7 0 R >>", None),
            ("<< /Type /Font /Subtype /CIDFontType2 /BaseFont /X >>", None),
            ("<<>>", Some(TOUNICODE)),
        ]);
        let m = crate::extract(&pdf, Some("a.pdf"), &crate::Limits::default()).unwrap();
        assert_eq!(m.bad_redactions.len(), 1, "{:?}", m.bad_redactions);
        assert!(
            m.bad_redactions[0].text.contains("ПРИВІТ"),
            "{:?}",
            m.bad_redactions
        );
    }
}
