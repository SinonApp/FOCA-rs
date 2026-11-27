//! Fonts for text extraction: ToUnicode CMaps (codespace ranges, `bfchar`, `bfrange` with
//! base and array destinations), simple-font encodings with `/Differences`, and glyph widths
//! used to place words on a line.

use std::collections::HashMap;
use std::rc::Rc;

use super::glyphs::{expand_ligature, glyph_text, BaseEncoding};
use super::syntax::{content_str, dget, dname, Dict, Lex, Obj};
use super::Pdf;
use crate::Ctx;

/// Entries kept per CMap (bfchar plus expanded ranges).
const MAX_CMAP_ENTRIES: usize = 200_000;
/// Ranges wider than this stay as ranges instead of being expanded.
const EXPAND_RANGE: u32 = 256;
/// Tokens read from one CMap stream.
const MAX_CMAP_TOKENS: usize = 2_000_000;

#[derive(Debug, Clone)]
enum RangeDst {
    /// UTF-16 units of the first code; the last unit grows with the code.
    Base(Vec<u16>),
    /// One destination per code.
    Arr(Vec<String>),
}

/// A parsed ToUnicode CMap.
#[derive(Debug, Default, Clone)]
pub(crate) struct CMap {
    /// Codespace ranges: byte length, low, high.
    codespace: Vec<(u8, u32, u32)>,
    map: HashMap<(u8, u32), String>,
    ranges: Vec<(u8, u32, u32, RangeDst)>,
}

fn be_code(b: &[u8]) -> Option<(u8, u32)> {
    if b.is_empty() || b.len() > 4 {
        return None;
    }
    Some((
        b.len() as u8,
        b.iter().fold(0u32, |a, &c| (a << 8) | u32::from(c)),
    ))
}

fn utf16_units(b: &[u8]) -> Vec<u16> {
    b.as_chunks::<2>()
        .0
        .iter()
        .map(|c| u16::from_be_bytes(*c))
        .collect()
}

/// Destination string of a CMap entry: UTF-16BE bytes (a single byte is taken as is).
fn dst_text(b: &[u8]) -> String {
    if b.len() == 1 {
        return char::from(b[0]).to_string();
    }
    String::from_utf16_lossy(&utf16_units(b))
}

impl CMap {
    pub(crate) fn parse(data: &[u8]) -> CMap {
        let mut cm = CMap::default();
        let mut lx = Lex::new(data, 0, 4);
        let mut toks: Vec<Obj> = Vec::new();
        let mut mode = "";
        let mut n = 0usize;
        while let Some(t) = lx.parse(0) {
            n += 1;
            if n > MAX_CMAP_TOKENS {
                break;
            }
            match t {
                Obj::Kw(k) => {
                    match k.as_str() {
                        "begincodespacerange" => mode = "cs",
                        "beginbfchar" => mode = "char",
                        "beginbfrange" => mode = "range",
                        "endcodespacerange" | "endbfchar" | "endbfrange" => mode = "",
                        _ => {}
                    }
                    toks.clear();
                }
                other if !mode.is_empty() => {
                    toks.push(other);
                    cm.take(mode, &mut toks);
                }
                _ => {}
            }
            if lx.at_end() {
                break;
            }
        }
        cm
    }

    fn entries(&self) -> usize {
        self.map.len() + self.ranges.len()
    }

    /// Consumes a complete group of operands for the current section.
    fn take(&mut self, mode: &str, toks: &mut Vec<Obj>) {
        match (mode, toks.as_slice()) {
            ("cs", [Obj::Str(lo), Obj::Str(hi)]) => {
                if let (Some((l, a)), Some((_, b))) = (be_code(lo), be_code(hi)) {
                    if self.codespace.len() < 64 {
                        self.codespace.push((l, a.min(b), a.max(b)));
                    }
                }
                toks.clear();
            }
            ("char", [Obj::Str(src), dst]) => {
                let text = match dst {
                    Obj::Str(d) => Some(dst_text(d)),
                    Obj::Name(n) => glyph_text(n),
                    _ => None,
                };
                if let (Some(code), Some(t)) = (be_code(src), text) {
                    if self.entries() < MAX_CMAP_ENTRIES {
                        self.map.insert(code, t);
                    }
                }
                toks.clear();
            }
            ("range", [Obj::Str(lo), Obj::Str(hi), dst]) => {
                if let (Some((l, a)), Some((_, b))) = (be_code(lo), be_code(hi)) {
                    let (a, b) = (a.min(b), a.max(b));
                    let dst = match dst {
                        Obj::Str(d) => Some(RangeDst::Base(utf16_units(d))),
                        Obj::Arr(arr) => Some(RangeDst::Arr(
                            arr.iter()
                                .map(|x| match x {
                                    Obj::Str(d) => dst_text(d),
                                    _ => String::new(),
                                })
                                .collect(),
                        )),
                        _ => None,
                    };
                    if let Some(dst) = dst {
                        self.add_range(l, a, b, dst);
                    }
                }
                toks.clear();
            }
            (_, t) if t.len() >= 3 => toks.clear(),
            _ => {}
        }
    }

    fn add_range(&mut self, l: u8, a: u32, b: u32, dst: RangeDst) {
        if self.entries() >= MAX_CMAP_ENTRIES {
            return;
        }
        if b - a < EXPAND_RANGE {
            for c in a..=b {
                if self.entries() >= MAX_CMAP_ENTRIES {
                    break;
                }
                if let Some(t) = range_text(&dst, c - a) {
                    self.map.insert((l, c), t);
                }
            }
        } else {
            self.ranges.push((l, a, b, dst));
        }
    }

    pub(crate) fn lookup(&self, len: u8, code: u32) -> Option<String> {
        if let Some(t) = self.map.get(&(len, code)) {
            return Some(t.clone());
        }
        self.ranges
            .iter()
            .find(|(l, a, b, _)| *l == len && (*a..=*b).contains(&code))
            .and_then(|(_, a, _, d)| range_text(d, code - a))
    }

    fn in_codespace(&self, len: u8, code: u32) -> bool {
        self.codespace
            .iter()
            .any(|(l, a, b)| *l == len && (*a..=*b).contains(&code))
    }

    /// Byte length of the code at the start of `s` per the codespace ranges, or `None` when
    /// no range matches (or none is declared).
    fn code_len(&self, s: &[u8]) -> Option<usize> {
        (1..=4usize.min(s.len()))
            .find(|&n| be_code(&s[..n]).is_some_and(|(l, c)| self.in_codespace(l, c)))
    }
}

fn range_text(d: &RangeDst, off: u32) -> Option<String> {
    match d {
        RangeDst::Base(units) => {
            let mut u = units.clone();
            let last = u.last_mut()?;
            *last = u16::try_from(u32::from(*last) + off).ok()?;
            Some(String::from_utf16_lossy(&u))
        }
        RangeDst::Arr(v) => v.get(off as usize).cloned(),
    }
}

/// Glyph widths in thousandths of text space.
#[derive(Debug, Clone)]
enum Widths {
    Simple {
        first: u32,
        w: Vec<f64>,
        missing: f64,
    },
    Cid {
        dw: f64,
        w: Vec<(u32, u32, f64)>,
    },
}

/// How a font turns string bytes into characters.
#[derive(Debug, Clone)]
pub(crate) struct Font {
    /// Fixed code length when no codespace applies (2 for Type0, else 1).
    code_len: u8,
    /// Codespace ranges of an embedded encoding CMap (Type0 with a non-Identity encoding).
    encoding_cs: Option<CMap>,
    to_unicode: Option<CMap>,
    /// Simple fonts: base encoding plus `/Differences`.
    simple: Option<Vec<Option<String>>>,
    /// Predefined Unicode CMaps (`UniGB-UCS2-H`, `UniJIS-UTF16-H`): codes are UTF-16BE.
    utf16: bool,
    widths: Widths,
    /// Multiplier from width units to text space (1/1000, or the Type3 FontMatrix).
    scale: f64,
}

/// One shown string: text, total glyph width (text space units before font size), glyph
/// count and number of single-byte space codes (for word spacing).
pub(crate) struct Shown {
    pub(crate) text: String,
    pub(crate) width: f64,
    pub(crate) glyphs: usize,
    pub(crate) spaces: usize,
}

fn num_arr(o: Option<&Obj>, pdf: &Pdf) -> Vec<f64> {
    match o.map(|x| pdf.resolve(x)) {
        Some(Obj::Arr(a)) => a
            .iter()
            .take(70_000)
            .map(|x| pdf.resolve(x).num().unwrap_or(0.0))
            .collect(),
        _ => Vec::new(),
    }
}

fn stream_data(pdf: &Pdf, o: Option<&Obj>, ctx: &Ctx) -> Option<Vec<u8>> {
    match o.map(|x| pdf.resolve(x)) {
        Some(Obj::Stream(d, s, e)) => pdf.decode(d, *s, *e, ctx).ok().flatten(),
        _ => None,
    }
}

impl Font {
    /// Builds a font from its dictionary. Never fails: unknown parts fall back to defaults.
    pub(crate) fn load(pdf: &Pdf, d: &Dict, ctx: &Ctx) -> Font {
        let subtype = dname(d, "Subtype").unwrap_or("");
        let to_unicode = stream_data(pdf, dget(d, "ToUnicode"), ctx).map(|b| CMap::parse(&b));
        if subtype == "Type0" {
            let desc = match dget(d, "DescendantFonts").map(|x| pdf.resolve(x)) {
                Some(Obj::Arr(a)) => a.first().and_then(|x| pdf.resolve(x).dict()),
                _ => None,
            };
            let (mut utf16, mut encoding_cs) = (false, None);
            match dget(d, "Encoding").map(|x| pdf.resolve(x)) {
                Some(Obj::Name(n)) => {
                    utf16 = n.starts_with("Uni") && (n.contains("UCS2") || n.contains("UTF16"));
                }
                Some(Obj::Stream(..)) => {
                    encoding_cs =
                        stream_data(pdf, dget(d, "Encoding"), ctx).map(|b| CMap::parse(&b));
                }
                _ => {}
            }
            let dw = desc
                .and_then(|x| dget(x, "DW"))
                .and_then(|x| pdf.resolve(x).num())
                .unwrap_or(1000.0);
            let mut w = Vec::new();
            if let Some(Obj::Arr(a)) = desc.and_then(|x| dget(x, "W")).map(|x| pdf.resolve(x)) {
                let mut i = 0;
                while i < a.len() && w.len() < 70_000 {
                    let first = pdf.resolve(&a[i]).num().unwrap_or(0.0).max(0.0) as u32;
                    match a.get(i + 1).map(|x| pdf.resolve(x)) {
                        Some(Obj::Arr(ws)) => {
                            for (k, x) in ws.iter().enumerate().take(70_000) {
                                let c = first.saturating_add(k as u32);
                                w.push((c, c, pdf.resolve(x).num().unwrap_or(dw)));
                            }
                            i += 2;
                        }
                        Some(Obj::Num(last)) => {
                            let width = a
                                .get(i + 2)
                                .and_then(|x| pdf.resolve(x).num())
                                .unwrap_or(dw);
                            w.push((first, (*last).max(0.0) as u32, width));
                            i += 3;
                        }
                        _ => break,
                    }
                }
            }
            return Font {
                code_len: 2,
                encoding_cs,
                to_unicode,
                simple: None,
                utf16,
                widths: Widths::Cid { dw, w },
                scale: 0.001,
            };
        }
        // simple fonts: Type1, MMType1, TrueType, Type3
        let enc = dget(d, "Encoding").map(|x| pdf.resolve(x));
        let default_base = if matches!(subtype, "Type1" | "MMType1") {
            BaseEncoding::Standard
        } else {
            BaseEncoding::WinAnsi
        };
        let (base, diffs) = match enc {
            Some(Obj::Name(n)) => (BaseEncoding::from_name(n).unwrap_or(default_base), None),
            Some(Obj::Dict(e)) => (
                dname(e, "BaseEncoding")
                    .and_then(BaseEncoding::from_name)
                    .unwrap_or(default_base),
                dget(e, "Differences").map(|x| pdf.resolve(x)),
            ),
            _ => (default_base, None),
        };
        let mut table: Vec<Option<String>> = (0..=255u8)
            .map(|c| base.char_of(c).map(String::from))
            .collect();
        if let Some(Obj::Arr(a)) = diffs {
            let mut code = 0usize;
            for x in a.iter().take(4096) {
                match pdf.resolve(x) {
                    Obj::Num(n) => code = n.max(0.0) as usize,
                    Obj::Name(name) => {
                        if let Some(slot) = table.get_mut(code) {
                            *slot = glyph_text(name);
                        }
                        code += 1;
                    }
                    _ => {}
                }
            }
        }
        let missing = dget(d, "FontDescriptor")
            .and_then(|x| pdf.resolve(x).dict())
            .and_then(|fd| dget(fd, "MissingWidth"))
            .and_then(|x| pdf.resolve(x).num())
            .unwrap_or(0.0);
        let scale = if subtype == "Type3" {
            num_arr(dget(d, "FontMatrix"), pdf)
                .first()
                .copied()
                .filter(|v| v.is_finite() && *v != 0.0)
                .map_or(0.001, f64::abs)
        } else {
            0.001
        };
        Font {
            code_len: 1,
            encoding_cs: None,
            to_unicode,
            simple: Some(table),
            utf16: false,
            widths: Widths::Simple {
                first: dget(d, "FirstChar")
                    .and_then(|x| pdf.resolve(x).num())
                    .unwrap_or(0.0)
                    .max(0.0) as u32,
                w: num_arr(dget(d, "Widths"), pdf),
                missing,
            },
            scale,
        }
    }

    /// Length of the code starting at `s[0]`: the embedded encoding CMap decides, then the
    /// ToUnicode codespace (simple fonts and non-Identity CMaps), then the fixed length.
    fn code_len_at(&self, s: &[u8]) -> usize {
        let from_cs = self
            .encoding_cs
            .as_ref()
            .and_then(|c| c.code_len(s))
            .or_else(|| {
                self.to_unicode
                    .as_ref()
                    .filter(|_| self.code_len != 2)
                    .and_then(|c| c.code_len(s))
            });
        from_cs.unwrap_or_else(|| usize::from(self.code_len).min(s.len()).max(1))
    }

    fn width_of(&self, code: u32) -> f64 {
        let w = match &self.widths {
            Widths::Simple { first, w, missing } => code
                .checked_sub(*first)
                .and_then(|i| w.get(i as usize).copied())
                .filter(|v| *v > 0.0)
                .unwrap_or(if *missing > 0.0 { *missing } else { 500.0 }),
            Widths::Cid { dw, w } => w
                .iter()
                .find(|(a, b, _)| (*a..=*b).contains(&code))
                .map_or(*dw, |x| x.2),
        };
        if w.is_finite() {
            w.clamp(0.0, 1e5)
        } else {
            0.0
        }
    }

    /// Decodes the bytes of one shown string.
    pub(crate) fn show(&self, s: &[u8]) -> Shown {
        let mut out = Shown {
            text: String::new(),
            width: 0.0,
            glyphs: 0,
            spaces: 0,
        };
        if self.utf16 {
            out.text = String::from_utf16_lossy(&utf16_units(s));
            out.glyphs = s.len() / 2;
            out.width = out.glyphs as f64 * self.width_of(0) * self.scale;
            return out;
        }
        let mut i = 0;
        let mut unmapped = 0usize;
        while i < s.len() {
            let n = self.code_len_at(&s[i..]);
            let (len, code) = be_code(&s[i..i + n]).unwrap_or((1, 0));
            i += n;
            out.glyphs += 1;
            out.width += self.width_of(code) * self.scale;
            if n == 1 && code == 32 {
                out.spaces += 1;
            }
            let t = self
                .to_unicode
                .as_ref()
                .and_then(|cm| cm.lookup(len, code))
                .or_else(|| {
                    self.simple
                        .as_ref()
                        .and_then(|t| t.get(code as usize).cloned().flatten())
                });
            match t {
                Some(t) => push_clean(&mut out.text, &t),
                None => unmapped += 1,
            }
        }
        // Type0 font without a usable ToUnicode: keep the legacy guess for the raw bytes.
        if self.simple.is_none() && unmapped == out.glyphs && out.glyphs > 0 {
            out.text = content_str(s);
        }
        out
    }
}

/// Fonts loaded once per document, keyed by the font object.
#[derive(Default)]
pub(crate) struct FontCache {
    map: HashMap<usize, Rc<Font>>,
}

impl FontCache {
    /// The font named `name` in the `/Font` resources of `res`.
    pub(crate) fn get(
        &mut self,
        pdf: &Pdf,
        res: Option<&Dict>,
        name: &str,
        ctx: &Ctx,
    ) -> Option<Rc<Font>> {
        let fonts = res
            .and_then(|r| dget(r, "Font"))
            .map(|f| pdf.resolve(f))
            .and_then(Obj::dict)?;
        let fo = pdf.resolve(dget(fonts, name)?);
        let d = fo.dict()?;
        let key = fo as *const Obj as usize;
        if let Some(f) = self.map.get(&key) {
            return Some(f.clone());
        }
        let f = Rc::new(Font::load(pdf, d, ctx));
        if self.map.len() < 4096 {
            self.map.insert(key, f.clone());
        }
        Some(f)
    }
}

/// Appends text, dropping control characters and expanding ligatures.
fn push_clean(out: &mut String, t: &str) {
    for c in t.chars() {
        if let Some(l) = expand_ligature(c) {
            out.push_str(l);
        } else if c == '\t' || !c.is_control() {
            out.push(c);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cmap_bfchar_bfrange_and_codespace() {
        let cm = CMap::parse(
            b"/CIDInit /ProcSet findresource begin 12 dict begin begincmap\n\
              1 begincodespacerange <0000> <FFFF> endcodespacerange\n\
              3 beginbfchar <0003> <0020> <0010> <D83DDE00> <0011> <00660069> endbfchar\n\
              2 beginbfrange <0020> <0022> <0410> <0030> <0031> [<0436> <FB01>] endbfrange\n\
              1 beginbfrange <1000> <2000> <4E00> endbfrange\n\
              endcmap",
        );
        assert_eq!(cm.lookup(2, 3).as_deref(), Some(" "));
        assert_eq!(cm.lookup(2, 0x10).as_deref(), Some("\u{1F600}"));
        assert_eq!(cm.lookup(2, 0x11).as_deref(), Some("fi"));
        assert_eq!(cm.lookup(2, 0x22).as_deref(), Some("В"));
        assert_eq!(cm.lookup(2, 0x30).as_deref(), Some("ж"));
        assert_eq!(cm.lookup(2, 0x31).as_deref(), Some("\u{FB01}"));
        assert_eq!(cm.lookup(2, 0x1005).as_deref(), Some("\u{4E05}"));
        assert_eq!(cm.lookup(2, 0x9999), None);
        assert!(cm.in_codespace(2, 0x1234));
        assert!(!cm.in_codespace(1, 0x12));
    }

    #[test]
    fn cmap_mixed_codespace_splits_codes() {
        let cm = CMap::parse(
            b"2 begincodespacerange <00> <80> <8140> <FFFF> endcodespacerange\n\
              2 beginbfchar <41> <0041> <8140> <3042> endbfchar",
        );
        let f = Font {
            code_len: 2,
            encoding_cs: Some(cm.clone()),
            to_unicode: Some(cm),
            simple: None,
            utf16: false,
            widths: Widths::Cid {
                dw: 1000.0,
                w: vec![],
            },
            scale: 0.001,
        };
        let s = f.show(b"\x41\x81\x40\x41");
        assert_eq!(s.text, "A\u{3042}A");
        assert_eq!(s.glyphs, 3);
    }

    #[test]
    fn cmap_garbage_never_panics() {
        let mut x = 0x1234_5678u32;
        for _ in 0..200 {
            let mut v = Vec::new();
            for _ in 0..300 {
                x ^= x << 13;
                x ^= x >> 17;
                x ^= x << 5;
                v.push(
                    b"<>[]0Fbegincodespacerange beginbfrange endbfchar beginbfchar 1 "
                        [(x as usize) % 59],
                );
            }
            let cm = CMap::parse(&v);
            let _ = cm.lookup(2, 0);
        }
    }
}
