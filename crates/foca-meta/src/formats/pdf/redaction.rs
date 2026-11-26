//! Bad redaction detector for PDF content streams.
//!
//! A minimal content-stream interpreter tracks the current transformation matrix (`cm`, `q`/`Q`),
//! the text matrices (`BT`, `Tm`, `Td`, `TD`, `T*`, `TL`, `Tf`, `Tz`, `Ts`, `Tr`), the fill colour
//! (`g`, `rg`, `k`, `sc`, `scn`, `cs`) and rectangle paths (`re` + `f`/`F`/`f*`/`B`/`b`). Text shown
//! with `Tj`/`TJ`/`'`/`"` gets an approximate bounding box (glyph width 0.5 em). Text is
//! reported when an opaque black or white rectangle painted *after* it covers most of its box:
//! the classic "black box drawn over text" redaction that leaves the text extractable.
//!
//! Limits: glyph widths are approximated, form XObjects are not entered, soft masks and
//! transparency (`gs` with `ca` < 1) are not evaluated, and clipping is ignored.

use std::collections::HashSet;

use super::syntax::{content_str, Lex, Obj};

/// Affine matrix `[a b c d e f]`.
#[derive(Clone, Copy, Debug, PartialEq)]
struct M([f64; 6]);

const ID: M = M([1.0, 0.0, 0.0, 1.0, 0.0, 0.0]);

impl M {
    /// `self × other`: apply `self`, then `other`.
    fn mul(self, o: M) -> M {
        let [a, b, c, d, e, f] = self.0;
        let [oa, ob, oc, od, oe, of] = o.0;
        M([
            a * oa + b * oc,
            a * ob + b * od,
            c * oa + d * oc,
            c * ob + d * od,
            e * oa + f * oc + oe,
            e * ob + f * od + of,
        ])
    }

    fn apply(self, x: f64, y: f64) -> (f64, f64) {
        let [a, b, c, d, e, f] = self.0;
        (a * x + c * y + e, b * x + d * y + f)
    }

    fn translate(tx: f64, ty: f64) -> M {
        M([1.0, 0.0, 0.0, 1.0, tx, ty])
    }

    fn finite(&self) -> bool {
        self.0.iter().all(|v| v.is_finite() && v.abs() < 1e9)
    }
}

/// Axis-aligned box `[x0, y0, x1, y1]`.
type Rect = [f64; 4];

fn bbox(m: M, x0: f64, y0: f64, x1: f64, y1: f64) -> Option<Rect> {
    let pts = [
        m.apply(x0, y0),
        m.apply(x1, y0),
        m.apply(x0, y1),
        m.apply(x1, y1),
    ];
    let mut r = [f64::MAX, f64::MAX, f64::MIN, f64::MIN];
    for (x, y) in pts {
        if !x.is_finite() || !y.is_finite() {
            return None;
        }
        r[0] = r[0].min(x);
        r[1] = r[1].min(y);
        r[2] = r[2].max(x);
        r[3] = r[3].max(y);
    }
    Some(r)
}

fn area(r: &Rect) -> f64 {
    (r[2] - r[0]).max(0.0) * (r[3] - r[1]).max(0.0)
}

fn intersection(a: &Rect, b: &Rect) -> f64 {
    let w = a[2].min(b[2]) - a[0].max(b[0]);
    let h = a[3].min(b[3]) - a[1].max(b[1]);
    if w <= 0.0 || h <= 0.0 {
        0.0
    } else {
        w * h
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Fill {
    Black,
    White,
    Other,
}

impl Fill {
    pub(crate) fn name(self) -> &'static str {
        match self {
            Fill::Black => "black",
            Fill::White => "white",
            Fill::Other => "other",
        }
    }

    pub(crate) fn from_components(v: &[f64]) -> Fill {
        let lo = |x: &f64| *x <= 0.05;
        let hi = |x: &f64| *x >= 0.95;
        match v {
            [g] if lo(g) => Fill::Black,
            [g] if hi(g) => Fill::White,
            [r, g, b] if lo(r) && lo(g) && lo(b) => Fill::Black,
            [r, g, b] if hi(r) && hi(g) && hi(b) => Fill::White,
            [c, m, y, k] if hi(k) || (hi(c) && hi(m) && hi(y)) => Fill::Black,
            [c, m, y, k] if lo(c) && lo(m) && lo(y) && lo(k) => Fill::White,
            _ => Fill::Other,
        }
    }
}

#[derive(Clone, Copy)]
struct Gs {
    ctm: M,
    fill: Fill,
}

struct TextItem {
    seq: usize,
    rect: Rect,
    text: String,
}

struct BoxItem {
    seq: usize,
    rect: Rect,
    fill: Fill,
}

/// An opaque rectangle supplied from outside the content stream (an unapplied `/Redact`
/// annotation); it is treated as painted after the page content.
pub(crate) struct ExtraBox {
    pub rect: [f64; 4],
    pub fill: Fill,
}

/// A detected redaction failure on one page.
pub(crate) struct Hit {
    pub text: String,
    pub fill: Fill,
    pub rect: [f64; 4],
}

/// Result of interpreting one page.
#[derive(Default)]
pub(crate) struct PageScan {
    /// Visible non-whitespace characters.
    pub visible_chars: usize,
    /// Characters drawn in invisible mode (`3 Tr`, typical OCR layers).
    pub invisible_chars: usize,
    /// Image XObjects and inline images painted.
    pub images: usize,
    pub hits: Vec<Hit>,
    /// Extracted text with line breaks, used for revision diffs.
    pub text: String,
}

const MAX_OPS: usize = 2_000_000;
const MAX_ITEMS: usize = 100_000;
const MAX_HITS: usize = 50;

fn nums(ops: &[Obj]) -> Vec<f64> {
    ops.iter()
        .filter_map(|o| match o {
            Obj::Num(n) if n.is_finite() => Some(*n),
            _ => None,
        })
        .collect()
}

fn last_n<const N: usize>(ops: &[Obj]) -> Option<[f64; N]> {
    let v = nums(ops);
    let s = v.get(v.len().checked_sub(N)?..)?;
    let mut out = [0.0; N];
    out.copy_from_slice(s);
    Some(out)
}

/// Interprets a page content stream. `image_names` are `/XObject` resource names that refer
/// to images; `page_box` is the MediaBox (boxes larger than 80 % of it are ignored).
pub(crate) fn scan_page(
    data: &[u8],
    image_names: &HashSet<String>,
    page_box: Option<[f64; 4]>,
    extra: &[ExtraBox],
) -> PageScan {
    let mut out = PageScan::default();
    let mut gs = Gs {
        ctm: ID,
        fill: Fill::Black,
    };
    let mut stack: Vec<Gs> = Vec::new();
    let mut tm = ID;
    let mut tlm = ID;
    let (mut fs, mut th, mut rise, mut leading, mut mode) = (0.0f64, 1.0f64, 0.0f64, 0.0f64, 0i64);
    let (mut char_sp, mut word_sp) = (0.0f64, 0.0f64);
    let mut path: Vec<Rect> = Vec::new();
    let mut path_complex = false;
    let mut texts: Vec<TextItem> = Vec::new();
    let mut boxes: Vec<BoxItem> = Vec::new();
    let mut seq = 0usize;
    let mut ops: Vec<Obj> = Vec::new();
    let mut lx = Lex::new(data, 0, 8);
    let mut nops = 0usize;
    let mut line_open = false;

    // Shows a run of strings/kerning numbers.
    let show = |items: &[Obj],
                tm: &mut M,
                gs: &Gs,
                fs: f64,
                th: f64,
                rise: f64,
                mode: i64,
                char_sp: f64,
                word_sp: f64,
                seq: usize,
                out: &mut PageScan,
                texts: &mut Vec<TextItem>| {
        let mut run = String::new();
        let start = *tm;
        let mut width = 0.0f64; // text space units (already scaled by fs)
        for it in items {
            match it {
                Obj::Str(s) => {
                    let t = content_str(s);
                    let n = t.chars().count() as f64;
                    let spaces = t.chars().filter(|c| *c == ' ').count() as f64;
                    width += (n * (0.5 * fs + char_sp) + spaces * word_sp) * th;
                    run.push_str(&t);
                }
                Obj::Num(k) if k.is_finite() => {
                    width -= k / 1000.0 * fs * th;
                    if *k < -200.0 {
                        run.push(' ');
                    }
                }
                _ => {}
            }
        }
        let visible = run.chars().filter(|c| !c.is_whitespace()).count();
        if mode == 3 || mode == 7 {
            out.invisible_chars += visible;
        } else {
            out.visible_chars += visible;
            let trm = M([1.0, 0.0, 0.0, 1.0, 0.0, rise]).mul(start).mul(gs.ctm);
            if visible > 0 && texts.len() < MAX_ITEMS && trm.finite() {
                let lo = -0.2 * fs;
                let hi = 0.8 * fs;
                if let Some(r) = bbox(trm, 0.0, lo, width.max(0.0), hi) {
                    texts.push(TextItem {
                        seq,
                        rect: r,
                        text: run.clone(),
                    });
                }
            }
        }
        out.text.push_str(&run);
        *tm = M::translate(width, 0.0).mul(*tm);
    };

    while let Some(tok) = lx.parse(0) {
        nops += 1;
        if nops > MAX_OPS {
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
        seq += 1;
        match k.as_str() {
            "q" => {
                if stack.len() < 64 {
                    stack.push(gs);
                }
            }
            "Q" => {
                if let Some(g) = stack.pop() {
                    gs = g;
                }
            }
            "cm" => {
                if let Some(m) = last_n::<6>(&ops) {
                    let n = M(m).mul(gs.ctm);
                    if n.finite() {
                        gs.ctm = n;
                    }
                }
            }
            "g" | "rg" | "k" | "sc" | "scn" => {
                let v = nums(&ops);
                let want = match k.as_str() {
                    "g" => 1,
                    "rg" => 3,
                    "k" => 4,
                    _ => v.len(),
                };
                gs.fill = match (v.len() >= want, ops.last()) {
                    (_, Some(Obj::Name(_))) => Fill::Other,
                    (true, _) if matches!(want, 1 | 3 | 4) => {
                        Fill::from_components(&v[v.len() - want..])
                    }
                    _ => Fill::Other,
                };
            }
            "cs" => gs.fill = Fill::Black,
            "re" => {
                if let Some([x, y, w, h]) = last_n::<4>(&ops) {
                    if let Some(r) = bbox(gs.ctm, x, y, x + w, y + h) {
                        if path.len() < 10_000 {
                            path.push(r);
                        }
                    }
                }
            }
            "m" | "l" | "c" | "v" | "y" | "h" => path_complex = true,
            "f" | "F" | "f*" | "B" | "B*" | "b" | "b*" => {
                if !path_complex && matches!(gs.fill, Fill::Black | Fill::White) {
                    for r in path.drain(..) {
                        if boxes.len() < MAX_ITEMS {
                            boxes.push(BoxItem {
                                seq,
                                rect: r,
                                fill: gs.fill,
                            });
                        }
                    }
                }
                path.clear();
                path_complex = false;
            }
            "n" | "S" | "s" => {
                path.clear();
                path_complex = false;
            }
            "BT" => {
                tm = ID;
                tlm = ID;
            }
            "ET" => {
                out.text.push('\n');
                line_open = false;
            }
            "Tf" => {
                if let Some(Obj::Num(n)) = ops.last() {
                    if n.is_finite() {
                        fs = n.abs().min(10_000.0);
                    }
                }
            }
            "Tz" => {
                if let Some([z]) = last_n::<1>(&ops) {
                    th = (z / 100.0).clamp(-100.0, 100.0);
                }
            }
            "Ts" => {
                if let Some([r]) = last_n::<1>(&ops) {
                    rise = r.clamp(-1e5, 1e5);
                }
            }
            "Tc" => {
                if let Some([v]) = last_n::<1>(&ops) {
                    char_sp = v.clamp(-1e4, 1e4);
                }
            }
            "Tw" => {
                if let Some([v]) = last_n::<1>(&ops) {
                    word_sp = v.clamp(-1e4, 1e4);
                }
            }
            "TL" => {
                if let Some([v]) = last_n::<1>(&ops) {
                    leading = v.clamp(-1e5, 1e5);
                }
            }
            "Tr" => {
                if let Some([v]) = last_n::<1>(&ops) {
                    mode = v as i64;
                }
            }
            "Td" | "TD" => {
                if let Some([tx, ty]) = last_n::<2>(&ops) {
                    if k == "TD" {
                        leading = -ty;
                    }
                    let n = M::translate(tx, ty).mul(tlm);
                    if n.finite() {
                        tlm = n;
                        tm = n;
                    }
                    if ty.abs() > 0.01 && line_open {
                        out.text.push('\n');
                        line_open = false;
                    } else {
                        out.text.push(' ');
                    }
                }
            }
            "Tm" => {
                if let Some(m) = last_n::<6>(&ops) {
                    let n = M(m);
                    if n.finite() {
                        tm = n;
                        tlm = n;
                    }
                    if line_open {
                        out.text.push('\n');
                        line_open = false;
                    }
                }
            }
            "T*" => {
                tlm = M::translate(0.0, -leading).mul(tlm);
                tm = tlm;
                out.text.push('\n');
                line_open = false;
            }
            "Tj" | "'" | "\"" | "TJ" => {
                if k == "'" || k == "\"" {
                    if k == "\"" {
                        let v = nums(&ops);
                        if v.len() >= 2 {
                            word_sp = v[0].clamp(-1e4, 1e4);
                            char_sp = v[1].clamp(-1e4, 1e4);
                        }
                    }
                    tlm = M::translate(0.0, -leading).mul(tlm);
                    tm = tlm;
                    out.text.push('\n');
                }
                let items: Vec<Obj> = match ops.last() {
                    Some(Obj::Arr(a)) if k == "TJ" => a.clone(),
                    Some(s @ Obj::Str(_)) if k != "TJ" => vec![s.clone()],
                    _ => Vec::new(),
                };
                if !items.is_empty() {
                    show(
                        &items, &mut tm, &gs, fs, th, rise, mode, char_sp, word_sp, seq, &mut out,
                        &mut texts,
                    );
                    line_open = true;
                }
            }
            "Do" => {
                if let Some(Obj::Name(n)) = ops.last() {
                    if image_names.contains(n) {
                        out.images += 1;
                    }
                }
            }
            "ID" => {
                // inline image data: skip to "EI" preceded by whitespace
                out.images += 1;
                lx.skip_inline_image();
            }
            _ => {}
        }
        ops.clear();
        if lx.at_end() {
            break;
        }
    }

    // match text against boxes painted later
    let page_area = page_box.map(|b| area(&b)).filter(|a| *a > 0.0);
    let mut all_boxes = boxes;
    for e in extra {
        all_boxes.push(BoxItem {
            seq: usize::MAX,
            rect: e.rect,
            fill: e.fill,
        });
    }
    let mut grouped: Vec<(usize, String)> = Vec::new(); // box index, text
    for t in &texts {
        let ta = area(&t.rect);
        if ta <= 0.0 {
            continue;
        }
        let hit = all_boxes.iter().enumerate().find(|(_, b)| {
            b.seq > t.seq
                && page_area.is_none_or(|pa| area(&b.rect) < pa * 0.8)
                && intersection(&t.rect, &b.rect) / ta >= 0.6
        });
        if let Some((bi, _)) = hit {
            match grouped.iter_mut().find(|(i, _)| *i == bi) {
                Some((_, s)) => {
                    if s.len() < 400 {
                        s.push(' ');
                        s.push_str(t.text.trim());
                    }
                }
                None => grouped.push((bi, t.text.trim().to_string())),
            }
        }
    }
    for (bi, text) in grouped {
        let text: String = text.split_whitespace().collect::<Vec<_>>().join(" ");
        if text.chars().filter(|c| c.is_alphanumeric()).count() < 2 {
            continue;
        }
        let Some(b) = all_boxes.get(bi) else { continue };
        if out.hits.len() >= MAX_HITS {
            break;
        }
        out.hits.push(Hit {
            text: crate::util::truncate(&text, 80),
            fill: b.fill,
            rect: b.rect,
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scan(s: &str) -> PageScan {
        scan_page(
            s.as_bytes(),
            &HashSet::from(["Im0".to_string()]),
            Some([0.0, 0.0, 612.0, 792.0]),
            &[],
        )
    }

    #[test]
    fn black_box_over_text() {
        let p =
            scan("BT /F1 12 Tf 72 700 Td (Secret name Ivan Petrenko) Tj ET 0 g 70 695 200 20 re f");
        assert_eq!(p.hits.len(), 1);
        assert!(p.hits[0].text.contains("Ivan Petrenko"));
        assert_eq!(p.hits[0].fill, Fill::Black);
    }

    #[test]
    fn box_before_text_is_fine() {
        let p = scan("1 g 70 695 200 20 re f 0 g BT /F1 12 Tf 72 700 Td (Visible) Tj ET");
        assert!(p.hits.is_empty());
        assert_eq!(p.visible_chars, 7);
    }

    #[test]
    fn matrices_and_colours() {
        // text placed via cm + Tm, white rectangle in a scaled coordinate system
        let p = scan(
            "q 2 0 0 2 0 0 cm BT /F1 6 Tf 1 0 0 1 36 350 Tm [(Hidden)-250(text)] TJ ET Q \
             q 1 1 1 rg 4 0 0 4 0 0 cm 17 174 30 5 re f Q",
        );
        assert_eq!(p.hits.len(), 1, "{:?}", p.text);
        assert_eq!(p.hits[0].fill, Fill::White);
        // coloured box: not a redaction
        let p = scan("BT /F1 12 Tf 72 700 Td (abc def) Tj ET 1 0 0 rg 70 695 200 20 re f");
        assert!(p.hits.is_empty());
        // invisible OCR text is not a redaction and counts separately
        let p = scan("/Im0 Do BT 3 Tr /F1 12 Tf 72 700 Td (ocr text) Tj ET 0 g 70 695 200 20 re f");
        assert!(p.hits.is_empty());
        assert_eq!(p.images, 1);
        assert_eq!(p.invisible_chars, 7);
    }

    #[test]
    fn garbage_is_safe() {
        for s in [
            "1e308 1e308 1e308 1e308 1e308 1e308 cm BT (x) Tj ET 0 g 0 0 1 1 re f",
            "Q Q Q q q ET ET Tj TJ ' \" re f Do ID",
            "BI /W 1 ID \x00\x01\x02 EI BT (a) Tj",
            "NaN 0 0 NaN 0 0 Tm",
        ] {
            let _ = scan(s);
        }
    }
}
