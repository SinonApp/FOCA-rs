//! Visually hidden content of office documents: text whose colour equals its background
//! (white on white, font colour equal to the cell fill), tiny text (3 pt or less), cells
//! hidden by a `;;;` number format, shapes placed outside the slide or flagged hidden.
//!
//! Each finding becomes a `HiddenContent` entry with one of the kinds `white_text`,
//! `tiny_text`, `invisible_format`, `off_slide`. A colour is compared with the background
//! that is actually under the text (run and paragraph shading, highlight, table cell fill,
//! page background); where that background is unknown (text boxes, table styles with
//! fills, pattern fills) no colour finding is made, so white text on a dark fill stays
//! visible.

use std::collections::HashMap;

use foca_core::{HiddenContent, Metadata};

use crate::util::truncate;
use crate::xml::Element;

const MAX_HIDDEN: usize = 500;
/// Font size in points at and below which text counts as unreadable.
const TINY_PT: f64 = 3.0;
const MAX_CELLS: usize = 200_000;

pub(crate) type Rgb = [u8; 3];
pub(crate) const WHITE: Rgb = [0xFF, 0xFF, 0xFF];

/// Parses `RRGGBB`, `AARRGGBB` or `#RRGGBB`.
pub(crate) fn hex(s: &str) -> Option<Rgb> {
    let s = s.trim().trim_start_matches('#');
    if !(s.len() == 6 || s.len() == 8) || !s.bytes().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    let s = &s[s.len() - 6..];
    let v = u32::from_str_radix(s, 16).ok()?;
    Some([(v >> 16) as u8, (v >> 8) as u8, v as u8])
}

/// Colours a reader cannot tell apart (each channel within 24 of 255).
pub(crate) fn close(a: Rgb, b: Rgb) -> bool {
    a.iter().zip(b.iter()).all(|(x, y)| x.abs_diff(*y) <= 24)
}

/// Text of the `text_tags` elements of a subtree, one line per `para_tags` element.
fn collect_text(
    e: &Element,
    text_tags: &[&str],
    para_tags: &[&str],
    out: &mut String,
    depth: usize,
) {
    if depth > 256 || out.len() > 8192 {
        return;
    }
    let l = e.local();
    if text_tags.contains(&l) {
        out.push_str(&e.text());
    } else {
        for c in e.elements() {
            collect_text(c, text_tags, para_tags, out, depth + 1);
        }
    }
    if para_tags.contains(&l) {
        out.push('\n');
    }
}

/// Adds one finding (whitespace-normalised text, capped).
pub(crate) fn push(meta: &mut Metadata, kind: &str, location: String, text: &str) {
    if meta.hidden_content.len() >= MAX_HIDDEN {
        return;
    }
    let text = text.split_whitespace().collect::<Vec<_>>().join(" ");
    meta.hidden_content.push(HiddenContent {
        kind: kind.into(),
        location: truncate(&location, 256),
        text: truncate(&text, 512),
    });
}

/// Theme colours in file order: dk1, lt1, dk2, lt2, accent1-6, hlink, folHlink.
pub(crate) fn theme_colors(theme: Option<&Element>) -> Vec<Rgb> {
    let Some(t) = theme else {
        return Vec::new();
    };
    let Some(scheme) = t.descendants("clrScheme").into_iter().next() else {
        return Vec::new();
    };
    scheme
        .elements()
        .map(|c| {
            c.elements()
                .find_map(|v| match v.local() {
                    "srgbClr" => v.attr("val").and_then(hex),
                    "sysClr" => v.attr("lastClr").and_then(hex),
                    _ => None,
                })
                .unwrap_or([0, 0, 0])
        })
        .collect()
}

// ------------------------------------------------------------------------------- Word

/// Word theme colour names (`w:themeColor`) as theme indices.
fn word_theme(name: &str) -> Option<usize> {
    Some(match name {
        "dark1" | "text1" => 0,
        "light1" | "background1" => 1,
        "dark2" | "text2" => 2,
        "light2" | "background2" => 3,
        "accent1" => 4,
        "accent2" => 5,
        "accent3" => 6,
        "accent4" => 7,
        "accent5" => 8,
        "accent6" => 9,
        "hyperlink" => 10,
        "followedHyperlink" => 11,
        _ => return None,
    })
}

fn highlight(name: &str) -> Option<Rgb> {
    hex(match name {
        "white" => "FFFFFF",
        "black" => "000000",
        "yellow" => "FFFF00",
        "green" => "00FF00",
        "cyan" => "00FFFF",
        "magenta" => "FF00FF",
        "blue" => "0000FF",
        "red" => "FF0000",
        "darkBlue" => "000080",
        "darkCyan" => "008080",
        "darkGreen" => "008000",
        "darkMagenta" => "800080",
        "darkRed" => "800000",
        "darkYellow" => "808000",
        "darkGray" => "808080",
        "lightGray" => "C0C0C0",
        _ => return None,
    })
}

/// Fill of a `w:shd`: the pattern colour for solid shading, otherwise the fill.
fn shd_fill(shd: &Element) -> Option<Rgb> {
    if shd.attr_local("val") == Some("solid") {
        return shd.attr_local("color").and_then(hex);
    }
    shd.attr_local("fill").and_then(hex)
}

/// Background known under some text: `Some(colour)` or unknown (`None`).
type Bg = Option<Rgb>;

struct Word<'a> {
    theme: &'a [Rgb],
    /// Table styles whose definition contains a fill (header rows of dark table styles).
    filled_styles: &'a [String],
    part: &'a str,
    para: usize,
}

impl Word<'_> {
    fn run_color(&self, rpr: &Element) -> Option<Rgb> {
        let c = rpr.child("color")?;
        if let Some(i) = c.attr_local("themeColor").and_then(word_theme) {
            return self.theme.get(i).copied();
        }
        c.attr_local("val").and_then(hex)
    }

    fn walk(&mut self, meta: &mut Metadata, e: &Element, bg: Bg, depth: usize) {
        if depth > 256 || meta.hidden_content.len() >= MAX_HIDDEN {
            return;
        }
        match e.local() {
            "p" if e.name.starts_with("w:") => {
                self.para += 1;
                self.paragraph(meta, e, bg, depth);
                return;
            }
            "tbl" => {
                let style = e
                    .child("tblPr")
                    .and_then(|p| p.child("tblStyle"))
                    .and_then(|s| s.attr_local("val"));
                let styled = style.is_some_and(|s| self.filled_styles.iter().any(|f| f == s));
                let bg = if styled { None } else { bg };
                for c in e.elements() {
                    self.walk(meta, c, bg, depth + 1);
                }
                return;
            }
            "tc" => {
                let fill = e
                    .child("tcPr")
                    .and_then(|p| p.child("shd"))
                    .and_then(shd_fill);
                let bg = fill.map(Some).unwrap_or(bg);
                for c in e.elements() {
                    self.walk(meta, c, bg, depth + 1);
                }
                return;
            }
            // shapes and text boxes have their own fills
            "txbxContent" | "pict" | "drawing" => {
                for c in e.elements() {
                    self.walk(meta, c, None, depth + 1);
                }
                return;
            }
            _ => {}
        }
        for c in e.elements() {
            self.walk(meta, c, bg, depth + 1);
        }
    }

    fn paragraph(&mut self, meta: &mut Metadata, p: &Element, bg: Bg, depth: usize) {
        let pbg = p
            .child("pPr")
            .and_then(|pr| pr.child("shd"))
            .and_then(shd_fill)
            .map(Some)
            .unwrap_or(bg);
        let mut white = String::new();
        let mut tiny = String::new();
        for c in p.elements() {
            match c.local() {
                "r" => self.run(c, pbg, &mut white, &mut tiny),
                // runs nested in hyperlinks, fields, insertions, smart tags
                "hyperlink" | "ins" | "smartTag" | "fldSimple" | "sdt" | "sdtContent"
                | "customXml" => {
                    for r in c.descendants("r") {
                        self.run(r, pbg, &mut white, &mut tiny);
                    }
                }
                _ => {}
            }
            if white.len() + tiny.len() > 4096 {
                break;
            }
        }
        let loc = format!("{}#p{}", self.part, self.para);
        if !white.trim().is_empty() {
            push(meta, "white_text", loc.clone(), &white);
        }
        if !tiny.trim().is_empty() {
            push(meta, "tiny_text", loc, &tiny);
        }
        // text boxes anchored in this paragraph
        for c in p.descendants("txbxContent") {
            self.walk(meta, c, None, depth + 1);
        }
    }

    fn run(&self, r: &Element, bg: Bg, white: &mut String, tiny: &mut String) {
        let Some(rpr) = r.child("rPr") else { return };
        // only the run's own text (a drawing in the run has its own background)
        let text: String = r
            .elements()
            .filter(|e| e.local() == "t")
            .map(Element::text)
            .collect();
        if text.trim().is_empty() {
            return;
        }
        let half_pt = rpr
            .child("sz")
            .and_then(|s| s.attr_local("val"))
            .and_then(|v| v.parse::<f64>().ok());
        let rbg = rpr
            .child("shd")
            .and_then(shd_fill)
            .or_else(|| {
                rpr.child("highlight")
                    .and_then(|h| h.attr_local("val"))
                    .and_then(highlight)
            })
            .map(Some)
            .unwrap_or(bg);
        let invisible = match (self.run_color(rpr), rbg) {
            (Some(c), Some(b)) => close(c, b),
            _ => false,
        };
        if invisible {
            white.push_str(&text);
            white.push(' ');
        } else if half_pt.is_some_and(|h| h > 0.0 && h / 2.0 <= TINY_PT) {
            tiny.push_str(&text);
            tiny.push(' ');
        }
    }
}

/// Table styles of styles.xml that paint a fill (their cells' background is not the page).
pub(crate) fn word_filled_table_styles(styles: Option<&Element>) -> Vec<String> {
    let Some(s) = styles else {
        return Vec::new();
    };
    s.elements()
        .filter(|e| e.local() == "style" && e.attr_local("type") == Some("table"))
        .filter(|e| {
            e.descendants("shd")
                .iter()
                .any(|d| shd_fill(d).is_some_and(|c| !close(c, WHITE)))
        })
        .filter_map(|e| e.attr_local("styleId").map(str::to_string))
        .take(1000)
        .collect()
}

/// White or background-coloured and tiny runs of a Word part.
pub(crate) fn word(
    meta: &mut Metadata,
    root: &Element,
    part: &str,
    theme: &[Rgb],
    filled_styles: &[String],
) {
    let page = root
        .child("background")
        .and_then(|b| b.attr_local("color"))
        .and_then(hex)
        .unwrap_or(WHITE);
    let mut w = Word {
        theme,
        filled_styles,
        part,
        para: 0,
    };
    w.walk(meta, root, Some(page), 0);
}

// ------------------------------------------------------------------------------- Excel

#[derive(Clone, Copy)]
enum Fill {
    None,
    Solid(Rgb),
    Unknown,
}

/// The parts of styles.xml that decide whether a cell is readable.
#[derive(Default)]
pub(crate) struct XlStyles {
    fonts: Vec<Option<Rgb>>,
    fills: Vec<Option<Rgb>>,
    fill_kind: Vec<u8>,
    /// cellXfs: (number format id, font, fill).
    xfs: Vec<(u32, usize, usize)>,
    num_fmts: HashMap<u32, String>,
}

/// Default indexed palette entries that matter (MS-XLS 2.5.161) and the system colours.
fn indexed(i: u32, custom: &[Rgb]) -> Option<Rgb> {
    if let Some(c) = custom.get(i as usize) {
        return Some(*c);
    }
    Some(match i {
        0 | 8 => [0, 0, 0],
        1 | 9 | 65 => WHITE,
        2 | 10 => [0xFF, 0, 0],
        3 | 11 => [0, 0xFF, 0],
        4 | 12 => [0, 0, 0xFF],
        5 | 13 => [0xFF, 0xFF, 0],
        6 | 14 => [0xFF, 0, 0xFF],
        7 | 15 => [0, 0xFF, 0xFF],
        22 => [0xC0, 0xC0, 0xC0],
        23 => [0x80, 0x80, 0x80],
        _ => return None,
    })
}

fn xl_color(c: &Element, theme: &[Rgb], custom: &[Rgb]) -> Option<Rgb> {
    if let Some(rgb) = c.attr("rgb").and_then(hex) {
        return Some(rgb);
    }
    if let Some(t) = c.attr("theme").and_then(|v| v.parse::<usize>().ok()) {
        // SpreadsheetML swaps the light/dark pairs: 0 = lt1, 1 = dk1, 2 = lt2, 3 = dk2
        let i = match t {
            0 => 1,
            1 => 0,
            2 => 3,
            3 => 2,
            x => x,
        };
        // a tint moves the colour away from the theme value: only exact theme colours count
        if c.attr("tint")
            .and_then(|v| v.parse::<f64>().ok())
            .unwrap_or(0.0)
            .abs()
            > 0.05
        {
            return None;
        }
        return theme.get(i).copied();
    }
    if let Some(i) = c.attr("indexed").and_then(|v| v.parse::<u32>().ok()) {
        return indexed(i, custom);
    }
    None
}

impl XlStyles {
    pub(crate) fn parse(styles: Option<&Element>, theme: &[Rgb]) -> Self {
        let mut st = XlStyles::default();
        let Some(s) = styles else { return st };
        let custom: Vec<Rgb> = s
            .child("colors")
            .and_then(|c| c.child("indexedColors"))
            .map(|ic| {
                ic.elements()
                    .map(|e| e.attr("rgb").and_then(hex).unwrap_or([0, 0, 0]))
                    .collect()
            })
            .unwrap_or_default();
        if let Some(f) = s.child("fonts") {
            st.fonts = f
                .elements()
                .take(10_000)
                .map(|font| {
                    font.child("color")
                        .and_then(|c| xl_color(c, theme, &custom))
                })
                .collect();
        }
        if let Some(f) = s.child("fills") {
            for fill in f.elements().take(10_000) {
                let pf = fill.child("patternFill");
                let kind = pf.and_then(|p| p.attr("patternType")).unwrap_or("none");
                let (k, c) = match kind {
                    "none" => (0, None),
                    "solid" => match pf
                        .and_then(|p| p.child("fgColor"))
                        .and_then(|c| xl_color(c, theme, &custom))
                    {
                        Some(c) => (1, Some(c)),
                        None => (2, None),
                    },
                    _ => (2, None),
                };
                // gradient fills are unknown backgrounds
                let k = if fill.child("gradientFill").is_some() {
                    2
                } else {
                    k
                };
                st.fill_kind.push(k);
                st.fills.push(c);
            }
        }
        if let Some(n) = s.child("numFmts") {
            for f in n.elements() {
                if let (Some(id), Some(code)) = (
                    f.attr("numFmtId").and_then(|v| v.parse().ok()),
                    f.attr("formatCode"),
                ) {
                    st.num_fmts.insert(id, code.to_string());
                }
            }
        }
        if let Some(x) = s.child("cellXfs") {
            st.xfs = x
                .elements()
                .take(100_000)
                .map(|xf| {
                    let n = |a: &str| {
                        xf.attr(a)
                            .and_then(|v| v.parse::<usize>().ok())
                            .unwrap_or(0)
                    };
                    (n("numFmtId") as u32, n("fontId"), n("fillId"))
                })
                .collect();
        }
        st
    }

    /// Why the value of a cell with style `s` cannot be seen, if it cannot.
    fn invisible(&self, s: usize, is_text: bool) -> Option<&'static str> {
        let &(num, font, fill) = self.xfs.get(s)?;
        if self
            .num_fmts
            .get(&num)
            .is_some_and(|code| format_hides(code, is_text))
        {
            return Some("invisible_format");
        }
        let fc = self.fonts.get(font).copied().flatten()?;
        let hidden = match self.fill(fill) {
            Fill::None => close(fc, WHITE),
            Fill::Solid(b) => close(fc, b),
            Fill::Unknown => false,
        };
        hidden.then_some("white_text")
    }

    fn fill(&self, i: usize) -> Fill {
        match self.fill_kind.get(i) {
            None | Some(0) => Fill::None,
            Some(1) => self.fills[i].map_or(Fill::Unknown, Fill::Solid),
            _ => Fill::Unknown,
        }
    }
}

/// Sections of a number format code, ignoring `;` inside quotes and after a backslash.
fn sections(code: &str) -> Vec<String> {
    let mut out = vec![String::new()];
    let mut quoted = false;
    let mut esc = false;
    for c in code.chars() {
        if !esc && !quoted && c == ';' {
            out.push(String::new());
            continue;
        }
        if esc {
            esc = false;
        } else if c == '\\' {
            esc = true;
        } else if c == '"' {
            quoted = !quoted;
        }
        if let Some(last) = out.last_mut() {
            last.push(c);
        }
    }
    out
}

/// Whether a number format hides the value: `;;;` hides everything, `;;;@` numbers only.
pub(crate) fn format_hides(code: &str, is_text: bool) -> bool {
    let s = sections(code);
    if s.len() < 3 {
        return false;
    }
    let empty = |x: &String| {
        let t = x.trim();
        // colour or condition prefixes alone print nothing
        t.is_empty() || (t.starts_with('[') && t.ends_with(']') && !t.contains('@'))
    };
    if is_text {
        s.len() >= 4 && empty(&s[3])
    } else {
        s.iter().take(3).all(empty)
    }
}

/// Collected findings of one sheet and kind.
#[derive(Default)]
struct Group {
    cells: Vec<String>,
    values: Vec<String>,
    n: usize,
}

impl Group {
    fn add(&mut self, cell: &str, v: &str) {
        self.n += 1;
        if self.cells.len() < 20 {
            self.cells.push(cell.to_string());
            self.values.push(v.to_string());
        }
    }

    fn flush(self, meta: &mut Metadata, kind: &str, sheet: &str) {
        if self.n == 0 {
            return;
        }
        let more = if self.n > self.cells.len() {
            format!(" (+{})", self.n - self.cells.len())
        } else {
            String::new()
        };
        let loc = format!("{sheet}!{}{more}", self.cells.join(","));
        push(meta, kind, loc, &self.values.join(" | "));
    }
}

/// Cells whose font colour equals their fill (white on no fill) or whose number format
/// prints nothing. `value` resolves a cell's cached value.
pub(crate) fn sheet(
    meta: &mut Metadata,
    sheet: &str,
    ws: &Element,
    st: &XlStyles,
    value: impl Fn(&Element) -> Option<String>,
) {
    let Some(data) = ws.child("sheetData") else {
        return;
    };
    let mut white = Group::default();
    let mut fmt = Group::default();
    let mut seen = 0usize;
    for row in data.elements().filter(|e| e.local() == "row") {
        for c in row.elements().filter(|e| e.local() == "c") {
            seen += 1;
            if seen > MAX_CELLS {
                break;
            }
            let Some(s) = c.attr("s").and_then(|v| v.parse::<usize>().ok()) else {
                continue;
            };
            let is_text = matches!(c.attr("t"), Some("s" | "inlineStr" | "str"));
            let Some(kind) = st.invisible(s, is_text) else {
                continue;
            };
            let Some(v) = value(c) else { continue };
            let cell = c.attr("r").unwrap_or("?");
            if kind == "invisible_format" {
                fmt.add(cell, &v);
            } else {
                white.add(cell, &v);
            }
        }
    }
    white.flush(meta, "white_text", sheet);
    fmt.flush(meta, "invisible_format", sheet);
}

/// Column letters of a 1-based column index.
fn col_name(mut n: usize) -> String {
    let mut s = Vec::new();
    while n > 0 && s.len() < 4 {
        s.push((b'A' + ((n - 1) % 26) as u8) as char);
        n = (n - 1) / 26;
    }
    s.iter().rev().collect()
}

// ------------------------------------------------------------------------- PowerPoint

/// Slide size (`p:sldSz cx cy`, EMU) of presentation.xml.
pub(crate) fn slide_size(pres: Option<&Element>) -> Option<(i64, i64)> {
    let s = pres?.child("sldSz")?;
    let n = |a: &str| s.attr(a).and_then(|v| v.parse::<i64>().ok());
    Some((n("cx")?, n("cy")?))
}

/// Whether a rectangle lies completely outside `0..w x 0..h`.
pub(crate) fn outside(x: i64, y: i64, cx: i64, cy: i64, w: i64, h: i64) -> bool {
    x >= w || y >= h || x.saturating_add(cx.max(0)) <= 0 || y.saturating_add(cy.max(0)) <= 0
}

/// Top-level shapes of a slide that lie outside the slide or are flagged hidden.
pub(crate) fn slide(meta: &mut Metadata, root: &Element, part: &str, size: (i64, i64)) {
    let Some(tree) = root.child("cSld").and_then(|c| c.child("spTree")) else {
        return;
    };
    for sh in tree.elements() {
        let xfrm = match sh.local() {
            "sp" | "pic" | "cxnSp" => sh.child("spPr").and_then(|p| p.child("xfrm")),
            "grpSp" => sh.child("grpSpPr").and_then(|p| p.child("xfrm")),
            "graphicFrame" => sh.child("xfrm"),
            _ => continue,
        };
        let nv = sh.descendants("cNvPr").into_iter().next();
        let name = nv.and_then(|n| n.attr("name")).unwrap_or("").to_string();
        let mut text = String::new();
        collect_text(sh, &["t"], &["p"], &mut text, 0);
        let loc = format!("{part}: {name}");
        if nv
            .and_then(|n| n.attr("hidden"))
            .is_some_and(|v| v == "1" || v == "true")
        {
            push(meta, "invisible_format", loc, &text);
            continue;
        }
        let Some(x) = xfrm else { continue };
        let num = |e: Option<&Element>, a: &str| {
            e.and_then(|e| e.attr(a))
                .and_then(|v| v.parse::<i64>().ok())
        };
        let (off, ext) = (x.child("off"), x.child("ext"));
        let (Some(ox), Some(oy)) = (num(off, "x"), num(off, "y")) else {
            continue;
        };
        let (ex, ey) = (num(ext, "cx").unwrap_or(0), num(ext, "cy").unwrap_or(0));
        if outside(ox, oy, ex, ey, size.0, size.1) {
            push(meta, "off_slide", loc, &text);
        }
    }
}

// ------------------------------------------------------------------------- OpenDocument

/// Length in millimetres (`2.5cm`, `10mm`, `1in`, `72pt`, `96px`).
fn odf_len(s: &str) -> Option<f64> {
    let s = s.trim();
    let split = s.find(|c: char| c.is_ascii_alphabetic() || c == '%')?;
    let v: f64 = s[..split].parse().ok()?;
    Some(match &s[split..] {
        "mm" => v,
        "cm" => v * 10.0,
        "in" => v * 25.4,
        "pt" => v * 25.4 / 72.0,
        "pc" => v * 25.4 / 6.0,
        "px" => v * 25.4 / 96.0,
        _ => return None,
    })
}

#[derive(Default, Clone)]
struct OdfStyle {
    parent: Option<String>,
    color: Option<Rgb>,
    /// `Some(None)`: transparent.
    bg: Option<Option<Rgb>>,
    cell_bg: Option<Option<Rgb>>,
    size_pt: Option<f64>,
    display_none: bool,
}

/// Text, paragraph and cell styles of content.xml and styles.xml by name.
pub(crate) struct OdfStyles {
    map: HashMap<String, OdfStyle>,
    page_bg: Rgb,
    page_mm: Option<(f64, f64)>,
}

fn odf_bg(v: Option<&str>) -> Option<Option<Rgb>> {
    let v = v?;
    Some(if v == "transparent" { None } else { hex(v) })
}

impl OdfStyles {
    pub(crate) fn parse(content: Option<&Element>, styles: Option<&Element>) -> Self {
        let mut map = HashMap::new();
        let mut page_bg = WHITE;
        let mut page_mm = None;
        for root in [styles, content].into_iter().flatten() {
            for s in root.descendants("style") {
                let Some(name) = s.attr("style:name") else {
                    continue;
                };
                let mut st = OdfStyle {
                    parent: s.attr("style:parent-style-name").map(str::to_string),
                    ..OdfStyle::default()
                };
                for p in s.elements() {
                    match p.local() {
                        "text-properties" => {
                            st.color = p.attr("fo:color").and_then(hex);
                            if let Some(b) = odf_bg(p.attr("fo:background-color")) {
                                st.bg = Some(b);
                            }
                            st.size_pt = p
                                .attr("fo:font-size")
                                .and_then(odf_len)
                                .map(|mm| mm * 72.0 / 25.4);
                            st.display_none = p.attr("text:display") == Some("none");
                        }
                        "paragraph-properties" => {
                            if let Some(b) = odf_bg(p.attr("fo:background-color")) {
                                st.bg.get_or_insert(b);
                            }
                        }
                        "table-cell-properties" => {
                            st.cell_bg = odf_bg(p.attr("fo:background-color"));
                        }
                        _ => {}
                    }
                }
                if map.len() < 50_000 {
                    map.insert(name.to_string(), st);
                }
            }
            for pl in root.descendants("page-layout-properties") {
                if let Some(Some(c)) = odf_bg(pl.attr("fo:background-color")) {
                    page_bg = c;
                }
                if page_mm.is_none() {
                    if let (Some(w), Some(h)) = (
                        pl.attr("fo:page-width").and_then(odf_len),
                        pl.attr("fo:page-height").and_then(odf_len),
                    ) {
                        page_mm = Some((w, h));
                    }
                }
            }
        }
        OdfStyles {
            map,
            page_bg,
            page_mm,
        }
    }

    /// Resolves a style through its parents.
    fn resolve(&self, name: Option<&str>) -> OdfStyle {
        let mut out = OdfStyle::default();
        let mut cur = name.map(str::to_string);
        for _ in 0..8 {
            let Some(s) = cur.as_deref().and_then(|n| self.map.get(n)) else {
                break;
            };
            out.color = out.color.or(s.color);
            out.bg = out.bg.or(s.bg);
            out.cell_bg = out.cell_bg.or(s.cell_bg);
            out.size_pt = out.size_pt.or(s.size_pt);
            out.display_none |= s.display_none;
            cur.clone_from(&s.parent);
        }
        out
    }
}

struct OdfWalk<'a> {
    st: &'a OdfStyles,
    para: usize,
    white: Vec<String>,
    tiny: Vec<String>,
    gone: Vec<String>,
}

impl OdfWalk<'_> {
    /// Classifies the text of `e` (a paragraph or span) under the inherited style.
    fn node(&mut self, e: &Element, inherited: &OdfStyle, bg: Bg, depth: usize) {
        if depth > 256 {
            return;
        }
        let own = self.st.resolve(e.attr("text:style-name"));
        let eff = OdfStyle {
            parent: None,
            color: own.color.or(inherited.color),
            bg: own.bg.or(inherited.bg),
            cell_bg: None,
            size_pt: own.size_pt.or(inherited.size_pt),
            display_none: own.display_none || inherited.display_none,
        };
        let here = match eff.bg {
            Some(Some(c)) => Some(c),
            _ => bg,
        };
        for n in &e.children {
            match n {
                crate::xml::Node::Text(t) if !t.trim().is_empty() => {
                    let slot = if eff.display_none {
                        Some(&mut self.gone)
                    } else if matches!((eff.color, here), (Some(c), Some(b)) if close(c, b)) {
                        Some(&mut self.white)
                    } else if eff.size_pt.is_some_and(|p| p > 0.0 && p <= TINY_PT) {
                        Some(&mut self.tiny)
                    } else {
                        None
                    };
                    if let Some(v) = slot {
                        if v.len() < 64 {
                            v.push(t.clone());
                        }
                    }
                }
                crate::xml::Node::El(c) if matches!(c.local(), "span" | "a") => {
                    self.node(c, &eff, here, depth + 1)
                }
                _ => {}
            }
        }
    }

    fn flush(&mut self, meta: &mut Metadata, loc: &str) {
        for (kind, v) in [
            ("white_text", std::mem::take(&mut self.white)),
            ("tiny_text", std::mem::take(&mut self.tiny)),
            ("hidden_text", std::mem::take(&mut self.gone)),
        ] {
            if !v.is_empty() {
                push(meta, kind, loc.to_string(), &v.join(" "));
            }
        }
    }

    fn walk(&mut self, meta: &mut Metadata, e: &Element, bg: Bg, depth: usize) {
        if depth > 256 || meta.hidden_content.len() >= MAX_HIDDEN {
            return;
        }
        match e.name.as_str() {
            "text:p" | "text:h" => {
                self.para += 1;
                self.node(e, &OdfStyle::default(), bg, depth);
                self.flush(meta, &format!("content.xml#p{}", self.para));
                // frames anchored in the paragraph have their own fills
                for f in e.descendants("text-box") {
                    for c in f.elements() {
                        self.walk(meta, c, None, depth + 1);
                    }
                }
                return;
            }
            "table:table-cell" => {
                let cbg = self.st.resolve(e.attr("table:style-name")).cell_bg;
                let bg = match cbg {
                    Some(Some(c)) => Some(c),
                    _ => bg,
                };
                for c in e.elements() {
                    self.walk(meta, c, bg, depth + 1);
                }
                return;
            }
            "draw:frame" | "draw:custom-shape" | "draw:text-box" => {
                for c in e.elements() {
                    self.walk(meta, c, None, depth + 1);
                }
                return;
            }
            _ => {}
        }
        for c in e.elements() {
            self.walk(meta, c, bg, depth + 1);
        }
    }
}

/// White, tiny and `text:display="none"` text of a text document body.
pub(crate) fn odf_text(meta: &mut Metadata, content: &Element, st: &OdfStyles) {
    let Some(body) = content.child("body").and_then(|b| b.child("text")) else {
        return;
    };
    let mut w = OdfWalk {
        st,
        para: 0,
        white: Vec::new(),
        tiny: Vec::new(),
        gone: Vec::new(),
    };
    w.walk(meta, body, Some(st.page_bg), 0);
}

/// Spreadsheet cells whose text colour equals the cell background (white on none).
pub(crate) fn odf_cells(meta: &mut Metadata, content: &Element, st: &OdfStyles) {
    for t in content.descendants("table") {
        let name = t.attr("table:name").unwrap_or("").to_string();
        let mut g = Group::default();
        let mut row = 0usize;
        let mut seen = 0usize;
        for r in t.descendants("table-row") {
            row += 1;
            let mut col = 0usize;
            for c in r.elements().filter(|e| e.local() == "table-cell") {
                col += 1;
                seen += 1;
                if seen > MAX_CELLS {
                    break;
                }
                let s = st.resolve(c.attr("table:style-name"));
                let Some(fc) = s.color else { continue };
                let bg = match s.cell_bg {
                    Some(Some(b)) => b,
                    _ => WHITE,
                };
                if !close(fc, bg) {
                    continue;
                }
                let v = c.text();
                if v.trim().is_empty() {
                    continue;
                }
                let cell = format!("{}{row}", col_name(col));
                g.add(&cell, v.trim());
            }
        }
        g.flush(meta, "white_text", &name);
    }
}

/// Presentation shapes placed outside the page.
pub(crate) fn odf_slides(meta: &mut Metadata, content: &Element, st: &OdfStyles) {
    let Some((pw, ph)) = st.page_mm else { return };
    for page in content.descendants("page") {
        let pname = page.attr("draw:name").unwrap_or("").to_string();
        for sh in page.elements() {
            let g = |a: &str| sh.attr(a).and_then(odf_len);
            let (Some(x), Some(y)) = (g("svg:x"), g("svg:y")) else {
                continue;
            };
            let (w, h) = (
                g("svg:width").unwrap_or(0.0),
                g("svg:height").unwrap_or(0.0),
            );
            // millimetres scaled to integers for the shared check
            let k = |v: f64| (v * 100.0) as i64;
            if outside(k(x), k(y), k(w), k(h), k(pw), k(ph)) {
                let mut text = String::new();
                collect_text(sh, &["p", "span"], &[], &mut text, 0);
                let name = sh.attr("draw:name").unwrap_or(sh.local());
                push(meta, "off_slide", format!("{pname}: {name}"), &text);
            }
        }
    }
}
