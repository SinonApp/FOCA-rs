//! Static inline SVG diagrams for the HTML/PDF report: a layered link graph, an internal
//! network map, a chronology by year and a 7×24 activity heat map.
//!
//! The report runs under a strict CSP without scripts and is printed to PDF by the Android
//! print service, so every diagram is plain SVG markup built in Rust:
//!
//! * no scripts, event handlers, external resources, fonts or `url(…)` references;
//! * every string from the data is hostile input: it is flattened to one line, stripped of
//!   control and bidi characters and XML-escaped ([`clean`]); long labels are shortened and
//!   the full text goes into `<title>`;
//! * output is deterministic (stable sorting, fixed number formatting) for golden tests;
//! * output size is bounded: node, row, year and event limits with automatic collapsing;
//! * light print palette that stays readable in black and white (shapes, outlines and
//!   numbers carry the meaning, color only reinforces it).
//!
//! The input structures here are independent of `foca-analysis`: the integrator converts the
//! analysis results into [`Visuals`].

use serde::{Deserialize, Serialize};
use std::fmt::Write as _;

pub mod graph;
pub mod heatmap;
pub mod netmap;
pub mod timeline;

pub use graph::{Graph, GraphEdge, GraphNode, NodeKind};
pub use heatmap::Heatmap;
pub use netmap::{NetKind, NetMap, NetNode, ServerRole};
pub use timeline::{Lane, Timeline, TimelineEvent};

/// Input data for all report diagrams. Empty parts are skipped (no section is rendered).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Visuals {
    pub graph: Graph,
    pub netmap: NetMap,
    pub timeline: Timeline,
    pub activity: Heatmap,
}

impl Visuals {
    /// Returns `true` when no diagram has data.
    pub fn is_empty(&self) -> bool {
        self.graph.nodes.is_empty()
            && self.netmap.nodes.is_empty()
            && self.timeline.events.is_empty()
            && !self.activity.has_data()
    }

    /// Returns a copy with every user-visible label passed through `f` (secret masking).
    pub(crate) fn map_text(&self, f: &dyn Fn(&str) -> String) -> Visuals {
        let mut v = self.clone();
        for n in &mut v.graph.nodes {
            n.label = f(&n.label);
        }
        for n in &mut v.netmap.nodes {
            n.label = f(&n.label);
        }
        for e in &mut v.timeline.events {
            e.label = f(&e.label);
        }
        v.activity = v.activity.map_text(f);
        v
    }
}

/// A rendered diagram: SVG markup and a short caption in the report language.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Figure {
    pub svg: String,
    pub caption: String,
    /// Natural width of the drawing in CSS pixels (the `viewBox` width).
    pub width: u32,
}

/// Flattens a label to one line and XML-escapes it: control characters become spaces,
/// bidi overrides are dropped, whitespace runs collapse.
pub fn clean(s: &str) -> String {
    let mut flat = String::with_capacity(s.len());
    let mut space = false;
    for c in s.chars() {
        let c = match c {
            '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}' | '\u{200e}' | '\u{200f}' => continue,
            '\u{fffe}' | '\u{ffff}' => continue,
            c if c.is_control() || c.is_whitespace() => ' ',
            c => c,
        };
        if c == ' ' {
            if !space && !flat.is_empty() {
                flat.push(' ');
            }
            space = true;
        } else {
            flat.push(c);
            space = false;
        }
    }
    if flat.ends_with(' ') {
        flat.pop();
    }
    crate::safe::xml(&flat)
}

/// Returns the plain (unescaped) one-line form of a label, used for length math.
pub(crate) fn flat(s: &str) -> String {
    s.split(|c: char| c.is_control() || c.is_whitespace())
        .filter(|w| !w.is_empty())
        .collect::<Vec<_>>()
        .join(" ")
        .chars()
        .filter(|c| !matches!(c, '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}' | '\u{200e}' | '\u{200f}'))
        .collect()
}

/// Shortens a string to `max` characters, ending with `…` when cut.
pub(crate) fn truncate(s: &str, max: usize) -> String {
    let max = max.max(2);
    if s.chars().count() <= max {
        return s.to_string();
    }
    let mut out: String = s.chars().take(max - 1).collect();
    out.truncate(out.trim_end().len());
    out.push('…');
    out
}

/// Wraps a string into at most `lines` lines of `max` characters, preferring breaks after
/// spaces and path separators; the last line is truncated with `…`.
pub(crate) fn wrap(s: &str, max: usize, lines: usize) -> Vec<String> {
    let max = max.max(4);
    let mut out = Vec::new();
    let mut rest: Vec<char> = s.chars().collect();
    while !rest.is_empty() && out.len() + 1 < lines {
        if rest.len() <= max {
            break;
        }
        // Break after a separator inside the first `max` characters, or after a space that
        // falls right on the limit; otherwise cut hard.
        let window = &rest[..=max.min(rest.len() - 1)];
        let cut = window
            .iter()
            .enumerate()
            .rev()
            .find(|&(i, c)| {
                i >= max / 3
                    && (*c == ' '
                        || (i < max && matches!(c, '\\' | '/' | '-' | '_' | '.' | ',' | '@')))
            })
            .map(|(i, _)| i + 1)
            .unwrap_or(max)
            .min(max);
        let line: String = rest[..cut].iter().collect();
        out.push(line.trim_end().to_string());
        rest.drain(..cut);
        while rest.first() == Some(&' ') {
            rest.remove(0);
        }
    }
    if !rest.is_empty() {
        out.push(truncate(&rest.iter().collect::<String>(), max));
    }
    out
}

/// Formats a coordinate with at most one decimal (deterministic, no `-0`).
pub(crate) fn n(v: f64) -> String {
    let r = (v * 10.0).round() / 10.0;
    let r = if r == 0.0 { 0.0 } else { r };
    if r.fract() == 0.0 {
        format!("{r:.0}")
    } else {
        format!("{r:.1}")
    }
}

/// Opens an `<svg>` element with a viewBox, natural size and accessible label.
pub(crate) fn open(out: &mut String, w: f64, h: f64, label: &str) {
    let _ = write!(
        out,
        "<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 {} {}\" width=\"{}\" height=\"{}\" \
         role=\"img\" aria-label=\"{}\" font-family=\"sans-serif\">",
        n(w),
        n(h),
        n(w),
        n(h),
        clean(label)
    );
    let _ = write!(out, "<title>{}</title>", clean(label));
}

/// Writes a `<text>` element; `inner` must already be escaped.
#[allow(clippy::too_many_arguments)]
pub(crate) fn text(
    out: &mut String,
    x: f64,
    y: f64,
    size: f64,
    fill: &str,
    anchor: &str,
    bold: bool,
    inner: &str,
) {
    let _ = write!(
        out,
        "<text x=\"{}\" y=\"{}\" font-size=\"{}\" fill=\"{fill}\"{}{}>{inner}</text>",
        n(x),
        n(y),
        n(size),
        if anchor == "start" {
            String::new()
        } else {
            format!(" text-anchor=\"{anchor}\"")
        },
        if bold { " font-weight=\"700\"" } else { "" },
    );
}

/// Pictogram shapes, distinguishable in black and white.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Glyph {
    Person,
    Document,
    Workstation,
    Printer,
    Share,
    Server,
    Domain,
    Pki,
}

/// Draws a pictogram of size `s` centered at `(cx, cy)`.
pub(crate) fn glyph(out: &mut String, g: Glyph, cx: f64, cy: f64, s: f64, color: &str) {
    let p = |dx: f64, dy: f64| format!("{} {}", n(cx + dx * s), n(cy + dy * s));
    let common = format!("fill=\"#fff\" stroke=\"{color}\" stroke-width=\"1.2\"");
    match g {
        Glyph::Person => {
            let _ = write!(
                out,
                "<circle cx=\"{}\" cy=\"{}\" r=\"{}\" fill=\"{color}\"/>\
                 <path d=\"M{} A{} {} 0 0 1 {} Z\" fill=\"{color}\"/>",
                n(cx),
                n(cy - 0.2 * s),
                n(0.2 * s),
                p(-0.38, 0.45),
                n(0.38 * s),
                n(0.38 * s),
                p(0.38, 0.45)
            );
        }
        Glyph::Document => {
            let _ = write!(
                out,
                "<path d=\"M{} H{} L{} V{} H{} Z\" {common}/><path d=\"M{} H{} M{} H{}\" stroke=\"{color}\" stroke-width=\"1\"/>",
                p(-0.32, -0.45),
                n(cx + 0.12 * s),
                p(0.32, -0.25),
                n(cy + 0.45 * s),
                n(cx - 0.32 * s),
                p(-0.18, 0.0),
                n(cx + 0.18 * s),
                p(-0.18, 0.2),
                n(cx + 0.18 * s)
            );
        }
        Glyph::Workstation => {
            let _ = write!(
                out,
                "<rect x=\"{}\" y=\"{}\" width=\"{}\" height=\"{}\" rx=\"1\" {common}/>\
                 <path d=\"M{} V{} M{} H{}\" stroke=\"{color}\" stroke-width=\"1.2\"/>",
                n(cx - 0.45 * s),
                n(cy - 0.42 * s),
                n(0.9 * s),
                n(0.6 * s),
                p(0.0, 0.18),
                n(cy + 0.42 * s),
                p(-0.25, 0.42),
                n(cx + 0.25 * s)
            );
        }
        Glyph::Printer => {
            let _ = write!(
                out,
                "<rect x=\"{}\" y=\"{}\" width=\"{}\" height=\"{}\" {common}/>\
                 <rect x=\"{}\" y=\"{}\" width=\"{}\" height=\"{}\" rx=\"1\" fill=\"{color}\"/>\
                 <rect x=\"{}\" y=\"{}\" width=\"{}\" height=\"{}\" {common}/>",
                n(cx - 0.25 * s),
                n(cy - 0.45 * s),
                n(0.5 * s),
                n(0.3 * s),
                n(cx - 0.45 * s),
                n(cy - 0.15 * s),
                n(0.9 * s),
                n(0.4 * s),
                n(cx - 0.25 * s),
                n(cy + 0.15 * s),
                n(0.5 * s),
                n(0.3 * s)
            );
        }
        Glyph::Share => {
            let _ = write!(
                out,
                "<path d=\"M{} V{} H{} L{} H{} V{} Z\" fill=\"{color}\" fill-opacity=\"0.25\" stroke=\"{color}\" stroke-width=\"1.2\"/>",
                p(-0.45, 0.38),
                n(cy - 0.38 * s),
                n(cx - 0.1 * s),
                p(0.02, -0.25),
                n(cx + 0.45 * s),
                n(cy + 0.38 * s)
            );
        }
        Glyph::Server => {
            let _ = write!(
                out,
                "<rect x=\"{}\" y=\"{}\" width=\"{}\" height=\"{}\" rx=\"1\" {common}/>\
                 <path d=\"M{} H{} M{} H{}\" stroke=\"{color}\" stroke-width=\"1\"/>\
                 <circle cx=\"{}\" cy=\"{}\" r=\"{}\" fill=\"{color}\"/>",
                n(cx - 0.3 * s),
                n(cy - 0.45 * s),
                n(0.6 * s),
                n(0.9 * s),
                p(-0.3, -0.15),
                n(cx + 0.3 * s),
                p(-0.3, 0.15),
                n(cx + 0.3 * s),
                n(cx + 0.12 * s),
                n(cy + 0.3 * s),
                n(0.06 * s)
            );
        }
        Glyph::Domain => {
            let _ = write!(
                out,
                "<circle cx=\"{}\" cy=\"{}\" r=\"{}\" {common}/>\
                 <ellipse cx=\"{}\" cy=\"{}\" rx=\"{}\" ry=\"{}\" fill=\"none\" stroke=\"{color}\" stroke-width=\"1\"/>\
                 <path d=\"M{} H{}\" stroke=\"{color}\" stroke-width=\"1\"/>",
                n(cx),
                n(cy),
                n(0.45 * s),
                n(cx),
                n(cy),
                n(0.18 * s),
                n(0.45 * s),
                p(-0.45, 0.0),
                n(cx + 0.45 * s)
            );
        }
        Glyph::Pki => {
            let _ = write!(
                out,
                "<path d=\"M{} L{} V{} Q{} {} Q{} {} V{} Z\" fill=\"{color}\" fill-opacity=\"0.25\" stroke=\"{color}\" stroke-width=\"1.2\"/>",
                p(0.0, -0.47),
                p(0.4, -0.3),
                n(cy),
                p(0.4, 0.32),
                p(0.0, 0.48),
                p(-0.4, 0.32),
                p(-0.4, 0.0),
                n(cy - 0.3 * s)
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clean_flattens_and_escapes() {
        assert_eq!(
            clean(" a\n\t<b onload='x'>\u{202e}&]]> "),
            "a &lt;b onload=&apos;x&apos;&gt;&amp;]]&gt;"
        );
    }

    #[test]
    fn wrap_prefers_separators_and_truncates() {
        assert_eq!(
            wrap("\\\\FS01\\Buh\\Reports\\2024", 12, 2),
            vec!["\\\\FS01\\Buh\\", "Reports\\2024"]
        );
        let w = wrap("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 10, 2);
        assert_eq!(w.len(), 2);
        assert!(w[1].ends_with('…') && w[1].chars().count() == 10);
        assert_eq!(wrap("short", 10, 2), vec!["short"]);
    }

    #[test]
    fn numbers_are_stable() {
        assert_eq!(n(1.0), "1");
        assert_eq!(n(1.26), "1.3");
        assert_eq!(n(-0.01), "0");
    }
}
