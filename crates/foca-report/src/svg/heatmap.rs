//! Activity heat map: weekday (rows, Monday first) × hour 0-23 (columns), with the working
//! week outlined so that off-hours work stands out in black and white too.
//!
//! The aggregate from `foca-analysis::timeline::Activity` has only marginals (`hours`,
//! `weekdays`); the full 7×24 `matrix` is optional. Without it the map degrades to two bar
//! strips (hours and weekdays) and never invents a joint distribution.

use std::fmt::Write as _;

use serde::{Deserialize, Serialize};

use super::{clean, n, open, text, Figure};
use crate::i18n;
use crate::opts::Lang;

fn default_start() -> u8 {
    8
}

fn default_end() -> u8 {
    19
}

/// Activity input for the report.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Heatmap {
    /// Seven rows (0 = Monday) of 24 hourly counts; empty when only marginals are known.
    pub matrix: Vec<Vec<u32>>,
    /// Counts per hour 0-23 (used when `matrix` is empty).
    pub hours: Vec<u32>,
    /// Counts per weekday, 0 = Monday (used when `matrix` is empty).
    pub weekdays: Vec<u32>,
    /// Off-hours count as computed by the analysis; derived from `matrix` when absent.
    pub out_of_hours: Option<u32>,
    /// Dominant time zone (`UTC+2`).
    pub tz: Option<String>,
    /// Working hours `[work_start, work_end)` on Monday-Friday.
    #[serde(default = "default_start")]
    pub work_start: u8,
    #[serde(default = "default_end")]
    pub work_end: u8,
}

impl Default for Heatmap {
    fn default() -> Self {
        Heatmap {
            matrix: Vec::new(),
            hours: Vec::new(),
            weekdays: Vec::new(),
            out_of_hours: None,
            tz: None,
            work_start: default_start(),
            work_end: default_end(),
        }
    }
}

/// Normalized activity: a full matrix (if known) plus marginals and totals.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Norm {
    pub matrix: Option<[[u32; 24]; 7]>,
    pub hours: [u32; 24],
    pub weekdays: [u32; 7],
    pub total: u32,
    pub off: u32,
    pub start: usize,
    pub end: usize,
}

impl Heatmap {
    /// Returns a copy with the free text shown with the map (the time zone label) passed
    /// through `f`, e.g. to mask secrets.
    pub fn map_text(&self, f: impl Fn(&str) -> String) -> Heatmap {
        Heatmap {
            tz: self.tz.as_deref().map(f),
            ..self.clone()
        }
    }

    /// Returns `true` when there is at least one timestamp.
    pub fn has_data(&self) -> bool {
        self.norm().is_some()
    }

    pub(crate) fn norm(&self) -> Option<Norm> {
        let start = usize::from(self.work_start.min(23));
        let end = usize::from(self.work_end.clamp(self.work_start.min(23) + 1, 24));
        let off_cell = |d: usize, h: usize| d >= 5 || h < start || h >= end;
        let valid = self.matrix.len() == 7 && self.matrix.iter().all(|r| r.len() == 24);
        let (matrix, hours, weekdays) = if valid {
            let mut m = [[0u32; 24]; 7];
            let (mut hs, mut ws) = ([0u32; 24], [0u32; 7]);
            for (d, row) in self.matrix.iter().enumerate() {
                for (h, v) in row.iter().enumerate() {
                    m[d][h] = *v;
                    hs[h] = hs[h].saturating_add(*v);
                    ws[d] = ws[d].saturating_add(*v);
                }
            }
            (Some(m), hs, ws)
        } else {
            let mut hs = [0u32; 24];
            let mut ws = [0u32; 7];
            for (i, v) in self.hours.iter().take(24).enumerate() {
                hs[i] = *v;
            }
            for (i, v) in self.weekdays.iter().take(7).enumerate() {
                ws[i] = *v;
            }
            (None, hs, ws)
        };
        let total = hours
            .iter()
            .fold(0u32, |a, v| a.saturating_add(*v))
            .max(weekdays.iter().fold(0u32, |a, v| a.saturating_add(*v)));
        if total == 0 {
            return None;
        }
        let off = match (matrix, self.out_of_hours) {
            (_, Some(o)) => o.min(total),
            (Some(m), None) => (0..7)
                .flat_map(|d| (0..24).map(move |h| (d, h)))
                .filter(|&(d, h)| off_cell(d, h))
                .map(|(d, h)| m[d][h])
                .fold(0u32, |a, v| a.saturating_add(v)),
            (None, None) => 0,
        };
        Some(Norm {
            matrix,
            hours,
            weekdays,
            total,
            off,
            start,
            end,
        })
    }
}

const W: f64 = 404.0;
const LEFT: f64 = 30.0;
const CELL: f64 = 14.0;
const TOP: f64 = 30.0;
/// Sequential palette, monotonic in lightness so that it survives grayscale printing.
const SCALE: [&str; 6] = [
    "#f8fafc", "#dbeafe", "#93c5fd", "#3b82f6", "#1d4ed8", "#1e3a8a",
];
const OUTLINE: &str = "#0f172a";

/// Bucket 0 (empty) to 5 (max) on a square-root scale.
fn level(v: u32, max: u32) -> usize {
    if v == 0 || max == 0 {
        return 0;
    }
    let r = (v as f64 / max as f64).sqrt();
    1 + ((r * 5.0).ceil() as usize).saturating_sub(1).min(4)
}

#[allow(clippy::too_many_arguments)]
fn cell(s: &mut String, x: f64, y: f64, w: f64, h: f64, v: u32, max: u32, title: &str) {
    let lv = level(v, max);
    let _ = write!(
        s,
        "<rect x=\"{}\" y=\"{}\" width=\"{}\" height=\"{}\" rx=\"2\" fill=\"{}\" stroke=\"#e2e8f0\" stroke-width=\"0.6\"><title>{}</title></rect>",
        n(x),
        n(y),
        n(w),
        n(h),
        SCALE[lv],
        clean(title)
    );
    if v > 0 && w >= 12.0 {
        let label = if v > 99 {
            "99+".to_string()
        } else {
            v.to_string()
        };
        let fill = if lv >= 3 { "#fff" } else { "#0f172a" };
        let size = if label.len() > 2 { 6.0 } else { 7.5 };
        text(
            s,
            x + w / 2.0,
            y + h / 2.0 + 2.6,
            size,
            fill,
            "middle",
            false,
            &label,
        );
    }
}

/// Renders the activity map, or `None` without timestamps.
pub fn render(a: &Heatmap, l: Lang) -> Option<Figure> {
    let t = i18n::viz(l);
    let m = a.norm()?;
    let grid_w = 24.0 * CELL;
    let mut s = String::with_capacity(12 * 1024);
    // Layout: hour labels, the 7×24 grid (or a weekday strip), the hour histogram, legend.
    let grid_h = if m.matrix.is_some() { 7.0 * CELL } else { 0.0 };
    let hist_top = TOP + grid_h + if m.matrix.is_some() { 10.0 } else { 0.0 };
    let hist_h = 34.0;
    let week_top = hist_top + hist_h + 22.0;
    let week_h = if m.matrix.is_some() {
        0.0
    } else {
        7.0 * 16.0 + 6.0
    };
    let legend_top = week_top + week_h;
    let height = legend_top + 40.0;
    open(&mut s, W, height, t.activity);
    // Hour axis labels and the working-hours bracket.
    for h in (0..24).step_by(3) {
        text(
            &mut s,
            LEFT + h as f64 * CELL + CELL / 2.0,
            TOP - 4.0,
            8.0,
            "#475569",
            "middle",
            false,
            &format!("{h:02}"),
        );
    }
    let (x0, x1) = (LEFT + m.start as f64 * CELL, LEFT + m.end as f64 * CELL);
    let _ = write!(
        s,
        "<path d=\"M{} 16 V12 H{} V16\" fill=\"none\" stroke=\"{OUTLINE}\" stroke-width=\"1\"/>",
        n(x0),
        n(x1)
    );
    text(
        &mut s,
        (x0 + x1) / 2.0,
        9.0,
        8.0,
        OUTLINE,
        "middle",
        true,
        &clean(&format!("{} {:02}-{:02}", t.work_hours, m.start, m.end)),
    );
    if let Some(mx) = m.matrix {
        let max = mx.iter().flatten().copied().max().unwrap_or(0);
        for (d, row) in mx.iter().enumerate() {
            let y = TOP + d as f64 * CELL;
            let weekend = d >= 5;
            text(
                &mut s,
                LEFT - 4.0,
                y + CELL / 2.0 + 3.5,
                9.0,
                if weekend { "#b91c1c" } else { "#0f172a" },
                "end",
                weekend,
                &clean(t.weekdays[d]),
            );
            for (h, v) in row.iter().enumerate() {
                let title = format!("{} {h:02}:00-{h:02}:59: {v}", t.weekdays[d]);
                cell(
                    &mut s,
                    LEFT + h as f64 * CELL + 0.5,
                    y + 0.5,
                    CELL - 1.0,
                    CELL - 1.0,
                    *v,
                    max,
                    &title,
                );
            }
            // Weekday total to the right of the row.
            text(
                &mut s,
                LEFT + grid_w + 4.0,
                y + CELL / 2.0 + 3.5,
                8.5,
                "#475569",
                "start",
                false,
                &m.weekdays[d].to_string(),
            );
        }
        // Working week outline (Mon-Fri × working hours): everything outside is off hours.
        let _ = write!(
            s,
            "<rect x=\"{}\" y=\"{}\" width=\"{}\" height=\"{}\" fill=\"none\" stroke=\"{OUTLINE}\" stroke-width=\"1.8\"/>",
            n(x0),
            n(TOP),
            n(x1 - x0),
            n(5.0 * CELL)
        );
        // Off-hours cells with activity get a corner mark.
        for (d, row) in mx.iter().enumerate() {
            for (h, v) in row.iter().enumerate() {
                if *v > 0 && (d >= 5 || h < m.start || h >= m.end) {
                    let (x, y) = (LEFT + (h + 1) as f64 * CELL, TOP + d as f64 * CELL);
                    let _ = write!(
                        s,
                        "<path d=\"M{} {} H{} V{} Z\" fill=\"#b91c1c\"/>",
                        n(x - 5.5),
                        n(y + 0.5),
                        n(x - 0.5),
                        n(y + 5.5)
                    );
                }
            }
        }
    }
    // Hour histogram.
    let hmax = m.hours.iter().copied().max().unwrap_or(0).max(1);
    let _ = write!(
        s,
        "<path d=\"M{} {} H{}\" stroke=\"#94a3b8\" stroke-width=\"1\"/>",
        n(LEFT),
        n(hist_top + hist_h),
        n(LEFT + grid_w)
    );
    for (h, v) in m.hours.iter().enumerate() {
        if *v == 0 {
            continue;
        }
        let bh = (hist_h - 2.0) * *v as f64 / hmax as f64;
        let off = h < m.start || h >= m.end;
        let _ = write!(
            s,
            "<rect x=\"{}\" y=\"{}\" width=\"{}\" height=\"{}\" fill=\"{}\" stroke=\"{OUTLINE}\" stroke-width=\"{}\"><title>{}</title></rect>",
            n(LEFT + h as f64 * CELL + 2.0),
            n(hist_top + hist_h - bh),
            n(CELL - 4.0),
            n(bh),
            if off { "#fecaca" } else { "#93c5fd" },
            if off { "1" } else { "0.4" },
            clean(&format!("{h:02}:00: {v}"))
        );
    }
    text(
        &mut s,
        LEFT - 4.0,
        hist_top + hist_h - 2.0,
        8.0,
        "#475569",
        "end",
        false,
        &clean(t.hour),
    );
    for h in (0..24).step_by(3) {
        text(
            &mut s,
            LEFT + h as f64 * CELL + CELL / 2.0,
            hist_top + hist_h + 10.0,
            8.0,
            "#475569",
            "middle",
            false,
            &format!("{h:02}"),
        );
    }
    // Weekday strip when no matrix is known.
    if m.matrix.is_none() {
        let wmax = m.weekdays.iter().copied().max().unwrap_or(0).max(1);
        for (d, v) in m.weekdays.iter().enumerate() {
            let y = week_top + d as f64 * 16.0;
            let weekend = d >= 5;
            text(
                &mut s,
                LEFT - 4.0,
                y + 11.0,
                9.0,
                if weekend { "#b91c1c" } else { "#0f172a" },
                "end",
                weekend,
                &clean(t.weekdays[d]),
            );
            let bw = (grid_w - 30.0) * *v as f64 / wmax as f64;
            let _ = write!(
                s,
                "<rect x=\"{}\" y=\"{}\" width=\"{}\" height=\"12\" rx=\"2\" fill=\"{}\" stroke=\"{OUTLINE}\" stroke-width=\"{}\"/>",
                n(LEFT),
                n(y + 2.0),
                n(bw.max(0.5)),
                if weekend { "#fecaca" } else { "#93c5fd" },
                if weekend { "1" } else { "0.4" }
            );
            text(
                &mut s,
                LEFT + bw + 4.0,
                y + 11.5,
                8.5,
                "#334155",
                "start",
                false,
                &v.to_string(),
            );
        }
    }
    // Legend: scale, off-hours mark, totals and time zone.
    let ly = legend_top;
    text(
        &mut s,
        LEFT,
        ly + 9.0,
        8.0,
        "#475569",
        "start",
        false,
        &clean(t.less),
    );
    for (i, c) in SCALE.iter().enumerate().skip(1) {
        let _ = write!(
            s,
            "<rect x=\"{}\" y=\"{}\" width=\"12\" height=\"10\" rx=\"2\" fill=\"{c}\" stroke=\"#e2e8f0\" stroke-width=\"0.6\"/>",
            n(LEFT + 34.0 + (i - 1) as f64 * 13.0),
            n(ly)
        );
    }
    text(
        &mut s,
        LEFT + 34.0 + 5.0 * 13.0 + 3.0,
        ly + 9.0,
        8.0,
        "#475569",
        "start",
        false,
        &clean(t.more_activity),
    );
    let mx = LEFT + 160.0;
    let _ = write!(
        s,
        "<rect x=\"{}\" y=\"{}\" width=\"12\" height=\"10\" fill=\"#fff\" stroke=\"#e2e8f0\" stroke-width=\"0.6\"/><path d=\"M{} {} H{} V{} Z\" fill=\"#b91c1c\"/>",
        n(mx),
        n(ly),
        n(mx + 6.5),
        n(ly),
        n(mx + 12.0),
        n(ly + 5.5)
    );
    let pct = (m.off as f64 * 100.0 / m.total as f64).round() as u32;
    text(
        &mut s,
        mx + 16.0,
        ly + 9.0,
        8.0,
        "#0f172a",
        "start",
        true,
        &clean(&format!(
            "{}: {} / {} ({pct}%)",
            t.off_hours, m.off, m.total
        )),
    );
    let tz =
        a.tz.as_deref()
            .map(super::flat)
            .filter(|s| !s.is_empty())
            .map(|z| format!("{}: {}", t.tz, super::truncate(&z, 24)))
            .unwrap_or_default();
    let peak = m
        .hours
        .iter()
        .enumerate()
        .max_by(|a, b| a.1.cmp(b.1).then(b.0.cmp(&a.0)))
        .map(|(h, _)| h)
        .unwrap_or(0);
    let line2 = [
        format!("{}: {} {}", t.total, m.total, t.timestamps),
        format!("{}: {peak:02}:00", t.peak),
        tz.clone(),
    ]
    .into_iter()
    .filter(|s| !s.is_empty())
    .collect::<Vec<_>>()
    .join(" · ");
    text(
        &mut s,
        LEFT,
        ly + 26.0,
        8.5,
        "#334155",
        "start",
        false,
        &clean(&line2),
    );
    s.push_str("</svg>");
    Some(Figure {
        svg: s,
        caption: line2,
        width: W as u32,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matrix_derives_marginals_and_off_hours() {
        let mut mx = vec![vec![0u32; 24]; 7];
        mx[0][10] = 4; // Monday 10:00: working time.
        mx[2][22] = 2; // Wednesday 22:00: off hours.
        mx[6][12] = 1; // Sunday: off hours.
        let a = Heatmap {
            matrix: mx,
            tz: Some("UTC+2".into()),
            ..Heatmap::default()
        };
        let m = a.norm().unwrap();
        assert_eq!((m.total, m.off), (7, 3));
        assert_eq!(m.hours[22], 2);
        assert_eq!(m.weekdays[6], 1);
        let f = render(&a, Lang::En).unwrap();
        assert!(f.svg.contains("off hours: 3 / 7 (43%)"));
        assert!(f.svg.contains("UTC+2"));
    }

    #[test]
    fn marginals_only_and_empty() {
        let a = Heatmap {
            hours: (0..24).collect(),
            weekdays: vec![1, 2, 3, 4, 5, 0, 0],
            out_of_hours: Some(5),
            matrix: vec![vec![1; 3]],
            ..Heatmap::default()
        };
        let f = render(&a, Lang::Uk).unwrap();
        assert!(f.svg.contains("поза графіком: 5 / 276"));
        assert!(!Heatmap::default().has_data());
        assert_eq!(level(1, 100), 1);
        assert_eq!(level(100, 100), 5);
    }
}
