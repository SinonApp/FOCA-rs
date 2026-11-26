//! Chronology by year: rows are years (ascending), columns are lanes (documents,
//! software/technology, CT certificates, Wayback snapshots). Each cell shows the event count
//! and the most frequent labels; the full list goes into `<title>`.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use serde::{Deserialize, Serialize};

use super::{clean, flat, n, open, text, truncate, Figure};
use crate::i18n;
use crate::opts::Lang;

/// Years drawn at most; older years fold into one `≤ YYYY` row.
pub const MAX_YEARS: usize = 20;
/// Labels written per cell.
pub const MAX_LABELS: usize = 2;
/// Events considered at all.
pub const MAX_EVENTS: usize = 20_000;

/// Chronology lane.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum Lane {
    #[default]
    Documents,
    Software,
    Certificates,
    Wayback,
}

/// A dated event; years outside 1970-2100 are ignored.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct TimelineEvent {
    pub lane: Lane,
    pub year: i32,
    pub label: String,
}

/// Chronology input for the report.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Timeline {
    pub events: Vec<TimelineEvent>,
}

/// One cell: event count and labels by frequency.
#[derive(Debug, Clone, Default, PartialEq)]
pub(crate) struct Cell {
    pub count: usize,
    /// Distinct labels, most frequent first, then alphabetical.
    pub labels: Vec<(String, usize)>,
}

/// The year × lane grid.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Grid {
    /// Lanes that have events, in lane order.
    pub lanes: Vec<Lane>,
    /// `(year, folded, cells per lane in `lanes` order)`; `folded` marks the `≤ year` row.
    pub rows: Vec<(i32, bool, Vec<Cell>)>,
    pub totals: Vec<usize>,
}

/// Builds the grid; labels (core data such as `Sony (камера)`) are put into the report language.
pub(crate) fn grid(tl: &Timeline, l: Lang) -> Option<Grid> {
    let mut by: BTreeMap<i32, [BTreeMap<String, usize>; 4]> = BTreeMap::new();
    for e in tl.events.iter().take(MAX_EVENTS) {
        if !(1970..=2100).contains(&e.year) {
            continue;
        }
        let label = flat(&crate::ftext::terms(&e.label, l));
        *by.entry(e.year).or_default()[e.lane as usize]
            .entry(label)
            .or_default() += 1;
    }
    if by.is_empty() {
        return None;
    }
    if by.len() > MAX_YEARS {
        let cut = *by.keys().nth(by.len() - MAX_YEARS).unwrap_or(&0);
        let old: Vec<i32> = by.range(..cut).map(|(y, _)| *y).collect();
        let last_old = *old.last().unwrap_or(&cut);
        let mut merged: [BTreeMap<String, usize>; 4] = Default::default();
        for y in old {
            if let Some(cells) = by.remove(&y) {
                for (i, c) in cells.into_iter().enumerate() {
                    for (k, v) in c {
                        *merged[i].entry(k).or_default() += v;
                    }
                }
            }
        }
        // The folded row keeps the key of the newest folded year, marked below.
        by.insert(last_old, merged);
        let lanes = present(&by);
        let mut g = build(by, &lanes);
        if let Some(first) = g.rows.first_mut() {
            first.1 = true;
        }
        return Some(g);
    }
    let lanes = present(&by);
    Some(build(by, &lanes))
}

fn present(by: &BTreeMap<i32, [BTreeMap<String, usize>; 4]>) -> Vec<Lane> {
    [
        Lane::Documents,
        Lane::Software,
        Lane::Certificates,
        Lane::Wayback,
    ]
    .into_iter()
    .filter(|l| by.values().any(|c| !c[*l as usize].is_empty()))
    .collect()
}

fn build(by: BTreeMap<i32, [BTreeMap<String, usize>; 4]>, lanes: &[Lane]) -> Grid {
    let mut totals = vec![0usize; lanes.len()];
    let rows = by
        .into_iter()
        .map(|(y, cells)| {
            let row = lanes
                .iter()
                .enumerate()
                .map(|(i, l)| {
                    let m = &cells[*l as usize];
                    let count: usize = m.values().sum();
                    totals[i] += count;
                    let mut labels: Vec<(String, usize)> =
                        m.iter().map(|(k, v)| (k.clone(), *v)).collect();
                    labels.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
                    Cell { count, labels }
                })
                .collect();
            (y, false, row)
        })
        .collect();
    Grid {
        lanes: lanes.to_vec(),
        rows,
        totals,
    }
}

const W: f64 = 400.0;
const PAD: f64 = 6.0;
const YEAR_W: f64 = 50.0;
const HEAD_H: f64 = 32.0;
const LINE_H: f64 = 12.0;
const FONT: f64 = 9.0;
const ADV: f64 = 5.0;
const LANE_INK: [&str; 4] = ["#1d4ed8", "#6d28d9", "#047857", "#b45309"];
const LANE_FILL: [&str; 4] = ["#dbeafe", "#ede9fe", "#d1fae5", "#fef3c7"];

fn pill_width(count: usize) -> f64 {
    8.0 + count.to_string().len() as f64 * 6.0
}

/// Text lines of a cell next to the count pill: the most frequent label wrapped to two
/// lines (so that `Microsoft Office 2016` stays whole in a narrow lane), then the second one.
fn cell_lines(c: &Cell, lane_w: f64) -> Vec<String> {
    let chars = ((lane_w - pill_width(c.count) - 10.0) / ADV)
        .floor()
        .max(4.0) as usize;
    let mut out = Vec::new();
    for (k, (lab, _)) in c
        .labels
        .iter()
        .filter(|l| !l.0.is_empty())
        .take(MAX_LABELS)
        .enumerate()
    {
        if k == 0 {
            out.extend(super::wrap(lab, chars, 2));
        } else {
            out.push(truncate(lab, chars));
        }
    }
    out
}

/// Renders the chronology, or `None` without dated events.
pub fn render(tl: &Timeline, l: Lang) -> Option<Figure> {
    let t = i18n::viz(l);
    let g = grid(tl, l)?;
    let lane_w = (W - YEAR_W - PAD) / g.lanes.len() as f64;
    let row_h: Vec<f64> = g
        .rows
        .iter()
        .map(|(_, _, cells)| {
            let lines = cells
                .iter()
                .map(|c| cell_lines(c, lane_w).len())
                .max()
                .unwrap_or(1)
                .max(1);
            lines as f64 * LINE_H + 8.0
        })
        .collect();
    let height = HEAD_H + row_h.iter().sum::<f64>() + PAD;
    let mut s = String::with_capacity(8 * 1024);
    open(&mut s, W, height, t.timeline);
    // Lane headers: name and total (two lines when the name is long).
    for (i, lane) in g.lanes.iter().enumerate() {
        let x = YEAR_W + i as f64 * lane_w;
        let li = *lane as usize;
        let _ = write!(
            s,
            "<rect x=\"{}\" y=\"2\" width=\"{}\" height=\"{}\" rx=\"4\" fill=\"{}\" stroke=\"{}\" stroke-width=\"0.8\"/>",
            n(x + 2.0),
            n(lane_w - 4.0),
            n(HEAD_H - 6.0),
            LANE_FILL[li],
            LANE_INK[li]
        );
        let name = format!("{} · {}", t.lanes[li], g.totals[i]);
        let chars = ((lane_w - 8.0) / 5.4).floor() as usize;
        let lines = super::wrap(&name, chars, 2);
        let y0 = if lines.len() == 1 { 19.0 } else { 13.5 };
        for (k, line) in lines.iter().enumerate() {
            text(
                &mut s,
                x + lane_w / 2.0,
                y0 + k as f64 * 10.5,
                9.0,
                "#0f172a",
                "middle",
                true,
                &clean(line),
            );
        }
    }
    text(
        &mut s,
        YEAR_W - 10.0,
        19.0,
        9.0,
        "#475569",
        "end",
        true,
        &clean(t.year),
    );
    // Year axis.
    let _ = write!(
        s,
        "<path d=\"M{} {} V{}\" stroke=\"#94a3b8\" stroke-width=\"1.5\"/>",
        n(YEAR_W - 5.0),
        n(HEAD_H),
        n(height - PAD)
    );
    let mut y = HEAD_H;
    for (r, (year, folded, cells)) in g.rows.iter().enumerate() {
        let h = row_h[r];
        if r % 2 == 1 {
            let _ = write!(
                s,
                "<rect x=\"0\" y=\"{}\" width=\"{}\" height=\"{}\" fill=\"#f8fafc\"/>",
                n(y),
                n(W),
                n(h)
            );
        }
        let label = if *folded {
            format!("≤{year}")
        } else {
            year.to_string()
        };
        let _ = write!(
            s,
            "<circle cx=\"{}\" cy=\"{}\" r=\"3\" fill=\"#334155\"/>",
            n(YEAR_W - 5.0),
            n(y + 10.0)
        );
        text(
            &mut s,
            YEAR_W - 12.0,
            y + 13.5,
            10.0,
            "#0f172a",
            "end",
            true,
            &clean(&label),
        );
        for (i, (lane, c)) in g.lanes.iter().zip(cells).enumerate() {
            if c.count == 0 {
                continue;
            }
            let li = *lane as usize;
            let x = YEAR_W + i as f64 * lane_w + 4.0;
            let num = c.count.to_string();
            let pill_w = pill_width(c.count);
            let mut title = format!("{} · {label}: {}", t.lanes[li], c.count);
            let names: Vec<String> = c
                .labels
                .iter()
                .take(15)
                .map(|(k, v)| {
                    if *v > 1 {
                        format!("{k} ×{v}")
                    } else {
                        k.clone()
                    }
                })
                .collect();
            if !names.is_empty() {
                let _ = write!(title, ": {}", names.join("; "));
                if c.labels.len() > 15 {
                    let _ = write!(title, " … (+{})", c.labels.len() - 15);
                }
            }
            let _ = write!(
                s,
                "<g><title>{}</title><rect x=\"{}\" y=\"{}\" width=\"{}\" height=\"14\" rx=\"7\" fill=\"{}\" stroke=\"{}\" stroke-width=\"1\"/>",
                clean(&title),
                n(x),
                n(y + 3.0),
                n(pill_w),
                LANE_FILL[li],
                LANE_INK[li]
            );
            text(
                &mut s,
                x + pill_w / 2.0,
                y + 13.5,
                9.0,
                "#0f172a",
                "middle",
                true,
                &num,
            );
            for (k, line) in cell_lines(c, lane_w).iter().enumerate() {
                text(
                    &mut s,
                    x + pill_w + 3.0,
                    y + 13.5 + k as f64 * LINE_H,
                    FONT,
                    "#1e293b",
                    "start",
                    false,
                    &clean(line),
                );
            }
            s.push_str("</g>");
        }
        y += h;
    }
    s.push_str("</svg>");
    let total: usize = g.totals.iter().sum();
    let first = g.rows.first().map(|r| r.0).unwrap_or_default();
    let last = g.rows.last().map(|r| r.0).unwrap_or_default();
    let caption = format!("{first}-{last} · {}: {total}", t.total);
    Some(Figure {
        svg: s,
        caption,
        width: W as u32,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(lane: Lane, year: i32, label: &str) -> TimelineEvent {
        TimelineEvent {
            lane,
            year,
            label: label.into(),
        }
    }

    #[test]
    fn grid_groups_ranks_and_folds_old_years() {
        let mut tl = Timeline::default();
        for y in 1990..2020 {
            tl.events.push(ev(Lane::Documents, y, "doc"));
        }
        tl.events.push(ev(Lane::Software, 2019, "Office 2016"));
        tl.events.push(ev(Lane::Software, 2019, "Office 2016"));
        tl.events.push(ev(Lane::Software, 2019, "Acrobat"));
        tl.events.push(ev(Lane::Software, 1800, "bogus"));
        let g = grid(&tl, Lang::Ru).unwrap();
        assert_eq!(g.lanes, vec![Lane::Documents, Lane::Software]);
        assert_eq!(g.rows.len(), MAX_YEARS + 1);
        assert!(g.rows[0].1 && g.rows[0].0 == 1999);
        assert_eq!(g.rows[0].2[0].count, 10);
        let last = &g.rows.last().unwrap().2[1];
        assert_eq!(last.labels[0], ("Office 2016".to_string(), 2));
        assert_eq!(g.totals, vec![30, 3]);
        assert!(render(&tl, Lang::Ru).unwrap().svg.contains("≤1999"));
    }
}
