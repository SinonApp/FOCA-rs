//! Layered link graph: people → documents → PCs/printers/shares → servers/domains/PKI.
//!
//! Layout follows the Sugiyama scheme in a simplified form: fixed layers by node kind
//! (columns, left to right), dummy nodes on edges that skip a layer, crossing reduction by
//! alternating barycenter sweeps (the order with the fewest crossings wins), then stacked
//! coordinates centered per column. Each layer keeps at most [`MAX_PER_LAYER`] boxes: the
//! least connected nodes collapse into one cluster per kind (`14 documents`), and edges are
//! rerouted to the cluster with a weight.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt::Write as _;

use serde::{Deserialize, Serialize};

use super::{clean, flat, glyph, n, open, text, wrap, Figure, Glyph};
use crate::i18n::{self, VizStrings};
use crate::opts::Lang;

/// Visible boxes per layer, cluster boxes included.
pub const MAX_PER_LAYER: usize = 10;
/// Input nodes considered at all (the rest are counted but ignored).
pub const MAX_INPUT_NODES: usize = 5000;
/// Edges drawn after collapsing (heaviest first).
pub const MAX_EDGES: usize = 240;

/// Graph node kind; determines the layer (column).
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum NodeKind {
    #[default]
    Person,
    Document,
    Workstation,
    Printer,
    Share,
    Server,
    Domain,
    Pki,
}

impl NodeKind {
    /// Layer index: 0 people, 1 documents, 2 PCs/printers/shares, 3 servers/domains/PKI.
    pub fn layer(self) -> usize {
        match self {
            NodeKind::Person => 0,
            NodeKind::Document => 1,
            NodeKind::Workstation | NodeKind::Printer | NodeKind::Share => 2,
            NodeKind::Server | NodeKind::Domain | NodeKind::Pki => 3,
        }
    }

    fn idx(self) -> usize {
        self as usize
    }

    pub(crate) fn glyph(self) -> Glyph {
        match self {
            NodeKind::Person => Glyph::Person,
            NodeKind::Document => Glyph::Document,
            NodeKind::Workstation => Glyph::Workstation,
            NodeKind::Printer => Glyph::Printer,
            NodeKind::Share => Glyph::Share,
            NodeKind::Server => Glyph::Server,
            NodeKind::Domain => Glyph::Domain,
            NodeKind::Pki => Glyph::Pki,
        }
    }
}

/// A graph node. `id` must be unique (duplicates: the first one wins).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct GraphNode {
    pub id: String,
    pub kind: NodeKind,
    pub label: String,
    /// Highlighted (red outline) and never collapsed before ordinary nodes.
    pub critical: bool,
}

/// An undirected link between two node ids.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct GraphEdge {
    pub from: String,
    pub to: String,
}

/// Graph input for the report.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Graph {
    pub nodes: Vec<GraphNode>,
    pub edges: Vec<GraphEdge>,
}

/// A visible box: a real node or a cluster of collapsed nodes.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct VNode {
    pub kind: NodeKind,
    pub label: String,
    pub critical: bool,
    /// Collapsed node labels for clusters (empty for real nodes).
    pub members: Vec<String>,
    pub degree: usize,
}

/// Collapsed graph: visible boxes per layer and weighted edges between box indices.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Model {
    pub nodes: Vec<VNode>,
    /// Box indices per layer (only non-empty layers, in layer order) with the layer index.
    pub layers: Vec<(usize, Vec<usize>)>,
    /// `(a, b, weight)` with `a < b` box indices.
    pub edges: Vec<(usize, usize, usize)>,
    pub total_nodes: usize,
    pub total_edges: usize,
}

pub(crate) fn cluster_label(t: &VizStrings, l: Lang, kind: NodeKind, count: usize) -> String {
    format!(
        "{count} {}",
        t.kinds[kind.idx()][i18n::plural_idx(l, count)]
    )
}

/// Collapses the input graph into at most [`MAX_PER_LAYER`] boxes per layer.
pub(crate) fn model(g: &Graph, l: Lang) -> Option<Model> {
    let t = i18n::viz(l);
    let mut index: HashMap<&str, usize> = HashMap::new();
    let mut nodes: Vec<&GraphNode> = Vec::new();
    for nd in g.nodes.iter().take(MAX_INPUT_NODES) {
        if !index.contains_key(nd.id.as_str()) {
            index.insert(nd.id.as_str(), nodes.len());
            nodes.push(nd);
        }
    }
    if nodes.is_empty() {
        return None;
    }
    let mut pairs: BTreeSet<(usize, usize)> = BTreeSet::new();
    for e in &g.edges {
        if let (Some(&a), Some(&b)) = (index.get(e.from.as_str()), index.get(e.to.as_str())) {
            if a != b {
                pairs.insert((a.min(b), a.max(b)));
            }
        }
    }
    let mut degree = vec![0usize; nodes.len()];
    for &(a, b) in &pairs {
        degree[a] += 1;
        degree[b] += 1;
    }
    // Rank inside each layer: critical, most connected, then by label and id.
    let mut by_layer: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
    for (i, nd) in nodes.iter().enumerate() {
        by_layer.entry(nd.kind.layer()).or_default().push(i);
    }
    let mut map = vec![usize::MAX; nodes.len()];
    let mut vnodes: Vec<VNode> = Vec::new();
    let mut layers = Vec::new();
    for (layer, mut ids) in by_layer {
        ids.sort_by(|&a, &b| {
            nodes[b]
                .critical
                .cmp(&nodes[a].critical)
                .then(degree[b].cmp(&degree[a]))
                .then_with(|| flat(&nodes[a].label).cmp(&flat(&nodes[b].label)))
                .then_with(|| nodes[a].id.cmp(&nodes[b].id))
        });
        let mut visible = ids.len();
        if ids.len() > MAX_PER_LAYER {
            visible = MAX_PER_LAYER - 1;
            loop {
                let kinds: BTreeSet<NodeKind> =
                    ids[visible..].iter().map(|&i| nodes[i].kind).collect();
                if visible + kinds.len() <= MAX_PER_LAYER || visible == 0 {
                    break;
                }
                visible -= 1;
            }
        }
        let mut col = Vec::new();
        for &i in &ids[..visible] {
            map[i] = vnodes.len();
            col.push(vnodes.len());
            vnodes.push(VNode {
                kind: nodes[i].kind,
                label: nodes[i].label.clone(),
                critical: nodes[i].critical,
                members: Vec::new(),
                degree: degree[i],
            });
        }
        let mut clusters: BTreeMap<NodeKind, Vec<usize>> = BTreeMap::new();
        for &i in &ids[visible..] {
            clusters.entry(nodes[i].kind).or_default().push(i);
        }
        for (kind, members) in clusters {
            let v = vnodes.len();
            for &i in &members {
                map[i] = v;
            }
            col.push(v);
            vnodes.push(VNode {
                kind,
                label: cluster_label(t, l, kind, members.len()),
                critical: members.iter().any(|&i| nodes[i].critical),
                members: members.iter().map(|&i| nodes[i].label.clone()).collect(),
                degree: 0,
            });
        }
        layers.push((layer, col));
    }
    let mut weights: BTreeMap<(usize, usize), usize> = BTreeMap::new();
    for &(a, b) in &pairs {
        let (x, y) = (map[a], map[b]);
        if x != y {
            *weights.entry((x.min(y), x.max(y))).or_default() += 1;
        }
    }
    let mut edges: Vec<(usize, usize, usize)> =
        weights.into_iter().map(|((a, b), w)| (a, b, w)).collect();
    if edges.len() > MAX_EDGES {
        edges.sort_by(|x, y| y.2.cmp(&x.2).then((x.0, x.1).cmp(&(y.0, y.1))));
        edges.truncate(MAX_EDGES);
        edges.sort();
    }
    for &(a, b, _) in &edges {
        if !vnodes[a].members.is_empty() {
            vnodes[a].degree += 1;
        }
        if !vnodes[b].members.is_empty() {
            vnodes[b].degree += 1;
        }
    }
    Some(Model {
        nodes: vnodes,
        layers,
        edges,
        total_nodes: nodes.len(),
        total_edges: pairs.len(),
    })
}

/// An item of the layered drawing: a box or a dummy point of a long edge.
#[derive(Debug, Clone, Copy)]
enum Item {
    Node(usize),
    Dummy,
}

/// Counts edge crossings between two adjacent columns.
fn crossings(segs: &[(usize, usize)], pos: &[usize]) -> usize {
    let mut c = 0;
    for i in 0..segs.len() {
        let (a1, b1) = (pos[segs[i].0], pos[segs[i].1]);
        for s in &segs[i + 1..] {
            let (a2, b2) = (pos[s.0], pos[s.1]);
            if (a1 < a2 && b1 > b2) || (a1 > a2 && b1 < b2) {
                c += 1;
            }
        }
    }
    c
}

const PAD: f64 = 6.0;
const COL_W: f64 = 132.0;
const BOX_W: f64 = 108.0;
const BOX_H: f64 = 32.0;
const GAP: f64 = 8.0;
const DUMMY_H: f64 = 6.0;
const HEAD_H: f64 = 34.0;
const FONT: f64 = 10.0;
const CHARS: usize = 15;

/// Fill and stroke per layer: light tints for print, darker outlines for black and white.
const LAYER_FILL: [&str; 4] = ["#eef2ff", "#f0fdf4", "#fff7ed", "#f5f3ff"];
const LAYER_INK: [&str; 4] = ["#3730a3", "#166534", "#9a3412", "#5b21b6"];
const CRIT: &str = "#b91c1c";

/// Renders the layered graph, or `None` when there are no nodes.
pub fn render(g: &Graph, l: Lang) -> Option<Figure> {
    let t = i18n::viz(l);
    let m = model(g, l)?;
    let ncol = m.layers.len();
    // Items per column: boxes first, dummies appended while splitting long edges.
    let mut col_of = vec![0usize; m.nodes.len()];
    let mut items: Vec<(usize, Item)> = Vec::new();
    let mut item_of = vec![0usize; m.nodes.len()];
    let mut cols: Vec<Vec<usize>> = vec![Vec::new(); ncol];
    for (c, (_, ids)) in m.layers.iter().enumerate() {
        for &v in ids {
            col_of[v] = c;
            item_of[v] = items.len();
            cols[c].push(items.len());
            items.push((c, Item::Node(v)));
        }
    }
    // Chains of items per edge (from the left column to the right one); same-column edges
    // are drawn as arcs and do not take part in ordering.
    let mut chains: Vec<(Vec<usize>, usize, bool)> = Vec::new();
    let mut arcs: Vec<(usize, usize, usize, bool)> = Vec::new();
    for &(a, b, w) in &m.edges {
        let crit = m.nodes[a].critical || m.nodes[b].critical;
        let (a, b) = if col_of[a] <= col_of[b] {
            (a, b)
        } else {
            (b, a)
        };
        if col_of[a] == col_of[b] {
            arcs.push((item_of[a], item_of[b], w, crit));
            continue;
        }
        let mut chain = vec![item_of[a]];
        for (c, col) in cols
            .iter_mut()
            .enumerate()
            .take(col_of[b])
            .skip(col_of[a] + 1)
        {
            chain.push(items.len());
            col.push(items.len());
            items.push((c, Item::Dummy));
        }
        chain.push(item_of[b]);
        chains.push((chain, w, crit));
    }
    let mut left: Vec<Vec<usize>> = vec![Vec::new(); items.len()];
    let mut right: Vec<Vec<usize>> = vec![Vec::new(); items.len()];
    let mut segs: Vec<Vec<(usize, usize)>> = vec![Vec::new(); ncol.saturating_sub(1)];
    for (chain, _, _) in &chains {
        for w in chain.windows(2) {
            right[w[0]].push(w[1]);
            left[w[1]].push(w[0]);
            segs[items[w[0]].0].push((w[0], w[1]));
        }
    }
    let mut pos = vec![0usize; items.len()];
    let set_pos = |cols: &Vec<Vec<usize>>, pos: &mut Vec<usize>| {
        for col in cols {
            for (i, &it) in col.iter().enumerate() {
                pos[it] = i;
            }
        }
    };
    set_pos(&cols, &mut pos);
    let total = |pos: &[usize]| segs.iter().map(|s| crossings(s, pos)).sum::<usize>();
    let mut best = (total(&pos), cols.clone());
    for iter in 0..12 {
        let order: Vec<usize> = if iter % 2 == 0 {
            (1..ncol).collect()
        } else {
            (0..ncol.saturating_sub(1)).rev().collect()
        };
        for c in order {
            let nb = if iter % 2 == 0 { &left } else { &right };
            let mut keyed: Vec<(f64, usize, usize)> = cols[c]
                .iter()
                .map(|&it| {
                    let b = if nb[it].is_empty() {
                        pos[it] as f64
                    } else {
                        nb[it].iter().map(|&x| pos[x] as f64).sum::<f64>() / nb[it].len() as f64
                    };
                    (b, pos[it], it)
                })
                .collect();
            keyed.sort_by(|x, y| x.0.total_cmp(&y.0).then(x.1.cmp(&y.1)));
            cols[c] = keyed.into_iter().map(|k| k.2).collect();
            for (i, &it) in cols[c].iter().enumerate() {
                pos[it] = i;
            }
        }
        let cr = total(&pos);
        if cr < best.0 {
            best = (cr, cols.clone());
        }
    }
    let cols = best.1;
    set_pos(&cols, &mut pos);
    // Coordinates: stacked boxes, each column centered against the tallest one.
    let h_of = |it: usize| match items[it].1 {
        Item::Node(_) => BOX_H,
        Item::Dummy => DUMMY_H,
    };
    let col_h: Vec<f64> = cols
        .iter()
        .map(|c| c.iter().map(|&it| h_of(it)).sum::<f64>() + GAP * c.len().saturating_sub(1) as f64)
        .collect();
    let max_h = col_h.iter().cloned().fold(0.0, f64::max);
    let mut cy = vec![0.0f64; items.len()];
    for (c, col) in cols.iter().enumerate() {
        let mut y = HEAD_H + (max_h - col_h[c]) / 2.0;
        for &it in col {
            cy[it] = y + h_of(it) / 2.0;
            y += h_of(it) + GAP;
        }
    }
    let x_of = |c: usize| PAD + c as f64 * COL_W;
    let extra = if arcs.iter().any(|a| items[a.0].0 + 1 == ncol) {
        18.0
    } else {
        0.0
    };
    let width = PAD * 2.0 + (ncol as f64 - 1.0) * COL_W + BOX_W + extra;
    let height = HEAD_H + max_h + PAD * 2.0;
    let mut s = String::with_capacity(16 * 1024);
    open(&mut s, width, height, t.graph);
    // Column headers.
    for (c, (layer, ids)) in m.layers.iter().enumerate() {
        let x = x_of(c) + BOX_W / 2.0;
        let count: usize = ids.iter().map(|&v| m.nodes[v].members.len().max(1)).sum();
        // `Name · N` on one line when it fits, otherwise split the name so that the count
        // never dangles alone on the second line.
        let name = t.layers[*layer];
        let tail = format!(" · {count}");
        let len = name.chars().count() + tail.chars().count();
        let mut lines = if len <= 22 {
            vec![name.to_string()]
        } else {
            wrap(name, (name.chars().count() * 2 / 3).max(8), 2)
        };
        if let Some(last) = lines.last_mut() {
            last.push_str(&tail);
        }
        for (i, line) in lines.iter().enumerate() {
            text(
                &mut s,
                x,
                12.0 + i as f64 * 12.0,
                10.0,
                LAYER_INK[*layer],
                "middle",
                true,
                &clean(line),
            );
        }
    }

    // Edges below boxes; critical edges dark and solid, the rest light.
    s.push_str("<g fill=\"none\" stroke-linecap=\"round\">");
    let stroke = |w: usize, crit: bool| {
        format!(
            "stroke=\"{}\" stroke-width=\"{}\"",
            if crit { CRIT } else { "#94a3b8" },
            n(1.0 + (w.min(5) as f64 - 1.0) * 0.6)
        )
    };
    for (chain, w, crit) in &chains {
        let mut d = String::new();
        let mut prev: Option<(f64, f64)> = None;
        for (k, &it) in chain.iter().enumerate() {
            let c = items[it].0;
            let (xin, xout) = (x_of(c), x_of(c) + BOX_W);
            let y = cy[it];
            if let Some((px, py)) = prev {
                let mx = (px + xin) / 2.0;
                let _ = write!(
                    d,
                    " C{} {} {} {} {} {}",
                    n(mx),
                    n(py),
                    n(mx),
                    n(y),
                    n(xin),
                    n(y)
                );
                if k + 1 < chain.len() {
                    let _ = write!(d, " H{}", n(xout));
                }
            } else {
                let _ = write!(d, "M{} {}", n(xout), n(y));
            }
            prev = Some((xout, y));
        }
        let _ = write!(s, "<path d=\"{d}\" {}/>", stroke(*w, *crit));
    }
    for &(a, b, w, crit) in &arcs {
        let x = x_of(items[a].0) + BOX_W;
        let (y1, y2) = (cy[a].min(cy[b]), cy[a].max(cy[b]));
        let bulge = 10.0 + ((y2 - y1) / 40.0).min(6.0);
        let _ = write!(
            s,
            "<path d=\"M{} {} C{} {} {} {} {} {}\" stroke-dasharray=\"3 2\" {}/>",
            n(x),
            n(y1),
            n(x + bulge),
            n(y1),
            n(x + bulge),
            n(y2),
            n(x),
            n(y2),
            stroke(w, crit)
        );
    }
    s.push_str("</g>");
    // Boxes.
    for (c, col) in cols.iter().enumerate() {
        for &it in col {
            let Item::Node(v) = items[it].1 else { continue };
            let nd = &m.nodes[v];
            let layer = nd.kind.layer();
            let (x, y) = (x_of(c), cy[it] - BOX_H / 2.0);
            let ink = LAYER_INK[layer];
            let full = flat(&nd.label);
            let title = if nd.members.is_empty() {
                format!(
                    "{}: {full} · {}: {}",
                    t.kinds[nd.kind.idx()][0],
                    t.links,
                    nd.degree
                )
            } else {
                let mut names: Vec<String> = nd.members.iter().map(|m| flat(m)).collect();
                names.sort();
                let more = names.len().saturating_sub(12);
                names.truncate(12);
                let mut s = format!("{full}: {}", names.join(", "));
                if more > 0 {
                    let _ = write!(s, " … (+{more})");
                }
                s
            };
            let _ = write!(s, "<g><title>{}</title>", clean(&title));
            if !nd.members.is_empty() {
                // A stacked card for clusters.
                let _ = write!(
                    s,
                    "<rect x=\"{}\" y=\"{}\" width=\"{}\" height=\"{}\" rx=\"5\" fill=\"#fff\" stroke=\"{ink}\" stroke-width=\"1\"/>",
                    n(x + 3.0),
                    n(y - 3.0),
                    n(BOX_W),
                    n(BOX_H)
                );
            }
            let (sw, sc) = if nd.critical {
                ("2.2", CRIT)
            } else {
                ("1", ink)
            };
            let dash = if nd.members.is_empty() {
                ""
            } else {
                " stroke-dasharray=\"4 2\""
            };
            let _ = write!(
                s,
                "<rect x=\"{}\" y=\"{}\" width=\"{}\" height=\"{}\" rx=\"5\" fill=\"{}\" stroke=\"{sc}\" stroke-width=\"{sw}\"{dash}/>",
                n(x),
                n(y),
                n(BOX_W),
                n(BOX_H),
                LAYER_FILL[layer]
            );
            glyph(
                &mut s,
                nd.kind.glyph(),
                x + 11.0,
                y + BOX_H / 2.0,
                13.0,
                ink,
            );
            let lines = wrap(&full, CHARS, 2);
            let base = y + BOX_H / 2.0 - (lines.len() as f64 - 1.0) * 6.0 + 3.5;
            for (i, line) in lines.iter().enumerate() {
                text(
                    &mut s,
                    x + 21.0,
                    base + i as f64 * 12.0,
                    FONT,
                    "#0f172a",
                    "start",
                    !nd.members.is_empty() || nd.critical,
                    &clean(line),
                );
            }
            if nd.critical {
                let _ = write!(
                    s,
                    "<circle cx=\"{}\" cy=\"{}\" r=\"6\" fill=\"{CRIT}\"/>",
                    n(x + BOX_W - 1.0),
                    n(y + 1.0)
                );
                text(
                    &mut s,
                    x + BOX_W - 1.0,
                    y + 4.5,
                    9.0,
                    "#fff",
                    "middle",
                    true,
                    "!",
                );
            }
            s.push_str("</g>");
        }
    }
    s.push_str("</svg>");
    let shown: usize = m.nodes.iter().filter(|v| v.members.is_empty()).count();
    let mut caption = format!(
        "{}: {shown} / {} · {}: {}",
        t.shown_of, m.total_nodes, t.links, m.total_edges
    );
    if shown < m.total_nodes {
        let _ = write!(caption, " · {}", t.collapsed);
    }
    Some(Figure {
        svg: s,
        caption,
        width: width.round() as u32,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(id: &str, kind: NodeKind) -> GraphNode {
        GraphNode {
            id: id.into(),
            kind,
            label: format!("Label {id}"),
            critical: false,
        }
    }

    fn edge(a: &str, b: &str) -> GraphEdge {
        GraphEdge {
            from: a.into(),
            to: b.into(),
        }
    }

    #[test]
    fn collapses_large_layers_into_clusters() {
        let mut g = Graph::default();
        g.nodes.push(node("p1", NodeKind::Person));
        for i in 0..30 {
            g.nodes.push(node(&format!("d{i:02}"), NodeKind::Document));
            g.edges.push(edge("p1", &format!("d{i:02}")));
        }
        let m = model(&g, Lang::Ru).unwrap();
        let docs = &m.layers.iter().find(|l| l.0 == 1).unwrap().1;
        assert_eq!(docs.len(), MAX_PER_LAYER);
        let cluster = &m.nodes[*docs.last().unwrap()];
        assert_eq!(cluster.members.len(), 21);
        assert_eq!(cluster.label, "21 документ");
        // The edges to collapsed documents merge into one weighted edge.
        assert!(m.edges.iter().any(|e| e.2 == 21));
        assert_eq!(m.total_edges, 30);
    }

    #[test]
    fn barycenter_removes_avoidable_crossings() {
        // p1-d2 and p2-d1 cross in the initial order; the sweep must untangle them.
        let mut g = Graph::default();
        for (id, k) in [
            ("p1", NodeKind::Person),
            ("p2", NodeKind::Person),
            ("d1", NodeKind::Document),
            ("d2", NodeKind::Document),
        ] {
            g.nodes.push(node(id, k));
        }
        g.nodes[1].critical = true;
        g.edges.push(edge("p1", "d2"));
        g.edges.push(edge("p2", "d1"));
        let svg = render(&g, Lang::En).unwrap().svg;
        let y = |label: &str| {
            let i = svg.find(&format!(">{label}<")).unwrap();
            let t = &svg[..i];
            let j = t.rfind("y=\"").unwrap();
            t[j + 3..]
                .split('"')
                .next()
                .unwrap()
                .parse::<f64>()
                .unwrap()
        };
        assert_eq!(y("Label p2") < y("Label p1"), y("Label d1") < y("Label d2"));
    }

    #[test]
    fn long_edges_and_same_layer_edges_render() {
        let mut g = Graph::default();
        g.nodes.push(node("p", NodeKind::Person));
        g.nodes.push(node("s", NodeKind::Server));
        g.nodes.push(node("dom", NodeKind::Domain));
        g.nodes.push(node("doc", NodeKind::Document));
        g.nodes.push(node("ws", NodeKind::Workstation));
        g.edges.push(edge("p", "s"));
        g.edges.push(edge("s", "dom"));
        g.edges.push(edge("s", "s"));
        g.edges.push(edge("s", "missing"));
        let f = render(&g, Lang::Uk).unwrap();
        assert!(f.svg.contains("stroke-dasharray=\"3 2\""));
        assert!(f.svg.matches("<path d=\"M").count() >= 2);
        assert!(f.caption.contains("5 / 5"));
    }

    #[test]
    fn empty_graph_renders_nothing() {
        assert!(render(&Graph::default(), Lang::Ru).is_none());
    }
}
