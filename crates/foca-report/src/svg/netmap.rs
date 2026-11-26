//! Internal network map: an indented tree `AD domain → servers by role → workstations →
//! users`, one row per node with a pictogram and elbow connectors. The tree reads well at
//! 360 dp (rows grow downwards, no horizontal scrolling) and on A4.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt::Write as _;

use serde::{Deserialize, Serialize};

use super::{clean, flat, glyph, n, open, text, truncate, Figure, Glyph};
use crate::i18n;
use crate::opts::Lang;

/// Rows drawn at most (the rest are summarized in a final row).
pub const MAX_ROWS: usize = 72;
/// Children shown per parent before a `… N more` row.
pub const MAX_CHILDREN: usize = 8;
/// Deepest level drawn.
pub const MAX_DEPTH: usize = 6;

/// Network node kind (pictogram and sort order).
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum NetKind {
    #[default]
    Domain,
    Server,
    Workstation,
    Printer,
    Share,
    User,
}

/// Server role, shown next to the server name.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum ServerRole {
    /// Domain controller.
    Dc,
    Pki,
    File,
    Mail,
    Print,
    Web,
    Db,
    #[default]
    Other,
}

/// A network node; `parent` links form the tree (unknown or cyclic parents make a root).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct NetNode {
    pub id: String,
    pub parent: Option<String>,
    pub kind: NetKind,
    pub label: String,
    pub role: Option<ServerRole>,
    pub critical: bool,
}

/// Network map input for the report.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct NetMap {
    pub nodes: Vec<NetNode>,
}

/// One row of the tree.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Row {
    pub depth: usize,
    /// `None` for a summary row (`… N more`).
    pub kind: Option<NetKind>,
    pub label: String,
    pub role: Option<ServerRole>,
    pub critical: bool,
    /// Row index of the parent.
    pub parent: Option<usize>,
    /// Hidden labels of a summary row.
    pub hidden: Vec<String>,
}

fn glyph_of(k: NetKind, role: Option<ServerRole>) -> Glyph {
    match (k, role) {
        (NetKind::Domain, _) => Glyph::Domain,
        (NetKind::Server, Some(ServerRole::Pki)) => Glyph::Pki,
        (NetKind::Server, _) => Glyph::Server,
        (NetKind::Workstation, _) => Glyph::Workstation,
        (NetKind::Printer, _) => Glyph::Printer,
        (NetKind::Share, _) => Glyph::Share,
        (NetKind::User, _) => Glyph::Person,
    }
}

/// Flattens the tree into rows with per-parent and global limits.
pub(crate) fn rows(m: &NetMap) -> Vec<Row> {
    let mut index: HashMap<&str, usize> = HashMap::new();
    let mut nodes: Vec<&NetNode> = Vec::new();
    for nd in &m.nodes {
        if !index.contains_key(nd.id.as_str()) {
            index.insert(nd.id.as_str(), nodes.len());
            nodes.push(nd);
        }
    }
    let mut children: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
    let mut roots = Vec::new();
    for (i, nd) in nodes.iter().enumerate() {
        match nd.parent.as_deref().and_then(|p| index.get(p)) {
            Some(&p) if p != i => children.entry(p).or_default().push(i),
            _ => roots.push(i),
        }
    }
    let key = |i: &usize| {
        let nd = nodes[*i];
        (
            nd.kind,
            nd.role.unwrap_or_default(),
            flat(&nd.label).to_lowercase(),
            nd.id.clone(),
        )
    };
    roots.sort_by_key(key);
    for v in children.values_mut() {
        v.sort_by_key(key);
    }
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    // Iterative DFS: (node, depth, parent row); summary rows are queued as `usize::MAX`.
    fn walk(
        i: usize,
        depth: usize,
        parent: Option<usize>,
        nodes: &[&NetNode],
        children: &BTreeMap<usize, Vec<usize>>,
        seen: &mut HashSet<usize>,
        out: &mut Vec<Row>,
    ) {
        if !seen.insert(i) || out.len() >= MAX_ROWS {
            return;
        }
        let nd = nodes[i];
        let row = out.len();
        out.push(Row {
            depth,
            kind: Some(nd.kind),
            label: nd.label.clone(),
            role: if nd.kind == NetKind::Server {
                Some(nd.role.unwrap_or_default())
            } else {
                None
            },
            critical: nd.critical,
            parent,
            hidden: Vec::new(),
        });
        let kids: Vec<usize> = children
            .get(&i)
            .map(|v| v.iter().copied().filter(|c| !seen.contains(c)).collect())
            .unwrap_or_default();
        if kids.is_empty() {
            return;
        }
        let limit = if depth + 1 >= MAX_DEPTH {
            0
        } else if kids.len() > MAX_CHILDREN {
            MAX_CHILDREN - 1
        } else {
            kids.len()
        };
        for &c in &kids[..limit] {
            walk(c, depth + 1, Some(row), nodes, children, seen, out);
        }
        if limit < kids.len() && out.len() < MAX_ROWS {
            let mut hidden = Vec::new();
            let mut stack: Vec<usize> = kids[limit..].to_vec();
            while let Some(h) = stack.pop() {
                if seen.insert(h) {
                    hidden.push(nodes[h].label.clone());
                    if let Some(v) = children.get(&h) {
                        stack.extend(v.iter().rev());
                    }
                }
            }
            out.push(Row {
                depth: depth + 1,
                kind: None,
                label: String::new(),
                role: None,
                critical: false,
                parent: Some(row),
                hidden,
            });
        }
    }
    let mut pending: Vec<usize> = roots;
    // Nodes caught in parent cycles are not reachable from any root: add them as roots.
    let mut rest: Vec<usize> = (0..nodes.len()).collect();
    rest.sort_by_key(key);
    pending.extend(rest);
    for r in pending {
        if out.len() >= MAX_ROWS {
            break;
        }
        walk(r, 0, None, &nodes, &children, &mut seen, &mut out);
    }
    if seen.len() < nodes.len() {
        let mut hidden: Vec<String> = (0..nodes.len())
            .filter(|i| !seen.contains(i))
            .map(|i| nodes[i].label.clone())
            .collect();
        hidden.sort();
        out.push(Row {
            depth: 0,
            kind: None,
            label: String::new(),
            role: None,
            critical: false,
            parent: None,
            hidden,
        });
    }
    out
}

/// Summary row label: `… 5 more`.
pub(crate) fn more_label(more: &str, l: Lang, count: usize) -> String {
    match l {
        Lang::En => format!("… {count} {more}"),
        _ => format!("… {more} {count}"),
    }
}

const W: f64 = 400.0;
const PAD: f64 = 6.0;
const ROW_H: f64 = 22.0;
const INDENT: f64 = 20.0;
const FONT: f64 = 11.0;
/// Approximate glyph advance for the label font (sans-serif, mixed case).
const ADV: f64 = 6.0;
const INK: [&str; 6] = [
    "#1e3a8a", "#5b21b6", "#9a3412", "#9a3412", "#166534", "#3730a3",
];

/// Renders the network map, or `None` without nodes.
pub fn render(m: &NetMap, l: Lang) -> Option<Figure> {
    let t = i18n::viz(l);
    let rows = rows(m);
    if rows.is_empty() {
        return None;
    }
    let height = PAD * 2.0 + rows.len() as f64 * ROW_H;
    let mut s = String::with_capacity(8 * 1024);
    open(&mut s, W, height, t.netmap);
    let icon_x = |depth: usize| PAD + 9.0 + depth as f64 * INDENT;
    let cy = |r: usize| PAD + r as f64 * ROW_H + ROW_H / 2.0;
    // Zebra rows for scanning across on paper.
    for r in (1..rows.len()).step_by(2) {
        let _ = write!(
            s,
            "<rect x=\"0\" y=\"{}\" width=\"{}\" height=\"{}\" fill=\"#f8fafc\"/>",
            n(cy(r) - ROW_H / 2.0),
            n(W),
            n(ROW_H)
        );
    }
    // Elbow connectors from the parent pictogram down and right to the child.
    s.push_str("<g fill=\"none\" stroke=\"#94a3b8\" stroke-width=\"1\">");
    for (r, row) in rows.iter().enumerate() {
        if let Some(p) = row.parent {
            let px = icon_x(rows[p].depth);
            let _ = write!(
                s,
                "<path d=\"M{} {} V{} H{}\"/>",
                n(px),
                n(cy(p) + 8.0),
                n(cy(r)),
                n(icon_x(row.depth) - 9.0)
            );
        }
    }
    s.push_str("</g>");
    for (r, row) in rows.iter().enumerate() {
        let x = icon_x(row.depth);
        let y = cy(r);
        let avail = ((W - PAD - x - 12.0) / ADV).floor().max(6.0) as usize;
        let Some(kind) = row.kind else {
            let mut hidden: Vec<String> = row.hidden.iter().map(|h| flat(h)).collect();
            let label = more_label(t.more, l, hidden.len());
            let extra = hidden.len().saturating_sub(20);
            hidden.truncate(20);
            let mut title = format!("{label}: {}", hidden.join(", "));
            if extra > 0 {
                let _ = write!(title, " … (+{extra})");
            }
            let _ = write!(s, "<g><title>{}</title>", clean(&title));
            text(
                &mut s,
                x - 4.0,
                y + 4.0,
                FONT - 1.0,
                "#475569",
                "start",
                false,
                &clean(&label),
            );
            s.push_str("</g>");
            continue;
        };
        let ink = INK[kind as usize];
        let role = row.role.map(|r| t.roles[r as usize]);
        let full = flat(&row.label);
        let title = match role {
            Some(r) => format!("{}: {full} · {r}", t.net_kinds[kind as usize]),
            None => format!("{}: {full}", t.net_kinds[kind as usize]),
        };
        let _ = write!(s, "<g><title>{}</title>", clean(&title));
        glyph(&mut s, glyph_of(kind, row.role), x, y, 14.0, ink);
        let role_len = role.map(|r| r.chars().count() + 3).unwrap_or(0);
        let label = truncate(&full, avail.saturating_sub(role_len).max(8));
        let mut inner = clean(&label);
        if let Some(r) = role {
            let _ = write!(
                inner,
                "<tspan fill=\"#475569\" font-weight=\"400\" font-size=\"{}\"> · {}</tspan>",
                n(FONT - 1.5),
                clean(r)
            );
        }
        let color = if row.critical { "#b91c1c" } else { "#0f172a" };
        let bold = row.critical || matches!(kind, NetKind::Domain | NetKind::Server);
        text(
            &mut s,
            x + 12.0,
            y + 4.0,
            FONT,
            color,
            "start",
            bold,
            &inner,
        );
        s.push_str("</g>");
    }
    s.push_str("</svg>");
    let mut counts = [0usize; 6];
    for nd in &m.nodes {
        counts[nd.kind as usize] += 1;
    }
    let caption = counts
        .iter()
        .enumerate()
        .filter(|(_, c)| **c > 0)
        .map(|(i, c)| format!("{}: {c}", t.net_kinds[i]))
        .collect::<Vec<_>>()
        .join(" · ");
    Some(Figure {
        svg: s,
        caption,
        width: W as u32,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nn(id: &str, parent: Option<&str>, kind: NetKind) -> NetNode {
        NetNode {
            id: id.into(),
            parent: parent.map(Into::into),
            kind,
            label: id.to_uppercase(),
            role: None,
            critical: false,
        }
    }

    #[test]
    fn tree_order_limits_and_cycles() {
        let mut m = NetMap::default();
        m.nodes.push(nn("ws", Some("dom"), NetKind::Workstation));
        m.nodes.push(nn("srv", Some("dom"), NetKind::Server));
        m.nodes.push(nn("dom", None, NetKind::Domain));
        for i in 0..12 {
            m.nodes
                .push(nn(&format!("u{i:02}"), Some("ws"), NetKind::User));
        }
        // A parent cycle without a root still shows up.
        m.nodes.push(nn("c1", Some("c2"), NetKind::Printer));
        m.nodes.push(nn("c2", Some("c1"), NetKind::Share));
        let r = rows(&m);
        assert_eq!(r[0].label, "DOM");
        assert_eq!(r[1].label, "SRV");
        assert_eq!(r[1].role, Some(ServerRole::Other));
        assert_eq!(r[2].label, "WS");
        let users: Vec<_> = r.iter().filter(|x| x.kind == Some(NetKind::User)).collect();
        assert_eq!(users.len(), MAX_CHILDREN - 1);
        let more = r.iter().find(|x| x.kind.is_none()).unwrap();
        assert_eq!(more.hidden.len(), 12 - (MAX_CHILDREN - 1));
        assert!(r.iter().any(|x| x.label == "C1") && r.iter().any(|x| x.label == "C2"));
    }

    #[test]
    fn row_limit_is_enforced() {
        let mut m = NetMap::default();
        for i in 0..500 {
            m.nodes
                .push(nn(&format!("n{i:03}"), None, NetKind::Workstation));
        }
        let r = rows(&m);
        assert_eq!(r.len(), MAX_ROWS + 1);
        assert_eq!(r.last().unwrap().hidden.len(), 500 - MAX_ROWS);
        assert!(render(&m, Lang::En).unwrap().svg.contains("428 more"));
    }
}
