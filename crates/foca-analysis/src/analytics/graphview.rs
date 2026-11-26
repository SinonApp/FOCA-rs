//! Graph view data for a 360 dp screen: layer filters and collapsing of nodes
//! of one kind with identical neighbours ("14 documents" instead of a hairball).
//!
//! Pure transformation of a [`Graph`]; the UI renders the result as is and expands a group by
//! its `members`.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::relations::Graph;
use crate::util::stable_id;

/// Filter layer of the graph screen.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Layer {
    People,
    Docs,
    Pcs,
    Servers,
    PkiDomains,
    Software,
}

impl Layer {
    pub const ALL: [Layer; 6] = [
        Layer::People,
        Layer::Docs,
        Layer::Pcs,
        Layer::Servers,
        Layer::PkiDomains,
        Layer::Software,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Layer::People => "people",
            Layer::Docs => "docs",
            Layer::Pcs => "pcs",
            Layer::Servers => "servers",
            Layer::PkiDomains => "pki_domains",
            Layer::Software => "software",
        }
    }
}

/// Layer of a node kind.
pub fn layer_of(kind: &str) -> Layer {
    match kind {
        "person" | "email" => Layer::People,
        "doc" => Layer::Docs,
        "pc" => Layer::Pcs,
        "host" | "printer" | "share" => Layer::Servers,
        "domain" | "forest" | "pki" | "ca" => Layer::PkiDomains,
        _ => Layer::Software,
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ViewNode {
    /// Original id, or `group:<kind>:<hash>` for a collapsed group.
    pub id: String,
    pub kind: String,
    /// Label of a single node; for a group the first member label (the UI shows
    /// `count` + localized kind, e.g. "14 документов").
    pub label: String,
    pub layer: Layer,
    /// 1 for a single node.
    pub count: u32,
    /// Ids of the collapsed nodes (empty for a single node).
    pub members: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct ViewEdge {
    pub from: String,
    pub to: String,
    pub kind: String,
    /// Number of original edges merged into this one.
    pub weight: u32,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct GraphView {
    pub nodes: Vec<ViewNode>,
    pub edges: Vec<ViewEdge>,
    /// Nodes per layer in the unfiltered graph (for the filter chips).
    pub layer_counts: BTreeMap<String, u32>,
    /// Nodes hidden by the layer filter.
    pub hidden: u32,
}

/// Default minimum group size for collapsing.
pub const MIN_GROUP: usize = 3;

/// Filters the graph by `layers` (empty = all) and collapses nodes of one kind with the same
/// neighbour set into groups of at least `min_group` (0 or 1 disables collapsing).
pub fn view(g: &Graph, layers: &[Layer], min_group: usize) -> GraphView {
    let mut layer_counts: BTreeMap<String, u32> = BTreeMap::new();
    for n in &g.nodes {
        *layer_counts
            .entry(layer_of(&n.kind).as_str().to_string())
            .or_default() += 1;
    }
    let keep: BTreeSet<&str> = g
        .nodes
        .iter()
        .filter(|n| layers.is_empty() || layers.contains(&layer_of(&n.kind)))
        .map(|n| n.id.as_str())
        .collect();
    let hidden = (g.nodes.len() - keep.len()) as u32;
    let edges: Vec<_> = g
        .edges
        .iter()
        .filter(|e| keep.contains(e.from.as_str()) && keep.contains(e.to.as_str()))
        .collect();
    let mut nb: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
    for e in &edges {
        nb.entry(e.from.as_str()).or_default().insert(e.to.as_str());
        nb.entry(e.to.as_str()).or_default().insert(e.from.as_str());
    }
    // Group by (kind, neighbour set); isolated nodes are never grouped.
    let mut groups: BTreeMap<(&str, Vec<&str>), Vec<&str>> = BTreeMap::new();
    for n in g.nodes.iter().filter(|n| keep.contains(n.id.as_str())) {
        if let Some(s) = nb.get(n.id.as_str()) {
            groups
                .entry((n.kind.as_str(), s.iter().copied().collect()))
                .or_default()
                .push(n.id.as_str());
        }
    }
    let mut rep: BTreeMap<&str, String> = BTreeMap::new();
    let mut out_nodes: Vec<ViewNode> = Vec::new();
    let label: BTreeMap<&str, &str> = g
        .nodes
        .iter()
        .map(|n| (n.id.as_str(), n.label.as_str()))
        .collect();
    for ((kind, neigh), members) in &groups {
        if min_group > 1 && members.len() >= min_group {
            let key: Vec<&str> = std::iter::once(*kind)
                .chain(neigh.iter().copied())
                .collect();
            let gid = format!("group:{kind}:{:x}", stable_id(&key));
            for m in members {
                rep.insert(m, gid.clone());
            }
            out_nodes.push(ViewNode {
                id: gid,
                kind: kind.to_string(),
                label: label
                    .get(members[0])
                    .copied()
                    .unwrap_or_default()
                    .to_string(),
                layer: layer_of(kind),
                count: members.len() as u32,
                members: members.iter().map(|s| s.to_string()).collect(),
            });
        }
    }
    for n in g.nodes.iter().filter(|n| keep.contains(n.id.as_str())) {
        if !rep.contains_key(n.id.as_str()) {
            out_nodes.push(ViewNode {
                id: n.id.clone(),
                kind: n.kind.clone(),
                label: n.label.clone(),
                layer: layer_of(&n.kind),
                count: 1,
                members: vec![],
            });
        }
    }
    out_nodes.sort_by(|a, b| a.layer.cmp(&b.layer).then(a.id.cmp(&b.id)));
    let mut merged: BTreeMap<(String, String, String), u32> = BTreeMap::new();
    for e in edges {
        let f = rep
            .get(e.from.as_str())
            .cloned()
            .unwrap_or_else(|| e.from.clone());
        let t = rep
            .get(e.to.as_str())
            .cloned()
            .unwrap_or_else(|| e.to.clone());
        if f != t {
            *merged.entry((f, t, e.kind.clone())).or_default() += 1;
        }
    }
    GraphView {
        nodes: out_nodes,
        edges: merged
            .into_iter()
            .map(|((from, to, kind), weight)| ViewEdge {
                from,
                to,
                kind,
                weight,
            })
            .collect(),
        layer_counts,
        hidden,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::relations::{Edge, Node};

    #[test]
    fn collapses_identical_neighbours_and_filters() {
        let mut g = Graph::default();
        let node = |id: &str, kind: &str| Node {
            id: id.into(),
            kind: kind.into(),
            label: id.into(),
        };
        g.nodes.push(node("person:a", "person"));
        g.nodes.push(node("pc:A", "pc"));
        g.nodes.push(node("sw:word", "software"));
        for i in 1..=14 {
            g.nodes.push(node(&format!("doc:{i}"), "doc"));
            g.edges.push(Edge {
                from: "person:a".into(),
                to: format!("doc:{i}"),
                kind: "author".into(),
            });
        }
        g.edges.push(Edge {
            from: "person:a".into(),
            to: "pc:A".into(),
            kind: "uses_pc".into(),
        });
        g.edges.push(Edge {
            from: "doc:1".into(),
            to: "sw:word".into(),
            kind: "created_with".into(),
        });
        let v = view(&g, &[], MIN_GROUP);
        let grp = v.nodes.iter().find(|n| n.count > 1).unwrap();
        // doc:1 also links to software, so 13 documents share the same neighbours.
        assert_eq!((grp.kind.as_str(), grp.count), ("doc", 13));
        let e = v.edges.iter().find(|e| e.to == grp.id).unwrap();
        assert_eq!((e.kind.as_str(), e.weight), ("author", 13));
        assert_eq!(v.layer_counts["docs"], 14);
        // Without the software layer doc:1 joins the group.
        let v = view(&g, &[Layer::People, Layer::Docs, Layer::Pcs], MIN_GROUP);
        assert_eq!(v.hidden, 1);
        assert_eq!(v.nodes.iter().find(|n| n.count > 1).unwrap().count, 14);
        // Collapsing off.
        assert_eq!(view(&g, &[], 0).nodes.len(), g.nodes.len());
    }
}
