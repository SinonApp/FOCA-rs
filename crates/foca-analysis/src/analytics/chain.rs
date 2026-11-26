//! "Link chain": the shortest readable path from a finding or a document to the
//! organization's infrastructure: `File → Author → PC → Printer/Share → Server → AD domain`.
//!
//! A cheapest-path search over the (extended) relation graph, edges undirected:
//! * every hop costs 2, entering another document costs 3 more (a chain through an unrelated
//!   document is legitimate, "the author also wrote X on server Y", but a direct one wins);
//! * hub kinds that connect unrelated things (`software`, `os`, collapsed groups) are never
//!   traversed;
//! * the target is the most "infrastructural" node reachable within `max_depth` hops
//!   (forest > domain > server > share/printer > PC), the cheapest one on a tie.

use std::cmp::Reverse;
use std::collections::{BTreeMap, BinaryHeap};

use foca_core::api::Finding;
use serde::Serialize;

use crate::relations::{Graph, Node};

/// Search options.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainOpts {
    /// Maximum number of hops.
    pub max_depth: usize,
    /// Node kinds that are never traversed.
    pub avoid: Vec<String>,
    /// Target kinds with their rank (higher is more infrastructural).
    pub targets: Vec<(String, u8)>,
}

impl Default for ChainOpts {
    fn default() -> Self {
        ChainOpts {
            max_depth: 6,
            avoid: ["software", "os", "group"].map(String::from).to_vec(),
            targets: [
                ("forest", 6),
                ("domain", 5),
                ("host", 4),
                ("share", 3),
                ("printer", 3),
                ("pc", 2),
            ]
            .map(|(k, r)| (k.to_string(), r))
            .to_vec(),
        }
    }
}

/// One step of a chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Step {
    pub node: Node,
    /// Edge kind from the previous step (`None` for the start).
    pub via: Option<String>,
    /// The edge is stored in the opposite direction (`person → doc` read as `doc ← person`).
    pub reverse: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Chain {
    pub steps: Vec<Step>,
    /// Kind of the last node.
    pub target_kind: String,
    pub hops: usize,
}

const HOP: u32 = 2;
const DOC_PENALTY: u32 = 3;

/// Search state of a node: cost, hops, previous node and edge index.
type Visit = (u32, usize, Option<(String, usize)>);

/// Cheapest paths from `start` (Dijkstra, bounded by `max_depth`). Returns, per reached node,
/// `(cost, hops, previous node, edge index)`.
fn search(g: &Graph, start: &str, opts: &ChainOpts) -> BTreeMap<String, Visit> {
    let kind: BTreeMap<&str, &str> = g
        .nodes
        .iter()
        .map(|n| (n.id.as_str(), n.kind.as_str()))
        .collect();
    let mut adj: BTreeMap<&str, Vec<(usize, &str)>> = BTreeMap::new();
    for (i, e) in g.edges.iter().enumerate() {
        adj.entry(e.from.as_str())
            .or_default()
            .push((i, e.to.as_str()));
        adj.entry(e.to.as_str())
            .or_default()
            .push((i, e.from.as_str()));
    }
    let mut best: BTreeMap<String, Visit> = BTreeMap::new();
    if !kind.contains_key(start) {
        return best;
    }
    best.insert(start.to_string(), (0, 0, None));
    let mut heap = BinaryHeap::new();
    heap.push(Reverse((0u32, 0usize, start.to_string())));
    while let Some(Reverse((cost, hops, id))) = heap.pop() {
        if best.get(&id).is_some_and(|b| b.0 < cost) || hops >= opts.max_depth {
            continue;
        }
        // Do not expand through a hub (the start itself may be anything).
        if id != start
            && kind
                .get(id.as_str())
                .is_some_and(|k| opts.avoid.iter().any(|a| a == k))
        {
            continue;
        }
        let Some(nb) = adj.get(id.as_str()) else {
            continue;
        };
        for &(ei, to) in nb {
            let Some(k) = kind.get(to) else { continue };
            if opts.avoid.iter().any(|a| a == k) {
                continue;
            }
            let c = cost + HOP + if *k == "doc" { DOC_PENALTY } else { 0 };
            let better = match best.get(to) {
                None => true,
                Some(b) => (c, hops + 1) < (b.0, b.1),
            };
            if better {
                best.insert(to.to_string(), (c, hops + 1, Some((id.clone(), ei))));
                heap.push(Reverse((c, hops + 1, to.to_string())));
            }
        }
    }
    best
}

fn path_to(g: &Graph, best: &BTreeMap<String, Visit>, target: &str) -> Option<Chain> {
    let nodes: BTreeMap<&str, &Node> = g.nodes.iter().map(|n| (n.id.as_str(), n)).collect();
    let mut rev: Vec<Step> = Vec::new();
    let mut cur = target.to_string();
    loop {
        let (_, _, prev) = best.get(&cur)?;
        let node = (*nodes.get(cur.as_str())?).clone();
        match prev {
            None => {
                rev.push(Step {
                    node,
                    via: None,
                    reverse: false,
                });
                break;
            }
            Some((p, ei)) => {
                let e = &g.edges[*ei];
                rev.push(Step {
                    node,
                    via: Some(e.kind.clone()),
                    reverse: e.from == cur,
                });
                cur = p.clone();
            }
        }
    }
    rev.reverse();
    let target_kind = rev.last()?.node.kind.clone();
    let hops = rev.len() - 1;
    Some(Chain {
        steps: rev,
        target_kind,
        hops,
    })
}

/// The best chain from `start` to the infrastructure, if any infrastructure is reachable.
pub fn find(g: &Graph, start: &str, opts: &ChainOpts) -> Option<Chain> {
    all(g, start, opts, 1).into_iter().next()
}

/// Up to `limit` chains to distinct infrastructure targets, best first (rank, then cost, then
/// id). Useful for a "more paths" list under the main card.
pub fn all(g: &Graph, start: &str, opts: &ChainOpts, limit: usize) -> Vec<Chain> {
    let best = search(g, start, opts);
    let rank: BTreeMap<&str, u8> = opts.targets.iter().map(|(k, r)| (k.as_str(), *r)).collect();
    let mut cands: Vec<(Reverse<u8>, u32, &str)> = g
        .nodes
        .iter()
        .filter(|n| n.id != start)
        .filter_map(|n| {
            let r = *rank.get(n.kind.as_str())?;
            let (c, _, _) = best.get(&n.id)?;
            Some((Reverse(r), *c, n.id.as_str()))
        })
        .collect();
    cands.sort();
    cands
        .into_iter()
        .take(limit)
        .filter_map(|(_, _, id)| path_to(g, &best, id))
        .collect()
}

/// Start node of a finding: its document, else its first computer, person or host.
pub fn start_of(f: &Finding) -> Option<String> {
    if let Some(d) = f.doc.or_else(|| f.rel.docs.first().copied()) {
        return Some(format!("doc:{d}"));
    }
    if let Some(p) = f.rel.pcs.first() {
        return Some(format!("pc:{p}"));
    }
    if let Some(p) = f.rel.people.first() {
        return Some(format!("person:{p}"));
    }
    (!f.host.is_empty()).then(|| format!("host:{}", f.host))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::relations::Edge;

    fn g(nodes: &[(&str, &str)], edges: &[(&str, &str, &str)]) -> Graph {
        Graph {
            nodes: nodes
                .iter()
                .map(|(id, k)| Node {
                    id: id.to_string(),
                    kind: k.to_string(),
                    label: id.to_string(),
                })
                .collect(),
            edges: edges
                .iter()
                .map(|(a, b, k)| Edge {
                    from: a.to_string(),
                    to: b.to_string(),
                    kind: k.to_string(),
                })
                .collect(),
        }
    }

    #[test]
    fn file_to_domain() {
        let graph = g(
            &[
                ("doc:1", "doc"),
                ("doc:2", "doc"),
                ("person:i.petrenko", "person"),
                ("pc:BUH-PC07", "pc"),
                ("share:\\\\SRV-FS01\\Buh", "share"),
                ("host:SRV-FS01", "host"),
                ("domain:corp.example.test", "domain"),
                ("sw:word2016", "software"),
                ("host:SRV-X", "host"),
            ],
            &[
                ("person:i.petrenko", "doc:1", "author"),
                ("person:i.petrenko", "pc:BUH-PC07", "uses_pc"),
                ("pc:BUH-PC07", "host:SRV-FS01", "uses_share"),
                ("host:SRV-FS01", "share:\\\\SRV-FS01\\Buh", "has_share"),
                ("host:SRV-FS01", "domain:corp.example.test", "member_of"),
                // A software hub must not shortcut to another server.
                ("doc:1", "sw:word2016", "created_with"),
                ("doc:2", "sw:word2016", "created_with"),
                ("doc:2", "host:SRV-X", "on_host"),
            ],
        );
        let c = find(&graph, "doc:1", &ChainOpts::default()).unwrap();
        let ids: Vec<&str> = c.steps.iter().map(|s| s.node.id.as_str()).collect();
        assert_eq!(
            ids,
            vec![
                "doc:1",
                "person:i.petrenko",
                "pc:BUH-PC07",
                "host:SRV-FS01",
                "domain:corp.example.test"
            ]
        );
        assert_eq!(c.target_kind, "domain");
        assert!(c.steps[1].reverse);
        assert_eq!(c.steps[1].via.as_deref(), Some("author"));
        // Depth limit.
        let short = ChainOpts {
            max_depth: 2,
            ..Default::default()
        };
        let c = find(&graph, "doc:1", &short).unwrap();
        assert_eq!(c.target_kind, "pc");
        // More paths, distinct targets.
        let v = all(&graph, "doc:1", &ChainOpts::default(), 3);
        assert_eq!(v.len(), 3);
        assert!(!v
            .iter()
            .any(|c| c.steps.iter().any(|s| s.node.id == "host:SRV-X")));
        assert!(find(&graph, "doc:404", &ChainOpts::default()).is_none());
    }
}
