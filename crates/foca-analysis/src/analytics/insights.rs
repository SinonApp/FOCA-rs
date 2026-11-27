//! Analytics over a finished [`Analysis`]: document correlation, org chart, metadata
//! anomalies, CISA KEV matches, the internal network map and the extended relation graph used
//! by the "link chain" ([`crate::chain`]) and the clustered graph view ([`crate::graphview`]).
//!
//! ```text
//! analyze(...) -> Analysis ──┐
//! DocInput[] ────────────────┼─> insights::build(inputs, &analysis, &pki, now) -> Insights
//! PkiInput[] (1.2 CDP/AIA) ──┘     ├─ correlate   RSID / XMP lineage
//!                                  ├─ orgchart    departments, organizations, roles
//!                                  ├─ anomalies   date/tool contradictions
//!                                  ├─ kev         offline CISA KEV matches
//!                                  ├─ netmap      forest → domain → servers → PCs → users
//!                                  └─ graph       relations + lineage + netmap edges
//! ```
//!
//! Everything is a pure function: no network, no storage, deterministic output.

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;
use time::OffsetDateTime;

use crate::anomalies::{self, Anomaly};
use crate::clusters::{self, TraceCluster};
use crate::correlate::{self, Correlation};
use crate::kev::{self, KevMatch};
use crate::netmap::{self, NetMap, PkiInput};
use crate::orgchart::{self, OrgChart};
use crate::relations::{Edge, Graph, Node};
use crate::{Analysis, DocInput};

/// All analytics of a project.
#[derive(Debug, Clone, Default, Serialize)]
pub struct Insights {
    pub correlation: Correlation,
    /// Same-author and same-machine document clusters.
    pub clusters: Vec<TraceCluster>,
    pub org: OrgChart,
    pub anomalies: Vec<Anomaly>,
    pub kev: Vec<KevMatch>,
    /// Offline NVD CVE matches of document software, OS and (filled by the engine) web
    /// technologies.
    pub cve: Vec<crate::cve::CveMatch>,
    pub netmap: NetMap,
    /// Relation graph extended with lineage and network map nodes/edges.
    pub graph: Graph,
}

/// Runs all analytics using the builtin CISA KEV snapshot.
pub fn build(inputs: &[DocInput], a: &Analysis, pki: &[PkiInput], now: OffsetDateTime) -> Insights {
    build_with_kev(inputs, a, pki, now, kev::KevCatalog::builtin())
}

/// Runs all analytics with a caller-provided [`kev::KevCatalog`] (e.g. extended by a signed bundle).
pub fn build_with_kev(
    inputs: &[DocInput],
    a: &Analysis,
    pki: &[PkiInput],
    now: OffsetDateTime,
    kev_cat: &kev::KevCatalog,
) -> Insights {
    let correlation = correlate::correlate(inputs);
    let netmap = netmap::build(inputs, a, pki);
    let graph = extended_graph(&a.graph, &correlation, &netmap);
    Insights {
        org: orgchart::build(inputs, a),
        clusters: clusters::clusters(inputs),
        anomalies: anomalies::detect(inputs, now),
        kev: kev::lookup(kev_cat, &kev::subjects_from(a)),
        cve: crate::cve::doc_matches(a, &crate::cve::db()),
        correlation,
        netmap,
        graph,
    }
}

/// Merges the relation graph with lineage edges and the network map. Node ids are shared
/// (`doc:`, `person:`, `pc:`, `host:`, `printer:`), so the same entity appears once; the
/// network map adds `share:`, `domain:` and `forest:` nodes.
pub fn extended_graph(base: &Graph, corr: &Correlation, net: &NetMap) -> Graph {
    let mut nodes: BTreeMap<String, Node> = base
        .nodes
        .iter()
        .map(|n| (n.id.clone(), n.clone()))
        .collect();
    let lower: BTreeMap<String, String> = nodes
        .keys()
        .map(|k| (k.to_lowercase(), k.clone()))
        .collect();
    let canon = |id: &str| {
        lower
            .get(&id.to_lowercase())
            .cloned()
            .unwrap_or_else(|| id.to_string())
    };
    let mut edges: BTreeSet<Edge> = base.edges.iter().cloned().collect();
    let ng = net.graph();
    for n in ng.nodes {
        let id = canon(&n.id);
        nodes.entry(id.clone()).or_insert(Node { id, ..n });
    }
    for e in ng.edges.into_iter().chain(corr.edges()) {
        let (from, to) = (canon(&e.from), canon(&e.to));
        if nodes.contains_key(&from) && nodes.contains_key(&to) && from != to {
            edges.insert(Edge {
                from,
                to,
                kind: e.kind,
            });
        }
    }
    Graph {
        nodes: nodes.into_values().collect(),
        edges: edges.into_iter().collect(),
    }
}
