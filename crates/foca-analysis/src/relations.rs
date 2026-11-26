//! Relation graph: document ↔ person ↔ computer ↔ host ↔ software ↔ e-mail ↔ printer.

use std::collections::BTreeSet;

use foca_core::api::{Email, Person, Software};
use serde::Serialize;

use crate::DocFacts;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct Node {
    /// `doc:12`, `person:a.bondar`, `pc:BUH-PC07`, `host:srv.corp`, `sw:word2013`,
    /// `email:x@y`, `printer:\\SRV\P`, `os:win7`.
    pub id: String,
    pub kind: String,
    pub label: String,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct Edge {
    pub from: String,
    pub to: String,
    /// `author`, `modified`, `mentioned`, `created_with`, `on_pc`, `on_host`, `hosted_on`,
    /// `printed_on`, `os`, `uses_pc`, `has_email`.
    pub kind: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Graph {
    pub nodes: Vec<Node>,
    pub edges: Vec<Edge>,
}

impl Graph {
    /// Returns the neighbours of a node.
    pub fn neighbors(&self, id: &str) -> Vec<&str> {
        let mut v: Vec<&str> = self
            .edges
            .iter()
            .filter_map(|e| {
                if e.from == id {
                    Some(e.to.as_str())
                } else if e.to == id {
                    Some(e.from.as_str())
                } else {
                    None
                }
            })
            .collect();
        v.sort_unstable();
        v.dedup();
        v
    }
}

pub fn build(
    docs: &[DocFacts],
    people: &[Person],
    software: &[Software],
    emails: &[Email],
) -> Graph {
    let mut nodes: BTreeSet<Node> = BTreeSet::new();
    let mut edges: BTreeSet<Edge> = BTreeSet::new();
    let mut node = |id: String, kind: &str, label: &str| {
        nodes.insert(Node {
            id: id.clone(),
            kind: kind.into(),
            label: label.into(),
        });
        id
    };
    let mut edge = |from: &str, to: &str, kind: &str| {
        edges.insert(Edge {
            from: from.into(),
            to: to.into(),
            kind: kind.into(),
        });
    };
    let pname = |l: &str| {
        people
            .iter()
            .find(|p| p.login == l)
            .map(|p| p.name.clone())
            .unwrap_or_else(|| l.to_string())
    };
    for d in docs.iter().filter(|d| d.analyzed) {
        let dn = node(format!("doc:{}", d.id), "doc", &d.name);
        for p in &d.people {
            let pn = node(format!("person:{p}"), "person", &pname(p));
            let kind = if d.author.as_deref() == Some(p.as_str()) {
                "author"
            } else if d.last_modified_by.as_deref() == Some(p.as_str()) {
                "modified"
            } else {
                "mentioned"
            };
            edge(&pn, &dn, kind);
        }
        for s in &d.software {
            let label = software
                .iter()
                .find(|x| &x.id == s)
                .map(|x| x.name.clone())
                .unwrap_or_else(|| s.clone());
            let sn = node(format!("sw:{s}"), "software", &label);
            edge(&dn, &sn, "created_with");
        }
        for pc in &d.pcs {
            let n = node(format!("pc:{pc}"), "pc", pc);
            edge(&dn, &n, "on_pc");
        }
        for h in d.servers.iter().filter(|h| !d.pcs.contains(h)) {
            let n = node(format!("host:{h}"), "host", h);
            edge(&dn, &n, "on_host");
        }
        if !d.host.is_empty() {
            let n = node(format!("host:{}", d.host), "host", &d.host);
            edge(&dn, &n, "hosted_on");
        }
        for pr in &d.printers {
            let n = node(format!("printer:{pr}"), "printer", pr);
            edge(&dn, &n, "printed_on");
        }
        if let Some(os) = &d.os {
            let n = node(format!("os:{os}"), "os", os);
            edge(&dn, &n, "os");
        }
    }
    for p in people {
        let pn = format!("person:{}", p.login);
        if let Some(pc) = &p.pc {
            node(pn.clone(), "person", &p.name);
            let n = node(format!("pc:{pc}"), "pc", pc);
            edge(&pn, &n, "uses_pc");
        }
    }
    for e in emails.iter().filter(|e| e.found) {
        if let Some(l) = &e.login {
            let pn = node(format!("person:{l}"), "person", &pname(l));
            let en = node(format!("email:{}", e.addr), "email", &e.addr);
            edge(&pn, &en, "has_email");
        }
    }
    Graph {
        nodes: nodes.into_iter().collect(),
        edges: edges.into_iter().collect(),
    }
}
