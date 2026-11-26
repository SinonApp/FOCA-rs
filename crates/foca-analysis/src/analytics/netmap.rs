//! Internal network map: `AD forest → domain → servers → workstations → users`,
//! assembled from what the documents and the certificate audit leak. Every node lists
//! the sources it was seen in.
//!
//! Sources:
//! * UNC paths of documents and `.lnk` files → file servers and their shares;
//! * printer names (`\\PRN01\HP-Buh-2F`) → print servers and printers;
//! * `Received:` hops of e-mails → mail servers (internal names and private IPs);
//! * `.rdp`/`.ica` addresses and gateways → terminal servers, `DOMAIN\user` → NetBIOS domain;
//! * certificate CDP/AIA URLs ([`PkiInput`]) → PKI servers and the AD domain of LDAP DNs;
//! * the computer list of the analysis (`ws`/`server`), `.lnk` machine ids and internal hosts;
//! * users from the computer list and the people of documents tied to a computer.
//!
//! Domains come from the suffix of internal FQDNs, LDAP `DC=` components and NetBIOS prefixes.
//! Two or more domains under one parent form a forest. Single-label names go to the only known
//! domain (lower confidence) or to the synthetic `domain:unknown` root.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::relations::{Edge, Graph, Node};
use crate::util::{is_private_ip, parse_ip, printer_host, strip_port, unc_parts, url_host};
use crate::{Analysis, DocInput};

/// A CDP/AIA hint of the TLS audit (mirrors `foca_net::tls::x509::PkiHint`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct PkiInput {
    pub url: String,
    /// `crl` | `ocsp` | `ca_issuers`.
    pub source: String,
    pub host: Option<String>,
    pub ldap_dn: Option<String>,
    pub ad_domain: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NetKind {
    Forest,
    Domain,
    Server,
    Workstation,
    User,
}

impl NetKind {
    /// Node kind in the relation graph.
    pub fn graph_kind(self) -> &'static str {
        match self {
            NetKind::Forest => "forest",
            NetKind::Domain => "domain",
            NetKind::Server => "host",
            NetKind::Workstation => "pc",
            NetKind::User => "person",
        }
    }
}

/// Where a node was seen.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct NetSource {
    /// `unc_path` | `lnk` | `printer` | `eml_received` | `rdp` | `rdp_user` | `pki` | `pki_ldap`
    /// | `pc_list` | `host_list` | `doc_pc` | `fqdn` | `child_domains`.
    pub kind: String,
    pub value: String,
    pub doc: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct NetNode {
    /// `forest:<fqdn>`, `domain:<fqdn|NETBIOS>`, `host:<name>`, `pc:<name>`, `person:<login>`.
    pub id: String,
    pub kind: NetKind,
    pub label: String,
    /// Full DNS name when a NetBIOS name and an FQDN of the same computer were merged.
    pub fqdn: Option<String>,
    /// Server roles: `dc`, `pki`, `file`, `mail`, `print`, `terminal`, `db`, `web`, `remote`.
    pub roles: Vec<String>,
    /// Shares (`\\SRV\Buh`) of a file server, printers of a print server.
    pub shares: Vec<String>,
    pub printers: Vec<String>,
    pub parent: Option<String>,
    /// 0-100.
    pub confidence: u8,
    pub sources: Vec<NetSource>,
    pub docs: Vec<u64>,
}

/// A usage link (workstation → server and similar).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct NetLink {
    pub from: String,
    pub to: String,
    /// `uses_share` | `prints_to` | `rdp_to` | `mail_via` | `uses_pc` between computers and
    /// users; `on_share` | `on_host` | `mail_via` | `rdp_to` from a document (`doc:<id>`).
    pub kind: String,
    pub docs: Vec<u64>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct NetMap {
    pub nodes: Vec<NetNode>,
    pub links: Vec<NetLink>,
}

impl NetMap {
    pub fn node(&self, id: &str) -> Option<&NetNode> {
        self.nodes.iter().find(|n| n.id == id)
    }

    pub fn of_kind(&self, k: NetKind) -> impl Iterator<Item = &NetNode> {
        self.nodes.iter().filter(move |n| n.kind == k)
    }

    /// Children of a node in the tree.
    pub fn children(&self, id: &str) -> Vec<&NetNode> {
        self.nodes
            .iter()
            .filter(|n| n.parent.as_deref() == Some(id))
            .collect()
    }

    /// The map as relation graph nodes and edges: `member_of` (child → parent), the usage
    /// links, and `share:`/`printer:` nodes (`has_share`, `has_printer`).
    pub fn graph(&self) -> Graph {
        let mut nodes: BTreeMap<String, Node> = BTreeMap::new();
        let mut edges: BTreeSet<Edge> = BTreeSet::new();
        for n in &self.nodes {
            nodes.insert(
                n.id.clone(),
                Node {
                    id: n.id.clone(),
                    kind: n.kind.graph_kind().into(),
                    label: n.label.clone(),
                },
            );
            if let Some(p) = &n.parent {
                edges.insert(Edge {
                    from: n.id.clone(),
                    to: p.clone(),
                    kind: "member_of".into(),
                });
            }
            for (list, kind, prefix, ek) in [
                (&n.shares, "share", "share:", "has_share"),
                (&n.printers, "printer", "printer:", "has_printer"),
            ] {
                for s in list {
                    let id = format!("{prefix}{s}");
                    nodes.entry(id.clone()).or_insert(Node {
                        id: id.clone(),
                        kind: kind.into(),
                        label: s.clone(),
                    });
                    edges.insert(Edge {
                        from: n.id.clone(),
                        to: id,
                        kind: ek.into(),
                    });
                }
            }
        }
        for l in &self.links {
            edges.insert(Edge {
                from: l.from.clone(),
                to: l.to.clone(),
                kind: l.kind.clone(),
            });
        }
        Graph {
            nodes: nodes.into_values().collect(),
            edges: edges.into_iter().collect(),
        }
    }
}

/// Server role hints from a host name label.
#[rustfmt::skip]
const ROLE_HINTS: &[(&str, &str)] = &[
    ("dc", "dc"), ("ad", "dc"), ("ldap", "dc"), ("pdc", "dc"), ("bdc", "dc"), ("adds", "dc"),
    ("ca", "pki"), ("pki", "pki"), ("crl", "pki"), ("ocsp", "pki"), ("adcs", "pki"),
    ("fs", "file"), ("file", "file"), ("files", "file"), ("nas", "file"), ("share", "file"), ("dfs", "file"), ("storage", "file"),
    ("mail", "mail"), ("exch", "mail"), ("exchange", "mail"), ("mx", "mail"), ("smtp", "mail"), ("owa", "mail"), ("cas", "mail"),
    ("print", "print"), ("prn", "print"), ("ps", "print"), ("printsrv", "print"),
    ("ts", "terminal"), ("rds", "terminal"), ("term", "terminal"), ("citrix", "terminal"), ("ctx", "terminal"), ("rdgw", "terminal"), ("rdweb", "terminal"),
    ("sql", "db"), ("db", "db"), ("mssql", "db"), ("ora", "db"), ("pg", "db"),
    ("web", "web"), ("www", "web"), ("intranet", "web"), ("portal", "web"), ("sp", "web"), ("sharepoint", "web"),
    ("vpn", "remote"), ("gw", "remote"),
];

fn name_roles(name: &str) -> Vec<&'static str> {
    let first = name.split('.').next().unwrap_or(name).to_ascii_lowercase();
    let mut out: Vec<&'static str> = first
        .split(['-', '_'])
        .map(|t| t.trim_end_matches(|c: char| c.is_ascii_digit()))
        .filter_map(|t| {
            ROLE_HINTS
                .iter()
                .find(|(k, _)| *k == t || (t.len() > 3 && t.starts_with(k) && k.len() > 2))
                .map(|(_, r)| *r)
        })
        .collect();
    // `srv-buh-fs01` / `buhfs01`: a known suffix.
    for (k, r) in ROLE_HINTS.iter().filter(|(k, _)| k.len() >= 2) {
        let t = first.trim_end_matches(|c: char| c.is_ascii_digit());
        if t.len() > k.len() + 2
            && t.ends_with(k)
            && !out.contains(r)
            && ["fs", "dc", "ts", "sql", "mail", "prn", "ca"].contains(k)
        {
            out.push(r);
        }
    }
    out.sort_unstable();
    out.dedup();
    out
}

fn is_ip(s: &str) -> bool {
    parse_ip(s).is_some()
}

/// Workstation-like host names (`ws-042`, `buh-pc-07`, `nb-ivan`, `laptop12`).
fn looks_like_workstation(name: &str) -> bool {
    if !name_roles(name).is_empty() || is_ip(name) {
        return false;
    }
    let first = name.split('.').next().unwrap_or(name).to_ascii_lowercase();
    first.split(['-', '_']).any(|t| {
        let t = t.trim_end_matches(|c: char| c.is_ascii_digit());
        [
            "ws", "pc", "nb", "wks", "laptop", "desktop", "notebook", "arm", "client",
        ]
        .contains(&t)
    })
}

fn is_public_ip(s: &str) -> bool {
    parse_ip(s).is_some_and(|ip| !is_private_ip(ip))
}

fn is_internal_name(name: &str) -> bool {
    match parse_ip(name) {
        Some(ip) => is_private_ip(ip),
        None => !name.contains('.') || crate::util::is_internal_fqdn(name),
    }
}

/// Domain of an FQDN: everything after the first label, if that leaves two labels or more.
fn domain_of(fqdn: &str) -> Option<String> {
    if is_ip(fqdn) {
        return None;
    }
    let (_, rest) = fqdn.split_once('.')?;
    (rest.contains('.') || crate::util::is_internal_fqdn(&format!(".{rest}")))
        .then(|| rest.to_ascii_lowercase())
}

#[derive(Default)]
struct Acc {
    label: String,
    kind: Option<NetKind>,
    roles: BTreeSet<String>,
    shares: BTreeSet<String>,
    printers: BTreeSet<String>,
    sources: BTreeSet<NetSource>,
    docs: BTreeSet<u64>,
    parent: Option<String>,
    fixed_conf: Option<u8>,
    fqdn: Option<String>,
}

struct Builder {
    nodes: BTreeMap<String, Acc>,
    /// lowercase name → id, to merge spellings.
    ids: BTreeMap<String, String>,
    links: BTreeMap<(String, String, String), BTreeSet<u64>>,
}

impl Builder {
    fn id_for(&mut self, prefix: &str, name: &str) -> String {
        let k = format!("{prefix}{}", name.to_lowercase());
        self.ids
            .entry(k)
            .or_insert_with(|| format!("{prefix}{name}"))
            .clone()
    }

    fn add(&mut self, kind: NetKind, prefix: &str, name: &str, src: NetSource) -> String {
        let id = self.id_for(prefix, name);
        let a = self.nodes.entry(id.clone()).or_default();
        if a.label.is_empty() {
            a.label = name.to_string();
        }
        // A computer seen as a server anywhere is a server.
        a.kind = Some(match (a.kind, kind) {
            (Some(NetKind::Server), NetKind::Workstation) => NetKind::Server,
            _ => kind,
        });
        if let Some(d) = src.doc {
            a.docs.insert(d);
        }
        a.sources.insert(src);
        id
    }

    fn server(&mut self, name: &str, role: Option<&str>, src: NetSource) -> String {
        let name = strip_port(name.trim());
        let lname = name.to_lowercase();
        let pc_key = format!("pc:{lname}");
        let host_key = format!("host:{lname}");
        // A generic internal name that looks like a workstation stays a workstation.
        let ws_like = role.is_none() && looks_like_workstation(name);
        if ws_like && !self.ids.contains_key(&host_key) {
            return self.add(NetKind::Workstation, "pc:", name, src);
        }
        // Workstation and server lists share the `pc:` namespace in the analysis; servers use
        // `host:` unless the computer list already knows the name.
        let id = if let Some(id) = self.ids.get(&pc_key).cloned() {
            let a = self.nodes.entry(id.clone()).or_default();
            if !(ws_like || role.is_none() && a.kind == Some(NetKind::Workstation)) {
                a.kind = Some(NetKind::Server);
            }
            if let Some(d) = src.doc {
                a.docs.insert(d);
            }
            a.sources.insert(src);
            id
        } else {
            self.add(NetKind::Server, "host:", name, src)
        };
        let a = self.nodes.get_mut(&id).expect("node just added");
        if a.kind == Some(NetKind::Server) {
            for r in name_roles(name) {
                a.roles.insert(r.into());
            }
            if let Some(r) = role {
                a.roles.insert(r.into());
            }
        }
        id
    }

    fn link(&mut self, from: &str, to: &str, kind: &str, doc: Option<u64>) {
        if from == to {
            return;
        }
        let e = self
            .links
            .entry((from.into(), to.into(), kind.into()))
            .or_default();
        e.extend(doc);
    }
}

fn src(kind: &str, value: &str, doc: Option<u64>) -> NetSource {
    NetSource {
        kind: kind.into(),
        value: value.into(),
        doc,
    }
}

/// Builds the network map.
pub fn build(inputs: &[DocInput], a: &Analysis, pki: &[PkiInput]) -> NetMap {
    let live: BTreeSet<u64> = inputs
        .iter()
        .filter(|i| !i.deleted)
        .map(|i| i.doc.id)
        .collect();
    let mut b = Builder {
        nodes: BTreeMap::new(),
        ids: BTreeMap::new(),
        links: BTreeMap::new(),
    };
    let service: BTreeSet<&str> = a
        .people
        .iter()
        .filter(|p| p.service)
        .map(|p| p.login.as_str())
        .collect();
    let mut domains: BTreeMap<String, BTreeSet<NetSource>> = BTreeMap::new();
    let mut netbios: BTreeMap<String, BTreeSet<NetSource>> = BTreeMap::new();

    // Computers known to the analysis.
    for pc in &a.pcs {
        let kind = if pc.kind == "server" {
            NetKind::Server
        } else {
            NetKind::Workstation
        };
        let id = b.add(kind, "pc:", &pc.name, src("pc_list", &pc.source, None));
        if kind == NetKind::Server {
            let roles = name_roles(&pc.name);
            let n = b.nodes.get_mut(&id).expect("added");
            n.roles.extend(roles.into_iter().map(str::to_string));
        }
        for u in pc.users.iter().filter(|u| !service.contains(u.as_str())) {
            let uid = b.add(NetKind::User, "person:", u, src("pc_list", &pc.name, None));
            b.nodes
                .get_mut(&uid)
                .expect("added")
                .parent
                .get_or_insert(id.clone());
            b.link(&uid, &id, "uses_pc", None);
        }
    }
    for p in a.people.iter().filter(|p| !p.service) {
        if let Some(pc) = &p.pc {
            let pid = b.add(
                NetKind::Workstation,
                "pc:",
                pc,
                src("pc_list", &p.login, None),
            );
            let uid = b.add(NetKind::User, "person:", &p.login, src("pc_list", pc, None));
            let n = b.nodes.get_mut(&uid).expect("added");
            n.label = p.name.clone();
            n.parent.get_or_insert(pid.clone());
            b.link(&uid, &pid, "uses_pc", None);
        }
    }
    for h in a.hosts.iter().filter(|h| h.internal) {
        let id = b.server(&h.name, None, src("host_list", &h.source, None));
        if !h.role.is_empty() {
            let n = b.nodes.get_mut(&id).expect("added");
            for r in h.role.split([',', ' ']).filter(|r| !r.is_empty()) {
                if ["mail", "web", "db", "file", "remote", "dc", "pki"].contains(&r) {
                    n.roles.insert(r.into());
                }
            }
        }
    }

    // Documents.
    for f in a
        .facts
        .iter()
        .filter(|f| f.analyzed && live.contains(&f.id))
    {
        let d = Some(f.id);
        let doc_id = format!("doc:{}", f.id);
        let ws: Vec<String> = f
            .pcs
            .iter()
            .chain(f.fx.lnk_machine.iter())
            .map(|p| b.add(NetKind::Workstation, "pc:", p, src("doc_pc", &f.name, d)))
            .collect();
        if let Some(m) = &f.fx.lnk_machine {
            let id = b.id_for("pc:", m);
            b.nodes
                .get_mut(&id)
                .expect("added")
                .sources
                .insert(src("lnk", m, d));
        }
        // Users of the document on its computers.
        for w in &ws {
            for l in f
                .author
                .iter()
                .chain(f.last_modified_by.iter())
                .filter(|l| !service.contains(l.as_str()))
            {
                let uid = b.add(NetKind::User, "person:", l, src("doc_pc", &f.name, d));
                b.nodes
                    .get_mut(&uid)
                    .expect("added")
                    .parent
                    .get_or_insert(w.clone());
                b.link(&uid, w, "uses_pc", d);
            }
        }
        // UNC paths → file servers.
        for p in f.paths.iter().chain(f.fx.lnk_unc.iter()) {
            let Some((host, share, _)) = unc_parts(p) else {
                continue;
            };
            if is_public_ip(&host)
                || [
                    "localhost",
                    "home",
                    "users",
                    "127.0.0.1",
                    "wsl$",
                    "wsl.localhost",
                ]
                .contains(&host.to_ascii_lowercase().as_str())
            {
                continue;
            }
            let kind = if f.fx.lnk_unc.contains(p) {
                "lnk"
            } else {
                "unc_path"
            };
            let sid = b.server(&host, Some("file"), src(kind, p, d));
            let mut target = sid.clone();
            if let Some(s) = share.filter(|s| !s.ends_with('$') || s.len() > 2) {
                let sh = format!("\\\\{host}\\{s}");
                target = format!("share:{sh}");
                b.nodes.get_mut(&sid).expect("added").shares.insert(sh);
            }
            b.link(&doc_id, &target, "on_share", d);
            for w in &ws {
                b.link(w, &sid, "uses_share", d);
            }
            if let Some(dm) = domain_of(&host) {
                domains.entry(dm).or_default().insert(src("fqdn", &host, d));
            }
        }
        // Printers → print servers.
        for pr in &f.printers {
            if let Some(h) = printer_host(pr).filter(|h| !is_public_ip(h)) {
                let sid = b.server(&h, Some("print"), src("printer", pr, d));
                b.nodes
                    .get_mut(&sid)
                    .expect("added")
                    .printers
                    .insert(pr.clone());
                for w in &ws {
                    b.link(w, &sid, "prints_to", d);
                }
            }
        }
        // E-mail relays.
        for h in &f.fx.mail_internal {
            if is_public_ip(h) {
                continue;
            }
            // The first Received hop is often the sender's own computer.
            let role = (!looks_like_workstation(h)).then_some("mail");
            let sid = b.server(h, role, src("eml_received", h, d));
            if b.nodes[&sid].kind != Some(NetKind::Server) {
                continue;
            }
            b.link(&doc_id, &sid, "mail_via", d);
            for w in &ws {
                b.link(w, &sid, "mail_via", d);
            }
            if let Some(dm) = domain_of(h) {
                domains.entry(dm).or_default().insert(src("fqdn", h, d));
            }
        }
        // RDP / ICA.
        if let Some(r) = &f.rdp {
            for (addr, kind) in [(&r.full_address, "rdp"), (&r.gateway, "rdp")] {
                let host = url_host(addr).unwrap_or_else(|| strip_port(addr.trim()).to_string());
                if host.is_empty() {
                    continue;
                }
                let sid = b.server(&host, Some("terminal"), src(kind, addr, d));
                b.link(&doc_id, &sid, "rdp_to", d);
                for w in &ws {
                    b.link(w, &sid, "rdp_to", d);
                }
                if let Some(dm) = domain_of(&host).filter(|_| is_internal_name(&host)) {
                    domains.entry(dm).or_default().insert(src("fqdn", &host, d));
                }
            }
            if let Some((nb, _)) = r.username.split_once('\\') {
                if !nb.is_empty() && nb != "." {
                    netbios.entry(nb.to_uppercase()).or_default().insert(src(
                        "rdp_user",
                        &r.username,
                        d,
                    ));
                }
            }
        }
        // Other internal servers of the document.
        for s in &f.servers {
            if !f.pcs.contains(s) && !is_public_ip(s) {
                let sid = b.server(s, None, src("unc_path", &f.name, d));
                b.link(&doc_id, &sid, "on_host", d);
                if let Some(dm) = domain_of(s) {
                    domains.entry(dm).or_default().insert(src("fqdn", s, d));
                }
            }
        }
    }

    // PKI hints.
    for h in pki {
        if let Some(host) = h.host.as_deref().filter(|x| is_internal_name(x)) {
            b.server(host, Some("pki"), src("pki", &h.url, None));
            if let Some(dm) = domain_of(host) {
                domains
                    .entry(dm)
                    .or_default()
                    .insert(src("fqdn", host, None));
            }
        }
        if let Some(dm) = &h.ad_domain {
            let v = h.ldap_dn.clone().unwrap_or_else(|| h.url.clone());
            domains
                .entry(dm.to_ascii_lowercase())
                .or_default()
                .insert(src("pki_ldap", &v, None));
        }
    }
    // `BUH-PC07` and `buh-pc07.corp.example.test` are one computer: the FQDN node merges into
    // the NetBIOS node (its id is the one the relation graph uses).
    let short: BTreeMap<String, String> = b
        .nodes
        .iter()
        .filter(|(_, n)| matches!(n.kind, Some(NetKind::Server | NetKind::Workstation)))
        .filter(|(_, n)| !n.label.contains('.') && !is_ip(&n.label))
        .map(|(id, n)| (n.label.to_ascii_lowercase(), id.clone()))
        .collect();
    let mut merged: BTreeMap<String, String> = BTreeMap::new();
    let longs: Vec<(String, String)> = b
        .nodes
        .iter()
        .filter(|(_, n)| matches!(n.kind, Some(NetKind::Server | NetKind::Workstation)))
        .filter(|(_, n)| n.label.contains('.') && !is_ip(&n.label))
        .map(|(id, n)| (id.clone(), n.label.clone()))
        .collect();
    let mut first_count: BTreeMap<String, usize> = BTreeMap::new();
    for (_, l) in &longs {
        *first_count
            .entry(l.split('.').next().unwrap_or("").to_ascii_lowercase())
            .or_default() += 1;
    }
    for (lid, label) in longs {
        let first = label.split('.').next().unwrap_or("").to_ascii_lowercase();
        let Some(sid) = short.get(&first).filter(|_| first_count[&first] == 1) else {
            continue;
        };
        let l = b.nodes.remove(&lid).expect("exists");
        let n = b.nodes.get_mut(sid).expect("exists");
        if l.kind == Some(NetKind::Server) {
            n.kind = Some(NetKind::Server);
        }
        n.fqdn = Some(label);
        n.roles.extend(l.roles);
        n.shares.extend(l.shares);
        n.printers.extend(l.printers);
        n.sources.extend(l.sources);
        n.docs.extend(l.docs);
        merged.insert(lid, sid.clone());
    }
    if !merged.is_empty() {
        let fix = |id: &String| merged.get(id).cloned().unwrap_or_else(|| id.clone());
        b.links = std::mem::take(&mut b.links).into_iter().fold(
            BTreeMap::new(),
            |mut acc, ((f, t, k), d)| {
                acc.entry((fix(&f), fix(&t), k))
                    .or_insert_with(BTreeSet::new)
                    .extend(d);
                acc
            },
        );
        b.links.retain(|(f, t, _), _| f != t);
        for n in b.nodes.values_mut() {
            if let Some(p) = &n.parent {
                n.parent = Some(fix(p));
            }
        }
    }

    // FQDN computers.
    let names: Vec<String> = b
        .nodes
        .values()
        .map(|n| n.fqdn.clone().unwrap_or_else(|| n.label.clone()))
        .collect();
    for n in names {
        if let Some(dm) = domain_of(&n).filter(|_| is_internal_name(&n)) {
            domains.entry(dm).or_default().insert(src("fqdn", &n, None));
        }
    }
    // NetBIOS names that match the first label of a DNS domain merge into it.
    for (nb, s) in netbios {
        let hit = domains
            .keys()
            .find(|d| {
                d.split('.')
                    .next()
                    .is_some_and(|l| l.eq_ignore_ascii_case(&nb))
            })
            .cloned();
        domains.entry(hit.unwrap_or(nb)).or_default().extend(s);
    }

    // Domain and forest nodes.
    let dnames: Vec<String> = domains.keys().cloned().collect();
    for (dm, srcs) in &domains {
        let id = format!("domain:{dm}");
        let acc = b.nodes.entry(id).or_default();
        acc.kind = Some(NetKind::Domain);
        acc.label = if dm.contains('.') {
            dm.clone()
        } else {
            dm.to_uppercase()
        };
        acc.docs.extend(srcs.iter().filter_map(|s| s.doc));
        acc.sources.extend(srcs.iter().cloned());
        if srcs.iter().any(|s| s.kind == "pki_ldap") {
            acc.fixed_conf = Some(90);
        }
    }
    // Child domains: a domain whose parent suffix is another domain hangs below it; siblings
    // under a common parent form a forest.
    let mut parent_of: BTreeMap<String, String> = BTreeMap::new();
    for d in &dnames {
        if let Some(p) = dnames
            .iter()
            .filter(|p| *p != d && d.ends_with(&format!(".{p}")))
            .max_by_key(|p| p.len())
        {
            parent_of.insert(d.clone(), p.clone());
        }
    }
    let mut by_suffix: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for d in dnames.iter().filter(|d| !parent_of.contains_key(*d)) {
        if let Some((_, rest)) = d.split_once('.') {
            if rest.contains('.') {
                by_suffix
                    .entry(rest.to_string())
                    .or_default()
                    .push(d.clone());
            }
        }
    }
    for (d, p) in &parent_of {
        b.nodes
            .get_mut(&format!("domain:{d}"))
            .expect("added")
            .parent = Some(format!("domain:{p}"));
    }
    for (root, kids) in by_suffix.into_iter().filter(|(_, k)| k.len() >= 2) {
        let fid = format!("forest:{root}");
        let acc = b.nodes.entry(fid.clone()).or_default();
        acc.kind = Some(NetKind::Forest);
        acc.label = root.clone();
        acc.sources
            .insert(src("child_domains", &kids.join(", "), None));
        for k in kids {
            b.nodes
                .get_mut(&format!("domain:{k}"))
                .expect("added")
                .parent = Some(fid.clone());
        }
    }

    // Users sit under workstations; usage links start at workstations or users.
    let servers: BTreeSet<String> = b
        .nodes
        .iter()
        .filter(|(_, n)| n.kind == Some(NetKind::Server))
        .map(|(id, _)| id.clone())
        .collect();
    for n in b.nodes.values_mut() {
        if n.kind == Some(NetKind::User) && n.parent.as_ref().is_some_and(|p| servers.contains(p)) {
            n.parent = None;
        }
    }
    b.links.retain(|(from, to, kind), _| {
        !(servers.contains(from) && kind != "has_share")
            && !(kind == "uses_pc" && servers.contains(to))
    });

    // Parents of computers and users.
    let only_domain = (dnames.len() == 1).then(|| format!("domain:{}", dnames[0]));
    let mut need_unknown = false;
    let ids: Vec<String> = b.nodes.keys().cloned().collect();
    for id in &ids {
        let (kind, label, has_parent) = {
            let n = &b.nodes[id];
            let name = n.fqdn.as_ref().unwrap_or(&n.label);
            (n.kind, name.to_ascii_lowercase(), n.parent.is_some())
        };
        if has_parent
            || !matches!(
                kind,
                Some(NetKind::Server | NetKind::Workstation | NetKind::User)
            )
        {
            continue;
        }
        let by_fqdn = dnames
            .iter()
            .filter(|d| label.ends_with(&format!(".{d}")))
            .max_by_key(|d| d.len())
            .map(|d| format!("domain:{d}"));
        let (parent, conf) = match (by_fqdn, &only_domain) {
            (Some(p), _) => (p, None),
            (None, Some(p)) => (p.clone(), Some(50)),
            (None, None) => {
                need_unknown = true;
                ("domain:unknown".to_string(), Some(40))
            }
        };
        let n = b.nodes.get_mut(id).expect("exists");
        n.parent = Some(parent);
        if let Some(c) = conf {
            n.fixed_conf.get_or_insert(c);
        }
    }
    if need_unknown {
        let acc = b.nodes.entry("domain:unknown".into()).or_default();
        acc.kind = Some(NetKind::Domain);
        acc.label = "Внутренняя сеть (домен не установлен)".into();
        acc.roles.insert("unknown".into());
        acc.fixed_conf = Some(0);
    }

    let mut nodes: Vec<NetNode> = b
        .nodes
        .into_iter()
        .filter_map(|(id, n)| {
            let kind = n.kind?;
            let strong = n
                .sources
                .iter()
                .any(|s| matches!(s.kind.as_str(), "lnk" | "pki" | "pki_ldap" | "pc_list"));
            let kinds: BTreeSet<&str> = n.sources.iter().map(|s| s.kind.as_str()).collect();
            let base = match (strong, kinds.len()) {
                (true, _) => 90,
                (_, 0 | 1) => 60,
                (_, 2) => 80,
                _ => 90,
            };
            let confidence = n.fixed_conf.map_or(base, |c| c.min(base));
            let mut sources: Vec<NetSource> = n.sources.into_iter().collect();
            sources.truncate(12);
            Some(NetNode {
                id,
                kind,
                label: n.label,
                fqdn: n.fqdn,
                roles: n.roles.into_iter().collect(),
                shares: n.shares.into_iter().collect(),
                printers: n.printers.into_iter().collect(),
                parent: n.parent,
                confidence,
                sources,
                docs: n.docs.into_iter().collect(),
            })
        })
        .collect();
    nodes.sort_by(|a, b| a.kind.cmp(&b.kind).then(a.id.cmp(&b.id)));
    let links = b
        .links
        .into_iter()
        .map(|((from, to, kind), docs)| NetLink {
            from,
            to,
            kind,
            docs: docs.into_iter().collect(),
        })
        .collect();
    NetMap { nodes, links }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn role_hints_and_domains() {
        assert_eq!(name_roles("SRV-FS01"), vec!["file"]);
        assert_eq!(name_roles("dc01.corp.example.test"), vec!["dc"]);
        assert_eq!(name_roles("buhfs01"), vec!["file"]);
        assert!(name_roles("BUH-PC07").is_empty());
        assert_eq!(
            domain_of("srv01.corp.example.test").as_deref(),
            Some("corp.example.test")
        );
        assert_eq!(domain_of("srv01.corp.local").as_deref(), Some("corp.local"));
        assert_eq!(domain_of("SRV01"), None);
        assert_eq!(domain_of("10.0.0.5"), None);
        assert!(is_internal_name("10.1.2.3") && !is_internal_name("8.8.8.8"));
    }
}
