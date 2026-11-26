//! Table exports: plain list, `.txt` wordlist, CSV, JSON, Maltego CSV, GraphML and Markdown
//! (a single file or an Obsidian ZIP vault). Secrets are hidden by default; PII redaction is
//! optional.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::io::{Cursor, Write as _};

use foca_core::api::Snapshot;
use serde_json::{json, Map, Value};

use crate::data::{sev_id, status_id, RequestEntry};
use crate::mask::{Pii, Redactor};
use crate::opts::{DictKind, ExportFormat, ExportKind, ExportOptions, Lang, MdLayout, SecretMode};
use crate::safe;

/// A finished export file (`export_build` → `{ name, size, count, secrets, pii_redacted }`).
#[derive(Debug, Clone, PartialEq)]
pub struct Artifact {
    pub bytes: Vec<u8>,
    pub file_name: String,
    pub mime: &'static str,
    /// Number of records (table rows, wordlist entries, graph links).
    pub count: usize,
    /// Secrets were exported in clear text.
    pub secrets: bool,
    pub pii_redacted: bool,
}

/// A table of one kind: column keys and rows (already masked).
#[derive(Debug, Clone, Default)]
pub struct Table {
    pub kind: &'static str,
    pub columns: Vec<&'static str>,
    pub rows: Vec<Vec<String>>,
}

/// Returns the default columns of a kind (keys for `ExportOptions.columns`).
pub fn columns(kind: ExportKind) -> &'static [&'static str] {
    match kind {
        ExportKind::Findings => &[
            "id",
            "severity",
            "status",
            "title",
            "host",
            "category",
            "mitre",
            "cve",
            "cvss",
            "description",
            "evidence",
            "recommendation",
            "url",
            "rule",
            "first_scan",
            "fixed_scan",
        ],
        ExportKind::Users => &[
            "login", "name", "role", "pc", "emails", "aliases", "docs", "service", "source",
        ],
        ExportKind::Emails => &["addr", "name", "login", "found", "role", "source"],
        ExportKind::Paths => &["path", "user", "host", "docs"],
        ExportKind::Software => &["name", "version", "kind", "eol", "eol_date", "cve", "docs"],
        ExportKind::Hosts => &[
            "name", "ip", "role", "tech", "cloud", "internal", "scope", "source", "services",
        ],
        ExportKind::Docs => &[
            "id",
            "name",
            "ext",
            "url",
            "title",
            "author",
            "last_modified_by",
            "software",
            "created",
            "modified",
            "size",
            "status",
            "flags",
        ],
        ExportKind::Log => &[
            "time", "scan_id", "module", "method", "url", "host", "status", "bytes", "active",
            "blocked", "error",
        ],
        ExportKind::All => &[],
    }
}

const SECRET_COLUMNS: &[&str] = &[
    "id", "type", "doc", "location", "severity", "value", "rule", "finding",
];

/// Kinds included in `all`.
const ALL_KINDS: [ExportKind; 8] = [
    ExportKind::Findings,
    ExportKind::Users,
    ExportKind::Emails,
    ExportKind::Paths,
    ExportKind::Software,
    ExportKind::Hosts,
    ExportKind::Docs,
    ExportKind::Log,
];

fn b(v: bool) -> String {
    if v { "true" } else { "false" }.into()
}

fn opt(v: &Option<String>) -> String {
    v.clone().unwrap_or_default()
}

struct Clean {
    red: Redactor,
    pii: Option<Pii>,
}

impl Clean {
    fn s(&self, v: &str) -> String {
        let v = self.red.text(v);
        match &self.pii {
            Some(p) => p.text(&v),
            None => v,
        }
    }
}

fn raw_rows(
    snap: &Snapshot,
    log: &[RequestEntry],
    kind: ExportKind,
    o: &ExportOptions,
) -> Vec<Vec<String>> {
    let want = |id: u64| o.ids.as_ref().is_none_or(|ids| ids.contains(&id));
    match kind {
        ExportKind::Findings => {
            let mut v: Vec<_> = snap.findings.iter().filter(|f| want(f.id)).collect();
            v.sort_by(|a, b| b.sev.rank().cmp(&a.sev.rank()).then(a.id.cmp(&b.id)));
            v.into_iter()
                .map(|f| {
                    vec![
                        format!("F-{}", f.id),
                        sev_id(f.sev).into(),
                        status_id(f.status).into(),
                        f.title.clone(),
                        f.host.clone(),
                        f.category.clone(),
                        f.mitre.clone(),
                        f.cve.join(" "),
                        f.cvss.map(|c| format!("{c:.1}")).unwrap_or_default(),
                        f.description.clone(),
                        f.evidence.clone(),
                        f.recommendation.clone(),
                        opt(&f.url),
                        f.provenance.rule.clone(),
                        opt(&f.first_scan),
                        opt(&f.fixed_scan),
                    ]
                })
                .collect()
        }
        ExportKind::Users => snap
            .people
            .iter()
            .map(|p| {
                vec![
                    p.login.clone(),
                    p.name.clone(),
                    p.role.clone(),
                    opt(&p.pc),
                    p.emails.join("; "),
                    p.aliases.join("; "),
                    p.docs.to_string(),
                    b(p.service),
                    p.src.clone(),
                ]
            })
            .collect(),
        ExportKind::Emails => snap
            .emails
            .iter()
            .map(|e| {
                vec![
                    e.addr.clone(),
                    opt(&e.name),
                    opt(&e.login),
                    b(e.found),
                    b(e.role),
                    e.src.clone(),
                ]
            })
            .collect(),
        ExportKind::Paths => snap
            .paths
            .iter()
            .map(|p| {
                vec![
                    p.path.clone(),
                    opt(&p.user),
                    opt(&p.host),
                    p.docs.to_string(),
                ]
            })
            .collect(),
        ExportKind::Software => snap
            .software
            .iter()
            .map(|s| {
                vec![
                    s.name.clone(),
                    s.ver.clone(),
                    s.kind.clone(),
                    b(s.eol),
                    opt(&s.eol_date),
                    s.cve.to_string(),
                    s.docs.to_string(),
                ]
            })
            .collect(),
        ExportKind::Hosts => snap
            .hosts
            .iter()
            .map(|h| {
                vec![
                    h.name.clone(),
                    h.ip.clone(),
                    h.role.clone(),
                    h.tech.clone(),
                    h.cloud.clone(),
                    b(h.internal),
                    h.scope.clone(),
                    h.source.clone(),
                    h.services
                        .iter()
                        .map(|(a, b, c)| {
                            [a.as_str(), b.as_str(), c.as_str()]
                                .iter()
                                .filter(|x| !x.is_empty())
                                .copied()
                                .collect::<Vec<_>>()
                                .join(" ")
                        })
                        .collect::<Vec<_>>()
                        .join("; "),
                ]
            })
            .collect(),
        ExportKind::Docs => snap
            .docs
            .iter()
            .filter(|d| !d.deleted && want(d.id))
            .map(|d| {
                vec![
                    d.id.to_string(),
                    d.name.clone(),
                    d.ext.clone(),
                    d.url.clone(),
                    d.title.clone(),
                    opt(&d.author),
                    opt(&d.last_modified_by),
                    opt(&d.software),
                    opt(&d.created_at),
                    opt(&d.modified_at),
                    d.size.to_string(),
                    d.status.clone(),
                    d.flags.join("; "),
                ]
            })
            .collect(),
        ExportKind::Log => log
            .iter()
            .map(|r| {
                vec![
                    r.time.clone(),
                    opt(&r.scan_id),
                    r.module.clone(),
                    r.method.clone(),
                    r.url.clone(),
                    r.host.clone(),
                    r.status.map(|s| s.to_string()).unwrap_or_default(),
                    r.bytes.to_string(),
                    b(r.active),
                    b(r.blocked),
                    crate::ftext::log_error(r.error.as_deref(), o.lang),
                ]
            })
            .collect(),
        ExportKind::All => Vec::new(),
    }
}

fn secrets_table(snap: &Snapshot, c: &Clean) -> Table {
    let doc_name = |id: u64| {
        snap.docs
            .iter()
            .find(|d| d.id == id)
            .map(|d| d.name.clone())
            .unwrap_or_else(|| format!("#{id}"))
    };
    Table {
        kind: "secrets",
        columns: SECRET_COLUMNS.to_vec(),
        rows: snap
            .secrets
            .iter()
            .map(|s| {
                vec![
                    s.id.to_string(),
                    s.kind.clone(),
                    c.s(&doc_name(s.doc)),
                    c.s(&s.location),
                    sev_id(s.sev).into(),
                    if s.kind == "host" {
                        c.s(s.value.expose())
                    } else {
                        c.red.mask(s.value.expose())
                    },
                    s.rule.clone(),
                    s.finding.map(|f| format!("F-{f}")).unwrap_or_default(),
                ]
            })
            .collect(),
    }
}

/// Builds the table of a kind with the selected columns, masked secrets and optionally
/// redacted PII.
fn table(
    snap: &Snapshot,
    log: &[RequestEntry],
    kind: ExportKind,
    o: &ExportOptions,
    c: &Clean,
) -> Table {
    let all = columns(kind);
    let idx: Vec<usize> = match &o.columns {
        Some(want) => {
            let v: Vec<usize> = want
                .iter()
                .filter_map(|w| all.iter().position(|c| c == w))
                .collect();
            if v.is_empty() {
                (0..all.len()).collect()
            } else {
                v
            }
        }
        None => (0..all.len()).collect(),
    };
    let rows = raw_rows(snap, log, kind, o)
        .into_iter()
        .map(|r| idx.iter().map(|i| c.s(&r[*i])).collect())
        .collect();
    Table {
        kind: kind.slug(),
        columns: idx.iter().map(|i| all[*i]).collect(),
        rows,
    }
}

fn tables(
    snap: &Snapshot,
    log: &[RequestEntry],
    kind: ExportKind,
    o: &ExportOptions,
    c: &Clean,
) -> Vec<Table> {
    if kind == ExportKind::All {
        let mut v: Vec<Table> = ALL_KINDS
            .iter()
            .map(|k| table(snap, log, *k, o, c))
            .collect();
        v.push(secrets_table(snap, c));
        v
    } else {
        vec![table(snap, log, kind, o, c)]
    }
}

/// Returns login variants: `ivan.petrov → ivanpetrov, petrov.ivan, petrov, ipetrov,
/// petrov.i, ivan`.
pub fn login_variants(l: &str) -> Vec<String> {
    let mut out = vec![l.to_string()];
    let parts: Vec<&str> = l.split(['.', '_']).filter(|s| !s.is_empty()).collect();
    if let [a, b] = parts.as_slice() {
        let a0: String = a.chars().take(1).collect();
        out.push(format!("{a}{b}"));
        out.push(format!("{b}.{a}"));
        out.push(b.to_string());
        if a.chars().count() > 1 {
            out.push(format!("{a0}{b}"));
            out.push(format!("{b}.{a0}"));
        }
    }
    out
}

/// Returns the directory of a document URL (for the paths wordlist):
/// `https://x/a/b/c.pdf` → `/a/b/`.
fn url_dir(u: &str) -> Option<String> {
    let u = u
        .strip_prefix("https://web.archive.org/web/")
        .and_then(|r| r.split_once('/').map(|(_, rest)| rest))
        .unwrap_or(u);
    let rest = u.split_once("://")?.1;
    let path = &rest[rest.find('/')?..];
    let path = path.split(['?', '#']).next().unwrap_or("");
    let dir = &path[..path.rfind('/')? + 1];
    (dir.len() > 1).then(|| dir.to_string())
}

fn dict_values(
    snap: &Snapshot,
    log: &[RequestEntry],
    kind: ExportKind,
    o: &ExportOptions,
    c: &Clean,
) -> (DictKind, Vec<String>) {
    let dk = o.dict.unwrap_or(match kind {
        ExportKind::Users => DictKind::Users,
        ExportKind::Emails => DictKind::Emails,
        ExportKind::Paths => DictKind::Paths,
        ExportKind::Software => DictKind::Software,
        _ => DictKind::Custom,
    });
    let mut raw: Vec<String> = match dk {
        DictKind::Users => {
            let base: Vec<String> = match (&o.items, kind) {
                (Some(items), ExportKind::Users) => items.clone(),
                _ => snap.people.iter().map(|p| p.login.clone()).collect(),
            };
            base.iter()
                .flat_map(|l| {
                    if o.login_variants {
                        login_variants(l)
                    } else {
                        vec![l.clone()]
                    }
                })
                .collect()
        }
        DictKind::Logins => {
            let wopts = foca_analysis::wordlist::WordlistOptions {
                ad_domain: o.ad_domain.clone(),
                lowercase: o.lowercase,
                ..Default::default()
            };
            foca_analysis::wordlist::generate_logins(snap, &wopts).2
        }
        DictKind::Context => {
            let wopts = foca_analysis::wordlist::WordlistOptions {
                ad_domain: o.ad_domain.clone(),
                lowercase: o.lowercase,
                ..Default::default()
            };
            foca_analysis::wordlist::generate_context(snap, &wopts)
        }
        DictKind::Emails => snap
            .emails
            .iter()
            .map(|e| e.addr.clone())
            .chain(snap.people.iter().flat_map(|p| p.emails.iter().cloned()))
            .collect(),
        DictKind::Paths => snap
            .paths
            .iter()
            .map(|p| p.path.clone())
            .chain(
                snap.docs
                    .iter()
                    .filter(|d| !d.deleted)
                    .filter_map(|d| url_dir(&d.url)),
            )
            .collect(),
        DictKind::Software => snap
            .software
            .iter()
            .map(|s| {
                if s.ver.is_empty() || s.name.contains(&s.ver) {
                    s.name.clone()
                } else {
                    format!("{} {}", s.name, s.ver)
                }
            })
            .collect(),
        DictKind::Custom => match &o.items {
            Some(items) => items.clone(),
            // First column of the kind's tables (of all tables for `all`).
            None => tables(snap, log, kind, o, c)
                .into_iter()
                .flat_map(|t| t.rows)
                .filter_map(|r| r.into_iter().next())
                .collect(),
        },
    };
    raw = raw.iter().map(|x| c.s(x)).collect();
    let set: BTreeSet<String> = raw
        .into_iter()
        // One wordlist line is one value: no line breaks or control characters.
        .map(|x| {
            x.chars()
                .filter(|ch| !ch.is_control())
                .collect::<String>()
                .trim()
                .to_string()
        })
        .map(|x| if o.lowercase { x.to_lowercase() } else { x })
        .filter(|x| !x.is_empty())
        .collect();
    (dk, set.into_iter().collect())
}

/// Entity graph for Maltego/GraphML: nodes `(Maltego type, value)` and links.
struct Graph {
    nodes: Vec<(&'static str, String)>,
    index: BTreeMap<(&'static str, String), usize>,
    edges: Vec<(usize, usize, &'static str)>,
}

impl Graph {
    fn node(&mut self, t: &'static str, v: &str) -> Option<usize> {
        let v = v.trim();
        if v.is_empty() {
            return None;
        }
        let key = (t, v.to_string());
        if let Some(i) = self.index.get(&key) {
            return Some(*i);
        }
        let i = self.nodes.len();
        self.nodes.push(key.clone());
        self.index.insert(key, i);
        Some(i)
    }
    fn edge(&mut self, a: Option<usize>, b: Option<usize>, label: &'static str) {
        if let (Some(a), Some(b)) = (a, b) {
            if a != b && !self.edges.contains(&(a, b, label)) {
                self.edges.push((a, b, label));
            }
        }
    }
}

const M_DOMAIN: &str = "maltego.Domain";
const M_DNS: &str = "maltego.DNSName";
const M_IP: &str = "maltego.IPv4Address";
const M_PERSON: &str = "maltego.Person";
const M_EMAIL: &str = "maltego.EmailAddress";
const M_DOC: &str = "maltego.Document";
const M_PHRASE: &str = "maltego.Phrase";
const M_DEVICE: &str = "maltego.Device";
const M_FILE: &str = "maltego.File";

fn graph(snap: &Snapshot, log: &[RequestEntry], kind: ExportKind, c: &Clean) -> Graph {
    let mut g = Graph {
        nodes: Vec::new(),
        index: BTreeMap::new(),
        edges: Vec::new(),
    };
    let all = kind == ExportKind::All;
    let is = |k: ExportKind| all || kind == k;
    let domain = if snap.project.domain.is_empty() {
        snap.project.name.clone()
    } else {
        snap.project.domain.clone()
    };
    let dom = g.node(M_DOMAIN, &c.s(&domain));
    // Person by login, name or alias.
    let mut person_of: BTreeMap<String, String> = BTreeMap::new();
    for p in &snap.people {
        let label = if p.name.is_empty() { &p.login } else { &p.name };
        for k in std::iter::once(&p.login)
            .chain(std::iter::once(&p.name))
            .chain(p.aliases.iter())
        {
            if !k.is_empty() {
                person_of.insert(k.to_lowercase(), c.s(label));
            }
        }
    }
    if is(ExportKind::Hosts) {
        for h in &snap.hosts {
            let is_ip = h.name.parse::<std::net::IpAddr>().is_ok();
            let n = g.node(if is_ip { M_IP } else { M_DNS }, &c.s(&h.name));
            if !h.internal {
                g.edge(dom, n, "host");
            }
            if !is_ip && !h.ip.is_empty() {
                let ip = g.node(M_IP, &c.s(&h.ip));
                g.edge(n, ip, "resolves to");
            }
        }
    }
    if is(ExportKind::Users) || is(ExportKind::Emails) {
        for p in &snap.people {
            let label = if p.name.is_empty() { &p.login } else { &p.name };
            let pn = g.node(M_PERSON, &c.s(label));
            for e in &p.emails {
                let en = g.node(M_EMAIL, &c.s(e));
                g.edge(pn, en, "email");
            }
            if is(ExportKind::Users) {
                if let Some(pc) = &p.pc {
                    let d = g.node(M_DEVICE, &c.s(pc));
                    g.edge(pn, d, "uses");
                }
            }
        }
        for e in &snap.emails {
            let en = g.node(M_EMAIL, &c.s(&e.addr));
            if let Some(dn) = e.addr.rsplit_once('@').map(|x| x.1) {
                let d = g.node(M_DOMAIN, &c.s(dn));
                g.edge(en, d, "domain");
            }
        }
    }
    if is(ExportKind::Docs) || is(ExportKind::Users) || is(ExportKind::Software) {
        for d in snap.docs.iter().filter(|d| !d.deleted) {
            let dn = g.node(M_DOC, &c.s(if d.url.is_empty() { &d.name } else { &d.url }));
            if is(ExportKind::Docs) && !d.host.is_empty() {
                let h = g.node(M_DNS, &c.s(&d.host));
                g.edge(h, dn, "hosts document");
            }
            for who in [&d.author, &d.last_modified_by].into_iter().flatten() {
                if let Some(label) = person_of.get(&who.to_lowercase()).cloned() {
                    let pn = g.node(M_PERSON, &label);
                    g.edge(pn, dn, "author");
                }
            }
            if is(ExportKind::Software) || all {
                if let Some(sw) = &d.software {
                    let s = g.node(M_PHRASE, &c.s(sw));
                    g.edge(dn, s, "software");
                }
            }
        }
    }
    if is(ExportKind::Paths) {
        for p in &snap.paths {
            let f = g.node(M_FILE, &c.s(&p.path));
            if let Some(h) = &p.host {
                let hn = g.node(M_DEVICE, &c.s(h));
                g.edge(hn, f, "share");
            }
            if let Some(u) = &p.user {
                if let Some(label) = person_of.get(&u.to_lowercase()).cloned() {
                    let pn = g.node(M_PERSON, &label);
                    g.edge(pn, f, "path");
                }
            }
        }
    }
    if is(ExportKind::Findings) {
        for f in &snap.findings {
            let fnode = g.node(M_PHRASE, &c.s(&format!("F-{} {}", f.id, f.title)));
            let mut linked = false;
            if !f.host.is_empty() && f.host != "-" {
                let h = g.node(M_DNS, &c.s(&f.host));
                g.edge(h, fnode, "finding");
                linked = true;
            }
            // The source is a document (local analysis without a host).
            if let Some(d) = f.doc.and_then(|id| snap.docs.iter().find(|d| d.id == id)) {
                let dn = g.node(M_DOC, &c.s(if d.url.is_empty() { &d.name } else { &d.url }));
                g.edge(dn, fnode, "evidence");
                linked = true;
            }
            // Without a host or document, attach to the project domain so the finding is not lost from
            // the graph.
            if !linked {
                g.edge(dom, fnode, "finding");
            }
        }
    }
    if kind == ExportKind::Log {
        for r in log {
            let h = g.node(M_DNS, &c.s(&r.host));
            g.edge(
                dom,
                h,
                if r.active {
                    "active request"
                } else {
                    "request"
                },
            );
        }
    }
    g
}

fn maltego_csv(g: &Graph, delim: char, bom: bool) -> String {
    let mut s = String::new();
    if bom {
        s.push('\u{feff}');
    }
    s.push_str(&safe::csv_row(
        &[
            "source_type",
            "source_value",
            "link",
            "target_type",
            "target_value",
        ],
        delim,
    ));
    for (a, b, l) in &g.edges {
        let (ta, va) = &g.nodes[*a];
        let (tb, vb) = &g.nodes[*b];
        s.push_str(&safe::csv_row(
            &[*ta, va.as_str(), *l, *tb, vb.as_str()],
            delim,
        ));
    }
    s
}

fn graphml(g: &Graph) -> String {
    let mut s = String::from(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <graphml xmlns=\"http://graphml.graphdrawing.org/xmlns\">\n\
         <key id=\"type\" for=\"node\" attr.name=\"type\" attr.type=\"string\"/>\n\
         <key id=\"label\" for=\"node\" attr.name=\"label\" attr.type=\"string\"/>\n\
         <key id=\"rel\" for=\"edge\" attr.name=\"label\" attr.type=\"string\"/>\n\
         <graph id=\"foca\" edgedefault=\"directed\">\n",
    );
    for (i, (t, v)) in g.nodes.iter().enumerate() {
        let _ = writeln!(
            s,
            "<node id=\"n{i}\"><data key=\"type\">{}</data><data key=\"label\">{}</data></node>",
            safe::xml(t),
            safe::xml(v)
        );
    }
    for (i, (a, b, l)) in g.edges.iter().enumerate() {
        let _ = writeln!(
            s,
            "<edge id=\"e{i}\" source=\"n{a}\" target=\"n{b}\"><data key=\"rel\">{}</data></edge>",
            safe::xml(l)
        );
    }
    s.push_str("</graph>\n</graphml>\n");
    s
}

fn csv(t: &Table, delim: char, bom: bool) -> String {
    let mut s = String::new();
    if bom {
        s.push('\u{feff}');
    }
    s.push_str(&safe::csv_row(&t.columns, delim));
    for r in &t.rows {
        s.push_str(&safe::csv_row(r, delim));
    }
    s
}

fn items_json(t: &Table) -> Vec<Value> {
    t.rows
        .iter()
        .map(|r| {
            let mut m = Map::new();
            for (k, v) in t.columns.iter().zip(r) {
                m.insert((*k).to_string(), Value::String(v.clone()));
            }
            Value::Object(m)
        })
        .collect()
}

fn md_table(out: &mut String, t: &Table) {
    out.push('|');
    for c in &t.columns {
        let _ = write!(out, " {} |", safe::md(c));
    }
    out.push_str("\n|");
    for _ in &t.columns {
        out.push_str(" --- |");
    }
    out.push('\n');
    for r in &t.rows {
        out.push('|');
        for c in r {
            let _ = write!(out, " {} |", safe::md(c));
        }
        out.push('\n');
    }
    out.push('\n');
}

fn zip(files: &[(String, Vec<u8>)]) -> Vec<u8> {
    let mut w = zip::ZipWriter::new(Cursor::new(Vec::new()));
    let opts = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated)
        .last_modified_time(zip::DateTime::default());
    let mut used = BTreeSet::new();
    for (name, data) in files {
        // Names inside the archive are sanitized too (no `..`, absolute paths or duplicates).
        let mut parts: Vec<String> = name.split('/').map(safe::file_name).collect();
        let mut n = parts.join("/");
        let mut k = 2;
        while used.contains(&n) {
            let last = parts.pop().unwrap_or_default();
            let (stem, ext) = last.rsplit_once('.').unwrap_or((&last, ""));
            parts.push(format!("{stem}_{k}.{ext}"));
            n = parts.join("/");
            parts.pop();
            parts.push(last);
            k += 1;
        }
        used.insert(n.clone());
        if w.start_file(n, opts).is_ok() {
            let _ = w.write_all(data);
        }
    }
    w.finish().map(|c| c.into_inner()).unwrap_or_default()
}

fn md_note(t: &Table, row: &[String], project: &str) -> String {
    let mut s = String::from("---\n");
    for (k, v) in t.columns.iter().zip(row) {
        let _ = writeln!(s, "{k}: {}", safe::yaml_str(v));
    }
    let _ = writeln!(s, "tags: [foca, {}]\n---\n", t.kind);
    let _ = writeln!(
        s,
        "# {}\n",
        safe::md(row.first().map(String::as_str).unwrap_or(""))
    );
    for (k, v) in t.columns.iter().zip(row).skip(1) {
        if !v.is_empty() {
            let _ = writeln!(s, "- **{}:** {}", safe::md(k), safe::md(v));
        }
    }
    let _ = writeln!(s, "\n[[{}]]", safe::md(project));
    s
}

/// Returns the file name stem: the project without its TLD (`contoso.example` →
/// `contoso`).
fn project_stem(snap: &Snapshot) -> String {
    let n = if snap.project.name.is_empty() {
        "foca"
    } else {
        snap.project.name.as_str()
    };
    n.split('.').next().unwrap_or(n).to_string()
}

fn today() -> String {
    let d = time::OffsetDateTime::now_utc().date();
    format!("{:04}-{:02}-{:02}", d.year(), u8::from(d.month()), d.day())
}

/// Exports without a request log (the `log` kind will be empty).
pub fn export(snap: &Snapshot, kind: ExportKind, fmt: ExportFormat, o: &ExportOptions) -> Artifact {
    export_with_log(snap, &[], kind, fmt, o)
}

/// Exports including the outgoing request log.
pub fn export_with_log(
    snap: &Snapshot,
    log: &[RequestEntry],
    kind: ExportKind,
    fmt: ExportFormat,
    o: &ExportOptions,
) -> Artifact {
    let mode = if o.include_secrets {
        SecretMode::Full
    } else {
        SecretMode::Hide
    };
    let c = Clean {
        red: Redactor::new(snap, mode, o.lang),
        pii: o.redact_pii.then(|| Pii::new(snap)),
    };
    let date = if o.date.is_empty() {
        today()
    } else {
        o.date.clone()
    };
    let stem = project_stem(snap);
    let mut slug = kind.slug().to_string();
    let (bytes, ext, mime, count): (Vec<u8>, &str, &'static str, usize) = match fmt {
        ExportFormat::List => {
            let ts = tables(snap, log, kind, o, &c);
            let vals: Vec<String> = ts
                .iter()
                .flat_map(|t| t.rows.iter().filter_map(|r| r.first().cloned()))
                .map(|v| v.replace(['\r', '\n'], " "))
                .collect();
            let mut s = vals.join("\n");
            s.push('\n');
            (
                s.into_bytes(),
                "txt",
                "text/plain; charset=utf-8",
                vals.len(),
            )
        }
        ExportFormat::Dict => {
            let (dk, vals) = dict_values(snap, log, kind, o, &c);
            slug = format!("dict-{}", dk.id());
            let mut s = vals.join("\n");
            if !s.is_empty() {
                s.push('\n');
            }
            (
                s.into_bytes(),
                "txt",
                "text/plain; charset=utf-8",
                vals.len(),
            )
        }
        ExportFormat::Csv => {
            let ts = tables(snap, log, kind, o, &c);
            let count = ts.iter().map(|t| t.rows.len()).sum();
            if kind == ExportKind::All {
                let files: Vec<(String, Vec<u8>)> = ts
                    .iter()
                    .map(|t| {
                        (
                            format!("{}.csv", t.kind),
                            csv(t, o.delimiter, o.bom).into_bytes(),
                        )
                    })
                    .collect();
                (zip(&files), "zip", "application/zip", count)
            } else {
                (
                    csv(&ts[0], o.delimiter, o.bom).into_bytes(),
                    "csv",
                    "text/csv; charset=utf-8",
                    count,
                )
            }
        }
        ExportFormat::Json => {
            let ts = tables(snap, log, kind, o, &c);
            let count = ts.iter().map(|t| t.rows.len()).sum();
            let items = if kind == ExportKind::All {
                Value::Object(
                    ts.iter()
                        .map(|t| (t.kind.to_string(), Value::Array(items_json(t))))
                        .collect(),
                )
            } else {
                Value::Array(items_json(&ts[0]))
            };
            let v = json!({
                "schema_version": crate::SCHEMA_VERSION,
                "schema": "foca-export/v1",
                "generator": crate::GENERATOR,
                "kind": kind.slug(),
                "project": c.s(&snap.project.name),
                "date": date,
                "count": count,
                "secrets": o.include_secrets,
                "pii_redacted": o.redact_pii,
                "items": items,
            });
            let mut s = if o.pretty {
                serde_json::to_string_pretty(&v)
            } else {
                serde_json::to_string(&v)
            }
            .unwrap_or_default();
            s.push('\n');
            (s.into_bytes(), "json", "application/json", count)
        }
        ExportFormat::MaltegoCsv => {
            let g = graph(snap, log, kind, &c);
            (
                maltego_csv(&g, o.delimiter, o.bom).into_bytes(),
                "csv",
                "text/csv; charset=utf-8",
                g.edges.len(),
            )
        }
        ExportFormat::Graphml => {
            let g = graph(snap, log, kind, &c);
            (
                graphml(&g).into_bytes(),
                "graphml",
                "application/graphml+xml",
                g.edges.len(),
            )
        }
        ExportFormat::Md => {
            let ts = tables(snap, log, kind, o, &c);
            let count = ts.iter().map(|t| t.rows.len()).sum();
            let project = c.s(&snap.project.name);
            match o.md_layout {
                MdLayout::One => {
                    let mut s = format!(
                        "---\nproject: {}\nkind: {}\ndate: {}\ncount: {count}\ntags: [foca, export]\n---\n\n# {}: {}\n\n",
                        safe::yaml_str(&project),
                        kind.slug(),
                        safe::yaml_str(&date),
                        safe::md(&project),
                        kind.slug()
                    );
                    for t in &ts {
                        if ts.len() > 1 {
                            let _ = writeln!(s, "## {}\n", t.kind);
                        }
                        md_table(&mut s, t);
                    }
                    (s.into_bytes(), "md", "text/markdown; charset=utf-8", count)
                }
                MdLayout::Many => {
                    let mut files = Vec::new();
                    let mut index = format!("# {}\n\n", safe::md(&project));
                    for t in &ts {
                        let _ = writeln!(index, "## {}\n", t.kind);
                        for r in &t.rows {
                            let title = r.first().cloned().unwrap_or_default();
                            let name = format!("{}/{}.md", t.kind, safe::file_name(&title));
                            let _ = writeln!(index, "- [[{}]]", safe::md(&safe::file_name(&title)));
                            files.push((name, md_note(t, r, &project).into_bytes()));
                        }
                        index.push('\n');
                    }
                    files.insert(
                        0,
                        (
                            format!("{}.md", safe::file_name(&project)),
                            index.into_bytes(),
                        ),
                    );
                    (zip(&files), "zip", "application/zip", count)
                }
            }
        }
        ExportFormat::Httpx => {
            slug = "httpx".into();
            let list = httpx_targets(snap, &c);
            let count = list.len();
            let txt = if list.is_empty() {
                String::new()
            } else {
                format!("{}\n", list.join("\n"))
            };
            (txt.into_bytes(), "txt", "text/plain; charset=utf-8", count)
        }
        ExportFormat::Nuclei => {
            slug = "nuclei".into();
            let list = nuclei_targets(snap, &c);
            let count = list.len();
            let txt = if list.is_empty() {
                String::new()
            } else {
                format!("{}\n", list.join("\n"))
            };
            (txt.into_bytes(), "txt", "text/plain; charset=utf-8", count)
        }
        ExportFormat::Stix => {
            slug = "stix".into();
            let (bytes, count) = crate::formats::stix::export_bundle(snap, o.pretty);
            (bytes, "json", "application/json", count)
        }
    };
    Artifact {
        bytes,
        file_name: safe::file_name_ext(&format!("{stem}_{slug}_{date}"), ext),
        mime,
        count,
        secrets: if fmt == ExportFormat::Stix {
            false
        } else {
            o.include_secrets
        },
        pii_redacted: if fmt == ExportFormat::Stix {
            true
        } else {
            o.redact_pii
        },
    }
}

fn clean_web_url(raw: &str, red: &Redactor) -> Option<String> {
    let masked = red.text(raw.trim());
    let u = safe::safe_href(&masked)?;
    if let Some((scheme, rest)) = u.split_once("://") {
        let rest = match rest.split_once('@') {
            Some((user, host_path)) if !user.contains('/') && !user.contains('?') => host_path,
            _ => rest,
        };
        let no_frag = rest.split('#').next().unwrap_or(rest);
        if no_frag.is_empty() {
            None
        } else {
            Some(format!("{scheme}://{no_frag}"))
        }
    } else {
        None
    }
}

fn clean_target_host(raw: &str) -> Option<String> {
    let h = raw.trim().trim_start_matches("*.").to_ascii_lowercase();
    if h.is_empty() || h.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return None;
    }
    Some(h)
}

fn httpx_targets(snap: &Snapshot, _c: &Clean) -> Vec<String> {
    let mut set = BTreeSet::new();
    let red_hide = Redactor::new(snap, SecretMode::Hide, Lang::Ru);
    for h in &snap.hosts {
        if h.internal || h.scope == "excluded" || h.scope == "out" {
            continue;
        }
        if let Some(host) = clean_target_host(&h.name) {
            set.insert(host);
        }
    }
    for t in &snap.scope.targets {
        if matches!(t.kind.as_str(), "domain" | "wildcard" | "url") {
            if let Some(u) = clean_web_url(&t.v, &red_hide) {
                set.insert(u);
            } else if let Some(host) = clean_target_host(&t.v) {
                set.insert(host);
            }
        }
    }
    for f in &snap.findings {
        if f.host.is_empty() {
            continue;
        }
        if let Some(u) = f.url.as_deref().and_then(|u| clean_web_url(u, &red_hide)) {
            if let Some((_, rest)) = u.split_once("://") {
                if let Some(authority) = rest.split('/').next().filter(|a| !a.is_empty()) {
                    let scheme = if u.starts_with("http://") {
                        "http"
                    } else {
                        "https"
                    };
                    set.insert(format!("{scheme}://{authority}"));
                }
            }
        }
    }
    set.into_iter().collect()
}

fn nuclei_targets(snap: &Snapshot, _c: &Clean) -> Vec<String> {
    let mut set = BTreeSet::new();
    let red_hide = Redactor::new(snap, SecretMode::Hide, Lang::Ru);
    for d in snap.docs.iter().filter(|d| !d.deleted) {
        if let Some(u) = clean_web_url(&d.url, &red_hide) {
            set.insert(u);
        }
    }
    for f in &snap.findings {
        if let Some(u) = f.url.as_deref().and_then(|u| clean_web_url(u, &red_hide)) {
            set.insert(u);
        }
    }
    for h in &snap.hosts {
        if h.internal || h.scope == "excluded" || h.scope == "out" {
            continue;
        }
        if let Some(host) = clean_target_host(&h.name) {
            set.insert(format!("https://{host}"));
        }
    }
    set.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn variants_and_dirs() {
        let v = login_variants("ivan.petrov");
        for x in [
            "ivan.petrov",
            "ivanpetrov",
            "petrov.ivan",
            "petrov",
            "ipetrov",
            "petrov.i",
        ] {
            assert!(v.contains(&x.to_string()), "{x}: {v:?}");
        }
        assert_eq!(login_variants("admin"), vec!["admin"]);
        assert_eq!(
            url_dir("https://x.ua/a/b/c.pdf?x=1").as_deref(),
            Some("/a/b/")
        );
        assert_eq!(
            url_dir("https://web.archive.org/web/2020/https://x.ua/docs/f.doc").as_deref(),
            Some("/docs/")
        );
        assert_eq!(url_dir("https://x.ua/f.pdf"), None);
    }

    #[test]
    fn zip_names_safe_and_unique() {
        let z = zip(&[
            ("../../evil.md".into(), b"a".to_vec()),
            ("users/a.md".into(), b"b".to_vec()),
            ("users/a.md".into(), b"c".to_vec()),
        ]);
        let mut ar = zip::ZipArchive::new(Cursor::new(z)).unwrap();
        let names: Vec<String> = (0..ar.len())
            .map(|i| ar.by_index(i).unwrap().name().unwrap().to_string())
            .collect();
        assert!(
            names
                .iter()
                .all(|n| !n.contains("..") && !n.starts_with('/')),
            "{names:?}"
        );
        assert_eq!(names.len(), 3);
        assert_ne!(names[1], names[2]);
    }

    #[test]
    fn dict_logins_and_context_export_cleanly() {
        let mut snap = Snapshot::default();
        snap.project.name = "contoso.ua".into();
        snap.project.domain = "contoso.ua".into();
        snap.scope.client = "Contoso".into();
        snap.people.push(foca_core::api::Person {
            login: "CORP\\i.petrov".into(),
            name: "Ігор Петров".into(),
            ..Default::default()
        });
        snap.secrets.push(foca_core::api::Secret {
            id: 1,
            kind: "pass".into(),
            value: foca_core::api::SecretValue::new("UltraSecret#2026"),
            doc: 1,
            location: "body".into(),
            sev: foca_core::Severity::Critical,
            host: None,
            finding: None,
            rule: "pass".into(),
        });

        let logins = export(
            &snap,
            ExportKind::Users,
            ExportFormat::Dict,
            &ExportOptions {
                dict: Some(DictKind::Logins),
                ..Default::default()
            },
        );
        let logins_txt = String::from_utf8(logins.bytes).unwrap();
        assert!(logins.file_name.contains("dict-logins"));
        assert!(logins_txt.contains("i.petrov\n"));
        assert!(logins_txt.contains("corp\\ipetrov\n"));
        assert!(!logins_txt.contains("UltraSecret"));

        let ctx = export(
            &snap,
            ExportKind::All,
            ExportFormat::Dict,
            &ExportOptions {
                dict: Some(DictKind::Context),
                ..Default::default()
            },
        );
        let ctx_txt = String::from_utf8(ctx.bytes).unwrap();
        assert!(ctx.file_name.contains("dict-context"));
        assert!(ctx_txt.contains("contoso2025\n"));
        assert!(!ctx_txt.to_lowercase().contains("ultrasecret"));
    }
}
