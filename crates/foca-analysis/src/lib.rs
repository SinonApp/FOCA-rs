//! Document analysis for a project: pure functions with no network or database access.
//!
//! Input is the documents with metadata (`foca-meta::extract`) and text (`foca-meta::text`),
//! the scope and the previous analysis state (finding triage). Output is entities and findings
//! in the snapshot shape described in `docs/API.md` (`foca_core::api::*`), plus the relation
//! graph, activity and risk.
//!
//! ```text
//! analyze(&[DocInput], &Scope, &PrevState) -> Analysis
//!   ├─ software   software and OS by signature (signatures/software.toml)
//!   ├─ secrets    gitleaks-style rules + entropy (signatures/secrets.toml)
//!   ├─ people     identity merging, service accounts
//!   ├─ emails     addresses and the corporate address pattern
//!   ├─ hosts      hosts/computers from paths, RDP/ICA, URLs, printers; scope status
//!   ├─ findings   findings with stable ids and preserved triage, risk
//!   ├─ timeline   events from dates, activity hours, time zone
//!   └─ relations  graph document ↔ person ↔ computer ↔ host ↔ software
//! ```
//!
//! Analytics run on top of the result ([`insights::build`]): document lineage
//! ([`correlate`]), org chart ([`orgchart`]), metadata anomalies ([`anomalies`]), offline CISA
//! KEV matches ([`kev`]), the internal network map ([`netmap`]), the "link chain" ([`chain`])
//! and the clustered graph view ([`graphview`]).
//!
//! Every call recomputes the analysis over all documents. It is deterministic and ids do not
//! depend on input order. Because finding ids are stable (hash of rule and object), it is safe
//! to call after each new document: triage statuses carry over from [`PrevState`].

pub mod alerts;
mod analytics;
mod assess;
mod content;
pub mod hosts;
mod identity;
mod products;
pub mod relations;
pub mod roles;
pub mod timeline;
pub mod util;

pub use analytics::{anomalies, chain, clusters, correlate, graphview, insights, netmap};
pub use assess::{attack_paths, findings, forensic, infra, playbooks, portmerge, standards};
pub use content::{artifacts, links, pii, rules, secrets};
pub use identity::{emails, orgchart, people, translit, wordlist};
pub use products::{cve, kev, software, vercmp};

use std::collections::{BTreeMap, BTreeSet};

use foca_core::api::{
    self, Doc, DocGps, DocRdp, DocRevision, Email, GpsPoint, Note, PathItem, Pattern, Person,
    Photo, Printer, Secret, SecretValue,
};
use foca_core::{
    DocFormat, DocStatus, Document, FindingStatus, Metadata, PersonRole, RevisionKind, Scope,
    Severity,
};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

pub use findings::{Risk, RiskLevel};
pub use relations::Graph;
pub use software::{Signatures, SwMatch};
pub use timeline::Activity;

/// A document passed to the analysis.
#[derive(Debug, Clone, Copy)]
pub struct DocInput<'a> {
    pub doc: &'a Document,
    /// Plain text of the document (`foca-meta::text`), searched for secrets and addresses.
    pub text: Option<&'a str>,
    /// Scan in which the document was first found.
    pub first_scan: Option<&'a str>,
    /// Soft-deleted (in the trash); excluded from entities and findings.
    pub deleted: bool,
    /// Result of comparing the EXIF thumbnail with the image, if the caller did it; otherwise
    /// `Thumbnail::differs` from foca-meta is used (no comparison, no finding).
    pub thumb_diff: Option<bool>,
}

impl<'a> DocInput<'a> {
    pub fn new(doc: &'a Document) -> Self {
        DocInput {
            doc,
            text: None,
            first_scan: None,
            deleted: false,
            thumb_diff: None,
        }
    }

    pub fn with_text(mut self, text: Option<&'a str>) -> Self {
        self.text = text;
        self
    }
}

/// Triage of a finding from the previous analysis.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct PrevFinding {
    pub status: FindingStatus,
    /// Severity overridden by the user (`finding_update`).
    pub sev: Option<Severity>,
    pub notes: Vec<Note>,
    pub tags: Vec<String>,
    pub photos: Vec<Photo>,
    pub first_scan: Option<String>,
    pub fixed_scan: Option<String>,
    /// Time of first detection.
    pub time: Option<String>,
}

/// State of the previous analysis and parameters of the current one.
#[derive(Debug, Clone, Default)]
pub struct PrevState {
    /// Finding id → triage.
    pub findings: BTreeMap<u64, PrevFinding>,
    /// Current scan (used as `first_scan` of new findings and hosts).
    pub scan_id: Option<String>,
    /// Reference "now" for EOL checks and finding times; `None` uses the system clock.
    pub now: Option<OffsetDateTime>,
    /// Compiled user search rules (`analysis.rules` of the project); `None` runs none.
    pub rules: Option<rules::RuleSet>,
}

/// Operating system (the OS branch of the entity tree; the snapshot has no dedicated key).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct OsInfo {
    pub id: String,
    pub name: String,
    pub ver: String,
    pub released: Option<i32>,
    pub eol_date: Option<String>,
    pub eol: bool,
    pub docs: u32,
    /// NVD CPE `vendor:product` keys (offline CVE table).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cpe: Vec<String>,
    /// Date of the newest document from this OS (`YYYY-MM-DD`).
    #[serde(default)]
    pub last_doc: Option<String>,
    /// Offline NVD CVE summary (an OS without a patch level has no version: count only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cve_sum: Option<api::CveSummary>,
}

/// Analysis result. Fields `docs` … `events` follow the snapshot format in `docs/API.md`
/// exactly.
#[derive(Debug, Clone, Default, Serialize)]
pub struct Analysis {
    pub docs: Vec<Doc>,
    pub people: Vec<Person>,
    pub emails: Vec<Email>,
    pub patterns: Vec<Pattern>,
    pub hosts: Vec<api::Host>,
    pub pcs: Vec<api::Pc>,
    pub software: Vec<api::Software>,
    pub os: Vec<OsInfo>,
    pub paths: Vec<PathItem>,
    pub printers: Vec<Printer>,
    pub secrets: Vec<Secret>,
    pub findings: Vec<api::Finding>,
    pub gps: Vec<GpsPoint>,
    pub events: Vec<api::Event>,
    pub graph: Graph,
    pub activity: Activity,
    pub risk: Risk,
    /// Findings of the previous analysis that no longer reproduce (candidates for `fixed`).
    pub resolved: Vec<u64>,
    /// Earlier findings that no longer stand on their own (merged per host by [`portmerge`], or
    /// provider-managed on a CDN edge, see [`infra::adjust_cdn_edges`]): the store deletes them
    /// instead of marking them fixed.
    #[serde(skip)]
    pub dropped: Vec<u64>,
    /// Per-document facts, kept for the derived analytics ([`insights`]); not serialized.
    #[serde(skip)]
    pub facts: Vec<DocFacts>,
}

/// `true` if an older PDF revision differs from a later one: removed or added page text, or a
/// non-empty Info value (author, creator, producer, modification date; title, subject,
/// keywords of the old Info dictionaries) that changed. Revisions without their own Info or
/// with empty values (an LTV increment writes `/Producer ()`) do not count.
pub fn revisions_differ(m: &foca_core::Metadata) -> bool {
    let revs = &m.pdf_revisions;
    if revs
        .iter()
        .any(|r| !r.removed_text.is_empty() || !r.added_text.is_empty())
    {
        return true;
    }
    let mut last: [Option<&str>; 4] = [None; 4];
    for r in revs {
        let vals = [&r.author, &r.creator, &r.producer, &r.modified];
        for (slot, v) in last.iter_mut().zip(vals) {
            let Some(v) = v.as_deref().map(str::trim).filter(|v| !v.is_empty()) else {
                continue;
            };
            if slot.is_some_and(|p| p != v) {
                return true;
            }
            *slot = Some(v);
        }
    }
    let current = [
        ("Title", m.title.as_deref()),
        ("Subject", m.subject.as_deref()),
        ("Keywords", m.keywords.as_deref()),
        ("Author", m.author.as_deref()),
    ];
    for (k, now) in current {
        let mut prev: Option<&str> = None;
        let olds = m
            .old_versions
            .iter()
            .map(|o| o.fields.get(k).map(String::as_str));
        for v in olds.chain(std::iter::once(now)) {
            let Some(v) = v.map(str::trim).filter(|v| !v.is_empty()) else {
                continue;
            };
            if prev.is_some_and(|p| p != v) {
                return true;
            }
            prev = Some(v);
        }
    }
    false
}

/// Per-document facts shared by the finding rules, the timeline and the graph.
#[derive(Debug, Clone, Default)]
pub struct DocFacts {
    pub id: u64,
    /// Stable document key: SHA-256, otherwise the URL, otherwise the id.
    pub key: String,
    pub name: String,
    pub url: Option<String>,
    pub host: String,
    pub analyzed: bool,
    pub first_scan: Option<String>,
    pub author: Option<String>,
    pub last_modified_by: Option<String>,
    /// Logins of all people of the document.
    pub people: Vec<String>,
    /// NetBIOS computer names.
    pub pcs: Vec<String>,
    /// Internal hosts (server computers, internal FQDNs, private IPs).
    pub servers: Vec<String>,
    pub paths: Vec<String>,
    pub path_hosts: Vec<String>,
    pub printers: Vec<String>,
    pub software: Vec<String>,
    pub os: Option<String>,
    pub created: Option<String>,
    pub modified: Option<String>,
    pub offsets: Vec<i32>,
    pub revisions: Vec<DocRevision>,
    pub revision_people: Vec<String>,
    pub old_versions: Vec<String>,
    pub incremental: u32,
    /// An older PDF revision really differs from the next one (Info values or page text):
    /// Word and online converters write empty or identical increments, a fact, not a finding.
    pub revisions_differ: bool,
    pub is_pdf: bool,
    pub gps: Option<(f64, f64)>,
    pub camera: Option<String>,
    pub thumb_diff: bool,
    pub has_macros: bool,
    pub macros: Vec<String>,
    pub hidden_sheets: Vec<String>,
    pub has_js: bool,
    pub rdp: Option<DocRdp>,
    /// Forensic facts.
    pub fx: forensic::Fx,
}

const COLORS: &[&str] = &[
    "#2563eb", "#0d9488", "#dc2626", "#c026d3", "#ea580c", "#65a30d", "#7c3aed", "#0891b2",
    "#64748b", "#db2777", "#0f766e", "#9333ea", "#b45309", "#4f46e5",
];

fn role_str(r: PersonRole) -> &'static str {
    match r {
        PersonRole::Author => "author",
        PersonRole::LastModifiedBy => "last_modified_by",
        PersonRole::Creator => "creator",
        PersonRole::Comment => "comment",
        PersonRole::Revision => "revision",
        PersonRole::PathUser => "path_user",
        PersonRole::Account => "account",
        PersonRole::Owner => "owner",
        PersonRole::PrintedBy => "printed_by",
        PersonRole::Other => "other",
    }
}

/// Splits a field holding several authors: `Travis Ferrell;MMildenberg@example.com` yields
/// two spellings.
fn split_names(s: &str) -> impl Iterator<Item = &str> {
    s.split(';').map(str::trim).filter(|x| !x.is_empty())
}

/// Returns `true` for a plausible name or login spelling; filters out phrases such as
/// "I wrote it" or "(c) 2024 Company".
fn plausible_name(raw: &str) -> bool {
    let s = raw.trim();
    if s.is_empty() || s.chars().count() > 64 || s.contains("://") || s.contains('\u{fffd}') {
        return false;
    }
    let words: Vec<&str> = s.split_whitespace().collect();
    if words.len() > 4 {
        return false;
    }
    if words.len() > 1 {
        let s2 = s.trim_start_matches(|c: char| !c.is_alphabetic());
        let body = s2
            .split_once(':')
            .map(|(_, b)| b.trim())
            .filter(|_| s2.to_lowercase().starts_with("author"))
            .unwrap_or(s2);
        if body.chars().any(|c| c.is_ascii_digit()) {
            return false;
        }
        // Every word of a name is capitalized (or an initial).
        return body.split_whitespace().all(|w| {
            w.chars()
                .find(|c| c.is_alphabetic())
                .is_some_and(char::is_uppercase)
        }) || people::is_service(s);
    }
    true
}

/// People with the `other` role that are real identities: signers of signatures, e-mail
/// senders/recipients, calendar organizers/attendees, contacts and pivot cache refreshers.
fn counted_other(source: &str) -> bool {
    [
        "signature:",
        "eml:",
        "msg:",
        "ics:",
        "vcf:",
        "xl:pivotCache",
    ]
    .iter()
    .any(|p| source.starts_with(p))
}

/// `Olena Kovalenko <o.kovalenko@example.com>` → `Olena Kovalenko` (the address is in
/// `Metadata::emails`).
fn strip_addr(s: &str) -> &str {
    match s.find('<') {
        Some(i) if i > 0 && s.trim_end().ends_with('>') => s[..i].trim().trim_matches('"'),
        _ => s,
    }
}

fn doc_key(d: &Document) -> String {
    if !d.sha256.is_empty() {
        d.sha256.clone()
    } else if let Some(u) = &d.url {
        u.clone()
    } else {
        format!("id:{}", d.id)
    }
}

fn status_str(s: DocStatus) -> &'static str {
    match s {
        DocStatus::Analyzed => "analyzed",
        DocStatus::Downloaded => "downloaded",
        DocStatus::Queued | DocStatus::Downloading => "queued",
        DocStatus::Error | DocStatus::Skipped => "error",
    }
}

fn now_iso(now: OffsetDateTime) -> String {
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}",
        now.year(),
        u8::from(now.month()),
        now.day(),
        now.hour(),
        now.minute(),
        now.second()
    )
}

fn fields_rdp(meta: &Metadata) -> Option<DocRdp> {
    let f = &meta.fields;
    match meta.format {
        DocFormat::Rdp => Some(DocRdp {
            full_address: f.get("rdp:full address").cloned().unwrap_or_default(),
            username: f.get("rdp:username").cloned().unwrap_or_default(),
            gateway: f.get("rdp:gatewayhostname").cloned().unwrap_or_default(),
        }),
        DocFormat::Ica => {
            let pick = |suffix: &str| {
                f.iter()
                    .find(|(k, _)| k.ends_with(suffix) && !k.starts_with("ica:WFClient"))
                    .map(|(_, v)| v.clone())
                    .unwrap_or_default()
            };
            Some(DocRdp {
                full_address: pick(".Address"),
                username: pick(".Username"),
                gateway: f
                    .get("ica:WFClient.HttpBrowserAddress")
                    .cloned()
                    .unwrap_or_default(),
            })
        }
        _ => None,
    }
}

/// Returns the document folder: the directory of the first path, without the file name.
fn folder_of(meta: &Metadata) -> Option<String> {
    let p = meta.paths.first()?;
    let mut path = p.path.strip_prefix("file://").unwrap_or(&p.path);
    // `file:///C:\…` and `file:///\\srv\…` lose the leading slash.
    let b = path.as_bytes();
    if b.len() > 3 && b[0] == b'/' && (b[2] == b':' || path[1..].starts_with("\\\\")) {
        path = &path[1..];
    }
    let sep = if path.contains('\\') { '\\' } else { '/' };
    let last = path.rsplit(sep).next().unwrap_or("");
    if last.contains('.') && path.len() > last.len() + 1 {
        Some(path[..path.len() - last.len() - 1].to_string())
    } else {
        Some(path.to_string())
    }
}

/// Metadata strings searched for secrets, as (location, text) pairs.
fn meta_texts(meta: &Metadata) -> Vec<(String, String)> {
    let mut v: Vec<(String, String)> = Vec::new();
    let mut push = |place: String, s: &str| {
        if s.len() >= 6 {
            v.push((place, s.to_string()));
        }
    };
    for (k, s) in [
        ("title", &meta.title),
        ("subject", &meta.subject),
        ("description", &meta.description),
        ("keywords", &meta.keywords),
        ("category", &meta.category),
    ] {
        if let Some(s) = s {
            push(format!("поле {k}"), s);
        }
    }
    for c in &meta.comments {
        push(format!("комментарий ({})", c.source), &c.text);
    }
    for r in &meta.revisions {
        push("исправление".into(), &r.text);
    }
    for (k, s) in &meta.custom {
        push(format!("поле custom:{k}"), &format!("{k}: {s}"));
    }
    for (k, s) in &meta.fields {
        let kl = k.to_lowercase();
        if kl.contains("password") || kl.contains("rsid") || s.len() > 4096 {
            continue;
        }
        push(format!("поле {k}"), s);
    }
    v
}

struct Pre<'a> {
    inp: &'a DocInput<'a>,
    meta: Option<&'a Metadata>,
    analyzed: bool,
    key: String,
    host: String,
    sw: Vec<SwMatch>,
    os: Option<SwMatch>,
    hits: Vec<secrets::SecretHit>,
    text_emails: Vec<String>,
}

/// Runs the analysis.
pub fn analyze(inputs: &[DocInput], scope: &Scope, prev: &PrevState) -> Analysis {
    let now = prev.now.unwrap_or_else(OffsetDateTime::now_utc);
    let now_s = now_iso(now);
    let today = now_s[..10].to_string();
    let sigs = Signatures::builtin();
    let rules = secrets::Rules::builtin();

    // Per document: software, OS, secrets, addresses.
    let mut pre: Vec<Pre> = inputs
        .iter()
        .map(|inp| {
            let d = inp.doc;
            let meta = d.metadata.as_ref();
            let analyzed = !inp.deleted && d.status == DocStatus::Analyzed && meta.is_some();
            // A storage provider (Google Drive, OneDrive, Dropbox...) is never a target host: a file
            // whose linking site is unknown gets no host rather than the provider's.
            let host = d
                .host
                .clone()
                // local files (`file://report.pdf`) have no web host
                .or_else(|| {
                    d.url
                        .as_deref()
                        .filter(|u| !u.trim_start().to_ascii_lowercase().starts_with("file:"))
                        .and_then(util::url_host)
                })
                .filter(|h| !util::is_storage_provider(h))
                .unwrap_or_default();
            let mut p = Pre {
                inp,
                meta,
                analyzed,
                key: doc_key(d),
                host,
                sw: vec![],
                os: None,
                hits: vec![],
                text_emails: vec![],
            };
            if let (true, Some(m)) = (analyzed, meta) {
                for c in software::candidates(m) {
                    if let Some(s) = sigs.match_software(&c) {
                        // One device, one entry (iOS 16.6, not an extra "Apple iPhone").
                        let dup_cam = s.kind == "camera" && p.sw.iter().any(|x| x.kind == "camera");
                        // The version is already known ("Word 2008 for Mac"), so the generic entry is redundant.
                        let generic =
                            p.sw.iter()
                                .any(|x| x.kind == s.kind && x.id.starts_with(&s.id));
                        if !dup_cam && !generic {
                            p.sw.push(s);
                        }
                    }
                }
                p.os = software::os_candidates(m)
                    .iter()
                    .find_map(|c| sigs.match_os(c));
                let mut hits: Vec<secrets::SecretHit> = Vec::new();
                let skip_text = matches!(m.format, DocFormat::Rdp | DocFormat::Ica);
                if let (Some(t), false) = (inp.text, skip_text) {
                    hits.extend(rules.scan(t, "текст"));
                    p.text_emails = emails::find_in_text(t);
                }
                for (place, t) in meta_texts(m) {
                    for h in rules.scan(&t, &place) {
                        if !hits.iter().any(|x| x.value == h.value) {
                            hits.push(h);
                        }
                    }
                }
                let rdp_host = fields_rdp(m)
                    .map(|r| util::strip_port(&r.full_address).to_string())
                    .filter(|h| !h.is_empty());
                for s in &m.secrets {
                    let (title, sev) = match s.kind.as_str() {
                        "ica_clearpassword" => {
                            ("Пароль в открытом виде в .ica-файле", Severity::Critical)
                        }
                        "rdp_password_51" => ("Сохранённый пароль в .rdp-файле", Severity::High),
                        "connection_password" => {
                            ("Пароль в строке подключения к данным", Severity::High)
                        }
                        _ => ("Пароль в метаданных", Severity::High),
                    };
                    hits.retain(|h| h.value.expose() != s.value);
                    hits.push(secrets::SecretHit {
                        rule: s.kind.clone(),
                        title: title.into(),
                        kind: "pass".into(),
                        sev,
                        value: SecretValue::new(s.value.clone()),
                        context: format!(
                            "{}: {{{{s:{}}}}}",
                            s.source,
                            foca_core::api::escape_secret_marker(&s.value)
                        ),
                        location: format!("поле {}", s.source),
                        host: rdp_host.clone(),
                        entropy: secrets::entropy(&s.value),
                    });
                }
                p.hits = hits;
            }
            p
        })
        .collect();
    pre.sort_by_key(|p| p.inp.doc.id);

    // People.
    let mut idents: Vec<people::Identity> = Vec::new();
    let mut occ: Vec<emails::Occurrence> = Vec::new();
    for p in pre.iter().filter(|p| p.analyzed) {
        let Some(m) = p.meta else { continue };
        let id = p.inp.doc.id;
        for pr in &m.people {
            let name = strip_addr(&pr.name);
            if pr.role == PersonRole::Other
                && (!counted_other(&pr.source)
                    || !name.chars().next().is_some_and(char::is_alphabetic))
            {
                continue;
            }
            for n in split_names(name).filter(|n| plausible_name(n)) {
                idents.push(people::Identity::new(
                    n,
                    id,
                    people::IdentSource::Meta,
                    role_str(pr.role),
                ));
            }
        }
        for (s, role) in [
            (&m.author, "author"),
            (&m.last_modified_by, "last_modified_by"),
        ] {
            for s in s.as_deref().into_iter().flat_map(split_names) {
                if plausible_name(s) {
                    idents.push(people::Identity::new(
                        s,
                        id,
                        people::IdentSource::Meta,
                        role,
                    ));
                }
            }
        }
        if let Some(o) = m.camera.as_ref().and_then(|c| c.owner.as_deref()) {
            idents.push(people::Identity::new(
                o,
                id,
                people::IdentSource::Meta,
                "owner",
            ));
        }
        // Word reviewers: `people:<name>` holds the account from word/people.xml; its AD address
        // belongs to that person.
        for (k, v) in &m.fields {
            let Some(name) = k.strip_prefix("people:").filter(|n| plausible_name(n)) else {
                continue;
            };
            if let Some(e) = people::presence_email(v).filter(|e| emails::valid_addr(e)) {
                idents.push(
                    people::Identity::new(&e, id, people::IdentSource::Meta, "email")
                        .with_link(name),
                );
                occ.push(emails::Occurrence {
                    addr: e,
                    doc: id,
                    src: "Метаданные документа".into(),
                });
            }
        }
        for e in &m.emails {
            let e = e.to_lowercase();
            if emails::valid_addr(&e) {
                occ.push(emails::Occurrence {
                    addr: e,
                    doc: id,
                    src: "Метаданные документа".into(),
                });
            }
        }
        for e in &p.text_emails {
            occ.push(emails::Occurrence {
                addr: e.clone(),
                doc: id,
                src: "Текст документа".into(),
            });
        }
    }
    let meta_addrs: BTreeSet<&str> = occ
        .iter()
        .filter(|o| o.src.starts_with("Метаданные"))
        .map(|o| o.addr.as_str())
        .collect();
    for o in &occ {
        if !emails::is_role(&o.addr) {
            let src = if meta_addrs.contains(o.addr.as_str()) {
                people::IdentSource::Meta
            } else {
                people::IdentSource::Text
            };
            idents.push(people::Identity::new(&o.addr, o.doc, src, "email"));
        }
    }
    let resolved = people::resolve(&idents);
    let keep: BTreeSet<usize> = resolved
        .clusters
        .iter()
        .enumerate()
        .filter(|(_, c)| {
            !c.email_only
                || matches!(
                    c.best_shape,
                    Some(people::Shape::Full) | Some(people::Shape::Partial)
                )
        })
        .map(|(i, _)| i)
        .collect();
    let login_of = |raw: &str| -> Option<String> {
        let i = *resolved.by_key.get(&people::ident_key(raw))?;
        keep.contains(&i)
            .then(|| resolved.clusters[i].login.clone())
    };

    // Hosts and computers.
    let mut mentions: Vec<hosts::Mention> = Vec::new();
    let mut doc_people: BTreeMap<u64, Vec<String>> = BTreeMap::new();
    for p in &pre {
        let id = p.inp.doc.id;
        let fs = p.inp.first_scan.map(str::to_string);
        if !p.host.is_empty() && !p.inp.deleted {
            mentions.push(hosts::Mention {
                name: p.host.clone(),
                source: hosts::HostSource::DocUrl,
                doc: id,
                users: vec![],
                port: None,
                first_scan: fs.clone(),
            });
        }
        let (true, Some(m)) = (p.analyzed, p.meta) else {
            continue;
        };
        let mut users: Vec<String> = Vec::new();
        for pr in &m.people {
            if let Some(l) = login_of(&pr.name) {
                if !users.contains(&l) {
                    users.push(l);
                }
            }
        }
        if let Some(o) = m.camera.as_ref().and_then(|c| c.owner.as_deref()) {
            if let Some(l) = login_of(o) {
                if !users.contains(&l) {
                    users.push(l);
                }
            }
        }
        for e in m.emails.iter().chain(p.text_emails.iter()) {
            if let Some(l) = login_of(e) {
                if !users.contains(&l) {
                    users.push(l);
                }
            }
        }
        // Logins associated with computers: only authors, owners and accounts.
        let owners: Vec<String> = m
            .people
            .iter()
            .filter(|pr| {
                matches!(
                    pr.role,
                    PersonRole::Author
                        | PersonRole::Owner
                        | PersonRole::Account
                        | PersonRole::Creator
                )
            })
            .filter_map(|pr| login_of(&pr.name))
            .chain(
                m.camera
                    .as_ref()
                    .and_then(|c| c.owner.as_deref())
                    .and_then(login_of),
            )
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        doc_people.insert(id, users);
        let mut push = |name: &str, source: hosts::HostSource, users: Vec<String>| {
            mentions.push(hosts::Mention {
                name: name.to_string(),
                source,
                doc: id,
                users,
                port: None,
                first_scan: fs.clone(),
            });
        };
        for pa in &m.paths {
            if let Some(h) = &pa.host {
                push(h, hosts::HostSource::Path, vec![]);
            }
        }
        for pr in &m.printers {
            if let Some(h) = util::printer_host(pr) {
                push(&h, hosts::HostSource::Printer, vec![]);
            }
        }
        for s in &m.servers {
            let src = if s.source.contains("HostComputer") || s.source.contains("Tag(Tiff, 316)") {
                hosts::HostSource::HostComputer
            } else if s.source.starts_with("rdp:") {
                hosts::HostSource::Rdp
            } else if s.source.starts_with("ica:") {
                hosts::HostSource::Ica
            } else if s.source == "path" {
                hosts::HostSource::Path
            } else {
                hosts::HostSource::Server
            };
            let u = match src {
                hosts::HostSource::HostComputer
                | hosts::HostSource::Rdp
                | hosts::HostSource::Ica => owners.clone(),
                _ => vec![],
            };
            // RDP/ICA addresses keep the port from the field.
            let raw = if matches!(src, hosts::HostSource::Rdp | hosts::HostSource::Ica) {
                m.fields
                    .iter()
                    .find(|(k, v)| {
                        (k.ends_with("full address") || k.ends_with(".Address"))
                            && util::strip_port(v).eq_ignore_ascii_case(&s.name)
                    })
                    .map(|(_, v)| v.clone())
                    .unwrap_or_else(|| s.name.clone())
            } else {
                s.name.clone()
            };
            push(&raw, src, u);
        }
        for l in &m.links {
            let ll = l.to_ascii_lowercase();
            if ll.starts_with("http://") || ll.starts_with("https://") || ll.starts_with("ftp://") {
                if let Some(h) = util::url_host(l) {
                    push(&h, hosts::HostSource::Link, vec![]);
                }
            }
        }
        for h in &p.hits {
            if let Some(hn) = &h.host {
                push(hn, hosts::HostSource::Secret, vec![]);
            }
        }
    }
    let hres = hosts::build(&mentions, scope, prev.scan_id.as_deref());
    // Host names per document (for the facts).
    let mut doc_pcs: BTreeMap<u64, BTreeSet<String>> = BTreeMap::new();
    let mut doc_servers: BTreeMap<u64, BTreeSet<String>> = BTreeMap::new();
    let mut doc_path_hosts: BTreeMap<u64, BTreeSet<String>> = BTreeMap::new();
    for m in &mentions {
        if m.source == hosts::HostSource::DocUrl {
            continue;
        }
        let Some((name, _, kind)) = hosts::normalize(&m.name) else {
            continue;
        };
        match kind {
            hosts::NameKind::NetBios => {
                doc_pcs.entry(m.doc).or_default().insert(name.clone());
                if hres.hosts.iter().any(|h| h.name == name) {
                    doc_servers.entry(m.doc).or_default().insert(name.clone());
                }
            }
            hosts::NameKind::Ip { private: true } | hosts::NameKind::Fqdn { internal: true } => {
                doc_servers.entry(m.doc).or_default().insert(name.clone());
            }
            _ => {}
        }
        if m.source == hosts::HostSource::Path {
            doc_path_hosts.entry(m.doc).or_default().insert(name);
        }
    }

    // People → Person.
    let mut persons: Vec<Person> = Vec::new();
    for (n, &i) in keep.iter().enumerate() {
        let c = &resolved.clusters[i];
        persons.push(Person {
            login: c.login.clone(),
            name: c.name.clone(),
            role: if c.service {
                "Служебная учётная запись".into()
            } else if people::is_reviewer(&c.roles) {
                // Only comments or revisions in other people's documents.
                "Рецензент".into()
            } else {
                String::new()
            },
            pc: hres.person_pc.get(&c.login).cloned(),
            color: COLORS[n % COLORS.len()].into(),
            src: if c.from_meta {
                "Метаданные документов".into()
            } else {
                "Текст документа".into()
            },
            src_kind: if c.from_meta { "meta" } else { "text" }.into(),
            docs: c.docs.len() as u32,
            src_doc: (!c.from_meta)
                .then(|| c.docs.iter().next().copied())
                .flatten(),
            aliases: c.aliases.clone(),
            service: c.service,
            emails: c.emails.clone(),
            ..Default::default()
        });
    }

    // ---------- 5. e-mail ----------
    let eres = emails::build(&occ, &resolved, &keep, scope);

    // Software and OS.
    let mut sw_agg: BTreeMap<String, (SwMatch, BTreeSet<u64>, Option<String>)> = BTreeMap::new();
    let mut os_agg: BTreeMap<String, (SwMatch, BTreeSet<u64>)> = BTreeMap::new();
    for p in pre.iter().filter(|p| p.analyzed) {
        let cam = p.meta.and_then(software::camera_label);
        for s in &p.sw {
            let e = sw_agg
                .entry(s.id.clone())
                .or_insert_with(|| (s.clone(), BTreeSet::new(), None));
            e.1.insert(p.inp.doc.id);
            if s.kind == "camera" && e.2.is_none() {
                e.2 = cam.clone();
            }
        }
        if let Some(o) = &p.os {
            os_agg
                .entry(o.id.clone())
                .or_insert_with(|| (o.clone(), BTreeSet::new()))
                .1
                .insert(p.inp.doc.id);
        }
    }
    let mut software_list: Vec<api::Software> = sw_agg
        .into_values()
        .map(|(m, docs, dev)| api::Software {
            eol: m.is_eol(&today),
            id: m.id,
            name: m.name,
            ver: m.ver,
            kind: m.kind,
            released: m.released,
            eol_date: m.eol_date,
            cve: 0,
            cves: vec![],
            dev,
            docs: docs.len() as u32,
            cpe: m.cpe,
            side: m.side,
            last_doc: None,
            cve_sum: None,
        })
        .collect();
    software_list.sort_by(|a, b| b.docs.cmp(&a.docs).then(a.id.cmp(&b.id)));
    let mut os_list: Vec<OsInfo> = os_agg
        .into_values()
        .map(|(m, docs)| OsInfo {
            eol: m.is_eol(&today),
            id: m.id,
            name: m.name,
            ver: m.ver,
            released: m.released,
            eol_date: m.eol_date,
            docs: docs.len() as u32,
            cpe: m.cpe,
            last_doc: None,
            cve_sum: None,
        })
        .collect();
    os_list.sort_by(|a, b| b.docs.cmp(&a.docs).then(a.id.cmp(&b.id)));
    let eol_ids: BTreeSet<&str> = software_list
        .iter()
        .filter(|s| s.eol)
        .map(|s| s.id.as_str())
        .chain(os_list.iter().filter(|o| o.eol).map(|o| o.id.as_str()))
        .collect();

    // Paths and printers.
    type PathAgg = (BTreeSet<u64>, Option<String>, Option<String>);
    let mut path_agg: BTreeMap<String, PathAgg> = BTreeMap::new();
    let mut prn_agg: BTreeMap<String, BTreeSet<u64>> = BTreeMap::new();
    for p in pre.iter().filter(|p| p.analyzed) {
        let Some(m) = p.meta else { continue };
        for pa in &m.paths {
            let e = path_agg.entry(pa.path.clone()).or_insert_with(|| {
                (
                    BTreeSet::new(),
                    pa.user.as_deref().and_then(login_of),
                    pa.host.clone(),
                )
            });
            e.0.insert(p.inp.doc.id);
        }
        for pr in &m.printers {
            prn_agg.entry(pr.clone()).or_default().insert(p.inp.doc.id);
        }
    }
    let mut paths: Vec<PathItem> = path_agg
        .into_iter()
        .map(|(path, (docs, user, host))| PathItem {
            path,
            docs: docs.len() as u32,
            user,
            host,
        })
        .collect();
    paths.sort_by(|a, b| b.docs.cmp(&a.docs).then(a.path.cmp(&b.path)));
    let mut printers: Vec<Printer> = prn_agg
        .into_iter()
        .map(|(name, docs)| Printer {
            host: util::printer_host(&name),
            name,
            docs: docs.len() as u32,
        })
        .collect();
    printers.sort_by(|a, b| b.docs.cmp(&a.docs).then(a.name.cmp(&b.name)));

    // Secrets.
    let mut secret_recs: Vec<findings::SecretRec> = Vec::new();
    for p in pre.iter().filter(|p| p.analyzed) {
        for h in &p.hits {
            secret_recs.push(findings::SecretRec {
                secret: Secret {
                    id: util::stable_id(&["secret", &p.key, &h.rule, h.value.expose()]),
                    kind: h.kind.clone(),
                    value: h.value.clone(),
                    doc: p.inp.doc.id,
                    location: h.location.clone(),
                    sev: h.sev,
                    host: h.host.clone(),
                    finding: None,
                    rule: h.rule.clone(),
                },
                title: h.title.clone(),
                context: h.context.clone(),
            });
        }
    }

    // Documents and facts.
    let mut docs_out: Vec<Doc> = Vec::with_capacity(pre.len());
    let mut facts: Vec<DocFacts> = Vec::with_capacity(pre.len());
    let secret_docs: BTreeSet<u64> = secret_recs.iter().map(|s| s.secret.doc).collect();
    for p in &pre {
        let d = p.inp.doc;
        let ext = if d.ext.is_empty() {
            p.meta
                .map(|m| m.format.ext().to_string())
                .unwrap_or_default()
        } else {
            d.ext.to_lowercase()
        };
        let mut out = Doc {
            id: d.id,
            ext,
            name: d.name.clone(),
            url: d.url.clone().unwrap_or_default(),
            host: p.host.clone(),
            title: p.meta.and_then(|m| m.title.clone()).unwrap_or_else(|| {
                d.name
                    .rsplit_once('.')
                    .map(|(a, _)| a.to_string())
                    .unwrap_or_else(|| d.name.clone())
            }),
            size: d.size.div_ceil(1024),
            first_scan: p.inp.first_scan.map(str::to_string),
            deleted: p.inp.deleted,
            status: status_str(d.status).into(),
            ..Default::default()
        };
        let mut f = DocFacts {
            id: d.id,
            key: p.key.clone(),
            name: d.name.clone(),
            url: d.url.clone(),
            host: p.host.clone(),
            analyzed: p.analyzed,
            first_scan: p.inp.first_scan.map(str::to_string),
            ..Default::default()
        };
        if let (true, Some(m)) = (p.analyzed, p.meta) {
            let who = |raw: &str| login_of(raw).unwrap_or_else(|| raw.to_string());
            out.author = m.author.as_deref().and_then(login_of);
            out.last_modified_by = m.last_modified_by.as_deref().and_then(login_of);
            out.software = p.sw.first().map(|s| s.id.clone());
            out.created_at = m.created.as_deref().and_then(util::local_iso);
            out.modified_at = m.modified.as_deref().and_then(util::local_iso);
            out.folder = folder_of(m);
            out.printer = m.printers.first().cloned();
            out.company = m.company.clone();
            out.camera = software::camera_label(m);
            out.gps = m.gps.map(|g| DocGps {
                lat: g.lat,
                lon: g.lon,
                place: format!("{:.4}, {:.4}", g.lat, g.lon),
            });
            for r in &m.revisions {
                let kind = match r.kind {
                    RevisionKind::Delete => "del",
                    RevisionKind::Insert => "ins",
                    _ => continue,
                };
                out.revisions.push(DocRevision {
                    kind: kind.into(),
                    who: r.author.as_deref().map(who),
                    at: r.date.as_deref().and_then(util::local_iso),
                    text: r.text.clone(),
                });
            }
            for c in &m.comments {
                out.revisions.push(DocRevision {
                    kind: "com".into(),
                    who: c.author.as_deref().map(who),
                    at: c.date.as_deref().and_then(util::local_iso),
                    text: c.text.clone(),
                });
            }
            out.rdp = fields_rdp(m);
            // Only a real pixel difference (foca-meta) or an explicit result from the caller. The
            // "edited in Photoshop" heuristic flagged almost every photo as High.
            out.thumb_diff = p
                .inp
                .thumb_diff
                .or(m.thumbnail.as_ref().and_then(|t| t.differs))
                .unwrap_or(false);
            let has_internal = !m.paths.is_empty()
                || doc_pcs.contains_key(&d.id)
                || doc_servers.contains_key(&d.id);
            let mut flags = Vec::new();
            if has_internal {
                flags.push("path");
            }
            if secret_docs.contains(&d.id) {
                flags.push("secret");
            }
            if p.sw.iter().any(|s| eol_ids.contains(s.id.as_str()))
                || p.os
                    .as_ref()
                    .is_some_and(|o| eol_ids.contains(o.id.as_str()))
            {
                flags.push("eol");
            }
            if out.gps.is_some() {
                flags.push("gps");
            }
            if !out.revisions.is_empty() {
                flags.push("revisions");
            }
            out.flags = flags.into_iter().map(str::to_string).collect();

            f.author = out.author.clone();
            f.last_modified_by = out.last_modified_by.clone();
            f.people = doc_people.get(&d.id).cloned().unwrap_or_default();
            f.pcs = doc_pcs
                .get(&d.id)
                .map(|s| s.iter().cloned().collect())
                .unwrap_or_default();
            f.servers = doc_servers
                .get(&d.id)
                .map(|s| s.iter().cloned().collect())
                .unwrap_or_default();
            f.paths = m.paths.iter().map(|p| p.path.clone()).collect();
            f.path_hosts = doc_path_hosts
                .get(&d.id)
                .map(|s| s.iter().cloned().collect())
                .unwrap_or_default();
            f.printers = m.printers.clone();
            f.software = p.sw.iter().map(|s| s.id.clone()).collect();
            f.os = p.os.as_ref().map(|o| o.id.clone());
            f.created = out.created_at.clone();
            f.modified = out.modified_at.clone();
            f.offsets = [&m.created, &m.modified]
                .into_iter()
                .flatten()
                .filter_map(|s| util::offset_minutes(s))
                .collect();
            f.revision_people = out
                .revisions
                .iter()
                .filter_map(|r| r.who.clone())
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect();
            f.revisions = out.revisions.clone();
            f.old_versions = m
                .old_versions
                .iter()
                .map(|v| {
                    let mut kv: Vec<String> = v
                        .fields
                        .iter()
                        .filter(|(k, _)| {
                            matches!(
                                k.as_str(),
                                "Author" | "Title" | "Creator" | "Producer" | "Company" | "Subject"
                            ) || k.contains("creator")
                                || k.contains("Author")
                        })
                        .map(|(k, v)| format!("{k}: {v}"))
                        .collect();
                    kv.sort();
                    format!("ревизия {}: {}", v.revision, kv.join("; "))
                })
                .collect();
            f.incremental = m.incremental_updates.unwrap_or(0);
            f.revisions_differ = revisions_differ(m);
            f.is_pdf = m.format == DocFormat::Pdf;
            f.gps = m.gps.map(|g| (g.lat, g.lon));
            f.camera = out.camera.clone();
            f.thumb_diff = out.thumb_diff;
            f.has_macros = m.has_macros;
            f.macros = m.macro_modules.clone();
            f.hidden_sheets = m.hidden_sheets.clone();
            f.has_js = m.has_javascript;
            f.rdp = out.rdp.clone();
            f.fx = forensic::facts(m, &d.name, p.inp.text, prev.rules.as_ref());
            if f.fx.any() {
                out.flags.push("forensic".into());
            }
            if f.fx
                .pii
                .iter()
                .any(|x| x.kind != "marking" && x.kind != "edrpou")
            {
                out.flags.push("pii".into());
            }
            if m.format == DocFormat::Lnk {
                let g = |k: &str| m.fields.get(k).cloned().unwrap_or_default();
                let target = [g("lnk:local_base_path"), g("lnk:network_path")]
                    .into_iter()
                    .find(|x| !x.is_empty())
                    .unwrap_or_default();
                out.lnk = Some(api::DocLnk {
                    machine: g("lnk:machine_id"),
                    mac: g("lnk:mac"),
                    volume_serial: g("lnk:volume_serial"),
                    target_dir: target
                        .rsplit_once('\\')
                        .map(|(a, _)| a.to_string())
                        .unwrap_or_default(),
                    target,
                });
            }
        }
        docs_out.push(out);
        facts.push(f);
    }

    // Findings.
    let fctx = findings::Ctx {
        docs: &facts,
        people: &persons,
        software: &software_list,
        os: &os_list,
        secrets: &secret_recs,
        patterns: &eres.patterns,
        now: &now_s,
        prev,
    };
    let findings_list = findings::build(&fctx);
    let fids: BTreeSet<u64> = findings_list.iter().map(|f| f.id).collect();
    let key_of: BTreeMap<u64, &str> = facts.iter().map(|f| (f.id, f.key.as_str())).collect();
    let mut secrets_out: Vec<Secret> = secret_recs
        .into_iter()
        .map(|mut r| {
            if let Some(k) = key_of.get(&r.secret.doc) {
                let fid = findings::secret_finding_id(&r.secret, k);
                if fids.contains(&fid) {
                    r.secret.finding = Some(fid);
                }
            }
            r.secret
        })
        .collect();
    secrets_out.sort_by(|a, b| {
        a.sev
            .cmp(&b.sev)
            .then(a.doc.cmp(&b.doc))
            .then(a.id.cmp(&b.id))
    });

    // Host severity follows the active findings.
    let mut hosts_out = hres.hosts;
    for h in &mut hosts_out {
        if let Some(s) = findings_list
            .iter()
            .filter(|f| {
                f.host == h.name
                    && !matches!(
                        f.status,
                        FindingStatus::FalsePositive | FindingStatus::Fixed
                    )
            })
            .map(|f| f.sev)
            .min()
        {
            h.sev = util::sev_name(s).into();
        }
    }

    // GPS, timeline, graph, risk.
    let gps: Vec<GpsPoint> = docs_out
        .iter()
        .filter(|d| d.gps.is_some() && !d.deleted)
        .map(|d| {
            let g = d.gps.clone().unwrap_or(DocGps {
                lat: 0.0,
                lon: 0.0,
                place: String::new(),
            });
            GpsPoint {
                doc: d.id,
                name: d.name.clone(),
                lat: g.lat,
                lon: g.lon,
                place: g.place,
                dev: d.camera.clone().unwrap_or_else(|| "-".into()),
                taken_at: d.created_at.clone(),
            }
        })
        .collect();
    let events = timeline::events(&facts, &software_list, &printers);
    let activity = timeline::activity(&facts);
    let graph = relations::build(&facts, &persons, &software_list, &eres.emails);
    let has_data = !inputs.is_empty() || prev.scan_id.is_some();
    let risk = findings::risk(&findings_list, has_data);
    let resolved_ids: Vec<u64> = prev
        .findings
        .iter()
        .filter(|(id, p)| {
            !fids.contains(id)
                && !matches!(
                    p.status,
                    FindingStatus::Fixed | FindingStatus::FalsePositive
                )
        })
        .map(|(id, _)| *id)
        .collect();

    Analysis {
        docs: docs_out,
        people: persons,
        emails: eres.emails,
        patterns: eres.patterns,
        hosts: hosts_out,
        pcs: hres.pcs,
        software: software_list,
        os: os_list,
        paths,
        printers,
        secrets: secrets_out,
        findings: findings_list,
        gps,
        events,
        graph,
        activity,
        risk,
        resolved: resolved_ids,
        dropped: vec![],
        facts,
    }
}

impl Analysis {
    /// Returns the triage of the current findings for the next [`analyze`] call.
    pub fn prev_state(&self, scan_id: Option<String>, now: Option<OffsetDateTime>) -> PrevState {
        PrevState {
            findings: self
                .findings
                .iter()
                .map(|f| {
                    (
                        f.id,
                        PrevFinding {
                            status: f.status,
                            sev: None,
                            notes: f.notes.clone(),
                            tags: f.tags.clone(),
                            photos: f.photos.clone(),
                            first_scan: f.first_scan.clone(),
                            fixed_scan: f.fixed_scan.clone(),
                            time: Some(f.time.clone()),
                        },
                    )
                })
                .collect(),
            scan_id,
            now,
            rules: None,
        }
    }
}

#[cfg(test)]
mod tests;
