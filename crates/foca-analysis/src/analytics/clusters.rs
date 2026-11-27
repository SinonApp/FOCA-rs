//! Same-author and same-machine clusters: documents that share a trace of where they were
//! made, beyond the document lineage of [`crate::correlate`] (which covers RSID and XMP ids).
//!
//! Traces:
//! * `template`: the same attached template given as a full path (a bare `Normal.dotm` is
//!   shared by everyone and ignored);
//! * `build_folder`: the same project folder in PDB paths of executables;
//! * `printer_author`: the same printer together with the same author;
//! * `camera_serial`: the same camera body (make and serial number).
//!
//! Values seen in a large share of a big project are dropped (a corporate template on every
//! file says little about one author). Pure and deterministic.

use std::collections::{BTreeMap, BTreeSet};

use foca_core::Metadata;
use serde::Serialize;

use crate::DocInput;

/// Documents per value above which a trace is considered generic.
const MAX_DOCS: usize = 500;
/// Clusters returned.
const MAX_CLUSTERS: usize = 200;

/// A group of documents sharing one trace.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TraceCluster {
    /// Stable id: `kind:value` lowercased.
    pub id: String,
    /// `template`, `build_folder`, `printer_author`, `camera_serial`.
    pub kind: String,
    /// The shared value as shown to the user.
    pub value: String,
    pub docs: Vec<u64>,
}

/// Traces of one document as `(kind, display value)`.
pub fn traces(m: &Metadata) -> Vec<(&'static str, String)> {
    let mut out = Vec::new();
    if let Some(t) = m.template.as_deref() {
        if t.contains(['\\', '/']) && t.len() > 3 {
            out.push(("template", t.to_string()));
        }
    }
    for p in m.paths.iter().filter(|p| p.source == "pe:pdb") {
        if let Some(dir) = build_folder(&p.path) {
            out.push(("build_folder", dir));
        }
    }
    if let Some(a) = m.author.as_deref().filter(|a| !a.trim().is_empty()) {
        for pr in &m.printers {
            out.push(("printer_author", format!("{pr} / {a}")));
        }
    }
    if let Some(c) = &m.camera {
        if let Some(s) = c.serial.as_deref().filter(|s| s.len() >= 4) {
            let make = c.make.as_deref().unwrap_or("").trim();
            out.push(("camera_serial", format!("{make} {s}").trim().to_string()));
        }
    }
    out
}

/// The project folder of a PDB path: everything before `\obj\`, `\bin\`, `\x64\`, `\Release\`
/// or `\Debug\`, otherwise the parent directory.
pub fn build_folder(path: &str) -> Option<String> {
    let norm = path.replace('/', "\\");
    let lower = norm.to_ascii_lowercase();
    let cut = [
        "\\obj\\",
        "\\bin\\",
        "\\x64\\",
        "\\x86\\",
        "\\release\\",
        "\\debug\\",
    ]
    .iter()
    .filter_map(|m| lower.find(m))
    .min()
    .or_else(|| lower.rfind('\\'))?;
    let dir = norm[..cut].trim_end_matches('\\');
    (dir.len() > 3).then(|| dir.to_string())
}

/// Builds the clusters of live, analyzed documents.
pub fn clusters(inputs: &[DocInput]) -> Vec<TraceCluster> {
    let mut by: BTreeMap<(String, String), (String, BTreeSet<u64>)> = BTreeMap::new();
    let mut total = 0usize;
    for i in inputs.iter().filter(|i| !i.deleted) {
        let Some(m) = &i.doc.metadata else { continue };
        total += 1;
        for (kind, value) in traces(m) {
            let e = by
                .entry((kind.to_string(), value.to_lowercase()))
                .or_insert_with(|| (value.clone(), BTreeSet::new()));
            e.1.insert(i.doc.id);
        }
    }
    let mut out: Vec<TraceCluster> = by
        .into_iter()
        .filter(|(_, (_, d))| {
            d.len() >= 2 && d.len() <= MAX_DOCS && !(total >= 20 && d.len() * 2 > total)
        })
        .map(|((kind, low), (value, docs))| TraceCluster {
            id: format!("{kind}:{low}"),
            kind,
            value,
            docs: docs.into_iter().collect(),
        })
        .collect();
    out.sort_by(|a, b| b.docs.len().cmp(&a.docs.len()).then(a.id.cmp(&b.id)));
    out.truncate(MAX_CLUSTERS);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use foca_core::{Camera, DocStatus, Document, PathKind, PathRef};

    fn doc(id: u64, f: impl FnOnce(&mut Metadata)) -> Document {
        let mut m = Metadata::default();
        f(&mut m);
        Document {
            id,
            name: format!("d{id}"),
            ext: "docx".into(),
            url: None,
            host: None,
            source: String::new(),
            size: 1,
            sha256: String::new(),
            status: DocStatus::Analyzed,
            error: None,
            found_at: None,
            metadata: Some(m),
        }
    }

    #[test]
    fn folders_and_clusters() {
        assert_eq!(
            build_folder(r"C:\Users\dev\source\repos\Billing\obj\Release\Billing.pdb").as_deref(),
            Some(r"C:\Users\dev\source\repos\Billing")
        );
        assert_eq!(build_folder("x.pdb"), None);
        let pdb = |m: &mut Metadata, p: &str| {
            m.paths.push(PathRef {
                path: p.into(),
                kind: PathKind::Windows,
                user: None,
                host: None,
                source: "pe:pdb".into(),
            })
        };
        let docs = [
            doc(1, |m| pdb(m, r"C:\src\Tool\bin\Debug\Tool.pdb")),
            doc(2, |m| pdb(m, r"c:\src\tool\obj\x64\Release\Tool.Core.pdb")),
            doc(3, |m| {
                m.template = Some(r"\\fs01\templates\Letter.dotx".into());
                m.author = Some("Jane".into());
                m.printers = vec!["HP-3F".into()];
            }),
            doc(4, |m| {
                m.template = Some(r"\\FS01\Templates\Letter.dotx".into());
                m.author = Some("jane".into());
                m.printers = vec!["hp-3f".into()];
            }),
            doc(5, |m| m.template = Some("Normal.dotm".into())),
            doc(6, |m| m.template = Some("Normal.dotm".into())),
            doc(7, |m| {
                m.camera = Some(Camera {
                    make: Some("Canon".into()),
                    serial: Some("123456789".into()),
                    ..Default::default()
                })
            }),
            doc(8, |m| {
                m.camera = Some(Camera {
                    make: Some("Canon".into()),
                    serial: Some("123456789".into()),
                    ..Default::default()
                })
            }),
        ];
        let inputs: Vec<DocInput> = docs.iter().map(DocInput::new).collect();
        let c = clusters(&inputs);
        let kinds: Vec<(&str, Vec<u64>)> = c
            .iter()
            .map(|c| (c.kind.as_str(), c.docs.clone()))
            .collect();
        assert!(kinds.contains(&("build_folder", vec![1, 2])), "{kinds:?}");
        assert!(kinds.contains(&("template", vec![3, 4])));
        assert!(kinds.contains(&("printer_author", vec![3, 4])));
        assert!(kinds.contains(&("camera_serial", vec![7, 8])));
        assert_eq!(c.len(), 4, "bare Normal.dotm is not a trace");
    }
}
