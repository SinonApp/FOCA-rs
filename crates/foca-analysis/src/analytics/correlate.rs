//! Document correlation: copies, clones and derivatives of one document found
//! through Word editing-session ids (`w:rsids`) and XMP Media Management ids
//! (`xmpMM:DocumentID`, `InstanceID`, `OriginalDocumentID`, `DerivedFrom`, `History`).
//!
//! The result is a list of pairwise [`DocLink`]s with a confidence and a reason, plus
//! [`Lineage`] clusters (connected components of the confident links). Pure function over the
//! documents; deterministic and independent of input order.
//!
//! Rules against false links:
//! * a shared RSID set can also come from a common template, so RSID links say so and only a
//!   strict superset (the later file contains every session of the earlier one) becomes
//!   `derived_from`;
//! * ids that appear in too many documents (a generator writing a constant id) are ignored.

use std::collections::{BTreeMap, BTreeSet};

use foca_core::{DocStatus, Metadata};
use serde::Serialize;

use crate::relations::Edge;
use crate::DocInput;

/// Kind of a correlation link.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LinkKind {
    /// Same XMP document and instance id: the same saved state copied under another name.
    Copy,
    /// `from` was produced from `to` (`DerivedFrom`, an earlier instance in `History`, or a
    /// strict superset of Word editing sessions).
    DerivedFrom,
    /// Both files belong to one lineage (same `DocumentID`/`OriginalDocumentID`, or shared Word
    /// sessions without a clear direction).
    SameLineage,
}

impl LinkKind {
    pub fn as_str(self) -> &'static str {
        match self {
            LinkKind::Copy => "copy",
            LinkKind::DerivedFrom => "derived_from",
            LinkKind::SameLineage => "same_lineage",
        }
    }
}

/// A link between two documents. For `derived_from` the direction is `from` → `to`
/// (derivative → source); for the symmetric kinds `from < to`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DocLink {
    pub from: u64,
    pub to: u64,
    pub kind: LinkKind,
    /// 0-100.
    pub confidence: u8,
    /// Machine-readable basis: `xmp_derived_instance`, `xmp_derived_document`, `xmp_history`,
    /// `xmp_document_id`, `xmp_original_id`, `xmp_instance_id`, `rsid_superset`, `rsid_shared`.
    pub basis: String,
    /// Russian explanation for the card (the core language; reports translate by `basis`).
    pub reason: String,
    /// The matching ids (shortened RSID lists).
    pub evidence: Vec<String>,
}

/// A cluster of correlated documents.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Lineage {
    /// Stable id: `lineage:<smallest doc id>`.
    pub id: String,
    pub docs: Vec<u64>,
    /// Probable original: the document nothing in the cluster derives it from, the earliest
    /// created on a tie.
    pub root: u64,
    /// Bases of the links inside the cluster.
    pub basis: Vec<String>,
    /// Lowest link confidence on the spanning links (the cluster is as strong as its weakest
    /// joining link).
    pub confidence: u8,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Correlation {
    pub links: Vec<DocLink>,
    pub lineages: Vec<Lineage>,
}

impl Correlation {
    /// Links as graph edges (`doc:<id>`), kinds `derived_from` / `same_lineage` / `copy`.
    pub fn edges(&self) -> Vec<Edge> {
        self.links
            .iter()
            .map(|l| Edge {
                from: format!("doc:{}", l.from),
                to: format!("doc:{}", l.to),
                kind: l.kind.as_str().into(),
            })
            .collect()
    }

    /// Lineage of a document, if any.
    pub fn lineage_of(&self, doc: u64) -> Option<&Lineage> {
        self.lineages.iter().find(|l| l.docs.contains(&doc))
    }
}

/// Minimum confidence of a link that joins documents into a [`Lineage`].
pub const CLUSTER_MIN_CONFIDENCE: u8 = 50;

/// Normalized XMP id: lowercase without the `uuid:`, `xmp.did:`, `xmp.iid:` prefixes; `None`
/// for empty, too short or all-zero ids.
pub fn norm_id(raw: &str) -> Option<String> {
    let mut s = raw.trim().to_ascii_lowercase();
    for p in ["uuid:", "xmp.did:", "xmp.iid:", "xmp.id:"] {
        if let Some(r) = s.strip_prefix(p) {
            s = r.to_string();
        }
    }
    let hex: String = s.chars().filter(char::is_ascii_alphanumeric).collect();
    if hex.len() < 8 || hex.chars().all(|c| c == '0') {
        return None;
    }
    Some(s)
}

#[derive(Default)]
struct Ids {
    doc: Option<String>,
    inst: Option<String>,
    orig: Option<String>,
    der_doc: Option<String>,
    der_inst: Option<String>,
    history: BTreeSet<String>,
}

fn ids_of(m: &Metadata) -> Ids {
    let mut out = Ids::default();
    if let Some(x) = &m.xmp_ids {
        out.doc = x.document_id.as_deref().and_then(norm_id);
        out.inst = x.instance_id.as_deref().and_then(norm_id);
        out.orig = x.original_document_id.as_deref().and_then(norm_id);
        out.der_doc = x.derived_from_document_id.as_deref().and_then(norm_id);
        out.der_inst = x.derived_from_instance_id.as_deref().and_then(norm_id);
    }
    out.history = m
        .xmp_history
        .iter()
        .filter_map(|e| e.instance_id.as_deref().and_then(norm_id))
        .filter(|i| Some(i) != out.inst.as_ref())
        .collect();
    out
}

fn rsids_of(m: &Metadata) -> BTreeSet<String> {
    m.rsids
        .iter()
        .map(|r| r.trim().to_ascii_uppercase())
        .filter(|r| r.len() == 8 && r.bytes().all(|b| b.is_ascii_hexdigit()) && r != "00000000")
        .collect()
}

fn short_list(v: &BTreeSet<&String>, n: usize) -> String {
    let mut s: Vec<&str> = v.iter().take(n).map(|x| x.as_str()).collect();
    if v.len() > n {
        s.push("…");
    }
    s.join(", ")
}

/// Correlates the analysed documents.
pub fn correlate(inputs: &[DocInput]) -> Correlation {
    let mut docs: Vec<(u64, &Metadata)> = inputs
        .iter()
        .filter(|i| !i.deleted && i.doc.status == DocStatus::Analyzed)
        .filter_map(|i| i.doc.metadata.as_ref().map(|m| (i.doc.id, m)))
        .collect();
    docs.sort_by_key(|d| d.0);
    docs.dedup_by_key(|d| d.0);
    let n = docs.len();
    let ids: Vec<Ids> = docs.iter().map(|(_, m)| ids_of(m)).collect();
    let rsids: Vec<BTreeSet<String>> = docs.iter().map(|(_, m)| rsids_of(m)).collect();

    // Ids shared by too many documents are generator constants, not lineage.
    let noisy_limit = |count: usize| count > 3 && count * 2 > n;
    let mut doc_count: BTreeMap<&String, usize> = BTreeMap::new();
    for i in &ids {
        if let Some(d) = &i.doc {
            *doc_count.entry(d).or_default() += 1;
        }
    }
    let noisy_doc: BTreeSet<&String> = doc_count
        .iter()
        .filter(|(_, c)| noisy_limit(**c))
        .map(|(k, _)| *k)
        .collect();
    // RSIDs in more than a third of the Word files (min 5) come from the template.
    let word_files = rsids.iter().filter(|r| !r.is_empty()).count();
    let mut rs_count: BTreeMap<&String, usize> = BTreeMap::new();
    for r in &rsids {
        for x in r {
            *rs_count.entry(x).or_default() += 1;
        }
    }
    let rs_limit = (word_files / 3).max(5);
    let template_rs: BTreeSet<&String> = rs_count
        .iter()
        .filter(|(_, c)| **c > rs_limit)
        .map(|(k, _)| *k)
        .collect();

    let mut best: BTreeMap<(u64, u64), DocLink> = BTreeMap::new();
    let mut put = |l: DocLink| {
        let key = (l.from.min(l.to), l.from.max(l.to));
        match best.get(&key) {
            Some(old) if old.confidence >= l.confidence => {}
            _ => {
                best.insert(key, l);
            }
        }
    };
    let link = |from: u64, to: u64, kind: LinkKind, conf: u8, basis: &str, reason: String| {
        let (from, to) = if kind == LinkKind::DerivedFrom || from < to {
            (from, to)
        } else {
            (to, from)
        };
        DocLink {
            from,
            to,
            kind,
            confidence: conf,
            basis: basis.into(),
            reason,
            evidence: vec![],
        }
    };

    for a in 0..n {
        for b in 0..n {
            if a == b {
                continue;
            }
            let (ia, ib) = (&ids[a], &ids[b]);
            let (da, db) = (docs[a].0, docs[b].0);
            // a derived from b.
            if let (Some(x), Some(y)) = (&ia.der_inst, &ib.inst) {
                if x == y {
                    let mut l = link(
                        da,
                        db,
                        LinkKind::DerivedFrom,
                        95,
                        "xmp_derived_instance",
                        "xmpMM:DerivedFrom указывает на сохранённое состояние (InstanceID) другого документа".into(),
                    );
                    l.evidence.push(x.clone());
                    put(l);
                    continue;
                }
            }
            if let (Some(x), Some(y)) = (&ia.der_doc, &ib.doc) {
                if x == y && ia.doc.as_ref() != Some(y) && !noisy_doc.contains(y) {
                    let mut l = link(
                        da,
                        db,
                        LinkKind::DerivedFrom,
                        85,
                        "xmp_derived_document",
                        "xmpMM:DerivedFrom указывает на DocumentID другого документа".into(),
                    );
                    l.evidence.push(x.clone());
                    put(l);
                    continue;
                }
            }
            if let Some(y) = &ib.inst {
                if ia.history.contains(y) && ia.inst.as_ref() != Some(y) {
                    let same_doc = ia.doc.is_some() && ia.doc == ib.doc;
                    let mut l = link(
                        da,
                        db,
                        LinkKind::DerivedFrom,
                        if same_doc { 92 } else { 80 },
                        "xmp_history",
                        "InstanceID этого файла записан в истории правок (xmpMM:History) другого: это его более ранняя версия".into(),
                    );
                    l.evidence.push(y.clone());
                    put(l);
                    continue;
                }
            }
            if a > b {
                continue;
            }
            // Symmetric checks once per pair.
            if let (Some(x), Some(y)) = (&ia.doc, &ib.doc) {
                if x == y && !noisy_doc.contains(x) {
                    let same_inst = ia.inst.is_some() && ia.inst == ib.inst;
                    let mut l = if same_inst {
                        link(
                            da,
                            db,
                            LinkKind::Copy,
                            98,
                            "xmp_instance_id",
                            "Совпадают DocumentID и InstanceID: одно и то же сохранение под разными именами".into(),
                        )
                    } else {
                        link(
                            da,
                            db,
                            LinkKind::SameLineage,
                            90,
                            "xmp_document_id",
                            "Совпадает xmpMM:DocumentID: версии одного документа".into(),
                        )
                    };
                    l.evidence.push(x.clone());
                    put(l);
                    continue;
                }
            }
            let orig_hit = [
                (&ia.orig, &ib.doc),
                (&ib.orig, &ia.doc),
                (&ia.orig, &ib.orig),
            ]
            .into_iter()
            .find_map(|(x, y)| match (x, y) {
                (Some(x), Some(y)) if x == y => Some(x.clone()),
                _ => None,
            });
            if let Some(x) = orig_hit {
                let mut l = link(
                    da,
                    db,
                    LinkKind::SameLineage,
                    80,
                    "xmp_original_id",
                    "Общий xmpMM:OriginalDocumentID: файлы получены из одного исходника".into(),
                );
                l.evidence.push(x);
                put(l);
                continue;
            }
            // Word sessions.
            let (ra, rb) = (&rsids[a], &rsids[b]);
            if ra.len() < 2 || rb.len() < 2 {
                continue;
            }
            let shared: BTreeSet<&String> = ra
                .intersection(rb)
                .filter(|r| !template_rs.contains(r))
                .collect();
            let own_a = ra.iter().filter(|r| !template_rs.contains(r)).count();
            let own_b = rb.iter().filter(|r| !template_rs.contains(r)).count();
            let small = own_a.min(own_b);
            if shared.len() < 2 || small == 0 {
                continue;
            }
            let containment = shared.len() * 100 / small;
            let sample = short_list(&shared, 6);
            if containment == 100 && own_a != own_b && shared.len() >= 3 {
                // The file with more sessions continued editing the other one.
                let (later, earlier) = if own_a > own_b { (da, db) } else { (db, da) };
                let mut l = link(
                    later,
                    earlier,
                    LinkKind::DerivedFrom,
                    75,
                    "rsid_superset",
                    format!(
                        "Все {} сеансов правки Word (RSID) одного файла есть в другом, у которого их больше: вероятно, его продолжали редактировать",
                        shared.len()
                    ),
                );
                l.evidence.push(sample);
                put(l);
            } else if containment >= 50 {
                let conf = (40 + shared.len().min(10) * 3 + containment / 10).min(70) as u8;
                let mut l = link(
                    da,
                    db,
                    LinkKind::SameLineage,
                    conf,
                    "rsid_shared",
                    format!(
                        "Общие сеансы правки Word (RSID): {} из {}, один исходный файл или общий шаблон",
                        shared.len(),
                        small
                    ),
                );
                l.evidence.push(sample);
                put(l);
            }
        }
    }

    let links: Vec<DocLink> = best.into_values().collect();
    let lineages = clusters(&links, &docs);
    Correlation { links, lineages }
}

fn clusters(links: &[DocLink], docs: &[(u64, &Metadata)]) -> Vec<Lineage> {
    let mut parent: BTreeMap<u64, u64> = BTreeMap::new();
    fn find(p: &mut BTreeMap<u64, u64>, x: u64) -> u64 {
        let mut r = x;
        while let Some(&q) = p.get(&r) {
            if q == r {
                break;
            }
            r = q;
        }
        p.insert(x, r);
        r
    }
    let strong: Vec<&DocLink> = links
        .iter()
        .filter(|l| l.confidence >= CLUSTER_MIN_CONFIDENCE)
        .collect();
    let mut sorted = strong.clone();
    sorted.sort_by_key(|l| std::cmp::Reverse(l.confidence));
    let mut join_conf: BTreeMap<u64, u8> = BTreeMap::new();
    for l in &sorted {
        parent.entry(l.from).or_insert(l.from);
        parent.entry(l.to).or_insert(l.to);
        let (a, b) = (find(&mut parent, l.from), find(&mut parent, l.to));
        if a != b {
            let (lo, hi) = (a.min(b), a.max(b));
            parent.insert(hi, lo);
            let c = join_conf
                .remove(&hi)
                .unwrap_or(100)
                .min(join_conf.get(&lo).copied().unwrap_or(100))
                .min(l.confidence);
            join_conf.insert(lo, c);
        }
    }
    let keys: Vec<u64> = parent.keys().copied().collect();
    let mut groups: BTreeMap<u64, Vec<u64>> = BTreeMap::new();
    for k in keys {
        let r = find(&mut parent, k);
        groups.entry(r).or_default().push(k);
    }
    let created: BTreeMap<u64, Option<(i64, bool)>> = docs
        .iter()
        .map(|(id, m)| (*id, m.created.as_deref().and_then(crate::util::instant)))
        .collect();
    groups
        .into_iter()
        .filter(|(_, v)| v.len() > 1)
        .map(|(r, mut v)| {
            v.sort_unstable();
            let inside = |l: &DocLink| v.contains(&l.from) && v.contains(&l.to);
            let derived: BTreeSet<u64> = strong
                .iter()
                .filter(|l| inside(l))
                .filter(|l| l.kind == LinkKind::DerivedFrom)
                .map(|l| l.from)
                .collect();
            let root = v
                .iter()
                .copied()
                .filter(|d| !derived.contains(d))
                .min_by_key(|d| {
                    (
                        created.get(d).copied().flatten().map_or(i64::MAX, |c| c.0),
                        *d,
                    )
                })
                .unwrap_or(v[0]);
            let basis: BTreeSet<String> = strong
                .iter()
                .filter(|l| inside(l))
                .map(|l| l.basis.clone())
                .collect();
            Lineage {
                id: format!("lineage:{}", v[0]),
                root,
                basis: basis.into_iter().collect(),
                confidence: join_conf.get(&r).copied().unwrap_or(100),
                docs: v,
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use foca_core::{DocFormat, Document, XmpEvent, XmpIds};

    fn doc(id: u64, f: impl FnOnce(&mut Metadata)) -> Document {
        let mut m = Metadata::new(DocFormat::Docx);
        f(&mut m);
        Document {
            id,
            name: format!("d{id}.docx"),
            status: DocStatus::Analyzed,
            metadata: Some(m),
            ..Default::default()
        }
    }

    fn run(docs: &[Document]) -> Correlation {
        let inp: Vec<DocInput> = docs.iter().map(DocInput::new).collect();
        correlate(&inp)
    }

    #[test]
    fn xmp_derived_and_lineage() {
        let docs = vec![
            doc(1, |m| {
                m.xmp_ids = Some(XmpIds {
                    document_id: Some("xmp.did:AAAA1111".into()),
                    instance_id: Some("xmp.iid:BBBB0001".into()),
                    ..Default::default()
                })
            }),
            doc(2, |m| {
                m.xmp_ids = Some(XmpIds {
                    document_id: Some("xmp.did:CCCC2222".into()),
                    instance_id: Some("xmp.iid:DDDD0002".into()),
                    derived_from_instance_id: Some("XMP.IID:bbbb0001".into()),
                    ..Default::default()
                })
            }),
            doc(3, |m| {
                m.xmp_ids = Some(XmpIds {
                    document_id: Some("uuid:aaaa1111".into()),
                    instance_id: Some("xmp.iid:EEEE0003".into()),
                    ..Default::default()
                });
                m.xmp_history = vec![XmpEvent {
                    action: Some("saved".into()),
                    instance_id: Some("xmp.iid:BBBB0001".into()),
                    ..Default::default()
                }];
            }),
            doc(4, |_| {}),
        ];
        let c = run(&docs);
        let l12 = c.links.iter().find(|l| l.from == 2 && l.to == 1).unwrap();
        assert_eq!(l12.kind, LinkKind::DerivedFrom);
        assert_eq!(l12.basis, "xmp_derived_instance");
        // 3 has 1's instance in its history (stronger than the shared DocumentID would be).
        let l31 = c.links.iter().find(|l| (l.from, l.to) == (3, 1)).unwrap();
        assert_eq!(l31.kind, LinkKind::DerivedFrom);
        assert_eq!((l31.confidence, l31.basis.as_str()), (92, "xmp_history"));
        assert_eq!(c.lineages.len(), 1);
        assert_eq!(c.lineages[0].docs, vec![1, 2, 3]);
        assert_eq!(c.lineages[0].root, 1);
        assert_eq!(c.edges().len(), c.links.len());
    }

    #[test]
    fn rsid_superset_and_template_noise() {
        let rs = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        let docs = vec![
            doc(1, |m| m.rsids = rs(&["00A1B2C3", "00A1B2C4", "00A1B2C5"])),
            doc(2, |m| {
                m.rsids = rs(&["00a1b2c3", "00A1B2C4", "00A1B2C5", "00F00001"])
            }),
            doc(3, |m| m.rsids = rs(&["11111111", "22222222"])),
            doc(5, |m| m.rsids = rs(&["11111111", "33333333"])),
        ];
        let c = run(&docs);
        let l = c.links.iter().find(|l| l.basis == "rsid_superset").unwrap();
        assert_eq!((l.from, l.to, l.kind), (2, 1, LinkKind::DerivedFrom));
        // One shared session is not enough.
        assert!(!c.links.iter().any(|l| l.from == 3 || l.to == 3));
    }

    #[test]
    fn noisy_constant_ids_ignored() {
        let docs: Vec<Document> = (1..=6)
            .map(|i| {
                doc(i, |m| {
                    m.xmp_ids = Some(XmpIds {
                        document_id: Some("uuid:12345678-constant".into()),
                        ..Default::default()
                    })
                })
            })
            .collect();
        assert!(run(&docs).links.is_empty());
        assert_eq!(norm_id("uuid:00000000-0000"), None);
    }
}
