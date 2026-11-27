//! CVE subjects: detected products with their version, side and evidence, matched against
//! the table ([`super::CveDb`]).
//!
//! Document software is grouped per product (its CPE keys): the version used for findings is
//! the one of the newest document by document date (modified, else created), so an
//! organisation that upgraded is judged by what it uses now. Every software and OS entry still
//! gets its own summary for its card ([`annotate`]).

use std::collections::BTreeMap;

use foca_core::api::CveSummary;
use serde::Serialize;

use super::{cmp_ver, CveDb, CveQuery};
use crate::kev::SubjectKind;
use crate::Analysis;

/// A detected product matched against the CVE table.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct CveMatch {
    pub kind: SubjectKind,
    /// Software id, OS id or host name.
    pub id: String,
    /// Display name with version (`Microsoft Office Word 2016`, `Nginx 1.18.0`).
    pub probe: String,
    pub name: String,
    pub ver: String,
    /// `server`, `workstation` (document software) or `site` (web technology).
    pub side: String,
    /// Newest document with this version (`YYYY-MM-DD`), document software only.
    pub last_doc: Option<String>,
    pub docs: Vec<u64>,
    pub hosts: Vec<String>,
    /// Technology this one is a plugin of (`wordpress`), web technologies only.
    pub plugin_of: Option<String>,
    pub summary: CveSummary,
}

impl CveMatch {
    /// CVE findings of workstation software are reconnaissance, capped at medium.
    pub fn is_workstation(&self) -> bool {
        self.side == "workstation" || self.kind == SubjectKind::Os
    }
}

fn day(s: &str) -> Option<String> {
    let d = s.get(..10)?;
    (d.len() == 10 && d.as_bytes()[4] == b'-').then(|| d.to_string())
}

/// Newest document date per software id and OS id, and the documents of each.
fn doc_dates(a: &Analysis) -> BTreeMap<String, (Option<String>, Vec<u64>)> {
    let mut m: BTreeMap<String, (Option<String>, Vec<u64>)> = BTreeMap::new();
    for f in a.facts.iter().filter(|f| f.analyzed) {
        let date = f
            .modified
            .as_deref()
            .and_then(day)
            .or_else(|| f.created.as_deref().and_then(day));
        for id in f.software.iter().chain(f.os.iter()) {
            let e = m.entry(id.clone()).or_default();
            e.1.push(f.id);
            if date > e.0 {
                e.0 = date.clone();
            }
        }
    }
    m
}

fn label(name: &str, ver: &str) -> String {
    if ver.is_empty() || name.contains(ver) {
        name.to_string()
    } else {
        format!("{name} {ver}")
    }
}

/// Fills `last_doc`, `cve_sum`, `cve` and `cves` of every software and OS entry.
pub fn annotate(a: &mut Analysis, db: &CveDb) {
    let dates = doc_dates(a);
    for s in &mut a.software {
        s.last_doc = dates.get(&s.id).and_then(|d| d.0.clone());
        s.cve_sum = db.lookup(&CveQuery {
            keys: s.cpe.clone(),
            version: Some(s.ver.clone()),
            source: "meta".into(),
            ..Default::default()
        });
        let (n, top) = s
            .cve_sum
            .as_ref()
            .map(|c| {
                let top = c
                    .cves
                    .iter()
                    .map(|r| (r.id.clone(), r.cvss.unwrap_or(0.0)))
                    .collect();
                (c.matched, top)
            })
            .unwrap_or_default();
        s.cve = n;
        s.cves = top;
    }
    for o in &mut a.os {
        o.last_doc = dates.get(&o.id).and_then(|d| d.0.clone());
        o.cve_sum = db.lookup(&CveQuery {
            keys: o.cpe.clone(),
            version: Some(o.ver.clone()),
            source: "meta".into(),
            ..Default::default()
        });
    }
}

/// Document software and OS subjects: one per product, at the version of the newest document.
pub fn doc_matches(a: &Analysis, db: &CveDb) -> Vec<CveMatch> {
    let dates = doc_dates(a);
    let mut groups: BTreeMap<String, Vec<CveMatch>> = BTreeMap::new();
    let items = a
        .software
        .iter()
        .filter(|s| !matches!(s.kind.as_str(), "camera" | "scanner"))
        .map(|s| {
            (
                SubjectKind::Software,
                &s.id,
                &s.name,
                &s.ver,
                &s.cpe,
                s.side.clone(),
            )
        })
        .chain(a.os.iter().map(|o| {
            (
                SubjectKind::Os,
                &o.id,
                &o.name,
                &o.ver,
                &o.cpe,
                "workstation".to_string(),
            )
        }));
    for (kind, id, name, ver, cpe, side) in items {
        if cpe.is_empty() {
            continue;
        }
        let Some(summary) = db.lookup(&CveQuery {
            keys: cpe.clone(),
            version: Some(ver.clone()),
            source: "meta".into(),
            ..Default::default()
        }) else {
            continue;
        };
        let (last_doc, docs) = dates.get(id).cloned().unwrap_or_default();
        groups
            .entry(format!("{kind:?}|{}", summary.product))
            .or_default()
            .push(CveMatch {
                kind,
                id: id.clone(),
                probe: label(name, ver),
                name: name.clone(),
                ver: ver.clone(),
                side,
                last_doc,
                docs,
                hosts: vec![],
                plugin_of: None,
                summary,
            });
    }
    groups
        .into_values()
        .filter_map(|mut g| {
            // Newest document first; among equal dates the higher version. Entries with a
            // known version win over unversioned ones.
            g.sort_by(|x, y| {
                y.summary
                    .version_known
                    .cmp(&x.summary.version_known)
                    .then(y.last_doc.cmp(&x.last_doc))
                    .then(cmp_ver(&y.ver, &x.ver))
            });
            g.into_iter().next()
        })
        .collect()
}

/// A web technology detected on a host.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TechInput {
    pub host: String,
    pub name: String,
    pub version: Option<String>,
    pub cpe: Option<String>,
    /// Plugin slug and the CMS it belongs to (`contact-form-7`, `wordpress`).
    pub slug: Option<String>,
    pub plugin_of: Option<String>,
    /// Detection evidence (`header server: nginx/1.18.0`, `script: /js/x.js?ver=1.2`).
    pub evidence: Vec<String>,
}

impl TechInput {
    /// The table query of this technology.
    pub fn query(&self) -> CveQuery {
        let plugin = self.plugin_of.is_some() && self.slug.is_some();
        CveQuery {
            keys: self.cpe.iter().cloned().collect(),
            slug: self.slug.clone().zip(self.plugin_of.clone()),
            version: self.version.clone(),
            source: version_source(&self.evidence, plugin),
        }
    }
}

/// Where a technology version was read from, from its evidence lines.
pub fn version_source(evidence: &[String], plugin: bool) -> String {
    let e = evidence.join("\n").to_ascii_lowercase();
    let src = if e.contains("readme") {
        "readme"
    } else if plugin || e.contains("/plugins/") || e.contains("/modules/") {
        "plugin_path"
    } else if e.starts_with("header") || e.contains("\nheader") || e.contains("cookie") {
        "header"
    } else if e.contains("script") || e.contains(".js") {
        "js"
    } else {
        "html"
    };
    src.into()
}

/// Web technology subjects merged across hosts (same product and version).
pub fn tech_matches(techs: &[TechInput], db: &CveDb) -> Vec<CveMatch> {
    let mut out: BTreeMap<(String, String), CveMatch> = BTreeMap::new();
    for t in techs {
        let plugin = t.plugin_of.is_some() && t.slug.is_some();
        let Some(summary) = db.lookup(&t.query()) else {
            continue;
        };
        let ver = t.version.clone().unwrap_or_default();
        let key = (summary.product.clone(), ver.to_ascii_lowercase());
        let e = out.entry(key).or_insert_with(|| CveMatch {
            kind: SubjectKind::Tech,
            id: t.host.clone(),
            probe: label(&t.name, &ver),
            name: t.name.clone(),
            ver: ver.clone(),
            side: "site".into(),
            last_doc: None,
            docs: vec![],
            hosts: vec![],
            plugin_of: t.plugin_of.clone().filter(|_| plugin),
            summary,
        });
        if !t.host.is_empty() && !e.hosts.contains(&t.host) {
            e.hosts.push(t.host.clone());
        }
    }
    out.into_values().collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DocFacts;
    use foca_core::api::Software;

    const TABLE: &str = "# foca-nvd v1 snapshot=2099-06-01 epss=2099-05-31
C\t2099-0001\t2099\t9.8\t31\t\tK\t
C\t2099-0002\t2099\t6.5\t31\t\t\t
C\t2099-0003\t2099\t7.8\t31\t\t\t
P\tlibreoffice:libreoffice\td
0\t[,7.0)
1\t[7.0,7.6.4)
1\t[24.2,24.8.1)
P\tf5:nginx\ts
0\t[,1.20.1)
P\texample_vendor:form_x@wordpress\tp
1\t[,2.0)
";

    fn sw(id: &str, ver: &str) -> Software {
        Software {
            id: id.into(),
            name: "LibreOffice".into(),
            ver: ver.into(),
            kind: "office".into(),
            cpe: vec!["libreoffice:libreoffice".into()],
            side: "workstation".into(),
            ..Default::default()
        }
    }

    fn doc(id: u64, sw: &str, modified: &str) -> DocFacts {
        DocFacts {
            id,
            analyzed: true,
            software: vec![sw.into()],
            modified: Some(modified.into()),
            ..Default::default()
        }
    }

    #[test]
    fn newest_document_version_wins_and_dates_are_kept() {
        let db = CveDb::parse_text(TABLE).unwrap();
        let mut a = Analysis {
            software: vec![
                sw("lo64", "6.4.2"),
                sw("lo75", "7.5.1"),
                sw("lo242", "24.2.0"),
            ],
            facts: vec![
                doc(1, "lo64", "2021-03-01T10:00:00Z"),
                doc(2, "lo75", "2026-05-01T10:00:00Z"),
                doc(3, "lo242", "2025-01-10T10:00:00Z"),
                doc(4, "lo64", "2020-01-01T10:00:00Z"),
            ],
            ..Default::default()
        };
        let m = doc_matches(&a, &db);
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].ver, "7.5.1");
        assert_eq!(m[0].last_doc.as_deref(), Some("2026-05-01"));
        assert_eq!(m[0].side, "workstation");
        assert!(m[0].is_workstation());
        assert_eq!(m[0].summary.matched, 1);
        annotate(&mut a, &db);
        assert_eq!(a.software[0].last_doc.as_deref(), Some("2021-03-01"));
        assert_eq!(a.software[0].cve, 1);
        assert_eq!(a.software[0].cves[0].0, "CVE-2099-0001");
        assert_eq!(a.software[2].cve_sum.as_ref().unwrap().high, 1);
    }

    #[test]
    fn tech_subjects_merge_hosts_and_use_plugin_slugs() {
        let db = CveDb::parse_text(TABLE).unwrap();
        let t = |host: &str| TechInput {
            host: host.into(),
            name: "Nginx".into(),
            version: Some("1.18.0".into()),
            cpe: Some("cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*".into()),
            evidence: vec!["header server: nginx/1.18.0".into()],
            ..Default::default()
        };
        let plugin = TechInput {
            host: "a.example.com".into(),
            name: "Form X".into(),
            version: Some("1.9".into()),
            slug: Some("form-x".into()),
            plugin_of: Some("wordpress".into()),
            evidence: vec!["path: /wp-content/plugins/form-x/readme.txt".into()],
            ..Default::default()
        };
        let none = TechInput {
            name: "Nginx".into(),
            version: None,
            cpe: Some("f5:nginx".into()),
            ..t("b.example.com")
        };
        let mut m = tech_matches(&[t("a.example.com"), t("b.example.com"), plugin, none], &db);
        m.sort_by(|a, b| a.probe.cmp(&b.probe));
        assert_eq!(m.len(), 3, "{m:?}");
        assert_eq!(m[2].probe, "Nginx 1.18.0");
        assert_eq!(m[2].hosts, vec!["a.example.com", "b.example.com"]);
        assert_eq!(m[2].summary.source, "header");
        assert_eq!(m[0].plugin_of.as_deref(), Some("wordpress"));
        assert_eq!(m[0].summary.source, "readme");
        assert_eq!(m[0].summary.matched, 1);
        assert!(!m[1].summary.version_known);
        assert_eq!(m[1].summary.known, 1);
    }
}
