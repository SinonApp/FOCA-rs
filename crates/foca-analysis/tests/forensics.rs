//! Forensic findings over the foca-meta forensic fixtures (signatures and qualified
//! certificates, bad redaction, hidden content, PDF revisions, scans) after the storage
//! sanitizing step, exactly as the engine stores them.

use std::path::Path;

use foca_analysis::{analyze, DocInput, PrevState};
use foca_core::{DocStatus, Document, Scope, Severity};

fn load() -> Vec<(Document, Option<String>)> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../foca-meta/tests/fixtures/forensics");
    let mut names: Vec<String> = std::fs::read_dir(&dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| !n.ends_with(".py"))
        .collect();
    names.sort();
    let lim = foca_meta::Limits::default();
    names
        .iter()
        .enumerate()
        .map(|(i, n)| {
            let b = std::fs::read(dir.join(n)).unwrap();
            let m = foca_meta::extract(&b, Some(n), &lim).unwrap();
            let t = foca_meta::text(&b, &lim).ok();
            let (m, t) = foca_analysis::pii::sanitize(&m, t.as_deref());
            let d = Document {
                id: i as u64 + 1,
                name: n.clone(),
                sha256: format!("sha-{n}"),
                status: DocStatus::Analyzed,
                metadata: Some(m),
                ..Default::default()
            };
            (d, t)
        })
        .collect()
}

#[test]
fn forensic_findings_from_fixtures() {
    let docs = load();
    let inputs: Vec<DocInput> = docs
        .iter()
        .map(|(d, t)| DocInput::new(d).with_text(t.as_deref()))
        .collect();
    let a = analyze(&inputs, &Scope::default(), &PrevState::default());
    let has = |rule: &str, doc: &str| {
        a.findings
            .iter()
            .find(|f| f.provenance.rule == rule && f.title.contains(doc))
    };
    // the covered text holds a passport number (masked in storage): critical, CVSS in the band
    let br = has("doc.bad_redaction", "redacted.pdf").expect("bad redaction");
    assert_eq!(br.sev, Severity::Critical);
    assert!(br.cvss.is_some_and(|c| c >= 9.0), "{:?}", br.cvss);
    assert!(has("doc.modified_after_signing", "signed_modified.pdf").is_some());
    let kep = has("doc.signer_identity", "signed.pdf").expect("signer");
    assert!(
        kep.evidence.contains("РНОКПП: ********"),
        "{}",
        kep.evidence
    );
    // a КЕП wrapper published as .pdf: one signer finding for the document, Medium (РНОКПП)
    let cms = has("doc.signer_identity", "kep_wrapped.pdf").expect("cms signer");
    assert_eq!(cms.sev, Severity::Medium);
    assert!(
        cms.evidence.contains("РНОКПП: ********"),
        "{}",
        cms.evidence
    );
    assert!(has("doc.hidden_content", "hidden.xlsx").is_some());
    assert!(has("doc.hidden_content", "signed_hidden.docx").is_some());
    assert!(has("doc.pdf_removed_text", "revisions.pdf").is_some());
    assert!(has("doc.scan_without_text", "scan.pdf").is_some());
    // Signers become people.
    assert!(
        a.people.iter().any(|p| p.name.contains("Петренко")),
        "{:?}",
        a.people.iter().map(|p| &p.name).collect::<Vec<_>>()
    );
    // Translations exist for every new finding text is checked in foca-report; here: no raw
    // РНОКПП in any finding.
    let js = serde_json::to_string(&a.findings).unwrap();
    assert!(
        !js.contains("TINUA-") && !js.contains("1234567899"),
        "raw РНОКПП leaked"
    );
}

/// `pdf-revisions` is a finding only when an older revision really differs: empty Word
/// increments and LTV data are a fact; changed Info values or page text are a finding.
#[test]
fn pdf_revisions_differ_only_on_real_changes() {
    use foca_core::{Metadata, OldVersion, PdfRevision};
    let rev = |n: u32, objects: u32, producer: Option<&str>| PdfRevision {
        revision: n,
        objects,
        producer: producer.map(str::to_string),
        author: (objects > 0).then(|| "Olena".to_string()),
        ..Default::default()
    };
    let mut m = Metadata {
        title: Some("Order 12".into()),
        ..Default::default()
    };
    // Word hybrid xref: a second revision with no objects; an LTV increment with /Producer ()
    m.pdf_revisions = vec![
        rev(1, 40, Some("Microsoft Word 2016")),
        rev(2, 0, None),
        rev(3, 12, Some("")),
    ];
    m.old_versions = vec![OldVersion {
        revision: 1,
        fields: [("Title".to_string(), "Order 12".to_string())].into(),
    }];
    assert!(!foca_analysis::revisions_differ(&m));
    // an older title
    let mut t = m.clone();
    t.old_versions[0]
        .fields
        .insert("Title".into(), "Draft order".into());
    assert!(foca_analysis::revisions_differ(&t));
    // another producer saved over the original
    let mut p = m.clone();
    p.pdf_revisions[2].producer = Some("iLovePDF".into());
    assert!(foca_analysis::revisions_differ(&p));
    // removed text
    let mut x = m.clone();
    x.pdf_revisions[1].removed_text = vec!["salary 1000".into()];
    assert!(foca_analysis::revisions_differ(&x));
}
