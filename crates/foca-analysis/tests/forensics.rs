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
    let br = has("doc.bad_redaction", "redacted.pdf").expect("bad redaction");
    assert_eq!(br.sev, Severity::Critical);
    assert!(has("doc.modified_after_signing", "signed_modified.pdf").is_some());
    let kep = has("doc.signer_identity", "signed.pdf").expect("signer");
    assert!(
        kep.evidence.contains("РНОКПП: ********"),
        "{}",
        kep.evidence
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
