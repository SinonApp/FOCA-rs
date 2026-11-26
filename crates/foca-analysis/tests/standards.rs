//! `signatures/standards.toml` refers only to finding rules the core actually emits.

use std::path::{Path, PathBuf};

use foca_analysis::standards::Standards;

fn sources() -> String {
    let crates = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    let mut out = String::new();
    let mut stack: Vec<PathBuf> = std::fs::read_dir(&crates)
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        // The report crate only translates rule texts; the rules must come from a generator.
        .filter(|p| p.file_name().is_some_and(|n| n != "foca-report"))
        .map(|p| p.join("src"))
        .collect();
    while let Some(p) = stack.pop() {
        if p.is_dir() {
            stack.extend(
                std::fs::read_dir(&p)
                    .unwrap()
                    .filter_map(|e| e.ok())
                    .map(|e| e.path()),
            );
        } else if p.extension().is_some_and(|e| e == "rs") {
            out.push_str(&std::fs::read_to_string(&p).unwrap());
        }
    }
    out
}

/// A rule exists when its id is a string literal in a generator, or, for rule ids built from a
/// prefix (`infra.{code}`, `recon.web.{issue}`), when the code is.
#[test]
fn mapped_rules_exist_in_the_finding_catalog() {
    let src = sources();
    let lit = |s: &str| src.contains(&format!("\"{s}\""));
    let mut missing = Vec::new();
    for r in &Standards::builtin().rules {
        let id = r.id.as_str();
        let ok = lit(id)
            || id.strip_prefix("infra.").is_some_and(lit)
            || id.strip_prefix("recon.web.").is_some_and(lit);
        if !ok {
            missing.push(id);
        }
    }
    assert!(
        missing.is_empty(),
        "rules not emitted by any crate: {missing:?}"
    );
}

fn analyze_dir(rel: &str) -> Vec<foca_core::api::Finding> {
    use foca_analysis::{analyze, DocInput, PrevState};
    use foca_core::{DocStatus, Document, Scope};
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join(rel);
    let mut names: Vec<String> = std::fs::read_dir(&dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.path().is_file())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| !n.ends_with(".py") && !n.ends_with(".json") && !n.ends_with(".md"))
        .collect();
    names.sort();
    let lim = foca_meta::Limits::default();
    let docs: Vec<(Document, Option<String>)> = names
        .iter()
        .enumerate()
        .filter_map(|(i, n)| {
            let b = std::fs::read(dir.join(n)).ok()?;
            let m = foca_meta::extract(&b, Some(n), &lim).ok()?;
            let t = foca_meta::text(&b, &lim).ok();
            let d = Document {
                id: i as u64 + 1,
                name: n.clone(),
                sha256: format!("sha-{n}"),
                status: DocStatus::Analyzed,
                metadata: Some(m),
                ..Default::default()
            };
            Some((d, t))
        })
        .collect();
    let inputs: Vec<DocInput> = docs
        .iter()
        .map(|(d, t)| DocInput::new(d).with_text(t.as_deref()))
        .collect();
    analyze(&inputs, &Scope::default(), &PrevState::default()).findings
}

/// The ATT&CK technique a rule emits is the first `mitre` id of its mapping, so the report
/// tables and the finding cards never disagree.
#[test]
fn mitre_matches_the_emitted_technique() {
    let st = Standards::builtin();
    let mut seen = 0;
    for rel in [
        "../foca-meta/tests/fixtures/forensics",
        "../../tests/corpus/forensics",
        "../../tests/corpus/lnk",
        "../../tests/corpus/mail",
        "../../tests/corpus/images",
        "../../tests/corpus/ooxml",
        "../../tests/corpus/pdf",
        "../../tests/corpus/pim",
        "../../tests/corpus/media",
    ] {
        for f in analyze_dir(rel) {
            let tech = f.mitre.split_whitespace().next().unwrap_or("");
            let Some(r) = st.for_rule(&f.provenance.rule) else {
                continue;
            };
            if tech.is_empty() || r.mitre.is_empty() {
                continue;
            }
            seen += 1;
            assert_eq!(r.mitre[0], tech, "rule {}", f.provenance.rule);
        }
    }
    assert!(seen > 5, "too few findings checked: {seen}");
}
