//! Golden test over the whole `tests/corpus`: `foca-meta` (extract + text) → `analyze` →
//! comparison with `tests/corpus/analysis.expected.json`.
//!
//! Regenerate the golden file with
//! `UPDATE_GOLDEN=1 cargo test -p foca-analysis --test corpus`.

use std::path::{Path, PathBuf};

use foca_analysis::{analyze, DocInput, PrevState, RiskLevel};
use foca_core::{DocStatus, Document, Scope, Severity};
use foca_meta::Limits;
use time::macros::datetime;

fn corpus_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/corpus")
}

fn corpus_files() -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![corpus_dir()];
    while let Some(d) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&d) else {
            continue;
        };
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
                continue;
            }
            let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if name.ends_with(".json") || name.ends_with(".md") || name.ends_with(".py") {
                continue;
            }
            out.push(p);
        }
    }
    out.sort();
    out
}

struct Loaded {
    docs: Vec<Document>,
    texts: Vec<Option<String>>,
}

fn load() -> Loaded {
    let l = Limits::default();
    let mut docs = Vec::new();
    let mut texts = Vec::new();
    for (i, f) in corpus_files().iter().enumerate() {
        let bytes = std::fs::read(f).unwrap();
        let rel = f
            .strip_prefix(corpus_dir())
            .unwrap()
            .to_string_lossy()
            .replace('\\', "/");
        let name = f.file_name().unwrap().to_string_lossy().to_string();
        let meta = foca_meta::extract(&bytes, Some(&name), &l).ok();
        let text = foca_meta::text(&bytes, &l).ok();
        docs.push(Document {
            id: i as u64 + 1,
            ext: name.rsplit('.').next().unwrap_or("").to_string(),
            name,
            url: Some(format!("https://files.contoso.example/corpus/{rel}")),
            source: "local".into(),
            size: bytes.len() as u64,
            status: if meta.is_some() {
                DocStatus::Analyzed
            } else {
                DocStatus::Error
            },
            metadata: meta,
            ..Default::default()
        });
        texts.push(text);
    }
    Loaded { docs, texts }
}

fn run(l: &Loaded) -> foca_analysis::Analysis {
    let inputs: Vec<DocInput> = l
        .docs
        .iter()
        .zip(&l.texts)
        .map(|(d, t)| DocInput {
            first_scan: Some("corpus-s1"),
            ..DocInput::new(d).with_text(t.as_deref())
        })
        .collect();
    let (scope, errs) = Scope::from_lines(
        "contoso.example\n*.contoso-group.example\n203.0.113.0/24",
        "mail.contoso.example\n10.10.1.0/24",
    );
    assert!(errs.is_empty());
    let prev = PrevState {
        now: Some(datetime!(2026-11-20 12:00 UTC)),
        scan_id: Some("corpus-s1".into()),
        ..Default::default()
    };
    analyze(&inputs, &scope, &prev)
}

#[test]
fn corpus_golden() {
    let l = load();
    assert!(l.docs.len() >= 25, "corpus is incomplete: {}", l.docs.len());
    let a = run(&l);
    // Round-trip through a string: f32 values (cvss) round differently in `Value` and in text.
    let got: serde_json::Value = serde_json::from_str(&serde_json::to_string(&a).unwrap()).unwrap();
    let exp_path = corpus_dir().join("analysis.expected.json");
    let update = std::env::var("UPDATE_GOLDEN").is_ok_and(|v| v == "1");
    if update || !exp_path.exists() {
        let mut s = serde_json::to_string_pretty(&got).unwrap();
        s.push('\n');
        std::fs::write(&exp_path, s).unwrap();
        assert!(
            update,
            "golden file was missing and has been created; review it"
        );
        return;
    }
    let exp: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&exp_path).unwrap()).unwrap();
    if exp != got {
        // Short diff by top-level key.
        let mut diff = Vec::new();
        for (k, v) in got.as_object().unwrap() {
            if exp.get(k) != Some(v) {
                diff.push(k.clone());
            }
        }
        panic!(
            "corpus analysis differs from the golden file in: {diff:?}\n\
             regenerate with: UPDATE_GOLDEN=1 cargo test -p foca-analysis --test corpus"
        );
    }
}

/// Explicit checks of the key conclusions on top of the golden file, so a reviewer can read
/// what is expected without diffing JSON.
#[test]
fn corpus_key_facts() {
    let l = load();
    let a = run(&l);
    let person = |login: &str| {
        a.people
            .iter()
            .find(|p| p.login == login)
            .unwrap_or_else(|| panic!("no {login}: {:#?}", a.people))
    };
    // Identity merging across Cyrillic, Latin, logins, paths and e-mail addresses.
    let mel = person("t.melnyk");
    assert!(mel.aliases.iter().any(|x| x == "Тетяна Мельник"));
    assert!(mel.aliases.iter().any(|x| x == "tmelnyk"));
    let sh = person("m.shevchuk");
    for alias in ["Марина Шевчук", "Marina Shevchuk", "mshevchuk"] {
        assert!(
            sh.aliases.iter().any(|x| x == alias),
            "{alias}: {:?}",
            sh.aliases
        );
    }
    let vt = person("v.tkachenko");
    assert!(vt.aliases.iter().any(|x| x == "Viktor Tkachenko"));
    assert!(vt.aliases.iter().any(|x| x == "Віктор Ткаченко"));
    assert_eq!(vt.pc.as_deref(), Some("ENG-WS11"));
    let ok = person("o.kovalenko");
    assert!(ok.aliases.iter().any(|x| x == "Олена Коваленко"));
    assert!(ok
        .emails
        .contains(&"o.kovalenko@contoso.example".to_string()));
    assert!(person("a.bondar")
        .aliases
        .iter()
        .any(|x| x == "Андрій Бондар"));
    assert!(a
        .people
        .iter()
        .any(|p| p.service && p.name == "Administrator"));
    assert!(!a.people.iter().any(|p| p.name == "I wrote it"));
    // E-mail addresses and the address pattern.
    let p = &a.patterns[0];
    assert_eq!(
        (p.p.as_str(), p.domain.as_str()),
        ("{f}.{last}", "contoso.example")
    );
    assert!(a
        .emails
        .iter()
        .any(|e| !e.found && e.addr == "a.bondar@contoso.example"));
    // Software.
    let sw: Vec<&str> = a.software.iter().map(|s| s.id.as_str()).collect();
    for id in [
        "word2013",
        "excel2010",
        "lo72",
        "ooo3",
        "aoo41",
        "acro11",
        "ios166",
        "ps2019",
        "gs",
        "pdfcreator",
        "inkscape",
        "canon-ir",
        "ps7",
        "macword2008",
    ] {
        assert!(sw.contains(&id), "missing software {id}: {sw:?}");
    }
    let os: Vec<&str> = a.os.iter().map(|o| o.id.as_str()).collect();
    for id in ["win7", "winxp", "win10", "macos"] {
        assert!(os.contains(&id), "missing OS {id}: {os:?}");
    }
    // Hosts and computers.
    for pc in ["SRV-FILE01", "NAS02", "SRV-PRN01", "ENG-WS11", "MFP-2F"] {
        assert!(a.pcs.iter().any(|p| p.name == pc), "missing computer {pc}");
    }
    let host = |n: &str| a.hosts.iter().find(|h| h.name == n);
    assert_eq!(
        host("10.10.1.40").map(|h| h.scope.as_str()),
        Some("excluded")
    );
    assert!(host("srv-ts01.corp.contoso.example").is_some_and(|h| h.internal));
    assert_eq!(
        host("portal.contoso.example").map(|h| h.scope.as_str()),
        Some("in_scope")
    );
    // Findings.
    let rule = |r: &str| a.findings.iter().filter(|f| f.provenance.rule == r).count();
    assert_eq!(rule("ica-password"), 1);
    assert_eq!(rule("rdp-password"), 1);
    assert!(rule("macros") >= 3);
    assert!(rule("hidden-sheets") >= 2);
    assert!(rule("revisions") >= 2);
    assert_eq!(rule("gps"), 1);
    assert_eq!(rule("thumbnail"), 1);
    assert!(rule("pdf-revisions") >= 1);
    assert!(rule("eol-software") >= 3);
    assert_eq!(rule("internal-paths"), 1);
    let ica = a
        .findings
        .iter()
        .find(|f| f.provenance.rule == "ica-password")
        .unwrap();
    assert_eq!(ica.sev, Severity::Critical);
    assert!(a.secrets.iter().any(|s| s.value.expose() == "Buh2023!"));
    // Finding ids are unique and secrets are linked to their findings.
    let mut ids: Vec<u64> = a.findings.iter().map(|f| f.id).collect();
    ids.sort_unstable();
    ids.dedup();
    assert_eq!(ids.len(), a.findings.len());
    assert!(a.secrets.iter().all(|s| s.finding.is_some()));
    assert!(matches!(
        a.risk.level,
        RiskLevel::High | RiskLevel::Critical
    ));
    assert!(!a.events.is_empty());
}
