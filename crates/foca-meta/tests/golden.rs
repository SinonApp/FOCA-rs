//! Golden tests: `extract()` output for every file in `tests/corpus/` is compared with
//! `<file>.expected.json`. Regenerate with `UPDATE_GOLDEN=1 cargo test -p foca-meta --test golden`.
//! Also covers robustness on truncated and corrupted corpus files, and metadata cleaning.

use std::path::{Path, PathBuf};

use foca_meta::{clean, extract, text, DocFormat, Limits};

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

fn rel(p: &Path) -> String {
    p.strip_prefix(corpus_dir())
        .unwrap_or(p)
        .to_string_lossy()
        .replace('\\', "/")
}

fn load(rel_path: &str) -> Vec<u8> {
    std::fs::read(corpus_dir().join(rel_path)).unwrap_or_else(|e| panic!("{rel_path}: {e}"))
}

#[test]
fn golden() {
    let update = std::env::var("UPDATE_GOLDEN").is_ok_and(|v| v == "1");
    let files = corpus_files();
    assert!(
        files.len() >= 20,
        "corpus missing or incomplete: {}",
        files.len()
    );
    let mut failures = Vec::new();
    for f in &files {
        let bytes = std::fs::read(f).unwrap();
        let name = f.file_name().and_then(|n| n.to_str());
        let got = match extract(&bytes, name, &Limits::default()) {
            Ok(m) => serde_json::to_value(&m).unwrap(),
            Err(e) => serde_json::json!({ "error": e.to_string() }),
        };
        let exp_path = PathBuf::from(format!("{}.expected.json", f.display()));
        if update || !exp_path.exists() {
            let mut s = serde_json::to_string_pretty(&got).unwrap();
            s.push('\n');
            std::fs::write(&exp_path, s).unwrap();
            if !update {
                failures.push(format!(
                    "{}: эталон отсутствовал, создан, проверьте его",
                    rel(f)
                ));
            }
            continue;
        }
        let exp: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&exp_path).unwrap()).unwrap();
        if exp != got {
            failures.push(format!(
                "{}: расхождение с эталоном\n--- ожидалось\n{}\n--- получено\n{}",
                rel(f),
                serde_json::to_string_pretty(&exp).unwrap(),
                serde_json::to_string_pretty(&got).unwrap()
            ));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n\n"));
}

/// Key fields of the synthetic corpus, asserted explicitly on top of the golden files for readability.
#[test]
fn key_fields() {
    let l = Limits::default();
    let m = extract(&load("ooxml/contract.docx"), None, &l).unwrap();
    assert_eq!(m.format, DocFormat::Docx);
    assert_eq!(m.author.as_deref(), Some("Андрій Бондар"));
    assert_eq!(m.last_modified_by.as_deref(), Some("a.bondar"));
    assert_eq!(
        m.template.as_deref(),
        Some(r"file:///\\SRV-FILE01\public\Шаблони\Договір.dotx")
    );
    assert_eq!(m.printers, vec![r"\\SRV-PRN01\Canon C5535 2F"]);
    assert_eq!(m.rsids, vec!["00A1B2C3", "00D4E5F6", "0012F00D"]);
    assert!(m
        .revisions
        .iter()
        .any(|r| r.author.as_deref() == Some("a.bondar") && r.text == "1 250 000 грн"));
    assert!(m
        .comments
        .iter()
        .any(|c| c.author.as_deref() == Some("Олена Коваленко")));
    assert!(m
        .paths
        .iter()
        .any(|p| p.user.as_deref() == Some("a.bondar")));
    assert!(m.servers.iter().any(|s| s.name == "SRV-FILE01"));
    assert!(m
        .emails
        .contains(&"o.kovalenko@contoso.example".to_string()));
    let photo = &m.embedded[0].metadata;
    assert_eq!(photo.format, DocFormat::Jpeg);
    assert!(photo.gps.is_some());

    let m = extract(&load("images/photo.jpg"), None, &l).unwrap();
    let g = m.gps.unwrap();
    assert_eq!((g.lat, g.lon, g.alt), (47.92, 33.43, Some(120.5)));
    let cam = m.camera.clone().unwrap();
    assert_eq!(cam.serial.as_deref(), Some("F2LXK0QJQ6"));
    assert_eq!(cam.model.as_deref(), Some("iPhone 13 Pro"));
    let th = m.thumbnail.unwrap();
    assert!(th.data.starts_with(&[0xFF, 0xD8]) && th.data.len() > 100);
    assert_eq!(m.created.as_deref(), Some("2024-08-02T11:05:33"));

    let m = extract(&load("pdf/report.pdf"), None, &l).unwrap();
    assert_eq!(m.incremental_updates, Some(1));
    assert_eq!(m.author.as_deref(), Some("Administrator"));
    assert_eq!(m.old_versions.len(), 1);
    assert_eq!(
        m.old_versions[0].fields.get("Author").map(String::as_str),
        Some("o.kovalenko")
    );
    assert!(m.has_javascript);
    assert_eq!(m.attachments[0].name, "creds.rdp");
    assert_eq!(m.embedded[0].metadata.format, DocFormat::Rdp);
    assert_eq!(m.title.as_deref(), Some("Річний звіт 2024"));

    let m = extract(&load("pdf/objstm.pdf"), None, &l).unwrap();
    assert_eq!(m.author.as_deref(), Some("m.shevchuk"));
    assert_eq!(m.producer.as_deref(), Some("GPL Ghostscript 9.50"));

    let m = extract(&load("ole/legacy.doc"), None, &l).unwrap();
    assert_eq!(m.author.as_deref(), Some("Олена Коваленко"));
    assert_eq!(
        m.template.as_deref(),
        Some(r"\\SRV-FILE01\public\Шаблони\Юридичний.dot")
    );
    assert_eq!(m.old_versions.len(), 2);
    assert_eq!(m.os.as_deref(), Some("Windows 7/Server 2008 R2"));
    assert_eq!(m.custom.get("Проєкт").map(String::as_str), Some("ТЕС-2"));
    assert!(m.has_macros && m.macro_modules.contains(&"AutoOpen".to_string()));

    let m = extract(&load("ole/budget.xls"), None, &l).unwrap();
    assert_eq!(m.hidden_sheets, vec!["Зарплати", "Службовий"]);
    assert_eq!(
        m.fields.get("xls:WriteAccess").map(String::as_str),
        Some("s.lysenko")
    );

    let m = extract(&load("ooxml/schedule.xlsx"), None, &l).unwrap();
    assert_eq!(m.hidden_sheets, vec!["Зарплати", "Паролі"]);
    assert!(m.has_macros && m.macro_modules.contains(&"Module1".to_string()));

    let m = extract(&load("remote/SRV-TS01.rdp"), Some("SRV-TS01.rdp"), &l).unwrap();
    assert!(m
        .servers
        .iter()
        .any(|s| s.name == "SRV-TS01.corp.contoso.example"));
    assert!(m.people.iter().any(|p| p.name == "i.petrenko"));
    assert_eq!(m.secrets.len(), 1);

    let m = extract(&load("real/poi-SampleDoc.doc"), None, &l).unwrap();
    assert_eq!(m.author.as_deref(), Some("Nick Burch"));
    assert_eq!(m.title.as_deref(), Some("Test Document"));
}

#[test]
fn text_for_secrets() {
    let l = Limits::default();
    let t = text(&load("ooxml/contract.docx"), &l).unwrap();
    assert!(t.contains("Password=Tender2024!"), "{t}");
    assert!(
        t.contains("1 250 000 грн"),
        "deleted text is searchable too"
    );
    let t = text(&load("ooxml/schedule.xlsx"), &l).unwrap();
    // connection string passwords are redacted; metadata keeps only a marker secret
    assert!(
        t.contains("AKIAIOSFODNN7EXAMPLE")
            && t.contains("Password=***")
            && !t.contains("Bill!ng2023"),
        "{t}"
    );
    let m = extract(&load("ooxml/schedule.xlsx"), None, &l).unwrap();
    assert!(m.secrets.iter().any(|s| s.kind == "connection_password"));

    let t = text(&load("pdf/objstm.pdf"), &l).unwrap();
    assert!(t.contains("password=Winter2024!"), "{t}");
    let t = text(&load("odf/letter.odt"), &l).unwrap();
    assert!(t.contains("Шановні колеги"), "{t}");
    let t = text(&load("ole/legacy.doc"), &l).unwrap();
    assert!(t.contains("P@ssw0rd2019"), "{t}");
}

#[test]
fn clean_ooxml_removes_authors_keeps_text() {
    let l = Limits::default();
    for f in [
        "ooxml/contract.docx",
        "ooxml/schedule.xlsx",
        "ooxml/strategy.pptx",
    ] {
        let orig = load(f);
        let before = extract(&orig, None, &l).unwrap();
        assert!(before.author.is_some());
        let cleaned = clean(&orig, before.format).unwrap();
        let m = extract(&cleaned, None, &l).expect("cleaned file must open");
        assert_eq!(m.format, before.format, "{f}");
        assert_eq!(m.author, None, "{f}");
        assert_eq!(m.last_modified_by, None, "{f}");
        assert!(
            m.company.is_none()
                && m.custom.is_empty()
                && m.rsids.is_empty()
                && m.printers.is_empty(),
            "{f}: {m:?}"
        );
        let names: Vec<&str> = m
            .people
            .iter()
            .filter(|p| p.role != foca_core::PersonRole::PathUser)
            .map(|p| p.name.as_str())
            .collect();
        for p in &before.people {
            if p.role != foca_core::PersonRole::PathUser {
                assert!(
                    !names.contains(&p.name.as_str()),
                    "{f}: {} still present",
                    p.name
                );
            }
        }
        assert!(m.comments.iter().all(|c| c.author.is_none()), "{f}");
        assert!(m.revisions.iter().all(|r| r.author.is_none()), "{f}");
        // document and comment text is unchanged (data connection strings are blanked)
        let strip = |t: String| -> String {
            t.lines()
                .map(|l| if l.contains("Provider=") { "" } else { l })
                .collect::<Vec<_>>()
                .join("\n")
        };
        assert_eq!(
            strip(text(&cleaned, &l).unwrap()),
            strip(text(&orig, &l).unwrap()),
            "{f}"
        );
        assert_eq!(m.comments.len(), before.comments.len());
        // embedded photos are cleaned as well
        for e in &m.embedded {
            assert!(
                e.metadata.gps.is_none() && e.metadata.camera.is_none(),
                "{f}: {}",
                e.name
            );
        }
        // the zip is valid: every entry can be read
        let mut z = zip::ZipArchive::new(std::io::Cursor::new(&cleaned)).unwrap();
        for i in 0..z.len() {
            let mut e = z.by_index(i).unwrap();
            std::io::copy(&mut e, &mut std::io::sink()).unwrap();
        }
    }
}

#[test]
fn clean_jpeg_removes_exif() {
    let l = Limits::default();
    for f in [
        "images/photo.jpg",
        "real/exiftool-GPS.jpg",
        "real/exiftool-ExifTool.jpg",
    ] {
        let orig = load(f);
        let cleaned = clean(&orig, DocFormat::Jpeg).unwrap();
        assert!(cleaned.len() < orig.len());
        let m = extract(&cleaned, None, &l).unwrap();
        assert_eq!(m.format, DocFormat::Jpeg);
        assert!(
            m.gps.is_none()
                && m.camera.is_none()
                && m.author.is_none()
                && m.thumbnail.is_none()
                && m.xmp.is_empty(),
            "{f}: {m:?}"
        );
        assert!(cleaned.ends_with(&[0xFF, 0xD9]), "{f}");
    }
    let png = clean(&load("images/screenshot.png"), DocFormat::Png).unwrap();
    let m = extract(&png, None, &l).unwrap();
    assert!(
        m.author.is_none() && m.camera.is_none() && m.xmp.is_empty() && m.fields.is_empty(),
        "{m:?}"
    );
    assert!(png.ends_with(b"IEND\xaeB`\x82"));
    assert!(clean(&load("pdf/report.pdf"), DocFormat::Jpeg).is_err());
    // PDF is cleaned by a full rewrite (see tests/hygiene.rs); unsupported formats still fail
    assert!(clean(&load("pdf/report.pdf"), DocFormat::Pdf).is_ok());
    assert!(clean(&load("mail/budget.eml"), DocFormat::Eml).is_err());
}

/// Truncated and corrupted corpus files do not crash the parser (deterministic PRNG).
#[test]
fn truncated_and_mutated_corpus_never_panics() {
    let limits = Limits::default();
    let mut seed: u64 = 0x9E37_79B9_7F4A_7C15;
    let mut next = || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };
    for f in corpus_files() {
        let bytes = std::fs::read(&f).unwrap();
        let n = bytes.len();
        for k in 1..=24 {
            let cut = n * k / 25;
            let _ = extract(&bytes[..cut], None, &limits);
        }
        for _ in 0..24 {
            let mut m = bytes.clone();
            for _ in 0..(1 + next() % 8) {
                let i = (next() as usize) % n.max(1);
                if let Some(b) = m.get_mut(i) {
                    *b = next() as u8;
                }
            }
            let _ = extract(&m, None, &limits);
            let _ = text(&m, &limits);
        }
    }
}
