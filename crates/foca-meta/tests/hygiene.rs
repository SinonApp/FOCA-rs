//! Cleaning (PDF full rewrite, ODF), before/after self-check and hygiene grade.
//!
//! Fixtures are synthetic (see `hygiene_gen`, also written to `tests/fixtures/hygiene/` by
//! `cargo run -p foca-meta --example make_hygiene_fixtures`).

mod hygiene_gen;

use std::io::Cursor;
use std::path::Path;

use foca_meta::{
    can_clean, clean_and_verify, clean_with_options, detect, extract, grade_document, grade_set,
    text, ChangeKind, CleanOptions, CleanWarning, DocFormat, FixCode, Grade, IssueCode, Limits,
    MetaError, Metadata,
};
use hygiene_gen::{KEPT_TEXT, REMOVED_TEXT};

fn lim() -> Limits {
    Limits::default()
}

fn fixture(rel: &str) -> Vec<u8> {
    let p = Path::new(env!("CARGO_MANIFEST_DIR")).join(rel);
    std::fs::read(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display()))
}

fn corpus(rel: &str) -> Vec<u8> {
    fixture(&format!("../../tests/corpus/{rel}"))
}

fn count(h: &[u8], n: &[u8]) -> usize {
    h.windows(n.len()).filter(|w| *w == n).count()
}

fn contains(h: &[u8], n: &str) -> bool {
    count(h, n.as_bytes()) > 0
}

fn zip_entry(b: &[u8], name: &str) -> Option<String> {
    use std::io::Read;
    let mut z = zip::ZipArchive::new(Cursor::new(b)).ok()?;
    let mut f = z.by_name(name).ok()?;
    let mut s = String::new();
    f.read_to_string(&mut s).ok()?;
    Some(s)
}

#[test]
fn pdf_rewrite_collapses_revisions_and_drops_metadata() {
    let src = hygiene_gen::pdf_revisions();
    let before = extract(&src, None, &lim()).unwrap();
    assert_eq!(before.incremental_updates, Some(1));
    assert_eq!(before.stats.get("pages"), Some(&2));
    assert!(before
        .pdf_revisions
        .iter()
        .any(|r| r.removed_text.iter().any(|t| t.contains(REMOVED_TEXT))));

    let r = clean_and_verify(&src, DocFormat::Pdf, &CleanOptions::default(), &lim()).unwrap();
    let rep = &r.report;
    assert!(rep.valid, "{:?}", rep.error);
    assert!(rep.clean, "remaining: {:?}", rep.changes);
    assert_eq!(rep.pages_before, Some(2));
    assert_eq!(rep.pages_after, Some(2));
    assert_eq!(rep.text_preserved, Some(true));
    for w in [
        CleanWarning::RevisionsCollapsed { count: 1 },
        CleanWarning::AnnotationAuthorsRemoved { count: 1 },
    ] {
        assert!(rep.warnings.contains(&w), "{:?}", rep.warnings);
    }
    assert!(rep
        .warnings
        .iter()
        .any(|w| matches!(w, CleanWarning::JavascriptRemoved { .. })));
    assert!(rep
        .warnings
        .iter()
        .any(|w| matches!(w, CleanWarning::EmbeddedFilesRemoved { .. })));

    // One revision, removed text physically gone, kept text still extractable.
    let b = &r.bytes;
    assert_eq!(count(b, b"%%EOF"), 1);
    assert_eq!(count(b, b"startxref"), 1);
    assert!(!contains(b, REMOVED_TEXT));
    for gone in [
        "/Info",
        "/Metadata",
        "/PieceInfo",
        "/Thumb",
        "/JavaScript",
        "/OpenAction",
        "/EmbeddedFile",
        "xpacket",
    ] {
        assert!(!contains(b, gone), "{gone} left in the clean copy");
    }
    let t = text(b, &lim()).unwrap();
    assert!(t.contains(KEPT_TEXT) && t.contains("Page two body") && t.contains("Approved"));
    assert!(
        t.contains("Check the numbers"),
        "annotation text is content"
    );

    let after = extract(b, None, &lim()).unwrap();
    assert_eq!(after.incremental_updates, Some(0));
    assert!(after.people.is_empty() && after.author.is_none() && after.xmp.is_empty());
    assert!(after.attachments.is_empty() && !after.has_javascript);
    assert!(after.comments.iter().all(|c| c.author.is_none()));

    // Diff rows: field, before, after.
    let author = rep.changes.iter().find(|c| c.field == "author").unwrap();
    assert_eq!(author.before.as_deref(), Some("Taras Bondar"));
    assert_eq!(author.after, None);
    assert_eq!(author.change, ChangeKind::Removed);
    assert!(author.sensitive);
    let pages = rep
        .changes
        .iter()
        .find(|c| c.field == "stats.pages")
        .unwrap();
    assert_eq!(pages.change, ChangeKind::Kept);
    assert!(!pages.sensitive);
    assert!(rep
        .changes
        .iter()
        .any(|c| c.field.starts_with("old_versions.") && c.change == ChangeKind::Removed));
}

#[test]
fn pdf_option_flags_keep_what_was_asked() {
    let src = hygiene_gen::pdf_revisions();
    let opts = CleanOptions {
        remove_embedded_files: false,
        remove_javascript: false,
        remove_annotation_authors: false,
    };
    let out = clean_with_options(&src, DocFormat::Pdf, &opts, &lim()).unwrap();
    assert!(out.warnings.contains(&CleanWarning::EmbeddedFilesKept));
    let m = extract(&out.bytes, None, &lim()).unwrap();
    assert!(m.has_javascript);
    assert_eq!(m.attachments.len(), 1);
    assert!(m
        .comments
        .iter()
        .any(|c| c.author.as_deref() == Some("Olena Kovalenko")));
    // Info, XMP and the old revision are removed regardless of the flags.
    assert!(m.author.is_none() && m.xmp.is_empty());
    assert_eq!(m.incremental_updates, Some(0));
    assert!(!contains(&out.bytes, REMOVED_TEXT));
}

#[test]
fn pdf_object_and_xref_streams_are_read_and_flattened() {
    let src = hygiene_gen::pdf_objstm();
    let before = extract(&src, None, &lim()).unwrap();
    assert_eq!(before.author.as_deref(), Some("Mykola Shevchuk"));
    let r = clean_and_verify(&src, DocFormat::Pdf, &CleanOptions::default(), &lim()).unwrap();
    assert!(r.report.clean, "{:?}", r.report);
    assert_eq!(r.report.pages_after, Some(1));
    assert_eq!(r.report.text_preserved, Some(true));
    assert!(!contains(&r.bytes, "/ObjStm") && !contains(&r.bytes, "/XRef"));
    assert!(contains(&r.bytes, "\nxref\n0 "));
    assert!(text(&r.bytes, &lim())
        .unwrap()
        .contains("Compressed object streams"));
}

#[test]
fn pdf_signatures_are_removed_with_warning() {
    for f in [
        "tests/fixtures/forensics/signed.pdf",
        "tests/fixtures/forensics/signed_modified.pdf",
        "tests/fixtures/forensics/timestamp.pdf",
    ] {
        let src = fixture(f);
        assert!(!extract(&src, None, &lim()).unwrap().signatures.is_empty());
        let r = clean_and_verify(&src, DocFormat::Pdf, &CleanOptions::default(), &lim()).unwrap();
        assert!(r.report.clean, "{f}: {:?}", r.report);
        assert!(
            r.report
                .warnings
                .iter()
                .any(|w| matches!(w, CleanWarning::SignatureRemoved { .. })),
            "{f}"
        );
        assert!(!contains(&r.bytes, "/ByteRange") && !contains(&r.bytes, "/SigFlags"));
        let m = extract(&r.bytes, None, &lim()).unwrap();
        assert!(m.signatures.is_empty(), "{f}");
        let sig = r.report.changes.iter().find(|c| c.field == "signatures");
        assert_eq!(sig.map(|c| c.change), Some(ChangeKind::Removed), "{f}");
    }
}

#[test]
fn ooxml_signatures_are_removed_consistently() {
    let src = fixture("tests/fixtures/forensics/signed_hidden.docx");
    let r = clean_and_verify(&src, DocFormat::Docx, &CleanOptions::default(), &lim()).unwrap();
    assert!(r.report.clean, "{:?}", r.report);
    assert!(r
        .report
        .warnings
        .iter()
        .any(|w| matches!(w, CleanWarning::SignatureRemoved { .. })));
    let mut z = zip::ZipArchive::new(Cursor::new(r.bytes.as_slice())).unwrap();
    let names: Vec<String> = (0..z.len())
        .map(|i| z.by_index_raw(i).unwrap().name().unwrap().to_string())
        .collect();
    assert!(names.iter().all(|n| !n.starts_with("_xmlsignatures/")));
    for part in ["[Content_Types].xml", "_rels/.rels"] {
        let x = zip_entry(&r.bytes, part).unwrap();
        assert!(!x.contains("_xmlsignatures"), "{part}: {x}");
    }
}

#[test]
fn encrypted_pdf_is_refused() {
    let e = clean_with_options(
        &hygiene_gen::pdf_encrypted(),
        DocFormat::Pdf,
        &CleanOptions::default(),
        &lim(),
    )
    .unwrap_err();
    assert!(
        matches!(&e, MetaError::Unsupported(m) if m.contains("зашифрован")),
        "{e}"
    );
}

#[test]
fn odf_clean_is_valid_and_metadata_free() {
    let src = hygiene_gen::odt_full();
    assert_eq!(detect(&src), DocFormat::Odt);
    let before = extract(&src, None, &lim()).unwrap();
    assert!(before.people.len() >= 2 && before.custom.contains_key("Department"));

    let r = clean_and_verify(&src, DocFormat::Odt, &CleanOptions::default(), &lim()).unwrap();
    assert!(r.report.valid, "{:?}", r.report.error);
    assert!(r.report.clean, "{:?}", r.report.changes);
    for w in [
        CleanWarning::ThumbnailRemoved,
        CleanWarning::VersionsRemoved { count: 2 },
        CleanWarning::AnnotationAuthorsRemoved { count: 2 },
    ] {
        assert!(r.report.warnings.contains(&w), "{:?}", r.report.warnings);
    }

    // Packaging: mimetype first and stored, removed parts absent.
    let b = &r.bytes;
    let mut z = zip::ZipArchive::new(Cursor::new(b.as_slice())).unwrap();
    {
        let first = z.by_index_raw(0).unwrap();
        assert_eq!(first.name().unwrap(), "mimetype");
        assert_eq!(first.compression(), zip::CompressionMethod::Stored);
    }
    let names: Vec<String> = (0..z.len())
        .map(|i| z.by_index_raw(i).unwrap().name().unwrap().to_string())
        .collect();
    assert!(names.iter().all(|n| !n.starts_with("Thumbnails/")
        && !n.starts_with("Versions/")
        && n != "VersionList.xml"));

    let manifest = zip_entry(b, "META-INF/manifest.xml").unwrap();
    assert!(!manifest.contains("Thumbnails") && !manifest.contains("VersionList"));
    assert!(manifest.contains("content.xml"));
    let meta = zip_entry(b, "meta.xml").unwrap();
    assert!(meta.contains("meta:document-statistic"));
    for gone in [
        "Olena",
        "o.kovalenko",
        "generator",
        "creation-date",
        "editing-cycles",
        "Finance",
        "memo.ott",
    ] {
        assert!(!meta.contains(gone), "{gone} left in meta.xml");
    }
    let settings = zip_entry(b, "settings.xml").unwrap();
    assert!(!settings.contains("PRN-SRV01") && !settings.contains("PrinterSetup"));
    assert!(!settings.contains("addresses.odb"));
    assert!(settings.contains("AddExternalLeading") && settings.contains("ViewAreaTop"));
    let content = zip_entry(b, "content.xml").unwrap();
    assert!(!content.contains("Taras Bondar"));
    assert!(content.contains("Quarterly budget &amp; plan") && content.contains("Recheck totals"));

    let after = extract(b, None, &lim()).unwrap();
    assert!(after.people.is_empty() && after.custom.is_empty() && after.template.is_none());
    assert_eq!(after.stats.get("pages"), Some(&1));
    assert_eq!(after.comments.len(), 1);
    assert!(text(b, &lim()).unwrap().contains("Second paragraph"));
}

#[test]
fn odf_corpus_letter_with_picture() {
    let src = corpus("odf/letter.odt");
    let r = clean_and_verify(&src, DocFormat::Odt, &CleanOptions::default(), &lim()).unwrap();
    assert!(r.report.clean, "{:?}", r.report);
    let after = extract(&r.bytes, None, &lim()).unwrap();
    // the embedded JPEG lost its EXIF (GPS, camera)
    assert!(after.embedded.iter().all(|e| e.metadata.gps.is_none()));
    // body hyperlinks are content: kept and reported separately
    assert!(r
        .report
        .changes
        .iter()
        .any(|c| c.field == "content.paths" && !c.sensitive));
}

/// Self-check works for every format the cleaner supports.
#[test]
fn self_check_on_all_cleanable_corpus_files() {
    let mut seen = 0;
    let mut stack = vec![Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/corpus")];
    while let Some(d) = stack.pop() {
        for e in std::fs::read_dir(&d).unwrap().flatten() {
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
                continue;
            }
            let b = std::fs::read(&p).unwrap();
            let k = detect(&b);
            if !can_clean(k) || p.extension().is_some_and(|x| x == "json") {
                continue;
            }
            let Ok(r) = clean_and_verify(&b, k, &CleanOptions::default(), &lim()) else {
                continue; // e.g. encrypted
            };
            seen += 1;
            assert!(r.report.valid, "{}: {:?}", p.display(), r.report.error);
            assert!(
                r.report.clean,
                "{}: {:?}",
                p.display(),
                r.report
                    .changes
                    .iter()
                    .filter(|c| c.sensitive && c.after.is_some())
                    .collect::<Vec<_>>()
            );
        }
    }
    assert!(seen >= 8, "only {seen} cleanable corpus files");
}

#[test]
fn grade_document_and_set() {
    let clean = Metadata::new(DocFormat::Pdf);
    let g = grade_document(&clean);
    assert_eq!((g.grade, g.score), (Grade::A, 100));
    assert!(g.issues.is_empty());

    let leaky = extract(&hygiene_gen::pdf_revisions(), None, &lim()).unwrap();
    let g = grade_document(&leaky);
    assert!(g.grade >= Grade::E, "{g:?}");
    let codes: Vec<IssueCode> = g.issues.iter().map(|i| i.code).collect();
    for c in [
        IssueCode::People,
        IssueCode::PdfRevisions,
        IssueCode::PdfRemovedText,
        IssueCode::EmbeddedFiles,
        IssueCode::Javascript,
    ] {
        assert!(codes.contains(&c), "{c:?} missing in {codes:?}");
    }
    let removed = g
        .issues
        .iter()
        .find(|i| i.code == IssueCode::PdfRemovedText)
        .unwrap();
    assert_eq!(removed.fix.code, FixCode::RewritePdf);
    assert!(removed.fix.auto);
    assert_eq!(g.issues[0].severity, foca_core::Severity::Critical);

    // after cleaning only content-level issues may remain
    let r = clean_and_verify(
        &hygiene_gen::pdf_revisions(),
        DocFormat::Pdf,
        &CleanOptions::default(),
        &lim(),
    )
    .unwrap();
    let g2 = grade_document(&extract(&r.bytes, None, &lim()).unwrap());
    assert!(g2.grade < g.grade, "{g2:?}");
    assert!(g2.issues.iter().all(|i| !i.fix.auto), "{:?}", g2.issues);

    // signatures are neutral
    let signed = extract(
        &fixture("tests/fixtures/forensics/timestamp.pdf"),
        None,
        &lim(),
    )
    .unwrap();
    let gs = grade_document(&signed);
    let s = gs
        .issues
        .iter()
        .find(|i| i.code == IssueCode::Signed)
        .unwrap();
    assert_eq!(s.severity, foca_core::Severity::Info);
    assert_eq!(s.fix.code, FixCode::ResignAfterCleaning);

    // non-cleanable format: metadata steps become "export and clean"
    let mut msg = Metadata::new(DocFormat::Msg);
    msg.author = Some("A".into());
    msg.add_person("Ivan", foca_core::PersonRole::Author, "x");
    let gm = grade_document(&msg);
    assert!(!gm.cleanable);
    assert_eq!(gm.issues[0].fix.code, FixCode::ExportAndClean);
    assert!(!gm.issues[0].fix.auto);

    let set = grade_set(&[g.clone(), g2.clone(), gs.clone()]);
    assert_eq!(set.documents, 3);
    assert_eq!(set.worst, Some(g.grade));
    assert!(set.grade <= g.grade && set.grade >= Grade::A);
    assert_eq!(set.by_grade.values().sum::<u32>(), 3);
    assert!(!set.issues.is_empty());
    let empty = grade_set(&[]);
    assert_eq!(
        (empty.grade, empty.score, empty.worst),
        (Grade::A, 100, None)
    );
}

/// Mutated and truncated inputs never panic in `clean_pdf`/`clean_odf` (a panic would surface
/// as the guard's "internal error" message) and every successful result re-parses.
#[test]
fn fuzz_clean_pdf_odf_120() {
    let mut seeds: Vec<(DocFormat, Vec<u8>)> = vec![
        (DocFormat::Pdf, hygiene_gen::pdf_revisions()),
        (DocFormat::Pdf, hygiene_gen::pdf_objstm()),
        (
            DocFormat::Pdf,
            fixture("tests/fixtures/forensics/signed.pdf"),
        ),
        (
            DocFormat::Pdf,
            fixture("tests/fixtures/forensics/redacted.pdf"),
        ),
        (DocFormat::Pdf, corpus("pdf/report.pdf")),
        (DocFormat::Odt, hygiene_gen::odt_full()),
        (DocFormat::Odt, corpus("odf/letter.odt")),
    ];
    seeds.push((DocFormat::Ods, corpus("odf/encrypted.ods")));
    let mut seed: u64 = 0xB1B1_2026_0000_0001;
    let mut next = || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };
    let opts = CleanOptions::default();
    let check = |kind: DocFormat, b: &[u8]| match clean_with_options(b, kind, &opts, &lim()) {
        Ok(out) => {
            let _ = extract(&out.bytes, None, &lim());
            let _ = foca_meta::verify_clean(b, &out.bytes, kind, &lim());
        }
        Err(e) => assert!(
            !e.to_string().contains("внутренняя ошибка"),
            "panic inside the cleaner: {e}"
        ),
    };
    for (kind, bytes) in &seeds {
        let n = bytes.len();
        for k in 1..=20 {
            check(*kind, &bytes[..n * k / 21]);
        }
        for _ in 0..120 {
            let mut m = bytes.clone();
            for _ in 0..(1 + next() % 12) {
                let i = (next() as usize) % m.len().max(1);
                match next() % 4 {
                    _ if m.is_empty() => m.push(next() as u8),
                    0 => m[i] = next() as u8,
                    1 => m[i] = b"0123456789<>[]()/R \n"[(next() % 20) as usize],
                    2 if m.len() > 2 => {
                        m.remove(i.min(m.len() - 1));
                    }
                    _ => m.insert(i, next() as u8),
                }
            }
            check(*kind, &m);
        }
    }
}
