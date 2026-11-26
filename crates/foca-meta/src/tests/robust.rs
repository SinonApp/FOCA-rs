//! Robustness tests: random bytes, signature mutations, zip bombs and limits.

use std::io::{Cursor, Write};

use crate::util::Rng;
use crate::{extract, text, Limits, MetaError};

fn zip_with(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut w = zip::ZipWriter::new(Cursor::new(Vec::new()));
    let opts = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated);
    for (n, d) in entries {
        w.start_file(*n, opts).unwrap();
        w.write_all(d).unwrap();
    }
    w.finish().unwrap().into_inner()
}

#[test]
fn random_bytes_never_panic() {
    let mut rng = Rng(0x5EED_1234_ABCD_0001);
    let prefixes: [&[u8]; 9] = [
        b"",
        b"PK\x03\x04",
        b"%PDF-1.7\n",
        &[0xFF, 0xD8, 0xFF, 0xE1],
        b"\x89PNG\r\n\x1a\n",
        b"II*\0",
        &[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1],
        b"<svg ",
        b"full address:s:",
    ];
    let limits = Limits::default();
    for i in 0..1500 {
        let len = (rng.next() % 2048) as usize;
        let mut v: Vec<u8> = prefixes[i % prefixes.len()].to_vec();
        v.extend((0..len).map(|_| rng.next() as u8));
        let _ = extract(&v, Some("x.bin"), &limits);
        let _ = text(&v, &limits);
    }
}

#[test]
fn pdf_garbage_structures() {
    let limits = Limits::default();
    let cases: [&[u8]; 7] = [
        b"%PDF-1.4\n1 0 obj << /Length 2 0 R >> stream\nabc\nendstream endobj 2 0 obj 2 0 R endobj trailer << /Info 3 0 R >> 3 0 obj 3 0 R endobj %%EOF",
        b"%PDF-1.4\n1 0 obj << /A 1 0 R /Info 1 0 R >> endobj trailer << /Info 1 0 R /Root 1 0 R >>%%EOF",
        b"%PDF-1.4\n1 0 obj << /Type /ObjStm /N 999999 /First 5 /Length 3 >> stream\n1 0 2\nendstream endobj",
        b"%PDF-1.4\n1 0 obj << /Length 99999999999 /Filter /FlateDecode >> stream\nxx",
        b"%PDF-1.4\n1 0 obj (((((((((((\\",
        b"%PDF-1.4\n1 0 obj <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<",
        b"%PDF-1.4\n 0 obj 99999999999 0 obj 4294967295 65535 obj endobj",
    ];
    for c in cases {
        let _ = extract(c, None, &limits);
        let _ = text(c, &limits);
    }
    // very deep array nesting
    let mut deep = b"%PDF-1.4\n1 0 obj ".to_vec();
    deep.extend(std::iter::repeat_n(b'[', 200_000));
    let _ = extract(&deep, None, &limits);
}

#[test]
fn zip_bomb_rejected() {
    // 20 MiB of zeros compress to about 20 KiB; the decompression budget is 1 MiB
    let zeros = vec![0u8; 20 * 1024 * 1024];
    let core = br#"<?xml version="1.0"?><cp:coreProperties xmlns:cp="c" xmlns:dc="d"><dc:creator>X</dc:creator></cp:coreProperties>"#;
    let z = zip_with(&[
        ("[Content_Types].xml", b"<Types/>"),
        ("word/document.xml", &zeros),
        ("docProps/core.xml", core),
    ]);
    assert!(z.len() < 200_000, "{}", z.len());
    let limits = Limits {
        max_unzipped_total: 1024 * 1024,
        ..Limits::default()
    };
    let r = extract(&z, None, &limits);
    assert!(matches!(r, Err(MetaError::ZipBomb(_))), "{r:?}");
    assert!(matches!(text(&z, &limits), Err(MetaError::ZipBomb(_))));
}

#[test]
fn nested_zip_bomb_budget_is_shared() {
    // docx inside docx inside docx: each embedded file is 400 KiB, total budget 1 MiB
    let pad = vec![b'a'; 400 * 1024];
    let mut inner = zip_with(&[
        ("[Content_Types].xml", b"<Types/>"),
        ("word/document.xml", &pad),
    ]);
    for _ in 0..3 {
        inner = zip_with(&[
            ("[Content_Types].xml", b"<Types/>"),
            ("word/document.xml", &pad),
            ("word/embeddings/x.docx", &inner),
        ]);
    }
    let limits = Limits {
        max_unzipped_total: 1024 * 1024,
        ..Limits::default()
    };
    assert!(matches!(
        extract(&inner, None, &limits),
        Err(MetaError::ZipBomb(_))
    ));
    // with a large budget and depth=1, exactly one level of embedded files is parsed
    let limits = Limits {
        max_depth: 1,
        ..Limits::default()
    };
    let m = extract(&inner, None, &limits).unwrap();
    assert_eq!(m.embedded.len(), 1);
    assert!(m.embedded[0].metadata.embedded.is_empty());
}

#[test]
fn too_many_entries_and_size() {
    let names: Vec<String> = (0..50).map(|i| format!("word/x{i}.xml")).collect();
    let mut entries: Vec<(&str, &[u8])> =
        names.iter().map(|n| (n.as_str(), &b"<a/>"[..])).collect();
    entries.push(("word/document.xml", b"<w:document/>"));
    let z = zip_with(&entries);
    let limits = Limits {
        max_entries: 10,
        ..Limits::default()
    };
    assert!(matches!(
        extract(&z, None, &limits),
        Err(MetaError::TooManyEntries(_))
    ));
    let limits = Limits {
        max_file: 10,
        ..Limits::default()
    };
    assert!(matches!(
        extract(&z, None, &limits),
        Err(MetaError::TooLarge { .. })
    ));
}

#[test]
fn xxe_in_docx_is_not_expanded() {
    let core = br#"<?xml version="1.0"?><!DOCTYPE c [<!ENTITY x SYSTEM "file:///etc/passwd">]><cp:coreProperties xmlns:cp="c" xmlns:dc="d"><dc:creator>&x;</dc:creator></cp:coreProperties>"#;
    let z = zip_with(&[
        ("word/document.xml", b"<w:document/>"),
        ("docProps/core.xml", core),
    ]);
    let m = extract(&z, None, &Limits::default()).unwrap();
    assert_eq!(m.author.as_deref(), Some("&x;"));
}

#[test]
fn deep_xml_rejected() {
    let deep = format!("<w:document>{}</w:document>", "<w:p>".repeat(1000));
    let z = zip_with(&[("word/document.xml", deep.as_bytes())]);
    let limits = Limits {
        max_xml_depth: 64,
        ..Limits::default()
    };
    assert!(matches!(
        extract(&z, None, &limits),
        Err(MetaError::TooDeep(_))
    ));
}

/// A path longer than 1024 bytes with a multi-byte char at the cut point is found (truncated on a
/// char boundary) without panicking. The minimal inputs come from fuzzing.
#[test]
fn long_path_with_multibyte_char_at_1024_does_not_panic() {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/robust/");
    for f in ["min_panic.docx", "min_panic.rdp"] {
        let b = std::fs::read(format!("{dir}{f}")).unwrap();
        let m = extract(&b, Some(f), &Limits::default()).unwrap_or_else(|e| panic!("{f}: {e:?}"));
        assert!(
            m.paths
                .iter()
                .any(|p| p.path.starts_with("C:\\") && p.path.len() <= 1024),
            "{f}: {:?}",
            m.paths
        );
        let _ = text(&b, &Limits::default());
    }
    // path discovery itself: U+3000 occupies bytes 1022..1025
    let s = format!("C:\\{}\u{3000}", "a".repeat(1019));
    let mut m = crate::Metadata {
        description: Some(s),
        ..Default::default()
    };
    crate::paths::finalize(&mut m);
    assert!(
        m.paths.iter().all(|p| p.path.len() <= 1024),
        "{:?}",
        m.paths
    );
}

/// A panic inside a parser is turned into a parse error.
#[test]
fn guard_turns_panic_into_malformed() {
    let r: Result<(), MetaError> = crate::guard("документ", || panic!("boom"));
    assert!(matches!(r, Err(MetaError::Malformed { .. })), "{r:?}");
}

#[test]
fn floor_char_boundary_basic() {
    let s = "ab\u{3000}c";
    assert_eq!(crate::util::floor_char_boundary(s, 3), 2);
    assert_eq!(crate::util::floor_char_boundary(s, 5), 5);
    assert_eq!(crate::util::floor_char_boundary(s, 99), s.len());
}
