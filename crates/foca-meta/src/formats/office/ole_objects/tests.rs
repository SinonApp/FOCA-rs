//! Embedded OLE objects, pictures, CompObj, recursion limits and cycle protection.

use std::cell::{Cell, RefCell};
use std::io::{Cursor, Write};

use crate::{extract, text, Ctx, DocFormat, Limits, Metadata};

pub(crate) fn cfb(streams: &[(&str, Vec<u8>)]) -> Vec<u8> {
    let mut c = cfb::CompoundFile::create(Cursor::new(Vec::new())).unwrap();
    for (path, data) in streams {
        if let Some((parent, _)) = path.rsplit_once('/') {
            if !parent.is_empty() {
                c.create_storage_all(parent).unwrap();
            }
        }
        c.create_stream(path).unwrap().write_all(data).unwrap();
    }
    c.flush().unwrap();
    c.into_inner().into_inner()
}

fn rec(ty: u16, data: &[u8]) -> Vec<u8> {
    let mut v = ty.to_le_bytes().to_vec();
    v.extend_from_slice(&(data.len() as u16).to_le_bytes());
    v.extend_from_slice(data);
    v
}

/// Minimal BIFF8 workbook whose WRITEACCESS names `user`.
pub(crate) fn workbook(user: &str) -> Vec<u8> {
    let mut bof = 0x0600u16.to_le_bytes().to_vec();
    bof.extend_from_slice(&5u16.to_le_bytes());
    bof.extend_from_slice(&[0; 12]);
    let mut wa = (user.encode_utf16().count() as u16).to_le_bytes().to_vec();
    wa.push(1);
    wa.extend(user.encode_utf16().flat_map(u16::to_le_bytes));
    let mut v = rec(0x0809, &bof);
    v.extend(rec(0x005C, &wa));
    v.extend(rec(0x000A, &[]));
    v
}

fn compobj(user: &str, prog: &str) -> Vec<u8> {
    let mut v = vec![0u8; 28];
    for s in [user, prog] {
        if s == prog {
            v.extend_from_slice(&0u32.to_le_bytes());
        }
        let mut z = s.as_bytes().to_vec();
        z.push(0);
        v.extend_from_slice(&(z.len() as u32).to_le_bytes());
        v.extend_from_slice(&z);
    }
    v
}

#[test]
fn doc_with_embedded_workbook_storage() {
    let doc = cfb(&[
        ("/WordDocument", vec![0; 64]),
        (
            "/\u{1}CompObj",
            compobj("Microsoft Word-Dokument", "Word.Document.8"),
        ),
        ("/ObjectPool/_1457338542/Workbook", workbook("Олена Коваль")),
        (
            "/ObjectPool/_1457338542/\u{1}CompObj",
            compobj("Microsoft Excel 97-Tabelle", "Excel.Sheet.8"),
        ),
        ("/ObjectPool/_99/EPRINT", vec![1, 2, 3]),
    ]);
    let m = extract(&doc, Some("a.doc"), &Limits::default()).unwrap();
    assert_eq!(m.format, DocFormat::Doc);
    assert_eq!(
        m.fields.get("ole:CompObjUserType").map(String::as_str),
        Some("Microsoft Word-Dokument (Word.Document.8)")
    );
    assert_eq!(m.embedded.len(), 1, "{:?}", m.warnings);
    let child = &m.embedded[0].metadata;
    assert_eq!(child.format, DocFormat::Xls);
    assert_eq!(
        child.fields.get("xls:WriteAccess").map(String::as_str),
        Some("Олена Коваль")
    );
    assert!(child
        .fields
        .get("ole:CompObjUserType")
        .is_some_and(|t| t.contains("Excel 97-Tabelle")));
    // the storage without a parsable document stays an attachment
    assert_eq!(m.attachments.len(), 1);
}

/// A document whose object pool holds `inner` as a Package stream.
fn wrap(inner: &[u8]) -> Vec<u8> {
    cfb(&[
        ("/WordDocument", vec![0; 64]),
        ("/ObjectPool/_1/Package", inner.to_vec()),
    ])
}

#[test]
fn recursion_stops_at_the_depth_limit() {
    let mut v = cfb(&[("/Workbook", workbook("innermost"))]);
    for _ in 0..6 {
        v = wrap(&v);
    }
    let m = extract(&v, Some("a.doc"), &Limits::default()).unwrap();
    let mut depth = 0;
    let mut cur = &m;
    while let Some(e) = cur.embedded.first() {
        depth += 1;
        cur = &e.metadata;
    }
    assert_eq!(depth, Limits::default().max_depth as usize);
}

#[test]
fn a_document_on_its_own_ancestor_chain_is_skipped() {
    let child = cfb(&[("/Workbook", workbook("loop"))]);
    let limits = Limits::default();
    let budget = Cell::new(limits.max_unzipped_total);
    let chain = RefCell::new(vec![crate::content_hash(&child)]);
    let ctx = Ctx::with_embedded(&limits, &budget, &chain, crate::extract_embedded);
    assert!(ctx.extract_child(&child, "x.xls").is_none());
    let mut m = Metadata::default();
    ctx.attach_child(&mut m, &child, "x.xls", "x").unwrap();
    assert!(m.embedded.is_empty());
    // a different document on the same chain is parsed
    let other = cfb(&[("/Workbook", workbook("other"))]);
    assert!(ctx.extract_child(&other, "y.xls").is_some());
    assert_eq!(chain.borrow().len(), 1);
}

#[test]
fn many_embedded_objects_stay_within_limits() {
    let inner = cfb(&[("/Workbook", workbook("x"))]);
    let mut streams = vec![("/WordDocument".to_string(), vec![0u8; 64])];
    for i in 0..400 {
        streams.push((format!("/ObjectPool/_{i}/Package"), inner.clone()));
    }
    let refs: Vec<(&str, Vec<u8>)> = streams
        .iter()
        .map(|(p, d)| (p.as_str(), d.clone()))
        .collect();
    let doc = cfb(&refs);
    let m = extract(&doc, Some("a.doc"), &Limits::default()).unwrap();
    assert!(m.embedded.len() <= crate::MAX_CHILDREN);
    assert!(!m.embedded.is_empty());
    // a small budget turns the bomb into an error instead of unbounded work
    let small = Limits {
        max_unzipped_total: 64 * 1024,
        ..Limits::default()
    };
    assert!(extract(&doc, Some("a.doc"), &small).is_err());
}

fn png() -> Vec<u8> {
    let mut v = b"\x89PNG\r\n\x1a\n".to_vec();
    let ihdr = [0u8, 0, 0, 1, 0, 0, 0, 1, 8, 2, 0, 0, 0];
    v.extend_from_slice(&13u32.to_be_bytes());
    v.extend_from_slice(b"IHDR");
    v.extend_from_slice(&ihdr);
    v.extend_from_slice(&[0; 4]);
    let t = b"Author\0Photo Owner";
    v.extend_from_slice(&(t.len() as u32).to_be_bytes());
    v.extend_from_slice(b"tEXt");
    v.extend_from_slice(t);
    v.extend_from_slice(&[0; 4]);
    v.extend_from_slice(&[0; 4]);
    v.extend_from_slice(b"IEND");
    v.extend_from_slice(&[0xAE, 0x42, 0x60, 0x82]);
    v
}

/// OfficeArt PNG BLIP record (one uid, tag byte).
pub(crate) fn png_blip() -> Vec<u8> {
    let img = png();
    let mut v = ((0x6E0u16 << 4).to_le_bytes()).to_vec();
    v.extend_from_slice(&0xF01Eu16.to_le_bytes());
    v.extend_from_slice(&((img.len() + 17) as u32).to_le_bytes());
    v.extend_from_slice(&[7; 16]);
    v.push(0xFF);
    v.extend(img);
    v
}

#[test]
fn word_data_stream_pictures() {
    let mut data = vec![0u8; 68];
    data.extend(png_blip());
    data.extend(png_blip());
    let mut emf = (0x3D4u16 << 4).to_le_bytes().to_vec();
    emf.extend_from_slice(&0xF01Au16.to_le_bytes());
    emf.extend_from_slice(&60u32.to_le_bytes());
    emf.extend_from_slice(&[1; 60]);
    data.extend(emf);
    let doc = cfb(&[("/WordDocument", vec![0; 64]), ("/Data", data)]);
    let m = extract(&doc, Some("a.doc"), &Limits::default()).unwrap();
    assert_eq!(m.embedded.len(), 1, "identical pictures are listed once");
    assert!(m.embedded[0]
        .metadata
        .people
        .iter()
        .any(|p| p.name == "Photo Owner"));
    assert_eq!(m.attachments.len(), 1);
}

#[test]
fn standalone_ole_object_package() {
    // word/embeddings/oleObject1.bin style: a Package stream at the root
    let inner = cfb(&[("/Workbook", workbook("pkg user"))]);
    let obj = cfb(&[("/Package", inner)]);
    let m = extract(&obj, Some("oleObject1.bin"), &Limits::default()).unwrap();
    assert_eq!(m.embedded.len(), 1);
    assert!(text(&obj, &Limits::default()).is_ok());
}

#[test]
fn officeart_picture_source_and_alt_text() {
    let z = |s: &str| -> Vec<u8> {
        let mut v: Vec<u8> = s.encode_utf16().flat_map(u16::to_le_bytes).collect();
        v.extend_from_slice(&[0, 0]);
        v
    };
    let pib = z("D:\\Мои документы\\логотип.png");
    let alt = z("Схема сети");
    let mut body = Vec::new();
    for (id, data) in [(0x0105u16 | 0xC000, &pib), (0x0381 | 0x8000, &alt)] {
        body.extend_from_slice(&id.to_le_bytes());
        body.extend_from_slice(&(data.len() as u32).to_le_bytes());
    }
    body.extend_from_slice(&0x007Fu16.to_le_bytes());
    body.extend_from_slice(&1u32.to_le_bytes());
    body.extend_from_slice(&pib);
    body.extend_from_slice(&alt);
    let mut rec = ((3u16 << 4) | 3).to_le_bytes().to_vec();
    rec.extend_from_slice(&0xF00Bu16.to_le_bytes());
    rec.extend_from_slice(&(body.len() as u32).to_le_bytes());
    rec.extend(body);
    let mut tbl = vec![0u8; 33];
    tbl.extend(rec);
    let doc = cfb(&[("/WordDocument", vec![0; 64]), ("/1Table", tbl)]);
    let m = extract(&doc, Some("a.doc"), &Limits::default()).unwrap();
    assert!(
        m.paths.iter().any(|p| p.path.ends_with("логотип.png")),
        "{:?}",
        m.fields
    );
    assert_eq!(
        m.fields.get("officeart:altText").map(String::as_str),
        Some("Схема сети")
    );
}
