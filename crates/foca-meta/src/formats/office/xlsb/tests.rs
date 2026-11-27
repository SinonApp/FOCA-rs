//! XLSB tests with a synthetic package.

use std::io::{Cursor, Write};

use crate::{extract, text, DocFormat, Limits};

fn varint(mut v: u32, out: &mut Vec<u8>) {
    loop {
        let b = (v & 0x7F) as u8;
        v >>= 7;
        if v == 0 {
            out.push(b);
            return;
        }
        out.push(b | 0x80);
    }
}

fn rec(ty: u32, data: &[u8]) -> Vec<u8> {
    let mut v = Vec::new();
    varint(ty, &mut v);
    varint(data.len() as u32, &mut v);
    v.extend_from_slice(data);
    v
}

fn wide(s: &str) -> Vec<u8> {
    let mut v = (s.encode_utf16().count() as u32).to_le_bytes().to_vec();
    v.extend(s.encode_utf16().flat_map(u16::to_le_bytes));
    v
}

fn cell(col: u32, value: &[u8]) -> Vec<u8> {
    let mut v = col.to_le_bytes().to_vec();
    v.extend_from_slice(&[0; 4]);
    v.extend_from_slice(value);
    v
}

fn package() -> Vec<u8> {
    let mut wb = Vec::new();
    for (state, name) in [(0u32, "Продажи"), (2, "Ключи")] {
        let mut d = state.to_le_bytes().to_vec();
        d.extend_from_slice(&1u32.to_le_bytes());
        d.extend(wide("rId1"));
        d.extend(wide(name));
        wb.extend(rec(0x9C, &d));
    }
    let mut sst = Vec::new();
    for s in ["株式会社テスト", "ivan.petrov@example.com"] {
        let mut d = vec![0u8];
        d.extend(wide(s));
        sst.extend(rec(0x13, &d));
    }
    let mut sh = rec(0, &[0; 8]);
    sh.extend(rec(7, &cell(0, &0u32.to_le_bytes())));
    sh.extend(rec(7, &cell(1, &1u32.to_le_bytes())));
    sh.extend(rec(0, &[0; 8]));
    sh.extend(rec(6, &cell(0, &wide("مرحبا بالعالم"))));
    sh.extend(rec(5, &cell(1, &4_915_112_345_678f64.to_le_bytes())));
    sh.extend(rec(5, &cell(2, &3.5f64.to_le_bytes())));
    let mut cm = rec(0x278, &wide("Олена Коваль"));
    cm.extend(rec(0x27B, &0u32.to_le_bytes()));
    let mut t = vec![0u8];
    t.extend(wide("Проверить ИНН"));
    cm.extend(rec(0x27D, &t));
    let mut w = zip::ZipWriter::new(Cursor::new(Vec::new()));
    let o = zip::write::SimpleFileOptions::default();
    for (n, d) in [
        ("[Content_Types].xml", b"<Types/>".to_vec()),
        ("xl/workbook.bin", wb),
        ("xl/sharedStrings.bin", sst),
        ("xl/worksheets/sheet1.bin", sh),
        ("xl/comments1.bin", cm),
    ] {
        w.start_file(n, o).unwrap();
        w.write_all(&d).unwrap();
    }
    w.finish().unwrap().into_inner()
}

#[test]
fn xlsb_text_and_metadata() {
    let p = package();
    let m = extract(&p, Some("book.xlsb"), &Limits::default()).unwrap();
    assert_eq!(m.format, DocFormat::Xlsx);
    assert_eq!(m.hidden_sheets, vec!["Ключи".to_string()]);
    assert!(m.people.iter().any(|x| x.name == "Олена Коваль"));
    assert_eq!(m.comments[0].text, "Проверить ИНН");
    let t = text(&p, &Limits::default()).unwrap();
    for want in [
        "株式会社テスト",
        "ivan.petrov@example.com",
        "مرحبا بالعالم",
        "4915112345678",
        "Продажи",
    ] {
        assert!(t.contains(want), "{want}: {t}");
    }
    assert!(!t.contains("3.5"));
}

#[test]
fn xlsb_garbage_never_panics() {
    let p = package();
    let mut rng = crate::util::Rng(0x0B12_0001);
    for _ in 0..200 {
        let mut v = p.clone();
        for _ in 0..4 {
            let i = (rng.next() as usize) % v.len();
            v[i] = rng.next() as u8;
        }
        let _ = extract(&v, Some("x.xlsb"), &Limits::default());
        let _ = text(&v, &Limits::default());
    }
    // records with absurd sizes and string lengths
    let mut sh = rec(7, &[0xFF; 12]);
    sh.extend(rec(6, &cell(0, &u32::MAX.to_le_bytes())));
    sh.extend([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
    let mut out = String::new();
    super::sheet_text(&sh, &[], true, &mut 0, &mut out);
}
