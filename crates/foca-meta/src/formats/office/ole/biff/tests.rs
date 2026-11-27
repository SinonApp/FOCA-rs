//! BIFF workbook tests with synthetic record streams (BIFF8 and BIFF5 code pages).

use super::parse;
use foca_core::Metadata;

fn rec(ty: u16, data: &[u8]) -> Vec<u8> {
    let mut v = ty.to_le_bytes().to_vec();
    v.extend_from_slice(&(data.len() as u16).to_le_bytes());
    v.extend_from_slice(data);
    v
}

fn u16s(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

/// XLUnicodeString in UTF-16 form.
fn xls_w(s: &str) -> Vec<u8> {
    let mut v = (s.encode_utf16().count() as u16).to_le_bytes().to_vec();
    v.push(1);
    v.extend(u16s(s));
    v
}

fn bof(vers: u16, dt: u16) -> Vec<u8> {
    let mut d = vers.to_le_bytes().to_vec();
    d.extend_from_slice(&dt.to_le_bytes());
    d.extend_from_slice(&[0; 12]);
    rec(0x0809, &d)
}

fn boundsheet(pos: u32, state: u8, name: &str) -> Vec<u8> {
    let mut d = pos.to_le_bytes().to_vec();
    d.push(state);
    d.push(0);
    d.push(name.encode_utf16().count() as u8);
    d.push(1);
    d.extend(u16s(name));
    rec(0x0085, &d)
}

fn cell_head(row: u16, col: u16) -> Vec<u8> {
    let mut d = row.to_le_bytes().to_vec();
    d.extend_from_slice(&col.to_le_bytes());
    d.extend_from_slice(&0u16.to_le_bytes());
    d
}

fn workbook() -> Vec<u8> {
    // globals: the sheet BOF offsets are patched after layout
    let build = |pos1: u32, pos2: u32| -> Vec<u8> {
        let mut g = bof(0x0600, 0x0005);
        g.extend(rec(0x0042, &1200u16.to_le_bytes()));
        g.extend(rec(0x005C, &xls_w("Олена Коваль")));
        g.extend(boundsheet(pos1, 0, "Дані"));
        g.extend(boundsheet(pos2, 1, "Secret"));
        // NAME "Клиенты"
        let nm = "Клиенты";
        let mut n = vec![0, 0, 0, nm.encode_utf16().count() as u8];
        n.extend_from_slice(&[0; 10]);
        n.push(1);
        n.extend(u16s(nm));
        g.extend(rec(0x0018, &n));
        // SUPBOOK with an encoded UNC path and one sheet name
        let path = "\u{1}\u{1}@fs01\u{3}finance\u{3}budget.xls";
        let mut sb = 1u16.to_le_bytes().to_vec();
        sb.extend_from_slice(&(path.encode_utf16().count() as u16).to_le_bytes());
        sb.push(1);
        sb.extend(u16s(path));
        sb.extend(xls_w("Q1"));
        g.extend(rec(0x01AE, &sb));
        // SST: 3 strings, the second one split across a CONTINUE (new flag byte: compressed)
        let mut sst = 3u32.to_le_bytes().to_vec();
        sst.extend_from_slice(&3u32.to_le_bytes());
        sst.extend(xls_w("東京本社"));
        let s2 = "Иван Петров";
        sst.extend_from_slice(&(s2.encode_utf16().count() as u16 + 6).to_le_bytes());
        sst.push(1);
        sst.extend(u16s(s2));
        g.extend(rec(0x00FC, &sst));
        let mut cont = vec![0u8];
        cont.extend_from_slice(b" admin");
        cont.extend(xls_w("مرحبا"));
        g.extend(rec(0x003C, &cont));
        g.extend(rec(0x000A, &[]));
        g
    };
    let g = build(0, 0);
    let s1_off = g.len() as u32;
    let mut s1 = bof(0x0600, 0x0010);
    let mut d = cell_head(0, 0);
    d.extend_from_slice(&0u32.to_le_bytes());
    s1.extend(rec(0x00FD, &d));
    let mut d = cell_head(0, 1);
    d.extend_from_slice(&1u32.to_le_bytes());
    s1.extend(rec(0x00FD, &d));
    let mut d = cell_head(1, 0);
    d.extend_from_slice(&380_441_234_567f64.to_le_bytes());
    s1.extend(rec(0x0203, &d));
    let mut d = cell_head(1, 1);
    d.extend_from_slice(&19.99f64.to_le_bytes());
    s1.extend(rec(0x0203, &d));
    // RK integer 1234567 (encoded << 2 | 2)
    let mut d = cell_head(2, 0);
    d.extend_from_slice(&((1_234_567u32 << 2) | 2).to_le_bytes());
    s1.extend(rec(0x027E, &d));
    // FORMULA with a string result + STRING
    let mut d = cell_head(3, 0);
    d.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0xFF, 0xFF]);
    d.extend_from_slice(&[0; 6]);
    s1.extend(rec(0x0006, &d));
    s1.extend(rec(0x0207, &xls_w("итого=42")));
    // hidden row 5
    let mut d = 4u16.to_le_bytes().to_vec();
    d.extend_from_slice(&[0; 10]);
    d.extend_from_slice(&0x20u16.to_le_bytes());
    d.extend_from_slice(&[0; 2]);
    s1.extend(rec(0x0208, &d));
    // comment: OBJ (id 7), TXO + CONTINUE, NOTE
    let mut obj = 0x15u16.to_le_bytes().to_vec();
    obj.extend_from_slice(&18u16.to_le_bytes());
    obj.extend_from_slice(&0x19u16.to_le_bytes());
    obj.extend_from_slice(&7u16.to_le_bytes());
    obj.extend_from_slice(&[0; 14]);
    s1.extend(rec(0x005D, &obj));
    let note_text = "Перевірити суму";
    let mut txo = vec![0u8; 10];
    txo.extend_from_slice(&(note_text.encode_utf16().count() as u16).to_le_bytes());
    txo.extend_from_slice(&[0; 6]);
    s1.extend(rec(0x01B6, &txo));
    let mut c = vec![1u8];
    c.extend(u16s(note_text));
    s1.extend(rec(0x003C, &c));
    let mut note = cell_head(0, 0);
    note.extend_from_slice(&7u16.to_le_bytes());
    note.extend(xls_w("Maria Garcia"));
    s1.extend(rec(0x001C, &note));
    s1.extend(rec(0x000A, &[]));
    let s2_off = s1_off + s1.len() as u32;
    let mut s2 = bof(0x0600, 0x0010);
    let mut d = cell_head(0, 0);
    d.extend_from_slice(&2u32.to_le_bytes());
    s2.extend(rec(0x00FD, &d));
    s2.extend(rec(0x000A, &[]));
    let mut out = build(s1_off, s2_off);
    assert_eq!(out.len() as u32, s1_off);
    out.extend(s1);
    out.extend(s2);
    out
}

#[test]
fn biff8_text_and_metadata() {
    let mut m = Metadata::default();
    let t = parse(&workbook(), &mut m);
    assert!(t.contains("東京本社\tИван Петров admin"), "{t}");
    assert!(t.contains("380441234567"), "{t}");
    assert!(!t.contains("19.99"), "{t}");
    assert!(t.contains("1234567"), "{t}");
    assert!(t.contains("итого=42"), "{t}");
    assert!(t.contains("مرحبا"), "{t}");
    assert!(t.contains("Дані"), "{t}");
    assert!(t.contains("Клиенты"), "{t}");
    assert_eq!(m.hidden_sheets, vec!["Secret".to_string()]);
    assert_eq!(
        m.fields.get("xls:WriteAccess").map(String::as_str),
        Some("Олена Коваль")
    );
    assert!(
        m.links.iter().any(|l| l == "\\\\fs01\\finance\\budget.xls"),
        "{:?}",
        m.links
    );
    assert!(m.hidden_content.iter().any(|h| h.location == "Дані!5"));
    let c = m.comments.first().expect("note");
    assert_eq!(c.author.as_deref(), Some("Maria Garcia"));
    assert_eq!(c.text, "Перевірити суму");
}

fn biff5_label(cp: u16, raw: &[u8]) -> Vec<u8> {
    let mut wb = bof(0x0500, 0x0005);
    wb.extend(rec(0x0042, &cp.to_le_bytes()));
    wb.extend(rec(0x000A, &[]));
    wb.extend(bof(0x0500, 0x0010));
    let mut d = cell_head(0, 0);
    d.extend_from_slice(&(raw.len() as u16).to_le_bytes());
    d.extend_from_slice(raw);
    wb.extend(rec(0x0204, &d));
    wb.extend(rec(0x000A, &[]));
    wb
}

#[test]
fn biff5_code_pages() {
    for (cp, raw, want) in [
        (1251u16, &b"\xcf\xf0\xe8\xe2\xe5\xf2"[..], "Привет"),
        (1250, &b"\x8akoda \xe8esk\xe1"[..], "Škoda česká"),
        (932, &b"\x93\xfa\x96\x7b"[..], "日本"),
        (936, &b"\xd6\xd0\xce\xc4"[..], "中文"),
    ] {
        let mut m = Metadata::default();
        let t = parse(&biff5_label(cp, raw), &mut m);
        assert!(t.contains(want), "cp{cp}: {t}");
    }
}

#[test]
fn garbage_never_panics() {
    let wb = workbook();
    let mut rng = crate::util::Rng(0xB1FF_0008);
    for n in (0..wb.len()).step_by(7) {
        let _ = parse(&wb[..n], &mut Metadata::default());
    }
    for _ in 0..300 {
        let mut v = wb.clone();
        for _ in 0..6 {
            let i = (rng.next() as usize) % v.len();
            v[i] = rng.next() as u8;
        }
        let _ = parse(&v, &mut Metadata::default());
    }
}

#[test]
fn sst_split_right_after_the_header() {
    // the header of the second string ends the SST record; its characters continue in the
    // CONTINUE record after a fresh option byte (UTF-16 here)
    let mut sst = 2u32.to_le_bytes().to_vec();
    sst.extend_from_slice(&2u32.to_le_bytes());
    sst.extend(xls_w("один"));
    sst.extend_from_slice(&3u16.to_le_bytes());
    sst.push(0);
    let mut cont = vec![1u8];
    cont.extend(u16s("два"));
    let mut wb = bof(0x0600, 0x0005);
    wb.extend(rec(0x00FC, &sst));
    wb.extend(rec(0x003C, &cont));
    wb.extend(rec(0x000A, &[]));
    wb.extend(bof(0x0600, 0x0010));
    for i in 0..2u32 {
        let mut d = cell_head(i as u16, 0);
        d.extend_from_slice(&i.to_le_bytes());
        wb.extend(rec(0x00FD, &d));
    }
    let t = parse(&wb, &mut Metadata::default());
    assert!(t.contains("один\nдва"), "{t}");
}
