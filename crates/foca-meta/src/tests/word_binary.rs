//! Word 97-2003 binary documents built in code: FIB language, DOP local times against the UTC
//! summary times (author time zone), AppVersion release year, default-account locale hint and
//! text from the piece table without the FIB bytes in front.

use std::io::{Cursor, Write};

use crate::{extract, text, Limits};

enum Val<'a> {
    /// Windows-1251 string (VT_LPSTR).
    Str(&'a str),
    I4(i32),
    FileTime(u64),
}

fn cp1251(s: &str) -> Vec<u8> {
    s.chars()
        .map(|c| match c {
            'А'..='я' => (0xC0 + (c as u32 - 0x410)) as u8,
            c => c as u8,
        })
        .collect()
}

fn pad4(v: &mut Vec<u8>) {
    while !v.len().is_multiple_of(4) {
        v.push(0);
    }
}

fn property_set(fmtid: [u8; 16], props: &[(u32, Val)]) -> Vec<u8> {
    let n = props.len() + 1;
    let base = 8 + n * 8;
    let mut offsets = vec![(1u32, base as u32)];
    let mut body = Vec::new();
    body.extend(2u32.to_le_bytes());
    body.extend(1251u16.to_le_bytes());
    body.extend([0, 0]);
    for (pid, v) in props {
        offsets.push((*pid, (base + body.len()) as u32));
        match v {
            Val::Str(s) => {
                let b = cp1251(s);
                body.extend(0x1Eu32.to_le_bytes());
                body.extend(((b.len() + 1) as u32).to_le_bytes());
                body.extend(b);
                body.push(0);
            }
            Val::I4(i) => {
                body.extend(3u32.to_le_bytes());
                body.extend(i.to_le_bytes());
            }
            Val::FileTime(t) => {
                body.extend(0x40u32.to_le_bytes());
                body.extend(t.to_le_bytes());
            }
        }
        pad4(&mut body);
    }
    let mut out = vec![0xFE, 0xFF, 0, 0];
    out.extend(0x0002_0006u32.to_le_bytes());
    out.extend([0u8; 16]);
    out.extend(1u32.to_le_bytes());
    out.extend(fmtid);
    out.extend(48u32.to_le_bytes());
    out.extend(((base + body.len()) as u32).to_le_bytes());
    out.extend((n as u32).to_le_bytes());
    for (pid, off) in offsets {
        out.extend(pid.to_le_bytes());
        out.extend(off.to_le_bytes());
    }
    out.extend(body);
    out
}

const SUMMARY: [u8; 16] = [
    0xE0, 0x85, 0x9F, 0xF2, 0xF9, 0x4F, 0x68, 0x10, 0xAB, 0x91, 0x08, 0x00, 0x2B, 0x27, 0xB3, 0xD9,
];
const DOC_SUMMARY: [u8; 16] = [
    0x02, 0xD5, 0xCD, 0xD5, 0x9C, 0x2E, 0x1B, 0x10, 0x93, 0x97, 0x08, 0x00, 0x2B, 0x2C, 0xF9, 0xAE,
];

/// Word DTTM: minute, hour, day, month, years since 1900.
fn dttm(y: u32, mo: u32, d: u32, h: u32, mi: u32) -> u32 {
    mi | (h << 6) | (d << 11) | (mo << 16) | ((y - 1900) << 20)
}

fn put_u32(v: &mut [u8], off: usize, x: u32) {
    v[off..off + 4].copy_from_slice(&x.to_le_bytes());
}

/// WordDocument + 1Table with a DOP and a two-piece CLX (one compressed, one UTF-16).
fn doc_fixture() -> Vec<u8> {
    let mut wd = vec![0u8; 0xA00];
    wd[0..2].copy_from_slice(&0xA5ECu16.to_le_bytes());
    wd[2..4].copy_from_slice(&0x00C1u16.to_le_bytes());
    wd[6..8].copy_from_slice(&0x0419u16.to_le_bytes()); // lid: Russian
    wd[0x0A..0x0C].copy_from_slice(&0x0200u16.to_le_bytes()); // 1Table
    wd[0x20..0x22].copy_from_slice(&14u16.to_le_bytes());
    wd[0x3E..0x40].copy_from_slice(&22u16.to_le_bytes());
    wd[0x98..0x9A].copy_from_slice(&93u16.to_le_bytes());
    let pair = |i: usize| 0x9A + i * 8;
    // binary bytes after the FIB that the old string scan used to print
    wd[0x400..0x410].copy_from_slice(b"zhzh]U]U]U]UJBJB");
    let p1 = b"Hello world\r";
    wd[0x800..0x800 + p1.len()].copy_from_slice(p1);
    let p2: Vec<u8> = "Привіт\u{7}світ\r"
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect();
    wd[0x900..0x900 + p2.len()].copy_from_slice(&p2);
    let cp2 = p1.len() as u32;
    let cp3 = cp2 + (p2.len() / 2) as u32;

    let mut tbl = vec![0u8; 0x100];
    put_u32(&mut tbl, 0x14, dttm(2024, 3, 5, 11, 22));
    put_u32(&mut tbl, 0x18, dttm(2024, 3, 6, 15, 10));
    let mut plc = Vec::new();
    for cp in [0, cp2, cp3] {
        plc.extend(cp.to_le_bytes());
    }
    for fc in [(0x800u32 * 2) | 0x4000_0000, 0x900] {
        plc.extend([0, 0]);
        plc.extend(fc.to_le_bytes());
        plc.extend([0, 0]);
    }
    let mut clx = vec![0x01, 0x02, 0x00, 0xAA, 0xBB]; // a Prc to skip
    clx.push(0x02);
    clx.extend((plc.len() as u32).to_le_bytes());
    clx.extend(&plc);
    let clx_at = tbl.len();
    tbl.extend(&clx);
    put_u32(&mut wd, pair(31), 0);
    put_u32(&mut wd, pair(31) + 4, 0x40);
    put_u32(&mut wd, pair(33), clx_at as u32);
    put_u32(&mut wd, pair(33) + 4, clx.len() as u32);

    let mut cf = cfb::CompoundFile::create(Cursor::new(Vec::new())).unwrap();
    for (name, data) in [
        ("/WordDocument", wd),
        ("/1Table", tbl),
        (
            "/\u{5}SummaryInformation",
            property_set(
                SUMMARY,
                &[
                    (4, Val::Str("Пользователь")),
                    (18, Val::Str("Microsoft Office Word")),
                    (12, Val::FileTime(133_541_005_610_000_000)),
                    (13, Val::FileTime(133_542_006_050_000_000)),
                ],
            ),
        ),
        (
            "/\u{5}DocumentSummaryInformation",
            property_set(DOC_SUMMARY, &[(0x17, Val::I4(12 << 16))]),
        ),
    ] {
        let mut s = cf.create_stream(name).unwrap();
        s.write_all(&data).unwrap();
    }
    cf.flush().unwrap();
    cf.into_inner().into_inner()
}

#[test]
fn word_binary_language_time_zone_release_and_locale() {
    let b = doc_fixture();
    let m = extract(&b, Some("report.example.doc"), &Limits::default()).unwrap();
    assert_eq!(m.application.as_deref(), Some("Microsoft Office Word 2007"));
    assert!(m
        .software
        .contains(&"Microsoft Office Word 12.0000".to_string()));
    assert_eq!(m.fields["office:release"], "2007");
    assert_eq!(m.language.as_deref(), Some("ru"));
    assert_eq!(m.fields["doc:lid"], "0x0419 (ru)");
    assert_eq!(m.fields["ole:CodePage"], "1251 (Windows Cyrillic)");
    assert_eq!(m.fields["doc:tz_offset"], "UTC+03:00");
    assert_eq!(m.fields["os:locale_hint"], "ru");
}

#[test]
fn word_text_comes_from_the_piece_table() {
    let b = doc_fixture();
    let t = text(&b, &Limits::default()).unwrap();
    assert!(t.starts_with("Hello world\nПривіт\tсвіт\n"), "{t:?}");
    assert!(!t.contains("zhzh"), "{t:?}");
}

#[test]
fn broken_piece_tables_never_panic() {
    let b = doc_fixture();
    let mut rng = crate::util::Rng(7);
    for _ in 0..200 {
        let mut x = b.clone();
        for _ in 0..8 {
            let i = (rng.next() as usize) % x.len();
            x[i] = rng.next() as u8;
        }
        let _ = text(&x, &Limits::default());
        let _ = extract(&x, Some("x.doc"), &Limits::default());
    }
}
