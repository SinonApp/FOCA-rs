//! Generates the OLE2 part of the test corpus (doc/xls/ppt/vbaProject.bin) using the `cfb` crate.
//!
//! Usage: `cargo run -p foca-meta --example make_ole_corpus -- tests/corpus`
//! (then run `python3 tests/corpus/make_corpus.py`, which embeds vbaProject.bin into an xlsx).

use std::io::{Cursor, Write};
use std::path::Path;

const FMTID_SUMMARY: [u8; 16] = [
    0xE0, 0x85, 0x9F, 0xF2, 0xF9, 0x4F, 0x68, 0x10, 0xAB, 0x91, 0x08, 0x00, 0x2B, 0x27, 0xB3, 0xD9,
];
const FMTID_DOCSUM: [u8; 16] = [
    0x02, 0xD5, 0xCD, 0xD5, 0x9C, 0x2E, 0x1B, 0x10, 0x93, 0x97, 0x08, 0x00, 0x2B, 0x2C, 0xF9, 0xAE,
];
const FMTID_USER: [u8; 16] = [
    0x05, 0xD5, 0xCD, 0xD5, 0x9C, 0x2E, 0x1B, 0x10, 0x93, 0x97, 0x08, 0x00, 0x2B, 0x2C, 0xF9, 0xAE,
];

enum Val {
    I2(i16),
    I4(i32),
    Str(&'static str),
    WStr(&'static str),
    Time(u64),
    Bool(bool),
}

/// Encodes to cp1251 (only the characters the corpus needs) or to cp1252/ASCII.
fn encode_cp(s: &str, cp: u16) -> Vec<u8> {
    s.chars()
        .map(|c| {
            let u = c as u32;
            if u < 0x80 {
                return u as u8;
            }
            if cp == 1251 {
                match u {
                    0x0410..=0x044F => (u - 0x0410 + 0xC0) as u8,
                    0x0406 => 0xB2,
                    0x0456 => 0xB3,
                    0x0407 => 0xAF,
                    0x0457 => 0xBF,
                    0x0404 => 0xAA,
                    0x0454 => 0xBA,
                    0x0490 => 0xA5,
                    0x0491 => 0xB4,
                    _ => b'?',
                }
            } else if u <= 0xFF {
                u as u8
            } else {
                b'?'
            }
        })
        .collect()
}

fn pad4(v: &mut Vec<u8>) {
    while !v.len().is_multiple_of(4) {
        v.push(0);
    }
}

fn section(props: &[(u32, Val)], codepage: u16, dict: &[(u32, &str)]) -> Vec<u8> {
    let mut values: Vec<(u32, Vec<u8>)> = Vec::new();
    values.push((1, {
        let mut v = 2u32.to_le_bytes().to_vec();
        v.extend((codepage as i16).to_le_bytes());
        pad4(&mut v);
        v
    }));
    if !dict.is_empty() {
        let mut v = (dict.len() as u32).to_le_bytes().to_vec();
        for (id, name) in dict {
            v.extend(id.to_le_bytes());
            if codepage == 1200 {
                let w: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
                v.extend((w.len() as u32).to_le_bytes());
                for u in w {
                    v.extend(u.to_le_bytes());
                }
                pad4(&mut v);
            } else {
                let mut b = encode_cp(name, codepage);
                b.push(0);
                v.extend((b.len() as u32).to_le_bytes());
                v.extend(b);
            }
        }
        pad4(&mut v);
        values.push((0, v));
    }
    for (pid, val) in props {
        let mut v = Vec::new();
        match val {
            Val::I2(x) => {
                v.extend(2u32.to_le_bytes());
                v.extend(x.to_le_bytes());
            }
            Val::I4(x) => {
                v.extend(3u32.to_le_bytes());
                v.extend(x.to_le_bytes());
            }
            Val::Bool(b) => {
                v.extend(0x0Bu32.to_le_bytes());
                v.extend((if *b { 0xFFFFu16 } else { 0 }).to_le_bytes());
            }
            Val::Time(t) => {
                v.extend(0x40u32.to_le_bytes());
                v.extend(t.to_le_bytes());
            }
            Val::Str(s) => {
                if codepage == 1200 {
                    let w: Vec<u16> = s.encode_utf16().chain(std::iter::once(0)).collect();
                    v.extend(0x1Eu32.to_le_bytes());
                    v.extend((w.len() as u32 * 2).to_le_bytes());
                    for u in w {
                        v.extend(u.to_le_bytes());
                    }
                } else {
                    let mut b = encode_cp(s, codepage);
                    b.push(0);
                    v.extend(0x1Eu32.to_le_bytes());
                    v.extend((b.len() as u32).to_le_bytes());
                    v.extend(b);
                }
            }
            Val::WStr(s) => {
                let w: Vec<u16> = s.encode_utf16().chain(std::iter::once(0)).collect();
                v.extend(0x1Fu32.to_le_bytes());
                v.extend((w.len() as u32).to_le_bytes());
                for u in w {
                    v.extend(u.to_le_bytes());
                }
            }
        }
        pad4(&mut v);
        values.push((*pid, v));
    }
    let header = 8 + values.len() * 8;
    let mut table = Vec::new();
    let mut body: Vec<u8> = Vec::new();
    for (pid, v) in &values {
        table.extend(pid.to_le_bytes());
        table.extend(((header + body.len()) as u32).to_le_bytes());
        body.extend(v);
    }
    let mut out = ((header + body.len()) as u32).to_le_bytes().to_vec();
    out.extend((values.len() as u32).to_le_bytes());
    out.extend(table);
    out.extend(body);
    out
}

fn property_set(os_ver: u32, sections: &[([u8; 16], Vec<u8>)]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend(0xFFFEu16.to_le_bytes());
    out.extend(0u16.to_le_bytes());
    out.extend(os_ver.to_le_bytes());
    out.extend([0u8; 16]);
    out.extend((sections.len() as u32).to_le_bytes());
    let mut off = 28 + sections.len() * 20;
    for (fmtid, s) in sections {
        out.extend(fmtid);
        out.extend((off as u32).to_le_bytes());
        off += s.len();
    }
    for (_, s) in sections {
        out.extend(s);
    }
    out
}

/// Builds a FILETIME from a UTC date and time (plain calendar arithmetic).
fn ft(y: i64, mo: i64, d: i64, h: i64, mi: i64, s: i64) -> u64 {
    // days since 1970-01-01 (Howard Hinnant's algorithm)
    let y2 = if mo <= 2 { y - 1 } else { y };
    let era = y2.div_euclid(400);
    let yoe = y2 - era * 400;
    let mp = (mo + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146097 + doe - 719468;
    let unix = days * 86400 + h * 3600 + mi * 60 + s;
    ((unix + 11_644_473_600) * 10_000_000) as u64
}

fn sttb_ext(strings: &[&str]) -> Vec<u8> {
    let mut v = vec![0xFF, 0xFF];
    v.extend((strings.len() as u16).to_le_bytes());
    v.extend(0u16.to_le_bytes());
    for s in strings {
        let w: Vec<u16> = s.encode_utf16().collect();
        v.extend((w.len() as u16).to_le_bytes());
        for u in w {
            v.extend(u.to_le_bytes());
        }
    }
    v
}

fn write_cfb(path: &Path, streams: &[(&str, Vec<u8>)]) -> std::io::Result<()> {
    let mut cf = cfb::CompoundFile::create(Cursor::new(Vec::new()))?;
    for (name, data) in streams {
        let p = Path::new(name);
        let mut acc = std::path::PathBuf::from("/");
        if let Some(parent) = p.parent() {
            for c in parent.components().skip(1) {
                acc.push(c);
                if !cf.exists(&acc) {
                    cf.create_storage(&acc)?;
                }
            }
        }
        let mut s = cf.create_stream(name)?;
        s.write_all(data)?;
    }
    // fixed storage timestamps keep the generated files byte-for-byte reproducible
    let ts = std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_710_441_720);
    let storages: Vec<std::path::PathBuf> = cf
        .walk()
        .filter(|e| !e.is_stream())
        .map(|e| e.path().to_path_buf())
        .collect();
    for p in storages {
        cf.set_created_time(&p, ts)?;
        cf.set_modified_time(&p, ts)?;
    }
    cf.flush()?;
    let bytes = cf.into_inner().into_inner();
    if let Some(d) = path.parent() {
        std::fs::create_dir_all(d)?;
    }
    std::fs::write(path, bytes)
}

fn word_fib_and_table() -> (Vec<u8>, Vec<u8>) {
    let mut table = vec![0u8; 16];
    let mut pairs: Vec<(usize, u32, u32)> = Vec::new();
    let mut add = |idx: usize, data: Vec<u8>, table: &mut Vec<u8>| {
        let fc = table.len() as u32;
        let lcb = data.len() as u32;
        table.extend(data);
        pairs.push((idx, fc, lcb));
    };
    add(
        71,
        sttb_ext(&[
            "o.kovalenko",
            r"C:\Users\o.kovalenko\Documents\Звіти\2019\Статут.doc",
            "Administrator",
            r"\\SRV-FILE01\public\Шаблони\Статут.doc",
        ]),
        &mut table,
    );
    add(
        32,
        sttb_ext(&[
            "",
            r"\\SRV-FILE01\public\Шаблони\Юридичний.dot",
            "",
            "",
            "",
            "",
            "",
            "",
        ]),
        &mut table,
    );
    add(51, sttb_ext(&["Unknown", "Андрій Бондар"]), &mut table);
    {
        let mut atn = Vec::new();
        for s in ["Тетяна Мельник", "i.petrenko"] {
            let w: Vec<u16> = s.encode_utf16().collect();
            atn.extend((w.len() as u16).to_le_bytes());
            for u in w {
                atn.extend(u.to_le_bytes());
            }
        }
        add(36, atn, &mut table);
    }
    let csw = 14u16;
    let cslw = 22u16;
    let cb = 93u16; // Word 97
    let mut wd = vec![0u8; 32];
    wd[0..2].copy_from_slice(&0xA5ECu16.to_le_bytes());
    wd[2..4].copy_from_slice(&0x00C1u16.to_le_bytes()); // nFib
    wd[0x0A..0x0C].copy_from_slice(&0x0200u16.to_le_bytes()); // fWhichTblStm = 1Table
    wd.extend(csw.to_le_bytes());
    wd.extend(vec![0u8; usize::from(csw) * 2]);
    wd.extend(cslw.to_le_bytes());
    wd.extend(vec![0u8; usize::from(cslw) * 4]);
    wd.extend(cb.to_le_bytes());
    let base = wd.len();
    wd.extend(vec![0u8; usize::from(cb) * 8]);
    for (idx, fc, lcb) in pairs {
        let p = base + idx * 8;
        wd[p..p + 4].copy_from_slice(&fc.to_le_bytes());
        wd[p + 4..p + 8].copy_from_slice(&lcb.to_le_bytes());
    }
    // a bit of document body text
    let text: Vec<u8> = "Статут підприємства. Пароль адміністратора: P@ssw0rd2019"
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect();
    wd.extend(text);
    (wd, table)
}

fn biff_record(ty: u16, data: &[u8]) -> Vec<u8> {
    let mut v = ty.to_le_bytes().to_vec();
    v.extend((data.len() as u16).to_le_bytes());
    v.extend(data);
    v
}

fn workbook() -> Vec<u8> {
    let mut wb = Vec::new();
    wb.extend(biff_record(
        0x0809,
        &[0x00, 0x06, 0x05, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    ));
    let user = "s.lysenko";
    let mut wa = (user.len() as u16).to_le_bytes().to_vec();
    wa.push(0);
    wa.extend(user.as_bytes());
    wa.resize(112, b' ');
    wb.extend(biff_record(0x005C, &wa));
    for (name, state) in [("Лист1", 0u8), ("Зарплати", 1u8), ("Службовий", 2u8)]
    {
        let w: Vec<u16> = name.encode_utf16().collect();
        let mut bs = 0u32.to_le_bytes().to_vec();
        bs.push(state);
        bs.push(0);
        bs.push(w.len() as u8);
        bs.push(1);
        for u in w {
            bs.extend(u.to_le_bytes());
        }
        wb.extend(biff_record(0x0085, &bs));
    }
    wb.extend(biff_record(0x000A, &[]));
    wb
}

fn current_user(name: &str) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend(0u16.to_le_bytes()); // recVer/instance
    v.extend(0x0FF6u16.to_le_bytes()); // recType
    v.extend(0u32.to_le_bytes()); // recLen (not validated)
    v.extend(20u32.to_le_bytes()); // size
    v.extend(0xE391C05Fu32.to_le_bytes()); // headerToken
    v.extend(0u32.to_le_bytes()); // offsetToCurrentEdit
    v.extend((name.len() as u16).to_le_bytes());
    v.extend(0x03F4u16.to_le_bytes());
    v.extend([3u8, 0]);
    v.extend(0u16.to_le_bytes());
    v.extend(name.as_bytes());
    v.extend(8u32.to_le_bytes());
    v
}

fn main() -> std::io::Result<()> {
    let out = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "tests/corpus".into());
    let out = Path::new(&out);
    let win7 = 0x0002_0106u32; // Windows 6.1, kind=2

    // --- legacy.doc ---
    let si = property_set(
        win7,
        &[(
            FMTID_SUMMARY,
            section(
                &[
                    (2, Val::Str("Статут підприємства")),
                    (3, Val::Str("Установчі документи")),
                    (4, Val::Str("Олена Коваленко")),
                    (5, Val::Str("статут, ТЕС-2")),
                    (6, Val::Str("Чернетка для юристів")),
                    (7, Val::Str("Юридичний.dot")),
                    (8, Val::Str("Administrator")),
                    (9, Val::Str("12")),
                    (10, Val::Time(3600 * 10_000_000)),
                    (12, Val::Time(ft(2019, 2, 11, 9, 30, 0))),
                    (13, Val::Time(ft(2019, 3, 1, 17, 45, 10))),
                    (11, Val::Time(ft(2019, 3, 1, 17, 50, 0))),
                    (14, Val::I4(4)),
                    (15, Val::I4(1234)),
                    (16, Val::I4(7034)),
                    (18, Val::Str("Microsoft Office Word")),
                    (19, Val::I4(0)),
                ],
                1251,
                &[],
            ),
        )],
    );
    let dsi = property_set(
        win7,
        &[
            (
                FMTID_DOCSUM,
                section(
                    &[
                        (2, Val::Str("Legal")),
                        (14, Val::Str("Bondar A.")),
                        (15, Val::Str("Contoso Energy LLC")),
                        (5, Val::I4(80)),
                        (6, Val::I4(20)),
                        (0x17, Val::I4(0x000E_0000)),
                    ],
                    1252,
                    &[],
                ),
            ),
            (
                FMTID_USER,
                section(
                    &[
                        (2, Val::Str("ТЕС-2")),
                        (3, Val::Bool(true)),
                        (4, Val::I2(7)),
                    ],
                    1200,
                    &[(2, "Проєкт"), (3, "Конфіденційно"), (4, "Версія")],
                ),
            ),
        ],
    );
    let (wd, table) = word_fib_and_table();
    write_cfb(
        &out.join("ole/legacy.doc"),
        &[
            ("/WordDocument", wd),
            ("/1Table", table),
            ("/\u{5}SummaryInformation", si),
            ("/\u{5}DocumentSummaryInformation", dsi),
            (
                "/Macros/VBA/ThisDocument",
                b"Attribute VB_Name = \"ThisDocument\"".to_vec(),
            ),
            ("/Macros/VBA/AutoOpen", b"Sub AutoOpen()".to_vec()),
            ("/Macros/VBA/dir", vec![1, 2, 3]),
            ("/Macros/VBA/_VBA_PROJECT", vec![0xCC, 0x61]),
            ("/ObjectPool/_1234567890/\u{1}Ole", vec![1, 0, 0, 2]),
        ],
    )?;

    // --- budget.xls ---
    let si = property_set(
        0x0002_000A, // Windows 10.0
        &[(
            FMTID_SUMMARY,
            section(
                &[
                    (2, Val::Str("Budget 2019")),
                    (4, Val::Str("s.lysenko")),
                    (8, Val::Str("v.tkachenko")),
                    (12, Val::Time(ft(2018, 12, 20, 8, 0, 0))),
                    (13, Val::Time(ft(2019, 1, 15, 12, 0, 0))),
                    (18, Val::Str("Microsoft Excel")),
                ],
                1252,
                &[],
            ),
        )],
    );
    let dsi = property_set(
        0x0002_000A,
        &[(
            FMTID_DOCSUM,
            section(&[(15, Val::WStr("ТОВ «Контосо Енерджі»"))], 1252, &[]),
        )],
    );
    write_cfb(
        &out.join("ole/budget.xls"),
        &[
            ("/Workbook", workbook()),
            ("/\u{5}SummaryInformation", si),
            ("/\u{5}DocumentSummaryInformation", dsi),
            ("/_VBA_PROJECT_CUR/VBA/Module1", b"Sub Calc()".to_vec()),
            ("/_VBA_PROJECT_CUR/VBA/dir", vec![1]),
        ],
    )?;

    // --- slides.ppt ---
    let si = property_set(
        0x0001_0000, // Macintosh
        &[(
            FMTID_SUMMARY,
            section(
                &[
                    (2, Val::Str("Strategy 2020")),
                    (4, Val::Str("Marina Shevchuk")),
                    (8, Val::Str("m.shevchuk")),
                    (18, Val::Str("Microsoft Macintosh PowerPoint")),
                    (12, Val::Time(ft(2019, 11, 5, 10, 0, 0))),
                ],
                1252,
                &[],
            ),
        )],
    );
    let dsi = property_set(
        0x0001_0000,
        &[(
            FMTID_DOCSUM,
            section(
                &[(7, Val::I4(12)), (8, Val::I4(3)), (9, Val::I4(1))],
                1252,
                &[],
            ),
        )],
    );
    write_cfb(
        &out.join("ole/slides.ppt"),
        &[
            ("/PowerPoint Document", vec![0u8; 64]),
            ("/Current User", current_user("m.shevchuk")),
            ("/\u{5}SummaryInformation", si),
            ("/\u{5}DocumentSummaryInformation", dsi),
        ],
    )?;

    // --- vbaProject.bin ---
    write_cfb(
        &out.join("ole/vbaProject.bin"),
        &[
            ("/VBA/dir", vec![1, 2, 3]),
            ("/VBA/_VBA_PROJECT", vec![0xCC, 0x61, 0xFF, 0xFF]),
            (
                "/VBA/ThisWorkbook",
                b"Attribute VB_Name = \"ThisWorkbook\"".to_vec(),
            ),
            (
                "/VBA/Module1",
                b"Sub Exfil()\n  Shell \"cmd /c whoami\"\nEnd Sub".to_vec(),
            ),
            ("/VBA/__SRP_0", vec![0]),
            (
                "/PROJECT",
                b"ID=\"{00000000-0000-0000-0000-000000000000}\"\r\nModule=Module1\r\n".to_vec(),
            ),
            ("/PROJECTwm", vec![0]),
        ],
    )?;
    println!("OLE corpus written to {}", out.display());
    Ok(())
}
