//! Generates the OLE2 part of the corpus (MSG, VSD, PUB, WPS) using the `cfb` crate.
//!
//! Usage: `cargo run -p foca-meta --example make_ole_corpus_13 -- tests/corpus`
//! (then `python3 tests/corpus/make_corpus_13.py`). All data is fictional.

use std::io::{Cursor, Write};
use std::path::Path;

const FMTID_SUMMARY: [u8; 16] = [
    0xE0, 0x85, 0x9F, 0xF2, 0xF9, 0x4F, 0x68, 0x10, 0xAB, 0x91, 0x08, 0x00, 0x2B, 0x27, 0xB3, 0xD9,
];

enum Val {
    Str(&'static str),
    Time(u64),
}

fn pad4(v: &mut Vec<u8>) {
    while !v.len().is_multiple_of(4) {
        v.push(0);
    }
}

/// SummaryInformation with code page 1200 (VT_LPSTR sizes in bytes).
fn summary(props: &[(u32, Val)]) -> Vec<u8> {
    let mut values: Vec<(u32, Vec<u8>)> = vec![(1, {
        let mut v = 2u32.to_le_bytes().to_vec();
        v.extend(1200u16.to_le_bytes());
        pad4(&mut v);
        v
    })];
    for (pid, val) in props {
        let mut v = Vec::new();
        match val {
            Val::Str(s) => {
                let w: Vec<u16> = s.encode_utf16().chain(std::iter::once(0)).collect();
                v.extend(0x1Eu32.to_le_bytes());
                v.extend((w.len() as u32 * 2).to_le_bytes());
                for u in w {
                    v.extend(u.to_le_bytes());
                }
            }
            Val::Time(t) => {
                v.extend(0x40u32.to_le_bytes());
                v.extend(t.to_le_bytes());
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
    let mut sec = ((header + body.len()) as u32).to_le_bytes().to_vec();
    sec.extend((values.len() as u32).to_le_bytes());
    sec.extend(table);
    sec.extend(body);
    let mut out = Vec::new();
    out.extend(0xFFFEu16.to_le_bytes());
    out.extend(0u16.to_le_bytes());
    out.extend(0x0002_000Au32.to_le_bytes()); // Windows 10.0
    out.extend([0u8; 16]);
    out.extend(1u32.to_le_bytes());
    out.extend(FMTID_SUMMARY);
    out.extend(48u32.to_le_bytes());
    out.extend(sec);
    out
}

fn ft(y: i64, mo: i64, d: i64, h: i64, mi: i64, s: i64) -> u64 {
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

fn write_cfb(path: &Path, streams: &[(String, Vec<u8>)]) -> std::io::Result<()> {
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
    println!("{}: {} bytes", path.display(), bytes.len());
    std::fs::write(path, bytes)
}

fn w(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

/// `__properties_version1.0`: header of `header` bytes, then 16-byte fixed properties.
fn props(header: usize, items: &[(u16, u16, u64)]) -> Vec<u8> {
    let mut v = vec![0u8; header];
    for (ty, id, val) in items {
        v.extend(ty.to_le_bytes());
        v.extend(id.to_le_bytes());
        v.extend(6u32.to_le_bytes());
        v.extend(val.to_le_bytes());
    }
    v
}

fn tiny_docx() -> Vec<u8> {
    let mut z = zip::ZipWriter::new(Cursor::new(Vec::new()));
    let opts = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Stored)
        .last_modified_time(zip::DateTime::from_date_and_time(2024, 3, 14, 18, 42, 0).unwrap());
    for (n, d) in [
        ("[Content_Types].xml", "<Types/>"),
        ("word/document.xml", "<w:document/>"),
        (
            "docProps/core.xml",
            r#"<cp:coreProperties xmlns:cp="c" xmlns:dc="http://purl.org/dc/elements/1.1/"><dc:creator>Olena Kovalenko</dc:creator></cp:coreProperties>"#,
        ),
    ] {
        z.start_file(n, opts).unwrap();
        z.write_all(d.as_bytes()).unwrap();
    }
    z.finish().unwrap().into_inner()
}

fn msg(dir: &Path) -> std::io::Result<()> {
    let s = |p: &str, id: &str, v: &str| (format!("{p}/__substg1.0_{id}"), w(v));
    let headers = "Received: from ws-042.corp.example.test (10.20.30.42) by EXCH01.corp.example.test\r\n (10.20.0.15) with Microsoft SMTP Server id 15.2.1118.40; Thu, 14 Mar 2024 18:42:07 +0200\r\nX-Originating-IP: [10.20.30.42]\r\nX-MS-Exchange-Organization-AuthAs: Internal\r\nX-Mailer: Microsoft Outlook 16.0\r\nMessage-ID: <b2c3d4e5f6@EXCH01.corp.example.test>\r\nDate: Thu, 14 Mar 2024 18:42:07 +0200\r\n";
    let x500 = "/O=EXCHANGELABS/OU=EXCHANGE ADMINISTRATIVE GROUP (FYDIBOHF23SPDLT)/CN=RECIPIENTS/CN=I.PETRENKO";
    let mut st = vec![
        s("", "001A001F", "IPM.Note"),
        s("", "0037001F", "Кошторис на 2024 рік (фінал)"),
        s("", "0C1A001F", "Іван Петренко"),
        s("", "0C1E001F", "EX"),
        s("", "0C1F001F", x500),
        s("", "5D01001F", "i.petrenko@example.com"),
        s("", "0E04001F", "John Doe"),
        s("", "0E03001F", "Olena Kovalenko"),
        s("", "007D001F", headers),
        s("", "1035001F", "<b2c3d4e5f6@EXCH01.corp.example.test>"),
        s("", "1000001F", "Фінальна версія: https://intranet.example.test/finance/2024\r\nШлях: \\\\FS01.corp.example.test\\finance$\\2024\r\n"),
        s("", "3FFA001F", "John Doe"),
        (
            "/__properties_version1.0".into(),
            props(
                32,
                &[
                    (0x0040, 0x0039, ft(2024, 3, 14, 16, 42, 7)),
                    (0x0040, 0x3007, ft(2024, 3, 14, 16, 30, 0)),
                    (0x0040, 0x3008, ft(2024, 3, 14, 16, 42, 9)),
                ],
            ),
        ),
        ("/__nameid_version1.0/__substg1.0_00020102".into(), Vec::new()),
    ];
    for (i, (name, smtp, kind)) in [
        ("John Doe", "john.doe@example.org", 1u64),
        ("Olena Kovalenko", "o.kovalenko@example.com", 2),
    ]
    .iter()
    .enumerate()
    {
        let p = format!("/__recip_version1.0_#{i:08X}");
        st.push(s(&p, "3001001F", name));
        st.push(s(&p, "39FE001F", smtp));
        st.push(s(&p, "3003001F", smtp));
        st.push((
            format!("{p}/__properties_version1.0"),
            props(8, &[(0x0003, 0x0C15, *kind)]),
        ));
    }
    let a0 = "/__attach_version1.0_#00000000";
    st.push(s(a0, "3707001F", "Кошторис.docx"));
    st.push(s(
        a0,
        "370E001F",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    ));
    st.push((format!("{a0}/__substg1.0_37010102"), tiny_docx()));
    st.push((
        format!("{a0}/__properties_version1.0"),
        props(8, &[(0x0003, 0x3705, 1)]),
    ));
    let a1 = "/__attach_version1.0_#00000001";
    st.push(s(a1, "3707001F", "Re: budget.msg"));
    st.push((
        format!("{a1}/__properties_version1.0"),
        props(8, &[(0x0003, 0x3705, 5)]),
    ));
    let e = format!("{a1}/__substg1.0_3701000D");
    st.push(s(&e, "0037001F", "Re: budget"));
    st.push(s(&e, "0C1A001F", "Olena Kovalenko"));
    st.push(s(&e, "5D01001F", "o.kovalenko@example.com"));
    st.push(s(
        &e,
        "007D001F",
        "Received: from buh-pc-07.corp.example.test (192.168.10.7) by EXCH02.corp.example.test (10.20.0.16); Wed, 13 Mar 2024 10:00:00 +0200\r\n",
    ));
    st.push((
        format!("{e}/__properties_version1.0"),
        props(24, &[(0x0040, 0x0039, ft(2024, 3, 13, 8, 0, 0))]),
    ));
    write_cfb(&dir.join("mail/budget.msg"), &st)?;
    // broken: properties stream with a truncated entry and a recipient storage without streams
    let broken = vec![
        ("/__substg1.0_0037001F".to_string(), vec![0x41, 0x00, 0x42]),
        ("/__properties_version1.0".to_string(), vec![0u8; 40]),
        (
            "/__recip_version1.0_#00000000/__properties_version1.0".to_string(),
            vec![1, 2, 3],
        ),
        (
            "/__attach_version1.0_#00000000/__substg1.0_3701000D/__substg1.0_0037001F".to_string(),
            w("x"),
        ),
    ];
    write_cfb(&dir.join("mail/broken.msg"), &broken)
}

fn main() -> std::io::Result<()> {
    let dir = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "tests/corpus".into());
    let dir = Path::new(&dir);
    msg(dir)?;
    let si = |title: &'static str, app: &'static str| {
        summary(&[
            (2, Val::Str(title)),
            (4, Val::Str("Іван Петренко")),
            (8, Val::Str("John Doe")),
            (18, Val::Str(app)),
            (12, Val::Time(ft(2024, 3, 1, 9, 0, 0))),
            (13, Val::Time(ft(2024, 3, 14, 16, 42, 0))),
        ])
    };
    let mut vsd_head = b"Visio (TM) Drawing\r\n".to_vec();
    vsd_head.resize(0x1A, 0);
    vsd_head.push(11);
    vsd_head.resize(64, 0);
    write_cfb(
        &dir.join("legacy/network.vsd"),
        &[
            ("/VisioDocument".into(), vsd_head),
            (
                "/\u{5}SummaryInformation".into(),
                si("Схема мережі", "Microsoft Visio"),
            ),
        ],
    )?;
    let mut quill = b"CHNKINK ".to_vec();
    quill.extend([0x04, 0x00, 0x02, 0x00, 0, 0, 0, 0]);
    write_cfb(
        &dir.join("legacy/leaflet.pub"),
        &[
            ("/Quill/QuillSub/CONTENTS".into(), quill),
            ("/Contents".into(), vec![0xE8, 0xAC, 0x2C, 0x00]),
            ("/Escher/EscherStm".into(), vec![0; 8]),
            (
                "/\u{5}SummaryInformation".into(),
                si("Буклет", "Microsoft Publisher 16.0"),
            ),
        ],
    )?;
    write_cfb(
        &dir.join("legacy/letter.wps"),
        &[
            ("/MatOST/MatOST".into(), vec![0; 16]),
            ("/CONTENTS".into(), b"CHNKWKS \x04\x00\x02\x00".to_vec()),
            ("/SPELLING".into(), vec![0; 4]),
            (
                "/\u{5}SummaryInformation".into(),
                si("Лист", "Microsoft Works"),
            ),
        ],
    )?;
    Ok(())
}
