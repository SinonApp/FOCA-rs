//! PowerPoint stream tests with synthetic records.

use std::io::Write;

use crate::formats::office::ole_objects::tests::{cfb, png_blip, workbook};
use crate::{extract, text, DocFormat, Limits};

fn atom(ty: u16, inst: u16, body: &[u8]) -> Vec<u8> {
    let mut v = (inst << 4).to_le_bytes().to_vec();
    v.extend_from_slice(&ty.to_le_bytes());
    v.extend_from_slice(&(body.len() as u32).to_le_bytes());
    v.extend_from_slice(body);
    v
}

fn container(ty: u16, kids: &[Vec<u8>]) -> Vec<u8> {
    let body: Vec<u8> = kids.concat();
    let mut v = 0x000Fu16.to_le_bytes().to_vec();
    v.extend_from_slice(&ty.to_le_bytes());
    v.extend_from_slice(&(body.len() as u32).to_le_bytes());
    v.extend(body);
    v
}

fn w(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

fn presentation() -> Vec<u8> {
    let mut st = vec![0u8; 4];
    for x in [2024u16, 3, 5, 14, 9, 30, 15, 0] {
        st.extend_from_slice(&x.to_le_bytes());
    }
    let obj = {
        let inner = cfb(&[("/Workbook", workbook("Embedded Author"))]);
        let mut z = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::fast());
        z.write_all(&inner).unwrap();
        let mut body = (inner.len() as u32).to_le_bytes().to_vec();
        body.extend(z.finish().unwrap());
        body
    };
    let doc = container(
        0x03E8,
        &[
            container(
                0x0FF0,
                &[
                    atom(0x0FA0, 0, &w("Квартальний звіт\rمرحبا 東京")),
                    atom(0x0FA8, 0, b"Contact: ops@corp.example"),
                ],
            ),
            container(
                0x2EE0,
                &[
                    atom(0x0FBA, 0, &w("Maria Garcia")),
                    atom(0x0FBA, 1, &w("Fix the numbers")),
                    atom(0x0FBA, 2, &w("MG")),
                    atom(0x2EE1, 0, &st),
                ],
            ),
            container(
                0x0FD7,
                &[
                    atom(0x0FD3, 0, &[0; 4]),
                    atom(0x0FBA, 0, &w("wiki")),
                    atom(0x0FBA, 1, &w("http://intranet.corp.example/wiki")),
                ],
            ),
            atom(0x1011, 1, &obj),
        ],
    );
    let mut s = doc;
    s.extend(atom(0x0FF5, 0, &[0; 28]));
    s.extend(atom(0x0FF5, 0, &[0; 28]));
    cfb(&[("/PowerPoint Document", s), ("/Pictures", png_blip())])
}

#[test]
fn ppt_text_comments_links_objects() {
    let p = presentation();
    let m = extract(&p, Some("a.ppt"), &Limits::default()).unwrap();
    assert_eq!(m.format, DocFormat::Ppt);
    let c = m.comments.first().expect("comment");
    assert_eq!(c.author.as_deref(), Some("Maria Garcia"));
    assert_eq!(c.initials.as_deref(), Some("MG"));
    assert_eq!(c.date.as_deref(), Some("2024-03-14T09:30:15"));
    assert!(m
        .links
        .iter()
        .any(|l| l == "http://intranet.corp.example/wiki"));
    assert_eq!(m.stats.get("saves"), Some(&2));
    let kinds: Vec<DocFormat> = m.embedded.iter().map(|e| e.metadata.format).collect();
    assert!(
        kinds.contains(&DocFormat::Xls),
        "{kinds:?} {:?}",
        m.warnings
    );
    assert!(kinds.contains(&DocFormat::Png), "{kinds:?}");
    let t = text(&p, &Limits::default()).unwrap();
    for want in [
        "Квартальний звіт",
        "مرحبا 東京",
        "ops@corp.example",
        "Fix the numbers",
    ] {
        assert!(t.contains(want), "{want}: {t}");
    }
}

#[test]
fn ppt_garbage_never_panics() {
    let p = presentation();
    let mut rng = crate::util::Rng(0x0997_0001);
    for _ in 0..200 {
        let mut v = p.clone();
        for _ in 0..8 {
            let i = (rng.next() as usize) % v.len();
            v[i] = rng.next() as u8;
        }
        let _ = extract(&v, Some("a.ppt"), &Limits::default());
        let _ = text(&v, &Limits::default());
    }
    let mut m = crate::Metadata::default();
    let limits = Limits::default();
    let budget = std::cell::Cell::new(1 << 20);
    let ctx = crate::Ctx::standalone(&limits, &budget);
    // a container claiming more bytes than exist, and deep nesting
    let mut deep = Vec::new();
    for _ in 0..100 {
        deep = container(0x03E8, &[deep]);
    }
    let _ = super::parse(&deep, &mut m, &ctx, true);
    let _ = super::parse(
        &[0x0F, 0, 0xE8, 3, 0xFF, 0xFF, 0xFF, 0xFF],
        &mut m,
        &ctx,
        true,
    );
}
