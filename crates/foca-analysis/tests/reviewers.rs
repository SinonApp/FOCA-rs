//! DOCX reviewers (comments and `w:ins`/`w:del` revisions) become people with the reviewer
//! role. The e-mail from the AD account in `word/people.xml`
//! (`w15:presenceInfo userId="S::user@domain::guid"`) is attached to that person and the login
//! is derived from it. The document is synthetic and built inside the test.
//!
//! Golden file: `crates/foca-analysis/tests/fixtures/reviewers.expected.json`
//! (regenerate with `UPDATE_GOLDEN=1 cargo test -p foca-analysis --test reviewers`).

use std::path::Path;

use foca_analysis::{analyze, DocInput, PrevState};
use foca_core::{DocStatus, Document, Scope};
use foca_meta::Limits;
use time::macros::datetime;

fn crc32(b: &[u8]) -> u32 {
    let mut c = 0xFFFF_FFFFu32;
    for &x in b {
        c ^= x as u32;
        for _ in 0..8 {
            c = if c & 1 != 0 {
                (c >> 1) ^ 0xEDB8_8320
            } else {
                c >> 1
            };
        }
    }
    !c
}

/// Builds a minimal uncompressed (stored) ZIP, which is enough for OOXML.
fn zip(files: &[(&str, &str)]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut cd = Vec::new();
    for (name, body) in files {
        let (n, b) = (name.as_bytes(), body.as_bytes());
        let off = out.len() as u32;
        let crc = crc32(b);
        let hdr = |sig: u32, central: bool| {
            let mut h = Vec::new();
            h.extend(sig.to_le_bytes());
            if central {
                h.extend(20u16.to_le_bytes());
            }
            h.extend(20u16.to_le_bytes()); // version
            h.extend(0u16.to_le_bytes()); // flags
            h.extend(0u16.to_le_bytes()); // stored
            h.extend(0u32.to_le_bytes()); // time+date
            h.extend(crc.to_le_bytes());
            h.extend((b.len() as u32).to_le_bytes());
            h.extend((b.len() as u32).to_le_bytes());
            h.extend((n.len() as u16).to_le_bytes());
            h.extend(0u16.to_le_bytes()); // extra
            if central {
                h.extend(0u16.to_le_bytes()); // comment
                h.extend(0u16.to_le_bytes()); // disk
                h.extend(0u16.to_le_bytes()); // int attr
                h.extend(0u32.to_le_bytes()); // ext attr
                h.extend(off.to_le_bytes());
            }
            h.extend(n);
            h
        };
        out.extend(hdr(0x0403_4b50, false));
        out.extend(b);
        cd.extend(hdr(0x0201_4b50, true));
    }
    let cd_off = out.len() as u32;
    out.extend(&cd);
    out.extend(0x0605_4b50u32.to_le_bytes());
    out.extend([0u8; 4]);
    out.extend((files.len() as u16).to_le_bytes());
    out.extend((files.len() as u16).to_le_bytes());
    out.extend((cd.len() as u32).to_le_bytes());
    out.extend(cd_off.to_le_bytes());
    out.extend(0u16.to_le_bytes());
    out
}

const W: &str = r#"xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:w15="http://schemas.microsoft.com/office/word/2012/wordml""#;

fn docx() -> Vec<u8> {
    let ct = r#"<?xml version="1.0" encoding="UTF-8"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="xml" ContentType="application/xml"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/><Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/></Types>"#;
    let rels = r#"<?xml version="1.0" encoding="UTF-8"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>"#;
    let core = r#"<?xml version="1.0" encoding="UTF-8"?><cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"><dc:title>Положення про закупівлі</dc:title><dc:creator>Петренко Ігор</dc:creator><cp:lastModifiedBy>Марія Шевченко</cp:lastModifiedBy><dcterms:created xsi:type="dcterms:W3CDTF">2026-03-02T09:00:00Z</dcterms:created></cp:coreProperties>"#;
    let doc = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?><w:document {W}><w:body><w:p><w:r><w:t>Пункт 1.</w:t></w:r><w:ins w:id="1" w:author="Олена Коваль" w:date="2026-03-03T10:00:00Z"><w:r><w:t>Додано.</w:t></w:r></w:ins><w:del w:id="2" w:author="Андрій Мельник" w:date="2026-03-04T11:00:00Z"><w:r><w:delText>Видалено.</w:delText></w:r></w:del></w:p></w:body></w:document>"#
    );
    let comments = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?><w:comments {W}><w:comment w:id="0" w:author="Олена Коваль" w:initials="ОК" w:date="2026-03-03T10:05:00Z"><w:p><w:r><w:t>Уточнити строки.</w:t></w:r></w:p></w:comment><w:comment w:id="1" w:author="Тарас Бондар" w:initials="ТБ" w:date="2026-03-03T12:00:00Z"><w:p><w:r><w:t>Згоден.</w:t></w:r></w:p></w:comment><w:comment w:id="2" w:author="Олена Коваль" w:date="2026-03-05T08:00:00Z"><w:p><w:r><w:t>Виправлено.</w:t></w:r></w:p></w:comment><w:comment w:id="3" w:author="Андрій Мельник" w:date="2026-03-05T09:00:00Z"><w:p><w:r><w:t>Ок.</w:t></w:r></w:p></w:comment><w:comment w:id="4" w:author="Сидоренко Ігор" w:date="2026-03-06T09:00:00Z"><w:p><w:r><w:t>Перевірено юристом.</w:t></w:r></w:p></w:comment></w:comments>"#
    );
    let people = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?><w15:people {W}><w15:person w15:author="Олена Коваль"><w15:presenceInfo w15:providerId="AD" w15:userId="S::Olena.Koval@contoso.example::7d1e2f3a-0b4c-4d5e-8f90-123456789abc"/></w15:person><w15:person w15:author="Тарас Бондар"><w15:presenceInfo w15:providerId="Windows Live" w15:userId="5a3c9e0f12b4d678"/></w15:person><w15:person w15:author="Сидоренко Ігор"><w15:presenceInfo w15:providerId="AD" w15:userId="S::ISD-0420@contoso.example::0f9e8d7c-6b5a-4433-8211-00aabbccddee"/></w15:person><w15:person w15:author="Андрій Мельник"><w15:presenceInfo w15:providerId="None" w15:userId="Андрій Мельник"/></w15:person></w15:people>"#
    );
    zip(&[
        ("[Content_Types].xml", ct),
        ("_rels/.rels", rels),
        ("docProps/core.xml", core),
        ("word/document.xml", &doc),
        ("word/comments.xml", &comments),
        ("word/people.xml", &people),
    ])
}

#[test]
fn reviewers_become_people_with_ad_email() {
    let bytes = docx();
    let l = Limits::default();
    let meta = foca_meta::extract(&bytes, Some("polozhennia.docx"), &l).expect("metadata");
    let doc = Document {
        id: 1,
        ext: "docx".into(),
        name: "polozhennia.docx".into(),
        url: Some("https://contoso.example/docs/polozhennia.docx".into()),
        source: "local".into(),
        size: bytes.len() as u64,
        status: DocStatus::Analyzed,
        metadata: Some(meta),
        ..Default::default()
    };
    let inputs = vec![DocInput {
        first_scan: Some("s1"),
        ..DocInput::new(&doc)
    }];
    let (scope, _) = Scope::from_lines("contoso.example", "");
    let prev = PrevState {
        now: Some(datetime!(2026-11-20 12:00 UTC)),
        scan_id: Some("s1".into()),
        ..Default::default()
    };
    let a = analyze(&inputs, &scope, &prev);
    let ppl: Vec<serde_json::Value> = a
        .people
        .iter()
        .map(|p| serde_json::json!({ "name": p.name, "login": p.login, "role": p.role, "emails": p.emails }))
        .collect();
    let find = |n: &str| {
        a.people
            .iter()
            .find(|p| p.name == n)
            .unwrap_or_else(|| panic!("{n:?} missing from people: {ppl:?}"))
    };
    // Author and last editor keep their usual roles.
    assert_eq!(find("Петренко Ігор").role, "");
    find("Марія Шевченко");
    // Reviewers come from comments and tracked changes.
    for n in ["Олена Коваль", "Тарас Бондар", "Андрій Мельник"] {
        assert_eq!(find(n).role, "Рецензент", "{n}: {ppl:?}");
    }
    // The AD account e-mail is attached to the person; the login is taken from it.
    let ok = find("Олена Коваль");
    assert_eq!(ok.emails, vec!["olena.koval@contoso.example".to_string()]);
    assert_eq!(ok.login, "olena.koval");
    // The login comes from the address even when it does not resemble the name: the link is
    // taken from people.xml, not inferred by similarity.
    let si = find("Сидоренко Ігор");
    assert_eq!(si.role, "Рецензент");
    assert_eq!(si.emails, vec!["isd-0420@contoso.example".to_string()]);
    assert_eq!(si.login, "isd-0420");
    assert_eq!(
        a.people
            .iter()
            .filter(|p| p.emails.iter().any(|e| e.starts_with("isd-0420")))
            .count(),
        1,
        "the address must not become a separate person: {ppl:?}"
    );
    // Windows Live and `None` ids are not e-mail addresses; nothing is invented.
    assert!(find("Тарас Бондар").emails.is_empty());
    assert!(a
        .emails
        .iter()
        .any(|e| e.addr == "olena.koval@contoso.example"));

    let got = serde_json::json!({ "people": ppl });
    let exp = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/reviewers.expected.json");
    if std::env::var("UPDATE_GOLDEN").is_ok_and(|v| v == "1") || !exp.exists() {
        std::fs::create_dir_all(exp.parent().unwrap()).unwrap();
        std::fs::write(&exp, serde_json::to_string_pretty(&got).unwrap() + "\n").unwrap();
    }
    let want: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&exp).unwrap()).unwrap();
    assert_eq!(
        got, want,
        "golden mismatch; regenerate with UPDATE_GOLDEN=1 cargo test -p foca-analysis --test reviewers"
    );
}
