//! Office wave of 2.0.0-beta.5: ODF printer, hidden content and objects, OOXML thumbnail and
//! hidden slides, encrypted OOXML in a compound file, the OS of property sets.

use std::io::{Cursor, Write};

use crate::formats::office::ole_objects::tests::cfb;
use crate::{extract, Limits};

fn zip(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut w = zip::ZipWriter::new(Cursor::new(Vec::new()));
    let o = zip::write::SimpleFileOptions::default();
    for (n, d) in entries {
        w.start_file(*n, o).unwrap();
        w.write_all(d).unwrap();
    }
    w.finish().unwrap().into_inner()
}

const PNG_1X1: &[u8] = b"\x89PNG\r\n\x1a\n\0\0\0\rIHDR\0\0\0\x01\0\0\0\x01\x08\x02\0\0\0\x90wS\xde\0\0\0\0IEND\xaeB`\x82";

#[test]
fn ods_printer_hidden_sheet_rows_thumbnail_and_objects() {
    // JobSetup: 4-byte header, 64-byte printer, 32-byte device, port and driver names
    let mut job = vec![0u8; 4];
    let mut put = |s: &str, n: usize| {
        let mut b = s.as_bytes().to_vec();
        b.resize(n, 0);
        job.extend(b);
    };
    put("\\\\print-srv.corp.local\\Бухгалтерия-2", 64);
    put("HP LaserJet 4250", 32);
    put("IP_10.1.2.3", 32);
    put("hpcups", 32);
    let b64 = foca_core::b64::encode(&job);
    let settings = format!(
        r#"<office:document-settings xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0" xmlns:config="urn:oasis:names:tc:opendocument:xmlns:config:1.0"><office:settings><config:config-item-set config:name="ooo:configuration-settings"><config:config-item config:name="PrinterName" config:type="string">Generic Printer</config:config-item><config:config-item config:name="PrinterSetup" config:type="base64Binary">{b64}</config:config-item></config:config-item-set></office:settings></office:document-settings>"#
    );
    let content = r#"<office:document-content xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0" xmlns:style="urn:oasis:names:tc:opendocument:xmlns:style:1.0" xmlns:table="urn:oasis:names:tc:opendocument:xmlns:table:1.0" xmlns:text="urn:oasis:names:tc:opendocument:xmlns:text:1.0"><office:automatic-styles><style:style style:name="ta2" style:family="table"><style:table-properties table:display="false"/></style:style></office:automatic-styles><office:body><office:spreadsheet><table:table table:name="Видимый"><table:table-row><table:table-cell><text:p>a</text:p></table:table-cell></table:table-row><table:table-row table:visibility="collapse"><table:table-cell><text:p>ИНН 1234567890</text:p></table:table-cell></table:table-row></table:table><table:table table:name="Секрет" table:style-name="ta2"/></office:spreadsheet></office:body></office:document-content>"#;
    let ods = zip(&[
        (
            "mimetype",
            b"application/vnd.oasis.opendocument.spreadsheet",
        ),
        ("content.xml", content.as_bytes()),
        ("settings.xml", settings.as_bytes()),
        ("Thumbnails/thumbnail.png", PNG_1X1),
        ("Object 1/content.xml", b"<x/>"),
        ("ObjectReplacements/Object 1", b"x"),
    ]);
    let m = extract(&ods, Some("a.ods"), &Limits::default()).unwrap();
    assert!(m.printers.iter().any(|p| p == "Generic Printer"));
    assert!(
        m.printers.iter().any(|p| p.contains("Бухгалтерия-2")),
        "{:?}",
        m.printers
    );
    assert!(
        m.servers.iter().any(|s| s.name == "print-srv.corp.local"),
        "{:?}",
        m.servers
    );
    assert_eq!(
        m.fields.get("odf:printer_driver").map(String::as_str),
        Some("hpcups")
    );
    assert_eq!(m.hidden_sheets, vec!["Секрет".to_string()]);
    assert!(m
        .hidden_content
        .iter()
        .any(|h| h.text.contains("ИНН 1234567890")));
    assert!(m
        .embedded
        .iter()
        .any(|e| e.name == "Thumbnails/thumbnail.png"));
    assert!(m.attachments.iter().any(|a| a.name == "Object 1"));
}

#[test]
fn pptx_hidden_slide_and_thumbnail() {
    let ct = br#"<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"/>"#;
    let s1 = r#"<p:sld xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main" xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main"><p:cSld><a:p><a:t>Публичный</a:t></a:p></p:cSld></p:sld>"#;
    let s2 = r#"<p:sld xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main" xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" show="0"><p:cSld><a:p><a:t>Скрытый план 東京</a:t></a:p></p:cSld></p:sld>"#;
    let p = zip(&[
        ("[Content_Types].xml", ct),
        ("ppt/presentation.xml", b"<p:presentation/>"),
        ("ppt/slides/slide1.xml", s1.as_bytes()),
        ("ppt/slides/slide2.xml", s2.as_bytes()),
        ("docProps/thumbnail.jpeg", b"\xff\xd8\xff\xd9"),
    ]);
    let m = extract(&p, Some("a.pptx"), &Limits::default()).unwrap();
    let h: Vec<_> = m
        .hidden_content
        .iter()
        .filter(|h| h.kind == "slide")
        .collect();
    assert_eq!(h.len(), 1);
    assert_eq!(h[0].text, "Скрытый план 東京");
    assert_eq!(
        m.fields.get("office:thumbnail").map(String::as_str),
        Some("docProps/thumbnail.jpeg")
    );
}

#[test]
fn encrypted_ooxml_in_a_compound_file() {
    let mut info = 4u16.to_le_bytes().to_vec();
    info.extend_from_slice(&4u16.to_le_bytes());
    info.extend_from_slice(&[0; 8]);
    let f = cfb(&[
        ("/EncryptionInfo", info),
        ("/EncryptedPackage", vec![0; 64]),
    ]);
    let m = extract(&f, Some("secret.xlsx"), &Limits::default()).unwrap();
    assert!(m.encrypted);
    assert_eq!(
        m.fields.get("ole:encryption").map(String::as_str),
        Some("OOXML agile encryption 4.4")
    );
}

/// SummaryInformation with only an OSVersion header and an empty section.
fn summary_with_os(os: u32) -> Vec<u8> {
    let mut v = 0xFFFEu16.to_le_bytes().to_vec();
    v.extend_from_slice(&0u16.to_le_bytes());
    v.extend_from_slice(&os.to_le_bytes());
    v.extend_from_slice(&[0; 16]);
    v.extend_from_slice(&1u32.to_le_bytes());
    v.extend_from_slice(&[
        0xE0, 0x85, 0x9F, 0xF2, 0xF9, 0x4F, 0x68, 0x10, 0xAB, 0x91, 0x08, 0x00, 0x2B, 0x27, 0xB3,
        0xD9,
    ]);
    v.extend_from_slice(&48u32.to_le_bytes());
    v.extend_from_slice(&8u32.to_le_bytes());
    v.extend_from_slice(&0u32.to_le_bytes());
    v
}

#[test]
fn os_version_placeholders_are_not_reported() {
    for (os, want) in [
        (0x0002_0001u32, None),
        (0x0000_0000, None),
        (0x0002_0105, Some("Windows XP")),
        (0x0002_000A, Some("Windows 10/11")),
    ] {
        let f = cfb(&[
            ("/WordDocument", vec![0; 64]),
            ("/\u{5}SummaryInformation", summary_with_os(os)),
        ]);
        let m = extract(&f, Some("a.doc"), &Limits::default()).unwrap();
        assert_eq!(m.os.as_deref(), want, "{os:#x}");
    }
}

#[test]
fn publisher_story_text_picture_paths_and_links() {
    let w = |s: &str| -> Vec<u8> { s.encode_utf16().flat_map(u16::to_le_bytes).collect() };
    let mut quill = b"CHNKINK \x04\x00\x01\x00".to_vec();
    quill.extend_from_slice(&[0; 16]);
    quill.extend(w("Оголошення відділу\rКонтакт: hr@corp.example\r"));
    let mut pib = w("C:\\DOCUME~1\\Nick\\LOCALS~1\\Temp\\pub19.tmp");
    pib.extend_from_slice(&[0, 0]);
    let mut body = (0x0105u16 | 0xC000).to_le_bytes().to_vec();
    body.extend_from_slice(&(pib.len() as u32).to_le_bytes());
    body.extend(pib);
    let mut fopt = ((1u16 << 4) | 3).to_le_bytes().to_vec();
    fopt.extend_from_slice(&0xF00Bu16.to_le_bytes());
    fopt.extend_from_slice(&(body.len() as u32).to_le_bytes());
    fopt.extend(body);
    let mut contents = vec![0u8; 8];
    contents.extend(w("http://intranet.corp.example/jobs"));
    contents.extend_from_slice(&[0, 0]);
    let f = cfb(&[
        ("/Quill/QuillSub/CONTENTS", quill),
        ("/Escher/EscherStm", fopt),
        ("/Contents", contents),
    ]);
    let m = extract(&f, Some("a.pub"), &Limits::default()).unwrap();
    assert_eq!(m.format, crate::DocFormat::Pub);
    assert!(
        m.paths.iter().any(|p| p.path.ends_with("pub19.tmp")),
        "{:?}",
        m.fields
    );
    assert!(m.people.iter().any(|p| p.name == "Nick"));
    assert!(m
        .links
        .iter()
        .any(|l| l == "http://intranet.corp.example/jobs"));
    let t = crate::text(&f, &Limits::default()).unwrap();
    assert!(t.contains("Оголошення відділу"), "{t}");
    assert!(t.contains("hr@corp.example"), "{t}");
}
