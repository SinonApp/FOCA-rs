//! Synthetic fixtures for the cleaning/hygiene tests. Shared by `tests/hygiene.rs` and
//! `examples/make_hygiene_fixtures.rs` (which writes them to `tests/fixtures/hygiene/`).
//! All names and data are fictional.

#![allow(dead_code)]

use std::io::{Cursor, Write};

/// Text present only in the first revision of [`pdf_revisions`].
pub const REMOVED_TEXT: &str = "SECRET-SALARY-4242";
/// Text present in the latest revision.
pub const KEPT_TEXT: &str = "Public notice";

/// Builds a PDF from object bodies (`objs[i]` is object `i + 1`) with a classic xref table.
/// `extra` is appended verbatim after the first `%%EOF` (an incremental update built with
/// [`pdf_update`]).
fn pdf_doc(objs: &[Vec<u8>], trailer: &str) -> Vec<u8> {
    let mut out = b"%PDF-1.7\n%\xE2\xE3\xCF\xD3\n".to_vec();
    let mut offs = Vec::new();
    for (i, body) in objs.iter().enumerate() {
        offs.push(out.len());
        out.extend_from_slice(format!("{} 0 obj\n", i + 1).as_bytes());
        out.extend_from_slice(body);
        out.extend_from_slice(b"\nendobj\n");
    }
    let xref = out.len();
    out.extend_from_slice(format!("xref\n0 {}\n0000000000 65535 f\r\n", objs.len() + 1).as_bytes());
    for o in offs {
        out.extend_from_slice(format!("{o:010} 00000 n\r\n").as_bytes());
    }
    out.extend_from_slice(
        format!(
            "trailer\n<< /Size {} {trailer} >>\nstartxref\n{xref}\n%%EOF\n",
            objs.len() + 1
        )
        .as_bytes(),
    );
    out
}

/// Appends an incremental update replacing objects `(num, body)`.
fn pdf_update(base: &mut Vec<u8>, objs: &[(u32, Vec<u8>)], size: usize, trailer: &str) {
    let prev = find_last(base, b"startxref")
        .map(|p| {
            String::from_utf8_lossy(&base[p + 9..])
                .split_whitespace()
                .next()
                .unwrap_or("0")
                .to_string()
        })
        .unwrap_or_default();
    let mut offs = Vec::new();
    for (n, body) in objs {
        offs.push((*n, base.len()));
        base.extend_from_slice(format!("{n} 0 obj\n").as_bytes());
        base.extend_from_slice(body);
        base.extend_from_slice(b"\nendobj\n");
    }
    let xref = base.len();
    base.extend_from_slice(b"xref\n");
    for (n, o) in offs {
        base.extend_from_slice(format!("{n} 1\n{o:010} 00000 n\r\n").as_bytes());
    }
    base.extend_from_slice(
        format!("trailer\n<< /Size {size} {trailer} /Prev {prev} >>\nstartxref\n{xref}\n%%EOF\n")
            .as_bytes(),
    );
}

fn find_last(h: &[u8], n: &[u8]) -> Option<usize> {
    h.windows(n.len()).rposition(|w| w == n)
}

fn stream(dict: &str, data: &[u8]) -> Vec<u8> {
    let mut v = format!("<< {dict} /Length {} >>\nstream\n", data.len()).into_bytes();
    v.extend_from_slice(data);
    v.extend_from_slice(b"\nendstream");
    v
}

fn content(lines: &[&str]) -> Vec<u8> {
    let mut s = String::new();
    for (i, l) in lines.iter().enumerate() {
        s.push_str(&format!(
            "BT /F1 12 Tf 72 {} Td ({l}) Tj ET\n",
            700 - i * 20
        ));
    }
    s.into_bytes()
}

const XMP: &str = r#"<?xpacket begin="" id="W5M0MpCehiHzreSzNTczkc9d"?><x:xmpmeta xmlns:x="adobe:ns:meta/"><rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#"><rdf:Description rdf:about="" xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:xmp="http://ns.adobe.com/xap/1.0/"><dc:creator><rdf:Seq><rdf:li>Olena Kovalenko</rdf:li></rdf:Seq></dc:creator><xmp:CreatorTool>Writer 7.1 (Windows)</xmp:CreatorTool></rdf:Description></rdf:RDF></x:xmpmeta><?xpacket end="w"?>"#;

/// Two-page PDF with every kind of removable metadata and one incremental update that
/// replaces page 1 content (dropping [`REMOVED_TEXT`]) and the Info dictionary.
pub fn pdf_revisions() -> Vec<u8> {
    let objs: Vec<Vec<u8>> = vec![
        // 1 catalog
        b"<< /Type /Catalog /Pages 2 0 R /Metadata 8 0 R /PieceInfo << /Writer << /Private (C:\\\\Users\\\\okoval\\\\draft.odt) >> >> /OpenAction 9 0 R /Names << /EmbeddedFiles << /Names [(notes.txt) 10 0 R] >> /JavaScript << /Names [(init) 9 0 R] >> >> >>".to_vec(),
        // 2 pages
        b"<< /Type /Pages /Kids [3 0 R 4 0 R] /Count 2 >>".to_vec(),
        // 3 page 1
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 5 0 R /Resources << /Font << /F1 7 0 R >> >> /Thumb 12 0 R /Annots [13 0 R] >>".to_vec(),
        // 4 page 2
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 6 0 R /Resources << /Font << /F1 7 0 R >> >> >>".to_vec(),
        // 5 page 1 content (revision 1)
        stream("", &content(&[KEPT_TEXT, REMOVED_TEXT])),
        // 6 page 2 content
        stream("", &content(&["Page two body"])),
        // 7 font
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>".to_vec(),
        // 8 XMP
        stream("/Type /Metadata /Subtype /XML", XMP.as_bytes()),
        // 9 JavaScript action
        b"<< /Type /Action /S /JavaScript /JS (app.alert\\('hi'\\);) >>".to_vec(),
        // 10 file specification
        b"<< /Type /Filespec /F (notes.txt) /UF (notes.txt) /EF << /F 11 0 R >> >>".to_vec(),
        // 11 embedded file
        stream("/Type /EmbeddedFile /Subtype /text#2Fplain", b"internal notes by Olena"),
        // 12 thumbnail image
        stream("/Type /XObject /Subtype /Image /Width 1 /Height 1 /ColorSpace /DeviceGray /BitsPerComponent 8", b"\x80"),
        // 13 text annotation with author
        b"<< /Type /Annot /Subtype /Text /Rect [10 10 30 30] /T (Olena Kovalenko) /Contents (Check the numbers) /M (D:20240105120000Z) >>".to_vec(),
        // 14 Info
        b"<< /Author (Olena Kovalenko) /Creator (Writer) /Producer (LibreOffice 7.1) /Title (Draft) /Company (Example LLC) /CreationDate (D:20240101100000Z) >>".to_vec(),
    ];
    let mut b = pdf_doc(&objs, "/Root 1 0 R /Info 14 0 R");
    pdf_update(
        &mut b,
        &[
            (5, stream("", &content(&[KEPT_TEXT, "Approved"]))),
            (
                14,
                b"<< /Author (Taras Bondar) /Producer (Acrobat 11) /ModDate (D:20240201100000Z) >>"
                    .to_vec(),
            ),
        ],
        15,
        "/Root 1 0 R /Info 14 0 R",
    );
    b
}

/// PDF 1.5 with an object stream and a cross-reference stream (compressed).
pub fn pdf_objstm() -> Vec<u8> {
    use flate2::write::ZlibEncoder;
    let z = |d: &[u8]| {
        let mut e = ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        e.write_all(d).unwrap();
        e.finish().unwrap()
    };
    let objs = [
        (1u32, "<< /Type /Catalog /Pages 2 0 R >>"),
        (2, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>"),
        (3, "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 << /Type /Font /Subtype /Type1 /BaseFont /Helvetica >> >> >> >>"),
        (5, "<< /Author (Mykola Shevchuk) /Producer (pdfTeX-1.40) >>"),
    ];
    let mut header = String::new();
    let mut body = String::new();
    for (n, s) in objs {
        header.push_str(&format!("{n} {} ", body.len()));
        body.push_str(s);
        body.push('\n');
    }
    let first = header.len();
    let objstm = format!("{header}{body}");
    let mut out = b"%PDF-1.5\n%\xE2\xE3\xCF\xD3\n".to_vec();
    let c4 = z(&content(&["Compressed object streams"]));
    let off4 = out.len();
    out.extend_from_slice(b"4 0 obj\n");
    out.extend_from_slice(&stream("/Filter /FlateDecode", &c4));
    out.extend_from_slice(b"\nendobj\n");
    let off6 = out.len();
    let os = z(objstm.as_bytes());
    out.extend_from_slice(b"6 0 obj\n");
    out.extend_from_slice(&stream(
        &format!("/Type /ObjStm /N 4 /First {first} /Filter /FlateDecode"),
        &os,
    ));
    out.extend_from_slice(b"\nendobj\n");
    let off7 = out.len();
    // xref stream: W [1 4 2]
    let mut x = Vec::new();
    let mut row = |t: u8, a: u32, b: u16| {
        x.push(t);
        x.extend_from_slice(&a.to_be_bytes());
        x.extend_from_slice(&b.to_be_bytes());
    };
    row(0, 0, 65535);
    row(2, 6, 0);
    row(2, 6, 1);
    row(2, 6, 2);
    row(1, off4 as u32, 0);
    row(2, 6, 3);
    row(1, off6 as u32, 0);
    row(1, off7 as u32, 0);
    let xs = z(&x);
    out.extend_from_slice(b"7 0 obj\n");
    out.extend_from_slice(&stream(
        "/Type /XRef /Size 8 /W [1 4 2] /Root 1 0 R /Info 5 0 R /Filter /FlateDecode",
        &xs,
    ));
    out.extend_from_slice(format!("\nendobj\nstartxref\n{off7}\n%%EOF\n").as_bytes());
    out
}

/// Encrypted PDF (only the trailer marker matters for the cleaner).
pub fn pdf_encrypted() -> Vec<u8> {
    pdf_doc(
        &[
            b"<< /Type /Catalog /Pages 2 0 R >>".to_vec(),
            b"<< /Type /Pages /Kids [] /Count 0 >>".to_vec(),
            b"<< /Filter /Standard /V 2 /R 3 /O <00> /U <00> /P -4 >>".to_vec(),
        ],
        "/Root 1 0 R /Encrypt 3 0 R /ID [<01> <01>]",
    )
}

const ODT_META: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<office:document-meta xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0" xmlns:meta="urn:oasis:names:tc:opendocument:xmlns:meta:1.0" xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:xlink="http://www.w3.org/1999/xlink" office:version="1.3"><office:meta><meta:generator>LibreOffice/7.5.1.2$Windows_X86_64</meta:generator><dc:title>Budget</dc:title><meta:initial-creator>Olena Kovalenko</meta:initial-creator><dc:creator>o.kovalenko</dc:creator><meta:creation-date>2024-01-10T09:00:00</meta:creation-date><dc:date>2024-01-12T17:30:00</dc:date><meta:print-date>2024-01-12T17:31:00</meta:print-date><meta:printed-by>Olena Kovalenko</meta:printed-by><meta:editing-cycles>7</meta:editing-cycles><meta:editing-duration>PT2H5M</meta:editing-duration><meta:template xlink:type="simple" xlink:href="file:///C:/Users/okoval/Templates/memo.ott" xlink:title="memo"/><meta:document-statistic meta:page-count="1" meta:paragraph-count="2" meta:word-count="6" meta:character-count="40"/><meta:user-defined meta:name="Department">Finance</meta:user-defined></office:meta></office:document-meta>"#;

const ODT_SETTINGS: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<office:document-settings xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0" xmlns:config="urn:oasis:names:tc:opendocument:xmlns:config:1.0" office:version="1.3"><office:settings><config:config-item-set config:name="ooo:view-settings"><config:config-item config:name="ViewAreaTop" config:type="long">0</config:config-item></config:config-item-set><config:config-item-set config:name="ooo:configuration-settings"><config:config-item config:name="PrinterName" config:type="string">\\PRN-SRV01\HP-Finance-3F</config:config-item><config:config-item config:name="PrinterSetup" config:type="base64Binary">UHJpbnRlclNldHVw</config:config-item><config:config-item config:name="CurrentDatabaseDataSource" config:type="string">file:///C:/Users/okoval/Documents/addresses.odb</config:config-item><config:config-item config:name="AddExternalLeading" config:type="boolean">true</config:config-item><config:config-item config:name="PrintEmptyPages" config:type="boolean"/></config:config-item-set></office:settings></office:document-settings>"#;

const ODT_CONTENT: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<office:document-content xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0" xmlns:text="urn:oasis:names:tc:opendocument:xmlns:text:1.0" xmlns:dc="http://purl.org/dc/elements/1.1/" office:version="1.3"><office:body><office:text><text:tracked-changes><text:changed-region text:id="ct1"><text:deletion><office:change-info><dc:creator>Taras Bondar</dc:creator><dc:date>2024-01-11T10:00:00</dc:date></office:change-info><text:p>old figure</text:p></text:deletion></text:changed-region></text:tracked-changes><text:p>Quarterly budget &amp; plan<office:annotation><dc:creator>Taras Bondar</dc:creator><dc:date>2024-01-11T10:05:00</dc:date><text:p>Recheck totals</text:p></office:annotation></text:p><text:p>Second paragraph</text:p></office:text></office:body></office:document-content>"#;

const ODT_MANIFEST: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<manifest:manifest xmlns:manifest="urn:oasis:names:tc:opendocument:xmlns:manifest:1.0" manifest:version="1.3"><manifest:file-entry manifest:full-path="/" manifest:media-type="application/vnd.oasis.opendocument.text"/><manifest:file-entry manifest:full-path="Thumbnails/thumbnail.png" manifest:media-type="image/png"/><manifest:file-entry manifest:full-path="content.xml" manifest:media-type="text/xml"/><manifest:file-entry manifest:full-path="meta.xml" manifest:media-type="text/xml"/><manifest:file-entry manifest:full-path="settings.xml" manifest:media-type="text/xml"/><manifest:file-entry manifest:full-path="VersionList.xml" manifest:media-type="text/xml"/></manifest:manifest>"#;

const VERSION_LIST: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<VL:version-list xmlns:VL="http://openoffice.org/2001/versions-list" xmlns:dc="http://purl.org/dc/elements/1.1/"><VL:version-entry VL:title="Version1" VL:comment="before review" dc:creator="Olena Kovalenko" dc:date-time="2024-01-11T08:00:00"/></VL:version-list>"#;

/// ODT with full metadata. `mimetype` is deliberately the *last*, deflated entry so the
/// cleaner has to reorder it.
pub fn odt_full() -> Vec<u8> {
    use zip::write::SimpleFileOptions;
    let mut w = zip::ZipWriter::new(Cursor::new(Vec::new()));
    let o = SimpleFileOptions::default();
    for (name, data) in [
        ("META-INF/manifest.xml", ODT_MANIFEST.as_bytes()),
        ("meta.xml", ODT_META.as_bytes()),
        ("settings.xml", ODT_SETTINGS.as_bytes()),
        ("content.xml", ODT_CONTENT.as_bytes()),
        (
            "Thumbnails/thumbnail.png",
            b"\x89PNG\r\n\x1a\nthumbnail".as_slice(),
        ),
        ("VersionList.xml", VERSION_LIST.as_bytes()),
        ("Versions/Version1", b"older package bytes".as_slice()),
        (
            "mimetype",
            b"application/vnd.oasis.opendocument.text".as_slice(),
        ),
    ] {
        w.start_file(name, o).unwrap();
        w.write_all(data).unwrap();
    }
    w.finish().unwrap().into_inner()
}
