//! Visually hidden content: synthetic DOCX/XLSX/PPTX/ODT/ODS/ODP/RTF/PPT files, each with a
//! visible control case that must not be flagged.

use std::io::{Cursor, Write};

use crate::formats::office::visual::format_hides;
use crate::{extract, Limits, Metadata};

fn zip(entries: &[(&str, &str)]) -> Vec<u8> {
    let mut w = zip::ZipWriter::new(Cursor::new(Vec::new()));
    let o = zip::write::SimpleFileOptions::default();
    for (n, d) in entries {
        w.start_file(*n, o).unwrap();
        w.write_all(d.as_bytes()).unwrap();
    }
    w.finish().unwrap().into_inner()
}

fn kinds<'a>(m: &'a Metadata, kind: &str) -> Vec<&'a str> {
    m.hidden_content
        .iter()
        .filter(|h| h.kind == kind)
        .map(|h| h.text.as_str())
        .collect()
}

const CT: &str = r#"<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"/>"#;
const THEME: &str = r#"<a:theme xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main"><a:themeElements><a:clrScheme name="Office"><a:dk1><a:sysClr val="windowText" lastClr="000000"/></a:dk1><a:lt1><a:sysClr val="window" lastClr="FFFFFF"/></a:lt1><a:dk2><a:srgbClr val="44546A"/></a:dk2><a:lt2><a:srgbClr val="E7E6E6"/></a:lt2></a:clrScheme></a:themeElements></a:theme>"#;

#[test]
fn number_formats_that_print_nothing() {
    assert!(format_hides(";;;", true));
    assert!(format_hides(";;;", false));
    assert!(format_hides(";;;@", false));
    assert!(!format_hides(";;;@", true));
    assert!(!format_hides("0.00;-0.00", false));
    assert!(!format_hides("\"a;b;c\";;", true));
    assert!(format_hides("[Red];;", false));
}

#[test]
fn xlsx_white_cells_invisible_formats_and_collapsed_rows() {
    let styles = r#"<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><numFmts count="2"><numFmt numFmtId="164" formatCode=";;;"/><numFmt numFmtId="165" formatCode=";;;@"/></numFmts><fonts count="3"><font><color theme="1"/></font><font><color rgb="00FFFFFF"/></font><font><color theme="0"/></font></fonts><fills count="3"><fill><patternFill/></fill><fill><patternFill patternType="gray125"/></fill><fill><patternFill patternType="solid"><fgColor rgb="FF1F3864"/></patternFill></fill></fills><cellXfs count="6"><xf fontId="0" fillId="0"/><xf fontId="1" fillId="0"/><xf fontId="1" fillId="2"/><xf numFmtId="164" fontId="0" fillId="0"/><xf numFmtId="165" fontId="0" fillId="0"/><xf fontId="2" fillId="0"/></cellXfs></styleSheet>"#;
    let sheet = r#"<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData>
<row r="1"><c r="A1" t="inlineStr" s="2"><is><t>Заголовок на темному</t></is></c></row>
<row r="2"><c r="B2"><v>120000</v></c><c r="D2" s="1" t="inlineStr"><is><t>погоджено з Петренко О.В., тел. +380 67 000 00 00</t></is></c></row>
<row r="3"><c r="A3" s="3" t="inlineStr"><is><t>ПАРОЛЬ qwerty</t></is></c><c r="B3" s="4" t="inlineStr"><is><t>видно</t></is></c><c r="C3" s="4"><v>4111111111111111</v></c></row>
<row r="4"><c r="A4" s="5" t="inlineStr"><is><t>біле тема</t></is></c></row>
<row r="5" outlineLevel="1" hidden="1"><c r="A5" t="inlineStr"><is><t>деталь групи</t></is></c></row>
<row r="6" collapsed="1"><c r="A6" t="inlineStr"><is><t>Разом</t></is></c></row>
</sheetData></worksheet>"#;
    let p = zip(&[
        ("[Content_Types].xml", CT),
        (
            "xl/workbook.xml",
            r#"<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets><sheet name="Кошторис" sheetId="1" r:id="rId1"/></sheets></workbook>"#,
        ),
        (
            "xl/_rels/workbook.xml.rels",
            r#"<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Target="worksheets/sheet1.xml" Type="x"/></Relationships>"#,
        ),
        ("xl/worksheets/sheet1.xml", sheet),
        ("xl/styles.xml", styles),
        ("xl/theme/theme1.xml", THEME),
    ]);
    let m = extract(&p, Some("kosht.xlsx"), &Limits::default()).unwrap();
    let white = kinds(&m, "white_text");
    assert_eq!(white.len(), 1, "{:?}", m.hidden_content);
    assert!(white[0].contains("Петренко") && white[0].contains("+380 67"));
    assert!(white[0].contains("біле тема"), "theme 0 (lt1) is white");
    assert!(
        !white[0].contains("Заголовок"),
        "white on a dark fill is visible"
    );
    let loc = &m
        .hidden_content
        .iter()
        .find(|h| h.kind == "white_text")
        .unwrap()
        .location;
    assert!(loc.starts_with("Кошторис!D2"), "{loc}");
    let fmt = kinds(&m, "invisible_format");
    assert_eq!(fmt.len(), 1);
    assert!(fmt[0].contains("ПАРОЛЬ") && fmt[0].contains("4111111111111111"));
    assert!(!fmt[0].contains("видно"));
    assert_eq!(kinds(&m, "collapsed_rows"), vec!["деталь групи"]);
}

fn docx(body: &str, styles: &str) -> Vec<u8> {
    let doc = format!(
        r#"<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">{body}</w:document>"#
    );
    zip(&[
        ("[Content_Types].xml", CT),
        ("word/document.xml", &doc),
        ("word/styles.xml", styles),
        ("word/theme/theme1.xml", THEME),
    ])
}

#[test]
fn docx_white_tiny_and_visible_controls() {
    let styles = r#"<w:styles xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:style w:type="table" w:styleId="GridTable4"><w:tblStylePr w:type="firstRow"><w:tcPr><w:shd w:val="clear" w:color="auto" w:fill="4472C4"/></w:tcPr></w:tblStylePr></w:style></w:styles>"#;
    let body = r#"<w:body>
<w:p><w:r><w:t>Наказ №12</w:t></w:r></w:p>
<w:p><w:r><w:rPr><w:color w:val="FFFFFF"/><w:sz w:val="4"/></w:rPr><w:t>внутрішня адреса: \\fs01.corp.example\buh\2024</w:t></w:r></w:p>
<w:p><w:r><w:rPr><w:color w:val="FFFFFF" w:themeColor="background1"/></w:rPr><w:t>тема фон</w:t></w:r></w:p>
<w:p><w:r><w:rPr><w:sz w:val="5"/></w:rPr><w:t>дрібний 東京</w:t></w:r></w:p>
<w:p><w:r><w:rPr><w:color w:val="FFFFFF"/><w:highlight w:val="black"/></w:rPr><w:t>білий на чорному</w:t></w:r></w:p>
<w:tbl><w:tr><w:tc><w:tcPr><w:shd w:val="clear" w:fill="002060"/></w:tcPr><w:p><w:r><w:rPr><w:color w:val="FFFFFF"/></w:rPr><w:t>Шапка таблиці</w:t></w:r></w:p></w:tc></w:tr></w:tbl>
<w:tbl><w:tblPr><w:tblStyle w:val="GridTable4"/></w:tblPr><w:tr><w:tc><w:p><w:r><w:rPr><w:color w:val="FFFFFF"/></w:rPr><w:t>Стиль таблиці</w:t></w:r></w:p></w:tc></w:tr></w:tbl>
<w:p><w:pPr><w:shd w:val="clear" w:fill="FFFFFF"/></w:pPr><w:r><w:rPr><w:color w:val="FAFAFA"/></w:rPr><w:t>майже білий</w:t></w:r></w:p>
</w:body>"#;
    let m = extract(&docx(body, styles), Some("nakaz.docx"), &Limits::default()).unwrap();
    let white = kinds(&m, "white_text");
    assert_eq!(white.len(), 3, "{:?}", m.hidden_content);
    assert!(white[0].contains(r"\\fs01.corp.example\buh\2024"));
    assert_eq!(white[1], "тема фон");
    assert_eq!(white[2], "майже білий");
    assert_eq!(kinds(&m, "tiny_text"), vec!["дрібний 東京"]);
    // a dark page background makes white text visible
    let dark = r#"<w:background w:color="000000"/><w:body><w:p><w:r><w:rPr><w:color w:val="FFFFFF"/></w:rPr><w:t>видно</w:t></w:r></w:p></w:body>"#;
    let m = extract(&docx(dark, styles), Some("d.docx"), &Limits::default()).unwrap();
    assert!(m.hidden_content.is_empty(), "{:?}", m.hidden_content);
}

#[test]
fn pptx_shapes_outside_the_slide_and_hidden_shapes() {
    let sp = |id: u32, name: &str, x: i64, y: i64, hidden: &str, text: &str| {
        format!(
            r#"<p:sp><p:nvSpPr><p:cNvPr id="{id}" name="{name}"{hidden}/></p:nvSpPr><p:spPr><a:xfrm><a:off x="{x}" y="{y}"/><a:ext cx="2743200" cy="914400"/></a:xfrm></p:spPr><p:txBody><a:p><a:r><a:t>{text}</a:t></a:r></a:p></p:txBody></p:sp>"#
        )
    };
    let slide = format!(
        r#"<p:sld xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main" xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main"><p:cSld><p:spTree><p:nvGrpSpPr/><p:grpSpPr/>{}{}{}{}</p:spTree></p:cSld></p:sld>"#,
        sp(2, "TextBox 1", 457200, 457200, "", "Звіт за рік"),
        sp(
            3,
            "TextBox 3",
            10058400,
            914400,
            "",
            "Чернетка: скорочення 5 ставок"
        ),
        sp(4, "TextBox 4", -3000000, 100, "", "ліворуч за краєм"),
        sp(
            5,
            "TextBox 5",
            100,
            100,
            r#" hidden="1""#,
            "прихована фігура"
        ),
    );
    let p = zip(&[
        ("[Content_Types].xml", CT),
        (
            "ppt/presentation.xml",
            r#"<p:presentation xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main"><p:sldSz cx="9144000" cy="6858000"/></p:presentation>"#,
        ),
        ("ppt/slides/slide1.xml", &slide),
    ]);
    let m = extract(&p, Some("zvit.pptx"), &Limits::default()).unwrap();
    let off = kinds(&m, "off_slide");
    assert_eq!(
        off,
        vec!["Чернетка: скорочення 5 ставок", "ліворуч за краєм"],
        "{:?}",
        m.hidden_content
    );
    assert_eq!(kinds(&m, "invisible_format"), vec!["прихована фігура"]);
}

const ODF_NS: &str = r#"xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0" xmlns:style="urn:oasis:names:tc:opendocument:xmlns:style:1.0" xmlns:text="urn:oasis:names:tc:opendocument:xmlns:text:1.0" xmlns:table="urn:oasis:names:tc:opendocument:xmlns:table:1.0" xmlns:fo="urn:oasis:names:tc:opendocument:xmlns:xsl-fo-compatible:1.0" xmlns:draw="urn:oasis:names:tc:opendocument:xmlns:drawing:1.0" xmlns:svg="urn:oasis:names:tc:opendocument:xmlns:svg-compatible:1.0""#;

fn odf(mime: &str, styles: &str, body: &str, master: &str) -> Vec<u8> {
    let content = format!(
        r#"<office:document-content {ODF_NS}><office:automatic-styles>{styles}</office:automatic-styles><office:body>{body}</office:body></office:document-content>"#
    );
    let st = format!(r#"<office:document-styles {ODF_NS}>{master}</office:document-styles>"#);
    zip(&[
        ("mimetype", mime),
        ("content.xml", &content),
        ("styles.xml", &st),
    ])
}

#[test]
fn odt_white_tiny_display_none_and_dark_paragraph() {
    let styles = r##"<style:style style:name="T1" style:family="text"><style:text-properties fo:color="#ffffff"/></style:style>
<style:style style:name="T2" style:family="text"><style:text-properties fo:font-size="2pt"/></style:style>
<style:style style:name="T3" style:family="text"><style:text-properties text:display="none"/></style:style>
<style:style style:name="P1" style:family="paragraph"><style:paragraph-properties fo:background-color="#000000"/></style:style>"##;
    let body = r#"<office:text><text:p>Видимий <text:span text:style-name="T1">ІПН 1234567890</text:span></text:p>
<text:p><text:span text:style-name="T2">крихітний</text:span></text:p>
<text:p><text:span text:style-name="T3">приховано стилем</text:span></text:p>
<text:p text:style-name="P1"><text:span text:style-name="T1">білий на чорному</text:span></text:p></office:text>"#;
    let m = extract(
        &odf("application/vnd.oasis.opendocument.text", styles, body, ""),
        Some("a.odt"),
        &Limits::default(),
    )
    .unwrap();
    assert_eq!(
        kinds(&m, "white_text"),
        vec!["ІПН 1234567890"],
        "{:?}",
        m.hidden_content
    );
    assert_eq!(kinds(&m, "tiny_text"), vec!["крихітний"]);
    assert_eq!(kinds(&m, "hidden_text"), vec!["приховано стилем"]);
}

#[test]
fn ods_white_cells_and_odp_off_page() {
    let styles = r##"<style:style style:name="ce1" style:family="table-cell"><style:text-properties fo:color="#ffffff"/></style:style>
<style:style style:name="ce2" style:family="table-cell"><style:table-cell-properties fo:background-color="#203864"/><style:text-properties fo:color="#ffffff"/></style:style>"##;
    let body = r#"<office:spreadsheet><table:table table:name="Лист1"><table:table-row><table:table-cell table:style-name="ce2"><text:p>Шапка</text:p></table:table-cell><table:table-cell table:style-name="ce1"><text:p>тел. 067 000 00 00</text:p></table:table-cell></table:table-row></table:table></office:spreadsheet>"#;
    let m = extract(
        &odf(
            "application/vnd.oasis.opendocument.spreadsheet",
            styles,
            body,
            "",
        ),
        Some("a.ods"),
        &Limits::default(),
    )
    .unwrap();
    let w: Vec<_> = m
        .hidden_content
        .iter()
        .filter(|h| h.kind == "white_text")
        .collect();
    assert_eq!(w.len(), 1, "{:?}", m.hidden_content);
    assert_eq!(w[0].text, "тел. 067 000 00 00");
    assert_eq!(w[0].location, "Лист1!B1");

    let master = r#"<office:automatic-styles><style:page-layout style:name="PM1"><style:page-layout-properties fo:page-width="28cm" fo:page-height="15.75cm"/></style:page-layout></office:automatic-styles>"#;
    let body = r#"<office:presentation><draw:page draw:name="page1"><draw:frame draw:name="Видимий" svg:x="2cm" svg:y="2cm" svg:width="10cm" svg:height="3cm"><draw:text-box><text:p>Заголовок</text:p></draw:text-box></draw:frame><draw:frame draw:name="Поза" svg:x="30cm" svg:y="2cm" svg:width="10cm" svg:height="3cm"><draw:text-box><text:p>за межами слайда</text:p></draw:text-box></draw:frame></draw:page></office:presentation>"#;
    let m = extract(
        &odf(
            "application/vnd.oasis.opendocument.presentation",
            "",
            body,
            master,
        ),
        Some("a.odp"),
        &Limits::default(),
    )
    .unwrap();
    assert_eq!(
        kinds(&m, "off_slide"),
        vec!["за межами слайда"],
        "{:?}",
        m.hidden_content
    );
}

#[test]
fn rtf_white_tiny_hidden_and_shaded_controls() {
    let doc = br"{\rtf1\ansi\ansicpg1251{\fonttbl{\f0\fcharset204 Arial;}}{\colortbl;\red255\green255\blue255;\red0\green0\blue0;\red31\green56\blue100;}
\pard Visible {\cf1 \'cf\'e0\'f0\'ee\'eb\'fc 123}\par
\pard {\fs4 tiny note}\par
\pard {\v rtf hidden}\par
\pard {\cf1\chcbpat2 white on black}\par
\trowd\clcbpat3\cellx5000\pard\intbl {\cf1 Header cell}\cell\row
\pard after}";
    let m = extract(doc, Some("a.rtf"), &Limits::default()).unwrap();
    assert_eq!(
        kinds(&m, "white_text"),
        vec!["Пароль 123"],
        "{:?}",
        m.hidden_content
    );
    assert_eq!(kinds(&m, "tiny_text"), vec!["tiny note"]);
    assert_eq!(kinds(&m, "rtf_hidden"), vec!["rtf hidden"]);
}

#[test]
fn ppt_shape_outside_the_slide() {
    use crate::formats::office::ole::objects::tests::cfb;
    let atom = |ty: u16, inst: u16, body: &[u8]| {
        let mut v = (inst << 4).to_le_bytes().to_vec();
        v.extend_from_slice(&ty.to_le_bytes());
        v.extend_from_slice(&(body.len() as u32).to_le_bytes());
        v.extend_from_slice(body);
        v
    };
    let cont = |ty: u16, kids: &[Vec<u8>]| {
        let b = kids.concat();
        let mut v = 0x000Fu16.to_le_bytes().to_vec();
        v.extend_from_slice(&ty.to_le_bytes());
        v.extend_from_slice(&(b.len() as u32).to_le_bytes());
        v.extend(b);
        v
    };
    let anchor = |t: i16, l: i16, r: i16, b: i16| {
        let mut v = Vec::new();
        for x in [t, l, r, b] {
            v.extend_from_slice(&x.to_le_bytes());
        }
        atom(0xF010, 0, &v)
    };
    let w = |s: &str| -> Vec<u8> { s.encode_utf16().flat_map(u16::to_le_bytes).collect() };
    let shape =
        |a: Vec<u8>, text: &str| cont(0xF004, &[a, cont(0xF00D, &[atom(0x0FA0, 0, &w(text))])]);
    let mut doc_atom = 5760i32.to_le_bytes().to_vec();
    doc_atom.extend_from_slice(&4320i32.to_le_bytes());
    doc_atom.extend_from_slice(&[0; 32]);
    let stream = [
        cont(0x03E8, &[atom(0x03E9, 1, &doc_atom)]),
        cont(
            0x03EE,
            &[cont(
                0x040C,
                &[cont(
                    0xF002,
                    &[cont(
                        0xF003,
                        &[
                            shape(anchor(100, 100, 2000, 600), "на слайді"),
                            shape(anchor(500, 6000, 7000, 900), "поза слайдом"),
                        ],
                    )],
                )],
            )],
        ),
    ]
    .concat();
    let f = cfb(&[("/PowerPoint Document", stream)]);
    let m = extract(&f, Some("a.ppt"), &Limits::default()).unwrap();
    assert_eq!(
        kinds(&m, "off_slide"),
        vec!["поза слайдом"],
        "{:?}",
        m.hidden_content
    );
}
