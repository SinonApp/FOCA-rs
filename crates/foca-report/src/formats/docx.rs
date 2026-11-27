//! Pure-Rust `.docx` (OOXML WordprocessingML) report generator.
//!
//! Produces a self-contained OOXML ZIP package using `quick-xml::Writer` and `zip::ZipWriter`,
//! including a raster severity-distribution bar chart PNG (`word/media/chart_sev.png`) encoded
//! purely in Rust (`flate2` zlib + CRC-32). All dynamic content passes through `Ctx::r` for
//! secret masking and `xml_clean` so no invalid XML 1.0 control characters ever enter the package.
//! A PNG or JPEG report logo goes in as `word/media/logo.{png,jpg}` above the title; a WebP logo
//! is left out because Word versions before 2021 cannot show it.

use std::io::{Cursor, Write as _};

use flate2::write::ZlibEncoder;
use flate2::Compression;
use foca_core::Severity;
use quick_xml::events::{BytesDecl, BytesEnd, BytesStart, BytesText, Event};
use quick_xml::Writer;
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, ZipWriter};

use crate::data::{dmy, SEV_ORDER};
use crate::i18n;
use crate::opts::Template;
use crate::table::DocTable;
use crate::templates::{blocks as template_blocks, Block, Cell};
use crate::Ctx;

/// A4 printable width in twips: 11906 - 2 * 1440 = 9026.
const PAGE_WIDTH_TWIPS: usize = 9026;

const CHART_W: u32 = 640;
const CHART_H: u32 = 180;
/// Display size on A4 page (EMUs): 15.24 cm × 4.29 cm (preserves 640:180 aspect ratio).
const CHART_CX_EMU: &str = "5486400";
const CHART_CY_EMU: &str = "1543050";

/// Logo box on the title (EMUs): at most 2 cm high and 6 cm wide, aspect ratio kept.
const LOGO_MAX_CY_EMU: u64 = 720_000;
const LOGO_MAX_CX_EMU: u64 = 2_160_000;
const LOGO_RID: &str = "rIdLogo1";

/// The report logo as a DOCX image part: bytes, part extension and display size in EMUs.
struct DocxLogo {
    bytes: Vec<u8>,
    ext: &'static str,
    cx: u64,
    cy: u64,
}

fn docx_logo(c: &Ctx) -> Option<DocxLogo> {
    let (bytes, info) = super::logo::image_of(&c.o.logo)?;
    let ext = match info.mime {
        "image/png" => "png",
        "image/jpeg" => "jpg",
        _ => return None,
    };
    let (w, h) = (u64::from(info.width), u64::from(info.height));
    // fit into the box: limited by height unless the logo is very wide
    let (mut cx, mut cy) = (LOGO_MAX_CY_EMU * w / h, LOGO_MAX_CY_EMU);
    if cx > LOGO_MAX_CX_EMU {
        cx = LOGO_MAX_CX_EMU;
        cy = (LOGO_MAX_CX_EMU * h / w).max(1);
    }
    Some(DocxLogo { bytes, ext, cx, cy })
}

pub(crate) fn render(c: &Ctx) -> Vec<u8> {
    let png = render_severity_chart_png(c);
    let logo = docx_logo(c);
    let document_xml = build_document_xml(c, logo.as_ref());
    let content_types = build_content_types_xml(logo.as_ref());
    let root_rels = build_root_rels_xml();
    let doc_rels = build_doc_rels_xml(logo.as_ref());
    let styles_xml = build_styles_xml();
    let core_xml = build_core_xml(c);
    let app_xml = build_app_xml();

    let buf = Cursor::new(Vec::with_capacity(64 * 1024));
    let mut zw = ZipWriter::new(buf);
    let opts = SimpleFileOptions::default()
        .compression_method(CompressionMethod::Deflated)
        .last_modified_time(zip::DateTime::default());

    let logo_name = logo.as_ref().map(|l| format!("word/media/logo.{}", l.ext));
    let mut entries: Vec<(&str, &[u8])> = vec![
        ("[Content_Types].xml", content_types.as_slice()),
        ("_rels/.rels", root_rels.as_slice()),
        ("docProps/core.xml", core_xml.as_slice()),
        ("docProps/app.xml", app_xml.as_slice()),
        ("word/_rels/document.xml.rels", doc_rels.as_slice()),
        ("word/styles.xml", styles_xml.as_slice()),
        ("word/document.xml", document_xml.as_slice()),
        ("word/media/chart_sev.png", png.as_slice()),
    ];
    if let (Some(name), Some(l)) = (logo_name.as_deref(), logo.as_ref()) {
        entries.push((name, l.bytes.as_slice()));
    }
    for (name, data) in entries {
        if zw.start_file(name, opts).is_ok() {
            let _ = zw.write_all(data);
        }
    }
    zw.finish().map(|c| c.into_inner()).unwrap_or_default()
}

/// Strips characters illegal in XML 1.0 (`#x9 | #xA | #xD | [#x20-#xD7FF] | [#xE000-#xFFFD] | [#x10000-#x10FFFF]`).
fn xml_clean(s: &str) -> String {
    s.chars()
        .filter(|&c| {
            matches!(
                c,
                '\t' | '\n' | '\r' | '\u{20}'..='\u{d7ff}' | '\u{e000}'..='\u{fffd}' | '\u{10000}'..='\u{10ffff}'
            )
        })
        .collect()
}

fn doc_tables(c: &Ctx, w: &mut DocWriter, list: &[DocTable]) {
    for d in list {
        w.heading(3, &d.title);
        if let Some(n) = &d.note {
            w.muted_para(n);
        }
        if d.head.is_empty() {
            continue;
        }
        if d.rows.is_empty() {
            w.para(c.t.no_data);
        } else {
            let head: Vec<&str> = d.head.iter().map(String::as_str).collect();
            w.table(&head, &d.rows);
        }
    }
}

/// Chronology as a year × lane table (the text form of the timeline diagram).
fn chronology(c: &Ctx, w: &mut DocWriter) {
    use crate::svg::{flat, timeline};
    let Some(g) = timeline::grid(&c.vis.timeline, c.o.lang) else {
        return;
    };
    let v = i18n::viz(c.o.lang);
    w.heading(2, v.timeline);
    let mut head = vec![v.year];
    head.extend(g.lanes.iter().map(|x| v.lanes[*x as usize]));
    let rows: Vec<Vec<String>> = g
        .rows
        .iter()
        .map(|(y, folded, cells)| {
            let mut r = vec![if *folded {
                format!("≤{y}")
            } else {
                y.to_string()
            }];
            r.extend(cells.iter().map(|cell| {
                if cell.count == 0 {
                    String::new()
                } else {
                    let all: Vec<String> = cell.labels.iter().map(|x| flat(&x.0)).collect();
                    let mut s = all.iter().take(3).cloned().collect::<Vec<_>>().join(", ");
                    if all.len() > 3 {
                        s.push_str(&format!(" (+{})", all.len() - 3));
                    }
                    format!("{} - {}", cell.count, s)
                }
            }));
            r
        })
        .collect();
    w.table(&head, &rows);
}

/// Non-empty lines of a text (CR LF tolerated); at least one (possibly empty) line.
fn lines(s: &str) -> Vec<&str> {
    let v: Vec<&str> = s
        .lines()
        .map(|l| l.trim_end_matches('\r'))
        .filter(|l| !l.trim().is_empty())
        .collect();
    if v.is_empty() {
        vec![""]
    } else {
        v
    }
}

// ---------------------------------------------------------------------------
// XML writer helpers
// ---------------------------------------------------------------------------

struct DocWriter {
    w: Writer<Vec<u8>>,
    /// Level-2 headings written so far: every major section after the first starts on a new
    /// page.
    sections: usize,
}

impl DocWriter {
    fn new() -> Self {
        let mut w = Writer::new(Vec::with_capacity(32 * 1024));
        let _ = w.write_event(Event::Decl(BytesDecl::new(
            "1.0",
            Some("UTF-8"),
            Some("yes"),
        )));
        Self { w, sections: 0 }
    }

    fn finish(self) -> Vec<u8> {
        self.w.into_inner()
    }

    fn start(&mut self, tag: &str, attrs: &[(&str, &str)]) {
        let mut el = BytesStart::new(tag);
        for (k, v) in attrs {
            let clean = xml_clean(v);
            el.push_attribute((*k, clean.as_str()));
        }
        let _ = self.w.write_event(Event::Start(el));
    }

    fn empty(&mut self, tag: &str, attrs: &[(&str, &str)]) {
        let mut el = BytesStart::new(tag);
        for (k, v) in attrs {
            let clean = xml_clean(v);
            el.push_attribute((*k, clean.as_str()));
        }
        let _ = self.w.write_event(Event::Empty(el));
    }

    fn end(&mut self, tag: &str) {
        let _ = self.w.write_event(Event::End(BytesEnd::new(tag)));
    }

    fn text(&mut self, s: &str) {
        let clean = xml_clean(s);
        let _ = self.w.write_event(Event::Text(BytesText::new(&clean)));
    }

    fn heading(&mut self, level: u8, s: &str) {
        let style = match level {
            1 => "Heading1",
            2 => "Heading2",
            _ => "Heading3",
        };
        let page_break = level == 2 && self.sections > 0;
        if level == 2 {
            self.sections += 1;
        }
        self.start("w:p", &[]);
        self.start("w:pPr", &[]);
        self.empty("w:pStyle", &[("w:val", style)]);
        if page_break {
            self.empty("w:pageBreakBefore", &[]);
        }
        self.end("w:pPr");
        self.run(s, false, None);
        self.end("w:p");
    }

    /// One paragraph per line: a `<w:br/>` inside a run is lost by many viewers and text
    /// extractors, which glue the lines together.
    fn para(&mut self, s: &str) {
        for line in lines(s) {
            self.start("w:p", &[]);
            self.run(line, false, None);
            self.end("w:p");
        }
    }

    fn muted_para(&mut self, s: &str) {
        for line in lines(s) {
            self.start("w:p", &[]);
            self.run(line, false, Some("556270"));
            self.end("w:p");
        }
    }

    /// `Label: value`; a multi-line value continues in its own paragraphs.
    fn bold_prefix_para(&mut self, label: &str, val: &str) {
        let mut it = lines(val).into_iter();
        self.start("w:p", &[]);
        self.run(label, true, None);
        self.run(": ", true, None);
        if let Some(first) = it.next() {
            self.run(first, false, None);
        }
        self.end("w:p");
        for line in it {
            self.start("w:p", &[]);
            self.start("w:pPr", &[]);
            self.empty("w:ind", &[("w:left", "360")]);
            self.end("w:pPr");
            self.run(line, false, None);
            self.end("w:p");
        }
    }

    fn bullet(&mut self, s: &str) {
        self.start("w:p", &[]);
        self.start("w:pPr", &[]);
        self.empty("w:ind", &[("w:left", "360")]);
        self.end("w:pPr");
        self.run("• ", true, None);
        self.run(s, false, None);
        self.end("w:p");
    }

    fn run(&mut self, s: &str, bold: bool, color: Option<&str>) {
        self.start("w:r", &[]);
        if bold || color.is_some() {
            self.start("w:rPr", &[]);
            if bold {
                self.empty("w:b", &[]);
            }
            if let Some(col) = color {
                self.empty("w:color", &[("w:val", col)]);
            }
            self.end("w:rPr");
        }
        let lines: Vec<&str> = s.split('\n').collect();
        for (i, part) in lines.iter().enumerate() {
            if i > 0 {
                self.empty("w:br", &[]);
            }
            self.start("w:t", &[("xml:space", "preserve")]);
            self.text(part);
            self.end("w:t");
        }
        self.end("w:r");
    }

    fn table(&mut self, head: &[&str], rows: &[Vec<String>]) {
        self.table_with_fills(head, rows, &[]);
    }

    /// Table whose first cell of row `i` is shaded with `fills[i]` (a legend for a chart).
    fn table_with_fills(&mut self, head: &[&str], rows: &[Vec<String>], fills: &[&str]) {
        if head.is_empty() {
            return;
        }
        let cols = head.len();
        let col_w = (PAGE_WIDTH_TWIPS / cols).max(600);
        let col_w_str = col_w.to_string();

        self.start("w:tbl", &[]);
        self.start("w:tblPr", &[]);
        self.empty("w:tblStyle", &[("w:val", "TableGrid")]);
        self.empty(
            "w:tblW",
            &[("w:w", &PAGE_WIDTH_TWIPS.to_string()), ("w:type", "dxa")],
        );
        self.end("w:tblPr");
        self.start("w:tblGrid", &[]);
        for _ in 0..cols {
            self.empty("w:gridCol", &[("w:w", &col_w_str)]);
        }
        self.end("w:tblGrid");

        // Header row.
        self.start("w:tr", &[]);
        for th in head {
            self.table_cell(th, &col_w_str, true, Some("F1F5F9"));
        }
        self.end("w:tr");

        // Data rows.
        for (r, row) in rows.iter().enumerate() {
            self.start("w:tr", &[]);
            for i in 0..cols {
                let val = row.get(i).map(String::as_str).unwrap_or("");
                let fill = if i == 0 { fills.get(r).copied() } else { None };
                self.table_cell(val, &col_w_str, false, fill);
            }
            self.end("w:tr");
        }
        self.end("w:tbl");
        self.para("");
    }

    fn table_cell(&mut self, text: &str, col_w: &str, bold: bool, fill: Option<&str>) {
        self.start("w:tc", &[]);
        self.start("w:tcPr", &[]);
        self.empty("w:tcW", &[("w:w", col_w), ("w:type", "dxa")]);
        if let Some(bg) = fill {
            self.empty(
                "w:shd",
                &[("w:val", "clear"), ("w:color", "auto"), ("w:fill", bg)],
            );
        }
        self.end("w:tcPr");
        for line in lines(text) {
            self.start("w:p", &[]);
            self.run(line, bold, None);
            self.end("w:p");
        }
        self.end("w:tc");
    }

    fn chart_drawing(&mut self, rid: &str, caption: &str) {
        self.picture(
            rid,
            caption,
            "chart_sev.png",
            "1",
            (CHART_CX_EMU, CHART_CY_EMU),
        );
    }

    /// An inline picture paragraph: `rid` names the image part, `id` must be unique per document.
    fn picture(&mut self, rid: &str, caption: &str, file: &str, id: &str, size: (&str, &str)) {
        let (cx, cy) = size;
        self.start("w:p", &[]);
        self.start("w:r", &[]);
        self.start("w:drawing", &[]);
        self.start(
            "wp:inline",
            &[
                ("distT", "0"),
                ("distB", "0"),
                ("distL", "0"),
                ("distR", "0"),
            ],
        );
        self.empty("wp:extent", &[("cx", cx), ("cy", cy)]);
        self.empty("wp:docPr", &[("id", id), ("name", caption)]);
        self.start("a:graphic", &[]);
        self.start(
            "a:graphicData",
            &[(
                "uri",
                "http://schemas.openxmlformats.org/drawingml/2006/picture",
            )],
        );
        self.start("pic:pic", &[]);
        self.start("pic:nvPicPr", &[]);
        self.empty("pic:cNvPr", &[("id", id), ("name", file)]);
        self.empty("pic:cNvPicPr", &[]);
        self.end("pic:nvPicPr");
        self.start("pic:blipFill", &[]);
        self.empty("a:blip", &[("r:embed", rid)]);
        self.start("a:stretch", &[]);
        self.empty("a:fillRect", &[]);
        self.end("a:stretch");
        self.end("pic:blipFill");
        self.start("pic:spPr", &[]);
        self.start("a:xfrm", &[]);
        self.empty("a:off", &[("x", "0"), ("y", "0")]);
        self.empty("a:ext", &[("cx", cx), ("cy", cy)]);
        self.end("a:xfrm");
        self.start("a:prstGeom", &[("prst", "rect")]);
        self.empty("a:avLst", &[]);
        self.end("a:prstGeom");
        self.end("pic:spPr");
        self.end("pic:pic");
        self.end("a:graphicData");
        self.end("a:graphic");
        self.end("wp:inline");
        self.end("w:drawing");
        self.end("w:r");
        self.end("w:p");
    }
}

// ---------------------------------------------------------------------------
// Document content builders
// ---------------------------------------------------------------------------

fn build_document_xml(c: &Ctx, logo: Option<&DocxLogo>) -> Vec<u8> {
    let mut w = DocWriter::new();
    w.start(
        "w:document",
        &[
            (
                "xmlns:w",
                "http://schemas.openxmlformats.org/wordprocessingml/2006/main",
            ),
            (
                "xmlns:r",
                "http://schemas.openxmlformats.org/officeDocument/2006/relationships",
            ),
            (
                "xmlns:wp",
                "http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing",
            ),
            (
                "xmlns:a",
                "http://schemas.openxmlformats.org/drawingml/2006/main",
            ),
            (
                "xmlns:pic",
                "http://schemas.openxmlformats.org/drawingml/2006/picture",
            ),
        ],
    );
    w.start("w:body", &[]);

    let t = c.t;
    let sc = &c.snap.scope;
    let client = if sc.client.is_empty() {
        c.r(&c.snap.project.client)
    } else {
        c.r(&sc.client)
    };

    // Cover / Title block, with the logo above the title.
    if let Some(l) = logo {
        let (cx, cy) = (l.cx.to_string(), l.cy.to_string());
        let file = format!("logo.{}", l.ext);
        w.picture(LOGO_RID, "Logo", &file, "2", (&cx, &cy));
    }
    w.heading(1, &format!("{} - {}", t.title, c.r(&c.snap.project.name)));
    w.muted_para(&format!(
        "{} · {} · {} ({}){}",
        t.conf,
        c.tpl_label(),
        c.date(),
        c.tz(),
        if c.o.company.is_empty() {
            String::new()
        } else {
            format!(" · {}", c.r(&c.o.company))
        }
    ));
    if !client.is_empty() {
        w.bold_prefix_para(t.client, &client);
    }

    if let Some((banner_title, banner_body)) = i18n::incomplete_banner(c.o.lang, &c.snap.scans) {
        w.bold_prefix_para(&format!("⚠ {banner_title}"), &banner_body);
    }

    if c.o.tpl.is_standalone() {
        render_standalone(c, &mut w);
    } else {
        render_classic(c, &mut w);
    }

    if c.o.custody {
        let l = crate::sections::custody::labels(c.o.lang);
        w.heading(2, l.title);
        w.muted_para(l.subtitle);
        let rows: Vec<Vec<String>> = crate::sections::custody::custody_rows(c)
            .into_iter()
            .map(|(k, v)| vec![k, v])
            .collect();
        w.table(&["Parameter", "Value"], &rows);
        w.muted_para(l.verify_hint);
    }

    // Footer metadata line.
    w.muted_para(&format!(
        "{} {} · {} · {}",
        t.generator,
        crate::GENERATOR,
        c.date(),
        t.conf
    ));

    // Section properties (A4 page).
    w.start("w:sectPr", &[]);
    w.empty("w:pgSz", &[("w:w", "11906"), ("w:h", "16838")]);
    w.empty(
        "w:pgMar",
        &[
            ("w:top", "1440"),
            ("w:right", "1440"),
            ("w:bottom", "1440"),
            ("w:left", "1440"),
        ],
    );
    w.end("w:sectPr");
    w.end("w:body");
    w.end("w:document");
    w.finish()
}

fn render_standalone(c: &Ctx, w: &mut DocWriter) {
    let (kind, blocks) = template_blocks(c);
    w.muted_para(&kind);
    let mut drew_chart = false;
    for blk in blocks {
        match blk {
            Block::H2(s) => w.heading(2, &s),
            Block::P(s) => w.para(&s),
            Block::Lead(s) => w.muted_para(&s),
            Block::Risk {
                score,
                level,
                label,
                ..
            } => {
                w.bold_prefix_para(&label, &format!("{score}/100: {level}"));
                if !drew_chart {
                    w.chart_drawing("rIdChart1", c.t.by_sev);
                    drew_chart = true;
                }
            }
            Block::List(v) => {
                for item in v {
                    w.bullet(&item);
                }
            }
            Block::OList(v) => {
                for (i, item) in v.into_iter().enumerate() {
                    w.para(&format!("{}. {}", i + 1, item));
                }
            }
            Block::Kv(v) => {
                let rows: Vec<Vec<String>> = v
                    .into_iter()
                    .map(|(k, val)| vec![k, if val.is_empty() { "-".into() } else { val }])
                    .collect();
                w.table(&["Field", "Value"], &rows);
            }
            Block::Table { head, rows, .. } => {
                let heads: Vec<&str> = head.iter().map(String::as_str).collect();
                let str_rows: Vec<Vec<String>> = rows
                    .into_iter()
                    .map(|r| {
                        r.into_iter()
                            .map(|cell| match cell {
                                Cell::Text(s) | Cell::Badge(_, s) => s,
                            })
                            .collect()
                    })
                    .collect();
                w.table(&heads, &str_rows);
            }
            Block::Note(title, body) => {
                w.bold_prefix_para(&title, &body);
            }
            Block::Sign(pairs) => {
                let rows: Vec<Vec<String>> = pairs
                    .into_iter()
                    .map(|(k, hint)| vec![k, format!("________________ ({hint})")])
                    .collect();
                w.table(&["Role", "Signature"], &rows);
            }
        }
    }
    if !drew_chart {
        w.chart_drawing("rIdChart1", c.t.by_sev);
    }
}

fn render_classic(c: &Ctx, w: &mut DocWriter) {
    let t = c.t;
    let s = &c.o.sections;
    let snap = c.snap;

    if let Some(a) = c.ai_summary() {
        w.heading(2, crate::i18n::ai_summary_title(c.o.lang));
        w.muted_para(&c.ai_summary_note(a));
        for b in crate::ai_blocks(&a.text) {
            match b {
                crate::AiBlock::Head(t) => w.heading(3, &c.r(&t)),
                crate::AiBlock::Item(t) => w.bullet(&c.r(&t)),
                crate::AiBlock::Para(t) => w.para(&c.r(&t)),
            }
        }
    }

    if s.summary {
        w.heading(2, t.summary);
        let risk = c
            .res
            .risk
            .map(|r| {
                format!(
                    "{r}/100 ({})",
                    i18n::risk_level(c.o.lang, &c.res.risk_level)
                )
            })
            .unwrap_or_else(|| c.t.no_data.to_string());
        w.bold_prefix_para(t.risk, &risk);
        if let Some(n) = c.oos_caveat() {
            w.muted_para(&n);
        }
        w.chart_drawing("rIdChart1", t.by_sev);

        let sev_rows: Vec<Vec<String>> = SEV_ORDER
            .iter()
            .map(|sev| vec![c.sev(*sev).to_string(), c.res.counts.get(*sev).to_string()])
            .collect();
        // The rows double as the chart legend: same order and colors as the bars.
        let fills: Vec<&str> = SEV_ORDER.iter().map(|s| sev_tint(*s)).collect();
        w.table_with_fills(&[t.sev, t.count], &sev_rows, &fills);

        let ov = &c.ov;
        let ov_rows = vec![
            vec![
                t.docs.into(),
                format!("{} / {}", ov.docs_analyzed, ov.docs_total),
            ],
            vec![t.hosts.into(), ov.hosts.to_string()],
            vec![t.pcs.into(), ov.pcs.to_string()],
            vec![t.people.into(), ov.people.to_string()],
            vec![t.emails.into(), ov.emails.to_string()],
            vec![t.software.into(), ov.software.to_string()],
            vec![t.secret.into(), ov.secrets.to_string()],
        ];
        w.table(&[t.kind, t.count], &ov_rows);
        if !ov.host_software.is_empty() {
            w.heading(3, t.host_software);
            let rows: Vec<Vec<String>> = ov
                .host_software
                .iter()
                .map(|(n, k)| vec![c.r(n), k.to_string()])
                .collect();
            w.table(&[t.software, t.n_hosts], &rows);
        }
        if !ov.eol_software.is_empty() {
            w.heading(3, t.eol_software);
            let rows: Vec<Vec<String>> = ov
                .eol_software
                .iter()
                .map(|(n, d, cve)| {
                    vec![
                        c.r(n),
                        crate::data::eol_label(d, c.o.lang),
                        cve.map_or_else(|| "-".into(), |x| x.to_string()),
                    ]
                })
                .collect();
            w.table(&[t.software, t.eol, t.cve], &rows);
        }
    }

    if s.scope {
        w.heading(2, t.scope);
        let sc = &snap.scope;
        if !sc.basis.trim().is_empty() {
            w.bold_prefix_para(t.basis, &c.r(&sc.basis));
        }
        let target_rows: Vec<Vec<String>> = sc
            .targets
            .iter()
            .map(|x| vec![c.r(&x.v), c.r(&x.kind)])
            .collect();
        if !target_rows.is_empty() {
            w.table(&[t.targets, t.kind], &target_rows);
        }
        if !sc.excl.is_empty() {
            w.bold_prefix_para(
                t.excl,
                &sc.excl
                    .iter()
                    .map(|x| c.r(x))
                    .collect::<Vec<_>>()
                    .join(", "),
            );
        }
    }

    if s.findings {
        w.heading(2, t.findings);
        if c.main.is_empty() {
            w.para(t.none);
        } else if c.o.tpl == Template::Full {
            for f in &c.main {
                w.heading(
                    3,
                    &format!("{} · {} ({})", c.fref(f), c.r(&f.title), c.sev(f.sev)),
                );
                w.bold_prefix_para(
                    t.host,
                    &format!("{} · {}: {}", c.r(&f.host), t.status, c.status(f.status)),
                );
                if !f.category.is_empty() {
                    w.bold_prefix_para(t.category, &c.r(&f.category));
                }
                if !f.cve.is_empty() {
                    w.bold_prefix_para(t.cve, &c.r(&f.cve.join(", ")));
                }
                if !f.mitre.is_empty() {
                    w.bold_prefix_para(t.mitre, &c.r(&f.mitre));
                }
                if let Some(u) = f.url.as_deref().filter(|u| !u.is_empty()) {
                    w.bold_prefix_para(t.url, &c.r(u));
                }
                if !f.description.is_empty() {
                    w.bold_prefix_para(t.description, &c.r(&f.description));
                }
                if !f.evidence.is_empty() {
                    w.bold_prefix_para(t.evidence, &c.r(&f.evidence));
                }
                if !f.recommendation.is_empty() {
                    w.bold_prefix_para(t.recommendation, &c.r(&f.recommendation));
                }
                let p = &f.provenance;
                let mut prov = Vec::new();
                if !p.rule.is_empty() {
                    prov.push(format!("{} {}", t.rule, c.r(&p.rule)));
                }
                if !p.docs.is_empty() {
                    let docs: Vec<String> = p.docs.iter().map(|d| c.r(&c.doc_name(*d))).collect();
                    prov.push(format!("{}: {}", t.source_docs, docs.join(", ")));
                }
                if !prov.is_empty() {
                    w.muted_para(&format!("{}: {}", t.provenance, prov.join("; ")));
                }
            }
        } else {
            let rows: Vec<Vec<String>> = c
                .main
                .iter()
                .map(|f| {
                    vec![
                        c.fref(f),
                        c.sev(f.sev).into(),
                        c.r(&f.title),
                        c.r(&f.host),
                        c.r(&f.mitre),
                    ]
                })
                .collect();
            w.table(&["ID", t.sev, t.finding, t.host, t.mitre], &rows);
        }
    }

    if s.fixed && !c.fixed.is_empty() {
        w.heading(2, t.fixed);
        let rows: Vec<Vec<String>> = c
            .fixed
            .iter()
            .map(|f| {
                vec![
                    c.fref(f),
                    c.sev(f.sev).into(),
                    c.r(&f.title),
                    c.r(&f.host),
                    c.r(&f
                        .fixed_scan
                        .as_deref()
                        .map(|s| c.scan_label(s))
                        .unwrap_or_else(|| "-".into())),
                ]
            })
            .collect();
        w.table(&["ID", t.sev, t.finding, t.host, t.fixed_in], &rows);
    }

    if s.people && !snap.people.is_empty() {
        w.heading(2, t.people);
        let rows: Vec<Vec<String>> = snap
            .people
            .iter()
            .map(|p| {
                vec![
                    c.r(&p.login),
                    c.r(&p.name),
                    c.r(&crate::ftext::role(&p.role, c.o.lang)),
                    c.r(&p.emails.join(", ")),
                    p.docs.to_string(),
                ]
            })
            .collect();
        w.table(&[t.login, t.name, t.role, t.emails, t.n_docs], &rows);
    }

    let extra: Vec<DocTable> = if s.infra {
        crate::sections::ports::doc_tables(c)
            .into_iter()
            .chain(crate::sections::infra::doc_tables(c))
            .chain(crate::sections::recon::doc_tables(c))
            .collect()
    } else {
        Vec::new()
    };
    if s.infra && (!snap.hosts.is_empty() || !extra.is_empty()) {
        w.heading(2, t.infra);
        let rows: Vec<Vec<String>> = snap
            .hosts
            .iter()
            .map(|h| {
                vec![
                    c.r(&h.name),
                    c.r(&h.ip),
                    c.yes_no(h.internal).into(),
                    c.r(&h.tech),
                ]
            })
            .collect();
        if !rows.is_empty() {
            w.table(&[t.hosts, t.ip, t.internal, t.tech], &rows);
        }
        doc_tables(c, w, &extra);
    }
    chronology(c, w);

    if s.docs && !snap.docs.is_empty() {
        w.heading(2, t.docs);
        let rows: Vec<Vec<String>> = snap
            .docs
            .iter()
            .filter(|d| !d.deleted)
            .take(150)
            .map(|d| {
                vec![
                    c.r(&d.name),
                    c.r(&d.ext),
                    c.r(d.author.as_deref().unwrap_or("")),
                    c.r(&dmy(d.modified_at.as_deref().unwrap_or(""))),
                ]
            })
            .collect();
        if !rows.is_empty() {
            w.table(&[t.doc_title, t.kind, t.author, t.modified], &rows);
        }
    }

    if s.log && !c.log.is_empty() {
        w.heading(2, t.log);
        const LOG_ROWS: usize = 100;
        if c.log.len() > LOG_ROWS {
            w.muted_para(
                &t.log_shown
                    .replace("{n}", &LOG_ROWS.to_string())
                    .replace("{m}", &c.log.len().to_string()),
            );
        }
        let rows: Vec<Vec<String>> = c
            .log
            .iter()
            .take(LOG_ROWS)
            .map(|r| {
                vec![
                    c.ts(&r.time),
                    c.r(&r.module),
                    c.r(&r.method),
                    c.r(&r.host),
                    r.status.map_or_else(|| "-".into(), |s| s.to_string()),
                ]
            })
            .collect();
        w.table(&[t.time, t.module, t.method, t.host, t.code], &rows);
    }

    if s.appx {
        w.heading(2, t.appx);
        w.para(t.method_text);
        if let Some(i18n::IncompleteTable { title, head, rows }) =
            i18n::incomplete_sources(c.o.lang, &snap.scans)
        {
            w.heading(3, title);
            let rows: Vec<Vec<String>> = rows.into_iter().map(Vec::from).collect();
            w.table(&head, &rows);
        }
        let secrets: Vec<_> = snap.secrets.iter().filter(|s| s.kind != "host").collect();
        if !secrets.is_empty() {
            let rows: Vec<Vec<String>> = secrets
                .iter()
                .map(|sec| {
                    vec![
                        c.r(&sec.kind),
                        c.r(&c.doc_name(sec.doc)),
                        c.r(&sec.location),
                        c.sev(sec.sev).into(),
                        c.red.mask(sec.value.expose()),
                    ]
                })
                .collect();
            w.table(&[t.kind, t.file, t.path, t.sev, t.secret], &rows);
        }
        let param_rows = vec![
            vec![t.only_confirmed.into(), c.yes_no(c.o.confirmed).into()],
            vec![
                t.min_sev.into(),
                c.o.min_sev.map(|s| c.sev(s)).unwrap_or(t.all).into(),
            ],
            vec![t.picked_only.into(), c.yes_no(c.o.picked_only).into()],
            vec![t.secrets_mode.into(), c.secret_mode().into()],
        ];
        w.table(&[t.report_params, t.status], &param_rows);
    }
}

// ---------------------------------------------------------------------------
// Static / small OOXML metadata XML parts
// ---------------------------------------------------------------------------

fn build_content_types_xml(logo: Option<&DocxLogo>) -> Vec<u8> {
    let mut w = DocWriter::new();
    w.start(
        "Types",
        &[(
            "xmlns",
            "http://schemas.openxmlformats.org/package/2006/content-types",
        )],
    );
    w.empty(
        "Default",
        &[
            ("Extension", "rels"),
            (
                "ContentType",
                "application/vnd.openxmlformats-package.relationships+xml",
            ),
        ],
    );
    w.empty(
        "Default",
        &[("Extension", "xml"), ("ContentType", "application/xml")],
    );
    w.empty(
        "Default",
        &[("Extension", "png"), ("ContentType", "image/png")],
    );
    if logo.is_some_and(|l| l.ext == "jpg") {
        w.empty(
            "Default",
            &[("Extension", "jpg"), ("ContentType", "image/jpeg")],
        );
    }
    w.empty(
        "Override",
        &[
            ("PartName", "/word/document.xml"),
            (
                "ContentType",
                "application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml",
            ),
        ],
    );
    w.empty(
        "Override",
        &[
            ("PartName", "/word/styles.xml"),
            (
                "ContentType",
                "application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml",
            ),
        ],
    );
    w.empty(
        "Override",
        &[
            ("PartName", "/docProps/core.xml"),
            (
                "ContentType",
                "application/vnd.openxmlformats-package.core-properties+xml",
            ),
        ],
    );
    w.empty(
        "Override",
        &[
            ("PartName", "/docProps/app.xml"),
            (
                "ContentType",
                "application/vnd.openxmlformats-officedocument.extended-properties+xml",
            ),
        ],
    );
    w.end("Types");
    w.finish()
}

fn build_root_rels_xml() -> Vec<u8> {
    let mut w = DocWriter::new();
    w.start(
        "Relationships",
        &[(
            "xmlns",
            "http://schemas.openxmlformats.org/package/2006/relationships",
        )],
    );
    w.empty(
        "Relationship",
        &[
            ("Id", "rId1"),
            (
                "Type",
                "http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument",
            ),
            ("Target", "word/document.xml"),
        ],
    );
    w.empty(
        "Relationship",
        &[
            ("Id", "rId2"),
            (
                "Type",
                "http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties",
            ),
            ("Target", "docProps/core.xml"),
        ],
    );
    w.empty(
        "Relationship",
        &[
            ("Id", "rId3"),
            (
                "Type",
                "http://schemas.openxmlformats.org/officeDocument/2006/relationships/extended-properties",
            ),
            ("Target", "docProps/app.xml"),
        ],
    );
    w.end("Relationships");
    w.finish()
}

fn build_doc_rels_xml(logo: Option<&DocxLogo>) -> Vec<u8> {
    let mut w = DocWriter::new();
    w.start(
        "Relationships",
        &[(
            "xmlns",
            "http://schemas.openxmlformats.org/package/2006/relationships",
        )],
    );
    w.empty(
        "Relationship",
        &[
            ("Id", "rId1"),
            (
                "Type",
                "http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles",
            ),
            ("Target", "styles.xml"),
        ],
    );
    w.empty(
        "Relationship",
        &[
            ("Id", "rIdChart1"),
            (
                "Type",
                "http://schemas.openxmlformats.org/officeDocument/2006/relationships/image",
            ),
            ("Target", "media/chart_sev.png"),
        ],
    );
    if let Some(l) = logo {
        let target = format!("media/logo.{}", l.ext);
        w.empty(
            "Relationship",
            &[
                ("Id", LOGO_RID),
                (
                    "Type",
                    "http://schemas.openxmlformats.org/officeDocument/2006/relationships/image",
                ),
                ("Target", &target),
            ],
        );
    }
    w.end("Relationships");
    w.finish()
}

fn build_core_xml(c: &Ctx) -> Vec<u8> {
    let mut w = DocWriter::new();
    w.start(
        "cp:coreProperties",
        &[
            (
                "xmlns:cp",
                "http://schemas.openxmlformats.org/package/2006/metadata/core-properties",
            ),
            ("xmlns:dc", "http://purl.org/dc/elements/1.1/"),
            ("xmlns:dcterms", "http://purl.org/dc/terms/"),
            ("xmlns:xsi", "http://www.w3.org/2001/XMLSchema-instance"),
        ],
    );
    w.start("dc:title", &[]);
    w.text(&format!("{} - {}", c.t.title, c.r(&c.snap.project.name)));
    w.end("dc:title");
    w.start("dc:creator", &[]);
    w.text(if c.o.company.is_empty() {
        crate::GENERATOR
    } else {
        &c.o.company
    });
    w.end("dc:creator");
    w.start("cp:lastModifiedBy", &[]);
    w.text(crate::GENERATOR);
    w.end("cp:lastModifiedBy");
    w.start("dcterms:created", &[("xsi:type", "dcterms:W3CDTF")]);
    w.text(&c.iso_time());
    w.end("dcterms:created");
    w.end("cp:coreProperties");
    w.finish()
}

fn build_app_xml() -> Vec<u8> {
    let mut w = DocWriter::new();
    w.start(
        "Properties",
        &[(
            "xmlns",
            "http://schemas.openxmlformats.org/officeDocument/2006/extended-properties",
        )],
    );
    w.start("Application", &[]);
    w.text(crate::GENERATOR);
    w.end("Application");
    w.end("Properties");
    w.finish()
}

fn build_styles_xml() -> Vec<u8> {
    let mut w = DocWriter::new();
    w.start(
        "w:styles",
        &[(
            "xmlns:w",
            "http://schemas.openxmlformats.org/wordprocessingml/2006/main",
        )],
    );
    let mut style = |id: &str, typ: &str, name: &str, sz_half_pt: &str, bold: bool, col: &str| {
        w.start("w:style", &[("w:type", typ), ("w:styleId", id)]);
        w.empty("w:name", &[("w:val", name)]);
        w.start("w:rPr", &[]);
        w.empty(
            "w:rFonts",
            &[
                ("w:ascii", "Calibri"),
                ("w:hAnsi", "Calibri"),
                ("w:cs", "DejaVu Sans"),
            ],
        );
        if bold {
            w.empty("w:b", &[]);
        }
        w.empty("w:color", &[("w:val", col)]);
        w.empty("w:sz", &[("w:val", sz_half_pt)]);
        w.end("w:rPr");
        w.end("w:style");
    };
    style("Normal", "paragraph", "Normal", "21", false, "1E293B");
    style("Heading1", "paragraph", "heading 1", "36", true, "0F172A");
    style("Heading2", "paragraph", "heading 2", "28", true, "1E3A8A");
    style("Heading3", "paragraph", "heading 3", "23", true, "334155");

    // Clean bordered table grid style.
    w.start(
        "w:style",
        &[("w:type", "table"), ("w:styleId", "TableGrid")],
    );
    w.empty("w:name", &[("w:val", "Table Grid")]);
    w.start("w:tblPr", &[]);
    w.start("w:tblBorders", &[]);
    for side in ["top", "left", "bottom", "right", "insideH", "insideV"] {
        w.empty(
            &format!("w:{side}"),
            &[
                ("w:val", "single"),
                ("w:sz", "4"),
                ("w:space", "0"),
                ("w:color", "CBD5E1"),
            ],
        );
    }
    w.end("w:tblBorders");
    w.end("w:tblPr");
    w.end("w:style");

    w.end("w:styles");
    w.finish()
}

// ---------------------------------------------------------------------------
// Pure-Rust PNG chart renderer (RGB horizontal bar chart)
// ---------------------------------------------------------------------------

fn sev_rgb(s: Severity) -> [u8; 3] {
    match s {
        Severity::Critical => [185, 28, 28],
        Severity::High => [234, 88, 12],
        Severity::Medium => [217, 119, 6],
        Severity::Low => [37, 99, 235],
        Severity::Info => [100, 116, 139],
    }
}

/// Light tint of the bar color for the legend cells of the severity table.
fn sev_tint(s: Severity) -> &'static str {
    match s {
        Severity::Critical => "FECACA",
        Severity::High => "FED7AA",
        Severity::Medium => "FDE68A",
        Severity::Low => "BFDBFE",
        Severity::Info => "E2E8F0",
    }
}

/// 3×5 bitmap digits (rows top to bottom, 3 bits each), drawn at `DIGIT_SCALE`.
const DIGITS: [[u8; 5]; 10] = [
    [0b111, 0b101, 0b101, 0b101, 0b111],
    [0b010, 0b110, 0b010, 0b010, 0b111],
    [0b111, 0b001, 0b111, 0b100, 0b111],
    [0b111, 0b001, 0b111, 0b001, 0b111],
    [0b101, 0b101, 0b111, 0b001, 0b001],
    [0b111, 0b100, 0b111, 0b001, 0b111],
    [0b111, 0b100, 0b111, 0b101, 0b111],
    [0b111, 0b001, 0b010, 0b010, 0b010],
    [0b111, 0b101, 0b111, 0b101, 0b111],
    [0b111, 0b101, 0b111, 0b001, 0b111],
];
const DIGIT_SCALE: usize = 3;
const DIGIT_ADV: usize = 4 * DIGIT_SCALE;

/// Draws a decimal number into an RGB buffer of width `w` (the bar chart's value labels).
fn draw_number(buf: &mut [u8], w: usize, x0: usize, y0: usize, n: usize, col: [u8; 3]) {
    let h = buf.len() / 3 / w;
    for (k, ch) in n.to_string().bytes().enumerate() {
        let glyph = DIGITS[(ch - b'0') as usize];
        for (row, bits) in glyph.iter().enumerate() {
            for bit in 0..3 {
                if bits & (0b100 >> bit) == 0 {
                    continue;
                }
                for dy in 0..DIGIT_SCALE {
                    for dx in 0..DIGIT_SCALE {
                        let x = x0 + k * DIGIT_ADV + bit * DIGIT_SCALE + dx;
                        let y = y0 + row * DIGIT_SCALE + dy;
                        if x < w && y < h {
                            let i = (y * w + x) * 3;
                            buf[i..i + 3].copy_from_slice(&col);
                        }
                    }
                }
            }
        }
    }
}

fn render_severity_chart_png(c: &Ctx) -> Vec<u8> {
    let w = CHART_W as usize;
    let h = CHART_H as usize;
    let mut rgb = vec![255u8; w * h * 3];

    let paint_rect = |buf: &mut [u8], x0: usize, y0: usize, rw: usize, rh: usize, col: [u8; 3]| {
        let x1 = (x0 + rw).min(w);
        let y1 = (y0 + rh).min(h);
        for y in y0..y1 {
            for x in x0..x1 {
                let idx = (y * w + x) * 3;
                buf[idx] = col[0];
                buf[idx + 1] = col[1];
                buf[idx + 2] = col[2];
            }
        }
    };

    // Subtle card border.
    paint_rect(&mut rgb, 0, 0, w, 1, [226, 232, 240]);
    paint_rect(&mut rgb, 0, h - 1, w, 1, [226, 232, 240]);
    paint_rect(&mut rgb, 0, 0, 1, h, [226, 232, 240]);
    paint_rect(&mut rgb, w - 1, 0, 1, h, [226, 232, 240]);

    let palette: [(Severity, [u8; 3]); 5] = SEV_ORDER.map(|s| (s, sev_rgb(s)));
    let max_v = palette
        .iter()
        .map(|(s, _)| c.res.counts.get(*s))
        .max()
        .unwrap_or(1)
        .max(1);

    let track_x = 32usize;
    let track_w = w - 64;
    // Room for the count at the right end of each track.
    let num_w = 4 * DIGIT_ADV + 8;
    let bar_max = track_w - num_w;
    for (idx, (sev, col)) in palette.iter().enumerate() {
        let y = 18 + idx * 30;
        // Color swatch on left.
        paint_rect(&mut rgb, 12, y + 3, 12, 16, *col);
        // Track background.
        paint_rect(&mut rgb, track_x, y, track_w, 22, [241, 245, 249]);
        // Filled bar.
        let cnt = c.res.counts.get(*sev) as usize;
        if cnt > 0 {
            let bw = ((cnt * bar_max) / max_v as usize).max(6).min(bar_max);
            paint_rect(&mut rgb, track_x, y, bw, 22, *col);
        }
        draw_number(
            &mut rgb,
            w,
            track_x + track_w - num_w + 6,
            y + 4,
            cnt,
            [30, 41, 59],
        );
    }

    encode_rgb_png(CHART_W, CHART_H, &rgb)
}

fn encode_rgb_png(width: u32, height: u32, rgb: &[u8]) -> Vec<u8> {
    let mut raw = Vec::with_capacity((width as usize * 3 + 1) * height as usize);
    let stride = width as usize * 3;
    for row in rgb.chunks_exact(stride) {
        raw.push(0); // filter type 0 (None)
        raw.extend_from_slice(row);
    }
    let mut enc = ZlibEncoder::new(Vec::new(), Compression::default());
    let _ = enc.write_all(&raw);
    let idat = enc.finish().unwrap_or_default();

    let mut png = Vec::with_capacity(idat.len() + 64);
    png.extend_from_slice(b"\x89PNG\r\n\x1a\n");

    let mut ihdr = [0u8; 13];
    ihdr[0..4].copy_from_slice(&width.to_be_bytes());
    ihdr[4..8].copy_from_slice(&height.to_be_bytes());
    ihdr[8] = 8; // bit depth
    ihdr[9] = 2; // RGB color type
    write_png_chunk(&mut png, b"IHDR", &ihdr);
    write_png_chunk(&mut png, b"IDAT", &idat);
    write_png_chunk(&mut png, b"IEND", &[]);
    png
}

fn write_png_chunk(out: &mut Vec<u8>, tag: &[u8; 4], data: &[u8]) {
    out.extend_from_slice(&(data.len() as u32).to_be_bytes());
    out.extend_from_slice(tag);
    out.extend_from_slice(data);
    let mut crc = 0xFFFF_FFFFu32;
    for &b in tag.iter().chain(data.iter()) {
        crc ^= u32::from(b);
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0xEDB8_8320
            } else {
                crc >> 1
            };
        }
    }
    out.extend_from_slice(&(!crc).to_be_bytes());
}

#[cfg(test)]
mod chart_tests {
    use super::*;

    #[test]
    fn digits_are_drawn_where_requested() {
        let (w, h) = (40usize, 20usize);
        let mut buf = vec![255u8; w * h * 3];
        draw_number(&mut buf, w, 2, 2, 18, [0, 0, 0]);
        let dark = buf.chunks(3).filter(|p| p[0] == 0).count();
        // "1" has 8 set bits, "8" has 13; each bit is a 3×3 block.
        assert_eq!(dark, (8 + 13) * DIGIT_SCALE * DIGIT_SCALE);
        // Nothing is drawn outside the buffer for large numbers.
        draw_number(&mut buf, w, 30, 15, 9999, [0, 0, 0]);
    }
}
