//! Report integration tests: the custom report logo in every format. HTML embeds it as a
//! `data:` URL (the PDF is printed from that HTML), DOCX carries it as an image part above the
//! title, Markdown leaves it out on purpose.
//!
//! Print the HTML of the logo report for the PDF check in `qa/scenarios/report-logo/pdf.mjs`:
//! `FOCA_REPORT_LOGO_HTML=/path/out.html cargo test -p foca-report --test logo`.

mod common;

use common::*;

/// A real 8×4 RGB PNG (decodable by browsers, so the printed PDF gets an image object).
const PNG_8X4: &str = "iVBORw0KGgoAAAANSUhEUgAAAAgAAAAECAIAAAA8r+mnAAAAJUlEQVR42mNgCDghF3DCJuBEVMCJioAT0wJObAk4cSngBAP1JAAgOzAh+r1X4QAAAABJRU5ErkJggg==";

fn logo_opts(fmt: ReportFormat) -> ReportOptions {
    ReportOptions {
        logo: Logo::from_data(&format!("data:image/png;base64,{PNG_8X4}")),
        ..opts(fmt)
    }
}

#[test]
fn html_embeds_the_logo_as_data_url_on_the_cover() {
    let o = logo_opts(ReportFormat::Html);
    assert!(matches!(o.logo, Logo::Image { .. }));
    let h = text(&build(&fixture().snap, &o));
    let img = format!("<img src=\"data:image/png;base64,{PNG_8X4}\" alt=\"\">");
    let cover = &h[h.find("<header class=\"cover\">").unwrap()..];
    let cover = &cover[..cover.find("</header>").unwrap()];
    assert!(cover.contains(&img), "{cover}");
    // the image replaces the initials, and the CSP allows only data: images
    assert!(!cover.contains("class=\"initials\""));
    assert!(h.contains("img-src data:;"));
    assert_safe_html(&h);
    if let Ok(path) = std::env::var("FOCA_REPORT_LOGO_HTML") {
        std::fs::write(path, &h).unwrap();
    }
}

#[test]
fn data_and_standalone_templates_show_the_logo_in_the_header() {
    let img = format!("data:image/png;base64,{PNG_8X4}");
    for tpl in [
        Template::Data,
        Template::Executive,
        Template::Compliance,
        Template::Lab,
    ] {
        let o = ReportOptions {
            tpl,
            sections: Sections::for_template(tpl),
            ..logo_opts(ReportFormat::Html)
        };
        let h = text(&build(&fixture().snap, &o));
        let head = &h[h
            .find("<header class=\"head-data with-logo\">")
            .expect("logo header")..];
        let head = &head[..head.find("</header>").unwrap()];
        assert!(head.contains(&img), "{tpl:?}: {head}");
    }
    // without a logo the header keeps its plain shape
    let o = ReportOptions {
        tpl: Template::Executive,
        sections: Sections::for_template(Template::Executive),
        ..opts(ReportFormat::Html)
    };
    let h = text(&build(&fixture().snap, &o));
    assert!(h.contains("<header class=\"head-data\"><h1>"));
}

#[test]
fn initials_remain_the_fallback_without_an_image() {
    let o = ReportOptions {
        logo: Logo::Initials,
        ..opts(ReportFormat::Html)
    };
    let h = text(&build(&fixture().snap, &o));
    assert!(h.contains("<div class=\"initials\" aria-hidden=\"true\">КА</div>"));
    assert!(!h.contains("data:image/"));
}

fn zip_names(bytes: &[u8]) -> Vec<String> {
    let mut z = zip::ZipArchive::new(std::io::Cursor::new(bytes)).unwrap();
    (0..z.len())
        .map(|i| z.by_index(i).unwrap().name().unwrap().to_string())
        .collect()
}

fn zip_text(bytes: &[u8], name: &str) -> String {
    let mut z = zip::ZipArchive::new(std::io::Cursor::new(bytes)).unwrap();
    let mut s = String::new();
    z.by_name(name).unwrap().read_to_string(&mut s).unwrap();
    s
}

#[test]
fn docx_carries_the_logo_image_part_above_the_title() {
    for tpl in [Template::Full, Template::Executive] {
        let o = ReportOptions {
            tpl,
            sections: Sections::for_template(tpl),
            ..logo_opts(ReportFormat::Docx)
        };
        let a = build(&fixture().snap, &o);
        assert!(zip_names(&a.bytes).contains(&"word/media/logo.png".to_string()));
        let mut part = Vec::new();
        zip::ZipArchive::new(std::io::Cursor::new(a.bytes.clone()))
            .unwrap()
            .by_name("word/media/logo.png")
            .unwrap()
            .read_to_end(&mut part)
            .unwrap();
        assert_eq!(foca_core::b64::encode(&part), PNG_8X4);
        let rels = zip_text(&a.bytes, "word/_rels/document.xml.rels");
        assert!(rels.contains("Id=\"rIdLogo1\"") && rels.contains("Target=\"media/logo.png\""));
        let x = docx_xml(&a);
        let pic = x.find("r:embed=\"rIdLogo1\"").expect("logo drawing");
        let title = x
            .find("<w:pStyle w:val=\"Heading1\"/>")
            .expect("title heading");
        assert!(pic < title, "the logo stands above the title");
        // 8×4 px fits the 2 cm box by height: 4 cm × 2 cm, unique drawing ids
        assert!(
            x.contains("<wp:extent cx=\"1440000\" cy=\"720000\"/>"),
            "{tpl:?}"
        );
        assert!(x.contains("<wp:docPr id=\"2\" name=\"Logo\"/>"));
    }
    // no logo, no part and no relationship
    let a = build(&fixture().snap, &opts(ReportFormat::Docx));
    assert!(!zip_names(&a.bytes).iter().any(|n| n.contains("logo")));
    assert!(!zip_text(&a.bytes, "word/_rels/document.xml.rels").contains("rIdLogo1"));
}

#[test]
fn markdown_leaves_the_logo_out() {
    let a = build(&fixture().snap, &logo_opts(ReportFormat::Md));
    let md = text(&a);
    assert!(!md.contains("data:image/") && !md.contains(PNG_8X4));
    // the stored options keep only the flag, never the image
    assert_eq!(a.opts["logo"], true);
    assert!(!a.opts.to_string().contains(PNG_8X4));
}
