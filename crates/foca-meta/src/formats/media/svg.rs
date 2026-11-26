//! SVG: RDF metadata, Inkscape/Sodipodi attributes (docname, docbase, export-filename), the
//! generator from comments (Illustrator), and absolute paths and external links in attributes.

use foca_core::{DocFormat, Metadata};

use crate::paths::analyze_path;
use crate::util::truncate;
use crate::xml;
use crate::{xmp, Ctx, MetaError};

pub fn extract(b: &[u8], ctx: &Ctx) -> Result<Metadata, MetaError> {
    let root = xml::parse_bytes(b, ctx.max_xml_depth(), ctx.max_xml_nodes())?;
    let mut meta = Metadata::new(DocFormat::Svg);
    if let Some(v) = root.attr("inkscape:version") {
        let sw = format!("Inkscape {}", v.split_whitespace().next().unwrap_or(v));
        Metadata::add_unique(&mut meta.software, &sw);
        meta.application = Some(sw);
    }
    for c in root.comments() {
        if let Some(g) = c.trim().strip_prefix("Generator:") {
            let g = g.split(',').next().unwrap_or(g).trim();
            Metadata::add_unique(&mut meta.software, g);
            meta.application.get_or_insert(g.to_string());
        } else if c.contains("Created with") {
            let g = c
                .trim()
                .trim_start_matches("Created with")
                .trim()
                .trim_end_matches(')')
                .trim_start_matches('(');
            Metadata::add_unique(&mut meta.software, g.trim());
        }
    }
    for (k, label) in [
        ("sodipodi:docname", "svg:docname"),
        ("sodipodi:docbase", "svg:docbase"),
        ("inkscape:export-filename", "svg:export-filename"),
    ] {
        for e in root.walk() {
            if let Some(v) = e.attr(k) {
                meta.fields
                    .entry(label.to_string())
                    .or_insert_with(|| truncate(v, 1024));
            }
        }
    }
    let mut map = std::collections::BTreeMap::new();
    for m in root.descendants("metadata") {
        xmp::parse_element(m, &mut map);
    }
    xmp::apply(&mut meta, &map, "svg:metadata");
    if meta.title.is_none() {
        meta.title = root.child("title").and_then(|t| t.text_opt());
    }
    if meta.description.is_none() {
        meta.description = root.child("desc").and_then(|t| t.text_opt());
    }
    // absolute paths and external links in attributes
    for e in root.walk() {
        for (k, v) in &e.attrs {
            if k.starts_with("xmlns") {
                continue;
            }
            let v = v.trim();
            if analyze_path(v).is_some() {
                meta.fields
                    .entry(format!("svg:path:{k}"))
                    .or_insert_with(|| truncate(v, 1024));
            } else if (xml::local(k) == "href")
                && (v.starts_with("http://") || v.starts_with("https://"))
            {
                Metadata::add_unique(&mut meta.links, v);
            }
        }
    }
    Ok(meta)
}

pub fn text(b: &[u8], ctx: &Ctx) -> Result<String, MetaError> {
    let root = xml::parse_bytes(b, ctx.max_xml_depth(), ctx.max_xml_nodes())?;
    Ok(root.text())
}
