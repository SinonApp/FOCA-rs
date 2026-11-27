//! SVG: RDF metadata, Inkscape/Sodipodi attributes (docname, docbase, export-filename), the
//! generator from comments (Illustrator), other comments, absolute paths and external links in
//! attributes, and `data:image/...;base64` images parsed recursively (EXIF/GPS of pasted photos).

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
        meta.fields
            .insert("svg:inkscape_version".into(), truncate(v, 128));
    }
    let mut notes: Vec<String> = Vec::new();
    for c in root.comments() {
        // other comments may carry contacts or paths; keep a few for the path/e-mail scan
        if !c.contains("Generator:") && !c.contains("Created with") && notes.len() < 20 {
            if let Some(t) = crate::util::clean_str(c) {
                notes.push(truncate(&t, 1024));
            }
        }
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
    if !notes.is_empty() {
        meta.fields
            .insert("svg:comments".into(), truncate(&notes.join("\n"), 4096));
    }
    // absolute paths, external links and embedded data: images in attributes
    let mut images = 0;
    for e in root.walk() {
        for (k, v) in &e.attrs {
            if k.starts_with("xmlns") {
                continue;
            }
            let v = v.trim();
            if xml::local(k) == "href" && v.starts_with("data:image/") {
                if let Some((_, data)) = v.split_once(";base64,") {
                    if images < 50 && data.len() <= 16 << 20 {
                        images += 1;
                        let img = crate::formats::mail::eml::base64_decode(data.as_bytes());
                        ctx.spend(img.len() as u64)?;
                        ctx.attach_child(
                            &mut meta,
                            &img,
                            "image",
                            &format!("svg:data-image-{images}"),
                        )?;
                    }
                }
                continue;
            }
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

#[cfg(test)]
mod tests {
    #[test]
    fn data_uri_image_and_comments() {
        let mut png = b"\x89PNG\r\n\x1a\n".to_vec();
        let text = b"Author\0Mykola Shevchenko";
        png.extend((text.len() as u32).to_be_bytes());
        png.extend(b"tEXt");
        png.extend(text);
        png.extend([0; 4]);
        png.extend(b"\0\0\0\0IEND\0\0\0\0");
        let b64 = foca_core::b64::encode(&png);
        let svg = format!(
            r#"<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink"><!-- contact: art@studio.example --><image xlink:href="data:image/png;base64,{b64}"/></svg>"#
        );
        let m = crate::extract(svg.as_bytes(), Some("a.svg"), &crate::Limits::default()).unwrap();
        assert_eq!(m.embedded.len(), 1);
        assert_eq!(
            m.embedded[0].metadata.author.as_deref(),
            Some("Mykola Shevchenko")
        );
        assert!(
            m.emails.iter().any(|e| e == "art@studio.example"),
            "{:?}",
            m.emails
        );
    }
}
