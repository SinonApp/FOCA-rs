//! EPUB e-book container (`.epub`).
//!
//! Parses `META-INF/container.xml` to locate the Open Packaging Format (`.opf`) rootfile,
//! extracts Dublin Core metadata (`dc:title`, `dc:creator`, `dc:contributor`, `dc:publisher`,
//! `dc:description`, `dc:subject`, `dc:language`, `dc:date`, `dc:identifier`), generator software
//! (`<meta name="generator">` / `dcterms:modified`), and recursively inspects embedded cover/page
//! images via [`crate::Ctx::attach_child`] under the shared [`Ctx`] budget.

use foca_core::{DocFormat, Metadata, PersonRole};

use crate::util::{clean_str, truncate};
use crate::xml;
use crate::zipx::SafeZip;
use crate::{Ctx, MetaError};

pub fn extract(bytes: &[u8], ctx: &Ctx) -> Result<Metadata, MetaError> {
    let mut z = SafeZip::open(bytes, ctx.max_entries())?;
    let mut meta = Metadata::new(DocFormat::Epub);
    let names: Vec<String> = z.names().to_vec();

    // 1. Locate the OPF package document from META-INF/container.xml or by `.opf` suffix.
    let mut opf_path = None;
    if let Ok(Some(cont)) = z.read("META-INF/container.xml", ctx) {
        opf_path = parse_container_xml(&cont, ctx);
    }
    if opf_path.is_none() {
        opf_path = names
            .iter()
            .find(|n| n.to_ascii_lowercase().ends_with(".opf"))
            .cloned();
    }

    if let Some(opf) = opf_path {
        match z.read(&opf, ctx) {
            Ok(Some(opf_bytes)) => parse_opf(&opf_bytes, ctx, &mut meta)?,
            Ok(None) => {}
            Err(
                e @ (MetaError::ZipBomb(_)
                | MetaError::TooManyEntries(_)
                | MetaError::TooDeep(_)
                | MetaError::TooLarge { .. }),
            ) => return Err(e),
            Err(_) => {}
        }
    }

    // 2. Recursively inspect embedded images (cover art, figures) for EXIF/GPS under budget.
    for name in &names {
        let low = name.to_ascii_lowercase();
        if low.ends_with(".jpg")
            || low.ends_with(".jpeg")
            || low.ends_with(".png")
            || low.ends_with(".tiff")
        {
            match z.read(name, ctx) {
                Ok(Some(img)) => ctx.attach_child(&mut meta, &img, name, name)?,
                Ok(None) => {}
                Err(
                    e @ (MetaError::ZipBomb(_)
                    | MetaError::TooManyEntries(_)
                    | MetaError::TooDeep(_)
                    | MetaError::TooLarge { .. }),
                ) => return Err(e),
                Err(_) => {}
            }
        }
    }

    Ok(meta)
}

fn parse_container_xml(xml_bytes: &[u8], ctx: &Ctx) -> Option<String> {
    let doc = xml::parse_bytes(xml_bytes, ctx.max_xml_depth(), ctx.max_xml_nodes()).ok()?;
    for el in doc.descendants("rootfile") {
        if let Some(p) = el.attr_local("full-path") {
            if !p.trim().is_empty() {
                return Some(p.trim().to_string());
            }
        }
    }
    None
}

fn parse_opf(xml_bytes: &[u8], ctx: &Ctx, meta: &mut Metadata) -> Result<(), MetaError> {
    let doc = xml::parse_bytes(xml_bytes, ctx.max_xml_depth(), ctx.max_xml_nodes())?;
    for el in doc.walk() {
        let ln = el.local();
        if ln == "meta" {
            if let (Some(name), Some(content)) = (el.attr_local("name"), el.attr_local("content")) {
                apply_meta_pair(meta, name, content);
            }
            if let (Some(prop), Some(txt)) = (el.attr_local("property"), el.text_opt()) {
                apply_meta_pair(meta, prop, &txt);
            }
            continue;
        }
        let Some(raw) = el.text_opt() else {
            continue;
        };
        let val = truncate(&raw, 2048);
        match ln {
            "title" if meta.title.is_none() => meta.title = Some(val),
            "creator" => {
                if meta.author.is_none() {
                    meta.author = Some(val.clone());
                }
                meta.add_person(&val, PersonRole::Author, "opf:dc:creator");
            }
            "contributor" => {
                meta.add_person(&val, PersonRole::Other, "opf:dc:contributor");
            }
            "publisher" if meta.company.is_none() => {
                meta.company = Some(val);
            }
            "description" if meta.description.is_none() => {
                meta.description = Some(val);
            }
            "subject" => {
                if meta.subject.is_none() {
                    meta.subject = Some(val.clone());
                }
                match &mut meta.keywords {
                    Some(k) if !k.contains(&val) => {
                        k.push_str(", ");
                        k.push_str(&val);
                    }
                    None => meta.keywords = Some(val),
                    _ => {}
                }
            }
            "language" if meta.language.is_none() => {
                meta.language = Some(val);
            }
            "date" if meta.created.is_none() => {
                meta.created = Some(val);
            }
            "identifier" => {
                meta.fields.entry("epub:identifier".into()).or_insert(val);
            }
            _ => {}
        }
    }
    Ok(())
}

fn apply_meta_pair(meta: &mut Metadata, key: &str, val: &str) {
    let Some(v) = clean_str(val) else {
        return;
    };
    let v = truncate(&v, 1024);
    let k_low = key.trim().to_ascii_lowercase();
    match k_low.as_str() {
        "generator" | "calibre:timestamp" | "sigil version" | "ibooks:version" => {
            if k_low == "generator" || k_low == "sigil version" {
                if meta.application.is_none() {
                    meta.application = Some(v.clone());
                }
                Metadata::add_unique(&mut meta.software, &v);
            }
            meta.fields.insert(format!("epub:{k_low}"), v);
        }
        "dcterms:modified" if meta.modified.is_none() => {
            meta.modified = Some(v);
        }
        _ => {
            meta.fields.insert(format!("epub:{k_low}"), v);
        }
    }
}
