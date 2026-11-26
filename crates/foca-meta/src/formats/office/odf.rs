//! ODF (odt/ods/odp/odg) and StarOffice 1.x (sxw, ...): meta.xml, tracked changes and
//! annotations from content.xml, external links, encryption and embedded images.

use foca_core::{CommentRef, DocFormat, Embedded, Metadata, PersonRole, RevisionKind, RevisionRef};

use crate::formats::office::ooxml::read_xml;
use crate::util::{normalize_date, parse_iso_duration, truncate};
use crate::xml::Element;
use crate::zipx::SafeZip;
use crate::{Ctx, MetaError};

fn meta_xml(meta: &mut Metadata, root: &Element) {
    let Some(m) = root
        .descendants("meta")
        .into_iter()
        .find(|e| e.name == "office:meta")
    else {
        return;
    };
    let mut keywords = Vec::new();
    for c in m.elements() {
        let name = c.name.as_str();
        if name == "meta:document-statistic" {
            for (k, v) in &c.attrs {
                let key = crate::xml::local(k)
                    .trim_end_matches("-count")
                    .replace('-', "_");
                let key = match key.as_str() {
                    "page" => "pages".to_string(),
                    "word" => "words".to_string(),
                    "character" => "characters".to_string(),
                    "paragraph" => "paragraphs".to_string(),
                    "table" => "tables".to_string(),
                    "image" => "images".to_string(),
                    "object" => "objects".to_string(),
                    "cell" => "cells".to_string(),
                    other => other.to_string(),
                };
                if let Ok(n) = v.parse::<u64>() {
                    meta.stats.insert(key, n);
                }
            }
            continue;
        }
        if name == "meta:user-defined" {
            if let Some(n) = c.attr("meta:name") {
                meta.custom
                    .insert(n.to_string(), truncate(c.text().trim(), 2048));
            }
            continue;
        }
        if name == "meta:template" {
            if let Some(h) = c.attr("xlink:href") {
                meta.template = Some(h.to_string());
            }
            if let Some(t) = c.attr("xlink:title") {
                meta.fields
                    .insert("odf:template_title".into(), t.to_string());
            }
            continue;
        }
        let Some(v) = c.text_opt() else { continue };
        match name {
            "meta:generator" => {
                Metadata::add_unique(&mut meta.software, &v);
                meta.application = Some(v);
            }
            "dc:title" => meta.title = Some(v),
            "dc:description" => meta.description = Some(v),
            "dc:subject" => meta.subject = Some(v),
            "meta:keyword" => keywords.push(v),
            "meta:initial-creator" => {
                meta.add_person(&v, PersonRole::Author, "meta.xml:meta:initial-creator");
                meta.author = Some(v);
            }
            "dc:creator" => {
                meta.add_person(&v, PersonRole::LastModifiedBy, "meta.xml:dc:creator");
                meta.last_modified_by = Some(v);
            }
            "meta:creation-date" => meta.created = normalize_date(&v),
            "dc:date" => meta.modified = normalize_date(&v),
            "meta:print-date" => meta.printed = normalize_date(&v),
            "meta:printed-by" => {
                meta.add_person(&v, PersonRole::PrintedBy, "meta.xml:meta:printed-by")
            }
            "dc:language" => meta.language = Some(v),
            "meta:editing-cycles" => meta.revision = Some(v),
            "meta:editing-duration" => meta.edit_time_secs = parse_iso_duration(&v),
            other => {
                meta.fields
                    .insert(format!("odf:{other}"), truncate(&v, 1024));
            }
        }
    }
    if !keywords.is_empty() {
        meta.keywords = Some(keywords.join(", "));
    }
}

fn content_xml(meta: &mut Metadata, root: &Element, source: &str) {
    for e in root.walk() {
        match e.name.as_str() {
            "text:changed-region" => {
                let kind_el = e.elements().next();
                let kind = match kind_el.map(|k| k.local()) {
                    Some("insertion") => RevisionKind::Insert,
                    Some("deletion") => RevisionKind::Delete,
                    Some("format-change") => RevisionKind::Format,
                    _ => RevisionKind::Other,
                };
                let info = kind_el.and_then(|k| k.child("change-info"));
                let author = info
                    .and_then(|i| i.child("creator"))
                    .and_then(|c| c.text_opt());
                let date = info
                    .and_then(|i| i.child("date"))
                    .and_then(|c| c.text_opt())
                    .and_then(|d| normalize_date(&d));
                let mut text = String::new();
                if kind == RevisionKind::Delete {
                    if let Some(k) = kind_el {
                        for p in k.elements().filter(|x| x.local() != "change-info") {
                            text.push_str(&p.text());
                        }
                    }
                }
                if let Some(a) = &author {
                    meta.add_person(a, PersonRole::Revision, source);
                }
                if meta.revisions.len() < 2000 {
                    meta.revisions.push(RevisionRef {
                        kind,
                        author,
                        date,
                        text: truncate(&text, 512),
                    });
                }
            }
            "office:annotation" => {
                let author = e.child("creator").and_then(|c| c.text_opt());
                let date = e
                    .child("date")
                    .and_then(|c| c.text_opt())
                    .and_then(|d| normalize_date(&d));
                let mut text = String::new();
                for p in e.elements().filter(|x| x.name.starts_with("text:")) {
                    text.push_str(&p.text());
                    text.push('\n');
                }
                if let Some(a) = &author {
                    meta.add_person(a, PersonRole::Comment, source);
                }
                if meta.comments.len() < 2000 {
                    meta.comments.push(CommentRef {
                        author,
                        initials: None,
                        date,
                        text: truncate(text.trim(), 2048),
                        source: source.into(),
                    });
                }
            }
            _ => {
                if let Some(h) = e.attr("xlink:href") {
                    let internal = h.starts_with('#')
                        || h.starts_with("Pictures/")
                        || h.starts_with("./")
                        || h.starts_with("Object");
                    if !internal && !h.is_empty() {
                        Metadata::add_unique(&mut meta.links, h);
                    }
                }
            }
        }
    }
}

pub fn extract(bytes: &[u8], format: DocFormat, ctx: &Ctx) -> Result<Metadata, MetaError> {
    let mut z = SafeZip::open(bytes, ctx.max_entries())?;
    let names: Vec<String> = z.names().to_vec();
    let mut meta = Metadata::new(format);
    if let Some(e) = read_xml(&mut z, "meta.xml", ctx, &mut meta)? {
        meta_xml(&mut meta, &e);
    }
    if let Some(e) = read_xml(&mut z, "META-INF/manifest.xml", ctx, &mut meta)? {
        if !e.descendants("encryption-data").is_empty() {
            meta.encrypted = true;
        }
    }
    if !meta.encrypted {
        for part in ["content.xml", "styles.xml"] {
            if let Some(e) = read_xml(&mut z, part, ctx, &mut meta)? {
                content_xml(&mut meta, &e, part);
            }
        }
    }
    for n in names
        .iter()
        .filter(|n| n.starts_with("Pictures/") && !n.ends_with('/'))
    {
        if meta.embedded.len() >= 200 || !ctx.can_descend() {
            break;
        }
        let Some(b) = z.read(n, ctx)? else { continue };
        let short = n.rsplit('/').next().unwrap_or(n);
        match ctx.extract_child(&b, short) {
            Some(Ok(m)) => meta.embedded.push(Embedded {
                name: n.clone(),
                metadata: Box::new(m),
            }),
            Some(Err(e @ MetaError::ZipBomb(_))) => return Err(e),
            Some(Err(e)) => meta.warnings.push(format!("{n}: {e}")),
            None => {}
        }
    }
    Ok(meta)
}

pub fn text(bytes: &[u8], ctx: &Ctx) -> Result<String, MetaError> {
    let mut z = SafeZip::open(bytes, ctx.max_entries())?;
    let mut dummy = Metadata::default();
    let mut out = String::new();
    if let Some(e) = read_xml(&mut z, "content.xml", ctx, &mut dummy)? {
        let mut s = String::new();
        collect_all(&e, &mut s, 0);
        out.push_str(&s);
    }
    Ok(out)
}

fn collect_all(e: &Element, out: &mut String, depth: usize) {
    if depth > 512 {
        return;
    }
    for n in &e.children {
        match n {
            crate::xml::Node::Text(t) => out.push_str(t),
            crate::xml::Node::El(c) => {
                if c.local() == "tab" {
                    out.push('\t');
                } else if c.local() == "s" {
                    out.push(' ');
                } else if c.local() == "line-break" {
                    out.push('\n');
                } else {
                    collect_all(c, out, depth + 1);
                }
                if matches!(c.local(), "p" | "h") {
                    out.push('\n');
                }
            }
            crate::xml::Node::Comment(_) => {}
        }
    }
}
