//! ODF (odt/ods/odp/odg) and StarOffice 1.x (sxw, ...): meta.xml, tracked changes and
//! annotations from content.xml, external links, encryption and embedded images.

use foca_core::{
    Attachment, CommentRef, DocFormat, Embedded, HiddenContent, Metadata, PersonRole, RevisionKind,
    RevisionRef,
};

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
                if part == "content.xml" {
                    hidden(&mut meta, &e);
                }
            }
        }
        if let Some(e) = read_xml(&mut z, "settings.xml", ctx, &mut meta)? {
            printer(&mut meta, &e);
        }
    }
    objects(&mut z, &names, ctx, &mut meta)?;
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

/// Printer from settings.xml: `PrinterName` and the base64 `PrinterSetup` (a LibreOffice
/// JobSetup: 4-byte header, then printer, device, port and driver names of 64/32/32/32
/// bytes; layout ported from the ODF settings written by vcl, not copied).
fn printer(meta: &mut Metadata, root: &Element) {
    for item in root.descendants("config-item") {
        match item.attr_local("name") {
            Some("PrinterName") => {
                if let Some(p) = item.text_opt() {
                    Metadata::add_unique(&mut meta.printers, &truncate(&p, 256));
                }
            }
            Some("PrinterSetup") => {
                let raw: String = item.text().split_whitespace().collect();
                let Some(b) = foca_core::b64::decode(&raw) else {
                    continue;
                };
                let field = |off: usize, len: usize| {
                    b.get(off..off + len)
                        .map(|r| r.split(|c| *c == 0).next().unwrap_or(r))
                        .map(|r| String::from_utf8_lossy(r).trim().to_string())
                        .filter(|s| !s.is_empty())
                };
                if let Some(p) = field(4, 64) {
                    Metadata::add_unique(&mut meta.printers, &p);
                }
                for (k, off, len) in [("device", 68, 32), ("port", 100, 32), ("driver", 132, 32)] {
                    if let Some(v) = field(off, len) {
                        meta.fields.insert(format!("odf:printer_{k}"), v);
                    }
                }
            }
            _ => {}
        }
    }
}

/// Hidden sheets, rows, columns, slides, sections and paragraphs of content.xml.
fn hidden(meta: &mut Metadata, root: &Element) {
    // automatic styles that hide a table or a drawing page
    let mut hidden_styles: Vec<&str> = Vec::new();
    for st in root.descendants("style") {
        let hides = st.elements().any(|p| {
            p.attr("table:display") == Some("false")
                || p.attr("presentation:visibility") == Some("hidden")
        });
        if let (true, Some(n)) = (hides, st.attr("style:name")) {
            hidden_styles.push(n);
        }
    }
    let push = |meta: &mut Metadata, kind: &str, loc: String, text: String| {
        if meta.hidden_content.len() < 500 {
            meta.hidden_content.push(HiddenContent {
                kind: kind.into(),
                location: truncate(&loc, 256),
                text: truncate(
                    text.split_whitespace().collect::<Vec<_>>().join(" ").trim(),
                    512,
                ),
            });
        }
    };
    for t in root.descendants("table") {
        let name = t.attr("table:name").unwrap_or("").to_string();
        if t.attr("table:style-name")
            .is_some_and(|s| hidden_styles.contains(&s))
        {
            Metadata::add_unique(&mut meta.hidden_sheets, &name);
        }
        let mut row = 0usize;
        for r in t.descendants("table-row") {
            row += r
                .attr("table:number-rows-repeated")
                .and_then(|n| n.parse::<usize>().ok())
                .unwrap_or(1)
                .min(1_048_576);
            if matches!(r.attr("table:visibility"), Some("collapse" | "filter")) {
                let mut text = String::new();
                collect_all(r, &mut text, 0);
                if !text.trim().is_empty() {
                    push(meta, "row", format!("{name}!{row}"), text);
                }
            }
        }
        let cols = t
            .descendants("table-column")
            .into_iter()
            .filter(|c| c.attr("table:visibility") == Some("collapse"))
            .count();
        if cols > 0 {
            push(
                meta,
                "column",
                format!("{name}!{cols} hidden"),
                String::new(),
            );
        }
    }
    for p in root.descendants("page") {
        if p.attr("draw:style-name")
            .is_some_and(|s| hidden_styles.contains(&s))
        {
            let mut text = String::new();
            collect_all(p, &mut text, 0);
            let name = p.attr("draw:name").unwrap_or("").to_string();
            push(meta, "slide", name, text);
        }
    }
    for e in root.walk() {
        let hide = match e.name.as_str() {
            "text:section" => e.attr("text:display") == Some("none"),
            "text:hidden-paragraph" | "text:hidden-text" => true,
            _ => false,
        };
        if hide {
            let mut text = e.attr("text:string-value").unwrap_or("").to_string();
            collect_all(e, &mut text, 0);
            push(meta, "hidden_text", e.name.clone(), text);
        }
    }
}

/// Thumbnail and embedded objects: `Thumbnails/thumbnail.png`, `Object N/` sub-documents
/// (charts, formulas) and binary `Object N` OLE objects parsed recursively.
fn objects(
    z: &mut SafeZip,
    names: &[String],
    ctx: &Ctx,
    meta: &mut Metadata,
) -> Result<(), MetaError> {
    let mut dirs: Vec<String> = Vec::new();
    for n in names {
        if n == "Thumbnails/thumbnail.png" {
            meta.fields.insert("office:thumbnail".into(), n.clone());
            let before = meta.embedded.len() + meta.attachments.len();
            if let Some(b) = z.read(n, ctx)? {
                ctx.attach_child(meta, &b, "thumbnail.png", n)?;
            }
            if meta.embedded.len() + meta.attachments.len() == before
                && meta.attachments.len() < 500
            {
                meta.attachments.push(Attachment {
                    name: n.clone(),
                    size: z.size(n),
                    mime: Some("image/png".into()),
                });
            }
            continue;
        }
        let Some(rest) = n.strip_prefix("Object ") else {
            continue;
        };
        match rest.split_once('/') {
            Some((num, _)) => {
                let d = format!("Object {num}");
                if !dirs.contains(&d) && dirs.len() < 500 {
                    dirs.push(d);
                }
            }
            None => {
                // binary OLE object
                let before = meta.embedded.len() + meta.attachments.len();
                if let Some(b) = z.read(n, ctx)? {
                    ctx.attach_child(meta, &b, n, n)?;
                }
                if meta.embedded.len() + meta.attachments.len() == before
                    && meta.attachments.len() < 500
                {
                    meta.attachments.push(Attachment {
                        name: n.clone(),
                        size: z.size(n),
                        mime: None,
                    });
                }
            }
        }
    }
    for d in dirs {
        if meta.attachments.len() < 500 {
            meta.attachments.push(Attachment {
                name: d,
                size: None,
                mime: Some("application/vnd.oasis.opendocument".into()),
            });
        }
    }
    Ok(())
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
