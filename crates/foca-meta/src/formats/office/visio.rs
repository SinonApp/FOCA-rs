//! Microsoft Visio: `.vsdx`/`.vsdm` (OPC package, core/app/custom properties, links, printers,
//! macros and media through the OOXML parser, plus page and master names, comments and data
//! connections) and `.vsd` (OLE2 property sets plus the `VisioDocument` header version).

use std::io::{Cursor, Read};

use foca_core::{CommentRef, DocFormat, Metadata, PersonRole};

use crate::util::{clean_str, normalize_date, truncate};
use crate::xml::{self, Element};
use crate::zipx::SafeZip;
use crate::{Ctx, MetaError};

const MAX_NAMES: usize = 200;
const MAX_COMMENTS: usize = 2000;

fn read_xml(
    z: &mut SafeZip,
    name: &str,
    ctx: &Ctx,
    meta: &mut Metadata,
) -> Result<Option<Element>, MetaError> {
    let Some(b) = z.read(name, ctx)? else {
        return Ok(None);
    };
    match xml::parse_bytes(&b, ctx.max_xml_depth(), ctx.max_xml_nodes()) {
        Ok(e) => Ok(Some(e)),
        Err(e @ (MetaError::TooDeep(_) | MetaError::TooManyEntries(_))) => Err(e),
        Err(e) => {
            meta.warnings.push(format!("{name}: {e}"));
            Ok(None)
        }
    }
}

fn names_of(e: &Element, tag: &str) -> Vec<String> {
    e.descendants(tag)
        .into_iter()
        .filter_map(|p| {
            p.attr("Name")
                .or_else(|| p.attr("NameU"))
                .and_then(clean_str)
        })
        .take(MAX_NAMES)
        .map(|n| truncate(&n, 256))
        .collect()
}

pub fn extract_vsdx(bytes: &[u8], ctx: &Ctx) -> Result<Metadata, MetaError> {
    let mut meta = crate::formats::office::ooxml::extract(bytes, DocFormat::Vsdx, ctx)?;
    let mut z = SafeZip::open(bytes, ctx.max_entries())?;
    if let Some(e) = read_xml(&mut z, "visio/pages/pages.xml", ctx, &mut meta)? {
        let pages = names_of(&e, "Page");
        meta.stats
            .insert("pages".into(), e.descendants("Page").len() as u64);
        if !pages.is_empty() {
            meta.fields
                .insert("visio:pages".into(), truncate(&pages.join("; "), 2048));
        }
    }
    if let Some(e) = read_xml(&mut z, "visio/masters/masters.xml", ctx, &mut meta)? {
        let masters = names_of(&e, "Master");
        if !masters.is_empty() {
            meta.stats.insert("masters".into(), masters.len() as u64);
            meta.fields
                .insert("visio:masters".into(), truncate(&masters.join("; "), 2048));
        }
    }
    if let Some(e) = read_xml(&mut z, "visio/comments.xml", ctx, &mut meta)? {
        let authors: Vec<(String, Option<String>, Option<String>)> = e
            .descendants("AuthorEntry")
            .into_iter()
            .map(|a| {
                (
                    a.attr("ID").unwrap_or("").to_string(),
                    a.attr("Name").and_then(clean_str),
                    a.attr("Initials").and_then(clean_str),
                )
            })
            .collect();
        for c in e.descendants("CommentEntry").into_iter().take(MAX_COMMENTS) {
            let id = c.attr("AuthorID").unwrap_or("");
            let who = authors.iter().find(|a| a.0 == id);
            let author = who.and_then(|a| a.1.clone());
            if let Some(a) = &author {
                meta.add_person(a, PersonRole::Comment, "visio/comments.xml");
            }
            meta.comments.push(CommentRef {
                author,
                initials: who.and_then(|a| a.2.clone()),
                date: c.attr("Date").and_then(normalize_date),
                text: truncate(c.text().trim(), 2048),
                source: "visio/comments.xml".into(),
            });
        }
    }
    if let Some(e) = read_xml(&mut z, "visio/data/connections.xml", ctx, &mut meta)? {
        for (i, c) in e
            .descendants("DataConnection")
            .into_iter()
            .take(64)
            .enumerate()
        {
            for (attr, key) in [
                ("ConnectionString", "connection"),
                ("FileName", "file"),
                ("Command", "command"),
            ] {
                if let Some(v) = c.attr(attr).and_then(clean_str) {
                    meta.fields
                        .insert(format!("visio:data.{:02}.{key}", i + 1), truncate(&v, 1024));
                    if attr == "ConnectionString" {
                        for part in v.split(';') {
                            if let Some((k, val)) = part.split_once('=') {
                                let k = k.trim().to_ascii_lowercase();
                                if matches!(
                                    k.as_str(),
                                    "data source" | "server" | "address" | "addr"
                                ) {
                                    meta.add_server(val.trim(), "visio:connection");
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    Ok(meta)
}

/// Returns the shape text of all pages.
pub fn text_vsdx(bytes: &[u8], ctx: &Ctx) -> Result<String, MetaError> {
    let mut z = SafeZip::open(bytes, ctx.max_entries())?;
    let mut names: Vec<String> = z
        .names()
        .iter()
        .filter(|n| n.starts_with("visio/pages/page") && n.ends_with(".xml"))
        .cloned()
        .collect();
    names.sort();
    let mut out = String::new();
    let mut sink = Metadata::default();
    for n in names {
        if let Some(e) = read_xml(&mut z, &n, ctx, &mut sink)? {
            for t in e.descendants("Text") {
                out.push_str(t.text().trim());
                out.push('\n');
            }
        }
    }
    Ok(out)
}

pub fn extract_vsd(bytes: &[u8], ctx: &Ctx) -> Result<Metadata, MetaError> {
    let mut meta = crate::formats::office::ole::extract(bytes, DocFormat::Vsd, ctx)?;
    let head = crate::guard("vsd", || {
        let mut cf = cfb::CompoundFile::open(Cursor::new(bytes))
            .map_err(|e| MetaError::malformed("vsd", e))?;
        let Ok(mut s) = cf.open_stream("/VisioDocument") else {
            return Ok(None);
        };
        let mut buf = Vec::new();
        let _ = (&mut s).take(64).read_to_end(&mut buf);
        Ok(Some(buf))
    })?;
    if let Some(h) = head {
        if h.starts_with(b"Visio (TM) Drawing") {
            if let Some(v) = h.get(0x1A) {
                meta.fields
                    .insert("visio:file_version".into(), v.to_string());
            }
        } else {
            meta.warnings
                .push("VSD: unexpected VisioDocument header".into());
        }
    }
    Ok(meta)
}
