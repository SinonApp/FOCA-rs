//! OOXML (docx/xlsx/pptx): core/app/custom properties, comments and their authors, tracked
//! changes, RSIDs, external links from `_rels`, template, printers, hidden sheets, macros and
//! embedded media; hidden text (`w:vanish`), hidden rows/columns, pivot cache and chart
//! authorship, data connections and digital signatures (XML-DSig, VBA project).

use std::io::Cursor;

use std::collections::HashMap;

use foca_core::{
    Attachment, CommentRef, DocFormat, Embedded, HiddenContent, Metadata, PersonRole, RevisionKind,
    RevisionRef,
};

use super::{ooxml_data, vba};
use crate::util::{clean_str, normalize_date, truncate, utf16le_z};
use crate::xml::{self, Element};
use crate::zipx::SafeZip;
use crate::{Ctx, MetaError};

const MAX_REVISIONS: usize = 2000;
const MAX_COMMENTS: usize = 2000;
const MAX_EMBEDDED: usize = 200;
const MAX_HIDDEN: usize = 500;

pub(crate) fn read_xml(
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

/// Collects subtree text: content of `text_tags` elements, with a line break after each of `para_tags`.
pub(crate) fn collect_text(
    e: &Element,
    text_tags: &[&str],
    para_tags: &[&str],
    out: &mut String,
    depth: usize,
) {
    if depth > 512 {
        return;
    }
    let l = e.local();
    if text_tags.contains(&l) {
        out.push_str(&e.text());
    } else if l == "tab" {
        out.push('\t');
    } else if l == "br" || l == "cr" {
        out.push('\n');
    } else {
        for c in e.elements() {
            collect_text(c, text_tags, para_tags, out, depth + 1);
        }
    }
    if para_tags.contains(&l) {
        out.push('\n');
    }
}

fn sorted_matching(names: &[String], pred: impl Fn(&str) -> bool) -> Vec<String> {
    let mut v: Vec<String> = names.iter().filter(|n| pred(n)).cloned().collect();
    v.sort_by_key(|a| natural_key(a));
    v
}

/// Returns a natural sort key, so that slide2 sorts before slide10.
fn natural_key(s: &str) -> (String, u64) {
    let digits: String = s
        .chars()
        .rev()
        .skip_while(|c| !c.is_ascii_digit())
        .take_while(|c| c.is_ascii_digit())
        .collect();
    let n: u64 = digits
        .chars()
        .rev()
        .collect::<String>()
        .parse()
        .unwrap_or(0);
    let prefix: String = s.chars().filter(|c| !c.is_ascii_digit()).collect();
    (prefix, n)
}

fn core_props(meta: &mut Metadata, el: &Element) {
    for c in el.elements() {
        let Some(v) = c.text_opt() else { continue };
        match c.local() {
            "title" => meta.title = Some(v),
            "subject" => meta.subject = Some(v),
            "creator" => {
                meta.add_person(&v, PersonRole::Author, "core.xml:dc:creator");
                meta.author = Some(v);
            }
            "keywords" => meta.keywords = Some(v),
            "description" => meta.description = Some(v),
            "lastModifiedBy" => {
                meta.add_person(&v, PersonRole::LastModifiedBy, "core.xml:cp:lastModifiedBy");
                meta.last_modified_by = Some(v);
            }
            "revision" => meta.revision = Some(v),
            "created" => meta.created = normalize_date(&v),
            "modified" => meta.modified = normalize_date(&v),
            "lastPrinted" => meta.printed = normalize_date(&v),
            "category" => meta.category = Some(v),
            "language" => meta.language = Some(v),
            other => {
                meta.fields
                    .insert(format!("core:{other}"), truncate(&v, 1024));
            }
        }
    }
}

fn snake(s: &str) -> String {
    let mut out = String::new();
    for (i, c) in s.char_indices() {
        if c.is_ascii_uppercase() {
            if i > 0 && !s[..i].ends_with(|p: char| p.is_ascii_uppercase()) {
                out.push('_');
            }
            out.push(c.to_ascii_lowercase());
        } else {
            out.push(c);
        }
    }
    out
}

fn app_props(meta: &mut Metadata, el: &Element) {
    let mut app_version = None;
    for c in el.elements() {
        let l = c.local();
        if matches!(l, "HeadingPairs") {
            continue;
        }
        if l == "TitlesOfParts" {
            let parts: Vec<String> = c
                .descendants("lpstr")
                .iter()
                .filter_map(|e| e.text_opt())
                .collect();
            if !parts.is_empty() {
                meta.fields.insert(
                    "app:TitlesOfParts".into(),
                    truncate(&parts.join("; "), 2048),
                );
            }
            continue;
        }
        let Some(v) = c.text_opt() else { continue };
        match l {
            "Application" => meta.application = Some(v),
            "AppVersion" => app_version = Some(v.clone()),
            "Company" => meta.company = Some(v),
            "Manager" => meta.manager = Some(v),
            "Template" => meta.template = Some(v),
            "TotalTime" => {
                meta.edit_time_secs = v.parse::<u64>().ok().map(|m| m.saturating_mul(60))
            }
            "Pages"
            | "Words"
            | "Characters"
            | "CharactersWithSpaces"
            | "Lines"
            | "Paragraphs"
            | "Slides"
            | "Notes"
            | "HiddenSlides"
            | "MMClips" => {
                if let Ok(n) = v.parse::<u64>() {
                    meta.stats.insert(snake(l), n);
                }
            }
            _ => {
                meta.fields.insert(format!("app:{l}"), truncate(&v, 1024));
            }
        }
    }
    if let Some(v) = &app_version {
        meta.fields.insert("app:AppVersion".into(), v.clone());
    }
    if let Some(a) = meta.application.clone() {
        let sw = match &app_version {
            Some(v) => format!("{a} {v}"),
            None => a,
        };
        Metadata::add_unique(&mut meta.software, &sw);
    }
    if let Some(v) = &app_version {
        super::office_info::apply_app_version(meta, v);
    }
}

fn custom_props(meta: &mut Metadata, el: &Element) {
    for p in el.elements().filter(|e| e.local() == "property") {
        if let Some(name) = p.attr("name") {
            meta.custom
                .insert(name.to_string(), truncate(p.text().trim(), 2048));
        }
    }
}

fn push_comment(meta: &mut Metadata, c: CommentRef) {
    if let Some(a) = &c.author {
        meta.add_person(a, PersonRole::Comment, &c.source);
    }
    if meta.comments.len() < MAX_COMMENTS {
        meta.comments.push(c);
    }
}

fn word_comments(meta: &mut Metadata, el: &Element, source: &str) {
    for c in el.descendants("comment") {
        let mut text = String::new();
        collect_text(c, &["t"], &["p"], &mut text, 0);
        push_comment(
            meta,
            CommentRef {
                author: c.attr_local("author").and_then(clean_str),
                initials: c.attr_local("initials").and_then(clean_str),
                date: c.attr_local("date").and_then(normalize_date),
                text: truncate(text.trim(), 2048),
                source: source.to_string(),
            },
        );
    }
}

fn revisions(meta: &mut Metadata, el: &Element) {
    for e in el.walk() {
        if !e.name.starts_with("w:") {
            continue;
        }
        let kind = match e.local() {
            "ins" | "moveTo" => RevisionKind::Insert,
            "del" | "moveFrom" => RevisionKind::Delete,
            "rPrChange" | "pPrChange" | "sectPrChange" | "tblPrChange" | "trPrChange"
            | "tcPrChange" => RevisionKind::Format,
            _ => continue,
        };
        // w:ins/w:del inside w:rPr mark the paragraph mark itself; the author is the same
        let author = e.attr_local("author").and_then(clean_str);
        if author.is_none() && e.attr_local("date").is_none() {
            continue;
        }
        let mut text = String::new();
        if kind != RevisionKind::Format {
            collect_text(e, &["t", "delText"], &[], &mut text, 0);
        }
        if let Some(a) = &author {
            meta.add_person(a, PersonRole::Revision, "revisions");
        }
        if meta.revisions.len() < MAX_REVISIONS {
            meta.revisions.push(RevisionRef {
                kind,
                author,
                date: e.attr_local("date").and_then(normalize_date),
                text: truncate(&text, 512),
            });
        }
    }
}

fn rels(meta: &mut Metadata, el: &Element) {
    for r in el.elements().filter(|e| e.local() == "Relationship") {
        let target = r.attr("Target").unwrap_or("").trim();
        let ty = r.attr("Type").unwrap_or("");
        let external = r
            .attr("TargetMode")
            .is_some_and(|m| m.eq_ignore_ascii_case("External"));
        if target.is_empty() {
            continue;
        }
        if ty.ends_with("/attachedTemplate") {
            meta.template = Some(target.to_string());
        }
        if external {
            Metadata::add_unique(&mut meta.links, target);
        }
    }
}

fn vba_modules(bin: &[u8]) -> Vec<String> {
    crate::guard("vba", || {
        let cf = cfb::CompoundFile::open(Cursor::new(bin))
            .map_err(|e| MetaError::malformed("vba", e))?;
        let mut mods = Vec::new();
        for e in cf.walk() {
            if !e.is_stream() {
                continue;
            }
            let parent_is_vba = e
                .path()
                .parent()
                .and_then(|p| p.file_name())
                .is_some_and(|n| n.eq_ignore_ascii_case("VBA"));
            let n = e.name();
            if parent_is_vba
                && !n.eq_ignore_ascii_case("dir")
                && !n.starts_with("_VBA_PROJECT")
                && !n.starts_with("__SRP_")
            {
                mods.push(n.to_string());
            }
            if mods.len() > 500 {
                break;
            }
        }
        Ok(mods)
    })
    .unwrap_or_default()
}

pub fn extract(bytes: &[u8], format: DocFormat, ctx: &Ctx) -> Result<Metadata, MetaError> {
    let mut z = SafeZip::open(bytes, ctx.max_entries())?;
    let names: Vec<String> = z.names().to_vec();
    let mut meta = Metadata::new(format);

    if let Some(e) = read_xml(&mut z, "docProps/core.xml", ctx, &mut meta)? {
        core_props(&mut meta, &e);
    }
    if let Some(e) = read_xml(&mut z, "docProps/app.xml", ctx, &mut meta)? {
        app_props(&mut meta, &e);
    }
    if let Some(e) = read_xml(&mut z, "docProps/custom.xml", ctx, &mut meta)? {
        custom_props(&mut meta, &e);
    }

    // _rels: external links and the template
    for n in names.iter().filter(|n| n.ends_with(".rels")) {
        if let Some(e) = read_xml(&mut z, n, ctx, &mut meta)? {
            rels(&mut meta, &e);
        }
    }

    match format {
        DocFormat::Docx => docx(&mut z, &names, ctx, &mut meta)?,
        DocFormat::Xlsx => xlsx(&mut z, &names, ctx, &mut meta)?,
        DocFormat::Pptx => pptx(&mut z, &names, ctx, &mut meta)?,
        _ => {}
    }

    // printers (DEVMODEW: dmDeviceName is the leading 32 WCHARs)
    for n in names
        .iter()
        .filter(|n| n.contains("printerSettings") && n.ends_with(".bin"))
    {
        if let Some(b) = z.read_prefix(n, 64, ctx)? {
            if let Some(p) = clean_str(&utf16le_z(&b)) {
                Metadata::add_unique(&mut meta.printers, &p);
            }
        }
    }

    // macros
    for n in names
        .iter()
        .filter(|n| n.to_ascii_lowercase().ends_with("vbaproject.bin"))
    {
        meta.has_macros = true;
        if let Some(b) = z.read(n, ctx)? {
            for m in vba_modules(&b) {
                Metadata::add_unique(&mut meta.macro_modules, &m);
            }
            vba::scan_ole(&b, &mut meta);
        }
    }

    signatures(&mut z, &names, ctx, &mut meta)?;
    charts(&mut z, &names, ctx, &mut meta)?;

    // document thumbnail (may show an older state of the document)
    if let Some(t) = names.iter().find(|n| n.starts_with("docProps/thumbnail")) {
        meta.fields.insert("office:thumbnail".into(), t.clone());
    }
    // embedded media and objects
    let media: Vec<&String> = names
        .iter()
        .filter(|n| {
            n.contains("/media/")
                || n.contains("/embeddings/")
                || n.starts_with("docProps/thumbnail")
        })
        .collect();
    for n in media {
        if n.ends_with('/') {
            continue;
        }
        let short = n.rsplit('/').next().unwrap_or(n);
        if n.contains("/embeddings/") {
            let size = z.size(n);
            meta.attachments.push(Attachment {
                name: short.to_string(),
                size,
                mime: None,
            });
        }
        if meta.embedded.len() >= MAX_EMBEDDED || !ctx.can_descend() {
            continue;
        }
        let Some(b) = z.read(n, ctx)? else { continue };
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

fn docx(
    z: &mut SafeZip,
    names: &[String],
    ctx: &Ctx,
    meta: &mut Metadata,
) -> Result<(), MetaError> {
    let parts = sorted_matching(names, |n| {
        n == "word/document.xml"
            || (n.starts_with("word/header") || n.starts_with("word/footer")) && n.ends_with(".xml")
            || n == "word/footnotes.xml"
            || n == "word/endnotes.xml"
    });
    for p in &parts {
        if let Some(e) = read_xml(z, p, ctx, meta)? {
            revisions(meta, &e);
            vanish(meta, &e, p);
        }
    }
    if let Some(e) = read_xml(z, "word/comments.xml", ctx, meta)? {
        word_comments(meta, &e, "word/comments.xml");
    }
    if let Some(e) = read_xml(z, "word/fontTable.xml", ctx, meta)? {
        ooxml_data::fonts(meta, &e);
    }
    if let Some(e) = read_xml(z, "word/people.xml", ctx, meta)? {
        for p in e.descendants("person") {
            if let Some(a) = p.attr_local("author") {
                meta.add_person(a, PersonRole::Comment, "word/people.xml");
                if let Some(pi) = p.child("presenceInfo") {
                    if let Some(uid) = pi.attr_local("userId") {
                        meta.fields.insert(format!("people:{a}"), uid.to_string());
                    }
                }
            }
        }
    }
    if let Some(e) = read_xml(z, "word/settings.xml", ctx, meta)? {
        if let Some(rs) = e.child("rsids") {
            for r in rs.elements() {
                if let Some(v) = r.attr_local("val") {
                    if meta.rsids.len() < 10_000 {
                        Metadata::add_unique(&mut meta.rsids, v);
                    }
                }
            }
        }
        ooxml_data::word_settings(meta, &e);
        for prot in ["documentProtection", "writeProtection"] {
            if let Some(p) = e.child(prot) {
                let edit = p.attr_local("edit").unwrap_or("on");
                meta.fields
                    .insert(format!("settings:{prot}"), edit.to_string());
            }
        }
    }
    Ok(())
}

fn xlsx(
    z: &mut SafeZip,
    names: &[String],
    ctx: &Ctx,
    meta: &mut Metadata,
) -> Result<(), MetaError> {
    if names.iter().any(|n| n == "xl/workbook.bin") {
        meta.fields
            .insert("ooxml:binary_workbook".into(), "xlsb".into());
        super::xlsb::parse(z, names, ctx, meta)?;
    }
    if let Some(wb) = read_xml(z, "xl/workbook.xml", ctx, meta)? {
        ooxml_data::external_defined_names(meta, &wb);
        for s in wb.descendants("sheet") {
            if let (Some(state), Some(name)) = (s.attr("state"), s.attr("name")) {
                if state == "hidden" || state == "veryHidden" {
                    Metadata::add_unique(&mut meta.hidden_sheets, name);
                    if state == "veryHidden" {
                        meta.fields
                            .insert(format!("xl:veryHidden:{name}"), "true".into());
                    }
                }
            }
        }
    }
    for n in sorted_matching(names, |n| {
        n.starts_with("xl/comments") && n.ends_with(".xml")
    }) {
        let Some(e) = read_xml(z, &n, ctx, meta)? else {
            continue;
        };
        let authors: Vec<String> = e
            .child("authors")
            .map(|a| a.elements().map(|x| x.text().trim().to_string()).collect())
            .unwrap_or_default();
        for c in e.descendants("comment") {
            let author = c
                .attr("authorId")
                .and_then(|i| i.parse::<usize>().ok())
                .and_then(|i| authors.get(i))
                .and_then(|a| clean_str(a));
            let mut text = String::new();
            collect_text(c, &["t"], &[], &mut text, 0);
            push_comment(
                meta,
                CommentRef {
                    author,
                    initials: None,
                    date: None,
                    text: truncate(text.trim(), 2048),
                    source: n.clone(),
                },
            );
        }
        for a in &authors {
            meta.add_person(a, PersonRole::Comment, &n);
        }
    }
    if let Some(e) = read_xml(z, "xl/persons/person.xml", ctx, meta)? {
        for p in e.descendants("person") {
            if let Some(name) = p.attr("displayName") {
                meta.add_person(name, PersonRole::Comment, "xl/persons/person.xml");
                if let Some(uid) = p.attr("userId") {
                    meta.fields
                        .insert(format!("persons:{name}"), uid.to_string());
                }
            }
        }
    }
    hidden_cells(z, ctx, meta)?;
    pivot_caches(z, names, ctx, meta)?;
    if let Some(e) = read_xml(z, "xl/connections.xml", ctx, meta)? {
        ooxml_data::spreadsheet_connections(meta, &e);
    }
    if let Some(e) = read_xml(z, "xl/styles.xml", ctx, meta)? {
        ooxml_data::fonts(meta, &e);
    }
    ooxml_data::power_query(z, names, ctx, meta)?;
    Ok(())
}

fn pptx(
    z: &mut SafeZip,
    names: &[String],
    ctx: &Ctx,
    meta: &mut Metadata,
) -> Result<(), MetaError> {
    let mut authors: Vec<(String, String, Option<String>)> = Vec::new(); // id, name, initials
    if let Some(e) = read_xml(z, "ppt/commentAuthors.xml", ctx, meta)? {
        for a in e.descendants("cmAuthor") {
            if let Some(name) = a.attr("name") {
                authors.push((
                    a.attr("id").unwrap_or("").to_string(),
                    name.to_string(),
                    a.attr("initials").map(str::to_string),
                ));
                meta.add_person(name, PersonRole::Comment, "ppt/commentAuthors.xml");
            }
        }
    }
    if let Some(e) = read_xml(z, "ppt/authors.xml", ctx, meta)? {
        for a in e.descendants("author") {
            if let Some(name) = a.attr("name") {
                authors.push((
                    a.attr("id").unwrap_or("").to_string(),
                    name.to_string(),
                    a.attr("initials").map(str::to_string),
                ));
                meta.add_person(name, PersonRole::Comment, "ppt/authors.xml");
                if let Some(uid) = a.attr("userId") {
                    meta.fields
                        .insert(format!("authors:{name}"), uid.to_string());
                }
            }
        }
    }
    for n in sorted_matching(names, |n| {
        n.starts_with("ppt/comments/") && n.ends_with(".xml")
    }) {
        let Some(e) = read_xml(z, &n, ctx, meta)? else {
            continue;
        };
        for c in e.descendants("cm") {
            let a = c
                .attr("authorId")
                .and_then(|id| authors.iter().find(|x| x.0 == id));
            let mut text = String::new();
            collect_text(c, &["text", "t"], &["p"], &mut text, 0);
            push_comment(
                meta,
                CommentRef {
                    author: a.and_then(|x| clean_str(&x.1)),
                    initials: a.and_then(|x| x.2.as_deref().and_then(clean_str)),
                    date: c
                        .attr("dt")
                        .or_else(|| c.attr("created"))
                        .and_then(normalize_date),
                    text: truncate(text.trim(), 2048),
                    source: n.clone(),
                },
            );
        }
    }
    // hidden slides (`<p:sld show="0">`) with their text
    for n in sorted_matching(names, |n| {
        n.starts_with("ppt/slides/slide") && n.ends_with(".xml")
    })
    .into_iter()
    .take(2000)
    {
        let Some(e) = read_xml(z, &n, ctx, meta)? else {
            continue;
        };
        if matches!(e.attr("show"), Some("0" | "false")) && meta.hidden_content.len() < MAX_HIDDEN {
            let mut text = String::new();
            collect_text(&e, &["t"], &["p"], &mut text, 0);
            let text = text.split_whitespace().collect::<Vec<_>>().join(" ");
            meta.hidden_content.push(HiddenContent {
                kind: "slide".into(),
                location: n.clone(),
                text: truncate(&text, 512),
            });
        }
    }
    let notes = names
        .iter()
        .filter(|n| n.starts_with("ppt/notesSlides/") && n.ends_with(".xml"))
        .count();
    if notes > 0 {
        meta.stats.entry("notes".into()).or_insert(notes as u64);
    }
    Ok(())
}

/// Whether a run property element (`w:vanish`, `w:b`) is switched on.
fn on_off(e: &Element) -> bool {
    !matches!(e.attr_local("val"), Some("0" | "false" | "off"))
}

/// Hidden text: runs formatted with `w:vanish`, grouped per paragraph.
fn vanish(meta: &mut Metadata, el: &Element, part: &str) {
    for p in el.descendants("p") {
        if meta.hidden_content.len() >= MAX_HIDDEN {
            return;
        }
        if !p.name.starts_with("w:") {
            continue;
        }
        let mut text = String::new();
        for r in p.descendants("r") {
            let hidden = r
                .child("rPr")
                .and_then(|pr| pr.child("vanish"))
                .is_some_and(on_off);
            if hidden {
                collect_text(r, &["t", "delText"], &[], &mut text, 0);
            }
            if text.len() > 4096 {
                break;
            }
        }
        let text = text.split_whitespace().collect::<Vec<_>>().join(" ");
        if !text.is_empty() {
            meta.hidden_content.push(HiddenContent {
                kind: "vanish".into(),
                location: part.to_string(),
                text: truncate(&text, 512),
            });
        }
    }
}

/// Column letters of a cell reference (`AB12` → 28).
fn col_index(r: &str) -> Option<u32> {
    let mut n: u32 = 0;
    let mut any = false;
    for c in r.chars() {
        if c.is_ascii_alphabetic() {
            n = n
                .checked_mul(26)?
                .checked_add(u32::from(c.to_ascii_uppercase() as u8 - b'A' + 1))?;
            any = true;
        } else {
            break;
        }
    }
    (any && n <= 16_384).then_some(n)
}

fn col_name(mut n: u32) -> String {
    let mut s = Vec::new();
    while n > 0 {
        let r = ((n - 1) % 26) as u8;
        s.push((b'A' + r) as char);
        n = (n - 1) / 26;
    }
    s.iter().rev().collect()
}

/// Cached value of a cell (shared/inline strings resolved).
fn cell_value(c: &Element, shared: &[String]) -> Option<String> {
    let v = match c.attr("t") {
        Some("s") => {
            let i: usize = c.child("v")?.text().trim().parse().ok()?;
            shared.get(i)?.clone()
        }
        Some("inlineStr") => {
            let mut t = String::new();
            collect_text(c.child("is")?, &["t"], &[], &mut t, 0);
            t
        }
        _ => c.child("v")?.text(),
    };
    clean_str(&v)
}

/// Joins `(start, end)` index runs into `5-7, 9` style text.
fn ranges(v: &[u32], fmt: impl Fn(u32) -> String) -> Vec<(u32, u32, String)> {
    let mut out: Vec<(u32, u32, String)> = Vec::new();
    for &x in v {
        match out.last_mut() {
            Some((_, e, _)) if *e + 1 == x => *e = x,
            _ => out.push((x, x, String::new())),
        }
    }
    for (s, e, label) in &mut out {
        *label = if s == e {
            fmt(*s)
        } else {
            format!("{}:{}", fmt(*s), fmt(*e))
        };
    }
    out
}

/// Hidden rows and columns of every worksheet, with the cached values they hide.
fn hidden_cells(z: &mut SafeZip, ctx: &Ctx, meta: &mut Metadata) -> Result<(), MetaError> {
    let mut sheets: Vec<(String, String)> = Vec::new(); // name, part
    let mut rid_target: HashMap<String, String> = HashMap::new();
    if let Some(r) = read_xml(z, "xl/_rels/workbook.xml.rels", ctx, meta)? {
        for rel in r.elements().filter(|e| e.local() == "Relationship") {
            if let (Some(id), Some(t)) = (rel.attr("Id"), rel.attr("Target")) {
                let t = t.trim_start_matches('/');
                let part = if t.starts_with("xl/") {
                    t.to_string()
                } else {
                    format!("xl/{t}")
                };
                rid_target.insert(id.to_string(), part);
            }
        }
    }
    if let Some(wb) = read_xml(z, "xl/workbook.xml", ctx, meta)? {
        for s in wb.descendants("sheet") {
            if let (Some(name), Some(rid)) = (s.attr("name"), s.attr_local("id")) {
                if let Some(part) = rid_target.get(rid) {
                    sheets.push((name.to_string(), part.clone()));
                }
            }
        }
    }
    if sheets.is_empty() {
        return Ok(());
    }
    let mut shared: Vec<String> = Vec::new();
    if let Some(sst) = read_xml(z, "xl/sharedStrings.xml", ctx, meta)? {
        for si in sst.elements().filter(|e| e.local() == "si").take(1_000_000) {
            let mut t = String::new();
            collect_text(si, &["t"], &[], &mut t, 0);
            shared.push(truncate(&t, 256));
        }
    }
    for (name, part) in sheets.into_iter().take(500) {
        if meta.hidden_content.len() >= MAX_HIDDEN {
            break;
        }
        let Some(ws) = read_xml(z, &part, ctx, meta)? else {
            continue;
        };
        let mut hidden_cols: Vec<u32> = Vec::new();
        if let Some(cols) = ws.child("cols") {
            for c in cols.elements().filter(|e| e.local() == "col") {
                if !c.attr("hidden").is_some_and(|v| v == "1" || v == "true") {
                    continue;
                }
                let min: u32 = c.attr("min").and_then(|v| v.parse().ok()).unwrap_or(0);
                let max: u32 = c.attr("max").and_then(|v| v.parse().ok()).unwrap_or(min);
                if min == 0 || max < min {
                    continue;
                }
                // a hidden tail up to XFD is formatting, not content
                for x in min..=max.min(min.saturating_add(256)).min(16_384) {
                    hidden_cols.push(x);
                }
            }
        }
        hidden_cols.sort_unstable();
        hidden_cols.dedup();
        let mut hidden_rows: Vec<u32> = Vec::new();
        let mut row_text: HashMap<u32, Vec<String>> = HashMap::new();
        let mut col_text: HashMap<u32, Vec<String>> = HashMap::new();
        if let Some(data) = ws.child("sheetData") {
            for (i, row) in data.elements().filter(|e| e.local() == "row").enumerate() {
                let r: u32 = row
                    .attr("r")
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(i as u32 + 1);
                let hidden = row.attr("hidden").is_some_and(|v| v == "1" || v == "true");
                if hidden && hidden_rows.len() < 10_000 {
                    hidden_rows.push(r);
                }
                if !hidden && hidden_cols.is_empty() {
                    continue;
                }
                for c in row.elements().filter(|e| e.local() == "c") {
                    let col = c.attr("r").and_then(col_index);
                    let in_col = col.is_some_and(|x| hidden_cols.binary_search(&x).is_ok());
                    if !hidden && !in_col {
                        continue;
                    }
                    let Some(v) = cell_value(c, &shared) else {
                        continue;
                    };
                    if hidden {
                        let e = row_text.entry(r).or_default();
                        if e.len() < 20 {
                            e.push(v.clone());
                        }
                    }
                    if let (true, Some(x)) = (in_col, col) {
                        let e = col_text.entry(x).or_default();
                        if e.len() < 20 {
                            e.push(v);
                        }
                    }
                }
            }
        }
        hidden_rows.sort_unstable();
        hidden_rows.dedup();
        for (s, e, label) in ranges(&hidden_rows, |x| x.to_string()) {
            let mut vals: Vec<String> = Vec::new();
            for r in s..=e.min(s + 1000) {
                vals.extend(row_text.get(&r).cloned().unwrap_or_default());
            }
            push_hidden(meta, "row", format!("{name}!{label}"), &vals);
        }
        for (s, e, label) in ranges(&hidden_cols, col_name) {
            let mut vals: Vec<String> = Vec::new();
            for x in s..=e {
                vals.extend(col_text.get(&x).cloned().unwrap_or_default());
            }
            push_hidden(meta, "column", format!("{name}!{label}"), &vals);
        }
    }
    Ok(())
}

fn push_hidden(meta: &mut Metadata, kind: &str, location: String, vals: &[String]) {
    if meta.hidden_content.len() >= MAX_HIDDEN {
        return;
    }
    meta.hidden_content.push(HiddenContent {
        kind: kind.into(),
        location,
        text: truncate(&vals.join(" | "), 512),
    });
}

/// Pivot caches: who refreshed them, when, and from which source.
fn pivot_caches(
    z: &mut SafeZip,
    names: &[String],
    ctx: &Ctx,
    meta: &mut Metadata,
) -> Result<(), MetaError> {
    for n in sorted_matching(names, |n| {
        n.starts_with("xl/pivotCache/pivotCacheDefinition") && n.ends_with(".xml")
    })
    .into_iter()
    .take(200)
    {
        let Some(e) = read_xml(z, &n, ctx, meta)? else {
            continue;
        };
        let id = n
            .trim_start_matches("xl/pivotCache/pivotCacheDefinition")
            .trim_end_matches(".xml");
        if let Some(who) = e.attr("refreshedBy").and_then(clean_str) {
            meta.add_person(&who, PersonRole::Other, &format!("{n}:refreshedBy"));
            meta.fields.insert(
                format!("xl:pivotCache{id}:refreshedBy"),
                truncate(&who, 512),
            );
        }
        if let Some(d) = e.attr("refreshedDateIso").or(e.attr("refreshedDate")) {
            meta.fields
                .insert(format!("xl:pivotCache{id}:refreshedDate"), truncate(d, 64));
        }
        if let Some(v) = e.attr("refreshedVersion") {
            meta.fields.insert(
                format!("xl:pivotCache{id}:refreshedVersion"),
                truncate(v, 16),
            );
        }
        if let Some(src) = e.child("cacheSource") {
            if let Some(cid) = src.attr("connectionId") {
                meta.fields
                    .insert(format!("xl:pivotCache{id}:connectionId"), truncate(cid, 16));
            }
            if let Some(ws) = src.child("worksheetSource") {
                let s = [ws.attr("sheet"), ws.attr("ref"), ws.attr("name")]
                    .into_iter()
                    .flatten()
                    .collect::<Vec<_>>()
                    .join("!");
                if !s.is_empty() {
                    meta.fields
                        .insert(format!("xl:pivotCache{id}:source"), truncate(&s, 512));
                }
            }
        }
    }
    Ok(())
}

/// Charts: external workbook references in series formulas (`c:f`).
fn charts(
    z: &mut SafeZip,
    names: &[String],
    ctx: &Ctx,
    meta: &mut Metadata,
) -> Result<(), MetaError> {
    for n in sorted_matching(names, |n| {
        n.contains("/charts/chart") && n.ends_with(".xml") && !n.contains("/_rels/")
    })
    .into_iter()
    .take(200)
    {
        let Some(e) = read_xml(z, &n, ctx, meta)? else {
            continue;
        };
        let mut refs: Vec<String> = Vec::new();
        for f in e.descendants("f") {
            let t = f.text();
            let t = t.trim();
            // external references look like '[1]Sheet'!A1 or 'C:\dir\[book.xlsx]Sheet'!A1
            if (t.contains('[') || t.contains('\\') || t.contains("://")) && refs.len() < 20 {
                let t = truncate(t, 512);
                if !refs.contains(&t) {
                    refs.push(t);
                }
            }
        }
        if !refs.is_empty() {
            meta.fields
                .insert(format!("chart:{n}:externalRef"), refs.join("; "));
        }
    }
    Ok(())
}

/// XML-DSig signature parts and VBA project signatures.
fn signatures(
    z: &mut SafeZip,
    names: &[String],
    ctx: &Ctx,
    meta: &mut Metadata,
) -> Result<(), MetaError> {
    for n in sorted_matching(names, |n| {
        n.starts_with("_xmlsignatures/") && n.ends_with(".xml") && !n.contains("/_rels/")
    })
    .into_iter()
    .take(32)
    {
        if let Some(e) = read_xml(z, &n, ctx, meta)? {
            if let Some(s) = crate::formats::signature::xmldsig(&e, &n) {
                meta.signatures.push(s);
            }
        }
    }
    for n in names
        .iter()
        .filter(|n| {
            let l = n.to_ascii_lowercase();
            l.contains("vbaprojectsignature") && l.ends_with(".bin")
        })
        .take(8)
    {
        if let Some(b) = z.read(n, ctx)? {
            if let Some(s) = crate::formats::signature::vba_signature(&b, n) {
                meta.signatures.push(s);
            }
        }
    }
    crate::formats::signature::apply_signers(meta, "signature:ooxml");
    Ok(())
}

/// Returns the plain text of the document.
pub fn text(bytes: &[u8], ctx: &Ctx) -> Result<String, MetaError> {
    let mut z = SafeZip::open(bytes, ctx.max_entries())?;
    let names: Vec<String> = z.names().to_vec();
    let mut dummy = Metadata::default();
    let parts = sorted_matching(&names, |n| {
        n.ends_with(".xml")
            && (n.starts_with("word/document")
                || n.starts_with("word/header")
                || n.starts_with("word/footer")
                || n.starts_with("word/footnotes")
                || n.starts_with("word/endnotes")
                || n.starts_with("word/comments")
                || n == "xl/sharedStrings.xml"
                || n.starts_with("xl/worksheets/sheet")
                || n.starts_with("xl/comments")
                || n == "xl/connections.xml"
                || n.starts_with("ppt/slides/slide")
                || n.starts_with("ppt/notesSlides/")
                || n.starts_with("ppt/comments/"))
    });
    let mut out = String::new();
    for p in parts {
        let Some(e) = read_xml(&mut z, &p, ctx, &mut dummy)? else {
            continue;
        };
        if p == "xl/connections.xml" {
            for c in e.descendants("dbPr") {
                if let Some(v) = c.attr("connection") {
                    out.push_str(&ooxml_data::parse_conn(v).redacted);
                    out.push('\n');
                }
            }
            continue;
        }
        collect_text(
            &e,
            &["t", "delText", "instrText", "text"],
            &["p", "si", "row", "comment", "cm"],
            &mut out,
            0,
        );
        out.push('\n');
    }
    if names.iter().any(|n| n == "xl/workbook.bin") {
        out.push_str(&super::xlsb::parse(&mut z, &names, ctx, &mut dummy)?);
    }
    for n in names
        .iter()
        .filter(|n| n.to_ascii_lowercase().ends_with("vbaproject.bin"))
    {
        if let Some(b) = z.read(n, ctx)? {
            for l in vba::scan_ole(&b, &mut dummy) {
                out.push_str(&l);
                out.push('\n');
            }
        }
    }
    Ok(out)
}
