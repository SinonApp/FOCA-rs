//! OOXML cleaning.
//!
//! Core/app/custom parts are replaced with empty ones; authors and initials of
//! comments and tracked changes, and authors in `people.xml`/`persons`/`commentAuthors`, are
//! blanked (comment and document text is left intact); RSIDs are removed; the template path
//! in `_rels` is replaced with `Normal.dotm`; the printer name in `printerSettings*.bin` is
//! zeroed; data connection strings, ODC/credential file paths and web query URLs in
//! `xl/connections.xml` are blanked (the cached data and query text stay); embedded JPEG and PNG images (`*/media/*`) are cleaned like standalone files.
//! Comment and revision dates are kept.

use std::io::{Cursor, Read, Write};

use foca_core::DocFormat;
use quick_xml::events::{BytesStart, BytesText, Event};
use quick_xml::{Reader, Writer};
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, ZipArchive, ZipWriter};

use super::raster::{clean_jpeg, clean_png};
use crate::util::decode_text;
use crate::{detect, Limits, MetaError};

const CORE_EMPTY: &str = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/" xmlns:dcmitype="http://purl.org/dc/dcmitype/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"/>"#;
const APP_EMPTY: &str = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties" xmlns:vt="http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes"/>"#;
const CUSTOM_EMPTY: &str = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/custom-properties" xmlns:vt="http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes"/>"#;

#[derive(Clone, Copy, PartialEq)]
enum Mode {
    Word,
    Rels,
    XlComments,
    Persons,
    PptAuthors,
    /// `xl/connections.xml`: connection strings and file paths (server, user, ODC file).
    Connections,
    /// Pivot cache definitions: who refreshed the cache and when.
    Pivot,
    /// Charts: directory paths of external workbooks in series formulas.
    Chart,
    /// `[Content_Types].xml`: overrides of removed signature parts are dropped.
    ContentTypes,
}

enum Action {
    Keep,
    /// Signature part: removed (any change invalidates it).
    DropSignature,
    Replace(&'static str),
    Rewrite(Mode),
    ZeroPrinter,
    /// Embedded image; JPEGs are cleaned recursively.
    Media,
}

/// XML-DSig package signatures and VBA project signatures.
fn is_signature_part(name: &str) -> bool {
    let n = name.trim_start_matches('/');
    n.starts_with("_xmlsignatures/")
        || n.rsplit('/')
            .next()
            .is_some_and(|f| f.starts_with("vbaProjectSignature"))
}

/// True if a relationship target or content-type part name points at a signature part.
fn refers_to_signature(target: &str) -> bool {
    target.contains("_xmlsignatures/")
        || target.contains("vbaProjectSignature")
        || target.ends_with("origin.sigs")
}

fn classify(name: &str) -> Action {
    if is_signature_part(name) {
        return Action::DropSignature;
    }
    match name {
        "[Content_Types].xml" => Action::Rewrite(Mode::ContentTypes),
        "docProps/core.xml" => Action::Replace(CORE_EMPTY),
        "docProps/app.xml" => Action::Replace(APP_EMPTY),
        "docProps/custom.xml" => Action::Replace(CUSTOM_EMPTY),
        _ if name.ends_with(".rels") => Action::Rewrite(Mode::Rels),
        _ if name.contains("printerSettings") && name.ends_with(".bin") => Action::ZeroPrinter,
        _ if name.contains("/media/") => Action::Media,
        _ if name.starts_with("word/") && name.ends_with(".xml") => Action::Rewrite(Mode::Word),
        _ if name.starts_with("xl/comments") && name.ends_with(".xml") => {
            Action::Rewrite(Mode::XlComments)
        }
        _ if name.starts_with("xl/persons/") && name.ends_with(".xml") => {
            Action::Rewrite(Mode::Persons)
        }
        "ppt/commentAuthors.xml" | "ppt/authors.xml" => Action::Rewrite(Mode::PptAuthors),
        "xl/connections.xml" => Action::Rewrite(Mode::Connections),
        _ if name.starts_with("xl/pivotCache/pivotCacheDefinition") && name.ends_with(".xml") => {
            Action::Rewrite(Mode::Pivot)
        }
        _ if name.contains("/charts/chart") && name.ends_with(".xml") => {
            Action::Rewrite(Mode::Chart)
        }
        _ => Action::Keep,
    }
}

fn zerr(e: impl ToString) -> MetaError {
    MetaError::malformed("zip", e)
}

/// Returns the clean package and the number of removed signature parts.
pub(super) fn clean_ooxml(bytes: &[u8], limits: &Limits) -> Result<(Vec<u8>, u32), MetaError> {
    let mut ar = ZipArchive::new(Cursor::new(bytes)).map_err(zerr)?;
    if ar.len() > limits.max_entries {
        return Err(MetaError::TooManyEntries(format!("{} записей", ar.len())));
    }
    let mut w = ZipWriter::new(Cursor::new(Vec::new()));
    let opts = SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);
    let mut budget = limits.max_unzipped_total;
    let mut sigs = 0u32;
    for i in 0..ar.len() {
        let name = ar
            .by_index_raw(i)
            .map_err(zerr)?
            .name()
            .map_err(zerr)?
            .to_string();
        let action = classify(&name);
        if let Action::DropSignature = action {
            // count signatures, not the origin/certificate helper parts
            let is_sig = (name.ends_with(".xml") && name.contains("sig")) || name.ends_with(".bin");
            sigs += u32::from(is_sig);
            continue;
        }
        if let Action::Keep = action {
            let f = ar.by_index_raw(i).map_err(zerr)?;
            w.raw_copy_file(f).map_err(zerr)?;
            continue;
        }
        if let Action::Replace(s) = action {
            w.start_file(name.as_str(), opts).map_err(zerr)?;
            w.write_all(s.as_bytes()).map_err(zerr)?;
            continue;
        }
        let mut data = Vec::new();
        {
            let f = ar.by_index(i).map_err(zerr)?;
            f.take(budget.saturating_add(1))
                .read_to_end(&mut data)
                .map_err(zerr)?;
        }
        if data.len() as u64 > budget {
            return Err(MetaError::ZipBomb(format!(
                "{name}: распаковано больше бюджета"
            )));
        }
        budget -= data.len() as u64;
        let out = match action {
            Action::ZeroPrinter => {
                for b in data.iter_mut().take(64) {
                    *b = 0;
                }
                data
            }
            Action::Rewrite(mode) => rewrite_xml(&data, mode)?,
            Action::Media => match detect(&data) {
                DocFormat::Jpeg => clean_jpeg(&data).unwrap_or(data),
                DocFormat::Png => clean_png(&data).unwrap_or(data),
                _ => data,
            },
            Action::Keep | Action::Replace(_) | Action::DropSignature => data,
        };
        w.start_file(name.as_str(), opts).map_err(zerr)?;
        w.write_all(&out).map_err(zerr)?;
    }
    Ok((w.finish().map_err(zerr)?.into_inner(), sigs))
}

/// Relationship or content-type override that points at a removed signature part.
fn is_signature_ref(e: &BytesStart, mode: Mode) -> bool {
    let key = match mode {
        Mode::Rels => "Target",
        Mode::ContentTypes => "PartName",
        _ => return false,
    };
    e.attributes()
        .with_checks(false)
        .flatten()
        .any(|a| a.key.as_ref() == key && refers_to_signature(&a.value))
}

fn local(name: &str) -> &str {
    crate::xml::local(name)
}

fn rewrite_start(e: &BytesStart, mode: Mode) -> BytesStart<'static> {
    let name = e.name().as_ref().to_string();
    let mut out = BytesStart::new(name.clone());
    let is_template_rel = mode == Mode::Rels
        && e.attributes()
            .flatten()
            .any(|a| a.key.as_ref() == "Type" && a.value.ends_with("/attachedTemplate"));
    for a in e.attributes().with_checks(false).flatten() {
        let k = a.key.as_ref().to_string();
        let raw = a.value.to_string();
        let v = a
            .normalized_value(quick_xml::XmlVersion::Implicit1_0)
            .map(|c| c.into_owned())
            .unwrap_or(raw);
        let l = local(&k);
        let new_v: Option<String> = match mode {
            Mode::Word => {
                if l.starts_with("rsid") {
                    None
                } else if matches!(l, "author" | "initials" | "userId" | "providerId") {
                    Some(String::new())
                } else {
                    Some(v)
                }
            }
            Mode::Rels => {
                if is_template_rel && k == "Target" {
                    Some("Normal.dotm".into())
                } else {
                    Some(v)
                }
            }
            Mode::Persons | Mode::PptAuthors => {
                if matches!(
                    l,
                    "displayName" | "name" | "initials" | "userId" | "providerId"
                ) {
                    Some(String::new())
                } else {
                    Some(v)
                }
            }
            Mode::Connections => {
                if matches!(
                    l,
                    "connection" | "odcFile" | "credentialsFile" | "sourceFile" | "url"
                ) {
                    Some(String::new())
                } else {
                    Some(v)
                }
            }
            Mode::Pivot => {
                if matches!(l, "refreshedBy" | "refreshedDate" | "refreshedDateIso") {
                    None
                } else {
                    Some(v)
                }
            }
            Mode::XlComments | Mode::Chart | Mode::ContentTypes => Some(v),
        };
        if let Some(v) = new_v {
            out.push_attribute((k.as_str(), v.as_str()));
        }
    }
    out
}

fn rewrite_xml(data: &[u8], mode: Mode) -> Result<Vec<u8>, MetaError> {
    let s = decode_text(data);
    let mut r = Reader::from_str(&s);
    r.config_mut().check_end_names = false;
    r.config_mut().allow_unmatched_ends = true;
    // a stray `&` in text is kept as is (seen in hand-edited documents)
    r.config_mut().allow_dangling_amp = true;
    let mut w = Writer::new(Vec::with_capacity(data.len()));
    let mut skip_depth = 0usize; // inside <w:rsids>
    let mut in_author = 0usize; // inside <author> (xl/comments)
    let mut in_formula = false; // inside <c:f> (charts)
    loop {
        let ev = r.read_event().map_err(|e| MetaError::malformed("xml", e))?;
        let werr = |e: std::io::Error| MetaError::malformed("xml", e);
        match ev {
            Event::Eof => break,
            Event::Start(e) => {
                if skip_depth > 0
                    || (mode == Mode::Word && e.name().as_ref() == "w:rsids")
                    || is_signature_ref(&e, mode)
                {
                    skip_depth += 1;
                    continue;
                }
                if mode == Mode::XlComments && local(e.name().as_ref()) == "author" {
                    in_author += 1;
                }
                if mode == Mode::Chart && local(e.name().as_ref()) == "f" {
                    in_formula = true;
                }
                w.write_event(Event::Start(rewrite_start(&e, mode)))
                    .map_err(werr)?;
            }
            Event::Empty(e) => {
                if skip_depth > 0
                    || (mode == Mode::Word && e.name().as_ref() == "w:rsids")
                    || is_signature_ref(&e, mode)
                {
                    continue;
                }
                w.write_event(Event::Empty(rewrite_start(&e, mode)))
                    .map_err(werr)?;
            }
            Event::End(e) => {
                if skip_depth > 0 {
                    skip_depth -= 1;
                    continue;
                }
                if mode == Mode::XlComments && local(e.name().as_ref()) == "author" {
                    in_author = in_author.saturating_sub(1);
                }
                in_formula = false;
                w.write_event(Event::End(e)).map_err(werr)?;
            }
            Event::Text(_) | Event::GeneralRef(_) | Event::CData(_)
                if skip_depth > 0 || in_author > 0 => {}
            Event::Text(t) if in_formula => {
                let f = strip_external_dirs(&t.xml10_content());
                w.write_event(Event::Text(BytesText::new(&f)))
                    .map_err(werr)?;
            }
            other => {
                if skip_depth == 0 {
                    w.write_event(other).map_err(werr)?;
                }
            }
        }
    }
    Ok(w.into_inner())
}

/// Removes directory paths of external workbooks from a formula:
/// `'C:\\Users\\u\\[book.xlsx]Sheet1'!A1` becomes `'[book.xlsx]Sheet1'!A1`.
fn strip_external_dirs(f: &str) -> String {
    let mut out = String::with_capacity(f.len());
    let mut rest = f;
    while let Some(b) = rest.find('[') {
        let head = &rest[..b];
        // the path starts after the last quote or formula delimiter before '['
        let start = head.rfind(['\'', '(', ',', '=', ' ']).map_or(0, |i| i + 1);
        let path = &head[start..];
        let is_path = path.ends_with(['\\', '/'])
            && (path.contains(":\\")
                || path.starts_with("\\\\")
                || path.starts_with('/')
                || path.contains("://"));
        out.push_str(if is_path { &head[..start] } else { head });
        out.push('[');
        rest = &rest[b + 1..];
    }
    out.push_str(rest);
    out
}

#[cfg(test)]
mod tests {
    use super::strip_external_dirs;

    #[test]
    fn external_workbook_dirs_are_stripped() {
        assert_eq!(
            strip_external_dirs(r"'C:\Users\u\Desktop\[budget.xlsx]Sheet1'!$A$1:$A$5"),
            "'[budget.xlsx]Sheet1'!$A$1:$A$5"
        );
        assert_eq!(
            strip_external_dirs(r"SUM('\\srv\share\[a.xlsx]S'!A1,[1]Sheet1!B2)"),
            "SUM('[a.xlsx]S'!A1,[1]Sheet1!B2)"
        );
        assert_eq!(strip_external_dirs("Sheet1!$A$1"), "Sheet1!$A$1");
    }
}
