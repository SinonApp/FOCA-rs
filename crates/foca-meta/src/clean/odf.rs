//! Metadata removal for OpenDocument packages (ODT/ODS/ODP/ODG).
//!
//! * `meta.xml` (also in embedded `Object N/` sub-documents): every child of `office:meta` is
//!   removed except `meta:document-statistic` (initial creator, creator, dates, editing cycles
//!   and duration, generator, template, printed-by, title/subject/keywords, user-defined fields).
//! * `settings.xml`: printer name and setup blob, data-source names and any configuration item
//!   whose value looks like a file path or URL to a local resource.
//! * `content.xml`/`styles.xml`: authors (`dc:creator`, `meta:creator-initials`) of annotations
//!   and tracked changes are blanked; text and dates are kept.
//! * `Thumbnails/`, `Versions/`, `VersionList.xml` and document signatures are dropped and
//!   unlisted from `META-INF/manifest.xml`.
//! * Embedded JPEG/PNG pictures are cleaned like standalone files.
//!
//! The package is rewritten with `mimetype` as the first, stored (uncompressed) entry.

use std::io::{Cursor, Read, Write};

use foca_core::DocFormat;
use quick_xml::events::{BytesStart, Event};
use quick_xml::{Reader, Writer};
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, ZipArchive, ZipWriter};

use super::output::{CleanOptions, CleanOutput, CleanWarning};
use super::raster::{clean_jpeg, clean_png};
use crate::util::decode_text;
use crate::{detect, Limits, MetaError};

/// `settings.xml` configuration items that are always removed.
const SETTINGS_DROP: &[&str] = &[
    "PrinterName",
    "PrinterSetup",
    "PrinterPaperFromSetup",
    "CurrentDatabaseDataSource",
    "CurrentDatabaseCommand",
    "CurrentDatabaseCommandType",
    "DataSourceName",
    "EmbeddedDatabaseName",
];

fn zerr(e: impl ToString) -> MetaError {
    MetaError::malformed("zip", e)
}

fn xerr(e: impl ToString) -> MetaError {
    MetaError::malformed("xml", e)
}

#[derive(Clone, Copy, PartialEq)]
enum Part {
    Meta,
    Settings,
    Content,
    Manifest,
}

enum Action {
    Keep,
    Drop,
    Rewrite(Part),
    Picture,
}

fn is_removed_path(name: &str) -> bool {
    let n = name.trim_start_matches('/');
    n.starts_with("Thumbnails/")
        || n.starts_with("Versions/")
        || n == "VersionList.xml"
        || n.starts_with("META-INF/documentsignatures")
        || n.starts_with("META-INF/macrosignatures")
}

fn classify(name: &str) -> Action {
    let leaf = name.rsplit('/').next().unwrap_or(name);
    if is_removed_path(name) {
        return Action::Drop;
    }
    if name == "META-INF/manifest.xml" {
        return Action::Rewrite(Part::Manifest);
    }
    match leaf {
        "meta.xml" => Action::Rewrite(Part::Meta),
        "settings.xml" => Action::Rewrite(Part::Settings),
        "content.xml" | "styles.xml" => Action::Rewrite(Part::Content),
        _ if name.starts_with("Pictures/") || name.contains("/Pictures/") => Action::Picture,
        _ => Action::Keep,
    }
}

/// True for a binary embedded object (`Object N` stored as a file, typically OLE2).
fn is_binary_object(name: &str) -> bool {
    !name.contains('/')
        && name
            .strip_prefix("Object ")
            .is_some_and(|n| !n.is_empty() && n.bytes().all(|c| c.is_ascii_digit()))
}

fn looks_like_path(v: &str) -> bool {
    let l = v.to_ascii_lowercase();
    l.contains("file:/")
        || v.starts_with("\\\\")
        || v.as_bytes().get(1..3) == Some(b":\\")
        || l.contains("/home/")
        || l.contains("/users/")
        || l.contains("vnd.sun.star.expand")
}

pub(crate) fn clean_odf(
    bytes: &[u8],
    opts: &CleanOptions,
    limits: &Limits,
) -> Result<CleanOutput, MetaError> {
    let mut ar = ZipArchive::new(Cursor::new(bytes)).map_err(zerr)?;
    if ar.len() > limits.max_entries {
        return Err(MetaError::TooManyEntries(format!("{} записей", ar.len())));
    }
    let names: Vec<String> = (0..ar.len())
        .map(|i| {
            ar.by_index_raw(i)
                .map_err(zerr)
                .and_then(|f| f.name().map(|n| n.to_string()).map_err(zerr))
        })
        .collect::<Result<_, _>>()?;
    let mut w = ZipWriter::new(Cursor::new(Vec::new()));
    let deflated = SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);
    let stored = SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
    let mut budget = limits.max_unzipped_total;
    let mut read = |ar: &mut ZipArchive<Cursor<&[u8]>>, i: usize| -> Result<Vec<u8>, MetaError> {
        let mut data = Vec::new();
        let f = ar.by_index(i).map_err(zerr)?;
        f.take(budget.saturating_add(1))
            .read_to_end(&mut data)
            .map_err(zerr)?;
        if data.len() as u64 > budget {
            return Err(MetaError::ZipBomb("ODF: распаковано больше бюджета".into()));
        }
        budget -= data.len() as u64;
        Ok(data)
    };

    // mimetype first, uncompressed (ODF 1.2 part 3, 3.3)
    if let Some(i) = names.iter().position(|n| n == "mimetype") {
        let data = read(&mut ar, i)?;
        w.start_file("mimetype", stored).map_err(zerr)?;
        w.write_all(&data).map_err(zerr)?;
    }
    let encrypted = names
        .iter()
        .position(|n| n == "META-INF/manifest.xml")
        .map(|i| read(&mut ar, i))
        .transpose()?
        .is_some_and(|m| crate::util::find(&m, b"encryption-data", 0).is_some());

    let mut thumbs = 0u32;
    let mut versions = 0u32;
    let mut signatures = 0u32;
    let mut authors = 0u32;
    let mut objects = Vec::new();
    for (i, name) in names.iter().enumerate() {
        if name == "mimetype" {
            continue;
        }
        if is_binary_object(name) {
            objects.push(name.clone());
        }
        let action = classify(name);
        match action {
            Action::Drop => {
                let n = name.trim_start_matches('/');
                if n.starts_with("Thumbnails/") {
                    thumbs += u32::from(!name.ends_with('/'));
                } else if n.starts_with("META-INF/") {
                    signatures += 1;
                } else {
                    versions += u32::from(!name.ends_with('/'));
                }
                continue;
            }
            Action::Keep => {
                let f = ar.by_index_raw(i).map_err(zerr)?;
                w.raw_copy_file(f).map_err(zerr)?;
                continue;
            }
            // In an encrypted package only the manifest and meta.xml are plain text.
            Action::Rewrite(Part::Content | Part::Settings) | Action::Picture if encrypted => {
                let f = ar.by_index_raw(i).map_err(zerr)?;
                w.raw_copy_file(f).map_err(zerr)?;
                continue;
            }
            _ => {}
        }
        let data = read(&mut ar, i)?;
        let out = match action {
            // encrypted entries are not XML: copied as is
            Action::Rewrite(_) if encrypted && !looks_like_xml(&data) => data,
            Action::Rewrite(part) => {
                let (x, n) = rewrite(&data, part, opts)?;
                authors += n;
                x
            }
            Action::Picture => match detect(&data) {
                DocFormat::Jpeg => clean_jpeg(&data).unwrap_or(data),
                DocFormat::Png => clean_png(&data).unwrap_or(data),
                _ => data,
            },
            Action::Keep | Action::Drop => data,
        };
        w.start_file(name.as_str(), deflated).map_err(zerr)?;
        w.write_all(&out).map_err(zerr)?;
    }
    let bytes = w.finish().map_err(zerr)?.into_inner();
    let mut warnings = Vec::new();
    if signatures > 0 {
        warnings.push(CleanWarning::SignatureRemoved { count: signatures });
    }
    if thumbs > 0 {
        warnings.push(CleanWarning::ThumbnailRemoved);
    }
    if versions > 0 {
        warnings.push(CleanWarning::VersionsRemoved { count: versions });
    }
    if authors > 0 {
        warnings.push(CleanWarning::AnnotationAuthorsRemoved { count: authors });
    }
    if encrypted {
        warnings.push(CleanWarning::EncryptedContentKept);
    }
    for name in objects.into_iter().take(50) {
        warnings.push(CleanWarning::EmbeddedObjectKept { name });
    }
    Ok(CleanOutput { bytes, warnings })
}

fn looks_like_xml(d: &[u8]) -> bool {
    let d = d.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(d);
    d.iter().find(|c| !c.is_ascii_whitespace()) == Some(&b'<')
}

fn attr_value(e: &BytesStart, key: &str) -> Option<String> {
    e.attributes()
        .with_checks(false)
        .flatten()
        .find(|a| a.key.as_ref() == key)
        .map(|a| a.value.to_string())
}

/// Rewrites one XML part; returns the new bytes and the number of blanked authors.
fn rewrite(data: &[u8], part: Part, opts: &CleanOptions) -> Result<(Vec<u8>, u32), MetaError> {
    let s = decode_text(data);
    let mut r = Reader::from_str(&s);
    r.config_mut().check_end_names = false;
    r.config_mut().allow_unmatched_ends = true;
    // a stray `&` in text is kept as is (seen in hand-edited documents)
    r.config_mut().allow_dangling_amp = true;
    let mut w = Writer::new(Vec::with_capacity(data.len()));
    let mut depth = 0usize;
    // depth of `office:meta` (Meta) while inside it
    let mut meta_depth: Option<usize> = None;
    // skip everything until depth drops below this value
    let mut skip_below: Option<usize> = None;
    // inside an author element whose text is blanked
    let mut blank = 0usize;
    let mut blanked = 0u32;
    // settings: a buffered config-item (events, text) decided at its end
    let mut item: Option<(Vec<Event<'static>>, String)> = None;
    loop {
        let ev = r.read_event().map_err(xerr)?;
        if let Some(lim) = skip_below {
            match &ev {
                Event::Start(_) => depth += 1,
                Event::End(_) => {
                    depth = depth.saturating_sub(1);
                    if depth < lim {
                        skip_below = None;
                    }
                }
                Event::Eof => break,
                _ => {}
            }
            continue;
        }
        match ev {
            Event::Eof => break,
            Event::Start(e) => {
                depth += 1;
                let name = e.name().as_ref().to_string();
                match part {
                    Part::Meta => {
                        if meta_depth.is_some_and(|m| depth == m + 1)
                            && name != "meta:document-statistic"
                        {
                            skip_below = Some(depth);
                            continue;
                        }
                        if name == "office:meta" {
                            meta_depth = Some(depth);
                        }
                    }
                    Part::Settings => {
                        if name == "config:config-item" {
                            item = Some((vec![Event::Start(e.into_owned())], String::new()));
                            continue;
                        }
                    }
                    Part::Content => {
                        if opts.remove_annotation_authors
                            && matches!(name.as_str(), "dc:creator" | "meta:creator-initials")
                        {
                            blank += 1;
                            blanked += 1;
                        }
                    }
                    Part::Manifest => {}
                }
                w.write_event(Event::Start(e)).map_err(xerr)?;
            }
            Event::Empty(e) => {
                let name = e.name().as_ref().to_string();
                let drop = match part {
                    Part::Meta => {
                        meta_depth.is_some_and(|m| depth == m) && name != "meta:document-statistic"
                    }
                    Part::Manifest => {
                        name == "manifest:file-entry"
                            && attr_value(&e, "manifest:full-path")
                                .is_some_and(|p| is_removed_path(&p))
                    }
                    Part::Settings => {
                        name == "config:config-item"
                            && attr_value(&e, "config:name")
                                .is_some_and(|n| SETTINGS_DROP.contains(&n.as_str()))
                    }
                    Part::Content => false,
                };
                if !drop {
                    w.write_event(Event::Empty(e)).map_err(xerr)?;
                }
            }
            Event::End(e) => {
                depth = depth.saturating_sub(1);
                if part == Part::Meta && meta_depth.is_some_and(|m| depth < m) {
                    meta_depth = None;
                }
                if let Some((events, text)) = item.take() {
                    let name = match events.first() {
                        Some(Event::Start(s)) => attr_value(s, "config:name").unwrap_or_default(),
                        _ => String::new(),
                    };
                    let drop = SETTINGS_DROP.contains(&name.as_str()) || looks_like_path(&text);
                    if !drop {
                        for ev in events {
                            w.write_event(ev).map_err(xerr)?;
                        }
                        w.write_event(Event::End(e)).map_err(xerr)?;
                    }
                    continue;
                }
                blank = blank.saturating_sub(1);
                w.write_event(Event::End(e)).map_err(xerr)?;
            }
            Event::Text(t) => {
                if let Some((events, text)) = item.as_mut() {
                    text.push_str(&t.xml10_content());
                    events.push(Event::Text(t.into_owned()));
                    continue;
                }
                if blank == 0 {
                    w.write_event(Event::Text(t)).map_err(xerr)?;
                }
            }
            Event::GeneralRef(g) => {
                if let Some((events, _)) = item.as_mut() {
                    events.push(Event::GeneralRef(g.into_owned()));
                    continue;
                }
                if blank == 0 {
                    w.write_event(Event::GeneralRef(g)).map_err(xerr)?;
                }
            }
            other => {
                if item.is_none() && blank == 0 {
                    w.write_event(other).map_err(xerr)?;
                }
            }
        }
    }
    Ok((w.into_inner(), blanked))
}
