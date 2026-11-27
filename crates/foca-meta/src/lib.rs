//! Extraction and removal of document metadata.
//!
//! Pure functions with no network or filesystem access: bytes in, [`Metadata`] out.
//!
//! * [`extract`]: metadata; the format is detected by signature, the file name is only a hint
//!   for text formats (RDP/ICA).
//! * [`text`]: plain text used to search for secrets.
//! * [`clean`]/[`clean_with_options`]: metadata removal (OOXML, ODF, PDF, JPEG, PNG);
//!   [`clean_and_verify`] re-extracts the result and diffs the fields.
//! * [`grade_document`]/[`grade_set`]: document hygiene grade A-F with fix steps.
//! * [`detect`]: format detection only.
//!
//! # Security
//!
//! Input files are untrusted: no `unwrap`/`panic` on input data, every size is checked, and
//! decompression is bounded by [`Limits`] (one decompression budget for the whole document,
//! embedded files included). Embedding recursion depth and XML nesting are limited. The XML
//! parser (quick-xml) does not expand external or custom entities, so `&xxe;` stays literal
//! text. PDF references are resolved with a depth limit and cycle protection.

use std::cell::Cell;

use foca_core::Embedded;
pub use foca_core::{DocFormat, Metadata};

mod clean;
mod formats;
mod hygiene;
mod paths;
pub mod thumbcmp;
mod util;
mod verify;
mod xml;
mod xmp;
mod zipx;

use formats::archive::{compressed, epub, rar, sevenz, tar, zipfile};
use formats::binary::{jar, pe};
use formats::detect::detect_with_hint;
use formats::mail::{eml, ics, msg, vcf};
use formats::media::{av, image, indesign, isobmff, mp3, postscript, psd, svg};
use formats::office::{legacy_office, odf, ole, ooxml, publisher, visio};
use formats::{cad, dev, geo, lnk, pdf, remote};

pub use clean::{
    can_clean, clean, clean_with_limits, clean_with_options, CleanOptions, CleanOutput,
    CleanWarning,
};
pub use formats::archive::zipfile::for_each_zip_member;
pub use formats::detect::detect;
pub use hygiene::{
    grade_document, grade_set, FixCode, FixStep, Grade, HygieneIssue, HygieneReport, IssueCode,
    SetHygiene,
};
pub use paths::{analyze_path, find_emails, find_paths, PathInfo};
pub use verify::{
    clean_and_verify, verify_clean, ChangeKind, CleanResult, FieldChange, VerifyReport,
};

/// Parsing limits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Limits {
    /// Maximum input file size in bytes.
    pub max_file: u64,
    /// Total decompressed data (zip entries, PDF streams, embedded files) in bytes.
    pub max_unzipped_total: u64,
    /// Maximum number of archive entries, PDF objects or OLE streams.
    pub max_entries: usize,
    /// Maximum recursion depth into embedded files (0 disables embedded parsing).
    pub max_depth: u32,
    /// Maximum nesting of XML elements and PDF objects.
    pub max_xml_depth: usize,
    /// Maximum number of nodes in a single XML document.
    pub max_xml_nodes: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            max_file: 200 * 1024 * 1024,
            max_unzipped_total: 256 * 1024 * 1024,
            max_entries: 20_000,
            max_depth: 3,
            max_xml_depth: 256,
            max_xml_nodes: 500_000,
        }
    }
}

/// Parse error.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MetaError {
    #[error("файл слишком большой: {size} байт (лимит {limit})")]
    TooLarge { size: u64, limit: u64 },
    #[error("превышен лимит распаковки (возможна zip-бомба): {0}")]
    ZipBomb(String),
    #[error("слишком много элементов: {0}")]
    TooManyEntries(String),
    #[error("слишком глубокая вложенность: {0}")]
    TooDeep(String),
    #[error("формат не поддерживается: {0}")]
    Unsupported(String),
    #[error("повреждённый файл {format}: {msg}")]
    Malformed { format: &'static str, msg: String },
}

impl MetaError {
    pub(crate) fn malformed(format: &'static str, msg: impl ToString) -> Self {
        MetaError::Malformed {
            format,
            msg: msg.to_string(),
        }
    }
}

/// Maximum number of parsed children per container (archive, message, contact list).
pub(crate) const MAX_CHILDREN: usize = 200;

/// Parses an embedded document; `None` when its format is not recognised.
type ExtractEmbedded = fn(&[u8], &str, &Ctx) -> Option<Result<Metadata, MetaError>>;

/// Per-call context: limits, current depth, the shared decompression budget and the parser for
/// embedded documents.
pub(crate) struct Ctx<'a> {
    limits: &'a Limits,
    depth: u32,
    budget: &'a Cell<u64>,
    embedded: Option<ExtractEmbedded>,
}

impl<'a> Ctx<'a> {
    /// A context for a single document that never descends into embedded documents.
    pub fn standalone(limits: &'a Limits, budget: &'a Cell<u64>) -> Self {
        Ctx {
            limits,
            depth: 0,
            budget,
            embedded: None,
        }
    }

    /// A top-level context that parses embedded documents with `embedded`.
    fn with_embedded(limits: &'a Limits, budget: &'a Cell<u64>, embedded: ExtractEmbedded) -> Self {
        Ctx {
            embedded: Some(embedded),
            ..Ctx::standalone(limits, budget)
        }
    }

    /// The context of a document embedded one level deeper, sharing the budget.
    pub fn nested(&self) -> Ctx<'a> {
        Ctx {
            limits: self.limits,
            depth: self.depth + 1,
            budget: self.budget,
            embedded: self.embedded,
        }
    }

    /// Maximum number of entries in one container (archive entries, PDF objects, OLE streams).
    pub fn max_entries(&self) -> usize {
        self.limits.max_entries
    }

    /// Maximum nesting of XML elements and PDF objects.
    pub fn max_xml_depth(&self) -> usize {
        self.limits.max_xml_depth
    }

    /// Maximum number of nodes in one XML document.
    pub fn max_xml_nodes(&self) -> usize {
        self.limits.max_xml_nodes
    }

    /// Maximum size of a single file or member in bytes.
    pub fn max_file(&self) -> u64 {
        self.limits.max_file
    }

    /// The whole decompression budget of the document in bytes.
    pub fn max_unzipped_total(&self) -> u64 {
        self.limits.max_unzipped_total
    }

    /// Returns `true` while embedded documents may still be parsed at this depth.
    pub fn can_descend(&self) -> bool {
        self.depth < self.limits.max_depth
    }

    /// Charges `n` bytes against the decompression budget.
    pub fn spend(&self, n: u64) -> Result<(), MetaError> {
        let left = self.budget.get();
        if n > left {
            return Err(MetaError::ZipBomb(format!(
                "распаковано больше {} байт",
                self.limits.max_unzipped_total
            )));
        }
        self.budget.set(left - n);
        Ok(())
    }

    /// Returns the remaining budget.
    pub fn remaining(&self) -> u64 {
        self.budget.get()
    }

    /// Parses an embedded document recursively. Returns `None` if the depth limit is reached or the format is unknown.
    pub fn extract_child(&self, bytes: &[u8], name: &str) -> Option<Result<Metadata, MetaError>> {
        if !self.can_descend() {
            return None;
        }
        let extract = self.embedded?;
        extract(bytes, name, &self.nested())
    }

    /// Parses an embedded document and attaches it to `meta` under `label` (up to
    /// [`MAX_CHILDREN`]). An exhausted decompression budget aborts the parent (zip bomb); other
    /// child errors become warnings. Unknown formats and the depth limit are silently skipped.
    pub fn attach_child(
        &self,
        meta: &mut Metadata,
        bytes: &[u8],
        name: &str,
        label: &str,
    ) -> Result<(), MetaError> {
        if meta.embedded.len() >= MAX_CHILDREN {
            return Ok(());
        }
        match self.extract_child(bytes, name) {
            Some(Ok(m)) => meta.embedded.push(Embedded {
                name: util::truncate(label, 512),
                metadata: Box::new(m),
            }),
            Some(Err(e @ MetaError::ZipBomb(_))) => return Err(e),
            Some(Err(e)) => meta
                .warnings
                .push(format!("{}: {e}", util::truncate(label, 128))),
            None => {}
        }
        Ok(())
    }
}

fn check_size(bytes: &[u8], limits: &Limits) -> Result<(), MetaError> {
    let size = bytes.len() as u64;
    if size > limits.max_file {
        return Err(MetaError::TooLarge {
            size,
            limit: limits.max_file,
        });
    }
    Ok(())
}

/// Extracts metadata from a document.
///
/// `name_hint` is the file name; it never affects binary formats and only disambiguates text
/// formats.
///
/// # Errors
///
/// Returns [`MetaError::Unsupported`] for an unknown format, or another [`MetaError`] if the
/// file exceeds the limits or cannot be parsed.
pub fn extract(
    bytes: &[u8],
    name_hint: Option<&str>,
    limits: &Limits,
) -> Result<Metadata, MetaError> {
    check_size(bytes, limits)?;
    let budget = Cell::new(limits.max_unzipped_total);
    let ctx = Ctx::with_embedded(limits, &budget, extract_embedded);
    // The whole per-file parse (parser plus path post-processing) runs under catch_unwind.
    guard("документ", || extract_ctx(bytes, name_hint, &ctx))
}

/// Parses an embedded document whose format is recognised by its signature (and name).
fn extract_embedded(bytes: &[u8], name: &str, ctx: &Ctx) -> Option<Result<Metadata, MetaError>> {
    if detect_with_hint(bytes, Some(name)) == DocFormat::Unknown {
        return None;
    }
    Some(extract_ctx(bytes, Some(name), ctx))
}

fn extract_ctx(bytes: &[u8], name_hint: Option<&str>, ctx: &Ctx) -> Result<Metadata, MetaError> {
    let format = detect_with_hint(bytes, name_hint);
    let mut meta = match format {
        DocFormat::Docx | DocFormat::Xlsx | DocFormat::Pptx => ooxml::extract(bytes, format, ctx)?,
        DocFormat::Odt | DocFormat::Ods | DocFormat::Odp | DocFormat::Odg | DocFormat::Sxw => {
            odf::extract(bytes, format, ctx)?
        }
        DocFormat::Pdf => pdf::extract(bytes, ctx)?,
        DocFormat::Jpeg | DocFormat::Png | DocFormat::Tiff => image::extract(bytes, format, ctx)?,
        DocFormat::Doc | DocFormat::Xls | DocFormat::Ppt | DocFormat::Ole | DocFormat::Msi => {
            ole::extract(bytes, format, ctx)?
        }
        DocFormat::Exe => pe::extract(bytes, ctx)?,
        DocFormat::Jar | DocFormat::Apk => jar::extract(bytes, format, ctx)?,
        DocFormat::Svg => svg::extract(bytes, ctx)?,
        DocFormat::Rdp => remote::extract_rdp(bytes),
        DocFormat::Ica => remote::extract_ica(bytes),
        DocFormat::Lnk => lnk::extract(bytes, ctx)?,
        DocFormat::Eml => eml::extract(bytes, ctx)?,
        DocFormat::Msg => msg::extract(bytes, ctx)?,
        DocFormat::Vsdx => visio::extract_vsdx(bytes, ctx)?,
        DocFormat::Vsd => visio::extract_vsd(bytes, ctx)?,
        DocFormat::Pub => publisher::extract(bytes, ctx)?,
        DocFormat::Indd => indesign::extract(bytes, ctx)?,
        DocFormat::Wpd => legacy_office::extract_wpd(bytes, ctx)?,
        DocFormat::Wps | DocFormat::Wks => legacy_office::extract_works(bytes, format, ctx)?,
        DocFormat::Ics => ics::extract(bytes, ctx)?,
        DocFormat::Vcf => vcf::extract(bytes, ctx)?,
        DocFormat::Mp4 | DocFormat::Mov | DocFormat::Heic => isobmff::extract(bytes, format, ctx)?,
        DocFormat::Zip => zipfile::extract(bytes, ctx)?,
        DocFormat::Epub => epub::extract(bytes, ctx)?,
        DocFormat::Mp3 => mp3::extract(bytes, ctx)?,
        DocFormat::Psd => psd::extract(bytes, ctx)?,
        DocFormat::SevenZ => sevenz::extract(bytes, ctx)?,
        DocFormat::Tar => tar::extract(bytes, ctx)?,
        DocFormat::Gzip => compressed::extract_gzip(bytes, name_hint, ctx)?,
        DocFormat::Bzip2 => compressed::extract_bzip2(bytes),
        DocFormat::Xz => compressed::extract_xz(bytes),
        DocFormat::Rar => rar::extract(bytes, ctx)?,
        DocFormat::Dwg => cad::extract_dwg(bytes, ctx)?,
        DocFormat::Dxf => cad::extract_dxf(bytes, ctx)?,
        DocFormat::Eps => postscript::extract_eps(bytes, ctx)?,
        DocFormat::Emf => postscript::extract_emf(bytes),
        DocFormat::Wmf => postscript::extract_wmf(bytes),
        DocFormat::Wav | DocFormat::Avi => av::extract_riff(bytes, format, ctx)?,
        DocFormat::Mkv => av::extract_mkv(bytes)?,
        DocFormat::Asf => av::extract_asf(bytes)?,
        DocFormat::Flac => av::extract_flac(bytes)?,
        DocFormat::Ogg => av::extract_ogg(bytes)?,
        DocFormat::Kml => geo::extract_kml(bytes, ctx)?,
        DocFormat::Kmz => geo::extract_kmz(bytes, ctx)?,
        DocFormat::Gpx => geo::extract_gpx(bytes, ctx)?,
        DocFormat::SourceMap => dev::extract_sourcemap(bytes)?,
        DocFormat::Ipynb => dev::extract_notebook(bytes)?,
        DocFormat::Unknown => return Err(MetaError::Unsupported("неизвестная сигнатура".into())),
    };
    meta.format = format;
    if format == DocFormat::Exe {
        pe::finish(&mut meta);
    }
    paths::finalize(&mut meta);
    if matches!(format, DocFormat::Eml | DocFormat::Msg) {
        eml::drop_message_ids(&mut meta);
    }
    Ok(meta)
}

/// Returns the plain text of a document for secret scanning: OOXML, ODF, PDF (strings from
/// content streams, ignoring font encodings), SVG, RDP/ICA and OLE2 (text strings in streams).
/// For images, returns the EXIF/XMP text fields.
///
/// # Errors
///
/// Returns [`MetaError`] if the format is unsupported or the limits are exceeded.
pub fn text(bytes: &[u8], limits: &Limits) -> Result<String, MetaError> {
    check_size(bytes, limits)?;
    let budget = Cell::new(limits.max_unzipped_total);
    let ctx = Ctx::with_embedded(limits, &budget, extract_embedded);
    guard("документ", || text_ctx(bytes, &ctx))
}

fn text_ctx(bytes: &[u8], ctx: &Ctx) -> Result<String, MetaError> {
    match detect(bytes) {
        DocFormat::Docx | DocFormat::Xlsx | DocFormat::Pptx => ooxml::text(bytes, ctx),
        DocFormat::Odt | DocFormat::Ods | DocFormat::Odp | DocFormat::Odg | DocFormat::Sxw => {
            odf::text(bytes, ctx)
        }
        DocFormat::Pdf => pdf::text(bytes, ctx),
        DocFormat::Svg => svg::text(bytes, ctx),
        DocFormat::Rdp | DocFormat::Ica => Ok(util::decode_text(bytes)),
        DocFormat::Doc | DocFormat::Xls | DocFormat::Ppt | DocFormat::Ole => ole::text(bytes, ctx),
        DocFormat::Jpeg | DocFormat::Png | DocFormat::Tiff => {
            let m = image::extract(bytes, DocFormat::Jpeg, ctx)?;
            let mut out = String::new();
            for v in [&m.title, &m.description, &m.author, &m.keywords]
                .into_iter()
                .flatten()
            {
                out.push_str(v);
                out.push('\n');
            }
            for v in m.xmp.values().chain(m.fields.values()) {
                out.push_str(v);
                out.push('\n');
            }
            Ok(out)
        }
        DocFormat::Eml => eml::text(bytes, ctx),
        DocFormat::Msg => msg::text(bytes, ctx),
        DocFormat::Ics | DocFormat::Vcf | DocFormat::Dxf | DocFormat::Kml | DocFormat::Gpx => {
            Ok(util::decode_text(bytes))
        }
        DocFormat::SourceMap => dev::sourcemap_text(bytes),
        DocFormat::Ipynb => dev::notebook_text(bytes),
        DocFormat::Vsdx => visio::text_vsdx(bytes, ctx),
        DocFormat::Vsd | DocFormat::Pub | DocFormat::Wps | DocFormat::Msi => ole::text(bytes, ctx),
        DocFormat::Lnk
        | DocFormat::Indd
        | DocFormat::Wpd
        | DocFormat::Wks
        | DocFormat::Mp4
        | DocFormat::Mov
        | DocFormat::Heic
        | DocFormat::Zip
        | DocFormat::Epub
        | DocFormat::Mp3
        | DocFormat::Psd
        | DocFormat::SevenZ
        | DocFormat::Exe
        | DocFormat::Jar
        | DocFormat::Apk
        | DocFormat::Tar
        | DocFormat::Gzip
        | DocFormat::Bzip2
        | DocFormat::Xz
        | DocFormat::Rar
        | DocFormat::Dwg
        | DocFormat::Eps
        | DocFormat::Emf
        | DocFormat::Wmf
        | DocFormat::Wav
        | DocFormat::Avi
        | DocFormat::Mkv
        | DocFormat::Asf
        | DocFormat::Flac
        | DocFormat::Ogg
        | DocFormat::Kmz => extract_ctx(bytes, None, ctx).map(|m| metadata_text(&m)),
        DocFormat::Unknown => Err(MetaError::Unsupported("неизвестная сигнатура".into())),
    }
}

/// Text fields of parsed metadata (and of embedded documents), one value per line.
fn metadata_text(m: &Metadata) -> String {
    let mut out = String::new();
    let mut push = |v: &str| {
        if out.len() < 4 << 20 {
            out.push_str(v);
            out.push('\n');
        }
    };
    for v in [&m.title, &m.subject, &m.description, &m.author, &m.keywords]
        .into_iter()
        .flatten()
    {
        push(v);
    }
    for v in m
        .xmp
        .values()
        .chain(m.fields.values())
        .chain(m.custom.values())
    {
        push(v);
    }
    for c in &m.comments {
        push(&c.text);
    }
    for e in &m.embedded {
        let t = metadata_text(&e.metadata);
        push(&t);
    }
    out
}

/// Runs third-party parsing code with panic catching. This is only a safety net: Android
/// release builds use `panic=abort`, so the real protection is validating input beforehand.
pub(crate) fn guard<T>(
    what: &'static str,
    f: impl FnOnce() -> Result<T, MetaError>,
) -> Result<T, MetaError> {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)) {
        Ok(r) => r,
        Err(_) => Err(MetaError::malformed(what, "внутренняя ошибка парсера")),
    }
}

#[cfg(test)]
mod tests;
