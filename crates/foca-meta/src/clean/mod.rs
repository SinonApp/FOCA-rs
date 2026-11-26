//! Metadata removal: the public cleaning entry points and the per-format dispatch.
//!
//! Format cleaners live in submodules: OOXML ([`ooxml`]), ODF ([`odf`]), PDF ([`pdf`]) and
//! JPEG/PNG ([`raster`]); OLE2 and ISO BMFF files are rewritten by their format parsers. The
//! self-check (re-extraction and field diff) lives in [`crate::verify`].

use foca_core::DocFormat;

use crate::{detect, Limits, MetaError};

mod odf;
mod ooxml;
mod output;
mod pdf;
mod raster;

pub use output::{CleanOptions, CleanOutput, CleanWarning};
use raster::{clean_jpeg, clean_png};

/// Cleans a document with the default limits. `kind` is the expected format, verified against the signature.
///
/// # Errors
///
/// Returns [`MetaError`] if the file is too large, its signature does not match `kind`, the
/// format cannot be cleaned, or parsing fails within the limits.
pub fn clean(bytes: &[u8], kind: DocFormat) -> Result<Vec<u8>, MetaError> {
    clean_with_limits(bytes, kind, &Limits::default())
}

/// Cleans a document with the default options; see [`clean`].
///
/// # Errors
///
/// See [`clean`].
pub fn clean_with_limits(
    bytes: &[u8],
    kind: DocFormat,
    limits: &Limits,
) -> Result<Vec<u8>, MetaError> {
    clean_with_options(bytes, kind, &CleanOptions::default(), limits).map(|o| o.bytes)
}

/// Cleans a document and reports what the user must know (removed signatures, collapsed
/// revisions, kept embedded objects).
///
/// Supported: OOXML, ODF (ODT/ODS/ODP/ODG), PDF, JPEG, PNG.
///
/// # Errors
///
/// Returns [`MetaError`] if the file is too large, its signature does not match `kind`, the
/// format cannot be cleaned, the PDF is encrypted, or parsing fails within the limits.
pub fn clean_with_options(
    bytes: &[u8],
    kind: DocFormat,
    opts: &CleanOptions,
    limits: &Limits,
) -> Result<CleanOutput, MetaError> {
    if bytes.len() as u64 > limits.max_file {
        return Err(MetaError::TooLarge {
            size: bytes.len() as u64,
            limit: limits.max_file,
        });
    }
    let actual = detect(bytes);
    let compatible = actual == kind
        || (kind.is_ooxml() && actual.is_ooxml())
        || (is_odf(kind) && is_odf(actual))
        || (is_ole(kind) && is_ole(actual));
    if !compatible {
        return Err(MetaError::Unsupported(format!(
            "ожидался {kind:?}, по сигнатуре {actual:?}"
        )));
    }
    let plain = |r: Result<Vec<u8>, MetaError>| {
        r.map(|bytes| CleanOutput {
            bytes,
            warnings: Vec::new(),
        })
    };
    match kind {
        DocFormat::Docx | DocFormat::Xlsx | DocFormat::Pptx => {
            crate::guard("zip", || ooxml::clean_ooxml(bytes, limits)).map(signatures_removed)
        }
        DocFormat::Odt | DocFormat::Ods | DocFormat::Odp | DocFormat::Odg => {
            crate::guard("zip", || odf::clean_odf(bytes, opts, limits))
        }
        DocFormat::Pdf => crate::guard("pdf", || pdf::clean_pdf(bytes, opts, limits)),
        DocFormat::Jpeg => plain(clean_jpeg(bytes)),
        DocFormat::Png => plain(clean_png(bytes)),
        DocFormat::Doc
        | DocFormat::Xls
        | DocFormat::Ppt
        | DocFormat::Vsd
        | DocFormat::Pub
        | DocFormat::Ole => crate::guard("ole", || {
            crate::formats::office::ole::clean_ole(bytes, limits)
        })
        .map(signatures_removed),
        DocFormat::Mp4 | DocFormat::Mov | DocFormat::Heic => crate::guard("isobmff", || {
            plain(crate::formats::media::isobmff::clean_isobmff(bytes))
        }),
        other => Err(MetaError::Unsupported(format!(
            "очистка {other:?} пока не поддерживается"
        ))),
    }
}

/// Returns true for the formats [`clean`] supports.
#[must_use]
pub fn can_clean(kind: DocFormat) -> bool {
    kind.is_ooxml()
        || is_odf(kind)
        || is_ole(kind)
        || matches!(
            kind,
            DocFormat::Pdf
                | DocFormat::Jpeg
                | DocFormat::Png
                | DocFormat::Mp4
                | DocFormat::Mov
                | DocFormat::Heic
        )
}

fn is_ole(kind: DocFormat) -> bool {
    matches!(
        kind,
        DocFormat::Doc
            | DocFormat::Xls
            | DocFormat::Ppt
            | DocFormat::Vsd
            | DocFormat::Pub
            | DocFormat::Ole
    )
}

fn is_odf(kind: DocFormat) -> bool {
    matches!(
        kind,
        DocFormat::Odt | DocFormat::Ods | DocFormat::Odp | DocFormat::Odg
    )
}

/// Wraps a rewritten file whose only notable change is the removal of `sigs` signatures.
fn signatures_removed((bytes, sigs): (Vec<u8>, u32)) -> CleanOutput {
    CleanOutput {
        bytes,
        warnings: if sigs > 0 {
            vec![CleanWarning::SignatureRemoved { count: sigs }]
        } else {
            Vec::new()
        },
    }
}
