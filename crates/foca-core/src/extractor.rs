//! Version of the document extraction (parsers and text) recorded with every analysed document.
//!
//! `FORMAT_REV` is bumped whenever `foca-meta` parsers or text extraction change so that
//! documents analysed earlier would give more or different data when parsed again. Documents with
//! a lower (or no) recorded revision are offered for re-analysis (`project_reextract`).

/// Revision of the document extraction. Documents analysed before 2.0.0-beta.4.1 carry none (0).
/// Revision 2: personal values and secrets are stored in full (earlier revisions stored masks,
/// re-analysis from the downloaded files restores the values).
pub const FORMAT_REV: u32 = 2;

/// Application version that analysed a document (all workspace crates share one version).
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
