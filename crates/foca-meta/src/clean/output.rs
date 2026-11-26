//! The cleaning vocabulary: options in, cleaned bytes and user-facing warnings out.

use serde::{Deserialize, Serialize};

/// Cleaning options. Signatures are always removed (any rewrite invalidates them) and reported
/// as [`CleanWarning::SignatureRemoved`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct CleanOptions {
    /// PDF: remove embedded files (`EmbeddedFiles`, file attachment annotations, `AF`).
    pub remove_embedded_files: bool,
    /// PDF: remove JavaScript, `AA` additional actions and non-`GoTo` `OpenAction`.
    pub remove_javascript: bool,
    /// PDF: remove `/T` (author) of markup annotations; ODF: blank annotation and tracked-change
    /// authors.
    pub remove_annotation_authors: bool,
}

impl Default for CleanOptions {
    fn default() -> Self {
        CleanOptions {
            remove_embedded_files: true,
            remove_javascript: true,
            remove_annotation_authors: true,
        }
    }
}

/// Something the user should know about a cleaned file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "code", rename_all = "snake_case")]
pub enum CleanWarning {
    /// Digital signatures were removed; the clean copy is no longer signed.
    SignatureRemoved {
        count: u32,
    },
    /// PDF incremental updates were collapsed into a single revision.
    RevisionsCollapsed {
        count: u32,
    },
    JavascriptRemoved {
        count: u32,
    },
    EmbeddedFilesRemoved {
        count: u32,
    },
    /// Embedded files were kept on request and may carry their own metadata.
    EmbeddedFilesKept,
    AnnotationAuthorsRemoved {
        count: u32,
    },
    /// ODF: the document thumbnail was removed.
    ThumbnailRemoved,
    /// ODF: stored older versions (`Versions/`, `VersionList.xml`) were removed.
    VersionsRemoved {
        count: u32,
    },
    /// ODF: a binary embedded object (OLE) was kept unchanged.
    EmbeddedObjectKept {
        name: String,
    },
    /// ODF: the package is encrypted; encrypted parts were copied unchanged.
    EncryptedContentKept,
}

/// A cleaned file with warnings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CleanOutput {
    pub bytes: Vec<u8>,
    pub warnings: Vec<CleanWarning>,
}
