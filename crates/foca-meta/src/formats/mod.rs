//! Format parsers, one module per format family, and signature-based format detection.

pub(crate) mod archive;
pub(crate) mod detect;
pub(crate) mod lnk;
pub(crate) mod mail;
pub(crate) mod media;
pub(crate) mod office;
pub(crate) mod pdf;
pub(crate) mod remote;
pub(crate) mod signature;
