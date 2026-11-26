//! Report sections shared by the format writers: each prepares its own rows and renders them
//! as HTML, Markdown and DOCX tables.

pub mod custody;
pub(crate) mod forensics;
pub(crate) mod infra;
pub(crate) mod ports;
pub(crate) mod recon;
