//! Command handlers grouped by domain (projects, findings, documents, reports, AI, security,
//! extensions, import/export, quick tools); `facade` routes every contract command to them.

mod ai;
pub(crate) mod bundle;
mod config;
pub(crate) mod demo_case;
mod documents;
mod extensions;
mod findings;
pub(crate) mod hygiene;
pub(crate) mod offline;
pub(crate) mod projects;
pub(crate) mod reextract;
mod reports;
mod scans;
mod security;
pub(crate) mod toolbox;
