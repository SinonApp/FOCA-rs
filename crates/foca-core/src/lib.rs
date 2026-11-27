//! Data model of FOCA-rs: projects, targets and scope, documents and their metadata,
//! entities, findings, scan events and the time source.
//!
//! The crate has no Android, UI or network dependencies; it is shared by `foca-meta`, the
//! application and the CLI.

pub mod api;
pub mod b64;
pub mod clock;
pub mod extractor;
pub mod forensics;
pub mod lang;
pub mod metadata;
pub mod model;
pub mod reqlog;
pub mod scope;
pub mod severity;
pub mod target;

pub use clock::{Clock, ManualClock, SystemClock};
pub use forensics::*;
pub use lang::Lang;
pub use metadata::*;
pub use model::*;
pub use scope::{LineError, Scope, ScopeDenied};
pub use severity::Severity;
pub use target::{normalize_domain, Target, TargetError};
