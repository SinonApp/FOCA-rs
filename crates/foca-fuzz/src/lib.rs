//! Discovery of forgotten publicly accessible documents, backups and service files on a
//! client's website during an authorized audit (the counterpart of the original FOCA's
//! "Backups Fuzzer"; content discovery and soft-404 auto-calibration follow ffuf, wordlists
//! come from SecLists, both MIT, see `THIRD_PARTY.md`).
//!
//! * Active scan profile only: every request goes through [`foca_net::NetClient`] with
//!   `Access::Active`, so scope, exclusions (hosts/IPs plus [`FuzzConfig::exclude_paths`]),
//!   per-hop redirect checks and the request log all apply.
//! * Gentle defaults: 4 workers, 5 req/s, jitter, a request budget and `max_time`.
//! * Auto-stop on a run of 429/403/5xx/errors ("the site throttled requests, fuzzing
//!   stopped"). There are no evasion attempts (IP/UA rotation, path obfuscation), no parameter
//!   fuzzing, payloads or password guessing, and no dumping of repositories or databases.
//! * A hit records only the fact of availability and short masked evidence; files are never
//!   downloaded in full (at most [`FuzzConfig::body_limit`] bytes are read).
//!
//! ```no_run
//! # async fn demo(net: foca_net::NetClient) {
//! use foca_fuzz::{FuzzConfig, FuzzTask, Fuzzer, Module};
//! let task = FuzzTask::new("https://contoso.ua/".parse().unwrap(), vec![Module::Docs, Module::Backups]);
//! let report = Fuzzer::new(net, FuzzConfig::default()).run(&task).await;
//! println!("{} findings, {}", report.hits.len(), report.stop.message_ru());
//! # }
//! ```

pub mod calibrate;
pub mod config;
pub mod dsstore;
pub mod evidence;
pub mod listing;
pub mod mutate;
pub mod plan;
mod rand;
pub mod runner;
pub mod types;
pub mod wordlists;

pub use config::{AutoStop, Filters, FuzzConfig, StatusRange};
pub use plan::{
    estimate, Cms, ContentSpec, Estimate, FuzzTask, Template, VhostSpec, DOC_EXTENSIONS,
};
pub use runner::{EventFn, FuzzControl, Fuzzer, LOG_MODULE};
pub use types::{
    ArtifactSummary, FilterReason, Filtered, FuzzEvent, FuzzHit, FuzzReport, FuzzStats, HitKind,
    Module, Risk, StopReason,
};
pub use wordlists::Wordlist;
