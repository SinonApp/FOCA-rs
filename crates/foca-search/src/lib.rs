//! Discovery and download of target documents.
//!
//! * [`DocumentSource`]: a source of document URLs: [`sources::Wayback`] (CDX API),
//!   [`sources::CommonCrawl`], [`sources::CrtSh`] (subdomains for the crawler),
//!   [`sources::Crawler`] (crawls the target site, `TouchesTarget`), [`sources::Brave`] and
//!   [`sources::Searx`]. Source identifiers match `ui/js/demo-backend.js`: `wayback`, `cc`,
//!   `crt`, `crawler`, `brave`, `searx`.
//! * [`filter`]: extension filter, URL normalization and deduplication;
//!   [`urlinfo`]: URL analysis before download (users in paths, servers, folders).
//! * [`download`]: the downloader: HEAD (or an aborted GET), a size limit on the actual stream,
//!   temporary file, SHA-256, file named by hash, concurrency, retries, and task state through
//!   the [`download::TaskQueue`] trait (a `foca-store` implementation is behind the `store` feature).
//!
//! All network calls go through [`foca_net::NetClient`]: scope, request log, limits, cancellation.

pub mod crawl;
mod dorkboard;
pub mod download;
pub mod filter;
pub mod html;
pub mod rate;
pub mod render;
pub mod source;
pub mod sources;
pub mod storage;
#[cfg(feature = "store")]
pub mod store;
pub mod urlinfo;

pub use download::{DownloadConfig, Downloaded, Downloader, MemQueue, QueuedTask, TaskQueue};
pub use filter::{normalize_url, ExtFilter, DEFAULT_EXTS};
pub use foca_net::{BoxFuture, NetError};
pub use render::{RenderFetch, RenderPage, RenderRequest, RenderStep};
pub use source::{
    dedupe, pick_fair, run_sources, run_sources_ctl, DocumentSource, Found, FoundUrl, SearchCtx,
    SearchResult, SourceCtl, SourceKind, SourceReport, SourceStatus,
};
pub use urlinfo::{analyze_url, summarize_urls, UrlInfo, UrlSummary};
