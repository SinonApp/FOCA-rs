//! Scan engine and command facade of FOCA-rs.
//!
//! * [`Engine::open`] opens the store (the app data directory) and wires up a [`KeyProvider`]
//!   (Android Keystore bridge or in-memory), an [`EventSink`] (`app.emit("scan://event")`) and,
//!   optionally, a [`ReportBuilder`]. An unfinished scan from the previous process is recorded in
//!   the history as `stopped` / `restart`.
//! * [`Engine::invoke`] handles every contract command from `docs/API.md` (`project_*`,
//!   `scope_*`, `scan_*`, `finding_*`, `doc_*`, `oos_*`, `settings_*`, `key_*`, `report_*`,
//!   `export_build`, `ai_*`, `pin_*`, `wipe_all`, `net_check`, `secret_reveal`) and returns a
//!   `serde_json::Value` or a [`CmdError`] `{ code, message, targets? }`.
//! * A scan runs as a background tokio task through 9 stages, `search → download → meta →
//!   analysis → network → ports → recon → fuzz → report` (`scan::STAGES`), emitting
//!   `scan://event` events (`started/stage/progress/source/finding/db/done/stopped`). Stopping
//!   is immediate ([`CancellationToken`](tokio_util::sync::CancellationToken)), pausing is
//!   driven from outside ([`Engine::pause`] / [`Engine::resume`]), and `resume_from` continues
//!   from the download queue.
//!
//! # Integration (Tauri)
//!
//! ```ignore
//! let mut cfg = EngineConfig::new(app_data_dir);          // projects.db, *.foca, files/
//! cfg.export_dir = download_dir.join("FOCA-rs");
//! cfg.utc_offset = UtcOffset::from_whole_seconds(tz_offset_secs)?; // dates are local, without an offset
//! let events = Arc::new(FnEvents(move |ev: &Value| { let _ = app.emit("scan://event", ev); }));
//! let engine = Engine::open(cfg, Arc::new(KeystoreBridge), events)?;  // KeyProvider
//! // Tauri command: invoke(cmd, args) -> engine.invoke(&cmd, args).await (Err -> { code, message, targets? })
//! // network/battery/Wi-Fi: engine.pause("offline") / engine.resume(); VPN drop: invoke("scan_stop", {reason:"vpn"})
//! ```
//!
//! Stage 1.5: quick tools without a project (`tool_file`, `tool_mail_domain`, `tool_host`,
//! `tool_secret`, `tool_log`, `tool_log_clear`; [`toolbox`]) and the scan queue (`queue_*`; [`queue`]).
//!
//! One extra command outside the contract table: `doc_import { project, paths }` imports local
//! files without network access.
//!
//! Logging: `tracing` events from the engine, foca-search and foca-net go to a ring buffer and to
//! `<data>/logs/foca.log` ([`logs`]); see the `logs_get` command.

mod alerts;
mod analysis;
mod cmds;
mod debug;
mod dto;
mod engine;
mod facade;
mod queue;
mod run;
mod scan;
mod services;
mod settings;
mod util;

pub use analysis::{intel, redact, rules};
pub use debug::TERMS_VERSION;
pub use foca_recon::screenshot::{ScreenshotRaw, ScreenshotRequest, WebScreenshotter};
pub use scan::sources::{DOC_SOURCE_IDS, HOST_SOURCE_IDS, INFRA_SOURCE_IDS};
pub use services::ocr::{OcrProvider, OcrRequest, OcrResult};
pub use services::{i18n, licenses, logs, ocr, plugins, resume, selfupdate, sigbundle};

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use serde::Serialize;
use serde_json::Value;

pub use engine::Engine;
pub use foca_search::sources::verify_markers;
pub use foca_search::{BoxFuture, RenderFetch, RenderPage, RenderRequest, RenderStep};
#[cfg(feature = "report")]
pub use services::report::FocaReport;

/// Command error: `Err({ code, message, message_msg?, targets? })` (see the general rules in
/// `docs/API.md`); `message_msg` is the `{ code, params }` of a known core message.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{code}: {message}")]
pub struct CmdError {
    pub code: String,
    pub message: String,
    pub targets: Option<Vec<String>>,
}

impl Serialize for CmdError {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        let msg = i18n::classify(&self.message);
        let mut m = s.serialize_map(None)?;
        m.serialize_entry("code", &self.code)?;
        m.serialize_entry("message", &self.message)?;
        if let Some(msg) = &msg {
            m.serialize_entry("message_msg", msg)?;
        }
        if let Some(t) = &self.targets {
            m.serialize_entry("targets", t)?;
        }
        m.end()
    }
}

impl CmdError {
    pub fn new(code: &str, message: impl Into<String>) -> Self {
        CmdError {
            code: code.into(),
            message: message.into(),
            targets: None,
        }
    }
    pub fn not_found(m: impl Into<String>) -> Self {
        Self::new("not_found", m)
    }
    pub fn internal(m: impl std::fmt::Display) -> Self {
        Self::new("internal", m.to_string())
    }
}

impl From<foca_store::StoreError> for CmdError {
    fn from(e: foca_store::StoreError) -> Self {
        CmdError::new(e.code(), e.to_string())
    }
}

impl From<serde_json::Error> for CmdError {
    fn from(e: serde_json::Error) -> Self {
        CmdError::new("bad_args", e.to_string())
    }
}

impl From<std::io::Error> for CmdError {
    fn from(e: std::io::Error) -> Self {
        CmdError::internal(e)
    }
}

pub type CmdResult = Result<Value, CmdError>;

/// Scan event sink. In Tauri: `app.emit("scan://event", ev)`.
pub trait EventSink: Send + Sync {
    fn emit(&self, event: &Value);
}

/// Collects events in memory (tests, CLI).
#[derive(Default)]
pub struct MemoryEvents(Mutex<Vec<Value>>);

impl MemoryEvents {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn events(&self) -> Vec<Value> {
        self.0.lock().map(|g| g.clone()).unwrap_or_default()
    }
    pub fn clear(&self) {
        if let Ok(mut g) = self.0.lock() {
            g.clear()
        }
    }
}

impl EventSink for MemoryEvents {
    fn emit(&self, event: &Value) {
        if let Ok(mut g) = self.0.lock() {
            g.push(event.clone());
        }
    }
}

/// Forwards events to a closure (the CLI prints them, Tauri calls `app.emit`).
pub struct FnEvents<F: Fn(&Value) + Send + Sync>(pub F);

impl<F: Fn(&Value) + Send + Sync> EventSink for FnEvents<F> {
    fn emit(&self, event: &Value) {
        (self.0)(event)
    }
}

/// Store of API key values (the Android Keystore, outside the core). Only the mask reaches the UI.
pub trait KeyProvider: Send + Sync {
    fn get(&self, service: &str) -> Option<String>;
    fn set(&self, service: &str, value: &str) -> Result<(), String>;
    fn delete(&self, service: &str) -> Result<(), String>;
}

/// In-memory keys (tests, CLI).
#[derive(Default)]
pub struct MemoryKeys(Mutex<HashMap<String, String>>);

impl MemoryKeys {
    pub fn new() -> Self {
        Self::default()
    }
}

impl KeyProvider for MemoryKeys {
    fn get(&self, service: &str) -> Option<String> {
        self.0.lock().ok()?.get(service).cloned()
    }
    fn set(&self, service: &str, value: &str) -> Result<(), String> {
        self.0
            .lock()
            .map_err(|e| e.to_string())?
            .insert(service.into(), value.into());
        Ok(())
    }
    fn delete(&self, service: &str) -> Result<(), String> {
        self.0.lock().map_err(|e| e.to_string())?.remove(service);
        Ok(())
    }
}

/// A finished report file: bytes plus the `Report` history record (with `result`).
pub struct BuiltReport {
    pub bytes: Vec<u8>,
    pub file_name: String,
    /// `Report` without `id` (assigned by the store): name, tpl, fmt, lang, size, opts, result.
    pub record: Value,
    /// Structured Chain of Custody metadata (`CustodyRecord` JSON) when built by `foca-report`.
    pub custody: Option<Value>,
    /// Canonical custody JSON bytes passed to [`ReportSigner`].
    pub custody_payload: Vec<u8>,
}

/// Cryptographic signature over a report's canonical Chain of Custody payload (`<report>.sig.json`).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ReportSignature {
    pub alg: String,
    pub key_alias: String,
    pub sig_b64: String,
    pub pubkey_b64: String,
}

/// Result of checking a report signature against the key embedded in `.sig.json`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SignatureCheck {
    /// The signature matches the payload under the embedded public key.
    pub valid: bool,
    /// The embedded public key is this device's signing key.
    pub own_key: bool,
}

/// Optional platform signer for generated reports (AndroidKeyStore ECDSA P-256 on device).
pub trait ReportSigner: Send + Sync {
    fn sign(&self, payload: &[u8]) -> Result<ReportSignature, String>;
    fn verify(&self, payload: &[u8], sig: &ReportSignature) -> Result<bool, String>;
    /// Tells a valid signature made with another device's key apart from a broken one. The default
    /// treats every signature as made with the own key (signers that cannot check foreign keys).
    fn verify_detail(
        &self,
        payload: &[u8],
        sig: &ReportSignature,
    ) -> Result<SignatureCheck, String> {
        self.verify(payload, sig).map(|valid| SignatureCheck {
            valid,
            own_key: valid,
        })
    }
}

/// A finished export file.
pub struct BuiltExport {
    pub bytes: Vec<u8>,
    pub file_name: String,
    pub count: usize,
    pub secrets: bool,
    pub pii_redacted: bool,
}

/// Report and export builder (implemented by foca-report behind the `report` feature).
pub trait ReportBuilder: Send + Sync {
    /// `visuals` is `foca_report::Visuals` as JSON (`null` = no diagrams).
    fn build_report(
        &self,
        snap: &foca_core::api::Snapshot,
        log: &[foca_store::RequestLog],
        visuals: &Value,
        opts: &Value,
        now: time::OffsetDateTime,
    ) -> Result<BuiltReport, CmdError>;
    fn export(
        &self,
        snap: &foca_core::api::Snapshot,
        log: &[foca_store::RequestLog],
        kind: &str,
        fmt: &str,
        opts: &Value,
    ) -> Result<BuiltExport, CmdError>;
}

/// Endpoints of external services (tests point them at a local server).
#[derive(Debug, Clone)]
pub struct Endpoints {
    pub wayback: String,
    pub crtsh: String,
    pub cc_collinfo: String,
    pub rdap: foca_net::rdap::RdapEndpoints,
    /// Base URL of the cloud API for each AI provider id (OpenAI-compatible, Anthropic Messages API,
    /// or Google Gemini native `v1beta`).
    pub ai: HashMap<String, String>,
    /// Egress IP echo service (`{"ip": "..."}`).
    pub ip_echo: String,
    /// IP geolocation: `{ip}` is replaced with the address; the response is JSON with `country`.
    pub ip_geo: String,
    /// Base URL overrides for keyless sources by id (`anubis` -> `http://127.0.0.1:...`; tests and
    /// mirrors). Empty means the public endpoints.
    pub sources: HashMap<String, String>,
    /// Public external storage providers (Drive, Docs, OneDrive): download, export and folder
    /// listing bases.
    pub storage: foca_search::storage::StorageEndpoints,
    /// GitHub REST API base of the in-app update check (`/repos/{repo}/releases`).
    pub github_api: String,
}

impl Default for Endpoints {
    fn default() -> Self {
        let mut ai = HashMap::new();
        ai.insert("openai".into(), "https://api.openai.com/v1".into());
        ai.insert("anthropic".into(), "https://api.anthropic.com/v1".into());
        ai.insert(
            "gemini".into(),
            "https://generativelanguage.googleapis.com/v1beta".into(),
        );
        ai.insert("deepseek".into(), "https://api.deepseek.com".into());
        ai.insert("xai".into(), "https://api.x.ai/v1".into());
        ai.insert("mistral".into(), "https://api.mistral.ai/v1".into());
        ai.insert("groq".into(), "https://api.groq.com/openai/v1".into());
        ai.insert("together".into(), "https://api.together.xyz/v1".into());
        ai.insert("openrouter".into(), "https://openrouter.ai/api/v1".into());
        Endpoints {
            wayback: "https://web.archive.org".into(),
            crtsh: "https://crt.sh".into(),
            cc_collinfo: "https://index.commoncrawl.org/collinfo.json".into(),
            rdap: Default::default(),
            ai,
            ip_echo: "https://api.ipify.org?format=json".into(),
            ip_geo: "https://ipinfo.io/{ip}/json".into(),
            sources: HashMap::new(),
            storage: Default::default(),
            github_api: "https://api.github.com".into(),
        }
    }
}

/// Engine configuration.
#[derive(Clone)]
pub struct EngineConfig {
    /// App data directory: `projects.db`, project files and downloaded documents.
    pub data_dir: PathBuf,
    /// Cache directory (downloaded update APKs); the platform may clear it at any time.
    pub cache_dir: PathBuf,
    /// Ed25519 public key that must have signed a release's `SHA256SUMS.txt` (the official
    /// signing key by default; tests use their own).
    pub release_pubkey: [u8; 32],
    /// Export directory (`Download/FOCA-rs` on Android).
    pub export_dir: PathBuf,
    /// Local time offset of the device (dates in responses are local, without an offset).
    pub utc_offset: time::UtcOffset,
    pub clock: Arc<dyn foca_core::Clock>,
    /// Base HTTP settings; `settings.net` (proxy, UA, limits) is applied on top.
    pub net: foca_net::NetConfig,
    pub endpoints: Endpoints,
    /// DNS resolver (hickory by default; `StaticDns` in tests).
    pub dns: Option<Arc<dyn foca_net::dns::DnsLookup>>,
    /// Hosts whose downloads are passive (archives); appended to the downloader's list.
    pub passive_download_hosts: Vec<String>,
    /// TCP liveness ports (standard and full scan profiles).
    pub alive_ports: Vec<u16>,
    /// Offline test harness only: the port target sites listen on. Direct site reconnaissance
    /// (standard/full profiles) then fetches `http(s)://<host>:<port>/` instead of the default
    /// ports. `None` on devices.
    pub site_port: Option<u16>,
    /// Documents queued per scan when `scan_start` has no `limit` argument (the argument wins,
    /// `0` there means no limit).
    pub max_docs: usize,
    pub meta_concurrency: usize,
    pub download_concurrency: usize,
    /// Number of addresses to look up via RDAP per scan (0 disables it).
    pub rdap_limit: usize,
    /// Number of CT subdomains to resolve and check per scan.
    pub host_limit: usize,
    /// Hard overall timeout of one search source (all pages and retries); overridden by
    /// `settings.net.source_timeout` (seconds). A hung source gets the `timeout` status and the stage moves on.
    pub source_timeout: std::time::Duration,
    /// Tests and offline bench only: brute force the site without pauses (1000 requests/s, no jitter).
    /// Always `false` on a phone, where the gentle `settings.fuzz` limits apply.
    pub fuzz_unthrottled: bool,
    /// Browser engine for search engines with JavaScript challenges (Startpage, keyless Brave, Mojeek):
    /// a hidden WebView through the bridge on Android; `None` makes those sources report that a WebView is required.
    pub render: Option<Arc<dyn foca_search::RenderFetch>>,
    /// True during autonomous headless background monitoring (no Android WebView / Activity): WebView
    /// dork sources are skipped with `skipped_headless`.
    pub headless: bool,
    /// How long `Engine::open` waits to acquire `<data_dir>/engine.lock` before returning `busy`.
    pub lock_wait: std::time::Duration,
    /// Network spoofing canary overrides (`None` uses defaults against live endpoints and skips external probes on offline test fixtures).
    pub canary: Option<foca_net::canary::CanaryConfig>,
    /// TLS ports inspected on live in-scope hosts (standard/full), besides services detected
    /// as `https`.
    pub tls_ports: Vec<u16>,
    /// Tests and offline bench only: subdomain brute force without its adaptive pace.
    pub dns_unthrottled: bool,
    /// Delay before the scan queue continues after `Engine::open` (lets the app's own
    /// auto-resume of an interrupted scan go first).
    pub queue_start_delay: std::time::Duration,
    /// Optional cryptographic signer for report Chain of Custody manifests (`<file>.sig.json`).
    pub signer: Option<Arc<dyn ReportSigner>>,
    /// Optional on-device OCR provider (Android ML Kit; called only when `settings.ocr.enabled` is true).
    pub ocr: Option<Arc<dyn OcrProvider>>,
    /// Optional isolated WebView screenshotter (never called in `Access::Passive`).
    pub screenshotter: Option<Arc<dyn WebScreenshotter>>,
}

impl EngineConfig {
    pub fn new(data_dir: impl Into<PathBuf>) -> Self {
        let data_dir = data_dir.into();
        EngineConfig {
            export_dir: data_dir.join("Download").join("FOCA-rs"),
            cache_dir: data_dir.join("cache"),
            release_pubkey: crate::sigbundle::official_pubkey_bytes(),
            data_dir,
            utc_offset: time::UtcOffset::UTC,
            clock: Arc::new(foca_core::SystemClock),
            net: foca_net::NetConfig::default(),
            endpoints: Endpoints::default(),
            dns: None,
            passive_download_hosts: vec![],
            alive_ports: vec![80, 443],
            site_port: None,
            max_docs: 200,
            meta_concurrency: 2,
            download_concurrency: 4,
            rdap_limit: 5,
            host_limit: 150,
            source_timeout: std::time::Duration::from_secs(90),
            fuzz_unthrottled: false,
            render: None,
            headless: false,
            lock_wait: std::time::Duration::from_millis(500),
            canary: None,
            tls_ports: crate::scan::infra::TLS_PORTS.to_vec(),
            dns_unthrottled: false,
            queue_start_delay: std::time::Duration::from_secs(2),
            signer: None,
            ocr: None,
            screenshotter: None,
        }
    }
}
