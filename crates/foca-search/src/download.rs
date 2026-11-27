//! Document downloader.
//!
//! * HEAD to check the size (if HEAD is not supported, a GET that is aborted after the headers);
//! * the size limit applies to the actual stream (Content-Length is not trusted);
//! * a temporary `<dir>/.tmp/*.part` file, hashed with SHA-256 on the fly, is moved to
//!   `<dir>/files/<sha256>.<ext>` (deduplicated by hash: identical files are stored once);
//! * access class: archive hosts (web.archive.org, ...) are `Passive`, everything else is
//!   `TouchesTarget` (`NetClient` checks the scope before the request and on every redirect);
//! * the task queue is the [`TaskQueue`] trait (an SQLite implementation lives in `crate::store`
//!   behind the `store` feature): after a restart, interrupted tasks are requeued and resumed.
//!
//! `foca-search` does not depend on rusqlite directly: the downloader works against the queue
//! trait and the `foca-store` adapter is an optional feature. This keeps the downloader
//! testable with [`MemQueue`], while the application and the CLI enable `store`.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use foca_net::{Access, NetClient, NetError, NetRequest, NetResponse};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt;

use crate::filter::{ext_of_url, file_name_of_url};

#[derive(Debug, Clone)]
pub struct DownloadConfig {
    pub max_size: u64,
    pub concurrency: usize,
    /// Attempts per task, including the first one.
    pub max_attempts: u32,
    pub head_first: bool,
    /// Hosts (with their subdomains) whose downloads are passive.
    pub passive_hosts: Vec<String>,
    /// Videos (MP4/MOV) larger than this are not downloaded whole: only the top-level boxes
    /// without media data (`ftyp`, `moov`, `meta`, ...) are fetched with HTTP Range requests,
    /// if the server supports them. Metadata lives in those boxes, the video data is skipped.
    pub max_media_full: u64,
    /// Files on public external storage linked from in-scope pages, by download URL. Only these
    /// exact URLs are fetched from a storage host (passive, journal module `storage`); any other
    /// URL on that host stays out of scope.
    pub storage: Arc<HashMap<String, StorageItem>>,
}

/// An allowed external storage download.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StorageItem {
    /// Hosts the download may hop through (the provider's own hosts).
    pub hosts: Vec<String>,
    /// Expected extension when neither the URL nor `Content-Disposition` gives one.
    pub ext: Option<String>,
    /// File name (without extension) used when the provider sends no `Content-Disposition`.
    pub name: Option<String>,
}

/// Request log module of external storage downloads.
pub const STORAGE_MODULE: &str = "storage";

impl Default for DownloadConfig {
    fn default() -> Self {
        DownloadConfig {
            max_size: 50 * 1024 * 1024,
            concurrency: 4,
            max_attempts: 3,
            head_first: true,
            passive_hosts: vec![
                "web.archive.org".into(),
                "archive.org".into(),
                "data.commoncrawl.org".into(),
                "arquivo.pt".into(),
            ],
            max_media_full: 8 * 1024 * 1024,
            storage: Arc::new(HashMap::new()),
        }
    }
}

/// A downloaded file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Downloaded {
    pub url: String,
    pub final_url: String,
    pub sha256: String,
    pub size: u64,
    pub path: PathBuf,
    pub name: String,
    pub mime: Option<String>,
    /// A file with the same hash already existed in the project directory.
    pub existing: bool,
}

#[derive(Clone)]
pub struct Downloader {
    net: NetClient,
    dir: PathBuf,
    cfg: DownloadConfig,
    seq: Arc<AtomicU64>,
}

/// A queued task.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueuedTask {
    pub id: i64,
    pub url: String,
    pub source: String,
    pub attempts: u32,
}

/// Download task queue (state survives restarts if the implementation is persistent).
pub trait TaskQueue: Send + Sync {
    /// Requeues interrupted (`downloading`) tasks and returns the number of pending ones.
    fn resume(&self) -> Result<u32, String>;
    /// Claims up to `limit` tasks (`queued` becomes `downloading`, the attempt counter is incremented).
    fn claim(&self, limit: usize) -> Result<Vec<QueuedTask>, String>;
    /// Marks a task as done and returns the document id, if the queue tracks documents.
    fn done(&self, task: &QueuedTask, d: &Downloaded) -> Result<Option<u64>, String>;
    /// Marks a task as failed; `permanent` disables retries (out of scope, 404, size limit exceeded).
    fn failed(&self, task: &QueuedTask, err: &str, permanent: bool) -> Result<(), String>;
}

/// Result of a queue run.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunStats {
    pub done: u32,
    pub duplicates: u32,
    pub failed: u32,
    pub retried: u32,
    pub bytes: u64,
    pub cancelled: bool,
}

/// Queue run event (for UI progress).
#[derive(Debug, Clone)]
pub enum QueueEvent<'a> {
    Done(&'a QueuedTask, &'a Downloaded, Option<u64>),
    Failed(&'a QueuedTask, &'a NetError),
}

fn permanent(e: &NetError) -> bool {
    e.is_scope_denial()
        || matches!(e, NetError::TooLarge { .. } | NetError::BadUrl(_))
        || matches!(e, NetError::Status(s) if matches!(s, 400 | 401 | 403 | 404 | 410 | 451))
}

/// Video extensions fetched box by box when large (see [`DownloadConfig::max_media_full`]).
pub const MEDIA_EXTS: &[&str] = &["mp4", "mov", "m4v", "qt", "3gp"];
/// Size of one Range request for media boxes.
const MEDIA_CHUNK: u64 = 512 * 1024;

/// A top-level ISOBMFF box: absolute start, total size (header included), type.
#[derive(Debug, Clone, PartialEq, Eq)]
struct BoxRef {
    start: u64,
    size: u64,
    kind: [u8; 4],
}

/// Walks the top-level boxes of a chunk that starts at absolute offset `base` of a file of
/// `total` bytes. Stops at the first box whose header is not complete or is malformed; a box
/// may extend past the chunk (the caller decides what to do with it).
fn isobmff_boxes(chunk: &[u8], base: u64, total: u64) -> Vec<BoxRef> {
    let mut out = Vec::new();
    let mut i = 0usize;
    while i + 8 <= chunk.len() && out.len() < 1024 {
        let size32 =
            u32::from_be_bytes([chunk[i], chunk[i + 1], chunk[i + 2], chunk[i + 3]]) as u64;
        let mut kind = [0u8; 4];
        kind.copy_from_slice(&chunk[i + 4..i + 8]);
        if !kind
            .iter()
            .all(|c| c.is_ascii_graphic() || *c == b' ' || *c == 0xa9)
        {
            break;
        }
        let start = base + i as u64;
        let size = match size32 {
            0 => total.saturating_sub(start),
            1 => {
                if i + 16 > chunk.len() {
                    break;
                }
                let mut b = [0u8; 8];
                b.copy_from_slice(&chunk[i + 8..i + 16]);
                u64::from_be_bytes(b)
            }
            s => s,
        };
        if size < 8 || start.checked_add(size).is_none_or(|end| end > total) {
            break;
        }
        out.push(BoxRef { start, size, kind });
        match usize::try_from(size).ok().and_then(|s| i.checked_add(s)) {
            Some(n) if n <= chunk.len() => i = n,
            _ => break,
        }
    }
    out
}

fn ext_from_mime(m: &str) -> Option<&'static str> {
    let m = m
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    Some(match m.as_str() {
        "application/pdf" => "pdf",
        "application/msword" => "doc",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document" => "docx",
        "application/vnd.ms-excel" => "xls",
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" => "xlsx",
        "application/vnd.ms-powerpoint" => "ppt",
        "application/vnd.openxmlformats-officedocument.presentationml.presentation" => "pptx",
        "application/vnd.oasis.opendocument.text" => "odt",
        "application/vnd.oasis.opendocument.spreadsheet" => "ods",
        "image/jpeg" => "jpg",
        "image/png" => "png",
        "image/tiff" => "tif",
        "image/svg+xml" => "svg",
        "image/heic" | "image/heif" => "heic",
        "message/rfc822" => "eml",
        "application/vnd.ms-outlook" => "msg",
        "text/calendar" => "ics",
        "text/vcard" | "text/x-vcard" => "vcf",
        "video/mp4" => "mp4",
        "video/quicktime" => "mov",
        "application/zip" | "application/x-zip-compressed" => "zip",
        "application/vnd.ms-visio.drawing" => "vsdx",
        "application/vnd.visio" => "vsd",
        "application/x-mspublisher" | "application/vnd.ms-publisher" => "pub",
        _ => return None,
    })
}

impl Downloader {
    /// Creates a downloader for the project directory `dir` (files go to `dir/files`, temporary files to `dir/.tmp`).
    pub fn new(net: NetClient, dir: impl AsRef<Path>, cfg: DownloadConfig) -> Self {
        Downloader {
            net,
            dir: dir.as_ref().to_path_buf(),
            cfg,
            seq: Arc::new(AtomicU64::new(0)),
        }
    }

    pub fn files_dir(&self) -> PathBuf {
        self.dir.join("files")
    }

    fn storage_item(&self, url: &str) -> Option<&StorageItem> {
        self.cfg.storage.get(url)
    }

    /// Returns `true` for an allowed linked external storage item.
    pub fn is_storage(&self, url: &str) -> bool {
        self.storage_item(url).is_some()
    }

    /// Request log module: `storage` for linked external storage, `download` otherwise.
    fn module(&self, url: &str) -> &'static str {
        if self.storage_item(url).is_some() {
            STORAGE_MODULE
        } else {
            "download"
        }
    }

    /// Returns the access class for a URL: archives and allowed external storage items are
    /// passive, everything else touches the target.
    pub fn access_for(&self, url: &str) -> Access {
        if self.storage_item(url).is_some() {
            return Access::Passive;
        }
        let host = url::Url::parse(url)
            .ok()
            .and_then(|u| u.host_str().map(|h| h.to_ascii_lowercase()))
            .unwrap_or_default();
        let passive = self
            .cfg
            .passive_hosts
            .iter()
            .any(|p| host == *p || foca_core::target::is_subdomain_of(&host, p));
        if passive {
            Access::Passive
        } else {
            Access::TouchesTarget
        }
    }

    /// Restricts redirect hops of passive (archive) downloads to passive hosts, so an archive cannot
    /// lead a passive request to a third-party host; the network layer blocks target hosts and exclusions.
    fn req(&self, r: NetRequest) -> NetRequest {
        if r.access.touches_target() {
            return r;
        }
        match self.storage_item(r.url.as_str()) {
            Some(item) => {
                let hosts = Arc::new(item.hosts.clone());
                r.passive_allow(hosts)
            }
            None => r.passive_allow(Arc::new(self.cfg.passive_hosts.clone())),
        }
    }

    /// Probes the size with HEAD (or an aborted GET if HEAD is not supported). Returns `None` if unknown.
    pub async fn probe(&self, url: &str) -> Result<Option<u64>, NetError> {
        let access = self.access_for(url);
        let r = self
            .net
            .send(self.req(NetRequest::head(url, self.module(url), access.clone())?))
            .await?;
        if r.is_success() {
            return Ok(r.content_length());
        }
        let st = r.status();
        drop(r);
        if matches!(st, 404 | 410) {
            return Err(NetError::Status(st));
        }
        // HEAD not supported (405/501/403, ...): GET and abort after the headers
        let r = self
            .net
            .send(self.req(NetRequest::get(url, self.module(url), access)?))
            .await?;
        let len = if r.is_success() {
            r.content_length()
        } else {
            None
        };
        let st = r.status();
        r.abort();
        if matches!(st, 404 | 410) {
            return Err(NetError::Status(st));
        }
        Ok(len)
    }

    /// Downloads a single URL.
    pub async fn download(&self, url: &str) -> Result<Downloaded, NetError> {
        let max = self.cfg.max_size;
        let media = ext_of_url(url).is_some_and(|e| MEDIA_EXTS.contains(&e.as_str()));
        let storage = self.storage_item(url).cloned();
        // storage providers answer HEAD poorly; the stream limit applies anyway
        if self.cfg.head_first && storage.is_none() {
            match self.probe(url).await {
                Ok(Some(len)) if media && len > self.cfg.max_media_full => {
                    return self.download_media_boxes(url, len).await;
                }
                Ok(Some(len)) if len > max => return Err(NetError::TooLarge { limit: max }),
                Err(e) if e.is_scope_denial() || e == NetError::Cancelled || permanent(&e) => {
                    return Err(e)
                }
                _ => {}
            }
        }
        let access = self.access_for(url);
        let mut r = self
            .net
            .send(self.req(NetRequest::get(url, self.module(url), access)?))
            .await?
            .ensure_success()?;
        if let Some(item) = &storage {
            r = self.storage_response(url, item, r).await?;
        }
        if r.content_length().is_some_and(|l| l > max) {
            r.abort();
            return Err(NetError::TooLarge { limit: max });
        }
        let final_url = r.url().to_string();
        let mime = r.content_type().map(String::from);
        let disposition = r
            .header("content-disposition")
            .and_then(crate::storage::disposition_name);
        let tmp_dir = self.dir.join(".tmp");
        tokio::fs::create_dir_all(&tmp_dir).await?;
        let n = self.seq.fetch_add(1, Ordering::Relaxed);
        let tmp = tmp_dir.join(format!("{}-{n}.part", std::process::id()));
        let res: Result<(String, u64), NetError> = async {
            let mut f = tokio::fs::File::create(&tmp).await?;
            let mut h = Sha256::new();
            let mut total = 0u64;
            while let Some(c) = r.chunk().await? {
                total += c.len() as u64;
                if total > max {
                    return Err(NetError::TooLarge { limit: max });
                }
                h.update(&c);
                f.write_all(&c).await?;
            }
            f.flush().await?;
            f.sync_all().await.ok();
            let sha: String = h.finalize().iter().map(|b| format!("{b:02x}")).collect();
            Ok((sha, total))
        }
        .await;
        let (sha, size) = match res {
            Ok(x) => x,
            Err(e) => {
                drop(r);
                let _ = tokio::fs::remove_file(&tmp).await;
                return Err(e);
            }
        };
        drop(r);
        let name = match (&storage, &disposition) {
            (Some(_), Some(n)) => n.clone(),
            (Some(StorageItem { name: Some(n), .. }), None) => n.clone(),
            _ => file_name_of_url(url),
        };
        let ext = match &storage {
            Some(item) => ext_of_url(&format!("https://x/{name}"))
                .or_else(|| item.ext.clone())
                .or_else(|| mime.as_deref().and_then(ext_from_mime).map(String::from)),
            None => ext_of_url(url)
                .or_else(|| mime.as_deref().and_then(ext_from_mime).map(String::from)),
        }
        .unwrap_or_else(|| "bin".into());
        let files = self.files_dir();
        tokio::fs::create_dir_all(&files).await?;
        let path = files.join(format!("{sha}.{ext}"));
        let existing = tokio::fs::try_exists(&path).await.unwrap_or(false);
        if existing {
            let _ = tokio::fs::remove_file(&tmp).await;
        } else {
            tokio::fs::rename(&tmp, &path).await?;
        }
        let name = if storage.is_some() && ext_of_url(&format!("https://x/{name}")).is_none() {
            format!("{name}.{ext}")
        } else {
            name
        };
        Ok(Downloaded {
            url: url.to_string(),
            final_url,
            sha256: sha,
            size,
            path,
            name,
            mime,
            existing,
        })
    }

    /// Checks an external storage answer: an HTML page instead of a file is either Google Drive's
    /// "can't scan for viruses" page (its form is followed once) or a sign-in/permission page,
    /// i.e. the file is not public (`Status(403)`).
    async fn storage_response(
        &self,
        url: &str,
        item: &StorageItem,
        r: NetResponse,
    ) -> Result<NetResponse, NetError> {
        let html = r
            .content_type()
            .is_some_and(|c| c.to_ascii_lowercase().contains("text/html"));
        if !html {
            return Ok(r);
        }
        let page = r.url().clone();
        let body = r.text_limited(1024 * 1024).await.unwrap_or_default();
        let Some(next) = crate::storage::drive_confirm_url(&body, &page) else {
            return Err(NetError::Status(403));
        };
        let req = NetRequest::get(&next, STORAGE_MODULE, Access::Passive)?
            .passive_allow(Arc::new(item.hosts.clone()));
        let r = self.net.send(req).await?.ensure_success()?;
        if r.content_type()
            .is_some_and(|c| c.to_ascii_lowercase().contains("text/html"))
        {
            r.abort();
            tracing::info!(target: "foca::download", "{}: хранилище вернуло страницу вместо файла", foca_net::sink::redact_url(url));
            return Err(NetError::Status(403));
        }
        Ok(r)
    }

    /// Fetches only the metadata boxes of a large MP4/MOV with Range requests: the head of the
    /// file, then every top-level box after the media data (`moov` is often at the end). Box
    /// payloads are kept as is; `mdat`/`free`/`skip` are dropped, so the stored file is a small
    /// valid ISOBMFF stream with the same metadata. Fails with `TooLarge` when the server
    /// ignores ranges or the metadata boxes exceed the budget.
    async fn download_media_boxes(&self, url: &str, total: u64) -> Result<Downloaded, NetError> {
        let limit = self.cfg.max_media_full;
        let too_large = || NetError::TooLarge {
            limit: self.cfg.max_size,
        };
        let mut kept: Vec<u8> = Vec::new();
        let mut fetched = 0u64;
        let mut off = 0u64;
        // Size of the next request when a metadata box is larger than one chunk.
        let mut need = MEDIA_CHUNK;
        let mut final_url = url.to_string();
        let mut mime = None;
        for _ in 0..8 {
            if off >= total {
                break;
            }
            let want = (total - off).min(need).min(limit.saturating_sub(fetched));
            if want < 8 {
                return Err(too_large());
            }
            let (chunk, fu, ct) = self.range(url, off, off + want - 1).await?;
            fetched += chunk.len() as u64;
            final_url = fu;
            mime = mime.or(ct);
            let chunk_end = off + chunk.len() as u64;
            let mut next = chunk_end;
            need = MEDIA_CHUNK;
            for b in isobmff_boxes(&chunk, off, total) {
                let Some(end) = b.start.checked_add(b.size) else {
                    break;
                };
                let skip = matches!(&b.kind, b"mdat" | b"free" | b"skip" | b"wide");
                if end <= chunk_end {
                    next = end;
                    if !skip {
                        let s = (b.start - off) as usize;
                        let Some(slice) = usize::try_from(b.size)
                            .ok()
                            .and_then(|len| s.checked_add(len))
                            .and_then(|e| chunk.get(s..e))
                        else {
                            break;
                        };
                        kept.extend_from_slice(slice);
                    }
                    continue;
                }
                // The box runs past this chunk: jump over media data, refetch anything else whole.
                if skip {
                    next = end;
                } else {
                    if b.size > limit.saturating_sub(fetched) {
                        return Err(too_large());
                    }
                    next = b.start;
                    need = b.size.max(MEDIA_CHUNK);
                }
                break;
            }
            if next <= off {
                return Err(too_large());
            }
            off = next;
        }
        if kept.is_empty() {
            return Err(too_large());
        }
        self.store_bytes(url, final_url, mime, &kept).await
    }

    /// GETs `first..=last` of `url`; the server must answer `206 Partial Content`.
    async fn range(
        &self,
        url: &str,
        first: u64,
        last: u64,
    ) -> Result<(Vec<u8>, String, Option<String>), NetError> {
        let access = self.access_for(url);
        let r = self
            .net
            .send(
                self.req(
                    NetRequest::get(url, self.module(url), access)?
                        .header("Range", &format!("bytes={first}-{last}")),
                ),
            )
            .await?;
        if r.status() != 206 {
            r.abort();
            return Err(NetError::TooLarge {
                limit: self.cfg.max_size,
            });
        }
        let fu = r.url().to_string();
        let ct = r.content_type().map(String::from);
        let b = r.bytes_limited(last - first + 1).await?;
        Ok((b, fu, ct))
    }

    /// Stores an in-memory file in the project directory under its SHA-256.
    async fn store_bytes(
        &self,
        url: &str,
        final_url: String,
        mime: Option<String>,
        bytes: &[u8],
    ) -> Result<Downloaded, NetError> {
        let sha: String = Sha256::digest(bytes)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let ext = ext_of_url(url)
            .or_else(|| mime.as_deref().and_then(ext_from_mime).map(String::from))
            .unwrap_or_else(|| "bin".into());
        let files = self.files_dir();
        tokio::fs::create_dir_all(&files).await?;
        let path = files.join(format!("{sha}.{ext}"));
        let existing = tokio::fs::try_exists(&path).await.unwrap_or(false);
        if !existing {
            tokio::fs::write(&path, bytes).await?;
        }
        Ok(Downloaded {
            url: url.to_string(),
            final_url,
            sha256: sha,
            size: bytes.len() as u64,
            path,
            name: file_name_of_url(url),
            mime,
            existing,
        })
    }

    /// Runs the queue until it is empty or cancelled, with up to `concurrency` downloads in flight.
    pub async fn run_queue(
        &self,
        q: &dyn TaskQueue,
        mut on_event: impl FnMut(QueueEvent<'_>),
    ) -> Result<RunStats, String> {
        q.resume()?;
        let mut stats = RunStats::default();
        let mut set: tokio::task::JoinSet<(QueuedTask, Result<Downloaded, NetError>)> =
            tokio::task::JoinSet::new();
        let conc = self.cfg.concurrency.max(1);
        let mut exhausted = false;
        loop {
            while !self.net.is_cancelled() && !exhausted && set.len() < conc {
                let batch = q.claim(conc - set.len())?;
                if batch.is_empty() {
                    exhausted = true;
                    break;
                }
                for t in batch {
                    let d = self.clone();
                    set.spawn(async move {
                        let r = d.download(&t.url).await;
                        (t, r)
                    });
                }
            }
            let Some(j) = set.join_next().await else {
                break;
            };
            let Ok((t, r)) = j else { continue };
            match r {
                Ok(d) => {
                    let doc = q.done(&t, &d)?;
                    stats.done += 1;
                    stats.bytes += d.size;
                    if d.existing {
                        stats.duplicates += 1;
                    }
                    on_event(QueueEvent::Done(&t, &d, doc));
                }
                // On cancellation the task stays `downloading` and is requeued by resume().
                Err(NetError::Cancelled) => stats.cancelled = true,
                Err(e) => {
                    let perm = permanent(&e) || t.attempts >= self.cfg.max_attempts;
                    q.failed(&t, &format!("{}: {e}", e.code()), perm)?;
                    if perm {
                        stats.failed += 1;
                    } else {
                        stats.retried += 1;
                        exhausted = false;
                    }
                    on_event(QueueEvent::Failed(&t, &e));
                }
            }
        }
        if self.net.is_cancelled() {
            stats.cancelled = true;
        }
        Ok(stats)
    }
}

/// In-memory queue (tests, CLI without a project) with the same semantics as `foca-store`.
#[derive(Debug, Default)]
pub struct MemQueue {
    inner: Mutex<Vec<MemTask>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemTask {
    pub task: QueuedTask,
    /// `queued` | `downloading` | `done` | `failed`
    pub state: String,
    pub error: Option<String>,
    pub sha256: Option<String>,
}

impl MemQueue {
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Vec<MemTask>> {
        match self.inner.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        }
    }

    /// Enqueues a URL unless it is already queued. Returns the task id.
    pub fn enqueue(&self, url: &str, source: &str) -> Option<i64> {
        let mut g = self.lock();
        if g.iter().any(|t| t.task.url == url) {
            return None;
        }
        let id = g.len() as i64 + 1;
        g.push(MemTask {
            task: QueuedTask {
                id,
                url: url.into(),
                source: source.into(),
                attempts: 0,
            },
            state: "queued".into(),
            error: None,
            sha256: None,
        });
        Some(id)
    }

    pub fn tasks(&self) -> Vec<MemTask> {
        self.lock().clone()
    }

    pub fn count(&self, state: &str) -> usize {
        self.lock().iter().filter(|t| t.state == state).count()
    }
}

impl TaskQueue for MemQueue {
    fn resume(&self) -> Result<u32, String> {
        let mut g = self.lock();
        for t in g.iter_mut().filter(|t| t.state == "downloading") {
            t.state = "queued".into();
        }
        Ok(g.iter().filter(|t| t.state == "queued").count() as u32)
    }

    fn claim(&self, limit: usize) -> Result<Vec<QueuedTask>, String> {
        let mut g = self.lock();
        let mut out = Vec::new();
        for t in g.iter_mut().filter(|t| t.state == "queued").take(limit) {
            t.state = "downloading".into();
            t.task.attempts += 1;
            out.push(t.task.clone());
        }
        Ok(out)
    }

    fn done(&self, task: &QueuedTask, d: &Downloaded) -> Result<Option<u64>, String> {
        let mut g = self.lock();
        let t = g
            .iter_mut()
            .find(|t| t.task.id == task.id)
            .ok_or("нет задачи")?;
        t.state = "done".into();
        t.error = None;
        t.sha256 = Some(d.sha256.clone());
        Ok(None)
    }

    fn failed(&self, task: &QueuedTask, err: &str, permanent: bool) -> Result<(), String> {
        let mut g = self.lock();
        let t = g
            .iter_mut()
            .find(|t| t.task.id == task.id)
            .ok_or("нет задачи")?;
        t.state = if permanent { "failed" } else { "queued" }.into();
        t.error = Some(err.into());
        Ok(())
    }
}

#[cfg(test)]
mod media_tests {
    #[test]
    fn isobmff_walk_stops_at_partial_box() {
        let mut b = Vec::new();
        b.extend_from_slice(&[0, 0, 0, 16]);
        b.extend_from_slice(b"ftypqt  \0\0\0\0");
        b.extend_from_slice(&[0, 0, 0x10, 0]);
        b.extend_from_slice(b"mdat");
        let v = super::isobmff_boxes(&b, 0, 10_000);
        assert_eq!(v.len(), 2);
        assert_eq!(&v[1].kind, b"mdat");
        assert_eq!(v[1].size, 4096);
    }

    #[test]
    fn isobmff_walk_rejects_u64_wrap_size() {
        let mut b = Vec::new();
        b.extend_from_slice(&[0, 0, 0, 1]);
        b.extend_from_slice(b"moov");
        b.extend_from_slice(&u64::MAX.to_be_bytes());
        assert!(super::isobmff_boxes(&b, 100, 10_000).is_empty());
    }
}
