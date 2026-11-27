//! Crawler wiring of the scan: crawl settings, the resumable frontier, document provenance,
//! files on public external storage linked from in-scope pages, image selection for EXIF and
//! links found inside downloaded documents.
//!
//! Crawling is a request to the target: it runs in the standard and active profiles only (the
//! search stage never adds the crawler at the passive level). External storage is a third party:
//! only the exact items linked from in-scope pages are fetched (passive access, journal module
//! `storage`, note `linked_storage`), never anything else on the storage host.

use std::collections::{BTreeMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use foca_core::api::DocProvenance;
use foca_net::{Access, NetClient, NetRequest};
use foca_search::crawl::select_images;
use foca_search::download::StorageItem;
use foca_search::sources::{
    CrawlOutput, CrawlStats, Crawler, Frontier, LinkedStorage, ProgressHook,
};
use foca_search::storage::{
    drive_file, parse_folder_listing, parse_storage, provider_hosts, ItemKind, Provider,
    StorageEndpoints, StorageLink, FOLDER_FILES, FOLDER_TOTAL,
};
use foca_search::store::StoreQueue;
use foca_search::FoundUrl;
use foca_store::PROVENANCE_KEY;

use crate::analysis::facts;
use crate::engine::lock;

use crate::scan::*;

/// Facts key: unfinished crawl frontier per domain (`BTreeMap<String, Frontier>`).
pub(crate) const K_FRONTIER: &str = "engine.crawl_frontier";
/// Facts key: script files the crawler saw per host (`BTreeMap<String, Vec<String>>`), for recon.
pub(crate) const K_SCRIPTS: &str = "engine.crawl_scripts";
/// Request journal note of a linked external storage request.
pub(crate) const STORAGE_NOTE: &str = "linked_storage";
/// Script files kept per host for recon.
const SCRIPTS_PER_HOST: usize = 50;

/// Facts key of the crawl parameters of one run (wizard), surviving a resume.
pub(crate) fn run_key(scan_id: &str) -> String {
    format!("engine.crawl_run.{scan_id}")
}

/// Default `settings.crawl` (see `docs/API.md`).
pub fn default_settings() -> Value {
    json!({
        "max_depth": 5, "max_pages": 1000, "max_minutes": 20, "max_rendered": 30,
        "nofollow": false, "resume": true, "storage": true, "images": true,
        "max_images": 300, "max_image_mb": 200, "doc_links": true, "doc_link_depth": 2
    })
}

/// Effective crawl parameters of a run.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct CrawlCfg {
    pub max_depth: usize,
    pub max_pages: usize,
    pub max_minutes: u64,
    pub max_rendered: usize,
    pub nofollow: bool,
    pub resume: bool,
    pub storage: bool,
    pub images: bool,
    pub max_images: usize,
    pub max_image_mb: u64,
    pub doc_links: bool,
    pub doc_link_depth: u8,
}

/// A manual number: never capped from above (ui/js/limits.js warns instead); `lo` is the
/// crash-safety floor, and huge values are kept within what the counters can hold.
fn num(v: &Value, k: &str, lo: u64, def: u64) -> u64 {
    v[k].as_u64().unwrap_or(def).clamp(lo, u64::from(u32::MAX))
}

impl CrawlCfg {
    fn from_value(v: &Value) -> CrawlCfg {
        let flag = |k: &str, def: bool| v[k].as_bool().unwrap_or(def);
        CrawlCfg {
            max_depth: num(v, "max_depth", 1, 5) as usize,
            max_pages: num(v, "max_pages", 1, 1000) as usize,
            max_minutes: num(v, "max_minutes", 1, 20),
            max_rendered: num(v, "max_rendered", 0, 30) as usize,
            nofollow: flag("nofollow", false),
            resume: flag("resume", true),
            storage: flag("storage", true),
            images: flag("images", true),
            max_images: num(v, "max_images", 0, 300) as usize,
            max_image_mb: num(v, "max_image_mb", 1, 200),
            doc_links: flag("doc_links", true),
            doc_link_depth: num(v, "doc_link_depth", 0, 2).min(255) as u8,
        }
    }
}

/// Effective parameters: defaults, then `settings.crawl`, then the run's wizard values (and the
/// legacy `crawl_depth`). External storage and images are off at the passive level.
pub(crate) fn cfg(c: &Ctx) -> CrawlCfg {
    let mut v = default_settings();
    if let Ok(s) = c.e.store().settings_get() {
        if s["crawl"].is_object() {
            foca_store::settings::merge(&mut v, &s["crawl"]);
        }
    }
    let run: Value = facts::get(&lock(&c.db), &run_key(&c.scan_id));
    let run_depth = run["max_depth"].is_u64();
    if run.is_object() {
        foca_store::settings::merge(&mut v, &run);
    }
    let mut cfg = CrawlCfg::from_value(&v);
    if let (false, Some(d)) = (run_depth, lock(&c.st).crawl_depth) {
        cfg.max_depth = d;
    }
    if c.level == "external" {
        cfg.storage = false;
        cfg.images = false;
    }
    cfg
}

/// Crawl counters as sent in `crawl` events and `scan_status.crawl`.
fn stats_json(s: &CrawlStats) -> Value {
    json!({
        "pages": s.pages, "queued": s.queued, "docs": s.docs, "storage": s.storage,
        "images": s.images, "rendered": s.rendered, "render_missing": s.render_missing,
        "sitemaps": s.sitemaps, "trap_skipped": s.trap_skipped, "limited": s.limited,
        "rate": s.rate, "stopped_hosts": s.stopped_hosts, "resumed": s.resumed,
        "finished": s.finished, "stop": s.stop,
    })
}

/// Sends the crawl counters (`crawl` event) and keeps them in `scan_status.crawl`.
fn emit_stats(e: &Core, st: &Mutex<RunState>, scan_id: &str, s: &CrawlStats) {
    let v = stats_json(s);
    lock(st).crawl = Some(v.clone());
    let mut ev = json!({ "type": "crawl", "scan_id": scan_id });
    if let (Some(o), Value::Object(x)) = (ev.as_object_mut(), v) {
        o.extend(x);
    }
    e.emit(ev);
}

/// Builds the crawler of this run.
pub(crate) fn crawler(c: &Ctx, cfg: &CrawlCfg) -> Crawler {
    let resume = if cfg.resume {
        facts::get::<BTreeMap<String, Frontier>>(&lock(&c.db), K_FRONTIER)
            .into_iter()
            .collect()
    } else {
        Default::default()
    };
    let (e, st, sid) = (c.e.clone(), c.st.clone(), c.scan_id.clone());
    let last: Mutex<Option<Instant>> = Mutex::new(None);
    let hook: ProgressHook = Arc::new(move |s: &CrawlStats| {
        {
            let mut l = lock(&last);
            if l.is_some_and(|t| t.elapsed() < Duration::from_millis(500)) {
                lock(&st).crawl = Some(stats_json(s));
                return;
            }
            *l = Some(Instant::now());
        }
        emit_stats(&e, &st, &sid, s);
    });
    // images off: image links are ignored, unless the run's document types ask for them
    let typed_images = lock(&c.st)
        .exts
        .iter()
        .any(|e| foca_search::filter::is_image_ext(e));
    Crawler {
        max_depth: cfg.max_depth,
        max_pages: cfg.max_pages,
        max_time: Duration::from_secs(cfg.max_minutes * 60),
        max_rendered: cfg.max_rendered,
        honor_nofollow: cfg.nofollow,
        storage: cfg.storage.then(|| c.e.cfg.endpoints.storage.clone()),
        collect_images: cfg.images,
        skip_images: !cfg.images && !typed_images,
        site_port: c.e.cfg.site_port,
        ..Default::default()
    }
    .with_resume(resume)
    .with_progress(hook)
}

/// Adds provenance records; the first record of a URL wins.
pub(crate) fn record_provenance(
    c: &Ctx,
    items: impl IntoIterator<Item = (String, DocProvenance)>,
) -> Result<(), Stop> {
    let db = lock(&c.db);
    let mut map: BTreeMap<String, DocProvenance> = facts::get(&db, PROVENANCE_KEY);
    let n = map.len();
    for (u, p) in items {
        map.entry(u).or_insert(p);
    }
    if map.len() != n {
        facts::put(&db, PROVENANCE_KEY, &map)?;
    }
    Ok(())
}

fn provenance_map(c: &Ctx) -> BTreeMap<String, DocProvenance> {
    facts::get(&lock(&c.db), PROVENANCE_KEY)
}

/// External storage downloads allowed for this project: exactly the linked items recorded in
/// the provenance, with the provider's hosts for redirects.
pub(crate) fn storage_allow(c: &Ctx) -> std::collections::HashMap<String, StorageItem> {
    let ep = &c.e.cfg.endpoints.storage;
    let mut out = std::collections::HashMap::new();
    for (fetch, p) in provenance_map(c) {
        let (Some(id), Some(link)) = (p.storage.as_deref(), p.link.as_deref()) else {
            continue;
        };
        let Some(provider) = Provider::from_id(id) else {
            continue;
        };
        let parsed = url::Url::parse(link)
            .ok()
            .and_then(|u| parse_storage(&u, ep))
            .filter(|l| l.fetch == fetch);
        if let Some(l) = parsed {
            let short: String =
                l.id.chars()
                    .filter(char::is_ascii_alphanumeric)
                    .take(16)
                    .collect();
            out.insert(
                fetch,
                StorageItem {
                    hosts: provider_hosts(provider, ep),
                    ext: l.ext,
                    name: Some(format!("{}-{short}", provider.id())),
                },
            );
        }
    }
    out
}

fn storage_prov(l: &StorageLink, kind: &str, from: &str) -> DocProvenance {
    DocProvenance {
        kind: kind.into(),
        from: from.into(),
        storage: Some(l.provider.id().into()),
        link: Some(l.link.clone()),
        export: l.exported(),
        ..Default::default()
    }
}

fn storage_found(l: &StorageLink, source: &str) -> FoundUrl {
    let mut f = FoundUrl::new(&l.fetch, source);
    f.hint_ext = l.ext.clone();
    f
}

/// Lists a public Drive folder (one request, journal module `storage`). Errors and private
/// folders give an empty listing.
async fn folder_files(net: &NetClient, ep: &StorageEndpoints, l: &StorageLink) -> Vec<StorageLink> {
    let hosts = Arc::new(provider_hosts(l.provider, ep));
    let Ok(req) = NetRequest::get(
        &l.fetch,
        foca_search::download::STORAGE_MODULE,
        Access::Passive,
    ) else {
        return Vec::new();
    };
    let req = req
        .passive_allow(hosts)
        .timeout(Duration::from_secs(30))
        .retries(1);
    let body = match net.send(req).await {
        Ok(r) if r.is_success() => r.text_limited(4 * 1024 * 1024).await.unwrap_or_default(),
        Ok(r) => {
            r.abort();
            return Vec::new();
        }
        Err(_) => return Vec::new(),
    };
    let (files, folders) = parse_folder_listing(&body);
    let mut out: Vec<StorageLink> = files.iter().filter_map(|f| drive_file(&f.id, ep)).collect();
    // subfolders become folder items of their own (listed one level deep by the caller)
    out.extend(folders.iter().filter_map(|id| {
        url::Url::parse(&format!(
            "{}/drive/folders/{id}",
            ep.drive.trim_end_matches('/')
        ))
        .ok()
        .and_then(|u| parse_storage(&u, ep))
    }));
    out
}

/// Linked storage after folder expansion.
#[derive(Default)]
struct Expanded {
    files: Vec<(StorageLink, String)>,
    /// Folder listing URLs fetched.
    listed: Vec<String>,
    /// Folders left unlisted because the files already fill the download limit.
    unlisted: usize,
}

/// Expands folder links into their files (capped per folder and in total, subfolders one level
/// deep) and keeps file and export links as they are. Each file keeps the linking page. Files
/// come in link order, folder contents after them; once the new files (not in `known`) fill
/// `room`, the remaining folders are not listed: their files could not be downloaded anyway.
async fn expand_storage(
    c: &Ctx,
    net: &NetClient,
    ep: &StorageEndpoints,
    linked: &[LinkedStorage],
    known: &HashSet<String>,
    room: usize,
) -> Result<Expanded, Stop> {
    let mut x = Expanded::default();
    let mut seen: HashSet<String> = HashSet::new();
    let mut from_folders = 0usize;
    let mut fresh = 0usize;
    let is_new = |l: &StorageLink| !known.contains(&foca_search::filter::target_key(&l.fetch));
    let mut folders: std::collections::VecDeque<(StorageLink, String, u8)> = Default::default();
    for s in linked {
        match s.link.kind {
            ItemKind::Folder => folders.push_back((s.link.clone(), s.page.clone(), 0)),
            _ => {
                if seen.insert(s.link.fetch.clone()) {
                    fresh += usize::from(is_new(&s.link));
                    x.files.push((s.link.clone(), s.page.clone()));
                }
            }
        }
    }
    let (files, listed) = (&mut x.files, &mut x.listed);
    while let Some((f, page, level)) = folders.pop_front() {
        c.gate().await?;
        if fresh >= room {
            x.unlisted += 1;
            continue;
        }
        if from_folders >= FOLDER_TOTAL || listed.contains(&f.fetch) {
            continue;
        }
        listed.push(f.fetch.clone());
        let mut taken = 0usize;
        for item in folder_files(net, ep, &f).await {
            if item.kind == ItemKind::Folder {
                if level == 0 {
                    folders.push_back((item, page.clone(), 1));
                }
                continue;
            }
            if taken >= FOLDER_FILES || from_folders >= FOLDER_TOTAL {
                break;
            }
            if seen.insert(item.fetch.clone()) {
                fresh += usize::from(is_new(&item));
                files.push((item, page.clone()));
                taken += 1;
                from_folders += 1;
            }
        }
    }
    Ok(x)
}

/// Marks this scan's requests to linked external storage in the request journal.
pub(crate) fn annotate_storage(c: &Ctx, urls: &[String]) {
    if urls.is_empty() {
        return;
    }
    let items: Vec<(String, String, Option<String>, u64)> = urls
        .iter()
        .map(|u| {
            (
                foca_net::sink::redact_url(u),
                STORAGE_NOTE.to_string(),
                None,
                0,
            )
        })
        .collect();
    if let Err(e) = lock(&c.db).annotate_requests(
        Some(&c.scan_id),
        foca_search::download::STORAGE_MODULE,
        &items,
    ) {
        tracing::warn!(target: "foca::scan", "{}: пометки хранилищ в журнале: {e}", c.scan_id);
    }
}

/// Items to download after a crawl of one domain: storage files and selected images, with
/// their provenance.
pub(crate) struct CrawlExtra {
    pub items: Vec<(FoundUrl, DocProvenance)>,
    pub storage_files: usize,
    pub images: usize,
}

/// Saves what a crawl of `domain` left (frontier, scripts, document provenance) and returns the
/// storage files and images to download.
pub(crate) async fn after_domain(
    c: &Ctx,
    cfg: &CrawlCfg,
    domain: &str,
    out: CrawlOutput,
    net: &NetClient,
    known: &HashSet<String>,
) -> Result<CrawlExtra, Stop> {
    {
        let db = lock(&c.db);
        let mut fr: BTreeMap<String, Frontier> = facts::get(&db, K_FRONTIER);
        let key = domain.to_ascii_lowercase();
        if out.frontier.is_empty() {
            fr.remove(&key);
        } else {
            fr.insert(key, out.frontier.clone());
        }
        facts::put(&db, K_FRONTIER, &fr)?;
        let mut sc: BTreeMap<String, Vec<String>> = facts::get(&db, K_SCRIPTS);
        for (s, _) in &out.scripts {
            let Some(h) = url::Url::parse(s)
                .ok()
                .and_then(|u| u.host_str().map(str::to_ascii_lowercase))
            else {
                continue;
            };
            let v = sc.entry(h).or_default();
            if v.len() < SCRIPTS_PER_HOST && !v.contains(s) {
                v.push(s.clone());
            }
        }
        facts::put(&db, K_SCRIPTS, &sc)?;
    }
    record_provenance(
        c,
        out.doc_pages.iter().map(|(d, p)| {
            (
                d.clone(),
                DocProvenance {
                    kind: "page".into(),
                    from: p.clone(),
                    ..Default::default()
                },
            )
        }),
    )?;
    let mut extra = CrawlExtra {
        items: Vec::new(),
        storage_files: 0,
        images: 0,
    };
    if cfg.storage && !out.storage.is_empty() {
        let ep = c.e.cfg.endpoints.storage.clone();
        // the crawl's own new documents are queued first and take room from the limit
        let room = doc_room(c)?.saturating_sub(out.doc_pages.len());
        let x = expand_storage(c, net, &ep, &out.storage, known, room).await?;
        annotate_storage(c, &x.listed);
        tracing::info!(target: "foca::scan", "{}: {domain}: хранилища: ссылок {}, папок раскрыто {}, не раскрыто (лимит загрузок) {}, файлов {}",
            c.scan_id, out.storage.len(), x.listed.len(), x.unlisted, x.files.len());
        extra.storage_files = x.files.len();
        for (l, page) in x.files {
            let p = storage_prov(&l, "page", &page);
            extra.items.push((storage_found(&l, "crawler"), p));
        }
    }
    if cfg.images {
        let picked = select_images(out.images.clone(), cfg.max_images);
        extra.images = picked.len();
        for im in picked {
            let p = DocProvenance {
                kind: "page".into(),
                from: im.page.clone(),
                ..Default::default()
            };
            extra.items.push((FoundUrl::new(&im.url, "crawler"), p));
        }
    }
    let mut s = out.stats.clone();
    s.queued = out.frontier.queue.len();
    emit_stats(&c.e, &c.st, &c.scan_id, &s);
    let note = format!(
        "обход: страниц {}, документов {}, файлов в хранилищах {}, изображений {}",
        s.pages, s.docs, extra.storage_files, extra.images
    );
    c.sub_note("crawl", s.pages, s.pages + s.queued, &note);
    tracing::info!(target: "foca::scan", "{}: {domain}: {note}; в очереди обхода {}, отрисовано {}, без браузера {}, ловушек {}, 429/503 {}, темп {:?}",
        c.scan_id, s.queued, s.rendered, s.render_missing, s.trap_skipped, s.limited, s.rate);
    if !s.stopped_hosts.is_empty() {
        c.warn("crawl_rate_limited", &rate_warning(&s.stopped_hosts));
    }
    if s.render_missing > 0 && s.rendered == 0 {
        // CLI and desktop have no platform browser: say so instead of an empty crawl
        c.warn("crawl_no_render", &no_render_warning(s.render_missing));
    }
    Ok(extra)
}

/// Warning for app-shell pages the crawl could not render (no platform browser).
pub(crate) fn no_render_warning(pages: usize) -> String {
    format!(
        "Страниц-приложений на JavaScript без отрисовки: {pages}. Встроенный браузер есть только \
         в Android, поэтому ссылки взяты только из HTML и часть документов могла остаться \
         ненайденной"
    )
}

/// Warning for hosts the crawl stopped because of repeated 429/503 answers.
pub(crate) fn rate_warning(hosts: &[String]) -> String {
    format!(
        "Обход остановлен на хостах, которые повторно отвечали 429/503: {}. Оставшиеся страницы \
         продолжатся в следующем скане",
        hosts.join(", ")
    )
}

/// A crawl summary as the core emits it (for the i18n sample test).
#[cfg(test)]
pub(crate) fn crawl_note_sample() -> String {
    format!(
        "обход: страниц {}, документов {}, файлов в хранилищах {}, изображений {}",
        12, 3, 4, 5
    )
}

/// A crawled image: it has its own count and byte caps instead of the document limit.
pub(crate) fn is_crawled_image(source: &str, url: &str) -> bool {
    source == "crawler"
        && foca_search::filter::ext_of_url(url)
            .is_some_and(|e| foca_search::filter::is_image_ext(&e))
}

/// Room left under the scan's document download limit: the limit minus the download tasks this
/// scan already queued (crawled images excluded).
pub(crate) fn doc_room(c: &Ctx) -> Result<usize, Stop> {
    let limit = lock(&c.st).limit;
    let queued = lock(&c.db)
        .tasks(None)?
        .iter()
        .filter(|t| {
            t.scan_id.as_deref() == Some(c.scan_id.as_str()) && !is_crawled_image(&t.source, &t.url)
        })
        .count();
    Ok(limit.saturating_sub(queued))
}

/// What [`enqueue`] queued and what the document limit left out.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Enqueued {
    pub added: usize,
    pub over_limit: usize,
}

/// Enqueues extra downloads that bypass the search-stage filters (they were checked here:
/// in-scope images, exact storage items) and records their provenance. Documents take at most
/// `room` new tasks (the scan's download limit), in the given order; images keep their own caps.
pub(crate) fn enqueue(
    c: &Ctx,
    queue: &StoreQueue,
    items: Vec<(FoundUrl, DocProvenance)>,
    known: &HashSet<String>,
    room: usize,
) -> Result<Enqueued, Stop> {
    let mut fresh: Vec<FoundUrl> = Vec::new();
    let mut prov: Vec<(String, DocProvenance)> = Vec::new();
    let mut seen = HashSet::new();
    let (mut docs, mut over_limit) = (0usize, 0usize);
    for (f, p) in items {
        let key = foca_search::filter::target_key(&f.url);
        if known.contains(&key) || !seen.insert(key) {
            continue;
        }
        if !is_crawled_image(&f.source, &f.url) {
            if docs >= room {
                over_limit += 1;
                continue;
            }
            docs += 1;
        }
        prov.push((f.url.clone(), p));
        fresh.push(f);
    }
    record_provenance(c, prov)?;
    let added = queue.enqueue(&fresh).map_err(Stop::Error)?;
    Ok(Enqueued { added, over_limit })
}

/// Strips author attribution from a Google export: its metadata describes Google's converter.
pub(crate) fn strip_export(m: &mut foca_core::Metadata) {
    m.author = None;
    m.last_modified_by = None;
    m.company = None;
    m.manager = None;
    m.template = None;
    m.application = None;
    m.producer = None;
    m.os = None;
    m.people.clear();
    m.software.clear();
}

/// URLs of Google exports among the project's documents.
pub(crate) fn export_urls(c: &Ctx) -> HashSet<String> {
    provenance_map(c)
        .into_iter()
        .filter(|(_, p)| p.export)
        .map(|(u, _)| u)
        .collect()
}

/// Collects candidate links from documents of this scan not yet looked at.
pub(crate) fn doc_link_items(
    c: &Ctx,
    cfg: &CrawlCfg,
    done: &mut HashSet<u64>,
) -> Result<Vec<(FoundUrl, DocProvenance)>, Stop> {
    let prov = provenance_map(c);
    let ep = c.e.cfg.endpoints.storage.clone();
    let exts = lock(&c.st).exts.clone();
    let filter = if exts.is_empty() {
        foca_search::filter::ExtFilter::default()
    } else {
        foca_search::filter::ExtFilter::new(&exts)
    };
    let db = lock(&c.db);
    let scope_hosts = known_hosts(&db);
    let docs = db.documents(false)?;
    drop(db);
    let mut out = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    for d in docs {
        if d.first_scan.as_deref() != Some(c.scan_id.as_str()) || !done.insert(d.doc.id) {
            continue;
        }
        let Some(m) = d.doc.metadata.as_ref() else {
            continue;
        };
        let depth = d
            .doc
            .url
            .as_ref()
            .and_then(|u| prov.get(u))
            .map_or(0, |p| p.depth);
        if depth >= cfg.doc_link_depth {
            continue;
        }
        for link in &m.links {
            let Ok(u) = url::Url::parse(link.trim()) else {
                continue;
            };
            if !matches!(u.scheme(), "http" | "https") {
                continue;
            }
            let base = DocProvenance {
                kind: "doc".into(),
                from: d.doc.name.clone(),
                from_doc: Some(d.doc.id),
                depth: depth + 1,
                ..Default::default()
            };
            if cfg.storage {
                if let Some(l) = parse_storage(&u, &ep) {
                    if l.kind != ItemKind::Folder && seen.insert(l.fetch.clone()) {
                        let mut p = storage_prov(&l, "doc", &d.doc.name);
                        p.from_doc = base.from_doc;
                        p.depth = base.depth;
                        out.push((storage_found(&l, &d.doc.source), p));
                    }
                    continue;
                }
            }
            // target documents need the site itself: never at the passive level
            if c.level == "external" || filter.matches(u.as_str()).is_none() {
                continue;
            }
            let host = u.host_str().unwrap_or("").to_ascii_lowercase();
            if !rules::check(&c.scope, &host, &scope_hosts).ok {
                continue;
            }
            let n = foca_search::normalize_url(u.as_str()).unwrap_or_else(|| u.to_string());
            if seen.insert(n.clone()) {
                out.push((FoundUrl::new(&n, &d.doc.source), base));
            }
        }
    }
    Ok(out)
}

/// Byte budget for crawled images: `settings.crawl.max_image_mb`, lowered by the mobile traffic
/// limit when it is on.
pub(crate) fn image_budget(c: &Ctx) -> u64 {
    let cfg = cfg(c);
    let mut mb = cfg.max_image_mb;
    if let Ok(s) = c.e.store().settings_get() {
        if s["power"]["lim_on"].as_bool() == Some(true) {
            if let Some(lim) = s["power"]["mob_limit"].as_u64().filter(|l| *l > 0) {
                mb = mb.min(lim);
            }
        }
    }
    mb * 1024 * 1024
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cfg_floors_without_caps_and_defaults() {
        let c = CrawlCfg::from_value(&default_settings());
        assert_eq!(c.max_depth, 5);
        assert_eq!(c.max_pages, 1000);
        assert_eq!(c.max_minutes, 20);
        assert!(c.storage && c.images && c.doc_links && c.resume);
        let c = CrawlCfg::from_value(
            &json!({ "max_depth": 99, "max_pages": 50000, "max_minutes": 0, "doc_link_depth": 9 }),
        );
        assert_eq!((c.max_depth, c.max_pages, c.max_minutes), (99, 50000, 1));
        assert_eq!(c.doc_link_depth, 9);
    }

    #[test]
    fn export_metadata_loses_authors() {
        let mut m = foca_core::Metadata {
            author: Some("someone".into()),
            producer: Some("Skia/PDF".into()),
            title: Some("Plan".into()),
            ..Default::default()
        };
        strip_export(&mut m);
        assert!(m.author.is_none() && m.producer.is_none());
        assert_eq!(m.title.as_deref(), Some("Plan"));
    }
}
