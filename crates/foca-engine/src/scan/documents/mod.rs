//! Document stages: download queue, metadata extraction and analysis.

pub(crate) mod crawl;

use std::sync::Arc;

use std::collections::HashSet;

use foca_core::api::DocProvenance;
use foca_core::DocStatus;
use foca_search::download::{DownloadConfig, Downloader, TaskQueue};
use foca_search::store::StoreQueue;

use crate::engine::lock;

use super::*;

pub(super) fn downloader(c: &Ctx) -> Downloader {
    let mut cfg = DownloadConfig {
        concurrency: c.e.cfg.download_concurrency,
        ..Default::default()
    };
    cfg.passive_hosts
        .extend(c.e.cfg.passive_download_hosts.iter().cloned());
    // file size limit from the wizard
    if let Some(mb) = lock(&c.st).max_size_mb {
        cfg.max_size = mb * 1024 * 1024;
    }
    // exactly the external storage items linked from in-scope pages
    cfg.storage = Arc::new(crawl::storage_allow(c));
    let dir = c.e.cfg.data_dir.join("files").join(&lock(&c.st).project);
    let target_net = c.group_net("target").unwrap_or_else(|_| c.net.clone());
    Downloader::new(target_net, dir, cfg)
}

pub(super) async fn stage_download(c: &mut Ctx) -> Result<(), Stop> {
    download_queue(c, 1).await
}

/// Downloads the task queue (the download stage, or follow-up downloads found by brute force; `stage` is for progress).
pub(super) async fn download_queue(c: &Ctx, stage: usize) -> Result<(), Stop> {
    let d = downloader(c);
    let q = StoreQueue::new(c.db.clone(), Some(c.scan_id.clone()));
    q.resume().map_err(Stop::Error)?;
    let total = {
        let db = lock(&c.db);
        let t = db.task_counts()?;
        (t.queued + t.downloading) as usize
    };
    let conc = c.e.cfg.download_concurrency.max(1);
    // The queue can grow while it is worked on (late search results, postponed dorks): the total is
    // re-read after every file, so the counter and the bar use the same pair and the growth is
    // reported as `added` in the `files` sub-step.
    let start_total = total;
    let mut breakdown = json!({});
    let mut finished = 0usize;
    let max_attempts = DownloadConfig::default().max_attempts;
    // images (any source) share a byte budget; past it the rest are skipped, not fetched
    let image_budget = crawl::image_budget(c);
    let mut image_bytes = 0u64;
    let mut storage_urls: Vec<String> = Vec::new();
    let mut private = 0usize;
    loop {
        c.gate().await?;
        let batch = q.claim(conc).map_err(Stop::Error)?;
        if batch.is_empty() {
            break;
        }
        let mut set = tokio::task::JoinSet::new();
        for t in batch {
            if image_task(&t) && image_bytes >= image_budget {
                q.failed(&t, "skipped: бюджет трафика на изображения исчерпан", true)
                    .map_err(Stop::Error)?;
                finished += 1;
                continue;
            }
            if is_storage(&d, &t.url) {
                storage_urls.push(t.url.clone());
            }
            let d = d.clone();
            let wb = c.e.cfg.endpoints.wayback.clone();
            set.spawn(async move {
                let mut r = d.download(&t.url).await;
                // a Common Crawl URL that is dead now: its Wayback copy (passive, archive.org)
                if let Err(e) = &r {
                    if let Some(copy) = wayback_fallback(&t.source, &t.url, e, &wb) {
                        tracing::info!(target: "foca::scan", "загрузка: {} недоступен ({e}), копия Wayback", t.url);
                        r = d.download(&copy).await;
                    }
                }
                (t, r)
            });
        }
        while let Some(j) = set.join_next().await {
            let Ok((t, r)) = j else { continue };
            match r {
                Ok(x) => {
                    if image_task(&t) {
                        image_bytes += x.size;
                    }
                    q.done(&t, &x).map_err(Stop::Error)?;
                }
                Err(foca_net::NetError::Cancelled) => {}
                Err(e) => {
                    let closed = is_storage(&d, &t.url)
                        && matches!(e, foca_net::NetError::Status(401 | 403 | 404 | 410));
                    if closed {
                        // a private or removed file on external storage is a fact, not an error
                        private += 1;
                        q.failed(&t, PRIVATE_FILE, true).map_err(Stop::Error)?;
                    } else {
                        let perm = matches!(e, foca_net::NetError::Status(404 | 410))
                            || e.is_scope_denial()
                            || t.attempts >= max_attempts;
                        q.failed(&t, &format!("{}: {e}", e.code()), perm)
                            .map_err(Stop::Error)?;
                    }
                }
            }
            finished += 1;
            let pending = {
                let t = lock(&c.db).task_counts()?;
                (t.queued + t.downloading) as usize
            };
            let total = finished + pending;
            // Only the download stage shows the file pair on its row; follow-up downloads inside
            // the metadata stage report through the `files` sub-step alone.
            c.progress_n(
                stage,
                finished as f64 / total.max(1) as f64,
                (stage == 1).then_some((finished, total)),
            );
            // The breakdown reads the task table: refreshed every few files, not on every one.
            if finished % 10 == 1 || pending == 0 {
                breakdown = queue_breakdown(c)?;
            }
            let mut extra = breakdown.clone();
            extra["added"] = json!(total.saturating_sub(start_total));
            c.substep_event("files", "running", finished, total, extra);
        }
        if c.cancel.is_cancelled() {
            return Err(Stop::Cancelled);
        }
    }
    let mut extra = queue_breakdown(c)?;
    extra["added"] = json!(finished.saturating_sub(start_total));
    c.substep_event("files", "done", finished, finished, extra);
    storage_urls.sort();
    storage_urls.dedup();
    crawl::annotate_storage(c, &storage_urls);
    if !storage_urls.is_empty() {
        let got = storage_urls.len().saturating_sub(private);
        let note = storage_note(got, private);
        tracing::info!(target: "foca::scan", "{}: внешние хранилища: {note}", c.scan_id);
        c.sub_note("storage", got, storage_urls.len(), &note);
    }
    Ok(())
}

/// Wayback copy URL for a failed download of a Common Crawl hit (dead now: 404/410, 5xx, DNS or
/// connection errors). The nearest capture of the current year is asked (`id_`, original bytes).
pub(crate) fn wayback_fallback(
    source: &str,
    url: &str,
    e: &foca_net::NetError,
    wayback: &str,
) -> Option<String> {
    use foca_net::NetError as N;
    if source != "cc" || url.contains("/web/") && url.starts_with(wayback) {
        return None;
    }
    let dead = match e {
        N::Status(s) => *s == 404 || *s == 410 || *s >= 500,
        N::Dns(_) | N::Request(_) | N::Timeout => true,
        _ => false,
    };
    if !dead || e.is_scope_denial() {
        return None;
    }
    let year = time::OffsetDateTime::now_utc().year().to_string();
    Some(foca_search::sources::copy_url(wayback, &year, url))
}

/// What the download queue turned into, for the stage line: `docs` = rows in the project's
/// document list (the Documents tab count; `images` among them), and this scan's tasks that ended
/// `failed` (404, timeouts), `private` (closed storage files), `skipped` (image budget) or as a
/// `duplicates` of a document already in the list (same SHA-256).
pub(crate) fn queue_breakdown(c: &Ctx) -> Result<Value, Stop> {
    let db = lock(&c.db);
    let docs = db.documents(false)?;
    let images = docs
        .iter()
        .filter(|d| crawl::is_image(d.doc.url.as_deref().unwrap_or(&d.doc.name)))
        .count();
    let tasks = db.tasks(None)?;
    drop(db);
    let (mut failed, mut private, mut skipped, mut dup) = (0usize, 0usize, 0usize, 0usize);
    let mut seen: HashSet<u64> = HashSet::new();
    for t in &tasks {
        let mine = t.scan_id.as_deref() == Some(c.scan_id.as_str());
        match t.state {
            foca_store::TaskState::Done => {
                if let Some(id) = t.doc_id {
                    if !seen.insert(id) && mine {
                        dup += 1;
                    }
                }
            }
            foca_store::TaskState::Failed if mine => {
                let e = t.last_error.as_deref().unwrap_or("");
                if e.starts_with("private:") {
                    private += 1;
                } else if e.starts_with("skipped:") {
                    skipped += 1;
                } else {
                    failed += 1;
                }
            }
            _ => {}
        }
    }
    Ok(json!({
        "docs": docs.len(), "images": images, "failed": failed, "private": private,
        "skipped": skipped, "duplicates": dup,
    }))
}

/// Summary of linked external storage downloads (core message `download.storage`). The scan screen
/// puts the sub-step label ("External storage") in front, so the text does not repeat it.
pub(crate) fn storage_note(got: usize, private: usize) -> String {
    format!("скачано {got}, без публичного доступа {private}")
}

/// Task error of a file on external storage that is not public (or was removed).
pub(crate) const PRIVATE_FILE: &str = "private: файл во внешнем хранилище закрыт или удалён";

fn image_task(t: &foca_search::QueuedTask) -> bool {
    crawl::is_image(&t.url)
}

fn is_storage(d: &Downloader, url: &str) -> bool {
    d.is_storage(url)
}

pub(super) async fn stage_meta(c: &mut Ctx) -> Result<(), Stop> {
    meta_pending(c, 2).await?;
    follow_doc_links(c, 2).await
}

/// Follows links found inside documents analyzed in this scan: in-scope document links and
/// linked external storage files are downloaded with provenance `doc`, up to
/// `doc_link_depth` steps from a crawled page or search result, within the download limit.
pub(super) async fn follow_doc_links(c: &Ctx, stage: usize) -> Result<(), Stop> {
    let cfg = crawl::cfg(c);
    if !cfg.doc_links || cfg.doc_link_depth == 0 {
        return Ok(());
    }
    let mut done: HashSet<u64> = HashSet::new();
    for round in 0..cfg.doc_link_depth {
        c.gate().await?;
        // the scan's download limit covers documents found inside documents too
        let room = crawl::doc_room(c)?;
        if room == 0 {
            tracing::info!(target: "foca::scan", "{}: ссылки из документов: лимит загрузок исчерпан", c.scan_id);
            break;
        }
        let items: Vec<(foca_search::FoundUrl, DocProvenance)> =
            crawl::doc_link_items(c, &cfg, &mut done)?;
        if items.is_empty() {
            break;
        }
        let known: HashSet<String> = lock(&c.db)
            .task_urls()?
            .iter()
            .map(|u| foca_search::filter::target_key(u))
            .collect();
        let queue = StoreQueue::new(c.db.clone(), Some(c.scan_id.clone()));
        let q = crawl::enqueue(c, &queue, items, &known, room)?;
        tracing::info!(target: "foca::scan", "{}: ссылки из документов: в загрузку {}, сверх лимита {}", c.scan_id, q.added, q.over_limit);
        if q.added == 0 {
            break;
        }
        // Visible sub-phase: links found inside documents, round N of the configured depth.
        c.substep_event(
            "doclinks",
            "running",
            round.into(),
            cfg.doc_link_depth.into(),
            json!({ "added": q.added }),
        );
        download_queue(c, stage).await?;
        meta_pending(c, stage).await?;
    }
    c.substep_event("doclinks", "done", 0, 0, json!({}));
    Ok(())
}

/// Parses downloaded documents (the metadata extraction stage, or after brute force).
pub(super) async fn meta_pending(c: &Ctx, stage: usize) -> Result<(), Stop> {
    let exports = crawl::export_urls(c);
    let todo: Vec<(u64, String, String, bool)> = {
        let db = lock(&c.db);
        db.documents(false)?
            .into_iter()
            .filter(|d| d.doc.status == DocStatus::Downloaded)
            .filter_map(|d| {
                let export = d.doc.url.as_ref().is_some_and(|u| exports.contains(u));
                Some((d.doc.id, d.local_path?, d.doc.name, export))
            })
            .collect()
    };
    let total = todo.len().max(1);
    let sem = Arc::new(tokio::sync::Semaphore::new(c.e.cfg.meta_concurrency.max(1)));
    let mut set = tokio::task::JoinSet::new();
    let mut done = 0usize;
    let mut it = todo.into_iter();
    let ocr_cfg = crate::services::ocr::OcrSettings::from_settings(
        &c.e.store().settings_get().unwrap_or_default(),
    );
    let ocr_prov = c.e.current_ocr();
    loop {
        // keep up to meta_concurrency parses in flight; pause/cancel is checked between documents
        while set.len() < c.e.cfg.meta_concurrency.max(1) {
            c.gate().await?;
            let Some((id, path, name, export)) = it.next() else {
                break;
            };
            let permit = sem
                .clone()
                .acquire_owned()
                .await
                .map_err(|e| Stop::Error(e.to_string()))?;
            let ocr_c = ocr_cfg.clone();
            let ocr_p = ocr_prov.clone();
            set.spawn_blocking(move || {
                let _p = permit;
                // A panic while parsing one file becomes a parse error for that document instead of leaving it
                // "downloaded" forever; the scan continues with the batch.
                let r = crate::util::catch_panic(|| {
                    let lim = foca_meta::Limits::default();
                    // The download size limit can be lifted by the user: never pull a file the
                    // parser would refuse anyway into memory.
                    let size = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
                    if size > lim.max_file {
                        return Err(foca_meta::MetaError::TooLarge {
                            size,
                            limit: lim.max_file,
                        }
                        .to_string());
                    }
                    std::fs::read(&path)
                        .map_err(|e| e.to_string())
                        .and_then(|b| {
                            let mut m = foca_meta::extract(&b, Some(&name), &lim)
                                .map_err(|e| e.to_string())?;
                            if export {
                                // Google rendered this file: its metadata is not the author's
                                crawl::strip_export(&mut m);
                            }
                            let mut t = foca_meta::text(&b, &lim).ok();
                            if let Some(ot) = crate::services::ocr::maybe_ocr(
                                &ocr_c,
                                ocr_p.as_deref(),
                                std::path::Path::new(&path),
                                &name,
                                &b,
                                t.as_deref(),
                            ) {
                                t = Some(ot);
                            }
                            Ok((m, t))
                        })
                });
                (id, r)
            });
        }
        let Some(j) = set.join_next().await else {
            break;
        };
        if let Ok((id, r)) = j {
            let db = lock(&c.db);
            match r {
                Ok((m, t)) => db.set_analyzed(id, &m, t.as_deref())?,
                Err(e) => db.set_doc_error(id, &e)?,
            }
            done += 1;
            drop(db);
            c.progress_n(stage, done as f64 / total as f64, Some((done, total)));
        }
        if c.cancel.is_cancelled() {
            return Err(Stop::Cancelled);
        }
    }
    Ok(())
}

pub(super) async fn stage_analysis(c: &mut Ctx) -> Result<(), Stop> {
    let new = reanalyze_bg(c).await?;
    c.findings_events(&new);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::wayback_fallback;
    use foca_net::NetError;

    #[test]
    fn dead_cc_urls_fall_back_to_wayback() {
        let wb = "https://web.archive.org";
        let u = "https://www.example.com/a.pdf";
        let c = wayback_fallback("cc", u, &NetError::Status(404), wb).unwrap();
        assert!(c.starts_with("https://web.archive.org/web/20"), "{c}");
        assert!(c.ends_with("id_/https://www.example.com/a.pdf"), "{c}");
        assert!(wayback_fallback("cc", u, &NetError::Dns("nx".into()), wb).is_some());
        assert!(wayback_fallback("cc", u, &NetError::Status(503), wb).is_some());
        // other sources, other errors and archive copies themselves keep the normal path
        assert!(wayback_fallback("brave", u, &NetError::Status(404), wb).is_none());
        assert!(wayback_fallback("cc", u, &NetError::Status(403), wb).is_none());
        assert!(wayback_fallback("cc", u, &NetError::TooLarge { limit: 1 }, wb).is_none());
        let copy = format!("{wb}/web/2024id_/{u}");
        assert!(wayback_fallback("cc", &copy, &NetError::Status(404), wb).is_none());
    }
}
