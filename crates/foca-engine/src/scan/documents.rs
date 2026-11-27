//! Document stages: download queue, metadata extraction and analysis.

use std::sync::Arc;

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
    let mut finished = 0usize;
    let max_attempts = DownloadConfig::default().max_attempts;
    loop {
        c.gate().await?;
        let batch = q.claim(conc).map_err(Stop::Error)?;
        if batch.is_empty() {
            break;
        }
        let mut set = tokio::task::JoinSet::new();
        for t in batch {
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
                    q.done(&t, &x).map_err(Stop::Error)?;
                }
                Err(foca_net::NetError::Cancelled) => {}
                Err(e) => {
                    let perm = matches!(e, foca_net::NetError::Status(404 | 410))
                        || e.is_scope_denial()
                        || t.attempts >= max_attempts;
                    q.failed(&t, &format!("{}: {e}", e.code()), perm)
                        .map_err(Stop::Error)?;
                }
            }
            finished += 1;
            c.progress_n(
                stage,
                finished as f64 / total.max(1) as f64,
                Some((finished, total.max(finished))),
            );
        }
        if c.cancel.is_cancelled() {
            return Err(Stop::Cancelled);
        }
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

pub(super) async fn stage_meta(c: &mut Ctx) -> Result<(), Stop> {
    meta_pending(c, 2).await
}

/// Parses downloaded documents (the metadata extraction stage, or after brute force).
pub(super) async fn meta_pending(c: &Ctx, stage: usize) -> Result<(), Stop> {
    let todo: Vec<(u64, String, String)> = {
        let db = lock(&c.db);
        db.documents(false)?
            .into_iter()
            .filter(|d| d.doc.status == DocStatus::Downloaded)
            .filter_map(|d| Some((d.doc.id, d.local_path?, d.doc.name)))
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
            let Some((id, path, name)) = it.next() else {
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
                            let m = foca_meta::extract(&b, Some(&name), &lim)
                                .map_err(|e| e.to_string())?;
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
