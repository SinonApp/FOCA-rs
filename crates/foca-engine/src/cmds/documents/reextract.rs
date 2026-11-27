//! Re-analysis of documents already in a project (`project_reextract`): stored files are parsed
//! again with the current parsers, missing files can be downloaded again from their URL, then
//! the analysis runs once. No search, no crawl: only documents the project already has.
//!
//! The run is a background job per project with `reextract` events. Each processed document gets
//! the run's mark (`documents.reextract_mark`) and the run itself is stored in the project
//! settings, so a killed process continues where it stopped on the next `project_reextract`.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use foca_core::api::DocProvenance;
use foca_core::extractor::FORMAT_REV;
use foca_core::{DocStatus, Scope};
use foca_search::download::{DownloadConfig, Downloader};
use foca_search::store::{SharedDb, StoreSink};
use foca_store::project::StoredDoc;
use foca_store::{ProjectDb, PROVENANCE_KEY};
use serde_json::{json, Value};
use tokio_util::sync::CancellationToken;

use crate::analysis::facts;
use crate::engine::lock;
use crate::util::{arg_ids, arg_str};
use crate::{CmdError, CmdResult, Engine};

/// Project setting with the unfinished run (resumed after a kill).
const RUN_KEY: &str = "reextract.run";
/// Project setting with the summary of the last finished run.
const LAST_KEY: &str = "reextract.last";

pub(crate) const BUSY_SCAN: &str =
    "Идёт скан: повторный анализ документов можно запустить после его завершения";
pub(crate) const BUSY_RUN: &str = "Повторный анализ документов уже идёт";
pub(crate) const NOTHING: &str = "Все документы уже разобраны текущей версией";

/// How a run ended for one document.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Outcome {
    Reparsed,
    Downloaded,
    NoFile,
    Failed,
}

/// Where the file of a stored document is now. The stored absolute path wins; a data directory
/// that moved (backup restore, another device, a copied project) still has the file under
/// `files/<project>/` with the same name.
pub(crate) fn resolve_local(
    data_dir: &Path,
    project: &str,
    stored: Option<&str>,
) -> Option<PathBuf> {
    let stored = stored.filter(|s| !s.is_empty())?;
    let p = PathBuf::from(stored);
    if p.is_file() {
        return Some(p);
    }
    let name = p.file_name()?;
    let base = data_dir.join("files").join(project);
    [base.join("files").join(name), base.join(name)]
        .into_iter()
        .find(|c| c.is_file())
}

/// Counts the summary compares before and after a run.
fn counts(db: &ProjectDb) -> Result<Value, CmdError> {
    let docs = db.documents(false)?;
    let text = docs
        .iter()
        .filter(|d| d.text.as_deref().is_some_and(|t| !t.trim().is_empty()))
        .count();
    let n = |k: &str| -> usize {
        db.entity(k)
            .ok()
            .and_then(|v| v.as_array().map(Vec::len))
            .unwrap_or(0)
    };
    let mut sev: BTreeMap<String, usize> = ["crit", "high", "warn", "low", "info"]
        .iter()
        .map(|s| (s.to_string(), 0))
        .collect();
    let mut live = Vec::new();
    for (id, s, status, present) in db.finding_states()? {
        if present && status != "false" {
            *sev.entry(s).or_default() += 1;
            live.push(id);
        }
    }
    Ok(json!({
        "docs": docs.len(), "text": text, "people": n("people"), "emails": n("emails"),
        "phones": n("phones"), "findings": sev, "findings_total": live.len(), "live": live,
    }))
}

/// Documents a run may touch: not deleted, already stored (analysed or failed to parse), limited
/// to `ids` when given.
fn candidates(docs: Vec<StoredDoc>, ids: &[u64]) -> Vec<StoredDoc> {
    docs.into_iter()
        .filter(|d| !d.deleted)
        .filter(|d| matches!(d.doc.status, DocStatus::Analyzed | DocStatus::Error))
        .filter(|d| {
            d.doc.status != DocStatus::Error
                || d.error_kind.as_deref().unwrap_or("parse") == "parse"
        })
        .filter(|d| ids.is_empty() || ids.contains(&d.doc.id))
        .collect()
}

/// Parses one file with the scan's limits; `export` drops metadata a Google export wrote.
fn parse_file(
    path: &Path,
    name: &str,
    export: bool,
    ocr_c: &crate::services::ocr::OcrSettings,
    ocr_p: Option<&dyn crate::OcrProvider>,
) -> Result<(foca_core::Metadata, Option<String>), String> {
    crate::util::catch_panic(|| {
        let lim = foca_meta::Limits::default();
        let size = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
        if size > lim.max_file {
            return Err(foca_meta::MetaError::TooLarge {
                size,
                limit: lim.max_file,
            }
            .to_string());
        }
        let b = std::fs::read(path).map_err(|e| e.to_string())?;
        let mut m = foca_meta::extract(&b, Some(name), &lim).map_err(|e| e.to_string())?;
        if export {
            crate::scan::documents::crawl::strip_export(&mut m);
        }
        let mut t = foca_meta::text(&b, &lim).ok();
        if let Some(ot) =
            crate::services::ocr::maybe_ocr(ocr_c, ocr_p, path, name, &b, t.as_deref())
        {
            t = Some(ot);
        }
        Ok((m, t))
    })
}

/// A mark unique to one run (wall time plus a process counter: the engine clock may stand still).
fn run_mark() -> String {
    static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let t = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    let n = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    format!("r{FORMAT_REV}-{t}-{n}")
}

impl Engine {
    /// `reextract_status { project }`: the running job, an unfinished run, the last summary and
    /// how many documents an older extraction revision analysed.
    pub(crate) fn reextract_status(&self, a: &Value) -> CmdResult {
        let id = self.project_arg(a)?;
        let db = self.db(&id)?;
        let db = lock(&db);
        let revs: BTreeMap<u64, u32> = db.doc_revs()?.into_iter().map(|r| (r.id, r.rev)).collect();
        let docs = candidates(db.documents(false)?, &[]);
        let (mut outdated, mut with_file, mut missing, mut missing_bytes, mut no_url) =
            (0, 0, 0, 0u64, 0);
        let (mut files, mut total_missing, mut total_missing_bytes) = (0, 0, 0u64);
        for d in &docs {
            let old = revs.get(&d.doc.id).copied().unwrap_or(0) < FORMAT_REV;
            let has =
                resolve_local(&self.inner.cfg.data_dir, &id, d.local_path.as_deref()).is_some();
            if has {
                files += 1;
            } else if d.doc.url.is_some() {
                total_missing += 1;
                total_missing_bytes += d.doc.size;
            }
            if !old {
                continue;
            }
            outdated += 1;
            if has {
                with_file += 1;
            } else if d.doc.url.is_some() {
                missing += 1;
                missing_bytes += d.doc.size;
            } else {
                no_url += 1;
            }
        }
        let running = lock(&self.inner.reextract_jobs)
            .get(&id)
            .map(|j| j.progress.clone());
        let pending = db.setting(RUN_KEY)?.filter(|r| !r.is_null()).map(|r| {
            json!({ "mode": r["mode"], "started": r["started"], "total": r["total"],
                "done": r["done"], "ids": r["ids"] })
        });
        Ok(json!({
            "project": id, "format_rev": FORMAT_REV, "version": foca_core::extractor::VERSION,
            "docs": docs.len(), "files": files, "missing": total_missing,
            "missing_bytes": total_missing_bytes,
            "outdated": { "total": outdated, "files": with_file, "missing": missing,
                "missing_bytes": missing_bytes, "no_url": no_url },
            "running": running, "pending": pending,
            "last": db.setting(LAST_KEY)?,
            "scan_running": self.active_scan_id().is_some(),
        }))
    }

    /// `reextract_cancel { project }`: stops the running re-analysis after the current document.
    /// The unfinished run stays and continues with the next `project_reextract`.
    pub(crate) fn reextract_cancel(&self, a: &Value) -> CmdResult {
        let id = self.project_arg(a)?;
        let tok = lock(&self.inner.reextract_jobs)
            .get(&id)
            .map(|j| j.cancel.clone());
        if let Some(t) = &tok {
            t.cancel();
        }
        Ok(json!({ "cancelled": tok.is_some() }))
    }

    /// `project_reextract { project, mode: "stored" | "stored_and_missing", ids?, outdated?, restart?, wait? }`.
    /// Starts the background run and returns `{ started, resumed, total }`; with `wait: true`
    /// (CLI, tests) it returns the final summary instead.
    pub(crate) async fn project_reextract(&self, a: &Value) -> CmdResult {
        let id = self.project_arg(a)?;
        if self.active_scan_id().is_some()
            || self
                .inner
                .finishing
                .load(std::sync::atomic::Ordering::SeqCst)
        {
            return Err(CmdError::new("busy", BUSY_SCAN));
        }
        let db = self.db(&id)?;
        let mode = match arg_str(a, "mode").unwrap_or("stored") {
            "stored_and_missing" => "stored_and_missing",
            "stored" => "stored",
            m => return Err(CmdError::new("bad_args", format!("mode: {m}"))),
        };
        let mut ids = arg_ids(a, "ids");
        // `outdated: true`: only documents an older extraction revision analysed
        if ids.is_empty() && a.get("outdated").and_then(Value::as_bool) == Some(true) {
            let g = lock(&db);
            let old: BTreeSet<u64> = g
                .doc_revs()?
                .into_iter()
                .filter(|r| r.rev < FORMAT_REV)
                .map(|r| r.id)
                .collect();
            ids = candidates(g.documents(false)?, &[])
                .into_iter()
                .map(|d| d.doc.id)
                .filter(|id| old.contains(id))
                .collect();
            if ids.is_empty() {
                return Err(CmdError::new("nothing", NOTHING));
            }
        }
        let restart = a.get("restart").and_then(Value::as_bool).unwrap_or(false);
        let (run, resumed) = {
            let g = lock(&db);
            match g.setting(RUN_KEY)?.filter(|v| !v.is_null() && !restart) {
                Some(r) => (r, true),
                None => {
                    let total = candidates(g.documents(false)?, &ids).len();
                    let r = json!({
                        "mark": run_mark(),
                        "mode": mode, "ids": ids, "started": self.now_iso(), "total": total,
                        "done": 0, "before": counts(&g)?, "tally": {},
                    });
                    g.set_setting(RUN_KEY, &r)?;
                    (r, false)
                }
            }
        };
        let total = run["total"].as_u64().unwrap_or(0);
        let run_mode = run["mode"].clone();
        let cancel = CancellationToken::new();
        {
            let mut jobs = lock(&self.inner.reextract_jobs);
            if jobs.contains_key(&id) {
                return Err(CmdError::new("busy", BUSY_RUN));
            }
            jobs.insert(
                id.clone(),
                crate::engine::ReJob {
                    cancel: cancel.clone(),
                    handle: None,
                    progress: json!({ "done": run["done"], "total": total, "name": "", "stage": "start" }),
                },
            );
        }
        let wait = a.get("wait").and_then(Value::as_bool).unwrap_or(false);
        let e = self.clone();
        let pid = id.clone();
        let fut = async move {
            let r = e.reextract_run(&pid, db, run, cancel).await;
            lock(&e.inner.reextract_jobs).remove(&pid);
            match r {
                Ok(v) => v,
                Err(err) => {
                    tracing::warn!(target: "foca::engine", "повторный анализ {pid}: {}", err.message);
                    let ev = json!({ "type": "reextract", "project": pid, "stage": "error",
                        "error": err.message, "code": err.code });
                    e.emit(ev.clone());
                    ev
                }
            }
        };
        if wait {
            let v = fut.await;
            if v["stage"] == "error" {
                return Err(CmdError::new(
                    v["code"].as_str().unwrap_or("internal"),
                    v["error"].as_str().unwrap_or(""),
                ));
            }
            return Ok(v);
        }
        let h = tokio::spawn(async move {
            fut.await;
        });
        if let Some(j) = lock(&self.inner.reextract_jobs).get_mut(&id) {
            j.handle = Some(h);
        }
        Ok(json!({ "started": true, "resumed": resumed, "total": total, "mode": run_mode }))
    }

    fn reextract_progress(&self, project: &str, stage: &str, done: u64, total: u64, name: &str) {
        let p = json!({ "done": done, "total": total, "name": name, "stage": stage });
        if let Some(j) = lock(&self.inner.reextract_jobs).get_mut(project) {
            j.progress = p.clone();
        }
        let mut ev = p;
        ev["type"] = json!("reextract");
        ev["project"] = json!(project);
        self.emit(ev);
    }

    /// Downloader for re-fetching stored URLs: the project's scope without the active phase,
    /// exclusions never touched, the user's network settings (rate, proxy, timeouts) applied.
    fn reextract_downloader(
        &self,
        project: &str,
        db: &SharedDb,
        cancel: &CancellationToken,
    ) -> Result<Downloader, CmdError> {
        let (scope, prov) = {
            let g = lock(db);
            let prov: BTreeMap<String, DocProvenance> = facts::get(&g, PROVENANCE_KEY);
            (g.scope_get()?, prov)
        };
        let sink = Arc::new(StoreSink {
            db: db.clone(),
            scan_id: None,
        });
        let core = crate::scan::core_scope_for(&scope, "standard");
        let net = self
            .net_client_group(core, sink, None, Some("target"))?
            .with_cancel(cancel.clone());
        net.set_passive_guard(Scope::from(&scope), false);
        let mut cfg = DownloadConfig {
            concurrency: 1,
            ..Default::default()
        };
        cfg.passive_hosts
            .extend(self.inner.cfg.passive_download_hosts.iter().cloned());
        cfg.storage = Arc::new(crate::scan::documents::crawl::storage_allow_for(
            prov,
            &self.inner.cfg.endpoints.storage,
        ));
        Ok(Downloader::new(
            net,
            self.inner.cfg.data_dir.join("files").join(project),
            cfg,
        ))
    }

    /// Why downloads may not run now: Wi-Fi only on a mobile network, or the monthly mobile limit.
    fn reextract_net_block(&self) -> Option<&'static str> {
        let s = self.store().settings_get().unwrap_or_default();
        if self.mobile.metered() && s["power"]["wifi_only"].as_bool().unwrap_or(true) {
            return Some("wifi_only");
        }
        if self.mobile.reached() {
            return Some("mobile_limit");
        }
        None
    }

    async fn reextract_run(
        &self,
        project: &str,
        db: SharedDb,
        mut run: Value,
        cancel: CancellationToken,
    ) -> Result<Value, CmdError> {
        let mark = run["mark"].as_str().unwrap_or("r").to_string();
        let mode = run["mode"].as_str().unwrap_or("stored").to_string();
        let ids = arg_ids(&run, "ids");
        let total = run["total"].as_u64().unwrap_or(0);
        let todo: Vec<StoredDoc> = {
            let g = lock(&db);
            let marks: BTreeMap<u64, Option<String>> =
                g.doc_revs()?.into_iter().map(|r| (r.id, r.mark)).collect();
            candidates(g.documents(false)?, &ids)
                .into_iter()
                .filter(|d| {
                    marks.get(&d.doc.id).cloned().flatten().as_deref() != Some(mark.as_str())
                })
                .collect()
        };
        let exports: BTreeSet<String> = {
            let g = lock(&db);
            let prov: BTreeMap<String, DocProvenance> = facts::get(&g, PROVENANCE_KEY);
            prov.into_iter()
                .filter(|(_, p)| p.export)
                .map(|(u, _)| u)
                .collect()
        };
        let ocr_cfg = crate::services::ocr::OcrSettings::from_settings(
            &self.store().settings_get().unwrap_or_default(),
        );
        let ocr_prov = self.current_ocr();
        let mut done = run["done"].as_u64().unwrap_or(0);
        let mut tally: BTreeMap<String, u64> =
            serde_json::from_value(run["tally"].clone()).unwrap_or_default();
        let mut net_block: Option<&'static str> = None;
        let mut dl: Option<Downloader> = None;
        tracing::info!(target: "foca::engine", "повторный анализ {project}: режим {mode}, документов {}, всего {total}", todo.len());
        self.reextract_progress(project, "start", done, total, "");
        let mut stop: Option<&'static str> = None;
        for (i, d) in todo.into_iter().enumerate() {
            if cancel.is_cancelled() {
                stop = Some("cancelled");
                break;
            }
            // A scan has priority: the run stops and continues later from the same place.
            if self.active_scan_id().is_some() {
                stop = Some("yielded");
                break;
            }
            let name = d.doc.name.clone();
            self.reextract_progress(project, "file", done, total, &name);
            let mut path =
                resolve_local(&self.inner.cfg.data_dir, project, d.local_path.as_deref());
            let mut outcome = None;
            if path.is_none() && mode == "stored_and_missing" {
                if let Some(url) = d.doc.url.clone() {
                    net_block = net_block.or_else(|| self.reextract_net_block());
                    if net_block.is_none() {
                        if dl.is_none() {
                            dl = Some(self.reextract_downloader(project, &db, &cancel)?);
                        }
                        self.reextract_progress(project, "download", done, total, &name);
                        match dl.as_ref().map(|x| x.download(&url)) {
                            Some(f) => match f.await {
                                Ok(x) => {
                                    let p = x.path.to_string_lossy().into_owned();
                                    if lock(&db).relink_file(d.doc.id, &x.sha256, x.size, &p)? {
                                        path = Some(x.path.clone());
                                        outcome = Some(Outcome::Downloaded);
                                    } else {
                                        outcome = Some(Outcome::Failed);
                                    }
                                }
                                Err(foca_net::NetError::Cancelled) => {
                                    stop = Some("cancelled");
                                    break;
                                }
                                Err(e) => {
                                    tracing::info!(target: "foca::engine", "повторный анализ: {url} не скачан: {e}");
                                    outcome = Some(Outcome::Failed);
                                }
                            },
                            None => outcome = Some(Outcome::Failed),
                        }
                    }
                }
            }
            if let Some(p) = path.clone() {
                let export = d.doc.url.as_ref().is_some_and(|u| exports.contains(u));
                let (oc, op, nm) = (ocr_cfg.clone(), ocr_prov.clone(), name.clone());
                let r = tokio::task::spawn_blocking(move || {
                    parse_file(&p, &nm, export, &oc, op.as_deref())
                })
                .await
                .map_err(CmdError::internal)?;
                let g = lock(&db);
                match r {
                    Ok((m, t)) => {
                        g.set_analyzed(d.doc.id, &m, t.as_deref())?;
                        outcome = Some(outcome.unwrap_or(Outcome::Reparsed));
                    }
                    Err(e) => {
                        // A document that parsed before keeps its data: a new parser failing on
                        // it must not erase what an older one found.
                        if d.doc.status == DocStatus::Error {
                            g.set_doc_error(d.doc.id, &e)?;
                        }
                        tracing::info!(target: "foca::engine", "повторный анализ: {name} не разобран: {e}");
                        outcome = Some(Outcome::Failed);
                    }
                }
            }
            let outcome = outcome.unwrap_or(Outcome::NoFile);
            let key = match outcome {
                Outcome::Reparsed => "reparsed",
                Outcome::Downloaded => "downloaded",
                Outcome::NoFile => "no_file",
                Outcome::Failed => "failed",
            };
            *tally.entry(key.into()).or_default() += 1;
            done += 1;
            {
                let g = lock(&db);
                g.set_reextract_mark(d.doc.id, &mark)?;
                // the run record follows every few documents (resume needs only the marks)
                if i % 10 == 9 {
                    run["done"] = json!(done);
                    run["tally"] = json!(tally);
                    g.set_setting(RUN_KEY, &run)?;
                }
            }
            tokio::task::yield_now().await;
        }
        run["done"] = json!(done);
        run["tally"] = json!(tally);
        if let Some(s) = stop {
            lock(&db).set_setting(RUN_KEY, &run)?;
            let ev = json!({ "type": "reextract", "project": project, "stage": s,
                "done": done, "total": total, "name": "" });
            self.emit(ev.clone());
            tracing::info!(target: "foca::engine", "повторный анализ {project}: {s} на {done}/{total}");
            return Ok(ev);
        }
        self.reextract_progress(project, "analysis", done, total, "");
        let e = self.clone();
        let db2 = db.clone();
        let summary = tokio::task::spawn_blocking(move || -> Result<Value, CmdError> {
            let g = lock(&db2);
            let new = crate::analysis::insights::reanalyze(&g, None)?;
            let after = counts(&g)?;
            let map = facts::assign_fids(&g)?;
            let before = &run["before"];
            let was: BTreeSet<u64> =
                serde_json::from_value(before["live"].clone()).unwrap_or_default();
            let now: BTreeSet<u64> =
                serde_json::from_value(after["live"].clone()).unwrap_or_default();
            let added: Vec<u64> = now.difference(&was).map(|h| map.get(*h)).collect();
            let removed = was.difference(&now).count();
            let strip = |mut v: Value| {
                if let Some(o) = v.as_object_mut() {
                    o.remove("live");
                }
                v
            };
            let summary = json!({
                "mode": run["mode"], "ids": run["ids"], "started": run["started"],
                "finished": e.now_iso(), "format_rev": FORMAT_REV,
                "version": foca_core::extractor::VERSION,
                "total": run["total"], "processed": done,
                "reparsed": tally.get("reparsed").copied().unwrap_or(0),
                "downloaded": tally.get("downloaded").copied().unwrap_or(0),
                "no_file": tally.get("no_file").copied().unwrap_or(0),
                "failed": tally.get("failed").copied().unwrap_or(0),
                "net_blocked": net_block,
                "before": strip(before.clone()), "after": strip(after),
                "new_findings": added.len(), "new_ids": added, "removed_findings": removed,
                "new_events": new.len(),
            });
            g.set_setting(LAST_KEY, &summary)?;
            // a null record means no unfinished run
            g.set_setting(RUN_KEY, &Value::Null)?;
            let _ = e.store().refresh_summary(&g);
            Ok(summary)
        })
        .await
        .map_err(CmdError::internal)??;
        tracing::info!(target: "foca::engine", "повторный анализ {project}: готово {}", summary);
        let ev = json!({ "type": "reextract", "project": project, "stage": "done",
            "done": done, "total": total, "name": "", "summary": summary });
        self.emit(ev.clone());
        self.emit(json!({ "type": "db", "project": project, "kind": "docs" }));
        Ok(ev)
    }
}
