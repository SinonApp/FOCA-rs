//! Deleting one scan of a project (`scan_delete`): the store erases the scan and what only it
//! produced; this side stops a running scan first, prunes engine state stored per scan (network
//! facts, history extras, alert log, cleaned copies, queue rows), wipes the files and rewrites
//! the remaining history so it carries no trace of the deleted scan. Also the postponed dork
//! groups of a project (`dorks_pending`, `dorks_retry`); their queue and in-scan retry live in
//! `scan::search::dorks`.

use std::collections::BTreeMap;

use foca_core::api::{Scan, ScanSnapshot};
use foca_store::{ProjectDb, ScanErase};
use serde_json::{json, Value};

use crate::analysis::facts::{self, FidMap, NetFacts};
use crate::analysis::insights;
use crate::engine::lock;
use crate::scan::search::dorks::{load, RETRY_ENGINES};
use crate::scan::sources;
use crate::util::req_str;
use crate::{CmdError, CmdResult, Engine};

/// What a deletion would remove (also the `dry_run` answer): documents downloaded by the scan,
/// findings first seen in it, hosts it discovered and its request log rows.
fn footprint(db: &ProjectDb, sid: &str) -> Result<Value, CmdError> {
    let docs = db
        .documents(true)?
        .iter()
        .filter(|d| d.first_scan.as_deref() == Some(sid))
        .count();
    let findings = db
        .findings()?
        .iter()
        .filter(|f| f.first_scan.as_deref() == Some(sid))
        .count();
    let nf: NetFacts = facts::get(db, facts::K_NET);
    let hosts = nf
        .hosts
        .values()
        .filter(|h| h.first_scan.as_deref() == Some(sid))
        .count();
    let requests = db.requests(Some(sid), false)?.len();
    Ok(
        json!({ "docs": docs, "findings": findings, "hosts": hosts, "requests": requests, "files": 0 }),
    )
}

/// Keeps network facts first seen in the deleted scan only when a later scan still listed them
/// (its snapshot), moving their first scan there; the rest goes.
fn prune_net_facts(
    db: &ProjectDb,
    sid: &str,
    later: &[Scan],
    fids: &FidMap,
) -> Result<(), CmdError> {
    let mut nf: NetFacts = facts::get(db, facts::K_NET);
    let before = nf.clone();
    let host_seen = |name: &str| {
        later
            .iter()
            .find(|s| s.snapshot.hosts.contains_key(name))
            .map(|s| s.id.clone())
    };
    nf.hosts.retain(|name, h| {
        if h.first_scan.as_deref() != Some(sid) {
            return true;
        }
        h.first_scan = host_seen(name);
        h.first_scan.is_some()
    });
    nf.findings.retain(|id, f| {
        if f.first_scan.as_deref() != Some(sid) {
            return true;
        }
        let short = fids.get(*id).to_string();
        f.first_scan = later
            .iter()
            .find(|s| s.snapshot.findings.contains_key(&short))
            .map(|s| s.id.clone());
        f.first_scan.is_some()
    });
    if nf != before {
        facts::put(db, facts::K_NET, &nf)?;
    }
    Ok(())
}

/// Removes what was deleted from a history snapshot.
fn scrub(snap: &mut ScanSnapshot, gone: &ScanSnapshot) {
    snap.docs.retain(|d| !gone.docs.contains(d));
    snap.people.retain(|p| !gone.people.contains(p));
    snap.hosts.retain(|h, _| !gone.hosts.contains_key(h));
    snap.findings.retain(|f, _| !gone.findings.contains_key(f));
}

/// Growth of `snap` over `prev` (the `added` record of a history entry).
fn added(snap: &ScanSnapshot, prev: &ScanSnapshot) -> Value {
    json!({
        "docs": snap.docs.iter().filter(|d| !prev.docs.contains(d)).count(),
        "people": snap.people.iter().filter(|p| !prev.people.contains(p)).count(),
        "hosts": snap.hosts.keys().filter(|h| !prev.hosts.contains_key(*h)).count(),
        "findings": snap.findings.keys().filter(|k| !prev.findings.contains_key(*k)).count(),
    })
}

impl Engine {
    /// `scan_delete { project, scan_id, dry_run? }`: erases one scan and everything only it
    /// produced. A running or paused scan of the project is cancelled first (no history record,
    /// no resume offer). Returns the removed counts (`dry_run`: what would be removed).
    pub(crate) async fn scan_delete(&self, a: &Value) -> CmdResult {
        let project = self.project_arg(a)?;
        let sid = req_str(a, "scan_id")?.to_string();
        let dry = a.get("dry_run").and_then(Value::as_bool).unwrap_or(false);
        let running = self.running_scan().filter(|r| r.0 == project);
        let is_running = running.as_ref().is_some_and(|r| r.1 == sid);
        let db_arc = self.db(&project)?;
        {
            let db = lock(&db_arc);
            if !is_running && !db.scans()?.iter().any(|s| s.id == sid) {
                return Err(CmdError::not_found(format!("Скан {sid} не найден")));
            }
            if dry {
                let mut v = footprint(&db, &sid)?;
                v["ok"] = json!(true);
                v["scan_id"] = json!(sid);
                v["dry_run"] = json!(true);
                return Ok(v);
            }
        }
        if running.is_some() && !is_running {
            return Err(CmdError::new(
                "busy",
                "Сначала остановите текущий скан проекта",
            ));
        }
        if is_running {
            self.stop_active_scan().await;
            let _ = std::fs::remove_file(self.run_file());
        }
        self.queue_forget_scan(&sid);
        let (counts, files) = {
            let db = lock(&db_arc);
            self.erase_scan(&db, &sid)?
        };
        let mut wiped = 0;
        for f in &files {
            if foca_store::wipe_file(std::path::Path::new(f)).is_ok() {
                wiped += 1;
            }
        }
        let settings = self.store().settings_get().unwrap_or_default();
        if settings["monitor_status"][&project]["scan_id"] == json!(sid) {
            let mut ms = settings["monitor_status"].clone();
            if let Some(o) = ms.as_object_mut() {
                o.remove(&project);
            }
            // a merge cannot drop a key: write the whole section back
            let _ = self
                .store()
                .settings_set(&json!({ "monitor_status": Value::Null }));
            let _ = self.store().settings_set(&json!({ "monitor_status": ms }));
        }
        if is_running {
            // the Android service and headless runner end on `stopped`; the UI drops the scan
            self.emit(json!({ "type": "stopped", "scan_id": sid, "project": project, "reason": "deleted" }));
        }
        let mut v = counts;
        v["files"] = json!(wiped);
        v["ok"] = json!(true);
        v["scan_id"] = json!(sid);
        v["dry_run"] = json!(false);
        Ok(v)
    }

    /// The project-file part of [`Self::scan_delete`]; returns the counts and the files to wipe.
    fn erase_scan(&self, db: &ProjectDb, sid: &str) -> Result<(Value, Vec<String>), CmdError> {
        let before = self.scan_snapshot(db)?;
        let fids: FidMap = facts::get(db, facts::K_FIDS);
        let scans = db.scans()?;
        let mut clean_names: Vec<String> = Vec::new();
        let erase: ScanErase =
            db.scan_delete(sid, |db, e: &ScanErase| -> Result<(), CmdError> {
                let later: Vec<Scan> = scans
                    .iter()
                    .filter(|s| e.later.contains(&s.id))
                    .cloned()
                    .collect();
                prune_net_facts(db, sid, &later, &fids)?;
                let mut cleaned: BTreeMap<String, Value> = facts::get(db, facts::K_CLEANED);
                let n = cleaned.len();
                cleaned.retain(|k, v| {
                    let keep = !e.docs.iter().any(|d| d.to_string() == *k);
                    if !keep {
                        if let Some(name) = v["name"].as_str() {
                            clean_names.push(name.to_string());
                        }
                    }
                    keep
                });
                if cleaned.len() != n {
                    facts::put(db, facts::K_CLEANED, &cleaned)?;
                }
                insights::reanalyze(db, None)?;
                Ok(())
            })?;
        let mut files = erase.files.clone();
        // cleaned copies of the deleted documents (`<data>/clean/<project>/<name>`)
        let clean_dir = self.inner.cfg.data_dir.join("clean").join(db.id());
        files.extend(
            clean_names
                .iter()
                .filter(|n| crate::engine::safe_report_leaf(n) == Some(n.as_str()))
                .map(|n| clean_dir.join(n).to_string_lossy().into_owned()),
        );
        let after = self.scan_snapshot(db)?;
        let gone = ScanSnapshot {
            docs: erase.docs.clone(),
            people: before
                .people
                .iter()
                .filter(|p| !after.people.contains(p))
                .cloned()
                .collect(),
            hosts: before
                .hosts
                .iter()
                .filter(|(h, _)| !after.hosts.contains_key(*h))
                .map(|(h, t)| (h.clone(), t.clone()))
                .collect(),
            findings: erase
                .findings
                .iter()
                .map(|h| (fids.get(*h).to_string(), foca_core::Severity::Info))
                .collect(),
            tech: BTreeMap::new(),
        };
        self.rewrite_history(db, &gone, erase.later.first().map(String::as_str))?;
        // engine-wide state keyed by the scan
        let log: Vec<Value> = facts::get(db, facts::K_ALERT_LOG);
        if log.iter().any(|x| x["scan_id"] == json!(sid)) {
            let log: Vec<Value> = log
                .into_iter()
                .filter(|x| x["scan_id"] != json!(sid))
                .collect();
            facts::put(db, facts::K_ALERT_LOG, &log)?;
        }
        if db
            .setting(facts::K_ALERT_SNAP)?
            .is_some_and(|v| v["scan_id"] == json!(sid))
        {
            // the next scan compares against nothing rather than against deleted results
            facts::put(db, facts::K_ALERT_SNAP, &Value::Null)?;
        }
        let mut map = fids.clone();
        map.forget(&erase.findings);
        if map != fids {
            facts::put(db, facts::K_FIDS, &map)?;
        }
        files.dedup();
        Ok((
            json!({
                "docs": erase.docs.len(),
                "findings": erase.findings.len(),
                "hosts": gone.hosts.len(),
                "requests": erase.requests,
            }),
            files,
        ))
    }

    /// Scrubs deleted items from the remaining history snapshots and recomputes the growth of
    /// the scan that followed the deleted one.
    fn rewrite_history(
        &self,
        db: &ProjectDb,
        gone: &ScanSnapshot,
        next: Option<&str>,
    ) -> Result<(), CmdError> {
        let scans = db.scans()?;
        let mut prev = ScanSnapshot::default();
        for mut s in scans {
            let old = s.clone();
            scrub(&mut s.snapshot, gone);
            s.docs = s.snapshot.docs.len() as u32;
            s.hosts = s.snapshot.hosts.len() as u32;
            s.people = s.snapshot.people.len() as u32;
            s.findings = s.snapshot.findings.len() as u32;
            if Some(s.id.as_str()) == next {
                let add = added(&s.snapshot, &prev);
                s.new_findings = add["findings"].as_u64().unwrap_or(0) as u32;
                let key = facts::scan_key(&s.id);
                let mut extra: Value = facts::get(db, &key);
                if extra.is_object() {
                    extra["added"] = add;
                    facts::put(db, &key, &extra)?;
                }
            }
            if s != old {
                db.scan_save(&s)?;
            }
            prev = s.snapshot;
        }
        Ok(())
    }
}

impl Engine {
    /// `dorks_pending { project }`: postponed dork groups and the time of the in-scan retry.
    pub(crate) fn dorks_pending(&self, a: &Value) -> CmdResult {
        let id = self.project_arg(a)?;
        let db = self.db(&id)?;
        let p = load(&lock(&db));
        let at = lock(&self.dork_jobs).get(&id).map(|j| j.at_ms);
        Ok(json!({ "project": id, "pending": p.len(), "items": p.0, "retry_at": at }))
    }

    /// `dorks_retry { project }`: retries the postponed groups now.
    pub(crate) async fn dorks_retry(&self, a: &Value) -> CmdResult {
        let id = self.project_arg(a)?;
        let pdb = self.db(&id)?;
        let n = load(&lock(&pdb)).len();
        let active = self.active_scan_id();
        if let Some(j) = lock(&self.dork_jobs).get(&id) {
            if active.as_deref() == Some(j.scan_id.as_str()) {
                j.wake.notify_one();
                return Ok(json!({ "ok": true, "mode": "now", "pending": n }));
            }
        }
        if n == 0 {
            return Ok(json!({ "ok": false, "mode": "none", "pending": 0 }));
        }
        if active.is_some() {
            return Ok(json!({ "ok": false, "mode": "busy", "pending": n }));
        }
        // no scan runs: a narrowed scan of the dork engines (postponed groups are planned first)
        let settings = self.store().settings_get()?;
        let keys = self.current_keys();
        let mut only: Vec<String> = RETRY_ENGINES
            .iter()
            .filter(|s| sources::source_enabled(&settings["sources"], s))
            .map(|s| format!("source:{s}"))
            .collect();
        for k in ["searx", "brave"] {
            if keys.get(k).is_some() {
                only.insert(0, format!("source:{k}"));
            }
        }
        let profile = lock(&pdb)
            .scans()
            .ok()
            .and_then(|v| v.last().map(|s| s.profile_id.clone()))
            .filter(|p| !p.is_empty())
            .unwrap_or_else(|| "std".into());
        let profile = if profile == "full" {
            "std".into()
        } else {
            profile
        };
        let mut exts: Vec<String> = Vec::new();
        for p in load(&lock(&pdb)).0 {
            for e in p.exts {
                if !exts.contains(&e) {
                    exts.push(e);
                }
            }
        }
        let r = self
            .scan_start(&json!({ "project": id, "profile": profile, "active": false,
                "only": only, "exts": exts }))
            .await?;
        Ok(json!({ "ok": true, "mode": "scan", "pending": n, "scan_id": r["scan_id"] }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scrub_and_growth() {
        let mut a = ScanSnapshot {
            docs: vec![1, 2],
            people: vec!["a".into(), "b".into()],
            ..Default::default()
        };
        a.hosts.insert("h1".into(), "-".into());
        a.findings.insert("3".into(), foca_core::Severity::High);
        let gone = ScanSnapshot {
            docs: vec![2],
            people: vec!["b".into()],
            findings: [("3".to_string(), foca_core::Severity::Info)].into(),
            ..Default::default()
        };
        scrub(&mut a, &gone);
        assert_eq!(a.docs, vec![1]);
        assert_eq!(a.people, vec!["a".to_string()]);
        assert!(a.findings.is_empty());
        let g = added(&a, &ScanSnapshot::default());
        assert_eq!(g["docs"], 1);
        assert_eq!(g["hosts"], 1);
    }
}
