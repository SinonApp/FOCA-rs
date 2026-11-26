//! Scan runs: starting a run from the wizard arguments, finishing it (history record, alerts,
//! monitoring status), stopping it, per-source skip/retry, and recording a run interrupted by a
//! process restart.

use std::collections::BTreeSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use foca_core::api::{Scan, ScanSource};
use foca_search::store::StoreSink;
use foca_store::project::profile_label;
use foca_store::ProjectDb;
use serde_json::{json, Value};
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;

use crate::analysis::facts;
use crate::analysis::rules;
use crate::engine::{lock, Core, Engine, Run};
use crate::scan::selection::Selection;
use crate::scan::{
    self, core_scope_for, default_modules, egress_label, expand_exts, fuzz, incomplete_sources,
    infra, known_hosts, minutes_between, opts_key, ports, profile_id, recon, source_enabled,
    source_modules, warn_key, Ctx, Stop, ACTIVE_MODULES, RECON_SOURCES, SEARCH_SOURCES, SOURCES,
    SRC_SUBDOMAINS, SRC_TLS, STAGES, TARGET_MODULES, WEBVIEW_SOURCES,
};
use crate::services::resume::RunState;
use crate::util::{arg_str, base36};
use crate::{CmdError, CmdResult};

impl Engine {
    /// On open, records the previous process's scan as `stopped` / `restart`.
    pub(crate) fn recover_run(&self) -> Result<(), CmdError> {
        let f = self.run_file();
        let Ok(b) = std::fs::read(&f) else {
            return Ok(());
        };
        let _ = std::fs::remove_file(&f);
        let Ok(st) = serde_json::from_slice::<RunState>(&b) else {
            return Ok(());
        };
        if let Ok(db) = self.db(&st.project) {
            let db = lock(&db);
            self.write_record(&db, &st, "stopped", Some("restart"))?;
        }
        Ok(())
    }

    /// Writes a history record; one rule for `done` and `stopped` (see "History records" in `docs/API.md`).
    pub(crate) fn write_record(
        &self,
        db: &ProjectDb,
        st: &RunState,
        status: &str,
        reason: Option<&str>,
    ) -> Result<Value, CmdError> {
        let snap = self.scan_snapshot(db)?;
        let prev = db
            .scans()?
            .into_iter()
            .rfind(|s| s.id != st.scan_id && s.status != "running")
            .map(|s| s.snapshot)
            .unwrap_or_default();
        let pd: BTreeSet<&u64> = prev.docs.iter().collect();
        let pp: BTreeSet<&String> = prev.people.iter().collect();
        let added = json!({
            "docs": snap.docs.iter().filter(|d| !pd.contains(d)).count(),
            "people": snap.people.iter().filter(|p| !pp.contains(p)).count(),
            "hosts": snap.hosts.keys().filter(|h| !prev.hosts.contains_key(*h)).count(),
            "findings": snap.findings.keys().filter(|k| !prev.findings.contains_key(*k)).count(),
        });
        let now = self.now_iso();
        let canary = st.canary.clone().unwrap_or_default();
        let proxy_used = self
            .store()
            .settings_get()
            .ok()
            .and_then(|s| crate::settings::resolve_proxy_spec(&s["net"], None))
            .is_some();
        let log = db.requests(Some(&st.scan_id), false).unwrap_or_default();
        let incomplete_reasons = incomplete_sources(&st.sources, &log);
        let incomplete_sources: Vec<String> =
            incomplete_reasons.iter().map(|s| s.id.clone()).collect();
        let env = foca_core::api::ScanEnv {
            egress: st.egress.clone(),
            proxy_used,
            tcp_intercept: canary.tcp_intercept,
            dns_hijack: canary.dns_hijack,
            tls_mitm: canary.tls_mitm,
            incomplete: status != "done" || !incomplete_sources.is_empty() || canary.unreliable,
            incomplete_sources,
            incomplete_reasons,
        };
        let rec = Scan {
            id: st.scan_id.clone(),
            profile_id: st.profile_id.clone(),
            profile: profile_label(&st.profile_id).into(),
            active: st.active,
            trigger: if st.trigger == "schedule" {
                "schedule".into()
            } else {
                "manual".into()
            },
            status: status.into(),
            reason: reason.map(str::to_string),
            started_at: st.started_at.clone(),
            finished_at: Some(now.clone()),
            minutes: minutes_between(&st.started_at, &now).max(1),
            targets: st.targets.clone(),
            egress: st.egress.clone(),
            sources: st.sources.clone(),
            docs: snap.docs.len() as u32,
            hosts: snap.hosts.len() as u32,
            people: snap.people.len() as u32,
            findings: snap.findings.len() as u32,
            new_findings: added["findings"].as_u64().unwrap_or(0) as u32,
            snapshot: snap,
            env: Some(env),
        };
        db.scan_save(&rec)?;
        let mut extra = json!({ "modules": st.modules, "added": added });
        // a narrowed run: the chosen items and the stages it executed
        if let Some(sel) = Selection::parse(&st.only) {
            extra["only"] = json!(sel.keys());
            extra["stages"] = json!(sel.stage_ids());
        }
        // incomplete snapshot: site reconnaissance did not answer, so the technologies come from older
        // data and "What changed" must not count them as gone
        let incomplete: Vec<&str> = st
            .sources
            .iter()
            .filter(|s| {
                ["recon", "wellknown"].contains(&s.id.as_str())
                    && matches!(
                        s.status.as_str(),
                        "error" | "timeout" | "skipped" | "blocked"
                    )
            })
            .map(|s| s.id.as_str())
            .collect();
        if !incomplete.is_empty() {
            extra["incomplete"] = json!(incomplete);
        }
        if status == "stopped" {
            extra["progress"] = json!(st.progress);
            extra["stage"] = json!(STAGES[st.stage.min(STAGES.len() - 1)].0);
        }
        facts::put(db, &facts::scan_key(&st.scan_id), &extra)?;
        let mut v = serde_json::to_value(&rec)?;
        if let (Some(o), Some(x)) = (v.as_object_mut(), extra.as_object()) {
            o.remove("snapshot");
            for (k, val) in x {
                o.insert(k.clone(), val.clone());
            }
        }
        Ok(v)
    }

    /// Takes the result snapshot for `Scan.snapshot`: live documents, authors of parsed documents,
    /// hosts to software fingerprints, and current findings (short ids) to severity.
    pub(crate) fn scan_snapshot(
        &self,
        db: &ProjectDb,
    ) -> Result<foca_core::api::ScanSnapshot, CmdError> {
        let docs = db.ui_docs()?;
        let live: Vec<_> = docs.iter().filter(|d| !d.deleted).collect();
        let mut people: Vec<String> = Vec::new();
        for d in &live {
            if d.status == "analyzed" {
                if let Some(a) = &d.author {
                    if !people.contains(a) {
                        people.push(a.clone());
                    }
                }
            }
        }
        let hosts: Vec<foca_core::api::Host> = match db.entity("hosts")? {
            Value::Null => vec![],
            v => serde_json::from_value(v)?,
        };
        let map = facts::assign_fids(db)?;
        Ok(foca_core::api::ScanSnapshot {
            docs: live.iter().map(|d| d.id).collect(),
            people,
            hosts: hosts.into_iter().map(|h| (h.name, h.tech)).collect(),
            findings: db
                .findings()?
                .into_iter()
                .filter(|f| {
                    !matches!(
                        f.status,
                        foca_core::FindingStatus::FalsePositive | foca_core::FindingStatus::Fixed
                    )
                })
                .map(|f| (map.get(f.id).to_string(), f.sev))
                .collect(),
            tech: recon::tech_versions(db),
        })
    }

    pub(crate) async fn scan_start(&self, a: &Value) -> CmdResult {
        let project = self.project_arg(a)?;
        let db = self.db(&project)?;
        if self.is_scanning() {
            return Err(CmdError::new("busy", "Скан уже идёт"));
        }
        let prof = profile_id(arg_str(a, "profile").unwrap_or("std"));
        let mods: Vec<String> = a
            .get("modules")
            .and_then(Value::as_array)
            .map(|v| {
                v.iter()
                    .filter_map(|x| x.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();
        let active = a.get("active").and_then(Value::as_bool).unwrap_or(false)
            || prof == "full"
            || mods.iter().any(|m| ACTIVE_MODULES.contains(&m.as_str()));
        let level = if active {
            "active"
        } else if prof == "std"
            || prof == "full"
            || mods.iter().any(|m| TARGET_MODULES.contains(&m.as_str()))
        {
            "target"
        } else {
            "external"
        };
        // scheduled rescans (monitoring) never use the active stage: active modules are manual only
        let trigger = match arg_str(a, "trigger") {
            Some("schedule") => "schedule",
            _ => "manual",
        };
        if trigger == "schedule" && level == "active" {
            return Err(CmdError::new(
                "monitor_active",
                "Плановый перескан не запускает активный профиль: только «Пассивный» или «Стандартный»",
            ));
        }
        let (scope, hosts, prev_stop) = {
            let d = lock(&db);
            let prev = match arg_str(a, "resume_from") {
                Some(rf) => {
                    let s = d
                        .scans()?
                        .into_iter()
                        .find(|s| s.id == rf && s.status == "stopped")
                        .ok_or_else(|| {
                            CmdError::not_found(format!("Остановленный скан {rf} не найден"))
                        })?;
                    let extra: Value = facts::get(&d, &facts::scan_key(rf));
                    Some((s, extra))
                }
                None => None,
            };
            (d.scope_get()?, known_hosts(&d), prev)
        };
        // scope check: the same rule for a new scan, a resume and "start over"
        let req: Vec<String> = match a.get("targets").and_then(Value::as_array) {
            Some(v) if !v.is_empty() => v
                .iter()
                .filter_map(|x| match x {
                    Value::String(s) => Some(s.clone()),
                    Value::Object(o) => o.get("v").and_then(Value::as_str).map(String::from),
                    _ => None,
                })
                .collect(),
            _ => scope.targets.iter().map(|t| t.v.clone()).collect(),
        };
        if level != "external" {
            let mut bad = Vec::new();
            for v in &req {
                let Some(t) = scope.targets.iter().find(|x| x.v.eq_ignore_ascii_case(v)) else {
                    if rules::entry(v, None) != rules::Entry::None {
                        bad.push(format!("{v}: нет в скоупе"));
                    }
                    continue;
                };
                let ck = rules::check_target(&scope, &t.v, &t.kind, &hosts);
                if ck.net && !ck.ok {
                    bad.push(format!("{v}: {}", ck.reason));
                }
            }
            if !bad.is_empty() {
                return Err(CmdError {
                    code: "out_of_scope".into(),
                    message: format!("Цели вне скоупа: {}", bad.join("; ")),
                    targets: Some(bad),
                });
            }
        }
        let settings = self.public_settings()?;
        // Settings → Sources: a source disabled by the user is never queried
        let user_sources = self.store().settings_get()?["sources"].clone();
        let user_off = |id: &str| !source_enabled(&user_sources, id);
        // An explicit `headless: false` lets a background core resume a full interactive run.
        let headless = a
            .get("headless")
            .and_then(Value::as_bool)
            .unwrap_or_else(|| self.is_headless());
        let has_render = self.current_render().is_some();
        let budget = a
            .get("budget_sec")
            .and_then(Value::as_u64)
            .filter(|&s| s > 0)
            .map(Duration::from_secs)
            .or_else(|| {
                a.get("budget_ms")
                    .and_then(Value::as_u64)
                    .filter(|&ms| ms > 0)
                    .map(Duration::from_millis)
            });
        // A narrowed run (follow-up of chosen items): from the arguments, or the one saved for
        // this scan on resume.
        let saved_opts: Value = match &prev_stop {
            Some((s, _)) => facts::get(&lock(&db), &opts_key(&s.id)),
            None => Value::Null,
        };
        let only_keys: Vec<String> = a
            .get("only")
            .or_else(|| saved_opts.get("only"))
            .and_then(Value::as_array)
            .map(|v| {
                v.iter()
                    .filter_map(|x| x.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();
        let sel = Selection::parse(&only_keys);
        let n_scans = lock(&db).scans()?.len();
        let now = self.now();
        let (scan_id, started, progress, stage) = match &prev_stop {
            Some((s, extra)) => (
                s.id.clone(),
                s.started_at.clone(),
                extra["progress"].as_u64().unwrap_or(0) as u8,
                STAGES
                    .iter()
                    .position(|x| Some(x.0) == extra["stage"].as_str())
                    .unwrap_or(0),
            ),
            None => (
                format!(
                    "{project}-s{}-{}",
                    n_scans + 1,
                    base36((now.unix_timestamp_nanos() / 1_000_000) as u64)
                ),
                crate::util::iso(now),
                0,
                // a follow-up run of queued restarts starts at the earliest stage they belong to
                match &sel {
                    Some(s) => s.first(),
                    None => STAGES
                        .iter()
                        .position(|x| Some(x.0) == arg_str(a, "from_stage"))
                        .unwrap_or(0),
                },
            ),
        };
        let source_ids: Vec<String> = match a.get("sources").and_then(Value::as_array) {
            Some(v) if !v.is_empty() => v
                .iter()
                .filter_map(|x| x.as_str().map(String::from))
                .collect(),
            // a narrowed run without its own list: the chosen sources
            _ if sel.as_ref().is_some_and(|s| !s.whole("search")) => SOURCES
                .iter()
                .map(|s| s.0)
                .filter(|id| sel.as_ref().is_some_and(|s| s.source(id)))
                .map(String::from)
                .collect(),
            // Without an explicit list, use every source except those disabled in the wizard (`sources_off`):
            // the wizard shows only some sources, and the rest (subdomains, dorks, archives) must not silently
            // drop out of the scan.
            _ => {
                let off: Vec<&str> = a
                    .get("sources_off")
                    .and_then(Value::as_array)
                    .map(|v| v.iter().filter_map(Value::as_str).collect())
                    .unwrap_or_default();
                SOURCES
                    .iter()
                    .map(|s| s.0)
                    .filter(|id| !off.contains(id))
                    .map(String::from)
                    .collect()
            }
        };
        // an explicit list does not include sources disabled in the settings either
        let source_ids: Vec<String> = source_ids.into_iter().filter(|id| !user_off(id)).collect();
        // Status before start: no key means `nokey`/`off` right away; disabled by the user means `off`;
        // a search source that will be queried is `wait` (`ok` only after it answers).
        let recon_stage = STAGES.iter().position(|x| x.0 == "recon").unwrap_or(5);
        let sources: Vec<ScanSource> = SOURCES
            .iter()
            .filter(|s| !(s.4 && level == "external"))
            .map(|s| {
                let key = self.source_status(s.0);
                let searched = SEARCH_SOURCES.contains(&s.0) || s.0 == "dns";
                let mod_off = prof == "custom"
                    && !mods.is_empty()
                    && !source_modules(s.0)
                        .iter()
                        .any(|m| mods.iter().any(|x| x == m));
                let status = if user_off(s.0) {
                    "off".into()
                } else if s.0 == SRC_SUBDOMAINS || s.0 == SRC_TLS {
                    let on =
                        level != "external" && (prof != "custom" || mods.iter().any(|m| m == s.0));
                    if !on {
                        "off".into()
                    } else if headless && s.0 == SRC_SUBDOMAINS {
                        "skipped_headless".into()
                    } else {
                        "wait".into()
                    }
                } else if s.0 == "fuzz" || s.0 == ports::SOURCE {
                    let on =
                        level == "active" && (prof != "custom" || mods.iter().any(|m| m == s.0));
                    if on {
                        "wait".into()
                    } else {
                        "off".into()
                    }
                } else if RECON_SOURCES.contains(&s.0) {
                    let on =
                        prof != "custom" || mods.is_empty() || mods.iter().any(|m| m == "recon");
                    if on && source_ids.iter().any(|x| x == s.0) && stage <= recon_stage {
                        "wait".into()
                    } else if on && source_ids.iter().any(|x| x == s.0) {
                        key
                    } else {
                        "off".into()
                    }
                } else if key != "ok" || !searched {
                    key
                } else if mod_off || (!source_ids.iter().any(|x| x == s.0) && s.0 != "dns") {
                    "off".into()
                } else if stage == 0 {
                    if headless && !has_render && WEBVIEW_SOURCES.contains(&s.0) {
                        "skipped_headless".into()
                    } else {
                        "wait".into()
                    }
                } else {
                    key
                };
                // a narrowed run leaves out every source outside the chosen items
                let status = match &sel {
                    Some(x) if !x.source(s.0) => "off".into(),
                    _ => status,
                };
                ScanSource {
                    id: s.0.into(),
                    name: s.1.into(),
                    status,
                }
            })
            .collect();
        // wizard parameters: from the arguments, or the ones saved for this scan on resume
        let saved = saved_opts;
        let pick = |k: &str| -> Option<Value> {
            a.get(k)
                .filter(|v| !v.is_null())
                .or_else(|| saved.get(k).filter(|v| !v.is_null()))
                .cloned()
        };
        let exts: Vec<String> = expand_exts(
            &pick("exts")
                .and_then(|v| {
                    v.as_array().map(|x| {
                        x.iter()
                            .filter_map(|s| s.as_str().map(String::from))
                            .collect::<Vec<_>>()
                    })
                })
                .unwrap_or_default(),
        );
        let crawl_depth = pick("crawl_depth")
            .and_then(|v| v.as_u64())
            .map(|d| d.clamp(1, 10) as usize);
        let max_size_mb = pick("max_size_mb")
            .and_then(|v| v.as_u64())
            .map(|m| m.clamp(1, 2048));
        let ua = pick("ua")
            .and_then(|v| v.as_str().map(|s| s.trim().to_string()))
            .filter(|s| !s.is_empty());
        let limit_arg = pick("limit").and_then(|v| v.as_u64());
        let limit = limit_arg
            .map(|l| l as usize)
            .unwrap_or(self.inner.cfg.max_docs)
            .min(self.inner.cfg.max_docs.max(1));
        let st = RunState {
            scan_id: scan_id.clone(),
            project: project.clone(),
            profile_id: prof.into(),
            active,
            level: level.into(),
            stage,
            progress,
            started_at: started,
            targets: req.clone(),
            modules: if mods.is_empty() {
                default_modules(prof)
            } else {
                mods
            },
            sources,
            source_ids,
            egress: egress_label(&settings),
            resumed: prev_stop.is_some(),
            auto: prev_stop.is_some() && a.get("auto").and_then(Value::as_bool).unwrap_or(false),
            limit,
            pause_reason: None,
            trigger: trigger.into(),
            exts: exts.clone(),
            crawl_depth,
            max_size_mb,
            ua: ua.clone(),
            canary: None,
            headless,
            substep: None,
            followup: vec![],
            only: sel.as_ref().map(Selection::keys).unwrap_or_default(),
        };
        facts::put(
            &lock(&db),
            &opts_key(&scan_id),
            &json!({ "exts": exts, "crawl_depth": crawl_depth, "max_size_mb": max_size_mb,
                "ua": ua, "limit": limit_arg, "only": sel.as_ref().map(Selection::keys) }),
        )?;
        // Network: an empty scope for the passive level (nothing may touch the target), a scope without
        // the active stage for standard, and a scope with the active stage for active.
        let core = core_scope_for(&scope, level);
        let sink = Arc::new(StoreSink {
            db: db.clone(),
            scan_id: Some(scan_id.clone()),
        });
        let cancel = CancellationToken::new();
        let net = self
            .net_client_ua(core, sink, ua.as_deref())?
            .with_cancel(cancel.clone());
        // passive requests: exclusions never, target hosts not at the passive level
        net.set_passive_guard(foca_core::Scope::from(&scope), level == "external");
        let (ptx, _) = watch::channel(None);
        let st = Arc::new(Mutex::new(st));
        let run = Run {
            st: st.clone(),
            skip: Default::default(),
            cancel: cancel.clone(),
            pause: ptx,
            handle: None,
            net: Some(net),
        };
        let ctx = Ctx::new(
            self.inner.clone(),
            &run,
            db.clone(),
            scope,
            &req,
            stage,
            level,
        );
        if let Some(fo) = a.get("fuzz").filter(|v| v.is_object()) {
            // brute-force parameters of this run (wizard), surviving a resume
            facts::put(&lock(&db), &fuzz::run_key(&scan_id), fo)?;
        }
        if let Some(so) = a.get("subdomains").filter(|v| v.is_object()) {
            // subdomain enumeration parameters of this run (wordlist), surviving a resume
            facts::put(&lock(&db), &infra::run_key(&scan_id), so)?;
        }
        if let Some(po) = a.get("ports").filter(|v| v.is_object()) {
            // port scan parameters of this run (top 100/1000/custom list), surviving a resume
            facts::put(&lock(&db), &ports::run_key(&scan_id), po)?;
        }
        if level == "active" {
            tracing::info!(target: "foca::scan", "активная фаза, цели: {}", req.join(", "));
        }
        let started_ev = {
            let s = lock(&st);
            json!({ "scan_id": scan_id, "profile": profile_label(prof), "profile_id": prof,
                "active": active, "egress": s.egress, "targets": s.targets, "resumed": s.resumed, "auto": s.auto,
                // a narrowed run: the stages it executes (the others are not selected)
                "stages": sel.as_ref().map(Selection::stage_ids) })
        };
        let cancel_for_budget = cancel.clone();
        {
            let mut g = lock(&self.inner.run);
            if g.is_some() {
                return Err(CmdError::new("busy", "Скан уже идёт"));
            }
            *g = Some(run);
        }
        self.persist_run(&lock(&st));
        let mut ev = started_ev.clone();
        ev["type"] = json!("started");
        ev["project"] = json!(project);
        self.emit(ev);
        for s in lock(&st).sources.clone() {
            self.emit(json!({ "type": "source", "scan_id": scan_id, "id": s.id, "name": s.name, "status": s.status }));
        }
        if progress > 0 {
            self.emit(json!({ "type": "progress", "scan_id": scan_id, "progress": progress, "stage": STAGES[stage].0 }));
        }
        let me = self.clone();
        let mut run_guard = lock(&self.inner.run);
        let sid_spawn = scan_id.clone();
        let h = tokio::spawn(async move {
            struct PanicRunGuard {
                core: Arc<Core>,
                scan_id: String,
                armed: bool,
            }
            impl Drop for PanicRunGuard {
                fn drop(&mut self) {
                    if !self.armed {
                        return;
                    }
                    let mut g = lock(&self.core.run);
                    if g.as_ref()
                        .is_some_and(|x| lock(&x.st).scan_id == self.scan_id)
                    {
                        *g = None;
                    }
                    self.core.finishing.store(false, Ordering::SeqCst);
                }
            }
            let mut guard = PanicRunGuard {
                core: me.inner.clone(),
                scan_id: sid_spawn.clone(),
                armed: true,
            };
            let r = scan::pipeline(ctx).await;
            guard.armed = false;
            me.finish(&sid_spawn, r).await;
        });
        if let Some(r) = run_guard.as_mut() {
            if lock(&r.st).scan_id == scan_id {
                r.handle = Some(h);
            }
        }
        drop(run_guard);
        if let Some(dur) = budget {
            let me_b = self.clone();
            let sid_b = scan_id.clone();
            tokio::spawn(async move {
                tokio::select! {
                    _ = cancel_for_budget.cancelled() => {}
                    _ = tokio::time::sleep(dur) => {
                        if me_b.active_scan_id().as_deref() == Some(sid_b.as_str()) {
                            tracing::warn!(target: "foca::scan", "{sid_b}: бюджет времени ({} мс) исчерпан: мягкая остановка", dur.as_millis());
                            let _ = me_b.scan_stop("budget").await;
                        }
                    }
                }
            });
        }
        Ok(started_ev)
    }

    pub(crate) fn record_monitor_status(
        &self,
        st: &RunState,
        status: &str,
        rec: Option<&Value>,
        error: Option<&str>,
    ) {
        if st.trigger != "schedule" {
            return;
        }
        let added = rec.and_then(|r| r.get("added"));
        let mut entry = json!({
            "status": status,
            "at": self.now_iso(),
            "scan_id": st.scan_id,
            "profile": st.profile_id,
            "headless": st.headless,
            "added_docs": added.and_then(|a| a["docs"].as_u64()).unwrap_or(0),
            "added_findings": added.and_then(|a| a["findings"].as_u64()).unwrap_or(0),
            "docs": rec.and_then(|r| r["docs"].as_u64()).unwrap_or(0),
            "findings": rec.and_then(|r| r["findings"].as_u64()).unwrap_or(0),
            "alerts_fired": rec.and_then(|r| r["alerts_fired"].as_u64()).unwrap_or(0),
        });
        if let Some(err) = error {
            entry["error"] = json!(err);
        }
        let _ = self
            .store()
            .settings_set(&json!({ "monitor_status": { &st.project: entry } }));
    }

    async fn finish(&self, scan_id: &str, r: Result<(), Stop>) {
        let Some(st) = ({
            let mut g = lock(&self.inner.run);
            let mine = g
                .as_ref()
                .is_some_and(|x| lock(&x.st).scan_id == scan_id && !x.cancel.is_cancelled());
            if !mine {
                return;
            }
            let Some(run) = g.take() else { return };
            run.cancel.cancel();
            // busy until the history record is written; the flag is set under the same lock as `take`
            self.inner.finishing.store(true, Ordering::SeqCst);
            let st = lock(&run.st).clone();
            Some(st)
        }) else {
            return;
        };
        let _busy = FinishGuard(&self.inner.finishing);
        let _ = std::fs::remove_file(self.run_file());
        let Ok(db_arc) = self.db(&st.project) else {
            return;
        };
        match r {
            Ok(()) => {
                let (warnings, rec) = {
                    let db = lock(&db_arc);
                    let w: Vec<Value> = facts::get(&db, &warn_key(scan_id));
                    let rec = self.write_record(&db, &st, "done", None);
                    (w, rec)
                };
                if let Ok(mut rec) = rec {
                    let alert_res = self.evaluate_and_deliver_alerts(&st, &rec).await;
                    let fired = alert_res["fired"].as_u64().unwrap_or(0);
                    if fired > 0 {
                        rec["alerts_fired"] = json!(fired);
                    }
                    self.record_monitor_status(&st, "done", Some(&rec), None);
                    let mut ev = json!({
                        "type": "done",
                        "scan_id": scan_id,
                        "project": st.project,
                        "scan": rec,
                        "alerts_fired": fired,
                        // restarts queued after their stage was over, for a follow-up run
                        "followup": st.followup,
                    });
                    if !warnings.is_empty() {
                        ev["warnings"] = json!(warnings);
                    }
                    self.emit(ev);
                }
            }
            Err(Stop::Cancelled | Stop::SkipStage | Stop::RestartStage) => {}
            Err(Stop::Error(m)) => {
                let rec = {
                    let db = lock(&db_arc);
                    self.write_record(&db, &st, "stopped", Some("error")).ok()
                };
                self.record_monitor_status(&st, "error", rec.as_ref(), Some(&m));
                self.emit(json!({ "type": "stopped", "scan_id": scan_id, "project": st.project, "reason": "error", "message": m }));
            }
        }
    }

    pub(crate) async fn scan_stop(&self, reason: &str) -> CmdResult {
        let run = {
            let mut g = lock(&self.inner.run);
            let run = g.take();
            if run.is_some() {
                self.inner.finishing.store(true, Ordering::SeqCst);
            }
            run
        };
        let Some(mut run) = run else {
            return Ok(json!({ "ok": false }));
        };
        let _busy = FinishGuard(&self.inner.finishing);
        run.cancel.cancel();
        if let Some(h) = run.handle.take() {
            let ab = h.abort_handle();
            if tokio::time::timeout(Duration::from_secs(5), h)
                .await
                .is_err()
            {
                ab.abort();
            }
        }
        let st = lock(&run.st).clone();
        let _ = std::fs::remove_file(self.run_file());
        let rec = {
            let db = self.db(&st.project)?;
            let db = lock(&db);
            self.write_record(&db, &st, "stopped", Some(reason))?
        };
        self.record_monitor_status(&st, reason, Some(&rec), None);
        self.emit(json!({ "type": "stopped", "scan_id": st.scan_id, "project": st.project, "reason": reason }));
        Ok(json!({ "ok": true }))
    }
}

/// Clears `Core::finishing` after the history record is written (also on early return or panic).
struct FinishGuard<'a>(&'a AtomicBool);

impl Drop for FinishGuard<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::SeqCst);
    }
}
