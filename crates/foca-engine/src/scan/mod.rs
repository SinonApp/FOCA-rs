//! Scan pipeline: the run context shared by the stages, the stage order and the helpers stages
//! have in common. Stages live in the submodules; the catalog of stages and sources in
//! [`sources`].

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use foca_core::api::{ScanSource, ScopeDto};
use foca_core::{Scope, Severity};
use foca_net::NetClient;
use foca_search::store::{SharedDb, StoreSink};
use foca_store::project::profile_label;
use foca_store::ProjectDb;
use serde_json::{json, Value};
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;

use crate::analysis::facts::{self};
use crate::analysis::rules::{self, KnownHost};
use crate::engine::{lock, Core, Run};
use crate::services::resume::RunState;
use crate::{CmdError, Engine};

use documents::{stage_analysis, stage_download, stage_meta};
use network::stage_network;
use search::stage_search;
pub(crate) use sources::{
    default_modules, expand_exts, profile_id, source_enabled, source_modules, ACTIVE_MODULES,
    DOC_SOURCE_IDS, HOST_SOURCE_IDS, RECON_SOURCES, RESOLVER_STEPS, RETRY_PREFIX, RETRY_SOURCES,
    SEARCH_SOURCES, SOURCES, SRC_SUBDOMAINS, SRC_TLS, STAGES, TARGET_MODULES, WEBVIEW_SOURCES,
};

/// Returns the core scope for a scan level: `external` is empty (nothing touches the target),
/// `target` has no active stage, and `active` enables the active stage (AXFR, brute force).
pub(crate) fn core_scope_for(scope: &foca_core::api::ScopeDto, level: &str) -> Scope {
    let mut core = Scope::from(scope);
    match level {
        "external" => core = Scope::default(),
        "active" => core.active_phase = true,
        _ => {}
    }
    core
}

/// Facts key for the run wizard parameters, which survive a resume.
pub(crate) fn opts_key(scan_id: &str) -> String {
    format!("scan_opts:{scan_id}")
}

/// Returns the duration in minutes between two ISO dates without an offset.
pub(crate) fn minutes_between(a: &str, b: &str) -> u32 {
    let f = time::macros::format_description!("[year]-[month]-[day]T[hour]:[minute]:[second]");
    match (
        time::PrimitiveDateTime::parse(a, &f),
        time::PrimitiveDateTime::parse(b, &f),
    ) {
        (Ok(x), Ok(y)) => ((y - x).whole_seconds().max(0) as f64 / 60.0).round() as u32,
        _ => 0,
    }
}

pub(crate) fn known_hosts(db: &ProjectDb) -> Vec<KnownHost> {
    let hosts: Vec<foca_core::api::Host> = match db.entity("hosts") {
        Ok(Value::Null) | Err(_) => vec![],
        Ok(v) => serde_json::from_value(v).unwrap_or_default(),
    };
    hosts
        .into_iter()
        .map(|h| KnownHost {
            name: h.name,
            ip: h.ip,
        })
        .collect()
}

/// Returns the network names of targets (domains, URL hosts) for search and DNS.
fn target_domains(sc: &ScopeDto, targets: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    for v in targets {
        let ty = sc
            .targets
            .iter()
            .find(|t| t.v.eq_ignore_ascii_case(v))
            .map(|t| t.kind.clone());
        let d = match rules::entry(v, ty.as_deref()) {
            rules::Entry::Domain(d) | rules::Entry::Wild(d) => d,
            rules::Entry::Url(h) if rules::ip4(&h).is_none() => h,
            _ => continue,
        };
        if !d.is_empty() && !out.contains(&d) {
            out.push(d);
        }
    }
    out
}

/// Expands direct IP, CIDR, IP-range, and IP-host URL targets into bounded IPv4 addresses,
/// skipping any excluded addresses (`scope.excl`) so they can enter RDAP, InternetDB, liveness,
/// TLS and port stages under ADR-0009.
fn target_ips(sc: &ScopeDto, targets: &[String], max_ips: usize) -> Vec<String> {
    let mut out = Vec::new();
    let cap = max_ips.min(256);
    if cap == 0 {
        return out;
    }
    for v in targets {
        let ty = sc
            .targets
            .iter()
            .find(|t| t.v.eq_ignore_ascii_case(v))
            .map(|t| t.kind.clone());
        let entry = rules::entry(v, ty.as_deref());
        let (lo, hi, is_cidr) = match entry {
            rules::Entry::Ip(lo, hi) => (lo, hi, ty.as_deref() == Some("cidr") || v.contains('/')),
            rules::Entry::Url(h) => match rules::ip4(&h) {
                Some(ip) => (ip, ip, false),
                None => continue,
            },
            _ => continue,
        };
        if hi < lo {
            continue;
        }
        // For CIDR subnets larger than /30, skip network (.0) and broadcast (.255) addresses.
        let (start, end) = if is_cidr && hi.saturating_sub(lo) >= 3 {
            (lo.saturating_add(1), hi.saturating_sub(1))
        } else {
            (lo, hi)
        };
        let mut checked = 0usize;
        for ip_u32 in start..=end {
            checked += 1;
            if checked > 4096 {
                break;
            }
            let ip = std::net::Ipv4Addr::from(ip_u32).to_string();
            if rules::check(sc, &ip, &[]).code == "excluded" {
                continue;
            }
            if !out.contains(&ip) {
                out.push(ip);
                if out.len() >= cap {
                    return out;
                }
            }
        }
    }
    out
}

/// Facts key for scan warnings.
pub(crate) fn warn_key(scan_id: &str) -> String {
    format!("scan_warnings:{scan_id}")
}

pub(crate) fn egress_label(settings: &Value) -> String {
    let n = &settings["net"];
    if n["proxy_on"].as_bool().unwrap_or(false) {
        format!(
            "{} · {}",
            n["out_ip"].as_str().unwrap_or(""),
            n["label"].as_str().unwrap_or("")
        )
    } else {
        "Напрямую (реальный IP)".into()
    }
}

pub(crate) enum Stop {
    Cancelled,
    Error(String),
    /// The user skipped the rest of the running stage (`scan_control`).
    SkipStage,
    /// The user asked to run the running stage again (`scan_control`).
    RestartStage,
}

impl From<CmdError> for Stop {
    fn from(e: CmdError) -> Self {
        Stop::Error(e.message)
    }
}

impl From<foca_store::StoreError> for Stop {
    fn from(e: foca_store::StoreError) -> Self {
        Stop::Error(e.to_string())
    }
}

pub(crate) struct Ctx {
    e: Arc<Core>,
    st: Arc<Mutex<RunState>>,
    cancel: CancellationToken,
    pause: watch::Receiver<Option<String>>,
    net: NetClient,
    db: SharedDb,
    scan_id: String,
    level: String,
    domains: Vec<String>,
    direct_ips: Vec<String>,
    start_stage: usize,
    scope: ScopeDto,
    skip: Arc<Mutex<std::collections::HashSet<String>>>,
}

impl Ctx {
    /// Context of a run registered in `run`: its shared state, cancellation, pause channel,
    /// network client and skip set, the targets derived from `scope` and `req`.
    pub(crate) fn new(
        e: Arc<Core>,
        run: &Run,
        db: SharedDb,
        scope: ScopeDto,
        req: &[String],
        start_stage: usize,
        level: &str,
    ) -> Ctx {
        let scan_id = lock(&run.st).scan_id.clone();
        let host_limit = e.cfg.host_limit.max(64);
        Ctx {
            st: run.st.clone(),
            cancel: run.cancel.clone(),
            pause: run.pause.subscribe(),
            net: run
                .net
                .clone()
                .expect("a run starts with its network client"),
            db,
            scan_id,
            level: level.into(),
            domains: target_domains(&scope, req),
            direct_ips: target_ips(&scope, req, host_limit),
            start_stage,
            scope,
            skip: run.skip.clone(),
            e,
        }
    }

    pub(crate) fn group_net(&self, group: &str) -> Result<NetClient, Stop> {
        let s = self.e.store().settings_get()?;
        let raw = s["net"]["groups"][group].as_str().unwrap_or("").trim();
        if raw.is_empty() {
            return Ok(self.net.clone());
        }
        let ua = lock(&self.st).ua.clone();
        let sink = Arc::new(StoreSink {
            db: self.db.clone(),
            scan_id: Some(self.scan_id.clone()),
        });
        let net = self
            .e
            .net_client_group(self.net.scope(), sink, ua.as_deref(), Some(group))?
            .with_cancel(self.cancel.clone());
        net.set_passive_guard(Scope::from(&self.scope), self.level == "external");
        Ok(net)
    }

    /// Checkpoint inside a stage: waits while the scan or this stage is paused, fails on stop
    /// and on the user's skip/restart of the running stage.
    async fn gate(&mut self) -> Result<(), Stop> {
        loop {
            self.gate_scan().await?;
            let id = STAGES[lock(&self.st).stage.min(STAGES.len() - 1)].0;
            match control::stage_mark(&self.skip, id) {
                control::StageMark::Go => return Ok(()),
                control::StageMark::Skip => return Err(Stop::SkipStage),
                control::StageMark::Restart => return Err(Stop::RestartStage),
                control::StageMark::Hold => {
                    tokio::select! {
                        _ = tokio::time::sleep(Duration::from_millis(300)) => {}
                        _ = self.cancel.cancelled() => return Err(Stop::Cancelled),
                    }
                }
            }
        }
    }

    /// Waits while the whole scan is paused; fails once it is stopped.
    async fn gate_scan(&mut self) -> Result<(), Stop> {
        loop {
            if self.cancel.is_cancelled() {
                return Err(Stop::Cancelled);
            }
            if self.pause.borrow().is_none() {
                return Ok(());
            }
            tokio::select! {
                _ = self.pause.changed() => {}
                _ = self.cancel.cancelled() => return Err(Stop::Cancelled),
            }
        }
    }

    fn progress(&self, stage: usize, frac: f64) {
        self.progress_n(stage, frac, None);
    }

    /// Reports progress with a stage counter (`done` of `total` files, e.g. "Download 3/29"): the download
    /// queue is not part of the snapshot, so without the counter the UI cannot tell how many files remain.
    fn progress_n(&self, stage: usize, frac: f64, n: Option<(usize, usize)>) {
        let p = ((stage as f64 + frac.clamp(0.0, 1.0)) * 100.0 / STAGES.len() as f64)
            .floor()
            .min(99.0) as u8;
        let mut st = lock(&self.st);
        if p <= st.progress && n.is_none() {
            return;
        }
        let grew = p > st.progress;
        st.progress = st.progress.max(p);
        let p = st.progress;
        // persist progress in the running scan file: after kill -9 the `stopped/restart` record shows
        // where the scan stopped rather than the percentage at stage entry
        if grew {
            self.e.persist_run(&st);
        }
        drop(st);
        let mut ev = json!({ "type": "progress", "scan_id": self.scan_id, "progress": p, "stage": STAGES[stage].0 });
        if let Some((done, total)) = n {
            ev["done"] = json!(done);
            ev["total"] = json!(total);
        }
        self.e.emit(ev);
    }

    fn enter(&self, i: usize) {
        {
            let mut st = lock(&self.st);
            st.stage = i;
        }
        self.e.persist_run(&lock(&self.st));
        self.e.emit(json!({ "type": "stage", "scan_id": self.scan_id, "stage": STAGES[i].0, "label": STAGES[i].1, "index": i }));
        self.progress(i, 0.0);
    }

    fn db_event(&self, i: usize) {
        let project = lock(&self.st).project.clone();
        self.e.emit(json!({ "type": "db", "scan_id": self.scan_id, "project": project, "kind": STAGES[i].0 }));
    }

    fn source_event(&self, id: &str, status: &str, n: Option<usize>) {
        self.source_event_full(id, status, n, None)
    }

    fn source_event_full(&self, id: &str, status: &str, n: Option<usize>, error: Option<&str>) {
        self.source_event_x(id, status, n, error, Value::Null)
    }

    /// Emits a `source` event with extra fields (`extra` is an object: `timeout_s`, `deadline_ms`, `round`, ...).
    fn source_event_x(
        &self,
        id: &str,
        status: &str,
        n: Option<usize>,
        error: Option<&str>,
        extra: Value,
    ) {
        let name = SOURCES
            .iter()
            .find(|s| s.0 == id)
            .map(|s| s.1)
            .unwrap_or(id);
        {
            let mut st = lock(&self.st);
            if let Some(s) = st.sources.iter_mut().find(|s| s.id == id) {
                s.status = status.into();
            }
        }
        // status of the latest answer, for Settings → Sources (settings.source_status.<id>)
        if !matches!(
            status,
            "wait" | "running" | "off" | "nokey" | "skipped_headless"
        ) && id != "dns"
        {
            let mut st =
                json!({ "status": status, "n": n, "error": error, "at": self.e.now_iso() });
            crate::services::i18n::annotate(&mut st, &["error"]);
            let rec = json!({ "source_status": { id: st } });
            let _ = self.e.store().settings_set(&rec);
        }
        let mut ev = json!({ "type": "source", "scan_id": self.scan_id, "id": id, "name": name, "status": status });
        if let Some(n) = n {
            ev["n"] = json!(n);
        }
        if let Some(e) = error {
            ev["error"] = json!(e);
        }
        if let (Some(o), Value::Object(x)) = (ev.as_object_mut(), extra) {
            o.extend(x);
        }
        crate::services::i18n::annotate(&mut ev, &["error", "detail"]);
        self.e.emit(ev);
    }

    /// Emits a scan warning (a `warning` event immediately, plus the `warnings` field in `done`).
    fn warn(&self, code: &str, message: &str) {
        let w = json!({ "code": code, "message": message });
        {
            let db = lock(&self.db);
            let key = warn_key(&self.scan_id);
            let mut v: Vec<Value> = facts::get(&db, &key);
            if !v.iter().any(|x| x["code"] == code) {
                v.push(w.clone());
                let _ = facts::put(&db, &key, &v);
            }
        }
        tracing::warn!(target: "foca::scan", "{}: {code}, {message}", self.scan_id);
        self.e.emit(
            json!({ "type": "warning", "scan_id": self.scan_id, "code": code, "message": message }),
        );
    }

    /// Returns `true` if the module is enabled: the custom profile allows only the selected modules,
    /// other profiles allow everything by their rules (the stage itself decides the access level).
    fn module(&self, m: &str) -> bool {
        let st = lock(&self.st);
        st.profile_id != "custom" || st.modules.iter().any(|x| x == m)
    }

    fn findings_events(&self, ids: &[u64]) {
        if ids.is_empty() {
            return;
        }
        let db = lock(&self.db);
        let map: facts::FidMap = facts::get(&db, facts::K_FIDS);
        let all = db.findings().unwrap_or_default();
        drop(db);
        for f in all.iter().filter(|f| ids.contains(&f.id)) {
            self.e.emit(
                json!({ "type": "finding", "scan_id": self.scan_id, "finding": {
                "id": map.get(f.id), "title": f.title, "sev": f.sev, "host": f.host,
                "rule": f.provenance.rule } }),
            );
        }
    }
}

impl Core {
    /// Returns `ScanStatus` (with `active`, `profile`, `profile_id`, `targets`, `modules`, `started_at`).
    pub(crate) fn scan_status(&self, for_project: Option<&str>) -> Value {
        let g = lock(&self.run);
        let Some(r) = g.as_ref() else {
            return json!({ "running": false });
        };
        let st = lock(&r.st);
        if for_project.is_some_and(|p| p != st.project) {
            return json!({ "running": false });
        }
        json!({
            "running": true, "scan_id": st.scan_id, "project": st.project,
            "profile": profile_label(&st.profile_id), "profile_id": st.profile_id,
            "active": st.active, "level": st.level, "progress": st.progress,
            "stage": STAGES[st.stage.min(STAGES.len() - 1)].0,
            "paused": st.pause_reason.is_some(), "pause_reason": st.pause_reason,
            "targets": st.targets, "modules": st.modules, "started_at": st.started_at,
            "resumed": st.resumed, "egress": st.egress, "auto": st.auto,
            "stage_index": st.stage.min(STAGES.len() - 1),
            // source statuses, for a UI reopened after an interface restart that missed the `source` events
            "sources": st.sources,
            // running sub-step of the stage (network: brute force 640/1500, ...)
            "substep": st.substep,
            // per-item controls: supported actions, items held by the user, queued restarts
            "controls": control::caps(),
            "held": control::held(&r.skip),
            "followup": st.followup,
        })
    }
}

impl Engine {}

pub(crate) async fn pipeline(mut c: Ctx) -> Result<(), Stop> {
    let mut i = c.start_stage;
    while i < STAGES.len() {
        let stage = &STAGES[i];
        let label = stage.1;
        c.gate_scan().await?;
        if lock(&c.skip).remove(&format!("{}{}", control::SKIP_STAGE, stage.0)) {
            // skipped by the user before it started
            tracing::info!(target: "foca::scan", "{}: этап «{}», пропущен пользователем", c.scan_id, label);
            c.enter(i);
            c.progress(i, 1.0);
            i += 1;
            continue;
        }
        c.enter(i);
        let t0 = std::time::Instant::now();
        tracing::info!(target: "foca::scan", "{}: этап «{}», старт", c.scan_id, label);
        let r = match i {
            0 => stage_search(&mut c).await,
            1 => stage_download(&mut c).await,
            2 => stage_meta(&mut c).await,
            3 => stage_analysis(&mut c).await,
            4 => stage_network(&mut c).await,
            _ => match stage.0 {
                "ports" => match ports::stage_ports(&mut c).await {
                    Ok(()) => infra::tls_active(&mut c).await,
                    e => e,
                },
                "recon" => match recon::stage_recon(&mut c).await {
                    Ok(()) => recon::recon_extra_ports(&mut c).await,
                    e => e,
                },
                "fuzz" => fuzz::stage_fuzz(&mut c).await,
                _ => Ok(()),
            },
        };
        let ms = t0.elapsed().as_millis();
        match &r {
            Ok(()) => {
                tracing::info!(target: "foca::scan", "{}: этап «{}», готово за {ms} мс", c.scan_id, label)
            }
            Err(Stop::Cancelled) => {
                tracing::info!(target: "foca::scan", "{}: этап «{}», остановлен через {ms} мс", c.scan_id, label)
            }
            Err(Stop::Error(e)) => {
                tracing::error!(target: "foca::scan", "{}: этап «{}», ошибка через {ms} мс: {e}", c.scan_id, label)
            }
            Err(Stop::SkipStage) => {
                tracing::info!(target: "foca::scan", "{}: этап «{}», пропущен пользователем через {ms} мс", c.scan_id, label)
            }
            Err(Stop::RestartStage) => {
                tracing::info!(target: "foca::scan", "{}: этап «{}», перезапуск по запросу через {ms} мс", c.scan_id, label)
            }
        }
        match r {
            Err(Stop::SkipStage) => {
                lock(&c.skip).remove(&format!("{}{}", control::SKIP_STAGE, stage.0));
            }
            // a restart asked while the stage was finishing runs it again as well
            Err(Stop::RestartStage) => continue,
            Ok(()) if c.take_restart("stage", stage.0) => continue,
            r => r?,
        }
        c.gate_scan().await?;
        c.progress(i, 1.0);
        c.db_event(i);
        i += 1;
    }
    Ok(())
}

async fn reanalyze_bg(c: &Ctx) -> Result<Vec<u64>, Stop> {
    let db = c.db.clone();
    let sid = c.scan_id.clone();
    tokio::task::spawn_blocking(move || {
        crate::analysis::insights::reanalyze(&lock(&db), Some(&sid))
    })
    .await
    .map_err(|e| Stop::Error(e.to_string()))?
    .map_err(Stop::from)
}

fn sev_of(s: &str) -> Severity {
    serde_json::from_value(json!(s)).unwrap_or(Severity::Info)
}

pub(crate) mod control;
mod documents;
pub(crate) mod fuzz;
pub(crate) mod infra;
mod network;
pub(crate) mod plugins;
pub(crate) mod ports;
pub(crate) mod recon;
pub(crate) mod search;
pub(crate) mod sources;
pub(crate) mod steps;
mod takeover;

#[cfg(test)]
mod target_tests {
    use super::*;
    use foca_core::api::ScopeTarget;

    #[test]
    fn expands_network_targets_and_ignores_non_network_and_exclusions() {
        let sc = ScopeDto {
            targets: vec![
                ScopeTarget {
                    v: "example.com".into(),
                    kind: "domain".into(),
                },
                ScopeTarget {
                    v: "*.sub.example.com".into(),
                    kind: "wild".into(),
                },
                ScopeTarget {
                    v: "https://portal.example.com/app".into(),
                    kind: "url".into(),
                },
                ScopeTarget {
                    v: "https://203.0.113.9/admin".into(),
                    kind: "url".into(),
                },
                ScopeTarget {
                    v: "203.0.113.5".into(),
                    kind: "ip".into(),
                },
                ScopeTarget {
                    v: "203.0.113.16/30".into(),
                    kind: "cidr".into(),
                },
                ScopeTarget {
                    v: "203.0.113.30-203.0.113.32".into(),
                    kind: "range".into(),
                },
                ScopeTarget {
                    v: "user@example.com".into(),
                    kind: "email".into(),
                },
                ScopeTarget {
                    v: "AS15169".into(),
                    kind: "asn".into(),
                },
                ScopeTarget {
                    v: "Example LLC".into(),
                    kind: "org".into(),
                },
            ],
            excl: vec!["203.0.113.31".into()],
            ..Default::default()
        };
        let req: Vec<String> = sc.targets.iter().map(|t| t.v.clone()).collect();
        let doms = target_domains(&sc, &req);
        assert_eq!(
            doms,
            vec!["example.com", "sub.example.com", "portal.example.com"]
        );
        let ips = target_ips(&sc, &req, 64);
        assert_eq!(
            ips,
            vec![
                "203.0.113.9",
                "203.0.113.5",
                "203.0.113.17",
                "203.0.113.18",
                "203.0.113.30",
                "203.0.113.32",
            ]
        );
        // Safe cap stops large CIDRs from exploding
        let capped = target_ips(&sc, &["198.51.100.0/24".into()], 8);
        assert_eq!(capped.len(), 8);
        assert_eq!(capped[0], "198.51.100.1");
    }
}

/// Requests of a source that finally failed with a rate limit or a server error (retried
/// attempts that later succeeded excluded).
fn lost_request(r: &foca_store::project::RequestLog) -> bool {
    let err = r.error.as_deref().unwrap_or("");
    if err.starts_with("retry:") {
        return false;
    }
    matches!(r.status, Some(429) | Some(500..=599))
        || (r.status.is_none() && err.starts_with("limit:"))
}

/// Sources whose data for this scan is incomplete: a failed final status (except a policy skip of
/// the plugins source), or an `ok` status while
/// some of the source's requests finally failed with a rate limit (429, or a request not sent
/// after an earlier 429) or a server error (5xx): retried attempts that later succeeded are
/// not counted.
///
/// Each entry carries the reason: the final status (`lost` for an `ok` source that lost
/// requests) and the HTTP code of the source's last failed request.
pub(crate) fn incomplete_sources(
    sources: &[ScanSource],
    log: &[foca_store::project::RequestLog],
) -> Vec<foca_core::api::IncompleteSource> {
    let lost: BTreeSet<&str> = log
        .iter()
        .filter(|r| lost_request(r))
        .map(|r| r.module.as_str())
        .collect();
    // Last HTTP error code per module (the log is in request order).
    let mut http: std::collections::BTreeMap<&str, u16> = Default::default();
    for r in log {
        if r.error.as_deref().is_some_and(|e| e.starts_with("retry:")) {
            continue;
        }
        if let Some(c) = r
            .status
            .filter(|c| *c == 429 || *c >= 500 || (*c >= 400 && r.error.is_some()))
        {
            http.insert(r.module.as_str(), c);
        }
    }
    sources
        .iter()
        .filter_map(|s| {
            let status = match s.status.as_str() {
                st @ ("error" | "timeout" | "blocked" | "captcha" | "limit") => st,
                // the plugins source is never skipped by the user: `skipped` there means the
                // passive-mode policy held every plugin back on purpose (no data was expected)
                "skipped" if s.id != plugins::SOURCE => "skipped",
                "ok" if lost.contains(s.id.as_str()) => "lost",
                _ => return None,
            };
            Some(foca_core::api::IncompleteSource {
                id: s.id.clone(),
                status: status.into(),
                http: http.get(s.id.as_str()).copied(),
            })
        })
        .collect()
}

#[cfg(test)]
mod incomplete_tests {
    use super::*;
    use foca_store::project::RequestLog;

    fn incomplete_source_ids(sources: &[ScanSource], log: &[RequestLog]) -> Vec<String> {
        incomplete_sources(sources, log)
            .into_iter()
            .map(|s| s.id)
            .collect()
    }

    fn src(id: &str, status: &str) -> ScanSource {
        ScanSource {
            id: id.into(),
            name: id.into(),
            status: status.into(),
        }
    }

    fn req(module: &str, status: Option<u16>, error: Option<&str>) -> RequestLog {
        RequestLog {
            module: module.into(),
            status,
            error: error.map(String::from),
            ..Default::default()
        }
    }

    #[test]
    fn partial_source_failures_mark_the_scan_incomplete() {
        let sources = [
            src("wayback", "ok"),
            src("cc", "ok"),
            src("otx", "ok"),
            src("crt", "ok"),
            src("urlscan", "limit"),
            src("bing", "off"),
        ];
        let log = [
            // Retried 503 that later succeeded: no data lost.
            req("crt", Some(503), Some("retry: HTTP 503")),
            req("crt", Some(200), None),
            // Final failures inside a source that still ended `ok`.
            req("wayback", Some(503), None),
            req("cc", Some(504), None),
            req("otx", None, Some("limit: already rate limited")),
            // Client errors are not data loss of the source.
            req("bing", Some(404), None),
        ];
        let got = incomplete_source_ids(&sources, &log);
        assert_eq!(got, ["wayback", "cc", "otx", "urlscan"]);
    }

    #[test]
    fn incomplete_sources_carry_status_and_last_http_code() {
        let sources = [
            src("cc", "error"),
            src("otx", "ok"),
            src("startpage", "captcha"),
            src("fuzz", "blocked"),
            src("crt", "ok"),
        ];
        let log = [
            req("cc", Some(502), Some("http_status: HTTP 502")),
            req("otx", Some(429), None),
            req("crt", Some(503), Some("retry: HTTP 503")),
            req("crt", Some(200), None),
        ];
        let got: Vec<(String, String, Option<u16>)> = incomplete_sources(&sources, &log)
            .into_iter()
            .map(|s| (s.id, s.status, s.http))
            .collect();
        let want = [
            ("cc", "error", Some(502)),
            ("otx", "lost", Some(429)),
            ("startpage", "captcha", None),
            ("fuzz", "blocked", None),
        ];
        assert_eq!(got, want.map(|(a, b, c)| (a.to_string(), b.to_string(), c)));
    }

    #[test]
    fn policy_skip_of_plugins_is_not_incomplete() {
        let sources = vec![
            src(plugins::SOURCE, "skipped"),
            src("crt", "skipped"),
            src("dns", "ok"),
        ];
        assert_eq!(incomplete_source_ids(&sources, &[]), ["crt"]);
        let failed = vec![src(plugins::SOURCE, "error")];
        assert_eq!(incomplete_source_ids(&failed, &[]), [plugins::SOURCE]);
    }
}
