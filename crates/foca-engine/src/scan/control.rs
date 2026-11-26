//! Per-item scan controls (`scan_control`): pause/resume, skip and restart of a stage, a single
//! source or a sub-step (`brute`, `permute`).
//!
//! Markers live in the run's shared `skip` set next to the plain source skips:
//! `pause:<kind>:<id>` holds the item, `skip:stage:<id>` drops the rest of a stage at its next
//! checkpoint, `restart:<kind>:<id>` re-runs it within the current scan. A restart of an item
//! whose stage is over (or that cannot be re-run live) is queued in `RunState::followup`; the
//! `done` event lists the queue so the UI can start a follow-up run from the earliest stage.

use std::collections::HashSet;
use std::sync::Mutex;
use std::time::Duration;

use serde_json::{json, Value};

use super::{
    ports, Ctx, Stop, DOC_SOURCE_IDS, RECON_SOURCES, RESOLVER_STEPS, RETRY_PREFIX, RETRY_SOURCES,
    SEARCH_SOURCES, SOURCES, SRC_SUBDOMAINS, SRC_TLS, STAGES,
};
use crate::engine::lock;
use crate::{CmdError, CmdResult, Engine};

pub(crate) const PAUSE: &str = "pause:";
pub(crate) const SKIP_STAGE: &str = "skip:stage:";
pub(crate) const RESTART: &str = "restart:";

/// What a stage checkpoint should do.
pub(crate) enum StageMark {
    Go,
    Hold,
    Skip,
    Restart,
}

/// Marker check for the running stage `id` at a checkpoint (the restart marker is consumed).
pub(crate) fn stage_mark(skip: &Mutex<HashSet<String>>, id: &str) -> StageMark {
    let mut sk = lock(skip);
    if sk.contains(&format!("{SKIP_STAGE}{id}")) {
        return StageMark::Skip;
    }
    if sk.remove(&format!("{RESTART}stage:{id}")) {
        return StageMark::Restart;
    }
    if sk.contains(&format!("{PAUSE}stage:{id}")) {
        return StageMark::Hold;
    }
    StageMark::Go
}

/// Stage that owns a source or a sub-step.
fn owner_stage(kind: &str, id: &str) -> Option<usize> {
    let pos = |s: &str| STAGES.iter().position(|x| x.0 == s);
    match kind {
        "stage" => pos(id),
        "step" if RESOLVER_STEPS.contains(&id) => pos("network"),
        "source" if SEARCH_SOURCES.contains(&id) => Some(0),
        "source" if id == SRC_SUBDOMAINS || id == SRC_TLS => pos("network"),
        "source" if id == ports::SOURCE => pos("ports"),
        "source" if RECON_SOURCES.contains(&id) => pos("recon"),
        "source" if id == "fuzz" => pos("fuzz"),
        _ => None,
    }
}

/// Actions an item supports (`scan_status.controls`).
fn actions(kind: &str, id: &str) -> &'static [&'static str] {
    match kind {
        "stage" => &["pause", "resume", "skip", "restart"],
        "step" => &["pause", "resume", "skip", "restart"],
        "source" if id == SRC_SUBDOMAINS || id == SRC_TLS => {
            &["pause", "resume", "skip", "restart"]
        }
        "source" => &["skip", "restart"],
        _ => &[],
    }
}

/// Capability table for the UI: `{ "stage:*": [...], "step:brute": [...], "source:crt": [...] }`.
pub(crate) fn caps() -> Value {
    let mut m = serde_json::Map::new();
    m.insert("stage:*".into(), json!(actions("stage", "")));
    for s in RESOLVER_STEPS {
        m.insert(format!("step:{s}"), json!(actions("step", s)));
    }
    let sources = SEARCH_SOURCES
        .iter()
        .chain(RECON_SOURCES.iter())
        .copied()
        .chain([SRC_SUBDOMAINS, SRC_TLS, ports::SOURCE, "fuzz"]);
    for s in sources {
        m.insert(format!("source:{s}"), json!(actions("source", s)));
    }
    Value::Object(m)
}

/// Items currently held by the user (`pause:<kind>:<id>` markers, without the prefix).
pub(crate) fn held(skip: &Mutex<HashSet<String>>) -> Vec<String> {
    let mut v: Vec<String> = lock(skip)
        .iter()
        .filter_map(|x| x.strip_prefix(PAUSE).map(String::from))
        .collect();
    v.sort();
    v
}

fn reply(ok: bool, state: &str, reason: &str) -> CmdResult {
    Ok(json!({ "ok": ok, "state": state, "reason": reason }))
}

impl Engine {
    /// `scan_skip_source { id }` skips a search source (running or not yet started).
    /// Returns `{ ok }`, which is `false` if no scan is running or the search stage is already over.
    pub(crate) fn scan_skip_source(&self, a: &Value) -> CmdResult {
        let id = crate::util::arg_str(a, "id")
            .ok_or_else(|| CmdError::new("bad_args", "нет id источника"))?
            .to_string();
        let is_fuzz = id == "fuzz";
        let is_recon = RECON_SOURCES.contains(&id.as_str());
        let is_ports = id == ports::SOURCE;
        // subdomain enumeration (network stage) and TLS inspection (network stage, active checks after ports)
        // brute force / permutations alone (the rest of the subdomain enumeration keeps running)
        let is_infra =
            id == SRC_SUBDOMAINS || id == SRC_TLS || RESOLVER_STEPS.contains(&id.as_str());
        if !SEARCH_SOURCES.contains(&id.as_str()) && !is_fuzz && !is_recon && !is_ports && !is_infra
        {
            return Err(CmdError::not_found(format!(
                "источник {id} не опрашивается этапом поиска"
            )));
        }
        let g = lock(&self.inner.run);
        let Some(r) = g.as_ref() else {
            return Ok(json!({ "ok": false }));
        };
        let st = lock(&r.st);
        // "stop brute force" works before and during the site discovery stage; search sources only during stage 0
        let fuzz_stage = STAGES.iter().position(|x| x.0 == "fuzz").unwrap_or(5);
        let recon_stage = STAGES.iter().position(|x| x.0 == "recon").unwrap_or(5);
        let ports_stage = STAGES.iter().position(|x| x.0 == "ports").unwrap_or(5);
        if (is_fuzz && st.stage > fuzz_stage)
            || (is_recon && st.stage > recon_stage)
            || (is_ports && st.stage > ports_stage)
            || (is_infra && st.stage > ports_stage)
            || (!is_fuzz && !is_recon && !is_ports && !is_infra && st.stage > 0)
        {
            return Ok(json!({ "ok": false }));
        }
        let src_id = if RESOLVER_STEPS.contains(&id.as_str()) {
            SRC_SUBDOMAINS
        } else {
            id.as_str()
        };
        let fin = st
            .sources
            .iter()
            .find(|s| s.id == src_id)
            .is_some_and(|s| !matches!(s.status.as_str(), "wait" | "running"));
        if fin {
            return Ok(json!({ "ok": false }));
        }
        lock(&r.skip).insert(id.clone());
        tracing::info!(target: "foca::source", "{}: пропуск по запросу пользователя", id);
        Ok(json!({ "ok": true }))
    }

    /// `scan_retry_source { id }` retries a browser-based search source (`startpage`, `mojeek`,
    /// `brave_web`) after a manual check (captcha): while the search stage is running, the source is
    /// queried once more after the current round. Returns `{ ok, reason? }`; `false` means no scan is
    /// running or the search stage is over (the challenge cookies are kept for the next scan).
    pub(crate) fn scan_retry_source(&self, a: &Value) -> CmdResult {
        let id = crate::util::arg_str(a, "id")
            .ok_or_else(|| CmdError::new("bad_args", "нет id источника"))?
            .to_string();
        if !RETRY_SOURCES.contains(&id.as_str()) {
            return Err(CmdError::not_found(format!(
                "источник {id} нельзя повторить: только поисковики через встроенный браузер"
            )));
        }
        let later = json!({ "ok": false,
            "reason": "Этап поиска уже закончился: проверка сохранена, следующий скан её использует",
            "reason_msg": { "code": "scan.retry_later", "params": {} } });
        let g = lock(&self.inner.run);
        let Some(r) = g.as_ref() else {
            return Ok(later);
        };
        if lock(&r.st).stage > 0 {
            return Ok(later);
        }
        let mut sk = lock(&r.skip);
        // a retry cancels an earlier skip
        sk.remove(&id);
        sk.insert(format!("{RETRY_PREFIX}{id}"));
        tracing::info!(target: "foca::source", "{id}: повтор после ручной проверки");
        Ok(json!({ "ok": true }))
    }

    pub(crate) fn source_status(&self, id: &str) -> String {
        let keys = self.current_keys();
        match SOURCES.iter().find(|s| s.0 == id) {
            Some((_, _, Some(k), optional, _)) => {
                if keys.get(k).is_some_and(|v| !v.is_empty()) {
                    "ok".into()
                } else if *optional {
                    "off".into()
                } else {
                    "nokey".into()
                }
            }
            _ => "ok".into(),
        }
    }

    /// `scan_control { kind, id, action }`: see the module docs. Returns `{ ok, state, reason }`;
    /// `reason` is `no_scan` | `finished` | `pending` | `unsupported` when `ok` is `false`.
    pub(crate) fn scan_control(&self, a: &Value) -> CmdResult {
        let arg = |k: &str| crate::util::arg_str(a, k).unwrap_or("").to_string();
        let (kind, id, action) = (arg("kind"), arg("id"), arg("action"));
        let Some(owner) = owner_stage(&kind, &id) else {
            return Err(CmdError::not_found(format!(
                "нет элемента скана {kind}:{id}"
            )));
        };
        if !actions(&kind, &id).contains(&action.as_str()) {
            return reply(false, "", "unsupported");
        }
        let (cur, skip) = {
            let g = lock(&self.inner.run);
            let Some(r) = g.as_ref() else {
                return reply(false, "", "no_scan");
            };
            let stage = lock(&r.st).stage;
            (stage, r.skip.clone())
        };
        let key = format!("{kind}:{id}");
        let done = cur > owner;
        let emit = |state: &str| {
            if let Some((project, scan_id, _)) = self.running_scan() {
                self.emit(
                    json!({ "type": "control", "scan_id": scan_id, "project": project,
                    "kind": kind, "id": id, "state": state }),
                );
            }
            tracing::info!(target: "foca::scan", "управление {key}: {action} → {state}");
        };
        match action.as_str() {
            "pause" | "resume" => {
                if done {
                    return reply(false, "", "finished");
                }
                let m = format!("{PAUSE}{key}");
                let state = if action == "pause" {
                    lock(&skip).insert(m);
                    "paused"
                } else {
                    lock(&skip).remove(&m);
                    "running"
                };
                emit(state);
                reply(true, state, "")
            }
            "skip" => {
                if done {
                    return reply(false, "", "finished");
                }
                if kind == "stage" {
                    let mut sk = lock(&skip);
                    sk.insert(format!("{SKIP_STAGE}{id}"));
                    sk.remove(&format!("{PAUSE}{key}"));
                } else {
                    let r = self.scan_skip_source(&json!({ "id": id }))?;
                    if r["ok"] != true {
                        return reply(false, "", "finished");
                    }
                    lock(&skip).remove(&format!("{PAUSE}{key}"));
                }
                emit("skipped");
                reply(true, "skipped", "")
            }
            _ => {
                if cur < owner {
                    return reply(false, "", "pending");
                }
                let live = cur == owner
                    && match kind.as_str() {
                        "stage" | "step" => true,
                        // search sources that can be built again in the retry pass
                        "source" => cur == 0 && DOC_SOURCE_IDS.contains(&id.as_str()),
                        _ => false,
                    };
                let state = if live {
                    let mut sk = lock(&skip);
                    if kind == "source" {
                        sk.remove(&id);
                        sk.insert(format!("{}{id}", super::RETRY_PREFIX));
                    } else {
                        sk.insert(format!("{RESTART}{key}"));
                        sk.remove(&format!("{PAUSE}{key}"));
                        if kind == "step" {
                            sk.remove(&id);
                        }
                    }
                    "restarting"
                } else {
                    let g = lock(&self.inner.run);
                    if let Some(r) = g.as_ref() {
                        let mut st = lock(&r.st);
                        if !st.followup.contains(&key) {
                            st.followup.push(key.clone());
                        }
                        self.persist_run(&st);
                    }
                    "queued"
                };
                emit(state);
                reply(true, state, "")
            }
        }
    }
}

impl Ctx {
    /// Waits while the user holds any of `keys` (`stage:network`, `source:tls`, ...), honouring
    /// the global pause and stop.
    pub(crate) async fn hold(&mut self, keys: &[String]) -> Result<(), Stop> {
        loop {
            self.gate().await?;
            if !self.is_held(keys) {
                return Ok(());
            }
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_millis(300)) => {}
                _ = self.cancel.cancelled() => return Err(Stop::Cancelled),
            }
        }
    }

    pub(crate) fn is_held(&self, keys: &[String]) -> bool {
        let sk = lock(&self.skip);
        keys.iter().any(|k| sk.contains(&format!("{PAUSE}{k}")))
    }

    /// Consumes a restart request for `kind:id`.
    pub(crate) fn take_restart(&self, kind: &str, id: &str) -> bool {
        lock(&self.skip).remove(&format!("{RESTART}{kind}:{id}"))
    }

    pub(crate) fn restart_asked(&self, kind: &str, id: &str) -> bool {
        lock(&self.skip).contains(&format!("{RESTART}{kind}:{id}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn owners_and_caps() {
        assert_eq!(owner_stage("step", "brute"), Some(4));
        assert_eq!(owner_stage("source", "crt"), Some(0));
        assert_eq!(owner_stage("source", "tls"), Some(4));
        assert_eq!(owner_stage("stage", "fuzz"), Some(7));
        assert_eq!(owner_stage("source", "nope"), None);
        let c = caps();
        assert_eq!(c["source:crt"], json!(["skip", "restart"]));
        assert!(c["step:brute"]
            .as_array()
            .unwrap()
            .contains(&json!("pause")));
    }

    #[test]
    fn stage_marks() {
        let s: Mutex<HashSet<String>> = Mutex::default();
        assert!(matches!(stage_mark(&s, "network"), StageMark::Go));
        lock(&s).insert(format!("{PAUSE}stage:network"));
        assert!(matches!(stage_mark(&s, "network"), StageMark::Hold));
        lock(&s).insert(format!("{RESTART}stage:network"));
        assert!(matches!(stage_mark(&s, "network"), StageMark::Restart));
        // a restart is consumed once
        assert!(matches!(stage_mark(&s, "network"), StageMark::Hold));
        lock(&s).insert(format!("{SKIP_STAGE}network"));
        assert!(matches!(stage_mark(&s, "network"), StageMark::Skip));
    }
}
