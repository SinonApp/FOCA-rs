//! Project and scope commands: create/update/duplicate/delete, scope edits, bulk host
//! additions and out-of-scope candidates.

use std::collections::BTreeMap;

use foca_core::api::{ScopeDto, ScopeTarget};
use foca_store::{NewProject, ProjectPatch};
use serde_json::{json, Value};

use crate::analysis::facts::{self, NetFacts};
use crate::analysis::rules;
use crate::analysis::rules::KnownHost;
use crate::analysis::scope_bulk::{plan, with_reason_msgs, NoProbe, K_NO_PROBE, MAX_HOSTS};
use crate::engine::{lock, Core};
use crate::util::{arg_str, req_str};
use crate::{CmdError, CmdResult, Engine};

pub(crate) fn project_create(core: &Core, a: &Value) -> CmdResult {
    // Plain strings get their kind from the store; objects keep the kind they carry.
    let mut targets: Vec<(String, Option<String>)> = Vec::new();
    for t in a
        .get("targets")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
    {
        match t {
            Value::String(v) => targets.push((v, None)),
            Value::Object(_) => {
                if let Ok(x) = serde_json::from_value::<ScopeTarget>(t) {
                    if !x.v.is_empty() {
                        targets.push((x.v, Some(x.kind)));
                    }
                }
            }
            _ => {}
        }
    }
    let req = NewProject {
        name: arg_str(a, "name").unwrap_or("").into(),
        client: arg_str(a, "client").unwrap_or("").into(),
        targets: targets.iter().map(|(v, _)| v.clone()).collect(),
        excludes: a
            .get("excludes")
            .and_then(Value::as_array)
            .map(|v| {
                v.iter()
                    .filter_map(|x| x.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default(),
    };
    let s = core.store().create_project(&req)?;
    let db = core.db(&s.id)?;
    let db = lock(&db);
    let mut sc = db.scope_get()?;
    for (stored, (_, kind)) in sc.targets.iter_mut().zip(targets) {
        if let Some(kind) = kind {
            stored.kind = kind;
        }
    }
    db.scope_set(&sc)?;
    Ok(serde_json::to_value(core.summary_of(&db)?)?)
}

impl Engine {
    pub(crate) fn project_update(&self, a: &Value) -> CmdResult {
        let id = self.project_arg(a)?;
        let patch: ProjectPatch =
            serde_json::from_value(a.get("patch").cloned().unwrap_or(json!({})))?;
        self.store().update_project(&id, &patch)?;
        let db = self.db(&id)?;
        let s = self.summary_of(&lock(&db))?;
        Ok(serde_json::to_value(s)?)
    }

    pub(crate) fn project_duplicate(&self, a: &Value) -> CmdResult {
        let id = self.project_arg(a)?;
        let s = self.store().duplicate_project(&id)?;
        let db = self.db(&s.id)?;
        let s = self.summary_of(&lock(&db))?;
        Ok(serde_json::to_value(s)?)
    }

    pub(crate) async fn project_delete(&self, a: &Value) -> CmdResult {
        let id = self.project_arg(a)?;
        if self.running_scan().is_some_and(|r| r.0 == id) {
            self.stop_active_scan().await;
            let _ = std::fs::remove_file(self.run_file());
        }
        self.forget_db(&id);
        self.store().delete_project(&id)?;
        for d in ["files", "clean", "reports"] {
            let _ = std::fs::remove_dir_all(self.inner.cfg.data_dir.join(d).join(&id));
        }
        Ok(json!({ "ok": true }))
    }

    pub(crate) fn scope_set(&self, a: &Value) -> CmdResult {
        let id = self.project_arg(a)?;
        let db = self.db(&id)?;
        let db = lock(&db);
        let mut cur = serde_json::to_value(db.scope_get()?)?;
        if let (Some(o), Some(p)) = (
            cur.as_object_mut(),
            a.get("scope").and_then(Value::as_object),
        ) {
            for (k, v) in p {
                o.insert(k.clone(), v.clone());
            }
        }
        let sc: ScopeDto = serde_json::from_value(cur)?;
        let out = db.scope_set(&sc)?;
        drop(db);
        // a running scan of this project picks up new exclusions immediately
        if let Some(r) = lock(&self.inner.run).as_ref() {
            let st = lock(&r.st);
            if st.project == id {
                if let Some(net) = &r.net {
                    net.set_scope(crate::scan::core_scope_for(&out, &st.level));
                    net.set_passive_guard(foca_core::Scope::from(&out), st.level == "external");
                }
            }
        }
        Ok(serde_json::to_value(out)?)
    }

    fn oos_find(&self, project: &str, id: &str) -> Result<Value, CmdError> {
        self.oos_json(project)?
            .as_array()
            .and_then(|l| l.iter().find(|x| x["id"] == id).cloned())
            .ok_or_else(|| CmdError::not_found(format!("Кандидат {id} не найден")))
    }

    pub(crate) fn oos_decide(&self, a: &Value) -> CmdResult {
        let p = self.project_arg(a)?;
        let o = self.oos_find(&p, req_str(a, "id")?)?;
        let decision = req_str(a, "decision")?;
        if !["new", "scope", "ignored"].contains(&decision) {
            return Err(CmdError::new("bad_status", decision));
        }
        if decision == "scope" {
            if let Some(b) = o["blocked"].as_str() {
                return Err(CmdError::new("blocked", b));
            }
        }
        let db = self.db(&p)?;
        {
            let db = lock(&db);
            let mut dec: BTreeMap<String, String> = facts::get(&db, facts::K_OOS);
            let host = o["host"].as_str().unwrap_or("").to_string();
            if decision == "new" {
                dec.remove(&host);
            } else {
                dec.insert(host, decision.into());
            }
            facts::put(&db, facts::K_OOS, &dec)?;
        }
        self.oos_json(&p)
    }

    pub(crate) fn oos_add_to_scope(&self, a: &Value) -> CmdResult {
        let p = self.project_arg(a)?;
        let o = self.oos_find(&p, req_str(a, "id")?)?;
        if let Some(b) = o["blocked"].as_str() {
            return Err(CmdError::new("blocked", b));
        }
        let host = o["host"].as_str().unwrap_or("").to_string();
        let db = self.db(&p)?;
        let scope = {
            let db = lock(&db);
            let mut sc = db.scope_get()?;
            if rules::check(&sc, &host, &crate::scan::known_hosts(&db)).code == "excluded" {
                return Err(CmdError::new("blocked", "Адрес в исключениях скоупа"));
            }
            let mut dec: BTreeMap<String, String> = facts::get(&db, facts::K_OOS);
            dec.insert(host.clone(), "scope".into());
            facts::put(&db, facts::K_OOS, &dec)?;
            // a whole network is never added from candidates, only a single address or name
            let kind = match o["kind"].as_str() {
                Some("ip") | Some("cdn") => "ip",
                _ => "domain",
            };
            if !sc.targets.iter().any(|t| t.v.eq_ignore_ascii_case(&host)) {
                sc.targets.push(ScopeTarget {
                    v: host,
                    kind: kind.into(),
                });
            }
            db.scope_set(&sc)?
        };
        Ok(json!({ "scope": scope, "oos": self.oos_json(&p)? }))
    }

    /// `scope_add_hosts { project, hosts[], dry_run? }` → `{ added, skipped, no_probe, scope, dry_run }`.
    /// With `dry_run: true` nothing is stored.
    pub(crate) fn scope_add_hosts(&self, a: &Value) -> CmdResult {
        let id = self.project_arg(a)?;
        let hosts: Vec<String> = a
            .get("hosts")
            .and_then(Value::as_array)
            .map(|v| {
                v.iter()
                    .filter_map(|x| x.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default();
        if hosts.is_empty() {
            return Err(CmdError::new("bad_args", "Нужен список hosts"));
        }
        if hosts.len() > MAX_HOSTS {
            return Err(CmdError::new(
                "bad_args",
                format!("Не больше {MAX_HOSTS} имён за раз"),
            ));
        }
        let db = self.db(&id)?;
        let db = lock(&db);
        let mut sc = db.scope_get()?;
        let net: NetFacts = facts::get(&db, facts::K_NET);
        let mut known = crate::scan::known_hosts(&db);
        for h in net.hosts.values() {
            if !known.iter().any(|k| k.name == h.name) {
                known.push(KnownHost {
                    name: h.name.clone(),
                    ip: h.ip.clone(),
                });
            }
        }
        let clouds: BTreeMap<String, String> = net
            .hosts
            .values()
            .map(|h| (h.name.clone(), h.cloud.clone()))
            .collect();
        let p = plan(&sc, &known, &clouds, &hosts);
        // dry run: the UI shows the plan (excluded CDN addresses) before the user confirms
        if a.get("dry_run").and_then(Value::as_bool) == Some(true) {
            return Ok(with_reason_msgs(json!({
                "added": p.added,
                "skipped": p.skipped,
                "no_probe": p.no_probe,
                "scope": sc,
                "dry_run": true,
            })));
        }
        let mut np: NoProbe = facts::get(&db, K_NO_PROBE);
        let mut dec: BTreeMap<String, String> = facts::get(&db, facts::K_OOS);
        for h in &p.added {
            sc.targets.push(ScopeTarget {
                v: h.clone(),
                kind: "domain".into(),
            });
            np.hosts.insert(h.clone());
            dec.insert(h.clone(), "scope".into());
        }
        for x in &p.no_probe {
            np.ips.insert(x.ip.clone(), x.reason.clone());
        }
        let scope = if p.added.is_empty() {
            sc
        } else {
            facts::put(&db, K_NO_PROBE, &np)?;
            facts::put(&db, facts::K_OOS, &dec)?;
            db.scope_set(&sc)?
        };
        drop(db);
        if !p.added.is_empty() {
            self.refresh_running_scope(&id, &scope);
        }
        Ok(with_reason_msgs(json!({
            "added": p.added,
            "skipped": p.skipped,
            "no_probe": p.no_probe,
            "scope": scope,
            "dry_run": false,
        })))
    }

    /// A running scan of this project picks up the new scope immediately (same as `scope_set`).
    fn refresh_running_scope(&self, id: &str, scope: &ScopeDto) {
        if let Some(r) = lock(&self.inner.run).as_ref() {
            let st = lock(&r.st);
            if st.project == id {
                if let Some(net) = &r.net {
                    net.set_scope(crate::scan::core_scope_for(scope, &st.level));
                    net.set_passive_guard(foca_core::Scope::from(scope), st.level == "external");
                }
            }
        }
    }
}
