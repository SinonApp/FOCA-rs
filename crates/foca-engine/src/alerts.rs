//! Event alerts (`foca_analysis::alerts`), Risk Trend, and Telegram / Webhook delivery (`foca_net::notify`).

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Duration;

use foca_analysis::alerts::{
    evaluate, risk_trend, AlertRule, AlertSettings, AlertSnapshot, CertRef, CtRef, DanglingRef,
    DocRef, PortRef, SevCounts,
};
use foca_core::api::Snapshot;
use foca_core::{Scope, Severity};
use foca_net::notify::{
    send, Channel, Delivery, Lang, Notice, NotifyAlert, NotifyOptions, Secret, WebhookKind,
};
use foca_search::store::StoreSink;
use foca_store::ProjectDb;
use serde_json::{json, Value};

use crate::analysis::facts::{
    self, NetFacts, K_ALERT_CFG, K_ALERT_FIRED, K_ALERT_LOG, K_ALERT_SNAP, K_NET,
};
use crate::engine::lock;
use crate::services::resume::RunState;
use crate::{CmdError, CmdResult, Engine};

const MAX_ALERT_LOG: usize = 200;

fn parse_webhook_kind(s: &str) -> Result<WebhookKind, CmdError> {
    match s.trim().to_ascii_lowercase().as_str() {
        "slack" => Ok(WebhookKind::Slack),
        "mattermost" => Ok(WebhookKind::Mattermost),
        "discord" => Ok(WebhookKind::Discord),
        "generic" | "" => Ok(WebhookKind::Generic),
        other => Err(CmdError::new(
            "bad_args",
            format!("неизвестный тип webhook: {other}"),
        )),
    }
}

const TG_TOKEN_MISSING: &str = "Токен Telegram-бота не задан";
const TG_CHAT_MISSING: &str = "Не указан chat_id";
const WEBHOOK_MISSING: &str = "URL webhook не задан";

fn validate_alert_patch(patch: &Value) -> Result<Value, CmdError> {
    let mut clean = patch.clone();
    if let Some(o) = clean.as_object_mut() {
        for f in [
            "token",
            "bot_token",
            "tg_token",
            "url",
            "webhook_url",
            "secret",
        ] {
            o.remove(f);
        }
        for sub in ["telegram", "webhook"] {
            if let Some(so) = o.get_mut(sub).and_then(Value::as_object_mut) {
                for f in [
                    "token",
                    "bot_token",
                    "url",
                    "webhook_url",
                    "value",
                    "secret",
                    "key",
                ] {
                    so.remove(f);
                }
            }
        }
    }
    if let Some(ms) = clean.get("min_severity") {
        let _: Severity = serde_json::from_value(ms.clone())
            .map_err(|_| CmdError::new("bad_args", "недопустимый min_severity"))?;
    }
    if let Some(wk) = clean["webhook"]["kind"].as_str() {
        parse_webhook_kind(wk)?;
    }
    Ok(clean)
}

fn parse_alert_settings(v: &Value) -> AlertSettings {
    AlertSettings::from_json(v)
}

fn available_rules_json() -> Vec<Value> {
    AlertRule::ALL
        .iter()
        .map(|r| json!({ "id": r.id(), "is_diff": r.is_diff() }))
        .collect()
}

fn infer_complete(rec: &Value) -> bool {
    rec["status"].as_str() == Some("done") && !rec["env"]["incomplete"].as_bool().unwrap_or(false)
}

/// Builds an [`AlertSnapshot`] from the project snapshot and database (counters and names only;
/// raw secrets and PII values are never included).
pub(crate) fn build_alert_snapshot(
    snap: &Snapshot,
    db: &ProjectDb,
    scan_id: &str,
    scan_time: &str,
    complete: bool,
) -> AlertSnapshot {
    let hosts: BTreeSet<String> = snap
        .hosts
        .iter()
        .filter(|h| h.scope != "excluded" && h.scope != "out_of_scope")
        .map(|h| h.name.clone())
        .collect();

    let mut ports = Vec::new();
    if let Some(arr) = snap.ports.as_array() {
        for entry in arr {
            let host = entry["host"].as_str().unwrap_or("").to_string();
            if host.is_empty() {
                continue;
            }
            for p in entry["ports"].as_array().into_iter().flatten() {
                if p["unconfirmed"].as_bool().unwrap_or(false) {
                    continue;
                }
                if let Some(port) = p["port"].as_u64().and_then(|n| u16::try_from(n).ok()) {
                    ports.push(PortRef {
                        host: host.clone(),
                        port,
                        service: p["service"].as_str().unwrap_or("").to_string(),
                    });
                }
            }
        }
    }

    let mut sec_by_doc: BTreeMap<u64, u32> = BTreeMap::new();
    for s in &snap.secrets {
        *sec_by_doc.entry(s.doc).or_default() += 1;
    }
    let mut pii_by_doc: BTreeMap<u64, u32> = BTreeMap::new();
    for f in &snap.findings {
        if f.module == "pii" {
            if let Some(did) = f.doc {
                *pii_by_doc.entry(did).or_default() += 1;
            }
        }
    }
    let docs: Vec<DocRef> = snap
        .docs
        .iter()
        .filter(|d| !d.deleted)
        .map(|d| {
            let has_pii_flag = d.flags.iter().any(|x| x == "pii");
            let pii = pii_by_doc
                .get(&d.id)
                .copied()
                .unwrap_or(0)
                .max(u32::from(has_pii_flag));
            DocRef {
                id: d.id,
                name: d.name.clone(),
                host: d.host.clone(),
                secrets: sec_by_doc.get(&d.id).copied().unwrap_or(0),
                pii,
                gps: d.gps.is_some(),
            }
        })
        .collect();

    let mut certs = Vec::new();
    for (_, rec) in db.infra_list("cert").unwrap_or_default() {
        let host = rec["host"].as_str().unwrap_or("").to_string();
        if host.is_empty() {
            continue;
        }
        if let Some(leaf) = rec["chain"].as_array().and_then(|a| a.first()) {
            let not_after = leaf["not_after"].as_str().unwrap_or("").to_string();
            if not_after.is_empty() {
                continue;
            }
            certs.push(CertRef {
                host,
                fingerprint: leaf["sha256"].as_str().unwrap_or("").to_string(),
                not_after,
            });
        }
    }

    let mut ct = Vec::new();
    for (_, rec) in db.infra_list("ct").unwrap_or_default() {
        for tl in rec["timeline"].as_array().into_iter().flatten() {
            let host = tl["host"].as_str().unwrap_or("").to_string();
            if host.is_empty() {
                continue;
            }
            let issuers = tl["issuers"].as_array().cloned().unwrap_or_default();
            if issuers.is_empty() {
                let count = tl["cert_count"].as_u64().unwrap_or(0);
                ct.push(CtRef {
                    source: "crtsh".into(),
                    id: format!("{host}:{count}"),
                    names: vec![host.clone()],
                    issuer: String::new(),
                    not_before: String::new(),
                });
            } else {
                for iss in issuers {
                    let from = iss["from"].as_i64().unwrap_or(0);
                    let to = iss["to"].as_i64().unwrap_or(0);
                    let certs_n = iss["certs"].as_u64().unwrap_or(0);
                    let nb = time::OffsetDateTime::from_unix_timestamp(from)
                        .ok()
                        .and_then(|dt| {
                            dt.format(&time::format_description::well_known::Rfc3339)
                                .ok()
                        })
                        .unwrap_or_default();
                    ct.push(CtRef {
                        source: "crtsh".into(),
                        id: format!("{host}:{from}:{to}:{certs_n}"),
                        names: vec![host.clone()],
                        issuer: iss["issuer"].as_str().unwrap_or("").to_string(),
                        not_before: nb,
                    });
                }
            }
        }
    }

    let net_facts: NetFacts = facts::get(db, K_NET);
    let dangling: Vec<DanglingRef> = net_facts
        .hosts
        .values()
        .filter_map(|h| {
            let target = h.dangling.as_ref()?;
            let is_crit = snap.findings.iter().any(|f| {
                f.host == h.name
                    && f.provenance.rule == "dangling-cname"
                    && f.sev == Severity::Critical
            });
            Some(DanglingRef {
                host: h.name.clone(),
                chain: vec![target.clone()],
                provider: (!h.cloud.is_empty() && h.cloud != "-").then(|| h.cloud.clone()),
                sev: if is_crit { "crit" } else { "high" }.into(),
            })
        })
        .collect();

    let mut counts = SevCounts::default();
    for f in &snap.findings {
        if matches!(
            f.status,
            foca_core::FindingStatus::FalsePositive | foca_core::FindingStatus::Fixed
        ) {
            continue;
        }
        counts.add(f.sev);
    }
    let risk = if counts.total() == 0 && docs.is_empty() && hosts.is_empty() {
        None
    } else {
        Some(counts.risk())
    };

    AlertSnapshot {
        scan_id: scan_id.into(),
        scan_time: scan_time.into(),
        complete,
        hosts,
        ports,
        docs,
        certs,
        ct,
        dangling,
        risk,
        counts,
    }
}

impl Engine {
    fn optional_project_arg(&self, a: &Value) -> Result<Option<String>, CmdError> {
        if let Some(p) = a
            .get("project")
            .or_else(|| a.get("id"))
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            return Ok(Some(p.to_string()));
        }
        Ok(None)
    }

    fn effective_alert_cfg(&self, project: Option<&str>) -> Result<Value, CmdError> {
        let mut cfg = self.public_settings()?["alerts"].clone();
        if let Some(pid) = project {
            let db = self.db(pid)?;
            let db = lock(&db);
            if let Ok(Some(ovr)) = db.setting(K_ALERT_CFG) {
                foca_store::settings::merge(&mut cfg, &ovr);
            }
        }
        if let Some(o) = cfg.as_object_mut() {
            for f in [
                "token",
                "bot_token",
                "tg_token",
                "url",
                "webhook_url",
                "secret",
            ] {
                o.remove(f);
            }
            for sub in ["telegram", "webhook"] {
                if let Some(so) = o.get_mut(sub).and_then(Value::as_object_mut) {
                    for f in [
                        "token",
                        "bot_token",
                        "url",
                        "webhook_url",
                        "value",
                        "secret",
                        "key",
                    ] {
                        so.remove(f);
                    }
                }
            }
        }
        Ok(cfg)
    }

    fn build_alert_rules_view(&self, project: Option<&str>) -> CmdResult {
        let mut cfg = self.effective_alert_cfg(project)?;
        let keys = self.current_keys();
        let tg_set = keys.get("tg_bot").is_some_and(|v| !v.trim().is_empty());
        let wh_set = keys.get("webhook").is_some_and(|v| !v.trim().is_empty());
        let chat_ok = !cfg["telegram"]["chat_id"]
            .as_str()
            .unwrap_or("")
            .trim()
            .is_empty();
        if let Some(t) = cfg["telegram"].as_object_mut() {
            t.insert("ready".into(), json!(tg_set && chat_ok));
        }
        if let Some(w) = cfg["webhook"].as_object_mut() {
            w.insert("ready".into(), json!(wh_set));
        }
        let hist_pid = match project {
            Some(p) => Some(p.to_string()),
            None => self.public_settings()?["last_project"]
                .as_str()
                .map(String::from),
        };
        let history: Vec<Value> = match hist_pid {
            Some(pid) => match self.db(&pid) {
                Ok(db) => facts::get(&lock(&db), K_ALERT_LOG),
                Err(_) => Vec::new(),
            },
            None => Vec::new(),
        };
        if let Some(o) = cfg.as_object_mut() {
            o.insert("available_rules".into(), json!(available_rules_json()));
            o.insert("history".into(), json!(history));
        }
        Ok(cfg)
    }

    pub(crate) fn alert_rules_get(&self, a: &Value) -> CmdResult {
        let pid = self.optional_project_arg(a)?;
        self.build_alert_rules_view(pid.as_deref())
    }

    /// A channel can be switched on only with its required settings: Telegram needs the bot
    /// token (key store) and a chat id, a webhook needs its URL (key store).
    fn check_channels_ready(&self, project: Option<&str>, patch: &Value) -> Result<(), CmdError> {
        let keys = self.current_keys();
        let has_key = |k: &str| keys.get(k).is_some_and(|v| !v.trim().is_empty());
        if patch["telegram"]["enabled"] == true {
            let chat = match patch["telegram"]["chat_id"].as_str() {
                Some(c) => c.trim().to_string(),
                None => self.effective_alert_cfg(project)?["telegram"]["chat_id"]
                    .as_str()
                    .unwrap_or("")
                    .trim()
                    .to_string(),
            };
            if !has_key("tg_bot") {
                return Err(CmdError::new("alert_not_ready", TG_TOKEN_MISSING));
            }
            if chat.is_empty() {
                return Err(CmdError::new("alert_not_ready", TG_CHAT_MISSING));
            }
        }
        let wh_override = self.inner.cfg.endpoints.sources.contains_key("webhook");
        if patch["webhook"]["enabled"] == true && !has_key("webhook") && !wh_override {
            return Err(CmdError::new("alert_not_ready", WEBHOOK_MISSING));
        }
        Ok(())
    }

    pub(crate) fn alert_rules_set(&self, a: &Value) -> CmdResult {
        let pid = self.optional_project_arg(a)?;
        let patch = validate_alert_patch(a.get("patch").unwrap_or(&json!({})))?;
        self.check_channels_ready(pid.as_deref(), &patch)?;
        if let Some(ref p) = pid {
            let db = self.db(p)?;
            let db = lock(&db);
            let mut cur: Value = db.setting(K_ALERT_CFG)?.unwrap_or_else(|| json!({}));
            foca_store::settings::merge(&mut cur, &patch);
            db.set_setting(K_ALERT_CFG, &cur)?;
        } else {
            self.store().settings_set(&json!({ "alerts": patch }))?;
        }
        self.build_alert_rules_view(pid.as_deref())
    }

    fn notify_options_for(&self, cfg: &Value) -> NotifyOptions {
        let mut opts = NotifyOptions::default();
        if let Some(tg) = self.inner.cfg.endpoints.sources.get("telegram") {
            opts.telegram_api = tg.trim_end_matches('/').to_string();
        }
        let raw_lang = cfg["lang"].as_str().unwrap_or("auto");
        opts.lang = Lang::parse(raw_lang).unwrap_or_else(|| self.ui_lang());
        let local_test = self.inner.cfg.endpoints.sources.contains_key("telegram")
            || self.inner.cfg.endpoints.sources.contains_key("webhook")
            || self
                .inner
                .cfg
                .endpoints
                .crtsh
                .starts_with("http://127.0.0.1");
        if local_test {
            opts.allow_http = true;
            opts.attempts = 2;
            opts.backoff = Duration::from_millis(20);
        }
        opts
    }

    fn redact_delivery_err(&self, project: Option<&str>, msg: &str) -> String {
        let mut known = self.known_secrets();
        if let Some(pid) = project {
            if let Ok(db) = self.db(pid) {
                known.extend(crate::settings::secret_values(&lock(&db)));
            }
        }
        crate::analysis::redact::redact(msg, &known)
    }

    /// Delivers `notice` to one channel: `{ ok, channel, status, attempts, sent, error }`, plus
    /// `error_msg` (code + params) when the error is a known core message.
    async fn deliver_to_channel(
        &self,
        project: Option<&str>,
        ch_name: &str,
        cfg: &Value,
        notice: &Notice,
    ) -> Value {
        let mut v = self.deliver_raw(project, ch_name, cfg, notice).await;
        crate::i18n::annotate(&mut v, &["error"]);
        v
    }

    async fn deliver_raw(
        &self,
        project: Option<&str>,
        ch_name: &str,
        cfg: &Value,
        notice: &Notice,
    ) -> Value {
        let channel = match ch_name {
            "telegram" => {
                let Some(tok) = self
                    .current_keys()
                    .get("tg_bot")
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                else {
                    return json!({
                        "ok": false,
                        "channel": "telegram",
                        "status": null,
                        "attempts": 0,
                        "sent": 0,
                        "error": TG_TOKEN_MISSING,
                    });
                };
                let chat_id = cfg["telegram"]["chat_id"]
                    .as_str()
                    .unwrap_or("")
                    .trim()
                    .to_string();
                if chat_id.is_empty() {
                    return json!({
                        "ok": false,
                        "channel": "telegram",
                        "status": null,
                        "attempts": 0,
                        "sent": 0,
                        "error": TG_CHAT_MISSING,
                    });
                }
                Channel::Telegram {
                    token: Secret::new(tok),
                    chat_id,
                }
            }
            "webhook" => {
                let raw_key = self
                    .current_keys()
                    .get("webhook")
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty());
                let override_url = self
                    .inner
                    .cfg
                    .endpoints
                    .sources
                    .get("webhook")
                    .map(String::as_str)
                    .filter(|s| !s.is_empty());
                let Some(url) = raw_key.or_else(|| override_url.map(String::from)) else {
                    return json!({
                        "ok": false,
                        "channel": "webhook",
                        "status": null,
                        "attempts": 0,
                        "sent": 0,
                        "error": WEBHOOK_MISSING,
                    });
                };
                let kind = parse_webhook_kind(cfg["webhook"]["kind"].as_str().unwrap_or("generic"))
                    .unwrap_or(WebhookKind::Generic);
                Channel::Webhook {
                    url: Secret::new(url),
                    kind,
                }
            }
            _ => {
                return json!({
                    "ok": false,
                    "channel": ch_name,
                    "status": null,
                    "attempts": 0,
                    "sent": 0,
                    "error": format!("неизвестный канал {ch_name}"),
                });
            }
        };

        let sink: Arc<dyn foca_net::RequestSink> = match project {
            Some(pid) => match self.db(pid) {
                Ok(db) => Arc::new(StoreSink { db, scan_id: None }),
                Err(_) => Arc::new(foca_net::MemorySink::new()),
            },
            None => Arc::new(foca_net::MemorySink::new()),
        };
        let net = match self.net_client(Scope::default(), sink) {
            Ok(n) => n,
            Err(e) => {
                return json!({
                    "ok": false,
                    "channel": ch_name,
                    "status": null,
                    "attempts": 0,
                    "sent": 0,
                    "error": self.redact_delivery_err(project, &e.message),
                });
            }
        };
        let opts = self.notify_options_for(cfg);
        match send(&net, &channel, notice, &opts, None).await {
            Ok(Delivery {
                status,
                attempts,
                sent,
            }) => json!({
                "ok": true,
                "channel": ch_name,
                "status": status,
                "attempts": attempts,
                "sent": sent,
                "error": Value::Null,
            }),
            Err(e) => json!({
                "ok": false,
                "channel": ch_name,
                "status": match e {
                    foca_net::notify::NotifyError::Rejected { status, .. } => json!(status),
                    _ => Value::Null,
                },
                "attempts": opts.attempts,
                "sent": 0,
                "error": self.redact_delivery_err(project, &e.to_string()),
            }),
        }
    }

    pub(crate) async fn alert_test(&self, a: &Value) -> CmdResult {
        let ch = crate::util::req_str(a, "channel")?
            .trim()
            .to_ascii_lowercase();
        if !matches!(ch.as_str(), "telegram" | "webhook") {
            return Err(CmdError::new("bad_args", format!("неизвестный канал {ch}")));
        }
        let pid = self.optional_project_arg(a)?;
        let cfg = self.effective_alert_cfg(pid.as_deref())?;
        let project_label = match &pid {
            Some(p) => self
                .db(p)
                .ok()
                .and_then(|db| lock(&db).info().ok())
                .map(|i| i.name)
                .unwrap_or_else(|| p.clone()),
            None => "FOCA-rs".into(),
        };
        let mut params = BTreeMap::new();
        params.insert("host".into(), json!("monitor-test.invalid"));
        let notice = Notice {
            project: project_label,
            scan_time: self.now_iso(),
            alerts: vec![NotifyAlert {
                rule: "new_host".into(),
                severity: Severity::Medium,
                title_key: "alert.new_host".into(),
                params,
            }],
            dropped: 0,
        };
        Ok(self
            .deliver_to_channel(pid.as_deref(), &ch, &cfg, &notice)
            .await)
    }

    pub(crate) fn risk_trend_get(&self, a: &Value) -> CmdResult {
        let pid = self.project_arg(a)?;
        let limit = a
            .get("limit")
            .and_then(Value::as_u64)
            .unwrap_or(30)
            .min(200) as usize;
        let db = self.db(&pid)?;
        let scans = lock(&db).scans()?;
        let trend = risk_trend(&scans, limit);
        let current = trend.points.last().map(|p| p.risk);
        let previous = if trend.points.len() >= 2 {
            Some(trend.points[trend.points.len() - 2].risk)
        } else {
            None
        };
        Ok(json!({
            "points": trend.points,
            "current": current,
            "previous": previous,
            "delta": trend.delta,
            "direction": trend.direction,
            "peak": trend.peak,
        }))
    }

    /// Evaluates alert rules right after a scan completes and delivers triggered notifications via
    /// enabled Telegram / Webhook channels without blocking scan completion on delivery errors.
    pub(crate) async fn evaluate_and_deliver_alerts(&self, st: &RunState, rec: &Value) -> Value {
        let Ok(cfg_val) = self.effective_alert_cfg(Some(&st.project)) else {
            return json!({ "fired": 0, "deliveries": [] });
        };
        let cfg = parse_alert_settings(&cfg_val);
        let Ok((snap, _)) = self.core_snapshot(&st.project) else {
            return json!({ "fired": 0, "deliveries": [] });
        };
        let scan_time = rec["finished_at"]
            .as_str()
            .filter(|s| !s.is_empty())
            .map(String::from)
            .unwrap_or_else(|| self.now_iso());
        let complete = infer_complete(rec);

        let (batch, prev_exists) = {
            let Ok(db_arc) = self.db(&st.project) else {
                return json!({ "fired": 0, "deliveries": [] });
            };
            let db = lock(&db_arc);
            let cur = build_alert_snapshot(&snap, &db, &st.scan_id, &scan_time, complete);
            let prev: Option<AlertSnapshot> = db
                .setting(K_ALERT_SNAP)
                .ok()
                .flatten()
                .and_then(|v| serde_json::from_value(v).ok());
            let fired: BTreeSet<String> = facts::get(&db, K_ALERT_FIRED);
            let batch = evaluate(prev.as_ref(), &cur, &cfg, &fired, self.now());
            let _ = facts::put(&db, K_ALERT_SNAP, &cur);
            let _ = facts::put(&db, K_ALERT_FIRED, &batch.state);
            (batch, prev.is_some())
        };

        let _ = prev_exists;
        if batch.alerts.is_empty() && batch.dropped == 0 {
            return json!({ "fired": 0, "deliveries": [] });
        }

        let notify_alerts: Vec<NotifyAlert> = batch
            .alerts
            .iter()
            .filter_map(|a| serde_json::to_value(a).ok())
            .filter_map(|v| serde_json::from_value::<NotifyAlert>(v).ok())
            .collect();
        let notice = Notice {
            project: if snap.project.name.is_empty() {
                st.project.clone()
            } else {
                snap.project.name.clone()
            },
            scan_time: scan_time.clone(),
            alerts: notify_alerts,
            dropped: batch.dropped,
        };

        let mut deliveries = Vec::new();
        if cfg_val["telegram"]["enabled"].as_bool().unwrap_or(false) {
            deliveries.push(
                self.deliver_to_channel(Some(&st.project), "telegram", &cfg_val, &notice)
                    .await,
            );
        }
        if cfg_val["webhook"]["enabled"].as_bool().unwrap_or(false) {
            deliveries.push(
                self.deliver_to_channel(Some(&st.project), "webhook", &cfg_val, &notice)
                    .await,
            );
        }

        let alerts_json = serde_json::to_value(&batch.alerts).unwrap_or_else(|_| json!([]));
        let log_entry = json!({
            "at": scan_time,
            "scan_id": st.scan_id,
            "count": batch.alerts.len(),
            "dropped": batch.dropped,
            "alerts": alerts_json,
            "deliveries": deliveries,
        });
        if let Ok(db_arc) = self.db(&st.project) {
            let db = lock(&db_arc);
            let mut hist: Vec<Value> = facts::get(&db, K_ALERT_LOG);
            hist.insert(0, log_entry);
            hist.truncate(MAX_ALERT_LOG);
            let _ = facts::put(&db, K_ALERT_LOG, &hist);
        }

        self.emit(json!({
            "type": "alert",
            "project": st.project,
            "scan_id": st.scan_id,
            "count": batch.alerts.len(),
            "dropped": batch.dropped,
            "alerts": alerts_json,
            "deliveries": deliveries,
        }));

        json!({
            "fired": batch.alerts.len(),
            "deliveries": deliveries,
        })
    }
}
