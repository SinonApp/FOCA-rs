//! Entry points of the engine: opening the data directory (with recovery of an interrupted scan
//! and the scan queue), attaching the interactive platform, and the command dispatcher.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use foca_core::Clock;
use foca_store::Store;
use serde_json::{json, Value};

use crate::cmds::{bundle, demo_case, hygiene, offline, projects, toolbox};
use crate::engine::{lock, Core, Engine};
use crate::util::LocalClock;
use crate::{CmdError, CmdResult, EngineConfig, EventSink, KeyProvider, ReportBuilder};

impl Engine {
    /// Opens the store in `cfg.data_dir`. A scan that was running when the previous process was
    /// unloaded is recorded in the history as `stopped` with `reason: "restart"` (it can be resumed).
    pub fn open(
        cfg: EngineConfig,
        keys: Arc<dyn KeyProvider>,
        events: Arc<dyn EventSink>,
    ) -> Result<Engine, CmdError> {
        let clock: Arc<dyn Clock> = Arc::new(LocalClock {
            inner: cfg.clock.clone(),
            off: cfg.utc_offset,
        });
        std::fs::create_dir_all(&cfg.data_dir)?;
        let mode = if cfg.headless { "headless" } else { "ui" };
        let dir_lock = foca_store::DataDirLock::acquire_wait(&cfg.data_dir, mode, cfg.lock_wait)
            .map_err(|owner| {
                let desc = match owner {
                    Some(o) => format!("{}, pid {}", o.mode, o.pid),
                    None => "другой процесс".into(),
                };
                CmdError::new(
                    "busy",
                    format!("каталог данных занят другим экземпляром ядра ({desc})"),
                )
            })?;
        crate::services::logs::install();
        crate::services::logs::set_file(&cfg.data_dir, cfg.utc_offset);
        tracing::info!(target: "foca::engine", "движок открыт: {}", cfg.data_dir.display());
        let store = Store::open_with_clock(&cfg.data_dir, clock.clone())?;
        // Data tables of an installed signature bundle (v2) replace the built-in ones.
        crate::services::sigbundle::activate(&cfg.data_dir);
        #[cfg(feature = "report")]
        let reports: Option<Arc<dyn ReportBuilder>> =
            Some(Arc::new(crate::services::report::FocaReport));
        #[cfg(not(feature = "report"))]
        let reports: Option<Arc<dyn ReportBuilder>> = None;
        let render = cfg.render.clone();
        let signer = cfg.signer.clone();
        let ocr = cfg.ocr.clone();
        let screenshotter = cfg.screenshotter.clone();
        let headless = cfg.headless;
        let e = Engine {
            inner: Arc::new(Core {
                cfg,
                clock,
                store: Arc::new(Mutex::new(store)),
                dbs: Mutex::new(HashMap::new()),
                keys: Mutex::new(keys),
                events: Mutex::new(events),
                render: Mutex::new(render),
                signer: Mutex::new(signer),
                ocr: Mutex::new(ocr),
                screenshotter: Mutex::new(screenshotter),
                headless: std::sync::atomic::AtomicBool::new(headless),
                dir_lock: Mutex::new(Some(dir_lock)),
                reports: Mutex::new(reports),
                run: Mutex::new(None),
                finishing: std::sync::atomic::AtomicBool::new(false),
                import_cancel: Mutex::new(None),
                tool_log: Default::default(),
                queue_lock: Mutex::new(()),
                queue_driver: std::sync::atomic::AtomicBool::new(false),
                queue_halt: std::sync::atomic::AtomicBool::new(false),
                queue_progress: Mutex::new(None),
                ai_models_cache: Mutex::new(HashMap::new()),
                ai_jobs: Mutex::new(HashMap::new()),
                dork_jobs: Mutex::new(HashMap::new()),
            }),
        };
        if let Ok(s) = e.store().settings_get() {
            crate::services::logs::set_level(s["debug"]["level"].as_str().unwrap_or("info"));
        }
        e.recover_run()?;
        // continue the scan queue left by the previous process (needs a tokio runtime)
        e.queue_kick(e.inner.cfg.queue_start_delay);
        Ok(e)
    }

    /// Upgrades a running headless engine with full interactive UI platform capabilities
    /// during headless-to-UI handoff.
    #[allow(clippy::too_many_arguments)]
    pub fn attach_ui_platform(
        &self,
        keys: Arc<dyn KeyProvider>,
        sink: Option<Arc<dyn EventSink>>,
        render: Option<Arc<dyn foca_search::RenderFetch>>,
        signer: Option<Arc<dyn crate::ReportSigner>>,
        ocr: Option<Arc<dyn crate::OcrProvider>>,
        screenshotter: Option<Arc<dyn crate::WebScreenshotter>>,
    ) {
        *lock(&self.inner.keys) = keys;
        if let Some(s) = sink {
            *lock(&self.inner.events) = s;
        }
        *lock(&self.inner.render) = render;
        *lock(&self.inner.signer) = signer;
        *lock(&self.inner.ocr) = ocr;
        *lock(&self.inner.screenshotter) = screenshotter;
        self.inner
            .headless
            .store(false, std::sync::atomic::Ordering::SeqCst);
        self.queue_kick(self.inner.cfg.queue_start_delay);
    }

    /// Executes a contract command from `docs/API.md`.
    pub async fn invoke(&self, cmd: &str, args: Value) -> CmdResult {
        let a = if args.is_null() { json!({}) } else { args };
        let t0 = std::time::Instant::now();
        let r = self.dispatch(cmd, a).await;
        match &r {
            Err(e) if e.code == "internal" || e.code == "bad_args" => {
                tracing::warn!(target: "foca::cmd", "{cmd}: {} {} ({} мс)", e.code, e.message, t0.elapsed().as_millis())
            }
            Err(e) => tracing::debug!(target: "foca::cmd", "{cmd}: {} {}", e.code, e.message),
            Ok(_) if cmd != "logs_get" && cmd != "scan_status" => {
                tracing::debug!(target: "foca::cmd", "{cmd}: ok ({} мс)", t0.elapsed().as_millis())
            }
            _ => {}
        }
        r
    }

    async fn dispatch(&self, cmd: &str, a: Value) -> CmdResult {
        match cmd {
            "project_list" => self.project_list(),
            "project_snapshot" => {
                let id = self.project_arg(&a)?;
                self.snapshot_json(&id)
            }
            "project_open" => {
                let id = self.project_arg(&a)?;
                let db = self.db(&id)?;
                // a reference case is never restored as the last opened project
                if !lock(&db).is_reference_case()? {
                    self.store().settings_set(&json!({ "last_project": id }))?;
                }
                self.snapshot_json(&id)
            }
            "project_create" => projects::project_create(self, &a),
            "project_update" => self.project_update(&a),
            "project_duplicate" => self.project_duplicate(&a),
            "project_delete" => self.project_delete(&a).await,
            "project_export_encrypted" => bundle::project_export_encrypted(self, &a),
            "project_import_encrypted" => bundle::project_import_encrypted(self, &a),
            "scope_get" => {
                let id = self.project_arg(&a)?;
                let db = self.db(&id)?;
                let s = lock(&db).scope_get()?;
                Ok(serde_json::to_value(s)?)
            }
            "scope_set" => self.scope_set(&a),
            "scope_add_hosts" => self.scope_add_hosts(&a),
            "scan_start" => self.scan_start(&a).await,
            "scan_stop" => {
                let reason = crate::util::arg_str(&a, "reason")
                    .unwrap_or("user")
                    .to_string();
                self.scan_stop(&reason).await
            }
            "scan_pause" => Ok(json!({ "ok": self.pause("user") })),
            "scan_resume" => Ok(json!({ "ok": self.resume() })),
            "scan_status" => Ok(self.scan_status(None)),
            "scan_delete" => self.scan_delete(&a).await,
            "oos_list" => {
                let id = self.project_arg(&a)?;
                self.oos_json(&id)
            }
            "oos_decide" => self.oos_decide(&a),
            "infra_get" => {
                let id = self.project_arg(&a)?;
                let db = self.db(&id)?;
                let db = lock(&db);
                Ok(crate::scan::infra::view(&db))
            }
            "insights_get" => self.insights_get(&a),
            "chain_get" => self.chain_get(&a),
            "attack_paths_get" => self.attack_paths_get(&a),
            "oos_add_to_scope" => self.oos_add_to_scope(&a),
            "finding_set_status" => self.finding_set_status(&a),
            "finding_update" => self.finding_update(&a),
            "finding_photo_add" => self.finding_photo_add(&a),
            "doc_delete" => self.doc_delete(&a, true),
            "doc_restore" => self.doc_delete(&a, false),
            "doc_clean" => hygiene::doc_clean(self, &a).await,
            "hygiene_get" => hygiene::hygiene_get(self, &a).await,
            "secret_reveal" => self.secret_reveal(&a),
            "secret_hibp_check" => self.secret_hibp_check(&a).await,
            "settings_get" => self.public_settings(),
            "settings_set" => self.settings_set(&a),
            "i18n_bundle" => self.i18n_bundle(&a),
            "licenses_get" => self.licenses_get(),
            "key_set" => self.key_set(&a),
            "key_delete" => self.key_delete(&a),
            "key_check" => self.key_check(&a).await,
            "dorks_pending" => self.dorks_pending(&a),
            "dorks_retry" => self.dorks_retry(&a).await,
            "net_check" => self.net_check().await,
            "net_proxy_check" => self.net_proxy_check(&a).await,
            "report_list" => self.report_list(&a),
            "report_build" => self.report_build(&a),
            "report_templates" => self.report_templates(&a),
            "report_delete" => self.report_delete(&a),
            "report_verify" => self.report_verify(&a),
            "finding_playbook" => self.finding_playbook(&a),
            "signatures_status" => self.signatures_status(),
            "signatures_import" => self.signatures_import(&a),
            "signatures_update" => self.signatures_update(&a).await,
            "signatures_rollback" => self.signatures_rollback(),
            "plugins_list" => self.plugins_list(),
            "plugin_install" => self.plugin_install(&a),
            "plugin_toggle" => self.plugin_toggle(&a),
            "plugin_remove" => self.plugin_remove(&a),
            "plugin_run_test" => self.plugin_run_test(&a).await,
            "export_build" => self.export_build(&a),
            "wordlist_preview" => self.wordlist_preview(&a),
            "ai_models_list" => self.ai_models_list(&a).await,
            "ai_preview" => self.ai_preview(&a),
            "ai_summarize" => self.ai_summarize(&a).await,
            "ai_cancel" => self.ai_cancel(&a),
            "ai_summaries_list" => self.ai_summaries_list(&a),
            "ai_summary_use" => self.ai_summary_use(&a),
            "ai_summary_delete" => self.ai_summary_delete(&a),
            "pin_set" => self.pin_set(&a),
            "pin_check" => self.pin_check(&a).await,
            "wipe_all" => self.wipe_all(&a).await,
            "doc_import" => self.doc_import(&a).await,
            "import_offline" => offline::import_offline(self, &a).await,
            "demo_case_import" => demo_case::demo_case_import(self, &a).await,
            "import_cancel" => offline::import_cancel(self),
            "docs_search" => offline::docs_search(self, &a),
            "doc_get" => offline::doc_get(self, &a),
            "rules_get" => offline::rules_get(self, &a),
            "rules_set" => offline::rules_set(self, &a),
            "rules_test" => offline::rules_test(&a),
            "scan_skip_source" => self.scan_skip_source(&a),
            "scan_retry_source" => self.scan_retry_source(&a),
            "scan_control" => self.scan_control(&a),
            "fuzz_estimate" => self.fuzz_estimate(&a),
            "wordlists_list" => self.wordlists_list(),
            "wordlists_download" => self.wordlists_download(&a).await,
            "wordlists_import" => self.wordlists_import(&a),
            "wordlists_delete" => self.wordlists_delete(&a),
            "doc_file" => self.doc_file(&a),
            "logs_get" => self.logs_get(&a),
            "logs_clear" => self.logs_clear(),
            "logs_export" => self.logs_export(&a),
            "crash_list" => self.crash_list(),
            "crash_get" => self.crash_get(&a),
            "request_log_get" => self.request_log_get(&a),
            "request_log_clear" => self.request_log_clear(&a),
            "search_journal" => self.search_journal(),
            "search_fingerprint" => self.search_fingerprint().await,
            "search_fingerprint_page" => self.search_fingerprint_page(),
            "search_captcha_test" => self.search_captcha_test(&a).await,
            "app_info" => self.app_info(),
            "terms_get" => self.terms_get(),
            "terms_accept" => self.terms_accept(&a),
            "tool_file" => toolbox::tool_file(self, &a).await,
            "tool_mail_domain" => toolbox::tool_mail_domain(self, &a).await,
            "tool_host" => toolbox::tool_host(self, &a).await,
            "tool_secret" => toolbox::tool_secret(self, &a).await,
            "tool_log" => toolbox::tool_log(self, &a),
            "tool_log_clear" => toolbox::tool_log_clear(self),
            "queue_add" => self.queue_add(&a),
            "queue_list" => self.queue_list(),
            "queue_pause" => self.queue_pause(),
            "queue_resume" => self.queue_resume(),
            "queue_remove" => self.queue_remove(&a).await,
            "queue_clear" => self.queue_clear(&a).await,
            "alert_rules_get" => self.alert_rules_get(&a),
            "alert_rules_set" => self.alert_rules_set(&a),
            "alert_test" => self.alert_test(&a).await,
            "risk_trend_get" => self.risk_trend_get(&a),
            _ => Err(CmdError::new("unknown_command", cmd)),
        }
    }
}
