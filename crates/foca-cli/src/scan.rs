//! `foca scan --project id --profile passive [--wait]`: a scan through foca-engine (the same
//! launch rules, stages and events as the app).

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{anyhow, Result};
use clap::Args;
use foca_engine::{Engine, EngineConfig, FnEvents, MemoryKeys};
use serde_json::{json, Value};

#[derive(Args, Debug)]
pub struct ScanOpts {
    /// Store directory (projects.db and <id>.foca)
    #[arg(long, env = "FOCA_HOME", default_value = "foca-data")]
    pub store: PathBuf,
    #[arg(long)]
    pub project: String,
    /// passive | std | full | custom
    #[arg(long, default_value = "passive")]
    pub profile: String,
    /// Sources (default: everything available to the profile)
    #[arg(long, value_delimiter = ',')]
    pub sources: Vec<String>,
    /// Modules of the custom profile
    #[arg(long, value_delimiter = ',')]
    pub modules: Vec<String>,
    /// Targets (default: all scope targets)
    #[arg(long = "target")]
    pub targets: Vec<String>,
    /// Maximum documents queued per scan
    #[arg(long, default_value_t = 50)]
    pub limit: usize,
    /// Resume a stopped scan
    #[arg(long)]
    pub resume_from: Option<String>,
    /// Wait for completion and print events
    #[arg(long)]
    pub wait: bool,
    /// Events as JSON lines
    #[arg(long)]
    pub json: bool,
    /// Source keys: brave=…,searx=… (the app keeps them in the Android Keystore)
    #[arg(long, value_delimiter = ',')]
    pub key: Vec<String>,
}

fn line(e: &Value) -> String {
    let t = e["type"].as_str().unwrap_or("");
    match t {
        "started" => format!(
            "▶ скан {} · {} · цели: {} · {}",
            e["scan_id"].as_str().unwrap_or(""),
            e["profile"].as_str().unwrap_or(""),
            e["targets"],
            e["egress"].as_str().unwrap_or("")
        ),
        "stage" => format!(
            "■ этап {}: {}",
            e["index"],
            e["label"].as_str().unwrap_or("")
        ),
        "progress" => format!(
            "  {}% ({})",
            e["progress"],
            e["stage"].as_str().unwrap_or("")
        ),
        "source" => format!(
            "  источник {}: {}{}",
            e["name"].as_str().unwrap_or(""),
            e["status"].as_str().unwrap_or(""),
            e.get("n")
                .map(|n| format!(", найдено {n}"))
                .unwrap_or_default()
        ),
        "finding" => format!(
            "  ! [{}] {} - {}",
            e["finding"]["sev"].as_str().unwrap_or(""),
            e["finding"]["title"].as_str().unwrap_or(""),
            e["finding"]["host"].as_str().unwrap_or("")
        ),
        "db" => format!("  данные обновлены: {}", e["kind"].as_str().unwrap_or("")),
        "done" => {
            let s = &e["scan"];
            format!(
                "✔ готово: документов {}, людей {}, хостов {}, находок {} (новых {}), {} мин",
                s["docs"], s["people"], s["hosts"], s["findings"], s["new_findings"], s["minutes"]
            )
        }
        "stopped" => format!("✖ остановлен: {}", e["reason"].as_str().unwrap_or("")),
        _ => e.to_string(),
    }
}

pub fn run(o: ScanOpts) -> Result<bool> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    rt.block_on(async move {
        let keys = Arc::new(MemoryKeys::new());
        for kv in &o.key {
            if let Some((k, v)) = kv.split_once('=') {
                use foca_engine::KeyProvider;
                keys.set(k.trim(), v.trim()).map_err(|e| anyhow!(e))?;
            }
        }
        let json_out = o.json;
        let wait = o.wait;
        let sink = Arc::new(FnEvents(move |e: &Value| {
            if !wait {
                return;
            }
            let p = e["type"] == "progress";
            if json_out {
                println!("{e}");
            } else if !p || e["progress"].as_u64().is_some_and(|x| x % 10 == 0) {
                println!("{}", line(e));
            }
        }));
        let mut cfg = EngineConfig::new(&o.store);
        cfg.max_docs = o.limit.max(1);
        let engine = Engine::open(cfg, keys, sink).map_err(|e| anyhow!("{e}"))?;
        let mut args = json!({ "project": o.project, "profile": o.profile, "limit": o.limit });
        if !o.sources.is_empty() {
            args["sources"] = json!(o.sources);
        }
        if !o.modules.is_empty() {
            args["modules"] = json!(o.modules);
        }
        if !o.targets.is_empty() {
            args["targets"] = json!(o.targets);
        }
        if let Some(r) = &o.resume_from {
            args["resume_from"] = json!(r);
        }
        let r = engine
            .invoke("scan_start", args)
            .await
            .map_err(|e| anyhow!("{}: {}", e.code, e.message))?;
        if !wait {
            println!("{r}");
            // Without --wait the scan cannot be left running after the CLI exits, so wait silently.
        }
        let eng = engine.clone();
        let ctrl_c = tokio::spawn(async move {
            if tokio::signal::ctrl_c().await.is_ok() {
                let _ = eng.invoke("scan_stop", json!({ "reason": "user" })).await;
            }
        });
        engine
            .wait_idle(std::time::Duration::from_secs(24 * 3600))
            .await;
        ctrl_c.abort();
        let s = engine
            .invoke("project_snapshot", json!({ "id": o.project }))
            .await
            .map_err(|e| anyhow!("{e}"))?;
        let last = s["scans"].as_array().and_then(|a| a.last()).cloned();
        Ok(last.is_some_and(|l| l["status"] == "done"))
    })
}
