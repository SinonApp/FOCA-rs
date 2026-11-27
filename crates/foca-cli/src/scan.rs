//! `foca scan --project id --profile passive [--wait]`: a scan through foca-engine (the same
//! launch rules, stages and events as the app). Crawl limits, the Common Crawl depth and a
//! stdin control channel (`--control`: pause, resume, stop, status, skip) let live runs be driven
//! without code.

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
    /// Crawl: links followed from the start pages (`crawl.max_depth`)
    #[arg(long)]
    pub crawl_depth: Option<u64>,
    /// Crawl: pages per scan (`crawl.max_pages`)
    #[arg(long)]
    pub crawl_pages: Option<u64>,
    /// Crawl: wall time in minutes (`crawl.max_minutes`)
    #[arg(long)]
    pub crawl_minutes: Option<u64>,
    /// Crawl: fetch files on public external storage linked from the site (`crawl.storage`)
    #[arg(long)]
    pub crawl_storage: Option<bool>,
    /// Crawl: follow links inside downloaded documents (`crawl.doc_links`)
    #[arg(long)]
    pub crawl_doc_links: Option<bool>,
    /// Images for EXIF from every source (`crawl.images`)
    #[arg(long)]
    pub crawl_images: Option<bool>,
    /// Images per scan, apart from the document limit (`crawl.max_images`)
    #[arg(long)]
    pub max_images: Option<u64>,
    /// Image traffic per scan in MB (`crawl.max_image_mb`)
    #[arg(long)]
    pub max_image_mb: Option<u64>,
    /// Common Crawl depth: latest | years | all
    #[arg(long)]
    pub cc_depth: Option<String>,
    /// Years of Common Crawl snapshots with `--cc-depth years`
    #[arg(long)]
    pub cc_years: Option<u64>,
    /// Read control commands from stdin while waiting: pause, resume, stop, status, skip <source>
    #[arg(long)]
    pub control: bool,
}

/// `scan_start` arguments of the options.
fn start_args(o: &ScanOpts) -> Value {
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
    let mut crawl = serde_json::Map::new();
    for (k, v) in [
        ("max_depth", o.crawl_depth),
        ("max_pages", o.crawl_pages),
        ("max_minutes", o.crawl_minutes),
        ("max_images", o.max_images),
        ("max_image_mb", o.max_image_mb),
    ] {
        if let Some(v) = v {
            crawl.insert(k.into(), json!(v));
        }
    }
    for (k, v) in [
        ("storage", o.crawl_storage),
        ("doc_links", o.crawl_doc_links),
        ("images", o.crawl_images),
    ] {
        if let Some(v) = v {
            crawl.insert(k.into(), json!(v));
        }
    }
    if !crawl.is_empty() {
        args["crawl"] = Value::Object(crawl);
    }
    if let Some(d) = &o.cc_depth {
        args["cc_depth"] = json!(d);
    }
    if let Some(y) = o.cc_years {
        args["cc_years"] = json!(y);
    }
    args
}

/// Engine command for one control line (`None` for an unknown one).
fn control_cmd(line: &str) -> Option<(&'static str, Value)> {
    let mut it = line.split_whitespace();
    let cmd = it.next()?.to_ascii_lowercase();
    let arg = it.next();
    Some(match cmd.as_str() {
        "pause" | "p" => ("scan_pause", json!({ "reason": arg.unwrap_or("user") })),
        "resume" | "r" => ("scan_resume", json!({})),
        "stop" | "s" => ("scan_stop", json!({ "reason": "user" })),
        "status" => ("scan_status", json!({})),
        "skip" => ("scan_skip_source", json!({ "id": arg? })),
        _ => return None,
    })
}

/// Runs control commands read from stdin until it closes.
async fn control_loop(engine: Engine) {
    use tokio::io::{AsyncBufReadExt, BufReader};
    let mut lines = BufReader::new(tokio::io::stdin()).lines();
    while let Ok(Some(l)) = lines.next_line().await {
        let Some((cmd, args)) = control_cmd(&l) else {
            eprintln!("control: pause [reason] | resume | stop | status | skip <source>");
            continue;
        };
        match engine.invoke(cmd, args).await {
            Ok(r) => eprintln!("control {cmd}: {r}"),
            Err(e) => eprintln!("control {cmd}: {}: {}", e.code, e.message),
        }
    }
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
        let args = start_args(&o);
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
        let control = o
            .control
            .then(|| tokio::spawn(control_loop(engine.clone())));
        engine
            .wait_idle(std::time::Duration::from_secs(24 * 3600))
            .await;
        ctrl_c.abort();
        if let Some(c) = control {
            c.abort();
        }
        let s = engine
            .invoke("project_snapshot", json!({ "id": o.project }))
            .await
            .map_err(|e| anyhow!("{e}"))?;
        let last = s["scans"].as_array().and_then(|a| a.last()).cloned();
        Ok(last.is_some_and(|l| l["status"] == "done"))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[derive(Parser)]
    struct T {
        #[command(flatten)]
        o: ScanOpts,
    }

    fn opts(args: &[&str]) -> ScanOpts {
        let mut v = vec!["foca", "--project", "p1"];
        v.extend_from_slice(args);
        T::parse_from(v).o
    }

    #[test]
    fn crawl_and_common_crawl_flags_become_scan_options() {
        let a = start_args(&opts(&[
            "--profile",
            "std",
            "--crawl-depth",
            "3",
            "--crawl-pages",
            "200",
            "--crawl-minutes",
            "10",
            "--crawl-storage",
            "false",
            "--crawl-doc-links",
            "true",
            "--crawl-images",
            "false",
            "--max-images",
            "40",
            "--max-image-mb",
            "25",
            "--cc-depth",
            "years",
            "--cc-years",
            "5",
        ]));
        assert_eq!(
            a["crawl"],
            json!({ "max_depth": 3, "max_pages": 200, "max_minutes": 10, "storage": false,
                "doc_links": true, "images": false, "max_images": 40, "max_image_mb": 25 })
        );
        assert_eq!(
            (a["cc_depth"].as_str(), a["cc_years"].as_u64()),
            (Some("years"), Some(5))
        );
        // without the flags the settings decide
        let a = start_args(&opts(&[]));
        assert!(
            a.get("crawl").is_none() && a.get("cc_depth").is_none(),
            "{a}"
        );
    }

    #[test]
    fn control_lines_map_to_engine_commands() {
        assert_eq!(control_cmd("pause").unwrap().0, "scan_pause");
        assert_eq!(control_cmd("p battery").unwrap().1["reason"], "battery");
        assert_eq!(control_cmd(" resume ").unwrap().0, "scan_resume");
        assert_eq!(control_cmd("stop").unwrap().0, "scan_stop");
        assert_eq!(control_cmd("skip cc").unwrap().1["id"], "cc");
        assert!(control_cmd("skip").is_none());
        assert!(control_cmd("hello").is_none());
        assert!(control_cmd("").is_none());
    }
}
