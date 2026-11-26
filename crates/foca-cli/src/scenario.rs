//! Declarative audit scenarios (`foca run <scenario.toml> [--json]`).
//!
//! Runs reproducible offline or passive/standard/full audits through the real `foca-engine`,
//! optionally builds reports, and enforces CI/CD threshold gates (`fail_on_severity`, `max_risk`).

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use clap::Args;
use foca_engine::{Engine, EngineConfig, MemoryEvents, MemoryKeys};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

#[derive(Args, Debug, Clone)]
pub struct RunOpts {
    /// Path to scenario TOML file (e.g. scenarios/kszi-audit.toml)
    pub scenario: PathBuf,
    /// Override project store directory (defaults to scenario.store or temporary dir)
    #[arg(long, env = "FOCA_HOME")]
    pub store: Option<PathBuf>,
    /// Print machine-readable JSON summary
    #[arg(long)]
    pub json: bool,
    /// Validate scenario TOML without executing scans/imports
    #[arg(long)]
    pub dry_run: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Scenario {
    pub name: String,
    pub client: String,
    /// `"offline"` (import local files/dirs only, 0 network requests) or `"scan"` (runs engine scan).
    #[serde(default = "default_mode")]
    pub mode: String,
    pub store: Option<PathBuf>,
    pub targets: Vec<String>,
    pub excludes: Vec<String>,
    /// Local files or directories to import offline before analysis/reporting.
    pub inputs: Vec<PathBuf>,
    /// Use built-in synthetic demo case (12 files, 0 network requests) when true.
    pub demo_case: bool,
    /// Scan profile when `mode = "scan"`: `passive` | `std` | `full`.
    #[serde(default = "default_profile")]
    pub profile: String,
    pub sources: Vec<String>,
    pub exts: Vec<String>,
    pub limit: Option<usize>,
    pub rules: Option<ScenarioRules>,
    pub report: Option<ScenarioReport>,
    pub gate: Option<ScenarioGate>,
}

fn default_mode() -> String {
    "offline".into()
}

fn default_profile() -> String {
    "passive".into()
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ScenarioRules {
    pub presets: Vec<String>,
    pub rules: Vec<Value>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ScenarioReport {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_fmt")]
    pub format: String,
    #[serde(default = "default_tpl")]
    pub template: String,
    #[serde(default = "default_lang")]
    pub lang: String,
    pub custody: bool,
    pub out: Option<PathBuf>,
}

fn default_true() -> bool {
    true
}
fn default_fmt() -> String {
    "md".into()
}
fn default_tpl() -> String {
    "full".into()
}
fn default_lang() -> String {
    "en".into()
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ScenarioGate {
    /// Fail (exit non-zero) if any live finding has severity >= this threshold:
    /// `low` | `warn`/`medium` | `high` | `crit`/`critical`.
    pub fail_on_severity: Option<String>,
    /// Fail if project risk score strictly exceeds `max_risk` (0..=100).
    pub max_risk: Option<u8>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScenarioOutcome {
    pub scenario: String,
    pub project_id: String,
    pub mode: String,
    pub docs: usize,
    pub findings: usize,
    pub max_severity: String,
    pub risk: Option<u8>,
    pub report_path: Option<String>,
    pub gate_passed: bool,
    pub gate_reasons: Vec<String>,
}

pub fn parse_scenario(raw: &str) -> Result<Scenario> {
    let sc: Scenario = toml::from_str(raw).context("разбор scenario.toml")?;
    if sc.name.trim().is_empty() {
        bail!("в сценарии отсутствует обязательное поле `name`");
    }
    if !matches!(sc.mode.as_str(), "offline" | "scan") {
        bail!(
            "неизвестный режим сценария `{}` (ожидается offline или scan)",
            sc.mode
        );
    }
    if !matches!(sc.profile.as_str(), "passive" | "std" | "full") {
        bail!(
            "неизвестный профиль `{}` (ожидается passive, std или full)",
            sc.profile
        );
    }
    if let Some(g) = &sc.gate {
        if let Some(sev) = &g.fail_on_severity {
            if sev_rank(sev).is_none() {
                bail!("неизвестный порог fail_on_severity: `{sev}`");
            }
        }
    }
    Ok(sc)
}

fn sev_rank(s: &str) -> Option<u8> {
    match s.trim().to_ascii_lowercase().as_str() {
        "info" => Some(0),
        "low" => Some(1),
        "warn" | "medium" => Some(2),
        "high" => Some(3),
        "crit" | "critical" => Some(4),
        _ => None,
    }
}

fn rank_label(r: u8) -> &'static str {
    match r {
        4 => "crit",
        3 => "high",
        2 => "warn",
        1 => "low",
        _ => "info",
    }
}

fn resolve_path(base_dir: &Path, p: &Path) -> PathBuf {
    if p.is_absolute() {
        p.to_path_buf()
    } else {
        base_dir.join(p)
    }
}

pub fn execute_scenario(
    scenario_path: &Path,
    store_override: Option<&Path>,
) -> Result<ScenarioOutcome> {
    let raw = std::fs::read_to_string(scenario_path)
        .with_context(|| format!("чтение {}", scenario_path.display()))?;
    let sc = parse_scenario(&raw)?;
    let base_dir = scenario_path.parent().unwrap_or_else(|| Path::new("."));

    let mut temp_hold = None;
    let store_dir = if let Some(s) = store_override {
        s.to_path_buf()
    } else if let Some(s) = &sc.store {
        resolve_path(base_dir, s)
    } else {
        let t = tempfile::tempdir().context("создание временного хранилища")?;
        let p = t.path().to_path_buf();
        temp_hold = Some(t);
        p
    };

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("tokio runtime")?;

    let outcome = rt.block_on(async move {
        let mut cfg = EngineConfig::new(&store_dir);
        cfg.headless = true;
        let eng = Engine::open(
            cfg,
            Arc::new(MemoryKeys::new()),
            Arc::new(MemoryEvents::new()),
        )
        .map_err(|e| anyhow::anyhow!("Engine::open: {}", e.message))?;

        let project_id = if sc.demo_case {
            let demo = eng
                .invoke("demo_case_import", json!({}))
                .await
                .map_err(|e| anyhow::anyhow!("demo_case_import: {}", e.message))?;
            demo["project"]
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("нет project id в ответе demo_case_import"))?
                .to_string()
        } else {
            let targets: Vec<Value> = sc.targets.iter().map(|t| json!(t)).collect();
            let p = eng
                .invoke(
                    "project_create",
                    json!({
                        "name": sc.name,
                        "client": sc.client,
                        "targets": targets,
                        "excludes": sc.excludes,
                    }),
                )
                .await
                .map_err(|e| anyhow::anyhow!("project_create: {}", e.message))?;
            p["id"]
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("нет project id"))?
                .to_string()
        };

        if let Some(rules) = &sc.rules {
            let _ = eng
                .invoke(
                    "rules_set",
                    json!({
                        "project": project_id,
                        "config": {
                            "presets": rules.presets,
                            "rules": rules.rules,
                        }
                    }),
                )
                .await
                .map_err(|e| anyhow::anyhow!("rules_set: {}", e.message))?;
        }

        if !sc.inputs.is_empty() {
            let paths: Vec<String> = sc
                .inputs
                .iter()
                .map(|p| resolve_path(base_dir, p).to_string_lossy().to_string())
                .collect();
            eng.invoke(
                "import_offline",
                json!({ "project": project_id, "paths": paths }),
            )
            .await
            .map_err(|e| anyhow::anyhow!("import_offline: {}", e.message))?;
        }

        if sc.mode == "scan" {
            let mut args = json!({
                "project": project_id,
                "profile": sc.profile,
                "headless": true,
            });
            if !sc.sources.is_empty() {
                args["sources"] = json!(sc.sources);
            }
            if !sc.exts.is_empty() {
                args["exts"] = json!(sc.exts);
            }
            if let Some(lim) = sc.limit {
                args["limit"] = json!(lim);
            }
            eng.invoke("scan_start", args)
                .await
                .map_err(|e| anyhow::anyhow!("scan_start: {}", e.message))?;
            if !eng.wait_idle(Duration::from_secs(600)).await {
                bail!("таймаут ожидания завершения скана сценария");
            }
        }

        let snap = eng
            .invoke("project_snapshot", json!({ "id": project_id }))
            .await
            .map_err(|e| anyhow::anyhow!("project_snapshot: {}", e.message))?;

        let mut report_path = None;
        if let Some(rep) = &sc.report {
            if rep.enabled {
                let lang_upper = rep.lang.trim().to_ascii_uppercase();
                let lang_code = match lang_upper.as_str() {
                    "UA" | "UK" => "UA",
                    "EN" => "EN",
                    _ => "RU",
                };
                let built = eng
                    .invoke(
                        "report_build",
                        json!({
                            "project": project_id,
                            "template": rep.template,
                            "custody": rep.custody,
                            "opts": {
                                "fmt": rep.format,
                                "lang": lang_code,
                                "min_sev": "all",
                                "confirmed": false,
                            }
                        }),
                    )
                    .await
                    .map_err(|e| anyhow::anyhow!("report_build: {}", e.message))?;
                let src_path = built["path"].as_str().unwrap_or("").to_string();
                if let Some(out) = &rep.out {
                    let dst = resolve_path(base_dir, out);
                    if let Some(parent) = dst.parent() {
                        std::fs::create_dir_all(parent)?;
                    }
                    std::fs::copy(&src_path, &dst).with_context(|| {
                        format!("копирование отчёта {} -> {}", src_path, dst.display())
                    })?;
                    copy_sidecars(Path::new(&src_path), &dst)?;
                    report_path = Some(dst.to_string_lossy().to_string());
                } else {
                    report_path = Some(src_path);
                }
            }
        }

        let findings = snap["findings"].as_array().cloned().unwrap_or_default();
        let live: Vec<&Value> = findings
            .iter()
            .filter(|f| !matches!(f["status"].as_str(), Some("false" | "fixed")))
            .collect();
        let max_rank = live
            .iter()
            .filter_map(|f| f["sev"].as_str().and_then(sev_rank))
            .max()
            .unwrap_or(0);
        // The snapshot carries no risk field: score its findings with the same formula as the
        // project summary. Offline scenarios have documents but no scans, so imported
        // documents count as data too.
        let risk = {
            let parsed: Vec<foca_core::api::Finding> =
                serde_json::from_value(Value::Array(findings.clone())).unwrap_or_default();
            let has_data = !parsed.is_empty()
                || snap["docs"].as_array().is_some_and(|d| !d.is_empty())
                || snap["scans"].as_array().is_some_and(|s| !s.is_empty());
            foca_analysis::findings::risk(&parsed, has_data).score
        };

        let mut gate_reasons = Vec::new();
        if let Some(g) = &sc.gate {
            if let Some(thresh_str) = &g.fail_on_severity {
                if let Some(thresh) = sev_rank(thresh_str) {
                    let count = live
                        .iter()
                        .filter(|f| {
                            f["sev"]
                                .as_str()
                                .and_then(sev_rank)
                                .is_some_and(|r| r >= thresh)
                        })
                        .count();
                    if count > 0 {
                        gate_reasons.push(format!(
                            "найдено {count} находок уровня >= {thresh_str} (макс. {})",
                            rank_label(max_rank)
                        ));
                    }
                }
            }
            if let (Some(max_r), Some(cur_r)) = (g.max_risk, risk) {
                if cur_r > max_r {
                    gate_reasons.push(format!(
                        "риск-скор {cur_r} превышает порог max_risk={max_r}"
                    ));
                }
            }
        }

        Ok(ScenarioOutcome {
            scenario: sc.name,
            project_id,
            mode: sc.mode,
            docs: snap["docs"].as_array().map_or(0, Vec::len),
            findings: live.len(),
            max_severity: if live.is_empty() {
                "none".into()
            } else {
                rank_label(max_rank).into()
            },
            risk,
            report_path,
            gate_passed: gate_reasons.is_empty(),
            gate_reasons,
        })
    })?;
    // Without an explicit store the report lives inside the temporary store: keep that folder,
    // otherwise the printed report path would already be gone.
    if let (Some(t), Some(rp)) = (temp_hold, &outcome.report_path) {
        if Path::new(rp).starts_with(t.path()) {
            let _ = t.keep();
        }
    }
    Ok(outcome)
}

/// Copies the `.sha256` / `.sig.json` sidecars of a built report next to its copy. The checksum
/// line names the file, so it is rewritten for the new name; the signed manifest is copied as is.
fn copy_sidecars(src: &Path, dst: &Path) -> Result<()> {
    let side = |p: &Path, suffix: &str| {
        let mut os = p.as_os_str().to_os_string();
        os.push(".");
        os.push(suffix);
        PathBuf::from(os)
    };
    let sha = side(src, "sha256");
    if let Ok(text) = std::fs::read_to_string(&sha) {
        let name = dst
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();
        let lines: Vec<String> = text
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| {
                let hex = l.split_whitespace().next().unwrap_or("");
                format!("{hex}  {name}")
            })
            .collect();
        std::fs::write(side(dst, "sha256"), lines.join("\n") + "\n")
            .with_context(|| format!("запись {}", side(dst, "sha256").display()))?;
    }
    let sig = side(src, "sig.json");
    if sig.exists() {
        std::fs::copy(&sig, side(dst, "sig.json"))
            .with_context(|| format!("копирование {}", sig.display()))?;
    }
    Ok(())
}

pub fn run(o: RunOpts) -> Result<bool> {
    if o.dry_run {
        let raw = std::fs::read_to_string(&o.scenario)
            .with_context(|| format!("чтение {}", o.scenario.display()))?;
        let sc = parse_scenario(&raw)?;
        if o.json {
            println!("{}", serde_json::to_string_pretty(&sc)?);
        } else {
            println!(
                "Сценарий валиден: «{}» (режим: {}, целей: {}, входов: {})",
                sc.name,
                sc.mode,
                sc.targets.len(),
                sc.inputs.len()
            );
        }
        return Ok(true);
    }
    let outcome = execute_scenario(&o.scenario, o.store.as_deref())?;
    if o.json {
        println!("{}", serde_json::to_string_pretty(&outcome)?);
    } else {
        println!("Сценарий: {}", outcome.scenario);
        println!(
            "Проект: {} · документов: {} · находок: {} (макс: {}) · риск: {}",
            outcome.project_id,
            outcome.docs,
            outcome.findings,
            outcome.max_severity,
            outcome
                .risk
                .map(|r| r.to_string())
                .unwrap_or_else(|| "-".into())
        );
        if let Some(p) = &outcome.report_path {
            println!("Отчёт: {p}");
        }
        if !outcome.gate_passed {
            for r in &outcome.gate_reasons {
                eprintln!("GATE FAILED: {r}");
            }
        }
    }
    Ok(outcome.gate_passed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_bundled_scenario_templates() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("scenarios");
        for name in [
            "kszi-audit.toml",
            "preflight-folder.toml",
            "passive-osint.toml",
        ] {
            let raw = std::fs::read_to_string(root.join(name))
                .unwrap_or_else(|e| panic!("missing scenario template {name}: {e}"));
            let sc = parse_scenario(&raw).unwrap_or_else(|e| panic!("invalid {name}: {e}"));
            assert!(!sc.name.is_empty());
        }
    }

    #[test]
    fn executes_offline_scenario_generates_report_and_evaluates_gate() {
        let dir = tempfile::tempdir().unwrap();
        let report_out = dir.path().join("audit.md");
        let sc_path = dir.path().join("demo.toml");
        std::fs::write(
            &sc_path,
            format!(
                r#"
name = "CI Demo Gate"
client = "Test Client"
mode = "offline"
demo_case = true

[report]
enabled = true
format = "md"
template = "compliance"
lang = "en"
custody = true
out = "{}"

[gate]
fail_on_severity = "high"
"#,
                report_out.to_string_lossy().replace('\\', "\\\\")
            ),
        )
        .unwrap();

        let store_dir = dir.path().join("store");
        let res = execute_scenario(&sc_path, Some(&store_dir)).unwrap();
        assert!(res.docs > 0);
        assert!(res.findings > 0);
        assert!(report_out.exists(), "report file must be written");
        // Demo case contains critical/high findings, so fail_on_severity = "high" must trip the gate
        assert!(!res.gate_passed);
        assert!(!res.gate_reasons.is_empty());
        // Sidecars follow the copied report and name the new file.
        let sha = std::fs::read_to_string(dir.path().join("audit.md.sha256")).unwrap();
        assert!(sha.trim_end().ends_with("  audit.md"), "{sha}");
        assert!(dir.path().join("audit.md.sig.json").exists());
    }

    #[test]
    fn max_risk_gate_reads_project_risk() {
        let dir = tempfile::tempdir().unwrap();
        let sc_path = dir.path().join("risk.toml");
        std::fs::write(
            &sc_path,
            "name = \"Risk gate\"\nmode = \"offline\"\ndemo_case = true\n\n[gate]\nmax_risk = 1\n",
        )
        .unwrap();
        let res = execute_scenario(&sc_path, Some(&dir.path().join("store"))).unwrap();
        assert!(res.risk.is_some_and(|r| r > 1), "{:?}", res.risk);
        assert!(!res.gate_passed);
        assert!(res.gate_reasons.iter().any(|r| r.contains("max_risk")));
    }

    #[test]
    fn folder_inputs_are_imported_and_temp_report_survives() {
        let dir = tempfile::tempdir().unwrap();
        let docs = dir.path().join("docs-to-publish");
        std::fs::create_dir_all(docs.join("nested")).unwrap();
        std::fs::write(docs.join("a.txt"), "Наказ № 1").unwrap();
        std::fs::write(docs.join("nested/b.txt"), "Наказ № 2").unwrap();
        let sc_path = dir.path().join("folder.toml");
        std::fs::write(
            &sc_path,
            "name = \"Folder\"\nmode = \"offline\"\ninputs = [\"./docs-to-publish\"]\n\n\
             [report]\nenabled = true\nformat = \"md\"\ntemplate = \"executive\"\nlang = \"en\"\n",
        )
        .unwrap();
        let res = execute_scenario(&sc_path, None).unwrap();
        assert_eq!(res.docs, 2);
        let rp = PathBuf::from(res.report_path.expect("report path"));
        assert!(
            rp.exists(),
            "report in the temporary store must outlive the run"
        );
        // Clean up the kept temporary store.
        let mut root = rp.as_path();
        while let Some(p) = root.parent() {
            if p == std::env::temp_dir() {
                break;
            }
            root = p;
        }
        if root.starts_with(std::env::temp_dir()) && root != std::env::temp_dir() {
            let _ = std::fs::remove_dir_all(root);
        }
    }
}
