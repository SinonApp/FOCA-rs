//! `foca fuzz`: discovers forgotten documents, backups and service files on a client's site
//! (foca-fuzz). Requests go only to scope hosts (`--targets`, defaulting to the `--url` host)
//! and never to exclusions (`--exclude`); `--dry-run` estimates request count and time
//! without network access.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use foca_core::Scope;
use foca_fuzz::config::Rule;
use foca_fuzz::plan::fmt_duration;
use foca_fuzz::wordlists::{self, Wordlist};
use foca_fuzz::{
    Cms, ContentSpec, Filters, FuzzConfig, FuzzEvent, FuzzTask, Fuzzer, Module, Template, VhostSpec,
};
use foca_net::{MemorySink, NetClient, NetConfig, RequestSink};
use url::Url;

/// Options of `foca fuzz`.
#[derive(clap::Args, Debug, Clone)]
pub struct FuzzOpts {
    /// Root of the client's site (https://contoso.ua/)
    #[arg(long)]
    pub url: Option<String>,
    /// Modules: docs, backups, exposed, dirlisting, vhost, cms, content
    #[arg(
        long,
        value_delimiter = ',',
        default_value = "docs,backups,exposed,dirlisting"
    )]
    pub modules: Vec<String>,
    /// Already known URLs (crawler/archives) used for name mutations, backups and listings
    #[arg(long)]
    pub known: Vec<String>,
    /// Scope targets (comma-separated); defaults to the host from --url
    #[arg(long, value_delimiter = ',')]
    pub targets: Vec<String>,
    /// Scope exclusions (hosts/IPs/networks, comma-separated)
    #[arg(long, value_delimiter = ',')]
    pub exclude: Vec<String>,
    /// Excluded paths (/private, /admin/); never requested
    #[arg(long)]
    pub exclude_path: Vec<String>,
    /// content: URL template with FUZZ (default <url>FUZZ)
    #[arg(long)]
    pub template: Option<String>,
    /// content: Host header template with FUZZ (vhost fuzzing with a custom wordlist)
    #[arg(long)]
    pub host_template: Option<String>,
    /// content: wordlist, either a built-in/downloaded id or a file path (default common)
    #[arg(long)]
    pub wordlist: Option<String>,
    /// content: comma-separated extensions (pdf,docx)
    #[arg(long, value_delimiter = ',')]
    pub ext: Vec<String>,
    /// vhost: client domains (default: domains from --targets)
    #[arg(long)]
    pub vhost_domain: Vec<String>,
    /// vhost: wordlist (id or file; default dns-top5000)
    #[arg(long)]
    pub vhost_wordlist: Option<String>,
    /// vhost: number of wordlist entries to use
    #[arg(long, default_value_t = 500)]
    pub vhost_words: usize,
    /// cms: wordpress | joomla | drupal | sharepoint
    #[arg(long)]
    pub cms: Option<String>,
    /// Directory with downloaded large wordlists
    #[arg(long)]
    pub wordlist_dir: Option<PathBuf>,
    /// Requests per second
    #[arg(long, default_value_t = 5.0)]
    pub rate: f64,
    /// Concurrent requests
    #[arg(long, default_value_t = 4)]
    pub threads: usize,
    /// Random delay before each request, ms (0..N)
    #[arg(long, default_value_t = 150)]
    pub jitter_ms: u64,
    /// Request budget (calibration included)
    #[arg(long, default_value_t = 3000)]
    pub max_requests: u64,
    /// Time limit, s
    #[arg(long, default_value_t = 1200)]
    pub max_time: u64,
    /// Recursion depth into discovered directories (content)
    #[arg(long, default_value_t = 1)]
    pub depth: u8,
    /// Status code matcher (ffuf -mc)
    #[arg(long)]
    pub mc: Option<String>,
    /// Status code filter (ffuf -fc)
    #[arg(long)]
    pub fc: Option<String>,
    /// Size filter (ffuf -fs)
    #[arg(long)]
    pub fs: Option<String>,
    /// Word count filter (ffuf -fw)
    #[arg(long)]
    pub fw: Option<String>,
    /// Line count filter (ffuf -fl)
    #[arg(long)]
    pub fl: Option<String>,
    /// Body regex filter (ffuf -fr)
    #[arg(long)]
    pub fr: Option<String>,
    /// Body regex matcher (ffuf -mr)
    #[arg(long)]
    pub mr: Option<String>,
    /// Disable soft-404 auto-calibration (debugging only)
    #[arg(long)]
    pub no_calibration: bool,
    /// Follow redirects (each hop is checked against the scope)
    #[arg(long)]
    pub follow_redirects: bool,
    /// Only estimate request count and time, without network access
    #[arg(long)]
    pub dry_run: bool,
    /// List built-in and registry wordlists
    #[arg(long)]
    pub list_wordlists: bool,
    /// Download a registry wordlist into --wordlist-dir (the request goes to GitHub, not the target)
    #[arg(long)]
    pub download_wordlist: Option<String>,
    /// JSON output
    #[arg(long)]
    pub json: bool,
    #[command(flatten)]
    pub net: crate::net::NetOpts,
}

fn load_wordlist(spec: &str, dir: Option<&std::path::Path>) -> Result<Wordlist> {
    let p = std::path::Path::new(spec);
    if p.is_file() {
        return Ok(wordlists::import_file(p, 64 * 1024 * 1024)?);
    }
    Ok(wordlists::resolve(spec, dir)?)
}

fn build(o: &FuzzOpts) -> Result<(FuzzTask, FuzzConfig, Scope)> {
    let url = o.url.as_deref().context("нужен --url")?;
    let mut base = Url::parse(url).with_context(|| format!("URL: {url}"))?;
    if !matches!(base.scheme(), "http" | "https") {
        bail!("нужен http(s) URL");
    }
    if !base.path().ends_with('/') {
        let p = format!("{}/", base.path());
        base.set_path(&p);
    }
    let host = base.host_str().context("в URL нет хоста")?.to_string();
    let targets = if o.targets.is_empty() {
        host.clone()
    } else {
        o.targets.join("\n")
    };
    let (mut scope, errs) = Scope::from_lines(&targets, &o.exclude.join("\n"));
    if let Some(e) = errs.first() {
        bail!("скоуп, строка {}: {}, {}", e.line, e.input, e.error);
    }
    scope.active_phase = true;
    if !scope.allows_host(&host) {
        bail!("{host} не входит в скоуп (--targets) или исключён");
    }
    let mut modules = Vec::new();
    for m in &o.modules {
        modules.push(Module::parse(m).with_context(|| format!("неизвестный модуль: {m}"))?);
    }
    let dir = o.wordlist_dir.as_deref();
    let mut task = FuzzTask::new(base.clone(), modules);
    task.known_urls = o.known.clone();
    if task.has(Module::Content) {
        let wl = load_wordlist(o.wordlist.as_deref().unwrap_or("common"), dir)?;
        let template = Template {
            url: o
                .template
                .clone()
                .unwrap_or_else(|| format!("{}FUZZ", base.as_str())),
            host: o.host_template.clone(),
        };
        template.validate().map_err(anyhow::Error::msg)?;
        task.content = Some(ContentSpec {
            template,
            wordlist: wl,
            extensions: o.ext.clone(),
        });
    }
    if task.has(Module::Vhost) {
        let domains = if o.vhost_domain.is_empty() {
            scope
                .targets
                .iter()
                .filter_map(|t| match t {
                    foca_core::Target::Domain { name, .. } => Some(name.clone()),
                    foca_core::Target::Wildcard { base, .. } => Some(base.clone()),
                    _ => None,
                })
                .collect()
        } else {
            o.vhost_domain.clone()
        };
        if domains.is_empty() {
            bail!("vhost: нет доменов (--vhost-domain или домен в --targets)");
        }
        let wl = load_wordlist(o.vhost_wordlist.as_deref().unwrap_or("dns-top5000"), dir)?
            .take(o.vhost_words);
        task.vhost = Some(VhostSpec {
            domains,
            wordlist: wl,
        });
    }
    if task.has(Module::Cms) {
        let c = o.cms.as_deref().context("модуль cms: укажите --cms")?;
        task.cms = Some(Cms::parse(c).with_context(|| format!("неизвестная CMS: {c}"))?);
    }
    let mut cfg = FuzzConfig {
        threads: o.threads.clamp(1, 16),
        rate: o.rate.clamp(0.1, 50.0),
        jitter: Duration::from_millis(o.jitter_ms),
        max_requests: o.max_requests,
        max_time: Duration::from_secs(o.max_time),
        recursion_depth: o.depth.min(3),
        calibrate: !o.no_calibration,
        follow_redirects: o.follow_redirects,
        exclude_paths: o.exclude_path.clone(),
        vhost_words: o.vhost_words,
        ..Default::default()
    };
    let rules = [
        (Rule::MatchStatus, &o.mc),
        (Rule::FilterStatus, &o.fc),
        (Rule::FilterSize, &o.fs),
        (Rule::FilterWords, &o.fw),
        (Rule::FilterLines, &o.fl),
        (Rule::FilterRegex, &o.fr),
        (Rule::MatchRegex, &o.mr),
    ];
    cfg.filters = Filters::from_rules(
        rules
            .iter()
            .filter_map(|(rule, spec)| spec.as_deref().map(|s| (*rule, s))),
    )
    .map_err(anyhow::Error::msg)?;
    Ok((task, cfg, scope))
}

fn list_wordlists(json: bool) -> Result<bool> {
    let mut b = Vec::new();
    for w in wordlists::BUILTIN {
        let n = wordlists::builtin(w.id)?.len();
        b.push(serde_json::json!({ "id": w.id, "source": w.source, "words": n, "builtin": true }));
    }
    for r in wordlists::REGISTRY {
        b.push(serde_json::json!({
            "id": r.id, "source": r.source, "size": r.size, "lines": r.lines,
            "sha256": r.sha256, "url": r.url(), "builtin": false
        }));
    }
    if json {
        println!("{}", serde_json::to_string_pretty(&b)?);
    } else {
        println!(
            "Встроенные (SecLists {}; сжато {} КБ):",
            &wordlists::SECLISTS_COMMIT[..12],
            wordlists::builtin_compressed_size() / 1024
        );
        for w in wordlists::BUILTIN {
            println!("  {:<24} {}", w.id, w.source);
        }
        println!("По требованию (--download-wordlist ID --wordlist-dir DIR):");
        for r in wordlists::REGISTRY {
            println!("  {:<24} {:>9} Б  {}", r.id, r.size, r.source);
        }
    }
    Ok(true)
}

fn rt() -> Result<tokio::runtime::Runtime> {
    Ok(tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()?)
}

fn net_config(o: &crate::net::NetOpts, threads: usize) -> NetConfig {
    let mut c = NetConfig {
        proxy: o.proxy.clone(),
        connect_timeout: Duration::from_secs(o.timeout),
        retries: 0,
        max_concurrency: threads.max(1),
        // The fuzzer paces itself (--rate), so the client-wide limit must not be lower.
        global_rps: None,
        proxy_resolver: Some(std::sync::Arc::new(foca_net::doh::DohProxyResolver)),
        ..Default::default()
    };
    if let Some(ua) = &o.ua {
        c.user_agent = ua.clone();
    }
    c
}

/// Runs `foca fuzz`.
pub fn run(o: FuzzOpts) -> Result<bool> {
    if o.list_wordlists {
        return list_wordlists(o.json);
    }
    if let Some(id) = &o.download_wordlist {
        let dir = o
            .wordlist_dir
            .clone()
            .context("--download-wordlist требует --wordlist-dir")?;
        let entry = wordlists::REGISTRY
            .iter()
            .find(|r| r.id == id)
            .with_context(|| format!("нет в реестре: {id}"))?;
        let rt = rt()?;
        let net = NetClient::new(
            net_config(&o.net, 1),
            Scope::default(),
            Arc::new(MemorySink::new()),
        )?;
        let p = rt.block_on(wordlists::download(&net, entry, &dir, None))?;
        println!("{} → {} (SHA-256 сверен)", entry.id, p.display());
        return Ok(true);
    }
    let (task, cfg, scope) = build(&o)?;
    if o.dry_run {
        // Estimate only: no network client is created at all.
        let e = foca_fuzz::estimate(&task, &cfg, Some(&scope), o.wordlist_dir.as_deref())
            .map_err(anyhow::Error::msg)?;
        if o.json {
            println!("{}", serde_json::to_string_pretty(&e)?);
        } else {
            println!("Оценка (без сети) для {}:", task.base);
            for (m, n) in &e.per_module {
                println!("  {m:<12} {n} кандидатов");
            }
            println!(
                "  калибровка  {} запросов\n  итого       {} запросов{}\n  время       ~{} при {} запр/с, {} потоках\n  исключено   {}\n  ({})",
                e.calibration,
                e.requests,
                if e.capped_by_budget { " (упирается в --max-requests)" } else { "" },
                fmt_duration(Duration::from_secs(e.seconds)),
                cfg.rate,
                cfg.threads,
                e.skipped_excluded,
                e.note
            );
        }
        return Ok(true);
    }
    let rt = rt()?;
    rt.block_on(async move {
        let mem = Arc::new(MemorySink::new());
        let sink: Arc<dyn RequestSink> = mem.clone();
        let net = NetClient::new(net_config(&o.net, cfg.threads), scope, sink)?;
        let fz = Fuzzer::new(net, cfg);
        let fz = match &o.wordlist_dir {
            Some(d) => fz.with_wordlist_dir(d.clone()),
            None => fz,
        };
        let ctl = fz.control();
        tokio::spawn(async move {
            if tokio::signal::ctrl_c().await.is_ok() {
                eprintln!("стоп перебора…");
                ctl.cancel();
            }
        });
        let json = o.json;
        let fz = fz.with_events(Arc::new(move |e: &FuzzEvent| {
            if json {
                return;
            }
            match e {
                FuzzEvent::Started { planned } => eprintln!("запланировано кандидатов: {planned}"),
                FuzzEvent::Calibrated { context, summary, .. } => {
                    eprintln!("калибровка {context}: {summary}")
                }
                FuzzEvent::Progress { stats } => eprintln!(
                    "проверено {} / найдено {} / отфильтровано калибровкой {} (запросов {})",
                    stats.checked, stats.found, stats.filtered_calibration, stats.requests
                ),
                FuzzEvent::Hit { hit } => println!(
                    "[{:?}] {} {}{} - {} ({} Б)",
                    hit.risk,
                    hit.status,
                    hit.url,
                    hit.host.as_deref().map(|h| format!(" Host: {h}")).unwrap_or_default(),
                    hit.kind.title_ru(),
                    hit.size
                ),
                _ => {}
            }
        }));
        let rep = fz.run(&task).await;
        if json {
            println!("{}", serde_json::to_string_pretty(&rep)?);
        } else {
            eprintln!(
                "{}: проверено {}, найдено {}, отфильтровано калибровкой {}, правилами {}, ошибок {}, запросов {}",
                rep.stop.message_ru(),
                rep.stats.checked,
                rep.stats.found,
                rep.stats.filtered_calibration,
                rep.stats.filtered_rules,
                rep.stats.errors,
                rep.stats.requests
            );
            if o.net.log {
                for r in mem.records() {
                    eprintln!(
                        "  {} {} {} {}{}",
                        r.method,
                        r.status.map(|s| s.to_string()).unwrap_or_else(|| "-".into()),
                        r.url,
                        if r.blocked { "[заблокирован] " } else { "" },
                        r.error.unwrap_or_default()
                    );
                }
            } else {
                eprintln!("журнал: {} запросов (подробно: --log)", mem.len());
            }
        }
        Ok(matches!(
            rep.stop,
            foca_fuzz::StopReason::Completed | foca_fuzz::StopReason::Budget
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[derive(Parser)]
    struct T {
        #[command(flatten)]
        o: FuzzOpts,
    }

    fn opts(args: &[&str]) -> FuzzOpts {
        let mut v = vec!["foca"];
        v.extend_from_slice(args);
        T::parse_from(v).o
    }

    #[test]
    fn dry_run_estimates_without_network() {
        let o = opts(&[
            "--url",
            "https://contoso.ua",
            "--modules",
            "docs,backups,exposed,dirlisting,vhost",
            "--rate",
            "5",
            "--dry-run",
        ]);
        let (task, cfg, scope) = build(&o).unwrap();
        assert_eq!(task.base.as_str(), "https://contoso.ua/");
        assert!(
            scope.active_phase,
            "fuzzing is an active operation and needs no extra flags"
        );
        assert_eq!((cfg.threads, cfg.rate), (4, 5.0));
        assert!(run(o).unwrap());
    }

    #[test]
    fn scope_required() {
        let o = opts(&[
            "--url",
            "https://contoso.ua/",
            "--targets",
            "other.ua",
            "--dry-run",
        ]);
        assert!(build(&o).is_err());
        let o = opts(&[
            "--url",
            "https://contoso.ua/",
            "--modules",
            "nope",
            "--dry-run",
        ]);
        assert!(build(&o).is_err());
        let o = opts(&[
            "--url",
            "https://contoso.ua/",
            "--modules",
            "cms",
            "--dry-run",
        ]);
        assert!(build(&o).is_err(), "cms without --cms");
    }
}
