//! `foca recon <url|domain>`: site recon (foca-recon) without a project: technologies with
//! versions, analytics ids, favicon hash (Shodan/FOFA/Censys queries), JS endpoints and
//! secrets (masked), robots/sitemap/security.txt from the archive, cloud storage references,
//! grep.app.
//!
//! `--passive` sends no requests to the site: the home page, favicon and scripts come from a
//! Wayback copy. Bucket listing (`--check-buckets`) and grep.app (`--grepapp`) run only when
//! explicitly requested.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Result};
use foca_core::Scope;
use foca_net::{Access, MemorySink, NetClient, NetConfig};
use foca_recon::buckets::{check_buckets, BucketCheckOptions};
use foca_recon::collect::{self, CollectOptions};
use foca_recon::grepapp::{self, GrepAppError};
use foca_recon::{analyze_site, ReconInput};

use crate::net::NetOpts;

#[derive(clap::Args, Debug)]
pub struct ReconOpts {
    /// Site URL or domain (https://example.com/ or example.com)
    pub target: String,
    /// Passive: take everything from the Wayback copy, send no requests to the site
    #[arg(long)]
    pub passive: bool,
    /// Ask grep.app where the domain appears in public code
    #[arg(long)]
    pub grepapp: bool,
    /// Check discovered cloud storage for public listing (GET to the provider)
    #[arg(long)]
    pub check_buckets: bool,
    /// Do not fetch robots/sitemap/security.txt from the archive
    #[arg(long)]
    pub no_archive: bool,
    /// Web archive base URL (mirrors, tests)
    #[arg(long, default_value = "https://web.archive.org")]
    pub wayback: String,
    /// grep.app base URL (tests)
    #[arg(long, default_value = grepapp::DEFAULT_BASE)]
    pub grepapp_base: String,
    /// JSON output (ReconReport)
    #[arg(long)]
    pub json: bool,
    #[command(flatten)]
    pub net: NetOpts,
}

/// Extracts the host from a URL or domain.
fn host_of(t: &str) -> Option<String> {
    let t = t.trim();
    let u = if t.contains("://") {
        url::Url::parse(t).ok()?
    } else {
        url::Url::parse(&format!("https://{t}/")).ok()?
    };
    let h = u.host_str()?.trim_end_matches('.').to_ascii_lowercase();
    (!h.is_empty()).then_some(h)
}

pub fn run(o: ReconOpts) -> Result<bool> {
    let Some(host) = host_of(&o.target) else {
        bail!("не адрес сайта и не домен: {}", o.target);
    };
    let guard_scope = if o.passive {
        let (s, _) = Scope::from_lines(&host, "");
        Some(s)
    } else {
        None
    };
    let scope = if o.passive {
        Scope::default()
    } else {
        let (s, errs) = Scope::from_lines(&host, "");
        if !errs.is_empty() || s.targets.is_empty() {
            bail!("не домен: {host}");
        }
        s
    };
    let mut cfg = NetConfig {
        proxy: o.net.proxy.clone(),
        connect_timeout: Duration::from_secs(o.net.timeout),
        timeout: Some(Duration::from_secs(60)),
        proxy_resolver: Some(std::sync::Arc::new(foca_net::doh::DohProxyResolver)),
        ..Default::default()
    };
    if let Some(ua) = &o.net.ua {
        cfg.user_agent = ua.clone();
    }
    let mem = Arc::new(MemorySink::new());
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    rt.block_on(async {
        let net = NetClient::new(cfg, scope, mem.clone())?;
        if let Some(gs) = guard_scope {
            net.set_passive_guard(gs, true);
        }
        let n2 = net.clone();
        tokio::spawn(async move {
            if tokio::signal::ctrl_c().await.is_ok() {
                eprintln!("отмена…");
                n2.cancel();
            }
        });
        let mut input = ReconInput {
            target: host.clone(),
            ..Default::default()
        };
        let opts = CollectOptions {
            archive: o.passive.then(|| o.wayback.clone()),
            ..Default::default()
        };
        let page = collect::fetch_site(&net, &host, &opts, &mut input).await;
        if let Err(e) = &page {
            eprintln!("главная недоступна: {e}");
        }
        if !o.no_archive {
            match collect::wellknown(&net, &o.wayback, &host).await {
                Ok(w) => input.wellknown = Some(w),
                Err(e) => eprintln!("архив robots/sitemap: {e}"),
            }
        }
        let mut grep_status = None;
        if o.grepapp {
            match grepapp::search(&net, &o.grepapp_base, &host, 1).await {
                Ok(r) => input.grepapp = Some(r),
                Err(GrepAppError::Challenge) => {
                    grep_status =
                        Some("grep.app: защита от ботов (челлендж): повторите позже".to_string())
                }
                Err(e) => grep_status = Some(e.to_string()),
            }
        }
        let mut rep = analyze_site(&input);
        if o.check_buckets && !rep.buckets.is_empty() {
            let bo = BucketCheckOptions {
                enabled: true,
                access: Access::Passive,
                max_checks: 20,
            };
            check_buckets(&net, &mut rep.buckets, &bo).await;
            rep.refresh_findings();
        }
        let recs = mem.records();
        if o.json {
            println!("{}", serde_json::to_string_pretty(&rep)?);
        } else {
            print_human(&rep, page.as_ref().ok(), o.passive, grep_status.as_deref());
        }
        let to_target = recs
            .iter()
            .filter(|r| r.host == host || r.host.ends_with(&format!(".{host}")))
            .count();
        eprintln!("журнал: {} запросов, к сайту цели: {to_target}", recs.len());
        Ok::<bool, anyhow::Error>(page.is_ok() || input.wellknown.is_some())
    })
}

fn print_human(
    rep: &foca_recon::ReconReport,
    page: Option<&String>,
    passive: bool,
    grep: Option<&str>,
) {
    println!("Разведка сайта: {}", rep.target);
    match page {
        Some(u) if passive => println!("  главная: {u} (архивная копия Wayback)"),
        Some(u) => println!("  главная: {u}"),
        None => println!("  главная: не получена"),
    }
    if !rep.technologies.is_empty() {
        println!("Технологии ({}):", rep.technologies.len());
        for t in &rep.technologies {
            println!(
                "  {:<24} {:<10} {}{}",
                t.name,
                t.version.as_deref().unwrap_or("-"),
                t.category,
                t.outdated
                    .as_deref()
                    .map(|x| format!("  [устарело: {x}]"))
                    .unwrap_or_default()
            );
        }
    }
    if let Some(f) = &rep.favicon {
        println!(
            "Favicon: {} · mmh3 {} · md5 {}",
            f.url, f.hash.mmh3, f.hash.md5
        );
        for q in &f.hash.queries {
            println!("  {q}");
        }
    }
    for a in &rep.analytics_ids {
        println!("ID аналитики: {} ({})", a.id, a.kind);
    }
    let eps: usize = rep.js.iter().map(|j| j.endpoints.len()).sum();
    if eps > 0 {
        println!("Эндпоинты в JS: {eps}");
        for e in rep.js.iter().flat_map(|j| &j.endpoints).take(20) {
            println!(
                "  {}{}",
                e.method
                    .as_deref()
                    .map(|m| format!("{m} "))
                    .unwrap_or_default(),
                e.resolved.as_deref().unwrap_or(&e.raw)
            );
        }
    }
    for j in &rep.js {
        for s in &j.secrets {
            println!(
                "Секрет: {} {} · {}:{}",
                s.title, s.masked, j.source_url, s.line
            );
        }
    }
    if let Some(w) = &rep.wellknown {
        for p in &w.hidden_paths {
            println!("Скрытый путь: {}, {}", p.path, p.reason);
        }
        if !w.sitemap_urls.is_empty() {
            println!("URL из sitemap: {}", w.sitemap_urls.len());
        }
        for s in &w.security {
            println!("security.txt: {}", s.contacts.join(", "));
        }
    }
    for b in &rep.buckets {
        println!(
            "Хранилище: {} {}, {:?}",
            b.provider.label(),
            b.name,
            b.status
        );
    }
    if let Some(g) = &rep.grepapp {
        println!("grep.app: {} совпадений", g.total);
        for h in g.hits.iter().take(10) {
            println!("  {} {}", h.repo, h.path);
        }
    }
    if let Some(g) = grep {
        println!("{g}");
    }
    println!("Находки ({}):", rep.findings.len());
    for f in &rep.findings {
        println!("  [{:?}] {}", f.sev, f.title);
    }
}
