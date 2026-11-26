//! Network commands of the CLI: `dns`, `subdomains`, `search`, `download`.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use foca_core::Scope;
use foca_net::dns::{dns_report, resolve_alive, DnsConfig, DnsLookup, HickoryDns};
use foca_net::sink::TeeSink;
use foca_net::{ct, rdap, MemorySink, NetClient, NetConfig, RequestRecord, RequestSink};
use foca_search::download::QueueEvent;
use foca_search::sources::{by_ids, SourceKeys, DEFAULT_PASSIVE};
use foca_search::store::{StoreQueue, StoreSink};
use foca_search::{
    run_sources, summarize_urls, DownloadConfig, Downloader, ExtFilter, SearchCtx, SourceKind,
};

/// Shared network options.
#[derive(clap::Args, Debug, Clone)]
pub struct NetOpts {
    /// Proxy: http://h:p, socks5://h:p, socks5h://h:p
    #[arg(long, env = "FOCA_PROXY")]
    pub proxy: Option<String>,
    /// User-Agent
    #[arg(long)]
    pub ua: Option<String>,
    /// Connection timeout, s
    #[arg(long, default_value_t = 15)]
    pub timeout: u64,
    /// DNS servers (comma-separated); defaults to /etc/resolv.conf, otherwise 1.1.1.1/8.8.8.8
    #[arg(long, value_delimiter = ',')]
    pub dns: Vec<std::net::IpAddr>,
    /// Print the outgoing request log (stderr)
    #[arg(long)]
    pub log: bool,
}

fn rt() -> Result<tokio::runtime::Runtime> {
    Ok(tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?)
}

fn net_config(o: &NetOpts) -> NetConfig {
    let mut c = NetConfig {
        proxy: o.proxy.clone(),
        connect_timeout: Duration::from_secs(o.timeout),
        proxy_resolver: Some(std::sync::Arc::new(foca_net::doh::DohProxyResolver)),
        ..Default::default()
    };
    if let Some(ua) = &o.ua {
        c.user_agent = ua.clone();
    }
    c
}

fn client(
    o: &NetOpts,
    scope: Scope,
    extra: Option<Arc<dyn RequestSink>>,
) -> Result<(NetClient, Arc<MemorySink>)> {
    let mem = Arc::new(MemorySink::new());
    let mut sinks: Vec<Arc<dyn RequestSink>> = vec![mem.clone()];
    sinks.extend(extra);
    let net = NetClient::new(net_config(o), scope, Arc::new(TeeSink(sinks)))?;
    // Ctrl+C cancels all requests.
    let n2 = net.clone();
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            eprintln!("отмена…");
            n2.cancel();
        }
    });
    Ok((net, mem))
}

fn print_log(o: &NetOpts, recs: &[RequestRecord]) {
    if !o.log {
        eprintln!("журнал: {} запросов (подробно: --log)", recs.len());
        return;
    }
    eprintln!("журнал исходящих запросов ({}):", recs.len());
    for r in recs {
        eprintln!(
            "  {} {:<8} {:<5} {:<4} {:>7}Б {}{}{}",
            r.time.time(),
            r.module,
            r.method,
            r.status
                .map(|s| s.to_string())
                .unwrap_or_else(|| "-".into()),
            r.bytes,
            if r.active { "[цель] " } else { "" },
            r.url,
            r.error
                .as_deref()
                .map(|e| format!("  ← {e}"))
                .unwrap_or_default()
        );
    }
}

fn domain_scope(domain: &str) -> Result<Scope> {
    let (s, errs) = Scope::from_lines(domain, "");
    if !errs.is_empty() || s.targets.is_empty() {
        bail!("не домен: {domain}");
    }
    Ok(s)
}

/// `foca dns <domain>`
pub fn dns(domain: &str, json: bool, whois: bool, o: &NetOpts) -> Result<bool> {
    rt()?.block_on(async {
        let (net, mem) = client(o, Scope::default(), None)?;
        let cfg = DnsConfig {
            servers: o.dns.clone(),
            ..Default::default()
        };
        let resolver = HickoryDns::new(&cfg, &net)?;
        let rep = dns_report(&resolver, domain).await;
        let mut who = serde_json::Value::Null;
        if whois && !rep.nxdomain {
            let ep = rdap::RdapEndpoints::default();
            let d = rdap::domain_info(&net, &ep, domain).await.ok();
            let mut ips = Vec::new();
            for ip in rep.records.get("A").into_iter().flatten().take(3) {
                if let Ok(ip) = ip.parse() {
                    if let Ok(i) = rdap::ip_info(&net, &ep, ip).await {
                        ips.push(i);
                    }
                }
            }
            who = serde_json::json!({ "domain": d, "ips": ips });
        }
        if json {
            let mut v = serde_json::to_value(&rep)?;
            v["whois"] = who;
            v["servers"] = serde_json::to_value(cfg.effective_servers())?;
            println!("{}", serde_json::to_string_pretty(&v)?);
        } else {
            println!(
                "DNS {} (серверы: {:?})",
                rep.domain,
                cfg.effective_servers()
            );
            if rep.nxdomain {
                println!("  NXDOMAIN");
            }
            for (t, v) in &rep.records {
                for x in v {
                    println!("  {t:<6} {x}");
                }
            }
            for (ip, v) in &rep.ptr {
                println!("  PTR    {ip} → {}", v.join(", "));
            }
            for (n, v) in &rep.srv {
                println!("  SRV    {n} → {}", v.join(", "));
            }
            let m = &rep.mail;
            println!(
                "почта: SPF {} · DMARC {} · DKIM {:?} → подделка писем {}",
                m.spf.as_ref().map(|s| s.record.as_str()).unwrap_or("нет"),
                m.dmarc.as_ref().map(|d| d.record.as_str()).unwrap_or("нет"),
                m.dkim_selectors,
                if m.spoofable {
                    "ВОЗМОЖНА"
                } else {
                    "затруднена"
                }
            );
            for i in &m.issues {
                println!("  [{}] {} - {}", i.sev, i.title, i.detail);
            }
            for d in &rep.dangling {
                println!("  [{}] висящий CNAME: {} → {}", d.sev, d.host, d.reason);
            }
            if !who.is_null() {
                println!("RDAP/RIPEstat: {}", serde_json::to_string_pretty(&who)?);
            }
            for e in &rep.errors {
                println!("  ошибка: {e}");
            }
        }
        print_log(o, &mem.records());
        Ok(!rep.nxdomain)
    })
}

/// `foca subdomains <domain>`
pub fn subdomains(
    domain: &str,
    json: bool,
    resolve: bool,
    certspotter: bool,
    o: &NetOpts,
) -> Result<bool> {
    rt()?.block_on(async {
        let (net, mem) = client(o, Scope::default(), None)?;
        let ep = ct::CtEndpoints::default();
        let mut all = BTreeSet::new();
        let mut errors = Vec::new();
        match ct::crtsh_subdomains(&net, &ep, domain).await {
            Ok(v) => all.extend(v),
            Err(e) => errors.push(format!("crt.sh: {e}")),
        }
        if certspotter {
            let key = std::env::var("FOCA_CERTSPOTTER_KEY").ok();
            match ct::certspotter_subdomains(&net, &ep, domain, key.as_deref(), 2).await {
                Ok(v) => all.extend(v),
                Err(e) => errors.push(format!("certspotter: {e}")),
            }
        }
        let hosts: Vec<String> = all.into_iter().collect();
        let alive = if resolve {
            let cfg = DnsConfig {
                servers: o.dns.clone(),
                ..Default::default()
            };
            let d: Arc<dyn DnsLookup> = Arc::new(HickoryDns::new(&cfg, &net)?);
            Some(resolve_alive(d, &hosts, 8).await)
        } else {
            None
        };
        if json {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "domain": domain, "hosts": hosts, "alive": alive, "errors": errors
                }))?
            );
        } else {
            println!("поддомены {domain} из CT: {}", hosts.len());
            for h in &hosts {
                let ips = alive
                    .as_ref()
                    .and_then(|a| a.iter().find(|x| &x.0 == h))
                    .map(|x| x.1.join(", "));
                match (&alive, ips) {
                    (Some(_), Some(ips)) => println!("  {h}  [{ips}]"),
                    (Some(_), None) => println!("  {h}  (не резолвится)"),
                    _ => println!("  {h}"),
                }
            }
            for e in &errors {
                println!("ошибка источника: {e}");
            }
        }
        print_log(o, &mem.records());
        Ok(!hosts.is_empty())
    })
}

/// `foca search <domain>`
pub fn search(
    domain: &str,
    sources: &[String],
    limit: usize,
    ext: &str,
    json: bool,
    o: &NetOpts,
) -> Result<bool> {
    let ids: Vec<String> = if sources.is_empty() {
        DEFAULT_PASSIVE.iter().map(|s| s.to_string()).collect()
    } else {
        sources.to_vec()
    };
    let keys = SourceKeys {
        brave: std::env::var("FOCA_BRAVE_KEY").ok(),
        searx: std::env::var("FOCA_SEARX_URL").ok(),
        vt: std::env::var("FOCA_VT_KEY").ok(),
        st: std::env::var("FOCA_ST_KEY").ok(),
        github: std::env::var("FOCA_GITHUB_KEY").ok(),
    };
    let (srcs, unknown) = by_ids(&ids, &keys);
    if !unknown.is_empty() {
        bail!("неизвестные источники: {}", unknown.join(", "));
    }
    if srcs.iter().any(|s| s.kind() == SourceKind::TouchesTarget) {
        eprintln!("внимание: источник «crawler» обращается к сайту цели ({domain}); скоуп: только этот домен");
    }
    rt()?.block_on(async {
        let (net, mem) = client(o, domain_scope(domain)?, None)?;
        let mut ctx = SearchCtx::new(net);
        ctx.limit = limit;
        ctx.filter = ExtFilter::parse(ext);
        let res = run_sources(&srcs, &ctx, domain, |r| {
            eprintln!("источник {:<8} {:?} {}{}", r.id, r.status, r.n, r.error.as_deref().map(|e| format!(" ({e})")).unwrap_or_default());
        })
        .await?;
        let summary = summarize_urls(res.urls.iter().map(|u| u.target_url()));
        if json {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "domain": domain, "sources": res.sources, "urls": res.urls, "hosts": res.hosts, "url_analysis": summary
                }))?
            );
        } else {
            println!("документы ({}):", res.urls.len());
            for u in &res.urls {
                println!(
                    "  [{}] {}{}",
                    u.source,
                    u.url,
                    u.size.map(|s| format!("  ({s} Б)")).unwrap_or_default()
                );
            }
            if !res.hosts.is_empty() {
                println!("хосты ({}): {}", res.hosts.len(), res.hosts.join(", "));
            }
            if !summary.users.is_empty() {
                println!("пользователи в путях: {:?}", summary.users);
            }
            println!("серверы: {:?}", summary.hosts);
        }
        print_log(o, &mem.records());
        Ok(!res.urls.is_empty() || !res.hosts.is_empty())
    })
}

fn project_files(store: &Path, id: &str) -> PathBuf {
    store.join(format!("{id}.files"))
}

/// `foca download <url...> --project id`
pub fn download(
    store_dir: &Path,
    project: &str,
    urls: &[String],
    max_mb: u64,
    json: bool,
    o: &NetOpts,
) -> Result<bool> {
    let store = foca_store::Store::open(store_dir)
        .with_context(|| format!("хранилище {}", store_dir.display()))?;
    let db = store.open_project(project)?;
    let scope = db.core_scope()?;
    let db = Arc::new(Mutex::new(db));
    let scan_id = format!("dl-{}", foca_store::iso(time::OffsetDateTime::now_utc()));
    rt()?.block_on(async {
        let sink: Arc<dyn RequestSink> = Arc::new(StoreSink {
            db: db.clone(),
            scan_id: Some(scan_id.clone()),
        });
        let (net, mem) = client(o, scope, Some(sink))?;
        let q = StoreQueue::new(db.clone(), Some(scan_id.clone()));
        let found: Vec<foca_search::FoundUrl> = urls
            .iter()
            .map(|u| foca_search::FoundUrl::new(u, "manual"))
            .collect();
        let added = q.enqueue(&found).map_err(anyhow::Error::msg)?;
        let pending = {
            let g = db.lock().map_err(|_| anyhow::anyhow!("lock"))?;
            g.task_counts()?
        };
        eprintln!(
            "в очереди: новых {added}, всего ожидают {} (прерванные ранее: продолжатся)",
            pending.queued + pending.downloading
        );
        let d = Downloader::new(
            net,
            project_files(store_dir, project),
            DownloadConfig {
                max_size: max_mb * 1024 * 1024,
                ..Default::default()
            },
        );
        let mut results = Vec::new();
        let stats = d
            .run_queue(&q, |e| match e {
                QueueEvent::Done(t, d, doc) => {
                    if !json {
                        println!(
                            "OK   {} → {} ({} Б, sha256 {}{}) doc={:?}",
                            t.url,
                            d.path.display(),
                            d.size,
                            &d.sha256[..16],
                            if d.existing { ", дубликат" } else { "" },
                            doc
                        );
                    }
                    results.push(serde_json::json!({"url": t.url, "ok": true, "sha256": d.sha256, "size": d.size, "path": d.path, "doc": doc, "duplicate": d.existing}));
                }
                QueueEvent::Failed(t, e) => {
                    if !json {
                        println!("FAIL {}: {e}", t.url);
                    }
                    results.push(serde_json::json!({"url": t.url, "ok": false, "error": e.to_string(), "code": e.code()}));
                }
            })
            .await
            .map_err(anyhow::Error::msg)?;
        if json {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({"results": results, "stats": stats}))?
            );
        } else {
            println!(
                "итог: скачано {}, дубликатов {}, ошибок {}, повторов {}, {} Б{}",
                stats.done,
                stats.duplicates,
                stats.failed,
                stats.retried,
                stats.bytes,
                if stats.cancelled { " (прервано: запустите снова, чтобы продолжить)" } else { "" }
            );
        }
        print_log(o, &mem.records());
        Ok(stats.failed == 0 && !stats.cancelled)
    })
}
