//! `foca ports <host> [--top 100|1000] [--ports 22,80,8000-8100]`: TCP ports and banners
//! (foca-net::ports, RustScan-style logic). This is an active check: only your own or
//! authorized hosts.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Result};
use foca_core::Scope;
use foca_net::ports::{parse_ports, scan_ports, top_ports, PortScanConfig};
use foca_net::{MemorySink, NetClient, NetConfig};

#[derive(clap::Args, Debug, Clone)]
pub struct PortsOpts {
    /// Host or IP (also the scan scope)
    pub host: String,
    /// Top-N ports: 100 or 1000
    #[arg(long, default_value_t = 100)]
    pub top: usize,
    /// Custom list: 22,80,443,8000-8100 (instead of --top)
    #[arg(long)]
    pub ports: Option<String>,
    /// Scope exclusions (comma-separated hosts/IPs/CIDRs); never scanned
    #[arg(long, value_delimiter = ',')]
    pub exclude: Vec<String>,
    /// Initial batch size (concurrent connections)
    #[arg(long, default_value_t = 50)]
    pub batch: usize,
    /// Per-port connection timeout, ms
    #[arg(long, default_value_t = 1500)]
    pub timeout_ms: u64,
    /// Connection attempts per second (0 = unlimited)
    #[arg(long, default_value_t = 100.0)]
    pub rate: f64,
    /// Skip banners (open/closed only)
    #[arg(long)]
    pub no_banners: bool,
    /// Proxy: socks5h://h:p, http://h:p (all connections go through it)
    #[arg(long, env = "FOCA_PROXY")]
    pub proxy: Option<String>,
    /// JSON instead of a table
    #[arg(long)]
    pub json: bool,
    /// Print the attempt log (stderr)
    #[arg(long)]
    pub log: bool,
}

pub fn run(o: PortsOpts) -> Result<bool> {
    let ports = match &o.ports {
        Some(s) => parse_ports(s).map_err(anyhow::Error::msg)?,
        None if o.top == 100 || o.top == 1000 => top_ports(o.top),
        None => bail!("--top: 100 или 1000"),
    };
    let (mut scope, errs) = Scope::from_lines(&o.host, &o.exclude.join("\n"));
    if !errs.is_empty() || scope.targets.is_empty() {
        bail!("не хост/IP: {}", o.host);
    }
    scope.active_phase = true;
    let cfg = PortScanConfig {
        ports,
        batch: o.batch.max(1),
        timeout: Duration::from_millis(o.timeout_ms.max(50)),
        rps: (o.rate > 0.0).then_some(o.rate),
        banners: !o.no_banners,
        ..Default::default()
    };
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()?;
    let sink = Arc::new(MemorySink::new());
    let ncfg = NetConfig {
        proxy: o.proxy.clone(),
        proxy_resolver: Some(std::sync::Arc::new(foca_net::doh::DohProxyResolver)),
        ..Default::default()
    };
    let res = rt.block_on(async {
        let net = NetClient::new(ncfg, scope, sink.clone())?;
        let n2 = net.clone();
        tokio::spawn(async move {
            if tokio::signal::ctrl_c().await.is_ok() {
                eprintln!("отмена…");
                n2.cancel();
            }
        });
        scan_ports(&net, &o.host, &cfg).await
    });
    let recs = sink.records();
    if o.log {
        for r in &recs {
            eprintln!(
                "  {} {} {}{}",
                r.time.time(),
                r.method,
                r.url,
                r.error
                    .as_deref()
                    .map(|e| format!("  ← {e}"))
                    .unwrap_or_default()
            );
        }
    }
    let r = res?;
    if o.json {
        println!("{}", serde_json::to_string_pretty(&r)?);
    } else {
        println!(
            "{} ({}): открыто {} из {}, закрыто {}, фильтр {}; {:.1} с, пачка {}{}",
            r.host,
            r.ip.as_deref().unwrap_or("через прокси"),
            r.open.len(),
            r.scanned,
            r.closed,
            r.filtered,
            r.ms as f64 / 1000.0,
            r.batch,
            if r.cancelled {
                ", ОТМЕНЕНО"
            } else {
                ""
            }
        );
        if let Some(why) = &r.unreliable {
            println!(
                "  ВНИМАНИЕ: скан недостоверен ({why}; канареек открыто {} из {}): сеть \
                 (VPN, AdGuard, прокси) принимает соединения на любом порту",
                r.canaries_open, r.canaries
            );
        }
        for p in &r.open {
            let pv = match (&p.product, &p.version) {
                (Some(p), Some(v)) => format!("{p} {v}"),
                (Some(p), None) => p.clone(),
                _ => String::new(),
            };
            println!(
                "  {:>5}/tcp  {:<12} {:<28} {}{}",
                p.port,
                p.service,
                pv,
                p.banner.as_deref().unwrap_or(""),
                if p.cert_names.is_empty() {
                    String::new()
                } else {
                    format!("  [TLS: {}]", p.cert_names.join(", "))
                }
            );
        }
    }
    eprintln!("журнал: {} попыток (подробно: --log)", recs.len());
    Ok(!r.cancelled)
}
