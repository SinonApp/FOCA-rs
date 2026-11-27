//! Dangling CNAME checks of candidate names with bounded concurrency. Results keep the input
//! order, so a parallel run yields exactly what a sequential one would.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use foca_core::Severity;
use foca_net::dns::DnsLookup;
use foca_net::takeover::{Dangling, HttpCandidate, Inspection};
use foca_net::{Access, NetClient, NetError, NetRequest};
use tokio::sync::{mpsc, watch};
use tokio_util::sync::CancellationToken;

use super::{sev_of, Ctx, Stop};
use crate::analysis::facts::{self, NetFacts};

/// Names checked at once.
pub(crate) const CONCURRENCY: usize = 8;

/// Waits while the scan is paused; fails once it is stopped.
pub(crate) async fn wait_gate(
    pause: &mut watch::Receiver<Option<String>>,
    cancel: &CancellationToken,
) -> Result<(), Stop> {
    loop {
        if cancel.is_cancelled() {
            return Err(Stop::Cancelled);
        }
        if pause.borrow().is_none() {
            return Ok(());
        }
        tokio::select! {
            r = pause.changed() => if r.is_err() { return Ok(()) },
            _ = cancel.cancelled() => return Err(Stop::Cancelled),
        }
    }
}

/// Follows the CNAME chain of every name of `names` ([`foca_net::takeover::inspect`]: dangling
/// CNAMEs and HTTP fingerprint candidates) with at most `conc` lookups in flight. Each worker
/// passes the pause/stop gate before every name; `on_done(n)` reports progress.
pub(crate) async fn check_all(
    dns: Arc<dyn DnsLookup>,
    names: &[String],
    conc: usize,
    pause: watch::Receiver<Option<String>>,
    cancel: CancellationToken,
    mut on_done: impl FnMut(usize),
) -> Result<Vec<Inspection>, Stop> {
    let names: Arc<Vec<String>> = Arc::new(names.to_vec());
    let next = Arc::new(AtomicUsize::new(0));
    let (tx, mut rx) = mpsc::unbounded_channel::<(usize, Inspection)>();
    let mut set = tokio::task::JoinSet::new();
    for _ in 0..conc.clamp(1, names.len().max(1)) {
        let (dns, names, next, tx, cancel) = (
            dns.clone(),
            names.clone(),
            next.clone(),
            tx.clone(),
            cancel.clone(),
        );
        let mut pause = pause.clone();
        set.spawn(async move {
            loop {
                if wait_gate(&mut pause, &cancel).await.is_err() {
                    return;
                }
                let i = next.fetch_add(1, Ordering::Relaxed);
                let Some(h) = names.get(i) else { return };
                let r = tokio::select! {
                    r = foca_net::takeover::inspect(dns.as_ref(), h) => r,
                    _ = cancel.cancelled() => return,
                };
                if tx.send((i, r)).is_err() {
                    return;
                }
            }
        });
    }
    drop(tx);
    let mut out: Vec<Inspection> = vec![Inspection::default(); names.len()];
    let mut done = 0usize;
    while let Some((i, r)) = rx.recv().await {
        out[i] = r;
        done += 1;
        on_done(done);
    }
    while set.join_next().await.is_some() {}
    if cancel.is_cancelled() || done < names.len() {
        return Err(Stop::Cancelled);
    }
    Ok(out)
}

/// Body bytes read from a takeover candidate (fingerprints sit in short error pages).
const HTTP_BODY_LIMIT: usize = 128 * 1024;

/// Per-request timeout of the HTTP fingerprint check.
const HTTP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

/// HTTP fingerprint check of CNAMEs that point at a live resource of a known service: GET the
/// subdomain itself (scope-checked target request, standard/full levels only, held CDN/cloud
/// names skipped) and match the service's unclaimed-resource text. Records a `takeover-http`
/// finding per hit; returns the hit count.
pub(super) async fn http_check(
    c: &Ctx,
    f: &mut NetFacts,
    cands: Vec<HttpCandidate>,
    now: &str,
    sid: &str,
) -> Result<usize, Stop> {
    let net = c.group_net("target")?;
    let held = super::ports::held_names(c, f);
    let mut hits = 0;
    for cand in cands {
        c.gate().await?;
        if held.contains(&cand.host) || !net.host_in_scope(&cand.host) {
            continue;
        }
        let urls = match c.e.cfg.site_port {
            // the offline harness serves sites on its own port, plain HTTP
            Some(p) => vec![format!("http://{}:{p}/", cand.host)],
            None => vec![
                format!("https://{}/", cand.host),
                format!("http://{}/", cand.host),
            ],
        };
        for url in urls {
            match fetch_prefix(&net, &url).await {
                Ok((status, body)) => {
                    if let Some(m) = cand.service.match_body(&String::from_utf8_lossy(&body)) {
                        hits += 1;
                        http_finding(f, &cand, &url, status, &m, now, sid);
                    }
                    break;
                }
                // scope or stop: the host is not checked at all
                Err(e) if e.is_scope_denial() || matches!(e, NetError::Cancelled) => break,
                Err(_) => continue,
            }
        }
    }
    Ok(hits)
}

/// GET without redirects (the fingerprint is on the subdomain's own answer, any status); reads
/// at most [`HTTP_BODY_LIMIT`] bytes.
async fn fetch_prefix(net: &NetClient, url: &str) -> Result<(u16, Vec<u8>), NetError> {
    let req = NetRequest::get(url, "takeover", Access::TouchesTarget)?
        .no_redirects()
        .retries(0)
        .timeout(HTTP_TIMEOUT);
    let mut r = net.send(req).await?;
    let status = r.status();
    let mut body = Vec::new();
    while let Some(chunk) = r.chunk().await? {
        if body.len() + chunk.len() > HTTP_BODY_LIMIT {
            body.extend_from_slice(&chunk[..HTTP_BODY_LIMIT - body.len()]);
            r.abort();
            break;
        }
        body.extend_from_slice(&chunk);
    }
    Ok((status, body))
}

/// Records a matched HTTP fingerprint as a `takeover-http` finding. Severity follows the
/// can-i-take-over-xyz status: `vulnerable` → high, `edge` (claimable only in some cases) → medium.
fn http_finding(
    f: &mut NetFacts,
    cand: &HttpCandidate,
    url: &str,
    status: u16,
    matched: &str,
    now: &str,
    sid: &str,
) {
    let s = &cand.service;
    let target = cand.chain.last().cloned().unwrap_or_default();
    let h = f.host(&cand.host);
    if h.cloud.is_empty() || h.cloud == "-" {
        h.cloud = s.service.clone();
    }
    if h.first_scan.is_none() {
        h.first_scan = Some(sid.into());
    }
    let sev = if s.status == "vulnerable" {
        Severity::High
    } else {
        Severity::Medium
    };
    let nf = facts::net_finding(
        "takeover-http",
        &cand.host,
        format!("Возможен subdomain takeover (сервис {})", s.service),
        sev,
        &cand.host,
        "dns",
        "HTTP",
        "dns",
        true,
        now,
        Some(sid),
        format!(
            "CNAME → {target} ({}): ответ {url} (HTTP {status}) содержит признак незанятого ресурса: «{matched}»",
            s.service
        ),
        "Удалить запись CNAME или занять ресурс у провайдера за компанией.",
        format!(
            "$ dig +short CNAME {}\n{}\n$ curl -s {url}\nHTTP {status}\n…{matched}…",
            cand.host,
            cand.chain.join("\n")
        ),
        Some(url.to_string()),
    );
    f.findings.entry(nf.id).or_insert(nf);
}

/// Records a dangling CNAME as a host fact and a `dangling-cname` finding.
pub(super) fn dangling(f: &mut NetFacts, dg: &Dangling, now: &str, sid: &str) {
    let target = dg.chain.last().cloned().unwrap_or_default();
    let h = f.host(&dg.host);
    h.ip = format!("CNAME → {target}");
    h.role = "Висящий CNAME".into();
    h.source = "DNS".into();
    h.dangling = Some(target.clone());
    if let Some(p) = &dg.provider {
        h.cloud = p.clone();
    }
    if h.first_scan.is_none() {
        h.first_scan = Some(sid.into());
    }
    h.dns = vec![(
        "CNAME".into(),
        target.clone(),
        "NXDOMAIN: ресурс удалён".into(),
    )];
    let nf = facts::net_finding(
        "dangling-cname",
        &dg.host,
        "Висящий CNAME → возможен subdomain takeover".into(),
        sev_of(&dg.sev),
        &dg.host,
        "dns",
        "DNS",
        "dns",
        false,
        now,
        Some(sid),
        dg.reason.clone(),
        "Удалить запись CNAME или повторно занять имя ресурса за компанией.",
        format!(
            "$ dig +short CNAME {}\n{}\n;; ->>HEADER<<- status: NXDOMAIN",
            dg.host,
            dg.chain.join("\n")
        ),
        Some(format!("dns://{}", dg.host)),
    );
    f.findings.entry(nf.id).or_insert(nf);
}

#[cfg(test)]
mod tests {
    use super::*;
    use foca_net::bruteforce::testdns::FakeDns;

    fn zone(n: usize) -> (Arc<dyn DnsLookup>, Vec<String>) {
        let mut dns = FakeDns::new();
        let mut names = Vec::new();
        for i in 0..n {
            let h = format!("h{i}.example.test");
            dns = match i % 3 {
                0 => dns.cname(&h, &format!("gone{i}.azurewebsites.net"), 60),
                1 => dns.cname(&h, "live.example.test", 60),
                _ => dns.host(&h, &["127.0.0.1"], 60),
            };
            names.push(h);
        }
        dns = dns.host("live.example.test", &["127.0.0.2"], 60);
        (Arc::new(dns), names)
    }

    #[tokio::test]
    async fn parallel_matches_sequential() {
        let (dns, names) = zone(40);
        let mut seq = Vec::new();
        for h in &names {
            seq.push(foca_net::takeover::check_dangling(dns.as_ref(), h).await);
        }
        assert!(seq.iter().filter(|x| x.is_some()).count() >= 10, "{seq:?}");
        let (_tx, rx) = watch::channel(None);
        let mut ticks = 0;
        let par = check_all(
            dns,
            &names,
            CONCURRENCY,
            rx,
            CancellationToken::new(),
            |_| ticks += 1,
        )
        .await
        .unwrap_or_else(|_| panic!("stopped"));
        let par: Vec<Option<Dangling>> = par.into_iter().map(|i| i.dangling).collect();
        assert_eq!(par, seq);
        assert_eq!(ticks, names.len());
    }

    #[tokio::test]
    async fn stop_is_honoured() {
        let (dns, names) = zone(40);
        let (_tx, rx) = watch::channel(None);
        let cancel = CancellationToken::new();
        let c2 = cancel.clone();
        let r = check_all(dns, &names, CONCURRENCY, rx, cancel, |n| {
            if n == 5 {
                c2.cancel();
            }
        })
        .await;
        assert!(matches!(r, Err(Stop::Cancelled)));
    }

    #[tokio::test]
    async fn pause_holds_workers_until_resumed() {
        let (dns, names) = zone(12);
        let (tx, rx) = watch::channel(Some("user".to_string()));
        let fut = check_all(
            dns,
            &names,
            CONCURRENCY,
            rx,
            CancellationToken::new(),
            |_| {},
        );
        tokio::pin!(fut);
        let held = tokio::time::timeout(std::time::Duration::from_millis(150), &mut fut).await;
        assert!(held.is_err(), "workers ran while paused");
        tx.send(None).unwrap();
        let r = fut.await.unwrap_or_else(|_| panic!("stopped"));
        assert_eq!(r.len(), names.len());
    }
}
