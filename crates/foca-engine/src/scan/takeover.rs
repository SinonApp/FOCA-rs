//! Dangling CNAME checks of candidate names with bounded concurrency. Results keep the input
//! order, so a parallel run yields exactly what a sequential one would.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use foca_net::dns::DnsLookup;
use foca_net::takeover::Dangling;
use tokio::sync::{mpsc, watch};
use tokio_util::sync::CancellationToken;

use super::{sev_of, Stop};
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

/// Checks every name of `names` for a dangling CNAME with at most `conc` lookups in flight.
/// Each worker passes the pause/stop gate before every name; `on_done(n)` reports progress.
pub(crate) async fn check_all(
    dns: Arc<dyn DnsLookup>,
    names: &[String],
    conc: usize,
    pause: watch::Receiver<Option<String>>,
    cancel: CancellationToken,
    mut on_done: impl FnMut(usize),
) -> Result<Vec<Option<Dangling>>, Stop> {
    let names: Arc<Vec<String>> = Arc::new(names.to_vec());
    let next = Arc::new(AtomicUsize::new(0));
    let (tx, mut rx) = mpsc::unbounded_channel::<(usize, Option<Dangling>)>();
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
                    r = foca_net::takeover::check_dangling(dns.as_ref(), h) => r,
                    _ = cancel.cancelled() => return,
                };
                if tx.send((i, r)).is_err() {
                    return;
                }
            }
        });
    }
    drop(tx);
    let mut out: Vec<Option<Dangling>> = vec![None; names.len()];
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
