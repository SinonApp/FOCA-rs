//! Live network tests against public services and safe domains. Run manually:
//! `cargo test -p foca-net --test live -- --ignored --nocapture --test-threads=1`

use std::sync::Arc;
use std::time::Duration;

use foca_core::Scope;
use foca_net::dns::{dns_report, DnsConfig, HickoryDns};
use foca_net::{ct, rdap, Access, MemorySink, NetClient, NetConfig};

fn net(scope: Scope) -> (NetClient, Arc<MemorySink>) {
    let sink = Arc::new(MemorySink::new());
    (
        NetClient::new(NetConfig::default(), scope, sink.clone()).unwrap(),
        sink,
    )
}

#[tokio::test]
#[ignore]
async fn live_https_and_dns() {
    let (n, sink) = net(Scope::default());
    let t = n
        .get_text("https://www.iana.org/", "probe", Access::Passive)
        .await
        .unwrap();
    assert!(t.contains("IANA"));
    let cfg = DnsConfig::default();
    let dns = HickoryDns::new(&cfg, &n).unwrap();
    println!("DNS-серверы: {:?}", cfg.effective_servers());
    let r = dns_report(&dns, "iana.org").await;
    println!("{}", serde_json::to_string_pretty(&r).unwrap());
    assert!(r.records.contains_key("A"));
    assert!(r.records.contains_key("NS"));
    println!("журнал: {} записей", sink.len());
}

#[tokio::test]
#[ignore]
async fn live_ct_and_rdap() {
    let (n, _) = net(Scope::default());
    let ep = ct::CtEndpoints::default();
    match ct::crtsh_subdomains(&n, &ep, "iana.org").await {
        Ok(v) => println!(
            "crt.sh iana.org: {} имён, напр. {:?}",
            v.len(),
            &v[..v.len().min(5)]
        ),
        Err(e) => println!("crt.sh: {e}"),
    }
    let v = ct::certspotter_subdomains(&n, &ep, "example.com", None, 1)
        .await
        .unwrap();
    println!("certspotter example.com: {v:?}");
    assert!(!v.is_empty());
    let re = rdap::RdapEndpoints::default();
    let i = rdap::ip_info(&n, &re, "192.0.43.8".parse().unwrap())
        .await
        .unwrap();
    println!("{i:?}");
    assert!(!i.asns.is_empty());
    let d = rdap::domain_info(&n, &re, "example.com").await.unwrap();
    println!("{d:?}");
}

/// zonetransfer.me deliberately allows AXFR (a training domain by digi.ninja).
#[tokio::test]
#[ignore]
async fn live_axfr_zonetransfer_me() {
    let (mut scope, _) =
        Scope::from_lines("zonetransfer.me\nnsztm1.digi.ninja\nnsztm2.digi.ninja", "");
    scope.active_phase = true;
    let (n, sink) = net(scope);
    let dns = HickoryDns::new(&DnsConfig::default(), &n).unwrap();
    let rs = foca_net::axfr::axfr(&n, &dns, "zonetransfer.me", Duration::from_secs(20))
        .await
        .unwrap();
    for r in &rs {
        println!(
            "{} ok={} записей={} err={:?}",
            r.server,
            r.ok,
            r.records.len(),
            r.error
        );
    }
    assert!(rs.iter().any(|r| r.ok && r.records.len() > 10));
    assert!(sink
        .records()
        .iter()
        .any(|r| r.method == "AXFR" && r.active));
}
