//! Parsing of real public API responses (fixtures) and DNS/mail/takeover logic on a fixture zone.

use std::sync::Arc;

use foca_core::Scope;
use foca_net::ct::{self, CtEndpoints};
use foca_net::dns::{dns_report, StaticDns};
use foca_net::rdap::{self, RdapEndpoints};
use foca_net::testserver::{TestResponse, TestServer};
use foca_net::{MemorySink, NetClient, NetConfig};

const CRTSH: &str = include_str!("fixtures/crtsh.json");
const CERTSPOTTER: &str = include_str!("fixtures/certspotter.json");
const RDAP: &str = include_str!("fixtures/rdap_domain.json");
const RIPE: &str = include_str!("fixtures/ripe_network_info.json");
const ZONE: &str = include_str!("fixtures/contoso_zone.txt");

fn net() -> (NetClient, Arc<MemorySink>) {
    let sink = Arc::new(MemorySink::new());
    let cfg = NetConfig {
        global_rps: None,
        source_rps: Default::default(),
        ..Default::default()
    };
    (
        NetClient::new(cfg, Scope::default(), sink.clone()).unwrap(),
        sink,
    )
}

#[test]
fn real_ct_fixtures() {
    let v = ct::parse_crtsh(CRTSH, "iana.org").unwrap();
    assert!(v.contains(&"www.iana.org".to_string()));
    assert!(v
        .iter()
        .all(|h| h == "iana.org" || h.ends_with(".iana.org")));
    let (v, last) = ct::parse_certspotter(CERTSPOTTER, "example.com").unwrap();
    assert!(v.contains(&"example.com".to_string()));
    assert!(
        !v.iter().any(|h| h.ends_with("example.net")),
        "foreign SANs are dropped"
    );
    assert!(last.is_some());
}

#[test]
fn real_rdap_fixtures() {
    let d = rdap::parse_rdap_domain(RDAP).unwrap();
    assert_eq!(d.domain, "example.com");
    assert!(d
        .registrar
        .unwrap()
        .contains("Internet Assigned Numbers Authority"));
    assert!(!d.nameservers.is_empty());
    let (prefix, asns) = rdap::parse_ripe_network_info(RIPE).unwrap();
    assert_eq!(prefix.as_deref(), Some("192.0.43.0/24"));
    assert_eq!(asns, vec![16876, 40528]);
}

#[tokio::test]
async fn ct_and_rdap_over_http() {
    let srv = TestServer::start(|r| match r.path() {
        "/" => TestResponse::ok(CRTSH),
        "/v1/issuances" if r.query("after").is_none() => TestResponse::ok(CERTSPOTTER),
        "/v1/issuances" => TestResponse::ok("[]"),
        "/data/network-info/data.json" => TestResponse::ok(RIPE),
        "/data/as-overview/data.json" => TestResponse::ok(r#"{"data":{"holder":"ICANN-DC"}}"#),
        "/ip/192.0.43.8" => TestResponse::ok(r#"{"name":"ICANN","startAddress":"192.0.43.0","endAddress":"192.0.43.255","country":"US"}"#),
        "/domain/example.com" => TestResponse::ok(RDAP),
        _ => TestResponse::status(404),
    })
    .await;
    let (net, sink) = net();
    let ep = CtEndpoints {
        crtsh: srv.url(),
        certspotter: srv.url(),
    };
    let a = ct::crtsh_subdomains(&net, &ep, "iana.org").await.unwrap();
    assert!(a.len() >= 5);
    let b = ct::certspotter_subdomains(&net, &ep, "example.com", None, 3)
        .await
        .unwrap();
    assert!(b.contains(&"www.example.com".to_string()) || b.contains(&"example.com".to_string()));
    let rep = RdapEndpoints {
        ripestat: srv.url(),
        rdap: srv.url(),
    };
    let info = rdap::ip_info(&net, &rep, "192.0.43.8".parse().unwrap())
        .await
        .unwrap();
    assert_eq!(info.holder.as_deref(), Some("ICANN-DC"));
    assert_eq!(info.country.as_deref(), Some("US"));
    let d = rdap::domain_info(&net, &rep, "example.com").await.unwrap();
    assert_eq!(d.domain, "example.com");
    assert!(sink.records().iter().all(|r| !r.active));
}

#[tokio::test]
async fn dns_report_on_zone_fixture() {
    let dns = StaticDns::from_zone_text(ZONE);
    let r = dns_report(&dns, "contoso.example").await;
    assert!(!r.nxdomain);
    assert_eq!(r.records["A"], vec!["192.0.2.10"]);
    assert_eq!(r.records["NS"].len(), 2);
    assert_eq!(r.ptr["192.0.2.10"], vec!["web01.contoso.example"]);
    assert_eq!(r.srv.len(), 1);
    // mail: ~all plus DMARC p=none means spoofing is possible
    assert!(r.mail.spoofable);
    let ids: Vec<_> = r.mail.issues.iter().map(|i| i.id.as_str()).collect();
    assert!(
        ids.contains(&"dmarc_none") && ids.contains(&"spf_softfail"),
        "{ids:?}"
    );
    assert_eq!(r.mail.dkim_selectors, vec!["selector1"]);
    assert_eq!(
        r.mail.spf.as_ref().unwrap().includes,
        vec!["spf.protection.outlook.com"]
    );
    // www points to a non-existent azurewebsites host: dangling CNAME (Azure)
    assert_eq!(r.dangling.len(), 1);
    assert_eq!(r.dangling[0].host, "www.contoso.example");
    assert_eq!(r.dangling[0].provider.as_deref(), Some("Azure"));
    let nx = dns_report(&dns, "nope.ua").await;
    assert!(nx.nxdomain);
}
