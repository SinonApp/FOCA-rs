//! Host spelling variants against scope exclusions (TouchesTarget / Active): case, trailing dot,
//! port, IP literals (hex/decimal/IPv4-mapped IPv6), IDN/punycode, a host resolving to an excluded IP.
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;

use foca_core::scope::Scope;
use foca_net::{Access, NetClient, NetConfig, NetRequest, NullSink};

#[tokio::main]
async fn main() {
    let mut ov: HashMap<String, Vec<IpAddr>> = HashMap::new();
    ov.insert("rebind.example.test".into(), vec!["10.0.0.5".parse().unwrap()]);
    let cfg = NetConfig { host_overrides: ov, retries: 0, global_rps: None, ..Default::default() };
    let (mut scope, errs) = Scope::from_lines(
        "example.test\n10.0.0.0/24\nпример.test",
        "secret.example.test\n10.0.0.5\nтайна.пример.test",
    );
    assert!(errs.is_empty(), "{errs:?}");
    scope.active_phase = true;
    let net = NetClient::new(cfg, scope, Arc::new(NullSink)).unwrap();
    let cases = [
        "http://SECRET.Example.TEST./x",
        "http://secret.example.test:8443/x",
        "http://secret.example.test../x",
        "http://[::ffff:10.0.0.5]/x",
        "http://[::ffff:a00:5]/x",
        "http://0x0a.0.0.5/x",
        "http://167772165/x",
        "http://10.0.5/x",
        "http://012.0.0.05/x",
        "http://xn--80aa0aqw.xn--e1afmkfd.test/x",
        "http://ТАЙНА.пример.test/x",
        "http://rebind.example.test/x",
        "http://ok.example.test/x",
        "http://10.0.0.6/x",
    ];
    for u in cases {
        for acc in [Access::TouchesTarget, Access::active("fuzz")] {
            let r = match NetRequest::get(u, "r1", acc.clone()) {
                Ok(req) => {
                    let host = match req.url.host() {
                        Some(url::Host::Ipv6(a)) => a.to_string(),
                        Some(h) => h.to_string(),
                        None => String::new(),
                    };
                    match net.authorize(&host, &acc).await {
                        Ok(_) => format!("ALLOWED (host={host})"),
                        Err(e) => format!("blocked (host={host}): {e}"),
                    }
                }
                Err(e) => format!("bad url: {e}"),
            };
            println!("{:<44} {:<7} {r}", u, acc.label());
        }
    }
}
