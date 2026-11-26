//! Port scan stage in the engine against local listeners: with the full profile ports are found and
//! stored on the host (with a banner); the passive and standard profiles make no connection
//! attempts; an excluded host (mail.example.test -> 127.0.0.2) gets no attempts either.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use crate::common::*;
use serde_json::{json, Value};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;

/// Spawns a listener that counts connections and optionally sends a greeting.
async fn listener(ip: &str, greet: Option<&'static str>) -> (u16, Arc<AtomicUsize>) {
    let l = TcpListener::bind((ip, 0)).await.unwrap();
    let port = l.local_addr().unwrap().port();
    let n = Arc::new(AtomicUsize::new(0));
    let n2 = n.clone();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = l.accept().await {
            n2.fetch_add(1, Ordering::SeqCst);
            if let Some(g) = greet {
                let _ = s.write_all(g.as_bytes()).await;
            }
            tokio::spawn(async move {
                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                drop(s);
            });
        }
    });
    (port, n)
}

async fn ports_log(e: &Env, id: &str) -> Vec<Value> {
    let log = e
        .call("request_log_get", json!({ "project": id, "limit": 100000 }))
        .await;
    log.as_array()
        .unwrap()
        .iter()
        .filter(|r| r["module"] == "ports")
        .cloned()
        .collect()
}

struct Stand {
    ssh: (u16, Arc<AtomicUsize>),
    plain: (u16, Arc<AtomicUsize>),
    excluded: (u16, Arc<AtomicUsize>),
}

async fn stand(e: &Env) -> Stand {
    let ssh = listener("127.0.0.1", Some("SSH-2.0-OpenSSH_9.2p1 Debian\r\n")).await;
    let plain = listener("127.0.0.1", None).await;
    let excluded = listener("127.0.0.2", Some("220 mail ESMTP\r\n")).await;
    // custom list: both 127.0.0.1 listeners, the excluded host's port and port 1, which is known closed
    let list = format!("1,{},{},{}", ssh.0, plain.0, excluded.0);
    e.call(
        "settings_set",
        // minimal site brute force in the full profile (this test is about ports)
        json!({ "patch": { "net": { "rps": 0 }, "ports": { "top": 0, "list": list },
            "fuzz": { "max_requests": 3, "max_hosts": 1, "rate": 50 } } }),
    )
    .await;
    Stand {
        ssh,
        plain,
        excluded,
    }
}

fn hits(s: &Stand) -> (usize, usize, usize) {
    (
        s.ssh.1.load(Ordering::SeqCst),
        s.plain.1.load(Ordering::SeqCst),
        s.excluded.1.load(Ordering::SeqCst),
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn passive_and_std_make_no_port_connections() {
    let e = env(0).await;
    let st = stand(&e).await;
    let id = e.project("example.test").await;
    e.passive_scan(&id).await;
    e.call(
        "scan_start",
        json!({ "project": id, "profile": "std", "sources": ["crt", "wayback"] }),
    )
    .await;
    e.wait().await;
    assert_eq!(hits(&st), (0, 0, 0), "the listeners were not contacted");
    assert!(
        ports_log(&e, &id).await.is_empty(),
        "no ports entries in the log"
    );
    let ev = e.events();
    let src: Vec<&Value> = ev
        .iter()
        .filter(|x| x["type"] == "source" && x["id"] == "ports")
        .collect();
    assert!(
        src.iter().all(|x| x["status"] == "off"),
        "the ports source is off outside the active profile: {src:?}"
    );
    let s = e.snap(&id).await;
    for h in s["hosts"].as_array().unwrap() {
        assert!(h["ports_scan"].is_null(), "{h}");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn full_scan_finds_ports_and_skips_excluded_host() {
    let e = env(0).await;
    let st = stand(&e).await;
    let id = e.project("example.test").await;
    e.call(
        "scan_start",
        json!({ "project": id, "profile": "full", "sources": ["crt", "wayback"] }),
    )
    .await;
    e.wait().await;
    let ev = e.events();
    assert!(ev.iter().any(|x| x["type"] == "done"), "scan finished");
    assert!(ev
        .iter()
        .any(|x| x["type"] == "stage" && x["stage"] == "ports"));
    let (ssh, plain, excl) = hits(&st);
    assert!(ssh >= 1 && plain >= 1, "127.0.0.1 listeners: {ssh}/{plain}");
    assert_eq!(
        excl, 0,
        "excluded mail.example.test (127.0.0.2) was not touched"
    );
    let src: Vec<&Value> = ev
        .iter()
        .filter(|x| x["type"] == "source" && x["id"] == "ports")
        .collect();
    assert!(src
        .iter()
        .any(|x| x["status"] == "running" && x["host"].is_string()));
    let last = src.last().unwrap();
    assert_eq!(last["status"], "ok", "{src:?}");
    assert_eq!(last["n"], 2, "{last}");
    // log: only 127.0.0.1, active access
    let log = ports_log(&e, &id).await;
    assert!(!log.is_empty());
    assert!(
        log.iter()
            .all(|r| !r["url"].as_str().unwrap_or("").contains("127.0.0.2")
                && !r["url"].as_str().unwrap_or("").contains("mail.")),
        "{log:?}"
    );
    // project host: ports from the scan; the SSH banner yields OpenSSH 9.2p1
    let s = e.snap(&id).await;
    let h = s["hosts"]
        .as_array()
        .unwrap()
        .iter()
        .find(|h| h["name"] == "example.test")
        .unwrap()
        .clone();
    let ports = h["ports"].as_array().unwrap();
    let p = ports.iter().find(|p| p["port"] == st.ssh.0).unwrap();
    assert_eq!(p["source"], "scan");
    assert_eq!(p["service"], "ssh", "{p}");
    assert_eq!(p["product"], "OpenSSH", "{p}");
    assert!(ports.iter().any(|p| p["port"] == st.plain.0));
    assert!(!ports.iter().any(|p| p["port"] == 1));
    let ps = &h["ports_scan"];
    assert_eq!(ps["open"], 2, "{ps}");
    assert_eq!(ps["scanned"], 4, "{ps}");
    assert!(ps["spec"].as_str().unwrap().starts_with("свой"));
    assert!(h["services"]
        .as_array()
        .unwrap()
        .iter()
        .any(|x| x[0] == format!("{}/tcp", st.ssh.0) && x[2] == "OpenSSH 9.2p1"));
    // www and ns1 share the IP and get the same result without a second scan
    let www = s["hosts"]
        .as_array()
        .unwrap()
        .iter()
        .find(|h| h["name"] == "www.example.test");
    if let Some(w) = www {
        assert_eq!(w["ports_scan"]["open"], 2, "{w}");
    }
    let mail = s["hosts"]
        .as_array()
        .unwrap()
        .iter()
        .find(|h| h["name"] == "mail.example.test");
    if let Some(m) = mail {
        assert!(m["ports_scan"].is_null(), "{m}");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn custom_profile_without_ports_module_does_not_scan() {
    let e = env(0).await;
    let st = stand(&e).await;
    let id = e.project("example.test").await;
    // custom profile with the active fuzz module but without ports
    e.call(
        "scan_start",
        json!({ "project": id, "profile": "custom", "modules": ["crt", "dns", "alive", "fuzz"], "sources": ["crt"] }),
    )
    .await;
    e.wait().await;
    assert_eq!(hits(&st), (0, 0, 0));
    assert!(ports_log(&e, &id).await.is_empty());
    // custom profile with ports only: active level, the scan runs
    e.call(
        "scan_start",
        json!({ "project": id, "profile": "custom", "modules": ["crt", "dns", "alive", "ports"], "sources": ["crt"] }),
    )
    .await;
    e.wait().await;
    let (a, b, c) = hits(&st);
    assert!(a >= 1 && b >= 1 && c == 0, "{a}/{b}/{c}");
}

/// The device network accepts connections on any port (local VPN/AdGuard), so the canaries are
/// open: no ports are recorded, there are no port findings, and the source reports `unreliable` with a clear message.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn accept_all_network_gives_warning_not_findings() {
    for mode in ["canary", "intercept"] {
        let e = env(0).await;
        let st = stand(&e).await;
        let c1 = listener("127.0.0.1", None).await;
        let c2 = listener("127.0.0.1", None).await;
        let patch = if mode == "canary" {
            json!({ "ports": { "canaries": [c1.0, c2.0] } })
        } else {
            json!({ "ports": { "intercept_probe": [format!("127.0.0.1:{}", c1.0)] } })
        };
        e.call("settings_set", json!({ "patch": patch })).await;
        let id = e.project("example.test").await;
        e.call(
            "scan_start",
            json!({ "project": id, "profile": "full", "sources": ["crt"] }),
        )
        .await;
        e.wait().await;
        let ev = e.events();
        let last = ev
            .iter()
            .rfind(|x| x["type"] == "source" && x["id"] == "ports")
            .unwrap()
            .clone();
        assert_eq!(last["status"], "unreliable", "{mode}: {last}");
        assert!(last["error"]
            .as_str()
            .unwrap()
            .contains("Скан портов недостоверен"));
        assert_eq!(
            last["unreliable"]["intercept"],
            mode == "intercept",
            "{last}"
        );
        let (ssh, plain, _) = hits(&st);
        assert_eq!((ssh, plain), (0, 0), "{mode}: the main scan was skipped");
        let s = e.snap(&id).await;
        let h = s["hosts"]
            .as_array()
            .unwrap()
            .iter()
            .find(|h| h["name"] == "example.test")
            .unwrap()
            .clone();
        assert!(
            h["ports"]
                .as_array()
                .unwrap()
                .iter()
                .all(|p| p["source"] != "scan"),
            "{h}"
        );
        assert_eq!(h["ports_scan"]["unreliable"], mode, "{h}");
        assert!(
            s["findings"]
                .as_array()
                .unwrap()
                .iter()
                .all(|f| f["module"] != "ports"),
            "no port findings"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stage_network_canary_verifies_liveness_without_false_services() {
    let silent = listener("127.0.0.1", None).await;
    let dir = tempfile::tempdir().unwrap();
    let srv = server(0).await;
    let keys = Arc::new(foca_engine::MemoryKeys::new());
    let (engine, events, pause_at) = open_with(dir.path(), &srv.url(), keys.clone(), |cfg| {
        cfg.alive_ports = vec![silent.0];
        cfg.canary = Some(foca_net::canary::CanaryConfig {
            probes: vec![format!("127.0.0.1:{}", silent.0)],
            dns_probe_domain: None,
            tls_probe_host: None,
            timeout: std::time::Duration::from_millis(300),
        });
    });
    let e = Env {
        dir,
        server: srv,
        engine,
        events,
        pause_at,
        keys,
    };
    let id = e.project("example.test").await;
    e.call(
        "scan_start",
        json!({ "project": id, "profile": "std", "sources": ["crt"] }),
    )
    .await;
    e.wait().await;
    let ev = e.events();
    let warns: Vec<&str> = ev
        .iter()
        .filter(|x| x["type"] == "warning")
        .filter_map(|x| x["code"].as_str())
        .collect();
    assert!(warns.contains(&"canary.tcp_intercept"), "{warns:?}");
    assert!(warns.contains(&"liveness.unreliable"), "{warns:?}");

    let snap = e.snap(&id).await;
    let host = snap["hosts"]
        .as_array()
        .unwrap()
        .iter()
        .find(|h| h["name"] == "example.test")
        .unwrap();
    let svcs = host["services"].as_array().unwrap();
    let silent_svc = format!("{}/tcp", silent.0);
    assert!(
        svcs.iter().all(|s| s[0] != silent_svc),
        "silent accept-all listener must not appear as a verified service: {svcs:?}"
    );
}

/// Names added through `scope_add_hosts` whose address is shared with names of other owners are not
/// port-scanned: the address is recorded as "no probe" and the host card carries the reason.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bulk_added_names_on_shared_addresses_are_not_port_scanned() {
    let e = env(0).await;
    let st = stand(&e).await;
    let id = e.project("example.test").await;
    // the standard profile resolves the zone (www, ns1) without touching ports
    e.call(
        "scan_start",
        json!({ "project": id, "profile": "std", "sources": ["crt", "wayback"] }),
    )
    .await;
    e.wait().await;
    // only the apex is in scope; www/ns1 share its address
    e.call(
        "scope_set",
        json!({ "project": id, "scope": { "targets": [{ "v": "https://example.test/", "type": "url" }] } }),
    )
    .await;
    let r = e
        .call(
            "scope_add_hosts",
            json!({ "project": id, "hosts": ["www.example.test"] }),
        )
        .await;
    assert_eq!(r["added"], json!(["www.example.test"]), "{r}");
    let np = r["no_probe"].as_array().unwrap();
    assert!(
        np.iter()
            .any(|x| x["ip"] == "127.0.0.1" && x["kind"] == "shared"),
        "{r}"
    );
    e.clear_events();
    e.call(
        "scan_start",
        json!({ "project": id, "profile": "full", "targets": ["www.example.test"], "sources": ["crt"] }),
    )
    .await;
    e.wait().await;
    let (ssh, plain, _) = hits(&st);
    assert_eq!(
        (ssh, plain),
        (0, 0),
        "the shared address was not port-scanned"
    );
    let ev = e.events();
    let last = ev
        .iter()
        .rfind(|x| x["type"] == "source" && x["id"] == "ports")
        .unwrap()
        .clone();
    assert!(
        last["error"]
            .as_str()
            .unwrap_or("")
            .contains("без скана портов"),
        "{last}"
    );
    let s = e.snap(&id).await;
    let www = s["hosts"]
        .as_array()
        .unwrap()
        .iter()
        .find(|h| h["name"] == "www.example.test")
        .unwrap()
        .clone();
    assert!(www["ports_scan"]["no_probe"].is_string(), "{www}");
}

/// A "no probe" address (here: shared by names of the bulk-added host) gets no TCP connection
/// from any stage: neither the network-stage liveness check nor TLS inspection, site brute force
/// or the port scan, with the standard and the full profile.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn no_probe_addresses_get_no_liveness_or_tls_connections() {
    let probe = listener("127.0.0.1", None).await;
    let dir = tempfile::tempdir().unwrap();
    let srv = server(0).await;
    let keys = Arc::new(foca_engine::MemoryKeys::new());
    let (engine, events, pause_at) = open_with(dir.path(), &srv.url(), keys.clone(), |cfg| {
        cfg.alive_ports = vec![probe.0];
        cfg.tls_ports = vec![probe.0];
    });
    let e = Env {
        dir,
        server: srv,
        engine,
        events,
        pause_at,
        keys,
    };
    e.call(
        "settings_set",
        json!({ "patch": { "net": { "rps": 0 }, "ports": { "top": 0, "list": probe.0.to_string() },
            "fuzz": { "max_requests": 3, "max_hosts": 1, "rate": 50 } } }),
    )
    .await;
    let id = e.project("example.test").await;
    // the standard profile resolves the zone (www, ns1 on the apex address); liveness may touch it
    e.call(
        "scan_start",
        json!({ "project": id, "profile": "std", "sources": ["crt", "wayback"] }),
    )
    .await;
    e.wait().await;
    e.call(
        "scope_set",
        json!({ "project": id, "scope": { "targets": [{ "v": "https://example.test/", "type": "url" }] } }),
    )
    .await;
    let r = e
        .call(
            "scope_add_hosts",
            json!({ "project": id, "hosts": ["www.example.test"] }),
        )
        .await;
    assert!(
        r["no_probe"]
            .as_array()
            .unwrap()
            .iter()
            .any(|x| x["ip"] == "127.0.0.1"),
        "{r}"
    );
    for profile in ["std", "full"] {
        let before = probe.1.load(Ordering::SeqCst);
        e.call(
            "scan_start",
            json!({ "project": id, "profile": profile, "targets": ["www.example.test"], "sources": ["crt"] }),
        )
        .await;
        e.wait().await;
        assert_eq!(
            probe.1.load(Ordering::SeqCst) - before,
            0,
            "{profile}: TCP connections to a no-probe address"
        );
    }
}
