//! Quick tools (Toolbox) on the offline stand: no project is created, nothing is written to
//! the project store, every tool answers within its 5 s budget, network tools report partial
//! results on timeout, and `tool_host` never leaves the requested host.

use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::common::*;
use foca_net::dns::{RType, StaticDns};
use foca_net::testserver::{TestResponse, TestServer};
use serde_json::{json, Value};

const BUDGET: Duration = Duration::from_secs(5);

async fn timed(e: &foca_engine::Engine, cmd: &str, args: Value) -> Value {
    let t0 = Instant::now();
    let v = e
        .invoke(cmd, args.clone())
        .await
        .unwrap_or_else(|err| panic!("{cmd} {args}: {err}"));
    let took = t0.elapsed();
    assert!(took < BUDGET, "{cmd} took {took:?}");
    assert!(v["elapsed_ms"].as_u64().unwrap() < 5000, "{v}");
    v
}

fn projects_dir_entries(dir: &std::path::Path) -> usize {
    std::fs::read_dir(dir)
        .map(|r| {
            r.filter_map(Result::ok)
                .filter(|e| e.path().extension().is_some_and(|x| x == "foca"))
                .count()
        })
        .unwrap_or(0)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn file_tool_parses_without_a_project_or_network() {
    let e = env(0).await;
    let before = e.call("project_list", json!({})).await;
    let pdf = corpus_dir().join("pdf/report.pdf");
    let v = timed(
        &e.engine,
        "tool_file",
        json!({ "path": pdf.to_string_lossy() }),
    )
    .await;
    assert_eq!(v["partial"], false, "{v}");
    assert_eq!(v["format"], "pdf");
    assert!(v["sha256"].as_str().unwrap().len() == 64);
    for k in [
        "metadata",
        "forensics",
        "pii",
        "bad_redactions",
        "secrets",
        "findings",
        "grade",
    ] {
        assert!(!v[k].is_null(), "{k} missing: {v}");
    }
    assert!(v["grade"]["grade"].is_string());
    assert_eq!(v["clean_with"]["cmd"], "doc_clean");
    assert_eq!(v["requests"], json!([]));

    // base64 data from the share sheet / picker cache, with a secret in the text
    let docx = std::fs::read(corpus_dir().join("ooxml/contract.docx")).unwrap();
    let v = timed(
        &e.engine,
        "tool_file",
        json!({ "data": foca_core::b64::encode(&docx), "name": "../x/contract.docx" }),
    )
    .await;
    assert_eq!(v["name"], "contract.docx");
    assert_eq!(v["ext"], "docx");
    assert!(v["clean_with"].is_null());
    // secrets in full (the toolbox shows what the file holds)
    for s in v["secrets"].as_array().unwrap() {
        assert!(s["value"].is_string() && s.get("mask").is_none());
    }

    // nothing was created: same project list, no project files, empty request journal
    assert_eq!(e.call("project_list", json!({})).await, before);
    assert_eq!(projects_dir_entries(e.dir.path()), 0);
    assert!(e.server.requests().is_empty());

    let err = e
        .err("tool_file", json!({ "path": "/nonexistent/x.pdf" }))
        .await;
    assert_eq!(err.code, "not_found");
    let err = e.err("tool_file", json!({ "data": "%%%" })).await;
    assert_eq!(err.code, "bad_args");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn secret_tool_is_local_and_never_echoes_the_value() {
    let e = env(0).await;
    // Default (hibp_opt_in omitted/false): local only, 0 network requests.
    let v = timed(
        &e.engine,
        "tool_secret",
        json!({ "value": "AKIAQ7XK2M9PLR4TZW8N" }),
    )
    .await;
    assert_eq!(v["hibp"]["status"], "not_requested");
    assert_eq!(v["requests"], json!([]));
    assert!(v.get("detected").is_some(), "{v}");
    assert!(!v.to_string().contains("Q7XK2M9P"));
    assert!(e.server.requests().is_empty());
    assert_eq!(e.call("tool_log", json!({})).await, json!([]));

    // Explicit opt-in: sends ONLY the 5-char SHA-1 prefix ("5BAA6") of "password" via /range/5BAA6.
    // The mock server in common::server returns match count 12345 for 1E4C9B93...FD8.
    let raw_pw = "password";
    let full_sha1 = foca_net::hibp::sha1_hex_upper(raw_pw.as_bytes());
    let (prefix, suffix) = full_sha1.split_at(5);
    let v = timed(
        &e.engine,
        "tool_secret",
        json!({ "value": raw_pw, "hibp_opt_in": true }),
    )
    .await;
    assert_eq!(v["score"], 0, "{v}");
    assert_eq!(v["hibp"]["status"], "ok", "{v}");
    assert_eq!(v["hibp"]["pwned"], true, "{v}");
    assert_eq!(v["hibp"]["count"], 12345, "{v}");
    assert_eq!(v["hibp"]["prefix"], prefix, "{v}");
    assert_eq!(v["partial"], false, "{v}");
    assert!(
        !v.to_string().contains(suffix),
        "full suffix leaked in response"
    );

    let reqs = v["requests"].as_array().unwrap();
    assert_eq!(reqs.len(), 1, "{reqs:?}");
    assert_eq!(reqs[0]["module"], "hibp");
    assert_eq!(reqs[0]["access"], "passive");
    assert!(reqs[0]["url"]
        .as_str()
        .unwrap()
        .ends_with(&format!("/range/{prefix}")));
    assert!(!reqs.iter().any(|r| r.to_string().contains(raw_pw)));
    assert!(!reqs.iter().any(|r| r.to_string().contains(suffix)));

    let tlog = e.call("tool_log", json!({})).await;
    assert_eq!(tlog[0]["tool"], "secret");
    assert!(!tlog.to_string().contains(raw_pw));
    assert!(!tlog.to_string().contains(suffix));
    // clearing the journal reports how many records went
    let n = tlog.as_array().unwrap().len();
    assert!(n > 0);
    let cl = e.call("tool_log_clear", json!({})).await;
    assert_eq!(cl, json!({ "ok": true, "removed": n }));
    assert_eq!(e.call("tool_log", json!({})).await, json!([]));
    assert_eq!(e.call("tool_log_clear", json!({})).await["removed"], 0);
    // Still no project created.
    assert_eq!(e.call("project_list", json!({})).await, json!([]));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn secret_hibp_check_sends_only_prefix_and_audits_request_log() {
    let dir = tempfile::tempdir().unwrap();
    let seen = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
    let seen_srv = seen.clone();

    // First import into an isolated env to learn the extracted secret and compute its mock HIBP response.
    let (raw_secret, target_prefix, target_suffix) = {
        let probe = env(0).await;
        let pid = probe.project("probe").await;
        probe
            .call(
                "doc_import",
                json!({ "project": pid, "paths": [corpus_dir().join("ooxml/contract.docx").to_string_lossy()] }),
            )
            .await;
        let snap = probe.snap(&pid).await;
        let sid = snap["secrets"][0]["id"].clone();
        let rev = probe
            .call("secret_reveal", json!({ "project": pid, "id": sid }))
            .await;
        let raw = rev["value"].as_str().unwrap().to_string();
        let h = foca_net::hibp::sha1_hex_upper(raw.as_bytes());
        (raw, h[..5].to_string(), h[5..].to_string())
    };

    let pfx = target_prefix.clone();
    let sfx = target_suffix.clone();
    let srv = TestServer::start(move |r| {
        seen_srv.lock().unwrap().push(r.path().to_string());
        if r.path() == format!("/range/{pfx}") {
            TestResponse::ok(format!("{sfx}:42\n").into_bytes())
        } else {
            TestResponse::status(404)
        }
    })
    .await;
    let base = srv.url();
    let (en, _, _) = open_with(
        dir.path(),
        &base,
        Arc::new(foca_engine::MemoryKeys::new()),
        |c| {
            c.endpoints.sources.insert("hibp".into(), base.clone());
        },
    );
    let p = en
        .invoke(
            "project_create",
            json!({
                "name": "hibp-proj",
                "targets": [{ "v": "example.test", "type": "domain" }],
                "excludes": []
            }),
        )
        .await
        .unwrap();
    let pid = p["id"].as_str().unwrap().to_string();
    en.invoke(
        "doc_import",
        json!({ "project": pid, "paths": [corpus_dir().join("ooxml/contract.docx").to_string_lossy()] }),
    )
    .await
    .unwrap();
    let snap = en
        .invoke("project_snapshot", json!({ "id": pid }))
        .await
        .unwrap();
    let sec_id = snap["secrets"][0]["id"].clone();
    // Before explicit opt-in check, 0 HIBP requests happened automatically.
    assert!(seen.lock().unwrap().is_empty());

    let res = en
        .invoke("secret_hibp_check", json!({ "project": pid, "id": sec_id }))
        .await
        .unwrap();
    assert_eq!(res["pwned"], true, "{res}");
    assert_eq!(res["count"], 42, "{res}");
    assert_eq!(res["prefix"], target_prefix, "{res}");
    assert!(!res.to_string().contains(&raw_secret));
    assert!(!res.to_string().contains(&target_suffix));

    let log = en
        .invoke("request_log_get", json!({ "project": pid, "limit": 100 }))
        .await
        .unwrap();
    let arr = log.as_array().unwrap();
    assert_eq!(arr.len(), 1, "{arr:?}");
    assert_eq!(arr[0]["module"], "hibp");
    assert_eq!(arr[0]["access"], "passive");
    assert!(arr[0]["url"]
        .as_str()
        .unwrap()
        .ends_with(&format!("/range/{target_prefix}")));
    let log_str = log.to_string();
    assert!(
        !log_str.contains(&raw_secret),
        "secret leaked into request_log"
    );
    assert!(
        !log_str.contains(&target_suffix),
        "full sha1 suffix leaked into request_log"
    );
}

fn mail_zone() -> StaticDns {
    StaticDns::new()
        .add("weak.test", RType::TXT, &["v=spf1 ~all"])
        .add("weak.test", RType::MX, &["10 mx.weak.test"])
        .add("_dmarc.weak.test", RType::TXT, &["v=DMARC1; p=none"])
        .add(
            "strict.test",
            RType::TXT,
            &["v=spf1 include:_spf.google.com -all"],
        )
        .add("strict.test", RType::MX, &["10 mx1.strict.test"])
        .add("strict.test", RType::CAA, &["0 issue \"letsencrypt.org\""])
        .add(
            "_dmarc.strict.test",
            RType::TXT,
            &["v=DMARC1; p=reject; rua=mailto:dmarc@strict.test"],
        )
        .add(
            "google._domainkey.strict.test",
            RType::TXT,
            &["v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtest"],
        )
        .add(
            "_mta-sts.strict.test",
            RType::TXT,
            &["v=STSv1; id=20261101"],
        )
        .add(
            "_smtp._tls.strict.test",
            RType::TXT,
            &["v=TLSRPTv1; rua=mailto:tls@strict.test"],
        )
        .add(
            "default._bimi.strict.test",
            RType::TXT,
            &["v=BIMI1; l=https://strict.test/logo.svg"],
        )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn mail_tool_rates_spoofing_risk() {
    let dir = tempfile::tempdir().unwrap();
    let srv = TestServer::start(|r| {
        if r.path() == "/.well-known/mta-sts.txt" {
            return TestResponse::ok(
                b"version: STSv1\nmode: enforce\nmx: mx1.strict.test\nmax_age: 86400\n".to_vec(),
            );
        }
        TestResponse::status(404)
    })
    .await;
    let base = srv.url();
    let (en, _ev, _) = open_with(
        dir.path(),
        &base,
        Arc::new(foca_engine::MemoryKeys::new()),
        |c| {
            c.dns = Some(Arc::new(mail_zone()));
            c.endpoints.sources.insert("mta_sts".into(), base.clone());
        },
    );
    let v = timed(&en, "tool_mail_domain", json!({ "domain": "weak.test" })).await;
    assert_eq!(v["risk"]["level"], "high", "{v}");
    assert!(!v["risk"]["reasons"].as_array().unwrap().is_empty());
    assert_eq!(v["partial"], false);
    assert_eq!(v["mta_sts"]["fetch"]["status"], "skipped");

    let v = timed(
        &en,
        "tool_mail_domain",
        json!({ "domain": "postmaster@Strict.TEST" }),
    )
    .await;
    assert_eq!(v["domain"], "strict.test");
    assert_eq!(v["risk"]["level"], "low", "{v}");
    assert_eq!(v["dkim"]["selectors"], json!(["google"]));
    assert_eq!(v["mta_sts"]["fetch"]["status"], "ok", "{v}");
    assert_eq!(v["mta_sts"]["policy"]["mode"], "enforce");
    assert!(v["bimi"].is_object());
    assert_eq!(v["caa"][0]["value"], "letsencrypt.org");
    // the policy file is the only HTTP request, logged with the toolbox module
    let reqs = v["requests"].as_array().unwrap();
    assert_eq!(reqs.len(), 1, "{reqs:?}");
    assert_eq!(reqs[0]["module"], "mail");
    assert_eq!(srv.hits("/.well-known/mta-sts.txt"), 1);
    let log = en.invoke("tool_log", json!({})).await.unwrap();
    assert_eq!(log[0]["tool"], "mail");
    assert_eq!(
        en.invoke("project_list", json!({})).await.unwrap(),
        json!([])
    );

    let err = en
        .invoke("tool_mail_domain", json!({ "domain": "localhost" }))
        .await
        .unwrap_err();
    assert_eq!(err.code, "bad_args");
}

/// A resolver that never answers: the tool must return a partial result on time.
struct HangDns;

impl foca_net::dns::DnsLookup for HangDns {
    fn lookup<'a>(
        &'a self,
        _name: &'a str,
        _t: RType,
    ) -> foca_net::BoxFuture<'a, Result<foca_net::dns::DnsAnswer, foca_net::NetError>> {
        Box::pin(async {
            tokio::time::sleep(Duration::from_secs(60)).await;
            Err(foca_net::NetError::Parse("unreachable".into()))
        })
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn mail_tool_times_out_honestly() {
    let dir = tempfile::tempdir().unwrap();
    let (en, _ev, _) = open_with(
        dir.path(),
        "http://127.0.0.1:9",
        Arc::new(foca_engine::MemoryKeys::new()),
        |c| c.dns = Some(Arc::new(HangDns)),
    );
    let t0 = Instant::now();
    let v = en
        .invoke(
            "tool_mail_domain",
            json!({ "domain": "slow.test", "timeout_ms": 1500 }),
        )
        .await
        .unwrap();
    assert!(t0.elapsed() < Duration::from_secs(3), "{:?}", t0.elapsed());
    assert_eq!(v["partial"], true);
    assert_eq!(v["risk"]["level"], "unknown");
    assert!(v["incomplete"].as_array().unwrap().len() >= 2);
}

async fn site() -> TestServer {
    TestServer::start(|r| match r.path() {
        "/" => TestResponse::ok(
            br#"<html><head><link rel="icon" href="/static/icon.png">
<script src="/js/jquery-1.8.2.min.js"></script></head><body>ok</body></html>"#
                .to_vec(),
        )
        .header("server", "nginx/1.18.0")
        .header("x-powered-by", "PHP/7.2.1")
        .header("content-type", "text/html"),
        "/static/icon.png" => TestResponse::ok(vec![0x89, b'P', b'N', b'G', 1, 2, 3, 4]),
        "/away" => TestResponse::redirect(302, "http://elsewhere.test/"),
        "/slow" => TestResponse::ok(b"late".to_vec()).delay(Duration::from_secs(8)),
        _ => TestResponse::status(404),
    })
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn host_tool_reads_headers_technologies_and_favicon() {
    let e = env(0).await;
    let s = site().await;
    let url = format!("{}/", s.url());
    let v = timed(&e.engine, "tool_host", json!({ "url": url })).await;
    assert_eq!(v["status"], 200, "{v}");
    assert_eq!(v["steps"]["page"]["status"], "ok");
    assert_eq!(v["steps"]["tls"]["status"], "skipped");
    assert_eq!(v["partial"], false);
    let techs: Vec<&str> = v["technologies"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|t| t["name"].as_str())
        .collect();
    assert!(
        techs.iter().any(|t| t.eq_ignore_ascii_case("nginx")),
        "{techs:?}"
    );
    assert!(v["header_issues"].as_array().unwrap().len() >= 2, "{v}");
    assert!(v["favicon"]["mmh3"].is_number(), "{v}");
    assert_eq!(s.hits("/static/icon.png"), 1);
    // exactly two GETs to this host: the page and the icon
    let reqs = v["requests"].as_array().unwrap();
    assert_eq!(reqs.len(), 2, "{reqs:?}");
    assert!(reqs
        .iter()
        .all(|r| r["host"] == "127.0.0.1" && r["method"] == "GET"));
    assert!(e.server.requests().is_empty(), "no other service contacted");
    assert_eq!(projects_dir_entries(e.dir.path()), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn host_tool_stays_on_the_host_and_times_out() {
    let e = env(0).await;
    let s = site().await;
    // a redirect to another host is refused by the scope (logged as blocked, never sent)
    let v = timed(
        &e.engine,
        "tool_host",
        json!({ "url": format!("{}/away", s.url()) }),
    )
    .await;
    assert_eq!(v["steps"]["page"]["status"], "error", "{v}");
    let reqs = v["requests"].as_array().unwrap();
    assert!(
        reqs.iter()
            .filter(|r| r["host"] == "elsewhere.test")
            .all(|r| r["blocked"] == true),
        "{reqs:?}"
    );
    // a hung page: the budget ends the call with a partial result
    let t0 = Instant::now();
    let v = e
        .call(
            "tool_host",
            json!({ "url": format!("{}/slow", s.url()), "timeout_ms": 1500 }),
        )
        .await;
    assert!(t0.elapsed() < Duration::from_secs(3), "{:?}", t0.elapsed());
    assert_eq!(v["partial"], true, "{v}");
    assert_eq!(v["steps"]["page"]["status"], "timeout");
    // TLS on a closed port fails fast and the page error is reported, not hidden
    let v = timed(
        &e.engine,
        "tool_host",
        json!({ "url": "https://127.0.0.1:9/" }),
    )
    .await;
    assert_eq!(v["steps"]["tls"]["status"], "error", "{v}");
    assert_eq!(v["steps"]["page"]["status"], "error");
    let err = e.err("tool_host", json!({ "url": "ftp://x.test/" })).await;
    assert_eq!(err.code, "bad_args");
}

/// `cve_list`: the full CVE list of a product version from the embedded NVD table, one page
/// at a time, with ranges, fixed versions and the document-year limit.
#[tokio::test]
async fn cve_list_pages_through_the_offline_table() {
    let e = env(0).await;
    let q = |extra: Value| {
        let mut a = json!({ "product": "f5:nginx", "version": "1.18.0" });
        for (k, v) in extra.as_object().unwrap() {
            a[k] = v.clone();
        }
        a
    };
    let p = e.call("cve_list", q(json!({ "limit": 5 }))).await;
    let total = p["total"].as_u64().unwrap();
    assert!(total > 5, "{p}");
    assert!(p["version_specific"].as_bool().unwrap());
    let items = p["items"].as_array().unwrap();
    assert_eq!(items.len(), 5);
    assert!(items[0]["id"].as_str().unwrap().starts_with("CVE-"));
    assert!(items.iter().all(|r| r["year"].as_u64().unwrap() > 1999));
    assert!(items.iter().any(|r| r["range"].is_string()), "{p}");
    let next = e
        .call("cve_list", q(json!({ "limit": 5, "offset": 5 })))
        .await;
    assert_ne!(next["items"][0]["id"], items[0]["id"]);
    let old = e.call("cve_list", q(json!({ "until_year": 2020 }))).await;
    assert!(old["total"].as_u64().unwrap() < total, "{old}");
    let any = e
        .call("cve_list", json!({ "product": "f5:nginx", "limit": 3 }))
        .await;
    assert_eq!(any["version_specific"], false);
    let none = e
        .err("cve_list", json!({ "product": "nobody:nothing" }))
        .await;
    assert_eq!(none.code, "not_found");
}
