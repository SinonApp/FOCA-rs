//! Offline tests of the fuzzer core: calibration (soft-404 with a random body, everything
//! redirected to /login, 403 for everything), auto-stop on a run of 429s, out-of-scope
//! redirects, the request budget (also one budget shared by fuzzers running together),
//! pause/stop, active requests being denied, and loading a wordlist from the registry with
//! SHA-256 verification.

mod common;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use common::*;
use foca_fuzz::{
    ContentSpec, FuzzConfig, FuzzControl, FuzzReport, FuzzTask, Fuzzer, Module, StopReason,
    Template, Wordlist,
};
use foca_net::testserver::{TestResponse, TestServer};
use url::Url;

const WORDS: &str =
    "admin\nbackup\nconfig.php\nreal.pdf\nold\ntest.bak\nimages\nupload.php\nindex.bak\nportal\n";

async fn content_run(srv: &TestServer, words: &str, cfg: FuzzConfig) -> FuzzReport {
    let (net, _sink) = client("127.0.0.1", "", true);
    let base = format!("{}/", srv.url());
    let mut task = FuzzTask::new(Url::parse(&base).unwrap(), vec![Module::Content]);
    task.content = Some(ContentSpec {
        template: Template::path(&format!("{base}FUZZ")),
        wordlist: Wordlist::from_text("t", words),
        extensions: vec![],
    });
    Fuzzer::new(net, cfg).run(&task).await
}

fn real_pdf() -> TestResponse {
    TestResponse::ok("%PDF-1.4\n% real\n1 0 obj << >> endobj\n%%EOF\n")
        .header("Content-Type", "application/pdf")
}

fn paths(r: &FuzzReport) -> Vec<String> {
    r.hits
        .iter()
        .map(|h| Url::parse(&h.url).unwrap().path().to_string())
        .collect()
}

#[tokio::test]
async fn calibration_soft404_random_body() {
    let srv = TestServer::start(|r| match r.path() {
        "/real.pdf" => real_pdf(),
        p => soft404(p),
    })
    .await;
    let rep = content_run(&srv, WORDS, fast_cfg()).await;
    assert_eq!(paths(&rep), vec!["/real.pdf"], "{:?}", rep.hits);
    assert_eq!(rep.stop, StopReason::Completed);
    assert!(rep.stats.filtered_calibration >= 9, "{:?}", rep.stats);
    // Discarded responses carry reason, size and type for the request log notes.
    use foca_fuzz::FilterReason;
    let soft: Vec<_> = rep
        .filtered
        .iter()
        .filter(|f| f.reason == FilterReason::Soft404)
        .collect();
    assert_eq!(soft.len() as u64, rep.stats.filtered_calibration);
    assert!(soft
        .iter()
        .all(|f| f.status == 200 && f.size > 0 && !f.url.ends_with("/real.pdf")));
    assert!(rep
        .filtered
        .iter()
        .any(|f| f.reason == FilterReason::Calibration));
    assert_eq!(
        rep.filtered
            .iter()
            .filter(|f| f.reason == FilterReason::Calibration)
            .count() as u64,
        rep.stats.calibration_requests
    );

    // Without calibration the same site yields false findings, so calibration is mandatory.
    let rep = content_run(
        &srv,
        WORDS,
        FuzzConfig {
            calibrate: false,
            ..fast_cfg()
        },
    )
    .await;
    assert!(rep.hits.len() >= 9, "{:?}", rep.hits.len());
}

#[tokio::test]
async fn calibration_redirect_everything_to_login() {
    let srv = TestServer::start(|r| match r.path() {
        "/real.pdf" => real_pdf(),
        "/login" => TestResponse::ok("<html>login</html>"),
        p => TestResponse::redirect(302, &format!("/login?next={p}")),
    })
    .await;
    let rep = content_run(&srv, WORDS, fast_cfg()).await;
    assert_eq!(paths(&rep), vec!["/real.pdf"], "{:?}", rep.hits);
}

#[tokio::test]
async fn calibration_forbidden_everything_no_autostop() {
    let srv = TestServer::start(|r| match r.path() {
        "/real.pdf" => real_pdf(),
        _ => TestResponse {
            status: 403,
            body: b"<html>403 Forbidden</html>".to_vec(),
            ..Default::default()
        },
    })
    .await;
    let mut words = String::from(WORDS);
    for i in 0..40 {
        words.push_str(&format!("w{i}\n"));
    }
    let rep = content_run(&srv, &words, fast_cfg()).await;
    assert_eq!(paths(&rep), vec!["/real.pdf"], "{:?}", rep.hits);
    // 403 is this site's normal response (learned by calibration), not a block.
    assert_eq!(rep.stop, StopReason::Completed);
}

#[tokio::test]
async fn autostop_on_429_series() {
    let n = Arc::new(AtomicUsize::new(0));
    let c = n.clone();
    let srv = TestServer::start(move |_| {
        if c.fetch_add(1, Ordering::SeqCst) < 3 {
            TestResponse::status(404)
        } else {
            TestResponse::status(429).header("Retry-After", "1")
        }
    })
    .await;
    let words: String = (0..300).map(|i| format!("p{i}\n")).collect();
    let cfg = fast_cfg();
    let consecutive = cfg.autostop.consecutive as usize;
    let rep = content_run(&srv, &words, cfg).await;
    match &rep.stop {
        StopReason::Blocked { .. } => {}
        s => panic!("expected auto-stop, got {s:?}"),
    }
    assert!(rep
        .stop
        .message_ru()
        .contains("сайт ограничил запросы: перебор остановлен"));
    let total = srv.requests().len();
    assert!(
        total <= 3 + consecutive + 8,
        "no requests after auto-stop: {total}"
    );
    assert!(rep.hits.is_empty());
}

/// A host that refuses connections is unreachable, not rate limited: its own stop reason and
/// text, never the "site limited requests" one.
#[tokio::test]
async fn unreachable_host_is_not_reported_as_rate_limited() {
    let port = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    let (net, _sink) = client("127.0.0.1", "", true);
    let base = format!("http://127.0.0.1:{port}/");
    let mut task = FuzzTask::new(Url::parse(&base).unwrap(), vec![Module::Content]);
    let words: String = (0..100).map(|i| format!("p{i}\n")).collect();
    task.content = Some(ContentSpec {
        template: Template::path(&format!("{base}FUZZ")),
        wordlist: Wordlist::from_text("t", &words),
        extensions: vec![],
    });
    let rep = Fuzzer::new(net, fast_cfg()).run(&task).await;
    assert!(
        matches!(rep.stop, StopReason::Unreachable { .. }),
        "{:?}",
        rep.stop
    );
    let msg = rep.stop.message_ru();
    assert!(msg.contains("хост недоступен"), "{msg}");
    assert!(!msg.contains("ограничил"), "{msg}");
    assert!(rep.stats.requests < 40, "stops early: {:?}", rep.stats);
}

#[tokio::test]
async fn redirect_out_of_scope_not_followed() {
    let srv = start_site(SiteOpts::default()).await;
    let (net, sink) = client("127.0.0.1", "", true);
    let base = format!("{}/", srv.url());
    let mut task = FuzzTask::new(Url::parse(&base).unwrap(), vec![Module::Content]);
    task.content = Some(ContentSpec {
        template: Template::path(&format!("{base}FUZZ")),
        wordlist: Wordlist::from_text("t", "go\n"),
        extensions: vec![],
    });
    let cfg = FuzzConfig {
        follow_redirects: true,
        ..fast_cfg()
    };
    let rep = Fuzzer::new(net, cfg).run(&task).await;
    assert!(rep.hits.is_empty(), "{:?}", rep.hits);
    let log = sink.records();
    let evil: Vec<_> = log.iter().filter(|r| r.host == "evil.example").collect();
    assert!(!evil.is_empty(), "the redirect hop attempt must be logged");
    assert!(evil.iter().all(|r| r.blocked && r.status.is_none()));
    assert!(rep.stats.skipped_excluded >= 1);
}

#[tokio::test]
async fn budget_and_denied() {
    let srv = start_site(SiteOpts::default()).await;
    let words: String = (0..100).map(|i| format!("p{i}\n")).collect();
    let rep = content_run(
        &srv,
        &words,
        FuzzConfig {
            max_requests: 10,
            ..fast_cfg()
        },
    )
    .await;
    assert_eq!(rep.stop, StopReason::Budget);
    assert!(srv.requests().len() <= 10, "{}", srv.requests().len());

    // A site in the scope exclusions receives no requests at all.
    let srv = start_site(SiteOpts::default()).await;
    let (net, sink) = client("127.0.0.1", "127.0.0.1", true);
    let task = FuzzTask::new(
        Url::parse(&format!("{}/", srv.url())).unwrap(),
        vec![Module::Exposed],
    );
    let rep = Fuzzer::new(net, fast_cfg()).run(&task).await;
    assert!(
        matches!(rep.stop, StopReason::Denied { .. }),
        "{:?}",
        rep.stop
    );
    assert_eq!(srv.requests().len(), 0);
    assert!(sink.records().is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shared_budget_caps_fuzzers_running_together() {
    let srv = start_site(SiteOpts::default()).await;
    let words: String = (0..100).map(|i| format!("p{i}\n")).collect();
    let pool = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let run = |pool: Arc<std::sync::atomic::AtomicU64>| {
        let (net, _sink) = client("127.0.0.1", "", true);
        let base = format!("{}/", srv.url());
        let mut task = FuzzTask::new(Url::parse(&base).unwrap(), vec![Module::Content]);
        task.content = Some(ContentSpec {
            template: Template::path(&format!("{base}FUZZ")),
            wordlist: Wordlist::from_text("t", &words),
            extensions: vec![],
        });
        let cfg = FuzzConfig {
            max_requests: 30,
            ..fast_cfg()
        };
        async move {
            Fuzzer::new(net, cfg)
                .with_shared_budget(pool)
                .run(&task)
                .await
        }
    };
    let (a, b) = tokio::join!(run(pool.clone()), run(pool.clone()));
    assert_eq!(a.stop, StopReason::Budget);
    assert_eq!(b.stop, StopReason::Budget);
    let n = srv.requests().len();
    assert!(n <= 30, "two fuzzers spent more than one budget: {n}");
    assert!(
        a.stats.requests + b.stats.requests <= 30,
        "{} + {}",
        a.stats.requests,
        b.stats.requests
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pause_resume_cancel() {
    let srv = start_site(SiteOpts::default()).await;
    let (net, _sink) = client("127.0.0.1", "", true);
    let base = format!("{}/", srv.url());
    let mut task = FuzzTask::new(Url::parse(&base).unwrap(), vec![Module::Content]);
    task.content = Some(ContentSpec {
        template: Template::path(&format!("{base}FUZZ")),
        wordlist: Wordlist::from_text(
            "t",
            &(0..2000).map(|i| format!("p{i}\n")).collect::<String>(),
        ),
        extensions: vec![],
    });
    let ctl = FuzzControl::new();
    let cfg = FuzzConfig {
        rate: 40.0,
        ..fast_cfg()
    };
    let fz = Fuzzer::new(net, cfg).with_control(ctl.clone());
    let h = tokio::spawn(async move { fz.run(&task).await });
    tokio::time::sleep(Duration::from_millis(300)).await;
    ctl.pause();
    tokio::time::sleep(Duration::from_millis(200)).await;
    let a = srv.requests().len();
    tokio::time::sleep(Duration::from_millis(500)).await;
    let b = srv.requests().len();
    assert!(a > 0);
    assert_eq!(a, b, "no requests while paused");
    ctl.resume();
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(srv.requests().len() > b, "fuzzing resumes after unpausing");
    ctl.cancel();
    let rep = tokio::time::timeout(Duration::from_secs(5), h)
        .await
        .expect("stop is fast")
        .unwrap();
    assert_eq!(rep.stop, StopReason::Cancelled);
    let after = srv.requests().len();
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(srv.requests().len(), after);
}

#[tokio::test]
async fn vhost_template_and_rate_limit() {
    // Rate: 10 requests at 20 req/s take at least ~0.45 s.
    let srv = TestServer::start(|r| {
        if host_of(r) == "intranet.contoso.test" {
            TestResponse::ok("<html><title>Intranet</title></html>")
        } else {
            TestResponse::ok("<html><title>Main</title></html>")
        }
    })
    .await;
    let (net, _sink) = client("127.0.0.1\ncontoso.test", "", true);
    let base = format!("{}/", srv.url());
    let mut task = FuzzTask::new(Url::parse(&base).unwrap(), vec![Module::Content]);
    task.content = Some(ContentSpec {
        template: Template {
            url: base.clone(),
            host: Some("FUZZ.contoso.test".into()),
        },
        wordlist: Wordlist::from_text("t", "www\nintranet\nmail\nftp\nshop\nblog\nm\n"),
        extensions: vec![],
    });
    let t0 = std::time::Instant::now();
    let rep = Fuzzer::new(
        net,
        FuzzConfig {
            rate: 20.0,
            ..fast_cfg()
        },
    )
    .run(&task)
    .await;
    assert!(
        t0.elapsed() >= Duration::from_millis(400),
        "{:?}",
        t0.elapsed()
    );
    assert_eq!(rep.hits.len(), 1, "{:?}", rep.hits);
    assert_eq!(rep.hits[0].host.as_deref(), Some("intranet.contoso.test"));
}

#[tokio::test]
async fn wordlist_download_checks_sha256() {
    let body = "alpha\nbeta\n";
    let srv = TestServer::start(move |_| TestResponse::ok(body)).await;
    let (net, _) = client("", "", false);
    let dir = tempfile::tempdir().unwrap();
    let sha: &'static str =
        Box::leak(foca_fuzz::wordlists::sha256_hex(body.as_bytes()).into_boxed_str());
    let entry = foca_fuzz::wordlists::RemoteList {
        id: "test-list",
        source: "x.txt",
        size: body.len() as u64,
        lines: 2,
        sha256: sha,
    };
    let url = format!("{}/x.txt", srv.url());
    let p = foca_fuzz::wordlists::download(&net, &entry, dir.path(), Some(&url))
        .await
        .unwrap();
    assert_eq!(std::fs::read_to_string(p).unwrap(), body);
    let bad = foca_fuzz::wordlists::RemoteList {
        sha256: "0000000000000000000000000000000000000000000000000000000000000000",
        ..entry
    };
    let e = foca_fuzz::wordlists::download(&net, &bad, dir.path(), Some(&url))
        .await
        .unwrap_err();
    assert!(matches!(
        e,
        foca_fuzz::wordlists::WordlistError::Checksum { .. }
    ));
}

#[tokio::test]
async fn content_recursion_into_found_directory() {
    let srv = start_site(SiteOpts::default()).await;
    let rep = content_run(&srv, "files\nreport_2024.pdf\nnope\n", fast_cfg()).await;
    let p = paths(&rep);
    assert!(p.contains(&"/files/".to_string()), "{p:?}");
    assert!(p.contains(&"/files/report_2024.pdf".to_string()), "{p:?}");
    assert_eq!(rep.stop, StopReason::Completed);
    // Without recursion the fuzzer does not descend.
    let rep = content_run(
        &srv,
        "files\nreport_2024.pdf\n",
        FuzzConfig {
            recursion_depth: 0,
            ..fast_cfg()
        },
    )
    .await;
    assert!(!paths(&rep).contains(&"/files/report_2024.pdf".to_string()));
}

#[tokio::test]
async fn cms_module_uses_cms_wordlist() {
    let srv = TestServer::start(|r| match r.path() {
        "/wp-login.php" => TestResponse::ok("<html><title>Log In</title></html>"),
        "/wp-content/" | "/wp-includes/" => TestResponse::status(403),
        p => soft404(p),
    })
    .await;
    let (net, sink) = client("127.0.0.1", "", true);
    let mut task = FuzzTask::new(
        Url::parse(&format!("{}/", srv.url())).unwrap(),
        vec![Module::Cms],
    );
    task.cms = foca_fuzz::Cms::parse("wordpress");
    let rep = Fuzzer::new(net, fast_cfg()).run(&task).await;
    let p = paths(&rep);
    assert!(p.contains(&"/wp-login.php".to_string()), "{p:?}");
    assert!(rep.hits.iter().all(|h| h.module == Module::Cms));
    assert!(
        sink.len() > 1000,
        "wordlist wordpress.fuzz.txt: {}",
        sink.len()
    );
}

/// Flutter-style SPA shell: the same `index.html` for every path, in two builds of different
/// size; random names with a static extension get a plain 404 (so calibration of `.txt`
/// sees a normal "not found").
fn spa_shell(variant: bool) -> TestResponse {
    let extra = if variant {
        "<script src=\"flutter_bootstrap.js\" async></script>"
    } else {
        ""
    };
    let body = format!(
        "<!DOCTYPE html>\n<html>\n<head>\n  <base href=\"/\">\n  <meta charset=\"UTF-8\">\n  <title>Portal</title>\n  <!--\n    If you are serving your web app in a path other than the root, change the\n    href value below to reflect the base path you are serving from.\n  -->\n  <link rel=\"manifest\" href=\"manifest.json\">\n</head>\n<body>\n  {extra}<script src=\"main.dart.js\" type=\"application/javascript\"></script>\n</body>\n</html>\n"
    );
    TestResponse::ok(body).header("Content-Type", "text/html; charset=utf-8")
}

#[tokio::test]
async fn spa_catch_all_reports_only_real_files() {
    let n = Arc::new(AtomicUsize::new(0));
    let c = n.clone();
    let srv = TestServer::start(move |r| {
        let p = r.path();
        match p {
            "/.env" => TestResponse::ok("APP_ENV=production\nDB_HOST=db.example.test\n")
                .header("Content-Type", "text/plain"),
            "/files/report_2024.pdf" => real_pdf(),
            _ => {
                let name = p.rsplit('/').next().unwrap_or("");
                let static_ext = !name.starts_with('.')
                    && [".txt", ".json", ".js", ".css", ".png"]
                        .iter()
                        .any(|e| name.ends_with(e));
                if static_ext {
                    TestResponse::status(404)
                } else {
                    spa_shell(c.fetch_add(1, Ordering::Relaxed).is_multiple_of(2))
                }
            }
        }
    })
    .await;
    let (net, _sink) = client("127.0.0.1", "", true);
    let base = format!("{}/", srv.url());
    let mut task = FuzzTask::new(
        Url::parse(&base).unwrap(),
        vec![Module::Exposed, Module::Backups, Module::Content],
    );
    task.content = Some(ContentSpec {
        template: Template::path(&format!("{base}FUZZ")),
        wordlist: Wordlist::from_text(
            "t",
            "files/report_2024.pdf\nadmin\n.csv\ndata.csv\nfiles/\n",
        ),
        extensions: vec![],
    });
    let rep = Fuzzer::new(net, fast_cfg()).run(&task).await;
    let mut p = paths(&rep);
    p.sort();
    assert_eq!(p, vec!["/.env", "/files/report_2024.pdf"], "{:?}", rep.hits);
    assert_eq!(rep.stop, StopReason::Completed);
    assert!(rep.stats.filtered_calibration > 100, "{:?}", rep.stats);
}

#[tokio::test]
async fn forbidden_ht_files_do_not_stop_fuzzing() {
    // Apache denies every `.ht*` path with 403; other missing paths are a plain 404.
    let srv = TestServer::start(|r| {
        let name = r.path().rsplit('/').next().unwrap_or("").to_string();
        if name.starts_with(".ht") {
            TestResponse {
                status: 403,
                body: b"<html><title>403 Forbidden</title>Forbidden</html>".to_vec(),
                ..Default::default()
            }
        } else if r.path() == "/real.pdf" {
            real_pdf()
        } else {
            TestResponse::status(404)
        }
    })
    .await;
    let mut words: String = [
        ".hta",
        ".htaccess",
        ".htaccess.bak",
        ".htaccess-dev",
        ".htaccess.old",
        ".htaccess~",
        ".htpasswd",
        ".htpasswd.bak",
        ".htaccess.orig",
        ".htaccess_old",
        ".htgroup",
        ".htusers",
    ]
    .iter()
    .map(|w| format!("{w}\n"))
    .collect();
    for i in 0..30 {
        words.push_str(&format!("p{i}\n"));
    }
    words.push_str("real.pdf\n");
    let cfg = FuzzConfig {
        threads: 1,
        ..fast_cfg()
    };
    let rep = content_run(&srv, &words, cfg).await;
    assert_eq!(rep.stop, StopReason::Completed, "{:?}", rep.stats);
    assert!(
        paths(&rep).contains(&"/real.pdf".to_string()),
        "{:?}",
        rep.hits
    );
}

#[tokio::test]
async fn forbidden_everywhere_after_a_while_stops() {
    // A WAF that starts answering 403 to everything: the control request confirms the block.
    let n = Arc::new(AtomicUsize::new(0));
    let c = n.clone();
    let srv = TestServer::start(move |_| {
        if c.fetch_add(1, Ordering::SeqCst) < 10 {
            TestResponse::status(404)
        } else {
            TestResponse::status(403)
        }
    })
    .await;
    let words: String = (0..300).map(|i| format!("p{i}\n")).collect();
    let rep = content_run(&srv, &words, fast_cfg()).await;
    match &rep.stop {
        StopReason::Blocked { detail } => assert!(detail.contains("HTTP 403"), "{detail}"),
        s => panic!("expected auto-stop, got {s:?}"),
    }
    assert!(srv.requests().len() < 40, "{}", srv.requests().len());
}

#[tokio::test]
async fn challenge_page_stops_at_once() {
    let n = Arc::new(AtomicUsize::new(0));
    let c = n.clone();
    let srv = TestServer::start(move |_| {
        if c.fetch_add(1, Ordering::SeqCst) < 6 {
            TestResponse::status(404)
        } else {
            TestResponse {
                status: 403,
                body: b"<html><title>Attention Required! | Cloudflare</title></html>".to_vec(),
                ..Default::default()
            }
            .header("cf-mitigated", "challenge")
        }
    })
    .await;
    let words: String = (0..300).map(|i| format!("p{i}\n")).collect();
    let cfg = fast_cfg();
    let consecutive = cfg.autostop.consecutive as usize;
    let rep = content_run(&srv, &words, cfg).await;
    assert!(
        matches!(rep.stop, StopReason::Blocked { .. }),
        "{:?}",
        rep.stop
    );
    assert!(srv.requests().len() <= 6 + consecutive + 8);
}
