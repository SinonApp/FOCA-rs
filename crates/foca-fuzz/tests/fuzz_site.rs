//! Offline integration test: a client site with the full set of forgotten files. Everything
//! is found with zero false positives, and the excluded path and host are never requested
//! (checked against both the request log and the server log).

mod common;

use std::sync::{Arc, Mutex};

use common::*;
use foca_fuzz::{
    ContentSpec, FuzzEvent, FuzzTask, Fuzzer, HitKind, Module, StopReason, Template, VhostSpec,
    Wordlist,
};
use url::Url;

async fn full_run(soft404: bool) {
    let srv = start_site(SiteOpts { soft404 }).await;
    let base = format!("{}/", srv.url());
    let (net, sink) = client("127.0.0.1\ncontoso.test", "dev.contoso.test", true);
    let cfg = foca_fuzz::FuzzConfig {
        exclude_paths: vec!["/private".into()],
        ..fast_cfg()
    };
    let mut task = FuzzTask::new(
        Url::parse(&base).unwrap(),
        vec![
            Module::Docs,
            Module::Backups,
            Module::Exposed,
            Module::DirListing,
            Module::Vhost,
            Module::Content,
        ],
    );
    task.current_year = Some(2026);
    task.known_urls = vec![
        base.clone(),
        format!("{base}files/report_2023.pdf"),
        format!("{base}index.php"),
    ];
    task.vhost = Some(VhostSpec {
        domains: vec!["contoso.test".into()],
        wordlist: Wordlist::from_text("t", "www\nintranet\ndev\nmail\nshop\n"),
    });
    task.content = Some(ContentSpec {
        template: Template::path(&format!("{base}FUZZ")),
        wordlist: Wordlist::from_text("t", "private/\nprivate/data.pdf\nprivate\nnothing-here\n"),
        extensions: vec![],
    });
    let events: Arc<Mutex<Vec<FuzzEvent>>> = Arc::default();
    let ev = events.clone();
    let rep = Fuzzer::new(net, cfg)
        .with_events(Arc::new(move |e| ev.lock().unwrap().push(e.clone())))
        .run(&task)
        .await;
    assert_eq!(rep.stop, StopReason::Completed, "{:?}", rep.stats);

    let has = |kind: HitKind, path: &str| {
        rep.hits
            .iter()
            .any(|h| h.kind == kind && Url::parse(&h.url).unwrap().path() == path)
    };
    let dump: Vec<String> = rep
        .hits
        .iter()
        .map(|h| format!("{:?} {} {:?} {}", h.kind, h.url, h.host, h.status))
        .collect();
    assert!(
        has(HitKind::Document, "/files/report_2024.pdf"),
        "{dump:#?}"
    );
    assert!(has(HitKind::Backup, "/index.php.bak"), "{dump:#?}");
    assert!(has(HitKind::GitRepo, "/.git/HEAD"), "{dump:#?}");
    assert!(has(HitKind::DsStore, "/.DS_Store"), "{dump:#?}");
    assert!(has(HitKind::Document, "/secret-plan_2024.pdf"), "{dump:#?}");
    assert!(has(HitKind::Exposed, "/.env"), "{dump:#?}");
    assert!(has(HitKind::DirListing, "/docs/"), "{dump:#?}");
    assert!(has(HitKind::DirListing, "/docs/sub/"), "{dump:#?}");
    assert!(
        rep.hits.iter().any(|h| h.kind == HitKind::Vhost
            && h.host.as_deref() == Some("intranet.contoso.test")),
        "{dump:#?}"
    );
    for d in [
        "docs/annual_report.docx",
        "docs/price.xlsx",
        "docs/sub/internal.pdf",
        "files/report_2024.pdf",
        "secret-plan_2024.pdf",
    ] {
        assert!(
            rep.documents.contains(&format!("{base}{d}")),
            "{d} not in documents: {:?}",
            rep.documents
        );
    }

    // Evidence is masked.
    let bak = rep
        .hits
        .iter()
        .find(|h| h.url.ends_with("/index.php.bak"))
        .unwrap();
    assert!(!bak.evidence.contains("S3cr3tPassw0rd"), "{}", bak.evidence);
    let env = rep.hits.iter().find(|h| h.url.ends_with("/.env")).unwrap();
    assert!(
        !env.evidence.contains("supersecretvalue"),
        "{}",
        env.evidence
    );
    // The artifact parser saw the raw body; only its masked summary is kept.
    let art = env.artifact.as_ref().expect(".env artifact summary");
    assert_eq!(art.kind, "env");
    assert!(
        art.lines.iter().any(|l| l.contains("DB_PASSWORD")),
        "{art:?}"
    );
    let js = serde_json::to_string(env).unwrap();
    assert!(!js.contains("supersecretvalue"), "{js}");
    let ds = rep
        .hits
        .iter()
        .find(|h| h.kind == HitKind::DsStore)
        .unwrap();
    assert!(ds.extra.contains(&"secret-plan_2024.pdf".to_string()));

    // Zero false positives: every finding is a real resource of the test site.
    for h in &rep.hits {
        let u = Url::parse(&h.url).unwrap();
        if h.kind == HitKind::Vhost {
            let host = h.host.as_deref().unwrap();
            assert_eq!(host, "intranet.contoso.test", "false vhost: {dump:#?}");
            continue;
        }
        let root = root_for(h.host.as_deref().unwrap_or(""));
        let p = fs_path(&root, u.path());
        assert!(
            p.exists(),
            "false finding {:?} {} ({dump:#?})",
            h.kind,
            h.url
        );
    }
    // The soft 404 is filtered out by calibration.
    if soft404 {
        assert!(rep.stats.filtered_calibration > 100, "{:?}", rep.stats);
    }

    // The excluded path and host were not requested, neither per the server nor per the log.
    let reqs = srv.requests();
    let priv_: Vec<&str> = reqs
        .iter()
        .map(|r| r.target.as_str())
        .filter(|p| *p == "/private" || p.starts_with("/private/"))
        .collect();
    assert!(priv_.is_empty(), "{priv_:?}");
    assert!(!reqs.iter().any(|r| host_of(r) == "dev.contoso.test"));
    let log = sink.records();
    let bad: Vec<_> = log
        .iter()
        .filter(|r| {
            let p = Url::parse(&r.url).unwrap().path().to_string();
            p == "/private" || p.starts_with("/private/")
        })
        .collect();
    assert!(bad.is_empty(), "{bad:?}");
    assert!(log
        .iter()
        .all(|r| r.module == foca_fuzz::LOG_MODULE && r.access == "active"));
    assert!(rep.stats.skipped_excluded >= 3, "{:?}", rep.stats);
    // Every request seen by the server is in the log.
    assert!(
        log.len() >= reqs.len(),
        "log {} < requests {}",
        log.len(),
        reqs.len()
    );
    // No path obfuscation in any request.
    let odd: Vec<&str> = reqs
        .iter()
        .map(|r| r.target.as_str())
        .filter(|t| t.contains('%') || t.contains(".."))
        .collect();
    assert!(odd.is_empty(), "{odd:?}");

    let ev = events.lock().unwrap();
    assert!(matches!(ev.first(), Some(FuzzEvent::Started { .. })));
    assert!(matches!(ev.last(), Some(FuzzEvent::Finished { .. })));
    assert!(ev.iter().any(|e| matches!(e, FuzzEvent::Calibrated { .. })));
    assert!(ev.iter().any(|e| matches!(e, FuzzEvent::Progress { .. })));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fixture_site_everything_found_no_false_positives() {
    full_run(false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fixture_site_with_soft404_everything_found_no_false_positives() {
    full_run(true).await;
}
