//! Downloader: SHA-256 and dedup, size limit with a lying Content-Length, HEAD to GET fallback,
//! scope, retries, cancellation and resume (MemQueue and the foca-store queue).

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use foca_core::Scope;
use foca_net::testserver::{TestResponse, TestServer};
use foca_net::{CancellationToken, MemorySink, NetClient, NetConfig, NetError};
use foca_search::download::QueueEvent;
#[cfg(feature = "store")]
use foca_search::TaskQueue;
use foca_search::{DownloadConfig, Downloader, MemQueue};
use sha2::{Digest, Sha256};

fn net(targets: &str, excludes: &str) -> (NetClient, Arc<MemorySink>) {
    let (scope, errs) = Scope::from_lines(targets, excludes);
    assert!(errs.is_empty());
    let sink = Arc::new(MemorySink::new());
    let cfg = NetConfig {
        global_rps: None,
        retries: 0,
        ..Default::default()
    };
    (NetClient::new(cfg, scope, sink.clone()).unwrap(), sink)
}

fn sha(b: &[u8]) -> String {
    Sha256::digest(b)
        .iter()
        .map(|x| format!("{x:02x}"))
        .collect()
}

fn pdf(n: u8) -> Vec<u8> {
    let mut v = b"%PDF-1.4\n".to_vec();
    v.extend(std::iter::repeat_n(n, 1000));
    v
}

async fn site() -> TestServer {
    TestServer::start(|r| match r.path() {
        "/a.pdf" | "/copy-of-a.pdf" => {
            TestResponse::ok(pdf(1)).header("Content-Type", "application/pdf")
        }
        "/b.pdf" => TestResponse::ok(pdf(2)),
        "/nohead.docx" if r.method == "HEAD" => TestResponse::status(405),
        "/nohead.docx" => TestResponse::ok(b"PK\x03\x04docx".to_vec()),
        "/liar.pdf" if r.method == "HEAD" => TestResponse::ok("").header("Content-Length", "100"),
        "/liar.pdf" => TestResponse {
            status: 200,
            stream_len: Some(3 * 1024 * 1024),
            ..Default::default()
        },
        "/huge.pdf" if r.method == "HEAD" => {
            TestResponse::ok("").header("Content-Length", "999999999")
        }
        "/slow.pdf" => TestResponse::ok(pdf(3)).delay(Duration::from_secs(3)),
        "/to-evil.pdf" => TestResponse::redirect(302, "http://evil.example/a.pdf"),
        _ => TestResponse::status(404),
    })
    .await
}

fn cfg() -> DownloadConfig {
    DownloadConfig {
        max_size: 1024 * 1024,
        concurrency: 2,
        ..Default::default()
    }
}

#[tokio::test]
async fn download_hash_and_dedup() {
    let srv = site().await;
    let dir = tempfile::tempdir().unwrap();
    let (net, sink) = net("127.0.0.1", "");
    let d = Downloader::new(net, dir.path(), cfg());
    let a = d.download(&format!("{}/a.pdf", srv.url())).await.unwrap();
    assert_eq!(a.sha256, sha(&pdf(1)));
    assert_eq!(a.size, 1009);
    assert_eq!(a.name, "a.pdf");
    assert_eq!(
        a.path,
        dir.path().join("files").join(format!("{}.pdf", a.sha256))
    );
    assert_eq!(std::fs::read(&a.path).unwrap(), pdf(1));
    assert!(!a.existing);
    let c = d
        .download(&format!("{}/copy-of-a.pdf", srv.url()))
        .await
        .unwrap();
    assert!(c.existing, "same hash, same file");
    assert_eq!(c.path, a.path);
    // no temporary files left
    assert_eq!(
        std::fs::read_dir(dir.path().join(".tmp")).unwrap().count(),
        0
    );
    // HEAD + GET per file, all to the target
    let log = sink.records();
    assert!(log.iter().all(|r| r.active && r.module == "download"));
    assert_eq!(log.iter().filter(|r| r.method == "HEAD").count(), 2);
    // HEAD not supported: GET aborted after headers, then the download
    let n = d
        .download(&format!("{}/nohead.docx", srv.url()))
        .await
        .unwrap();
    assert_eq!(n.size, 8);
}

#[tokio::test]
async fn size_limit_with_lying_server() {
    let srv = site().await;
    let dir = tempfile::tempdir().unwrap();
    let (net, sink) = net("127.0.0.1", "");
    let d = Downloader::new(net, dir.path(), cfg());
    let e = d
        .download(&format!("{}/liar.pdf", srv.url()))
        .await
        .unwrap_err();
    assert_eq!(e, NetError::TooLarge { limit: 1024 * 1024 });
    assert_eq!(
        std::fs::read_dir(dir.path().join(".tmp")).unwrap().count(),
        0,
        "the partial file is removed"
    );
    assert!(
        !dir.path().join("files").exists()
            || std::fs::read_dir(dir.path().join("files")).unwrap().count() == 0
    );
    let get = sink
        .records()
        .into_iter()
        .find(|r| r.method == "GET")
        .unwrap();
    assert!(
        get.bytes <= 1024 * 1024 + 64 * 1024,
        "stream cut off: {}",
        get.bytes
    );
    // a HEAD reporting a huge size: no GET
    let e = d
        .download(&format!("{}/huge.pdf", srv.url()))
        .await
        .unwrap_err();
    assert!(matches!(e, NetError::TooLarge { .. }));
    assert_eq!(
        srv.requests()
            .iter()
            .filter(|r| r.path() == "/huge.pdf" && r.method == "GET")
            .count(),
        0
    );
}

#[tokio::test]
async fn scope_and_passive_hosts() {
    let srv = site().await;
    let dir = tempfile::tempdir().unwrap();
    // target site out of scope: denied before the request
    let (n1, sink) = net("contoso.ua", "");
    let d = Downloader::new(n1.clone(), dir.path(), cfg());
    let e = d
        .download(&format!("{}/a.pdf", srv.url()))
        .await
        .unwrap_err();
    assert!(e.is_scope_denial());
    assert_eq!(srv.requests().len(), 0);
    assert!(sink.records().iter().all(|r| r.blocked));
    // the same host declared as an archive (like web.archive.org) is passive and needs no scope
    let mut c = cfg();
    c.passive_hosts = vec!["127.0.0.1".into()];
    let d = Downloader::new(n1, dir.path(), c);
    let ok = d.download(&format!("{}/a.pdf", srv.url())).await.unwrap();
    assert_eq!(ok.size, 1009);
    assert!(sink.records().iter().any(|r| !r.active && !r.blocked));
    // redirect from the target to outside the scope
    let (n2, _) = net("127.0.0.1", "");
    let d = Downloader::new(n2, dir.path(), cfg());
    let e = d
        .download(&format!("{}/to-evil.pdf", srv.url()))
        .await
        .unwrap_err();
    assert!(matches!(e, NetError::OutOfScope { ref host, .. } if host == "evil.example"));
    assert_eq!(
        Downloader::new(net("", "").0, dir.path(), DownloadConfig::default())
            .access_for("https://web.archive.org/web/1id_/http://a.ua/x.pdf"),
        foca_net::Access::Passive
    );
}

#[tokio::test]
async fn queue_retries_and_permanent_failures() {
    let fails = Arc::new(AtomicUsize::new(0));
    let f2 = fails.clone();
    let srv = TestServer::start(move |r| match r.path() {
        "/flaky.pdf" if r.method == "GET" => {
            if f2.fetch_add(1, Ordering::SeqCst) < 1 {
                TestResponse::status(503)
            } else {
                TestResponse::ok(pdf(9))
            }
        }
        "/flaky.pdf" => TestResponse::ok(""),
        "/ok.pdf" => TestResponse::ok(pdf(4)),
        _ => TestResponse::status(404),
    })
    .await;
    let dir = tempfile::tempdir().unwrap();
    let (net, _) = net("127.0.0.1", "");
    let d = Downloader::new(net, dir.path(), cfg());
    let q = MemQueue::new();
    for p in ["/ok.pdf", "/flaky.pdf", "/missing.pdf"] {
        q.enqueue(&format!("{}{p}", srv.url()), "crawler");
    }
    assert!(
        q.enqueue(&format!("{}/ok.pdf", srv.url()), "cc").is_none(),
        "queue dedup"
    );
    let mut events = 0;
    let st = d.run_queue(&q, |_| events += 1).await.unwrap();
    assert_eq!((st.done, st.failed, st.retried), (2, 1, 1));
    assert_eq!(q.count("done"), 2);
    let missing = q.tasks().into_iter().find(|t| t.state == "failed").unwrap();
    assert!(missing.task.url.ends_with("/missing.pdf"));
    assert_eq!(missing.task.attempts, 1, "404 is not retried");
    assert!(missing.error.unwrap().contains("404"));
    assert_eq!(events, 4);
}

#[tokio::test]
async fn cancel_then_resume_continues() {
    let srv = site().await;
    let dir = tempfile::tempdir().unwrap();
    let q = MemQueue::new();
    for p in ["/a.pdf", "/slow.pdf", "/b.pdf"] {
        q.enqueue(&format!("{}{p}", srv.url()), "wayback");
    }
    let (net1, _) = net("127.0.0.1", "");
    let token = CancellationToken::new();
    let net1 = net1.with_cancel(token.clone());
    let mut c = cfg();
    c.concurrency = 1;
    let d1 = Downloader::new(net1, dir.path(), c.clone());
    // cancel as soon as the slow download starts
    let t2 = token.clone();
    let st = d1
        .run_queue(&q, move |e| {
            if let QueueEvent::Done(t, _, _) = e {
                if t.url.ends_with("/a.pdf") {
                    let t3 = t2.clone();
                    tokio::spawn(async move {
                        tokio::time::sleep(Duration::from_millis(300)).await;
                        t3.cancel();
                    });
                }
            }
        })
        .await
        .unwrap();
    assert!(st.cancelled);
    assert_eq!(q.count("done"), 1);
    assert_eq!(
        q.count("downloading"),
        1,
        "the interrupted task stays in progress"
    );
    assert_eq!(q.count("queued"), 1);
    // "restart": a new client, resume() puts the interrupted task back into the queue
    let (net2, _) = net("127.0.0.1", "");
    let d2 = Downloader::new(net2, dir.path(), c);
    let st = d2.run_queue(&q, |_| {}).await.unwrap();
    assert!(!st.cancelled);
    assert_eq!(st.done, 2);
    assert_eq!(q.count("done"), 3);
    assert_eq!(
        srv.hits("/a.pdf"),
        2,
        "a.pdf (HEAD+GET) was not downloaded again"
    );
}

#[cfg(feature = "store")]
mod store {
    use super::*;
    use foca_search::store::{StoreQueue, StoreSink};
    use foca_search::FoundUrl;
    use foca_store::{NewProject, Store};
    use std::sync::Mutex;

    #[tokio::test]
    async fn sqlite_queue_resume_and_request_log() {
        let srv = site().await;
        let tmp = tempfile::tempdir().unwrap();
        let store = Store::open(tmp.path()).unwrap();
        let p = store
            .create_project(&NewProject {
                name: "t".into(),
                targets: vec!["127.0.0.1".into()],
                ..Default::default()
            })
            .unwrap();
        let db = Arc::new(Mutex::new(store.open_project(&p.id).unwrap()));
        let scope = db.lock().unwrap().core_scope().unwrap();
        let q = StoreQueue::new(db.clone(), Some("s1".into()));
        let urls: Vec<FoundUrl> = ["/a.pdf", "/b.pdf", "/copy-of-a.pdf", "/missing.pdf"]
            .iter()
            .map(|p| FoundUrl::new(&format!("{}{p}", srv.url()), "crawler"))
            .collect();
        assert_eq!(q.enqueue(&urls).unwrap(), 4);
        assert_eq!(q.enqueue(&urls).unwrap(), 0);
        // "crash" mid-download: two tasks are claimed and abandoned
        let claimed = q.claim(2).unwrap();
        assert_eq!(claimed.len(), 2);
        let sink = Arc::new(StoreSink {
            db: db.clone(),
            scan_id: Some("s1".into()),
        });
        let net = NetClient::new(
            NetConfig {
                global_rps: None,
                retries: 0,
                ..Default::default()
            },
            scope,
            sink,
        )
        .unwrap();
        let files = tmp.path().join(&p.id);
        let d = Downloader::new(net, &files, cfg());
        let st = d.run_queue(&q, |_| {}).await.unwrap();
        assert_eq!((st.done, st.failed, st.duplicates), (3, 1, 1));
        let g = db.lock().unwrap();
        let c = g.task_counts().unwrap();
        assert_eq!((c.done, c.failed, c.queued, c.downloading), (3, 1, 0, 0));
        let docs = g.documents(false).unwrap();
        assert_eq!(docs.len(), 2, "copy-of-a.pdf is a SHA-256 duplicate");
        assert!(docs.iter().all(|d| d
            .local_path
            .as_deref()
            .is_some_and(|p| std::path::Path::new(p).exists())));
        let log = g.requests(Some("s1"), true).unwrap();
        assert!(log.len() >= 7, "{}", log.len());
        assert!(log
            .iter()
            .all(|r| r.module == "download" && r.host == "127.0.0.1"));
        assert!(log.iter().any(|r| r.status == Some(404)));
    }

    /// The download stage claims rich documents first and site graphics last, whatever the order
    /// the finds were queued in; with a document limit the cut keeps the office/PDF files.
    #[tokio::test]
    async fn queue_claims_documents_before_site_graphics() {
        let tmp = tempfile::tempdir().unwrap();
        let store = Store::open(tmp.path()).unwrap();
        let p = store
            .create_project(&NewProject {
                name: "t".into(),
                targets: vec!["a.example".into()],
                ..Default::default()
            })
            .unwrap();
        let db = Arc::new(Mutex::new(store.open_project(&p.id).unwrap()));
        let q = StoreQueue::new(db.clone(), Some("s1".into()));
        let names = [
            "fontello.svg",
            "about.png",
            "favicon.png",
            "prices.doc",
            "koledzh.docx",
            "report.pdf",
            "photo.jpg",
            "app.exe",
        ];
        let urls: Vec<FoundUrl> = names
            .iter()
            .map(|n| FoundUrl::new(&format!("https://a.example/f/{n}"), "crawler"))
            .collect();
        assert_eq!(q.enqueue(&urls).unwrap(), names.len());
        let mut order = Vec::new();
        loop {
            let b = q.claim(1).unwrap();
            let Some(t) = b.first() else { break };
            order.push(t.url.rsplit('/').next().unwrap().to_string());
        }
        assert_eq!(
            order,
            [
                "prices.doc",
                "koledzh.docx",
                "report.pdf",
                "app.exe",
                "photo.jpg",
                "fontello.svg",
                "about.png",
                "favicon.png"
            ]
        );
        // A document limit of 3 keeps the three office/PDF files, never the program or images.
        let picked = foca_search::source::pick_fair(urls.clone(), 3, 0);
        let picked: Vec<&str> = picked
            .iter()
            .map(|u| u.url.rsplit('/').next().unwrap())
            .collect();
        assert_eq!(picked, ["prices.doc", "koledzh.docx", "report.pdf"]);
        let balanced = foca_search::source::take_balanced(urls, 3, 1);
        let balanced: Vec<&str> = balanced
            .iter()
            .map(|u| u.url.rsplit('/').next().unwrap())
            .collect();
        assert_eq!(
            balanced,
            ["prices.doc", "koledzh.docx", "report.pdf", "photo.jpg"]
        );
    }
}

/// A large MOV with `moov` after the media data: only the metadata boxes are fetched with
/// Range requests; a server without Range support yields `TooLarge` (no full download).
#[tokio::test]
async fn large_video_fetches_only_metadata_boxes() {
    let src = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/corpus/media/iphone.mov"
    ))
    .unwrap();
    // Top-level boxes of the sample, then rebuild: ftyp/... + 3 MiB mdat + moov.
    let mut boxes: Vec<&[u8]> = Vec::new();
    let mut i = 0;
    while i + 8 <= src.len() {
        let n = u32::from_be_bytes(src[i..i + 4].try_into().unwrap()) as usize;
        if n < 8 || i + n > src.len() {
            break;
        }
        boxes.push(&src[i..i + n]);
        i += n;
    }
    let mut file = Vec::new();
    for b in boxes
        .iter()
        .filter(|b| &b[4..8] != b"moov" && &b[4..8] != b"mdat")
    {
        file.extend_from_slice(b);
    }
    let mdat_len = 3 * 1024 * 1024 + 8;
    file.extend_from_slice(&(mdat_len as u32).to_be_bytes());
    file.extend_from_slice(b"mdat");
    file.extend(std::iter::repeat_n(0u8, mdat_len - 8));
    let moov = boxes
        .iter()
        .find(|b| &b[4..8] == b"moov")
        .expect("moov in sample");
    file.extend_from_slice(moov);
    let file = Arc::new(file);
    let f2 = file.clone();
    let srv = TestServer::start(move |r| {
        let len = f2.len();
        let ranged = r.path() == "/clip.mov";
        if r.method == "HEAD" {
            return TestResponse::ok("").header("Content-Length", &len.to_string());
        }
        match (ranged, r.headers.get("range")) {
            (true, Some(h)) => {
                let spec = h.trim_start_matches("bytes=");
                let (a, b) = spec.split_once('-').unwrap();
                let a: usize = a.parse().unwrap();
                let b: usize = b.parse::<usize>().unwrap().min(len - 1);
                TestResponse {
                    status: 206,
                    body: f2[a..=b].to_vec(),
                    ..Default::default()
                }
                .header("Content-Range", &format!("bytes {a}-{b}/{len}"))
            }
            _ => TestResponse::ok(f2.to_vec()),
        }
    })
    .await;
    let (n, _) = net("127.0.0.1", "");
    let dir = tempfile::tempdir().unwrap();
    let d = Downloader::new(
        n,
        dir.path(),
        DownloadConfig {
            max_media_full: 1024 * 1024,
            ..cfg()
        },
    );
    let got = d
        .download(&format!("{}/clip.mov", srv.url()))
        .await
        .unwrap();
    let stored = std::fs::read(&got.path).unwrap();
    assert!(stored.len() < 512 * 1024, "{}", stored.len());
    assert!(stored.windows(4).any(|w| w == b"moov"));
    assert!(!stored.windows(4).any(|w| w == b"mdat"));
    // Every GET carried a Range header.
    assert!(srv
        .requests()
        .iter()
        .filter(|r| r.method == "GET")
        .all(|r| r.headers.contains_key("range")));
    // No Range support: refused instead of downloading the whole video.
    let e = d.download(&format!("{}/norange.mov", srv.url())).await;
    assert!(matches!(e, Err(NetError::TooLarge { .. })), "{e:?}");
}

/// Linked external storage: only the exact allowed URLs are fetched (passive, module `storage`);
/// the file name comes from `Content-Disposition`; Drive's virus-scan page is passed once; a
/// sign-in page means a private file (403); anything else on the host stays out of scope.
#[tokio::test]
async fn storage_items_only_and_private_files() {
    let srv = TestServer::start(|r| {
        let id = r.query("id").unwrap_or_default();
        match (r.path(), id.as_str()) {
            ("/uc", "PUB") => TestResponse::ok(pdf(7))
                .header("Content-Type", "application/pdf")
                .header("Content-Disposition", "attachment; filename=\"Plan 2026.pdf\""),
            ("/uc", "PRIV") => TestResponse::ok("<html><title>Sign in</title></html>")
                .header("Content-Type", "text/html; charset=utf-8"),
            ("/uc", "BIG") => TestResponse::ok(
                r#"<form id="download-form" action="/download" method="get"><input type="hidden" name="id" value="BIG"><input type="hidden" name="confirm" value="t"></form>"#,
            )
            .header("Content-Type", "text/html"),
            ("/download", "BIG") if r.query("confirm").as_deref() == Some("t") => {
                TestResponse::ok(b"PK\x03\x04sheet".to_vec())
                    .header("Content-Type", "application/octet-stream")
            }
            ("/uc", _) => TestResponse::ok(pdf(9)),
            _ => TestResponse::status(404),
        }
    })
    .await;
    let dir = tempfile::tempdir().unwrap();
    let (net, sink) = net("site.example", "");
    let mut cfg = DownloadConfig::default();
    let mut allow = std::collections::HashMap::new();
    let item = |ext: Option<&str>| foca_search::download::StorageItem {
        hosts: vec!["127.0.0.1".into()],
        ext: ext.map(String::from),
        name: Some("gdrive-BIG".into()),
    };
    let u = |id: &str| format!("{}/uc?export=download&id={id}", srv.url());
    allow.insert(u("PUB"), item(None));
    allow.insert(u("PRIV"), item(None));
    allow.insert(u("BIG"), item(Some("xlsx")));
    cfg.storage = Arc::new(allow);
    let d = Downloader::new(net, dir.path(), cfg);
    let a = d.download(&u("PUB")).await.unwrap();
    assert_eq!(a.name, "Plan 2026.pdf");
    assert!(a.path.to_string_lossy().ends_with(".pdf"));
    assert_eq!(
        d.download(&u("PRIV")).await.unwrap_err(),
        NetError::Status(403)
    );
    let b = d.download(&u("BIG")).await.unwrap();
    assert!(b.path.to_string_lossy().ends_with(".xlsx"), "{:?}", b.path);
    assert_eq!(b.name, "gdrive-BIG.xlsx");
    // another item on the same host was never linked: it stays out of scope
    assert!(d.download(&u("OTHER")).await.unwrap_err().is_scope_denial());
    assert_eq!(
        srv.requests()
            .iter()
            .filter(|r| r.target.contains("OTHER"))
            .count(),
        0
    );
    let log = sink.records();
    assert!(log
        .iter()
        .filter(|r| !r.blocked)
        .all(|r| r.module == "storage" && !r.active));
    assert!(
        srv.requests().iter().all(|r| r.method == "GET"),
        "no HEAD probes on storage"
    );
}

/// Storage answers with `application/octet-stream`: the name comes from a raw UTF-8
/// `Content-Disposition` (no `filename*`, as Google Drive sends it), and without any name the
/// type is taken from the file signature instead of `.bin`.
#[tokio::test]
async fn storage_names_from_raw_utf8_disposition_or_signature() {
    let srv = TestServer::start(|r| {
        let id = r.query("id").unwrap_or_default();
        let r = TestResponse::ok(pdf(3)).header("Content-Type", "application/octet-stream");
        match id.as_str() {
            "NAMED" => r.header(
                "Content-Disposition",
                "attachment; filename=\"Розклад занять.pdf\"",
            ),
            _ => r,
        }
    })
    .await;
    let dir = tempfile::tempdir().unwrap();
    let (net, _sink) = net("site.example", "");
    let mut cfg = DownloadConfig::default();
    let u = |id: &str| format!("{}/uc?export=download&id={id}", srv.url());
    let mut allow = std::collections::HashMap::new();
    for id in ["NAMED", "BARE"] {
        allow.insert(
            u(id),
            foca_search::download::StorageItem {
                hosts: vec!["127.0.0.1".into()],
                ext: None,
                name: Some(format!("gdrive-{id}")),
            },
        );
    }
    cfg.storage = Arc::new(allow);
    let d = Downloader::new(net, dir.path(), cfg);
    let a = d.download(&u("NAMED")).await.unwrap();
    assert_eq!(a.name, "Розклад занять.pdf");
    let b = d.download(&u("BARE")).await.unwrap();
    assert_eq!(b.name, "gdrive-BARE.pdf");
    assert!(b.path.to_string_lossy().ends_with(".pdf"), "{:?}", b.path);
}
