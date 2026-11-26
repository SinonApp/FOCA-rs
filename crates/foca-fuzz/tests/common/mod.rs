//! Offline test site: a client site served from `tests/fixtures/fuzz-site` on 127.0.0.1.
#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use foca_core::Scope;
use foca_fuzz::FuzzConfig;
use foca_net::testserver::{TestRequest, TestResponse, TestServer};
use foca_net::{MemorySink, NetClient, NetConfig};

pub fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/fuzz-site")
}

pub fn host_of(r: &TestRequest) -> String {
    r.headers
        .get("host")
        .map(|h| h.split(':').next().unwrap_or("").to_ascii_lowercase())
        .unwrap_or_default()
}

/// Maps a URL path to the fixture file system. Git cannot store `.git` directories, so
/// `/.git/` lives in `dot-git/`.
pub fn fs_path(root: &Path, url_path: &str) -> PathBuf {
    let mapped: Vec<&str> = url_path
        .trim_start_matches('/')
        .split('/')
        .map(|s| if s == ".git" { "dot-git" } else { s })
        .collect();
    root.join(mapped.join("/"))
}

/// Returns the document root for a `Host` header.
pub fn root_for(host: &str) -> PathBuf {
    let f = fixtures();
    match host {
        "intranet.contoso.test" => f.join("intranet"),
        "dev.contoso.test" => f.join("dev"),
        _ => f.join("www"),
    }
}

fn content_type(p: &Path) -> &'static str {
    match p
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_ascii_lowercase()
        .as_str()
    {
        "html" | "php" => "text/html; charset=utf-8",
        "pdf" => "application/pdf",
        "docx" => "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "xlsx" => "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "txt" => "text/plain",
        _ => "application/octet-stream",
    }
}

static SEQ: AtomicU64 = AtomicU64::new(1);

/// Soft 404: status 200 with a body containing a random "request id" of varying length.
pub fn soft404(path: &str) -> TestResponse {
    let n = SEQ.fetch_add(1, Ordering::Relaxed);
    let junk: String = format!("{:x}", n.wrapping_mul(0x9e37_79b9_7f4a_7c15))
        .chars()
        .cycle()
        .take(8 + (n as usize * 7) % 40)
        .collect();
    let body = format!(
        "<!doctype html><html><head><title>Contoso</title></head><body><h1>Oops</h1>\n<p>We could not find {path}. Request id {junk}.</p>\n</body></html>"
    );
    TestResponse::ok(body).header("Content-Type", "text/html; charset=utf-8")
}

fn listing(path: &str, dir: &Path) -> TestResponse {
    let mut names: Vec<(String, bool)> = std::fs::read_dir(dir)
        .map(|it| {
            it.filter_map(|e| e.ok())
                .map(|e| {
                    (
                        e.file_name().to_string_lossy().into_owned(),
                        e.path().is_dir(),
                    )
                })
                .collect()
        })
        .unwrap_or_default();
    names.sort();
    let mut b = format!(
        "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 3.2 Final//EN\">\n<html><head><title>Index of {path}</title></head><body><h1>Index of {path}</h1>\n<table><tr><th><a href=\"?C=N;O=D\">Name</a></th></tr>\n<tr><td><a href=\"../\">Parent Directory</a></td></tr>\n"
    );
    for (n, d) in names {
        let s = if d { "/" } else { "" };
        b.push_str(&format!(
            "<tr><td><a href=\"{n}{s}\">{n}{s}</a></td></tr>\n"
        ));
    }
    b.push_str("</table></body></html>\n");
    TestResponse::ok(b).header("Content-Type", "text/html;charset=UTF-8")
}

/// Test site behaviour.
#[derive(Clone, Copy, Debug, Default)]
pub struct SiteOpts {
    pub soft404: bool,
}

/// Test site request handler.
pub fn site(r: &TestRequest, o: SiteOpts) -> TestResponse {
    let host = host_of(r);
    let root = root_for(&host);
    let path = r.path().to_string();
    if path.contains("..") || path.contains('\\') || path.contains("dot-git") {
        return TestResponse::status(400);
    }
    if path == "/go" {
        return TestResponse::redirect(302, "http://evil.example/x");
    }
    let fs = fs_path(&root, &path);
    let not_found = || {
        if o.soft404 {
            soft404(&path)
        } else {
            TestResponse {
                status: 404,
                body: b"<html><body>404 Not Found</body></html>".to_vec(),
                ..Default::default()
            }
            .header("Content-Type", "text/html")
        }
    };
    if fs.is_dir() {
        if !path.ends_with('/') {
            return TestResponse::redirect(301, &format!("{path}/"));
        }
        let idx = fs.join("index.html");
        if idx.is_file() {
            return TestResponse::ok(std::fs::read(idx).unwrap_or_default())
                .header("Content-Type", "text/html; charset=utf-8");
        }
        if path.starts_with("/docs/") && host != "intranet.contoso.test" {
            return listing(&path, &fs);
        }
        return TestResponse {
            status: 403,
            body: format!("<html><body>Forbidden: {path}</body></html>").into_bytes(),
            ..Default::default()
        }
        .header("Content-Type", "text/html");
    }
    if fs.is_file() && !path.ends_with('/') {
        return TestResponse::ok(std::fs::read(&fs).unwrap_or_default())
            .header("Content-Type", content_type(&fs));
    }
    not_found()
}

pub async fn start_site(o: SiteOpts) -> TestServer {
    TestServer::start(move |r| site(r, o)).await
}

/// Fast settings for the test site (the device uses the defaults).
pub fn fast_cfg() -> FuzzConfig {
    FuzzConfig {
        threads: 4,
        rate: 1000.0,
        jitter: Duration::ZERO,
        max_requests: 50_000,
        max_time: Duration::from_secs(120),
        request_timeout: Duration::from_secs(5),
        ..Default::default()
    }
}

pub fn client(targets: &str, excludes: &str, active_phase: bool) -> (NetClient, Arc<MemorySink>) {
    let (mut scope, errs) = Scope::from_lines(targets, excludes);
    assert!(errs.is_empty(), "{errs:?}");
    scope.active_phase = active_phase;
    let sink = Arc::new(MemorySink::new());
    let cfg = NetConfig {
        global_rps: None,
        max_concurrency: 8,
        retries: 0,
        ..Default::default()
    };
    (NetClient::new(cfg, scope, sink.clone()).unwrap(), sink)
}
