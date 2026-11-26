//! `foca testnet --port 8788 --corpus tests/corpus --domain example.test --write-config net.json`:
//! a local "internet" for e2e (offline, deterministic): web archive CDX, crt.sh, copies of
//! documents from `tests/corpus`, IP echo/geo and an AI stub. Mirrors the foca-engine test
//! harness (`crates/foca-engine/tests/common`). `--write-config` writes the file for
//! `foca serve --test-net` (source base URLs, StaticDns zone, liveness ports).
//!
//! `GET /__delay?ms=N[&cdx=M]` changes the document (and web archive) response delay on the
//! fly.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Result};
use clap::Args;
use foca_net::testserver::{TestResponse, TestServer};
use serde_json::{json, Value};

#[derive(Args, Debug)]
pub struct TestNetOpts {
    #[arg(long, default_value_t = 8788)]
    pub port: u16,
    /// Document directory (recursive; *.json, *.md, *.py are skipped)
    #[arg(long, default_value = "tests/corpus")]
    pub corpus: PathBuf,
    /// Domain of the "site" whose documents are in the web archive
    #[arg(long, default_value = "example.test")]
    pub domain: String,
    /// Delay before serving each document, ms
    #[arg(long, default_value_t = 0)]
    pub delay_ms: u64,
    /// Write the configuration for `foca serve --test-net`
    #[arg(long)]
    pub write_config: Option<PathBuf>,
    /// Client site for forgotten-file discovery: `www.<domain>` serves `<dir>/www` (documents,
    /// a backup, .git/HEAD, .env, .DS_Store, a /docs/ listing); empty disables it
    #[arg(long, default_value = "tests/fixtures/fuzz-site")]
    pub fuzz_site: PathBuf,
}

/// Site recon fixture: an archived copy of the `<domain>` home page (technologies, GA4, an S3
/// bucket), a favicon, a script with an endpoint and a decoy key, robots.txt in CDX and the
/// archive; grep.app answers with a 429 challenge.
fn recon_site(d: &str, p: &str, cdx_url: Option<&str>) -> Option<TestResponse> {
    if p == "/api/search" {
        return Some(TestResponse {
            status: 429,
            ..TestResponse::ok(br#"{"error":{"code":"challenge"}}"#.to_vec())
                .header("Content-Type", "application/json")
        });
    }
    if p == "/cdx/search/cdx" {
        let u = cdx_url?;
        if u.ends_with("robots.txt") {
            return Some(TestResponse::ok(format!(
                "test,example)/robots.txt 20250101000000 https://{d}/robots.txt text/plain 200 RBT1 120\n"
            )));
        }
        if u.ends_with("sitemap.xml") || u.ends_with("security.txt") {
            return Some(TestResponse::ok(Vec::new()));
        }
        return None;
    }
    let orig = p.strip_prefix("/web/")?.split_once("id_/")?.1;
    let path = orig
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .strip_prefix(d)?;
    match path {
        "/" => Some(
            TestResponse::ok(format!(
                r#"<html><head><title>{d}</title><link rel="icon" href="/favicon.ico"><script src="/js/jquery-1.8.2.min.js"></script>
<script src="/app.js"></script><script>gtag('config', 'G-ABC123XYZ9');</script></head>
<body><h1>{d}</h1><a href="https://contoso-backup.s3.amazonaws.com/report.pdf">pdf</a></body></html>"#
            ))
            .header("Content-Type", "text/html")
            .header("x-archive-orig-server", "nginx/1.18.0")
            .header(
                "x-archive-orig-content-security-policy",
                &format!("default-src 'self'; script-src 'self' 'unsafe-inline' https://api.{d} https://cdn.partner-cdn.test; connect-src https://staging-api.{d}"),
            ),
        ),
        "/favicon.ico" => Some(TestResponse::ok(vec![0u8, 0, 1, 0, 1, 0, 16, 16, 0, 0, 1, 0])),
        "/app.js" => {
            let key = format!("{}{}", "AKIA", "Q7XK2M9PLR4TZW8N");
            Some(TestResponse::ok(
                format!("fetch('/api/v2/users');const k=\"{key}\";").into_bytes(),
            ))
        }
        "/robots.txt" => Some(TestResponse::ok(
            b"User-agent: *\nDisallow: /admin/\nDisallow: /backup/\n".to_vec(),
        )),
        _ => None,
    }
}

/// The live `<domain>` site for direct recon and the web audit (standard/full profiles): security
/// headers with a weak CSP that names API/staging hosts, a session cookie without flags, a script
/// with a source map (npm packages, a local path), an OpenAPI spec with unauthenticated operations,
/// and `OPTIONS` advertising PUT/DELETE (the audit never sends them).
fn live_site(d: &str, method: &str, p: &str) -> Option<TestResponse> {
    if method == "OPTIONS" {
        return Some(
            TestResponse::status(200).header("Allow", "GET, HEAD, POST, OPTIONS, PUT, DELETE"),
        );
    }
    if method != "GET" && method != "HEAD" {
        return Some(TestResponse::status(405));
    }
    match p {
        "/" => Some(
            TestResponse::ok(format!(
                r#"<html><head><title>{d}</title><script src="/static/app.js"></script></head>
<body><h1>{d}</h1></body></html>"#
            ))
            .header("Content-Type", "text/html")
            .header("Server", "nginx/1.18.0")
            .header("X-Powered-By", "PHP/7.2.34")
            .header("Set-Cookie", "PHPSESSID=e2e0session; path=/")
            .header(
                "Content-Security-Policy",
                &format!("default-src 'self'; script-src 'self' 'unsafe-inline' https://api.{d} https://cdn.partner-cdn.test; connect-src https://staging-api.{d}"),
            ),
        ),
        "/static/app.js" => Some(
            TestResponse::ok(
                "fetch('/api/v2/users').then(r=>r.json());\n//# sourceMappingURL=app.js.map\n",
            )
            .header("Content-Type", "application/javascript"),
        ),
        "/static/app.js.map" => Some(
            TestResponse::ok(
                r#"{"version":3,"file":"app.js","sources":["webpack:///./src/main.ts","webpack:///./node_modules/axios/lib/axios.js","/home/ivanenko/projects/portal/src/api.ts"],"names":[],"mappings":"AAAA"}"#,
            )
            .header("Content-Type", "application/json"),
        ),
        "/swagger.json" => Some(
            TestResponse::ok(format!(
                r#"{{"swagger":"2.0","info":{{"title":"Portal API","version":"1.4.2"}},"host":"api.{d}","paths":{{"/users":{{"get":{{}}}},"/users/{{id}}":{{"get":{{}},"delete":{{}}}}}}}}"#
            ))
            .header("Content-Type", "application/json"),
        ),
        _ => None,
    }
}

/// Serves the client site (`www.<domain>`) from the offline fuzz-site fixture; `None` if the
/// path is not part of it.
fn fuzz_site(root: &std::path::Path, path: &str) -> Option<TestResponse> {
    if path.contains("..") || path.contains('\\') || path.contains("dot-git") {
        return Some(TestResponse::status(400));
    }
    // Git cannot store `.git` directories, so the fixture keeps it in `dot-git/`.
    let rel: Vec<&str> = path
        .trim_start_matches('/')
        .split('/')
        .map(|s| if s == ".git" { "dot-git" } else { s })
        .collect();
    let fs = root.join(rel.join("/"));
    if fs.is_file() && !path.ends_with('/') {
        return Some(TestResponse::ok(std::fs::read(&fs).ok()?));
    }
    if fs.is_dir() && path.starts_with("/docs/") && path.ends_with('/') {
        let mut names: Vec<String> = std::fs::read_dir(&fs)
            .ok()?
            .filter_map(|e| e.ok())
            .map(|e| {
                let n = e.file_name().to_string_lossy().into_owned();
                if e.path().is_dir() {
                    format!("{n}/")
                } else {
                    n
                }
            })
            .collect();
        names.sort();
        let mut b = format!("<html><head><title>Index of {path}</title></head><body><h1>Index of {path}</h1><pre><a href=\"../\">../</a>\n");
        for n in names {
            b.push_str(&format!("<a href=\"{n}\">{n}</a>\n"));
        }
        b.push_str("</pre></body></html>\n");
        return Some(TestResponse::ok(b).header("Content-Type", "text/html"));
    }
    None
}

fn collect(dir: &std::path::Path, out: &mut BTreeMap<String, PathBuf>) -> std::io::Result<()> {
    let mut ents: Vec<_> = std::fs::read_dir(dir)?.filter_map(|e| e.ok()).collect();
    ents.sort_by_key(|e| e.path());
    for e in ents {
        let p = e.path();
        if p.is_dir() {
            collect(&p, out)?;
            continue;
        }
        let n = p.file_name().unwrap().to_string_lossy().into_owned();
        let ext = n.rsplit('.').next().unwrap_or("").to_ascii_lowercase();
        if matches!(ext.as_str(), "json" | "md" | "py" | "bin" | "tag") {
            continue;
        }
        out.entry(n).or_insert(p);
    }
    Ok(())
}

pub fn zone(domain: &str) -> String {
    format!(
        "{d} A 127.0.0.1
{d} MX 10 mail.{d}
{d} TXT \"v=spf1 ip4:127.0.0.1 ~all\"
{d} NS ns1.{d}
_dmarc.{d} TXT \"v=DMARC1; p=none\"
www.{d} A 127.0.0.1
mail.{d} A 127.0.0.2
ns1.{d} A 127.0.0.1
dev.{d} A 127.0.0.1
old.{d} CNAME ghost-app.azurewebsites.net
",
        d = domain
    )
}

pub fn run(o: TestNetOpts) -> Result<bool> {
    let mut files = BTreeMap::new();
    collect(&o.corpus, &mut files)?;
    if files.is_empty() {
        return Err(anyhow!("в {} нет документов", o.corpus.display()));
    }
    let docs: Arc<BTreeMap<String, Vec<u8>>> = Arc::new(
        files
            .iter()
            .map(|(n, p)| Ok((n.clone(), std::fs::read(p)?)))
            .collect::<std::io::Result<_>>()?,
    );
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()?;
    rt.block_on(async move {
        let delay = Arc::new(AtomicU64::new(o.delay_ms));
        let cdx_delay = Arc::new(AtomicU64::new(0));
        let d = o.domain.clone();
        let (dl, dc, cdl) = (delay.clone(), docs.clone(), cdx_delay.clone());
        let site_root = o.fuzz_site.join("www");
        let site_on = site_root.is_dir();
        let www = format!("www.{}", o.domain);
        let server = TestServer::start_on(&format!("127.0.0.1:{}", o.port), move |r| {
            let p = r.path().to_string();
            let host = r
                .headers
                .get("host")
                .map(|h| h.split(':').next().unwrap_or("").to_ascii_lowercase())
                .unwrap_or_default();
            if site_on && host == www && p != "/" {
                if let Some(resp) = fuzz_site(&site_root, &p) {
                    return resp;
                }
            }
            if p == "/__delay" {
                let ms = r.query("ms").and_then(|v| v.parse().ok()).unwrap_or(0);
                dl.store(ms, Ordering::SeqCst);
                // cdx=N simulates a hanging web archive (the "skip source" / timeout scenario).
                let cdx = r.query("cdx").and_then(|v| v.parse().ok()).unwrap_or(0);
                cdl.store(cdx, Ordering::SeqCst);
                return TestResponse::ok(format!("{{\"delay_ms\":{ms},\"cdx_ms\":{cdx}}}"));
            }
            if host == d {
                if let Some(resp) = live_site(&d, &r.method, &p) {
                    return resp;
                }
            }
            if let Some(resp) = recon_site(&d, &p, r.query("url").as_deref()) {
                return resp;
            }
            if p == "/cdx/search/cdx" {
                let hang = cdl.load(Ordering::SeqCst);
                let mut rows = vec![json!(["timestamp", "original", "mimetype", "length", "statuscode"])];
                for (n, b) in dc.iter() {
                    rows.push(json!(["20240301000000", format!("https://{d}/upload/{n}"),
                        "application/octet-stream", b.len().to_string(), "200"]));
                }
                let resp = TestResponse::ok(serde_json::to_vec(&rows).unwrap());
                return if hang > 0 { resp.delay(Duration::from_millis(hang)) } else { resp };
            }
            if p == "/" && r.query("output").is_some() {
                return TestResponse::ok(
                    json!([{ "name_value": format!("www.{d}\nmail.{d}\nold.{d}") },
                        { "name_value": format!("dev.{d}") }])
                    .to_string(),
                );
            }
            if p.starts_with("/web/") || p.starts_with("/upload/") {
                let name = p.rsplit('/').next().unwrap_or("");
                let name = name.replace("%20", " ");
                if let Some(b) = dc.get(&name) {
                    let mut resp = TestResponse::ok(b.clone());
                    let ms = dl.load(Ordering::SeqCst);
                    if ms > 0 && r.method == "GET" {
                        resp = resp.delay(Duration::from_millis(ms));
                    }
                    return resp;
                }
            }
            match p.as_str() {
                "/collinfo.json" => TestResponse::ok(b"[]".to_vec()),
                "/ip" => TestResponse::ok(br#"{"ip":"203.0.113.7"}"#.to_vec()),
                "/ai/chat/completions" => TestResponse::ok(
                    r###"{"model":"deepseek-chat","choices":[{"message":{"content":"## Ключевые риски\n1. Пароли в документах."}}],"usage":{"prompt_tokens":321,"completion_tokens":12}}"###
                        .as_bytes()
                        .to_vec(),
                ),
                "/" => TestResponse::ok(format!(
                    "<html><head><title>{d}</title></head><body><h1>{d}</h1></body></html>"
                ))
                .header("Content-Type", "text/html"),
                _ if p.starts_with("/geo/") => {
                    TestResponse::ok(br#"{"ip":"203.0.113.7","country":"DE"}"#.to_vec())
                }
                _ => TestResponse::status(404),
            }
        })
        .await;
        let base = server.url();
        let site_port = server.port();
        let cfg: Value = json!({
            "base": base,
            "domain": o.domain,
            "zone": zone(&o.domain),
            "host_overrides": {
                o.domain.clone(): ["127.0.0.1"],
                format!("www.{}", o.domain): ["127.0.0.1"],
                format!("ns1.{}", o.domain): ["127.0.0.1"],
                format!("dev.{}", o.domain): ["127.0.0.1"],
            },
            "passive_download_hosts": ["127.0.0.1"],
            "alive_ports": [server.port()],
            // direct site recon (standard/full) and the web audit reach the site on this port
            "site_port": site_port,
            "download_concurrency": 2,
            "meta_concurrency": 1,
            // Fuzz without delays (harness only; the phone uses the gentle settings.fuzz).
            "fuzz_fast": true,
            "docs": docs.keys().collect::<Vec<_>>(),
        });
        if let Some(f) = &o.write_config {
            std::fs::write(f, serde_json::to_string_pretty(&cfg)?)?;
        }
        eprintln!("foca testnet: {base} · {} документов · домен {}", docs.len(), o.domain);
        let _ = tokio::signal::ctrl_c().await;
        Ok(true)
    })
}
