//! Crawler v2 on a local site: pages deeper than two links, sitemap-only pages, files on public
//! external storage linked from the site (a fake storage host, never a real provider), links
//! inside downloaded documents, a resumable frontier, 429 pacing and the passive profile.

use std::sync::Arc;
use std::time::Duration;

use foca_engine::MemoryKeys;
use foca_net::testserver::{TestRequest, TestResponse, TestServer};
use serde_json::{json, Value};

use crate::common::{self, corpus_dir, Env};

const PUB: &str = "PUBfile00000001";
const PRIV: &str = "PRIVfile0000001";
const FOLD: &str = "FOLDER000000001";
const F1: &str = "FOLDfile0000001";
const F2: &str = "FOLDfile0000002";
const DOC: &str = "DOCSexport00001";

fn host_of(r: &TestRequest) -> String {
    let h = r.headers.get("host").cloned().unwrap_or_default();
    h.split(':').next().unwrap_or("").to_string()
}

fn html(b: impl Into<String>) -> TestResponse {
    TestResponse::ok(b.into()).header("Content-Type", "text/html; charset=utf-8")
}

fn file(path: &str) -> Vec<u8> {
    std::fs::read(corpus_dir().join(path)).unwrap()
}

/// A one-page PDF with an author and, optionally, a link annotation.
fn pdf(author: &str, link: Option<&str>) -> Vec<u8> {
    let annot = link
        .map(|l| format!("/Annots [<< /Type /Annot /Subtype /Link /A << /S /URI /URI ({l}) >> >>]"))
        .unwrap_or_default();
    format!(
        "%PDF-1.4\n1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj\n2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj\n3 0 obj << /Type /Page /Parent 2 0 R {annot} >> endobj\n4 0 obj << /Author ({author}) /Producer (Writer) >> endobj\ntrailer << /Root 1 0 R /Info 4 0 R >>\n%%EOF\n"
    )
    .into_bytes()
}

fn pdf_resp(b: Vec<u8>, name: Option<&str>) -> TestResponse {
    let r = TestResponse::ok(b).header("Content-Type", "application/pdf");
    match name {
        Some(n) => r.header(
            "Content-Disposition",
            &format!("attachment; filename=\"{n}\""),
        ),
        None => r,
    }
}

/// The site (`example.test`) and the storage host (`drive.storage.test`) on one server, routed by
/// the Host header.
fn site(port_cell: Arc<std::sync::OnceLock<u16>>, r: &TestRequest) -> TestResponse {
    let port = port_cell.get().copied().unwrap_or(0);
    let site = format!("http://example.test:{port}");
    let drive = format!("http://drive.storage.test:{port}");
    if host_of(r) == "drive.storage.test" {
        let id = r.query("id").unwrap_or_default();
        return match (r.path(), id.as_str()) {
            ("/uc", PUB) => pdf_resp(pdf("Olena Koval", None), Some("Plan 2026.pdf")),
            ("/uc", F1) => pdf_resp(pdf("Taras Melnyk", None), Some("Minutes.pdf")),
            ("/uc", F2) => pdf_resp(pdf("Iryna Bondar", None), Some("Budget.pdf")),
            ("/uc", PRIV) => html("<html><title>Sign in</title></html>"),
            ("/embeddedfolderview", FOLD) => html(format!(
                r#"<div class="flip-entry" id="entry-{F1}"><a href="https://drive.storage.test/file/d/{F1}/view?usp=drive_web"><div class="flip-entry-title">Minutes.pdf</div></a></div>
                   <div class="flip-entry" id="entry-{F2}"><a href="https://drive.storage.test/file/d/{F2}/view?usp=drive_web"><div class="flip-entry-title">Budget.pdf</div></a></div>"#
            )),
            _ if r.path() == format!("/presentation/d/{DOC}/export/pptx") => {
                TestResponse::ok(file("ooxml/strategy.pptx")).header(
                    "Content-Type",
                    "application/vnd.openxmlformats-officedocument.presentationml.presentation",
                )
            }
            _ => TestResponse::status(404),
        };
    }
    match r.path() {
        "/robots.txt" => TestResponse::ok("User-agent: *\nDisallow: /admin/\n"),
        "/sitemap.xml" => TestResponse::ok(format!(
            "<urlset><url><loc>{site}/hidden</loc></url></urlset>"
        )),
        "/" => html(
            r#"<a href="/a">a</a><a href="/storage">storage</a><a href="/files/start.pdf">start</a>
               <img src="/img/photo.jpg" width="1600" height="1200"><img src="/img/logo.png">"#,
        ),
        "/a" => html(r#"<a href="/b">b</a>"#),
        "/b" => html(r#"<a href="/c">c</a>"#),
        "/c" => html(r#"<a href="/d">d</a>"#),
        "/d" => html(r#"<a href="/files/deep.docx">deep</a>"#),
        "/hidden" => html(r#"<a href="/files/hidden.xlsx">hidden</a>"#),
        "/storage" => html(format!(
            r#"<a href="{drive}/file/d/{PUB}/view?usp=sharing">plan</a>
               <a href="{drive}/drive/folders/{FOLD}?usp=sharing">folder</a>
               <a href="{drive}/presentation/d/{DOC}/edit">slides</a>
               <a href="{drive}/file/d/{PRIV}/view">private</a>"#
        )),
        "/files/deep.docx" => TestResponse::ok(file("ooxml/contract.docx")),
        "/files/hidden.xlsx" => TestResponse::ok(file("ooxml/schedule.xlsx")),
        "/files/start.pdf" => pdf_resp(pdf("A", Some(&format!("{site}/files/l1.pdf"))), None),
        "/files/l1.pdf" => pdf_resp(pdf("B", Some(&format!("{site}/files/l2.pdf"))), None),
        "/files/l2.pdf" => pdf_resp(pdf("C", Some(&format!("{site}/files/l3.pdf"))), None),
        "/files/l3.pdf" => pdf_resp(pdf("D", None), None),
        "/img/photo.jpg" => TestResponse::ok(file("images/photo.jpg")),
        "/img/logo.png" => TestResponse::ok(vec![0u8; 10]),
        _ => TestResponse::status(404),
    }
}

async fn env_with_site(
    route: impl Fn(Arc<std::sync::OnceLock<u16>>, &TestRequest) -> TestResponse + Send + Sync + 'static,
) -> (Env, TestServer) {
    let cell: Arc<std::sync::OnceLock<u16>> = Arc::new(std::sync::OnceLock::new());
    let c2 = cell.clone();
    let site = TestServer::start(move |r| route(c2.clone(), r)).await;
    let port = site.port();
    let _ = cell.set(port);
    let dir = tempfile::tempdir().unwrap();
    let server = common::server(0).await;
    let keys = Arc::new(MemoryKeys::new());
    let (engine, events, pause_at) =
        common::open_with(dir.path(), &server.url(), keys.clone(), |c| {
            c.site_port = Some(port);
            c.endpoints.storage.drive = format!("http://drive.storage.test:{port}");
            c.endpoints.storage.docs = format!("http://drive.storage.test:{port}");
            c.net.host_overrides.insert(
                "drive.storage.test".into(),
                vec!["127.0.0.1".parse().unwrap()],
            );
        });
    (
        Env {
            dir,
            server,
            engine,
            events,
            pause_at,
            keys,
        },
        site,
    )
}

async fn crawl_scan(e: &Env, id: &str, extra: Value) {
    let mut args = json!({ "project": id, "profile": "std", "sources": ["crawler"] });
    if let (Some(o), Value::Object(x)) = (args.as_object_mut(), extra) {
        o.extend(x);
    }
    e.call("scan_start", args).await;
    e.wait().await;
}

fn doc<'a>(s: &'a Value, name: &str) -> Option<&'a Value> {
    s["docs"]
        .as_array()
        .unwrap()
        .iter()
        .find(|d| d["name"] == name)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn crawl_finds_deep_sitemap_storage_and_doc_link_documents() {
    let (e, site) = env_with_site(site).await;
    let id = e.project("crawl").await;
    crawl_scan(&e, &id, json!({})).await;
    let s = e.snap(&id).await;
    let names: Vec<&str> = s["docs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|d| d["name"].as_str().unwrap())
        .collect();
    // deeper than the old depth 2, and a page only the sitemap knows
    for want in ["deep.docx", "hidden.xlsx"] {
        assert!(names.contains(&want), "{want}: {names:?}");
    }
    // linked external storage: a file, a folder's files and a Google export
    for want in [
        "Plan 2026.pdf",
        "Minutes.pdf",
        "Budget.pdf",
        "gdocs-DOCSexport00001.pptx",
    ] {
        assert!(names.contains(&want), "{want}: {names:?}");
    }
    // the private file is reported, not downloaded
    assert!(site.requests().iter().any(|r| r.target.contains(PRIV)));
    let storage_note = e
        .events()
        .into_iter()
        .find(|x| x["type"] == "substep" && x["id"] == "storage")
        .expect("storage summary");
    assert!(
        storage_note["reason"]
            .as_str()
            .unwrap()
            .contains("без публичного доступа 1"),
        "{storage_note}"
    );
    // links inside documents: two steps from the crawled page, no third
    for want in ["start.pdf", "l1.pdf", "l2.pdf"] {
        assert!(names.contains(&want), "{want}: {names:?}");
    }
    assert!(
        !names.contains(&"l3.pdf"),
        "doc-link depth limit: {names:?}"
    );
    assert_eq!(site.hits("/files/l3.pdf"), 0);
    // selected images only
    assert!(names.contains(&"photo.jpg"));
    assert!(!names.contains(&"logo.png"));

    // provenance
    let deep = doc(&s, "deep.docx").unwrap();
    assert_eq!(deep["provenance"]["kind"], "page");
    assert!(
        deep["provenance"]["from"].as_str().unwrap().ends_with("/d"),
        "{deep}"
    );
    let plan = doc(&s, "Plan 2026.pdf").unwrap();
    assert_eq!(plan["provenance"]["storage"], "gdrive");
    assert!(plan["provenance"]["from"]
        .as_str()
        .unwrap()
        .ends_with("/storage"));
    assert!(plan["provenance"]["link"]
        .as_str()
        .unwrap()
        .contains("/file/d/"));
    let l2 = doc(&s, "l2.pdf").unwrap();
    assert_eq!(l2["provenance"]["kind"], "doc");
    assert_eq!(l2["provenance"]["from"], "l1.pdf");
    assert_eq!(l2["provenance"]["depth"], 2);
    // a Google export: the metadata is Google's, not the author's
    let ex = doc(&s, "gdocs-DOCSexport00001.pptx").unwrap();
    assert_eq!(ex["provenance"]["export"], true);
    assert!(ex["author"].is_null(), "{ex}");
    assert!(!s["people"]
        .as_array()
        .unwrap()
        .iter()
        .any(|p| p["src"].as_str().is_some_and(|x| x.contains("gdocs-"))));

    // the storage host saw only the linked items, as passive requests marked in the journal
    for r in site
        .requests()
        .iter()
        .filter(|r| host_of(r) == "drive.storage.test")
    {
        let t = &r.target;
        assert!(
            [PUB, PRIV, FOLD, F1, F2, DOC]
                .iter()
                .any(|id| t.contains(id)),
            "unexpected storage request {t}"
        );
    }
    let log = e
        .call("request_log_get", json!({ "project": id, "limit": 2000 }))
        .await;
    let storage: Vec<&Value> = log
        .as_array()
        .unwrap()
        .iter()
        .filter(|r| r["host"] == "drive.storage.test")
        .collect();
    assert!(!storage.is_empty());
    assert!(storage
        .iter()
        .all(|r| r["module"] == "storage" && r["access"] == "passive"));
    assert!(storage.iter().any(|r| r["note"] == "linked_storage"));
    // crawler counters reached the UI
    let crawl = e
        .events()
        .into_iter()
        .rfind(|x| x["type"] == "crawl")
        .expect("crawl event");
    assert!(crawl["pages"].as_u64().unwrap() >= 7, "{crawl}");
    assert_eq!(crawl["storage"], 4);
    assert_eq!(crawl["finished"], true);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn crawl_resumes_frontier_in_next_scan() {
    let (e, site) = env_with_site(|_, r: &TestRequest| {
        let p = r.path().to_string();
        if let Some(n) = p.strip_prefix("/p").and_then(|n| n.parse::<u32>().ok()) {
            return if n < 14 {
                html(format!(r#"<a href="/p{}">next</a>"#, n + 1))
            } else {
                html(r#"<a href="/files/end.docx">end</a>"#)
            };
        }
        match p.as_str() {
            "/" => html(r#"<a href="/p1">start</a>"#),
            "/files/end.docx" => TestResponse::ok(file("ooxml/contract.docx")),
            _ => TestResponse::status(404),
        }
    })
    .await;
    let id = e.project("resume").await;
    let opts = json!({ "crawl": { "max_pages": 10, "max_depth": 20 } });
    crawl_scan(&e, &id, opts.clone()).await;
    let s = e.snap(&id).await;
    assert!(doc(&s, "end.docx").is_none());
    let first = e
        .events()
        .into_iter()
        .rfind(|x| x["type"] == "crawl")
        .unwrap();
    assert_eq!(first["finished"], false);
    assert_eq!(first["stop"], "pages");
    e.clear_events();
    crawl_scan(&e, &id, opts).await;
    let s = e.snap(&id).await;
    assert!(
        doc(&s, "end.docx").is_some(),
        "the second scan continues the frontier"
    );
    let second = e
        .events()
        .into_iter()
        .rfind(|x| x["type"] == "crawl")
        .unwrap();
    assert_eq!(second["resumed"], true);
    assert_eq!(second["finished"], true);
    for p in ["/", "/p1", "/p5"] {
        assert_eq!(site.hits(p), 1, "{p} is not fetched again");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn crawl_slows_down_and_stops_a_rate_limited_host() {
    let (e, site) = env_with_site(|_, r: &TestRequest| match r.path() {
        "/" => html(
            (1..=8)
                .map(|i| format!(r#"<a href="/p{i}">{i}</a>"#))
                .collect::<String>(),
        ),
        "/robots.txt" | "/sitemap.xml" => TestResponse::status(404),
        _ => TestResponse::status(429).header("Retry-After", "0"),
    })
    .await;
    let id = e.project("limits").await;
    crawl_scan(&e, &id, json!({})).await;
    let limited = site
        .requests()
        .iter()
        .filter(|r| r.path().starts_with("/p"))
        .count();
    // five limited answers stop the host; a request already in flight may add one
    assert!((5..=6).contains(&limited), "{limited}");
    let crawl = e
        .events()
        .into_iter()
        .rfind(|x| x["type"] == "crawl")
        .unwrap();
    assert_eq!(crawl["rate"], "stopped");
    assert_eq!(crawl["stopped_hosts"][0], "example.test");
    assert!(e
        .events()
        .iter()
        .any(|x| x["type"] == "warning" && x["code"] == "crawl_rate_limited"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn passive_profile_sends_no_crawl_requests() {
    let (e, site) = env_with_site(site).await;
    let id = e.project("passive").await;
    e.call(
        "scan_start",
        json!({ "project": id, "profile": "passive", "sources": ["crawler", "wayback"] }),
    )
    .await;
    e.wait().await;
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(site.requests().is_empty(), "{:?}", site.requests());
    let log = e
        .call("request_log_get", json!({ "project": id, "limit": 2000 }))
        .await;
    assert!(!log
        .as_array()
        .unwrap()
        .iter()
        .any(|r| r["module"] == "crawler" || r["module"] == "storage"));
}
