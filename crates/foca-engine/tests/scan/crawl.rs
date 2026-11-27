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
    env_with_site_hosts(route, &[]).await
}

/// Like [`env_with_site`], with extra host names resolving to the local server: a request to any
/// of them would reach the test server and show up in its log with that Host header.
async fn env_with_site_hosts(
    route: impl Fn(Arc<std::sync::OnceLock<u16>>, &TestRequest) -> TestResponse + Send + Sync + 'static,
    hosts: &[String],
) -> (Env, TestServer) {
    let hosts = hosts.to_vec();
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
            for h in std::iter::once("drive.storage.test".to_string()).chain(hosts) {
                c.net
                    .host_overrides
                    .insert(h, vec!["127.0.0.1".parse().unwrap()]);
            }
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
    // the note body does not repeat the sub-step label the scan screen puts in front
    assert!(
        !storage_note["reason"]
            .as_str()
            .unwrap()
            .starts_with("внешние хранилища"),
        "{storage_note}"
    );
    // download stage counters: one queue pair from running to done, never shrinking, with the
    // breakdown whose documents number is the snapshot's document count
    let files: Vec<Value> = e
        .events()
        .into_iter()
        .filter(|x| x["type"] == "substep" && x["id"] == "files" && x["stage"] == "download")
        .collect();
    let last = files.last().expect("files sub-step");
    assert_eq!(last["state"], "done", "{last}");
    let max_total = files
        .iter()
        .map(|x| x["total"].as_u64().unwrap())
        .max()
        .unwrap();
    assert_eq!(last["total"].as_u64().unwrap(), max_total, "{files:?}");
    assert_eq!(last["done"], last["total"], "{last}");
    let progress: Vec<Value> = e
        .events()
        .into_iter()
        .filter(|x| x["type"] == "progress" && x["stage"] == "download" && x["total"].is_u64())
        .collect();
    let lp = progress.last().expect("download progress pair");
    assert_eq!(lp["done"], last["done"], "{lp} vs {last}");
    assert_eq!(lp["total"], last["total"], "{lp} vs {last}");
    assert!(last["private"].as_u64().unwrap() >= 1, "{last}");
    let docs_now = e.snap(&id).await["docs"].as_array().unwrap().len() as u64;
    assert!(
        last["docs"].as_u64().unwrap() <= docs_now,
        "{last} vs {docs_now}"
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
async fn storage_files_and_doc_links_stay_within_the_download_limit() {
    let (e, site) = env_with_site(site).await;
    let id = e.project("limit").await;
    // three own documents on the site, then room for two linked storage files
    crawl_scan(&e, &id, json!({ "limit": 5 })).await;
    let s = e.snap(&id).await;
    let docs: Vec<&str> = s["docs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|d| d["name"].as_str().unwrap())
        .filter(|n| !n.ends_with(".jpg"))
        .collect();
    assert_eq!(docs.len(), 5, "{docs:?}");
    for want in ["deep.docx", "hidden.xlsx", "start.pdf"] {
        assert!(docs.contains(&want), "{want}: {docs:?}");
    }
    // directly linked files come before folder contents; the rest is never fetched
    assert!(docs.contains(&"Plan 2026.pdf"), "{docs:?}");
    for id in [F1, F2] {
        assert!(
            !site.requests().iter().any(|r| r.target.contains(id)),
            "{id} is over the limit"
        );
    }
    // links inside documents get no room either
    assert_eq!(site.hits("/files/l1.pdf"), 0);
    // direct files already fill the limit: the folder is not even listed
    assert_eq!(site.hits("/embeddedfolderview"), 0);
}

/// A one-page PDF whose link annotations point at every given URL (a reference list).
fn pdf_refs(author: &str, links: &[String]) -> Vec<u8> {
    let annots: String = links
        .iter()
        .map(|l| format!("<< /Type /Annot /Subtype /Link /A << /S /URI /URI ({l}) >> >>"))
        .collect();
    format!(
        "%PDF-1.4\n1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj\n2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj\n3 0 obj << /Type /Page /Parent 2 0 R /Annots [{annots}] >> endobj\n4 0 obj << /Author ({author}) /Producer (Writer) >> endobj\ntrailer << /Root 1 0 R /Info 4 0 R >>\n%%EOF\n"
    )
    .into_bytes()
}

/// Reference hosts outside the scope that a bibliography links to: they resolve to the local
/// server, so a single request to any of them would show up in its log.
fn reference_hosts() -> Vec<String> {
    let mut v: Vec<String> = (0..24).map(|i| format!("journal{i}.example")).collect();
    v.extend(["doi.example", "publisher.example"].map(String::from));
    v
}

/// A paper with a bibliography: 50 references to journal, DOI-like and publisher hosts outside
/// the scope, a subdomain document (`docs.`), a document on an excluded subdomain (`mail.`), a
/// file and a folder on external storage, a link back to itself and a chain of in-scope documents.
fn bibliography_site(port_cell: Arc<std::sync::OnceLock<u16>>, r: &TestRequest) -> TestResponse {
    let port = port_cell.get().copied().unwrap_or(0);
    let site = format!("http://example.test:{port}");
    let drive = format!("http://drive.storage.test:{port}");
    let doc = |p: &str| format!("{site}/files/{p}");
    let host = host_of(r);
    if host == "drive.storage.test" {
        let id = r.query("id").unwrap_or_default();
        return match (r.path(), id.as_str()) {
            ("/uc", PUB) => pdf_resp(pdf("Olena Koval", None), Some("Plan 2026.pdf")),
            ("/uc", F1) => pdf_resp(pdf("Taras Melnyk", None), Some("Minutes.pdf")),
            ("/embeddedfolderview", FOLD) => html(format!(
                r#"<div class="flip-entry" id="entry-{F1}"><a href="https://drive.storage.test/file/d/{F1}/view"><div class="flip-entry-title">Minutes.pdf</div></a></div>"#
            )),
            _ => TestResponse::status(404),
        };
    }
    if host != "example.test" {
        // any other host: a document that must never be fetched
        return pdf_resp(pdf("X", None), None);
    }
    match r.path() {
        "/" => html(r#"<a href="/files/paper.pdf">paper</a>"#),
        "/files/paper.pdf" => {
            let hosts = reference_hosts();
            let mut refs: Vec<String> = (0..50)
                .map(|i| {
                    let h = &hosts[i % hosts.len()];
                    if h.starts_with("doi") {
                        format!("http://{h}:{port}/10.5555/ref.{i}.pdf")
                    } else {
                        format!("http://{h}:{port}/articles/{i}.pdf")
                    }
                })
                .collect();
            refs.push(doc("a.pdf"));
            refs.push(doc("paper.pdf"));
            refs.push(format!("{site}/about"));
            refs.push(format!("http://docs.example.test:{port}/files/sub.pdf"));
            refs.push(format!(
                "http://mail.example.test:{port}/files/excluded.pdf"
            ));
            refs.push(format!("{drive}/file/d/{PUB}/view?usp=sharing"));
            refs.push(format!("{drive}/drive/folders/{FOLD}?usp=sharing"));
            pdf_resp(pdf_refs("P", &refs), None)
        }
        // a -> paper closes the loop paper -> a -> paper; a -> a links to itself
        "/files/a.pdf" => pdf_resp(
            pdf_refs("A", &[doc("b.pdf"), doc("paper.pdf"), doc("a.pdf")]),
            None,
        ),
        "/files/b.pdf" => pdf_resp(pdf_refs("B", &[doc("a.pdf"), doc("c.pdf")]), None),
        "/files/c.pdf" => pdf_resp(pdf_refs("C", &[doc("d.pdf")]), None),
        "/files/d.pdf" => pdf_resp(pdf("D", None), None),
        _ => TestResponse::status(404),
    }
}

/// Only in-scope things are followed from links inside documents: none of the 50 off-scope
/// bibliography hosts, no subdomain outside an exact-host scope, no excluded subdomain; in-scope
/// documents once each up to two steps (a loop fetches nothing twice); nothing from the site at
/// the passive level; external storage only when its switch is on, and then only the exact
/// linked file, never the folder. Followed documents also count against the download limit.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn doc_links_only_follow_scope() {
    let mut extra = reference_hosts();
    extra.extend(["docs.example.test", "mail.example.test"].map(String::from));
    let (e, site) = env_with_site_hosts(bibliography_site, &extra).await;
    let gets = |from: usize, host: &str, path: &str| {
        site.requests()[from..]
            .iter()
            .filter(|r| r.method == "GET" && host_of(r) == host && r.path() == path)
            .count()
    };
    let hosts_since =
        |from: usize| -> Vec<String> { site.requests()[from..].iter().map(host_of).collect() };
    let names = |s: &Value| -> Vec<String> {
        let mut v: Vec<String> = s["docs"]
            .as_array()
            .unwrap()
            .iter()
            .map(|d| d["name"].as_str().unwrap().to_string())
            .collect();
        v.sort_unstable();
        v
    };
    let refs = reference_hosts();
    let no_reference_requests = |from: usize, label: &str| {
        let hit: Vec<String> = hosts_since(from)
            .into_iter()
            .filter(|h| refs.contains(h))
            .collect();
        assert!(
            hit.is_empty(),
            "{label}: requests to reference hosts {hit:?}"
        );
    };

    // domain scope example.test with mail.example.test excluded, storage on
    let id = e.project("bib").await;
    let from = site.requests().len();
    crawl_scan(&e, &id, json!({})).await;
    let s = e.snap(&id).await;
    assert_eq!(
        names(&s),
        ["Plan 2026.pdf", "a.pdf", "b.pdf", "paper.pdf", "sub.pdf"],
        "depth 2 from the page, in-scope subdomain, the linked storage file"
    );
    // (a) none of the 50 references
    no_reference_requests(from, "domain scope");
    // (c) the excluded subdomain is never contacted, although it is under the target domain
    assert!(
        !hosts_since(from).iter().any(|h| h == "mail.example.test"),
        "excluded host requested"
    );
    // (d) in-scope documents once each, up to two steps; the loop adds nothing
    for (path, n) in [
        ("/files/paper.pdf", 1),
        ("/files/a.pdf", 1),
        ("/files/b.pdf", 1),
        ("/files/c.pdf", 0),
        ("/files/d.pdf", 0),
        ("/about", 0),
    ] {
        assert_eq!(gets(from, "example.test", path), n, "{path}");
    }
    assert_eq!(gets(from, "docs.example.test", "/files/sub.pdf"), 1);
    let b = s["docs"]
        .as_array()
        .unwrap()
        .iter()
        .find(|d| d["name"] == "b.pdf")
        .unwrap();
    assert_eq!(b["provenance"]["depth"], 2);
    // (f, on) only the exact linked file id on the storage, the folder is never listed
    let drive: Vec<String> = site.requests()[from..]
        .iter()
        .filter(|r| host_of(r) == "drive.storage.test")
        .map(|r| r.target.clone())
        .collect();
    assert!(!drive.is_empty(), "the linked storage file is fetched");
    assert!(drive.iter().all(|t| t.contains(PUB)), "{drive:?}");
    assert!(
        !drive.iter().any(|t| t.contains(FOLD) || t.contains(F1)),
        "{drive:?}"
    );
    // the request journal agrees: no reference host, no excluded host
    let log = e
        .call("request_log_get", json!({ "project": id, "limit": 2000 }))
        .await;
    for r in log.as_array().unwrap() {
        let h = r["host"].as_str().unwrap_or("");
        assert!(
            !refs.iter().any(|x| x == h) && h != "mail.example.test",
            "journal row to an off-scope host {r}"
        );
    }

    // (b) exact-host scope: the docs. subdomain is not covered and not requested
    let p = e
        .call(
            "project_create",
            json!({ "name": "bib-exact", "targets": [{ "v": "http://example.test/", "type": "url" }],
                "excludes": [] }),
        )
        .await;
    let id = p["id"].as_str().unwrap().to_string();
    let from = site.requests().len();
    crawl_scan(&e, &id, json!({})).await;
    let got = names(&e.snap(&id).await);
    assert!(
        got.iter().any(|n| n == "a.pdf"),
        "in-scope links still followed: {got:?}"
    );
    assert!(
        !hosts_since(from).iter().any(|h| h == "docs.example.test"),
        "subdomain outside an exact-host scope requested"
    );
    assert!(!got.iter().any(|n| n == "sub.pdf"), "{got:?}");
    no_reference_requests(from, "exact-host scope");

    // (f, off) storage switch off: the storage link inside the document is not requested
    let id = e.project("bib-nostorage").await;
    let from = site.requests().len();
    crawl_scan(&e, &id, json!({ "crawl": { "storage": false } })).await;
    assert!(
        !hosts_since(from).iter().any(|h| h == "drive.storage.test"),
        "storage requested with the switch off"
    );
    assert!(!names(&e.snap(&id).await)
        .iter()
        .any(|n| n == "Plan 2026.pdf"));
    no_reference_requests(from, "storage off");

    // (e) passive level: the site is never contacted, so no document link is followed either
    let id = e.project("bib-passive").await;
    let from = site.requests().len();
    e.call(
        "scan_start",
        json!({ "project": id, "profile": "passive", "sources": ["crawler"] }),
    )
    .await;
    e.wait().await;
    let hit = hosts_since(from);
    assert!(hit.is_empty(), "passive scan contacted {hit:?}");

    // the followed documents use up the download limit like any other document
    let id = e.project("bib-limit").await;
    let from = site.requests().len();
    crawl_scan(&e, &id, json!({ "limit": 2 })).await;
    assert_eq!(names(&e.snap(&id).await), ["a.pdf", "paper.pdf"]);
    assert_eq!(gets(from, "example.test", "/files/b.pdf"), 0);
    no_reference_requests(from, "limit");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn crawl_warns_when_app_shell_pages_cannot_be_rendered() {
    let (e, _site) = env_with_site(|_, r: &TestRequest| match r.path() {
        "/" => html(
            r#"<!doctype html><html><head><script type="module" src="/assets/index.js"></script></head>
            <body><div id="root"></div></body></html>"#,
        ),
        _ => TestResponse::status(404),
    })
    .await;
    let id = e.project("shell").await;
    crawl_scan(&e, &id, json!({})).await;
    let w = e
        .events()
        .into_iter()
        .find(|x| x["type"] == "warning" && x["code"] == "crawl_no_render")
        .expect("no-render warning");
    assert!(w["message"].as_str().unwrap().contains(": 1."), "{w}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn images_off_are_neither_fetched_nor_counted_as_documents() {
    let (e, site) = env_with_site(site).await;
    let id = e.project("noimg").await;
    crawl_scan(&e, &id, json!({ "limit": 4, "crawl": { "images": false } })).await;
    let s = e.snap(&id).await;
    let names: Vec<&str> = s["docs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|d| d["name"].as_str().unwrap())
        .collect();
    assert!(
        !names
            .iter()
            .any(|n| n.ends_with(".jpg") || n.ends_with(".png")),
        "{names:?}"
    );
    assert_eq!(site.hits("/img/photo.jpg") + site.hits("/img/logo.png"), 0);
    // images no longer use up the limit: the deep page is still reached
    for want in ["deep.docx", "hidden.xlsx", "start.pdf"] {
        assert!(names.contains(&want), "{want}: {names:?}");
    }
    let crawl = e
        .events()
        .into_iter()
        .rfind(|x| x["type"] == "crawl")
        .unwrap();
    assert_ne!(crawl["stop"], "docs", "{crawl}");
}

/// Archive images have their own budget: they neither take room from the document limit nor
/// wait for it, obey `crawl.max_images`, and stay out when images are off.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn archive_images_use_the_image_budget_not_the_document_limit() {
    let e = common::env(0).await;
    let names = |s: &Value| -> Vec<String> {
        s["docs"]
            .as_array()
            .unwrap()
            .iter()
            .map(|d| d["name"].as_str().unwrap().to_string())
            .collect()
    };
    let scan = |id: String, extra: Value| {
        let e = &e;
        async move {
            let mut args = json!({ "project": id, "profile": "passive", "sources": ["wayback"],
                "limit": 2 });
            if let (Some(o), Value::Object(x)) = (args.as_object_mut(), extra) {
                o.extend(x);
            }
            e.call("scan_start", args).await;
            e.wait().await;
        }
    };
    let id = e.project("img-budget").await;
    scan(id.clone(), json!({})).await;
    let got = names(&e.snap(&id).await);
    let docs = got.iter().filter(|n| !n.ends_with(".jpg")).count();
    assert_eq!(docs, 2, "the document limit holds: {got:?}");
    assert!(
        got.iter().any(|n| n == "photo.jpg"),
        "the archive image comes on top of the limit: {got:?}"
    );
    // images off: the archive image is not queued at all
    let id = e.project("img-off").await;
    scan(id.clone(), json!({ "crawl": { "images": false } })).await;
    let got = names(&e.snap(&id).await);
    assert!(!got.iter().any(|n| n.ends_with(".jpg")), "{got:?}");
    assert_eq!(got.len(), 2, "{got:?}");
    // the image cap applies to archive images too
    let id = e.project("img-cap").await;
    scan(id.clone(), json!({ "crawl": { "max_images": 0 } })).await;
    let got = names(&e.snap(&id).await);
    assert!(!got.iter().any(|n| n.ends_with(".jpg")), "{got:?}");
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
async fn pause_stops_new_crawl_requests_at_once() {
    let (e, site) = env_with_site(|_, r: &TestRequest| match r.path() {
        "/" => html(
            (1..=16)
                .map(|i| format!(r#"<a href="/p{i}">{i}</a>"#))
                .collect::<String>(),
        ),
        "/robots.txt" | "/sitemap.xml" => TestResponse::status(404),
        _ => html("<p>page</p>"),
    })
    .await;
    // a slow limiter keeps a whole batch of pages waiting for tokens when the pause comes
    e.call("settings_set", json!({ "patch": { "net": { "rps": 2 } } }))
        .await;
    let id = e.project("pause").await;
    e.call(
        "scan_start",
        json!({ "project": id, "profile": "std", "sources": ["crawler"] }),
    )
    .await;
    let pages = || {
        site.requests()
            .iter()
            .filter(|r| r.path().starts_with("/p"))
            .count()
    };
    for _ in 0..400 {
        if pages() >= 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    e.call("scan_pause", json!({})).await;
    // requests already on the wire may still land
    tokio::time::sleep(Duration::from_millis(300)).await;
    let at_pause = site.requests().len();
    tokio::time::sleep(Duration::from_millis(2000)).await;
    assert_eq!(
        site.requests().len(),
        at_pause,
        "no request may start after the pause"
    );
    e.call("scan_resume", json!({})).await;
    e.wait().await;
    assert_eq!(pages(), 16, "the crawl continues after the resume");
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

/// Files in the formats added in 2.0.0-beta.4 linked from a page.
fn new_formats_site(_port: Arc<std::sync::OnceLock<u16>>, r: &TestRequest) -> TestResponse {
    const KML: &str = r#"<kml xmlns="http://www.opengis.net/kml/2.2"><Document><name>Depots</name><Placemark><Point><coordinates>30.5,50.4</coordinates></Point></Placemark></Document></kml>"#;
    const GPX: &str = r#"<gpx version="1.1" creator="Example Tracker"><trk><trkseg><trkpt lat="50.4" lon="30.5"/></trkseg></trk></gpx>"#;
    const DXF: &str =
        "  0\nSECTION\n  2\nHEADER\n  9\n$LASTSAVEDBY\n  1\nmkovalenko\n  0\nENDSEC\n  0\nEOF\n";
    const NB: &str = r#"{"cells":[],"metadata":{"kernelspec":{"display_name":"Python 3","name":"python3"}},"nbformat":4,"nbformat_minor":5}"#;
    const MAP: &str =
        r#"{"version":3,"sources":["file:///home/jdev/app/src/a.ts"],"mappings":"AAAA"}"#;
    match r.path() {
        "/" => html(
            r#"<a href="/files/depots.kml">kml</a><a href="/files/run.gpx">gpx</a>
               <a href="/files/plan.dxf">dxf</a><a href="/files/report.ipynb">nb</a>
               <a href="/files/app.js.map">map</a><a href="/files/page.php">php</a>"#,
        ),
        "/files/depots.kml" => TestResponse::ok(KML),
        "/files/run.gpx" => TestResponse::ok(GPX),
        "/files/plan.dxf" => TestResponse::ok(DXF),
        "/files/report.ipynb" => TestResponse::ok(NB),
        "/files/app.js.map" => TestResponse::ok(MAP),
        "/files/page.php" => html("<p>x</p>"),
        _ => TestResponse::status(404),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn crawl_downloads_the_new_document_formats() {
    let (e, site) = env_with_site(new_formats_site).await;
    let id = e.project("newfmt").await;
    crawl_scan(&e, &id, json!({})).await;
    let s = e.snap(&id).await;
    for want in [
        "depots.kml",
        "run.gpx",
        "plan.dxf",
        "report.ipynb",
        "app.js.map",
    ] {
        let d = doc(&s, want).unwrap_or_else(|| panic!("{want}: {}", s["docs"]));
        assert_ne!(d["status"], "error", "{d}");
    }
    assert!(doc(&s, "page.php").is_none());
    // the wizard's "kml" choice also brings KMZ, but not the other new formats
    let id2 = e.project("newfmt2").await;
    crawl_scan(&e, &id2, json!({ "exts": ["kml"] })).await;
    let s2 = e.snap(&id2).await;
    assert!(doc(&s2, "depots.kml").is_some());
    assert!(doc(&s2, "plan.dxf").is_none());
    assert!(site.hits("/files/depots.kml") >= 1);
}
