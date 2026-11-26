//! Live check of search result parsing: HTML captured by a real browser, fed to the core parser.
//!
//! `cargo run -p foca-search --example render_parse -- <startpage|brave|mojeek> <domain> <ext> <file.html>...`
//!
//! For each file it prints the page type and the number of result links, links in the target
//! domain and links with the requested extension; at the end it prints the unique documents
//! across all pages (deduplicated the same way the source does it).

use std::collections::BTreeSet;

use foca_search::filter::{dedup_key, ext_of_url};
use foca_search::sources::{
    classify, parse_brave_web, parse_mojeek, parse_startpage, url_in_domain, RenderEngine,
};
use foca_search::RenderPage;

fn main() {
    let a: Vec<String> = std::env::args().skip(1).collect();
    if a.len() < 4 {
        eprintln!("render_parse <startpage|brave|mojeek|yahoo|searx> <домен> <ext> <файл.html>…");
        std::process::exit(2);
    }
    let engine = match a[0].as_str() {
        "startpage" => RenderEngine::Startpage,
        "brave" | "brave_web" => RenderEngine::BraveWeb,
        "mojeek" => RenderEngine::Mojeek,
        "yahoo" => RenderEngine::Yahoo,
        // SearXNG has its own parser; the Yahoo classification is not actually used for it
        "searx" | "searx_pool" => RenderEngine::Yahoo,
        e => {
            eprintln!("неизвестный поисковик {e}");
            std::process::exit(2);
        }
    };
    let (domain, ext) = (a[1].as_str(), a[2].as_str());
    let mut all = BTreeSet::new();
    let mut pages = Vec::new();
    for f in &a[3..] {
        let html = std::fs::read_to_string(f).unwrap_or_default();
        let page = RenderPage {
            html: html.clone(),
            ..Default::default()
        };
        let searx = a[0].starts_with("searx");
        let kind = if searx {
            format!(
                "{:?}",
                foca_search::sources::searx_pool::classify_searx(None, &html)
            )
        } else {
            format!("{:?}", classify(engine, &page))
        };
        let links = match engine {
            _ if searx => foca_search::sources::parse_searx_html(&html),
            RenderEngine::Startpage => parse_startpage(&html),
            RenderEngine::BraveWeb => parse_brave_web(&html),
            RenderEngine::Mojeek => parse_mojeek(&html),
            RenderEngine::Yahoo => foca_search::sources::parse_yahoo(&html),
        };
        let dom: Vec<&String> = links.iter().filter(|u| url_in_domain(u, domain)).collect();
        let docs: Vec<&&String> = dom
            .iter()
            // same rule as the source: the requested extension, or a URL without one (search engine filetype:)
            .filter(|u| ext_of_url(u).is_none_or(|e| e == ext))
            .collect();
        let before = all.len();
        for u in &docs {
            all.insert(dedup_key(u));
        }
        pages.push(serde_json::json!({
            "file": f.rsplit('/').next().unwrap_or(f), "kind": kind,
            "links": links.len(), "in_domain": dom.len(), "docs": docs.len(), "new": all.len() - before,
        }));
    }
    let out = serde_json::json!({ "engine": a[0], "domain": domain, "ext": ext,
        "pages": pages, "unique_docs": all.len(), "sample": all.iter().take(5).collect::<Vec<_>>() });
    println!("{}", serde_json::to_string_pretty(&out).unwrap());
}
