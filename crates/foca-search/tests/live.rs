//! Live source tests (a few requests to public APIs for iana.org).
//! `cargo test -p foca-search --test live -- --ignored --nocapture --test-threads=1`

use std::sync::Arc;

use foca_core::Scope;
use foca_net::{MemorySink, NetClient, NetConfig};
use foca_search::sources::{CommonCrawl, Wayback};
use foca_search::{DocumentSource, DownloadConfig, Downloader, ExtFilter, SearchCtx};

fn ctx() -> SearchCtx {
    let net = NetClient::new(
        NetConfig::default(),
        Scope::default(),
        Arc::new(MemorySink::new()),
    )
    .unwrap();
    let mut c = SearchCtx::new(net);
    c.limit = 10;
    c.filter = ExtFilter::parse("pdf");
    c
}

#[tokio::test]
#[ignore]
async fn live_wayback_and_passive_download() {
    let c = ctx();
    let wb = Wayback {
        max_pages: 4,
        ..Default::default()
    };
    let f = wb.find(&c, "iana.org").await.unwrap();
    for u in &f.urls {
        println!("{} {:?}", u.url, u.size);
    }
    assert!(!f.urls.is_empty());
    let small = f
        .urls
        .iter()
        .filter(|u| u.size.unwrap_or(u64::MAX) < 2_000_000)
        .min_by_key(|u| u.size);
    if let Some(u) = small {
        let dir = tempfile::tempdir().unwrap();
        let d = Downloader::new(c.net.clone(), dir.path(), DownloadConfig::default());
        let r = d.download(&u.url).await.unwrap();
        println!(
            "скачано пассивно: {} {} байт sha256={}",
            r.name, r.size, r.sha256
        );
    }
}

#[tokio::test]
#[ignore]
async fn live_common_crawl() {
    let c = ctx();
    match CommonCrawl::default().find(&c, "iana.org").await {
        Ok(f) => println!(
            "CC: {} URL: {:?}",
            f.urls.len(),
            f.urls.iter().map(|u| &u.url).collect::<Vec<_>>()
        ),
        Err(e) => println!("CC недоступен: {e}"),
    }
}
