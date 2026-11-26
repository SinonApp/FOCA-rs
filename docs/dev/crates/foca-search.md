# foca-search

↑ [Core Crates](README.md) · [Developer Guide](../README.md) · [Architecture](../architecture.md)

- [Purpose](#purpose)
- [Modules](#modules)
- [Public API](#public-api)
- [Tests](#tests)
- [Pitfalls](#pitfalls)

Path: `crates/foca-search/` · `src/` lines: 8,092 · tests: 73 · depends on: [foca-core](foca-core.md), [foca-net](foca-net.md), [foca-store](foca-store.md) *(optional, feature `store`)*

## Purpose

`foca-search` discovers target document URLs and subdomains across passive archives, APIs, WebView dork engines, and site crawling, and downloads files safely through a resumable queue.

- **`DocumentSource`** (`source.rs`): pluggable source trait covering Wayback CDX, Common Crawl, crt.sh, CertSpotter, AlienVault OTX, urlscan.io, Arquivo.pt, HudsonRock, passive subdomain sources (`sources/subdomains.rs`), search APIs (`Brave`, `SearXNG`), WebView search-engine dorks (`Startpage`, `Brave Web`, `Yahoo`, `Mojeek`, public `SearXNG` pool) coordinated via the scan-wide `dorkboard.rs` and `sources/dorkpool.rs`, and the target site `Crawler` (`TouchesTarget`).
- **`filter` & `urlinfo`**: extension filtering (`F-5`), URL normalization and deduplication, and pre-download URL analysis (`F-7`: usernames in paths, servers, folders).
- **`download`**: streaming downloader (`F-8`, `F-9`, `I-21`) using HEAD (or aborted GET), actual byte-stream size capping, temporary file → SHA-256 → content-addressed storage, concurrency, retries, and resumable persistence via `TaskQueue` (implemented on top of `foca-store` behind the `store` feature).

All network calls go through `foca_net::NetClient` for scope enforcement, request logging, rate limits, and cancellation.

Fixtures: [crates/foca-search/tests/fixtures/README.md](../../../crates/foca-search/tests/fixtures/README.md).

## Modules

Layout: `sources/` holds one module per source family; the scan-wide dork queue is `dorkboard.rs`, driven by `sources/dorkpool.rs`.

| File | Lines | Contents |
|---|---|---|
| `src/dorkboard.rs` | 485 | Scan-wide dork board: one queue of `site:<domain> filetype:…` queries shared by all keyless dork engines |
| `src/download.rs` | 702 | Resumable, size-capped, SHA-256 content-addressed document downloader |
| `src/filter.rs` | 287 | Extension filter (`DEFAULT_EXTS`), URL normalization, and deduplication |
| `src/html.rs` | 361 | Lightweight tag/attribute HTML link tokenizer (no DOM), `robots.txt`, and `sitemap.xml` parsers |
| `src/lib.rs` | 35 | Crate root and re-exports |
| `src/render.rs` | 251 | `RenderFetch` trait and `RenderRequest` / `RenderStep` browser scripting model (executed by Android `RenderFetcher.kt`) |
| `src/source.rs` | 597 | `DocumentSource` trait and concurrent runner (`run_sources`, `run_sources_ctl`) |
| `src/sources/archive.rs` | 874 | Passive archives & CT: Wayback CDX, Common Crawl Index, crt.sh |
| `src/sources/crawler.rs` | 523 | Target-site breadth-first crawler (`TouchesTarget`): `robots.txt`, `sitemap.xml`, link traversal |
| `src/sources/dorkpool.rs` | 326 | Dork driver of the keyless engines (`run_dorks`): query planning, paging, cache, budget, pacing, failover |
| `src/sources/engines.rs` | 539 | Search APIs without HTML scraping: Brave Search API (key) and custom SearXNG instance |
| `src/sources/mod.rs` | 83 | Source catalog and `by_ids` lookup |
| `src/sources/render_engines.rs` | 1,056 | Embedded-browser dork sources (`Startpage`, `Brave Web`, `Yahoo`, `Mojeek`, `DuckDuckGo`, `Bing`) |
| `src/sources/searx_pool.rs` | 676 | Public SearXNG instance pool driven through the embedded browser |
| `src/sources/subdomains.rs` | 277 | Keyless passive subdomain sources (modeled on subfinder) |
| `src/sources/urls.rs` | 723 | Keyless passive document URL sources (AlienVault OTX `url_list`, urlscan.io, Arquivo.pt, HudsonRock, ...) |
| `src/store.rs` | 139 | `foca-store` adapters (`store` feature): SQLite-backed download `TaskQueue` and `RequestSink` |
| `src/urlinfo.rs` | 158 | Pre-download URL analysis (`PathAnalysis`-style extraction of usernames, servers, and directories) |

## Public API

Re-exports in `src/lib.rs`:

- `download::{DownloadConfig, Downloaded, Downloader, MemQueue, QueuedTask, TaskQueue}`
- `filter::{dedupe, normalize_url, ExtFilter, DEFAULT_EXTS}`
- `foca_net::{BoxFuture, NetError}`
- `render::{RenderFetch, RenderPage, RenderRequest, RenderStep}`
- `source::{run_sources, run_sources_ctl, DocumentSource, Found, FoundUrl, SearchCtx, SearchResult, SourceCtl, SourceKind, SourceReport, SourceStatus}`
- `urlinfo::{analyze_url, summarize_urls, UrlInfo, UrlSummary}`

Full API docs: `cargo doc -p foca-search --no-deps --open`.

## Tests

`cargo test -p foca-search`: 31 unit tests in `src/` + 40 integration tests in `tests/`:

| File | Tests |
|---|---|
| `tests/crawler.rs` | 67 |
| `tests/download.rs` | 441 |
| `tests/live.rs` | 2 (`#[ignore]` by default) |
| `tests/render_sources.rs` | 573 |
| `tests/sources.rs` | 726 |

## Pitfalls

- Full catalog of all discovery sources: [docs/user/sources.md](../../user/sources.md) and `sources/{subdomains,urls,render_engines,dorkpool}.rs`.
- Adding a source requires matching IDs in `foca-engine::scan::SOURCES`, `ui/screens/sources.js`, and `ui/js/demo-backend.js` (see [Contributing → Adding a Source](../contributing.md#adding-a-source)).
- WebView-backed engines (`startpage`, `brave_web`, `mojeek`, `yahoo`, `searx_pool`) require a `RenderFetch` implementation; in CLI, `foca serve`, and headless monitoring they report `unavailable` / `skipped_headless`.
- Always detect CAPTCHAs from visible page text (Brave embeds the word `CAPTCHA` inside i18n script bundles on normal pages).
- Render fixtures live in `tests/fixtures/render/`, captured via `qa/search-fixtures.mjs` and verified via `cargo run -p foca-search --example render_parse`.
- Wayback CDX frequently returns HTTP 504 after 60 s (especially with `filter=mimetype:` on large domains) and throttles concurrent requests.
