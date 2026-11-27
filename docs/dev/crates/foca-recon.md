# foca-recon

↑ [Core Crates](README.md) · [Developer Guide](../README.md) · [Architecture](../architecture.md)

- [Purpose](#purpose)
- [Modules](#modules)
- [Public API](#public-api)
- [Tests](#tests)
- [Pitfalls](#pitfalls)

Path: `crates/foca-recon/` · `src/` lines: 7,761 · tests: 57 · depends on: [foca-core](foca-core.md), [foca-net](foca-net.md)

## Purpose

`foca-recon` performs website reconnaissance, tiered web auditing, and isolated visual snapshotting.

Core analysis functions take already-fetched data (HTML, JS bodies, document text, Wayback CDX snapshots) and return serializable `serde` structs plus `ReconFinding` items. Network calls happen strictly through `foca_net::NetClient` (enforcing scope, rate limits, logging, and cancellation) and only in explicit network modules (`collect`, `grepapp`, `wellknown`, `webaudit`, and opt-in bucket listing in `buckets`).

### Core Modules & Web Audit Levels

- **Passive Recon**:
  - `favicon.rs`: Shodan-compatible MurmurHash3 (`http.favicon.hash`), SHA-256/MD5, `<link rel=icon>` discovery.
  - `tech.rs`: Wappalyzer-style technology fingerprinting + analytics ID pivots (rules in `crates/foca-recon/data/`; details in [crates/foca-recon/README.md](../../../crates/foca-recon/README.md)). Static signals cover headers, cookies, meta, HTML, script URLs, page URL, JS file contents, visible text, CSS, the TLS issuer and robots.txt (`SiteExtra`, `detect_with`).
  - `tech/browser.rs`: browser-only signals (JS globals, DOM selectors, request hosts): `probe_script` builds the bounded read-only script the Android WebView runs after a render, `BrowserSignals` parses its answer.
  - `tech/cmsparts.rs`: WordPress/Drupal/Joomla/Magento/PrestaShop plugins, themes and modules by asset path with `?ver=` versions (core version ignored), CPE guess, `readme.txt` check for the active profile.
  - `js.rs`: JavaScript endpoint discovery and masked secret detection.
  - `grepapp.rs`: passive public GitHub code search via grep.app (`Access::Passive`).
  - `wellknown.rs` - `robots.txt`, `sitemap.xml`, and `security.txt` parsers plus Wayback archive collection.
  - `buckets.rs`: cloud storage bucket reference extraction (S3, GCS, Azure Blob, DO Spaces, Yandex) with opt-in listing check (disabled by default).
- **Tiered Web Audit (`webaudit/mod.rs`, `AuditLevel`)**:
  - **Passive**: zero extra target requests, `webaudit/headers.rs` (HSTS, cookies, version leaks, framing, `nosniff`, Referrer/Permissions-Policy, static CORS), `webaudit/csp.rs` (weak directives + CSP host extraction into scope/out-of-scope), and source-map URL references.
  - **Standard**: in-scope GETs, `webaudit/sourcemaps.rs` (package versions, developer paths, masked secrets, 8 MB cap) and `webaudit/apidocs.rs` (Swagger/OpenAPI specs, Swagger UI, Actuator names only, `openid-configuration`).
  - **Active**: spoofed-Origin CORS probe, `webaudit/methods.rs` (`OPTIONS`, `TRACE`, `PROPFIND Depth 0` - `PUT`/`DELETE` are never sent, only inferred from `Allow`), and GraphQL introspection.
- **Visual Snapshots (`screenshot.rs`)**:
  - Defines the `WebScreenshotter` trait (`ScreenshotRequest`, `ScreenshotRaw`) backed on Android by isolated offscreen `WebScreenshotter.kt` and computes 64-bit perceptual hashes (`dHash`) from 9×8 luminance grids to cluster identical/default web pages.

## Modules

Layout: `webaudit/` holds the deep web audit and its probes (headers, CSP, methods, source maps, API docs) with shared response helpers in `webaudit/fetch.rs`; the root modules are independent collectors called by `report.rs`.

| File | Lines | Contents |
|---|---|---|
| `src/buckets.rs` | 476 | Cloud bucket reference extraction (S3, GCS, Azure, DO Spaces, Yandex) |
| `src/collect.rs` | 212 | Fetches `analyze_site` inputs through `NetClient` (live site or Wayback copy) |
| `src/favicon.rs` | 167 | Shodan-compatible MurmurHash3 favicon hash, SHA-256/MD5, icon link extraction |
| `src/finding.rs` | 100 | `ReconFinding` model aligned with `foca-analysis` (severity, MITRE, recommendation) |
| `src/grepapp.rs` | 261 | Keyless grep.app search for public GitHub code mentions of a domain |
| `src/hash.rs` | 170 | Dependency-free MurmurHash3 x86_32, MD5 (RFC 1321), and MIME base64 |
| `src/js.rs` | 605 | JavaScript analysis: API endpoints and masked secret detection |
| `src/lib.rs` | 43 | Crate root and re-exports |
| `src/report.rs` | 554 | `analyze_site` orchestrator returning `ReconReport` |
| `src/screenshot.rs` | 387 | Isolated Android WebView visual snapshots (`WebScreenshotter`) and 64-bit `dHash` perceptual hashing |
| `src/tech.rs` | 1443 | Wappalyzer-style technology fingerprinting and analytics pivot IDs |
| `src/tech/browser.rs` | 304 | Browser-only signals: probe script and answer matching |
| `src/tech/cmsparts.rs` | 686 | CMS plugins, themes and modules by asset path |
| `src/webaudit/apidocs.rs` | 855 | Exposed Swagger/OpenAPI specs, Swagger UI, Spring Actuator, and OIDC discovery |
| `src/webaudit/csp.rs` | 387 | Content-Security-Policy parser, weakness audit, and host extraction |
| `src/webaudit/fetch.rs` | 32 | Response helpers shared by the probes that contact the target |
| `src/webaudit/headers.rs` | 601 | Passive security response header audit (HSTS, CORS, cookies, framing, policies) |
| `src/webaudit/methods.rs` | 290 | Active HTTP method probes (`OPTIONS`, `TRACE`, `PROPFIND Depth 0`; never `PUT`/`DELETE`) |
| `src/webaudit/mod.rs` | 824 | Tiered deep web audit (`AuditLevel`: passive / standard / active) |
| `src/webaudit/sourcemaps.rs` | 442 | JavaScript source map discovery and bounded (8 MB) inspection |
| `src/wellknown.rs` | 791 | `robots.txt` / `sitemap.xml` / `security.txt` parsing and Wayback collection |

## Public API

Re-exports in `src/lib.rs`:

- `finding::ReconFinding`
- `report::{analyze_site, ReconInput, ReconReport}`

All submodules (including `screenshot::{WebScreenshotter, ScreenshotRequest, ScreenshotRaw}` and `webaudit`) are public.

Full API docs: `cargo doc -p foca-recon --no-deps --open`.

## Tests

`cargo test -p foca-recon`: 41 unit tests in `src/` + 10 integration tests in `tests/`:

| File | Tests |
|---|---|
| `tests/net.rs` | 121 |
| `tests/webaudit.rs` | 388 |

## Pitfalls

- Pure analysis functions operate on already-downloaded bytes; network access is limited strictly to `collect`, `grepapp`, `wellknown`, `webaudit`, and opt-in `buckets` listing.
- In `passive` profile, the homepage, favicon, and scripts are retrieved from Wayback snapshots rather than the target host.
- Secrets detected in JS or source maps are always masked and never persisted raw; HTTP response bodies use `read_capped`.
- A failed recon run does not erase prior snapshot data: the snapshot is marked incomplete instead.
