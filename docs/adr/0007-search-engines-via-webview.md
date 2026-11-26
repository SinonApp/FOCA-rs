# ADR-0007: Search Engines via Hidden WebView, Dropping Google

↑ [Decisions (ADR)](README.md) · [Documentation](../README.md)

- Status: accepted (2026-11-20; amended in 1.0.1 and 1.1)
- Context: `site:domain filetype:pdf` dorks are FOCA's primary way to discover public documents. Google CSE requires an
  API key and a paid quota, while scraping Google directly violates its terms and immediately hits CAPTCHAs. Startpage
  (Google search results), Brave Search, and Mojeek reject datacenter IPs and bare HTTP clients via JS proof-of-work
  (Anubis on Startpage), anti-bot checks, and HTTP 403 ("automated queries").
- Decision:
  - Google CSE is completely removed (source, key, UI, tests; legacy `gcs` key is ignored). Google is not queried
    directly; Google search results are accessed only through Startpage.
  - The `startpage`, `brave_web` (and `mojeek`, when a browser is available) sources declare a scripted scenario
    (`foca-search::render::RenderRequest`: navigate, wait, submit form, click "Next"), executed by a hidden WebView on
    the phone (`platform/RenderFetcher.kt`) through `trait RenderFetch` → `bridge.rs NativeRender` → JNI
    `FocaDirect.call("render_fetch")`. The core parses the returned HTML (unit-testable against fixtures).
  - Without an embedded browser (CLI, `foca serve`), these sources honestly report `unavailable` rather than an empty
    result set.
  - DuckDuckGo/Bing HTML scraping is best-effort ("no guarantees"); Brave Search API and self-hosted SearXNG work via
    API key / instance URL.
- Consequences: Dorks run only in the Android app; CAPTCHAs are handled manually
  ([ADR-0012](0012-no-captcha-solving-no-public-proxies.md)); 1.1 introduces an honest mobile WebView profile and a
  shared dork queue with failover across engines. Code: `crates/foca-search/src/render.rs`,
  `sources/render_engines.rs`, `sources/dorkpool.rs`.
