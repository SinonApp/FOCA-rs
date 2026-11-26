# ADR-0011: Port Third-Party Tool Logic Instead of Bundling Binaries

↑ [Decisions (ADR)](README.md) · [Documentation](../README.md)

- Status: accepted (2026-11-20, beta plan; reaffirmed in 1.0)
- Context: Mature OSINT tools exist (subfinder, ffuf, RustScan, Wappalyzer, nmap, spider-rs). Bundling their binaries
  into the APK adds megabytes per ABI, introduces foreign network stacks that bypass scope filtering and request
  logging, and several carry licenses incompatible with GPL-3.0 (nmap's NPSL).
- Decision:
  - Core logic is ported to Rust on top of our own `foca_net::NetClient` (scope, logging, rate limits, cancellation):
    subdomains modeled after subfinder; content discovery and soft-404 auto-calibration inspired by ffuf (MIT) with
    SecLists wordlists (MIT); port scanning modeled after RustScan; technology fingerprinting using the
    Wappalyzer/webappanalyzer rule format; favicon hashing via MurmurHash3 (public domain); `.DS_Store` parsed per the
    format specification.
  - The `spider-rs` crawler dependency was rejected because it constructs its own `reqwest::Client`, hiding redirects
    from our scope filter and request log.
  - Code or data under incompatible licenses (`nmap-services`, nmap probes) are never used.
  - Attribution and third-party service terms are documented in `THIRD_PARTY.md`.
- Consequences: More first-party code and tests, in exchange for uniform scope and logging guarantees, a compact APK,
  and a clean license posture. Source research: [research/oss-sources.md](../research/oss-sources.md).
