# foca-net

↑ [Core Crates](README.md) · [Developer Guide](../README.md) · [Architecture](../architecture.md)

- [Purpose](#purpose)
- [Modules](#modules)
- [Public API](#public-api)
- [Tests](#tests)
- [Pitfalls](#pitfalls)

Path: `crates/foca-net/` · `src/` lines: 19,383 · tests: 169 · depends on: [foca-core](foca-core.md)

## Purpose

`foca-net` is the single network layer of FOCA-rs.

- **`NetClient`**: shared HTTP client supporting HTTP/SOCKS5 proxies (including per-group proxies), consistent browser User-Agent + Client Hints profiles (`ua.rs`), timeouts, exponential-backoff retries, global and per-module token-bucket rate limits, concurrency semaphores, cancellation (`CancellationToken`), and a mandatory request log (`RequestSink`, `I-23`) with credential redaction (`sink::redact_url`).
- **Scope & Access enforcement**: every request declares `Access`: `Passive` (third-party services like `crt.sh`, `archive.org`, Telegram/webhooks, cloud AI), `TouchesTarget` (target host in standard/full profiles), or `Active` (active modules). For `TouchesTarget` and `Active`, `NetClient` validates `foca_core::Scope` before opening a connection, including every redirect hop and resolved IP address (to enforce exclusions), and `Active` also enforces `check_active`.
- **Infrastructure & Recon Protocols**: DNS (`dns/mod.rs` via `hickory-resolver`), DoH (`dns/doh.rs`), Certificate Transparency (`tls/ct.rs`), RDAP/RIPEstat (`intel/rdap.rs`), mail security (`dns/mail.rs`: SPF/DMARC/DKIM/BIMI/MTA-STS/TLS-RPT/CAA/DNSSEC), dangling CNAME takeover (`dns/takeover.rs`), subdomain brute force (`dns/bruteforce.rs`) & smart permutations (`dns/permute.rs`), CDN/WAF & origin ranking (`intel/cdn.rs`), M365/Entra ID (`intel/m365.rs`), SaaS DNS fingerprinting (`intel/saas.rs`), reverse DNS (`dns/ptr.rs`), TCP liveness (`tcp.rs`), active AXFR (`dns/axfr.rs`) & NSEC walking (`dns/nsec.rs`), active TCP port scanning & custom banner probes (`scan/ports.rs`), full TLS/X.509/STARTTLS/legacy-cipher auditing (`tls/*`), network spoofing canaries (`scan/canary.rs`), proxy health/exit-IP classification (`proxy_check.rs`), and opt-in HIBP k-anonymity password checks (`intel/hibp.rs`).
- **Localized Alert Delivery (`notify.rs`)**: sends monitoring alerts to Telegram Bot API (`sendMessage`, HTML) and webhooks (Slack, Mattermost, Discord, Generic JSON) strictly through `NetClient` without following redirects. Uses unified `foca_core::Lang` and loads alert message templates from `locales/{en,ru,uk}/notify.json` (overridable via `Translate`). Bot tokens and webhook URLs are wrapped in `Secret` (never printed in `Debug`/`Display`, redacted from `request_log`), and message parameters pass through `sanitize_param` to mask secrets, tokens, e-mails, and long digit runs.

TLS uses `rustls` + `ring` + `webpki-roots`: no OpenSSL dependency and no Android JNI initialization required before the first request.

## Modules

| File | Lines | Contents |
|---|---|---|
| `src/client.rs` | 1,315 | Scoped HTTP client with rate limiting, retries, cancellation, and request logging |
| `src/dns/axfr.rs` | 384 | Active DNS zone transfer (AXFR, `F-14`) |
| `src/dns/bruteforce.rs` | 1,632 | Subdomain brute force (dnsx/puredns logic): built-in `top-1500`/`top-5000` gzipped SecLists wordlists, AIMD pacing, two-phase verification, multi-layer wildcard filtering, `testdns::FakeDns` |
| `src/dns/doh.rs` | 330 | DNS over HTTPS (RFC 8484 JSON `application/dns-json`) through `NetClient` |
| `src/dns/mail.rs` | 1,147 | Domain mail security: SPF, DMARC, DKIM, BIMI, MTA-STS, TLS-RPT, CAA, DNSSEC |
| `src/dns/mod.rs` | 596 | DNS record lookups (`A`/`AAAA`/`MX`/`NS`/`TXT`/`SOA`/`CNAME`/`SRV`/`CAA`/`PTR`/`DS`/`DNSKEY`) via `hickory-resolver` |
| `src/dns/nsec.rs` | 779 | Active DNSSEC NSEC zone walking (`Access::ZoneInfra`, TCP/53 to target NS; stops on NSEC3/black lies/loops) |
| `src/dns/permute.rs` | 813 | Smart subdomain permutations (alterx/gotator style) incorporating document metadata tokens |
| `src/dns/ptr.rs` | 636 | Reverse DNS (PTR) for in-scope IPs, FCrDNS, hosting classification, and host discovery |
| `src/dns/takeover.rs` | 427 | Dangling CNAME detection and HTTP fingerprint candidates (`inspect`, `TakeoverService::match_body`) for subdomain takeover risk |
| `src/error.rs` | 87 | Network layer error types (`NetError`) |
| `src/intel/cdn.rs` | 820 | CDN/WAF/cloud classification (~10.5k CIDR prefixes in `data/cloud_ranges.txt.gz`) and origin IP candidate ranking |
| `src/intel/hibp.rs` | 258 | Strictly opt-in Have I Been Pwned (Pwned Passwords) k-anonymity client |
| `src/intel/m365.rs` | 528 | Passive Microsoft 365 / Entra ID tenant discovery (OpenID, `getuserrealm.srf`, autodiscover) |
| `src/intel/rdap.rs` | 242 | IP network/ASN and domain registration lookup via RIPEstat and RDAP |
| `src/intel/saas.rs` | 721 | Passive SaaS/cloud fingerprinting via DNS TXT verification records (~50 services), SPF includes, MX, and CNAME |
| `src/lib.rs` | 55 | Module declarations, `BoxFuture`, `Result`, and re-exports |
| `src/notify.rs` | 1,132 | Telegram & webhook alert delivery using `foca_core::Lang` and `locales/{en,ru,uk}/notify.json` |
| `src/proxy_check.rs` | 299 | User proxy health check (`SOCKS5`/`HTTP`/`v2rayNG`/`Orbot`) and exit-IP classification |
| `src/ratelimit.rs` | 115 | Token bucket rate limiter (global and per source module) |
| `src/scan/canary.rs` | 771 | Passive network spoofing & interception detector (TCP canaries, `.invalid` DNS, TLS MITM CAs) |
| `src/scan/ports.rs` | 1,581 | Active TCP connect port scanner (RustScan logic) and custom protocol banner probes |
| `src/sink.rs` | 216 | Outgoing request log (`RequestSink`, `RequestRecord`) and URL credential redaction (`redact_url`) |
| `src/tcp.rs` | 547 | TCP liveness checks (`F-20`) and raw TCP helpers for active modules |
| `src/testserver.rs` | 240 | Minimal tokio HTTP/1.1 test server for offline tests |
| `src/tls/audit.rs` | 645 | Offline certificate/chain audit (`webpki` + Mozilla roots, expiry, weak crypto, CAA, ALPN/OCSP) |
| `src/tls/ct.rs` | 764 | Certificate Transparency (`crt.sh`, CertSpotter): full `CtCert` metadata, timelines, abandoned hosts, org pivots (passive) |
| `src/tls/handshake.rs` | 358 | `rustls` handshake inspection (`inspect_standard` `TouchesTarget`, `inspect_no_sni` active, origin verification) |
| `src/tls/legacy.rs` | 639 | Hand-built raw `ClientHello` probes for TLS 1.0/1.1 (and opt-in SSL 3.0) and weak ciphers |
| `src/tls/mod.rs` | 95 | X.509 and TLS inspector root |
| `src/tls/starttls.rs` | 266 | STARTTLS upgrades for SMTP, IMAP, POP3, FTP, PostgreSQL `SSLRequest`, and RDP X.224 |
| `src/tls/x509.rs` | 614 | X.509 parsing (`x509-parser`), SANs, SPKI/SHA-256, CDP/AIA, internal PKI/AD hints, RFC 6125 host matching |
| `src/ua.rs` | 584 | Consistent browser fingerprint profiles (UA + Client Hints) |

## Public API

Re-exports in `src/lib.rs`:

- `client::{Access, Method, NetClient, NetConfig, NetRequest, NetResponse}`
- `error::NetError`
- `ratelimit::TokenBucket`
- `sink::{MemorySink, NullSink, RequestRecord, RequestSink}`
- `tokio_util::sync::CancellationToken`

Top-level types: `BoxFuture<'a, T>`, `Result<T, E = NetError>`, plus `notify::Lang` (re-export of `foca_core::Lang`) and all public protocol modules.

Full API docs: `cargo doc -p foca-net --no-deps --open`.

## Tests

`cargo test -p foca-net`: 116 unit tests in `src/` + 46 integration tests in `tests/`:

| File | Tests |
|---|---|
| `tests/client.rs` | 650 |
| `tests/fixtures.rs` | 126 |
| `tests/live.rs` | 3 (`#[ignore]` by default) |
| `tests/ports.rs` | 344 |
| `tests/tls.rs` | 639 |
| `tests/ua.rs` | 92 |

## Pitfalls

- Every network call in the workspace must go through `NetClient` with the right `Access` class; direct `reqwest` usage in other crates is forbidden because it bypasses scope checks and request logging.
- `reqwest`'s `read_timeout` resets on each byte received: trickle responses will not time out unless an overall `.timeout()` or source deadline is set.
- Port lists (`top-100`/`top-1000`) are authored in-house (no NPSL `nmap-services`, [ADR-0008](../../adr/0008-ports-tcp-connect-own-probes.md)); local VPNs can fake open ports, which is why canary/TEST-NET checks exist.
- Live internet tests (`tests/live.rs`) are `#[ignore]` by default.
- Access-level discipline: brute force, permutations, PTR, and standard TLS use `TouchesTarget`; NSEC, AXFR, ports, legacy TLS/STARTTLS/no-SNI require `Active`; SaaS, M365, CT, CDN, HIBP, and notifications are `Passive`. Passive scans reject target-touching calls before opening a socket.
- TLS test fixtures are pre-generated with OpenSSL (`tests/fixtures/tls/generate.sh`); because `rustls` refuses RSA-1024 keys, weak-cert tests use a minimal raw TLS 1.0 server.
- Set `cfg.dns_unthrottled = true` in engine tests that run subdomain brute force, or `top-1500` takes minutes; use `bruteforce::testdns::FakeDns` for wildcard tests.
