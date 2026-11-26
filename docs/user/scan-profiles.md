# Scan Profiles

↑ [User Guide](README.md) · [Documentation](../README.md)

- [Summary](#summary)
- [Network Behavior by Profile](#network-behavior-by-profile)
- [Custom Profile Modules](#custom-profile-modules)
- [The 9 Scan Stages](#the-9-scan-stages)
- [Pause, Stop & Resume](#pause-stop--resume)

## Summary

| Profile | Est. time* | Access level | Contacts target? |
|---|---|---|---|
| **Passive** | ~5 min | `external` | Never: third-party services and archived copies only |
| **Standard** | ~25 min | `target` | Normal client requests: downloading documents, DNS, TCP liveness, site crawling, TLS inspection |
| **Full** | ~45 min | `active` | Standard + active phase: AXFR, NSEC walking, TCP port scan, forgotten file discovery, active web probes |
| **Custom** | - | Determined by selected modules | Matches the highest access level among selected modules |

\* Estimates shown in the launch wizard (`ui/screens/launch.js`); real duration depends on network speed, proxy/Tor latency, and target size.

Default module sets (core `default_modules` in `crates/foca-engine/src/scan/mod.rs`, matched by `PROFILE_MODS` in `ui/screens/launch.js`):

- All profiles: `search`, `crt`, `wayback`, `cc`, `meta`, `analysis`, `ct`, `recon`, `infra`;
- Non-passive (Standard & Full): + `crawler`, `dns`, `docs`, `alive`, `subdomains`, `tls`;
- Full: + `axfr`, `ports`, `fuzz`, `nsec`.

## Network Behavior by Profile

**Passive**: all traffic goes strictly to external third-party services (search engines, web archives, CT logs, subdomain aggregators, RDAP, Shodan InternetDB, grep.app, and optional keyed APIs such as VirusTotal, SecurityTrails, and GitHub Code Search):

- Search-engine dorks (Startpage, Brave Search, Yahoo, and public SearXNG instances via the embedded Android browser), plus URLs from archives and OSINT feeds;
- Target documents are fetched exclusively as archived snapshots from the Wayback Machine (`id_` raw copies): the target site itself is never contacted; if no snapshot exists, the task records an error and the target remains untouched;
- Subdomains from CT logs and passive aggregators, resolved via the device resolver or DoH (never querying target nameservers directly);
- Direct `ip`, `cidr`, and `range` targets flow into passive RDAP and Shodan InternetDB enrichment (ASN, netblock, cached ports, CPEs, CVEs);
- Site reconnaissance operates on archived snapshots of the homepage, favicon, scripts, and `robots.txt` / `sitemap.xml` / `security.txt` from CDX;
- DNS-based infrastructure mapping (`infra`): SaaS detection via TXT/SPF/MX/CNAME, Microsoft 365 tenant discovery (Microsoft endpoints only), mail security policies (BIMI, MTA-STS via DNS, TLS-RPT, CAA, DNSSEC), CDN/cloud ranges, origin candidates behind CDNs, CT certificate history, and heuristic host roles;
- Sandboxed plugins marked passive (`net:passive`) also run through `NetClient` with target hosts strictly blocked.

This guarantee is enforced in the Rust core: at `Access::Passive` (`external`), `NetClient` refuses any connection to an in-scope or excluded target host, including after HTTP redirects ([ADR-0009](../adr/0009-passive-never-touches-target.md)).

**Standard** = Passive + direct non-intrusive requests to in-scope targets:

- Downloading public documents directly from target websites;
- Authoritative DNS summary for target domains: A/AAAA/MX/NS/TXT/SOA, SPF/DMARC/DKIM, dangling CNAMEs (subdomain takeover indicators);
- Protocol-verified TCP liveness checks (`tcp_alive_checked` on common web/service ports, protected against local-VPN false positives);
- Website crawler traversing pages within configured depth and limits (wizard → Advanced);
- **Subdomain brute-force & permutations** (top-1,500 built-in wordlist by default, configurable in the wizard) plus permutations seeded from discovered hostnames and document metadata tokens, PTR lookups on in-scope IPs, and multi-level wildcard DNS filtering;
- **TLS/X.509 certificate inspection** on open TLS ports of live in-scope hosts (expiration, chain, SANs, CAA alignment, internal PKI) and live MTA-STS policy retrieval;
- **Web audit** (`GET` checks for `.js.map` source maps, Swagger/OpenAPI, Spring Actuator, `openid-configuration`);
- Optional WebView screenshots & `pHash` clustering of live web services when explicitly enabled (`settings.recon.screenshots = true`, off by default; never executed in Passive).

**Full** = Standard + active phase (strictly within authorized scope; exclusions are never touched):

- **AXFR**: attempts a full DNS zone transfer from target nameservers;
- **NSEC walking**: enumerates signed DNSSEC zones via NSEC records, plus expanded top-5,000 subdomain brute-force;
- **TCP port scanning** on live in-scope hosts (up to 20 hosts, top-100 or top-1,000 ports) with service banners and version fingerprinting; if local-VPN interference is detected, results are flagged Unreliable, see [VPN, AdGuard & Unreliable Port Scans](settings-network.md#vpn-adguard--unreliable-port-scans);
- **Forgotten file discovery (`foca-fuzz`)**: documents, backups, `.env` / `.git` / `.DS_Store`, directory listings, hidden virtual hosts, and CMS paths, rate-limited probing with soft-404 calibration and automatic back-off on HTTP 429/403/5xx;
- Open listing checks on discovered S3/GCS/Azure cloud storage buckets;
- **Active TLS audit**: legacy TLS 1.0/1.1 and weak ciphers, STARTTLS probing (25/587/143/110/21/5432/3389), direct-IP checks without SNI (in-scope non-shared IPs only) to confirm origin servers behind a CDN, plus non-standard web ports (`8080`, `8443`, `3000`, `9000`, `5601`, `9200`);
- **Active web audit**: `OPTIONS`, `TRACE`, `PROPFIND`, and reflected-Origin CORS probes (`PUT` and `DELETE` are never sent).

Scheduled monitoring runs Passive or Standard profiles only: the core rejects active-level scans on a schedule.

## Custom Profile Modules

Available in the launch wizard (`MODS` in `ui/screens/launch.js`):

| ID | Module | Access type |
|---|---|---|
| `search` | Search engines (Startpage, Brave, Yahoo, public SearXNG via built-in browser; Brave API, custom SearXNG, VirusTotal, SecurityTrails, GitHub via API keys) | External |
| `crt` | Certificate Transparency (`crt.sh`): subdomains from CT logs | External |
| `wayback` | Web archives: historical snapshots of pages and documents | External |
| `recon` | Site reconnaissance (archived copies in Passive; live + optional screenshots in Standard/Full) | External / Target |
| `infra` | DNS infrastructure: SaaS & Microsoft 365, mail policies, CDN/cloud, CT history, host roles | External |
| `dns` | Authoritative DNS records and zone checks | Target |
| `docs` | Downloading documents from target sites | Target |
| `alive` | Host liveness check (TCP) | Target |
| `subdomains` | Subdomain brute-force & permutations (wordlist chosen in wizard) | Target |
| `tls` | TLS/X.509 certificate inspection | Target |
| `axfr` | DNS zone transfer (AXFR) | Active |
| `nsec` | DNSSEC zone walking (NSEC) | Active |
| `ports` | TCP connect port scan | Active |
| `fuzz` | Forgotten file discovery (submodules: `docs`, `backups`, `exposed`, `dirlisting`, `vhost`, `cms`) | Active |

## The 9 Scan Stages

`STAGES` in `crates/foca-engine/src/scan/mod.rs` (progress advances across all 9 stages):

| # | ID | Stage | What happens |
|---|---|---|---|
| 1 | `search` | Search | Parallel URL & subdomain collection across enabled sources (shared dork queue with CAPTCHA failover) |
| 2 | `download` | Download | Document downloads (or Wayback snapshots in Passive), size/count limits, SHA-256 hashing, deduplication |
| 3 | `meta` | Metadata extraction | `foca-meta` parsing (plus optional on-device ML Kit OCR in `play` builds when enabled) |
| 4 | `analysis` | Analysis | People, e-mail patterns, workstations, software/EOL/KEV+CPE ranges, secrets, masked PII, findings, attack paths, risk score |
| 5 | `network` | Network & DNS | DNS summary, CT subdomains, direct IP/CIDR seeding, RDAP, InternetDB, TCP liveness, AXFR, SaaS/M365, mail policies, CDN, CT history, brute-force/permutations/PTR/NSEC, TLS inspection, host roles |
| 6 | `ports` | Ports | TCP connect scan + active TLS audit (legacy protocols, STARTTLS, direct-IP without SNI): Full only |
| 7 | `recon` | Site recon | Technologies, favicon hash, JS endpoints/secrets, web audit, robots/sitemap/security.txt, cloud buckets, grep.app, optional WebView screenshots (`pHash`); Full adds ports `8080/8443/3000/9000/5601/9200` |
| 8 | `fuzz` | Path discovery | Wordlist-based forgotten file discovery: Full only |
| 9 | `report` | Summary | Finalize counters, snapshot for Diff ("What changed"), trigger monitoring alerts if scheduled |

Stages not enabled by the chosen profile are skipped immediately.

## Pause, Stop & Resume

- **Pause / Resume:** Tap the button on the Scan screen, or let the engine pause automatically on network loss, VPN/proxy drop (kill switch), low battery, or thermal throttling (`src-tauri/src/policy.rs`).
- **Skip source:** Skip any slow-responding source (including `subdomains` and `tls`) without aborting the scan; every search source also enforces an overall timeout.
- **Per-item controls:** while a scan runs, a stage, a source or a brute-force step of Network and DNS can be paused, skipped or restarted on its own; the rest of the scan continues. A restart of a stage that is already over is queued; after the scan, Re-run queued runs only those parts.
- **Network and DNS progress:** the stage shows its current step with a counter (DNS records, subdomain addresses, dangling CNAME check, subdomain brute force, name permutations, RDAP, liveness, TLS certificates). When the resolver is slow, often behind a VPN, a warning shows the expected brute-force time and a Skip brute force button.
- **Stop & resume later:** Stopping a scan preserves everything collected so far. Stopped or process-killed scans are saved with status `stopped` and can be resumed (`scan_start { resume_from }`) without re-downloading existing documents or re-probing already checked hosts.
