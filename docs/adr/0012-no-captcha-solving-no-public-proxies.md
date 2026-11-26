# ADR-0012: No Automatic CAPTCHA Solving and No Public Proxies

↑ [Decisions (ADR)](README.md) · [Documentation](../README.md)

- Status: accepted (2026-11-21, 1.0.1 and 1.1 plan; partially implemented)
- Context: Web search engines respond with CAPTCHAs to frequent requests, especially from VPN, proxy, and mobile carrier
  CGNAT IPs. Tempting "solutions": anti-CAPTCHA services, verification bypasses, rotating public/free proxies: violate
  search engine terms of service, route user queries through third-party nodes (leaking the audit target and data), are
  unreliable, and make the tool look like an abuse utility.
- Decision:
  - CAPTCHAs are never solved automatically or bypassed. A detected CAPTCHA produces the "Verification required"
    status and a "Verify" button: a visible WebView sharing the same cookie profile (`VerifyDialog.kt`), followed by
    retrying the source within the current scan (`scan_retry_source`): implemented in 1.0.1.
  - Reduce CAPTCHA incidence through honest means: a single honest WebView profile (1.1), a shared dork queue with
    OR-grouped queries, a 24 h cache and 6-14 s pacing delays, and failover to another engine upon hitting a CAPTCHA
    (1.1).
  - Proxies are strictly user-owned proxies only (SOCKS5/HTTP/Tor via Orbot; 1.1 plan adds v2ray and an on-demand
    checker). The app never discovers, substitutes, or suggests public proxies. The pool of public SearXNG instances
    (1.2 plan) consists of search services rather than proxies and runs through the embedded browser.
  - If every search engine hits a CAPTCHA, the scan summary displays a hint (likely cause: IP address) rather than
    attempting to bypass protection.
- Consequences: Some dorks on a flagged IP will not finish without manual verification or the user's own proxy, this is
  reported honestly via statuses; archives and CT continue discovering documents without search engines.
