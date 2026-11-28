# Glossary

↑ [User Guide](README.md) · [Documentation](../README.md)

Core security, OSINT, and FOCA-rs terminology: synchronized with the in-app offline glossary (Help → Glossary, `locales/{en,ru,uk}/help.json` rendered by `ui/screens/help.js`), plus key technical terms used in this documentation. Developer-internal terms (snapshot, stage, access class) are covered in [architecture](../dev/architecture.md).

| Term | Meaning |
|---|---|
| **Active phase** | Requests that noticeably interact with the target: DNS zone transfer (`AXFR`), `NSEC` walking, TCP port scanning, website path fuzzing, and active CORS/method probes. Runs only in Full (or Custom with those modules enabled) and strictly with written authorization. |
| **AD FS** | Active Directory Federation Services: on-premises Microsoft sign-in server; under federation, it validates corporate passwords instead of cloud Entra ID. |
| **ASN** | Autonomous System Number: identifies an ISP's or large organization's routing network (shown in RDAP enrichment; not a direct scan target). |
| **Attack Path** | A ranked compromise chain computed by `foca-analysis::attack_paths` connecting leaked documents/artifacts, extracted credentials/logins, internal hosts, and externally reachable entry points. |
| **AXFR** | DNS zone transfer: requesting a complete zone copy from a nameserver. If permitted publicly, it exposes every DNS record in the zone. |
| **Built-in browser** | Hidden Android WebView used by the core to query Startpage, Brave Search, Yahoo, and public SearXNG instances (`RenderFetcher.kt`). |
| **CAA** | DNS Certification Authority Authorization record specifying which Certificate Authorities are allowed to issue TLS certificates for a domain. |
| **Canary** | A guaranteed-closed port, unroutable `TEST-NET` IP, or DNS/TLS probe used by `foca-net::canary` to detect local VPNs or intercepting proxies spoofing connections. |
| **CAPTCHA** | *"Verify you are human"* anti-bot challenge presented by search engines on automated traffic. Solved manually via Complete verification; never bypassed automatically. |
| **Chain of Custody** | Cryptographic provenance block (`CustodyRecord`, `.sha256` sidecar, and Android Keystore `ECDSA P-256` `.sig.json` signature) proving a report's inputs and integrity have not been tampered with. |
| **Choke Point** | A minimum-cut remediation node in the Attack Path graph whose remediation breaks the maximum number of compromise chains simultaneously. |
| **CIDR** | Network block notation, e.g., `203.0.113.0/24` (256 IPv4 addresses). |
| **CPE** | Common Platform Enumeration: standardized identifier for software products and versions, used to match CVE ranges. |
| **Crawler** | Follows internal links across an authorized target website to discover public documents. Contacts the target. |
| **CT logs** | Public Certificate Transparency logs recording issued TLS certificates, revealing active and historical subdomains. |
| **CVE** | Common Vulnerabilities and Exposures: unique identifier for a publicly disclosed vulnerability (e.g., `CVE-2021-41773`). |
| **CVSS** | Common Vulnerability Scoring System: numeric severity scale from `0.0` to `10.0`. |
| **Directory listing** | An exposed web folder page (`Index of /`) enumerating stored files. |
| **DKIM** | DomainKeys Identified Mail: cryptographic signature attached to outgoing e-mails and verified against a public key published in DNS. |
| **DMARC** | DNS policy telling mail receivers how to handle messages that fail SPF/DKIM. Missing DMARC makes domain spoofing easier. |
| **DoH** | DNS over HTTPS: encrypts DNS queries and routes them cleanly through configured HTTP/SOCKS proxies. |
| **Dork** | A search query using operators such as `site:example.com filetype:pdf` to locate public documents via search engines. |
| **EDRPOU (ЄДРПОУ)** | 8-digit organization identifier in the Unified State Register of Ukraine: public registry information (`Info` severity). |
| **EOL** | End of Life: software or OS that no longer receives security patches. Documents created by EOL software signal workstation fleet risk. |
| **Exclusion** | A host, IP, or CIDR network that must never be contacted, even if covered by a broader target. Exclusions always override targets. |
| **EXIF** | Image metadata embedded in photos: camera model, serial number, timestamps, thumbnails, and sometimes GPS coordinates. |
| **False positive** | A reported finding that does not represent a real security issue. Marking it False positive excludes it from reports and persists across rescans. |
| **Finding** | A concrete security issue with severity, evidence, provenance, standards mapping, and remediation guidance/playbook. |
| **`.foca.enc` Bundle** | Encrypted portable project archive (`FOCAENC1`: `PBKDF2-HMAC-SHA256` + `ChaCha20-Poly1305` + `CustodyManifest`) for secure project handover or backup. |
| **`foss` / `play` Flavors** | The two Android distribution builds of FOCA-rs: `foss` (100% free `GPL-3.0` / F-Droid, no proprietary Google ML Kit) and `play` (adds optional on-device ML Kit offline OCR). |
| **Infostealer** | Malware that harvests browser credentials and cookies; HudsonRock surfaces domain URLs appearing in stealer intelligence feeds. |
| **k-anonymity (HIBP)** | Privacy-preserving breach check that sends only the first 5 hex characters of a local SHA-1 hash (`/range/<prefix>`) with `Add-Padding: true` so the full secret never leaves the phone. |
| **Kill switch** | Automatic scan stop or pause when your VPN or proxy drops, preventing exposure of your real IP address. |
| **M365 tenant** | An organization's Microsoft 365 / Entra ID directory: tenant ID, verified domains, and federation/auth mode. |
| **Metadata** | Hidden structured fields inside files: author, username, authoring software, disk/UNC paths, printers, revision history, and timestamps. |
| **MTA-STS** | Mail Transfer Agent Strict Transport Security: domain policy enforcing TLS encryption for inbound mail delivery. |
| **NS** | Authoritative nameservers responsible for answering DNS queries for a domain. |
| **NSEC** | DNSSEC record pointing to the next name in a zone; without NSEC3 hashing, it allows enumerating all hostnames in the zone. |
| **Origin** | The real backend server behind a CDN. If directly reachable, CDN WAF/DDoS protections can be bypassed. |
| **Passive mode** | Zero requests sent to target hosts: strictly queries third-party open sources and web archives ([ADR-0009](../adr/0009-passive-never-touches-target.md)). |
| **Path fuzzing** | Probing common URL paths (backups, `.env`, `.git`, listings) from a wordlist: called Forgotten file discovery in the app. |
| **pHash** | Perceptual hash (64-bit `dHash`/`pHash`) used to cluster visually identical web-service screenshots by Hamming distance. |
| **PII** | Personally Identifiable Information (RNOKPP, IBAN, payment cards, passports, phones). Shown in full in the app; masked in logs and, on request, in reports. |
| **Playbook** | Context-aware, step-by-step remediation plan on a finding card with effort estimates, owner roles, safe commands, and verification checklist. |
| **Proxy** | Network intermediary forwarding your traffic so targets see the proxy's address instead of yours (e.g., Orbot/Tor or v2rayNG). |
| **QES (КЕП)** | Qualified Electronic Signature (Ukraine): certificate carries signer's name, title, organization, EDRPOU, and RNOKPP. See [Documents](documents.md#forensics-in-the-document-card). |
| **RDAP** | Registration Data Access Protocol: modern JSON successor to WHOIS showing IP netblock and domain ownership. |
| **RNOKPP (РНОКПП)** | 10-digit Ukrainian Individual Taxpayer Registration Number (ІПН). Shown in full when the document holds it. |
| **SAN** | Subject Alternative Name: list of hostnames covered by a TLS certificate. Out-of-scope SANs become candidates on `/p/out-of-scope`. |
| **Sandbox (Plugins)** | Isolated pure-Rust runtime (declarative JSON/TOML or memory/fuel-capped WASM) for FOCA-rs plugins with zero filesystem, raw-socket, or `KeyVault` access. |
| **Scope** | The authorized set of network targets that may be assessed and exclusions that must never be touched. |
| **Secret** | Password, API key, token, or webhook discovered inside a document or script. Shown in full in the app, masked in logs. |
| **Severity** | `Critical`, `High`, `Medium`, `Low`, `Info`: indicates remediation urgency. |
| **Soft 404** | A server returning HTTP `200 OK` with a custom error page for missing URLs; baseline calibration filters these out during fuzzing. |
| **Software fingerprint** | Identified application name and version extracted from documents, banners, or web headers. |
| **SPF** | Sender Policy Framework: DNS TXT record listing servers authorized to send mail for a domain. |
| **STIX 2.1** | OASIS Structured Threat Information Expression JSON bundle exported by FOCA-rs for MISP, OpenCTI, and SIEM ingestion. |
| **Subdomain** | A hostname beneath a parent domain, e.g., `mail.example.com` under `example.com`. |
| **Subdomain brute-force** | Testing candidate hostnames from a wordlist against target DNS servers (Standard/Full only). |
| **Target** | An authorized network target accepted by FOCA-rs: `domain` (`example.com`), wildcard `*.domain`, `http(s)://url`, `ip`, `cidr`, or `ip-range`. (E-mail addresses, person names, organizations, and ASNs are not scan targets.) |
| **Thinking (Reasoning)** | Provider-native extended reasoning controls in Cloud AI (`auto`/`off`/`minimal`/`low`/`medium`/`high`/`xhigh`/`max`, token budget, optional reasoning trace display). |
| **TSA** | Time Stamping Authority (RFC 3161) server cryptographically certifying when a document was signed. |
| **vhost** | Virtual host: multiple sites hosted on the same IP address and distinguished by the HTTP `Host` header. |
| **WAF** | Web Application Firewall inspecting and blocking suspicious or high-rate HTTP requests. |
| **w:vanish** | Word run property marking text invisible on screen and in print while keeping it stored inside the document XML. |
| **Web archive** | Stored snapshots of web pages and documents (Wayback Machine, Common Crawl, Arquivo.pt) allowing recovery even after files are removed from the live site. |
| **Wildcard DNS** | A DNS zone configured to resolve arbitrary nonexistent hostnames; multi-level wildcard filtering prevents false subdomain hits. |
| **Wordlist** | List of candidate paths or subdomain labels (built-in, SecLists downloads, or custom). |
| **XMP** | Adobe Extensible Metadata Platform XML block embedded in PDFs, images, and creative files storing authoring tools, `DocumentID`, `DerivedFrom`, and edit history. |
| **Access level** | Core request classification: `Passive` (third-party only), `TouchesTarget` (in-scope target host), `Active` (active phase). Scan levels `external` / `target` / `active` map to Passive / Standard / Full profiles. |
