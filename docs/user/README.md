# FOCA-rs User Guide

English | [Русский](../ru/user/README.md)

↑ [Documentation](../README.md) · [Repository root](../../README.md)

FOCA-rs 2.0.0-beta.4.1.1 is an Android application (Tauri 2 + pure-Rust core) for open-source intelligence (OSINT), document metadata forensics, and attack-surface analysis: a mobile reimagining of FOCA (ElevenPaths).

> ⚠️ Test only infrastructure you own or are explicitly authorized in writing to assess.
> See [Legal boundaries](getting-started.md#legal-boundaries).

## Sections

| Section | What it covers |
|---|---|
| [Getting Started, Projects & Scope](getting-started.md) | Installing `foss` / `play` APKs, onboarding, projects, honest network targets & exclusions, legal boundaries |
| [Scan Profiles](scan-profiles.md) | Passive / Standard / Full / Custom: network behavior, 9 scan stages, screenshots, pause & resume |
| [Sources](sources.md) | All 42 built-in sources (free, WebView, keyed APIs including VirusTotal/SecurityTrails/GitHub), statuses, API keys |
| [Documents: Formats, Forensics, Search, Rules & Offline Analysis](documents.md) | Formats (`Office`, `PDF`, `OLE2`, `EPUB`, `MP3`, `PSD`, `7z`, `LNK`, `EML/MSG`, media), signatures & QES (КЕП), broken redaction, masked PII, FTS5 search, custom regex rules, offline analysis, optional ML Kit OCR |
| [Analytics, Attack Paths, Web Audit, Hygiene & Reports](analytics-and-hygiene.md) | Reference case, link graph & chains, Attack Paths & Choke Points, internal network map, timeline & heatmap, CISA KEV + CPE 2.3 version ranges, web audit & screenshots, document hygiene & sanitization, Share Target, report templates & standards |
| [Data, Findings, Reports, Bundles & Monitoring](data-and-reports.md) | Overview, Findings & Remediation Playbooks, Data & HIBP k-anonymity, reports (HTML/PDF/DOCX/MD/CSV/JSON + Chain of Custody & ECDSA P-256), contractor logo, report preview, STIX 2.1/Nuclei/httpx exports, encrypted `.foca.enc` bundles, `foca run scenario.toml`, headless monitoring & alerts |
| [Project risk score](risk-score.md) | How the 0-100 risk score is computed: weights, dampening per category, caps for findings without a critical one and for metadata-only exposure, levels |
| [Own SearXNG instance](searxng.md) | Self-hosting SearXNG with Docker, enabling JSON, connecting and testing it in Settings → API keys, Brave Search API key |
| [Settings, Network, Cloud AI & Plugins](settings-network.md) | Settings map, browser profiles, proxy/Tor/v2rayNG & kill switch, network canaries, CAPTCHA handling, Cloud AI (10 providers, live `/models` & Thinking), sandboxed plugins, signed `Ed25519` signature updates, live `EN/RU/UA` localization, `/settings/licenses` & `foss`/`play` builds |
| [FAQ & Troubleshooting](faq.md) | Background scans on Xiaomi/HyperOS, 0 documents, CAPTCHA, local VPN port distortion, honest network targets, Cloud AI, `foss` vs `play` builds, logs & updates |
| [Glossary](glossary.md) | Key terms: scope, target, attack path, choke point, dork, EOL, CVE, AXFR, QES, `.foca.enc`… |

Shorter offline versions of these articles are built right into the app under ⋮ → Help (`/help`) in English, Russian, and Ukrainian: no internet connection required.
In-app help strings live in `locales/{en,ru,uk}/help.json` (delivered over IPC via `i18n_bundle` and rendered by `ui/screens/help.js`); if anything diverges, the app code is authoritative.
