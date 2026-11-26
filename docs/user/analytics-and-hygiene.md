# Analytics, Attack Paths, Web Audit, Hygiene & Reports

↑ [User Guide](README.md) · [Documentation](../README.md)

Besides collecting raw OSINT artifacts, FOCA-rs shows how documents relate to people and servers, what internal network topology they disclose, which compromise chains lead from a leaked file to an exposed entry point, and how to clean files before publication. Concise offline summaries are built into ⋮ → Help.

- [Reference Case](#reference-case)
- [Link Graph & Evidence Chain](#link-graph--evidence-chain)
- [Attack Paths & Choke Points](#attack-paths--choke-points)
- [Internal Network Map](#internal-network-map)
- [Timeline & Activity Heatmap](#timeline--activity-heatmap)
- [Org Chart, Metadata Anomalies, CISA KEV & Document Lineage](#org-chart-metadata-anomalies-cisa-kev--document-lineage)
- [Web Audit & Visual Screenshots](#web-audit--visual-screenshots)
- [Document Hygiene & Sanitization](#document-hygiene--sanitization)
- [Share to FOCA-rs](#share-to-foca-rs)
- [Report Templates](#report-templates)
- [Standards Mapping](#standards-mapping)
- [Limitations](#limitations)

## Reference Case

To test all analytics, visualization, sanitization, and reporting features without scanning any live domain, tap Open reference case, available on Projects, in Analyze files offline, or under Help → Getting started → First steps: reference case.

- Bundles 12 synthetic documents for the fictional company ТОВ «Приклад» (Pryklad LLC): Word document version lineage (RSID), Ukrainian QES (КЕП) signature, broken PDF redaction, incremental PDF revisions, hidden Excel worksheet and data connection, Windows `LNK` shortcut, e-mail with a `Received` relay chain, GPS-tagged photo, ODT file, `ICS` calendar invite, and `VCF` contact card. All names, addresses, and keys are fictional.
- Imports locally on your phone with zero network requests (project request log remains empty) and opens a ready-to-explore Reference case project within seconds.
- Tapping again lets you open the existing project or re-import the reference case cleanly.

## Link Graph & Evidence Chain

Open Overview → Infrastructure picture → Link graph (`/p/graph`). Nodes are arranged in columns from left to right: People → Documents → Workstations → Servers → PKI / Domains.

- Top filter chips toggle individual layers; the badge on each chip shows total nodes in that layer.
- Identical node types sharing the same neighbors collapse into clusters (e.g., *"14 documents"*); tap a cluster to expand it or Collapse all to reset.
- Red outlines highlight documents or hosts with Critical/High findings; dashed edges denote versions of the same document, and arrows represent *"derived from"*. Pan and zoom with gestures or `−` / `+` controls.
- **Evidence chain:** Tap any node or Critical finding to inspect the vertical chain *file → author → workstation → printer/share → server → domain*, with alternative paths shown in tabs. Chains are investigative hypotheses to verify, not proof of direct access.

## Attack Paths & Choke Points

The Attack Path Engine (`foca-analysis::attack_paths`, accessible via Analytics `/p/insights` and `attack_paths_get`) automatically correlates isolated findings into ranked compromise scenarios:

- **Directed attacker graph:** Connects leaked documents and sensitive artifacts (`.ovpn`, `.env`, configs, exposed secrets, internal paths) → extracted usernames, e-mail patterns, and Active Directory domains → externally reachable entry points (VPN gateways, OWA, RDP, open administrative ports, or web panels matching CISA KEV).
- **Top-5 ranked paths:** Computes up to 5 highest-probability compromise chains, listing concrete `finding_id`, `doc_id`, and `host` references at each step. Raw secrets and unmasked PII are never exposed in path descriptions.
- **Remediation Choke Points:** Computes minimum-cut nodes: identifying which single finding, credential exposure, or misconfigured asset breaks the greatest number of attack paths when remediated first.
- Attack paths and choke points are embedded automatically in HTML, PDF, DOCX, and Markdown reports.

## Internal Network Map

`/p/netmap` builds an inferred tree of AD domain → servers by role (domain controller, PKI, file server, mail, print server, database, terminal/RDS) → workstations → users. Reconstructed from `UNC` paths, printers, `LNK` shortcuts, e-mail `Received` chains, `RDP`/`ICA` files, and certificate `CDP`/`AIA` URLs. Tap any node to view provenance (document, path, or header) and confidence level; hosts without an identified domain appear under Unknown domain.

## Timeline & Activity Heatmap

`/p/timeline`:

- **Yearly evolution:** Horizontal lanes for document formats, authoring software, and first-seen CT certificates by year; tap any year for the complete item list.
- **7 × 24 activity heatmap:** Day of week × hour of document creation. Outlined region shows configured business hours (Mon-Fri); highlighted cells outside the outline indicate off-hours activity, summarized at the bottom by peak hour and off-hours percentage. Timestamps use document local time with the timezone shown below the chart.

Link graph, internal network map, timeline, and heatmap are also exported as static SVG diagrams in full HTML/PDF reports (and as structured text in Markdown).

## Org Chart, Metadata Anomalies, CISA KEV & Document Lineage

- **Org chart** (Data → People, Overview): Infers departments from folder/UNC paths, printer names, Organization fields, certificate `OU` attributes, and document roles, each with confidence score and supporting evidence.
- **Metadata anomalies** (document card, `doc.anomaly.*` findings): Creation timestamp later than modification timestamp or in the future, PDF/XMP/EXIF timestamp discrepancies, XMP edit history outside file lifetime, or authoring software newer than the document date. Treated as analyst signals rather than vulnerabilities.
- **CISA KEV & semantic CPE 2.3 version ranges:** An offline copy of the CISA Known Exploited Vulnerabilities catalog is bundled in the app (and updatable via signed `Ed25519` signature bundles). Starting in 2.0, `foca-analysis::vercmp` evaluates exact vulnerable version ranges (`[from_inc, to_exc)`):
  - **Confirmed vulnerable version (`confirmed_version`):** Extracted software version falls inside a known vulnerable range (`< fixed_in`): promoted to High severity.
  - **Patched version (`patched_version`):** Version is strictly `>= fixed_in`: suppresses false-positive KEV alerts.
  - **Possible / Likely vulnerable software:** Reported when only the product family or an end-of-life branch is known from metadata, with an explicit caveat to verify the patch level.
- **Document lineage & copies** (document card): Tracks *"copy / derived from / same lineage"* relationships via XMP `DocumentID`/`DerivedFrom` and Word `RSID`, highlighting the probable original file.

## Web Audit & Visual Screenshots

Source `webaudit` in the Site recon stage ([source table](sources.md#source-table)):

- **Passive:** Zero packets to the site: analyzes already collected archived responses only.
- **Standard:** Adds benign `GET` requests to in-scope hosts for `.js.map` source maps, Swagger/OpenAPI specs, Spring Actuator, and `openid-configuration`.
- **Full (active phase):** Adds `OPTIONS`, `TRACE`, `PROPFIND`, and reflected-Origin CORS probes. `PUT` and `DELETE` are never sent: their presence is inferred strictly from the `Allow` header.

Domains found in `Content-Security-Policy` headers are promoted to hosts if in scope, or listed under Out-of-scope candidates otherwise. Results appear in the host card (Web audit) and as `recon.web.*` findings.

- **Optional visual screenshots & `pHash` clustering (2.0):** When explicitly enabled (`settings.recon.screenshots = true`, off by default), Standard and Full scans capture isolated offscreen Android WebView thumbnails (`360×640`, cookies/JS/cache disabled, routed through the active proxy) of live in-scope web services. FOCA-rs computes a 64-bit perceptual hash (`dHash`/`pHash`) to cluster visually identical login portals and placeholder pages. Never runs in Passive mode ([ADR-0009](../adr/0009-passive-never-touches-target.md)).

## Document Hygiene & Sanitization

**Pre-publication check** (`/p/preflight`):

- **A-F hygiene grade** for a batch and each individual file: starts at 100 points and deducts per issue (Critical `−40`, High `−20`, Medium `−10`, Low `−4`); any Critical issue (exposed secret, broken redaction, deleted revision text) caps the grade at `E`.
- **Remediation steps:** Checkmark items are fixed automatically by Clean; warning-triangle items require manual edits (accepting tracked changes, removing secrets, properly re-redacting text).
- **Sanitization** writes a clean copy without modifying the original file:
  - **PDF:** Fully rewritten without incremental revisions, XMP, attachments, or scripts (configurable).
  - **OOXML & ODF:** Strips properties, paths, printers, revision authors, thumbnails, and data connections.
  - **Binary OLE2 (`.doc`, `.xls`, `.ppt`, `.vsd`, `.pub`):** Wipes `\x05SummaryInformation`, `\x05DocumentSummaryInformation`, digital signatures, Word `SttbSavedBy` / `SttbfAssoc` / `SttbfRMark` / `GrpXstAtnOwners` tables, Excel `WRITEACCESS`, and PowerPoint `/Current User`.
  - **Media (`JPEG`, `MP4`, `MOV`, `HEIC`):** Strips EXIF/GPS/XMP metadata; ISO-BMFF containers are sanitized in-place by zeroing timestamps (`mvhd`/`tkhd`/`mdhd`) and replacing metadata boxes (`udta`, `XMP_`, `meta`, HEIC EXIF/XMP extents) with zeroed `free` boxes without re-encoding video streams.
- **"Before / After" self-verification:** Re-parses the cleaned copy automatically, listing stripped fields, the "0 metadata · file valid" verdict, grade progression (*before → after*), and page count comparison. Digital signatures are always stripped because rewriting invalidates them: re-sign the clean copy afterward if needed.

## Share to FOCA-rs

From Telegram, e-mail, a browser, or a file manager, tap Share → Inspect in FOCA-rs. No project is created and zero network traffic is sent: up to 20 files / 256 MB per share (max 100 MB per file) are copied into private app storage and opened directly on the pre-publication hygiene screen. After cleaning, review Before / After and tap Share clean copy (exports with the local directory path stripped from the filename).

## Report Templates

Open Reports → New report (`/p/report-new`) and pick a template at the top (a description appears in the selected report language):

| Template | Contents | Formats |
|---|---|---|
| **Full** | Cover page, executive summary, scope, findings with evidence, attack paths & choke points, infrastructure, SVG/PNG diagrams, appendices; sections toggleable via checkboxes | `PDF`, `HTML`, `DOCX`, `Markdown` |
| **Summary** | Concise overview: overall risk, critical findings, priority fixes | `Markdown`, `HTML`, `PDF`, `DOCX` |
| **Data** | Tabular exports of findings, people, hosts, and documents | `CSV`, `JSON` |
| **Executive** | Single-page brief: risk score, top five findings in plain language, three priority actions | `PDF`, `HTML`, `DOCX`, `Markdown` |
| **KSZI / Compliance** | *"Finding × standards"* matrix, per-standard summaries, auditor disclaimer | `PDF`, `HTML`, `DOCX`, `Markdown` |
| **Laboratory work** | Objective, methodology, inputs, procedure, standards-mapped findings table, conclusions, *"Performed by / Checked by"* fields | `PDF`, `HTML`, `DOCX`, `Markdown` |

**Executive**, KSZI / Compliance, and Laboratory work use fixed structures (individual sections are not toggleable), while severity/status filters, report language (`EN` / `RU` / `UA`), header metadata, secrets redaction policy, and optional Chain of Custody & ECDSA P-256 signature apply to all templates.

## Standards Mapping

On each finding card, the Standards block displays verified mappings for the rule that fired: MITRE ATT&CK v20 technique, CWE weakness class (with a "Top 25" mark for the 2025 CWE Top 25), OWASP Top 10:2025 & WSTG v4.2, ISO/IEC 27001:2022 (ДСТУ ISO/IEC 27001:2023) Annex A control, NIST SP 800-53 Rev. 5 control (the same code as the НД ТЗІ 3.6-006-24 measure), GDPR / Law 2297-VI articles for findings with personal data, and, for systems certified under KSZI, НД ТЗІ 2.5-004-99 (security service) and НД ТЗІ 3.7-003-05 (KSZI implementation stage). Mappings are bundled offline and verified against primary specifications; only grounded mappings are included, so some findings omit this block. See [STANDARDS.md](../STANDARDS.md).

> **Disclaimer.** Standards mappings are an auditor's reference aid, not an official state KSZI expertise or compliance certification. Formal compliance determinations require a full review by an accredited assessor.

## Limitations

- The timeline does not include a Wayback snapshot lane (archive capture years are not tracked per project document).
- Evidence chains occasionally route through a shared web host when multiple documents were downloaded from the same server.
- Live WebView screenshots and Android Share Target URI grants require an actual Android device (not exercised in headless desktop test runs).
