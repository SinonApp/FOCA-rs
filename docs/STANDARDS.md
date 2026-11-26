# Security Standards Mapping (`crates/foca-analysis/signatures/standards.toml`)

↑ [Documentation](README.md) · [Third-Party Attributions](../THIRD_PARTY.md)

Declarative mapping from finding rule identifiers (`provenance.rule`) to international and Ukrainian information-security standards, loaded via `foca_analysis::standards::Standards::builtin()`. Every field is optional: only defensible, non-stretched mappings are recorded.

> **Auditor Disclaimer.** This mapping serves as an orientation guide and is not a formal state security examination (KSZI / КСЗІ) or certification opinion. Final compliance determinations must be made by an authorized auditor against the primary normative texts. The same localized disclaimer (`uk`/`ru`/`en`) is stored in `[disclaimer]` and embedded in the `compliance` and `lab` report templates.

| Field | Standard | Primary Source (verified 2026-11-26) |
|---|---|---|
| `mitre` | MITRE ATT&CK Enterprise v20 (reports print "ATT&CK v20") | https://attack.mitre.org/ and the STIX bundle at https://github.com/mitre/cti tag `ATT&CK-v20.0` (released 2026-10-13). Every cited technique exists there and is neither revoked nor deprecated. |
| `cwe` | MITRE CWE; ids in the 2025 CWE Top 25 are flagged | https://cwe.mitre.org/top25/archive/2025/2025_cwe_top25.html (`standards::CWE_TOP25_2025`) |
| `owasp` | OWASP Top 10:2025 | https://owasp.org/Top10/2025/ and the "List of Mapped CWEs" in https://github.com/OWASP/Top10/tree/master/2025/docs/en. A category is assigned only when its list includes the rule's CWE (A03 also for vulnerable components without a CWE). |
| `wstg` | OWASP WSTG v4.2 (stable) | https://github.com/OWASP/wstg/tree/v4.2/document/4-Web_Application_Security_Testing. Numbering in `latest` differs (e.g., `CONF-12`). |
| `iso27001` | ISO/IEC 27001:2022 Annex A, shown as "ISO/IEC 27001:2022 (ДСТУ ISO/IEC 27001:2023)" | 93 controls `5.1-8.34`. DSTU catalogue entry: https://online.budstandart.com/ua/catalog/doc-page?id_doc=104398 |
| `nist` | NIST SP 800-53 Rev. 5 (5.2.0) controls, also cited as НД ТЗІ 3.6-006-24 measures | NIST OSCAL catalogue https://github.com/usnistgov/oscal-content (`NIST_SP-800-53_rev5_catalog.json`, 5.2.0). НД ТЗІ 3.6-006-24 *"Порядок вибору заходів захисту інформації, вимога щодо захисту якої встановлена законом та не становить державної таємниці, для інформаційних систем"*: https://cip.gov.ua/services/cm/api/attachment/download?id=64620 |
| `privacy` | GDPR and Law of Ukraine No. 2297-VI *"On Personal Data Protection"* | https://eur-lex.europa.eu/eli/reg/2016/679/oj, https://zakon.rada.gov.ua/laws/show/2297-17 |
| `ndtzi` | Legacy, for systems certified under КСЗІ. НД ТЗІ 2.5-004-99 *"Criteria for Assessing Information Security in Computer Systems against Unauthorized Access"*, functional security services | https://tzi.com.ua/downloads/2.5-004-99.pdf, Section 4 ("Позначення послуг"), clauses 6-9 |
| `kszi` | Legacy, for systems certified under КСЗІ. НД ТЗІ 3.7-003-05 *"Procedure for Creating a Comprehensive Information Protection System (KSZI / КСЗІ) in ITS"*, lifecycle stages | https://tzi.com.ua/downloads/3.7-003-2005.pdf, Section 6 |

## OWASP Top 10: 2021 → 2025

The categories the mapping used were renumbered: `A01 → A01` (Broken Access Control), `A02 → A04` (Cryptographic Failures), `A05 → A02` (Security Misconfiguration), `A06 → A03` (Software Supply Chain Failures, which now includes vulnerable components), `A07 → A07` (Authentication Failures). The 2025 CWE lists also add `A01` for CWE-749 (unsafe HTTP methods, WebDAV) and `A06` Insecure Design for CWE-256 (plaintext passwords in RDP/ICA files), CWE-693 (no CSP) and CWE-1021 (clickjacking).

## ATT&CK v20

ATT&CK v19 split Defense Evasion into Stealth (`TA0005`, keeps the old id) and Defense Impairment (`TA0112`). No finding rule cites a technique from either tactic: the rules map to Reconnaissance, Resource Development, Initial Access, Execution, Credential Access, Discovery, Collection and Impact techniques. So the split changes no id here. `mitre_ids_exist_in_attack_v20` lists the checked ids.

## NIST SP 800-53 and НД ТЗІ 3.6-006-24

НД ТЗІ 3.6-006-24 is the Ukrainian catalogue of security measures for security profiles (base profile: order of the Administration of the State Service of Special Communications No. 317 of 24.06.2024). It is built on NIST SP 800-53 and keeps the Latin measure codes, so `SC-8` in the catalogue is NIST `SC-8`. Every `nist` id in the mapping was checked in two places: the 5.2.0 OSCAL catalogue, where it is not withdrawn, and the section 9 measure list of НД ТЗІ 3.6-006-24, under the same code. Ukrainian titles come from that list. Mapped controls:

| Control | Used for |
|---|---|
| `AC-22` Publicly Accessible Content | internal data, hidden content and personal data inside published documents |
| `SI-12(1)` Limit PII Elements | personal data in published documents |
| `IA-5(7)` No Embedded Unencrypted Static Authenticators | passwords and keys in documents, RDP/ICA files and JavaScript |
| `AT-2(3)` Social Engineering and Mining | e-mail address pattern, Reply-To mismatch |
| `SC-18` Mobile Code | macros, PDF JavaScript |
| `SA-22` Unsupported System Components | end-of-life software and OS |
| `SI-2` Flaw Remediation, `RA-5` Vulnerability Monitoring | outdated versions, KEV / InternetDB CVEs |
| `SI-10` Information Input Validation | ZIP path traversal |
| `AC-3` Access Enforcement | exposed backups, `.git`, listings, open buckets, open AXFR |
| `AC-4` Information Flow Enforcement | permissive CORS |
| `CM-7` Least Functionality | directory listing, TRACE, unsafe methods, WebDAV, exposed ports |
| `SC-7` Boundary Protection | exposed origin, exposed ports |
| `SC-8` Transmission Confidentiality and Integrity | missing HSTS, legacy TLS, weak ciphers |
| `SC-12` / `SC-13` Cryptographic keys / protection | weak keys, ciphers and signatures |
| `SC-17` PKI Certificates | expired, self-signed and weakly signed certificates |
| `SC-23` Session Authenticity | cookie flags |

Signature findings (modified after signing, digest mismatch, TSA gap), document lineage, org structure, internal network map, CSP/clickjacking, robots.txt, source maps, dangling CNAME and missing buckets have no NIST id. No control fits them without a stretch.

## Personal data findings

Rules that expose personal data (`pii`, `gps`, `mass-names`, `email-pattern`, `pim.contact_pii`, `doc.signer_identity`, `doc.pdf_revision_authors`) cite:

- GDPR Art. 5(1)(c) (data minimisation), Art. 5(1)(f) (integrity and confidentiality) and Art. 32 (security of processing);
- Law of Ukraine No. 2297-VI, Art. 6 part 3 (data must be relevant, adequate and not excessive) and Art. 24 (protection of personal data).

Draft law No. 8153 has not been adopted and is not cited.

## Verified Ukrainian Regulatory Details (legacy НД ТЗІ)

- **НД ТЗІ 2.5-004-99**, Section 4 defines the functional service codes: `КД`, `КА`, `КО`, `КК`, `КВ`, `ЦД`, `ЦА`, `ЦО`, `ЦВ`, `ДР`, `ДВ` (fault tolerance: printed as `ДВ` in the normative text, commonly referred to as `ДС`), `ДЗ`, `ДВ` (failure recovery), `НР`, `НИ`, `НК`, `НО`, `НЦ`, `НТ`, `НВ`, `НА`, `НП`. The code `КЦ` does not exist in the normative document and is never used.
- These functional services describe the system's protection suite (КЗЗ / комплекс засобів захисту), so a code is assigned only when a finding directly demonstrates failure of that control:
  - `КА` (6.2): exposed backups, `.git`, directory listings;
  - `КВ` (6.5) and `ЦВ` (7.4): weak TLS, missing HSTS, documents modified after digital signing;
  - `НИ` (9.2): passwords and cryptographic keys leaked in documents;
  - `НА` (9.8): digital signature / QES (КЕП) anomalies.
  - Ordinary document metadata leaks are intentionally not mapped to 2.5-004-99 functional services to avoid overclaiming.
- **НД ТЗІ 3.7-003-05**, Section 6 defines the KSZI lifecycle stages: `6.1` General requirements (`6.1.2` Environment survey: `6.1.2.4` computing system, `6.1.2.5` information environment, `6.1.2.7` user environment), `6.2` Security policy, `6.3` Technical specification, `6.4` Design, `6.5` Commissioning (`6.5.8` State expert review), and `6.6` Maintenance. OSINT findings serve as input evidence for the environment survey (`6.1.2.x`) and periodic monitoring during maintenance (`6.6`).
- Both documents are shown with the note "for systems certified under КСЗІ" (uk: «для систем, атестованих за КСЗІ», ru: «для систем, аттестованных по КСЗИ»): new systems are built on security profiles with НД ТЗІ 3.6-006-24 measures.

## Automated Verification (Unit & Integration Tests)

- `standards::tests::builtin_is_valid`: validates identifier syntax (`T\d{4}(.\d{3})?`, `CWE-\d+`, `A\d\d:2025`, `WSTG-[A-Z]{4}-\d\d`, NIST `AA-n` / `AA-n(n)`, ISO `5.1-5.37 / 6.1-6.8 / 7.1-7.14 / 8.1-8.34`). It also ensures zero duplicates, confirms every ISO / NIST / privacy / ND TZI / KSZI code exists in the file's dictionaries, and checks the tri-lingual disclaimer.
- `tests/standards.rs::mapped_rules_exist_in_the_finding_catalog`: confirms every mapped rule is actually emitted by at least one workspace crate.
- `wstg_ids_exist_in_v4_2`, `owasp_matches_cwe`, `mitre_ids_exist_in_attack_v20`, `nist_ids_exist_in_both_catalogues` and `mitre_matches_the_emitted_technique`: enforce consistency against the primary-source tables.
