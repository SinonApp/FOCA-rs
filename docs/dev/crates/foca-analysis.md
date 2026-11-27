# foca-analysis

↑ [Core Crates](README.md) · [Developer Guide](../README.md) · [Architecture](../architecture.md)

- [Purpose](#purpose)
- [Modules](#modules)
- [Public API](#public-api)
- [Tests](#tests)
- [Pitfalls](#pitfalls)

Path: `crates/foca-analysis/` · `src/` lines: 20,852 · tests: 119 · depends on: [foca-core](foca-core.md), [foca-meta](foca-meta.md)

## Purpose

`foca-analysis` runs deterministic, pure-Rust analysis over a project's extracted documents and infrastructure facts: with zero network access, zero database access, and NO local AI / on-device LLM synthesizer (AI summaries are strictly cloud-only in `foca-engine`, never generated locally).

Given extracted `Metadata` + plain text (`foca-meta`), the project `Scope`, and previous finding triage state (`PrevState`), `analyze()` outputs entities, findings (in exact `docs/API.md` snapshot DTO format), relation graphs, activity timelines, and risk scores. Full deterministic recalculation paired with stable finding IDs (hash of rule ID + object key) preserves user triage across incremental scans.

Built-in signature tables live in `crates/foca-analysis/signatures/` (`software.toml`, `secrets.toml`, `standards.toml`, `kev.tsv.gz`, `kev_products.toml`).

### Key Subsystems

- **Forensics, PII & Custom Rules**:
  - `assess/forensic.rs`: per-document facts (recursively across attachments) and ~25 rules (`doc.*`, `mail.*`, `cal.*`, `pim.*`, `media.*`, `zip.*`, `doc.links`, `doc.user_rule`, `pii`).
  - `content/pii.rs`: Ukrainian RNOKPP, EDRPOU, UA IBAN, payment cards (Luhn + BIN), passports/IDs (context-aware), phone numbers, and classification markings (stamp lines only, `content/markings.rs`); `sanitize` masks text and metadata before persistence (`ProjectDb::set_analyzed`).
  - `content/links.rs`: cloud workspaces and tokens in URLs (SAS, presigned URLs, webhooks, bot tokens), always masked.
  - `content/rules.rs`-"YARA-lite" presets (`ua-gov`, `credentials`, `infra`, `crypto`, `personal`) and bounded user regexes (`<= 512` chars, `<= 64` rules, `<= 1 MiB` DFA, no empty matches).
  - `content/artifacts.rs`: parses exposed `.git/config`, `.git/logs/HEAD`, `.env`, `.ovpn`, `package.json`, `composer.json` from `foca-fuzz` into masked summaries.
- **Analytics & Insights**:
  - `analytics/insights.rs`, `analytics/correlate.rs`, `identity/orgchart.rs`, `analytics/anomalies.rs`, `analytics/netmap.rs`, `analytics/chain.rs`, `analytics/graphview.rs`: document lineage/clones (`xmpMM:DerivedFrom`, RSIDs), inferred org chart with bounded confidence (`<= 95`), metadata contradiction anomalies (`doc.anomaly.*`), internal AD forest/domain/server/workstation/user tree (`netmap`), Dijkstra link chains, and 360 dp collapsed layered graph views.
  - `products/kev.rs` + `products/vercmp.rs`: offline CISA KEV catalog + semantic version / CPE 2.3 / CVE range evaluation (`I-10`); reports `possible` / `likely` without asserting exploitability.
  - `assess/standards.rs` + `signatures/standards.toml`: maps finding rules to MITRE ATT&CK v20, CWE (2025 Top 25 flag), OWASP Top 10:2025, WSTG v4.2, ISO/IEC 27001:2022 Annex A, NIST SP 800-53 Rev. 5 / ND TZI 3.6-006-24, GDPR / Law 2297-VI articles, and the legacy ND TZI 2.5-004-99 and ND TZI 3.7-003-05 (see [docs/STANDARDS.md](../../STANDARDS.md)).
- **Attack Path Engine (`assess/attack_paths.rs`)**:
  - Correlates leaked documents and configuration artifacts (`.ovpn`, `.env`, `.rdp`, secrets, LNK/UNC paths), extracted corporate identities / AD login templates (`identity/wordlist.rs`), and exposed perimeter hosts or KEV vulnerabilities into ranked directed `AttackPath` chains (`AttackStep`, score, severity, likelihood).
  - Computes minimum-cut Remediation Choke Points (`ChokePoint`): the fixes that break the most attack paths at once. Raw secrets and unmasked PII are never interpolated into labels or details.
- **Localized Remediation Playbooks (`assess/playbooks.rs` + `locales/{en,ru,uk}/playbooks.json`)**:
  - Maps `provenance.rule` (or category fallback) to contextual remediation steps (`Playbook`, `PlaybookStep`), owner roles, safe verification commands parameterized with sanitized host/domain/port/URL/CVE/document names, and standard references.
  - Uses unified `foca_core::Lang` and loads templates from `locales/{en,ru,uk}/playbooks.json` via `include_str!`. Never interpolates raw finding `evidence`.
- **Monitoring Alerts & Wordlists**:
  - `alerts.rs`: scheduled monitoring diff alerts (mini-ASM) and inter-scan risk trend computation.
  - `identity/wordlist.rs`: corporate login template generation (`CORP\i.petrov`, `ipetrov`, `petrov_i`, …) and targeted dictionaries.

## Modules

Layout: `lib.rs` runs `analyze()`; submodules group the rules by subject: `content/` (what is inside documents), `identity/` (people, e-mails, org chart, wordlists), `products/` (software, versions, KEV), `assess/` (findings, forensics, standards, playbooks, attack paths), `analytics/` (correlation, anomalies, network map, graph views). Root modules hold hosts, roles, relations, timeline, alerts and shared helpers.

| File | Lines | Contents |
|---|---|---|
| `src/alerts.rs` | 1,016 | Scheduled monitoring event alerts (mini-ASM) and risk trend computation |
| `src/analytics/anomalies.rs` | 464 | Metadata contradictions (`created_after_modified`, `date_mismatch`, `history_*`, `software_newer_than_document`) |
| `src/analytics/chain.rs` | 293 | Shortest readable Dijkstra "link chain" from a finding/document to high-value infrastructure |
| `src/analytics/correlate.rs` | 588 | Document correlation: copies, clones, and derivatives (`Lineage`) via XMP IDs and Word RSIDs |
| `src/analytics/graphview.rs` | 254 | Layered graph views with node collapsing tailored for 360 dp mobile screens |
| `src/analytics/insights.rs` | 108 | Analytics aggregator over a finished `Analysis` (`correlation`, `org`, `anomalies`, `kev`, `netmap`, `graph`) |
| `src/analytics/netmap.rs` | 878 | Internal network map (`AD forest → domain → servers → workstations → users`) |
| `src/assess/attack_paths.rs` | 662 | Attack Path Engine & Remediation Choke Points (`AttackPathReport`, `AttackPath`, `ChokePoint`) |
| `src/assess/draft.rs` | 55 | A finding under construction, turned into findings with stable ids by `assess/findings.rs` |
| `src/assess/findings.rs` | 1,043 | Core finding generation rules, severity, MITRE mapping, stable IDs, and risk scoring |
| `src/assess/forensic.rs` | 1,090 | Document forensics facts and ~25 rules (signatures, KEP, revisions, redactions, mail/PIM/media/ZIP) |
| `src/assess/infra.rs` | 226 | Infrastructure finding rules (TLS/X.509, subdomain enumeration, mail policies, SaaS/CDN) |
| `src/assess/playbooks.rs` | 667 | Contextual remediation playbooks (`finding_playbook`) localized via `locales/{en,ru,uk}/playbooks.json` |
| `src/assess/standards.rs` | 523 | Rule → security standards mapping (`signatures/standards.toml`) and validator |
| `src/content/artifacts.rs` | 881 | Safe masked parsing of `foca-fuzz` artifacts (`.git/config`, `.env`, `.ovpn`, `package.json`, `composer.json`) |
| `src/content/links.rs` | 678 | External cloud links and masked token detection inside documents |
| `src/content/pii.rs` | 1,406 | Personal data & access markings detection plus pre-persistence sanitization (`sanitize`) |
| `src/content/rules.rs` | 536 | Built-in and user-defined bounded regex search rules ("YARA-lite") |
| `src/content/secrets.rs` | 527 | Gitleaks-style secret detection (`signatures/secrets.toml`) with masking |
| `src/hosts.rs` | 494 | Hosts and computers from document URLs, UNC/local paths, printers, and mail headers |
| `src/identity/emails.rs` | 556 | E-mail collection, role-address detection, and corporate address pattern inference |
| `src/identity/orgchart.rs` | 723 | Automatic org chart: departments, organizations, and person roles with provenance |
| `src/identity/people.rs` | 1,323 | Person name normalization, service-account filtering, and identity merging |
| `src/identity/translit.rs` | 360 | Cyrillic-to-Latin transliteration and phonetic identity skeletons |
| `src/identity/wordlist.rs` | 848 | Corporate login template generation and targeted wordlists |
| `src/lib.rs` | 1,303 | `analyze()` orchestrator, `DocInput`, `PrevState`, `Analysis`, and re-exports |
| `src/products/kev.rs` | 623 | Offline CISA KEV catalog matcher (`signatures/kev.tsv.gz`, `kev_products.toml`) |
| `src/products/software.rs` | 477 | Software and OS detection (`signatures/software.toml`) + EOL checks |
| `src/products/vercmp.rs` | 538 | Semantic version parsing, comparison, and CPE 2.3 / CVE range evaluation (`I-10`) |
| `src/relations.rs` | 148 | Relation graph (`document ↔ person ↔ computer ↔ host ↔ software ↔ e-mail ↔ printer`) |
| `src/roles.rs` | 512 | Hostname role classification (e.g., `dev-api.staging.example.com` → staging/API) |
| `src/tests.rs` | 365 | Synthetic end-to-end `analyze` unit tests |
| `src/timeline.rs` | 262 | Document chronology and 7×24 weekday/hour activity matrix with inferred timezone |
| `src/util.rs` | 385 | Shared helpers: stable IDs, dates, hosts from URLs, IP helpers |

## Public API

Re-exports in `src/lib.rs`:

- `findings::{Risk, RiskLevel}`
- `relations::Graph`
- `software::{Signatures, SwMatch}`
- `timeline::Activity`

Top-level types & functions: `analyze()`, `DocInput`, `PrevFinding`, `PrevState`, `OsInfo`, `Analysis`, `DocFacts`, plus public modules (`attack_paths`, `playbooks`, `insights`, `alerts`, `standards`, `pii`, `vercmp`, `wordlist`, ...).

Full API docs: `cargo doc -p foca-analysis --no-deps --open`.

## Tests

`cargo test -p foca-analysis`: 105 unit tests in `src/` + 8 integration tests in `tests/`:

| File | Tests |
|---|---|
| `tests/corpus.rs` | 260 |
| `tests/forensics.rs` | 80 |
| `tests/insights.rs` | 320 |
| `tests/reviewers.rs` | 187 |
| `tests/standards.rs` | 123 |

## Pitfalls

- **No local AI**: do not add on-device LLM or heuristic "AI summary" code here: `foca-analysis` is strictly deterministic analytics; AI summarization is cloud-only in `foca-engine`.
- Built-in signatures (`signatures/*.toml`, `kev.tsv.gz`) are compiled into the binary; runtime updates come via signed `sigbundle` overlays in `foca-engine`.
- Historical EOL findings (from Wayback or documents older than 3 years) are downgraded by one severity level.
- Raw PII must never be persisted to SQLite: any new string metadata field must pass through `pii::sanitize` (enforced by `foca-engine/tests/offline.rs`).
- Localized playbook entries live in `locales/{en,ru,uk}/playbooks.json`; all three locales must stay key-synchronized. Core finding texts are translated for reports via `locales/{en,ru,uk}/findings.json` in `foca-report/src/ftext.rs`.
