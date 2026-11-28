# Security Policy

## Supported versions

| Version | Supported |
|---|---|
| 2.0.0-beta.4.1.1 (latest pre-release) | ✅ security fixes |
| 1.x | ✖, please update (uninstall first: 2.0 is signed with a new key) |

Fixes land on `main` and ship in the next beta.

## Reporting a vulnerability

**Do not open a public issue** for a security problem.

Report it privately through GitHub Security Advisories: open the repository's **Security** tab and choose
**Report a vulnerability**, or go straight to
<https://github.com/SinonApp/FOCA-rs/security/advisories/new>. Only the maintainers see the report.

Please include:

- the app version and build (`foss` or `play`, shown in Settings → About) and the Android version;
- what an attacker can do and the steps or a proof of concept to reproduce it;
- whether it needs a crafted document, a malicious site, a plugin or physical access to the phone.

Do not attach real client data or reports from real targets. A synthetic file that triggers the issue is enough.

We aim to acknowledge a report within 7 days and to agree on a disclosure date with you once a fix is ready.
Reporters are credited in the advisory unless they ask otherwise.

## What counts as a vulnerability

In scope, for example:

- a request to a target host in the Passive profile, or to an excluded host in any profile;
- code execution, file access or a crash through a crafted document, archive or plugin;
- leaks of API keys, secrets or personal data into logs, reports, exports or AI prompts;
- bypassing the PIN, the panic PIN, plugin sandbox limits or signature checks of signature databases and reports.

Out of scope: findings that need a rooted or already compromised phone, social engineering, and denial of service
through scans you start yourself.

## How the app protects data

- **Storage**: one SQLite file per project in private app storage; Android backup is disabled.
- **Keys**: API keys and alert tokens live in Android Keystore (KeyVault), never in settings, logs or reports.
- **Secrets and personal data**: personal data is masked before it is stored; secrets stay hidden until you confirm
  with a fingerprint or the PIN; AI prompts use placeholders and you review them before sending.
- **App lock**: PIN at launch, auto-lock, a panic PIN that wipes all data, clipboard clearing; screenshot blocking is
  an opt-in switch.
- **Encrypted export**: `.foca.enc` uses PBKDF2-HMAC-SHA256 (210,000 iterations) and ChaCha20-Poly1305; passwords are
  never stored.
- **Integrity**: signature database updates are verified with Ed25519 and SHA-256; reports can carry a SHA-256 digest
  and an ECDSA P-256 signature from Android Keystore.
- **Plugins**: run in a sandbox with memory and instruction limits, without file or socket access, under the same
  scope and passive rules as built-in modules.

## Responsible use

FOCA-rs is meant for authorized assessments: your own organization, or a client who gave written permission.

- **Passive** queries only public third-party sources and sends nothing to target hosts
  ([ADR-0009](docs/adr/0009-passive-never-touches-target.md)).
- **Standard** and **Full** contact in-scope targets; Full adds active modules (zone transfer, NSEC walking, port
  scan, site search, CORS and HTTP-method checks). Exclusions always win over targets, on every redirect and resolved
  address, and every outgoing request is written to the project request log.
- Holding the authorization is the operator's responsibility.
