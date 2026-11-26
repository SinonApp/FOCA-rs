# Decisions (ADR)

↑ [Documentation](../README.md) · [Architecture](../dev/architecture.md)

Architecture Decision Records, short notes capturing major design decisions: context, decision, and consequences.
Format: `NNNN-short-name.md`, heading `# ADR-NNNN: …`, fields "Status", "Context", "Decision", "Consequences".
Decisions are never rewritten retroactively: a new decision is recorded as a new ADR or an "Addendum" section.

| No. | Decision | Status |
|---|---|---|
| [0001](0001-android-only.md) | Android-only target | accepted (2026-11-20) |
| [0002](0002-vanilla-js-ui.md) | Vanilla JS UI without a bundler | accepted |
| [0003](0003-native-insets.md) | System bar insets from Kotlin | accepted |
| [0004](0004-sqlite-per-project.md) | One SQLite file per project | accepted (from spec, F-2) |
| [0005](0005-panic-strategy.md) | `panic = "unwind"` in release builds | accepted |
| [0006](0006-native-bridge.md) | Native bridge: single `foca` command, in-app Kotlin plugin | accepted |
| [0007](0007-search-engines-via-webview.md) | Search engines via hidden WebView, dropping Google | accepted (2026-11-20; amended in 1.0.1 and 1.1) |
| [0008](0008-ports-tcp-connect-own-probes.md) | Ports: rootless TCP connect, custom probes, VPN canaries | accepted (2026-11-21; amended in 1.0.1) |
| [0009](0009-passive-never-touches-target.md) | Passive access never contacts target or excluded hosts | accepted (2026-11-21, from security review finding) |
| [0010](0010-api-keys-optional.md) | API keys are strictly optional, UI "Variant D" | accepted (2026-11-21) |
| [0011](0011-port-logic-not-binaries.md) | Port third-party tool logic instead of bundling binaries | accepted (2026-11-20, beta plan; reaffirmed in 1.0) |
| [0012](0012-no-captcha-solving-no-public-proxies.md) | No automatic CAPTCHA solving and no public proxies | accepted (2026-11-21, 1.0.1 and 1.1 plan; partially implemented) |

Related documents: [Architecture](../dev/architecture.md), Specification (TZ), [Roadmap](../ROADMAP.md).
