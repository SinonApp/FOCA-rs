# ADR-0001: Android-Only Target

↑ [Decisions (ADR)](README.md) · [Documentation](../README.md)

- Status: accepted (2026-11-20)
- Context: The original specification assumed Windows/Linux/macOS. The client decided to drop the desktop version.
- Decision: A single target client, Android (Tauri 2 + WebView). The core remains a cross-platform Rust crate and is
  verified on desktop via tests and the CLI.
- Consequences: The UI is designed for touch, one-handed use, and large text; ICMP, AXFR, and background tasks operate
  under Android platform restrictions.
