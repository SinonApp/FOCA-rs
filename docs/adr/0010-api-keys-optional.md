# ADR-0010: API Keys Are Strictly Optional, UI "Variant D"

↑ [Decisions (ADR)](README.md) · [Documentation](../README.md)

- Status: accepted (2026-11-21)
- Context: In 0.2-0.3, the wizard, sources screen, and scan screen displayed "Key required" badges and "Configure"
  buttons: users assumed the app would not work without keys and abandoned their first scan. Free keyless sources are
  sufficient (search engines via embedded browser, web archives, CT, 10 subdomain services, site recon).
- Decision ("Variant D"):
  - API keys are configured only in "Settings → API Keys". The wizard, sources screen, and scan screen show no
    "Configure" buttons or "Key required" badges; paid sources without a key are hidden during scans.
  - Adding a key automatically enables its source (`F.sourceKeyAdded`).
  - Sources are organized into 5 groups (Search Engines, Archives, Subdomains, Recon, Crawler) with a group toggle and
    expand control, plus a collapsed "Additional, with key" group (Brave Search API, SearXNG, Shodan).
  - Keys are stored in Android Keystore (`KeyVault.kt`, AES-256-GCM); the database stores only status and masked value.
- Consequences: The first scan works out of the box; API keys only provide higher quotas or extra sources. 1.1 plan:
  optional OTX key. Code: `ui/screens/sources.js`, `ui/screens/settings.js`, `docs/dev/ui.md`.
