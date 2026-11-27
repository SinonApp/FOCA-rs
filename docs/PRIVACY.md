# Privacy policy

FOCA-rs is an open-source Android app (GPL-3.0) published by SinonApp. This page describes what
data the app handles, where it goes and what stays on your device. It applies to both builds
(`foss` and `play`) unless a section says otherwise.

## Summary

- There is no FOCA-rs account and no FOCA-rs server. The developers receive no data from the app.
- The app contains no advertising, no analytics and no usage telemetry.
- Projects, documents, findings, reports and settings stay on your device, in the app's private
  storage (Android app sandbox and device encryption). API keys and tokens are encrypted with the
  Android Keystore.
- Network requests are made only to run the checks you start, to update the signature database
  and to use services you configure yourself.

## Data stored on the device

- **Projects**: targets and scope, downloaded documents, extracted metadata and text, findings,
  your triage notes, scan history and reports. They are stored in the app's private storage, which
  Android isolates from other apps and encrypts with the device. Exports are written only where you choose; `.foca.enc` bundles are encrypted with your
  passphrase, reports are plain files.
- **Settings and keys**: settings are stored in the app's private storage. API keys, bot tokens
  and webhook URLs are encrypted with the Android Keystore and never written to settings files,
  exports or logs.
- **Logs**: the debug log and the request journal stay on the device. They leave it only when you
  share them yourself (Settings > About > Report a problem creates a ZIP in `Download/FOCA-rs`).

You can delete any project in the app. Uninstalling the app removes all of its private data.

## Network requests

FOCA-rs is a reconnaissance tool, so most of its work is network requests made on your behalf.
What each request carries:

| When | Where it goes | What is sent |
|---|---|---|
| Passive sources (search engines, web archives, certificate transparency, passive DNS, public scan caches) | The services listed in [Sources](user/sources.md) | The target domain or search query, as in any web search |
| Standard and Full profiles | The target's own servers (crawler, DNS, TLS, port scan, path discovery, as enabled in the profile and scope) | Ordinary HTTP, DNS and TCP requests to the target |
| Services with your API key (Brave Search API, Shodan, VirusTotal, SecurityTrails, GitHub, your own SearXNG) | That service | The target domain or query and your key |
| AI summary, only when you run it | The AI provider you configured, with your key | The findings and project data selected for the summary |
| Breach check of a found password, only when enabled | Pwned Passwords (`api.pwnedpasswords.com`) | The first 5 characters of the SHA-1 hash (k-anonymity); the password and the rest of the hash never leave the device |
| Alerts, only when configured | Your Telegram bot or webhook | The alert text |
| Signature database updates | GitHub Releases of SinonApp/FOCA-rs | A plain download request, no identifiers |

All requests honour the app's network settings (proxy, Wi-Fi only, mobile data limit). HTTPS is
used wherever the remote side supports it.

## Optional OCR in the `play` build

The `play` build can recognise text in scanned documents (OCR, off by default, enabled in
settings). It uses Google ML Kit, which runs on the device; the documents are not uploaded. The
ML Kit library may send anonymous diagnostic and usage data to Google under
[Google's terms for ML Kit](https://developers.google.com/ml-kit/terms). The `foss` build does
not include ML Kit.

## Personal data of third parties

Documents you analyse can contain names, e-mail addresses, phone numbers and identifiers of other
people. The app processes them only on your device and masks identifiers in the interface and
reports. You are responsible for having a lawful basis for the checks you run and for handling
the results according to the data protection laws that apply to you.

## Children

The app is a professional security tool and is not intended for children.

## Changes and contact

Changes to this policy are visible in the repository history. Questions and security reports:
[SECURITY.md](../SECURITY.md) (private security advisory on GitHub) or an issue in the
repository.
