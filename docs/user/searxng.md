# Own SearXNG instance

↑ [User Guide](README.md) · [Sources](sources.md)

Public search engines show CAPTCHAs to phones on shared IPs (mobile CGNAT, VPN, Wi-Fi of a provider), and FOCA-rs never solves them. A SearXNG instance you run yourself asks the search engines from your server's IP and answers FOCA-rs with plain JSON, so dorks keep working when Startpage or Brave refuse the phone.

FOCA-rs asks your instances **before** the public SearXNG pool and the keyless engines. Several instances are fine: enter them separated by commas or one per line; an instance that refuses JSON or keeps failing is skipped for the rest of the scan.

## Requirements

- An address with **HTTPS and a public host name** (`https://search.example.org`). Plain HTTP, `localhost`, `.local`/`.internal` names and private or reserved IP addresses are refused, like every other user URL in the app.
- The **JSON output format** enabled (it is off by default).

## Quick start with Docker

```sh
docker run -d --name searxng --restart unless-stopped \
  -p 127.0.0.1:8080:8080 \
  -v ./searxng:/etc/searxng \
  -e SEARXNG_BASE_URL=https://search.example.org/ \
  searxng/searxng
```

The first start writes `./searxng/settings.yml`. Open it, add `json` to the output formats and restart the container:

```yaml
search:
  formats:
    - html
    - json
```

```sh
docker restart searxng
```

Put the container behind your usual HTTPS reverse proxy (Caddy, nginx, Traefik) for the public name. Check it from any browser: `https://search.example.org/search?q=test&format=json` must return JSON, not an error page (HTTP 403 means `json` is still missing from `formats`).

Keep the instance for yourself: an open instance attracts bots, and its upstream engines then rate-limit it too. Limit access at the reverse proxy, for example with an IP allow list. The SearXNG `limiter` (bot detection) treats API requests as bots, so keep it off when only you use the instance.

## Connect it in FOCA-rs

1. **Settings → API keys → SearXNG**.
2. Paste the address (or several, separated by commas).
3. Tap **Test instances**: each address shows "answers JSON, results: N", or the reason (no JSON, not HTTPS/public, no answer, rate limit).
4. **Save**. The address is stored encrypted like the API keys (Android Keystore) and the `searx` source turns on by itself.

During a scan the `searx` card on the scan screen shows its status; a 429 or 503 from the instance slows the source down and, if it repeats, stops it for this scan with the "rate limit" status.

## Related

- [Sources](sources.md): all document and subdomain sources, statuses and keys.
- [CAPTCHA & Manual Verification](settings-network.md#captcha--manual-verification): what happens when every engine shows a CAPTCHA (postponed searches, "Retry now").
- Official guide: [SearXNG installation with Docker](https://docs.searxng.org/admin/installation-docker.html).
