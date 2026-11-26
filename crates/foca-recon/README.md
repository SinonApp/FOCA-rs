# foca-recon

Пассивная разведка сайта для FOCA-rs. Работает по **уже скачанным** данным; сеть: только через
`foca_net::NetClient` (скоуп, лимиты, журнал, отмена). Не подключён к движку (этап 4h).

| Модуль | Что делает | Сеть |
|---|---|---|
| `favicon` | `favicon_hash(bytes)` → mmh3 (Shodan `http.favicon.hash`), sha256, md5; `find_icon_links(html, base)` | нет |
| `tech` | `detect(&PageInput)` → технологии/версии/уверенность/доказательства; `extract_analytics_ids` (UA-/G-/GTM-/AW-/ca-pub-/Метрика/Pixel) | нет |
| `js` | `analyze_js(url, body)` → эндпоинты (fetch/axios/XHR/$.ajax/литералы/GraphQL/ws/source map) и секреты (маска 4+2) | нет |
| `grepapp` | `search(&client, DEFAULT_BASE, "example.com", 1)` → репозитории/файлы/строки | `Passive` |
| `wellknown` | `parse_robots` / `parse_sitemap` / `parse_security_txt`, `parse_cdx`, `select_snapshots`, `harvest_from_archive(&client, cdx, &opts)` | `Passive` (web.archive.org) |
| `buckets` | `find_buckets(text, source)`, `merge_buckets`, `check_buckets(&client, &mut b, &opts)` (по флагу, выкл.) | по флагу |
| `report` | `analyze_site(&ReconInput) -> ReconReport` + `findings: Vec<ReconFinding>` | нет |

```rust
let mut rep = foca_recon::analyze_site(&input);          // страницы, JS, favicon, тексты, URL
foca_recon::buckets::check_buckets(&net, &mut rep.buckets, &opts).await; // если пользователь разрешил
rep.refresh_findings();
let findings: Vec<_> = rep.findings.iter().map(|f| f.to_finding(&now)).collect();
```

Находки: `recon.bucket_listing` (высокая), `recon.bucket_missing` (средняя), `recon.js_secret`
(высокая/критическая; generic/JWT/Google key: средняя), `recon.outdated_tech` (средняя),
`recon.sourcemap` (низкая), `recon.robots_hidden`, `recon.bucket_refs`, `recon.code_mentions`,
`recon.analytics_pivots`, `recon.favicon` (инфо).

Ограничения: JS не исполняется (нет правил по JS-глобалам/DOM); grep.app закрыт Vercel-челленджем для
серверных IP (`GrepAppError::Challenge`); сжатые `sitemap.xml.gz` распаковывает вызывающий.
Правила технологий: `data/tech.json` (GPL-3.0, см. THIRD_PARTY.md).
