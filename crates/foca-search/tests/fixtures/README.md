# Фикстуры ответов источников (офлайн-тесты foca-search / foca-net)

Сняты 2026-11-20 одним запросом к публичным API по безопасным доменам `iana.org` / `example.com`:

| Файл | Источник | Запрос |
|---|---|---|
| `wayback_cdx.json` | реальный ответ | `web.archive.org/cdx/search/cdx?url=iana.org/*&output=json&fl=timestamp,original,mimetype,length,statuscode&filter=statuscode:200&filter=mimetype:application/pdf&collapse=urlkey&limit=6&showResumeKey=true` |
| `cc_collinfo.json` | реальный ответ (первые 3 индекса) | `index.commoncrawl.org/collinfo.json` |
| `../../foca-net/tests/fixtures/crtsh.json` | реальный ответ (первые 40 из 276 строк) | `crt.sh/?q=%.iana.org&output=json` |
| `../../foca-net/tests/fixtures/certspotter.json` | реальный ответ | `api.certspotter.com/v1/issuances?domain=example.com&include_subdomains=true&expand=dns_names` |
| `../../foca-net/tests/fixtures/rdap_domain.json` | реальный ответ | `rdap.org/domain/example.com` |
| `../../foca-net/tests/fixtures/ripe_network_info.json` | реальный ответ | `stat.ripe.net/data/network-info/data.json?resource=192.0.43.8` |
| `cc_index.ndjson` | **по документации** формата | индекс CC в момент съёмки отвечал 504 Gateway Time-out (3 попытки) |
| `brave.json` | **по документации** Brave Search API | ключа нет |
| `searx.json` | **по документации** SearXNG (`format=json`) | публичные экземпляры отдают капчу/запрещают JSON |

### `render/`: страницы поисковиков для дорков через встроенный браузер

Сняты 2026-11-20 скриптом `qa/search-fixtures.mjs` (Playwright/Chromium, десктопный Chrome UA: тот же
сценарий, что `RenderFetcher.kt`: Startpage, главная → проверка → форма → «Next»; Brave:
`search?q=…&source=web&offset=N`). Из HTML вырезаны `<style>`, `<svg>`, data:-картинки; у Startpage:
скрипты, у Brave: скрипты кроме данных выдачи (`meta_url`). IP машины, с которой снимались страницы, в странице проверки заменён на
`203.0.113.7`.

| Файл | Что |
|---|---|
| `startpage_verify.html` | реальная страница проверки Startpage (Anubis proof-of-work, «Verifying your request…») |
| `startpage_nasa_gov_pdf_p1.html`, `_p2.html` | реальная выдача `site:nasa.gov filetype:pdf`, стр. 1-2 |
| `startpage_testfire_net_pdf_p1.html` | реальная выдача `site:testfire.net filetype:pdf` (1 результат) |
| `brave_nasa_gov_pdf_p1.html`, `_p2.html` | реальная выдача Brave (ссылки скрыты за `/go/v1/…`, адрес: из `meta_url`) |
| `brave_testfire_net_pdf_p1.html` | реальная выдача Brave, 2 результата |
| `brave_testfire_net_pdf_p2_empty.html` | реальная стр. 2 Brave «Not many great matches» (пустая выдача; скрипт со строкой «CAPTCHA» оставлен: регрессия живой проверки) |
| `mojeek_403.html` | реальный ответ Mojeek с IP дата-центра: 403 «automated queries» |
| `mojeek_testfire_net_pdf_manual.html` | **вручную** по разметке Mojeek (`ul.results-standard > li > a.ob`, `h2 > a`, `p.s`, как в searxng `engines/mojeek.py`): живая выдача с сервера недоступна |

`crtsh.json` лежит в `crates/foca-net/tests/fixtures/` (используется обоими крейтами). `contoso_zone.txt` там же: синтетическая зона для DNS/SPF/DMARC/takeover.
