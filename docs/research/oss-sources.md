# Открытые проекты и бесплатные источники для FOCA-rs

↑ [Исследования](README.md) · [Документация](../README.md)

Собрано 20.11.2026. Лицензии взяты из GitHub API. Живые проверки делались `curl` из песочницы по домену iana.org.
Наш проект под GPL-3.0. Код из MIT, Apache, BSD и GPL-3.0 можно переносить с указанием авторства. Из GPL-2.0-only, проектов без лицензии и CC-BY берём только факты (эндпоинты, форматы ответов, списки отпечатков) и пишем код сами.

## 1. Поддомены без ключа

Источник истины: список `projectdiscovery/subfinder` (MIT, Go) `pkg/subscraping/sources/<имя>/<имя>.go`, метод `KeyRequirement()`.

| Источник | subfinder | Эндпоинт | Живая проверка |
|---|---|---|---|
| crt.sh | NoKey | `https://crt.sh/?q=%25.<d>&output=json` | 200, 11,5 с, медленно, нужен таймаут |
| CertSpotter | RequiredKey в subfinder | `https://api.certspotter.com/v1/issuances?domain=<d>&include_subdomains=true&expand=dns_names` | 200 без ключа (лимит малый) |
| Anubis | NoKey | `https://anubisdb.com/anubis/subdomains/<d>` (jldc.me → 301 сюда) | 200 |
| HackerTarget | OptionalKey | `https://api.hackertarget.com/hostsearch/?q=<d>` | 200, CSV host,ip, ~50 запросов/день |
| RapidDNS | NoKey | `https://rapiddns.io/subdomain/<d>?full=1` (HTML) | 200, 2,5 с |
| subdomain.center | OptionalKey | `https://api.subdomain.center/?domain=<d>` | 200, 5,9 с |
| THC | NoKey | `https://ip.thc.org/api/v1/subdomains/download?domain=<d>&limit=N` | 200 |
| Common Crawl | NoKey | `index.commoncrawl.org/<CC-MAIN-…>-index?url=*.<d>&output=json` | 200 |
| Wayback | NoKey | CDX `web.archive.org/cdx/search/cdx?url=*.<d>&fl=original&collapse=urlkey` | таймаут 40 с: нестабилен, нужны ретраи и пагинация |
| Shodan CT | NoKey | `ctl.shodan.io` (см. `shodanct.go`) | не проверял |
| HudsonRock | NoKey | `cavalier.hudsonrock.com/api/json/v2/osint-tools/urls-by-domain?domain=<d>` | 200 (утечки инфостилеров: URL/поддомены) |
| digitorus | NoKey | `certificatedetails.com` | не проверял |
| ScanMalware | NoKey | `scanmalware.com` | не проверял |
| Sitedossier | NoKey | `sitedossier.com/parentdomain/<d>` | 403 (антибот), не брать |
| AlienVault OTX | RequiredKey в subfinder | `otx.alienvault.com/api/v1/indicators/domain/<d>/url_list` и `/passive_dns` | url_list 200 без ключа |
| urlscan.io | RequiredKey в subfinder | `urlscan.io/api/v1/search/?q=domain:<d>` | 200 без ключа (малый лимит) |

Ещё без ключа: theHarvester `discovery/` (GPL-2.0, только факты): `arquivo.py`, `duckduckgosearch.py`, `mojeek.py`, `yahoosearch.py`, `baidusearch.py`, `robtex.py`, `thc.py`, `subdomaincenter.py`, `shodan_internetdb.py`, `takeover.py`.

## 2. URL и документы без ключа

- `lc/gau` (MIT, Go) `pkg/providers/{wayback,commoncrawl,otx,urlscan}/`: образец пагинации CDX (`showNumPages`, `page=`), перебора индексов Common Crawl через `collinfo.json`, OTX `url_list?page=`, urlscan `search_after`. Это главное решение для «Wayback то работает, то нет».
- `xnl-h4ck3r/waymore` (MIT, Python) `waymore/waymore.py`, то же плюс скачивание архивных копий файлов из Wayback через `https://web.archive.org/web/<ts>id_/<url>` (документ берётся из архива, цель не трогается, это подходит для пассивного режима). Ретраи, обработка 429/503, ограничение скорости.
- Arquivo.pt: `https://arquivo.pt/textsearch?q=site:<d>&type=pdf` и CDX `arquivo.pt/wayback/cdx`, работает (200).
- FOCA (ElevenPaths, GPL-3.0, C#) `SearcherCore/SearcherCore/Searcher/{GoogleWebSearcher,BingWebSearcher,DuckduckgoWebSearcher}.cs`: разбор HTML-выдачи для дорков `site:<d> filetype:<ext>` без ключа. Код совместим по лицензии, можно портировать.
- `dwisiswant0/go-dork` (MIT, Go), дорки по Google/Bing/DuckDuckGo/Yahoo/Ask: парсеры и пагинация.
- `opsdisk/metagoofil` (лицензия NOASSERTION): дорки по документам; только идеи (задержки, user-agent, обход блокировок).
- `m8sec/pymeta` (GPL-3.0, Python): дорки Google и Bing под типы документов и выгрузка метаданных; можно портировать.
- Краулеры: `projectdiscovery/katana` (MIT): эвристики (sitemap, robots, JS-ссылки, `known-files`); `hakluke/hakrawler` (GPL-3.0).

## 3. DNS-перебор и пермутации (профиль «Стандартный»)

- Словари: `danielmiessler/SecLists` (MIT) `Discovery/DNS/subdomains-top1million-5000.txt` / `-20000.txt` (для телефона 5000: разумно), `dns-Jhaddix.txt`; FOCA `FOCA/DNSDictionary/hosts.txt` (GPL-3.0, 45 КБ: исторический словарь FOCA).
- Публичные резолверы: `trickest/resolvers` (MIT) `resolvers-trusted.txt`.
- Фильтр wildcard-ответов: `d3mondev/puredns` (GPL-3.0): алгоритм wildcard-детекта.
- Пермутации: `projectdiscovery/alterx` (MIT, DSL-шаблоны `{{word}}-{{sub}}` и т.д., `permutations.yaml`), `AlephNullSK/dnsgen` (MIT), Findomain `src/permutations.rs` (Rust, GPL-3.0: переносимо напрямую). `resyncgg/ripgen`: Rust, но без лицензии, только идеи.
- Предсказание имён FOCA: `FOCA/FormDNSPrediction.cs` (`srv01` → `srv02…`), `DNSEnumeration/DNSUtil.cs`, `PanelTryCommonNames.cs`.

## 4. Захват поддоменов (takeover)

- `EdOverflow/can-i-take-over-xyz` (CC-BY-4.0) `fingerprints.json`: сервис, CNAME, текст-отпечаток, vulnerable. С указанием авторства можно положить в `signatures/`.
- `projectdiscovery/nuclei-templates` (MIT) `http/takeovers/*.yaml`: ~70 шаблонов с точными матчерами.

## 5. Пассивные данные об IP без ключа

- Shodan InternetDB: `https://internetdb.shodan.io/<ip>`, порты, CPE, CVE, hostnames, без ключа, проверено (200). Закрывает F-17 «Shodan» без ключа и даёт сопоставление CVE.

## 6. Метаданные (сверка с нашим foca-meta)

- FOCA `MetadataExtractCore/Metadata/*.cs` (GPL-3.0): `OleDocument.cs` (44 КБ), `Office972003.cs`, `OfficeOpenXML.cs`, `OpenOfficeDocument.cs`, `PDFDocument.cs`, `EXIFDocument.cs`, `XMPExtractor.cs`, `ICADocument.cs` (Citrix .ica), `InDDDocument.cs` (InDesign), `WPDDocument.cs` (WordPerfect), `RDPDocument.cs`, `SVGDocument.cs`. Покрытие поля к полю сверить с foca-meta; ICA/InDD/WPD у нас нет.
- FOCA `FOCA/Analysis/OperatingSystemUtils.cs`: сопоставление строк ПО/путей с ОС; `FormBackupsFuzzer.cs`: список суффиксов бэкапов (`.bak`, `~`, `.old`…).

## Что берём в первую очередь

1. gau + waymore → переписать Wayback (пагинация, ретраи, mimetype-фильтр, архивные копии `id_`) и Common Crawl (несколько индексов).
2. Источники поддоменов без ключа: crt.sh, CertSpotter, Anubis, HackerTarget, RapidDNS, subdomain.center, THC, OTX, urlscan, HudsonRock, Shodan CT.
3. Shodan InternetDB для IP.
4. Дорки: портировать FOCA/pymeta (GPL-3.0) + go-dork (MIT) через DuckDuckGo/Bing/Mojeek HTML, best-effort.
5. Словарь SecLists top-5000 + trickest resolvers + wildcard-фильтр + пермутации (alterx/Findomain).
6. can-i-take-over-xyz + nuclei takeovers → signatures/takeover.
