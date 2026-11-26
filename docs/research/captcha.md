# Капча в дорках без ключей (исследование для 1.1): причины, опенсорс-подходы, измерения, решение

Дата: 2026-11-21. Скрипты и сырые данные стенда: `<исследования>/captcha/` (`bench.mjs`, `phaseB.sh`,
`results.jsonl`, `TABLE.md`, `html/`): вне репозитория. Без автоматического решения капч, без чужих
прокси/резидентных сетей, без подделки чужого отпечатка.

## 0. Главный факт с телефона пользователя
Startpage в обычном Chrome на домашнем Wi‑Fi: «Verifying your request…» → «Something went wrong during
verification». Тот же `site:<публичный сайт> filetype:pdf` через мобильную сеть 4G: сразу результаты.
**Вывод: на Wi‑Fi главная причина, репутация IP провайдера (CGNAT/общий адрес), а не отпечаток WebView.**
Правки отпечатка и темпа: вторичный фактор (нужны, чтобы WebView не выдавал себя сверх того, что даёт
IP); приоритет, чтобы дорки при «плохом» IP не терялись (failover) и ручная проверка была удобной.

## 1. Сигналы антиботов (что применимо честно)
| Сигнал | Где | Что сделали |
|---|---|---|
| `X-Requested-With: <пакет>` на каждом запросе WebView | Android WebView шлёт по умолчанию; Google убирает его через allow-list ([блог Android, 2023](https://android-developers.googleblog.com/2023/02/improving-user-privacy-by-requiring-opt-in-to-send-x-requested-wih-header-from-webview.html), [WebSettingsCompat](https://developer.android.com/reference/androidx/webkit/WebSettingsCompat)) | `setRequestedWithHeaderOriginAllowList(settings, emptySet())` при `REQUESTED_WITH_HEADER_ALLOW_LIST` |
| `document.visibilityState=hidden`, стоящий `requestAnimationFrame` | WebView без окна; stealth-плагины подменяют это у headless ([разбор puppeteer-extra-stealth](https://blog.crawlex.net/blog/puppeteer-stealth-plugin)): мы не подменяем, а делаем страницу честно видимой | WebView прикреплён к окну Activity под основным WebView (visible, rAF идёт); свёрнуто, без окна |
| Несогласованный отпечаток: десктопный UA + сенсор/`Linux armv8l`/мобильные Client Hints/узкий экран | классический признак автоматизации | всегда настоящий мобильный UA этого WebView без `; wv`, размер окна = экран |
| Картинки/CSS не грузятся | SearXNG `botdetection` (link_token: клиент должен загрузить CSS), антиботы смотрят загрузку ресурсов | картинки включены |
| `navigator.webdriver` | у WebView `false` и так | проверяется в диагностике |
| Сразу на выдачу без главной/кук/Referer; серия запросов подряд | Startpage (форма с `sc`), DDG (`vqd` без него → блок), Bing/Yahoo (куки) | главная в начале сессии Brave/Mojeek, Startpage: всегда через форму; темп 6-14 с с джиттером; меньше запросов |
| **IP** (дата-центр, CGNAT провайдера, VPN) | всё перечисленное | кодом не чинится → failover + ручная проверка + (отдельная задача) выбор сети |

## 2. Как это делают метапоисковики (SearXNG, AGPL: код не копировался, только подходы)
- **Startpage** ([engines/startpage.py](https://github.com/searxng/searxng/blob/master/searx/engines/startpage.py)): POST формы `/sp/search` с полем `sc` с главной (кэш 1 ч), `Origin`/`Referer`, cookie `preferences`; с 2026: Anubis PoW (`spchal-auth`), SearXNG решает его в Python. Нам: в браузере PoW выполняет сама страница (разрешено): так и было (главная → форма).
- **DuckDuckGo** ([engines/duckduckgo.py](https://github.com/searxng/searxng/blob/master/searx/engines/duckduckgo.py)): html.duckduckgo.com POST, `Sec-Fetch-*`, `Referer: https://html.duckduckgo.com/`; вторая страница без `vqd` = немедленный блок. Нам: пагинацию DDG не делаем (одна страница), запрос с OR.
- **Bing** ([engines/bing.py](https://github.com/searxng/searxng/blob/master/searx/engines/bing.py)): `setlang`/`cc`/`adlt`, разбор `ck/a?u=a1<base64>`. Из ДЦ выдача мусорная.
- **Mojeek** ([engines/mojeek.py](https://github.com/searxng/searxng/blob/master/searx/engines/mojeek.py), [PR #6696](https://github.com/searxng/searxng/pull/6696)): с 23.06.2026 Mojeek ставит ALTCHA-стену почти всем ([форум Mojeek](https://community.mojeek.com/t/altcha-appears-before-i-can-get-search-results-and-i-cant-pass-it/3036): ~8 млн автоматических запросов в сутки); SearXNG решает ALTCHA программно: это авторешение капчи, нам запрещено. Mojeek у нас: только ручная проверка (кука `chllg` живёт долго), не на `s=0`.
- **Yahoo** ([engines/yahoo.py](https://github.com/searxng/searxng/blob/master/searx/engines/yahoo.py)): кука `YBV` из первого ответа, разбор `/RU=<url>/`. Из ЕС главная → стена согласия на cookies; прямая выдача, без неё.
- **Публичные SearXNG**: JSON почти везде выключен, [0/38 инстансов отдали JSON](https://github.com/ChHsiching/agent-web-search/issues/10); список и здоровье: [searx.space/data/instances.json](https://searx.space/) (`uptime.uptimeMonth`, `timing.search.success_percentage`, `working_engine_names`).

## 3. Измерения (песочница, IP дата-центра Финляндии: худший случай; Playwright Chromium, эмуляция Pixel 7, темп 10-20 с; всего ≈ 100 запросов)
| Поисковик | Итог | site: / filetype: / OR | Заметки |
|---|---|---|---|
| Startpage (браузер) | 3/4 выдача (10 ссылок/запрос) | да / да / да | PoW 34-62 с; со «скрытой» страницей (hidden + rAF стоит): 86 с; разбор мобильной вёрстки работает |
| Brave (браузер) | 4/10 выдача, затем 429 «Verifying you're not a bot» после 4 запросов за ~40 с; дальше капча во всех вариантах | да / да / да | IP-лимит держится >10 мин; мобильная вёрстка разбирается (20 PDF с публичного сайта) |
| **Yahoo** (браузер) | 6/7 выдача (до 10 PDF), 500 при втором запросе за 10 с | да / да / да | главная из ЕС: согласие cookies; прямой URL работает; HTTP из ядра: 500 |
| **Публичные SearXNG** (браузер, 4 инстанса) | 3 из 4 инстансов: выдача (10-28 ссылок) | да / да / да | 1: 403; голый HTTP: 429 (лимитер), JSON: 429 |
| Mojeek | 403 «automated queries» | - | + ALTCHA для всех с 06.2026 |
| DDG html/lite | 403 | - | из ДЦ; DDG JS: пусто |
| Bing | мусорная выдача / «нет результатов» | - | ДЦ |
| Qwant, Marginalia, Swisscows | пусто (нет site:/filetype: или ссылки не в DOM) | - | не годятся |
| Ecosia, Yandex | капча | - | |
| Presearch, 4get.ca | 530 / 503 | - | недоступны |

Сравнение вариантов поведения (Brave/Yahoo/Startpage): у Yahoo без разницы (hidden, X-Requested-With,
desktop UA, без картинок: везде выдача): решает IP и частота; у Brave после первого 429 капча во всех
вариантах: IP-лимит маскирует эффект отпечатка (на ДЦ различий не измерить); у Startpage «скрытая»
страница проходит PoW в 2,5 раза дольше. Главная перед выдачей пользы на ДЦ не показала (Yahoo: даже
вредна: стена согласия), но для Brave/Mojeek оставлена как естественная сессия (1 запрос за скан).

## 4. Что сделано (кратко)
- Kotlin `RenderFetcher`: без `X-Requested-With`; всегда мобильный UA без `; wv`; картинки; WebView в окне
  Activity (visible), свёрнуто, без окна с размером экрана; куки `flush` после каждого запроса.
- Ядро: общая очередь дорков скана (`dorkboard.rs`, драйвер `sources/dorkpool.rs`): группы типов (`pdf`, `doc|docx|odt|rtf`, `xls|xlsx|ods`,
  `ppt|pptx`) одним OR-запросом, одна группа: один движок (пусто: ещё один), **капча → группа другим
  движкам**, бюджет 24 запроса на движок за скан, кэш выдачи 24 ч (`dork-cache.json`), темп 6-14 с,
  пагинация только при полной странице.
- Новые источники: Yahoo (браузер), пул публичных SearXNG (браузер) с health-check по searx.space и
  ротацией инстансов.
- UX: одна кнопка «Пройти проверку» для всех поисковиков в капче по очереди; «Настройки → Сеть →
  Подготовить поисковики»; «Отладка → Поиск»: отпечаток поискового браузера + страница для Chrome +
  журнал по движкам.

## 5. Сеть для поиска (отдельная задача: только ограничения)
- WebView: прокси, только `androidx.webkit.ProxyController.setProxyOverride` (процесс целиком, все WebView,
  включая UI; правила по хостам: `addBypassRule`/`ProxyConfig` с reverse-bypass, своих «маршрутов по
  сети» нет).
- Выбрать мобильную сеть при включённом Wi‑Fi: `ConnectivityManager.requestNetwork(TRANSPORT_CELLULAR)` +
  `bindProcessToNetwork(net)`: действует на весь процесс (и на WebView, и на нативные сокеты reqwest),
  точечно для WebView нельзя. Для reqwest можно точечно: `Network.bindSocket(fd)` / `SocketFactory`: через
  JNI на каждый сокет (в reqwest/hyper это свой коннектор).
- Локальный VPN (AdGuard, v2rayNG) перехватывает всё на уровне системы: `bindProcessToNetwork` на сотовую
  сеть он может обойти только если VPN не «always-on/lockdown»; иначе трафик всё равно идёт через VPN.
- Мобильный трафик: страницы выдачи с картинками ≈ 0,5-1,5 МБ за запрос.

## 6. Что проверить на телефоне
1. «Отладка → Поиск → Проверить отпечаток»: `visibilityState=visible`, rAF ≈ 60, UA без `; wv`, Client Hints
   mobile=true; «Страница для Chrome», то же в Chrome.
2. Wi‑Fi (плохой IP): скан с дорками, Startpage в капче, его группы уходят Brave/Yahoo/SearXNG (журнал в
   «Отладке»: «отдано другим» / «взято у других»), предупреждение только если дорки не сделал никто.
3. Кнопка «Пройти проверку (N)»: по очереди; основной UI и тачи не ломаются, TalkBack не читает скрытый
   WebView (он под основным WebView в decorView).
4. 4G: те же дорки, без капчи; повтор в течение суток: из кэша.
