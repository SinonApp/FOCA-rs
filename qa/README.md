# qa/: проверка интерфейса и сквозные тесты

↑ [Корень](../README.md) · [Тестирование](../docs/testing/README.md)

Подробно: [docs/testing/README.md](../docs/testing/README.md), сценарии: [docs/testing/scenarios.md](../docs/testing/scenarios.md).

| Файл | Что делает |
|---|---|
| `run-all.sh` | Полный прогон: `static` (node --check, инварианты, ссылки документации), `routes`, `steps`; `--real`: плюс `real-e2e.sh` |
| `real-e2e.sh` | Сценарии `scenarios/real-core/NN-*.mjs` и маршруты на настоящем ядре (`foca testnet` + `foca serve` + `tauri-shim.js`) |
| `e2e-serve.sh` | Управление стендом: `start/stop/kill/restart/delay` |
| `shoot.sh`, `shoot.mjs` | Скриншоты маршрутов и сценарии `--steps` (Playwright): ошибки консоли, переполнение, «undefined» в тексте |
| `tauri-shim.js` | `window.__TAURI__` поверх `foca serve` |
| `data-invariants.mjs` | Инварианты демо-данных без браузера |
| `check-docs-links.py` | Относительные ссылки и якоря во всех `.md` |
| `search-fixtures.mjs` | Захват HTML-фикстур поисковиков (только под `flock /tmp/foca-pw.lock`) |
| `routes.txt` | Маршруты для скриншот-тестов |
| `scenarios/<имя>/` | Сценарии Playwright (`steps.mjs`, `fix.mjs`), E2E `real-core/`, скрипты ревью и PoC |
| `out/` | Вывод прогонов: снимки, логи, JSON-отчёты (целиком в `.gitignore`) |

```sh
qa/run-all.sh static        # секунды
qa/run-all.sh > /tmp/qa.out 2>&1 &   # всё на демо (≈15 мин)
```
