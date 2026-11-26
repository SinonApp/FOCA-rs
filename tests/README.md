# tests/: корпус документов и фикстуры

↑ [Корень](../README.md) · [Тестирование](../docs/testing/README.md)

| Путь | Что |
|---|---|
| [`corpus/`](corpus/SOURCES.md) | Эталонные документы (OOXML, ODF, PDF, OLE, изображения, SVG, remote) и `*.expected.json` для golden-тестов `foca-meta`; генератор `make_corpus.py`; `analysis.expected.json`: эталон анализа |
| [`fixtures/fuzz-site/`](fixtures/fuzz-site/README.md) | Офлайн-сайт для `foca-fuzz` и E2E-08 (`foca testnet` отдаёт его как `www.<домен>`) |

```sh
cargo test -p foca-meta --test golden                  # сверка с эталонами
UPDATE_GOLDEN=1 cargo test -p foca-meta --test golden  # обновить после осознанного изменения парсера (смотреть diff)
```

Корпус: синтетические файлы и публичные образцы с указанием источника и лицензии (`corpus/real/`, см. SOURCES.md);
документы реальных целей аудита в репозиторий не добавляются.
