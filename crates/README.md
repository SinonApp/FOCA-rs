# crates/: Rust-ядро FOCA-rs

↑ [Корень](../README.md) · [Документация](../docs/README.md)

Ядро без Android и UI: собирается и тестируется на ПК. Описание каждого крейта: [docs/dev/crates/](../docs/dev/crates/README.md),
архитектура и граф зависимостей: [docs/dev/architecture.md](../docs/dev/architecture.md).

| Папка | Кратко |
|---|---|
| [`foca-core/`](foca-core/) | модель данных, цели, скоуп, DTO контракта: [страница](../docs/dev/crates/foca-core.md) |
| [`foca-meta/`](foca-meta/) | метаданные документов и очистка: [страница](../docs/dev/crates/foca-meta.md) |
| [`foca-net/`](foca-net/) | сетевой слой: NetClient, DNS, CT, RDAP, порты, UA, [страница](../docs/dev/crates/foca-net.md) |
| [`foca-search/`](foca-search/) | источники, дорки, краулер, загрузчик: [страница](../docs/dev/crates/foca-search.md) |
| [`foca-store/`](foca-store/) | SQLite на проект, миграции, снапшот: [страница](../docs/dev/crates/foca-store.md) |
| [`foca-analysis/`](foca-analysis/) | люди, ПО, секреты, находки, риск: [страница](../docs/dev/crates/foca-analysis.md) |
| [`foca-recon/`](foca-recon/) | разведка сайта: [страница](../docs/dev/crates/foca-recon.md) |
| [`foca-fuzz/`](foca-fuzz/) | поиск забытых файлов на сайте: [страница](../docs/dev/crates/foca-fuzz.md) |
| [`foca-report/`](foca-report/) | отчёты и экспорт RU/UK/EN: [страница](../docs/dev/crates/foca-report.md) |
| [`foca-engine/`](foca-engine/) | движок скана и фасад команд: [страница](../docs/dev/crates/foca-engine.md) |
| [`foca-cli/`](foca-cli/) | CLI `foca`, стенды `serve`/`testnet`: [страница](../docs/dev/crates/foca-cli.md) |

```sh
cargo test                       # все крейты ядра (default-members)
cargo test -p foca-meta          # один крейт
cargo clippy --workspace --all-targets -- -D warnings
cargo run -p foca-cli -- --help  # CLI для ручной проверки
```

Правила: библиотеки, `thiserror`, бинарники, `anyhow`; никаких `panic!`/`unwrap()` на входных данных; сеть: только через
`foca_net::NetClient`. Подробно: [CONTRIBUTING](../docs/dev/contributing.md).
