# Офлайн-стенд foca-fuzz («сайт заказчика»)

Обслуживается тестовым сервером из `crates/foca-fuzz/tests/common/mod.rs` на 127.0.0.1.

- `www/`, основной сайт: `index.html` (ссылка на `files/report_2023.pdf`), `index.php` и забытый
  `index.php.bak` (пароль в исходнике), `files/report_2024.pdf` (нигде не связан: ищется мутацией
  года), `docs/` (открытый листинг, вложенный `docs/sub/`), `.DS_Store` (перечисляет скрытый
  `secret-plan_2024.pdf`), `.env`, `.git/HEAD` (хранится как `dot-git/HEAD`: git не хранит каталоги
  `.git`), `private/`: путь исключён из скоупа и не должен запрашиваться.
- `intranet/`: скрытый vhost `intranet.contoso.test` на том же адресе.
- `dev/`: vhost `dev.contoso.test`, исключён из скоупа и не должен запрашиваться.
- `dsstore/big.DS_Store`: 600 имён в Unicode, двухуровневое B-дерево (для парсера).

`.DS_Store` созданы модулем `ds_store` (MIT) как независимый эталон формата.
