# ui/: интерфейс FOCA-rs

↑ [Корень](../README.md) · [Документация](../docs/README.md)

Ванильный JS без сборщика ([ADR-0002](../docs/adr/0002-vanilla-js-ui.md)), WebView Tauri на Android; в браузере работает на
демо-бэкенде с теми же командами.

- Правила для авторов экранов, API `window.FOCA`, CSS-классы, проверка: **[README-UI.md](README-UI.md)** (основной документ).
- Устройство, карта всех маршрутов и принципы: [docs/dev/ui.md](../docs/dev/ui.md).
- Контракт с ядром: [docs/API.md](../docs/API.md).

| Путь | Что |
|---|---|
| `index.html` | оболочка, подключение скриптов |
| `js/` | `core.js` (роутер, шторки), `main.js`, `api.js` (доступ к данным), `demo-backend.js`, `sel.js` (селекторы), `icons.js` |
| `screens/` | экраны `*.js` + `*.css` |
| `css/`, `fonts/`, `data/` | базовые стили, шрифт Inter, данные карты (Natural Earth) |
