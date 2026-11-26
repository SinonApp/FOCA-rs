# FOCA-rs UI: правила для авторов экранов

↑ [ui/](README.md) · [docs/dev/ui.md](../docs/dev/ui.md) · [docs/API.md](../docs/API.md)

Интерфейс работает только в Android WebView (Tauri 2), версии для ПК нет. В браузере он открывается на
демо-бэкенде с теми же командами, что и у ядра: `ui/index.html#/маршрут` (например `#/p/findings`).

## Данные

Данные берутся только из единого слоя (см. [docs/API.md](../docs/API.md)): читать `F.db.*` и селекторы
`F.sel.*` (числа, риск, скоуп, связи, поиск, дифф), менять через `F.api.*`, подписка на изменения:
`F.on("db", fn)` / `F.on("scan", fn)`. Не заводите демо-массивы и не зашивайте числа в экран: новые демо-данные
добавляются в `ui/js/demo-backend.js` и проверяются `node qa/data-invariants.mjs`. `window.DEMO`,
`F.demoFindings`, `F.demoProjects`, `F.project` остались как алиасы на `F.db`.

## API ядра (`window.FOCA`, коротко `F`)

- `F.route(pattern, def)` регистрирует экран. `pattern` вида `"/p/finding/:id"`. Поля `def`:
  - `title`, `sub` (строка или `p => строка`; по умолчанию имя проекта), `tab` (id вкладки
    `overview|findings|data|reports` для подсветки нижней навигации);
  - `render(params) → html`, `mount(pageEl, params)` навешивает обработчики после вставки;
  - `fab: {icon, label, act}` или функция, `actions: [{icon, act, label, badge}]`: кнопки в шапке справа
    (по умолчанию «⋮ меню»);
  - `search: "Поиск по находкам"` показывает строку поиска у нижнего края, `nav: false` скрывает нижнюю
    навигацию, `back: true` добавляет стрелку назад, `hideMini: true` скрывает мини-панель скана.
- Навигация: `F.go(path)`, `F.back()`, `F.tab(path)`, `F.reset([paths])`; в разметке `data-act="go:/p/doc/12"`,
  `data-act="back"`.
- Действия: `F.actions["имя"] = (arg, el, event) => {}`; в разметке `data-act="имя:аргумент"`.
- Долгое нажатие (1,2 с) только для разрушительных действий (удаление, затирание); скан запускается обычным
  нажатием: `<button class="btn danger hold" data-hold="имя:арг"><span class="hold-fill"></span>Текст</button>`.
- Шторка снизу: `F.sheet({title, html, footer, full, onMount(sheetEl), onClose})`, закрыть: `F.closeSheet()`.
  Системная кнопка «Назад» закрывает шторку сама.
- Snackbar с отменой: `F.snack("Перемещено в «Ложные»", {action: () => undo()})`.
- Перерисовать текущий экран: `F.render(true)` (прокрутка сохраняется). Текущая страница: `F.page()`.
- Состояния: оборачивайте рендер в `F.withStates(() => html, {empty:{icon,title,text,action},
  loading:"list"|"cards", error:{}})`, тогда демо-режим (меню ⋮ → «Демо-состояния») подставит
  пусто/загрузку/ошибку. Плашку «нет сети» показывает ядро.
- Готовые блоки `F.ui`: `row({lead,title,sub,tail,act,chev,cls,attrs})`, `leadIcon(name,color)`,
  `secH(title, extra, actionHtml)`, `toggle(on, act)`, `sev("crit|high|warn|low|info|ok")`, `secret(value)`
  (размыто, раскрывается через `data-act="reveal"`), `check(on, labelHtml, act = "toggle-check", sub)`,
  `empty/error/skeletonList/skeletonCards`.
- Иконки: `F.ic("name")`, список в `ui/js/icons.js`. Свои иконки:
  `F.addIcons('<symbol id="i-xxx" viewBox="0 0 16 16">…</symbol>')` (stroke-иконки 16×16, без emoji).
- Меню ⋮: массив `F.menuItems` из `{ id, icon, label, sub, act, order, chev, show() }` (icon/label/sub могут
  быть функциями). Экран добавляет пункт через `F.menuItems.push({...})`; порядок: проекты 10, скоуп 20,
  инструменты 40, настройки 50, тема 60, демо 90. `F.actions.menu` не оборачивайте.
- Слот над страницей для превью и плашек: `F.overlaySlot()` (элемент `#overlay-slot` внутри `#viewport`, выше
  страницы, ниже FAB). Ядро очищает его при уходе с экрана, вручную: `F.clearOverlay()`.
- Перехват системной «Назад» на экране (режим выбора и т. п.): `F.onBack(() => { выйти из режима; return true; })`,
  снять: `F.onBack(null)`. Хук сбрасывается при уходе с экрана; `def.unmount(page, params)` вызывается там же.
- Живые экраны (данные меняются без действий пользователя: скан, смена проекта, ключи), в `def` маршрута:
  - `live: true` или `live: (kind, ev) => bool`: ядро само вызывает `F.render(true)` (прокрутка сохраняется,
    не чаще 2-3 раз в секунду);
  - `onData(kind, ev)`: экран обновляется сам, точечно (так сделан `/p/scan`).

  `kind`: `"scan"` (события скана, `ev.type`), `"db"` (`ev.kind`: project/scan/scope/settings/oos…), `"net"`
  (`ev.online`). Обновить только шапку: `F.refreshBar()`.
- «Назад» при стеке из одного экрана (глубокая ссылка, уведомление Android) ведёт на родителя `F.parentOf(path)`:
  `/p/*` → Обзор, `/p/overview` → Проекты, `/settings/*` → Настройки.
- Сеть: `F.setOffline(on)` показывает плашку и отправляет в шину `F.emit("net", { online })`.
- Скоуп и запуск: `F.moduleBadge(kind)` (метка «обращается к цели» / «только внешние источники»),
  `F.parseTarget(str)`, `F.scopeInfo()`, `F.state.scope`; новый проект: `F.state.newTarget = "…"` перед
  `F.go("/new")`; правки скоупа через `F.api.scope_set`.
- Скан: `F.scan = {running, paused, pauseReason, pauseLabel, active, progress, stageLabel, summary, egress,
  project, profile}` заполняется только событиями `F.on("scan")` (владелец `scan.js`), мини-панель
  перерисовывает `F.updateChrome()`. Запуск: `F.actions["scan-start"]({ profile, active, modules, sources,
  targets, resume_from, open })` → `F.api.scan_start` (Promise). Кандидаты вне скоупа: `F.db.oos`, решения:
  `F.api.oos_decide`.
- Ключи API: `F.openKeySheet(service)` открывает шторку ввода и проверки ключа поверх текущего экрана;
  сохранение через `F.api.key_set`, после него приходит `F.on("db", {kind:"settings"})`.
- Данные: `F.db = {project, scope, docs, people, emails, hosts, pcs, software, paths, printers, secrets, findings,
  gps, events, scans, reports, settings}`; селекторы `F.sel.counts()/risk()/scope.*/entity/related/search/
  timeline/diff/graph`; команды `F.api.*`.

## CSS-классы ядра

Используйте их; свои стили кладите в `.css` экрана с префиксом экрана.

`.card .card.pad .card.tap .list .row .row.tap .row.sel .lead-ic .body .t .s .tail .chev .grid.g2/.g3 .stat
.sec-h .lead .chips .chip(.on) .seg>button(.on) .btn(.primary/.tonal/.danger/.text/.sm/.block) .btnrow .field
.flabel .fhint(.err) select.sel .toggle(.on) .kv>.kvr>.k/.v .pill(.ok/.warn/.bad/.crit/.info/.mute/.vio)
.banner(.warn/.crit/.info) .ext.pdf/.docx… .avatar .pbar>i .skel .empty .srow .mono .muted .secret`.

Общие блоки (вместо своих копий): `.sub-h` (подзаголовок в форме или секции), `.foot` + `.foot-s` (липкий низ с
главной кнопкой; странице нужен класс `no-pb`), `.factive` + `.fchip` (активные фильтры), `.ctxbar` + `.ctxbar-n`
и `.selbar` (режим выбора), `.cbx` (чекбокс в карточке), `.radio` (радио в карточке выбора, внутри `.on`), `.pn`
(пред./след. внизу карточки), `.steps/.steprow/.step-l/.step` (степпер), `.qlink` + `.qlink-in` (плитка быстрого
перехода), `.lead-ic.lg` / `.lead-ic.accent`, `.btn.danger-o` (опасное действие без удержания), плотность
`html.st-dense/.st-airy`, планшетная раскладка (от 720px) в base.css.

Единые правила: кнопки `.btn` высотой 48px (`.sm` 40px); `.pill` и `.seg` переносятся сами (не задавайте им
nowrap или прокрутку); в футере шторки «Отмена» слева, главное действие справа, при переносе главное сверху
(wrap-reverse). Важность везде через `F.ui.sev()`: Критический / Высокий / Средний / Низкий / Инфо. Числа с
единицами пишутся через неразрывный пробел (`5 мин`, `1,5 МБ`).

Цвета только через переменные: `--bg --bar --layer --layer-2 --layer-3 --hover --stroke --stroke-2 --text
--text-2 --text-3 --accent --accent-strong --accent-soft --ok --warn --bad --crit --info (+ -soft) --active`.

## Требования к качеству

- Для шрифтов только `rem` (1rem = 14px × масштаб). Цели нажатия от 48px. У текстовых блоков нет фиксированной
  высоты; длинный текст переносится или режется через `-webkit-line-clamp`.
- Экран ровно выглядит в тёмной и светлой теме, при ширине 360/393/412 и масштабе шрифта `--fs` 1, 1.3 и 2 (при
  2 допустим перенос, но не обрезка и не горизонтальная прокрутка).
- Критичность показывается иконкой и текстом, а не только цветом. У кнопок-иконок есть `aria-label`.
- Без emoji и без внешних ресурсов: всё работает офлайн.
- У каждого экрана есть состояния «пусто», «загрузка» и «ошибка» через `F.withStates`.

## Проверка

```
qa/shoot.sh --routes "/p/x,/p/y" --out qa/out/<имя> [--w 360] [--fs 1.3] [--theme light] \
  [--demo empty|loading|error] [--tall] [--steps /абсолютный/путь/steps.mjs]
```

- Скрипт ставит запуски в очередь (flock), поэтому одновременно работает один браузер.
- В JSON-отчёте `errors` должен быть пустым, а `overflow.sw/docw` равен 0.
- `--steps` принимает ES-модуль `export default async (page, {out, W, prep}) => {...}` для кликов, открытия шторок
  и т. п. (`page` это Playwright Page).
- Синтаксис: `node --check файл.js`. Полный прогон: `bash qa/run-all.sh` (см. [qa/README.md](../qa/README.md)).
