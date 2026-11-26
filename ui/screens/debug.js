// Settings → Debug: #/settings/debug[/log|req|crash|dev|search] (search shows the search browser
// fingerprint and the per-engine journal). Core and Android log (logs_get), project network request log
// (request_log_get), crashes (crash_list / crash_get), device info (app_info + platform_device_info).
// Actions: Copy, Share logs (logs_export → secret-free ZIP → platform_share), Clear logs, and the log level
// (settings.debug.level: info | debug: applied by the core at runtime).
(function () {
  const F = window.FOCA,
    ui = F.ui,
    ic = F.ic,
    esc = F.esc;
  const NB = "\u00a0";
  // Decimal separator follows the UI language.
  const dec = s => (F.i18n && F.i18n.lang() === "en" ? String(s) : String(s).replace(".", ","));
  // Labels for fuzzer responses in the request log (request_log.note).
  const NOTE = () => ({
    soft404: F.t("debug.note_soft404", "soft-404, отброшен"),
    calibration: F.t("debug.note_calibration", "калибровка (случайный путь)"),
    filtered: F.t("debug.note_filtered", "отсеян фильтром"),
    rate_limited: F.t("debug.note_rate_limited", "429: лимит частоты"),
  });
  const dbg = (F.state.dbg = F.state.dbg || {
    seg: "log",
    lv: { error: true, warn: true, info: true, debug: false },
    src: "all",
    q: "",
    auto: false,
    logs: null,
    shown: 200,
    open: {},
    req: null,
    onlyTarget: false,
    crashes: null,
    dev: null,
    app: null,
  });
  const SEGS = () => [
    ["log", F.t("debug.seg_log", "Журнал")],
    ["req", F.t("debug.seg_req", "Запросы")],
    ["crash", F.t("debug.seg_crash", "Сбои")],
    ["dev", F.t("debug.seg_dev", "Устройство")],
    ["search", F.t("debug.seg_search", "Поиск")],
  ];
  const LV = () => [
    ["error", F.t("debug.lv_error", "Ошибки")],
    ["warn", F.t("debug.lv_warn", "Предупр.")],
    ["info", F.t("debug.lv_info", "Инфо")],
    ["debug", F.t("debug.lv_debug", "Отладка")],
  ];
  const LV_CLS = { error: "bad", warn: "warn", info: "info", debug: "mute" };
  const ACC = () => ({
    passive: [F.t("debug.acc_passive", "Пассивный"), "mute"],
    target: [F.t("debug.acc_target", "Касание цели"), "warn"],
    active: [F.t("debug.acc_active", "Активный"), "bad"],
  });
  const time = t => String(t || "").slice(11, 19) || "-";
  const kb = n =>
    n >= 1048576
      ? dec((n / 1048576).toFixed(1)) + NB + F.t("debug.unit_mb", "МБ")
      : Math.max(0, Math.round((n || 0) / 1024)) + NB + F.t("debug.unit_kb", "КБ");
  const settings = () => (F.db && F.db.settings) || {};
  const level = () => (settings().debug || {}).level || (dbg.app && dbg.app.log_level) || "info";

  // ---------- loading ----------
  const loadLogs = () =>
    F.api.logs_get({ source: "all", limit: 2000 }).then(
      v => {
        dbg.logs = v || [];
        rr();
      },
      e => {
        dbg.logs = [];
        dbg.err = e.message;
        rr();
      },
    );
  const loadReq = () =>
    F.api.request_log_get({ limit: 500, only_active: dbg.onlyTarget }).then(
      v => {
        dbg.req = v || [];
        rr();
      },
      () => {
        dbg.req = [];
        rr();
      },
    );
  const loadCrash = () =>
    F.api.crash_list().then(
      v => {
        dbg.crashes = v || [];
        rr();
      },
      () => {
        dbg.crashes = [];
        rr();
      },
    );
  const loadDev = () =>
    Promise.all([
      F.api.app_info().catch(() => ({})),
      F.api.platform_device_info().catch(e => ({ error: e.message })),
      F.api.platform_permissions_status().catch(() => ({})),
      F.api.platform_bg_status ? F.api.platform_bg_status().catch(() => ({})) : {},
    ]).then(([a, d, p, b]) => {
      dbg.app = a;
      dbg.dev = d;
      dbg.perm = p;
      dbg.bg = b || {};
      rr();
    });
  // Dork search engines: per-engine journal (search_journal) and the embedded browser fingerprint.
  const loadSearch = () =>
    F.api.search_journal().then(
      v => {
        dbg.sj = (v && v.engines) || {};
        rr();
      },
      () => {
        dbg.sj = {};
        rr();
      },
    );
  const reload = () =>
    (
      ({ log: loadLogs, req: loadReq, crash: loadCrash, dev: loadDev, search: loadSearch })[dbg.seg] ||
      loadLogs
    )();
  const rr = () => {
    if (/^\/settings\/debug/.test(F.current())) F.render(true);
  };

  // ---------- log ----------
  function logRows() {
    const q = dbg.q.trim().toLowerCase();
    return (dbg.logs || []).filter(
      e =>
        (dbg.lv[e.level] || (e.level === "trace" && dbg.lv.debug)) &&
        (dbg.src === "all" || e.source === dbg.src) &&
        (!q || (e.msg + " " + e.target).toLowerCase().includes(q)),
    );
  }
  function renderLog() {
    if (!dbg.logs) return ui.skeletonList();
    const all = logRows(),
      rows = all.slice(-dbg.shown).reverse();
    return `
      <div class="chips wrap dbg-chips" role="group"
        aria-label="${esc(F.t("debug.levels_aria", "Уровни"))}">${LV()
          .map(
            ([k, l]) => `<button class="chip ${dbg.lv[k] ? "on" : ""}"
        aria-pressed="${!!dbg.lv[k]}" data-act="dbg-lv:${k}">${esc(l)}</button>`,
          )
          .join("")}</div>
      <div class="dbg-bar">
        <div class="seg dbg-src" role="tablist">${[
          ["all", F.t("common.all", "Все")],
          ["core", F.t("debug.src_core", "Ядро")],
          ["android", "Android"],
        ]
          .map(
            ([k, l]) =>
              `<button class="${dbg.src === k ? "on" : ""}" role="tab"
                aria-selected="${dbg.src === k}" data-act="dbg-src:${k}">${esc(l)}</button>`,
          )
          .join("")}</div>
        <div class="field dbg-q">${ic("search")}<input id="dbg-q" value="${esc(dbg.q)}"
          placeholder="${esc(F.t("debug.log_search", "Поиск по журналу"))}" aria-label="${esc(F.t("debug.log_search", "Поиск по журналу"))}" autocapitalize="off"
          spellcheck="false"></div>
      </div>
      <div class="checkrow dbg-auto"><span class="lbl"
        id="dbg-auto-l">${esc(F.t("debug.auto", "Автообновление"))}<small>${esc(F.t("debug.auto_sub", "Каждые 3\u00a0с, пока открыт журнал"))}</small></span>${ui.toggle(dbg.auto, "dbg-auto", `aria-labelledby="dbg-auto-l" aria-label="${esc(F.t("debug.auto_aria", "Автообновление журнала"))}"`)}</div>
      <p class="fhint dbg-n">${all.length ? esc(F.t("debug.shown", { n: Math.min(dbg.shown, all.length), total: all.length }, "Показано {n} из {total}, новые сверху")) : ""}</p>
      ${
        rows.length
          ? `<div class="card dbg-log" role="list">${rows
              .map(e => {
                const k = e.source + e.id + e.t;
                const o = dbg.open[k];
                return `<div class="dbg-l ${o ? "open" : ""}" role="listitem"
                  data-act="dbg-open:${esc(k)}"><span class="dbg-t">${time(e.t)}</span><span class="dbg-lv ${LV_CLS[e.level] || "mute"}">${(e.level || "").slice(0, 4).toUpperCase()}</span><span class="dbg-tg" title="${esc(e.target)}">${esc(e.target)}</span><span class="dbg-m" title="${esc(e.msg)}">${esc(e.msg)}</span></div>`;
              })
              .join("")}</div>`
          : ui.empty({
              icon: "log",
              title: dbg.logs.length
                ? F.t("debug.log_none", "Ничего не найдено")
                : F.t("debug.log_empty", "Журнал пуст"),
              text: dbg.logs.length
                ? F.t("debug.log_none_text", "Измените фильтры уровней, источника или поиск.")
                : F.t("debug.log_empty_text", "Записи появятся после запуска скана."),
            })
      }
      ${
        all.length > dbg.shown
          ? `<button class="btn block dbg-more"
        data-act="dbg-more">${esc(F.t("debug.more", { n: Math.min(500, all.length - dbg.shown) }, "Показать ещё {n}"))}</button>`
          : ""
      }`;
  }
  // ---------- requests ----------
  function renderReq() {
    if (!F.db || !F.db.project)
      return ui.empty({
        icon: "folder",
        title: F.t("debug.no_project", "Проект не открыт"),
        text: F.t("debug.no_project_text", "Журнал запросов ведётся по проекту, откройте проект."),
      });
    if (!dbg.req) return ui.skeletonList();
    return `
      <p class="fhint">${esc(F.tp("debug.req_head", dbg.req.length, { name: F.db.project.name, n: dbg.req.length }, "Проект «{name}» · {n} последний запрос|Проект «{name}» · {n} последних запроса|Проект «{name}» · {n} последних запросов"))}</p>
      ${ui.check(dbg.onlyTarget, F.t("debug.only_target", "Только к цели"), "dbg-only", F.t("debug.only_target_sub", "Касание цели и активная фаза, без внешних сервисов"))}
      ${
        dbg.req.length
          ? `<div class="list dbg-req">${dbg.req
              .map(r => {
                const acc = ACC(),
                  a = acc[r.access] || acc.passive;
                return `<div class="row dbg-r"><div class="body"><div class="t dbg-rt"><span class="mono dbg-meth">${esc(r.method)}</span> <span class="dbg-host">${esc(r.host)}</span>${r.blocked ? `<span class="pill crit">${ic("lock")}${esc(F.t("debug.blocked", "Заблокирован"))}</span>` : `<span class="pill ${r.status >= 400 || !r.status ? "bad" : "ok"}">${r.status || "-"}</span>`}</div>
          <div class="s mono dbg-url">${esc(r.url)}</div>
          <div class="s dbg-meta"${r.error ? ` title="${esc(r.error)}"` : ""}><span class="pill ${a[1]}">${esc(a[0])}</span><span>${time(r.time)} · ${esc(r.module)}${r.bytes ? " · " + kb(r.bytes) : ""}${r.note ? " · " + esc(NOTE()[r.note] || r.note) : ""}${r.error ? " · " + esc(errText(r)) : ""}</span></div></div></div>`;
              })
              .join("")}</div>`
          : ui.empty({
              icon: "net",
              title: F.t("debug.req_none", "Запросов нет"),
              text: dbg.onlyTarget
                ? F.t("debug.req_none_target", "К целям проекта ещё не обращались.")
                : F.t("debug.req_none_text", "Журнал заполняется во время скана."),
            })
      }`;
  }
  // ---------- crashes ----------
  function renderCrash() {
    if (!dbg.crashes) return ui.skeletonList();
    return dbg.crashes.length
      ? `<div class="list">${dbg.crashes.map(c => ui.row({ lead: ui.leadIcon("alert", "var(--bad)"), title: `<span class="mono">${esc(c.name)}</span>`, sub: `${c.kind === "android" ? "Android (Kotlin)" : esc(F.t("debug.crash_core", "Ядро (Rust)"))} · ${kb(c.size)}<div class="dbg-ct">${esc(c.title || "")}</div>`, act: `dbg-crash:${c.name}`, chev: true })).join("")}</div>`
      : ui.empty({
          icon: "check",
          title: F.t("debug.crash_none", "Сбоев нет"),
          text: F.t("debug.crash_none_text", "Если приложение упадёт, отчёт о сбое появится здесь."),
        });
  }
  // ---------- device ----------
  function devText() {
    const app = dbg.app || {},
      dev = dbg.dev || {},
      perm = dbg.perm || {},
      net = settings().net || {};
    const yes = v => (v === true ? F.t("debug.yes", "да") : v === false ? F.t("debug.no", "нет") : "-");
    const mb = F.t("debug.unit_mb", "МБ"),
      dataMb = v => F.t("debug.app_data", { v: dec(v) + NB + mb }, "данные приложения {v}");
    return [
      [F.t("debug.dev_version", "Версия"), `${app.version || "-"}${app.commit ? ` (${app.commit})` : ""}`],
      ["Android", dev.release ? `${dev.release} (API ${dev.sdk})${dev.rom ? " · " + dev.rom : ""}` : "-"],
      [F.t("debug.seg_dev", "Устройство"), [dev.manufacturer, dev.model].filter(Boolean).join(" ") || "-"],
      ["ABI", dev.abi || "-"],
      [
        F.t("debug.dev_mem", "Память"),
        dev.mem_total_mb > 0
          ? F.t(
              "debug.mem_free",
              { free: dev.mem_avail_mb + NB + mb, total: dev.mem_total_mb + NB + mb },
              "свободно {free} из {total}",
            )
          : "-",
      ],
      [
        F.t("debug.dev_disk", "Место"),
        dev.disk_free_mb > 0
          ? F.t(
              "debug.disk_free",
              { free: dec((dev.disk_free_mb / 1024).toFixed(1)) + NB + F.t("debug.unit_gb", "ГБ") },
              "свободно {free}",
            ) +
            " · " +
            dataMb(app.data_mb ?? "-")
          : app.data_mb != null
            ? dataMb(app.data_mb)
            : "-",
      ],
      [
        F.t("debug.dev_service", "Сервис скана"),
        dev.service_running ? F.t("debug.service_on", "работает") : F.t("debug.service_off", "не запущен"),
      ],
      [
        F.t("debug.dev_battery", "Батарея"),
        dev.battery_ignoring === true
          ? F.t("debug.battery_free", "без оптимизации")
          : dev.battery_ignoring === false
            ? F.t("debug.battery_opt", "оптимизация включена")
            : "-",
      ],
      [
        F.t("debug.dev_net", "Сеть"),
        `${dev.net === false ? F.t("debug.net_off", "нет сети") : F.t("debug.net_on", "есть")}${dev.vpn ? " · VPN" : ""} · ${net.proxy_on ? F.t("debug.proxy", { type: net.type || "" }, "прокси {type}") : F.t("debug.no_proxy", "без прокси")}`,
      ],
      [F.t("debug.dev_notif", "Уведомления"), yes(perm.notifications ?? dev.notifications)],
      [F.t("debug.dev_bg", "Работа в фоне"), yes(perm.battery ?? dev.battery_ignoring)],
      // Raw on/off/unknown token: the line is read in exported diagnostics.
      ["autostart", (dbg.bg || {}).autostart || "unknown"],
      [
        F.t("debug.log_level", "Уровень журнала"),
        level() === "debug" ? F.t("debug.lv_debug", "Отладка") : F.t("debug.lv_info", "Инфо"),
      ],
    ];
  }
  function renderDev() {
    if (!dbg.dev && !dbg.app) return ui.skeletonCards(2);
    return `<div class="kv dbg-kv">${devText()
      .map(([k, v]) => `<div class="kvr"><div class="k">${esc(k)}</div><div class="v">${esc(v)}</div></div>`)
      .join("")}</div>
      ${dbg.dev && dbg.dev.error ? `<p class="fhint">${ic("info")}${esc(F.t("debug.android_na", { err: dbg.dev.error }, "Данные Android недоступны: {err}"))}</p>` : ""}`;
  }

  // ---------- search engines ----------
  const ENG = {
    startpage: "Startpage",
    brave_web: "Brave",
    mojeek: "Mojeek",
    yahoo: "Yahoo",
    searx_pool: "SearXNG",
    ddg: "DuckDuckGo",
    bing: "Bing",
  };
  const FP_ROWS = () => [
    ["userAgent", "User-Agent"],
    ["uaBrands", F.t("debug.fp_brands", "Client Hints: бренды")],
    ["uaMobile", "Client Hints: mobile"],
    ["uaPlatform", F.t("debug.fp_platform", "Client Hints: платформа")],
    ["uaModel", F.t("debug.fp_model", "Client Hints: модель")],
    ["visibilityState", "visibilityState"],
    ["rafPerSecond", F.t("debug.fp_raf", "requestAnimationFrame, кадр/с")],
    ["webdriver", "navigator.webdriver"],
    ["innerWidth", F.t("debug.fp_width", "Ширина окна")],
    ["innerHeight", F.t("debug.fp_height", "Высота окна")],
    ["screen", F.t("debug.fp_screen", "Экран")],
    ["devicePixelRatio", "devicePixelRatio"],
    ["maxTouchPoints", F.t("debug.fp_touch", "Точек касания")],
    ["languages", F.t("debug.fp_langs", "Языки")],
    ["platform", "navigator.platform"],
    ["timezone", F.t("debug.fp_tz", "Часовой пояс")],
  ];
  const fpText = () =>
    dbg.fp
      ? FP_ROWS()
          .map(([k, l]) => `${l}: ${dbg.fp.fp[k] ?? "-"}`)
          .concat([
            F.t(
              "debug.fp_signs",
              { v: (dbg.fp.issues || []).join("; ") || F.t("debug.no", "нет") },
              "Признаки: {v}",
            ),
          ])
          .join("\n")
      : "";
  function renderSearch() {
    const sj = dbg.sj,
      ids = sj ? Object.keys(sj) : [];
    const fp = dbg.fp;
    return `
      ${ui.secH(F.t("debug.fp_title", "Отпечаток поискового браузера"))}
      <p class="fhint">${esc(F.t("debug.fp_hint", "Что видят Startpage, Brave и другие о встроенном браузере: должен выглядеть как обычный мобильный Chrome этого телефона, видимая страница, без «; wv» и webdriver. Сравните с той же страницей в Chrome."))}</p>
      ${
        fp
          ? `${(fp.issues || []).length ? `<div class="banner warn">${ic("alert")}<div><b>${esc(F.t("debug.fp_issues", "Заметные признаки"))}</b><ul>${fp.issues.map(x => `<li>${esc(x)}</li>`).join("")}</ul></div></div>` : `<div class="banner info">${ic("check")}<div>${esc(F.t("debug.fp_clean", "Признаков «сломанного» браузера нет"))}</div></div>`}
        <div class="kv dbg-kv">${FP_ROWS()
          .map(
            ([k, l]) =>
              `<div class="kvr"><div class="k">${esc(l)}</div><div class="v mono">${esc(String(fp.fp[k] ?? "-"))}</div></div>`,
          )
          .join("")}</div>`
          : dbg.fpErr
            ? `<p class="fhint">${ic("info")}${esc(dbg.fpErr)}</p>`
            : ""
      }
      <div class="btnrow"><button class="btn tonal"
        data-act="dbg-fp">${ic("search")}${esc(fp ? F.t("debug.fp_again", "Проверить ещё раз") : F.t("debug.fp_check", "Проверить отпечаток"))}</button><button class="btn text"
        data-act="dbg-fp-page">${ic("share")}${esc(F.t("debug.fp_page", "Страница для Chrome"))}</button></div>
      ${ui.secH(F.t("debug.engines", "Поисковики дорков"))}
      ${
        !sj
          ? ui.skeletonList()
          : ids.length
            ? `<div class="list dbg-eng">${ids
                .map(id => {
                  const e = sj[id];
                  return `<div class="row"><div class="body"><div class="t">${esc(id === "searx_pool" ? F.t("debug.searx_pool", "SearXNG (пул)") : ENG[id] || id)}${e.blocked ? ` <span class="pill warn">${ic("alert")}${esc(F.t("debug.captcha", "капча"))}</span>` : ""}</div>
          <div class="s">${esc(F.t("debug.eng_stats", { req: e.requests, ans: e.answered, links: e.links, cap: e.captchas }, "запросов {req} · выдач {ans} · ссылок {links} · капч {cap}"))}${e.cached ? " · " + esc(F.t("debug.eng_cached", { n: e.cached }, "из кэша {n}")) : ""}${e.moved ? " · " + esc(F.t("debug.eng_moved", { n: e.moved }, "отдано другим {n}")) : ""}${e.taken_over ? " · " + esc(F.t("debug.eng_taken", { n: e.taken_over }, "взято у других {n}")) : ""}</div></div></div>`;
                })
                .join("")}</div>`
            : ui.empty({
                icon: "search",
                title: F.t("debug.eng_none", "Дорков ещё не было"),
                text: F.t(
                  "debug.eng_none_text",
                  "Счётчики по поисковикам появятся после скана (с момента запуска приложения).",
                ),
              })
      }`;
  }

  function render() {
    const body =
      { log: renderLog, req: renderReq, crash: renderCrash, dev: renderDev, search: renderSearch }[dbg.seg] ||
      renderLog;
    return `
      <div class="seg dbg-seg"
        role="tablist">${SEGS()
          .map(
            ([k, l]) => `<button class="${dbg.seg === k ? "on" : ""}" role="tab"
        aria-selected="${dbg.seg === k}" data-act="dbg-seg:${k}">${esc(l)}</button>`,
          )
          .join("")}</div>
      <div class="dbg-body">${body()}</div>
      ${ui.secH(F.t("debug.actions", "Действия"))}
      <div class="list">
        ${ui.row({ lead: ui.leadIcon("copy"), title: F.t("debug.copy", "Скопировать"), sub: dbg.seg === "dev" ? F.t("debug.copy_dev", "Сведения об устройстве") : dbg.seg === "req" ? F.t("debug.copy_req", "Показанные запросы") : F.t("debug.copy_log", "Показанные записи журнала"), act: "dbg-copy" })}
        ${ui.row({ lead: ui.leadIcon("share", "var(--accent)"), title: F.t("debug.share", "Поделиться логами"), sub: F.t("debug.share_sub", "ZIP: журналы, сбои, устройство · ключи и пароли вычищаются"), act: "dbg-share" })}
        ${ui.row({ lead: ui.leadIcon("trash", "var(--bad)"), title: F.t("debug.clear", "Очистить логи"), sub: F.t("debug.clear_sub", "Журналы ядра и Android, отчёты о сбоях"), act: "dbg-clear" })}
      </div>
      ${ui.secH(F.t("debug.log_level", "Уровень журнала"))}
      <div class="seg dbg-level" role="radiogroup">${[
        ["info", F.t("debug.lv_info", "Инфо")],
        ["debug", F.t("debug.lv_debug", "Отладка")],
      ]
        .map(
          ([k, l]) =>
            `<button class="${level() === k ? "on" : ""}" role="radio"
              aria-checked="${level() === k}" data-act="dbg-level:${k}">${esc(l)}</button>`,
        )
        .join("")}</div>
      <p class="fhint">${esc(F.t("debug.level_hint", "«Отладка» пишет подробности каждого запроса и этапа; применяется сразу, без перезапуска."))}</p>`;
  }
  // Request log errors are stored as "code: detail"; known codes get a label in the UI language and the
  // raw text stays in the row tooltip. Unknown errors go through the core message catalogue.
  const ERR_KIND = () => ({
    blocked: F.t("debug.err_blocked", "заблокирован политикой скоупа"),
    out_of_scope: F.t("debug.err_out_of_scope", "вне скоупа"),
    excluded: F.t("debug.err_excluded", "в исключениях скоупа"),
    not_active_phase: F.t("debug.err_not_active_phase", "активная фаза выключена"),
    active_not_allowed: F.t("debug.err_active_not_allowed", "активные запросы запрещены профилем"),
    timeout: F.t("debug.err_timeout", "таймаут"),
    network: F.t("debug.err_network", "ошибка сети"),
    dns: F.t("debug.err_dns", "ошибка DNS"),
    tls: F.t("debug.err_tls", "ошибка TLS"),
    http: F.t("debug.err_http", "ошибка HTTP"),
    too_large: F.t("debug.err_too_large", "ответ слишком большой"),
    cancelled: F.t("debug.err_cancelled", "отменён"),
    rate_limited: F.t("debug.err_rate_limited", "лимит запросов"),
    limit: F.t("debug.err_limit", "лимит 429: запрос не отправлен"),
    refused: F.t("debug.err_refused", "соединение отклонено"),
    http_status: F.t("debug.err_http_status", "ошибка HTTP"),
    redirect: F.t("debug.err_redirect", "ошибка перенаправления"),
  });
  const errText = r => {
    const raw = String(r.error);
    const kinds0 = ERR_KIND();
    // Newer cores send a stable error_code plus the detail (translated through error_detail_msg when known).
    if (r.error_code && r.error_code !== "other" && kinds0[r.error_code]) {
      const det = r.error_detail_msg ? F.coreMsg(r.error_detail, r.error_detail_msg) : "";
      return det && det !== kinds0[r.error_code] ? `${kinds0[r.error_code]}: ${det}` : kinds0[r.error_code];
    }
    const m = /^([a-z_]+)(?::\s*(.*))?$/.exec(raw.trim());
    const kinds = ERR_KIND();
    if (m && kinds[m[1]]) {
      const detail = (m[2] || "").trim();
      if (m[1] === "out_of_scope" && kinds[detail]) return kinds[detail];
      return kinds[m[1]];
    }
    return F.coreMsg(raw, r.error_msg);
  };
  let autoT = null;
  const stopAuto = () => {
    clearInterval(autoT);
    autoT = null;
  };
  const mountDbg = (page, params) => {
    page.classList.add("dbg-pg");
    // A deep link (/settings/debug/req) picks the tab once; later renders keep the tab the user chose.
    const path = F.current();
    if (dbg.linkPath !== path) {
      dbg.linkPath = path;
      if (params && params.seg && SEGS().some(s => s[0] === params.seg)) dbg.seg = params.seg;
    }
    const inp = page.querySelector("#dbg-q");
    if (inp)
      inp.addEventListener("input", () => {
        dbg.q = inp.value;
        clearTimeout(dbg.qt);
        dbg.qt = setTimeout(() => {
          F.render(true);
          const i = F.page().querySelector("#dbg-q");
          if (i) {
            i.focus();
            i.setSelectionRange(i.value.length, i.value.length);
          }
        }, 250);
      });
    stopAuto();
    if (dbg.auto && dbg.seg === "log") autoT = setInterval(loadLogs, 3000);
  };
  const def = {
    title: () => F.t("debug.title", "Отладка"),
    sub: () => F.t("settings.title", "Настройки"),
    nav: false,
    back: true,
    actions: () => [{ icon: "refresh", act: "dbg-reload", label: F.t("common.refresh", "Обновить") }],
    hideMini: true,
    render: () => F.withStates(render, { loading: "list" }),
    mount(page, params) {
      mountDbg(page, params);
      const need = { log: !dbg.logs, req: !dbg.req, crash: !dbg.crashes, dev: !dbg.dev, search: !dbg.sj }[
        dbg.seg
      ];
      if (need) reload();
    },
    unmount: () => {
      stopAuto();
      dbg.linkPath = null;
    },
  };
  F.route("/settings/debug", def);
  F.route("/settings/debug/:seg", def);

  Object.assign(F.actions, {
    "dbg-seg": k => {
      dbg.seg = k;
      F.render(true);
      reload();
    },
    "dbg-reload": () => {
      reload();
      F.snack(F.t("debug.refreshed", "Обновлено"));
    },
    "dbg-lv": k => {
      dbg.lv[k] = !dbg.lv[k];
      F.render(true);
    },
    "dbg-src": k => {
      dbg.src = k;
      F.render(true);
    },
    "dbg-auto": () => {
      dbg.auto = !dbg.auto;
      F.render(true);
      if (dbg.auto) loadLogs();
    },
    "dbg-more": () => {
      dbg.shown += 500;
      F.render(true);
    },
    "dbg-open": k => {
      dbg.open[k] = !dbg.open[k];
      const el = [...F.page().querySelectorAll(".dbg-l")].find(x => x.dataset.act === "dbg-open:" + k);
      if (el) el.classList.toggle("open", !!dbg.open[k]);
    },
    "dbg-only": () => {
      dbg.onlyTarget = !dbg.onlyTarget;
      dbg.req = null;
      F.render(true);
      loadReq();
    },
    "dbg-crash": name =>
      F.api.crash_get(name).then(
        r =>
          F.sheet({
            title: F.t("debug.crash_title", "Отчёт о сбое"),
            full: true,
            cls: "dbg-sheet",
            html: `<p class="fhint mono">${esc(r.name)}</p><pre class="dbg-pre">${esc(r.text)}</pre>`,
            footer: `<button class="btn"
              data-act="sheet-close">${esc(F.t("common.close", "Закрыть"))}</button><button class="btn primary"
              data-act="dbg-copy-crash">${ic("copy")}${esc(F.t("debug.copy", "Скопировать"))}</button>`,
            onMount() {
              dbg.crashText = r.text;
            },
          }),
        e => F.snack(F.t("debug.open_fail", { err: e.message }, "Не удалось открыть: {err}")),
      ),
    "dbg-copy-crash": () => copy(dbg.crashText || ""),
    "dbg-fp": (_, el) => {
      if (el) {
        el.disabled = true;
        el.innerHTML = `${ic("spin", "spin")}${esc(F.t("debug.checking", "Проверяем…"))}`;
      }
      F.api.search_fingerprint().then(
        r => {
          dbg.fp = r;
          dbg.fpErr = null;
          loadSearch();
        },
        e => {
          dbg.fp = null;
          dbg.fpErr = e.message || String(e);
          rr();
        },
      );
    },
    "dbg-fp-page": () =>
      F.api.search_fingerprint_page().then(
        r =>
          F.api.platform_share({ path: r.path, name: r.name, mime: "text/html" }).then(
            () =>
              F.snack(
                F.t(
                  "debug.fp_page_open",
                  "Откройте файл в Chrome и сравните с отпечатком встроенного браузера",
                ),
                {
                  ms: 6000,
                },
              ),
            () =>
              F.snack(
                F.t(
                  "debug.fp_page_saved",
                  { name: r.name },
                  "Файл сохранён: Download/FOCA-rs/{name}. Откройте его в Chrome",
                ),
                {
                  ms: 7000,
                },
              ),
          ),
        e =>
          F.snack(F.t("debug.fp_page_fail", { err: e.message || e }, "Не удалось сохранить страницу: {err}")),
      ),
    "dbg-copy": () => {
      copy(segmentText());
    },
    "dbg-share": () => {
      F.collectLogs().then(
        r =>
          F.api.platform_share({ path: r.path, name: r.name, mime: "application/zip" }).then(
            () => F.snack(F.t("debug.share_ok", { name: r.name }, "Журналы собраны: {name}")),
            e => F.snack(F.t("debug.share_fail", { err: e.message }, "Не удалось поделиться: {err}")),
          ),
        e => F.snack(F.t("debug.collect_fail", { err: e.message }, "Не удалось собрать журналы: {err}")),
      );
    },
    "dbg-clear": () =>
      F.sheet({
        title: F.t("debug.clear_q", "Очистить логи?"),
        html: `<p class="lead">${esc(F.t("debug.clear_text", "Журналы ядра и Android и отчёты о сбоях будут удалены. Данные проектов не затрагиваются."))}</p>`,
        footer: `<button class="btn"
          data-act="sheet-close">${esc(F.t("common.cancel", "Отмена"))}</button><button class="btn danger"
          data-act="dbg-clear-go">${ic("trash")}${esc(F.t("debug.clear_go", "Очистить"))}</button>`,
      }),
    "dbg-clear-go": () => {
      F.closeSheet();
      F.api.logs_clear().then(
        () => {
          dbg.logs = null;
          dbg.crashes = null;
          F.snack(F.t("debug.cleared", "Журналы очищены"));
          reload();
        },
        e => F.snack(F.t("debug.fail", { err: e.message }, "Не удалось: {err}")),
      );
    },
    "dbg-level": k =>
      F.api.settings_set({ debug: { level: k } }).then(() => {
        if (dbg.app) dbg.app.log_level = k;
        F.render(true);
        F.snack(
          k === "debug"
            ? F.t("debug.level_on", "Подробный журнал включён")
            : F.t("debug.level_off", "Журнал: только важное"),
        );
      }),
  });
  /**
   * Builds the secret-free logs ZIP (core and Android logs, crash reports, device.txt); resolves to
   * `{ path, name }`. device.txt is built from fresh device data: the "Device" segment may never have
   * been opened. Also used by "Report a problem" (beta note, About).
   */
  F.collectLogs = () =>
    loadDev().then(() =>
      F.api.logs_export({
        lang: F.i18n ? F.i18n.lang() : undefined,
        device: devText()
          .map(([k, v]) => `${k}: ${v}`)
          .join("\n"),
      }),
    );
  /** Plain-text dump of the currently open debug segment (for the "Copy" action). */
  function segmentText() {
    switch (dbg.seg) {
      case "search":
        return fpText() || F.t("debug.fp_none", "Отпечаток не проверен");
      case "dev":
        return devText()
          .map(([k, v]) => `${k}: ${v}`)
          .join("\n");
      case "req":
        return (dbg.req || [])
          .map(r => `${r.time} ${r.method} ${r.status || "-"} ${r.access} ${r.url}`)
          .join("\n");
      case "crash":
        return (dbg.crashes || []).map(c => `${c.name} ${c.title}`).join("\n");
      default:
        return logRows()
          .slice(-dbg.shown)
          .map(e => `${e.t} ${e.level.toUpperCase()} ${e.target} ${e.msg}`)
          .join("\n");
    }
  }
  function copy(text) {
    const done = () => F.snack(F.t("debug.copied", "Скопировано"));
    try {
      navigator.clipboard.writeText(text).then(done, () => fallback(text));
    } catch (e) {
      fallback(text);
    }
    function fallback(s) {
      const ta = document.createElement("textarea");
      ta.value = s;
      document.body.appendChild(ta);
      ta.select();
      try {
        document.execCommand("copy");
        done();
      } catch (e) {
        F.snack(F.t("debug.copy_fail", "Не удалось скопировать"));
      }
      ta.remove();
    }
  }
})();
