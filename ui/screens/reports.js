// Reports and export screens (CSS prefix rp-).
// F.exportSheet({title, kind, count, items, fmt}) is the shared export sheet; F.actions.export(kind) opens
// it.
// Routes: /p/reports (tab), /p/report-new (builder), /p/report-preview (A4 preview).
(function () {
  const F = window.FOCA,
    { ic, esc, ui } = F;
  const demo = window.DEMO;
  const numLoc = () =>
    ({ en: "en-US", uk: "uk-UA" })[F.i18n && F.i18n.lang ? F.i18n.lang() : "ru"] || "ru-RU";
  const fmtN = n =>
    Number(n)
      .toLocaleString(numLoc())
      .replace(/\u202f|\u00a0/g, "\u00a0");
  const isEn = () => !!(F.i18n && F.i18n.lang && F.i18n.lang() === "en");
  // Plural forms come from the dictionary as "one|few|many" (ru/uk) or "one|other" (en).
  const plural = (n, key, one, few, many) => {
    const f = String(F.t(key, `${one}|${few}|${many}`)).split("|");
    if (isEn()) return `${fmtN(n)} ${Math.abs(n) === 1 ? f[0] : (f[1] ?? f[0])}`;
    const a = n % 10,
      b = n % 100;
    return `${fmtN(n)} ${a === 1 && b !== 11 ? f[0] : a >= 2 && a <= 4 && (b < 12 || b > 14) ? f[1] : (f[2] ?? f[1])}`;
  };
  const kb = n =>
    n >= 1024
      ? (n / 1024).toFixed(1).replace(".", isEn() ? "." : ",") + " " + F.t("reports.mb", "МБ")
      : Math.max(1, Math.round(n)) + " " + F.t("reports.kb", "КБ");

  F.addIcons(`
<symbol id="i-rp-csv" viewBox="0 0 16 16"><rect x="2.5" y="2.5" width="11" height="11"
  rx="1.2"/><path d="M2.5 6.5h11M2.5 10h11M6.5 2.5v11"/></symbol>
<symbol id="i-rp-json"
  viewBox="0 0 16 16"><path d="M5.5 2.5c-1.5 0-2 .7-2 2v1.5c0 1-.5 2-1.5 2 1 0 1.5 1 1.5 2v1.5c0 1.3.5 2 2 2M10.5 2.5c1.5 0 2 .7 2 2v1.5c0 1 .5 2 1.5 2-1 0-1.5 1-1.5 2v1.5c0 1.3-.5 2-2 2"/></symbol>
<symbol id="i-rp-md" viewBox="0 0 16 16"><rect x="1.5" y="3.5" width="13" height="9"
  rx="1.2"/><path d="M4 10.5v-5l2 2.5 2-2.5v5M11.5 5.5v5M10 9l1.5 1.5L13 9"/></symbol>
<symbol id="i-rp-dict"
  viewBox="0 0 16 16"><path d="M3.5 2.5h8a1 1 0 0 1 1 1v10h-8a1 1 0 0 1-1-1z"/><path d="M3.5 12.5a1 1 0 0 1 1-1h8M6 5.5h4M6 8h3"/></symbol>`);

  // ================= DATA =================
  const FND = () => F.db.findings;
  const SEV_RU = { crit: "Критический", high: "Высокий", warn: "Средний", low: "Низкий", info: "Инфо" };
  const SEV = new Proxy(SEV_RU, { get: (o, k) => (k in o ? F.t("sev." + String(k), o[k]) : o[k]) });

  const KINDS = {
    findings: {
      get l() {
        return F.t("reports.kind_findings", "Находки");
      },
      icon: "bug",
      n: () => FND().length,
      fields: [
        "Название",
        "Важность",
        "Статус",
        "Хост",
        "CVE",
        "CVSS",
        "Источник",
        "Описание",
        "Рекомендация",
        "Доказательство",
      ],
      off: ["Доказательство"],
      secrets: true,
      pii: false,
      items: () => FND().map(f => `${SEV[f.sev] || ""}: ${f.title} (${f.host})`),
    },
    users: {
      get l() {
        return F.t("reports.kind_users", "Пользователи");
      },
      icon: "users",
      n: () => F.db.people.length,
      fields: ["Логин", "ФИО", "Отдел", "Компьютер", "Документов"],
      pii: true,
      items: () => F.db.people.map(u => u.login),
    },
    emails: {
      l: "E-mail",
      icon: "mail",
      n: () => F.db.emails.length,
      fields: ["Адрес", "Имя", "Источник", "Утечки"],
      pii: true,
      items: () => F.db.emails.map(e => e.addr),
    },
    paths: {
      get l() {
        return F.t("reports.kind_paths", "Пути");
      },
      icon: "path",
      n: () => demo.folders.length,
      fields: ["Путь", "Хост", "Документ"],
      items: () => demo.folders.slice(),
    },
    software: {
      get l() {
        return F.t("reports.kind_software", "ПО");
      },
      icon: "app",
      n: () => demo.software.length,
      fields: ["Название", "Версия", "Документов", "EOL", "CVE"],
      items: () => demo.software.map(s => `${s.name} ${s.ver}`),
    },
    hosts: {
      get l() {
        return F.t("reports.kind_hosts", "Хосты");
      },
      icon: "server",
      n: () => demo.hosts.length,
      fields: ["Имя", "IP", "Роль", "Технологии", "Облако", "Риск"],
      items: () => demo.hosts.map(h => h.name),
    },
    docs: {
      get l() {
        return F.t("reports.kind_docs", "Документы");
      },
      icon: "doc",
      n: () => F.sel.docsLive().length,
      fields: ["Имя файла", "URL", "Автор", "ПО", "Создан", "Размер", "SHA-256"],
      pii: true,
      items: () =>
        F.sel
          .docsLive()
          .slice(0, 40)
          .map(d => d.url),
    },
    log: {
      get l() {
        return F.t("reports.kind_log", "Журнал запросов");
      },
      icon: "log",
      n: () => F.sel.requests().total,
      fields: ["Время", "Метод", "URL", "Код ответа", "Модуль", "Выходной IP"],
      items: () => F.sel.requests().sample,
    },
    all: {
      get l() {
        return F.t("reports.kind_all", "Все данные проекта");
      },
      icon: "db",
      n: () =>
        FND().length +
        F.db.people.length +
        demo.hosts.length +
        F.sel.docsLive().length +
        demo.software.length,
      fields: ["Находки", "Люди", "E-mail", "Хосты", "Документы", "ПО", "Пути", "Журнал запросов"],
      off: ["Журнал запросов"],
      secrets: true,
      pii: true,
      items: () => demo.hosts.map(h => h.name),
    },
  };
  // Export field names stay Russian internally (k.off); translated only for display.
  const fieldL = f =>
    ({
      Название: F.t("reports.fld_0", "Название"),
      Важность: F.t("reports.fld_1", "Важность"),
      Статус: F.t("reports.fld_2", "Статус"),
      Хост: F.t("reports.fld_3", "Хост"),
      Источник: F.t("reports.fld_4", "Источник"),
      Описание: F.t("reports.fld_5", "Описание"),
      Рекомендация: F.t("reports.fld_6", "Рекомендация"),
      Доказательство: F.t("reports.fld_7", "Доказательство"),
      Логин: F.t("reports.fld_8", "Логин"),
      ФИО: F.t("reports.fld_9", "ФИО"),
      Отдел: F.t("reports.fld_10", "Отдел"),
      Компьютер: F.t("reports.fld_11", "Компьютер"),
      Документов: F.t("reports.fld_12", "Документов"),
      Адрес: F.t("reports.fld_13", "Адрес"),
      Имя: F.t("reports.fld_14", "Имя"),
      Утечки: F.t("reports.fld_15", "Утечки"),
      Путь: F.t("reports.fld_16", "Путь"),
      Документ: F.t("reports.fld_17", "Документ"),
      Версия: F.t("reports.fld_18", "Версия"),
      Роль: F.t("reports.fld_19", "Роль"),
      Технологии: F.t("reports.fld_20", "Технологии"),
      Облако: F.t("reports.fld_21", "Облако"),
      Риск: F.t("reports.fld_22", "Риск"),
      "Имя файла": F.t("reports.fld_23", "Имя файла"),
      Автор: F.t("reports.fld_24", "Автор"),
      ПО: F.t("reports.fld_25", "ПО"),
      Создан: F.t("reports.fld_26", "Создан"),
      Размер: F.t("reports.fld_27", "Размер"),
      Время: F.t("reports.fld_28", "Время"),
      Метод: F.t("reports.fld_29", "Метод"),
      "Код ответа": F.t("reports.fld_30", "Код ответа"),
      Модуль: F.t("reports.fld_31", "Модуль"),
      "Выходной IP": F.t("reports.fld_32", "Выходной IP"),
      Находки: F.t("reports.fld_33", "Находки"),
      Люди: F.t("reports.fld_34", "Люди"),
      Хосты: F.t("reports.fld_35", "Хосты"),
      Документы: F.t("reports.fld_36", "Документы"),
      Пути: F.t("reports.fld_37", "Пути"),
      "Журнал запросов": F.t("reports.fld_38", "Журнал запросов"),
    })[f] || f;
  const kindOf = k => KINDS[k] || KINDS.all;

  const FORMATS = [
    {
      id: "list",
      icon: "copy",
      get t() {
        return F.t("reports.fmt_list_t", "Скопировать как список");
      },
      get d() {
        return F.t("reports.fmt_list_d", "По строке на значение: в буфер обмена");
      },
    },
    {
      id: "dict",
      icon: "rp-dict",
      get t() {
        return F.t("reports.fmt_dict_t", "Словарь .txt");
      },
      get d() {
        return F.t("reports.fmt_dict_d", "Пользователи, e-mail, пути или ПО: для перебора и фаззинга");
      },
    },
    {
      id: "csv",
      icon: "rp-csv",
      t: "CSV",
      get d() {
        return F.t("reports.fmt_csv_d", "Таблица для Excel, LibreOffice, Google Таблиц");
      },
    },
    {
      id: "json",
      icon: "rp-json",
      t: "JSON",
      get d() {
        return F.t("reports.fmt_json_d", "Структурированные данные для скриптов и SIEM");
      },
    },
    {
      id: "stix",
      icon: "rp-json",
      t: "STIX 2.1 (JSON)",
      get d() {
        return F.t("reports.fmt_stix_d", "Бандл OASIS STIX 2.1 для MISP, OpenCTI и SIEM (без секретов)");
      },
    },
    {
      id: "nuclei",
      icon: "rp-dict",
      get t() {
        return F.t("reports.fmt_nuclei_t", "Цели для Nuclei (.txt)");
      },
      get d() {
        return F.t("reports.fmt_nuclei_d", "Нормализованные URL и эндпоинты в скоупе для nuclei -l");
      },
    },
    {
      id: "httpx",
      icon: "rp-dict",
      get t() {
        return F.t("reports.fmt_httpx_t", "Цели для httpx (.txt)");
      },
      get d() {
        return F.t("reports.fmt_httpx_d", "Домены, хосты и веб-ориджины в скоупе для httpx -l");
      },
    },
    {
      id: "maltego",
      icon: "graph",
      get t() {
        return F.t("reports.fmt_maltego_t", "Для Maltego");
      },
      get d() {
        return F.t("reports.fmt_maltego_d", "Сущности и связи: CSV или GraphML");
      },
    },
    {
      id: "md",
      icon: "rp-md",
      t: "Markdown (Obsidian)",
      get d() {
        return F.t("reports.fmt_md_d", "Заметки со ссылками [[…]] для базы знаний");
      },
    },
    {
      id: "tpl",
      icon: "report",
      get t() {
        return F.t("reports.fmt_tpl_t", "Отчёт по шаблону");
      },
      get d() {
        return F.t("reports.fmt_tpl_d", "HTML/PDF/DOCX с титулом, сводкой и находками");
      },
    },
  ];
  const EXT = {
    dict: "txt",
    csv: "csv",
    json: "json",
    stix: "json",
    nuclei: "txt",
    httpx: "txt",
    maltego: "csv",
    md: "md",
  };
  const slug = {
    findings: "findings",
    users: "users",
    emails: "emails",
    paths: "paths",
    software: "software",
    hosts: "hosts",
    docs: "documents",
    log: "requests-log",
    all: "project",
  };

  // ================= EXPORT SHEET =================
  const exp = (F.state.export = {
    o: null,
    fmt: null,
    sh: null,
    mask: false,
    dict: "users",
    mal: "csv",
    md: "many",
    delim: ",",
    bom: true,
    pretty: true,
    uniq: true,
    lower: true,
    variants: true,
  });
  // Default dictionary type per export source: e-mails from E-mail, logins from People, etc.
  const DICT_OF = { emails: "emails", users: "users", paths: "paths", software: "software" };
  const setSheet = (title, html, footer) => {
    const sh = exp.sh;
    if (!sh || !sh.isConnected) return;
    sh.querySelector(".sh-h h3").textContent = title;
    const bodyEl = sh.querySelector(".sh-b");
    bodyEl.innerHTML = html;
    bodyEl.scrollTop = 0;
    let footEl = sh.querySelector(".sh-f");
    if (footer) {
      if (!footEl) {
        footEl = document.createElement("div");
        footEl.className = "sh-f";
        sh.append(footEl);
      }
      footEl.innerHTML = footer;
    } else if (footEl) footEl.remove();
  };
  const head = () => {
    const k = kindOf(exp.o.kind);
    const n = exp.o.count ?? k.n();
    return `<div class="rp-exh">${ui.leadIcon(k.icon, "var(--accent)")}<div class="rp-exh-b"><b>${esc(exp.o.subject || k.l)}</b><span>${n == null ? F.t("reports.no_records", "записи: нет данных") : plural(n, "reports.pl_record", "запись", "записи", "записей")} · ${esc(F.project ? F.project.name : "")}</span></div></div>`;
  };
  function step1() {
    return (
      head() +
      `<div class="rp-fmts">${FORMATS.map(
        f => `<div class="srow rp-fmt" role="button"
        data-act="rp-ex-fmt:${f.id}">${ic(f.icon)}<span class="lbl">${f.t}<small>${f.d}</small></span>${f.id === "list" ? "" : ic("chev", "chev")}</div>`,
      ).join("")}</div>`
    );
  }
  const togRow = (on, act, t, s, cls = "") =>
    `<div class="row rp-tg ${cls}">${""}<div class="body"><div class="t">${t}</div>${s ? `<div class="s">${s}</div>` : ""}</div><div class="tail">${ui.toggle(on, act, `aria-label="${esc(t)}"`)}</div></div>`;
  const fileName = () =>
    `${(F.project ? F.project.name : "foca").replace(/\..*$/, "")}_${exp.fmt === "dict" ? "dict-" + exp.dict : slug[exp.o.kind] || "export"}_${F.sel.scope.today}.${exp.fmt === "maltego" && exp.mal === "graphml" ? "graphml" : exp.fmt === "md" && exp.md === "many" ? "zip" : EXT[exp.fmt]}`;
  const estSize = () => {
    const n = exp.fmt === "dict" ? dictItems(exp.dict).length : (exp.o.count ?? kindOf(exp.o.kind).n() ?? 0);
    const per = { dict: 0.02, csv: 0.25, json: 0.6, maltego: 0.3, md: 0.9 }[exp.fmt] || 0.3;
    return kb(n * per * (exp.o.kind === "log" ? 0.4 : 1) + 2);
  };
  // Dictionaries are built from project data (F.db); login variants: i.petrenko → ipetrenko, petrenko.i,
  // petrenko.
  const loginVariants = l => {
    const [a, b] = String(l).split(".");
    return b ? [l, a + b, `${b}.${a}`, b] : [l];
  };
  /** Raw items of export dictionary `id`, before the lower-case/unique options are applied. */
  const dictSource = id => {
    if (id === "custom") return (exp.o.items || []).slice();
    if (id === "users")
      return (exp.o.items && exp.o.kind === "users" ? exp.o.items : F.db.people.map(p => p.login)).flatMap(
        x => (exp.variants ? loginVariants(x) : [x]),
      );
    if (id === "logins") return F.db.people.filter(p => !p.service).flatMap(p => loginVariants(p.login));
    if (id === "context") {
      const n = (F.project ? F.project.name : "target").split(".")[0];
      return [n, `${n}2025`, `${n}2026`, `${n}123`].filter(Boolean);
    }
    if (id === "emails") return F.db.emails.map(e => e.addr);
    if (id === "paths")
      return F.db.paths
        .map(p => p.path)
        .concat(
          F.sel
            .docsLive()
            .map(d => {
              try {
                return new URL(
                  d.url.replace(/^https:\/\/web\.archive\.org\/web\/\d+\//, ""),
                ).pathname.replace(/[^/]*$/, "");
              } catch (e) {
                return "";
              }
            })
            .filter(Boolean),
        );
    return F.db.software.map(s => `${s.name} ${s.ver}`);
  };
  const dictItems = id => {
    let l = dictSource(id);
    if (exp.lower) l = l.map(x => x.toLowerCase());
    if (exp.uniq) l = [...new Set(l)];
    return l;
  };
  const DICTS = () => [
    ...(exp.o && exp.o.items && exp.o.kind !== "users"
      ? [["custom", exp.o.subject || F.t("reports.sel_custom", "Выборка")]]
      : []),
    [
      "users",
      exp.o && exp.o.items && exp.o.kind === "users"
        ? exp.o.subject || F.t("reports.sel_logins", "Логины выборки")
        : F.t("reports.kind_users", "Пользователи"),
    ],
    ["logins", F.t("reports.dict_logins", "Шаблоны логинов")],
    ["context", F.t("reports.dict_context", "Контекстный словарь")],
    ["emails", "E-mail"],
    ["paths", F.t("reports.kind_paths", "Пути")],
    ["software", F.t("reports.kind_software", "ПО")],
  ];
  /** Format-specific export options (CSV delimiter, JSON indentation, Maltego flavour, Markdown layout). */
  function formatOptions() {
    if (exp.fmt === "csv")
      return `<h4 class="sub-h rp-h4">${esc(F.t("reports.delim", "Разделитель"))}</h4><div class="seg" role="radiogroup">${[
        [",", F.t("reports.comma", "Запятая")],
        [";", F.t("reports.semicolon", "Точка с запятой")],
        ["tab", F.t("reports.tab", "Табуляция")],
      ]
        .map(
          ([v, l]) =>
            `<button class="${exp.delim === v ? "on" : ""}" role="radio"
                    aria-checked="${exp.delim === v}" data-act="rp-ex-delim:${v}">${l}</button>`,
        )
        .join("")}</div>
          <div class="list rp-opts">${togRow(exp.bom, "rp-ex-bom", F.t("reports.bom", "UTF-8 с BOM"), F.t("reports.bom_sub", "Чтобы Excel правильно показал кириллицу"))}</div>`;
    if (exp.fmt === "json")
      return `<div class="list rp-opts">${togRow(exp.pretty, "rp-ex-pretty", F.t("reports.pretty", "С отступами"), F.t("reports.pretty_sub", "Удобно читать; без отступов: меньше размер"))}</div>`;
    if (exp.fmt === "stix")
      return `<p class="fhint rp-hint">${ic("shield")} ${esc(F.t("reports.stix_hint", "Бандл OASIS STIX 2.1 (SDO/SCO + связи): секреты и ПДн принудительно маскируются даже при включённом тумблере."))}</p>`;
    if (exp.fmt === "nuclei")
      return `<p class="fhint rp-hint">${esc(F.t("reports.nuclei_hint", "По одному URL/эндпоинту в скоупе на строку, готово для"))} <span class="mono">nuclei -l</span>.</p>`;
    if (exp.fmt === "httpx")
      return `<p class="fhint rp-hint">${esc(F.t("reports.httpx_hint", "Дедуплицированные домены, хосты и origins в скоупе, готово для"))} <span class="mono">httpx -l</span>.</p>`;
    if (exp.fmt === "maltego")
      return `<h4 class="sub-h rp-h4">${esc(F.t("reports.maltego_fmt", "Формат Maltego"))}</h4><div class="seg" role="radiogroup">${[
        ["csv", F.t("reports.mt_csv", "CSV (импорт таблицы)")],
        ["graphml", F.t("reports.mt_graphml", "GraphML (граф)")],
      ]
        .map(
          ([v, l]) =>
            `<button class="${exp.mal === v ? "on" : ""}" role="radio"
                        aria-checked="${exp.mal === v}" data-act="rp-ex-mal:${v}">${l}</button>`,
        )
        .join("")}</div>
          <p class="fhint rp-hint">${esc(F.t("reports.entities", "Сущности:"))} maltego.Domain, maltego.IPv4Address, maltego.Person, maltego.EmailAddress, maltego.Document.</p>`;
    if (exp.fmt === "md")
      return `<h4 class="sub-h rp-h4">${esc(F.t("reports.structure", "Структура"))}</h4><div class="seg" role="radiogroup">${[
        ["many", F.t("reports.md_many", "Заметка на сущность")],
        ["one", F.t("reports.md_one", "Один файл")],
      ]
        .map(
          ([v, l]) =>
            `<button class="${exp.md === v ? "on" : ""}" role="radio"
                          aria-checked="${exp.md === v}" data-act="rp-ex-md:${v}">${l}</button>`,
        )
        .join("")}</div>
          <div class="list rp-opts">${ui.check(true, F.t("reports.md_links", "Ссылки [[wikilinks]] между людьми, хостами и документами"))}${ui.check(true, F.t("reports.md_yaml", "Свойства YAML (теги, важность, источник)"))}</div>`;
    return "";
  }
  function step2() {
    const k = kindOf(exp.o.kind);
    let body;
    if (exp.fmt === "dict") {
      const all = dictItems(exp.dict);
      const prev = all.slice(0, 6).concat(all.length > 6 ? ["…"] : []);
      const ex = (F.db.people.find(p => p.login.includes(".")) || {}).login;
      body = `<h4 class="sub-h rp-h4">${esc(F.t("reports.dict_h", "Словарь"))}</h4>
        <div class="chips wrap rp-radio" role="radiogroup">${DICTS()
          .map(
            ([id, l]) =>
              `<button class="chip ${exp.dict === id ? "on" : ""}" role="radio"
                aria-checked="${exp.dict === id}"
                data-act="rp-ex-dict:${id}">${esc(l)}<span class="c">${dictItems(id).length}</span></button>`,
          )
          .join("")}</div>
        <div class="list rp-opts">${ui.check(exp.uniq, F.t("reports.uniq", "Только уникальные"), "rp-ex-opt:uniq")}${ui.check(exp.lower, F.t("reports.lower", "В нижнем регистре"), "rp-ex-opt:lower")}${exp.dict === "users" ? ui.check(exp.variants, F.t("reports.variants", "Варианты логинов"), "rp-ex-opt:variants", ex ? esc(`${ex} → ${loginVariants(ex).slice(1).join(", ")}`) : F.t("reports.variants_ex", "имя.фамилия → имяфамилия, фамилия.имя, фамилия")) : ""}</div>
        <h4 class="sub-h rp-h4">${esc(F.t("reports.preview", "Предпросмотр"))}</h4>${all.length ? `<pre class="rp-pre">${esc(prev.join("\n"))}</pre>` : `<p class="fhint rp-hint">${ic("info")} ${esc(F.t("reports.dict_empty", "В проекте пока нет данных для этого словаря."))}</p>`}`;
    } else {
      const off = new Set(k.off || []);
      const extra = formatOptions();
      body = `<h4 class="sub-h rp-h4">${esc(exp.fmt === "csv" ? F.t("reports.columns", "Колонки") : F.t("reports.fields", "Поля"))}</h4>
        <div class="list rp-cols">${k.fields.map(f => ui.check(!off.has(f), esc(fieldL(f)))).join("")}</div>${extra}`;
    }
    const privacy = `<h4 class="sub-h rp-h4">${esc(F.t("reports.privacy", "Конфиденциальность"))}</h4>
      <div class="list rp-opts">
        ${togRow(exp.mask, "rp-ex-mask", F.t("reports.mask_pd", "Маскировать персональные данные и секреты"), F.t("reports.mask_pd_sub", "Телефоны, IBAN, РНОКПП, карты, e-mail, имена и секреты заменяются масками"))}
      </div>`;
    const file = `<div class="rp-file">${ic("doc")}<span class="mono">${esc(fileName())}</span><span class="muted">~${estSize()}</span></div>`;
    // The request log can be cleared where it is exported (debug.js F.reqLogClear).
    const clear =
      exp.o.kind === "log" && F.reqLogClear
        ? `<button class="btn text crit rp-logclr" data-act="rl-clear">${ic("trash")}${esc(F.t("debug.rl_clear", "Очистить журнал запросов"))}</button>`
        : "";
    return head() + body + privacy + file + clear;
  }
  const step2Footer = () =>
    `<button class="btn rp-back" data-act="rp-ex-back"
      aria-label="${esc(F.t("reports.back_formats", "Назад к форматам"))}">${ic("back")}</button><button class="btn"
      data-act="rp-ex-save">${ic("download")}${esc(F.t("reports.save_files", "Сохранить в файлы"))}</button><button class="btn primary"
      data-act="rp-ex-share">${ic("share")}${esc(F.t("reports.share", "Поделиться…"))}</button>`;
  const fmtTitle = id => (FORMATS.find(f => f.id === id) || {}).t || F.t("reports.export", "Экспорт");
  const redraw2 = () => setSheet(fmtTitle(exp.fmt), step2(), step2Footer());

  F.exportSheet = (opts = {}) => {
    Object.assign(exp, {
      o: { kind: "all", ...opts },
      fmt: null,
      mask: false,
    });
    exp.dict =
      opts.items && opts.kind !== "users" && opts.fmt === "dict" ? "custom" : DICT_OF[opts.kind] || exp.dict;
    const sh = F.sheet({
      title: opts.title || F.t("reports.export", "Экспорт"),
      cls: "rp-sheet",
      html: "",
      onClose: () => {
        exp.sh = null;
      },
    });
    exp.sh = sh;
    if (opts.fmt) {
      exp.fmt = opts.fmt;
      redraw2();
    } else setSheet(opts.title || F.t("reports.export", "Экспорт"), step1(), "");
    return sh;
  };
  F.actions.export = kind => F.exportSheet({ kind: kind || "all" });

  // Demo stand-in for the Android Share sheet.
  const APPS = () => [
    ["Telegram", "#229ED9", "TG"],
    ["Signal", "#3A76F0", "SG"],
    ["Gmail", "#D93025", "GM"],
    [F.t("reports.app_drive", "Диск"), "#1E8E3E", "GD"],
    [F.t("reports.app_files", "Файлы"), "#5F6368", "FS"],
    ["Quick Share", "#1A73E8", "QS"],
    ["Element", "#0DBD8B", "EL"],
    [F.t("reports.app_more", "Ещё"), "#3C4043", "··"],
  ];
  F.shareSheet = (name, size) =>
    F.sheet({
      cls: "rp-sheet rp-share",
      html: `<div class="rp-shh">${extTag(name.split(".").pop())}<div class="rp-shh-b"><b>${esc(name)}</b><span>${esc(size || "")} · ${esc(F.t("reports.via_android", "Отправка через Android"))}</span></div></div>
      <div class="rp-apps">${APPS()
        .map(
          ([n, c, a]) => `<button class="rp-app"
        data-act="rp-share-to:${n}" aria-label="${esc(n)}"><span class="rp-app-ic"
        style="background:${c}">${a}</span><span class="rp-app-l">${esc(n)}</span></button>`,
        )
        .join("")}</div>
      <div class="srow"
        data-act="rp-share-to:copy">${ic("copy")}<span class="lbl">${esc(F.t("reports.copy_file", "Скопировать файл"))}</span></div>
      <div class="srow"
        data-act="rp-share-to:save">${ic("download")}<span class="lbl">${esc(F.t("reports.save_dl", "Сохранить в «Загрузки»"))}</span></div>
      <p class="fhint rp-hint">${ic("info")} ${esc(F.t("reports.share_demo", "Демо: в приложении откроется системное окно Android «Поделиться»."))}</p>`,
    });

  // In the app: system Share (ACTION_SEND via FileProvider) and "Save to files" (MediaStore
  // Download/FOCA-rs); the file is taken from the core's private folder (platform_share / platform_save,
  // docs/API.md).
  const nativeShare = o =>
    F.api
      .platform_share(o)
      .catch(e => F.snack(F.t("reports.share_fail", "Не удалось поделиться: ") + e.message));
  const nativeSave = o =>
    F.api.platform_save(o).then(
      r => {
        if (r && r.ok) F.snack(F.t("reports.saved_path", { path: r.path }, "Сохранено: {path}"));
      },
      e => F.snack(F.t("reports.save_fail", "Не удалось сохранить: ") + e.message),
    );
  const shareReport = h => {
    if (F.isTauri) nativeShare({ report: h.id, name: h.name });
    else F.shareSheet(h.name, sizeOf(h));
  };
  const exportNow = () =>
    F.api.export_build(exp.o.kind || "all", exp.fmt, {
      dict: exp.dict,
      delim: exp.delim,
      bom: exp.bom,
      pretty: exp.pretty,
      mal: exp.mal,
      md: exp.md,
      mask: !!exp.mask,
      items:
        exp.fmt === "dict" && exp.dict !== "logins" && exp.dict !== "context"
          ? dictItems(exp.dict)
          : exp.o.items,
    });
  Object.assign(F.actions, {
    "rp-ex-fmt": id => {
      if (id === "list") {
        const k = kindOf(exp.o.kind);
        const items = exp.o.items || k.items();
        F.clipWrite(items.join("\n"));
        F.closeSheet();
        F.snack(
          F.t(
            "reports.copied_n",
            { n: plural(items.length, "reports.pl_row", "строка", "строки", "строк") },
            "Скопировано: {n}",
          ),
        );
        return;
      }
      if (id === "tpl") {
        F.closeSheet();
        F.go("/p/report-new");
        return;
      }
      exp.fmt = id;
      redraw2();
    },
    "rp-ex-back": () => {
      exp.fmt = null;
      setSheet(exp.o.title || F.t("reports.export", "Экспорт"), step1(), "");
    },
    "rp-ex-dict": id => {
      exp.dict = id;
      redraw2();
    },
    "rp-ex-opt": k => {
      exp[k] = !exp[k];
      const y = exp.sh.querySelector(".sh-b").scrollTop;
      redraw2();
      exp.sh.querySelector(".sh-b").scrollTop = y;
    },
    "rp-ex-delim": v => {
      exp.delim = v;
      redraw2();
    },
    "rp-ex-mal": v => {
      exp.mal = v;
      redraw2();
    },
    "rp-ex-md": v => {
      exp.md = v;
      redraw2();
    },
    "rp-ex-bom": (_, el) => {
      exp.bom = !exp.bom;
      F.actions.toggle(null, el);
    },
    "rp-ex-pretty": (_, el) => {
      exp.pretty = !exp.pretty;
      F.actions.toggle(null, el);
    },
    "rp-ex-mask": (_, el) => {
      exp.mask = !exp.mask;
      F.actions.toggle(null, el);
    },
    // The file is built by the core (export_build): name, size, path; the screen only shows the result.
    "rp-ex-save": () => {
      if (F.isTauri) {
        exportNow().then(
          r => {
            F.closeSheet();
            return nativeSave({ path: r.path, name: r.name });
          },
          e => F.snack(F.t("reports.failed", "Не удалось: ") + e.message),
        );
        return;
      }
      exportNow().then(
        r => {
          F.closeSheet();
          F.snack(F.t("reports.saved_path", { path: r.path }, "Сохранено: {path}"), {
            label: F.t("common.open", "Открыть"),
            action: () => F.snack(F.t("reports.open_ext", "Открытие во внешнем приложении")),
          });
        },
        e => F.snack(F.t("reports.failed", "Не удалось: ") + e.message),
      );
    },
    "rp-ex-share": () => {
      exportNow().then(
        r => {
          F.closeSheet();
          if (F.isTauri) nativeShare({ path: r.path, name: r.name });
          else setTimeout(() => F.shareSheet(r.name, r.size), 260);
        },
        e => F.snack(F.t("reports.failed", "Не удалось: ") + e.message),
      );
    },
    "rp-share-to": to => {
      F.closeSheet();
      F.snack(
        to === "copy"
          ? F.t("reports.file_copied", "Файл скопирован в буфер")
          : to === "save"
            ? F.t("reports.saved_dl", "Сохранено в «Загрузки»")
            : F.t("reports.sent_to", { to }, "Передано в {to}"),
      );
    },
  });

  // ================= REPORTS TAB =================
  const TPLS = [
    {
      id: "full",
      icon: "report",
      get t() {
        return F.t("reports.tpl_full_t", "Полный отчёт пентеста");
      },
      f: ["HTML", "PDF", "DOCX"],
      get d() {
        return F.t(
          "reports.tpl_full_d",
          "Титул, резюме для руководства, скоуп, все находки с доказательствами и рекомендациями, приложения.",
        );
      },
      fmt: "pdf",
    },
    {
      id: "brief",
      icon: "rp-md",
      get t() {
        return F.t("reports.tpl_brief_t", "Краткая сводка");
      },
      f: ["Markdown", "DOCX"],
      get d() {
        return F.t(
          "reports.tpl_brief_d",
          "Одна-две страницы: риск, критичные находки, что исправить в первую очередь.",
        );
      },
      fmt: "md",
    },
    {
      id: "data",
      icon: "rp-csv",
      get t() {
        return F.t("reports.tpl_data_t", "Данные");
      },
      f: ["CSV", "JSON"],
      get d() {
        return F.t(
          "reports.tpl_data_d",
          "Все находки, люди, хосты и документы: для своих инструментов и трекеров.",
        );
      },
      fmt: "csv",
    },
    // Fixed-structure templates of the core (report_templates / report_build.template).
    {
      id: "executive",
      icon: "user",
      get t() {
        return F.t("reports.tpl_exec_t", "Для руководства");
      },
      f: ["HTML", "PDF", "DOCX", "Markdown"],
      get d() {
        return F.t(
          "reports.tpl_exec_d",
          "Одна страница: риск-скор, пять главных находок простым языком и три первоочередных действия.",
        );
      },
      fmt: "pdf",
    },
    {
      id: "compliance",
      icon: "shield",
      get t() {
        return F.t("reports.tpl_comp_t", "КСЗІ / Соответствие");
      },
      f: ["HTML", "PDF", "DOCX", "Markdown"],
      get d() {
        return F.t(
          "reports.tpl_comp_d",
          "Находки × MITRE ATT&CK v20, CWE, OWASP Top 10:2025, ISO/IEC 27001, NIST SP 800-53 / НД ТЗІ 3.6-006-24, персональные данные и НД ТЗІ для систем с КСЗИ, сводки и оговорка аудитора.",
        );
      },
      fmt: "pdf",
    },
    {
      id: "lab",
      icon: "note",
      get t() {
        return F.t("reports.tpl_lab_t", "Лабораторная работа");
      },
      f: ["HTML", "PDF", "DOCX", "Markdown"],
      get d() {
        return F.t(
          "reports.tpl_lab_d",
          "Цель, методика, исходные данные, ход работы, таблица находок со стандартами, выводы.",
        );
      },
      fmt: "pdf",
    },
  ];
  // History rows store the template title in the language of the build; show it in the UI language.
  const TPL_TITLE_RU = {
    "Полный отчёт пентеста": "full",
    "Краткая сводка": "brief",
    Данные: "data",
    "Для руководства": "executive",
    "КСЗІ / Соответствие": "compliance",
    "Лабораторная работа": "lab",
  };
  const tplTitle = h => {
    const id = (h.opts && (h.opts.tpl_id || h.opts.template)) || TPL_TITLE_RU[h.tpl];
    const t = TPLS.find(x => x.id === id);
    return t ? t.t : h.tpl;
  };
  const TPL_FMTS = {
    full: ["pdf", "html", "docx", "md"],
    brief: ["md", "html", "pdf", "docx"],
    data: ["csv", "json"],
    executive: ["pdf", "html", "docx", "md"],
    compliance: ["pdf", "html", "docx", "md"],
    lab: ["pdf", "html", "docx", "md"],
  };
  // Short labels of the template chips in the builder.
  const TPL_SHORT = {
    get full() {
      return F.t("reports.short_full", "Полный");
    },
    get brief() {
      return F.t("reports.short_brief", "Сводка");
    },
    get data() {
      return F.t("reports.short_data", "Данные");
    },
    get executive() {
      return F.t("reports.short_executive", "Руководство");
    },
    get compliance() {
      return F.t("reports.short_compliance", "КСЗІ");
    },
    get lab() {
      return F.t("reports.short_lab", "Лабораторная");
    },
  };
  // Templates with a fixed structure: sections are not configurable, the core lays them out itself.
  const FIXED_TPL_RU = {
    executive: [
      "Риск-скор и уровень риска",
      "Пять главных находок простым языком",
      "Три первоочередных действия",
    ],
    compliance: [
      "Таблица находка × MITRE ATT&CK v20 / CWE / OWASP Top 10:2025 / WSTG / ISO 27001 / NIST · НД ТЗІ 3.6-006-24 / НД ТЗІ / КСЗІ",
      "Сводки по каждому стандарту",
      "Оговорка аудитора",
    ],
    lab: [
      "Цель и методика",
      "Исходные данные и ход работы",
      "Таблица находок со стандартами",
      "Выводы, поля «Выполнил / Проверил»",
    ],
  };
  // Outline texts in the UI language (the RU preview keeps FIXED_TPL_RU).
  const FIXED_TPL = Object.fromEntries(Object.keys(FIXED_TPL_RU).map(id => [id, null]));
  Object.keys(FIXED_TPL_RU).forEach(id =>
    Object.defineProperty(FIXED_TPL, id, {
      enumerable: true,
      get: () => FIXED_TPL_RU[id].map((x, i) => F.t(`reports.fixed_${id}_${i}`, x)),
    }),
  );
  // Core template id of a builder template (brief/data are UI-only selections of the full report).
  const coreTpl = id => (id === "full" || FIXED_TPL[id] ? id : null);
  // Template titles and descriptions from the core (report_templates) per report language.
  const coreTpls = {};
  function coreTplsOf(lang) {
    const L = lang === "UA" || lang === "EN" ? lang : "RU";
    if (!coreTpls[L]) {
      coreTpls[L] = { list: null };
      F.api
        .report_templates(L)
        .then(list => {
          coreTpls[L].list = Array.isArray(list) ? list : [];
          if (F.cur && F.cur.path === "/p/report-new") F.render(true);
        })
        .catch(() => {
          coreTpls[L].list = [];
        });
    }
    return coreTpls[L].list || [];
  }
  // Report history lives in F.db.reports (api.js keeps F.state.reports.history in sync).
  const reps = (F.state.reports = F.state.reports || { history: [], d: null });
  const LEGACY_COMPANY = "ТОВ «Кібер Аудит»"; // Former hard-coded sample executor.
  const defCompany = () => String((((F.db && F.db.settings) || {}).report || {}).company || "");
  const draft0 = (tpl = "full") => ({
    tpl,
    fmt: (TPLS.find(t => t.id === tpl) || TPLS[0]).fmt,
    sec: {
      summary: true,
      scope: true,
      findings: true,
      fixed: tpl !== "data",
      people: tpl === "full",
      infra: tpl !== "brief",
      docs: tpl === "full",
      log: false,
      appx: tpl === "full",
    },
    // Default filter is "everything except false positives" (right after a scan findings are "new", so
    // "confirmed only" would produce an empty report).
    v: 2,
    confirmed: false,
    minSev: "all",
    pickedOnly: false,
    // Report language follows the effective UI language (auto = device locale).
    lang: (F.i18n && F.i18n.uiCode && F.i18n.uiCode()) || "RU",
    logo: true,
    // Executor name: the last one entered (settings.report.company), empty for a fresh install.
    company: defCompany(),
    // Full values by default; one switch masks personal data and secrets (applied by the core).
    mask: false,
    custody: false,
    // Include the project's latest AI summary ("Executive summary (AI-assisted)"); the core adds the section
    // only when a summary was created, so the default is on.
    aiSummary: true,
    secTouched: false,
  });
  // The builder draft is stored in settings (settings.report.draft[project]) and survives reloads and
  // re-entry. The executor name is shared by all projects (settings.report.company).
  const projId = () => (F.db.project && F.db.project.id) || "";
  const clone = o => JSON.parse(JSON.stringify(o));
  function loadDraft() {
    const saved = (((F.db.settings || {}).report || {}).draft || {})[projId()];
    if (!saved || !saved.tpl) return draft0();
    const base = draft0(saved.tpl);
    const d = { ...base, ...clone(saved), sec: { ...base.sec, ...(saved.sec || {}) } };
    if (d.company === LEGACY_COMPANY) d.company = defCompany();
    // Drafts before v2 stored old filter defaults (confirmed: true, minSev: low); reset them to "everything
    // except false positives".
    if (!(saved.v >= 2)) {
      d.v = 2;
      d.confirmed = base.confirmed;
      d.minSev = base.minSev;
    }
    return d;
  }
  let saveT = null;
  const saveDraft = () => {
    clearTimeout(saveT);
    const id = projId(),
      d = clone(reps.d);
    saveT = setTimeout(() => {
      if (id) F.api.settings_set({ report: { draft: { [id]: d } } });
    }, 250);
  };
  const D0 = () => {
    if (!reps.d || reps.d.__p !== projId()) {
      reps.d = loadDraft();
      Object.defineProperty(reps.d, "__p", { value: projId(), enumerable: false });
    }
    return reps.d;
  };
  const setDraft = d => {
    reps.d = d;
    Object.defineProperty(reps.d, "__p", { value: projId(), enumerable: false });
    saveDraft();
  };
  F.on("db", e => {
    if (e.kind === "project" || e.kind === "reset") reps.d = null;
  });
  const FMT_L = {
    pdf: "PDF",
    html: "HTML",
    docx: "DOCX",
    md: "Markdown",
    csv: "CSV",
    json: "JSON",
  };
  const EXT_CLS = {
    pdf: "pdf",
    html: "odt",
    docx: "docx",
    md: "lnk",
    csv: "xlsx",
    json: "pptx",
    txt: "lnk",
    zip: "jpg",
    graphml: "docx",
  };
  const extTag = f => `<span class="ext ${EXT_CLS[f] || "lnk"}">${f === "md" ? "md" : f}</span>`;
  // Sizes arrive as Russian strings ("4,8 МБ"); localize the unit and decimal mark for display.
  const sizeOf = h => {
    const v = h.size && h.size !== "-" ? h.size : (h.opts && h.opts.size) || "-";
    if (!/[КМГ]Б$/.test(v)) return v;
    const unit = { КБ: F.t("reports.kb", "КБ"), МБ: F.t("reports.mb", "МБ"), ГБ: F.t("reports.gb", "ГБ") };
    return v.replace(/(\d),(\d)/, isEn() ? "$1.$2" : "$1,$2").replace(/([КМГ]Б)$/, m => unit[m]);
  };

  function renderReports() {
    const rq = F.sel.requests();
    return `
      ${ui.secH(F.t("reports.templates", "Шаблоны"))}
      <div class="rp-tpls">${TPLS.map(t => {
        const pg = pagesEst(draft0(t.id));
        return `
        <div class="card rp-tpl tap" role="button" data-act="rp-tpl:${t.id}">
          <div class="rp-tpl-ic">${ic(t.icon)}</div>
          <div class="rp-tpl-b">
            <div class="rp-tpl-t"><b>${t.t}</b></div>
            <div class="rp-tpl-f">${t.f.map(x => `<span class="pill mute">${x}</span>`).join("")}<span class="muted">${pg ? `~${plural(pg, "reports.pl_page", "страница", "страницы", "страниц")}` : F.t("reports.n_tables", "9 таблиц")}</span></div>
            <div class="rp-tpl-d">${t.d}</div>
          </div>
          ${ic("chev", "chev")}
        </div>`;
      }).join("")}</div>

      ${ui.secH(F.t("reports.quick_export", "Быстрый экспорт"))}
      <div class="grid g2 rp-quick">
        ${[
          [
            "rp-dict",
            F.t("reports.q_dict", "Словари"),
            F.t("reports.q_dict_s", "логины, e-mail, пути"),
            "rp-quick:dict",
          ],
          [
            "rp-csv",
            F.t("reports.q_csv", "CSV всего"),
            F.t("reports.q_csv_s", "9 таблиц в архиве"),
            "rp-quick:csv",
          ],
          ["rp-json", "STIX 2.1", F.t("reports.q_stix_s", "бандл для MISP / OpenCTI"), "rp-quick:stix"],
          ["rp-dict", "Nuclei / httpx", F.t("reports.q_nuclei_s", "списки URL и хостов"), "rp-quick:nuclei"],
          ["graph", "Maltego", F.t("reports.q_maltego_s", "сущности и связи"), "rp-quick:maltego"],
          [
            "log",
            F.t("reports.kind_log", "Журнал запросов"),
            rq.total == null
              ? F.sel.scans().length
                ? "-"
                : F.t("reports.no_scans", "сканов ещё не было")
              : rq.total
                ? plural(rq.total, "reports.pl_request", "запрос", "запроса", "запросов")
                : F.t("reports.no_requests", "запросов нет"),
            "rp-quick:log",
          ],
        ]
          .map(
            ([i, t, s, a]) => `
          <button class="card rp-qt tap"
            data-act="${a}">${ui.leadIcon(i)}<span class="rp-qt-b"><b>${esc(t)}</b><small>${esc(s)}</small></span></button>`,
          )
          .join("")}
      </div>

      ${ui.secH(F.t("reports.history", "История"), reps.history.length || "")}
      ${
        reps.history.length
          ? `<div class="list rp-hist">${reps.history
              .map(
                h => `
        <div class="row tap rp-hrow" data-act="rp-open:${h.id}">
          ${extTag(h.fmt)}
          <div class="body"><div class="t">${esc(h.name)}</div><div class="s">${esc(tplTitle(h))} · ${FMT_L[h.fmt] || h.fmt}${h.lang && h.lang !== "-" ? " · " + h.lang : ""}</div><div class="s">${esc(h.date)} · ${esc(sizeOf(h))}</div></div>
          <button class="ib rp-hmore" data-act="rp-hmenu:${h.id}"
            aria-label="${esc(F.t("reports.report_actions", { name: h.name }, "Действия с отчётом {name}"))}">${ic("more")}</button>
        </div>`,
              )
              .join("")}</div>`
          : `<div class="card pad rp-hempty">${ic("history")}<span>${esc(F.t("reports.hist_empty", "Сформированные отчёты появятся здесь."))}</span></div>`
      }
      <p class="fhint rp-hint">${ic("lock")} ${esc(F.t("reports.hist_enc", "Отчёты хранятся в зашифрованном хранилище проекта."))}</p>`;
  }

  F.route("/p/reports", {
    title: () => F.t("reports.title", "Отчёты"),
    tab: "reports",
    fab: () => ({ icon: "plus", label: F.t("reports.new_report", "Новый отчёт"), act: "rp-new" }),
    render: () =>
      F.withStates(renderReports, {
        loading: "cards",
        empty: {
          icon: "report",
          title: F.t("reports.empty_title", "Отчётов пока нет"),
          text: F.t(
            "reports.empty_text",
            "Выберите шаблон, отметьте разделы и сформируйте первый отчёт по проекту.",
          ),
          action: `<button class="btn primary" data-act="rp-new">${ic("plus")}${esc(F.t("reports.new_report", "Новый отчёт"))}</button>`,
        },
        error: {
          title: F.t("reports.err_title", "Не удалось открыть отчёты"),
          text: F.t("reports.err_text", "Хранилище проекта недоступно. Попробуйте снова."),
        },
      }),
    mount(page) {
      page.classList.add("rp-pg");
    },
  });

  // Template switch: changes the template, the format (if unavailable) and the default sections, but only
  // those not edited by hand.
  function switchTpl(id, snack = true) {
    const d = D0();
    if (d.tpl === id) return;
    const n = { ...d, tpl: id, fmt: TPL_FMTS[id].includes(d.fmt) ? d.fmt : draft0(id).fmt };
    if (!d.secTouched) n.sec = draft0(id).sec;
    setDraft(n);
    if (snack && d.secTouched)
      F.snack(F.t("reports.kept_sections", "Ваши разделы и фильтры сохранены"), {
        label: F.t("reports.tpl_sections", "Разделы шаблона"),
        action: () => {
          setDraft({ ...D0(), sec: draft0(id).sec, secTouched: false });
          F.render(true);
        },
      });
  }
  const findHist = id => reps.history.find(h => h.id === +id);
  // Saved report parameters → draft (preview from history, "Build again").
  const tplIdOf = h =>
    (h.opts && h.opts.tpl_id) ||
    (
      TPLS.find(t => t.t === h.tpl) || {
        id: h.fmt === "md" ? "brief" : h.fmt === "csv" || h.fmt === "json" ? "data" : "full",
      }
    ).id;
  function draftOf(hist) {
    const opts = hist.opts || {};
    const base = draft0(tplIdOf(hist));
    return {
      ...base,
      fmt: hist.fmt || base.fmt,
      lang: hist.lang && hist.lang !== "-" ? hist.lang : base.lang,
      minSev: opts.min_sev || "all",
      confirmed: !!opts.confirmed,
      pickedOnly: !!opts.picked_only,
      picked: opts.picked || null,
      sec: { ...base.sec, ...(opts.sections || {}) },
      mask: !!opts.mask,
      company: opts.company ?? base.company,
      logo: opts.logo ?? base.logo,
      custody: !!(opts.custody || hist.custody),
      aiSummary: opts.ai_summary !== false,
    };
  }
  let delT = null;
  Object.assign(F.actions, {
    "rp-new": () => {
      D0();
      F.go("/p/report-new");
    },
    "rp-tpl": id => {
      switchTpl(id);
      F.go("/p/report-new");
    },
    "rp-quick": q => {
      if (q === "dict")
        F.exportSheet({ kind: "users", fmt: "dict", title: F.t("reports.q_dict", "Словари") });
      if (q === "csv")
        F.exportSheet({ kind: "all", fmt: "csv", title: F.t("reports.q_csv_t", "CSV всего проекта") });
      if (q === "stix")
        F.exportSheet({ kind: "all", fmt: "stix", title: F.t("reports.q_stix_t", "Экспорт STIX 2.1") });
      if (q === "nuclei")
        F.exportSheet({
          kind: "hosts",
          fmt: "nuclei",
          title: F.t("reports.q_nuclei_t", "Цели для Nuclei / httpx"),
        });
      if (q === "maltego")
        F.exportSheet({
          kind: "all",
          fmt: "maltego",
          title: F.t("reports.q_maltego_t", "Экспорт для Maltego"),
        });
      if (q === "log")
        F.exportSheet({ kind: "log", fmt: "csv", title: F.t("reports.kind_log", "Журнал запросов") });
    },
    "rp-open": id => {
      const h = findHist(id);
      if (!h) return;
      // CSV/JSON have no in-app preview: hand the file to another app via the system chooser.
      if (h.fmt === "csv" || h.fmt === "json") return shareReport(h);
      reps.prevOf = h;
      F.go("/p/report-preview");
    },
    "rp-hmenu": (id, el, e) => {
      e && e.stopPropagation();
      const hist = findHist(id);
      if (!hist) return;
      F.sheet({
        cls: "rp-sheet",
        html: `<div class="rp-shh">${extTag(hist.fmt)}<div class="rp-shh-b"><b>${esc(hist.name)}</b><span>${esc(hist.date)} · ${esc(sizeOf(hist))}</span></div></div>
          <div class="srow"
            data-act="rp-h-open:${hist.id}">${ic("open")}<span class="lbl">${esc(F.t("common.open", "Открыть"))}</span></div>
          <div class="srow"
            data-act="rp-h-share:${hist.id}">${ic("share")}<span class="lbl">${esc(F.t("reports.share", "Поделиться…"))}</span></div>
          ${
            hist.fmt === "pdf" || isHtmlName(hist.name)
              ? `<div class="srow"
            data-act="rp-h-pdf:${hist.id}">${ic("download")}<span class="lbl">${esc(F.t("report.pdf.history", "Получить PDF"))}<small>A4</small></span></div>`
              : ""
          }
          <div class="srow"
            data-act="rp-h-verify:${hist.id}">${ic("shield")}<span class="lbl">${esc(F.t("reports.verify_sig", "Проверить подпись / SHA-256"))}<small>Chain of Custody (.sha256 / .sig.json)</small></span></div>
          ${
            F.isTauri
              ? `<div class="srow"
            data-act="rp-h-save:${hist.id}">${ic("download")}<span class="lbl">${esc(F.t("reports.save_files", "Сохранить в файлы"))}<small>${esc(F.t("reports.dl_path", "Загрузки › FOCA-rs"))}</small></span></div>`
              : ""
          }
          <div class="srow"
            data-act="rp-h-again:${hist.id}">${ic("refresh")}<span class="lbl">${esc(F.t("reports.rebuild", "Сформировать заново"))}<small>${esc(F.t("reports.rebuild_sub", "С теми же параметрами и актуальными находками"))}</small></span></div>
          <div class="srow rp-del"
            data-act="rp-h-del:${hist.id}">${ic("trash")}<span class="lbl">${esc(F.t("common.delete", "Удалить"))}</span></div>`,
      });
    },
    "rp-h-verify": id => {
      const VERIFY_STATUS = {
        verified_signed: [
          F.t("report.verify.verified_signed", "Подпись устройства и SHA-256 подтверждены"),
          "ok",
          "check",
        ],
        verified_hash: [
          F.t("report.verify.verified_hash", "Контрольная сумма SHA-256 подтверждена"),
          "ok",
          "check",
        ],
        tampered: [
          F.t("report.verify.tampered", "Внимание: файл изменён. SHA-256 или подпись не совпадают!"),
          "crit",
          "alert",
        ],
        unsigned: [
          F.t("report.verify.unsigned", "Нет файла .sha256 и подписи, проверить целостность нечем"),
          "warn",
          "info",
        ],
        verified_foreign: [
          F.t(
            "report.verify.verified_foreign",
            "Подпись верна, но ключ не ваш. Отчёт подписан на другом устройстве",
          ),
          "ok",
          "shield",
        ],
        missing: [F.t("report.verify.missing", "Файл отчёта отсутствует на диске"), "crit", "alert"],
      };
      const h = findHist(id);
      F.closeSheet();
      if (!h) return;
      F.api
        .report_verify(h.id)
        .then(r => {
          // Statuses of the core's report_verify: verified_signed, verified_foreign (valid signature made
          // with another device's key), verified_hash, tampered, unsigned, missing.
          const [stLabel, tone, icon] = VERIFY_STATUS[r.status] || [
            F.t("report.verify.unknown", "Статус проверки: ") + r.status,
            "warn",
            "alert",
          ];
          const cust = r.custody;
          F.sheet({
            title: F.t("reports.verify_title", "Проверка целостности отчёта"),
            cls: "rp-sheet",
            html: `<div class="banner ${tone}" data-verify="${esc(r.status)}">${ic(icon)}<div><b>${esc(stLabel)}</b><div class="s">${esc(h.name)}</div></div></div>
              <div class="list rp-opts">
                <div class="row"><div class="body"><div class="t">${esc(F.t("reports.sha_report", "SHA-256 отчёта"))}</div><div class="s mono">${esc(r.actual_sha256 || r.sha256 || "-")}</div></div></div>
                ${r.expected_sha256 ? `<div class="row"><div class="body"><div class="t">${esc(F.t("reports.sha_expected", "Ожидаемый SHA-256 (.sha256)"))}</div><div class="s mono">${esc(r.expected_sha256)}</div></div></div>` : ""}
                ${cust ? `<div class="row"><div class="body"><div class="t">${esc(F.t("reports.cust_digest", "Дайджест входных данных (Chain of Custody)"))}</div><div class="s mono">${esc(cust.inputs_sha256 || cust.inputs_digest || "-")}</div><div class="s">${esc(F.t("reports.cust_counts", { f: cust.findings_total ?? cust.findings_count ?? "-", d: cust.docs_total ?? cust.docs_count ?? "-" }, "Находок: {f} · Документов: {d}"))}</div></div></div>` : ""}
                ${r.signature_alg ? `<div class="row"><div class="body"><div class="t">${esc(F.t("reports.dev_sig", { alg: r.signature_alg }, "Подпись устройства ({alg})"))}</div><div class="s mono">${esc(F.t("reports.key_alias", { k: r.key_alias || "AndroidKeyStore" }, "Ключ: {k}"))}</div>${r.key_fingerprint ? `<div class="s">${esc(r.signature_own_key === false ? F.t("report.verify.fp_foreign", "Отпечаток чужого ключа (SHA-256):") : F.t("report.verify.fp", "Отпечаток ключа (SHA-256):"))}</div><div class="s mono rp-fp" data-fp="${esc(r.key_fingerprint)}">${esc(String(r.key_fingerprint).replace(/(.{4})(?=.)/g, "$1 "))}</div>` : ""}</div></div>` : ""}
              </div>`,
            footer: `<button class="btn primary" data-act="sheet-close">${esc(F.t("reports.got_it", "Понятно"))}</button>`,
          });
        })
        .catch(e => F.snack(F.t("reports.verify_err", "Ошибка проверки: ") + (e.message || e)));
    },
    "rp-h-open": id => {
      F.closeSheet();
      F.actions["rp-open"](id);
    },
    "rp-h-share": id => {
      const h = findHist(id);
      F.closeSheet();
      setTimeout(() => shareReport(h), 260);
    },
    "rp-h-save": id => {
      const h = findHist(id);
      F.closeSheet();
      if (h) nativeSave({ report: h.id, name: h.name });
    },
    "rp-h-again": id => {
      const h = findHist(id);
      F.closeSheet();
      const d = draftOf(h);
      delete d.picked;
      d.secTouched = !!(h.opts && h.opts.sections);
      setDraft(d);
      F.go("/p/report-new");
    },
    "rp-h-del": id => {
      const i = reps.history.findIndex(h => h.id === +id);
      if (i < 0) return;
      const hist = reps.history.splice(i, 1)[0];
      F.closeSheet();
      F.render(true);
      clearTimeout(delT);
      delT = setTimeout(() => F.api.report_delete(hist.id), 4200); // Deletion in the core happens after the Undo window.
      F.snack(F.t("reports.deleted", { name: hist.name }, "Отчёт «{name}» удалён"), {
        action: () => {
          clearTimeout(delT);
          reps.history.splice(i, 0, hist);
          F.render(true);
        },
      });
    },
  });

  // ================= BUILDER /p/report-new =================
  const SECTIONS = [
    ["summary", "Сводка", "Резюме для руководства, общий риск"],
    ["scope", "Скоуп", "Цели, исключения, основание проверки"],
    ["findings", "Находки", "С доказательствами и рекомендациями"],
    ["fixed", "Исправленные", "Отдельный раздел: устранено к моменту отчёта"],
    ["people", "Люди", "Сотрудники, логины, e-mail"],
    ["infra", "Инфраструктура", "Хосты, домены, ПО и версии, найденное на сайте"],
    ["docs", "Документы", "Источники метаданных"],
    ["log", "Журнал запросов", "Что и когда запрашивал сканер"],
    ["appx", "Приложения", "Снимки, хеши, методика"],
  ];
  const SEVF = () => [
    ["all", F.t("reports.sevf_all", "Все")],
    ["low", F.t("reports.sevf_low", "Низкий+")],
    ["warn", F.t("reports.sevf_warn", "Средний+")],
    ["high", F.t("reports.sevf_high", "Высокий+")],
    ["crit", F.t("reports.sevf_crit", "Критичные")],
  ];
  const sel = d =>
    F.sel.reportFindings({
      confirmed: d.confirmed,
      min_sev: d.minSev,
      picked_only: d.pickedOnly,
      picked: d.picked || undefined,
    });
  const fFindings = d => sel(d).main;
  const fFixed = d => (d.sec.fixed ? sel(d).fixed : []);
  // Same formula as foca-report `pages_estimate`: the short summary lists findings as table rows.
  const pagesFull = draft => {
    if (draft.fmt === "csv" || draft.fmt === "json") return null;
    const s = draft.sec;
    const brief = draft.tpl === "brief";
    const w = brief ? [1, 0.5, 0.5, 0.04, 0.03, 2, 2, 3, 6, 2, 1] : [3, 2, 2, 1.6, 0.5, 4, 5, 6, 12, 4, 2];
    const raw =
      w[0] +
      (s.summary ? w[1] : 0) +
      (s.scope ? w[2] : 0) +
      (s.findings ? fFindings(draft).length * w[3] : 0) +
      (s.fixed ? fFixed(draft).length * w[4] : 0) +
      (s.people ? w[5] : 0) +
      (s.infra ? w[6] : 0) +
      (s.docs ? w[7] : 0) +
      (s.log ? w[8] : 0) +
      (s.appx ? w[9] : 0);
    return Math.max(w[10], Math.round(raw));
  };
  const pagesEst = draft =>
    draft.tpl === "executive"
      ? draft.fmt === "csv" || draft.fmt === "json"
        ? null
        : 1
      : FIXED_TPL[draft.tpl]
        ? Math.max(2, Math.round((draft.tpl === "lab" ? 3 : 2) + fFindings(draft).length * 0.3))
        : pagesFull(draft);
  const segH = (key, opts, cur) =>
    `<div class="seg" role="radiogroup">${opts
      .map(
        ([v, l]) => `<button class="${cur === v ? "on" : ""}"
      role="radio" aria-checked="${cur === v}" data-act="rp-d:${key}:${v}">${l}</button>`,
      )
      .join("")}</div>`;
  // A secret from finding evidence ({{s:…}}) as the core renders it (masked only with the option on).
  const secretsOf = f =>
    String(f.evidence || "")
      .split("{{s:")
      .slice(1)
      .map(x => x.split("}}")[0]);
  const maskAs = (v, mask) => {
    if (!mask) return v;
    return v.length > 6 ? v.slice(0, 2) + "••••••" + v.slice(-3) : "••••••";
  };
  const sampleSecret = () => {
    const f = F.db.findings.find(x => secretsOf(x).length);
    return f ? secretsOf(f)[0] : (F.db.secrets[0] || {}).value || "";
  };

  // "The report will include: …": what the current filters select; with zero findings, explains why.
  function incl(draft) {
    const db = F.db,
      sl = sel(draft),
      n = draft.sec.findings ? sl.main.length : 0;
    const docs = draft.sec.docs ? F.sel.docsLive().length : 0,
      ppl = draft.sec.people ? (db.people || []).length : 0,
      hosts = draft.sec.infra ? (db.hosts || []).length : 0;
    const parts = [plural(n, "reports.pl_finding", "находка", "находки", "находок")];
    if (draft.sec.docs) parts.push(plural(docs, "reports.pl_doc", "документ", "документа", "документов"));
    if (draft.sec.people) parts.push(plural(ppl, "reports.pl_person", "человек", "человека", "человек"));
    if (draft.sec.infra) parts.push(plural(hosts, "reports.pl_host", "хост", "хоста", "хостов"));
    let why = "";
    const live = (db.findings || []).filter(F.sel.isLive);
    if (!n && live.length) {
      if (!draft.sec.findings) why = F.t("reports.why_off", "раздел «Находки» выключен");
      else if (draft.pickedOnly) why = F.t("reports.why_picked", "включено «Только выбранные»");
      else if (draft.confirmed && !live.some(f => f.status === "confirmed"))
        why = F.t(
          "reports.why_conf",
          {
            n: plural(
              live.length,
              "reports.pl_finding_new",
              "находка новая",
              "находки новые",
              "находок новые",
            ),
          },
          "включено «Только подтверждённые», а подтверждённых нет ({n})",
        );
      else if (draft.minSev !== "all") why = F.t("reports.why_sev", "все находки ниже выбранной важности");
      else why = F.t("reports.why_flt", "фильтры исключили все находки");
    }
    return `<p class="fhint rp-hint rp-incl">${ic("info")} ${esc(F.t("reports.included", { list: parts.join(", ") }, "В отчёт войдут: {list}."))}${why ? ` <b>${esc(F.t("reports.zero_why", { why }, "Находок 0: {why}."))}</b>` : ""}</p>`;
  }

  function renderNew() {
    if (!F.db.findings.length && !F.sel.scans().length)
      return ui.empty({
        icon: "bug",
        title: F.t("reports.nothing_title", "Нечего включить в отчёт"),
        text: F.t("reports.nothing_text", "В проекте пока нет находок и данных. Запустите скан."),
        action: `<button class="btn tonal" data-act="go:/new">${ic("play")}${esc(F.t("reports.new_scan", "Новый скан"))}</button>`,
      });
    const draft = D0();
    const n = fFindings(draft).length;
    const nf = fFixed(draft).length;
    const pg = pagesEst(draft);
    const tpl = TPLS.find(t => t.id === draft.tpl) || TPLS[0];
    const fmts = TPL_FMTS[draft.tpl].map(f => [f, FMT_L[f]]);
    const secN = Object.values(draft.sec).filter(Boolean).length;
    const pk = F.sel.reportPicked().length;
    const sx = sampleSecret();
    const ct = coreTpl(draft.tpl) && coreTplsOf(draft.lang).find(t => t.id === coreTpl(draft.tpl));
    const fixed = FIXED_TPL[draft.tpl];
    return `
      <h3 class="sub-h rp-h3">${esc(F.t("reports.template", "Шаблон"))}</h3>
      <div class="chips wrap rp-tplc" role="radiogroup" aria-label="${esc(F.t("reports.tpl_aria", "Шаблон отчёта"))}">${TPLS.map(
        t => `<button class="chip ${draft.tpl === t.id ? "on" : ""}" role="radio"
        aria-checked="${draft.tpl === t.id}" data-act="rp-d:tpl:${t.id}">${TPL_SHORT[t.id]}</button>`,
      ).join("")}</div>
      <div class="card pad rp-tpl-desc"><b>${esc(ct ? ct.title : tpl.t)}</b><p class="rp-tpl-hint">${esc(ct ? ct.description : tpl.d)}</p>${ct ? `<small class="muted">${esc(F.t("reports.tpl_desc_lang", "Описание шаблона на языке отчёта"))} · ${esc(draft.lang)}</small>` : ""}</div>

      <h3 class="sub-h rp-h3">${esc(F.t("reports.format", "Формат"))}</h3>
      ${segH("fmt", fmts, draft.fmt)}
      ${draft.fmt === "pdf" ? `<p class="fhint rp-pdf-hint">${F.isTauri ? F.t("report.pdf.hint", "PDF: отчёт собирается в HTML и сразу сохраняется PDF-файлом (A4), который можно отправить или сохранить в «Загрузки». Если не получится, откроется системная печать.") : F.t("report.pdf.hint_web", "PDF-файл создаётся на Android. Здесь (без Android) сохранится HTML с печатными стилями. Откройте его в браузере и напечатайте в PDF.")}</p>` : ""}

      ${
        fixed
          ? `<h3 class="sub-h rp-h3">${esc(F.t("reports.tpl_structure", "Структура шаблона"))}</h3>
      <ul class="card pad rp-fixed">${fixed.map(x => `<li>${esc(x)}</li>`).join("")}</ul>
      <p class="fhint rp-hint">${ic("info")}<span>${esc(F.t("reports.fixed_hint", "Разделы фиксированы шаблоном; фильтры находок, язык и шапка ниже применяются."))}</span>${F.helpBtn ? F.helpBtn("report-templates", F.t("reports.tpl_help", "Шаблоны отчётов")) : ""}</p>`
          : `<h3 class="sub-h rp-h3">${esc(F.t("reports.sections", "Разделы"))} <span class="muted">${esc(F.t("reports.n_of_m", { n: secN, m: SECTIONS.length }, "{n} из {m}"))}</span></h3>
      <div class="list rp-secs">${SECTIONS.map(([k, t, s]) => ui.check(draft.sec[k], esc(F.t(`reports.sec_${k}`, t)), `rp-sec:${k}`, esc(F.t(`reports.sec_${k}_sub`, s)))).join("")}</div>`
      }
      ${draft.fmt === "csv" || draft.fmt === "json" ? "" : `<div class="list rp-ai">${ui.check(draft.aiSummary !== false, F.t("reports.ai_sum", "Резюме для руководства (с помощью ИИ)"), "rp-ai", F.t("reports.ai_sum_sub", "Последнее ИИ-резюме проекта с пометкой об источнике; если резюме не создавалось, раздел не добавляется"))}${draft.aiSummary !== false ? rpAiRow() : ""}</div>`}

      <h3 class="sub-h rp-h3">${esc(F.t("reports.in_report", "Находки в отчёте"))} <span class="muted">${plural(n, "reports.pl_finding", "находка", "находки", "находок")}${nf ? ` + ${esc(F.t("reports.n_fixed", { n: nf }, "{n} испр."))}` : ""}</span></h3>
      <div class="list rp-opts">${ui.check(draft.confirmed, F.t("reports.conf_only", "Только подтверждённые"), "rp-conf", F.t("reports.conf_only_sub", "Новые и принятые риски не попадут в отчёт; ложные: никогда"))}${pk ? ui.check(draft.pickedOnly, F.t("reports.picked_only", { n: pk }, "Только выбранные ({n})"), "rp-picked", F.t("reports.picked_sub", "Отмечены «Добавить в отчёт» в находках")) : `<div class="row rp-tg rp-pk0"><div class="body"><div class="t">${esc(F.t("reports.picked_0", "Только выбранные (0)"))}</div><div class="s">${esc(F.t("reports.picked_0_sub", "Отметьте находки через «Добавить в отчёт», здесь появится выборка"))}</div></div></div>`}</div>
      ${(() => {
        const out =
          draft.pickedOnly && draft.confirmed
            ? F.db.findings.filter(f => F.sel.reportPicked().includes(f.id) && f.status !== "confirmed")
                .length
            : 0;
        return out
          ? `<p class="fhint rp-hint">${ic("info")} ${esc(out === 1 ? F.t("reports.sel_unconf_1", "Из выборки 1 находка не подтверждена и не попадёт в отчёт, пока включено «Только подтверждённые».") : F.t("reports.sel_unconf_n", { n: out }, "Из выборки {n} не подтверждены и не попадёт в отчёт, пока включено «Только подтверждённые»."))}</p>`
          : "";
      })()}
      <label class="flabel">${esc(F.t("reports.sev_from", "Важность от"))}</label>
      <div class="chips wrap rp-sevf"
        role="radiogroup">${SEVF()
          .map(
            ([v, l]) => `<button class="chip ${draft.minSev === v ? "on" : ""}"
        role="radio" aria-checked="${draft.minSev === v}"
        data-act="rp-d:minSev:${v}">${l}</button>`,
          )
          .join("")}</div>
      ${incl(draft)}

      <h3 class="sub-h rp-h3">${esc(F.t("reports.report_lang", "Язык отчёта"))}</h3>
      ${segH(
        "lang",
        [
          ["RU", "Русский"],
          ["UA", "Українська"],
          ["EN", "English"],
        ],
        draft.lang,
      )}

      <h3 class="sub-h rp-h3">${esc(F.t("reports.header", "Шапка"))}</h3>
      <div class="list rp-opts">
        ${(() => {
          const l = logoOf();
          const thumb = l
            ? `<img src="${esc(l.data)}" alt="">`
            : draft.logo
              ? `<span>${esc(initials(draft.company))}</span>`
              : ic("camera");
          const sub = l
            ? `${esc(l.name)} · ${l.w}×${l.h} · ${kb(l.bytes / 1024)}`
            : esc(F.t("reports.not_chosen", "Не выбран"));
          return `<div class="row rp-tg rp-logorow"><div class="rp-logo${l ? " has-img" : ""}">${thumb}</div><div class="body"><div class="t">${esc(F.t("reports.logo", "Логотип исполнителя"))}</div><div class="s">${sub}</div></div><div class="tail"><button class="btn sm"
          data-act="rp-logo-pick">${esc(l ? F.t("reports.replace", "Заменить") : F.t("reports.choose", "Выбрать"))}</button>${l ? `<button class="btn sm text" data-act="rp-logo-del">${esc(F.t("reports.remove", "Убрать"))}</button>` : ""}</div></div>`;
        })()}
        ${ui.check(!!draft.logo, esc(F.t("reports.logo_in_report", "Логотип в отчёте")), "rp-logo", esc(F.t("reports.logo_in_report_sub", "В шапке и на титуле. Без картинки: инициалы компании")))}
      </div>
      <label class="flabel" for="rp-company">${esc(F.t("reports.company_l", "Исполнитель в колонтитуле"))}</label>
      <div class="field">${ic("contract")}<input id="rp-company" value="${esc(draft.company)}"
        placeholder="${esc(F.t("reports.company_ph", "Название компании"))}"></div>

      <h3 class="sub-h rp-h3">${esc(F.t("reports.privacy", "Конфиденциальность"))}</h3>
      <div class="list rp-opts">${ui.check(!!draft.mask, F.t("reports.mask_pd", "Маскировать персональные данные и секреты"), "rp-mask", F.t("reports.mask_pd_sub", "Телефоны, IBAN, РНОКПП, карты, e-mail, имена и секреты заменяются масками"))}</div>
      ${draft.mask && sx ? `<div class="rp-secx"><span class="muted">${esc(F.t("reports.example", "Пример:"))}</span> <span class="mono">${esc(maskAs(sx, true))}</span></div>` : ""}

      <h3 class="sub-h rp-h3">${esc(F.t("reports.custody_h", "Цепочка хранения (Chain of Custody) и подпись"))}</h3>
      <div class="list rp-opts">${ui.check(!!draft.custody, F.t("reports.custody", "Блок Chain of Custody и ЭЦП"), "rp-custody", F.t("reports.custody_sub", "Дайджест входных данных, файл .sha256 и подпись ECDSA P-256 (.sig.json)"))}</div>

      <div class="foot rp-foot">
        <div class="foot-s rp-foot-s">${FMT_L[draft.fmt]}${pg ? ` · ~${plural(pg, "reports.pl_page", "страница", "страницы", "страниц")}` : ""} · ${plural(n, "reports.pl_finding", "находка", "находки", "находок")}</div>
        <div class="btnrow"><button class="btn" data-act="rp-preview"
          ${draft.fmt === "csv" || draft.fmt === "json" ? "disabled" : ""}>${ic("eye")}${esc(F.t("reports.preview_btn", "Просмотр"))}</button><button class="btn primary"
          data-act="rp-build">${ic("report")}${esc(F.t("reports.build", "Сформировать"))}</button></div>
      </div>`;
  }
  // Logo initials as in foca-report (html.rs initials): quotes and legal-form words are skipped,
  // e.g. TOV "Kiber Audyt" → KA.
  const ORG_FORMS = new Set([
    "тов",
    "тоо",
    "ооо",
    "пат",
    "ат",
    "прат",
    "пао",
    "зао",
    "оао",
    "фоп",
    "чп",
    "пп",
    "ип",
    "llc",
    "ltd",
    "inc",
    "gmbh",
    "corp",
    "plc",
    "llp",
    "ag",
    "sa",
    "co",
  ]);
  const initials = s =>
    String(s || "")
      .split(/[\s,]+/)
      .map(w => w.replace(/^[^\p{L}\p{N}]+|[^\p{L}\p{N}]+$/gu, ""))
      .filter(w => w && !ORG_FORMS.has(w.toLowerCase()))
      .map(w => w[0])
      .join("")
      .slice(0, 2)
      .toUpperCase() || "-";

  // ---------- report logo (Settings → Report, report_logo_* in docs/API.md) ----------
  // The core keeps one logo per user. The picker is the system chooser of <input type=file> (on
  // Android the WebView opens the system file picker), the WebView downscales the picture to
  // LOGO_SIDE px and the core checks it again before saving.
  const LOGO_MAX_BYTES = 2 * 1024 * 1024;
  const LOGO_SIDE = 512;
  const LOGO_ACCEPT = "image/png,image/jpeg,image/webp,.png,.jpg,.jpeg,.webp";
  // undefined: not loaded yet; null: no logo; else { data, mime, name, w, h, bytes }.
  const logoOf = () => {
    if (reps.logo === undefined) {
      reps.logo = null;
      F.api
        .report_logo_get()
        .then(r => {
          reps.logo = (r && r.logo) || null;
          if (reps.logo && F.cur && /^\/p\/report-(new|preview)$/.test(F.cur.path)) F.render(true);
        })
        .catch(() => {});
    }
    return reps.logo;
  };
  // Image type by signature: SVG and everything else is refused (SVG can carry scripts).
  const sniffImage = b =>
    b[0] === 0x89 && b[1] === 0x50 && b[2] === 0x4e && b[3] === 0x47
      ? "image/png"
      : b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff
        ? "image/jpeg"
        : b[0] === 0x52 && b[1] === 0x49 && b[2] === 0x46 && b[3] === 0x46 && b[8] === 0x57 && b[9] === 0x45
          ? "image/webp"
          : "";
  const readAs = (file, how) =>
    new Promise((resolve, reject) => {
      const r = new FileReader();
      r.onload = () => resolve(r.result);
      r.onerror = () => reject(r.error);
      r[how](file);
    });
  const logoErr = (key, ru) => new Error(F.t(key, ru));
  // Checks a picked file and returns { data, name } ready for report_logo_set: PNG/JPEG up to
  // LOGO_SIDE px stay as they are, larger pictures and WebP are redrawn as PNG.
  async function prepareLogo(file) {
    if (file.size > LOGO_MAX_BYTES) throw logoErr("reports.logo_too_large", "Файл больше 2 МБ");
    const head = new Uint8Array(await readAs(file.slice(0, 16), "readAsArrayBuffer"));
    const mime = sniffImage(head);
    if (!mime) throw logoErr("reports.logo_format", "Подходят только PNG, JPEG и WebP");
    const src = await readAs(file, "readAsDataURL");
    const img = await new Promise((resolve, reject) => {
      const i = new Image();
      i.onload = () => resolve(i);
      i.onerror = () => reject(logoErr("reports.logo_broken", "Не удалось прочитать картинку"));
      i.src = src;
    });
    const w = img.naturalWidth;
    const h = img.naturalHeight;
    if (!w || !h) throw logoErr("reports.logo_broken", "Не удалось прочитать картинку");
    const keep = mime !== "image/webp" && Math.max(w, h) <= LOGO_SIDE;
    if (keep) return { data: `data:${mime};base64,${String(src).split(",")[1]}`, name: file.name };
    const k = Math.min(1, LOGO_SIDE / Math.max(w, h));
    const c = document.createElement("canvas");
    c.width = Math.max(1, Math.round(w * k));
    c.height = Math.max(1, Math.round(h * k));
    const g = c.getContext("2d");
    g.imageSmoothingQuality = "high";
    g.drawImage(img, 0, 0, c.width, c.height);
    const name = String(file.name || "logo").replace(/\.[^.]*$/, "") + ".png";
    return { data: c.toDataURL("image/png"), name };
  }
  function pickLogo() {
    const inp = document.createElement("input");
    inp.type = "file";
    inp.accept = LOGO_ACCEPT;
    inp.onchange = () => {
      const file = inp.files && inp.files[0];
      if (!file) return;
      prepareLogo(file)
        .then(x => F.api.report_logo_set(x))
        .then(r => {
          reps.logo = (r && r.logo) || null;
          D0().logo = true;
          saveDraft();
          F.snack(F.t("reports.logo_saved", "Логотип сохранён"));
          F.render(true);
        })
        .catch(e => F.snack(e.message));
    };
    inp.click();
  }
  // Logo markup for the preview: the saved image, else the initials (option on), else nothing.
  const logoMark = (draft, cls) => {
    if (!draft.logo) return "";
    const l = logoOf();
    if (l && l.data) return `<img class="${cls} rp-logoimg" src="${esc(l.data)}" alt="">`;
    return draft.company ? `<i class="${cls}">${esc(initials(draft.company))}</i>` : "";
  };

  F.route("/p/report-new", {
    title: () => F.t("reports.new_report", "Новый отчёт"),
    sub: () => (F.project ? F.project.name : ""),
    nav: false,
    back: true,
    hideMini: true,
    actions: [
      {
        icon: "refresh",
        act: "rp-reset",
        label: () => F.t("reports.reset_label", "Сбросить настройки отчёта"),
      },
    ],
    render: () =>
      F.withStates(renderNew, {
        loading: "cards",
        empty: {
          icon: "bug",
          title: F.t("reports.nothing_title", "Нечего включить в отчёт"),
          text: F.t(
            "reports.nothing_text2",
            "В проекте пока нет находок и данных. Запустите скан или снимите фильтры.",
          ),
          action: `<button class="btn tonal" data-act="go:/new">${ic("play")}${esc(F.t("reports.new_scan", "Новый скан"))}</button>`,
        },
      }),
    mount(page) {
      page.classList.add("rp-pg", "rp-nopb", "no-pb");
      rpAiLoad();
      const c = page.querySelector("#rp-company");
      if (c)
        c.addEventListener("input", () => {
          D0().company = c.value;
          saveDraft();
          clearTimeout(companyT);
          companyT = setTimeout(() => F.api.settings_set({ report: { company: c.value.trim() } }), 400);
        });
    },
  });

  // AI summary of the report: the project's history from the core, newest first; the one the
  // report uses is `report_id` (the latest by default, `ai_summary_use` picks another).
  let rpAi = null;
  const rpAiPid = () => (F.db.project || {}).id || "";
  const rpAiSet = r => {
    rpAi = { pid: rpAiPid(), items: r.items || [], report_id: r.report_id || null };
  };
  function rpAiLoad() {
    if (!F.api.ai_summaries_list) return;
    F.api.ai_summaries_list().then(
      r => {
        const was = JSON.stringify(rpAi);
        rpAiSet(r);
        if (JSON.stringify(rpAi) !== was && F.current() === "/p/report-new") F.render(true);
      },
      () => {},
    );
  }
  const rpAiWhen = iso => {
    const d = new Date(iso || "");
    return Number.isNaN(d.getTime())
      ? iso || ""
      : d.toLocaleString(F.i18n.lang() === "en" ? "en-GB" : F.i18n.lang() === "uk" ? "uk-UA" : "ru-RU", {
          day: "2-digit",
          month: "2-digit",
          year: "numeric",
          hour: "2-digit",
          minute: "2-digit",
        });
  };
  const rpAiLabel = e => [rpAiWhen(e.created), e.model].filter(Boolean).join(" · ");
  function rpAiRow() {
    const h = rpAi && rpAi.pid === rpAiPid() ? rpAi : null;
    if (!h || !h.items.length) return "";
    const cur = h.items.find(e => e.id === h.report_id);
    return `<div class="row tap rp-aipick" data-act="rp-aipick"><div class="body"><div class="t">${esc(F.t("reports.ai_pick", "Какая сводка"))}</div><div class="s">${esc(cur ? rpAiLabel(cur) : F.t("reports.ai_pick_none", "Не выбрана: раздел не добавится"))}</div></div>${ic("chev", "chev")}</div>`;
  }

  Object.assign(F.actions, {
    "rp-aipick": () => {
      const h = rpAi;
      if (!h || !h.items.length) return;
      F.choose({
        title: F.t("reports.ai_pick", "Какая сводка"),
        value: h.report_id,
        options: h.items.map((e, i) => ({
          v: e.id,
          t: rpAiLabel(e),
          s: i === 0 ? F.t("reports.ai_pick_latest", "последняя") : "",
        })),
        onPick: v =>
          F.api.ai_summary_use(v).then(
            r => {
              rpAiSet(r);
              F.render(true);
            },
            e => F.snack(F.t("ai.failed", "Не удалось: ") + e.message),
          ),
      });
    },
    "rp-d": a => {
      const [k, v] = a.split(":");
      if (k === "tpl") switchTpl(v);
      else {
        D0()[k] = v;
        saveDraft();
      }
      F.render(true);
    },
    "rp-sec": k => {
      const d = D0();
      d.sec[k] = !d.sec[k];
      d.secTouched = true;
      saveDraft();
      F.render(true);
    },
    "rp-conf": () => {
      const d = D0();
      d.confirmed = !d.confirmed;
      saveDraft();
      F.render(true);
    },
    "rp-ai": () => {
      const d = D0();
      d.aiSummary = d.aiSummary === false;
      saveDraft();
      F.render(true);
    },
    "rp-picked": () => {
      const d = D0();
      d.pickedOnly = !d.pickedOnly;
      saveDraft();
      F.render(true);
    },
    "rp-logo": () => {
      const d = D0();
      d.logo = !d.logo;
      saveDraft();
      F.render(true);
    },
    "rp-logo-pick": () => pickLogo(),
    "rp-logo-del": () =>
      F.api
        .report_logo_clear()
        .then(() => {
          reps.logo = null;
          F.snack(F.t("reports.logo_removed", "Логотип убран"));
          F.render(true);
        })
        .catch(e => F.snack(e.message)),
    "rp-custody": () => {
      const d = D0();
      d.custody = !d.custody;
      saveDraft();
      F.render(true);
    },
    "rp-preview": () => {
      reps.prevOf = null;
      F.go("/p/report-preview");
    },
    "rp-reset": () =>
      F.sheet({
        title: F.t("reports.reset_q", "Сбросить настройки?"),
        html: `<p class="lead">${esc(F.t("reports.reset_lead", "Шаблон, разделы, фильтры находок, язык и шапка вернутся к значениям по умолчанию."))}</p>`,
        footer: `<button class="btn"
          data-act="sheet-close">${esc(F.t("common.cancel", "Отмена"))}</button><button class="btn primary"
          data-act="rp-reset-go">${ic("refresh")}${esc(F.t("reports.reset", "Сбросить"))}</button>`,
      }),
    "rp-reset-go": () => {
      const keep = D0().company;
      setDraft({ ...draft0(), company: keep });
      F.closeSheet();
      F.render(true);
      F.snack(F.t("reports.reset_done", "Настройки отчёта сброшены"));
    },
    "rp-build": () => buildSheet(),
    "rp-mask": () => {
      const d = D0();
      d.mask = !d.mask;
      saveDraft();
      F.render(true);
    },
  });

  let companyT = null;
  // Build: progress → report_build (parameters are stored with the report) → Share / Open.
  let buildT = null;
  function buildSheet() {
    const draft = D0();
    const steps = [
      F.t("reports.st_collect", "Сбор находок и данных"),
      draft.mask
        ? F.t("reports.st_mask_pd", "Маскирование персональных данных и секретов")
        : F.t("reports.st_check", "Проверка секретов"),
      F.t("reports.st_layout", "Вёрстка разделов"),
      draft.fmt === "pdf"
        ? F.t("report.pdf.step", "Подготовка PDF")
        : F.t("reports.saving_file", "Сохранение файла"),
    ];
    const pg = pagesEst(draft) || 0;
    const n = fFindings(draft).length;
    void pg;
    void n; // The file size is computed by the core (report_build → size).
    let i = 0,
      built = null;
    const draw = sh => {
      const done = i >= steps.length && built;
      sh.querySelector(".sh-b").innerHTML = done
        ? `<div class="rp-done"><div class="rp-done-ic">${ic("check")}</div><h3>${esc(F.t("reports.ready", "Отчёт готов"))}</h3><div class="rp-file">${extTag(built.fmt)}<span class="mono">${esc(built.name)}</span><span class="muted">${esc(sizeOf(built))}</span></div></div>`
        : `<div class="pbar rp-pb"><i style="width:${Math.round((Math.min(i, steps.length) / steps.length) * 100)}%"></i></div>
           <div class="rp-steps">${steps.map((s, k) => `<div class="rp-step ${k < i ? "ok" : k === i ? "now" : ""}">${ic(k < i ? "check" : k === i ? "spin" : "dot", k === i ? "spin" : "")}<span>${s}</span></div>`).join("")}</div>`;
      const footEl = sh.querySelector(".sh-f");
      footEl.innerHTML =
        done && draft.fmt === "pdf"
          ? `<button class="btn"
            data-act="rp-b-print">${ic("report")}${esc(F.t("report.pdf.print", "Печать"))}</button><button class="btn primary"
            data-act="rp-b-pdf">${ic("download")}${esc(F.t("report.pdf.get", "Получить PDF"))}</button>`
          : done
            ? `<button class="btn"
              data-act="rp-b-open">${ic("open")}${esc(F.t("common.open", "Открыть"))}</button><button class="btn primary"
              data-act="rp-b-share">${ic("share")}${esc(F.t("reports.share", "Поделиться…"))}</button>`
            : `<button class="btn" data-act="rp-b-cancel">${esc(F.t("common.cancel", "Отмена"))}</button>`;
      const titleEl = sh.querySelector(".sh-h h3");
      if (titleEl)
        titleEl.textContent = done
          ? F.t("common.done", "Готово")
          : F.t("reports.building", "Формирование отчёта");
    };
    F.sheet({
      title: F.t("reports.building", "Формирование отчёта"),
      cls: "rp-sheet",
      html: "",
      footer: " ",
      onMount: sh => {
        draw(sh);
        clearInterval(buildT);
        buildT = setInterval(() => {
          i++;
          if (i >= steps.length && !built) {
            clearInterval(buildT);
            const tpl = TPLS.find(t => t.id === draft.tpl) || TPLS[0];
            F.api
              .report_build(
                {
                  tpl: tpl.t,
                  tpl_id: draft.tpl,
                  fmt: draft.fmt,
                  lang: draft.fmt === "csv" || draft.fmt === "json" ? "-" : draft.lang,
                  min_sev: draft.minSev,
                  confirmed: draft.confirmed,
                  picked_only: draft.pickedOnly,
                  picked: draft.pickedOnly ? F.sel.reportPicked() : [],
                  sections: clone(draft.sec),
                  mask: !!draft.mask,
                  company: draft.company,
                  logo: draft.logo,
                  custody: !!draft.custody,
                  ai_summary: draft.aiSummary !== false,
                },
                FIXED_TPL[draft.tpl] ? draft.tpl : undefined,
              )
              .then(r => {
                built = reps.history.find(h => h.id === r.id) || r;
                reps.last = built;
                if (sh.isConnected) draw(sh);
              })
              .catch(e => {
                F.closeSheet();
                F.snack(F.t("reports.build_fail", "Не удалось сформировать отчёт: ") + e.message);
              });
          }
          if (sh.isConnected) draw(sh);
        }, 700);
      },
      onClose: () => clearInterval(buildT),
    });
  }
  Object.assign(F.actions, {
    "rp-b-cancel": () => {
      clearInterval(buildT);
      F.closeSheet();
      F.snack(F.t("reports.build_cancel", "Формирование отменено"));
    },
    "rp-b-open": () => {
      F.closeSheet();
      reps.prevOf = reps.last;
      if (reps.last.fmt === "csv" || reps.last.fmt === "json") return shareReport(reps.last);
      F.reset(["/projects", "/p/reports", "/p/report-preview"]);
    },
    "rp-b-share": () => {
      const h = reps.last;
      F.closeSheet();
      setTimeout(() => shareReport(h), 260);
    },
    // PDF file: the core builds HTML, the phone renders it off-screen into <exports>/<name>.pdf
    // (platform_pdf); system printing (platform_print) stays the fallback.
    "rp-b-pdf": () => {
      const h = reps.last;
      F.closeSheet();
      if (h) makePdf(h);
    },
    "rp-pdf-share": () =>
      pdfLast && nativeShare({ path: pdfLast.path, name: pdfLast.name, mime: "application/pdf" }),
    "rp-pdf-save": () =>
      pdfLast && nativeSave({ path: pdfLast.path, name: pdfLast.name, mime: "application/pdf" }),
    "rp-h-pdf": id => {
      const h = findHist(id);
      F.closeSheet();
      if (h) setTimeout(() => makePdf(h), 260);
    },
    // System printing: the user picks "Save as PDF" in the print dialog.
    "rp-b-print": () => {
      const h = reps.last;
      F.closeSheet();
      if (h) printReport(h);
    },
  });
  // Last PDF made on this screen: { path, name, size } for the Share / Save buttons of its sheet.
  let pdfLast = null;
  const isHtmlName = n => /\.html?$/i.test(String(n || ""));
  const fmtBytes = b =>
    b >= 1048576
      ? `${(b / 1048576).toFixed(1)} ${F.t("reports.mb", "МБ")}`
      : `${Math.max(1, Math.round(b / 1024))} ${F.t("reports.kb", "КБ")}`;
  function makePdf(h) {
    if (!F.isTauri && !F.api.platform_pdf) return printReport(h);
    F.snack(F.t("report.pdf.making", "Создаём PDF…"));
    F.api.platform_pdf({ report: h.id, name: h.name }).then(
      r => {
        pdfLast = { path: r.path, name: r.name, size: r.size };
        const sn = document.getElementById("snack");
        if (sn) sn.classList.remove("show");
        F.sheet({
          title: F.t("report.pdf.ready", "PDF готов"),
          cls: "rp-sheet",
          html: `<div class="rp-done" data-pdf="${esc(r.name)}"><div class="rp-done-ic">${ic("check")}</div><div class="rp-file">${extTag("pdf")}<span class="mono">${esc(r.name)}</span><span class="muted">${esc(r.size ? fmtBytes(r.size) : "")}</span></div></div>`,
          footer: `${
            F.isTauri
              ? `<button class="btn" data-act="rp-pdf-save">${ic("download")}${esc(F.t("report.pdf.save", "В «Загрузки»"))}</button>`
              : ""
          }<button class="btn primary" data-act="rp-pdf-share">${ic("share")}${esc(F.t("report.pdf.share", "Поделиться…"))}</button>`,
        });
      },
      e => {
        F.snack(F.t("report.pdf.failed", "Не удалось создать PDF открываем печать: ") + (e.message || e), {
          ms: 6000,
        });
        printReport(h);
      },
    );
  }
  function printReport(h) {
    if (!F.isTauri) {
      F.snack(
        F.t(
          "reports.pdf_web",
          "PDF создаётся системной печатью Android. Здесь сохранён HTML с печатными стилями. Откройте его и напечатайте в PDF",
        ),
        { ms: 7000 },
      );
      return;
    }
    {
      if (!F.isTauri) {
        F.snack(
          F.t(
            "reports.pdf_web",
            "PDF создаётся системной печатью Android. Здесь сохранён HTML с печатными стилями. Откройте его и напечатайте в PDF",
          ),
          { ms: 7000 },
        );
        return;
      }
      F.api.platform_print({ report: h.id, name: h.name }).then(
        () => F.snack(F.t("reports.pick_printer", "Выберите принтер «Сохранить как PDF»")),
        e => F.snack(F.t("reports.print_fail", "Не удалось открыть печать: ") + e.message),
      );
    }
  }

  // ================= PREVIEW /p/report-preview =================
  // Table rows per preview sheet: longer tables continue on the next sheet.
  const PREVIEW_ROWS = 10;
  const L10N = {
    RU: {
      title: "Отчёт о тестировании на проникновение",
      conf: "Конфиденциально",
      client: "Заказчик",
      period: "Период работ",
      by: "Исполнитель",
      sum: "Резюме для руководства",
      risk: "Общий уровень риска",
      find: "Находки",
      fixed: "Исправлено",
      th: ["№", "Находка", "Хост", "Важность"],
      page: "стр.",
      secret: "Секрет",
      cont: "(продолжение)",
      tail: n =>
        `Конец предпросмотра: здесь только сводные таблицы. Файл отчёта (около ${n} стр.) содержит все разделы, выбранные в конструкторе.`,
      none: "Находок, отвечающих условиям отчёта, нет.",
      nodata: "нет данных",
      lvl: { crit: "Критический", high: "Высокий", mid: "Средний", low: "Низкий", none: "Нет данных" },
      riskBy: n => `по находкам отчёта: ${n}`,
      text: o =>
        o.n
          ? `В ходе работ выявлено ${o.n} ${o.n % 10 === 1 && o.n % 100 !== 11 ? "находка" : o.n % 10 >= 2 && o.n % 10 <= 4 && (o.n % 100 < 12 || o.n % 100 > 14) ? "находки" : "находок"}: критичных ${o.c}, высоких ${o.h}. Наиболее значимые: ${o.top}.${o.c ? " Рекомендуется устранить критичные находки в течение 7 дней." : ""}${o.fx ? ` Исправлено к моменту отчёта: ${o.fx}.` : ""}`
          : `Находок, отвечающих условиям отчёта, нет.${o.fx ? ` Исправлено к моменту отчёта: ${o.fx}.` : ""}`,
    },
    UA: {
      title: "Звіт про тестування на проникнення",
      conf: "Конфіденційно",
      client: "Замовник",
      period: "Період робіт",
      by: "Виконавець",
      sum: "Резюме для керівництва",
      risk: "Загальний рівень ризику",
      find: "Знахідки",
      fixed: "Виправлено",
      th: ["№", "Знахідка", "Хост", "Важливість"],
      page: "стор.",
      secret: "Секрет",
      cont: "(продовження)",
      tail: n =>
        `Кінець попереднього перегляду: тут лише зведені таблиці. Файл звіту (близько ${n} стор.) містить усі розділи, вибрані в конструкторі.`,
      none: "Знахідок, що відповідають умовам звіту, немає.",
      nodata: "немає даних",
      lvl: { crit: "Критичний", high: "Високий", mid: "Середній", low: "Низький", none: "Немає даних" },
      riskBy: n => `за знахідками звіту: ${n}`,
      text: o =>
        o.n
          ? `Під час робіт виявлено знахідок: ${o.n}, з них критичних ${o.c}, високих ${o.h}. Найважливіші: ${o.top}.${o.c ? " Рекомендовано усунути критичні знахідки протягом 7 днів." : ""}${o.fx ? ` Виправлено на момент звіту: ${o.fx}.` : ""}`
          : `Знахідок, що відповідають умовам звіту, немає.${o.fx ? ` Виправлено на момент звіту: ${o.fx}.` : ""}`,
    },
    EN: {
      title: "Penetration Test Report",
      conf: "Confidential",
      client: "Client",
      period: "Testing period",
      by: "Prepared by",
      sum: "Executive summary",
      risk: "Overall risk level",
      find: "Findings",
      fixed: "Remediated",
      th: ["#", "Finding", "Host", "Severity"],
      page: "p.",
      secret: "Secret",
      cont: "(continued)",
      tail: n =>
        `End of the preview: it shows the summary tables only. The report file (about ${n} pages) holds every section chosen in the builder.`,
      none: "No findings match the report filters.",
      nodata: "no data",
      lvl: { crit: "Critical", high: "High", mid: "Medium", low: "Low", none: "No data" },
      riskBy: n => `based on report findings: ${n}`,
      text: o =>
        o.n
          ? `The engagement identified ${o.n} finding(s): ${o.c} critical and ${o.h} high. Most significant: ${o.top}.${o.c ? " Critical findings should be remediated within 7 days." : ""}${o.fx ? ` Remediated at reporting time: ${o.fx}.` : ""}`
          : `No findings match the report filters.${o.fx ? ` Remediated at reporting time: ${o.fx}.` : ""}`,
    },
  };
  const SEV_L = {
    RU: SEV_RU,
    UA: { crit: "Критичний", high: "Високий", warn: "Середній", low: "Низький", info: "Інфо" },
    EN: { crit: "Critical", high: "High", warn: "Medium", low: "Low", info: "Info" },
  };
  const prev = (F.state.rpPrev = F.state.rpPrev || { z: 1 });

  const SITE_L = { RU: "Найдено на сайте", UA: "Знайдено на сайті", EN: "Found on the website" };
  // Texts of the fixed-template preview (executive / compliance / lab) in the report language.
  const FIX_L = {
    RU: {
      finding: "Находка",
      std: "Стандарты",
      sev: "Важность",
      noStd: "У находок отчёта нет сопоставлений со стандартами.",
      none: "Находок, отвечающих условиям отчёта, нет.",
      caveat: "Сопоставление: ориентир для аудитора, а не заключение экспертизы КСЗІ.",
      outline: FIXED_TPL_RU,
    },
    UA: {
      finding: "Знахідка",
      std: "Стандарти",
      sev: "Важливість",
      noStd: "Знахідки звіту не зіставлені зі стандартами.",
      none: "Знахідок, що відповідають умовам звіту, немає.",
      caveat: "Зіставлення: орієнтир для аудитора, а не висновок експертизи КСЗІ.",
      outline: {
        executive: [
          "Ризик-скор і рівень ризику",
          "П'ять головних знахідок простою мовою",
          "Три першочергові дії",
        ],
        compliance: [
          "Таблиця знахідка × MITRE ATT&CK v20 / CWE / OWASP Top 10:2025 / WSTG / ISO 27001 / NIST · НД ТЗІ 3.6-006-24 / НД ТЗІ / КСЗІ",
          "Зведення за кожним стандартом",
          "Застереження аудитора",
        ],
        lab: [
          "Мета й методика",
          "Вихідні дані та хід роботи",
          "Таблиця знахідок зі стандартами",
          "Висновки, поля «Виконав / Перевірив»",
        ],
      },
    },
    EN: {
      finding: "Finding",
      std: "Standards",
      sev: "Severity",
      noStd: "No report findings are mapped to standards.",
      none: "No findings match the report filters.",
      caveat: "The mapping guides the auditor; it is not a KSZI certification opinion.",
      outline: {
        executive: [
          "Risk score and risk level",
          "Top five findings in plain language",
          "Three priority actions",
        ],
        compliance: [
          "Findings × MITRE ATT&CK v20 / CWE / OWASP Top 10:2025 / WSTG / ISO 27001 / NIST · ND TZI 3.6-006-24 / ND TZI / KSZI table",
          "Summary per standard",
          "Auditor caveat",
        ],
        lab: [
          "Goal and method",
          "Input data and procedure",
          "Findings table with standards",
          "Conclusions, “Done by / Checked by” fields",
        ],
      },
    },
  };
  // Finding titles in the preview follow the app language; the core writes the file in the report language.
  const titleNote = lang =>
    lang && lang !== F.i18n.uiCode()
      ? `<p class="fhint rp-hint rp-tnote">${ic("info")} ${esc(F.t("reports.preview_note", "Названия находок в предпросмотре: на языке приложения; в файле отчёта они на языке отчёта."))}</p>`
      : "";
  // Standards of a finding as short labels (the core attaches finding.standards, null when unmapped).
  const STD_LABEL = [
    ["mitre", "ATT&CK "],
    ["cwe", ""],
    ["owasp", "OWASP "],
    ["wstg", ""],
    ["iso27001", "ISO 27001 A."],
    ["nist", "NIST "],
    ["privacy", ""],
    ["ndtzi", "НД ТЗІ "],
    ["kszi", "КСЗІ "],
  ];
  const stdLabels = f =>
    f && f.standards
      ? STD_LABEL.flatMap(([k, p]) =>
          (f.standards[k] || []).map(v => (k === "privacy" ? F.t(`findings.std.pv.${v}`, v) : p + v)),
        )
      : [];
  // Fixed-structure templates: an outline page with the core title and description, plus the findings
  // × standards table for КСЗІ and the laboratory work.
  function renderFixedPreview(draft) {
    const ct = coreTplsOf(draft.lang).find(t => t.id === draft.tpl);
    const tpl = TPLS.find(t => t.id === draft.tpl);
    const res = reps.prevOf && reps.prevOf.result;
    const byId = id => F.db.findings.find(f => f.id === id);
    const list = res ? res.finding_ids.map(byId).filter(Boolean) : fFindings(draft);
    const sl = SEV_L[draft.lang] || SEV;
    const fl = FIX_L[draft.lang] || FIX_L.RU;
    const pages = (res && res.pages) || pagesEst(draft) || 1;
    const by = esc(draft.company || "-");
    const withStd = draft.tpl !== "executive";
    const rows = withStd ? list.filter(f => f.standards) : list;
    return `
      <div class="rp-ptools"><span class="rp-pinfo">${FMT_L[draft.fmt] || "PDF"} · ${draft.lang} · ~${plural(pages, "reports.pl_page", "страница", "страницы", "страниц")}${res ? ` · ${esc(F.t("reports.snapshot", { d: reps.prevOf.date || "" }, "снимок {d}"))}` : ""}</span></div>
      ${titleNote(draft.lang)}
      <div class="rp-scroll"><div class="rp-paperw" style="--z:1">
        <section class="rp-paper rp-fixedp"><div class="rp-pi">
          <div class="rp-ph"><span>${logoMark(draft, "rp-plogo")}${by}</span><span>${esc(F.db.project ? F.db.project.name : "")}</span></div>
          <h2>${esc(ct ? ct.title : tpl.t)}</h2>
          <p>${esc(ct ? ct.description : tpl.d)}</p>
          <ol>${(fl.outline[draft.tpl] || FIXED_TPL[draft.tpl]).map(x => `<li>${esc(x)}</li>`).join("")}</ol>
          ${
            rows.length
              ? `<table class="rp-tbl"><thead><tr><th>№</th><th>${fl.finding}</th><th>${withStd ? fl.std : fl.sev}</th></tr></thead>
          <tbody>${rows
            .map(
              (f, i) =>
                `<tr><td>${i + 1}</td><td>${esc(f.title)}</td><td>${withStd ? esc(stdLabels(f).join(", ")) : `<span class="rp-sev s-${f.sev}">${sl[f.sev] || ""}</span>`}</td></tr>`,
            )
            .join("")}</tbody></table>`
              : `<p>${withStd ? fl.noStd : fl.none}</p>`
          }
          ${withStd ? `<p class="rp-more">${fl.caveat}</p>` : ""}
        </div></section>
      </div></div>`;
  }
  function renderPreview() {
    const draft = reps.prevOf ? draftOf(reps.prevOf) : D0();
    if (FIXED_TPL[draft.tpl]) return renderFixedPreview(draft);
    const tr = L10N[draft.lang] || L10N.RU;
    const sl = SEV_L[draft.lang] || SEV;
    // A report from history shows the SNAPSHOT taken at build time (result), not the current data.
    const res = reps.prevOf && reps.prevOf.result;
    const byId = id => F.db.findings.find(f => f.id === id);
    const list = res ? res.finding_ids.map(byId).filter(Boolean) : fFindings(draft);
    const fixed = res ? (res.fixed_ids || []).map(byId).filter(Boolean) : fFixed(draft);
    const cnt = s => (res && res.counts ? res.counts[s] || 0 : list.filter(f => f.sev === s).length);
    const sc = F.sel.scope.info();
    const pages = (res && res.pages) || pagesEst(draft) || 3;
    // Report risk is computed over the included findings; for history entries it comes from the snapshot.
    const rk = res
      ? { score: res.risk, level: res.risk_level || "none" }
      : F.sel.scans().length
        ? (s => ({
            score: s,
            level: F.rules.riskLevel(s, F.rules.hasCrit(list)),
          }))(F.rules.riskScore(list))
        : { score: null, level: "none" };
    const by = esc(draft.company || "-");
    const maxCount = Math.max(1, ...["crit", "high", "warn", "low", "info"].map(cnt));
    const bars = ["crit", "high", "warn", "low", "info"]
      .map(s => {
        const n = cnt(s);
        return `<div class="rp-bar"><span class="rp-bl">${sl[s]}</span><span class="rp-bt"><i class="s-${s}"
          style="width:${(n / maxCount) * 100}%"></i></span><b>${n}</b></div>`;
      })
      .join("");
    const top = list
      .slice(0, 3)
      .map(f => f.title)
      .join("; ");
    const text = tr.text({ n: list.length, c: cnt("crit"), h: cnt("high"), top, fx: fixed.length });
    const row = (f, i) =>
      `<tr><td>${i + 1}</td><td>${esc(f.title)}${secretsOf(f)
        .map(v => `<div class="rp-sec">${tr.secret}: ${esc(maskAs(v, !!draft.mask))}</div>`)
        .join(
          "",
        )}</td><td>${esc(f.host)}</td><td><span class="rp-sev s-${f.sev}">${sl[f.sev] || ""}</span></td></tr>`;
    const siteRow = (f, i) =>
      `<tr><td>${i + 1}</td><td>${esc(f.title)}</td><td class="rp-url">${esc(f.url || f.host)}</td><td><span class="rp-sev s-${f.sev}">${sl[f.sev] || ""}</span></td></tr>`;
    const secNo = (() => {
      let k = 0;
      return () => ++k;
    })();
    // Every included row is shown: long tables continue on the next sheets (PREVIEW_ROWS rows per
    // sheet, the header row repeats), so scrolling reaches the real end of the report tables.
    const sheets = [];
    const table = (h2, head, rows, render) => {
      const parts = [];
      for (let i = 0; i < rows.length; i += PREVIEW_ROWS) parts.push(rows.slice(i, i + PREVIEW_ROWS));
      parts.forEach((part, k) =>
        sheets.push(
          `${k === 0 ? `<h2>${h2}</h2>` : `<h2 class="rp-cont">${h2} <small>${esc(tr.cont)}</small></h2>`}
          <table class="rp-tbl"><thead><tr>${head}</tr></thead>
          <tbody>${part.map((f, i) => render(f, k * PREVIEW_ROWS + i)).join("")}</tbody></table>`,
        ),
      );
    };
    const thAll = tr.th.map(x => `<th>${x}</th>`).join("");
    if (draft.sec.summary)
      sheets.push(`<h2>${secNo()}. ${tr.sum}</h2>
          <div class="rp-risk"><div class="rp-rv">${rk.score == null ? "-" : rk.score}<small>/100</small></div><div><b>${tr.risk}</b><span>${tr.lvl[rk.level] || tr.nodata}</span><small class="rp-rnote">${esc(tr.riskBy(res ? res.total : list.length))}</small></div></div>
          <p>${esc(text)}</p>
          <div class="rp-bars">${bars}</div>`);
    if (draft.sec.findings) {
      const h2 = `${secNo()}. ${tr.find}`;
      if (list.length) table(h2, thAll, list, row);
      else sheets.push(`<h2>${h2}</h2><p>${tr.none}</p>`);
    }
    // "Found on the site" (forgotten-file search, fuzz module) is a subsection of Infrastructure, as in
    // foca-report.
    const site = list.filter(f => f.module === "fuzz");
    if (draft.sec.infra && site.length)
      table(
        `${secNo()}. ${SITE_L[draft.lang] || SITE_L.RU}`,
        `<th>#</th><th>${tr.th[1]}</th><th>URL</th><th>${tr.th[3]}</th>`,
        site,
        siteRow,
      );
    if (draft.sec.fixed && fixed.length) table(`${secNo()}. ${tr.fixed}`, thAll, fixed, row);
    // The footer counts the sheets of this preview; the file estimate stays in the info line.
    const total = sheets.length + 1;
    const head = n =>
      `<div class="rp-ph"><span>${logoMark(draft, "rp-plogo")}${by}</span><span>${tr.conf}</span></div><div class="rp-pf"><span>${esc(F.db.project ? F.db.project.name : "")}</span><span>${tr.page} ${n} / ${total}</span></div>`;
    const tail = `<p class="rp-more rp-end">${esc(tr.tail(pages))}</p>`;
    return `
      <div class="rp-ptools">
        <span class="rp-pinfo">${FMT_L[draft.fmt] || "PDF"} · ${draft.lang} · ~${plural(pages, "reports.pl_page", "страница", "страницы", "страниц")}${draft.pickedOnly ? ` · ${esc(F.t("reports.selection_l", "выборка"))}` : ""}${res ? ` · ${esc(F.t("reports.snapshot", { d: reps.prevOf.date || "" }, "снимок {d}"))}` : ""}</span>
        <div class="rp-zoom" role="group" aria-label="${esc(F.t("reports.zoom", "Масштаб"))}">
          <button class="ib" data-act="rp-z:-1" aria-label="${esc(F.t("reports.zoom_out", "Уменьшить"))}"
            ${prev.z <= 1 ? "disabled" : ""}>${ic("zoom-out")}</button>
          <button class="rp-zv" data-act="rp-z:0" aria-label="${esc(F.t("reports.fit_width", "По ширине"))}">${Math.round(prev.z * 100)}%</button>
          <button class="ib" data-act="rp-z:1" aria-label="${esc(F.t("reports.zoom_in", "Увеличить"))}"
            ${prev.z >= 2.5 ? "disabled" : ""}>${ic("zoom-in")}</button>
        </div>
      </div>
      ${titleNote(draft.lang)}
      <div class="rp-scroll${prev.z > 1 ? " rp-zoomed" : ""}"><div class="rp-paperw" style="--z:${prev.z}">
        <section class="rp-paper rp-title"><div class="rp-pi">
          ${head(1)}
          <div class="rp-tmain">
            ${logoMark(draft, "rp-tlogo")}
            <div class="rp-tkind">${tr.conf.toUpperCase()}</div>
            <h1>${tr.title}</h1>
            <div class="rp-tline"></div>
            <dl>
              <dt>${tr.client}</dt><dd>${esc(sc.client || (F.db.project && F.db.project.client) || "-")}</dd>
              <dt>${tr.by}</dt><dd>${by}</dd>
            </dl>
          </div>
          ${sheets.length ? "" : tail}
        </div></section>
        ${sheets
          .map(
            (body, i) => `<section class="rp-paper"><div class="rp-pi">
          ${head(i + 2)}
          ${body}
          ${i === sheets.length - 1 ? tail : ""}
        </div></section>`,
          )
          .join("")}
      </div></div>`;
  }

  F.route("/p/report-preview", {
    title: () => F.t("reports.preview", "Предпросмотр"),
    sub: () => (reps.prevOf ? reps.prevOf.name : F.t("reports.draft", "Черновик отчёта")),
    nav: false,
    back: true,
    hideMini: true,
    actions: [{ icon: "share", act: "rp-pv-share", label: () => F.t("reports.share_l", "Поделиться") }],
    render: () =>
      F.withStates(renderPreview, {
        loading: "cards",
        empty: {
          icon: "report",
          title: F.t("reports.nothing_show", "Нечего показать"),
          text: F.t("reports.nothing_show_text", "Включите хотя бы один раздел в конструкторе отчёта."),
        },
      }),
    mount(page) {
      page.classList.add("rp-pg", "rp-pvpg");
    },
    unmount() {
      reps.prevOf = null;
    },
  });
  Object.assign(F.actions, {
    "rp-z": v => {
      v = +v;
      prev.z = v === 0 ? 1 : Math.max(1, Math.min(2.5, Math.round((prev.z + v * 0.5) * 10) / 10));
      F.render(true);
    },
    "rp-pv-share": () => {
      if (F.isTauri) {
        if (reps.prevOf && reps.prevOf.id) shareReport(reps.prevOf);
        else
          F.snack(F.t("reports.build_first", "Сначала сформируйте отчёт: поделиться можно готовым файлом"));
        return;
      }
      const h = reps.prevOf || {
        name: `${F.t("reports.draft_file", "Черновик_отчёта_")}${F.db.project ? F.db.project.name : ""}.${D0().fmt}`,
        size: `~${kb(180 * (pagesEst(D0()) || 3) + 300)}`,
      };
      F.shareSheet(h.name, sizeOf(h));
    },
  });
})();
