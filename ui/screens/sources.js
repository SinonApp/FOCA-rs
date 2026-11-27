/*
 * Settings → Sources: five source groups, each with a group-wide toggle and an expandable list
 * (search engines, archives, subdomains, site recon, crawler), plus a collapsed "With an API key" group.
 * State lives in settings.sources.<id>.enabled and settings.source_status.<id> (the core writes the status
 * after each poll). The id list matches SOURCES in foca-engine/scan.rs. API keys are entered only under
 * Settings → API keys; a keyed source enables itself once its key is set (a source disabled here is never
 * polled).
 */
(function () {
  const F = window.FOCA;
  const { ui, ic, esc } = F;
  /**
   * Source catalogue, exported as F.SOURCE_LIST.
   * Each entry is a tuple `[id, name, group, access, description]`:
   * - `group`: a GROUPS id ("search", "arch", "sub", "intel", "crawl") or "key" for paid services;
   * - `access`: a key of ACCESS describing how the source reaches the target.
   */
  const SRC = [
    [
      "startpage",
      "Startpage (через браузер)",
      "search",
      "web",
      "Выдача Google через Startpage: site:домен filetype:pdf… Открывается во встроенном браузере (скрытый WebView), проверку поисковика он проходит сам",
    ],
    [
      "brave_web",
      "Brave Search (через браузер)",
      "search",
      "web",
      "Независимый индекс Brave, без ключа: через встроенный браузер",
    ],
    [
      "yahoo",
      "Yahoo (через браузер)",
      "search",
      "web",
      "Выдача Bing через Yahoo: понимает site:, filetype: и OR: через встроенный браузер; из ЕС может попросить согласие на cookies (кнопка «Пройти проверку»)",
    ],
    [
      "searx_pool",
      "Публичные SearXNG (через браузер)",
      "search",
      "web",
      "Пул открытых экземпляров SearXNG (searx.space: аптайм ≥ 90 %); экземпляр с лимитом пропускается, капч нет",
    ],
    [
      "mojeek",
      "Mojeek (дорки)",
      "search",
      "free",
      "Через встроенный браузер, если он есть; без гарантий: с IP дата-центров блокирует",
    ],
    ["ddg", "DuckDuckGo (дорки)", "search", "free", "site:домен filetype:pdf…: без гарантий, бывает капча"],
    ["bing", "Bing (дорки)", "search", "free", "Без гарантий, бывает капча"],
    [
      "wayback",
      "Wayback Machine",
      "arch",
      "free",
      "Архивные копии документов (web.archive.org, цель не трогаем)",
    ],
    [
      "cc",
      "Common Crawl",
      "arch",
      "free",
      "Индексы веб-обхода: 3 последних или глубже, за годы или все снимки (ниже, «Глубина поиска»)",
    ],
    ["arquivo", "Arquivo.pt", "arch", "free", "Португальский веб-архив: поиск по типу файла"],
    ["crt", "crt.sh", "sub", "free", "Поддомены из журналов сертификатов (CT)"],
    ["crtname", "crt.name", "sub", "opt", "Поддомены из CT (зеркало-индекс)"],
    ["scanmalware", "ScanMalware", "sub", "free", "Поддомены из CT/DNS"],
    ["certspotter", "CertSpotter", "sub", "opt", "CT-журналы, малый лимит без ключа"],
    ["anubis", "Anubis", "sub", "free", "Поддомены"],
    ["hackertarget", "HackerTarget", "sub", "opt", "Поддомены, ~50 запросов в сутки без ключа"],
    ["rapiddns", "RapidDNS", "sub", "free", "Поддомены"],
    ["subcenter", "subdomain.center", "sub", "opt", "Поддомены"],
    ["thc", "THC ip.thc.org", "sub", "free", "Поддомены"],
    ["shodanct", "Shodan CT", "sub", "free", "Поддомены из CT по данным Shodan"],
    ["otx_dns", "OTX passive DNS", "sub", "opt", "Пассивный DNS; без ключа часто «лимит»"],
    // Subdomain enumeration: DNS queries to the target's name servers, standard/full profiles only.
    [
      "subdomains",
      "Перебор и перестановки поддоменов",
      "sub",
      "dns",
      "Только в «Стандартном» и «Полном»: имена из словаря и перестановки известных. Запросами к DNS цели; словарь выбирается в мастере запуска",
    ],
    ["otx_url", "AlienVault OTX (URL)", "intel", "free", "Известные URL домена"],
    ["urlscan", "urlscan.io", "intel", "free", "URL из публичных сканов (малый лимит без ключа)"],
    ["internetdb", "Shodan InternetDB", "intel", "free", "Порты, ПО и CVE по IP, пассивно"],
    ["hudson", "HudsonRock", "intel", "free", "URL из логов инфостилеров"],
    // Site recon (foca-recon): the passive profile works from the archived copy and never contacts the
    // site.
    [
      "recon",
      "Сайт: технологии, favicon, JS",
      "intel",
      "free",
      "Технологии с версиями, ID аналитики, хэш favicon, эндпоинты и секреты (маской) в JS главной",
    ],
    [
      "webaudit",
      "Веб-аудит: заголовки, CSP, source maps, API",
      "intel",
      "free",
      "Заголовки безопасности, домены из CSP, source maps и Swagger/OpenAPI; в пассивном: только разбор уже полученных ответов",
    ],
    [
      "wellknown",
      "robots / sitemap / security.txt",
      "intel",
      "free",
      "Из архива Wayback: скрытые пути, URL из sitemap, контакты security.txt",
    ],
    [
      "buckets",
      "Облачные хранилища",
      "intel",
      "free",
      "Ссылки на S3/GCS/Azure из страниц и документов; листинг: только в «Полном»",
    ],
    [
      "grepapp",
      "grep.app (публичный код)",
      "intel",
      "free",
      "Где домен встречается в публичных репозиториях; без гарантий: бывает защита от ботов",
    ],
    // Port scan is an active module: only in the Full / Custom profile with the module on, live scope hosts
    // only.
    [
      "ports",
      "Скан портов (TCP)",
      "intel",
      "target",
      "Только в «Полном»: открытые TCP-порты, баннеры и версии на живых хостах скоупа (исключения не трогаются)",
    ],
    // TLS/X.509 inspector: handshakes with open TLS ports of live in-scope hosts.
    [
      "tls",
      "TLS/X.509-инспектор",
      "intel",
      "target",
      "Только в «Стандартном» и «Полном»: сертификаты открытых TLS-портов хостов скоупа (срок, цепочка, имя); в «Полном»: ещё TLS 1.0/1.1, слабые шифры и STARTTLS",
    ],
    [
      "crawler",
      "Обход сайта",
      "crawl",
      "target",
      "Только в «Стандартном» и «Полном»: ходит по страницам сайта цели",
    ],
    [
      "brave",
      "Brave Search API",
      "key",
      "key",
      "Официальный API Brave по ключу: ещё один поисковик для дорков. Нужна карта; кредит $5 в месяц, около 1000 запросов",
    ],
    [
      "searx",
      "SearXNG",
      "key",
      "key",
      "Свой экземпляр SearXNG (адрес в «Ключах API»): спрашивается раньше публичных",
    ],
    ["shodan", "Shodan (кэш баннеров)", "key", "key", "Порты и баннеры из базы Shodan, без обращения к цели"],
  ];
  /** Source groups, exported as F.SOURCE_GROUPS. Each entry is a tuple `[id, title, icon]`. */
  const GROUPS = [
    ["search", "Поисковики", "search"],
    ["arch", "Архивы", "history"],
    ["sub", "Поддомены", "domain"],
    ["intel", "Разведка", "net"],
    ["crawl", "Краулер сайта", "alert"],
  ];
  const ACCESS_HTML = () => ({
    free: `<span class="pill ok">${ic("check")}${esc(F.t("sources.access_free", "Ключ не нужен"))}</span>`,
    web: `<span class="pill ok">${ic("check")}${esc(F.t("sources.access_web", "Без ключа · через встроенный браузер"))}</span>`,
    opt: `<span class="pill ok">${ic("check")}${esc(F.t("sources.access_opt", "Без ключа · с ключом лимит выше"))}</span>`,
    target: `<span class="pill warn">${ic("alert")}${esc(F.t("sources.access_target", "Ходит на сайт цели"))}</span>`,
    dns: `<span class="pill warn">${ic("alert")}${esc(F.t("sources.access_dns", "Запросы к DNS цели"))}</span>`,
  });
  const ST = () => ({
    ok: F.t("sources.status_ok", "ответил"),
    error: F.t("sources.status_error", "ошибка"),
    timeout: F.t("sources.status_timeout", "нет ответа"),
    blocked: F.t("sources.status_blocked", "капча / заблокировано"),
    skipped: F.t("sources.status_skipped", "пропущен"),
    nokey: F.t("sources.status_nokey", "нет ключа"),
    unavailable: F.t("sources.status_unavailable", "нужен встроенный браузер (только Android)"),
    skipped_headless: F.t("sources.status_skipped_headless", "пропущен в фоне (нет WebView)"),
    unreliable: F.t("sources.status_unreliable", "недостоверно (VPN/прокси устройства)"),
    limit: F.t("sources.status_limit", "лимит запросов (HTTP 429)"),
  });
  // Localized source name/description; the tuples keep the Russian originals as fallbacks.
  const nm = s => F.t("sources.name_" + s[0], s[1]);
  const ds = s => F.t("sources.desc_" + s[0], s[4]);
  const gname = g => F.t("sources.group_" + g[0], g[1]);
  const sset = () => (F.db.settings || {}).sources || {};
  const sstat = () => (F.db.settings || {}).source_status || {};
  const keyOk = id => {
    const k = ((F.db.settings || {}).keys || {})[id];
    return !!k && k.status === "ok";
  };
  const on = id => (sset()[id] || {}).enabled !== false;
  // A source is working when it is enabled and either needs no key or has a valid one.
  const works = s => on(s[0]) && (s[2] !== "key" || keyOk(s[0]));
  const FREE = () => SRC.filter(s => s[2] !== "key");
  F.sourcesFree = () => {
    const l = FREE();
    return {
      total: l.length,
      on: l.filter(s => on(s[0])).length,
      names: l.filter(s => on(s[0])).map(s => nm(s).replace(/\s*\(.*\)$/, "")),
    };
  };
  const open = (F.state.srcOpen = F.state.srcOpen || {});
  const when = at => {
    if (!at) return "";
    const d = String(at).replace("T", " ").slice(0, 16);
    return " · " + d;
  };
  function line(id) {
    const s = sstat()[id];
    if (!s) return esc(F.t("sources.never_polled", "ещё не опрашивался"));
    const n =
      s.n != null && s.status === "ok" ? " · " + esc(F.t("sources.found_n", { n: s.n }, "найдено {n}")) : "";
    const err = s.error && s.status !== "ok" ? ` · ${esc(String(s.error).slice(0, 80))}` : "";
    return `${esc(ST()[s.status] || s.status)}${n}${err}${when(s.at)}`;
  }
  const isBad = id => {
    const st = (sstat()[id] || {}).status;
    return st === "error" || st === "timeout" || st === "blocked";
  };
  const short = n => n.replace(/\s*\(.*\)$/, "");
  function item(src) {
    const [id, , g, acc] = src,
      name = nm(src),
      what = ds(src);
    const keyless = g === "key" && !keyOk(id);
    return `<div class="row src-it" data-src="${id}">
      <div class="body"><div class="t">${esc(name)}</div><div class="s">${esc(what)}</div>
        <div class="st-rpill">${keyless ? `<span class="pill mute">${ic("key")}${esc(F.t("sources.key_missing", "Ключ не указан"))}</span>` : g === "key" ? `<span class="pill info">${ic("key")}${esc(F.t("sources.key_set", "Ключ указан"))}</span>` : ACCESS_HTML()[acc]}</div>
        <div class="s ${isBad(id) ? "bad" : ""}">${keyless ? esc(F.t("sources.keyless_hint", "Включится сам, когда ключ появится в «Ключах API»")) : line(id)}</div></div>
      <div class="tail">${keyless ? "" : ui.toggle(on(id), `src-t:${id}`, `aria-label="${esc(name)}"`)}</div></div>`;
  }
  function group(grp) {
    const [groupId, , icon] = grp,
      title = gname(grp);
    const rows = SRC.filter(s => s[2] === groupId),
      n = rows.filter(s => on(s[0])).length,
      all = n === rows.length,
      bad = rows.some(s => isBad(s[0]));
    const names = rows.map(s => short(nm(s)));
    const sub =
      groupId === "sub"
        ? F.tp(
            "sources.group_sub_summary",
            rows.length,
            { n: rows.length, names: names.slice(0, 2).join(", ") },
            "{n} источник · {names}…|{n} источника · {names}…|{n} источников · {names}…",
          )
        : names.join(", ");
    return `<div class="src-g ${open[groupId] ? "open" : ""}" data-grp="${groupId}">
      <div class="row src-gh">
        <button class="src-gb" data-act="src-open:${groupId}" aria-expanded="${!!open[groupId]}"
          aria-label="${esc(title)}: ${esc(open[groupId] ? F.t("sources.collapse", "свернуть") : F.t("sources.show_sources", "показать источники"))}">
          ${ui.leadIcon(icon, bad ? "var(--warn)" : n ? "var(--accent)" : "")}
          <div class="body"><div class="t">${esc(title)}</div><div class="s">${esc(sub)}</div>${n && !all ? `<div class="s src-part">${esc(F.t("sources.enabled_n_of", { n, total: rows.length }, "включено {n} из {total}"))}</div>` : ""}</div>
          ${ic("chev-down", "src-c")}
        </button>
        <div class="tail">${ui.toggle(n > 0, `src-g:${groupId}`, `aria-label="${esc(title)}: ${esc(F.t("sources.group_all_aria", "все источники группы"))}"`)}</div>
      </div>
      ${open[groupId] ? `<div class="src-in">${rows.map(item).join("")}</div>` : ""}
    </div>`;
  }
  function render() {
    const paid = SRC.filter(s => s[2] === "key"),
      paidOn = paid.filter(works).length;
    return `
      <p class="lead st-lead">${esc(F.t("sources.lead", "Группы источников этапа «Поиск». Выключенный источник не запрашивается ни в одном скане. Пассивные источники к цели не обращаются; краулер, скан портов, перебор поддоменов и TLS-инспектор работают только в «Стандартном» и «Полном»."))}</p>
      <div class="list src-list">${GROUPS.map(group).join("")}</div>
      <div class="list src-list src-paid">
        <div class="src-g ${open.key ? "open" : ""}" data-grp="key">
          <div class="row tap src-gh" data-act="src-open:key" role="button" aria-expanded="${!!open.key}">
            ${ui.leadIcon("key", paidOn ? "var(--accent)" : "")}
            <div class="body"><div class="t">${esc(F.t("help.extra_key_group", "Дополнительно, с ключом"))}</div><div class="s">${esc(F.tp("sources.paid_summary", paid.length, { n: paid.length }, "{n} платный сервис · необязательно|{n} платных сервиса · необязательно|{n} платных сервисов · необязательно"))}${paidOn ? " · " + esc(F.t("sources.paid_connected", { n: paidOn }, "подключено {n}")) : ""}</div></div>
            ${ic("chev-down", "src-c")}
          </div>
          ${
            open.key
              ? `<div class="src-in">${paid.map(item).join("")}
            ${ui.row({ lead: ui.leadIcon("key", "var(--accent)"), title: esc(F.t("sources.keys_title", "Ключи API")), sub: esc(F.t("sources.keys_sub", "Настройки → Ключи API (необязательно)")), act: "go:/settings/keys", chev: true, cls: "src-keys" })}</div>`
              : ""
          }
        </div>
      </div>
      <p class="fhint st-hint">${ic("info")}${esc(F.t("sources.hint", "Группы вместо длинного списка: внутри, отдельные переключатели. Ключи нужны только платным сервисам."))}</p>
      ${depthHTML()}`;
  }
  // Search depth and retries (settings.search): Common Crawl depth and pacing, postponed dork retries.
  const srch = () => (F.db.settings || {}).search || {};
  const segOf = (key, cur, opts) =>
    `<div class="seg src-seg" role="radiogroup">${opts
      .map(
        ([v, l]) =>
          `<button class="${String(cur) === String(v) ? "on" : ""}" role="radio" aria-checked="${String(cur) === String(v)}" data-act="src-set:${key}:${v}">${esc(l)}</button>`,
      )
      .join("")}</div>`;
  function depthHTML() {
    const s = srch(),
      depth = s.cc_depth || "latest",
      years = s.cc_years || 3,
      pace = s.cc_pace_s || 3,
      retry = s.dork_retry_min == null ? 15 : s.dork_retry_min;
    const yr = n => F.t("sources.cc_years_n", { n }, "{n} г.");
    return `${ui.secH(F.t("sources.depth_h", "Глубина поиска и повторы"))}
      <div class="card pad src-depth">
        <div class="flabel">${esc(F.t("sources.cc_depth", "Common Crawl: какие снимки"))}</div>
        ${segOf("cc_depth", depth, [
          ["latest", F.t("sources.cc_latest", "3 последних")],
          ["years", F.t("sources.cc_years", "За годы")],
          ["all", F.t("sources.cc_all", "Все снимки")],
        ])}
        ${
          depth === "years"
            ? `<div class="flabel">${esc(F.t("sources.cc_years_h", "Сколько лет"))}</div>${segOf(
                "cc_years",
                years,
                [1, 2, 3, 5, 10].map(n => [n, yr(n)]),
              )}`
            : ""
        }
        <div class="flabel">${esc(F.t("sources.cc_pace", "Пауза между запросами к индексу"))}</div>
        ${segOf(
          "cc_pace_s",
          pace,
          [3, 5, 10].map(n => [n, F.t("sources.sec_n", { n }, "{n} с")]),
        )}
        <div class="flabel">${esc(F.t("sources.dork_retry", "Повтор поисков, отложенных из-за капчи"))}</div>
        ${segOf("dork_retry_min", retry, [
          [0, F.t("sources.retry_off", "Только в следующем скане")],
          [5, F.t("sources.min_n", { n: 5 }, "{n} мин")],
          [15, F.t("sources.min_n", { n: 15 }, "{n} мин")],
          [60, F.t("sources.min_n", { n: 60 }, "{n} мин")],
        ])}
      </div>
      <p class="fhint st-hint">${ic("info")}${esc(F.t("sources.depth_hint", "Индекс Common Crawl часто отвечает ошибками: запросы идут не чаще раза в 3 секунды, сбои повторяются с паузой. Глубокий обход идёт в фоне этапа «Поиск», не задерживая другие источники; результаты по домену хранятся сутки, а недоделанные снимки продолжатся в следующем скане. Капчи мы не решаем: поиски, на которые все поисковики ответили капчей, повторятся позже, по одному."))}</p>`;
  }
  F.actions["src-set"] = arg => {
    const i = arg.indexOf(":"),
      key = arg.slice(0, i),
      raw = arg.slice(i + 1);
    const v = /^[0-9.]+$/.test(raw) ? +raw : raw;
    const st = F.db.settings || (F.db.settings = {});
    st.search = { ...(st.search || {}), [key]: v };
    F.api.settings_set({ search: { [key]: v } });
    F.render(true);
  };
  F.route("/settings/sources", {
    title: () => F.t("sources.title", "Источники"),
    nav: false,
    back: true,
    actions: [],
    hideMini: true,
    sub: () => {
      const f = FREE().filter(works).length,
        k = SRC.filter(s => s[2] === "key" && works(s)).length;
      return (
        F.t("sources.sub_free", { n: f }, "без ключей: {n}") +
        (k ? " · " + F.t("sources.sub_keyed", { n: k }, "с ключом: {n}") : "")
      );
    },
    live: (kind, ev) => kind === "db" && ev && ev.kind === "settings",
    render: () => F.withStates(render, { loading: "list" }),
    mount: page => page.classList.add("st-pg"),
  });
  const setOn = (ids, v) => {
    F.api.settings_set({ sources: Object.fromEntries(ids.map(id => [id, { enabled: v }])) });
    const s = F.db.settings || (F.db.settings = {});
    s.sources = s.sources || {};
    ids.forEach(id => {
      s.sources[id] = { ...(s.sources[id] || {}), enabled: v };
    });
  };
  F.actions["src-t"] = id => {
    const v = !on(id);
    setOn([id], v);
    F.render(true);
    F.refreshBar && F.refreshBar();
    const hit = SRC.find(x => x[0] === id),
      name = hit ? nm(hit) : id;
    F.snack(
      v
        ? F.t("sources.snack_on", { name }, "{name}: включён")
        : F.t("sources.snack_off", { name }, "{name}: выключен: в сканах не опрашивается"),
    );
  };
  F.actions["src-g"] = g => {
    const rows = SRC.filter(s => s[2] === g),
      v = !rows.some(s => on(s[0]));
    setOn(
      rows.map(s => s[0]),
      v,
    );
    F.render(true);
    F.refreshBar && F.refreshBar();
    const hitG = GROUPS.find(x => x[0] === g),
      t = hitG ? gname(hitG) : g;
    F.snack(
      v
        ? F.t("sources.snack_group_on", { group: t }, "«{group}»: включены все")
        : F.t("sources.snack_group_off", { group: t }, "«{group}»: выключены: в сканах не опрашиваются"),
    );
  };
  F.actions["src-open"] = g => {
    open[g] = !open[g];
    F.render(true);
  };
  /** Called by settings.js after key_set: a source enables itself once its API key is provided. */
  F.sourceKeyAdded = id => {
    if (SRC.some(s => s[0] === id && s[2] === "key") && !on(id)) setOn([id], true);
  };
  F.SOURCE_LIST = SRC;
  F.SOURCE_GROUPS = GROUPS;
  // Localized labels for other screens (tuples above keep the Russian originals).
  F.sourceName = nm;
  F.sourceDesc = ds;
  F.sourceGroupName = gname;
})();
