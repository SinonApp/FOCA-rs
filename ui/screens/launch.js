// Targets & launch and Scope screens.
// /new creates a new project (from /projects, "New target" field) or starts a new scan of the current
// project (targets come from the scope). Any profile starts with a single "Start" tap without intermediate
// confirmations: out-of-scope and excluded targets are not scanned (a snackbar lists them).
// /p/scope is the project scope (edited via F.api.scope_set).
// Helper F.moduleBadge(kind): "active" | "target" → "contacts the target", otherwise → "external sources
// only".
(function () {
  const F = window.FOCA,
    { ic, esc, ui } = F;
  // Bare QA harnesses load this file without core.js: keep the Russian originals there.
  const tx =
    F.t ||
    ((key, params, fallback) => {
      const tpl = typeof params === "string" ? params : (fallback ?? key);
      const p = params && typeof params === "object" ? params : {};
      return String(tpl).replace(/\{(\w+)\}/g, (m, k) => (k in p && p[k] != null ? String(p[k]) : m));
    });
  const lang = () => (F.i18n ? F.i18n.lang() : "ru");
  const plural = (n, one, few, many) => {
    if (lang() === "en") return `${fmt(n)}\u00a0${n === 1 ? one : few}`;
    const a = n % 10,
      b = n % 100;
    return `${fmt(n)}\u00a0${a === 1 && b !== 11 ? one : a >= 2 && a <= 4 && (b < 12 || b > 14) ? few : many}`;
  };
  const fmt = n =>
    Number(n)
      .toLocaleString(lang() || "ru")
      .replace(/\u202f|\u00a0/g, "\u00a0");
  // Plural with forms from the dictionary: "one|few|many" (EN uses "one|other|other").
  const pl = (n, key, forms) => plural(n, ...tx(key, forms).split("|"));
  // Localized table fields: a getter reads tx(key, original) on every access, so the tables keep their
  // Russian originals as fallbacks and consumers keep destructuring them as before.
  const lzField = (obj, field, key) => {
    const ru = obj[field];
    Object.defineProperty(obj, field, { get: () => tx(key, ru), enumerable: true, configurable: true });
  };
  const curId = () => F.db.project && F.db.project.id;

  F.addIcons(`
<symbol id="i-la-org"
  viewBox="0 0 16 16"><path d="M3 13.5V3.5a1 1 0 0 1 1-1h5a1 1 0 0 1 1 1v10M10 6.5h2a1 1 0 0 1 1 1v6M2 13.5h12M5.5 5h2M5.5 7.5h2M5.5 10h2"/></symbol>
<symbol id="i-la-wild" viewBox="0 0 16 16"><path d="M8 3v10M3.7 5.5l8.6 5M3.7 10.5l8.6-5"/></symbol>
<symbol id="i-la-range"
  viewBox="0 0 16 16"><path d="M2.5 8h11M5 5.5 2.5 8 5 10.5M11 5.5 13.5 8 11 10.5"/></symbol>
<symbol id="i-la-ban" viewBox="0 0 16 16"><circle cx="8" cy="8" r="5.5"/><path d="m4.2 4.2 7.6 7.6"/></symbol>
<symbol id="i-la-file"
  viewBox="0 0 16 16"><path d="M4 2.5h5.5L12 5v8.5H4z"/><path d="M9.5 2.5V5H12M8 7.5v4M6 9.5l2 2 2-2"/></symbol>`);

  // ---------- module badge ----------
  F.moduleBadge = (kind = "external") =>
    kind === "active" || kind === "target"
      ? `<span class="pill la-mb la-mb-hit">${ic("target")}${esc(tx("launch.badge_target", "обращается к цели"))}</span>`
      : `<span class="pill la-mb la-mb-ext">${ic("globe")}${esc(tx("launch.badge_external", "только внешние источники"))}</span>`;

  // ---------- target types and detection ----------
  // Network targets only: foca-engine scans every type listed here.
  const TYPES = {
    domain: { icon: "domain", label: "Домен" },
    wild: { icon: "la-wild", label: "Домен с поддоменами" },
    url: { icon: "link", label: "URL" },
    ip: { icon: "server", label: "IPv4" },
    cidr: { icon: "net", label: "Сеть CIDR" },
    range: { icon: "la-range", label: "Диапазон IP" },
    host: { icon: "server", label: "Хост" },
  };
  Object.keys(TYPES).forEach(
    k => /[А-я]/.test(TYPES[k].label) && lzField(TYPES[k], "label", "launch.type_" + k),
  );
  const NET = ["domain", "wild", "url", "ip", "cidr", "range", "host"];
  const ipParse = s => {
    const m = s.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
    if (!m) return { err: tx("launch.err_ip_incomplete", "неполный IP-адрес") };
    const o = m.slice(1).map(Number);
    const bad = o.find(x => x > 255);
    if (bad != null) return { err: tx("launch.err_octet", { n: bad }, "октет {n} больше 255") };
    return { n: o[0] * 16777216 + o[1] * 65536 + o[2] * 256 + o[3] };
  };
  const DOM = /^(?=.{3,253}$)([\p{L}\d]([\p{L}\d-]{0,61}[\p{L}\d])?\.)+\p{L}{2,}$/u;
  // A pasted list: one target per line, comma or semicolon; spaces separate targets too, except inside an
  // IP range written with spaces ("192.0.2.1 - 192.0.2.9").
  const RANGE_RE = /^[\d.]+\s*[-\u2013]\s*[\d.]+$/;
  function splitTargets(text) {
    return String(text || "")
      .split(/[\n\r,;]+/)
      .flatMap(chunk => {
        const c = chunk.trim();
        if (!c) return [];
        return RANGE_RE.test(c) ? [c] : c.split(/\s+/);
      })
      .filter(Boolean);
  }
  function parse(raw) {
    const text = raw.trim().replace(/\s+/g, " ");
    if (!text) return null;
    const ok = (type, v, extra = "") => ({ type, v, extra, key: type + ":" + v.toLowerCase() });
    const bad = (v, why) => ({ err: why, v });
    if (text.includes("@")) {
      const m = text.match(/^[^\s@]+@(([a-z0-9-]+\.)+[a-z]{2,})$/i);
      return bad(
        text,
        m
          ? tx(
              "launch.err_email_domain",
              { domain: m[1].toLowerCase() },
              "e-mail не является целью скана, введите домен {domain}",
            )
          : tx("launch.err_email", "e-mail не поддерживается: введите домен, URL, IP или CIDR"),
      );
    }
    if (/^[a-z]+:\/\//i.test(text)) {
      if (!/^https?:\/\//i.test(text))
        return bad(text, tx("launch.err_scheme", "поддерживаются только http и https"));
      try {
        const url = new URL(text);
        if (!DOM.test(url.hostname) && ipParse(url.hostname).err) throw 0;
        return ok("url", text);
      } catch (e) {
        return bad(text, tx("launch.err_url", "некорректный URL"));
      }
    }
    if (/^as[\s-]?\d+$/i.test(text))
      return bad(text, tx("launch.err_asn", "ASN не поддерживается как цель. Укажите домен, IP или CIDR"));
    let match = text.match(/^([\d.]+)\s?[-\u2013\u2014]\s?([\d.]+)$/);
    if (match) {
      let rangeEnd = match[2];
      if (/^\d{1,3}$/.test(rangeEnd)) rangeEnd = match[1].replace(/\d+$/, rangeEnd);
      const start = ipParse(match[1]),
        end = ipParse(rangeEnd);
      if (start.err)
        return bad(text, tx("launch.err_range_start", { err: start.err }, "начало диапазона: {err}"));
      if (end.err) return bad(text, tx("launch.err_range_end", { err: end.err }, "конец диапазона: {err}"));
      if (end.n < start.n) return bad(text, tx("launch.err_range_order", "конец диапазона меньше начала"));
      const n = end.n - start.n + 1;
      if (n > 65536)
        return bad(
          text,
          tx(
            "launch.err_range_big",
            { n: pl(n, "launch.pl_address", "адрес|адреса|адресов") },
            "слишком большой диапазон ({n}), максимум 65 536",
          ),
        );
      return ok("range", `${match[1]}-${rangeEnd}`, pl(n, "launch.pl_address", "адрес|адреса|адресов"));
    }
    match = text.match(/^([\d.]+)\/(\d{1,2})$/);
    if (match) {
      const base = ipParse(match[1]);
      if (base.err) return bad(text, base.err);
      const prefix = +match[2];
      if (prefix > 32) return bad(text, tx("launch.err_mask", "маска больше /32"));
      if (prefix < 16)
        return bad(
          text,
          tx("launch.err_net_wide", { prefix }, "слишком широкая сеть /{prefix}, минимум /16"),
        );
      return ok(
        "cidr",
        text,
        `/${prefix} = ${pl(2 ** (32 - prefix), "launch.pl_address", "адрес|адреса|адресов")}`,
      );
    }
    if (/^[\d.\s]+$/.test(text)) {
      const addr = ipParse(text);
      return addr.err ? bad(text, addr.err) : ok("ip", text);
    }
    match = text.match(/^\*\.(.+)$/);
    if (match)
      return DOM.test(match[1])
        ? ok("wild", "*." + match[1].toLowerCase())
        : bad(text, tx("launch.err_wild", "некорректный домен после «*.»"));
    if (DOM.test(text)) return ok("domain", text.toLowerCase());
    if (!text.includes(" ") && text.includes("."))
      return bad(text, tx("launch.err_domain", "некорректный домен"));
    if (!text.includes(" ") && /^[a-z0-9-]+$/i.test(text))
      return bad(text, tx("launch.err_tld", "домен без зоны (.ua, .com…)"));
    return bad(
      text,
      tx("launch.err_generic", "укажите сетевую цель: домен, *.домен, URL, IP, CIDR или диапазон IP"),
    );
  }
  F.parseTarget = parse;
  // Scope target ({v, type, active}) → wizard chip.
  const fromScope = t => {
    const r = parse(t.v);
    return r && !r.err
      ? r
      : {
          type: TYPES[t.type] ? t.type : "domain",
          v: t.v,
          extra: "",
          key: (t.type || "x") + ":" + String(t.v).toLowerCase(),
        };
  };
  const hostOf = t =>
    t.type === "url"
      ? (() => {
          try {
            return new URL(t.v).hostname;
          } catch (e) {
            return t.v;
          }
        })()
      : t.type === "wild"
        ? t.v.slice(2)
        : t.v;

  // ---------- profiles and modules ----------
  // kind: external, external sources only; target: regular requests to the target (downloads, DNS to the
  // target's NS, TCP), requires a scope check; active: the active phase (site file search, AXFR) against
  // network
  // scope targets. There are no confirmations: a scan starts with a single tap.
  const PROFILES = [
    {
      id: "passive",
      icon: "shield",
      t: "Пассивный",
      d: "Не обращается к цели: поисковые API, сертификаты, веб-архив, кэш Shodan, SaaS и Microsoft 365 по DNS.",
      kind: "external",
      time: "~5\u00a0мин",
    },
    {
      id: "std",
      icon: "scan",
      t: "Стандартный",
      d: "Пассивный + скачивание публичных документов, DNS-записи, проверка живости хостов, перебор поддоменов (топ-1500) и проверка TLS-сертификатов.",
      kind: "target",
      time: "~25\u00a0мин",
    },
    {
      id: "full",
      icon: "target",
      t: "Полный",
      d: "Стандартный + активная фаза: поиск забытых документов, бэкапов и служебных файлов на сайте, перенос зоны (AXFR) и обход NSEC, скан портов живых хостов (топ-100), аудит TLS (устаревшие версии, STARTTLS), перебор топ-5000. CVE: пассивно из Shodan InternetDB.",
      kind: "active",
      time: "~45\u00a0мин",
      warn: "Активная фаза",
    },
    { id: "custom", icon: "gear", t: "Свой", d: "Выберите модули вручную.", kind: null, time: "" },
  ];
  PROFILES.forEach(p => {
    lzField(p, "t", "launch.profile_" + p.id);
    ["d", "time", "warn"].forEach(f => p[f] && lzField(p, f, `launch.prof_${p.id}_${f}`));
  });
  const MODS = [
    [
      "search",
      "Поисковые API",
      "Startpage и Brave через встроенный браузер, без ключа; Brave API и SearXNG: по ключу",
      "external",
    ],
    ["crt", "Сертификаты crt.sh", "Поддомены из журналов CT", "external"],
    ["wayback", "Веб-архив", "Старые копии страниц и файлов", "external"],
    ["dns", "DNS", "Записи и поддомены у серверов имён цели", "target"],
    ["docs", "Скачивание документов", "Файлы с сайтов целей", "target"],
    ["alive", "Проверка живости (TCP)", "TCP-connect к 80/443 и типовым портам, без сканирования", "target"],
    [
      "subdomains",
      "Перебор поддоменов",
      "Имена из словаря и перестановки известных. DNS-запросы к серверам имён цели",
      "target",
    ],
    [
      "tls",
      "Проверка TLS-сертификатов",
      "Рукопожатие с открытыми TLS-портами живых хостов скоупа: срок, цепочка, имя, УЦ",
      "target",
    ],
    [
      "recon",
      "Разведка сайта",
      "Технологии, favicon, JS, robots/sitemap, облачные хранилища, grep.app: в «Пассивном» по архивной копии",
      "external",
    ],
    [
      "infra",
      "Инфраструктура по DNS",
      "SaaS и Microsoft 365, почтовые политики, CDN, история сертификатов, роли хостов: без обращения к цели",
      "external",
    ],
    ["axfr", "Перенос зоны (AXFR)", "Попытка получить всю зону у NS цели", "active"],
    ["nsec", "Обход зоны (NSEC)", "Список имён подписанной зоны у NS цели, как перенос зоны", "active"],
    [
      "ports",
      "Скан портов (TCP)",
      "Открытые порты, баннеры и версии сервисов на живых хостах скоупа. До 20 хостов, исключения не трогаются",
      "active",
    ],
    [
      "fuzz",
      "Поиск забытых файлов на сайте",
      "Документы, бэкапы, служебные файлы и листинги на сайте заказчика. Щадящий перебор с автостопом",
      "active",
    ],
  ];
  // Site file search modules (foca-fuzz; same ids as settings.fuzz.modules and wordlists_list.modules).
  const FZ_MODS = [
    ["docs", "Документы", "Типовые папки и имена офисных файлов, варианты известных имён (год, версия)"],
    ["backups", "Бэкапы", "Резервные копии известных файлов (.bak, ~, .old, .zip) и дампы баз"],
    ["exposed", "Служебные файлы", "Забытые .env, .git, .DS_Store, конфиги, с проверкой формата"],
    ["dirlisting", "Листинги каталогов", "Открытые «Index of /» и документы из них"],
    ["vhost", "Скрытые vhost", "Поддомены заказчика на том же адресе (только из скоупа)"],
    ["cms", "Пути CMS", "Только если CMS определена по найденным адресам"],
  ];
  MODS.forEach(m => {
    if (/[А-я]/.test(m[1])) lzField(m, 1, `launch.mod_${m[0]}`);
    lzField(m, 2, `launch.mod_${m[0]}_d`);
  });
  FZ_MODS.forEach(m => {
    lzField(m, 1, `launch.fz_${m[0]}`);
    lzField(m, 2, `launch.fz_${m[0]}_d`);
  });
  const MOD_KIND = Object.fromEntries(MODS.map(m => [m[0], m[3]]));
  // Same sets as default_modules() in foca-engine/src/scan/sources.rs (the wizard shows only modules from MODS; the
  // core also runs cc/meta/analysis/ct for every profile).
  const PROFILE_MODS = {
    passive: ["search", "crt", "wayback", "recon", "infra"],
    std: [
      "search",
      "crt",
      "wayback",
      "recon",
      "infra",
      "crawler",
      "dns",
      "docs",
      "alive",
      "subdomains",
      "tls",
    ],
    full: [
      "search",
      "crt",
      "wayback",
      "recon",
      "infra",
      "crawler",
      "dns",
      "docs",
      "alive",
      "subdomains",
      "tls",
      "axfr",
      "ports",
      "fuzz",
      "nsec",
    ],
  };
  /**
   * Sources shown in the wizard: `key` is the API-key id required by the source (null for keyless ones);
   * `via: "web"` marks sources queried through the embedded browser.
   * @type {{id: string, name: string, key: ?string, via?: string}[]}
   */
  const SRC_DEF = [
    { id: "startpage", name: "Startpage (выдача Google)", key: null, via: "web" },
    { id: "brave_web", name: "Brave Search", key: null, via: "web" },
    { id: "wayback", name: "Wayback Machine", key: null },
    { id: "cc", name: "Common Crawl", key: null },
    { id: "crt", name: "crt.sh", key: null },
    { id: "dns", name: "DNS / CT", key: null },
    { id: "brave", name: "Brave Search API", key: "brave" },
    { id: "searx", name: "SearXNG (свой адрес)", key: "searx" },
    { id: "shodan", name: "Shodan (кэш баннеров)", key: "shodan" },
    { id: "hibp", name: "Have I Been Pwned", key: "hibp" },
    { id: "censys", name: "Censys", key: "censys" },
    { id: "vt", name: "VirusTotal", key: "vt" },
  ];
  SRC_DEF.forEach(s => /[А-я]/.test(s.name) && lzField(s, "name", "launch.src_" + s.id));
  const keySt = id => {
    const k = ((F.db.settings || {}).keys || {})[id];
    return !k || k.status === "none" ? "need" : k.status === "error" ? "err" : "set";
  };
  // Document types offered in the wizard.
  // Document types grouped as in the core filter (foca-search DEFAULT_EXTS; related extensions such as
  // docm/jpeg/m4v are added by the core, scan.rs expand_exts).
  const DOC_GROUPS = [
    [
      "Документы и таблицы",
      ["doc", "docx", "xls", "xlsx", "ppt", "pptx", "pdf", "rtf", "odt", "ods", "odp", "sxw"],
    ],
    ["Схемы и вёрстка", ["vsdx", "vsd", "pub", "indd", "svg", "wpd", "wps"]],
    ["Почта, календари, контакты", ["eml", "msg", "ics", "vcf"]],
    ["Фото и видео", ["jpg", "png", "tiff", "heic", "mp4", "mov"]],
    ["Подключения, ярлыки, архивы", ["rdp", "ica", "lnk", "zip"]],
  ];
  const DOC_TYPES = DOC_GROUPS.flatMap(g => g[1]);
  const DOC_DEFAULT = [
    "doc",
    "docx",
    "xls",
    "xlsx",
    "ppt",
    "pptx",
    "pdf",
    "odt",
    "ods",
    "odp",
    "rdp",
    "ica",
    "lnk",
    "jpg",
    // 1.3 formats: diagrams, publications, mail/calendar/contact exports, HEIC photos and archives.
    "rtf",
    "vsdx",
    "vsd",
    "pub",
    "eml",
    "msg",
    "ics",
    "vcf",
    "heic",
    "zip",
  ];
  DOC_GROUPS.forEach((g, i) => lzField(g, 0, `launch.docgrp_${i}`));
  // User-Agent profiles: same ids as the core and Settings → Network (foca-net::ua); the value goes to
  // scan_start.ua.
  const UAS = {
    chrome: "Chrome · Windows (свежая версия)",
    chrome_android: "Chrome · Android",
    firefox: "Firefox · Windows",
    safari: "Safari · macOS",
    honest: "FOCA-rs (честный UA)",
    custom: "Свой (из «Настройки → Сеть»)",
  };
  ["chrome", "honest", "custom"].forEach(k => lzField(UAS, k, "launch.ua_" + k));
  const uaOf = v => ({ auto: "chrome", random: "chrome", foca: "honest" })[v] || (UAS[v] ? v : "chrome");
  const NETS = () => (F.db.settings || {}).net || {};

  // ---------- wizard state ----------
  const wiz = (F.state.launch = F.state.launch || {
    targets: [],
    errors: [],
    draft: "",
    files: [],
    adv: false,
    mods: {},
    src: {},
  });
  Object.assign(wiz, {
    mode: wiz.mode || "scan",
    newExcl: wiz.newExcl || [],
    docs: wiz.docs || DOC_DEFAULT.slice(),
    depth: wiz.depth || 2,
    maxDocs: wiz.maxDocs || 500,
    maxSize: wiz.maxSize || 50,
    ua: uaOf(wiz.ua || NETS().ua),
  });
  delete wiz.excl;
  // Site file search: modules and rate are seeded once from settings.fuzz and then edited in the wizard.
  const fzSeed = () => {
    if (wiz.fzMods) return;
    const z = (F.db.settings || {}).fuzz || {};
    wiz.fzMods = (z.modules || ["docs", "backups", "exposed", "dirlisting"]).slice();
    wiz.fzRate = Math.max(1, Math.min(10, Math.round(z.rate || 5)));
  };
  // Exclusions: a new project keeps its own list (sent with project_create); the current project uses
  // F.db.scope.excl (edited via F.api.scope_set).
  const exclList = () => (wiz.mode === "project" ? wiz.newExcl : (F.db.scope || {}).excl || []);
  Object.defineProperty(wiz, "excl", { configurable: true, get: exclList });
  const prof = () => PROFILES.find(p => p.id === wiz.profile) || PROFILES[0];
  const modsOn = () =>
    wiz.profile === "custom"
      ? MODS.map(m => m[0]).filter(k => wiz.mods[k])
      : PROFILE_MODS[wiz.profile] || PROFILE_MODS.passive;
  // Launch level: "active" when active modules are on (AXFR, fuzzing), "target" when modules contact the
  // target (scope applies), null for external sources only.
  const needConfirm = () => {
    const ms = modsOn();
    return ms.some(k => MOD_KIND[k] === "active")
      ? "active"
      : ms.some(k => MOD_KIND[k] === "target")
        ? "target"
        : null;
  };

  const addLine = line => {
    const r = parse(line);
    if (!r) return 0;
    if (r.err) {
      if (!wiz.errors.some(e => e.v === r.v)) wiz.errors.push(r);
      return 0;
    }
    if (wiz.targets.some(t => t.key === r.key)) return -1;
    wiz.targets.push(r);
    return 1;
  };
  const addText = (text, { quiet = false } = {}) => {
    let dup = 0,
      ok = 0;
    const bad0 = wiz.errors.length,
      n0 = wiz.targets.length;
    splitTargets(text).forEach(l => {
      const r = addLine(l);
      if (r === -1) dup++;
      if (r === 1) ok++;
    });
    const bad = wiz.errors.length - bad0;
    // Refused lines are listed right under the field; a snackbar only adds counts when something else happened.
    if (!quiet && (dup || (bad && ok)))
      F.snack(
        [
          ok ? tx("launch.imp_added", { n: ok }, "Добавлено: {n}") : "",
          dup ? tx("launch.imp_dup", { n: dup }, "дублей схлопнуто: {n}") : "",
          bad ? tx("launch.imp_bad", { n: bad }, "с ошибкой: {n}") : "",
        ]
          .filter(Boolean)
          .join(" · ")
          .replace(/^./, c => c.toUpperCase()),
      );
    void n0; // Targets entered in the New scan wizard are not written to the scope: they apply to this scan only (external sources).
    if (wiz.mode === "project" && !wiz.pnameTouched) wiz.pname = defaultName();
    return { ok, dup, bad };
  };
  // Wizard targets that are not in the project scope (this scan only, external sources only).
  const extraTargets = () => {
    const have = new Set(((F.db.scope || {}).targets || []).map(t => String(t.v).toLowerCase()));
    return wiz.mode === "scan" ? wiz.targets.filter(t => !have.has(t.v.toLowerCase())) : [];
  };
  const defaultName = () => {
    const t = wiz.targets.find(x => NET.includes(x.type)) || wiz.targets[0];
    return t ? hostOf(t) : "";
  };

  // New project draft: stored in settings.ui.new_draft, survives Back and reloads.
  const draftSaved = () => ((F.db.settings || {}).ui || {}).new_draft || null;
  const hasDraft = () =>
    wiz.mode === "project" &&
    (wiz.targets.length > 0 ||
      !!(wiz.pclient || "").trim() ||
      wiz.newExcl.length > 0 ||
      wiz.files.length > 0 ||
      wiz.errors.length > 0);
  const saveDraft = () =>
    F.api.settings_set({
      ui: {
        new_draft: {
          targets: wiz.targets.map(t => t.v),
          pname: wiz.pnameTouched ? wiz.pname : "",
          pclient: wiz.pclient || "",
          excl: wiz.newExcl.slice(),
          profile: wiz.profile,
          at: F.sel.scope.today,
        },
      },
    });
  const clearDraft = () => {
    if (draftSaved()) F.api.settings_set({ ui: { new_draft: null } });
  };
  F.launchDraft = draftSaved;
  function seed() {
    if (F.state.newDraft) {
      // /projects → "Continue draft".
      F.state.newDraft = false;
      const draft = draftSaved();
      F.state.newTarget = draft ? draft.targets.join("\n") : "";
      seed();
      if (draft) {
        Object.assign(wiz, {
          pclient: draft.pclient || "",
          newExcl: (draft.excl || []).slice(),
          profile: draft.profile || "passive",
        });
        if (draft.pname) Object.assign(wiz, { pname: draft.pname, pnameTouched: true });
      }
      return;
    }
    if (F.state.newTarget != null) {
      // From /projects: new project.
      const target = F.state.newTarget;
      F.state.newTarget = null;
      Object.assign(wiz, {
        mode: "project",
        targets: [],
        errors: [],
        files: [],
        draft: "",
        newExcl: [],
        pname: "",
        pclient: "",
        pnameTouched: false,
        profile: "passive",
        leave: false,
        seededFor: "new",
        netcheck: null,
        resume: null,
      });
      wiz.mods = Object.fromEntries(MODS.map(m => [m[0], PROFILE_MODS.passive.includes(m[0])]));
      wiz.src = Object.fromEntries(SRC_DEF.map(src => [src.id, !src.key || keySt(src.key) === "set"]));
      wiz.docs = DOC_DEFAULT.slice();
      wiz.threads = NETS().threads || 8;
      wiz.rps = NETS().rps || 10;
      if (target) addText(target, { quiet: true }); // The wizard lists the targets and refused lines itself.
      wiz.pname = defaultName();
      return;
    }
    if (!curId()) {
      if (wiz.mode !== "project") {
        F.state.newTarget = "";
        return seed();
      }
      return;
    }
    if (wiz.mode === "project" && !wiz.leave) return; // Returned to the new-project wizard (e.g. from key settings).
    if (!wiz.leave && wiz.mode === "scan" && wiz.seededFor === curId()) return;
    // New scan in the current project: targets come from the scope, discovered file types are preselected.
    const sc = F.db.scope || {},
      last = F.sel.lastScan();
    Object.assign(wiz, {
      mode: "scan",
      targets: (sc.targets || []).map(fromScope),
      errors: [],
      files: [],
      draft: "",
      leave: false,
      seededFor: curId(),
      netcheck: null,
      resume: null,
      profile: last && last.profile_id === "std" ? "std" : "passive",
    });
    wiz.mods = Object.fromEntries(MODS.map(m => [m[0], PROFILE_MODS.std.includes(m[0])]));
    wiz.src = Object.fromEntries(SRC_DEF.map(src => [src.id, !src.key || keySt(src.key) === "set"]));
    const found = [...new Set((F.db.docs || []).map(d => d.ext))].filter(e => DOC_TYPES.includes(e));
    wiz.docs = [...new Set(DOC_DEFAULT.concat(found))];
    wiz.foundExts = found;
    wiz.threads = NETS().threads || 8;
    wiz.rps = NETS().rps || 10;
  }

  // ---------- /new building blocks ----------
  const chip = (t, i) => {
    const ty = TYPES[t.type] || TYPES.domain;
    return `<div class="la-chip"><span class="la-chip-ic">${ic(ty.icon)}</span><span class="la-chip-b"><span class="la-chip-v">${esc(t.v)}</span><span class="la-chip-t">${ty.label}${t.extra ? " · " + esc(t.extra) : ""}</span></span><button class="la-chip-x"
      data-act="la-del:${i}" aria-label="${esc(tx("launch.chip_del_aria", { v: t.v }, "Удалить {v}"))}">${ic("x")}</button></div>`;
  };
  const errChip = (e, i) =>
    `<div class="la-errrow"><div class="la-chip bad"><span class="la-chip-ic">${ic("alert")}</span><span class="la-chip-b"
      data-act="la-fix:${i}" role="button"
      aria-label="${esc(tx("launch.chip_fix_aria", "Исправить"))}"><span class="la-chip-v">${esc(e.v)}</span><span class="la-chip-t">${esc(e.err)}</span></span><button class="la-chip-x"
      data-act="la-delerr:${i}" aria-label="${esc(tx("launch.chip_drop_aria", "Убрать строку"))}">${ic("x")}</button></div></div>`;
  function targetsBlock() {
    const cnt = {};
    wiz.targets.forEach(t => (cnt[t.type] = (cnt[t.type] || 0) + 1));
    const sum = Object.entries(cnt)
      .map(([k, n]) => `${(TYPES[k] || TYPES.domain).label}: ${n}`)
      .join(" · ");
    return `
      ${wiz.targets.length ? `<div class="la-chips">${wiz.targets.map(chip).join("")}</div>` : wiz.errors.length ? `<p class="la-none">${esc(tx("launch.none_fix", "Корректных целей пока нет: исправьте строки с ошибкой ниже."))}</p>` : `<p class="la-none">${esc(wiz.mode === "scan" ? tx("launch.none_scan", "В скоупе проекта нет целей. Добавьте их на экране «Скоуп» или введите здесь. Для этого скана, только внешние источники.") : tx("launch.none_new", "Целей пока нет. Добавьте домен (example.com, *.example.com), URL (http/https), IP, CIDR или диапазон IP."))}</p>`}
      ${
        wiz.mode === "scan" && extraTargets().length
          ? `<p class="fhint la-extra">${ic("info")}${esc(tx("launch.extra_pre", "Не из скоупа:"))} ${esc(
              extraTargets()
                .map(t => t.v)
                .join(", "),
            )}: ${esc(tx("launch.extra_post", "только для этого скана и только внешние источники. Запросы к цели: после добавления в скоуп."))}</p>`
          : ""
      }
      ${wiz.errors.length ? `<div class="la-errs"><div class="la-errh">${ic("alert")}${esc(tx("launch.unrecognized", { n: wiz.errors.length }, "Не распознано: {n}"))}<span>${esc(tx("launch.tap_to_fix", "нажмите, чтобы исправить"))}</span></div>${wiz.errors.map(errChip).join("")}</div>` : ""}
      ${wiz.targets.length ? `<p class="la-sum"><b>${pl(wiz.targets.length, "launch.pl_target", "цель|цели|целей")}:</b> ${esc(sum)}</p>` : ""}`;
  }
  function filesBlock() {
    if (!wiz.files.length) return "";
    return `<div class="list la-files">${wiz.files
      .map((f, i) =>
        ui.row({
          lead: f.dir ? ui.leadIcon("folder") : `<span class="ext ${esc(f.ext)}">${esc(f.ext)}</span>`,
          title: esc(f.name),
          sub: esc(f.sub),
          tail: `<button class="ib"
      data-act="la-file-del:${i}"
      aria-label="${esc(tx("launch.file_del_aria", { name: f.name }, "Убрать {name}"))}">${ic("x")}</button>`,
        }),
      )
      .join("")}</div>`;
  }
  // Numeric input with ± (F.numField from help.js), applied on blur/Enter.
  const nfL = (key, label, unit, min, max, rec, note, help, whyMax, whyMin, step = 1, after) =>
    F.numField({
      id: "la-" + key,
      label,
      unit,
      min,
      max,
      step,
      rec,
      note,
      help,
      whyMax,
      whyMin,
      get: () => +wiz[key],
      set: v => {
        wiz[key] = v;
        if (after) after(v);
      },
    });
  // Threads and requests/s are shared with Settings → Network (settings.net), not limited to this scan.
  const nfNet = (key, label, unit, min, max, rec, note, help, whyMax, whyMin) =>
    F.numField({
      id: "la-net-" + key,
      label,
      unit,
      min,
      max,
      step: 1,
      rec,
      note,
      help,
      whyMax,
      whyMin,
      get: () => +(NETS()[key] || { threads: 4, hosts_parallel: 4 }[key] || 5),
      set: v => {
        F.api.settings_set({ net: { [key]: v } });
      },
    });
  function proxyBlock() {
    const n = NETS(),
      c = wiz.netcheck;
    return `<div class="list la-net">${ui.row({
      lead: ui.leadIcon("shield", n.proxy_on ? "var(--ok)" : "var(--bad)"),
      title: n.proxy_on ? esc(`${n.label || n.type} · ${n.addr}`) : esc(tx("launch.no_proxy", "Без прокси")),
      sub: n.proxy_on
        ? `${esc(tx("launch.out_ip", { ip: n.out_ip || "-" }, "Выходной IP {ip}"))}${n.out_country ? " · " + esc(n.out_country) : ""} · ${esc(n.kill_switch ? tx("launch.ks_on", "защита от утечки IP включена") : tx("launch.ks_off", "защита от утечки IP выключена"))}`
        : esc(tx("launch.real_ip", "Запросы пойдут с вашего реального IP")),
    })}</div>
      ${c ? `<p class="fhint la-nc ${c.ok ? "" : "err"}">${ic(c.ok ? "check" : "alert")}${c.ok ? `${esc(tx("launch.net_checked", { ip: c.out_ip }, "Проверено: выходной IP {ip}"))} · ${esc(c.country)} (${esc(c.via)})` : esc(tx("launch.proxy_dead", "Прокси не отвечает"))}</p>` : ""}
      <div class="btnrow la-netb"><button class="btn tonal"
        data-act="la-netcheck">${ic("refresh")}${esc(tx("launch.check", "Проверить"))}</button><button class="btn"
        data-act="go:/settings/network">${ic("gear")}${esc(tx("launch.change", "Изменить"))}</button></div>`;
  }

  function advBlock() {
    return `
      <h3 class="sub-h la-h3">${esc(tx("launch.excl_h", "Исключения (вне скоупа)"))}${wiz.mode === "scan" ? `<small class="la-h3s">${esc(tx("launch.excl_shared", "общие со скоупом проекта"))}</small>` : ""}</h3>
      ${
        wiz.excl.length
          ? `<div class="la-chips">${wiz.excl
              .map(
                (
                  x,
                  i,
                ) => `<div class="la-chip ex"><span class="la-chip-ic">${ic("la-ban")}</span><span class="la-chip-b"><span class="la-chip-v">${esc(x)}</span></span><button class="la-chip-x"
        data-act="la-excl-del:${i}"
        aria-label="${esc(tx("launch.excl_del_aria", { v: x }, "Удалить исключение {v}"))}">${ic("x")}</button></div>`,
              )
              .join("")}</div>`
          : `<p class="la-none">${esc(tx("launch.excl_none", "Исключений нет."))}</p>`
      }
      <div class="la-inline"><div class="field">${ic("la-ban")}<input id="la-excl"
        placeholder="${esc(tx("launch.excl_ph", "Хост или сеть"))}" autocapitalize="off" spellcheck="false"
        enterkeyhint="done"></div><button class="btn tonal" data-act="la-excl-add">${esc(tx("common.add", "Добавить"))}</button></div>

      <h3 class="sub-h la-h3">${esc(tx("launch.doc_types", "Типы документов"))}${wiz.foundExts && wiz.foundExts.length ? `<small class="la-h3s">${esc(tx("launch.doc_types_found", "найденные в проекте выбраны"))}</small>` : ""}</h3>
      ${DOC_GROUPS.map(
        ([label, exts]) =>
          `<div class="la-dg">${esc(label)}</div><div class="chips wrap la-docs">${exts
            .map(
              d => `<button class="chip ${wiz.docs.includes(d) ? "on" : ""}"
        data-act="la-doc:${d}" aria-pressed="${wiz.docs.includes(d)}">.${d}</button>`,
            )
            .join("")}</div>`,
      ).join("")}

      <h3 class="sub-h la-h3">${esc(tx("launch.crawl_depth", "Глубина краулера, уровней"))}</h3>
      <div class="seg"
        role="radiogroup">${[1, 2, 3, 5]
          .map(
            n => `<button class="${wiz.depth === n ? "on" : ""}" role="radio"
        aria-checked="${wiz.depth === n}" data-act="la-depth:${n}">${n}</button>`,
          )
          .join("")}</div>

      <h3 class="sub-h la-h3">${esc(tx("launch.limits", "Лимиты"))}</h3>
      <div class="card nfs la-nfs">${nfL("maxDocs", tx("launch.nf_maxdocs", "Документов на цель"), "", 50, 5000, [200, 1000], tx("launch.nf_maxdocs_note", "больше: дольше скачивание"), "set-limits", tx("launch.nf_maxdocs_max", "столько документов телефон будет качать часами"), tx("launch.nf_maxdocs_min", "меньше 50: можно пропустить важное"), 50)}${nfL("maxSize", tx("launch.nf_maxsize", "Размер файла, до"), tx("launch.nf_mb", "МБ"), 5, 500, [20, 100], tx("launch.nf_maxsize_note", "крупнее: редко документы"), "set-limits", tx("launch.nf_maxsize_max", "такие файлы почти всегда видео или архивы"), tx("launch.nf_maxsize_min", "многие PDF больше 5 МБ"), 5)}</div>

      <h3 class="sub-h la-h3">${esc(tx("launch.net", "Сеть"))}</h3>
      <p class="fhint la-nh">${esc(tx("launch.net_hint", "Весь трафик скана идёт через прокси из настроек. Один для мастера и скана."))}</p>
      ${proxyBlock()}
      <label class="flabel" for="la-ua">User-Agent</label>
      ${ui.select({
        id: "la-ua",
        value: wiz.ua,
        title: "User-Agent",
        attrs: 'data-key="ua"',
        options: Object.entries(UAS).map(([k, v]) => ({ v: k, t: v })),
      })}
      <div class="card nfs la-nfs la-steps2">${nfNet("threads", tx("launch.nf_threads", "Потоков"), "", 1, 64, [4, 8], tx("launch.nf_threads_note", "больше: риск бана"), "set-threads", tx("launch.nf_threads_max", "телефон и сеть больше не вытянут"), tx("launch.nf_threads_min", "нужен хотя бы один поток"))}${nfNet("rps", tx("launch.nf_rps", "Запросов в сек."), tx("launch.nf_per_s", "/с"), 1, 100, [5, 10], tx("launch.nf_rps_note", "на один хост"), "set-rps", tx("launch.nf_rps_max", "так быстро сайт почти наверняка заблокирует"), tx("launch.nf_rps_min", "меньше одного запроса в секунду ядро не поддерживает"))}${nfNet("hosts_parallel", tx("launch.nf_hosts_parallel", "Хостов одновременно"), "", 1, 8, [2, 4], tx("launch.nf_hosts_parallel_note", "1: по очереди"), "set-hosts-parallel", tx("launch.nf_hosts_parallel_max", "больше 8 хостов сразу телефон не потянет"), tx("launch.nf_hosts_parallel_min", "нужен хотя бы один хост"))}</div>
      <p class="fhint">${esc(tx("launch.net_shared", "Потоки, запросы в секунду и хосты одновременно. Общие с «Настройки → Сеть». Скан не превысит лимит запросов к одному хосту, даже при большом числе потоков."))}</p>`;
  }

  // The core sends the RU note with a message code (`note_msg`); the text is the fallback.
  const fzNote = e => {
    if (!e.note) return tx("launch.fz_est_nohosts", "Нет веб-адресов в скоупе");
    return e.note_msg && F.coreMsg ? F.coreMsg(e.note, e.note_msg) : e.note;
  };
  const fzEstText = () => {
    const e = wiz.fzEst;
    if (wiz.mode === "project" || !curId())
      return `${ic("info")}${esc(tx("launch.fz_est_later", { n: fmt(((F.db.settings || {}).fuzz || {}).max_requests || 3000) }, "Оценка запросов появится после создания проекта; общий бюджет: до {n} запросов."))}`;
    if (!e) return `${ic("clock")}${esc(tx("launch.fz_est_calc", "Считаем объём перебора…"))}`;
    if (e.error)
      return `${ic("alert")}${esc(tx("launch.fz_est_err", { err: e.error }, "Оценка недоступна: {err}"))}`;
    if (!e.hosts || !e.hosts.length) return `${ic("info")}${esc(fzNote(e))}`;
    const m = Math.max(1, Math.round((e.seconds || 0) / 60));
    return `${ic("clock")}${esc(F.tp ? F.tp("launch.fz_est", e.requests, { n: fmt(e.requests), m, rate: wiz.fzRate }, "≈ {n} запрос · ≈ {m} мин при {rate} запр/с|≈ {n} запроса · ≈ {m} мин при {rate} запр/с|≈ {n} запросов · ≈ {m} мин при {rate} запр/с") : tx("launch.fz_est", { n: fmt(e.requests), m, rate: wiz.fzRate }, "≈ {n} запросов · ≈ {m} мин при {rate} запр/с"))} · ${pl(e.hosts.length, "launch.pl_address", "адрес|адреса|адресов")}${e.capped_by_budget ? " · " + esc(tx("launch.fz_capped", "упирается в бюджет")) : ""}`;
  };
  let fzTimer = null;
  function fzEstimate() {
    clearTimeout(fzTimer);
    if (wiz.mode === "project" || !curId() || !modsOn().includes("fuzz")) return;
    fzTimer = setTimeout(
      () =>
        F.api
          .fuzz_estimate({ project: curId(), modules: wiz.fzMods, rate: wiz.fzRate })
          .then(
            r => {
              wiz.fzEst = r;
            },
            e => {
              wiz.fzEst = { error: e.message || String(e) };
            },
          )
          .then(() => {
            const el = document.getElementById("la-fz-est");
            if (el) el.innerHTML = fzEstText();
          }),
      200,
    );
  }
  function fuzzBlock() {
    if (!modsOn().includes("fuzz")) return "";
    fzSeed();
    return `<div class="card pad la-fz" id="la-fz">
      <h3 class="sub-h la-h3 la-fz-h">${ic("folder")}${esc(tx("launch.mod_fuzz", "Поиск забытых файлов на сайте"))}</h3>
      <p class="la-fz-d">${esc(tx("launch.fz_d", "Ищет на сайте заказчика забытые документы, резервные копии, служебные файлы и открытые листинги, чтобы владелец их убрал. Только цели из скоупа, исключения не запрашиваются; если сайт начнёт ограничивать запросы, перебор остановится сам."))}</p>
      <div class="la-fz-mods">${FZ_MODS.map(([k, t, d]) => ui.check(wiz.fzMods.includes(k), esc(t), "la-fz-mod:" + k, esc(d))).join("")}</div>
      <div class="card nfs la-nfs la-fz-rate">${nfL(
        "fzRate",
        tx("launch.fz_rate", "Скорость, запросов в секунду"),
        tx("launch.nf_per_s", "/с"),
        1,
        10,
        [3, 5],
        tx("launch.fz_rate_note", "сайт не должен заметить нагрузку"),
        "set-fuzz",
        tx("wordlists.nf_rate_why_max", "быстрее перебор по сайту заказчика не идёт"),
        tx("wordlists.nf_rate_why_min", "меньше одного запроса в секунду не бывает"),
        1,
        () => {
          wiz.fzEst = null;
          fzEstimate();
        },
      )}</div>
      <p class="fhint la-fz-est" id="la-fz-est" aria-live="polite">${fzEstText()}</p>
      <p class="fhint la-fz-ack">${ic("info")}${esc(tx("launch.fz_wordlists", "Словари: в «Настройках → Словари»."))}</p>
    </div>`;
  }

  // Subdomain brute force wordlist (scan_start.subdomains): off / top-1500 / top-5000 / own words. Defaults to
  // settings.subdomains, otherwise the profile's choice (top-5000 in the full profile, as the core).
  const SUB_WL = [
    ["off", "Выкл"],
    ["top-1500", "Топ-1500"],
    ["top-5000", "Топ-5000"],
    ["custom", "Свой"],
  ];
  SUB_WL.forEach(w => lzField(w, 1, "launch.subwl_" + w[0].replace("-", "_")));
  const subWl = () =>
    wiz.subWl ||
    ((F.db.settings || {}).subdomains || {}).wordlist ||
    (needConfirm() === "active" ? "top-5000" : "top-1500");
  const subWords = () =>
    String(wiz.subCustom || "")
      .split(/[\s,;]+/)
      .map(w => w.trim().toLowerCase())
      .filter(w => /^[a-z0-9_-]+(\.[a-z0-9_-]+)*$/.test(w));
  function subBlock() {
    if (!modsOn().includes("subdomains")) return "";
    const wl = subWl();
    const hint = {
      off: tx(
        "launch.subhint_off",
        "Перебор не запускается; перестановки известных имён и PTR адресов скоупа работают.",
      ),
      "top-1500": tx("launch.subhint_1500", "1500 самых частых имён (SecLists), несколько минут."),
      "top-5000": tx(
        "launch.subhint_5000",
        "5000 имён: шире охват, дольше и заметнее для DNS-серверов цели.",
      ),
      custom: tx("launch.subhint_custom", "Свои имена: по одному в строке или через запятую."),
    }[wl];
    return `<div class="card pad la-sub" id="la-sub">
      <h3 class="sub-h la-h3">${ic("domain")}${esc(tx("launch.sub_title", "Перебор поддоменов"))}${F.helpBtn ? F.helpBtn("subdomains-help", tx("launch.sub_title", "Перебор поддоменов")) : ""}</h3>
      <p class="la-fz-d">${esc(tx("launch.sub_d1", "Ищет имена вида"))} <span class="mono">${esc(tx("launch.sub_d_name", "имя.домен"))}</span> ${esc(tx("launch.sub_d2", "запросами к DNS цели. Её серверы имён видят эти запросы. Только домены скоупа, без исключений; ответы «на любое имя» (wildcard) отбрасываются."))}</p>
      <div class="seg la-sub-seg" role="radiogroup" aria-label="${esc(tx("launch.sub_wl_aria", "Словарь перебора"))}">${SUB_WL.map(
        ([k, l]) => `<button class="${wl === k ? "on" : ""}" role="radio"
        aria-checked="${wl === k}" data-act="la-sub-wl:${k}">${esc(l)}</button>`,
      ).join("")}</div>
      <p class="fhint">${esc(hint)}</p>
      ${
        wl === "custom"
          ? `<label class="flabel" for="la-sub-words">${esc(tx("launch.sub_custom_label", "Свой словарь"))}</label>
      <div class="field la-ta">${ic("domain")}<textarea id="la-sub-words" rows="3" placeholder="vpn&#10;portal&#10;crm" autocapitalize="off" spellcheck="false">${esc(wiz.subCustom || "")}</textarea></div>
      <p class="fhint" id="la-sub-n">${esc(subWords().length ? tx("launch.sub_words", { n: subWords().length }, "Слов: {n}") : tx("launch.sub_words_none", "Добавьте хотя бы одно имя"))}</p>`
          : ""
      }
    </div>`;
  }

  // Port scan: top 100 (default) or top 1000, as a segmented control like the crawler depth.
  const portsTop = () => wiz.portsTop || (((F.db.settings || {}).ports || {}).top >= 1000 ? 1000 : 100);
  function portsBlock() {
    if (!modsOn().includes("ports")) return "";
    const top = portsTop();
    return `<div class="card pad la-ports" id="la-ports">
      <h3 class="sub-h la-h3">${ic("server")}${esc(tx("launch.ports_h", "Скан портов"))}</h3>
      <p class="la-fz-d">${esc(tx("launch.ports_d", { n: ((F.db.settings || {}).ports || {}).max_hosts || 20 }, "Проверяет TCP-порты живых хостов из скоупа (до {n} за скан), читает баннеры и версии сервисов. Хосты из исключений не трогаются."))}</p>
      <div class="seg" role="radiogroup"
        aria-label="${esc(tx("launch.ports_aria", "Сколько портов"))}">${[100, 1000]
          .map(
            n => `<button class="${top === n ? "on" : ""}"
        role="radio" aria-checked="${top === n}"
        data-act="la-ports-top:${n}">${esc(tx("launch.ports_top", { n }, "Топ-{n}"))}</button>`,
          )
          .join("")}</div>
      <p class="fhint">${esc(top === 100 ? tx("launch.ports_100", "~1 с на хост, самые распространённые сервисы") : tx("launch.ports_1000", "до ~15 с на хост. Шире охват, больше соединений"))}. ${esc(tx("launch.ports_custom", "Свой список портов: в «Настройках → Сеть»."))}</p>
    </div>`;
  }

  function projectBlock() {
    if (wiz.mode !== "project") return "";
    return `${ui.secH(tx("launch.project", "Проект"))}
      <label class="flabel" for="la-pname">${esc(tx("launch.pname", "Имя проекта"))}</label>
      <div class="field">${ic("folder")}<input id="la-pname" value="${esc(wiz.pname || "")}"
        placeholder="${esc(defaultName() || tx("launch.pname_ph", "По первому домену"))}" autocapitalize="off"
        spellcheck="false"></div>
      <label class="flabel" for="la-pclient">${esc(tx("launch.client", "Заказчик"))} <span class="muted">${esc(tx("launch.optional", "(необязательно)"))}</span></label>
      <div class="field">${ic("la-org")}<input id="la-pclient" value="${esc(wiz.pclient || "")}"
        placeholder="${esc(tx("launch.client_ph", "Название организации"))}"></div>
      <p class="fhint">${esc(tx("launch.project_hint", "Проект создаётся при запуске скана или по кнопке «Сохранить»."))}</p>`;
  }

  // A single "N keyless sources" row → Settings → Sources; API keys live in settings only.
  function srcBlock() {
    const f = F.sourcesFree ? F.sourcesFree() : { total: 0, on: 0, names: [] };
    const all = f.on === f.total,
      names = f.names.filter(n => /Startpage|Brave|Wayback|crt\.sh/.test(n)).slice(0, 4);
    return `<h3 class="sub-h la-h3">${esc(tx("launch.sources", "Источники"))}</h3>
      <div class="list la-srcs">${ui.row({
        lead: ui.leadIcon("search", "var(--accent)"),
        title: esc(
          tx(
            "launch.src_keyless",
            { n: pl(f.on, "launch.pl_source", "источник|источника|источников") },
            "{n} без ключей",
          ),
        ),
        sub: `${esc(tx("launch.src_names_more", { names: (names.length ? names : f.names.slice(0, 4)).join(", ") }, "{names} и др."))}<div class="la-src-p"><span class="pill ${all ? "ok" : "mute"}">${all ? `${ic("check")}${esc(tx("launch.src_all_on", "все включены"))}` : esc(tx("launch.src_off_n", { n: f.total - f.on }, "выключено {n}"))}</span></div>`,
        act: "go:/settings/sources",
        chev: true,
        cls: "la-srcrow",
      })}</div>
      <p class="fhint la-srch">${esc(tx("launch.src_hint", "Ключи API не нужны. Если добавите их в «Настройках → Ключи API», платные источники подключатся сами."))}</p>`;
  }

  function renderNew() {
    seed();
    return `
      ${projectBlock()}
      ${ui.secH(
        tx("launch.targets", "Цели"),
        wiz.targets.length || "",
        wiz.mode === "scan"
          ? `<button class="sec-a"
        data-act="go:/p/scope">${esc(tx("launch.scope", "Скоуп"))}</button>`
          : "",
      )}
      <div class="field la-ta">${ic("target")}<textarea id="la-in" rows="3"
        placeholder="${esc(tx("launch.targets_ph", "Домен (example.com, *.example.com), URL (http/https), IP или CIDR: по одной в строке"))}"
        title="${esc(tx("launch.targets_ph", "Домен (example.com, *.example.com), URL (http/https), IP или CIDR: по одной в строке"))}"
        autocapitalize="off" spellcheck="false">${esc(wiz.draft)}</textarea><button class="ib la-add"
        data-act="la-commit" aria-label="${esc(tx("launch.commit_aria", "Добавить цели из поля"))}">${ic("plus")}</button></div>
      <div class="la-btns"><button class="btn tonal"
        data-act="la-paste">${ic("paste")}${esc(tx("launch.from_clipboard", "Из буфера"))}</button>${
          F.isDemo
            ? `<button class="btn"
        data-act="la-import"
        aria-label="${esc(tx("launch.from_file_aria", "Импорт из файла .txt или .csv"))}">${ic("la-file")}${esc(tx("launch.from_file", "Из файла"))}</button>`
            : ""
        }</div>
      <div id="la-tg">${targetsBlock()}</div>

      ${ui.secH(tx("launch.local_files", "Локальные файлы"), wiz.files.length || "")}
      <p class="lead">${esc(tx("launch.local_files_d", "Документы с флешки или из папки будут разобраны вместе с найденными в сети."))}</p>
      ${filesBlock()}
      <button class="btn block la-addfiles"
        data-act="la-files">${ic("folder")}${esc(tx("launch.add_local_files", "Добавить локальные файлы"))}</button>

      ${ui.secH(tx("launch.scan_profile", "Профиль скана"))}
      <div class="la-profs" role="radiogroup" aria-label="${esc(tx("launch.scan_profile", "Профиль скана"))}">${PROFILES.map(
        pr => `
        <div class="card la-prof ${wiz.profile === pr.id ? "on" : ""}" role="radio"
          aria-checked="${wiz.profile === pr.id}" tabindex="0" data-act="la-prof:${pr.id}">
          <span class="radio la-radio"></span>
          <div class="la-prof-b">
            <div class="la-prof-t">${ic(pr.icon)}<b>${esc(pr.t)}</b>${pr.time ? `<span class="muted">${esc(pr.time)}</span>` : ""}</div>
            <div class="la-prof-d">${esc(pr.d)}</div>
            ${pr.kind ? `<div class="la-prof-p">${F.moduleBadge(pr.kind)}${pr.warn ? `<span class="pill warn">${ic("shield")}${esc(pr.warn)}</span>` : ""}</div>` : ""}
          </div>
        </div>`,
      ).join("")}</div>
      ${srcBlock()}
      ${wiz.profile === "custom" ? `<div class="list la-mods">${MODS.map(([k, t, d, kind]) => `<div class="row la-mod">${ui.leadIcon(kind === "external" ? "globe" : "target", kind === "active" ? "var(--bad)" : kind === "target" ? "var(--warn)" : "")}<div class="body"><div class="t">${esc(t)}</div><div class="s">${esc(d)}</div><div class="la-src-p">${F.moduleBadge(kind)}${kind === "active" ? `<span class="pill warn">${ic("contract")}${esc(tx("launch.by_contract", "по договору"))}</span>` : ""}</div></div><div class="tail">${ui.toggle(wiz.mods[k], `la-mod:${k}`, `aria-label="${esc(t)}"`)}</div></div>`).join("")}</div>` : ""}

      ${subBlock()}
      ${portsBlock()}
      ${fuzzBlock()}

      <div class="card la-adv ${wiz.adv ? "open" : ""}">
        <button class="la-adv-h" data-act="la-adv"
          aria-expanded="${wiz.adv}">${ic("filter")}<span><b>${esc(tx("launch.adv", "Дополнительно"))}</b><small>${esc(tx("launch.adv_sub", "Исключения, типы файлов, глубина, лимиты, сеть"))}</small></span>${ic("chev-down", "la-adv-c")}</button>
        ${wiz.adv ? `<div class="la-adv-b">${advBlock()}</div>` : ""}
      </div>

      <div id="la-bg">${F.launchBgHint()}</div>

      <div class="foot la-foot">
        <div class="foot-s la-foot-s" id="la-fs">${footSum()}</div>
        ${
          wiz.mode === "project"
            ? `<div class="btnrow la-fbtns"><button class="btn" id="la-save"
          data-act="la-save-only"
          ${wiz.targets.length ? "" : "disabled"}>${ic("save")}${esc(tx("common.save", "Сохранить"))}</button>${startBtn()}</div>`
            : startBtn()
        }
      </div>`;
  }
  // Autostart/battery card from Settings › Background (settings.js, F.bgSetup) on firmwares that kill
  // background apps; empty when everything is set or the device is not one of them.
  F.launchBgHint = () => {
    const card = F.bgSetup ? F.bgSetup.launchCard() : "";
    return card
      ? `${ui.secH(tx("launch.bg_title", "Чтобы прошивка не остановила скан"))}<p class="lead">${esc(tx("launch.bg_lead", "Скан может идти долго. Эта прошивка закрывает приложения в фоне. Проверьте два пункта перед запуском."))}</p>${card}`
      : "";
  };
  const startLabel = () =>
    wiz.mode === "project"
      ? tx("launch.start_project", "Создать проект и запустить")
      : wiz.resume
        ? tx("launch.start_resume", "Продолжить скан")
        : tx("launch.start", "Запустить");
  const startBtn = () =>
    `<button class="btn primary ${wiz.mode === "project" ? "" : "block"}" id="la-start"
      data-act="la-start" ${wiz.targets.length ? "" : "disabled"}>${ic("play")}${esc(startLabel())}</button>`;
  const footSum = () =>
    wiz.targets.length
      ? esc(
          `${wiz.mode === "project" ? tx("launch.new_project", "Новый проект") + " · " : ""}${pl(wiz.targets.length, "launch.pl_target", "цель|цели|целей")}${wiz.files.length ? ` + ${pl(wiz.files.length, "launch.pl_file", "файл|файла|файлов")}` : ""} · ${prof().t}${prof().time ? " · " + prof().time : ""}`,
        )
      : `<span class="foot-w la-foot-w">${ic("info")}${esc(tx("launch.need_target", "Добавьте хотя бы одну цель"))}</span>`;

  function refreshTargets() {
    const pg = F.page();
    if (!pg || !pg.querySelector("#la-tg")) return;
    pg.querySelector("#la-tg").innerHTML = targetsBlock();
    pg.querySelector("#la-fs").innerHTML = footSum();
    const startBtn = pg.querySelector("#la-start");
    startBtn.disabled = !wiz.targets.length;
    const sv = pg.querySelector("#la-save");
    if (sv) sv.disabled = !wiz.targets.length;
    const countEl = pg.querySelector(".sec-h .muted");
    if (countEl && wiz.mode === "scan") countEl.textContent = wiz.targets.length || "";
    const pn = pg.querySelector("#la-pname");
    if (pn && !wiz.pnameTouched) {
      pn.value = wiz.pname || "";
    }
  }

  F.route("/new", {
    title: () =>
      F.state.newTarget != null || wiz.mode === "project" || !curId()
        ? tx("launch.new_project", "Новый проект")
        : tx("launch.title", "Новый скан"),
    sub: () =>
      F.state.newTarget != null || wiz.mode === "project" || !curId()
        ? tx("launch.new_sub", "Цели, профиль и запуск")
        : F.project
          ? F.project.name
          : "",
    nav: false,
    back: true,
    actions: [],
    hideMini: true,
    render: () =>
      F.withStates(renderNew, {
        loading: "cards",
        empty: {
          icon: "target",
          title: tx("launch.empty_title", "Целей пока нет"),
          text: tx("launch.empty_text", "Вставьте домены, URL, IP-адреса или сети CIDR."),
          action: `<button class="btn primary" data-act="retry">${ic("plus")}${esc(tx("launch.add_target", "Добавить цель"))}</button>`,
        },
      }),
    mount(page) {
      const ta = page.querySelector("#la-in");
      if (!ta) return;
      page.classList.add("la-page", "la-pg", "no-pb");
      // Firmwares that kill background apps: autostart/battery status before a long scan (settings.js).
      if (F.bgSetup) F.bgSetup.refresh();
      if (page.querySelector("#la-fz")) fzEstimate();
      const sw = page.querySelector("#la-sub-words");
      if (sw)
        sw.addEventListener("input", () => {
          wiz.subCustom = sw.value;
          const n = page.querySelector("#la-sub-n");
          if (n)
            n.textContent = subWords().length
              ? tx("launch.sub_words", { n: subWords().length }, "Слов: {n}")
              : tx("launch.sub_words_none", "Добавьте хотя бы одно имя");
        });
      const grow = () => {
        ta.style.height = "auto";
        ta.style.height = Math.min(ta.scrollHeight, 220) + "px";
      };
      ta.addEventListener("input", () => {
        if (ta.value.includes("\n")) {
          const lines = ta.value.split("\n");
          const rest = lines.pop();
          addText(lines.join("\n"));
          ta.value = rest;
          refreshTargets();
        }
        wiz.draft = ta.value;
        grow();
      });
      ta.addEventListener("paste", () =>
        setTimeout(() => {
          addText(ta.value);
          ta.value = "";
          wiz.draft = "";
          grow();
          refreshTargets();
        }, 0),
      );
      ta.addEventListener("blur", () => {
        if (ta.value.trim()) {
          addText(ta.value);
          ta.value = "";
          wiz.draft = "";
          grow();
          refreshTargets();
        }
      });
      page.querySelectorAll("button.pick[data-key]").forEach(s =>
        s.addEventListener("change", () => {
          wiz[s.dataset.key] = s.value;
        }),
      );
      const ex = page.querySelector("#la-excl");
      if (ex)
        ex.addEventListener("keydown", e => {
          if (e.key === "Enter") {
            e.preventDefault();
            F.actions["la-excl-add"]();
          }
        });
      const pn = page.querySelector("#la-pname");
      if (pn)
        pn.addEventListener("input", () => {
          wiz.pname = pn.value;
          wiz.pnameTouched = !!pn.value.trim();
        });
      const pc = page.querySelector("#la-pclient");
      if (pc)
        pc.addEventListener("input", () => {
          wiz.pclient = pc.value;
        });
      // Back from the new-project wizard with entered data must not discard it silently.
      if (wiz.mode === "project")
        F.onBack(() => {
          if (!hasDraft()) {
            clearDraft();
            return false;
          }
          leaveSheet();
          return true;
        });
    },
    // Leaving the wizard (except temporary trips to settings/scope): targets are re-read from the scope next
    // time.
    unmount() {
      const nx = F.current() || "";
      if (!/^\/settings|^\/p\/scope/.test(nx)) wiz.leave = true;
    },
    // A key was saved in a sheet over the wizard or the scope changed: refresh statuses.
    // Do not re-render while the user is typing a number (focus and keyboard would be lost).
    live: (kind, ev) =>
      kind === "db" &&
      (ev.kind === "settings" || ev.kind === "scope") &&
      !(document.activeElement && document.activeElement.matches("[data-nf-in]")),
  });

  // Simulated system file picker (Android SAF); in the app the system provides the list.
  const DEMO_FILES = [
    { name: "Звіт_аудит_2025.docx", ext: "docx", sub: "Download · 1,2 МБ" },
    { name: "специфікація.pdf", ext: "pdf", sub: "Download · 4,8 МБ" },
    { name: "штатний_розклад.xlsx", ext: "xlsx", sub: "Documents · 310 КБ" },
    { name: "презентація.pptx", ext: "pptx", sub: "Documents · 12,4 МБ" },
    { name: "IMG_4127.jpg", ext: "jpg", sub: "DCIM/Camera · 3,1 МБ" },
  ];
  // Demo "file" and "clipboard" contents are derived from the current targets' domain.
  const baseDom = () => {
    const t = wiz.targets.find(x => x.type === "domain" || x.type === "wild");
    return t ? hostOf(t) : "example.org";
  };
  const importText = () => {
    const d = baseDom();
    return `${d}\nwww.${d}\nhttps://${d}/upload/\n${d.replace(/\..*$/, "")}-group.example\n203.0.113.10\n10.0.0.300`;
  };

  // Preview of a targets file before import; the text waits in importPending until "Import".
  let importPending = null;
  function importSheet(name, text, where = "") {
    importPending = String(text || "");
    const lines = importPending.split(/\r?\n/).filter(x => x.trim());
    const shown = lines.slice(0, 40).join("\n");
    const ext = (name.split(".").pop() || "txt").toLowerCase().slice(0, 4);
    F.sheet({
      cls: "la-sheet",
      title: tx("launch.import_title", "Импорт целей из файла"),
      html: `<div class="list">${ui.row({ lead: `<span class="ext xlsx">${esc(ext)}</span>`, title: esc(name), sub: `${esc(where)}${esc(tx("launch.import_lines", { n: lines.length }, "{n} строк"))}` })}</div>
        <h3 class="sub-h la-h3">${esc(tx("launch.preview", "Предпросмотр"))}</h3>
        <pre class="la-pre">${esc(shown)}${lines.length > 40 ? "\n… " + esc(tx("launch.more_n", { n: lines.length - 40 }, "ещё {n}")) : ""}</pre>
        <p class="fhint">${esc(tx("launch.import_hint", "Каждая строка (или значение через запятую) станет целью. Дубли схлопнутся, ошибки покажем отдельно."))}</p>`,
      footer: `<button class="btn"
          data-act="sheet-close">${esc(tx("common.cancel", "Отмена"))}</button><button class="btn primary"
          data-act="la-import-go" ${lines.length ? "" : "disabled"}>${ic("download")}${esc(tx("launch.import_btn", "Импортировать"))}</button>`,
    });
  }

  // Shared with the Projects screen: the "New target" field previews and checks a pasted list.
  F.launchTargets = { split: splitTargets, parse };

  Object.assign(F.actions, {
    "la-commit": () => {
      const ta = F.page().querySelector("#la-in");
      if (!ta.value.trim()) {
        ta.focus();
        F.snack(tx("launch.commit_empty", "Введите домен, URL, IP или CIDR, затем нажмите «+»"));
        return;
      }
      addText(ta.value);
      ta.value = "";
      wiz.draft = "";
      refreshTargets();
    },
    "la-del": i => {
      const removed = wiz.targets.splice(+i, 1)[0];
      if (wiz.mode === "project" && !wiz.pnameTouched) wiz.pname = defaultName();
      refreshTargets();
      const inSc = ((F.db.scope || {}).targets || []).some(
        x => String(x.v).toLowerCase() === removed.v.toLowerCase(),
      );
      F.snack(
        wiz.mode === "scan"
          ? inSc
            ? tx("launch.snack_t_skip", { v: removed.v }, "«{v}» не войдёт в этот скан (в скоупе осталась)")
            : tx("launch.snack_t_removed", { v: removed.v }, "«{v}» убрана из этого скана")
          : tx("launch.snack_t_deleted", { v: removed.v }, "Цель «{v}» удалена"),
        {
          action: () => {
            wiz.targets.splice(+i, 0, removed);
            if (wiz.mode === "project" && !wiz.pnameTouched) wiz.pname = defaultName();
            refreshTargets();
          },
        },
      );
    },
    "la-delerr": i => {
      wiz.errors.splice(+i, 1);
      refreshTargets();
    },
    "la-fix": i => {
      const e = wiz.errors.splice(+i, 1)[0];
      const ta = F.page().querySelector("#la-in");
      ta.value = e.v;
      wiz.draft = e.v;
      refreshTargets();
      ta.focus();
      ta.setSelectionRange(e.v.length, e.v.length);
    },
    "la-paste": async () => {
      const r = await F.clipRead();
      let txt = r.text;
      if (!txt.trim()) {
        if (!F.isDemo) {
          F.snack(
            r.ok
              ? tx("launch.clip_empty", "Буфер обмена пуст")
              : tx("launch.clip_unreadable", "Не удалось прочитать буфер обмена: вставьте цели вручную"),
          );
          return;
        }
        txt = `${baseDom().replace(/\..*$/, "")}-group.com\n*.${baseDom()}`;
      } // Demo clipboard.
      addText(txt);
      refreshTargets();
      F.snack(tx("launch.clip_pasted", "Вставлено из буфера"));
    },
    "la-import": () => {
      // Production: the user's own .txt/.csv; the demo shows a sample derived from the current targets.
      if (!F.isDemo)
        return F.pickTextFile({ maxBytes: 512 * 1024 }).then(
          f => f && importSheet(f.name, f.text),
          e =>
            F.snack(
              tx("launch.file_read_err", { err: (e && e.message) || e }, "Не удалось прочитать файл: {err}"),
            ),
        );
      importSheet(`targets_${baseDom()}.csv`, importText(), "Download · ");
    },
    "la-import-go": () => {
      F.closeSheet();
      const r = addText(importPending || "");
      importPending = null;
      refreshTargets();
      if (!r.dup && !r.bad) F.snack(tx("launch.imported", { n: r.ok }, "Импортировано: {n}"));
    },
    "la-files": () => {
      // With the core: system file picker (SAF), copies in the private folder, doc_import after the project
      // is created.
      if (!F.isDemo) {
        return F.api.platform_pick_files({ multiple: true }).then(
          res => {
            const fl = (res && res.files) || [];
            if (!fl.length) return;
            const kb = n =>
              n >= 1048576
                ? tx(
                    "launch.size_mb",
                    { n: (n / 1048576).toFixed(1).replace(".", lang() === "en" ? "." : ",") },
                    "{n} МБ",
                  )
                : tx("launch.size_kb", { n: Math.max(1, Math.round(n / 1024)) }, "{n} КБ");
            fl.forEach(f => {
              if (!wiz.files.some(x => x.path === f.path))
                wiz.files.push({
                  name: f.name,
                  ext: (f.name.split(".").pop() || "").toLowerCase().slice(0, 4),
                  sub: kb(f.size || 0),
                  path: f.path,
                });
            });
            F.render(true);
          },
          e =>
            F.snack(tx("launch.files_pick_err", { err: e.message || e }, "Не удалось выбрать файлы: {err}")),
        );
      }
      const sel = new Set(wiz.files.map(f => f.name));
      F.sheet({
        cls: "la-sheet",
        title: tx("launch.local_files", "Локальные файлы"),
        html: `<div class="srow"
          data-act="la-folder">${ic("folder")}<span class="lbl">${esc(tx("launch.pick_folder", "Выбрать папку целиком"))}<small>${esc(tx("launch.pick_folder_sub", "Все документы во вложенных папках"))}</small></span>${ic("chev", "chev")}</div>
          ${ui.secH(tx("launch.recent_files", "Недавние файлы"))}
          <div class="list"
            id="la-fl">${DEMO_FILES.map(
              f => `<div class="row tap la-frow ${sel.has(f.name) ? "sel" : ""}"
            data-act="la-fpick:${esc(f.name)}" role="checkbox"
            aria-checked="${sel.has(f.name)}"><span class="check">${ic("check")}</span><span class="ext ${f.ext}">${f.ext}</span><div class="body"><div class="t">${esc(f.name)}</div><div class="s">${esc(f.sub)}</div></div></div>`,
            ).join("")}</div>`,
        footer: `<button class="btn"
          data-act="sheet-close">${esc(tx("common.cancel", "Отмена"))}</button><button class="btn primary"
          data-act="la-files-go">${esc(tx("common.add", "Добавить"))}</button>`,
      });
    },
    "la-fpick": (n, el) => {
      el.classList.toggle("sel");
      el.setAttribute("aria-checked", el.classList.contains("sel"));
    },
    "la-folder": () => {
      if (!wiz.files.some(f => f.dir))
        wiz.files.push({
          name: tx("launch.demo_folder", "USB/Архив"),
          sub: tx("launch.demo_folder_sub", "Папка · документы во вложенных папках"),
          dir: true,
        });
      F.closeSheet();
      F.render(true);
      F.snack(tx("launch.folder_added", "Папка добавлена"));
    },
    "la-files-go": () => {
      const picked = [...document.querySelectorAll(".sheet .la-frow.sel")].map(
        r => r.dataset.act.split(/:(.*)/s)[1],
      );
      wiz.files = wiz.files.filter(f => f.dir).concat(DEMO_FILES.filter(f => picked.includes(f.name)));
      F.closeSheet();
      F.render(true);
    },
    "la-file-del": i => {
      wiz.files.splice(+i, 1);
      F.render(true);
    },
    "la-prof": id => {
      wiz.profile = id;
      F.render(true);
    },
    "la-fz-mod": (k, el) => {
      const i = wiz.fzMods.indexOf(k);
      i >= 0 ? wiz.fzMods.splice(i, 1) : wiz.fzMods.push(k);
      if (el) {
        el.classList.toggle("on", i < 0);
        el.setAttribute("aria-checked", i < 0);
      }
      wiz.fzEst = null;
      const e = document.getElementById("la-fz-est");
      if (e) e.innerHTML = fzEstText();
      fzEstimate();
    },
    "la-mod": (k, el) => {
      wiz.mods[k] = !wiz.mods[k];
      F.actions.toggle(null, el);
      if (k === "fuzz" || k === "ports" || k === "subdomains") return F.render(true);
      const pg = F.page();
      const b = pg && pg.querySelector("#la-start");
      if (b) b.outerHTML = startBtn();
    },
    "la-src": (k, el) => {
      wiz.src[k] = wiz.src[k] === false;
      F.actions.toggle(null, el);
    },
    "la-netcheck": () =>
      F.api.net_check().then(
        r => {
          wiz.netcheck = r;
          F.render(true);
        },
        () => {
          wiz.netcheck = { ok: false };
          F.render(true);
        },
      ),
    "la-adv": () => {
      wiz.adv = !wiz.adv;
      F.render(true);
    },
    "la-doc": (d, el) => {
      const i = wiz.docs.indexOf(d);
      i >= 0 ? wiz.docs.splice(i, 1) : wiz.docs.push(d);
      el.classList.toggle("on", i < 0);
      el.setAttribute("aria-pressed", i < 0);
    },
    "la-depth": n => {
      wiz.depth = +n;
      F.render(true);
    },
    "la-ports-top": n => {
      wiz.portsTop = +n;
      F.render(true);
    },
    "la-sub-wl": k => {
      wiz.subWl = k;
      F.render(true);
    },
    "la-step": a => {
      const [k, d, mn, mx] = a.split(":");
      wiz[k] = Math.max(+mn, Math.min(+mx, wiz[k] + +d));
      if (k === "fzRate") wiz.fzEst = null;
      F.render(true);
    },
    "la-excl-add": () => {
      const inp = F.page().querySelector("#la-excl");
      const v = parseExcl(inp.value);
      if (!v) {
        inp.focus();
        return;
      }
      addExcl(v, () => {
        F.render(true);
      });
    },
    "la-excl-del": i => delExcl(+i, () => F.render(true)),
    // Any profile starts with a single tap, without confirmations.
    "la-start": () => {
      if (!wiz.targets.length) return;
      if (modsOn().includes("subdomains") && subWl() === "custom" && !subWords().length) {
        F.snack(
          tx("launch.sub_empty", "Свой словарь перебора пуст. Добавьте имена или выберите другой словарь"),
        );
        const ta = document.getElementById("la-sub-words");
        if (ta) ta.focus();
        return;
      }
      startScan(needConfirm() === "active");
    },
    // Explicit "Save" of a new project without scanning.
    "la-save-only": () => {
      if (!wiz.targets.length) return;
      createProject().then(
        p => {
          wiz.leave = true;
          clearDraft();
          F.api.project_open(p.id).then(() => F.reset(["/projects", "/p/overview"]));
          F.snack(tx("launch.project_saved", { name: p.name }, "Проект «{name}» сохранён"));
        },
        e => F.snack(tx("launch.project_err", { err: e.message || e }, "Не удалось создать проект: {err}")),
      );
    },
    "la-leave-keep": () => {
      saveDraft();
      F.closeSheet();
      F.onBack(null);
      wiz.leave = true;
      F.back();
      F.snack(tx("launch.draft_saved", "Черновик сохранён: продолжить можно на экране «Проекты»"));
    },
    "la-leave-drop": () => {
      F.closeSheet();
      clearDraft();
      F.onBack(null);
      wiz.leave = true;
      wiz.targets = [];
      wiz.pclient = "";
      wiz.newExcl = [];
      wiz.files = [];
      F.back();
    },
  });
  const parseExcl = raw => {
    const v = String(raw || "").trim();
    if (!v) return null;
    const r =
      /^[\d.]+\/([89]|1[0-5])$/.test(v) && !ipParse(v.split("/")[0]).err ? { type: "cidr", v } : parse(v);
    if (!r || r.err || !NET.includes(r.type)) {
      F.snack(
        r && r.err
          ? tx("launch.excl_err", { err: r.err }, "Исключение: {err}")
          : tx("launch.excl_bad", "Исключение должно быть хостом, сетью или URL"),
      );
      return null;
    }
    return r.v;
  };
  function addExcl(v, done) {
    if (wiz.mode === "project") {
      if (!wiz.newExcl.includes(v)) wiz.newExcl.push(v);
      done();
      return;
    }
    const cur = ((F.db.scope || {}).excl || []).slice();
    if (cur.includes(v)) {
      done();
      return;
    }
    F.api.scope_set({ excl: cur.concat(v) }).then(done);
  }
  // Removing an exclusion widens the scan area, so it always offers Undo.
  function delExcl(i, done) {
    if (wiz.mode === "project") {
      const removed = wiz.newExcl.splice(i, 1)[0];
      done();
      F.snack(tx("launch.excl_removed", { v: removed }, "Исключение «{v}» удалено: адрес попадёт в скан"), {
        action: () => {
          wiz.newExcl.splice(i, 0, removed);
          done();
        },
      });
      return;
    }
    const cur = ((F.db.scope || {}).excl || []).slice();
    const removed = cur.splice(i, 1)[0];
    F.api.scope_set({ excl: cur }).then(done);
    F.snack(tx("launch.excl_removed", { v: removed }, "Исключение «{v}» удалено: адрес попадёт в скан"), {
      action: () => {
        const now = ((F.db.scope || {}).excl || []).slice();
        now.splice(i, 0, removed);
        F.api.scope_set({ excl: now }).then(done);
      },
    });
  }

  function leaveSheet() {
    const n = wiz.targets.length;
    F.sheet({
      cls: "la-sheet",
      title: tx("launch.leave_title", "Выйти из мастера?"),
      html: `<p class="lead">${esc(n ? `${pl(n, "launch.pl_target", "цель|цели|целей")}${wiz.pclient ? " " + tx("launch.leave_client", { client: wiz.pclient }, "и заказчик «{client}»") : ""}` : tx("launch.leave_data", "Введённые данные"))} ${esc(tx("launch.leave_unsaved", "ещё не сохранены. Проект пока не создан."))}</p>
        <div class="srow"
          data-act="la-leave-keep">${ic("save")}<span class="lbl">${esc(tx("launch.leave_keep", "Выйти и сохранить черновик"))}<small>${esc(tx("launch.leave_keep_sub", "Продолжить можно на экране «Проекты»"))}</small></span></div>
        <div class="srow pj-danger"
          data-act="la-leave-drop">${ic("trash")}<span class="lbl">${esc(tx("launch.leave_drop", "Выйти без сохранения"))}<small>${esc(tx("launch.leave_drop_sub", "Цели и настройки мастера будут удалены"))}</small></span></div>`,
      footer: `<button class="btn primary" data-act="sheet-close">${esc(tx("launch.stay", "Остаться"))}</button>`,
    });
  }
  function createProject() {
    const name = (wiz.pname || "").trim() || defaultName();
    const paths = wiz.files.filter(f => f.path).map(f => f.path);
    return (
      F.api
        .project_create({
          name,
          client: (wiz.pclient || "").trim(),
          targets: wiz.targets.map(t => ({ v: t.v, type: t.type })),
          excludes: wiz.newExcl.slice(),
        })
        .then(p =>
          F.api.project_open(p.id).then(() => {
            Object.assign(wiz, { mode: "scan", seededFor: p.id, leave: false });
            return p;
          }),
        )
        // Own files from the wizard go into the project right away (no network), before the scan.
        .then(p =>
          paths.length
            ? F.api.doc_import(paths).then(
                () => p,
                e => {
                  F.snack(tx("launch.files_add_err", { err: e.message || e }, "Файлы не добавлены: {err}"));
                  return p;
                },
              )
            : p,
        )
    );
  }
  // Scope used to check targets: the current project or the new-project draft (wizard targets and
  // exclusions).
  const draftScope = () => ({
    client: wiz.pclient || "",
    targets: wiz.targets.map(t => ({ v: t.v, type: t.type })),
    excl: wiz.newExcl.slice(),
  });
  // Launch targets: modules that contact the target get only in-scope, non-excluded targets (non-network
  // ones go to external sources); the passive profile gets all wizard targets.
  function launchTargets(need) {
    if (!need) return { targets: wiz.targets.map(t => t.v), skipped: [] };
    const sc = wiz.mode === "project" ? draftScope() : F.db.scope || {};
    const targets = [],
      skipped = [];
    wiz.targets.forEach(t => {
      const c = F.sel.scope.checkTarget({ v: t.v, type: t.type }, sc);
      if (!c.net || c.ok) targets.push(t.v);
      else skipped.push(`${t.v}: ${c.reason || tx("launch.not_in_scope", "нет в скоупе")}`);
    });
    return { targets, skipped };
  }
  function startScan(active) {
    const need = needConfirm(),
      { targets, skipped } = launchTargets(need);
    if (!targets.length) {
      F.snack(
        tx("launch.no_scope_targets", { list: skipped.join("; ") }, "Нет целей в скоупе: {list}"),
        wiz.mode === "project"
          ? { ms: 7000 }
          : { action: () => F.go("/p/scope"), label: tx("launch.scope", "Скоуп"), ms: 7000 },
      );
      return Promise.resolve();
    }
    // Only DISABLED sources are sent to the core: the wizard does not list all of them (subdomains,
    // ddg/bing/mojeek
    // dorks and archives are always polled unless disabled in Settings → Sources).
    // A keyed source is enabled when its key is set (adding a key connects it automatically);
    // sources disabled in Settings → Sources are excluded by the core itself (settings.sources.<id>.enabled).
    const sources_off = SRC_DEF.filter(({ id, key }) =>
      key ? keySt(key) !== "set" : wiz.src[id] === false,
    ).map(src => src.id);
    const wasProject = wiz.mode === "project",
      resume = wiz.resume;
    const fuzz =
      active && modsOn().includes("fuzz")
        ? (fzSeed(), { modules: wiz.fzMods.slice(), rate: wiz.fzRate })
        : undefined;
    const ports = active && modsOn().includes("ports") ? { top: portsTop() } : undefined;
    // Subdomain brute force wordlist for this run (survives "Continue" in the core).
    const subdomains =
      !resume && modsOn().includes("subdomains")
        ? subWl() === "custom"
          ? { wordlist: "custom", custom: subWords() }
          : { wordlist: subWl() }
        : undefined;
    // Wizard parameters: types, limit, depth, size, UA. They are not sent on "Continue": the core reuses the
    // ones saved for that scan. scan-start (scan.js) forwards only known fields, so they are added to the API
    // call.
    const run = resume
      ? {}
      : {
          exts: wiz.docs.slice(),
          limit: wiz.maxDocs,
          crawl_depth: wiz.depth,
          max_size_mb: wiz.maxSize,
          ua: wiz.ua,
        };
    const withRun = fn => {
      const api = F.api,
        orig = api.scan_start;
      api.scan_start = a => orig({ ...a, ...run });
      try {
        return fn();
      } finally {
        api.scan_start = orig;
      }
    };
    const go = project =>
      withRun(() =>
        F.actions["scan-start"]({
          profile: wiz.profile,
          active,
          modules: modsOn(),
          sources_off,
          targets,
          resume_from: resume || undefined,
          fuzz,
          ports,
          subdomains,
        }),
      )
        .then(() => {
          wiz.leave = true;
          wiz.resume = null;
          if (wasProject) clearDraft();
          F.reset(["/projects", "/p/overview"]);
          F.snack(
            (project
              ? tx("launch.started_project", { name: project.name }, "Проект «{name}» создан · ")
              : "") +
              (resume
                ? tx("launch.started_resume", "Скан продолжен с места остановки")
                : active
                  ? tx("launch.started_active", "Скан с активной фазой запущен")
                  : tx("launch.started", "Скан запущен")) +
              (skipped.length
                ? " · " + tx("launch.started_skipped", { n: skipped.length }, "пропущено вне скоупа: {n}")
                : ""),
          );
        })
        .catch(() => {});
    if (!wasProject) return go(null);
    return createProject().then(go, e =>
      F.snack(tx("launch.project_err", { err: e.message || e }, "Не удалось создать проект: {err}")),
    ); // The project is created only when a scan actually starts.
  }
  // Resuming or restarting a stopped scan: immediately, with the project's CURRENT scope.
  F.launchRestart = ({ profile = "std", modules, resume_from } = {}) => {
    const sc = F.db.scope || {};
    Object.assign(wiz, {
      mode: "scan",
      targets: (sc.targets || []).map(fromScope),
      errors: [],
      files: [],
      draft: "",
      leave: false,
      seededFor: curId(),
      netcheck: null,
      profile: PROFILES.some(p => p.id === profile) ? profile : "std",
      resume: resume_from || null,
    });
    wiz.mods = Object.fromEntries(
      MODS.map(m => [
        m[0],
        (profile === "custom" && modules && modules.length
          ? modules
          : PROFILE_MODS[wiz.profile] || PROFILE_MODS.std
        ).includes(m[0]),
      ]),
    );
    wiz.src = Object.fromEntries(SRC_DEF.map(src => [src.id, !src.key || keySt(src.key) === "set"]));
    return startScan(needConfirm() === "active");
  };

  // ---------- Scope ----------
  // Same object as F.db.scope (api.js keeps the reference); edit only via F.api.scope_set.
  const scope = F.state.scope;
  F.scopeInfo = () => F.sel.scope.info();

  // Project properties: notes and alternative domains (alternative domains are regular "domain" scope
  // targets).
  /** Hint under the "add scope target" input for a parsed value `r` (see parse). */
  function targetHint(r, dup) {
    if (!r) return tx("launch.type_auto", "Тип определится автоматически.");
    if (r.err) return tx("launch.hint_err", { err: r.err }, "Ошибка: {err}");
    if (dup) return tx("launch.hint_dup", "Эта цель уже в скоупе");
    const extra = r.extra ? " · " + r.extra : "";
    return `${TYPES[r.type].label}${extra}${NET.includes(r.type) ? "" : " · " + tx("launch.badge_external", "только внешние источники")}`;
  }
  function projectBlock2() {
    const p = F.db.project || {};
    const doms = (scope.targets || []).filter(t => t.type === "domain");
    const alt = doms.filter(t => lowS(t.v) !== lowS(p.domain || p.name));
    return `${ui.secH(tx("launch.project", "Проект"), "", `<button class="sec-a" data-act="la-props">${esc(tx("launch.change", "Изменить"))}</button>`)}
      <div class="kv">
        <div class="kvr"><div class="k">${esc(tx("launch.alt_domains", "Альтернативные домены"))}</div><div class="v">${alt.length ? esc(alt.map(t => t.v).join(", ")) : `<span class="muted">${esc(tx("launch.none", "нет"))}</span>`}<div class="la-kvs">${esc(tx("launch.alt_domains_sub", "цели скоупа типа «домен»"))}</div></div></div>
        <div class="kvr"><div class="k">${esc(tx("launch.notes", "Заметки"))}</div><div class="v la-notes">${p.notes ? esc(p.notes) : `<span class="muted">${esc(tx("launch.none", "нет"))}</span>`}</div></div>
      </div>`;
  }
  function renderScope() {
    const targets = scope.targets || [],
      excl = scope.excl || [];
    return `
      ${ui.secH(tx("launch.engagement", "Проверка"), "", `<button class="sec-a" data-act="la-params">${esc(tx("launch.change", "Изменить"))}</button>`)}
      <div class="kv">
        <div class="kvr"><div class="k">${esc(tx("launch.client", "Заказчик"))}</div><div class="v">${esc(scope.client || (F.project && F.project.client) || "-")}</div></div>
        <div class="kvr"><div class="k">${esc(tx("launch.active_phase", "Активная фаза"))}</div><div class="v">${esc(tx("launch.active_phase_v", "профиль «Полный»: по всем сетевым целям скоупа, кроме исключений"))}</div></div>
        ${scope.contact || scope.phone ? `<div class="kvr"><div class="k">${esc(tx("launch.contact", "Контакт"))}</div><div class="v">${esc(scope.contact || "-")}${scope.phone ? `<div class="la-kvs">${esc(scope.phone)}</div>` : ""}</div></div>` : ""}
        ${scope.basis ? `<div class="kvr"><div class="k">${esc(tx("launch.basis", "Заметка о разрешении"))}</div><div class="v la-notes">${esc(scope.basis)}</div></div>` : ""}
      </div>

      ${ui.secH(tx("launch.doc_analysis", "Анализ документов"))}
      <div class="list la-rules">${ui.row({
        lead: ui.leadIcon("filter"),
        title: esc(tx("launch.rules", "Правила поиска")),
        sub: esc(tx("launch.rules_sub", "Готовые наборы и свои регулярные выражения для текста документов")),
        act: "go:/p/rules",
      })}</div>

      ${ui.secH(tx("launch.targets", "Цели"), targets.length, `<button class="sec-a" data-act="la-tadd">${esc(tx("common.add", "Добавить"))}</button>`)}
      ${
        targets.length
          ? `<div class="list">${targets
              .map((t, i) =>
                ui.row({
                  lead: ui.leadIcon((TYPES[t.type] || TYPES.domain).icon),
                  title: esc(t.v),
                  sub: `${t.type === "domain" && lowS(t.v) !== lowS((F.db.project || {}).domain || (F.db.project || {}).name) ? esc(tx("launch.alt_domain", "Альтернативный домен")) : esc((TYPES[t.type] || TYPES.domain).label)}${!NET.includes(t.type) ? `<div class="la-tperm"><span class="pill mute">${ic("globe")}${esc(tx("launch.external_only", "Только внешние источники"))}</span></div>` : ""}`,
                  act: `la-tmenu:${i}`,
                }),
              )
              .join("")}</div>`
          : `<p class="la-none">${esc(tx("launch.scope_no_targets", "Целей нет: добавьте домен, *.домен, URL, IP или сеть CIDR."))}</p>`
      }
      <button class="btn block la-addt" data-act="la-tadd">${ic("plus")}${esc(tx("launch.add_target", "Добавить цель"))}</button>

      ${ui.secH(tx("launch.exclusions", "Исключения"), excl.length, `<button class="sec-a" data-act="la-xadd">${esc(tx("common.add", "Добавить"))}</button>`)}
      ${
        excl.length
          ? `<div class="list">${excl
              .map((x, i) =>
                ui.row({
                  lead: ui.leadIcon("la-ban", "var(--bad)"),
                  title: `<span class="mono">${esc(x)}</span>`,
                  sub: esc(tx("launch.excl_sub", "Вне скоупа: не сканируется")),
                  tail: `<button class="ib"
        data-act="la-xdel:${i}"
        aria-label="${esc(tx("launch.excl_del_aria", { v: x }, "Удалить исключение {v}"))}">${ic("x")}</button>`,
                }),
              )
              .join("")}</div>`
          : `<p class="la-none">${esc(tx("launch.excl_none", "Исключений нет."))}</p>`
      }

      ${projectBlock2()}`;
  }
  F.route("/p/scope", {
    title: () => tx("launch.scope", "Скоуп"),
    tab: "overview",
    actions: () => [{ icon: "gear", act: "la-params", label: tx("launch.params", "Параметры проверки") }],
    mount(page) {
      page.classList.add("la-pg");
    },
    render: () =>
      F.withStates(renderScope, {
        loading: "cards",
        empty: {
          icon: "target",
          title: tx("launch.scope_empty", "Скоуп пуст"),
          text: tx(
            "launch.scope_empty_text",
            "Добавьте сетевые цели проекта: домены, *.домены, URL, IP или сети CIDR.",
          ),
          action: `<button class="btn primary" data-act="la-tadd">${ic("plus")}${esc(tx("launch.add_target", "Добавить цель"))}</button>`,
        },
      }),
    live: (kind, ev) => kind === "db" && ev.kind === "scope",
  });

  F.actions["la-props"] = () => (F.projectProps ? F.projectProps(curId()) : null);
  const fld = (id, label, val, type = "text", ph = "") =>
    `<label class="flabel" for="${id}">${label}</label><div class="field"><input id="${id}"
      type="${type}" value="${esc(val || "")}" placeholder="${esc(ph)}"></div>`;
  const setScope = (patch, msg, undo) =>
    F.api.scope_set(patch).then(() => {
      F.render(true);
      if (msg)
        F.snack(msg, undo ? { action: () => F.api.scope_set(undo).then(() => F.render(true)) } : undefined);
    });
  function targetSheet() {
    F.sheet({
      cls: "la-sheet",
      title: tx("launch.tadd_title", "Добавить цель в скоуп"),
      html: `<label class="flabel"
        for="la-tv">${esc(tx("launch.target", "Цель"))}</label><div class="field">${ic("target")}<input id="la-tv"
        placeholder="${esc(tx("launch.tadd_ph", "Домен, *.домен, URL, IP, CIDR или диапазон"))}" autocapitalize="off" spellcheck="false"
        enterkeyhint="done"></div>
        <p class="fhint" id="la-tvh">${esc(tx("launch.type_auto", "Тип определится автоматически."))}</p>`,
      footer: `<button class="btn" data-act="sheet-close">${esc(tx("common.cancel", "Отмена"))}</button><button class="btn primary"
        data-act="la-tadd-go" id="la-tgo" disabled>${ic("plus")}${esc(tx("common.add", "Добавить"))}</button>`,
      onMount(sh) {
        const inp = sh.querySelector("#la-tv"),
          hintEl = sh.querySelector("#la-tvh"),
          addBtn = sh.querySelector("#la-tgo");
        const upd = () => {
          const r = parse(inp.value);
          const dup =
            r && !r.err && (scope.targets || []).some(t => String(t.v).toLowerCase() === r.v.toLowerCase());
          hintEl.className = "fhint" + (r && (r.err || dup) ? " err" : "");
          hintEl.textContent = targetHint(r, dup);
          addBtn.disabled = !r || !!r.err || dup;
        };
        inp.addEventListener("input", upd);
        inp.addEventListener("keydown", e => {
          if (e.key === "Enter" && !addBtn.disabled) F.actions["la-tadd-go"]();
        });
        setTimeout(() => inp.focus(), 200);
      },
    });
  }
  Object.assign(F.actions, {
    "la-tadd": () => targetSheet(),
    "la-tadd-go": () => {
      const r = parse((document.getElementById("la-tv") || {}).value || "");
      if (!r || r.err) return;
      const prev = (scope.targets || []).slice();
      F.closeSheet();
      setScope(
        { targets: prev.concat({ v: r.v, type: r.type }) },
        tx("launch.t_added", { v: r.v }, "Цель «{v}» добавлена в скоуп"),
        {
          targets: prev,
        },
      );
    },
    "la-xadd": () =>
      F.sheet({
        cls: "la-sheet",
        title: tx("launch.xadd_title", "Добавить исключение"),
        html: `<label class="flabel"
          for="la-xv">${esc(tx("launch.xadd_label", "Хост, сеть или URL"))}</label><div class="field">${ic("la-ban")}<input id="la-xv"
          placeholder="${esc(tx("launch.xadd_ph", "mail.example.ua или 10.0.0.0/8"))}" autocapitalize="off" spellcheck="false"
          enterkeyhint="done"></div><p class="fhint">${esc(tx("launch.xadd_hint", "Исключения важнее целей: адрес не сканируется ни пассивно-активными, ни активными модулями."))}</p>`,
        footer: `<button class="btn"
          data-act="sheet-close">${esc(tx("common.cancel", "Отмена"))}</button><button class="btn primary"
          data-act="la-xadd-go">${ic("plus")}${esc(tx("common.add", "Добавить"))}</button>`,
        onMount(sh) {
          const i = sh.querySelector("#la-xv");
          i.addEventListener("keydown", e => {
            if (e.key === "Enter") F.actions["la-xadd-go"]();
          });
          setTimeout(() => i.focus(), 200);
        },
      }),
    "la-xadd-go": () => {
      const v = parseExcl((document.getElementById("la-xv") || {}).value);
      if (!v) return;
      F.closeSheet();
      const prev = (scope.excl || []).slice();
      if (prev.includes(v)) return;
      setScope({ excl: prev.concat(v) }, tx("launch.x_added", { v }, "Исключение «{v}» добавлено"), {
        excl: prev,
      });
    },
    "la-xdel": i => {
      const prev = (scope.excl || []).slice();
      const x = prev[+i];
      setScope(
        { excl: prev.filter((_, j) => j !== +i) },
        tx("launch.excl_removed", { v: x }, "Исключение «{v}» удалено: адрес попадёт в скан"),
        { excl: prev },
      );
    },
    "la-params": () =>
      F.sheet({
        cls: "la-sheet",
        title: tx("launch.params", "Параметры проверки"),
        full: true,
        html: `${fld("ct-client", esc(tx("launch.client", "Заказчик")), scope.client || (F.project && F.project.client))}
        ${fld("ct-contact", esc(tx("launch.contact_person", "Контактное лицо")), scope.contact)}${fld("ct-phone", esc(tx("launch.phone", "Телефон или e-mail")), scope.phone, "tel")}
        <label class="flabel"
          for="ct-basis">${esc(tx("launch.basis", "Заметка о разрешении"))} <span class="muted">${esc(tx("launch.optional", "(необязательно)"))}</span></label>
        <div class="field pp-ta"><textarea id="ct-basis" rows="3" maxlength="1000"
          placeholder="${esc(tx("launch.basis_ph", "Кто и когда разрешил проверку, ссылка на письмо"))}">${esc(scope.basis || "")}</textarea></div>
        <p class="fhint">${esc(tx("launch.basis_hint", "Если заполнено, попадёт в отчёт разделом «Основание проверки»."))}</p>`,
        footer: `<button class="btn"
          data-act="sheet-close">${esc(tx("common.cancel", "Отмена"))}</button><button class="btn primary"
          data-act="la-params-save">${ic("check")}${esc(tx("common.save", "Сохранить"))}</button>`,
      }),
    "la-params-save": () => {
      const g = id => document.getElementById(id).value.trim();
      const patch = {
        client: g("ct-client"),
        contact: g("ct-contact"),
        phone: g("ct-phone"),
        basis: g("ct-basis"),
      };
      F.closeSheet();
      setScope(patch, tx("launch.params_saved", "Параметры проверки сохранены"));
    },
    "la-tmenu": i => {
      const t = scope.targets[+i];
      if (!t) return;
      F.sheet({
        cls: "la-sheet",
        title: t.v,
        html: `<p class="lead">${esc(tx("launch.tmenu_d", "Сетевая цель скоупа: в «Пассивном» используются только внешние источники, в «Стандартном» (проверка живости и TLS, в «Полном») также AXFR, порты и поиск забытых файлов."))}</p>
          <div class="srow pj-danger"
            data-act="la-tdel:${i}">${ic("x")}<span class="lbl">${esc(tx("launch.tmenu_remove", "Убрать из скоупа"))}</span></div>`,
      });
    },
    "la-tdel": i => {
      const prev = (scope.targets || []).slice();
      const t = prev[+i];
      F.closeSheet();
      setScope(
        { targets: prev.filter((_, j) => j !== +i) },
        tx("launch.t_removed", { v: t.v }, "Цель «{v}» убрана из скоупа"),
        {
          targets: prev,
        },
      );
    },
  });

  const lowS = s => String(s || "").toLowerCase();
})();
