/*
 * FOCA-rs demo backend.
 * Implements the same commands as the Rust core (contract: docs/API.md): project_list, project_snapshot,
 * scan_start…
 * Active only when window.__TAURI__ is absent (browser, screenshot tests, node checks in
 * qa/data-invariants.mjs).
 * Data is deterministic (seeded), internally consistent and persisted in localStorage ("foca-demo-v1").
 * Responses are shaped "as from serde": snake_case, ISO 8601 dates, references by id; api.js hydrates them
 * into screen objects.
 */
(function (root) {
  "use strict";
  // Generator version; bump it whenever generated data changes so stored demo data is regenerated.
  // 21: plain hyphen as the empty-value mark in stored hosts and findings;
  // 22: English demo data for an English UI; 12: document forensics (new formats, doc_get records, forensic findings); 11: infrastructure;
  // 10: port scan (Host.ports/ports_scan, ports stage); 9: technologies in scan snapshots;
  // 8: site recon (snapshot.recon); 7: Startpage/Brave via the browser; 6: no Google CSE;
  // 5: no allow_active / "active" target marks / confirmation log.
  const GEN_VERSION = 23;
  // User rule presets of the core (foca-analysis::rules::presets), same ids, titles and patterns.
  const DEMO_RULE_PRESETS = [
    {
      id: "ua-gov",
      title: "Документы госорганов Украины",
      description: "Реквизиты служебных документов: номера наказів, вихідні номери, інвентарні номери ДСК.",
      rules: [
        {
          id: "ua-order",
          title: "Номер наказу/розпорядження",
          pattern:
            "(?i)\\b(?:наказ|розпорядження|постанова)\\s+(?:від\\s+\\d{2}\\.\\d{2}\\.\\d{4}\\s+)?№\\s*\\d{1,5}(?:[-/]\\p{L}{1,6})?",
          sev: "info",
          mask: false,
        },
        {
          id: "ua-outgoing",
          title: "Вихідний номер листа",
          pattern: "(?i)\\bвих(?:ідний|\\.)\\s*№\\s*[\\p{L}\\d/.\\-]{1,20}",
          sev: "info",
          mask: false,
        },
        {
          id: "ua-dsk-inv",
          title: "Інвентарний номер ДСК",
          pattern: "(?i)\\bінв\\.?\\s*№\\s*\\d{1,6}\\s*(?:дск|дсп)\\b",
          sev: "high",
          mask: false,
        },
      ],
    },
    {
      id: "credentials",
      title: "Учётные данные в тексте",
      description: "Пары «логин/пароль» в свободной форме на украинском, русском и английском.",
      rules: [
        {
          id: "cred-login-pass",
          title: "Логин и пароль в тексте",
          pattern:
            "(?i)\\b(?:логін|логин|login|user(?:name)?|користувач)\\s*[:=]\\s*\\S{2,64}\\s*[,;/]?\\s*(?:пароль|password|pass|pwd)\\s*[:=]\\s*\\S{4,64}",
          sev: "crit",
          mask: true,
        },
        {
          id: "cred-wifi",
          title: "Пароль Wi-Fi",
          pattern:
            "(?i)\\b(?:wi-?fi|ssid)\\b[^\\n]{0,60}?(?:пароль|password|ключ|key)\\s*[:=\\-]\\s*\\S{8,63}",
          sev: "high",
          mask: true,
        },
      ],
    },
    {
      id: "infra",
      title: "Внутренняя инфраструктура",
      description: "UNC-пути, RDP/SSH-адреса с портами, имена контроллеров домена.",
      rules: [
        {
          id: "infra-unc",
          title: "UNC-путь к сетевому ресурсу",
          pattern: "\\\\\\\\[A-Za-z0-9][A-Za-z0-9.\\-]{0,62}\\\\[^\\s\\\\/:*?<>|]{1,80}",
          sev: "low",
          mask: false,
        },
        {
          id: "infra-rdp",
          title: "Адрес удалённого доступа с портом",
          pattern:
            "(?i)\\b(?:rdp|ssh|vnc|anydesk|teamviewer)\\b[^\\n]{0,40}?\\b(?:\\d{1,3}\\.){3}\\d{1,3}(?::\\d{2,5})?",
          sev: "warn",
          mask: false,
        },
      ],
    },
    {
      id: "crypto",
      title: "Криптовалютные кошельки",
      description: "Адреса Bitcoin (bech32), Ethereum и TRON.",
      rules: [
        {
          id: "crypto-btc",
          title: "Адрес Bitcoin",
          pattern: "\\bbc1[ac-hj-np-z02-9]{25,59}\\b",
          sev: "low",
          mask: true,
        },
        {
          id: "crypto-eth",
          title: "Адрес Ethereum",
          pattern: "\\b0x[0-9a-fA-F]{40}\\b",
          sev: "low",
          mask: true,
        },
        {
          id: "crypto-trx",
          title: "Адрес TRON",
          pattern: "\\bT[1-9A-HJ-NP-Za-km-z]{33}\\b",
          sev: "low",
          mask: true,
        },
      ],
    },
    {
      id: "personal",
      title: "Персональные данные (свободная форма)",
      description: "Даты рождения, адреса регистрации и медицинские сведения рядом с ключевыми словами.",
      rules: [
        {
          id: "pd-birth",
          title: "Дата рождения",
          pattern:
            "(?i)\\b(?:дата\\s+народження|дата\\s+рождения|date\\s+of\\s+birth|д\\.\\s*н\\.)\\s*[:\\-]?\\s*\\d{2}[./]\\d{2}[./]\\d{4}",
          sev: "warn",
          mask: true,
        },
        {
          id: "pd-address",
          title: "Адрес регистрации",
          pattern:
            "(?i)\\b(?:зареєстрован\\p{L}*|місце\\s+проживання|адреса\\s+реєстрації)\\s*[:\\-]?\\s*[^\\n]{10,120}",
          sev: "warn",
          mask: true,
        },
        {
          id: "pd-medical",
          title: "Медицинские сведения",
          pattern:
            "(?i)\\b(?:діагноз|диагноз|лікарняний|больничный|інвалідність|инвалидность)\\b[^\\n]{0,80}",
          sev: "high",
          mask: true,
        },
      ],
    },
  ];
  const STORE_KEY = "foca-demo-v1";
  const TODAY = "2026-11-20";

  // ================= utilities =================
  const rng = seed => {
    let s = seed >>> 0 || 1;
    const r = () => (s = (Math.imul(s, 1103515245) + 12345) & 0x7fffffff) / 0x7fffffff;
    return {
      r,
      pick: a => a[Math.floor(r() * a.length)],
      int: (a, b) => a + Math.floor(r() * (b - a + 1)),
      chance: p => r() < p,
      wpick: list => {
        const t = list.reduce((x, [, w]) => x + w, 0);
        let v = r() * t;
        for (const [x, w] of list) {
          if ((v -= w) <= 0) return x;
        }
        return list[list.length - 1][0];
      },
    };
  };
  const hash = s => {
    let h = 2166136261 >>> 0;
    for (const c of String(s)) h = Math.imul(h ^ c.charCodeAt(0), 16777619) >>> 0;
    return h;
  };
  const sha = s => {
    let h = 2166136261 >>> 0,
      out = "";
    for (let k = 0; k < 8; k++) {
      for (const c of s + k) h = Math.imul(h ^ c.charCodeAt(0), 16777619) >>> 0;
      out += h.toString(16).padStart(8, "0");
    }
    return out;
  };
  const pad = n => String(n).padStart(2, "0");
  const iso = (y, m, d, hh = 0, mm = 0) => `${y}-${pad(m)}-${pad(d)}T${pad(hh)}:${pad(mm)}:00`;
  const addMin = (isoS, min) => {
    const t = new Date(isoS + "Z").getTime() + min * 60000;
    return new Date(t).toISOString().slice(0, 19);
  };
  const clone = o => JSON.parse(JSON.stringify(o));
  const uniq = a => [...new Set(a)];
  const countBy = (arr, f) => {
    const m = new Map();
    arr.forEach(x => {
      const k = f(x);
      if (k != null) m.set(k, (m.get(k) || 0) + 1);
    });
    return m;
  };
  const translit = s =>
    s.toLowerCase().replace(
      /[а-яіїєґ']/g,
      c =>
        ({
          а: "a",
          б: "b",
          в: "v",
          г: "h",
          ґ: "g",
          д: "d",
          е: "e",
          є: "ie",
          ж: "zh",
          з: "z",
          и: "y",
          і: "i",
          ї: "i",
          й: "i",
          к: "k",
          л: "l",
          м: "m",
          н: "n",
          о: "o",
          п: "p",
          р: "r",
          с: "s",
          т: "t",
          у: "u",
          ф: "f",
          х: "kh",
          ц: "ts",
          ч: "ch",
          ш: "sh",
          щ: "shch",
          ь: "",
          ю: "iu",
          я: "ia",
          "'": "",
        })[c] ?? c,
    );

  // ================= reference data =================
  // Software: rel is the release year (a document cannot be older), exts lists the file types it produces.
  const SOFTWARE = [
    {
      id: "word2013",
      name: "Microsoft Office Word 2013",
      ver: "15.0.4420",
      rel: 2013,
      eol_date: "2023-04-11",
      exts: ["docx", "doc", "pdf"],
      kind: "office",
      cves: [
        ["CVE-2023-21716", 9.8],
        ["CVE-2022-30190", 7.8],
        ["CVE-2021-40444", 8.8],
        ["CVE-2017-11882", 7.8],
      ],
      cve: 14,
    },
    {
      id: "word2016",
      name: "Microsoft Office Word 2016",
      ver: "16.0.4266",
      rel: 2016,
      eol_date: "2025-10-14",
      exts: ["docx", "doc", "pdf"],
      kind: "office",
      cves: [
        ["CVE-2023-21716", 9.8],
        ["CVE-2021-40444", 8.8],
      ],
      cve: 6,
    },
    {
      id: "word2019",
      name: "Microsoft Office Word 2019",
      ver: "16.0.10827",
      rel: 2019,
      eol_date: "2025-10-14",
      exts: ["docx", "doc", "pdf"],
      kind: "office",
      cves: [
        ["CVE-2023-21716", 9.8],
        ["CVE-2024-38021", 8.8],
      ],
      cve: 2,
    },
    {
      id: "excel2010",
      name: "Microsoft Excel 2010",
      ver: "14.0.7268",
      rel: 2010,
      eol_date: "2020-10-13",
      exts: ["xlsx", "xls"],
      kind: "office",
      cves: [
        ["CVE-2018-0802", 7.8],
        ["CVE-2017-11882", 7.8],
        ["CVE-2016-7262", 7.8],
      ],
      cve: 21,
    },
    {
      id: "excel2016",
      name: "Microsoft Excel 2016",
      ver: "16.0.4266",
      rel: 2016,
      eol_date: "2025-10-14",
      exts: ["xlsx", "xls"],
      kind: "office",
      cves: [["CVE-2023-21716", 9.8]],
      cve: 5,
    },
    {
      id: "ppt2016",
      name: "Microsoft PowerPoint 2016",
      ver: "16.0.4266",
      rel: 2016,
      eol_date: "2025-10-14",
      exts: ["pptx", "pdf"],
      kind: "office",
      cves: [
        ["CVE-2023-21716", 9.8],
        ["CVE-2021-28449", 7.8],
      ],
      cve: 6,
    },
    {
      id: "lo72",
      name: "LibreOffice",
      ver: "7.2.5.2",
      rel: 2021,
      eol_date: "2022-06-12",
      exts: ["odt", "docx", "xlsx", "pdf"],
      kind: "office",
      cves: [
        ["CVE-2022-26305", 7.5],
        ["CVE-2022-26306", 7.5],
      ],
      cve: 4,
    },
    {
      id: "acro11",
      name: "Adobe Acrobat Pro XI",
      ver: "11.0.23",
      rel: 2012,
      eol_date: "2017-10-15",
      exts: ["pdf"],
      kind: "pdf",
      cves: [
        ["CVE-2018-4990", 8.8],
        ["CVE-2019-7089", 7.5],
        ["CVE-2020-3803", 7.8],
        ["CVE-2018-12808", 8.8],
      ],
      cve: 37,
    },
    {
      id: "pdflib15",
      name: "Adobe PDF Library",
      ver: "15.0",
      rel: 2015,
      eol_date: null,
      exts: ["pdf"],
      kind: "pdf",
      cves: [],
      cve: 0,
    },
    {
      id: "canon",
      name: "Canon iR-ADV C5535 PDF",
      ver: "1.2",
      rel: 2015,
      eol_date: null,
      exts: ["pdf"],
      kind: "scanner",
      cves: [],
      cve: 0,
    },
    {
      id: "ios93",
      name: "iOS 9.3",
      ver: "9.3.5",
      rel: 2016,
      eol_date: "2018-09-17",
      exts: ["jpg"],
      kind: "camera",
      dev: "Apple iPhone 6s",
      cves: [["CVE-2016-4657", 8.8]],
      cve: 11,
    },
    {
      id: "ios144",
      name: "iOS 14.4",
      ver: "14.4",
      rel: 2021,
      eol_date: "2022-09-12",
      exts: ["jpg"],
      kind: "camera",
      dev: "Apple iPhone 11",
      cves: [["CVE-2021-1782", 7.0]],
      cve: 6,
    },
    {
      id: "ios166",
      name: "iOS 16.6",
      ver: "16.6",
      rel: 2023,
      eol_date: "2024-09-16",
      exts: ["jpg", "heic", "mp4", "mov"],
      kind: "camera",
      dev: "Apple iPhone 13 Pro",
      cves: [
        ["CVE-2023-41064", 7.8],
        ["CVE-2023-41061", 7.8],
      ],
      cve: 9,
    },
    {
      id: "android12",
      name: "Android 12 (One UI 4)",
      ver: "12",
      rel: 2022,
      eol_date: "2025-03-01",
      exts: ["jpg"],
      kind: "camera",
      dev: "Samsung SM-G991B",
      cves: [["CVE-2022-20210", 7.8]],
      cve: 4,
    },
    {
      id: "sony",
      name: "Sony ILCE-7M3 v3.01",
      ver: "3.01",
      rel: 2018,
      eol_date: null,
      exts: ["jpg"],
      kind: "camera",
      dev: "Sony ILCE-7M3",
      cves: [],
      cve: 0,
    },
    {
      id: "ps2019",
      name: "Adobe Photoshop CC 2019",
      ver: "20.0",
      rel: 2018,
      eol_date: "2020-10-20",
      exts: ["jpg"],
      kind: "image",
      cves: [["CVE-2019-7968", 8.8]],
      cve: 3,
    },
  ];
  // Mail, calendar and contact exports (eml/msg/ics/vcf) of the story documents.
  SOFTWARE.push({
    id: "outlook365",
    name: "Microsoft Outlook (Microsoft 365)",
    ver: "16.0.17928",
    rel: 2024,
    eol_date: null,
    exts: ["eml", "msg", "ics", "vcf"],
    kind: "mail",
    cves: [],
    cve: 0,
  });
  const SW = Object.fromEntries(SOFTWARE.map(s => [s.id, s]));
  const swEol = s => !!(s && s.eol_date && s.eol_date < TODAY);
  const swFor = (ext, year, allow) =>
    SOFTWARE.filter(s => s.exts.includes(ext) && s.rel <= year && (!allow || allow.includes(s.id)));

  const PROFILES = { passive: "Пассивный", std: "Стандартный", full: "Полный", custom: "Свой" };
  const STAGES = [
    { id: "search", label: "Поиск" },
    { id: "download", label: "Загрузка" },
    { id: "meta", label: "Извлечение метаданных" },
    { id: "analysis", label: "Анализ" },
    { id: "network", label: "Сеть и DNS" },
    { id: "ports", label: "Порты" },
    { id: "recon", label: "Разведка сайта" },
    { id: "fuzz", label: "Поиск на сайте" },
    { id: "report", label: "Отчёт" },
  ];
  // Sources: no Bing/Google scraping. Keyed ones carry their status from settings.keys.
  const SOURCES = [
    { id: "wayback", name: "Wayback Machine", key: null },
    { id: "cc", name: "Common Crawl", key: null },
    { id: "crt", name: "crt.sh", key: null },
    // Keyless sources: subdomains, document URLs, dorks, same as SOURCES in foca-engine/scan.rs.
    { id: "crtname", name: "crt.name", key: null },
    { id: "anubis", name: "Anubis", key: null },
    { id: "hackertarget", name: "HackerTarget", key: null },
    { id: "rapiddns", name: "RapidDNS", key: null },
    { id: "subcenter", name: "subdomain.center", key: null },
    { id: "thc", name: "THC ip.thc.org", key: null },
    { id: "arquivo", name: "Arquivo.pt", key: null },
    { id: "otx_url", name: "AlienVault OTX (URL)", key: null },
    { id: "ddg", name: "DuckDuckGo (дорки)", key: null },
    { id: "crawler", name: "Обход сайта", key: null, active: true },
    // Keyless dork engines via the embedded browser (hidden WebView on Android).
    { id: "startpage", name: "Startpage (через браузер)", key: null },
    { id: "brave_web", name: "Brave Search (через браузер)", key: null },
    { id: "yahoo", name: "Yahoo (через браузер)", key: null },
    { id: "searx_pool", name: "Публичные SearXNG (через браузер)", key: null },
    { id: "brave", name: "Brave Search API (с ключом)", key: "brave", optional: true },
    { id: "searx", name: "SearXNG", key: "searx" },
    { id: "dns", name: "DNS / CT", key: null },
    { id: "shodan", name: "Shodan (кэш баннеров)", key: "shodan" },
    // User-installed sandboxed plugins (WASM/declarative), run in the network stage.
    { id: "plugins", name: "Плагины (WASM и декларативные)", key: null },
    // Site recon (foca-recon): passive from the archive; bucket listing only at the active level.
    { id: "recon", name: "Сайт: технологии, favicon, JS", key: null },
    { id: "webaudit", name: "Веб-аудит: заголовки, CSP, source maps, API", key: null },
    { id: "wellknown", name: "robots / sitemap / security.txt (архив)", key: null },
    { id: "buckets", name: "Облачные хранилища", key: null },
    { id: "grepapp", name: "grep.app (публичный код)", key: null },
    // Port scan (foca_net::ports) and site file search (foca-fuzz): active phase only.
    { id: "ports", name: "Порты (TCP)", key: null, active: true },
    // Subdomain enumeration and the TLS/X.509 inspector: standard and full profiles only.
    { id: "subdomains", name: "Перебор и перестановки поддоменов", key: null, active: true },
    { id: "tls", name: "TLS/X.509-инспектор", key: null, active: true },
    { id: "fuzz", name: "Поиск на сайте", key: null, active: true },
  ];
  // Active modules, same as ACTIVE_MODULES in foca-engine/scan.rs (ports: passive = Shodan InternetDB cache,
  // active = own scan).
  const ACTIVE_MODULES = ["axfr", "fuzz", "ports", "nsec"];
  // Sources of the infrastructure modules (network stage): enumeration and TLS inspection.
  const INFRA_SRC = ["subdomains", "tls"];
  // Fuzzing wordlists (as wordlists::BUILTIN/REGISTRY in foca-fuzz; line counts and sizes follow SecLists).
  const WL_BUILTIN = [
    ["common", "Частые пути (common)", "Discovery/Web-Content/common.txt", 4752, 38536],
    ["quickhits", "Служебные файлы (quickhits)", "Discovery/Web-Content/quickhits.txt", 2571, 40210],
    ["db-backups", "Бэкапы баз данных", "Discovery/Web-Content/Common-DB-Backups.txt", 335, 4590],
    ["raft-small-files", "Файлы (raft small)", "Discovery/Web-Content/raft-small-files.txt", 11424, 148390],
    [
      "raft-small-directories",
      "Каталоги (raft small)",
      "Discovery/Web-Content/raft-small-directories.txt",
      20115,
      163189,
    ],
    ["dsstore", "Имена из .DS_Store", "Discovery/Web-Content/dsstorewordlist.txt", 1828, 17378],
    [
      "dns-top5000",
      "Поддомены, топ-5000 (для vhost)",
      "Discovery/DNS/subdomains-top1million-5000.txt",
      5000,
      30075,
    ],
    ["cms-wordpress", "WordPress", "Discovery/Web-Content/CMS/wordpress.fuzz.txt", 1578, 58959],
  ];
  const WL_REMOTE = [
    ["dns-top20000", "Поддомены, топ-20000", "Discovery/DNS/subdomains-top1million-20000.txt", 20000, 135562],
    [
      "dns-top110000",
      "Поддомены, топ-110000",
      "Discovery/DNS/subdomains-top1million-110000.txt",
      110000,
      1311067,
    ],
    [
      "raft-medium-files",
      "Файлы (raft medium)",
      "Discovery/Web-Content/raft-medium-files.txt",
      17129,
      224381,
    ],
    [
      "raft-medium-directories",
      "Каталоги (raft medium)",
      "Discovery/Web-Content/raft-medium-directories.txt",
      29999,
      250427,
    ],
    [
      "dirbuster-small",
      "DirBuster small",
      "Discovery/Web-Content/DirBuster-2007_directory-list-2.3-small.txt",
      87663,
      725433,
    ],
    [
      "dirbuster-medium",
      "DirBuster medium",
      "Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt",
      220559,
      1979956,
    ],
  ];
  const FZ_MODULES = [
    ["docs", "Документы", "Типовые папки и имена офисных файлов, варианты известных имён (год, версия)"],
    ["backups", "Бэкапы", "Резервные копии известных файлов (.bak, ~, .old, .zip) и дампы баз"],
    ["exposed", "Служебные файлы", "Забытые .env, .git, .DS_Store, конфиги, с проверкой формата"],
    ["dirlisting", "Листинги каталогов", "Открытые «Index of /» и ссылки на документы из них"],
    ["vhost", "Скрытые vhost", "Поддомены заказчика на том же адресе (заголовок Host, только из скоупа)"],
    ["cms", "Пути CMS", "Словарь по определённой CMS (WordPress, Joomla, Drupal, SharePoint)"],
  ];
  const FZ_PER = { docs: 1400, backups: 420, exposed: 2580, dirlisting: 160, vhost: 500, cms: 1400 };
  const COLORS = [
    "#2563eb",
    "#0d9488",
    "#dc2626",
    "#c026d3",
    "#ea580c",
    "#65a30d",
    "#7c3aed",
    "#0891b2",
    "#64748b",
    "#db2777",
    "#0f766e",
    "#9333ea",
    "#b45309",
    "#4f46e5",
  ];

  const FIRST = [
    "Олена",
    "Ігор",
    "Марина",
    "Андрій",
    "Тетяна",
    "Віктор",
    "Сергій",
    "Юлія",
    "Дмитро",
    "Наталія",
    "Оксана",
    "Богдан",
    "Ірина",
    "Максим",
    "Світлана",
    "Роман",
    "Галина",
    "Павло",
  ];
  const LAST = [
    ["Коваленко", "Коваленко"],
    ["Петренко", "Петренко"],
    ["Шевчук", "Шевчук"],
    ["Бондар", "Бондар"],
    ["Мельник", "Мельник"],
    ["Ткаченко", "Ткаченко"],
    ["Лисенко", "Лисенко"],
    ["Гриценко", "Гриценко"],
    ["Мороз", "Мороз"],
    ["Савченко", "Савченко"],
    ["Кравчук", "Кравчук"],
    ["Олійник", "Олійник"],
    ["Поліщук", "Поліщук"],
    ["Руденко", "Руденко"],
    ["Марченко", "Марченко"],
    ["Литвин", "Литвин"],
  ];

  // ================= project specifications =================
  const CONTOSO = {
    id: "contoso",
    name: "contoso.example",
    client: "ТОВ «Контосо Енерджі»",
    domain: "contoso.example",
    created_at: "2026-10-28T09:12:00",
    seed: 20261119,
    ndocs: 342,
    scope: {
      contact: "Ігор Петренко, ІТ-директор",
      phone: "+380 44 123-45-67",
      targets: [
        { v: "contoso.example", type: "domain" },
        { v: "*.contoso-group.example", type: "wild" },
        { v: "203.0.113.0/24", type: "cidr" },
      ],
      excl: ["mail.contoso.example", "10.0.0.0/8"],
    },
    people: [
      { login: "o.kovalenko", name: "Олена Коваленко", role: "Бухгалтерія", pc: "BUH-PC07", dept: "buh" },
      { login: "i.petrenko", name: "Ігор Петренко", role: "ІТ-відділ", pc: "IT-WS02", dept: "it" },
      { login: "admin", name: "Administrator", role: "Службова", pc: "SRV-FILE01", dept: "svc" },
      { login: "m.shevchuk", name: "Марина Шевчук", role: "Маркетинг", pc: "MKT-NB14", dept: "mkt" },
      { login: "a.bondar", name: "Андрій Бондар", role: "Юридичний", pc: "LAW-PC03", dept: "law" },
      { login: "t.melnyk", name: "Тетяна Мельник", role: "HR", pc: "HR-PC01", dept: "hr" },
      { login: "v.tkachenko", name: "Віктор Ткаченко", role: "Інженерія", pc: "ENG-WS11", dept: "eng" },
      { login: "s.lysenko", name: "Сергій Лисенко", role: "Продажі", pc: "SAL-NB05", dept: "sales" },
      { login: "scan", name: "scan", role: "МФУ", pc: "MFP-2F", dept: "mfp" },
    ],
    text_people: [
      {
        login: "y.hrytsenko",
        name: "Юлія Гриценко",
        role: "Закупівлі",
        src: "Текст документа",
        ext: "pdf",
      },
      { login: "d.moroz", name: "Петро Приклад", role: "Енергетика", src: "Текст документа", ext: "pdf" },
      {
        login: "n.savchenko",
        name: "Наталія Савченко",
        role: "Фінанси",
        src: "Текст документа",
        ext: "xlsx",
      },
    ],
    web: [
      {
        name: "contoso.example",
        paths: ["/upload/docs/", "/wp-content/uploads/2024/", "/about/reports/", "/hr/"],
      },
      { name: "portal.contoso.example", paths: ["/public/", "/media/"] },
      { name: "files.contoso.example", paths: ["/files/", "/media/tender/", "/public/"] },
    ],
    titles: {
      pdf: [
        "Річний звіт 2024",
        "Тендерна документація ТЕС-2",
        "Прайс-лист послуг",
        "Політика конфіденційності",
        "Звіт про сталий розвиток",
        "Інструкція з охорони праці",
        "Технічні умови підключення",
        "Фінансова звітність Q3",
      ],
      docx: [
        "Договір постачання",
        "Наказ про відпустку",
        "Шаблон комерційної пропозиції",
        "Положення про закупівлі",
        "Акт виконаних робіт",
        "Протокол засідання",
      ],
      xlsx: [
        "Графік відключень",
        "Кошторис ремонту",
        "Перелік обладнання",
        "Тарифи 2025",
        "Звіт по споживанню",
      ],
      pptx: ["Презентація для інвесторів", "Стратегія 2026", "Онбординг нових співробітників"],
      doc: ["Статут підприємства", "Типовий договір", "Заявка на підключення"],
      xls: ["Реєстр лічильників", "Бюджет 2019"],
      jpg: ["office_team", "board_meeting", "substation_view"],
      odt: ["Лист-відповідь", "Службова записка"],
    },
    exts: [
      ["pdf", 26],
      ["docx", 17],
      ["xlsx", 12],
      ["pptx", 6],
      ["doc", 6],
      ["xls", 5],
      ["jpg", 13],
      ["odt", 5],
    ],
    dept_exts: {
      buh: ["xlsx", "xls", "pdf", "docx"],
      it: ["pdf", "docx", "xlsx"],
      svc: ["pdf", "xlsx", "docx"],
      mkt: ["pptx", "jpg", "pdf", "docx"],
      law: ["docx", "doc", "pdf"],
      hr: ["docx", "doc", "pptx"],
      eng: ["xlsx", "jpg", "odt", "pdf", "docx"],
      sales: ["pdf", "pptx", "docx", "xls"],
      mfp: ["pdf"],
    },
    folders: {
      buh: ["C:\\Users\\o.kovalenko\\Documents\\Звіти\\2024", "\\\\SRV-FILE01\\buh$\\Податкова"],
      it: ["C:\\Users\\i.petrenko\\Documents\\ІТ"],
      svc: ["C:\\Users\\Administrator\\Downloads"],
      mkt: ["C:\\Users\\m.shevchuk\\Desktop\\Презентації"],
      law: ["\\\\SRV-FILE01\\public\\Шаблони"],
      hr: ["\\\\NAS02\\hr\\Накази"],
      eng: ["D:\\Projects\\ТЕС-2\\КД"],
      sales: ["\\\\SRV-FILE01\\public\\Шаблони"],
    },
    folder_from: { "\\\\NAS02\\hr\\Накази": 2020 },
    printers: [
      { name: "\\\\SRV-PRN01\\Canon iR-ADV C5535 2F", from: 2018 },
      { name: "HP LaserJet Pro M404 (BUH)", depts: ["buh"], from: 2019 },
      { name: "\\\\SRV-PRN01\\Kyocera ECOSYS M2540dn", from: 2017 },
      { name: "Microsoft Print to PDF", from: 2016 },
    ],
    sw_allow: null,
    years: [2016, 2025],
    gps_places: [
      ["Кривий Ріг, промзона ТЕС-2", 47.92, 33.43],
      ["Київ, головний офіс", 50.45, 30.52],
      ["Дніпро, підстанція", 48.46, 35.04],
      ["Львів, філія", 49.84, 24.03],
      ["Одеса, склад", 46.48, 30.72],
      ["Харків, ПС-110", 49.99, 36.23],
    ],
    hosts: [
      {
        name: "contoso.example",
        ip: "203.0.113.10",
        role: "Веб-сервер",
        tech: "nginx 1.18.0, WordPress 6.2",
        cloud: "-",
        services: [
          ["80/tcp", "http", "nginx 1.18.0 → 301"],
          ["443/tcp", "https", "nginx 1.18.0"],
        ],
      },
      {
        name: "portal.contoso.example",
        ip: "203.0.113.12",
        role: "Портал",
        tech: "Microsoft-IIS/8.5, ASP.NET 4.0",
        cloud: "-",
        services: [
          ["443/tcp", "https", "IIS 8.5"],
          ["3389/tcp", "rdp", "Microsoft Terminal Services"],
        ],
      },
      {
        name: "files.contoso.example",
        ip: "203.0.113.15",
        role: "Файловый",
        tech: "Apache 2.4.29 (Ubuntu)",
        cloud: "-",
        services: [
          ["80/tcp", "http", "Apache 2.4.29"],
          ["443/tcp", "https", "Apache 2.4.29"],
          ["21/tcp", "ftp", "vsftpd 3.0.3"],
        ],
      },
      {
        name: "mail.contoso.example",
        ip: "203.0.113.20",
        role: "Почта",
        tech: "Microsoft Exchange 2016 CU12 (Shodan)",
        cloud: "-",
        services: [
          ["25/tcp", "smtp", "Exchange 2016 (Shodan)"],
          ["443/tcp", "https", "OWA 15.1.1713 (Shodan)"],
        ],
        source: "Shodan",
      },
      {
        name: "vpn.contoso.example",
        ip: "203.0.113.30",
        role: "VPN",
        tech: "FortiGate SSL-VPN (FortiOS 7.0.9)",
        tech_s1: "-",
        cloud: "-",
        services: [
          ["443/tcp", "https", "FortiGate SSL-VPN"],
          ["500/udp", "isakmp", "IKEv2"],
        ],
        source: "crt.sh",
      },
      {
        name: "cdn.contoso.example",
        ip: "192.0.2.150",
        role: "CDN",
        tech: "Cloudflare",
        cloud: "Cloudflare",
        services: [["443/tcp", "https", "cloudflare"]],
      },
      {
        name: "dev.contoso.example",
        ip: "198.51.100.144",
        role: "Тестовый",
        tech: "Jenkins 2.263",
        tech_s1: "-",
        cloud: "AWS eu-central-1",
        services: [
          ["8080/tcp", "http", "Jenkins 2.263"],
          ["22/tcp", "ssh", "OpenSSH 7.6p1"],
        ],
        source: "crt.sh",
      },
      {
        name: "old.contoso.example",
        ip: "CNAME → contoso-example.azurewebsites.net",
        role: "Висящий CNAME",
        tech: "-",
        cloud: "Azure",
        services: [],
        source: "DNS",
      },
      // Found by the enumeration: brute force (wordlist) and the Microsoft 365 tenant (AD FS host).
      {
        name: "staging.contoso.example",
        ip: "203.0.113.41",
        role: "Тестовый",
        tech: "nginx 1.22.1",
        cloud: "-",
        services: [["443/tcp", "https", "nginx 1.22.1"]],
        source: "bruteforce",
      },
      {
        name: "sts.contoso.example",
        ip: "203.0.113.25",
        role: "Вход (AD FS)",
        tech: "Microsoft-HTTPAPI/2.0 (AD FS)",
        cloud: "-",
        services: [["443/tcp", "https", "Microsoft-HTTPAPI/2.0"]],
        source: "m365",
      },
      {
        name: "ns1.contoso.example",
        ip: "203.0.113.2",
        role: "DNS",
        tech: "BIND 9.11",
        cloud: "-",
        services: [["53/udp", "domain", "BIND 9.11"]],
        source: "DNS",
      },
      {
        name: "ns2.contoso.example",
        ip: "203.0.113.3",
        role: "DNS",
        tech: "BIND 9.11",
        cloud: "-",
        services: [["53/tcp", "domain", "BIND 9.11 (AXFR открыт)"]],
        source: "DNS",
      },
    ],
    scans: [
      {
        id: "contoso-s1",
        profile_id: "std",
        active: false,
        started_at: "2026-11-12T10:03:00",
        minutes: 26,
        trigger: "manual",
      },
      {
        id: "contoso-s2",
        profile_id: "full",
        active: true,
        started_at: "2026-11-19T19:58:00",
        minutes: 76,
        trigger: "manual",
      },
    ],
    reports: [
      {
        id: 3,
        name: "Звіт_пентест_contoso.example_v2.pdf",
        tpl: "Полный отчёт пентеста",
        fmt: "pdf",
        created_at: "2026-11-19T23:40:00",
        size: "4,8 МБ",
        lang: "UA",
        opts: { min_sev: "warn", confirmed: true },
      },
      {
        id: 2,
        name: "Сводка_для_директора.md",
        tpl: "Краткая сводка",
        fmt: "md",
        created_at: "2026-11-19T22:15:00",
        size: "14 КБ",
        lang: "RU",
        opts: { min_sev: "high", confirmed: true },
      },
      {
        id: 1,
        name: "Pentest_report_contoso.example_v1.html",
        tpl: "Полный отчёт пентеста",
        fmt: "html",
        created_at: "2026-11-12T10:31:00",
        size: "2,1 МБ",
        lang: "EN",
        opts: { min_sev: "low", confirmed: false },
      },
    ],
  };

  // ---- 1.3: document forensics of the story documents (doc_get.forensics, keyed by document name) ----
  // Every value is fictional and consistent with the organization: the signer Петро Приклад (a text person
  // "Підпис у PDF"), SRV-SQL02 / MAIL01 (extra computers), the Microsoft 365 tenant of contoso.example.
  // Personal values are stored masked, as the core does (foca_analysis::pii::sanitize).
  const CONTOSO_EDRPOU = "12345678";
  // Documents in the extended formats, added after the generated ones (ids follow ndocs).
  const CONTOSO_FX_DOCS = [
    {
      ext: "eml",
      name: "Re_Тендер_ТЕС-2_уточнення.eml",
      title: "Re: Тендер ТЕС-2, уточнення",
      host: "files.contoso.example",
      author: "s.lysenko",
      sw: "outlook365",
      year: 2025,
      m: 2,
      day: 18,
      hh: 13,
      mm: 20,
      size: 214,
    },
    {
      ext: "ics",
      name: "Нарада_ТЕС-2_графік.ics",
      title: "Нарада ТЕС-2: графік робіт",
      host: "portal.contoso.example",
      author: "i.petrenko",
      sw: "outlook365",
      year: 2025,
      m: 2,
      day: 26,
      hh: 9,
      mm: 12,
      size: 6,
    },
    {
      ext: "vcf",
      name: "Контакти_відділу_продажів.vcf",
      title: "Контакти відділу продажів",
      host: "contoso.example",
      author: "s.lysenko",
      sw: "outlook365",
      year: 2025,
      m: 1,
      day: 15,
      hh: 16,
      mm: 40,
      size: 4,
    },
    {
      ext: "heic",
      name: "IMG_4127.heic",
      title: "IMG_4127",
      host: "contoso.example",
      author: "v.tkachenko",
      sw: "ios166",
      year: 2024,
      m: 8,
      day: 2,
      hh: 11,
      mm: 9,
      size: 2860,
      gps: ["Кривий Ріг, промзона ТЕС-2", 47.92, 33.43],
    },
    {
      ext: "mp4",
      name: "IMG_4131.mp4",
      title: "IMG_4131",
      host: "contoso.example",
      author: "v.tkachenko",
      sw: "ios166",
      year: 2024,
      m: 8,
      day: 2,
      hh: 11,
      mm: 26,
      size: 48210,
      gps: ["Кривий Ріг, промзона ТЕС-2", 47.92, 33.43],
    },
    {
      ext: "zip",
      name: "Тендер_ТЕС-2_додатки.zip",
      title: "Тендер ТЕС-2: додатки",
      host: "files.contoso.example",
      author: null,
      sw: null,
      year: 2024,
      m: 11,
      day: 4,
      hh: 17,
      mm: 5,
      size: 1830,
    },
  ];
  /** Full forensics record of doc_get with empty defaults (same keys as the core). */
  const fxRec = (o = {}) => ({
    signatures: [],
    bad_redactions: [],
    hidden_content: [],
    pdf_revisions: [],
    scan_without_text: false,
    xmp_history: [],
    xmp_ids: null,
    pii: [],
    links: [],
    fields: {},
    embedded: [],
    ...o,
  });
  const KEP_ISSUER = "O=Інформаційно-довідковий департамент ДПС, CN=КНЕДП - ІДД ДПС, C=UA";
  const CONTOSO_FX = {
    "Договір_постачання_ТЕС-2_v3.docx": fxRec({
      hidden_content: [
        {
          kind: "vanish",
          location: "абзац 18",
          text: "Знижка 8% погоджена усно з ТОВ «Енергобуд», у договір не вносити",
        },
        { kind: "vanish", location: "абзац 41", text: "Реквізити: IBAN ••••••••••••••••••••••••4417" },
      ],
      pii: [
        {
          kind: "iban",
          sev: "high",
          count: 1,
          samples: ["Реквізити: IBAN ••••••••••••••••••••••••4417"],
          location: "абзац 41",
        },
        {
          kind: "edrpou",
          sev: "info",
          count: 2,
          samples: ["ЄДРПОУ ••••••89", "ЄДРПОУ ••••••72"],
          location: "абзац 2",
        },
      ],
      links: [
        {
          url: "https://contosoexample.sharepoint.com/:f:/s/Legal/EhT••••••••Qw?e=••••••",
          host: "contosoexample.sharepoint.com",
          service: "share_point",
          shared: true,
          internal: false,
          expires: null,
          tokens: [{ name: "e", kind: "query" }],
          sev: "warn",
        },
      ],
    }),
    "tes2_build.jpg": fxRec({
      xmp_history: [
        {
          action: "created",
          when: "2024-08-02T11:05:12+03:00",
          software_agent: "iOS 16.6",
          instance_id: "xmp.iid:5e1a7c0b-2f4d-4c1e-9a77-1f0d3b6c2a11",
        },
        {
          action: "derived",
          when: "2024-08-05T09:31:40+03:00",
          software_agent: "Adobe Photoshop Lightroom Classic 13.4 (Windows)",
          parameters: "converted from image/heic to image/jpeg",
        },
        {
          action: "saved",
          when: "2024-08-05T09:34:02+03:00",
          software_agent: "Adobe Photoshop 25.9 (Windows)",
          instance_id: "xmp.iid:9b3e4d21-6a80-4f5b-8c2d-07e1f4a9b6c3",
          changed: "/",
        },
      ],
      xmp_ids: {
        document_id: "xmp.did:5e1a7c0b-2f4d-4c1e-9a77-1f0d3b6c2a11",
        instance_id: "xmp.iid:9b3e4d21-6a80-4f5b-8c2d-07e1f4a9b6c3",
        original_document_id: "xmp.did:5e1a7c0b-2f4d-4c1e-9a77-1f0d3b6c2a11",
        derived_from_document_id: "xmp.did:5e1a7c0b-2f4d-4c1e-9a77-1f0d3b6c2a11",
        derived_from_instance_id: "xmp.iid:5e1a7c0b-2f4d-4c1e-9a77-1f0d3b6c2a11",
      },
    }),
    "Перелік_обладнання_ТЕС-2.xlsx": fxRec({
      hidden_content: [
        {
          kind: "row",
          location: "Обладнання!12:14",
          text: "Закупівельна ціна; Знижка постачальника; Маржа, %",
        },
        { kind: "column", location: "Обладнання!H:I", text: "Ціна закупівлі, грн; Постачальник" },
        { kind: "sheet", location: "Постачальники_контакти", text: "" },
      ],
      fields: {
        "xl:connection:ERP_Billing:database": "Billing",
        "xl:connection:ERP_Billing:user": "svc_report",
        "xl:connection:ERP_Billing:odcFile": "\\\\SRV-FILE01\\public\\Підключення\\ERP_Billing.odc",
        "xl:pivotCache1:refreshedBy": "Віктор Ткаченко",
        "xl:pivotCache1:refreshedDate": "2025-02-03T14:20:00",
        "xl:pivotCache1:source": "SRV-SQL02",
      },
    }),
    "Звіти.lnk": fxRec({
      fields: {
        "lnk:machine_id": "buh-pc07",
        "lnk:mac": "3c:52:82:4a:1f:0b",
        "lnk:volume_serial": "6A2F-91C4",
        "lnk:volume_label": "OS",
        "lnk:drive_type": "DRIVE_FIXED",
        "lnk:local_base_path": "C:\\Users\\o.kovalenko\\Documents\\Звіти\\2024",
        "lnk:network_share": "\\\\SRV-FILE01\\buh$",
        "lnk:network_path": "\\\\SRV-FILE01\\buh$\\Звіти\\2024\\Податкова_Q4.xlsx",
        "lnk:access_time": "2024-01-22T08:51:00Z",
        "lnk:droid_file_id": "8a1c7e40-b8f2-11ee-9d3a-3c52824a1f0b",
      },
    }),
    "Технічні_умови_підключення.pdf": fxRec({
      signatures: [
        {
          kind: "pdf",
          source: "pdf:obj 41",
          signer: {
            subject: `CN=Приклад Петро Тестович, SN=Приклад, GN=Петро Тестович, O=ТОВ «Контосо Енерджі», T=Головний енергетик, serialNumber=TINUA-********57, C=UA, L=Київ`,
            common_name: "Приклад Петро Тестович",
            given_name: "Петро Тестович",
            surname: "Мороз",
            organization: "ТОВ «Контосо Енерджі»",
            org_unit: "Служба головного енергетика",
            title: "Головний енергетик",
            locality: "Київ",
            country: "UA",
            email: "d.moroz@contoso.example",
            edrpou: CONTOSO_EDRPOU,
            rnokpp_masked: "********57",
            rnokpp_valid: true,
            issuer: KEP_ISSUER,
            issuer_cn: "КНЕДП - ІДД ДПС",
            serial: "58E2D9E7F900307B04000000A1C42B00",
            not_before: "2016-11-21T10:00:00Z",
            not_after: "2018-11-21T21:59:59Z",
          },
          certificates: 2,
          signing_time: "2017-06-16T09:41:12+03:00",
          timestamp: {
            gen_time: "2017-06-19T08:02:13Z",
            tsa: "TSP-сервер КНЕДП - ІДД ДПС",
            policy: "1.2.804.2.1.1.1.2.3.1",
            serial: "1F3A00C2",
          },
          digest_algorithm: "ДСТУ ГОСТ 34.311-95",
          sub_filter: "ETSI.CAdES.detached",
          name: "Приклад Петро Тестович",
          reason: "Погоджено",
          location: "Київ",
          contact: "d.moroz@contoso.example",
          byte_range: [0, 412880, 429264, 96210],
          bytes_after: 18432,
          modified_after_signing: true,
          digest_valid: null,
        },
      ],
      pdf_revisions: [
        {
          revision: 1,
          end_offset: 401220,
          author: "i.petrenko",
          creator: "Acrobat PDFMaker 11 для Word",
          producer: "Adobe PDF Library 11.0",
          modified: "2017-06-14T15:10:40+03:00",
          objects: 212,
        },
        {
          revision: 2,
          end_offset: 525474,
          author: "i.petrenko",
          producer: "Adobe PDF Library 11.0",
          modified: "2017-06-16T09:41:12+03:00",
          objects: 9,
        },
        {
          revision: 3,
          end_offset: 543906,
          author: "admin",
          creator: "Adobe Acrobat Pro 11.0.10",
          producer: "Adobe Acrobat Pro 11.0.10",
          modified: "2017-06-19T10:55:01+03:00",
          objects: 14,
          removed_text: ["Потужність приєднання: 2,5 МВт", "Точка підключення: ПС-110 «Харків», комірка 14"],
          added_text: ["Потужність приєднання: 1,6 МВт"],
        },
      ],
      bad_redactions: [
        {
          page: 3,
          fill: "black",
          rect: [72, 518.4, 412.6, 532.8],
          text: "Резервна лінія: ПС-35 «Західна», вул. Промислова, 12",
        },
        {
          page: 4,
          fill: "white",
          rect: [72, 140.2, 300.5, 154.6],
          text: "Тел. чергового диспетчера: +380 67 ••• •• 14",
        },
      ],
      xmp_history: [
        {
          action: "converted",
          when: "2017-06-14T15:10:38+03:00",
          software_agent: "Acrobat PDFMaker 11 для Word",
          parameters:
            "from application/vnd.openxmlformats-officedocument.wordprocessingml.document to application/pdf",
        },
        {
          action: "saved",
          when: "2017-06-19T10:55:01+03:00",
          software_agent: "Adobe Acrobat Pro 11.0.10",
          instance_id: "uuid:4b1f9c2e-77a0-4e3d-b1c5-92d6e0f3a8b4",
          changed: "/",
        },
      ],
      xmp_ids: {
        document_id: "uuid:0c6e3b2a-91d4-4f87-a2e5-6b8d1c7f9e30",
        instance_id: "uuid:4b1f9c2e-77a0-4e3d-b1c5-92d6e0f3a8b4",
      },
      pii: [
        {
          kind: "phone",
          sev: "low",
          count: 3,
          samples: ["Тел. чергового диспетчера: +380 67 ••• •• 14", "тел. +380 44 ••• •• 67"],
          location: "стор. 4",
        },
        { kind: "rnokpp", sev: "high", count: 1, samples: ["РНОКПП ••••••••57"], location: "підпис" },
      ],
      links: [
        {
          url: "https://drive.google.com/drive/folders/1Qx••••••••hT?usp=sharing",
          host: "drive.google.com",
          service: "google_drive",
          shared: true,
          internal: false,
          expires: null,
          tokens: [],
          sev: "low",
        },
        {
          url: "https://contosoexample.blob.core.windows.net/scada/tes2-scheme.zip?sv=2021-08-06&sp=r&sig=••••••••",
          host: "contosoexample.blob.core.windows.net",
          service: "azure_storage",
          shared: false,
          internal: false,
          expires: null,
          tokens: [{ name: "sig", kind: "azure_sas" }],
          sev: "crit",
        },
      ],
    }),
    "Звіт_по_споживанню_2019.xlsx": fxRec({
      pii: [
        {
          kind: "iban",
          sev: "high",
          count: 12,
          samples: ["UA •••••••••••••••••••••••••0417", "UA •••••••••••••••••••••••••2290"],
          location: "Споживачі!F2:F13",
        },
        {
          kind: "card",
          sev: "high",
          count: 2,
          samples: ["•••• •••• •••• 4471", "•••• •••• •••• 9015"],
          details: ["Visa ×1", "ПРОСТІР ×1"],
          location: "Споживачі!G4",
        },
      ],
    }),
    "Re_Тендер_ТЕС-2_уточнення.eml": fxRec({
      fields: {
        "eml:message-id": "<7f3c2a91e0b84d@MAIL01.contoso.local>",
        "eml:message_id_domain": "mail01.contoso.local",
        "eml:x-mailer": "Microsoft Outlook 16.0",
        "eml:x-originating-ip": "[10.10.3.45]",
        "eml:originating_ips": "10.10.3.45",
        "eml:internal_hosts": "SAL-NB05.contoso.local, MAIL01.contoso.local",
        "eml:internal_ips": "10.10.3.45, 10.10.1.5",
        "eml:reply-to": "lysenko.serhii@example.net",
        "eml:reply_to_differs": "true",
        "eml:return-path": "<s.lysenko@contoso.example>",
        "eml:organization": "ТОВ «Контосо Енерджі»",
        "eml:dkim_domain": "contoso.example",
        "eml:received.01":
          "from mail.contoso.example (mail.contoso.example [203.0.113.20]) by mx.tender.example (Postfix) with ESMTPS; Tue, 18 Feb 2025 11:20:41 +0000",
        "eml:received.02":
          "from MAIL01.contoso.local (10.10.1.5) by mail.contoso.example (203.0.113.20) with Microsoft SMTP Server id 15.1.2507.39; Tue, 18 Feb 2025 13:20:39 +0200",
        "eml:received.03":
          "from SAL-NB05.contoso.local (10.10.3.45) by MAIL01.contoso.local (10.10.1.5) with Microsoft SMTP Server; Tue, 18 Feb 2025 13:20:37 +0200",
      },
      embedded: [{ name: "Кошторис_ТЕС-2_v2.xlsx", format: "xlsx" }],
      pii: [
        { kind: "phone", sev: "low", count: 1, samples: ["моб. +380 67 ••• •• 31"], location: "тіло листа" },
      ],
    }),
    "Нарада_ТЕС-2_графік.ics": fxRec({
      fields: {
        "ics:method": "REQUEST",
        "ics:x-wr-timezone": "Europe/Kyiv",
        "ics:uid_domains": "contoso.example",
        "ics:meeting_links": "https://teams.microsoft.com/l/meetup-join/19%3ameeting_NjA••••••@thread.v2/0",
        "ics:event.01.summary": "Нарада: графік робіт ТЕС-2",
        "ics:event.01.location": "Microsoft Teams; переговорна 3.12",
        "ics:event.01.organizer": "i.petrenko@contoso.example",
        "ics:event.01.start": "2025-03-04T10:00:00+02:00",
      },
      links: [
        {
          url: "https://teams.microsoft.com/l/meetup-join/19%3ameeting_NjA••••••@thread.v2/0",
          host: "teams.microsoft.com",
          service: "meeting",
          shared: true,
          internal: false,
          expires: null,
          tokens: [],
          sev: "warn",
        },
      ],
    }),
    "Контакти_відділу_продажів.vcf": fxRec({
      fields: {
        "vcf:01.fn": "Сергій Лисенко",
        "vcf:01.org": "ТОВ «Контосо Енерджі»",
        "vcf:01.title": "Менеджер з продажів",
        "vcf:01.tel": "+380 67 ••• •• 31",
        "vcf:02.fn": "Віктор Ткаченко",
        "vcf:02.org": "ТОВ «Контосо Енерджі»",
        "vcf:02.tel": "+380 50 ••• •• 08",
        "vcf:02.bday": "••••-••-14",
        "vcf:02.adr": "м. Кривий Ріг, вул. ••••••••",
      },
      pii: [
        {
          kind: "phone",
          sev: "low",
          count: 2,
          samples: ["+380 67 ••• •• 31", "+380 50 ••• •• 08"],
          location: "vcf",
        },
      ],
    }),
    "IMG_4127.heic": fxRec({
      fields: {
        "media:major_brand": "heic",
        "media:handler": "pict",
        "media:creation_date": "2024-08-02T11:09:31+03:00",
      },
      xmp_ids: { document_id: "8C1F0B5E-2A7D-4E10-9B3C-6D2E8F4A1C07" },
    }),
    "IMG_4131.mp4": fxRec({
      fields: {
        "media:major_brand": "qt  ",
        "media:handler": "vide",
        "media:creation_date": "2024-08-02T11:26:05+03:00",
        "media:com.apple.quicktime.make": "Apple",
        "media:com.apple.quicktime.model": "iPhone 13 Pro",
        "media:com.apple.quicktime.software": "16.6",
        "media:com.apple.quicktime.location.ISO6709": "+47.9214+033.4286+072.312/",
        "media:camera_serial": "F2LX••••Q1PK",
      },
    }),
    "Тендер_ТЕС-2_додатки.zip": fxRec({
      fields: { "zip:unsafe_names": "../../Users/Public/Startup/update.lnk" },
      embedded: [
        { name: "Тендерна_пропозиція.docx", format: "docx" },
        { name: "Кошторис_ТЕС-2.xlsx", format: "xlsx" },
        { name: "Re_Тендер_ТЕС-2_уточнення.eml", format: "eml" },
        { name: "../../Users/Public/Startup/update.lnk", format: "lnk" },
      ],
    }),
  };
  /** Forensic flags of a document (Doc.flags gained "forensic" and "pii" in 1.3). */
  const fxFlags = fx => {
    if (!fx) return [];
    const out = [];
    if (
      fx.signatures.length ||
      fx.bad_redactions.length ||
      fx.hidden_content.length ||
      fx.pdf_revisions.length > 1 ||
      fx.scan_without_text
    )
      out.push("forensic");
    if (fx.pii.some(p => p.kind !== "edrpou")) out.push("pii");
    return out;
  };

  // Compact specifications of small projects (data is generated by the same rules).
  const SMALL = [
    {
      id: "logistics",
      name: "logistics.example",
      client: "ПрАТ «Приклад Логістик»",
      seed: 7101,
      ndocs: 46,
      years: [2019, 2025],
      created_at: "2026-11-05T14:20:00",
      scope: {
        contact: "Роман Литвин, CISO",
        phone: "+380 44 555-01-02",
        basis: "Лист CISO від 02.11.2026",
        targets: [
          { v: "logistics.example", type: "domain" },
          { v: "198.51.100.0/26", type: "cidr" },
        ],
        excl: ["crm.logistics.example"],
      },
      npeople: 6,
      depts: ["log", "buh", "it", "hr", "sales", "log"],
      web: ["logistics.example", "docs.logistics.example"],
      ips: ["198.51.100.10", "198.51.100.12"],
      extra_hosts: [
        {
          name: "crm.logistics.example",
          ip: "198.51.100.20",
          role: "CRM",
          tech: "Bitrix24 (Shodan)",
          source: "crt.sh",
        },
        {
          name: "mail.logistics.example",
          ip: "198.51.100.25",
          role: "Почта",
          tech: "Postfix",
          source: "DNS",
        },
      ],
      tech: ["nginx 1.22.1, 1C-Bitrix", "Apache 2.4.41 (Ubuntu)"],
      sw_allow: ["word2016", "word2019", "excel2016", "ppt2016", "pdflib15", "acro11", "android12", "ios144"],
      gps_places: [
        ["Київ, термінал Борщагівка", 50.43, 30.39],
        ["Бориспіль, склад", 50.35, 30.95],
      ],
      scans: [
        {
          id: "logistics-s1",
          profile_id: "std",
          active: false,
          started_at: "2026-11-12T09:41:00",
          minutes: 21,
          trigger: "manual",
        },
      ],
      dmarc: "none",
      fileserver: "\\\\KT-FS01\\docs",
      printer: "\\\\KT-FS01\\HP M428 Склад",
    },
    {
      id: "medlab",
      name: "clinic.example",
      client: "Мережа клінік «Приклад Мед»",
      seed: 7202,
      ndocs: 71,
      years: [2017, 2025],
      created_at: "2026-10-14T11:00:00",
      scope: {
        contact: "Ірина Поліщук, ІТ",
        phone: "+380 67 000-11-22",
        basis: "",
        targets: [{ v: "clinic.example", type: "domain" }],
        excl: [],
      },
      npeople: 7,
      depts: ["med", "buh", "it", "hr", "mkt", "med", "law"],
      web: ["clinic.example", "lab.clinic.example"],
      ips: ["192.0.2.4", "192.0.2.9"],
      extra_hosts: [
        {
          name: "results.clinic.example",
          ip: "192.0.2.11",
          role: "Портал",
          tech: "Microsoft-IIS/10.0",
          source: "crt.sh",
        },
      ],
      tech: ["nginx 1.14.0, WordPress 5.8", "Microsoft-IIS/10.0"],
      sw_allow: [
        "word2013",
        "word2016",
        "excel2010",
        "excel2016",
        "ppt2016",
        "acro11",
        "pdflib15",
        "canon",
        "ios144",
        "ios166",
        "sony",
      ],
      gps_places: [
        ["Київ, клініка на Подолі", 50.46, 30.51],
        ["Біла Церква, лабораторія", 49.8, 30.12],
        ["Житомир, філія", 50.25, 28.66],
      ],
      scans: [
        {
          id: "medlab-s1",
          profile_id: "std",
          active: false,
          started_at: "2026-10-21T16:02:00",
          minutes: 38,
          trigger: "manual",
        },
      ],
      dmarc: "quarantine",
      fileserver: "\\\\ML-NAS\\shared",
      printer: "\\\\ML-NAS\\Canon MF445 Реєстратура",
    },
    {
      id: "agro",
      name: "agro.example",
      client: "ТОВ «Приклад Агро»",
      seed: 7303,
      ndocs: 14,
      years: [2020, 2025],
      created_at: "2026-10-30T08:30:00",
      scope: {
        contact: "",
        phone: "",
        basis: "",
        targets: [{ v: "agro.example", type: "domain" }],
        excl: [],
      },
      npeople: 3,
      depts: ["buh", "log", "mkt"],
      web: ["agro.example"],
      ips: ["192.0.2.77"],
      extra_hosts: [],
      wayback: true,
      tech: ["Apache 2.4.57"],
      sw_allow: ["word2019", "excel2016", "pdflib15", "android12"],
      gps_places: [["Чернігів, елеватор", 51.49, 31.29]],
      scans: [
        {
          id: "agro-s1",
          profile_id: "passive",
          active: false,
          started_at: "2026-11-02T09:15:00",
          minutes: 7,
          trigger: "manual",
        },
      ],
      dmarc: "reject",
      fileserver: null,
      printer: null,
    },
    {
      id: "dnipro",
      name: "steel.example",
      client: "ПАТ «Приклад Сталь»",
      seed: 7404,
      ndocs: 0,
      years: [2018, 2025],
      created_at: "2026-11-18T17:45:00",
      scope: {
        contact: "",
        phone: "",
        basis: "",
        targets: [{ v: "steel.example", type: "domain" }],
        excl: [],
      },
      npeople: 0,
      depts: [],
      web: [],
      ips: [],
      extra_hosts: [],
      tech: [],
      scans: [],
    },
  ];
  const DEPT = {
    log: { role: "Логістика", exts: ["xlsx", "pdf", "docx", "jpg"], pc: "LOG" },
    buh: { role: "Бухгалтерія", exts: ["xlsx", "xls", "pdf", "docx"], pc: "BUH" },
    it: { role: "ІТ-відділ", exts: ["pdf", "docx", "xlsx"], pc: "IT" },
    hr: { role: "HR", exts: ["docx", "pptx", "pdf"], pc: "HR" },
    sales: { role: "Продажі", exts: ["pdf", "pptx", "docx"], pc: "SAL" },
    med: { role: "Медичний персонал", exts: ["pdf", "docx", "jpg"], pc: "MED" },
    mkt: { role: "Маркетинг", exts: ["pptx", "jpg", "pdf"], pc: "MKT" },
    law: { role: "Юридичний", exts: ["docx", "pdf"], pc: "LAW" },
  };
  const GENERIC_TITLES = {
    pdf: [
      "Прайс-лист",
      "Політика конфіденційності",
      "Річний звіт",
      "Інструкція для клієнтів",
      "Тендерна пропозиція",
      "Сертифікат відповідності",
    ],
    docx: ["Договір про надання послуг", "Наказ", "Службова записка", "Шаблон заяви", "Положення про відділ"],
    xlsx: ["Графік змін", "Реєстр клієнтів", "Звіт по продажах", "Тарифна сітка"],
    xls: ["Бюджет", "Реєстр рахунків"],
    pptx: ["Презентація компанії", "Навчання персоналу"],
    doc: ["Статут"],
    odt: ["Лист"],
    jpg: ["team", "office", "event"],
  };

  // ================= project generator =================
  // File name: "Name.ext"; on collision the document year is appended, then a version.
  const fmtName = (title, ext, used, year, R) => {
    const base = title.replace(/\s+/g, "_");
    const cands = [`${base}.${ext}`];
    if (year && !/\d{4}/.test(base)) cands.push(`${base}_${year}.${ext}`);
    let n = cands.find(c => !used.has(c.toLowerCase()));
    if (!n) {
      const b2 = year && !/\d{4}/.test(base) ? `${base}_${year}` : base;
      let k = 2;
      do {
        n = `${b2}_v${k++}.${ext}`;
      } while (used.has(n.toLowerCase()));
    }
    used.add(n.toLowerCase());
    return n;
  };

  function buildPeople(spec, R) {
    if (spec.people) return spec.people.map((p, i) => ({ ...p, color: COLORS[i % COLORS.length] }));
    const out = [];
    const usedL = new Set();
    for (let i = 0; i < spec.npeople; i++) {
      const dept = spec.depts[i % spec.depts.length];
      let first, last, login;
      do {
        first = R.pick(FIRST);
        last = R.pick(LAST)[0];
        login = translit(first)[0] + "." + translit(last);
      } while (usedL.has(login));
      usedL.add(login);
      out.push({
        login,
        name: `${first} ${last}`,
        role: DEPT[dept].role,
        pc: `${DEPT[dept].pc}-${["PC", "WS", "NB"][i % 3]}${pad(R.int(1, 30))}`,
        dept,
        color: COLORS[(i + 3) % COLORS.length],
      });
    }
    return out;
  }

  // Document: only parsed ones (status analyzed) have metadata. Software matches the extension and year.
  function makeDoc(ctx, o) {
    const { spec, R, used } = ctx;
    const ext = o.ext;
    const status = o.status || "analyzed";
    const web = o.host ? ctx.web.find(w => w.name === o.host) : R.pick(ctx.web);
    const title = o.title || R.pick((spec.titles || GENERIC_TITLES)[ext] || GENERIC_TITLES.pdf);
    // Software and year are chosen before the file name (photo names depend on the camera).
    let year = null,
      sw = null;
    if (status === "analyzed") {
      // A year in the title (e.g. "... 2024") sets the document date.
      const ty = +((title.match(/(20\d\d)/) || [])[1] || 0);
      const tyear = ty ? (/звіт/i.test(title) ? ty + R.int(0, 1) : ty - R.int(0, 1)) : 0;
      year =
        o.year ||
        (tyear
          ? Math.max(spec.years[0], Math.min(spec.years[1], tyear))
          : R.int(spec.years[0], spec.years[1]));
      if (ext !== "rdp" && ext !== "lnk") {
        if (o.sw === null) sw = null;
        else if (o.sw) sw = SW[o.sw];
        else {
          let cand = swFor(ext, year, ctx.swAllow);
          if (!cand.length) cand = swFor(ext, spec.years[1], ctx.swAllow);
          if (!cand.length) cand = swFor(ext, spec.years[1]);
          sw = R.pick(cand);
        }
        if (sw && sw.rel > year)
          year = Math.min(spec.years[1], sw.rel + R.int(0, Math.max(0, spec.years[1] - sw.rel)));
      }
    }
    let name;
    if (o.name) {
      name = o.name;
      used.add(name.toLowerCase());
    } else if (ext === "jpg" && !(sw && sw.kind === "image")) {
      const pre = sw && sw.id === "sony" ? "DSC0" : "IMG_";
      do {
        name = `${pre}${R.int(1000, 9899)}.jpg`;
      } while (used.has(name.toLowerCase()));
      used.add(name.toLowerCase());
    } else
      name = fmtName(
        title,
        ext,
        used,
        year || (R.chance(0.7) ? R.int(spec.years[0], spec.years[1]) : null),
        R,
      );
    const path = web ? R.pick(web.paths) : "/";
    const host = web ? web.name : spec.name;
    let url = `https://${host}${path}${encodeURIComponent(name)}`;
    if (spec.wayback)
      url = `https://web.archive.org/web/2024${pad(R.int(1, 12))}${pad(R.int(1, 28))}000000/${url}`;
    const size = o.size || Math.floor(20 + R.r() * (ext === "pdf" ? 9000 : ext === "jpg" ? 4200 : 2500));
    const d = {
      id: o.id,
      ext,
      name,
      url,
      host,
      status,
      size,
      first_scan: o.first_scan || null,
      deleted: false,
      author: null,
      last_modified_by: null,
      software: null,
      created_at: null,
      modified_at: null,
      folder: null,
      printer: null,
      company: null,
      gps: null,
      camera: null,
      revisions: [],
      rdp: null,
      lnk: null,
      flags: [],
      title,
      thumb_diff: !!o.thumb_diff,
    };
    // Like the core: a document in "error" is a downloaded file that could not be parsed.
    if (status === "error") {
      d.error_kind = "parse";
      d.error_reason = "не удалось разобрать файл: повреждённая структура";
    }
    if (status !== "analyzed") return d;
    // --- metadata (parsed documents only) ---
    const m = o.m || R.int(1, 12),
      day = o.day || R.int(1, 28),
      hh = o.hh ?? R.int(7, 18),
      mm = o.mm ?? R.int(0, 59);
    d.created_at = iso(year, m, day, hh, mm);
    d.software = sw ? sw.id : null;
    // Author: by department; scanners → "scan"; photos do not always have an Artist.
    const pool = ctx.people.filter(
      p => p.dept !== "mfp" && (!ctx.deptExts[p.dept] || ctx.deptExts[p.dept].includes(ext)),
    );
    if (o.author !== undefined) d.author = o.author;
    else if (sw && sw.kind === "scanner")
      d.author = (ctx.people.find(p => p.dept === "mfp") || {}).login || null;
    else if (ext === "jpg")
      d.author = R.chance(sw && sw.kind === "image" ? 0.8 : 0.35)
        ? (R.pick(pool.length ? pool : ctx.people) || {}).login || null
        : null;
    else d.author = (R.pick(pool.length ? pool : ctx.people) || {}).login || null;
    const author = ctx.people.find(p => p.login === d.author);
    if (sw && sw.kind === "office") {
      d.company = spec.client;
      const mod = o.modified_at || addMin(d.created_at, R.int(30, 60 * 24 * 20));
      d.modified_at = mod;
      d.last_modified_by = o.last_modified_by || d.author;
      const fl = author ? ctx.folders[author.dept] || [] : [];
      if (o.folder !== undefined) d.folder = o.folder;
      else if (ext !== "pdf" && fl.length && R.chance(0.5)) {
        const f = R.pick(fl);
        if (!(ctx.folderFrom[f] > year)) d.folder = f;
      }
      if (o.printer !== undefined) d.printer = o.printer;
      else if (ext !== "pdf" && R.chance(0.32)) {
        const pr = ctx.printers.filter(
          p => (!p.depts || (author && p.depts.includes(author.dept))) && (!p.from || p.from <= year),
        );
        if (pr.length) d.printer = R.pick(pr).name;
      }
      if ((ext === "docx" || ext === "doc") && (o.revisions || R.chance(0.22))) {
        d.revisions = o.revisions || [
          {
            kind: "del",
            who: d.author,
            at: addMin(d.created_at, 40),
            text: "Відповідальна особа: тел. 067 *** ** 14",
          },
          {
            kind: "com",
            who: d.last_modified_by,
            at: addMin(d.created_at, 90),
            text: "перевірити перед публікацією",
          },
        ];
      }
    } else if (sw && sw.kind === "pdf") {
      d.modified_at = addMin(d.created_at, R.int(1, 300));
    } else if (sw && (sw.kind === "camera" || sw.kind === "image")) {
      d.camera = sw.dev || null;
      if (sw.kind === "camera" && o.gps !== false && (o.gps || R.chance(sw.id === "sony" ? 0.3 : 0.7))) {
        const pl = o.gps || R.pick(ctx.spec.gps_places || CONTOSO.gps_places);
        const j = ((hash(name) % 200) - 100) / 10000;
        d.gps = { lat: +(pl[1] + j).toFixed(4), lon: +(pl[2] - j).toFixed(4), place: pl[0] };
      }
    } else if (ext === "rdp") {
      d.rdp = o.rdp;
      d.author = o.author ?? null;
    } else if (ext === "lnk") {
      d.lnk = o.lnk;
      d.folder = o.lnk ? o.lnk.target_dir : null;
    }
    return d;
  }

  function deriveFlags(st) {
    const secretDocs = new Set(st.secrets.map(s => s.doc));
    st.docs.forEach(d => {
      const f = [];
      if (d.status === "analyzed") {
        if (d.folder && /^(\\\\|[A-Z]:\\|\/Users\/)/.test(d.folder)) f.push("path");
        if (secretDocs.has(d.id)) f.push("secret");
        if (d.software && swEol(SW[d.software])) f.push("eol");
        if (d.gps) f.push("gps");
        if (d.revisions && d.revisions.length) f.push("revisions");
        f.push(...fxFlags(CONTOSO_FX[d.name]));
      }
      d.flags = f;
    });
  }

  // Derived entities: people/PCs/software/paths/printers are inferred from metadata.
  function deriveEntities(st, spec) {
    const an = st.docs.filter(d => d.status === "analyzed" && !d.deleted);
    const authors = countBy(an, d => d.author);
    const textPeople = spec.text_people || st.text_people || [];
    st.people = st.all_people
      .filter(p => authors.has(p.login))
      .map(p => ({
        login: p.login,
        name: p.name,
        role: p.role,
        pc: p.pc || null,
        color: p.color,
        src: "Метаданные документов",
        src_kind: "meta",
        docs: authors.get(p.login),
      }));
    textPeople.forEach((p, i) => {
      const doc = an.find(d => d.ext === p.ext && d.author !== p.login);
      if (!doc) return;
      st.people.push({
        login: p.login,
        name: p.name,
        role: p.role,
        pc: null,
        color: COLORS[(9 + i) % COLORS.length],
        src: p.src,
        src_kind: "text",
        docs: 0,
        src_doc: doc.id,
      });
    });
    const swc = countBy(an, d => d.software);
    st.software = SOFTWARE.filter(s => swc.has(s.id)).map(s => ({
      id: s.id,
      name: s.name,
      ver: s.ver,
      kind: s.kind,
      released: s.rel,
      eol_date: s.eol_date,
      eol: swEol(s),
      cve: s.cve,
      cves: s.cves,
      dev: s.dev || null,
      docs: swc.get(s.id),
    }));
    const fc = countBy(an, d => d.folder);
    st.paths = [...fc.entries()]
      .sort((a, b) => b[1] - a[1])
      .map(([path, n]) => {
        const u = (path.match(/Users[\\/]+([^\\/]+)/) || [])[1];
        const login = u
          ? u === "Administrator"
            ? "admin"
            : (st.people.find(p => p.login === u || p.login.replace(".", "") === u.replace(".", "")) || {})
                .login || null
          : null;
        const host = (path.match(/^\\\\([^\\]+)/) || [])[1] || null;
        return { path, docs: n, user: login, host };
      });
    const pc = countBy(an, d => d.printer);
    st.printers = [...pc.entries()]
      .sort((a, b) => b[1] - a[1])
      .map(([name, n]) => ({ name, docs: n, host: (name.match(/^\\\\([^\\]+)/) || [])[1] || null }));
    // PCs: authors' workstations plus servers from paths, printers, .rdp files, secrets and findings.
    const pcs = new Map();
    const addPc = (name, kind, extra = {}) => {
      if (!name) return;
      const x = pcs.get(name) || { name, kind, users: [], ip: null, source: extra.source || "" };
      Object.assign(x, Object.fromEntries(Object.entries(extra).filter(([, v]) => v != null && v !== "")));
      pcs.set(name, x);
      return x;
    };
    st.people
      .filter(p => p.pc)
      .forEach(p => {
        const x = addPc(p.pc, /^SRV|MFP/.test(p.pc) ? "server" : "ws", { source: "Метаданные документов" });
        x.users.push(p.login);
      });
    st.paths.forEach(p => p.host && addPc(p.host, "server", { source: "Пути в метаданных" }));
    st.printers.forEach(p => p.host && addPc(p.host, "server", { source: "Принтеры в метаданных" }));
    an.filter(d => d.rdp).forEach(d =>
      addPc(d.rdp.gateway, "server", { ip: d.rdp.full_address, source: ".rdp-файл" }),
    );
    an.filter(d => d.lnk).forEach(d => addPc(d.lnk.machine, "ws", { source: ".lnk-ярлык" }));
    (st.extra_pcs || []).forEach(p => addPc(p.name, p.kind, p));
    st.pcs = [...pcs.values()].map(p => ({
      ...p,
      docs: an.filter(d => {
        const a = st.people.find(x => x.login === d.author);
        return (
          (a && a.pc === p.name) ||
          (d.folder || "").includes(p.name) ||
          (d.printer || "").includes(p.name) ||
          (d.rdp && d.rdp.gateway === p.name) ||
          (d.lnk && d.lnk.machine === p.name)
        );
      }).length,
    }));
    // GPS only for photos with coordinates.
    st.gps = an
      .filter(d => d.gps)
      .map(d => ({
        doc: d.id,
        name: d.name,
        lat: d.gps.lat,
        lon: d.gps.lon,
        place: d.gps.place,
        dev: d.camera || (SW[d.software] || {}).dev || "-",
        taken_at: d.created_at,
      }));
  }

  function deriveEmails(st, spec) {
    const dom = spec.domain || spec.name;
    const found = st.email_found || {};
    const out = st.people
      .filter(p => p.login.includes("."))
      .map(p => ({
        addr: `${p.login}@${dom}`,
        login: p.login,
        name: p.name,
        found: !!found[p.login],
        src: found[p.login] || "Шаблон {f}.{last} (85%)",
        role: false,
      }));
    out.sort((a, b) => b.found - a.found || a.addr.localeCompare(b.addr));
    (st.role_mails || []).forEach(([addr, src]) =>
      out.push({ addr, login: null, name: null, found: true, src, role: true }),
    );
    st.emails = out;
    const nf = out.filter(e => e.found && !e.role).length;
    st.patterns = nf
      ? [
          { p: "{и}.{фамилия}", ex: (out[0] || {}).login || "", conf: 100, n: nf },
          { p: "{имя}.{фамилия}", ex: "", conf: 0, n: 0 },
          { p: "{и}{фамилия}", ex: "", conf: 0, n: 0 },
        ]
      : [];
  }

  function deriveHosts(st, spec) {
    const ext = (spec.hosts || []).map(h => ({ ...h }));
    const internal = [];
    const addInt = (name, ip, role, tech, source) => {
      if (!internal.some(h => h.name === name))
        internal.push({
          name,
          ip: ip || "-",
          role,
          tech: tech || "-",
          cloud: "-",
          services: [],
          source,
          internal: true,
        });
    };
    st.pcs
      .filter(p => p.kind === "server")
      .forEach(p => {
        const role =
          p.source === ".rdp-файл"
            ? "Терминальный"
            : p.source === "Принтеры в метаданных"
              ? "Принт-сервер"
              : /NAS/.test(p.name)
                ? "Хранилище"
                : /SQL/.test(p.name)
                  ? "СУБД"
                  : /MFP/.test(p.name)
                    ? "МФУ"
                    : "Файловый (внутр.)";
        if (p.users.length && !/^SRV|^MFP/.test(p.name)) return;
        if (/^MFP|^MAIL/.test(p.name)) return;
        addInt(
          p.name,
          p.ip,
          role,
          p.source === ".rdp-файл" ? "RDP" : /SRV-FILE/.test(p.name) ? "Windows Server" : "-",
          p.source,
        );
      });
    st.hosts = [...ext, ...internal];
  }

  // ---------------- findings ----------------
  const findTpl = (st, o) => ({
    id: o.id,
    title: o.title,
    sev: o.sev,
    status: o.status || "new",
    host: o.host || "-",
    category: o.cat,
    source: o.source,
    module: o.module || null,
    active: !!o.active,
    time: o.time,
    first_scan: o.first_scan,
    tags: o.tags || [],
    cve: o.cve || [],
    cvss: o.cvss ?? null,
    mitre: o.mitre || "",
    description: o.description,
    recommendation: o.recommendation,
    evidence: o.evidence || "",
    request: o.request || "",
    url: o.url || null,
    doc: o.doc || null,
    fixed_scan: o.fixed_scan || null,
    notes: o.notes || [],
    photos: o.photos || [],
    rel: {
      people: (o.rel && o.rel.people) || [],
      pcs: (o.rel && o.rel.pcs) || [],
      docs: o.doc ? [o.doc] : [],
    },
    // Infrastructure findings carry the core rule id (provenance.rule = "infra.<code>").
    ...(o.rule ? { provenance: { rule: o.rule, fields: [], docs: [] } } : {}),
  });
  const docById = (st, id) => st.docs.find(d => d.id === id);
  const topAuthors = (docs, n) =>
    [...countBy(docs, d => d.author).entries()]
      .sort((a, b) => b[1] - a[1])
      .slice(0, n)
      .map(x => x[0]);

  function contosoFindings(st) {
    const S0 = "{{s:",
      S1 = "}}";
    const an = st.docs.filter(d => d.status === "analyzed");
    const s1 = "contoso-s1",
      s2 = "contoso-s2";
    const acro = an.filter(d => d.software === "acro11");
    const acroDoc = acro.find(d => d.id > 8) || acro[0];
    const pathDocs = an.filter(d => d.flags.includes("path"));
    const pathDoc = docById(st, 9);
    const topFold = st.paths.slice(0, 4).map(p => p.path);
    const pcOf = l => (st.people.find(p => p.login === l) || {}).pc;
    const foundMail = st.emails.filter(e => e.found && !e.role);
    const zone = st.hosts.filter(h => !h.internal && h.name.endsWith(".contoso.example"));
    const D3 = docById(st, 3),
      D5 = docById(st, 5),
      D2 = docById(st, 2),
      D1 = docById(st, 1);
    const L = [
      {
        title: "Exchange 2016 CU12: ProxyShell (CVE-2021-34473)",
        sev: "crit",
        status: "confirmed",
        host: "mail.contoso.example",
        cat: "sw",
        source: "Shodan (кэш баннеров)",
        module: "shodan",
        time: "2026-11-12T10:12:00",
        first_scan: s1,
        cve: ["CVE-2021-34473", "CVE-2021-34523", "CVE-2021-31207"],
        cvss: 9.8,
        mitre: "T1190 · Exploit Public-Facing Application",
        description:
          "По кэшу баннеров Shodan сервер Microsoft Exchange 2016 CU12 (15.1.1713.5) отвечает на /owa и /autodiscover. Сборка уязвима к цепочке ProxyShell: обход аутентификации, повышение привилегий и запись произвольного файла. Хост в исключениях скоупа: к нему не обращались, версия взята только из внешнего кэша.",
        recommendation:
          "Срочно установить последний CU и Security Update для Exchange 2016, проверить каталоги aspnet_client и FrontEnd на веб-шеллы, ограничить доступ к /autodiscover и /mapi с внешних адресов.",
        evidence:
          "Shodan · 203.0.113.20:443 · снимок 2026-11-08\nHTTP/1.1 200 OK\nServer: Microsoft-IIS/8.5\nX-OWA-Version: 15.1.1713.5\nX-FEServer: MAIL01",
        url: "https://www.shodan.io/host/203.0.113.20",
        rel: { pcs: ["MAIL01"] },
        notes: [
          {
            text: "Хост у винятках скоупу: дані лише з кешу Shodan, до сервера не зверталися. Експлуатацію не проводили.",
            who: "Вы",
            time: "19.11, 22:10",
          },
        ],
        tags: ["внешний периметр", "RCE", "out_of_scope"],
      },
      {
        title: "Висящий CNAME → возможен subdomain takeover",
        sev: "crit",
        host: "old.contoso.example",
        cat: "dns",
        source: "DNS",
        module: "dns",
        time: "2026-11-12T10:08:00",
        first_scan: s1,
        cvss: 8.2,
        mitre: "T1584.001 · Compromise Infrastructure: Domains",
        description:
          "Поддомен указывает CNAME на ресурс Azure App Service, который больше не существует. Любой пользователь Azure может зарегистрировать это имя и раздавать контент от имени домена компании.",
        recommendation:
          "Удалить запись CNAME old.contoso.example или повторно занять имя contoso-example.azurewebsites.net за компанией. Провести инвентаризацию всех CNAME на облачные сервисы.",
        evidence:
          "$ dig +short CNAME old.contoso.example\ncontoso-example.azurewebsites.net.\n$ dig +short contoso-example.azurewebsites.net\n;; ->>HEADER<<- status: NXDOMAIN",
        url: "dns://old.contoso.example",
        tags: ["takeover"],
      },
      {
        title: "Jenkins 2.263 доступен из интернета без авторизации",
        sev: "crit",
        host: "dev.contoso.example",
        cat: "web",
        source: "Shodan InternetDB",
        module: "internetdb",
        active: false,
        time: "2026-11-19T20:58:00",
        first_scan: s2,
        cve: ["CVE-2024-23897"],
        cvss: 9.8,
        mitre: "T1190 · Exploit Public-Facing Application",
        description:
          "Тестовый Jenkins 2.263 в AWS доступен из интернета, анонимный пользователь имеет права на чтение заданий и консоль сценариев.",
        recommendation:
          "Закрыть доступ к Jenkins из интернета (VPN или IP-allowlist), отключить анонимный доступ, обновить до актуальной LTS, сменить все секреты из заданий сборки.",
        evidence:
          "GET /script HTTP/1.1\nHost: dev.contoso.example\n\nHTTP/1.1 200 OK\nX-Jenkins: 2.263\n<title>Script Console [Jenkins]</title>",
        request: "GET https://dev.contoso.example/script",
        url: "https://dev.contoso.example/script",
        rel: { people: ["i.petrenko"] },
      },
      {
        title: "Пароль в тексте документа (connection string)",
        sev: "crit",
        host: D1.host,
        cat: "docs",
        source: "Секреты в документах",
        module: "secrets",
        time: "2026-11-19T21:12:00",
        first_scan: s2,
        cvss: 9.1,
        mitre: "T1552.001 · Unsecured Credentials: Credentials In Files",
        doc: 1,
        description:
          "В тексте публично доступного договора найдена строка подключения к MS SQL с учётной записью sa и паролем в открытом виде. Сервер SRV-SQL02 есть в зоне DNS (AXFR) как внутренний.",
        recommendation:
          "Немедленно сменить пароль учётной записи sa, отключить её для удалённых подключений, удалить документ с сайта и из кэша поисковиков, проверить журналы входа SQL.",
        evidence:
          "стр. 14, Приложение 3 «Интеграція»:\nData Source=SRV-SQL02;Initial Catalog=Billing;\nUser ID=sa;Password=" +
          S0 +
          "Kont0so#2024!" +
          S1 +
          ";",
        rel: { people: [D1.author], pcs: [pcOf(D1.author), "SRV-SQL02"] },
        photos: [{ name: "IMG_20261119_2130.jpg", time: "19.11, 21:30", from: "галерея" }],
        tags: ["пароль", "в отчёт"],
      },
      {
        title: "Открытый листинг каталога: /upload/docs/",
        sev: "warn",
        host: "contoso.example",
        cat: "web",
        source: "Поиск на сайте",
        module: "fuzz",
        active: true,
        time: "2026-11-19T20:33:00",
        first_scan: s2,
        cvss: 5.3,
        mitre: "T1083 · File and Directory Discovery",
        description:
          "Веб-сервер nginx отдаёт автолистинг каталога /upload/docs/: видны имена и даты всех загруженных файлов, включая не опубликованные на сайте.",
        recommendation:
          "Отключить autoindex в конфигурации nginx для каталогов загрузок, перенести служебные файлы из публичного каталога.",
        evidence:
          "GET /upload/docs/ HTTP/1.1\n\nHTTP/1.1 200 OK\nServer: nginx/1.18.0\n<h1>Index of /upload/docs/</h1>",
        url: "https://contoso.example/upload/docs/",
      },
      {
        title: "Резервная копия файла на сайте: /web.config.bak",
        sev: "warn",
        host: "portal.contoso.example",
        cat: "web",
        source: "Поиск на сайте",
        module: "fuzz",
        active: true,
        time: "2026-11-19T20:49:00",
        first_scan: s2,
        cvss: 5.3,
        mitre: "T1083 · File and Directory Discovery",
        description:
          "Рядом с рабочим файлом лежит его старая или резервная копия; в копиях конфигурации часто видны пароли и внутренние адреса.\n\nАдрес: https://portal.contoso.example/web.config.bak\nОтвет: HTTP 200, 3 412 байт, application/octet-stream.",
        recommendation:
          "Удалить резервную копию и запретить отдачу файлов *.bak, *~, *.old, *.orig, *.swp на веб-сервере.",
        evidence:
          '<connectionStrings>\n  <add name="Portal" connectionString="Server=SRV-SQL02;User Id=portal;Password=***" />',
        url: "https://portal.contoso.example/web.config.bak",
      },
      {
        title: "DMARC p=none: подделка писем от домена возможна",
        sev: "warn",
        status: "confirmed",
        host: "contoso.example",
        cat: "mail",
        source: "SPF/DMARC",
        module: "dns",
        time: "2026-11-12T10:06:00",
        first_scan: s1,
        cvss: 5.8,
        mitre: "T1566 · Phishing",
        description:
          "Политика DMARC установлена в режим мониторинга (p=none). Письма, подделывающие отправителя @contoso.example, не будут отклонены получателями.",
        recommendation:
          "После анализа отчётов rua перевести политику в p=quarantine, затем в p=reject; добавить pct=100 и выравнивание adkim=s.",
        evidence: '_dmarc.contoso.example. 3600 IN TXT\n"v=DMARC1; p=none; rua=mailto:dmarc@contoso.example"',
        url: "dns://_dmarc.contoso.example",
        tags: ["почта"],
      },
      {
        title: `Adobe Acrobat XI (EOL) у ${acro.length} документов, 37 CVE`,
        sev: "warn",
        status: "accepted",
        host: "-",
        cat: "sw",
        source: "ПО → CVE",
        module: "analysis",
        time: "2026-11-12T10:24:00",
        first_scan: s1,
        cve: ["CVE-2018-4990", "CVE-2019-7089", "CVE-2020-3803"],
        cvss: 7.8,
        mitre: "T1203 · Exploitation for Client Execution",
        doc: acroDoc.id,
        description: `${acro.length} опубликованных PDF созданы в Adobe Acrobat Pro XI 11.0.23, поддержка которого завершена в 2017 году. Это указывает на рабочие станции с уязвимым ПО, пригодные для фишинга с вредоносными PDF.`,
        recommendation:
          "Обновить Acrobat до поддерживаемой версии или заменить, централизованно контролировать версии офисного ПО.",
        evidence: `Creator: Adobe Acrobat Pro 11.0.23\nProducer: Adobe Acrobat Pro 11.0.23\nДокументов: ${acro.length} · авторов: ${uniq(acro.map(d => d.author).filter(Boolean)).length}`,
        rel: { people: topAuthors(acro, 2), pcs: topAuthors(acro, 2).map(pcOf).filter(Boolean) },
        notes: [
          {
            text: "Заказчик планирует замену в Q1 2027, риск принят письмом от 18.11.",
            who: "Вы",
            time: "19.11, 23:02",
          },
        ],
      },
      {
        title: "Открытый репозиторий .git: /.git/HEAD",
        sev: "crit",
        host: "files.contoso.example",
        cat: "web",
        source: "Поиск на сайте",
        module: "fuzz",
        active: true,
        time: "2026-11-19T20:37:00",
        first_scan: s2,
        cvss: 7.5,
        mitre: "T1213 · Data from Information Repositories",
        description:
          "Каталог .git доступен по HTTP. Из него можно восстановить исходный код сайта и историю коммитов, в которой часто остаются ключи и пароли.",
        recommendation:
          "Запретить доступ к /.git на веб-сервере, удалить каталог из публичной директории, проверить историю репозитория на секреты и сменить их.",
        evidence:
          "GET /.git/HEAD HTTP/1.1\n\nHTTP/1.1 200 OK\nContent-Type: text/plain\n\nref: refs/heads/master",
        request: "GET https://files.contoso.example/.git/HEAD",
        url: "https://files.contoso.example/.git/HEAD",
      },
      {
        title: "Apache 2.4.29 устарел (2017), 19 CVE",
        sev: "warn",
        host: "files.contoso.example",
        cat: "sw",
        source: "Отпечаток ПО",
        module: "download",
        time: "2026-11-12T10:15:00",
        first_scan: s1,
        cve: ["CVE-2019-0211", "CVE-2021-44790", "CVE-2022-22720"],
        cvss: 9.8,
        mitre: "T1190 · Exploit Public-Facing Application",
        description:
          "Заголовок Server при скачивании документов раскрывает Apache 2.4.29 (Ubuntu 18.04), выпущенный в 2017 году. Для версии известно 19 CVE.",
        recommendation:
          "Обновить Apache через пакеты дистрибутива, скрыть версию (ServerTokens Prod, ServerSignature Off).",
        evidence: "HTTP/1.1 200 OK\nServer: Apache/2.4.29 (Ubuntu)",
        url: "https://files.contoso.example/",
      },
      {
        title: "Ключ доступа AWS в комментарии таблицы",
        sev: "crit",
        host: D3.host,
        cat: "docs",
        source: "Секреты в документах",
        module: "secrets",
        time: "2026-11-12T10:21:00",
        first_scan: s1,
        cvss: 9.0,
        mitre: "T1552.001 · Credentials In Files",
        doc: 3,
        description:
          "В примечании к ячейке опубликованной таблицы найдена пара ключей AWS IAM. Ключ относится к аккаунту, где размещён dev.contoso.example.",
        recommendation:
          "Деактивировать ключ в IAM, проверить CloudTrail на использование, удалить файл с сайта.",
        evidence:
          "Лист «Обладнання», ячейка H17, примечание:\naws_access_key_id = «redacted:AKIA…»\naws_secret_access_key = " +
          S0 +
          "wJx9Fq2+Lr8kZ0aT3vYpQe7mNc5bHs1uKd4oGi6E" +
          S1,
        rel: { people: [D3.author], pcs: [pcOf(D3.author)] },
        tags: ["облако"],
      },
      {
        title: `Внутренние пути и логины в метаданных ${pathDocs.length} документов`,
        sev: "low",
        host: pathDoc.host,
        cat: "docs",
        source: "Метаданные",
        module: "meta",
        time: "2026-11-12T10:19:00",
        first_scan: s1,
        cvss: 3.7,
        mitre: "T1592 · Gather Victim Host Information",
        doc: pathDoc.id,
        description: `Поля Author, LastModifiedBy и пути шаблонов в ${pathDocs.length} документах раскрывают логины сотрудников и структуру файловых ресурсов (\\\\SRV-FILE01\\buh$).`,
        recommendation:
          "Очищать метаданные перед публикацией (Инспектор документов, exiftool), внедрить проверку в процесс публикации.",
        evidence: topFold.join("\n"),
        rel: {
          people: topAuthors(pathDocs, 3),
          pcs: uniq(st.paths.map(p => p.host).filter(Boolean)).slice(0, 2),
        },
      },
      {
        title: "Имена внутренних серверов раскрыты в .rdp-файле",
        sev: "low",
        host: D5.host,
        cat: "docs",
        source: "Метаданные",
        module: "meta",
        time: "2026-11-12T10:19:30",
        first_scan: s1,
        cvss: 4.3,
        mitre: "T1590.002 · Gather Victim Network Information: DNS",
        doc: 5,
        description:
          "Опубликованный файл подключения к удалённому рабочему столу содержит адрес терминального сервера и имя пользователя по умолчанию.",
        recommendation: "Удалить файл с сайта, не публиковать служебные файлы конфигурации.",
        evidence: `full address:s:${D5.rdp.full_address}\nusername:s:${D5.rdp.username}\ngatewayhostname:s:${D5.rdp.gateway}`,
        rel: { pcs: [D5.rdp.gateway], people: [D5.author] },
      },
      {
        title: "GPS-координаты промышленного объекта в фото",
        sev: "high",
        host: D2.host,
        cat: "docs",
        source: "EXIF",
        module: "meta",
        time: "2026-11-12T10:20:00",
        first_scan: s1,
        cvss: 6.5,
        mitre: "T1591.001 · Gather Victim Org Information: Physical Locations",
        doc: 2,
        description: `Фото со стройки ТЕС-2 содержит точные координаты съёмки и модель телефона (${D2.camera}). Это раскрывает расположение режимного объекта.`,
        recommendation:
          "Удалять EXIF перед публикацией, настроить CMS на автоматическую очистку метаданных изображений.",
        evidence: `GPSLatitude: ${D2.gps.lat}\nGPSLongitude: ${D2.gps.lon}\nModel: ${D2.camera} · ${SW[D2.software].name}\nDateTimeOriginal: ${D2.created_at.replace("T", " ").replace(/-/g, ":")}\nArtist: ${D2.author}`,
        rel: { people: [D2.author] },
      },
      {
        title: "Исправления в docx: удалённые суммы договора",
        sev: "warn",
        host: D1.host,
        cat: "docs",
        source: "Метаданные",
        module: "meta",
        time: "2026-11-19T21:13:00",
        first_scan: s2,
        cvss: 4.3,
        mitre: "T1213 · Data from Information Repositories",
        doc: 1,
        description:
          "В документе сохранены режим рецензирования и удалённые фрагменты: прежняя цена договора и комментарии юристов.",
        recommendation:
          "Принимать все исправления и удалять комментарии перед публикацией; использовать PDF для внешних документов.",
        evidence: `w:del автор ${D1.revisions[0].who}, ${D1.revisions[0].at.slice(8, 10)}.${D1.revisions[0].at.slice(5, 7)}.${D1.revisions[0].at.slice(0, 4)}:\n«${D1.revisions[0].text}»\nКомментарий: «${D1.revisions[2].text}»`,
        rel: { people: uniq(D1.revisions.map(r => r.who)) },
      },
      {
        title: "SPF с мягкой политикой ~all",
        sev: "low",
        host: "contoso.example",
        cat: "mail",
        source: "SPF/DMARC",
        module: "dns",
        time: "2026-11-12T10:06:30",
        first_scan: s1,
        cvss: 3.1,
        mitre: "T1566 · Phishing",
        description:
          "SPF заканчивается на ~all (softfail), поэтому письма с посторонних серверов только помечаются, но не отклоняются.",
        recommendation: "После инвентаризации отправителей заменить ~all на -all.",
        evidence:
          'contoso.example. IN TXT\n"v=spf1 ip4:203.0.113.0/24 include:spf.protection.outlook.com ~all"',
        url: "dns://contoso.example",
      },
      {
        title: "DNSSEC не настроен для зоны",
        sev: "info",
        host: "contoso.example",
        cat: "dns",
        source: "DNS",
        module: "dns",
        time: "2026-11-12T10:05:00",
        first_scan: s1,
        description: "Для зоны contoso.example нет записей DS и DNSKEY. Ответы DNS не подписаны.",
        recommendation: "Рассмотреть включение DNSSEC у регистратора и на авторитетных серверах.",
        evidence: "$ dig +short DS contoso.example\n(пусто)",
        url: "dns://contoso.example",
      },
      {
        title: "Разрешён трансфер зоны (AXFR) на ns2",
        sev: "high",
        status: "confirmed",
        host: "ns2.contoso.example",
        cat: "dns",
        source: "DNS (AXFR)",
        module: "axfr",
        active: true,
        time: "2026-11-19T20:15:00",
        first_scan: s2,
        cvss: 5.3,
        mitre: "T1590.002 · DNS",
        description: `Вторичный DNS-сервер отдаёт полную копию зоны любому запросившему: ${zone.length + 6} записей, включая внутренний SRV-SQL02.`,
        recommendation:
          "Ограничить AXFR только адресами первичного сервера (allow-transfer) и использовать TSIG.",
        evidence: `$ dig axfr contoso.example @ns2.contoso.example\nvpn   A 203.0.113.30\ndev   A 198.51.100.144\nsql02 A 10.10.1.12\n;; XFR size: ${zone.length + 6} records`,
        url: "dns://ns2.contoso.example",
        rel: { pcs: ["SRV-SQL02"] },
      },
      {
        title: "FortiGate SSL-VPN: версия уязвима к CVE-2023-27997",
        sev: "high",
        host: "vpn.contoso.example",
        cat: "sw",
        source: "Отпечаток ПО (Shodan InternetDB)",
        module: "internetdb",
        active: false,
        time: "2026-11-19T20:52:00",
        first_scan: s2,
        cve: ["CVE-2023-27997", "CVE-2022-42475"],
        cvss: 9.8,
        mitre: "T1133 · External Remote Services",
        description:
          "По хешу статических ресурсов страницы входа определена сборка FortiOS 7.0.9. Для неё известно переполнение кучи до аутентификации (XORtigate).",
        recommendation:
          "Обновить FortiOS до 7.0.12 или новее, проверить журналы на индикаторы компрометации.",
        evidence:
          'GET /remote/login HTTP/1.1\n\nHTTP/1.1 200 OK\nSet-Cookie: ***;\nETag: "5ba1-6447a2d1" → FortiOS 7.0.9',
        request: "GET https://vpn.contoso.example/remote/login",
        url: "https://vpn.contoso.example/remote/login",
      },
      {
        title: "WordPress 6.2 и плагины устарели",
        sev: "warn",
        host: "contoso.example",
        cat: "web",
        source: "Отпечаток ПО",
        module: "download",
        time: "2026-11-12T10:11:00",
        first_scan: s1,
        cve: ["CVE-2023-38000"],
        cvss: 6.1,
        mitre: "T1190 · Exploit Public-Facing Application",
        description:
          "Сайт работает на WordPress 6.2 с плагинами Contact Form 7 5.6 и Elementor 3.11. Известны XSS и раскрытие информации.",
        recommendation: "Обновить ядро и плагины, включить автообновления безопасности.",
        evidence:
          '<meta name="generator" content="WordPress 6.2">\n/wp-content/plugins/contact-form-7/ ver=5.6\n/wp-content/plugins/elementor/ ver=3.11.2',
        url: "https://contoso.example/",
      },
      {
        title: "Определён шаблон корпоративных e-mail: i.surname@contoso.example",
        sev: "info",
        host: "contoso.example",
        cat: "people",
        source: "Люди и e-mail",
        module: "analysis",
        time: "2026-11-12T10:25:00",
        first_scan: s1,
        description: `По ${foundMail.length} адресам из документов и открытых источников определён шаблон i.surname@contoso.example. Это упрощает подготовку целевого фишинга.`,
        recommendation:
          "Учесть в программе обучения сотрудников; включить DMARC p=reject и защиту от спуфинга во внешнем шлюзе.",
        evidence: foundMail
          .slice(0, 5)
          .map(e => e.addr + "  - " + e.src)
          .join("\n"),
        rel: { people: foundMail.slice(0, 4).map(e => e.login) },
      },
      {
        title: "Адрес сотрудника найден в утечке паролей",
        sev: "high",
        status: "false",
        host: "-",
        cat: "people",
        source: "Утечки (HIBP)",
        module: "hibp",
        time: "2026-11-12T10:26:00",
        first_scan: s1,
        cvss: 0,
        mitre: "T1589.001 · Gather Victim Identity Information: Credentials",
        description: "Адрес o.kovalenko@contoso.example присутствует в сборнике утечек Collection #1 (2019).",
        recommendation: "Проверить, что пароль сменён и включена двухфакторная аутентификация.",
        evidence:
          "Источник: Have I Been Pwned · Collection #1 (2019)\nE-mail: o.kovalenko@contoso.example\nПароль: " +
          S0 +
          "Olena1985" +
          S1,
        rel: { people: ["o.kovalenko"], pcs: [pcOf("o.kovalenko")] },
        notes: [
          {
            text: "ИТ подтвердило: пароль сменён в 2021, включена 2FA. Ложная.",
            who: "Вы",
            time: "20.11, 09:40",
          },
        ],
      },
      {
        title: "Cookie без флагов Secure и HttpOnly, нет HSTS",
        sev: "low",
        status: "fixed",
        host: "portal.contoso.example",
        cat: "web",
        source: "HTTP-заголовки",
        module: "download",
        time: "2026-11-12T10:14:00",
        first_scan: s1,
        cvss: 4.3,
        mitre: "T1539 · Steal Web Session Cookie",
        description:
          "Сессионная cookie ASP.NET_SessionId выдавалась без Secure/HttpOnly, заголовок Strict-Transport-Security отсутствовал. При скане 19.11 не воспроизводится.",
        recommendation:
          "Включить requireSSL и httpOnlyCookies в web.config, добавить HSTS с max-age не менее 6 месяцев.",
        evidence: "Set-Cookie: ***\n(Strict-Transport-Security отсутствует)",
        url: "https://portal.contoso.example/",
        fixed_scan: s2,
      },
      {
        title: "Включён TLS 1.0 на портале",
        sev: "low",
        status: "false",
        host: "portal.contoso.example",
        cat: "web",
        source: "Shodan InternetDB (баннер TLS)",
        module: "internetdb",
        active: false,
        time: "2026-11-19T21:01:00",
        first_scan: s2,
        cvss: 3.7,
        mitre: "T1557 · Adversary-in-the-Middle",
        description: "Сканер сообщил о поддержке TLS 1.0 на порту 443.",
        recommendation: "Отключить TLS 1.0/1.1 в SCHANNEL.",
        evidence: "443/tcp  TLSv1.0: offered (?)\nПовторная проверка: handshake failure",
        url: "https://portal.contoso.example/",
      },
      {
        title: "TLS-сертификат на cdn.contoso.example:443 скоро истекает",
        sev: "info",
        host: "cdn.contoso.example",
        cat: "tls",
        source: "TLS/X.509",
        module: "tls",
        rule: "infra.cert_expires_soon",
        time: "2026-11-12T10:07:00",
        first_scan: s1,
        description: "Сертификат для cdn.contoso.example действителен до 29.11.2026.",
        recommendation: "Проверить автопродление сертификата.",
        evidence:
          "Subject: CN=cdn.contoso.example\nIssuer: Cloudflare Inc ECC CA-3\nNot After: 2026-11-29 23:59:59 UTC",
        url: "https://cdn.contoso.example/",
      },
      // Infrastructure modules: host roles and the Microsoft 365 tenant.
      {
        title: "Доступен служебный хост: staging.contoso.example",
        sev: "warn",
        host: "staging.contoso.example",
        cat: "hosts",
        source: "Роли хостов",
        module: "roles",
        rule: "infra.host_role_exposed",
        tags: ["role:dev_stage"],
        time: "2026-11-12T10:09:00",
        first_scan: s1,
        description:
          "Обнаружено при проверке staging.contoso.example: имя найдено перебором поддоменов, хост отвечает на 443/tcp; роль: тестовая среда.",
        recommendation:
          "Закрыть тестовые и служебные хосты от интернета (VPN, белый список адресов) или убрать их из публичного DNS.",
        evidence: "staging.contoso.example → 203.0.113.41\n443/tcp открыт",
        url: "https://staging.contoso.example/",
      },
      {
        title: "Арендатор Microsoft 365 с федерацией AD FS: sts.contoso.example",
        sev: "info",
        host: "contoso.example",
        cat: "cloud",
        source: "Microsoft 365",
        module: "m365",
        rule: "infra.m365_federated_adfs",
        time: "2026-11-12T10:05:00",
        first_scan: s1,
        description:
          "Обнаружено при проверке contoso.example: вход в Microsoft 365 перенаправляется на AD FS организации (getuserrealm.srf: Federated).",
        recommendation:
          "Убедиться, что AD FS обновлён и закрыт от перебора паролей (Extranet Smart Lockout), и что страница входа не раскрывает лишнего.",
        evidence: `NameSpaceType: Federated\nAuthURL: https://sts.contoso.example/adfs/ls/\ntenant_id: ${tenantId("contoso.example")}`,
        url: "https://login.microsoftonline.com/getuserrealm.srf?login=user@contoso.example",
      },
      ...contosoFxFindings(st, s1),
      ...contosoInsightFindings(st, s1),
    ];
    return L.map((o, i) => findTpl(st, { ...o, id: i + 1 }));
  }

  // Insight findings (rules sw.kev, doc.anomaly.*, doc.lineage, org.structure, net.internal_map,
  // recon.web.*), consistent with insights_get and recon.web[] of the same project.
  function contosoInsightFindings(st, scan) {
    const dom = "contoso.example";
    const sw = id => (st.software || []).find(s => s.id === id);
    const base = o => ({ time: "2026-11-12T10:24:00", first_scan: scan, host: "-", ...o });
    const out = [];
    const w13 = sw("word2013"),
      w16 = sw("word2016");
    if (w13)
      out.push(
        base({
          rule: "sw.kev",
          cat: "sw",
          sev: "warn",
          source: "Аналитика",
          module: "analysis",
          title: `Вероятно уязвимое ПО (CISA KEV): ${w13.name}`,
          description: `${w13.name} (${w13.ver}) найден в ${w13.docs} документах. Поддержка закончилась ${w13.eol_date || "2023-04-11"}, а в каталоге CISA KEV есть эксплуатируемые CVE для этого продукта, опубликованные позже.`,
          recommendation:
            "Сверьте версии на рабочих станциях с бюллетенями Microsoft и переведите их на поддерживаемую версию Office.",
          cve: (w13.cves || []).map(c => (Array.isArray(c) ? c[0] : c)),
          tags: ["kev", "likely"],
        }),
      );
    if (w16)
      out.push(
        base({
          rule: "sw.kev",
          cat: "sw",
          sev: "low",
          source: "Аналитика",
          module: "analysis",
          title: `Возможно уязвимое ПО (CISA KEV): ${w16.name}, сверьте версию`,
          description: `${w16.name} (${w16.ver}) есть в каталоге CISA KEV. Каталог не указывает уязвимые версии, поэтому это повод проверить версию, а не подтверждённая уязвимость.`,
          recommendation: "Проверьте номер сборки по бюллетеням производителя.",
          cve: (w16.cves || []).map(c => (Array.isArray(c) ? c[0] : c)),
          tags: ["kev", "possible"],
        }),
      );
    const pdf = st.docs.find(x => !x.deleted && x.ext === "pdf" && x.created_at && x.modified_at);
    if (pdf)
      out.push(
        base({
          rule: "doc.anomaly.date_mismatch",
          cat: "docs",
          sev: "low",
          source: "Аналитика",
          module: "analysis",
          doc: pdf.id,
          host: pdf.host,
          url: pdf.url,
          title: `Даты PDF и XMP расходятся: «${pdf.name}»`,
          description:
            "Дата создания в словаре Info и в XMP отличается на 3 часа: файл пересохраняли другой программой или дату правили вручную.",
          recommendation: "Сверьте документ с оригиналом; при публикации очищайте метаданные.",
          tags: ["forensics"],
        }),
      );
    const memo = st.docs.filter(x => !x.deleted && /^Службова_записка_2025(_v\d+)?\.odt$/.test(x.name));
    if (memo.length > 1)
      out.push(
        base({
          rule: "doc.lineage",
          cat: "docs",
          sev: "low",
          source: "Аналитика",
          module: "analysis",
          doc: memo[0].id,
          host: memo[0].host,
          url: memo[0].url,
          title: `Опубликованы ${memo.length} ${memo.length < 5 ? "версии" : "версий"} одного документа: «${memo[0].name}»`,
          description:
            "Версии связаны идентификатором XMP (DerivedFrom): по ним видно, как менялся текст и кто правил документ.",
          recommendation: "Оставьте на сайте только итоговую версию.",
          tags: ["forensics"],
        }),
      );
    out.push(
      base({
        rule: "org.structure",
        cat: "people",
        sev: "info",
        source: "Аналитика",
        module: "analysis",
        mitre: "T1591.004 · Gather Victim Org Information: Identify Roles",
        title: "Оргструктура восстанавливается по документам: 4 отдела",
        description:
          "Пути к сетевым папкам, принтеры и поля документов связывают сотрудников с отделами (бухгалтерия, кадры, юристы, инженеры).",
        recommendation: "Очищайте метаданные перед публикацией: пути и принтеры выдают структуру компании.",
      }),
      base({
        rule: "net.internal_map",
        cat: "hosts",
        sev: "low",
        source: "Аналитика",
        module: "analysis",
        title: "Схема внутренней сети: домен corp, 6 серверов, 7 рабочих станций",
        description:
          "Из UNC-путей, принтеров и метаданных собрана схема: файловые серверы, принт-сервер, терминальный сервер, СУБД и рабочие станции с пользователями.",
        recommendation:
          "Проверьте, какие из этих имён не должны быть видны снаружи, и очистите метаданные документов.",
      }),
      base({
        rule: "recon.web.hsts_missing",
        cat: "web",
        sev: "warn",
        source: "Веб-аудит",
        module: "webaudit",
        host: dom,
        url: `https://${dom}/`,
        title: `Нет заголовка HSTS на ${dom}`,
        description: "Сайт не отдаёт Strict-Transport-Security: браузер может открыть его по HTTP.",
        recommendation: "Добавьте Strict-Transport-Security: max-age=31536000; includeSubDomains.",
      }),
      base({
        rule: "recon.web.csp_unsafe_inline",
        cat: "web",
        sev: "warn",
        source: "Веб-аудит",
        module: "webaudit",
        host: dom,
        url: `https://${dom}/`,
        title: `CSP разрешает 'unsafe-inline' на ${dom}`,
        description:
          "Политика безопасности контента не защищает от внедрения скриптов; в connect-src виден staging-api.",
        recommendation:
          "Уберите 'unsafe-inline', используйте nonce/hash; не упоминайте тестовые хосты в CSP.",
      }),
    );
    return out;
  }

  // Forensic findings of the story documents (foca-analysis::forensic rules; provenance.rule = code).
  function contosoFxFindings(st, scan) {
    const by = n => st.docs.find(d => d.name === n);
    const person = l => (st.people.some(p => p.login === l) ? [l] : []);
    const D = {
      contract: by("Договір_постачання_ТЕС-2_v3.docx"),
      equip: by("Перелік_обладнання_ТЕС-2.xlsx"),
      lnk: by("Звіти.lnk"),
      tu: by("Технічні_умови_підключення.pdf"),
      usage: by("Звіт_по_споживанню_2019.xlsx"),
      eml: by("Re_Тендер_ТЕС-2_уточнення.eml"),
      ics: by("Нарада_ТЕС-2_графік.ics"),
      vcf: by("Контакти_відділу_продажів.vcf"),
      mp4: by("IMG_4131.mp4"),
      zip: by("Тендер_ТЕС-2_додатки.zip"),
    };
    const N = Object.fromEntries(Object.entries(D).map(([k, d]) => [k, d ? d.name : ""]));
    const base = (d, o) =>
      d && {
        host: d.host,
        cat: "docs",
        source: "Форензика документов",
        module: "forensics",
        time: "2026-11-12T10:20:00",
        first_scan: scan,
        doc: d.id,
        url: d.url,
        tags: ["forensics"],
        ...o,
      };
    const signer =
      "Подписант: Приклад Петро Тестович\nОрганизация: ТОВ «Контосо Енерджі»\nЄДРПОУ: " +
      CONTOSO_EDRPOU +
      "\nДолжность: Головний енергетик\nE-mail: d.moroz@contoso.example\nРНОКПП: ********57\nАЦСК: КНЕДП - ІДД ДПС\nВремя подписи: 2017-06-16T09:41:12+03:00\nМетка TSA: 2017-06-19T08:02:13Z";
    const L = [
      base(D.tu, {
        rule: "doc.bad_redaction",
        title: `Плохое замазывание: текст под закраской читается (${N.tu})`,
        sev: "crit",
        cvss: 7.5,
        mitre: "T1213 · Data from Information Repositories",
        description:
          "Конфиденциальный фрагмент закрыт чёрным или белым прямоугольником поверх текста, но сам текст остался в документе: его можно скопировать или извлечь любой программой просмотра PDF.",
        recommendation:
          "Удалить документ с сайта; замазывать средствами настоящего редактирования (Redact → Apply), затем пересохранять PDF и проверять копированием текста.",
        evidence:
          "стр. 3 (black): «Резервна лінія: ПС-35 «Західна», вул. Промислова, 12»\nстр. 4 (white): «Тел. чергового диспетчера: +380 67 ••• •• 14»",
      }),
      base(D.tu, {
        rule: "doc.modified_after_signing",
        title: `Документ изменён после подписания (${N.tu})`,
        sev: "high",
        mitre: "T1565.001 · Data Manipulation: Stored Data Manipulation",
        description:
          "После байтов, покрытых подписью (/ByteRange), в файл дописаны изменения: видимое содержимое может отличаться от подписанного.",
        recommendation:
          "Сверить документ с подписанным оригиналом; публиковать только неизменённую подписанную версию.",
        evidence: signer,
        tags: ["forensics", "qes"],
      }),
      base(D.tu, {
        rule: "doc.signer_identity",
        title: `Данные подписанта (КЕП) в документе ${N.tu}: Приклад Петро Тестович`,
        sev: "warn",
        cat: "people",
        mitre: "T1589.001 · Gather Victim Identity Information: Credentials",
        description:
          "Сертификат подписи раскрывает ФИО, должность, организацию и центр сертификации подписанта; для украинского КЕП: коды ЄДРПОУ и РНОКПП (РНОКПП хранится только маскированным).",
        recommendation:
          "Учитывать, что подписанные документы раскрывают данные сертификата; для публикации использовать печать организации или отдельную публичную подпись.",
        evidence: signer,
        rel: { people: person("d.moroz") },
        tags: ["qes"],
      }),
      base(D.tu, {
        rule: "doc.signature_tsa_gap",
        title: `Время подписи и метка TSA расходятся более чем на сутки (${N.tu})`,
        sev: "low",
        description:
          "Заявленное время подписания заметно отличается от времени метки доверенного сервиса (TSA): часы подписанта неверны или дата подписи указана задним числом.",
        recommendation: "Проверить дату подписания по метке времени TSA.",
        evidence: signer,
      }),
      base(D.tu, {
        rule: "doc.pdf_removed_text",
        title: `Удалённый текст восстанавливается из старых ревизий PDF (${N.tu})`,
        sev: "high",
        mitre: "T1213 · Data from Information Repositories",
        description:
          "PDF сохранён инкрементально: в предыдущих ревизиях остался текст, удалённый из последней версии.",
        recommendation:
          "Пересохранить PDF полностью (без инкрементальных обновлений) и заменить опубликованный файл.",
        evidence:
          "ревизия 2 → 3: «Потужність приєднання: 2,5 МВт»\nревизия 2 → 3: «Точка підключення: ПС-110 «Харків», комірка 14»",
      }),
      base(D.tu, {
        rule: "doc.pdf_revision_authors",
        title: `Разные авторы или программы в ревизиях PDF (${N.tu})`,
        sev: "warn",
        description:
          "Ревизии PDF сохранены разными людьми или программами: видна цепочка согласования и использованное ПО.",
        recommendation: "Пересохранять итоговый PDF полностью перед публикацией.",
        evidence:
          "ревизия 1: i.petrenko · Acrobat PDFMaker 11 для Word\nревизия 3: admin · Adobe Acrobat Pro 11.0.10",
        rel: { people: person("i.petrenko") },
      }),
      base(D.tu, {
        rule: "doc.links",
        title: `Ссылки на облачные пространства и URL с токенами в ${N.tu}`,
        sev: "crit",
        mitre: "T1213.003 · Data from Information Repositories: Code Repositories",
        description:
          "Документ ссылается на облачные рабочие пространства (Google Drive, SharePoint, Notion, Trello, Jira…) или содержит URL со встроенными токенами доступа (токены маскированы).",
        recommendation:
          "Проверить права доступа по ссылкам, отозвать токены и SAS-ссылки, закрыть публичный доступ к рабочим пространствам.",
        evidence:
          "Google Drive: https://drive.google.com/drive/folders/1Qx••••••••hT?usp=sharing\nAzure Storage: https://contosoexample.blob.core.windows.net/scada/tes2-scheme.zip?sv=2021-08-06&sp=r&sig=••••••••",
      }),
      base(D.contract, {
        rule: "doc.hidden_content",
        title: `Скрытый текст и скрытые строки/столбцы в ${N.contract}`,
        sev: "high",
        mitre: "T1213 · Data from Information Repositories",
        description:
          "Документ содержит скрытое форматирование (w:vanish) или скрытые строки и столбцы таблицы: при просмотре их не видно, но данные остаются в файле.",
        recommendation:
          "Удалять, а не скрывать служебные данные; проверять документ Инспектором документов перед публикацией.",
        evidence:
          "абзац 18: Знижка 8% погоджена усно з ТОВ «Енергобуд», у договір не вносити\nабзац 41: Реквізити: IBAN ••••••••••••••••••••••••4417",
      }),
      base(D.equip, {
        rule: "doc.hidden_content",
        title: `Скрытый текст и скрытые строки/столбцы в ${N.equip}`,
        sev: "high",
        mitre: "T1213 · Data from Information Repositories",
        description:
          "Документ содержит скрытое форматирование (w:vanish) или скрытые строки и столбцы таблицы: при просмотре их не видно, но данные остаются в файле.",
        recommendation:
          "Удалять, а не скрывать служебные данные; проверять документ Инспектором документов перед публикацией.",
        evidence:
          "Обладнання!12:14: Закупівельна ціна; Знижка постачальника; Маржа, %\nОбладнання!H:I: Ціна закупівлі, грн; Постачальник\nлист «Постачальники_контакти» скрыт",
      }),
      base(D.equip, {
        rule: "doc.data_connection",
        title: `Внешние источники данных в ${N.equip}`,
        sev: "warn",
        mitre: "T1590 · Gather Victim Network Information",
        description:
          "Подключения к базам данных, файлы .odc, сводные таблицы и внешние ссылки диаграмм раскрывают серверы, базы, учётные записи и пути к файлам.",
        recommendation:
          "Удалять подключения к данным и кэши сводных таблиц перед публикацией (вставлять значения).",
        evidence:
          "ERP_Billing: база Billing, пользователь svc_report\n.odc: \\\\SRV-FILE01\\public\\Підключення\\ERP_Billing.odc\nсводная таблица: источник SRV-SQL02, обновил Віктор Ткаченко",
        rel: { pcs: ["SRV-SQL02"] },
      }),
      base(D.lnk, {
        rule: "doc.lnk_host_mac",
        title: `Ярлык LNK раскрывает имя компьютера и MAC-адрес (${N.lnk})`,
        sev: "high",
        mitre: "T1592.001 · Gather Victim Host Information: Hardware",
        description:
          "Ярлык Windows хранит NetBIOS-имя компьютера, MAC-адрес сетевой карты и серийный номер тома, на котором он создан.",
        recommendation: "Не публиковать ярлыки .lnk; удалить файл с сайта.",
        evidence:
          "Компьютер: buh-pc07\nMAC: 3c:52:82:4a:1f:0b\nСерийный номер тома: 6A2F-91C4\nПуть: C:\\Users\\o.kovalenko\\Documents\\Звіти\\2024",
        rel: { pcs: ["BUH-PC07"] },
      }),
      base(D.lnk, {
        rule: "doc.lnk_unc_path",
        title: `Ярлык LNK указывает на сетевой ресурс (${N.lnk})`,
        sev: "warn",
        mitre: "T1135 · Network Share Discovery",
        description:
          "Ярлык ссылается на файл на сетевом ресурсе: раскрываются имя файлового сервера и структура папок.",
        recommendation: "Не публиковать ярлыки .lnk.",
        evidence: "\\\\SRV-FILE01\\buh$\\Звіти\\2024\\Податкова_Q4.xlsx",
        rel: { pcs: ["SRV-FILE01"] },
      }),
      base(D.usage, {
        rule: "pii",
        title: `Номер счёта IBAN в документе (${N.usage})`,
        sev: "high",
        cat: "people",
        source: "Персональные данные",
        module: "pii",
        mitre: "T1213 · Data from Information Repositories",
        description:
          "В документе найдено значений: 12. Значения проверены по контрольным суммам, где это возможно; в базе и отчёте хранятся только маски.",
        recommendation:
          "Удалить персональные данные из публикуемого документа (обезличить) или убрать документ; оценить уведомление владельцев данных.",
        evidence: "UA •••••••••••••••••••••••••0417\nUA •••••••••••••••••••••••••2290",
        tags: ["pii"],
      }),
      base(D.usage, {
        rule: "pii",
        title: `Номер банковской карты в документе (${N.usage})`,
        sev: "high",
        cat: "people",
        source: "Персональные данные",
        module: "pii",
        mitre: "T1213 · Data from Information Repositories",
        description:
          "В документе найдено значений: 2. Значения проверены по контрольным суммам, где это возможно; в базе и отчёте хранятся только маски.",
        recommendation:
          "Удалить персональные данные из публикуемого документа (обезличить) или убрать документ; оценить уведомление владельцев данных.",
        evidence: "•••• •••• •••• 4471\n•••• •••• •••• 9015\nVisa ×1, ПРОСТІР ×1",
        tags: ["pii"],
      }),
      base(D.eml, {
        rule: "mail.internal_relay",
        title: `Внутренние почтовые серверы и адреса в заголовках письма (${N.eml})`,
        sev: "high",
        mitre: "T1590.005 · Gather Victim Network Information: IP Addresses",
        description:
          "Цепочка Received раскрывает внутренние почтовые релеи, рабочие станции и их частные IP-адреса.",
        recommendation:
          "Удалять внутренние заголовки Received на пограничном почтовом шлюзе; не публиковать исходные письма.",
        evidence: "SAL-NB05.contoso.local, MAIL01.contoso.local, 10.10.3.45, 10.10.1.5",
        rel: { pcs: ["MAIL01", "SAL-NB05"] },
      }),
      base(D.eml, {
        rule: "mail.originating_ip",
        title: `IP-адрес отправителя в заголовках письма (${N.eml})`,
        sev: "high",
        description: "Заголовок X-Originating-IP раскрывает адрес рабочей станции отправителя.",
        recommendation: "Отключить добавление X-Originating-IP на почтовом сервере.",
        evidence: "10.10.3.45",
      }),
      base(D.eml, {
        rule: "mail.internal_domain",
        title: `Внутренний домен в Message-ID (${N.eml})`,
        sev: "warn",
        description:
          "Идентификатор письма содержит внутреннее имя почтового сервера или домена Active Directory.",
        recommendation: "Настроить почтовый сервер на внешнее имя в Message-ID.",
        evidence: "mail01.contoso.local",
      }),
      base(D.eml, {
        rule: "mail.reply_to_mismatch",
        title: `Reply-To отличается от отправителя (${N.eml})`,
        sev: "warn",
        mitre: "T1566 · Phishing",
        description:
          "Ответы на письмо уходят на другой адрес, чем адрес отправителя: типичный признак фишинга или личного ящика сотрудника.",
        recommendation: "Проверить адрес Reply-To; не использовать личные ящики для служебной переписки.",
        evidence: "lysenko.serhii@example.net",
      }),
      base(D.eml, {
        rule: "mail.m365_tenant",
        title: `Идентификатор арендатора Microsoft 365 в письме (${N.eml})`,
        sev: "low",
        description: "Заголовки письма содержат идентификатор арендатора Microsoft 365 организации.",
        recommendation: "Учитывать при оценке поверхности атаки облачной инфраструктуры.",
        evidence: tenantId("contoso.example"),
      }),
      base(D.ics, {
        rule: "cal.meeting_link",
        title: `Ссылки на онлайн-встречи в календаре (${N.ics})`,
        sev: "warn",
        description:
          "Приглашение содержит ссылки подключения к Teams/Zoom (иногда с паролем): посторонний может войти на встречу.",
        recommendation: "Не публиковать приглашения; включить зал ожидания и пароли встреч.",
        evidence: "https://teams.microsoft.com/l/meetup-join/19%3ameeting_NjA••••••@thread.v2/0",
      }),
      base(D.vcf, {
        rule: "pim.contact_pii",
        title: `Личные контакты в визитных карточках (${N.vcf})`,
        sev: "warn",
        cat: "people",
        description:
          "Файл контактов содержит телефоны, адреса и даты рождения (значения в базе маскированы).",
        recommendation: "Не публиковать файлы контактов .vcf.",
        evidence: "Сергій Лисенко: +380 67 ••• •• 31\nВіктор Ткаченко: +380 50 ••• •• 08, ДР ••••-••-14",
        rel: { people: person("s.lysenko").concat(person("v.tkachenko")) },
      }),
      base(D.mp4, {
        rule: "media.device_serial",
        title: `Серийный номер устройства в медиафайле (${N.mp4})`,
        sev: "warn",
        mitre: "T1592.001 · Gather Victim Host Information: Hardware",
        description:
          "Видео или фото содержит серийный номер камеры/телефона: по нему связываются другие публикации с того же устройства.",
        recommendation: "Удалять метаданные медиафайлов перед публикацией.",
        evidence: "Apple iPhone 13 Pro · F2LX••••Q1PK",
      }),
      base(D.zip, {
        rule: "zip.path_traversal",
        title: `Архив с опасными путями (Zip-Slip): ${N.zip}`,
        sev: "high",
        mitre: "T1204.002 · User Execution: Malicious File",
        description:
          "Имена файлов в архиве выходят за пределы папки распаковки (../, абсолютные пути): архив враждебен или повреждён.",
        recommendation: "Не распаковывать архив; проверить источник файла.",
        evidence: "../../Users/Public/Startup/update.lnk",
      }),
    ];
    return L.filter(Boolean);
  }

  // Findings of small projects, built from the data (same rules as the scan).
  function genericFindings(st, spec, scanId, scanAt) {
    const out = [];
    let id = 1;
    const at = k => addMin(scanAt, 3 + k);
    const an = st.docs.filter(d => d.status === "analyzed");
    const dom = spec.domain || spec.name;
    const add = o => out.push(findTpl(st, { ...o, id: id++, first_scan: scanId, time: at(id) }));
    if (spec.dmarc === "none")
      add({
        title: "DMARC p=none: подделка писем от домена возможна",
        sev: "warn",
        host: dom,
        cat: "mail",
        source: "SPF/DMARC",
        module: "dns",
        cvss: 5.8,
        mitre: "T1566 · Phishing",
        description: `Политика DMARC для ${dom} в режиме мониторинга (p=none).`,
        recommendation: "Перевести политику в p=quarantine, затем в p=reject.",
        evidence: `_dmarc.${dom}. IN TXT\n"v=DMARC1; p=none"`,
        url: `dns://_dmarc.${dom}`,
      });
    st.secrets.forEach(s => {
      const d = docById(st, s.doc);
      add({
        title:
          s.type === "pass"
            ? "Пароль в тексте документа"
            : s.type === "api"
              ? "API-токен в документе"
              : "Внутренний адрес в документе",
        sev: s.sev,
        host: d.host,
        cat: "docs",
        source: "Секреты в документах",
        module: "secrets",
        cvss: s.sev === "crit" ? 9.0 : 6.5,
        mitre: "T1552.001 · Credentials In Files",
        doc: d.id,
        description: `В документе ${d.name} найдено: ${s.where}.`,
        recommendation: "Сменить секрет, удалить документ с сайта.",
        evidence: `${s.where}:\n{{s:${s.value}}}`,
        rel: { people: [d.author].filter(Boolean) },
      });
    });
    st.software
      .filter(s => s.eol && s.docs >= 2)
      .slice(0, 2)
      .forEach(s => {
        const docs = an.filter(d => d.software === s.id);
        add({
          title: `${s.name} (EOL) у ${docs.length} документов`,
          sev: s.cve > 10 ? "warn" : "low",
          host: "-",
          cat: "sw",
          source: "ПО → CVE",
          module: "analysis",
          cve: s.cves.map(c => c[0]).slice(0, 3),
          cvss: s.cves.length ? s.cves[0][1] : null,
          mitre: "T1203 · Exploitation for Client Execution",
          doc: docs[0].id,
          description: `${docs.length} документов созданы в ${s.name} ${s.ver}, поддержка завершена.`,
          recommendation: "Обновить ПО до поддерживаемой версии.",
          evidence: `Producer/Application: ${s.name} ${s.ver}\nДокументов: ${docs.length}`,
          rel: { people: topAuthors(docs, 2) },
        });
      });
    const pd = an.filter(d => d.flags.includes("path"));
    if (pd.length)
      add({
        title: `Внутренние пути и логины в метаданных ${pd.length} документов`,
        sev: "low",
        host: pd[0].host,
        cat: "docs",
        source: "Метаданные",
        module: "meta",
        cvss: 3.7,
        mitre: "T1592 · Gather Victim Host Information",
        doc: pd[0].id,
        description: "Пути шаблонов и поля Author раскрывают логины и файловые ресурсы.",
        recommendation: "Очищать метаданные перед публикацией.",
        evidence: st.paths
          .slice(0, 3)
          .map(p => p.path)
          .join("\n"),
        rel: { people: topAuthors(pd, 3) },
      });
    const gd = an.filter(d => d.gps);
    if (gd.length)
      add({
        title: `GPS-координаты в ${gd.length} фото`,
        sev: "warn",
        host: gd[0].host,
        cat: "docs",
        source: "EXIF",
        module: "meta",
        cvss: 4.3,
        mitre: "T1591.001 · Physical Locations",
        doc: gd[0].id,
        description: "Опубликованные фото содержат координаты съёмки и модель телефона.",
        recommendation: "Удалять EXIF перед публикацией.",
        evidence: gd
          .slice(0, 3)
          .map(d => `${d.name}: ${d.gps.lat}, ${d.gps.lon} · ${d.camera}`)
          .join("\n"),
        rel: { people: topAuthors(gd, 2) },
      });
    const old = st.hosts.find(h => /1\.14|5\.8|2\.4\.41/.test(h.tech));
    if (old)
      add({
        title: `Устаревшее ПО веб-сервера: ${old.tech.split(",")[0]}`,
        sev: "warn",
        host: old.name,
        cat: "sw",
        source: spec.wayback ? "Shodan (кэш баннеров)" : "Отпечаток ПО",
        module: spec.wayback ? "shodan" : "download",
        cvss: 6.5,
        mitre: "T1190 · Exploit Public-Facing Application",
        description: `Заголовок Server раскрывает ${old.tech}.`,
        recommendation: "Обновить веб-сервер, скрыть версию.",
        evidence: `HTTP/1.1 200 OK\nServer: ${old.tech.split(",")[0]}`,
        url: `https://${old.name}/`,
      });
    const fm = st.emails.filter(e => e.found && !e.role);
    if (fm.length >= 2)
      add({
        title: `Определён шаблон корпоративных e-mail: i.surname@${dom}`,
        sev: "info",
        host: dom,
        cat: "people",
        source: "Люди и e-mail",
        module: "analysis",
        description: `По ${fm.length} адресам определён шаблон i.surname@${dom}.`,
        recommendation: "Учесть в обучении сотрудников.",
        evidence: fm
          .slice(0, 4)
          .map(e => e.addr + " - " + e.src)
          .join("\n"),
        rel: { people: fm.slice(0, 3).map(e => e.login) },
      });
    add({
      title: "DNSSEC не настроен для зоны",
      sev: "info",
      host: dom,
      cat: "dns",
      source: "DNS",
      module: "dns",
      description: `Для зоны ${dom} нет записей DS и DNSKEY.`,
      recommendation: "Рассмотреть включение DNSSEC.",
      evidence: `$ dig +short DS ${dom}\n(пусто)`,
      url: `dns://${dom}`,
    });
    // Some findings are already triaged.
    out.forEach((f, i) => {
      if (i % 3 === 1) f.status = "confirmed";
    });
    return out;
  }

  // ---------------- timeline events, from document dates ----------------
  function deriveEvents(st) {
    // `<field>_msg` as the core annotates timeline texts (locales/<lang>/ui/core.json, core.timeline.*).
    const cm = (code, params = {}) => ({ code, params });
    const an = st.docs
      .filter(d => d.status === "analyzed" && d.created_at)
      .slice()
      .sort((a, b) => a.created_at.localeCompare(b.created_at));
    const ev = [];
    const ym = s => ({ y: +s.slice(0, 4), m: s.slice(5, 7) });
    if (!an.length) return ev;
    const first = an[0];
    ev.push({
      ...ym(first.created_at),
      ic: "doc",
      k: "Документы",
      k_msg: cm("timeline.cat_docs"),
      t: "Самый ранний документ в выборке",
      t_msg: cm("timeline.earliest"),
      s: `${first.name}${first.software ? " · " + SW[first.software].name : ""}`,
      ref: { type: "doc", id: first.id },
    });
    st.software.forEach(s => {
      const docs = an.filter(d => d.software === s.id);
      if (!docs.length) return;
      const f = docs[0],
        l = docs[docs.length - 1];
      if (f !== first)
        ev.push({
          ...ym(f.created_at),
          ic: "app",
          k: "ПО",
          k_msg: cm("timeline.cat_software"),
          t: `Первый документ из ${s.name}`,
          t_msg: cm("timeline.first_from", { name: s.name }),
          s: `${f.name} · ${s.ver}`,
          sev: "ok",
          ref: { type: "doc", id: f.id },
        });
      if (s.eol && l.created_at.slice(0, 10) > s.eol_date)
        ev.push({
          ...ym(l.created_at),
          ic: "alert",
          k: "ПО",
          k_msg: cm("timeline.cat_software"),
          t: `${s.name} используется после окончания поддержки`,
          t_msg: cm("timeline.after_eol", { name: s.name }),
          s: `Последний документ: ${l.name} · поддержка до ${s.eol_date.split("-").reverse().join(".")}`,
          s_msg: cm("timeline.last_doc", { doc: l.name, date: s.eol_date.split("-").reverse().join(".") }),
          sev: "warn",
          ref: { type: "doc", id: l.id },
        });
    });
    st.paths
      .filter(p => p.host)
      .forEach(p => {
        const f = an.find(d => d.folder === p.path);
        if (f)
          ev.push({
            ...ym(f.created_at),
            ic: "server",
            k: "Инфраструктура",
            k_msg: cm("timeline.cat_infra"),
            t: `В путях появляется \\\\${p.host}`,
            t_msg: cm("timeline.path_host", { host: p.host }),
            s: p.path,
            ref: { type: "doc", id: f.id },
          });
      });
    st.printers.forEach(p => {
      const f = an.find(d => d.printer === p.name);
      if (f)
        ev.push({
          ...ym(f.created_at),
          ic: "printer",
          k: "Инфраструктура",
          k_msg: cm("timeline.cat_infra"),
          t: `Принтер ${p.name.replace(/^\\\\[^\\]+\\/, "")}`,
          t_msg: cm("timeline.printer", { name: p.name.replace(/^\\\\[^\\]+\\/, "") }),
          s: `Первый документ: ${f.name}`,
          s_msg: cm("timeline.first_doc", { doc: f.name }),
          ref: { type: "doc", id: f.id },
        });
    });
    an.filter(d => d.gps)
      .slice(0, 3)
      .forEach(d =>
        ev.push({
          ...ym(d.created_at),
          ic: "pin",
          k: "Утечка",
          k_msg: cm("timeline.cat_leak"),
          t: `Фото с GPS-координатами: ${d.gps.place}`,
          t_msg: cm("timeline.gps_photo", { coords: d.gps.place }),
          s: `${d.name} · ${d.camera || ""}`,
          sev: "warn",
          ref: { type: "doc", id: d.id },
        }),
      );
    return ev.sort((a, b) => a.y - b.y || a.m.localeCompare(b.m));
  }

  // ---------------- scans: result snapshots for diffs ----------------
  // ONE rule for all history records (generated, done, stopped; docs/API.md "Scan"):
  // snapshot.docs: non-deleted documents known at record time; people: authors of the parsed ones (metadata);
  // hosts: name → software fingerprint; findings: id → severity of current findings (no false positives or
  // fixed);
  // findings = |snapshot.findings|; new_findings = ids missing from the previous record's snapshot; added =
  // growth in this scan.
  function scanSnapshot(st, scanId, order) {
    const seen = id => order.indexOf(id) <= order.indexOf(scanId);
    const docs = st.docs.filter(d => d.first_scan && seen(d.first_scan) && !d.deleted);
    const an = docs.filter(d => d.status === "analyzed");
    const hosts = {};
    st.hosts
      .filter(h => !h.first_scan || seen(h.first_scan))
      .forEach(h => {
        hosts[h.name] = scanId === order[0] && h.tech_s1 ? h.tech_s1 : h.tech;
      });
    const finds = {};
    st.findings
      .filter(
        f =>
          seen(f.first_scan) &&
          f.status !== "false" &&
          !(f.fixed_scan && seen(f.fixed_scan)) &&
          !(f.status === "fixed" && !f.fixed_scan),
      )
      .forEach(f => {
        finds[f.id] = f.sev;
      });
    // Site technologies (recon): early scans lack the latest one and have an older jQuery (for scan
    // comparison).
    const tl = (st.recon && st.recon.tech) || [],
      early = scanId !== order[order.length - 1];
    const tech = Object.fromEntries(
      tl
        .filter((t, i) => !early || i < tl.length - 1)
        .map(t => [t.name, early && t.name === "jQuery" ? "1.12.4" : t.version || ""]),
    );
    return {
      docs: docs.map(d => d.id),
      people: uniq(an.map(d => d.author).filter(Boolean)),
      hosts,
      findings: finds,
      tech,
    };
  }
  // "As of now" snapshot, for the record of the running scan (done/stopped).
  const stateSnap = st => {
    const docs = st.docs.filter(d => !d.deleted);
    return {
      docs: docs.map(d => d.id),
      people: uniq(
        docs
          .filter(d => d.status === "analyzed")
          .map(d => d.author)
          .filter(Boolean),
      ),
      hosts: Object.fromEntries(st.hosts.map(h => [h.name, h.tech])),
      findings: Object.fromEntries(
        st.findings.filter(f => f.status !== "false" && f.status !== "fixed").map(f => [f.id, f.sev]),
      ),
      tech: Object.fromEntries(((st.recon && st.recon.tech) || []).map(t => [t.name, t.version || ""])),
    };
  };
  const EMPTY_SNAP = { docs: [], people: [], hosts: {}, findings: {}, tech: {} };
  const addedOf = (snap, prev) => {
    prev = prev || EMPTY_SNAP;
    const pd = new Set(prev.docs),
      pp = new Set(prev.people);
    return {
      docs: snap.docs.filter(i => !pd.has(i)).length,
      people: snap.people.filter(l => !pp.has(l)).length,
      hosts: Object.keys(snap.hosts).filter(h => !(h in prev.hosts)).length,
      findings: Object.keys(snap.findings).filter(k => !(k in prev.findings)).length,
    };
  };
  const countsOf = (snap, prev) => ({
    docs: snap.docs.length,
    hosts: Object.keys(snap.hosts).length,
    people: snap.people.length,
    findings: Object.keys(snap.findings).length,
    new_findings: addedOf(snap, prev).findings,
    added: addedOf(snap, prev),
    snapshot: snap,
  });

  function buildScans(st, spec, settings) {
    const order = spec.scans.map(s => s.id);
    st.scans = spec.scans.map((s, i) => {
      const snap = scanSnapshot(st, s.id, order);
      const prev = i ? scanSnapshot(st, order[i - 1], order) : null;
      return {
        id: s.id,
        profile_id: s.profile_id,
        profile: PROFILES[s.profile_id],
        active: s.active,
        trigger: s.trigger,
        status: "done",
        reason: null,
        started_at: s.started_at,
        finished_at: addMin(s.started_at, s.minutes),
        minutes: s.minutes,
        targets: st.scope.targets.map(t => t.v),
        egress: egressLabel(settings),
        sources: SOURCES.filter(x => !x.active || s.profile_id !== "passive").map(x => ({
          id: x.id,
          name: x.name,
          status: sourceStatus(x, settings),
        })),
        ...countsOf(snap, prev),
      };
    });
  }

  const egressLabel = s => (s.net.proxy_on ? `${s.net.out_ip} · ${s.net.label}` : "Напрямую (реальный IP)");
  const sourceStatus = (x, s) => {
    if (!x.key) return "ok";
    const k = s.keys[x.key];
    if (!k) return "nokey";
    return k.status === "ok" ? "ok" : k.status === "error" ? "error" : x.optional ? "off" : "nokey";
  };

  // ---------------- secrets ----------------
  function contosoSecrets(st) {
    const rdp = docById(st, 5);
    return [
      {
        id: 1,
        type: "conn",
        value: "Data Source=SRV-SQL02;Initial Catalog=Billing;User ID=sa;Password=Kont0so#2024!",
        doc: 1,
        where: "текст, строка 14",
        sev: "crit",
        host: "SRV-SQL02",
        finding: 4,
      },
      {
        id: 2,
        type: "api",
        value: "aws_secret_access_key = wJx9Fq2+Lr8kZ0aT3vYpQe7mNc5bHs1uKd4oGi6E",
        doc: 3,
        where: "комментарий (Обладнання!H17)",
        sev: "crit",
        host: "dev.contoso.example",
        finding: 11,
      },
      {
        id: 3,
        type: "pass",
        value: "Wi-Fi «CONTOSO-STAFF»: Energy2023!",
        doc: 4,
        where: "текст, строка 212",
        sev: "high",
      },
      {
        id: 4,
        type: "pass",
        value: "password 51:b:01000000D08C9DDF0115D1118C7A00C04FC297EB01",
        doc: rdp.id,
        where: "поле password",
        sev: "high",
        host: rdp.rdp.gateway,
        finding: 13,
      },
      {
        id: 5,
        type: "api",
        value: "AIzaSyD4-redacted-key-9f2Qx",
        doc: 7,
        where: "текст, строка 31",
        sev: "warn",
      },
      {
        id: 6,
        type: "api",
        value: "bot6412093355:AAF-redacted-token",
        doc: 8,
        where: "текст, строка 4",
        sev: "warn",
      },
      {
        id: 7,
        type: "host",
        value: "10.10.1.12  sql02.corp.contoso.local",
        doc: 9,
        where: "поле connections.xml",
        sev: "low",
        host: "SRV-SQL02",
      },
      {
        id: 8,
        type: "host",
        value: `${rdp.rdp.full_address}  ${rdp.rdp.gateway}`,
        doc: rdp.id,
        where: "full address:s:",
        sev: "low",
        host: rdp.rdp.gateway,
        finding: 13,
      },
    ];
  }

  // ================= project assembly =================
  function buildContoso(settings) {
    const spec = CONTOSO,
      R = rng(spec.seed);
    const st = { id: spec.id, all_people: buildPeople(spec, R), docs: [], secrets: [] };
    const ctx = {
      spec,
      R,
      used: new Set(),
      people: st.all_people,
      web: spec.web,
      deptExts: spec.dept_exts,
      folders: spec.folders,
      folderFrom: spec.folder_from,
      printers: spec.printers,
      swAllow: spec.sw_allow,
    };
    const S1 = "contoso-s1",
      S2 = "contoso-s2";
    // Story documents (referenced by findings and secrets).
    const fixed = [
      {
        id: 1,
        ext: "docx",
        name: "Договір_постачання_ТЕС-2_v3.docx",
        title: "Договір постачання",
        host: "files.contoso.example",
        author: "a.bondar",
        sw: "word2013",
        year: 2024,
        m: 3,
        day: 11,
        hh: 10,
        mm: 15,
        modified_at: "2024-03-17T20:42:00",
        last_modified_by: "o.kovalenko",
        folder: "\\\\SRV-FILE01\\public\\Шаблони",
        printer: "\\\\SRV-PRN01\\Canon iR-ADV C5535 2F",
        size: 184,
        first_scan: S2,
        revisions: [
          {
            kind: "del",
            who: "a.bondar",
            at: "2024-03-12T16:20:00",
            text: "Ціна договору становить 18 450 000 грн",
          },
          {
            kind: "ins",
            who: "a.bondar",
            at: "2024-03-12T16:21:00",
            text: "Ціна договору становить 16 900 000 грн",
          },
          {
            kind: "com",
            who: "a.bondar",
            at: "2024-03-12T16:24:00",
            text: "узгодити знижку з ТОВ Енергобуд",
          },
          {
            kind: "com",
            who: "o.kovalenko",
            at: "2024-03-13T09:02:00",
            text: "Реквізити рахунку взяти з 1С, не з минулого договору",
          },
        ],
      },
      {
        id: 2,
        ext: "jpg",
        name: "tes2_build.jpg",
        title: "tes2_build",
        host: "contoso.example",
        author: "v.tkachenko",
        sw: "ios166",
        year: 2024,
        m: 8,
        day: 2,
        hh: 11,
        mm: 5,
        size: 3412,
        gps: CONTOSO.gps_places[0],
        thumb_diff: true,
        first_scan: S1,
      },
      {
        id: 3,
        ext: "xlsx",
        name: "Перелік_обладнання_ТЕС-2.xlsx",
        title: "Перелік обладнання",
        host: "files.contoso.example",
        author: "v.tkachenko",
        sw: "excel2016",
        year: 2025,
        m: 2,
        day: 3,
        hh: 14,
        mm: 22,
        folder: "D:\\Projects\\ТЕС-2\\КД",
        printer: null,
        first_scan: S1,
      },
      {
        id: 4,
        ext: "pptx",
        name: "Онбординг_нових_співробітників.pptx",
        title: "Онбординг нових співробітників",
        host: "contoso.example",
        author: "t.melnyk",
        sw: "ppt2016",
        year: 2023,
        m: 9,
        day: 4,
        hh: 9,
        mm: 40,
        folder: "\\\\NAS02\\hr\\Накази",
        printer: null,
        first_scan: S1,
      },
      {
        id: 5,
        ext: "rdp",
        name: "SRV-TS01.rdp",
        title: "SRV-TS01",
        host: "files.contoso.example",
        author: "admin",
        year: 2022,
        m: 5,
        day: 16,
        hh: 12,
        mm: 3,
        size: 3,
        first_scan: S1,
        rdp: { full_address: "10.10.1.21", username: "CONTOSO\\admin", gateway: "SRV-TS01" },
      },
      {
        id: 6,
        ext: "lnk",
        name: "Звіти.lnk",
        title: "Звіти",
        host: "portal.contoso.example",
        author: "o.kovalenko",
        year: 2024,
        m: 1,
        day: 22,
        hh: 8,
        mm: 51,
        size: 2,
        first_scan: S1,
        lnk: {
          machine: "BUH-PC07",
          mac: "3C:52:82:4A:1F:0B",
          volume_serial: "6A2F-91C4",
          target: "C:\\Users\\o.kovalenko\\Documents\\Звіти\\2024",
          target_dir: "C:\\Users\\o.kovalenko\\Documents\\Звіти\\2024",
        },
      },
      {
        id: 7,
        ext: "pdf",
        name: "Технічні_умови_підключення.pdf",
        title: "Технічні умови підключення",
        host: "contoso.example",
        author: "i.petrenko",
        sw: "acro11",
        year: 2017,
        m: 6,
        day: 14,
        hh: 15,
        mm: 10,
        first_scan: S1,
      },
      {
        id: 8,
        ext: "odt",
        name: "Службова_записка.odt",
        title: "Службова записка",
        host: "portal.contoso.example",
        author: "v.tkachenko",
        sw: "lo72",
        year: 2022,
        m: 10,
        day: 6,
        hh: 16,
        mm: 2,
        folder: null,
        printer: null,
        first_scan: S1,
      },
      {
        id: 9,
        ext: "xlsx",
        name: "Звіт_по_споживанню_2019.xlsx",
        title: "Звіт по споживанню",
        host: "files.contoso.example",
        author: "o.kovalenko",
        sw: "excel2010",
        year: 2019,
        m: 4,
        day: 9,
        hh: 11,
        mm: 30,
        folder: "\\\\SRV-FILE01\\buh$\\Податкова",
        printer: "HP LaserJet Pro M404 (BUH)",
        first_scan: S1,
      },
    ];
    fixed.forEach(o => st.docs.push(makeDoc(ctx, { ...o, status: "analyzed" })));
    // The rest: statuses, extensions and years are random but consistent.
    for (let id = fixed.length + 1; id <= spec.ndocs; id++) {
      const ext = R.wpick(spec.exts);
      const status = R.wpick([
        ["analyzed", 82],
        ["downloaded", 6],
        ["queued", 5],
        ["error", 7],
      ]);
      const first_scan = id > spec.ndocs - 20 ? S2 : S1;
      st.docs.push(makeDoc(ctx, { id, ext, status, first_scan }));
    }
    CONTOSO_FX_DOCS.forEach((o, i) =>
      st.docs.push(makeDoc(ctx, { ...o, id: spec.ndocs + 1 + i, status: "analyzed", first_scan: S1 })),
    );
    st.secrets = contosoSecrets(st);
    deriveFlags(st);
    st.extra_pcs = [
      { name: "SRV-SQL02", kind: "server", ip: "10.10.1.12", source: "DNS (AXFR)" },
      { name: "MAIL01", kind: "server", ip: null, source: "Shodan (X-FEServer)" },
    ];
    deriveEntities(st, spec);
    st.email_found = {
      "o.kovalenko": "Метаданные документа",
      "i.petrenko": "Метаданные документа",
      "v.tkachenko": "Текст документа",
      "t.melnyk": "Метаданные документа",
      "s.lysenko": "Текст документа",
      "y.hrytsenko": "Текст документа",
    };
    st.role_mails = [
      ["info@contoso.example", "Текст документа"],
      ["tender@contoso.example", "Текст документа"],
      ["dmarc@contoso.example", "DNS TXT (_dmarc)"],
      ["hr@contoso-group.example", "crt.sh"],
    ];
    deriveEmails(st, spec);
    deriveHosts(st, spec);
    const fs = { "dev.contoso.example": S1, "vpn.contoso.example": S1, "SRV-SQL02": S2 };
    st.hosts.forEach(h => {
      h.first_scan = fs[h.name] || S1;
    });
    st.leaks = {
      "o.kovalenko": [
        { name: "Collection #1", date: "01.2019", data: "e-mail, пароль" },
        { name: "Canva", date: "05.2019", data: "e-mail, имя, город" },
      ],
      "i.petrenko": [{ name: "Adobe", date: "10.2013", data: "e-mail, хеш пароля, подсказка" }],
      "m.shevchuk": [{ name: "Wattpad", date: "06.2020", data: "e-mail, имя, IP" }],
    };
    st.findings = contosoFindings(st);
    return finishProject(st, spec, settings);
  }

  function buildSmall(spec, settings) {
    const R = rng(spec.seed);
    const st = { id: spec.id, all_people: buildPeople(spec, R), docs: [], secrets: [] };
    if (!spec.ndocs) {
      Object.assign(st, {
        people: [],
        software: [],
        paths: [],
        printers: [],
        pcs: [],
        gps: [],
        emails: [],
        patterns: [],
        hosts: [],
        findings: [],
        leaks: {},
      });
      return finishProject(st, spec, settings);
    }
    const web = spec.web.map((n, i) => ({
      name: n,
      paths: i ? ["/files/", "/docs/"] : ["/upload/", "/wp-content/uploads/2024/", "/about/"],
    }));
    const deptExts = {};
    const folders = {};
    spec.depts.forEach(d => {
      deptExts[d] = DEPT[d].exts;
    });
    st.all_people.forEach(p => {
      folders[p.dept] = (folders[p.dept] || []).concat(
        [`C:\\Users\\${p.login}\\Documents`],
        spec.fileserver ? [`${spec.fileserver}\\${p.dept}`] : [],
      );
    });
    const printers = spec.printer
      ? [
          { name: spec.printer, from: spec.years[0] },
          { name: "Microsoft Print to PDF", from: 2016 },
        ]
      : [];
    const ctx = {
      spec,
      R,
      used: new Set(),
      people: st.all_people,
      web,
      deptExts,
      folders,
      folderFrom: {},
      printers,
      swAllow: spec.sw_allow,
    };
    const sid = spec.scans[0].id;
    for (let id = 1; id <= spec.ndocs; id++) {
      const ext = R.wpick([
        ["pdf", 30],
        ["docx", 22],
        ["xlsx", 16],
        ["pptx", 6],
        ["jpg", 14],
        ["xls", 4],
      ]);
      const status = R.wpick([
        ["analyzed", 80],
        ["downloaded", 6],
        ["queued", 6],
        ["error", 8],
      ]);
      st.docs.push(makeDoc(ctx, { id, ext, status, first_scan: sid }));
    }
    // 1-2 secrets in parsed office documents.
    const off = st.docs.filter(d => d.status === "analyzed" && ["docx", "xlsx", "pdf"].includes(d.ext));
    if (off[1])
      st.secrets.push({
        id: 1,
        type: "pass",
        value: `Пароль від порталу: ${spec.id.slice(0, 3).toUpperCase()}-2024!q`,
        doc: off[1].id,
        where: "текст, строка 3",
        sev: "high",
      });
    if (off[4] && spec.ndocs > 30)
      st.secrets.push({
        id: 2,
        type: "api",
        value: "sk_live_51H-redacted",
        doc: off[4].id,
        where: "комментарий (C4)",
        sev: "crit",
      });
    deriveFlags(st);
    st.extra_pcs = [];
    deriveEntities(st, spec);
    st.email_found = {};
    st.people
      .filter(p => p.login.includes("."))
      .slice(0, 3)
      .forEach(p => {
        st.email_found[p.login] = "Метаданные документов";
      });
    st.role_mails = [[`info@${spec.name}`, "Текст документа"]];
    deriveEmails(st, spec);
    spec.hosts = spec.web
      .map((n, i) => ({
        name: n,
        ip: spec.ips[i] || "-",
        role: i ? "Файловый" : "Веб-сервер",
        tech: spec.tech[i] || "-",
        cloud: "-",
        services: [["443/tcp", "https", (spec.tech[i] || "").split(",")[0]]],
      }))
      .concat(spec.extra_hosts.map(h => ({ cloud: "-", services: [], ...h })));
    deriveHosts(st, spec);
    st.hosts.forEach(h => {
      h.first_scan = sid;
    });
    st.leaks = {};
    st.findings = genericFindings(st, spec, sid, spec.scans[0].started_at);
    return finishProject(st, spec, settings);
  }

  function hostSev(st, h) {
    const live = st.findings.filter(f => f.host === h.name && f.status !== "false" && f.status !== "fixed");
    const ord = ["crit", "high", "warn", "low", "info"];
    for (const s of ord) if (live.some(f => f.sev === s)) return s;
    return h.internal ? "info" : "ok";
  }

  // Host network details: DNS records, ASN, TLS, derived from project data (hosts, roles, findings) for all
  // projects.
  const ISPS = [
    "Ukrtelecom JSC",
    "Example Hosting",
    "Volia LLC",
    "Kyivstar PJSC",
    "Hosting Ukraine LLC",
    "Lanet Network Ltd",
  ];
  const CAS = [
    "Sectigo RSA Domain Validation Secure Server CA",
    "Let's Encrypt R11",
    "GlobalSign GCC R3 DV TLS CA 2020",
  ];
  // Host roles by name tokens (as foca-analysis::roles: weight of the strongest role + 10 per extra role).
  const ROLE_TOKENS = {
    dev_stage:
      "dev devel develop development stage staging stg test testing tst qa uat preprod pre sandbox demo beta alpha lab poc pilot tmp temp old legacy",
    remote_access:
      "vpn sslvpn remote rdp rds rdweb rdg citrix netscaler owa exchange anyconnect globalprotect fortigate vdi horizon bastion jump ssh gateway",
    admin:
      "admin administrator adm panel cpanel whm plesk manage manager management mgmt console dashboard backoffice cms webmin phpmyadmin ilo idrac ipmi vcenter esxi proxmox",
    api: "api apis graphql gql rest ws soap rpc grpc swagger openapi backend",
    vcs_ci:
      "git gitlab github gitea bitbucket svn jenkins ci cicd build drone teamcity sonar nexus artifactory registry harbor docker repo jira confluence",
    mail: "mail email smtp imap pop mx webmail autodiscover autoconfig relay roundcube zimbra",
    monitoring:
      "grafana kibana prometheus zabbix nagios monitor monitoring metrics elk splunk sentry graylog logs",
    database: "db database mysql postgres pg sql mssql mongo mongodb redis elasticsearch clickhouse",
    storage: "ftp sftp files share storage minio backup backups bak nas nextcloud owncloud webdav",
    auth: "sso auth login idp adfs sts oauth saml keycloak okta cas",
    internal: "intranet internal corp lan office",
  };
  const ROLE_W = {
    admin: 40,
    database: 40,
    remote_access: 35,
    vcs_ci: 35,
    dev_stage: 30,
    monitoring: 30,
    storage: 30,
    internal: 30,
    auth: 25,
    api: 20,
    mail: 10,
  };
  const ROLE_OF = {};
  Object.entries(ROLE_TOKENS).forEach(([r, t]) => t.split(" ").forEach(k => (ROLE_OF[k] = r)));
  function hostRoles(name, dom) {
    const h = String(name).toLowerCase();
    const rest = h === dom ? "" : h.endsWith("." + dom) ? h.slice(0, -dom.length - 1) : "";
    const tags = [];
    rest
      .split(".")
      .filter(Boolean)
      .forEach(label => {
        const toks = [label];
        label
          .split(/[-_]/)
          .forEach(p => [p, p.replace(/\d+$/, "")].forEach(x => x && !toks.includes(x) && toks.push(x)));
        toks.forEach(t => {
          const r = ROLE_OF[t];
          if (r && !tags.some(x => x.role === r)) tags.push({ role: r, token: t });
        });
      });
    const max = Math.max(0, ...tags.map(x => ROLE_W[x.role]));
    return {
      roles: tags.map(x => x.role),
      tags,
      priority: Math.min(100, max + 10 * Math.max(0, tags.length - 1)),
    };
  }
  // CDN / cloud ranges of the demo addresses (as foca-net::cdn classify_ip), inside documentation blocks.
  const CDN_RANGES = [
    ["192.0.2.128/26", "cloudflare", "Cloudflare", "cdn"],
    ["198.51.100.128/26", "aws", "Amazon Web Services", "cloud"],
    ["203.0.113.192/27", "azure", "Microsoft Azure", "cloud"],
  ];
  function cdnOf(h, ip) {
    const n = ip4(ip);
    if (n == null || h.internal) return null;
    const r = CDN_RANGES.find(([c]) => {
      const [b, m] = c.split("/");
      const mask = m === "0" ? 0 : (~0 << (32 - +m)) >>> 0;
      return (ip4(b) & mask) >>> 0 === (n & mask) >>> 0;
    });
    return r ? { host: h.name, ip, provider: r[1], name: r[2], kind: r[3], prefix: r[0], via: "ip" } : null;
  }
  function deriveNet(st, spec) {
    const dom = spec.domain || spec.name;
    const ext = st.hosts.filter(h => !h.internal);
    const fnd = st.findings || [];
    const dmarcNone = fnd.some(f => f.category === "mail" && /DMARC p=none/.test(f.title));
    const spfSoft = fnd.some(
      f => f.category === "mail" && /SPF/.test(f.title) && /~all/.test(f.title + f.evidence),
    );
    const spfTxt = (fnd.find(f => /v=spf1/.test(f.evidence || "")) || {}).evidence;
    const nsHosts = ext.filter(h => h.role === "DNS").map(h => h.name);
    const ns = nsHosts.length
      ? nsHosts
      : [
          `ns1.${ISPS[hash(dom) % ISPS.length].split(" ")[0].toLowerCase()}.net`,
          `ns2.${ISPS[hash(dom) % ISPS.length].split(" ")[0].toLowerCase()}.net`,
        ];
    const mail = ext.find(h => h.role === "Почта");
    st.hosts.forEach(h => {
      const ip = String(h.ip || "").split(" ")[0];
      const numeric = ip4(ip) != null;
      const dns = [];
      const cname = (String(h.ip).match(/CNAME → (\S+)/) || [])[1];
      if (cname)
        dns.push([
          "CNAME",
          cname,
          fnd.some(f => f.host === h.name && /NXDOMAIN/.test(f.evidence || ""))
            ? "NXDOMAIN: ресурс удалён"
            : "",
        ]);
      else if (numeric && !h.internal) dns.push(["A", ip, "TTL 3600"]);
      if (h.cloud === "Cloudflare") dns.push(["CNAME", `${dom}.cdn.cloudflare.net`, "Cloudflare"]);
      if (h.name === dom) {
        if (mail) dns.push(["MX", `10 ${mail.name}`, ""]);
        const spf = spfTxt ? (spfTxt.match(/"(v=spf1[^"]*)"/) || [])[1] : null;
        dns.push([
          "TXT",
          spf || `v=spf1 ip4:${ip} ${spfSoft ? "~all" : "-all"}`,
          spfSoft || /~all/.test(spf || "") ? "SPF ~all" : "SPF -all",
        ]);
        const pol = dmarcNone ? "none" : spec.dmarc || "quarantine";
        dns.push(["TXT", `_dmarc: v=DMARC1; p=${pol}`, `DMARC p=${pol}`]);
        dns.push(["NS", ns.join(", "), ""]);
      }
      if (mail && h.name === mail.name && numeric) dns.push(["PTR", mail.name, ""]);
      h.dns = dns;
      const pre = ip.split(".").slice(0, 2).join(".");
      h.asn =
        !numeric || h.internal
          ? null
          : h.cloud === "Cloudflare" || pre === "104.21"
            ? "AS13335 · Cloudflare, Inc."
            : /^AWS/.test(h.cloud) || pre === "52.29"
              ? "AS16509 · Amazon.com, Inc."
              : /^Azure/.test(h.cloud)
                ? "AS8075 · Microsoft Corporation"
                : `AS${40000 + (hash(ip.split(".").slice(0, 3).join(".")) % 20000)} · ${ISPS[hash(ip.split(".").slice(0, 3).join(".")) % ISPS.length]} (UA)`;
      const https = (h.services || []).some(s => /^443\//.test(s[0]));
      if (numeric && !h.internal && https) {
        const nf = fnd
          .map(f =>
            f.host === h.name ? String(f.evidence || "").match(/Not After: (\d{4}-\d\d-\d\d)/) : null,
          )
          .find(Boolean);
        const till = nf
          ? nf[1]
          : `2027-${pad(1 + (hash(h.name) % 12))}-${pad(1 + (hash(h.name + "d") % 28))}`;
        const own = h.cloud === "Cloudflare" || h.source === "crt.sh";
        h.tls = {
          cn: own ? h.name : `*.${dom}`,
          issuer:
            h.cloud === "Cloudflare"
              ? "Cloudflare Inc ECC CA-3"
              : /^AWS/.test(h.cloud)
                ? "Let's Encrypt R11"
                : CAS[hash(h.name) % CAS.length],
          not_after: till,
          san: own ? [h.name] : [dom, `*.${dom}`],
        };
      } else h.tls = null;
      // Host ports (as scan/ports.rs → host_view): own scan only if a Full scan ran.
      const full = ((st.scans && st.scans.length ? st.scans : spec.scans) || []).find(
        s => s.profile_id === "full" || s.active,
      );
      const svc = (h.services || []).filter(s => /\/tcp$/.test(s[0]));
      const idb = s => /Shodan/.test(s[2] || "") || h.source === "Shodan";
      const SENS = {
        21: "FTP",
        23: "Telnet",
        445: "SMB",
        3306: "MySQL",
        3389: "RDP",
        5432: "PostgreSQL",
        6379: "Redis",
        9200: "Elasticsearch",
        2375: "Docker API",
        27017: "MongoDB",
      };
      // Hosts from scope exclusions are not scanned (as the core's targets()).
      const excl = ((st.scope || spec.scope || {}).excl || []).some(
        x => x === h.name || x === ip || h.name.endsWith("." + x),
      );
      const scanned = !!full && numeric && !h.internal && !excl;
      h.ports = svc
        .filter(s => scanned || idb(s))
        .map(s => {
          const port = +s[0].split("/")[0],
            scan = !idb(s) && scanned;
          const m = String(s[2] || "")
            .replace(/\s*\(Shodan\)$/, "")
            .match(/^([A-Za-z][\w .-]*?)\s+v?(\d[\w.]*)/);
          return {
            port,
            proto: "tcp",
            service: s[1],
            banner: scan ? s[2] || null : null,
            product: scan && m ? m[1] : null,
            version: scan && m ? m[2] : null,
            tls: /https|ssl/.test(s[1]),
            cert_names: [],
            source: scan ? "scan" : "internetdb",
            cached: !scan,
            unconfirmed: false,
            outdated:
              scan && /Apache 2\.2|Apache 2\.4\.(?:[0-4]?\d)\b|IIS 8|vsftpd 2/.test(s[2] || "")
                ? "версия старее поддерживаемой"
                : null,
            sensitive: SENS[port] || null,
          };
        })
        .sort((a, b) => a.port - b.port);
      const open = h.ports.filter(p => p.source === "scan").length;
      h.ports_scan = scanned
        ? {
            scan: full.id,
            at: full.finished_at || full.started_at,
            ip,
            spec: "топ-100",
            scanned: 100,
            open,
            closed: 100 - open,
            filtered: 0,
            ms: 800 + (hash(h.name) % 900),
            cancelled: false,
            error: null,
          }
        : null;
      // Infrastructure: name roles with the check priority and the CDN/cloud label of the address.
      const rl = h.internal ? { roles: [], priority: 0 } : hostRoles(h.name, dom);
      h.roles = rl.roles;
      h.priority = rl.priority;
      h.cdn = numeric ? cdnOf(h, ip) : null;
    });
  }

  // ---- Site recon (snapshot.recon, as crates/foca-engine/src/scan/recon.rs → snapshot_of) ----
  const RECON_SRC = ["recon", "webaudit", "wellknown", "buckets", "grepapp"];
  const emptyRecon = () => ({
    at: null,
    scan: null,
    level: null,
    sources: { recon: null, webaudit: null, wellknown: null, buckets: null, grepapp: null },
    // Web audit per site (docs/API.md → recon.web[]); filled by the core's webaudit source.
    web: [],
    sites: [],
    tech: [],
    analytics: [],
    hidden_paths: [],
    sitemap: [],
    sitemap_total: 0,
    security: [],
    endpoints: [],
    endpoints_total: 0,
    secrets: [],
    buckets: [],
    code: null,
  });
  // Versions with an "outdated" threshold, as in the foca-recon/tech.rs rules.
  const TECH_DB = {
    nginx: ["Nginx", "Веб-сервер", "1.20"],
    apache: ["Apache HTTP Server", "Веб-сервер", "2.4.58"],
    wordpress: ["WordPress", "CMS", "6.4"],
    "1c-bitrix": ["1C-Bitrix", "CMS", null],
    "microsoft-iis/10.0": ["Microsoft IIS", "Веб-сервер", null],
    php: ["PHP", "Язык", "8.1"],
    jquery: ["jQuery", "JS-библиотека", "3.5.0"],
  };
  // Web audit of the main site (docs/API.md → recon.web[]): the passive level only reads the archived
  // response (0 requests), the standard one adds GETs (source map, OpenAPI), the active one OPTIONS/TRACE.
  function webAuditOf(dom, lvl) {
    const level = lvl === "external" ? "passive" : lvl === "active" ? "active" : "standard";
    const url = `https://${dom}/`;
    const issues = [
      {
        id: "hsts_missing",
        sev: "warn",
        title: "Нет заголовка Strict-Transport-Security (HSTS)",
        detail: "Браузер может открыть сайт по HTTP: возможен перехват и подмена страницы.",
      },
      {
        id: "csp_unsafe_inline",
        sev: "warn",
        title: "CSP разрешает 'unsafe-inline' в script-src",
        detail: "Политика не защищает от внедрения скриптов (XSS).",
      },
      {
        id: "version_disclosure",
        sev: "low",
        title: "Версия сервера в заголовках: Server: nginx/1.18.0, X-Powered-By: PHP/7.4.3",
        detail: "Версии помогают подобрать известные уязвимости.",
      },
      {
        id: "cookie_flags",
        sev: "low",
        title: "Cookie PHPSESSID без SameSite",
        detail: "Сессионный cookie отправляется в межсайтовых запросах.",
      },
    ];
    const deep = level !== "passive";
    return {
      host: dom,
      level,
      requests: level === "passive" ? 0 : level === "active" ? 9 : 5,
      errors: [],
      headers: [{ url, issues }],
      csp_domains: [
        { host: `api.${dom}`, wildcard: false, directives: ["connect-src"], in_scope: true, hint: "" },
        {
          host: `staging-api.${dom}`,
          wildcard: false,
          directives: ["connect-src"],
          in_scope: true,
          hint: "staging",
        },
        { host: "cdn.jsdelivr.net", wildcard: false, directives: ["script-src"], in_scope: false, hint: "" },
      ],
      hosts: [`api.${dom}`, `staging-api.${dom}`],
      candidates: ["cdn.jsdelivr.net"],
      source_maps: deep
        ? [
            {
              map_url: `${url}assets/app.3f9c2a.js.map`,
              script_url: `${url}assets/app.3f9c2a.js`,
              via: "sourceMappingURL",
              sources_total: 214,
              sources: ["src/main.js", "src/api/client.js", "src/views/Tenders.vue"],
              has_content: true,
              packages: ["vue", "axios", "vue-router"],
              local_paths: ["C:/Users/dev/projects/site/src"],
              secrets: [],
              truncated: false,
            },
          ]
        : [],
      api_docs: deep
        ? [
            {
              kind: "openapi",
              url: `https://api.${dom}/v2/api-docs`,
              title: `API ${dom}`,
              spec_version: "2.0",
              api_version: "1.4.2",
              endpoints: 38,
              operations: 61,
              auth: ["bearer"],
              unauthenticated: 4,
            },
          ]
        : [],
      cors: [],
      methods:
        level === "active"
          ? [
              {
                url,
                allow: ["GET", "POST", "OPTIONS", "TRACE"],
                unsafe_advertised: [],
                trace_reflected: true,
                webdav: false,
                errors: [],
              },
            ]
          : [],
    };
  }
  function reconOf(st, spec, R) {
    const dom = spec.domain || spec.name;
    if (!dom || !(spec.scans || []).length) return emptyRecon();
    const last = spec.scans[spec.scans.length - 1],
      lvl = last.active ? "active" : last.profile_id === "passive" ? "external" : "target";
    const tech = [];
    const addT = (key, ver) => {
      const d = TECH_DB[key.toLowerCase()];
      if (!d || tech.some(t => t.name === d[0])) return;
      const old =
        ver && d[2] && ver.split(".").map(Number).join(".") && cmpVer(ver, d[2]) < 0
          ? `версия ${ver} старее ${d[2]}`
          : null;
      tech.push({
        name: d[0],
        version: ver || null,
        category: d[1],
        outdated: old,
        confidence: ver ? 100 : 75,
        host: dom,
      });
    };
    (
      (spec.tech && spec.tech.length
        ? spec.tech
        : (st.hosts || []).filter(h => h.name === dom).map(h => h.tech)) || []
    )
      .join(", ")
      .split(/,\s*/)
      .forEach(x => {
        // eslint-disable-next-line no-useless-escape
        const m = x.trim().match(/^([A-Za-z0-9\-\/.]+?)(?:[ \/](\d[\d.]*))?(?:\s|$)/);
        if (m) addT(m[1], m[2]);
      });
    addT("jquery", R.pick(["1.12.4", "3.6.0", "3.7.1"]));
    if (tech.some(t => t.name === "WordPress")) addT("php", "7.4.3");
    // Fixed collation: the order decides which technology the earlier demo scans lack.
    tech.sort((a, b) => a.category.localeCompare(b.category, "en") || a.name.localeCompare(b.name, "en"));
    const mmh3 = hash(dom + "fav") | 0,
      md5 = (hash(dom) >>> 0).toString(16).padStart(8, "0").repeat(4);
    const via = lvl === "external" ? "archive" : "site";
    const site = {
      host: dom,
      url: `https://${dom}/`,
      via,
      error: null,
      at: addMin(last.started_at, Math.max(1, last.minutes - 3)),
      favicon: {
        url: `https://${dom}/favicon.ico`,
        mmh3,
        md5,
        sha256: md5 + md5,
        size: 1150 + R.int(0, 4000),
        queries: [
          { engine: "shodan", q: `http.favicon.hash:${mmh3}` },
          { engine: "fofa", q: `icon_hash="${mmh3}"` },
          { engine: "censys", q: `services.http.response.favicons.md5_hash:${md5}` },
        ],
      },
    };
    const wp = tech.some(t => t.name === "WordPress");
    const hidden = [
      ["/admin/", "админка"],
      ["/backup/", "резервные копии"],
      [wp ? "/wp-admin/" : "/bitrix/admin/", "админка CMS"],
      ["/1c-exchange/", "обмен 1С"],
    ]
      .slice(0, 2 + R.int(0, 2))
      .map(([path, reason]) => ({
        path,
        reason,
        source: `https://web.archive.org/web/2025id_/https://${dom}/robots.txt`,
        host: dom,
      }));
    const sm = ["", "about/", "contacts/", "tenders/", "docs/zvit-2024.pdf", "news/", "vacancies/"]
      .slice(0, 4 + R.int(0, 3))
      .map((p, i) => ({ loc: `https://${dom}/${p}`, lastmod: `2025-0${1 + i}-15`, host: dom }));
    const sec = R.chance(0.5)
      ? [
          {
            host: dom,
            source: `https://web.archive.org/web/2025id_/https://${dom}/.well-known/security.txt`,
            contacts: [`mailto:security@${dom}`],
            emails: [`security@${dom}`],
            expires: "2026-12-31T23:00:00Z",
            policy: [],
          },
        ]
      : [];
    const ep = [wp ? "/wp-json/wp/v2/users" : "/api/v1/feedback", "/api/v1/tariffs", "/ajax/search.php"].map(
      (u, i) => ({
        url: `https://${dom}${u}`,
        kind: "api",
        method: i === 0 ? "GET" : null,
        source: "fetch",
        host: dom,
      }),
    );
    const secrets = R.chance(0.5)
      ? [
          {
            kind: "google_api_key",
            title: "Ключ Google API",
            mask: "AIza…Q4",
            source: `https://${dom}/js/app.min.js`,
            line: 1,
            sev: "warn",
            host: dom,
          },
        ]
      : [];
    const bname = dom.split(".")[0] + "-docs";
    const buckets = R.chance(0.6)
      ? [
          {
            provider: "aws_s3",
            label: "Amazon S3",
            name: bname,
            url: `https://${bname}.s3.amazonaws.com/?max-keys=50`,
            status: lvl === "active" ? "closed" : "unchecked",
            keys: null,
            sources: [`https://${dom}/`],
          },
        ]
      : [];
    const blocked = R.chance(0.5);
    const code = blocked
      ? null
      : {
          query: dom,
          total: 2,
          hits: [
            {
              repo: "dev-ua/landing-themes",
              path: "config/sites.yml",
              url: `https://github.com/dev-ua/landing-themes/blob/main/config/sites.yml`,
              matches: 1,
              lines: [{ line: 14, text: `  - host: ${dom}` }],
            },
            {
              repo: "ivan-k/scrapers",
              path: "tenders/sources.py",
              url: "https://github.com/ivan-k/scrapers/blob/master/tenders/sources.py",
              matches: 1,
              lines: [{ line: 7, text: `BASE = "https://${dom}/tenders/"` }],
            },
          ],
        };
    return {
      at: site.at,
      scan: last.id,
      level: lvl,
      sources: {
        recon: { status: "ok", n: tech.length, error: null },
        webaudit: { status: "ok", n: 0, error: null },
        wellknown: { status: "ok", n: hidden.length + sm.length + sec.length, error: null },
        buckets: { status: "ok", n: buckets.length, error: null },
        grepapp: blocked
          ? { status: "blocked", n: null, error: "защита от ботов (челлендж grep.app)" }
          : { status: "ok", n: 2, error: null },
      },
      sites: [site],
      web: [webAuditOf(dom, lvl)],
      tech,
      analytics: [
        { kind: "ga4", id: "G-" + (hash(dom) >>> 0).toString(36).toUpperCase().slice(0, 8), host: dom },
      ].concat(
        R.chance(0.5)
          ? [{ kind: "yandex-metrika", id: String(80000000 + R.int(0, 9999999)), host: dom }]
          : [],
      ),
      hidden_paths: hidden,
      sitemap: sm,
      sitemap_total: sm.length,
      security: sec,
      endpoints: ep,
      endpoints_total: ep.length,
      secrets,
      buckets,
      code,
    };
  }
  const cmpVer = (a, b) => {
    const p = s =>
      String(s)
        .split(".")
        .map(x => parseInt(x, 10) || 0);
    const x = p(a),
      y = p(b);
    for (let i = 0; i < Math.max(x.length, y.length); i++) {
      if ((x[i] || 0) !== (y[i] || 0)) return (x[i] || 0) - (y[i] || 0);
    }
    return 0;
  };

  function finishProject(st, spec, settings) {
    st.project = {
      id: spec.id,
      name: spec.name,
      client: spec.client,
      domain: spec.domain || spec.name,
      created_at: spec.created_at,
      archived: false,
      notes: "",
    };
    st.scope = { client: spec.client, ...clone(spec.scope) };
    st.hosts = st.hosts || [];
    st.hosts.forEach(h => {
      h.sev = hostSev(st, h);
      h.internal = !!h.internal;
    });
    deriveNet(st, spec);
    st.events = deriveEvents(st);
    st.recon = reconOf(st, spec, rng((spec.seed || 1) + 77));
    buildScans(st, spec, settings);
    st.reports = clone(spec.reports || []);
    st.reports.forEach(r => {
      r.result = reportResult(st, { ...r.opts, fmt: r.fmt });
    }); // Result snapshot for the generated history as well.
    st.patterns = st.patterns || [];
    delete st.all_people_tmp;
    return st;
  }

  function defaultSettings() {
    return {
      net: {
        proxy_on: true,
        preset: "orbot",
        type: "socks5",
        addr: "127.0.0.1:9050",
        label: "Orbot (Tor)",
        orbot: true,
        groups: { search: "", recon: "", target: "" },
        out_ip: "198.51.100.200",
        out_country: "Германия",
        kill_switch: true,
        kill_action: "stop",
        ua: "chrome",
        threads: 8,
        rps: 10,
        timeout: 15,
        retries: 2,
        dns: "system",
        dns_custom: "9.9.9.9",
        hosts_parallel: 4,
      },
      keys: {
        brave: { status: "ok", mask: "BSAq…ab12", used: 1840, limit: 2000 },
        searx: { status: "ok", mask: "https://searx.local:8888", used: 0, limit: 0, kind: "url" },
        shodan: { status: "ok", mask: "Kx9f…c8e4", used: 61, limit: 100 },
        hibp: { status: "ok", mask: "a91c…77d0", used: 14, limit: 0 },
        vt: { status: "error", mask: "4b1e…10", error: "401 Unauthorized: ключ отозван" },
        st: { status: "ok", mask: "Y3pR…9f0", used: 22, limit: 50 },
        urlscan: { status: "none", mask: "" },
        censys: { status: "none", mask: "" },
        github: { status: "ok", mask: "ghp_Wm…Nn33", used: 312, limit: 5000, per: "ч" },
        otx: { status: "none", mask: "" },
        ai: { status: "ok", mask: "sk-ds-…0xV5", used: 0, limit: 0, note: "DeepSeek · баланс $4,20" },
        tg_bot: { status: "none", mask: "" },
        webhook: { status: "none", mask: "", kind: "url" },
      },
      power: {
        wifi_only: true,
        lim_on: true,
        mob_limit: 1000,
        batt_on: true,
        batt: 20,
        batt_action: "pause",
        heat: true,
        charge_only: false,
        period: "month",
        auto_resume: true,
      },
      sec: {
        // Fresh install: no PIN yet, so neither the PIN lock nor biometrics are on.
        pin: false,
        bio: false,
        autolock: "5",
        hide: true,
        clip: true,
        panic: false,
        autodel: true,
        autodel_days: "30",
      },
      work_hours: { from: 8, to: 19, tz: "UTC+2" },
      debug: { level: "info" },
      fuzz: {
        modules: ["docs", "backups", "exposed", "dirlisting"],
        rate: 5,
        threads: 4,
        max_requests: 3000,
        max_time_min: 20,
        max_hosts: 3,
        exclude_paths: [],
        wordlists: [],
        follow_redirects: false,
        show_paths: false,
      },
      ports: { top: 100, list: "", max_hosts: 20, banners: true },
      // Secondary-screen state persisted with the demo data: plugins are global, monitoring is per project.
      plugins: {},
      monitor: {},
      monitor_status: {},
      alerts: {
        enabled: false,
        min_severity: "warn",
        rules: {
          new_host: true,
          new_port: true,
          doc_secret: true,
          doc_pii: true,
          doc_gps: true,
          tls_expiry: true,
          dangling_cname: true,
          ct_new_cert: true,
          risk_rise: true,
        },
        tls_warn_days: 30,
        tls_crit_days: 14,
        risk_threshold: 70,
        risk_delta: 15,
        risky_ports: [21, 23, 445, 1433, 2375, 3306, 3389, 5432, 5900, 6379, 9200, 11211, 27017],
        max_alerts: 50,
        telegram: { enabled: false, chat_id: "" },
        webhook: { enabled: false, kind: "generic" },
        lang: "auto",
      },
      ocr: {
        enabled: false,
        max_pages: 10,
        max_mb: 15,
      },
      recon: {
        screenshots: false,
      },
      ai: {
        provider: "deepseek",
        model: "",
        base_url: "",
        thinking: "auto",
        thinking_budget: 0,
        max_tokens: 0,
        temperature: null,
        show_thoughts: false,
        redact: { secrets: true, pii: true, client: true, evid: false },
      },
      lang: "auto",
      last_project: "contoso",
    };
  }

  // ================= English demo data =================
  // The demo company and its documents are Ukrainian. When the demo state is generated for an English
  // UI, data written in Ukrainian (people, roles, document titles and file names, folders, places,
  // company names) is replaced by English names or a Latin transliteration, so the English UI shows
  // no Cyrillic data. Texts that the UI translates itself (finding texts, core labels) stay as they are.
  const DEMO_EN_PHRASES = {
    // Companies and contacts.
    "ТОВ «Контосо Енерджі»": "Contoso Energy LLC",
    "ПрАТ «Приклад Логістик»": "Example Logistics PJSC",
    "Мережа клінік «Приклад Мед»": "Example Med clinics",
    "ТОВ «Приклад Агро»": "Example Agro LLC",
    "ПАТ «Приклад Сталь»": "Example Steel PJSC",
    "ТОВ Енергобуд": "Energobud LLC",
    "ІТ-директор": "IT director",
    // Roles and departments.
    "ІТ-відділ": "IT",
    Бухгалтерія: "Accounting",
    Службова: "Service account",
    Маркетинг: "Marketing",
    Юридичний: "Legal",
    Інженерія: "Engineering",
    Продажі: "Sales",
    Закупівлі: "Procurement",
    Енергетика: "Energy",
    Фінанси: "Finance",
    Логістика: "Logistics",
    "Медичний персонал": "Medical staff",
    "відділ продажів": "sales department",
    // Document titles (file names use the same words with underscores).
    "Договір постачання": "Supply contract",
    "Перелік обладнання": "Equipment list",
    "Онбординг нових співробітників": "New employee onboarding",
    "Технічні умови підключення": "Connection specifications",
    "Службова записка": "Internal memo",
    "Звіт по споживанню": "Consumption report",
    "Фінансова звітність": "Financial statements",
    "Положення про закупівлі": "Procurement policy",
    "Політика конфіденційності": "Privacy policy",
    "Протокол засідання": "Meeting minutes",
    "Статут підприємства": "Company charter",
    "Тендерна документація": "Tender documents",
    "Річний звіт": "Annual report",
    "Лист-відповідь": "Reply letter",
    "Презентація для інвесторів": "Investor presentation",
    "Акт виконаних робіт": "Certificate of completed works",
    "Прайс-лист послуг": "Service price list",
    "Наказ про відпустку": "Leave order",
    "Кошторис ремонту": "Repair estimate",
    "Звіт про сталий розвиток": "Sustainability report",
    Тарифи: "Tariffs",
    "Інструкція з охорони праці": "Workplace safety manual",
    "Реєстр лічильників": "Meter register",
    "Заявка на підключення": "Connection request",
    "Графік відключень": "Outage schedule",
    "Шаблон комерційної пропозиції": "Sales proposal template",
    Стратегія: "Strategy",
    "Типовий договір": "Standard contract",
    "Тендер ТЕС-2, уточнення": "TPP-2 tender, clarification",
    "Нарада ТЕС-2: графік робіт": "TPP-2 meeting: work schedule",
    "Контакти відділу продажів": "Sales contacts",
    "Тендер ТЕС-2: додатки": "TPP-2 tender: annexes",
    "Сертифікат відповідності": "Certificate of conformity",
    "Графік змін": "Shift schedule",
    "Звіт по продажах": "Sales report",
    "Реєстр клієнтів": "Client register",
    "Прайс-лист": "Price list",
    "Договір про надання послуг": "Service agreement",
    "Тарифна сітка": "Rate table",
    "Навчання персоналу": "Staff training",
    "Презентація компанії": "Company presentation",
    "Положення про відділ": "Department regulations",
    "Реєстр рахунків": "Invoice register",
    "Тендерна пропозиція": "Tender bid",
    "Інструкція для клієнтів": "Client instructions",
    "Шаблон заяви": "Application template",
    Бюджет: "Budget",
    Наказ: "Order",
    Звіт_пентест: "Pentest_report",
    Сводка_для_директора: "Summary_for_director",
    // Folders and places.
    Шаблони: "Templates",
    Накази: "Orders",
    Звіти: "Reports",
    Податкова: "Tax",
    Презентації: "Presentations",
    Підключення: "Connections",
    Договори: "Contracts",
    Обладнання: "Equipment",
    "ТЕС-2": "TPP-2",
    КД: "Design",
    ІТ: "IT",
    "Кривий Ріг, промзона": "Kryvyi Rih, industrial zone",
    "головний офіс": "head office",
    філія: "branch",
    склад: "warehouse",
    термінал: "terminal",
    лабораторія: "laboratory",
    "клініка на Подолі": "Podil clinic",
    елеватор: "grain elevator",
    промзона: "industrial zone",
    Тестович: "Testovych",
    Ірина: "Iryna",
    Київ: "Kyiv",
    Львів: "Lviv",
    Харків: "Kharkiv",
    Бориспіль: "Boryspil",
    Борщагівка: "Borshchahivka",
    Чернігів: "Chernihiv",
    Реєстратура: "Reception",
    "Головний енергетик": "Chief power engineer",
    "Тендер_ТЕС-2_уточнення": "TPP-2_tender_clarification",
    "Нарада_ТЕС-2_графік": "TPP-2_meeting_schedule",
    "Тендер_ТЕС-2_додатки": "TPP-2_tender_annexes",
    "Пароль від порталу": "Portal password",
    "Лист CISO від": "CISO letter of",
    "«Интеграція»": "«Integration»",
    "Біла Церква": "Bila Tserkva",
    Одеса: "Odesa",
    Житомир: "Zhytomyr",
    "ПС-110": "substation 110",
    Склад: "Warehouse",
    // Tracked changes in the demo contract.
    "Ціна договору становить": "Contract price is",
    грн: "UAH",
    "узгодити знижку з": "agree a discount with",
    "Реквізити рахунку взяти з 1С, не з минулого договору":
      "Take the account details from 1C, not from the previous contract",
    "Відповідальна особа: тел.": "Contact person: tel.",
    "перевірити перед публікацією": "check before publishing",
  };
  // Whole values only: these words also occur in Russian texts that the UI translates.
  const DEMO_EN_EXACT = { МФУ: "MFP" };
  const DEMO_TRANSLIT = {
    а: "a",
    б: "b",
    в: "v",
    г: "h",
    ґ: "g",
    д: "d",
    е: "e",
    є: "ie",
    ж: "zh",
    з: "z",
    и: "y",
    і: "i",
    ї: "i",
    й: "i",
    к: "k",
    л: "l",
    м: "m",
    н: "n",
    о: "o",
    п: "p",
    р: "r",
    с: "s",
    т: "t",
    у: "u",
    ф: "f",
    х: "kh",
    ц: "ts",
    ч: "ch",
    ш: "sh",
    щ: "shch",
    ь: "",
    ю: "iu",
    я: "ia",
    ы: "y",
    э: "e",
    ъ: "",
    ё: "io",
    "'": "",
    ʼ: "",
    "’": "",
  };
  // Ukrainian national transliteration (2010): word-initial є/ї/й/ю/я become ye/yi/y/yu/ya, зг becomes zgh.
  const demoTranslit = word => {
    let out = "";
    const low = word.toLowerCase();
    for (let i = 0; i < low.length; i++) {
      const ch = low[i];
      let t = DEMO_TRANSLIT[ch];
      if (t === undefined) t = ch;
      if (i === 0 || !/[\u0400-\u04ff]/.test(low[i - 1]))
        t = { є: "ye", ї: "yi", й: "y", ю: "yu", я: "ya" }[ch] || t;
      if (ch === "г" && low[i - 1] === "з") t = "gh";
      if (word[i] !== low[i] && t) t = t[0].toUpperCase() + t.slice(1);
      out += t;
    }
    return out;
  };
  const demoRegEsc = x => x.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  // Rewrites Ukrainian data in any value (strings, arrays, objects, keys). Built once: names come from
  // the name lists and the project specs, not from the state, so it also works on a reloaded state.
  let demoEnWalk = null;
  function demoEnLatinizer() {
    if (demoEnWalk) return demoEnWalk;
    const map = new Map();
    const add = (from, to) => {
      if (map.has(from)) return;
      map.set(from, to);
      if (from.includes(" ")) map.set(from.replace(/ /g, "_"), to.replace(/ /g, "_"));
    };
    for (const [k, v] of Object.entries(DEMO_EN_PHRASES)) add(k, v);
    const names = [...FIRST, ...LAST.flat()];
    for (const sp of [CONTOSO, ...SMALL])
      for (const x of [...(sp.people || []), ...(sp.text_people || [])]) if (x && x.name) names.push(x.name);
    for (const n of names)
      if (/[\u0400-\u04ff]/.test(n))
        for (const part of [n, ...n.split(/\s+/)]) add(part, part.split(/\s+/).map(demoTranslit).join(" "));
    const keys = [...map.keys()].sort((a, b) => b.length - a.length);
    const re = new RegExp(`(?<![\\p{L}])(?:${keys.map(demoRegEsc).join("|")})(?![\\p{L}])`, "gu");
    // Quoted document text inside evidence stays as written: it is what the document says.
    const fix = str => DEMO_EN_EXACT[str] || str.replace(re, m => map.get(m));
    const walk = v => {
      if (typeof v === "string") return /[\u0400-\u04ff]/.test(v) ? fix(v) : v;
      if (Array.isArray(v)) return v.map(walk);
      if (v && typeof v === "object") {
        const o = {};
        for (const k of Object.keys(v)) o[/[\u0400-\u04ff]/.test(k) ? fix(k) : k] = walk(v[k]);
        return o;
      }
      return v;
    };
    return (demoEnWalk = walk);
  }
  function latinizeDemoData(projects) {
    const walk = demoEnLatinizer();
    for (const id of Object.keys(projects)) projects[id] = walk(projects[id]);
    return projects;
  }
  // Results built at call time from the static tables (doc_get forensics, document text) need the same
  // rewrite; tables keyed by the Ukrainian file name are looked up through the rewritten name.
  const demoEnData = () => load().data_lang === "en";
  const demoEnOut = v => (demoEnData() ? demoEnLatinizer()(v) : v);
  const demoByName = (table, name) => {
    if (table[name] || !demoEnData()) return table[name];
    const walk = demoEnLatinizer();
    const k = Object.keys(table).find(x => walk(x) === name);
    return k ? table[k] : undefined;
  };
  // Language of the generated demo data: the explicit setting, else the device locale.
  const demoDataLang = settings =>
    demoResolveLang(
      settings.lang ?? "auto",
      demoDeviceLocale || (typeof navigator !== "undefined" && navigator.language) || "uk",
    ).lang;

  function generate() {
    const settings = defaultSettings();
    const projects = {};
    projects.contoso = buildContoso(settings);
    SMALL.forEach(s => {
      projects[s.id] = buildSmall(clone(s), settings);
    });
    const en = demoDataLang(settings) === "en";
    if (en) latinizeDemoData(projects);
    const st = {
      v: GEN_VERSION,
      settings,
      projects,
      order: ["contoso", ...SMALL.map(s => s.id)],
      next_id: 1,
    };
    if (en) st.data_lang = "en";
    return st;
  }

  // ================= state and storage =================
  const store = (() => {
    try {
      return root.localStorage || null;
    } catch (e) {
      return null;
    }
  })();
  let STATE = null;
  // Demo Debug log: startup, stages of the latest scan, source warnings, Android.
  function demoLogs() {
    if (load().logs_cleared) return [];
    const L = [];
    let id = 1;
    const add = (t, level, target, msg, source = "core") =>
      L.push({ id: id++, t: `2026-11-20T${t}`, level, target, msg, source });
    add("11:58:02.114", "info", "foca::engine", "движок открыт: /data/user/0/app.sinon.focars/files");
    add("11:58:02.120", "info", "android/main", "MainActivity.onCreate (холодный старт)", "android");
    add(
      "11:58:02.301",
      "debug",
      "android/main",
      "DeviceMonitor: Wi-Fi, батарея 78 %, зарядка нет",
      "android",
    );
    add(
      "12:00:00.004",
      "info",
      "foca::scan",
      "скан contoso-s4: профиль «Стандартный», цели: contoso.example",
    );
    add("12:00:00.010", "info", "foca::scan", "этап search: старт, 4 источника");
    add(
      "12:00:03.882",
      "debug",
      "foca_net",
      "GET https://crt.sh/?q=%25.contoso.example&output=json → 200, 47 КБ, 3,8 с",
    );
    add(
      "12:00:41.520",
      "warn",
      "foca_search::wayback",
      "web.archive.org: 504 Gateway Timeout, повтор 1 из 2",
    );
    add("12:01:30.003", "warn", "foca_search::cc", "index.commoncrawl.org: таймаут 90 с, источник пропущен");
    add("12:01:30.010", "info", "foca::scan", "этап search: 90 с, найдено 212 ссылок");
    add("12:01:31.200", "info", "foca::scan", "этап download: 118 документов в очереди");
    add(
      "12:04:12.877",
      "error",
      "foca_meta::pdf",
      "Положение_про_ЕДО.pdf: битая таблица xref, разобрано частично",
    );
    add("12:06:40.115", "info", "foca::scan", "этап analysis: 342 документа, 25 находок, 3 секрета");
    add("12:06:41.002", "info", "android/main", "ScanService: уведомление обновлено (88 %)", "android");
    add("12:07:02.540", "info", "foca::scan", "скан завершён за 7 мин 2 с");
    return L;
  }
  function load() {
    if (STATE) return STATE;
    try {
      const raw = store && store.getItem(STORE_KEY);
      if (raw) {
        const s = JSON.parse(raw);
        if (s && s.v === GEN_VERSION) STATE = s;
      }
    } catch (e) {}
    if (!STATE) STATE = generate();
    else if (STATE.run) recoverRun(); // The app restarted during a scan.
    // Demo: terms already accepted (older QA scenarios); "First run" in the demo menu resets this (null).
    if (STATE.terms === undefined) STATE.terms = { terms_version: "1", accepted_at: "2026-11-01T10:00:00" };
    return STATE;
  }
  let saveT = null;
  function save() {
    if (!store) return;
    clearTimeout(saveT);
    saveT = setTimeout(() => {
      try {
        store.setItem(STORE_KEY, JSON.stringify(STATE));
      } catch (e) {}
    }, 50);
  }
  const P = id => {
    const p = load().projects[id];
    if (!p) throw apiErr("not_found", `Проект ${id} не найден`);
    return p;
  };
  const apiErr = (code, message, msg) => {
    const e = new Error(message);
    e.code = code;
    // Like CmdError.message_msg: the UI shows the message in its language (api.js toErr).
    if (msg) e.message_msg = msg;
    return e;
  };
  // Core message of a host found in documents (dto.rs: "Хост в документах ({source})").
  const docWhyMsg = {
    code: "oos.doc_why",
    params: { source: { code: "oos.doc_meta", params: {}, text: "метаданные" } },
  };

  // ================= backend selectors (same rule as F.sel) =================
  // Like the core: an offline import (documents, no scan) is assessed too.
  const riskOf = st => {
    const imported = !st.scans.length && st.docs.some(x => !x.deleted);
    return imported || (st.scans.length && RULES().analyzedScans(st.scans))
      ? RULES().riskScore(st.findings)
      : null;
  };
  const summary = st => {
    const last = st.scans[st.scans.length - 1];
    return {
      id: st.project.id,
      name: st.project.name,
      client: st.project.client,
      created_at: st.project.created_at,
      archived: !!st.project.archived,
      last_scan_at: last ? last.finished_at : null,
      last_profile: last ? last.profile : null,
      scans: st.scans.length,
      docs: st.docs.filter(d => !d.deleted).length,
      findings: st.findings.filter(f => f.status !== "false" && f.status !== "fixed").length,
      risk: riskOf(st),
      scanning: !!(RUN && RUN.project === st.project.id),
      progress: RUN && RUN.project === st.project.id ? RUN.progress : 0,
      reference: !!st.project.reference,
    };
  };

  // Scope: ONE rule, FOCA_RULES.scope from ui/js/sel.js (matches crates/foca-core/src/scope.rs). No local
  // copy here.
  const RULES = () => {
    const r = root.FOCA_RULES;
    if (!r) throw apiErr("not_ready", "Правила FOCA_RULES не загружены (ui/js/sel.js)");
    return r;
  };
  const ip4 = s => {
    const m = String(s).match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/);
    return m ? ((+m[1] << 24) >>> 0) + (+m[2] << 16) + (+m[3] << 8) + +m[4] : null;
  }; // Address parsing for the generator (ASN, DNS).
  const scopeCheck = (scope, host, hosts) => RULES().scope.check(scope, host, { hosts: hosts || [] });

  // ================= out-of-scope candidates (derived from project data, decisions in st.oos_dec)

  // ================= analytics: insights_get / chain_get (docs/API.md → "Аналитика") =================
  // Derived from the snapshot like the core does from stored documents: org chart from people's roles, internal
  // network map from internal hosts/PCs/printers, KEV from EOL software, chronology and a 7×24 activity grid
  // from document dates, a clustered graph view with layer filters, and BFS link chains.
  const DEPT_RX = [
    ["finance", /бухгалт|фінанс|финанс|buh|finance/i],
    ["hr", /кадр|персонал|hr\b/i],
    ["legal", /юрид|legal/i],
    ["it", /\bit\b|айті|ит-|інформ|информ/i],
    ["engineering", /інженер|инженер|проект|eng/i],
    ["management", /директ|керів|руковод|management/i],
  ];
  function graphOf(snap) {
    const nodes = [],
      edges = [];
    const add = (id, kind, label) => nodes.find(n => n.id === id) || nodes.push({ id, kind, label });
    snap.people.forEach(p => add("person:" + p.login, "person", p.name || p.login));
    snap.pcs.forEach(p => {
      add("pc:" + p.name, "pc", p.name);
      (p.users || []).forEach(u => edges.push({ from: "person:" + u, to: "pc:" + p.name, kind: "uses_pc" }));
    });
    snap.hosts
      .filter(h => h.internal)
      .forEach(h => {
        add("host:" + h.name, "host", h.name);
        edges.push({ from: "host:" + h.name, to: "domain:corp", kind: "member_of" });
      });
    if (nodes.some(n => n.kind === "host")) add("domain:corp", "domain", "corp");
    snap.printers.forEach(p => {
      add("printer:" + p.name, "printer", p.name);
      if (p.host && nodes.some(n => n.id === "host:" + p.host))
        edges.push({ from: "printer:" + p.name, to: "host:" + p.host, kind: "on_host" });
    });
    snap.docs
      .filter(d => !d.deleted && d.status === "analyzed")
      .slice(0, 120)
      .forEach(d => {
        add("doc:" + d.id, "doc", d.name);
        if (d.author) edges.push({ from: "person:" + d.author, to: "doc:" + d.id, kind: "author" });
        if (d.printer) edges.push({ from: "doc:" + d.id, to: "printer:" + d.printer, kind: "printed_on" });
      });
    const ids = new Set(nodes.map(n => n.id));
    return { nodes, edges: edges.filter(e => ids.has(e.from) && ids.has(e.to)) };
  }
  const LAYER_OF = k =>
    k === "person" || k === "email"
      ? "people"
      : k === "doc"
        ? "docs"
        : k === "pc"
          ? "pcs"
          : k === "host" || k === "printer" || k === "share"
            ? "servers"
            : k === "domain" || k === "forest" || k === "pki"
              ? "pki_domains"
              : "software";
  function graphView(g, layers, minGroup) {
    const layer_counts = { people: 0, docs: 0, pcs: 0, servers: 0, pki_domains: 0, software: 0 };
    g.nodes.forEach(n => layer_counts[LAYER_OF(n.kind)]++);
    const vis = g.nodes.filter(n => layers.includes(LAYER_OF(n.kind)));
    const nodes = [],
      map = {};
    const byKind = {};
    vis.forEach(n => (byKind[n.kind] = byKind[n.kind] || []).push(n));
    Object.entries(byKind).forEach(([k, list]) => {
      // leaves with one link collapse into a group node of their kind
      const deg = id => g.edges.filter(e => e.from === id || e.to === id).length;
      const leaves = list.filter(n => deg(n.id) <= 1);
      if (leaves.length >= minGroup) {
        const id = "group:" + k;
        nodes.push({
          id,
          kind: k,
          label: k,
          layer: LAYER_OF(k),
          count: leaves.length,
          members: leaves.map(n => n.id),
        });
        leaves.forEach(n => (map[n.id] = id));
      }
      list
        .filter(n => !map[n.id])
        .forEach(n => {
          nodes.push({
            id: n.id,
            kind: n.kind,
            label: n.label,
            layer: LAYER_OF(n.kind),
            count: 1,
            members: [],
          });
          map[n.id] = n.id;
        });
    });
    const w = {};
    g.edges.forEach(e => {
      const a = map[e.from],
        b = map[e.to];
      if (!a || !b || a === b) return;
      const key = a + "|" + b + "|" + e.kind;
      (w[key] = w[key] || { from: a, to: b, kind: e.kind, weight: 0 }).weight++;
    });
    return { nodes, edges: Object.values(w), layer_counts, hidden: g.nodes.length - vis.length };
  }
  function insightsOf(id, a) {
    const snap = snapshot(id);
    const layers = Array.isArray(a.layers) ? a.layers : ["people", "docs", "pcs", "servers", "pki_domains"];
    const minGroup = Math.max(2, +a.min_group || 3);
    const people = snap.people.map(p => {
      const d = DEPT_RX.find(([, rx]) => rx.test(p.role || ""));
      return {
        login: p.login,
        name: p.name,
        roles: { author: p.docs || 0 },
        primary_role: "author",
        title: null,
        department: d ? "dept:" + d[0] : null,
        dept_confidence: d ? 70 : 0,
        organizations: [],
      };
    });
    const departments = DEPT_RX.map(([key]) => ({
      id: "dept:" + key,
      key,
      labels: [key],
      known: true,
      members: people
        .filter(p => p.department === "dept:" + key)
        .map(p => ({
          login: p.login,
          confidence: 70,
          evidence: [{ source: "local_path", value: p.login, doc: 1, weight: 70 }],
        })),
      candidates: [],
      docs: [1],
      confidence: 70,
    })).filter(d => d.members.length);
    const internal = snap.hosts.filter(h => h.internal);
    const netNodes = [];
    // Network map from the project data: servers by role (internal hosts and server PCs), workstations, their
    // users; every node cites the first document that mentions it (folder, printer or author).
    const docMention = name =>
      snap.docs.find(
        d => !d.deleted && ((d.folder || "").includes(name) || (d.printer || "").includes(name)),
      );
    const roleOfHost = (name, role) =>
      /prn|print|принт/i.test(name + role)
        ? ["print"]
        : /ts\d|термин/i.test(name + role)
          ? ["rdp"]
          : /sql|субд|db/i.test(name + role)
            ? ["db"]
            : /mail/i.test(name + role)
              ? ["mail"]
              : /^dc\d|контроллер/i.test(name + role)
                ? ["dc"]
                : ["file"];
    const servers = [
      ...internal.map(h => ({ name: h.name, role: h.role || "" })),
      ...snap.pcs
        .filter(p => p.kind === "server" && !internal.some(h => h.name === p.name) && !/^MFP/i.test(p.name))
        .map(p => ({ name: p.name, role: "" })),
    ];
    if (servers.length || snap.pcs.length)
      netNodes.push({
        id: "domain:corp",
        kind: "domain",
        label: "corp",
        fqdn: "corp.contoso.local",
        roles: [],
        shares: [],
        printers: [],
        parent: null,
        confidence: 60,
        sources: [{ kind: "unc", value: "\\\\corp\\dfs", doc: 1 }],
        docs: [1],
      });
    servers.forEach(h => {
      const d = docMention(h.name);
      netNodes.push({
        id: "host:" + h.name,
        kind: "server",
        label: h.name,
        fqdn: null,
        roles: roleOfHost(h.name, h.role),
        shares: snap.docs
          .filter(x => (x.folder || "").startsWith("\\\\" + h.name + "\\"))
          .map(x => x.folder.split("\\").slice(0, 4).join("\\"))
          .filter((v, i, l) => l.indexOf(v) === i)
          .slice(0, 4),
        printers: snap.printers.filter(p => p.host === h.name).map(p => p.name),
        parent: "domain:corp",
        confidence: d ? 75 : 55,
        sources: d
          ? [
              {
                kind: (d.printer || "").includes(h.name) ? "printer" : "unc",
                value: (d.printer || "").includes(h.name) ? d.printer : d.folder,
                doc: d.id,
              },
            ]
          : [{ kind: "meta", value: h.name, doc: null }],
        docs: d ? [d.id] : [],
      });
    });
    snap.pcs
      .filter(p => p.kind !== "server")
      .forEach(p => {
        const owner = snap.people.find(x => x.pc === p.name);
        const d = owner && snap.docs.find(x => !x.deleted && x.author === owner.login);
        netNodes.push({
          id: "pc:" + p.name,
          kind: "workstation",
          label: p.name,
          fqdn: null,
          roles: [],
          shares: [],
          printers: [],
          parent: "domain:corp",
          confidence: 60,
          sources: d
            ? [{ kind: "meta", value: p.name, doc: d.id }]
            : [{ kind: "lnk", value: p.name, doc: null }],
          docs: d ? [d.id] : [],
        });
        snap.people
          .filter(x => x.pc === p.name)
          .forEach(u =>
            netNodes.push({
              id: "user:" + u.login,
              kind: "user",
              label: u.name + " (" + u.login + ")",
              fqdn: null,
              roles: [],
              shares: [],
              printers: [],
              parent: "pc:" + p.name,
              confidence: 70,
              sources: d ? [{ kind: "meta", value: "CORP\\" + u.login, doc: d.id }] : [],
              docs: d ? [d.id] : [],
            }),
          );
      });
    // Lineage: versions "<name>_vN" of one document (xmpMM:DerivedFrom of the previous version).
    const base = n => n.replace(/_v\d+(\.[^.]+)$/, "$1");
    const groups = new Map();
    snap.docs
      .filter(d => !d.deleted)
      .forEach(d => {
        const k = base(d.name);
        if (!groups.has(k)) groups.set(k, []);
        groups.get(k).push(d);
      });
    const verOf = d => +(d.name.match(/_v(\d+)\.[^.]+$/) || [0, 1])[1];
    const links = [],
      lineages = [];
    [...groups.values()]
      .filter(g => g.length > 1)
      .slice(0, 6)
      .forEach(g => {
        g.sort((x, y) => verOf(x) - verOf(y));
        for (let k = 1; k < g.length; k++)
          links.push({
            from: g[k].id,
            to: g[k - 1].id,
            kind: "derived_from",
            confidence: 85,
            basis: "xmp_derived_document",
            reason: `xmpMM:DerivedFrom указывает на «${g[k - 1].name}»`,
            evidence: ["xmp.did:" + (hash(g[0].name) >>> 0).toString(16)],
          });
        lineages.push({
          id: "lineage:" + Math.min(...g.map(x => x.id)),
          docs: g.map(x => x.id),
          root: g[0].id,
          basis: ["xmp_derived_document"],
          confidence: 85,
        });
      });
    // Anomalies: a later version whose XMP history starts before its own creation date (inherited from the
    // original), and the PDF dates of the first lineage root disagree with its XMP dates.
    const anomalies = [];
    lineages.forEach(l => {
      if (anomalies.length >= 2) return;
      const root = snap.docs.find(x => x.id === l.root),
        last = snap.docs.find(x => x.id === l.docs[l.docs.length - 1]);
      if (root && last && root.created_at && last.created_at && root.created_at < last.created_at)
        anomalies.push({
          doc: last.id,
          code: "history_before_created",
          sev: "info",
          confidence: 70,
          title: "История правок начинается раньше создания",
          detail: `История XMP с ${root.created_at.slice(0, 10)}, а документ создан ${last.created_at.slice(0, 10)}: файл унаследован от «${root.name}»`,
          fields: ["xmpMM:History", "created"],
        });
    });
    const pdfAnom = snap.docs.find(x => !x.deleted && x.ext === "pdf" && x.created_at && x.modified_at);
    if (pdfAnom)
      anomalies.push({
        doc: pdfAnom.id,
        code: "date_mismatch",
        sev: "low",
        confidence: 60,
        title: "Даты PDF и XMP расходятся",
        detail: `Info/CreationDate ${pdfAnom.created_at.replace("T", " ")}, xmp:CreateDate на 3 ч позже: файл пересохраняли или правили дату`,
        fields: ["created", "xmp:CreateDate"],
      });
    const kev = snap.software
      .filter(s => s.eol && (s.cves || []).length)
      .map(s => ({
        product_key: s.id,
        product_label: s.name,
        subject: {
          kind: "software",
          id: s.id,
          name: s.name,
          ver: s.ver || "",
          eol: true,
          eol_date: s.eol_date || null,
          docs: s.docs || 0,
        },
        total: s.cves.length,
        ransomware: 0,
        after_eol: 0,
        cves: s.cves.map(c => ({ cve: c[0], date_added: "2024-01-01", ransomware: false, name: s.name })),
        confidence: s.eol_date && s.eol_date < "2024-01-01" ? "likely" : "possible",
        score: s.eol_date && s.eol_date < "2024-01-01" ? 70 : 40,
        sev: "medium",
        title:
          (s.eol_date && s.eol_date < "2024-01-01" ? "Вероятно" : "Возможно") +
          " уязвимое ПО (CISA KEV): " +
          s.name +
          (s.eol_date && s.eol_date < "2024-01-01" ? "" : ": сверьте версию"),
        reason:
          s.eol_date && s.eol_date < "2024-01-01"
            ? `Версия снята с поддержки (${s.eol_date}): исправления больше не выходят.`
            : `KEV не указывает уязвимые версии: сверьте версию ${s.name} с бюллетенями производителя.`,
      }));
    const matrix = Array.from({ length: 7 }, () => Array(24).fill(0));
    const timeline = [];
    let total = 0,
      ooh = 0;
    snap.docs
      .filter(d => !d.deleted)
      .forEach(d => {
        const t = d.created_at || d.modified_at;
        const m = typeof t === "string" && t.match(/^(\d{4})-(\d\d)-(\d\d)T(\d\d)/);
        if (!m) return;
        timeline.push({ lane: "documents", year: +m[1], label: (d.ext || "?").toUpperCase() });
        const wd = (new Date(Date.UTC(+m[1], +m[2] - 1, +m[3])).getUTCDay() + 6) % 7,
          h = +m[4];
        matrix[wd][h]++;
        total++;
        if (h < 8 || h >= 19 || wd >= 5) ooh++;
      });
    // Software lane: years in which documents made with each program appear; CT lane: first certificate per host.
    snap.software.forEach(sw => {
      const years = new Set(
        snap.docs
          .filter(d => !d.deleted && d.software === sw.id && /^\d{4}/.test(d.created_at || ""))
          .map(d => +d.created_at.slice(0, 4)),
      );
      [...years].sort().forEach(y => timeline.push({ lane: "software", year: y, label: sw.name }));
    });
    const ct = (() => {
      try {
        return (infraOf(P(id)).ct || []).flatMap(c => c.timeline || []);
      } catch (e) {
        return [];
      }
    })();
    ct.forEach(t => {
      if (t.first_seen)
        timeline.push({
          lane: "certificates",
          year: new Date(t.first_seen * 1000).getUTCFullYear(),
          label: t.host,
        });
    });
    const g = graphOf(snap);
    const attack_paths = attackPathsOf(id, snap);
    return {
      org: { organizations: [], departments, people },
      correlation: { links, lineages },
      anomalies,
      kev,
      netmap: { nodes: netNodes, links: [] },
      graph: graphView(g, layers, minGroup),
      layers,
      timeline,
      activity: {
        hours: Array.from({ length: 24 }, (_, h) => matrix.reduce((s, r) => s + r[h], 0)),
        weekdays: matrix.map(r => r.reduce((s, x) => s + x, 0)),
        matrix,
        total,
        out_of_hours: ooh,
        tz: "UTC+2",
        tz_counts: { "UTC+2": total },
      },
      attack_paths,
      counts: {
        departments: departments.length,
        people: people.length,
        lineages: lineages.length,
        links: links.length,
        anomalies: anomalies.length,
        kev: kev.length,
        net_nodes: netNodes.length,
        graph_nodes: g.nodes.length,
      },
    };
  }
  function attackPathsOf(id, preSnap) {
    const snap = preSnap || snapshot(id);
    const sevW = s =>
      s === "critical" ? 40 : s === "high" ? 30 : s === "medium" ? 20 : s === "low" ? 10 : 4;
    const leaks = (snap.findings || [])
      .filter(
        f =>
          /secret|password|remote-file|artifact\.|internal-paths|internal-addresses|lnk\./.test(
            f.rule || "",
          ) ||
          ((f.module === "secrets" || f.module === "forensics") &&
            (f.sev === "critical" || f.sev === "high")),
      )
      .sort((a, b) => sevW(b.sev) - sevW(a.sev) || a.id - b.id);
    const targets = (snap.findings || [])
      .filter(
        f =>
          f.rule === "sw.kev" ||
          /^(recon|port|tls|mail|infra)\./.test(f.rule || "") ||
          (f.cve && f.cve.length),
      )
      .sort((a, b) => sevW(b.sev) - sevW(a.sev) || a.id - b.id);
    const loginAnchor = ((snap.people || []).find(p => !p.service && p.login) || {}).login || null;
    const hostFallback = ((snap.hosts || []).find(h => h.name) || {}).name || "perimeter";
    const paths = [];
    leaks.slice(0, 5).forEach((lf, idx) => {
      const targetHost =
        lf.host && lf.host !== "-"
          ? lf.host
          : targets[0] && targets[0].host !== "-"
            ? targets[0].host
            : hostFallback;
      const vf = targets.find(t => t.host === targetHost) || targets[0] || null;
      const steps = [];
      const docObj = lf.doc ? (snap.docs || []).find(d => d.id === lf.doc && !d.deleted) : null;
      if (docObj) {
        steps.push({
          kind: "document",
          node_id: "doc:" + docObj.id,
          label: docObj.name,
          detail: `Документ (${docObj.ext}) на хосте ${docObj.host}`,
          finding_id: lf.id,
          doc_id: docObj.id,
          host: docObj.host,
        });
      }
      steps.push({
        kind: "credential",
        node_id: "finding:" + lf.id,
        label: lf.title,
        detail: lf.title,
        finding_id: lf.id,
        doc_id: lf.doc || null,
        host: targetHost,
      });
      if (loginAnchor) {
        steps.push({
          kind: "identity",
          node_id: "person:" + loginAnchor.toLowerCase(),
          label: "Логин/УЗ: " + loginAnchor,
          detail: "Корпоративная учётная запись / формат входа",
          finding_id: null,
          doc_id: lf.doc || null,
          host: null,
        });
      }
      steps.push({
        kind: vf ? "vulnerability" : "perimeter",
        node_id: "host:" + targetHost.toLowerCase(),
        label: targetHost,
        detail: vf ? vf.title : "Точка входа внешнего периметра",
        finding_id: vf ? vf.id : null,
        doc_id: null,
        host: targetHost,
      });
      const score = Math.min(
        99,
        sevW(lf.sev) + 15 + (vf ? Math.floor(sevW(vf.sev) / 2) + 12 : 0) + (loginAnchor ? 10 : 0),
      );
      const severity = score >= 85 ? "critical" : score >= 65 ? "high" : score >= 45 ? "medium" : "low";
      const likelihood = score >= 65 ? "high" : score >= 45 ? "medium" : "low";
      paths.push({
        id: "ap-" + (idx + 1),
        title: `${lf.title} → ${targetHost}`,
        severity,
        score,
        likelihood,
        target_host: targetHost,
        steps,
        finding_ids: vf && vf.id !== lf.id ? [lf.id, vf.id] : [lf.id],
        doc_ids: docObj ? [docObj.id] : [],
      });
    });
    const agg = new Map();
    paths.forEach((p, pIdx) => {
      p.steps.forEach(s => {
        if (!s.finding_id) return;
        const cur = agg.get(s.node_id) || {
          node_id: s.node_id,
          kind: s.kind,
          label: s.label,
          paths: new Set(),
          findings: new Set(),
          maxScore: 0,
        };
        cur.paths.add(pIdx);
        cur.findings.add(s.finding_id);
        cur.maxScore = Math.max(cur.maxScore, p.score);
        agg.set(s.node_id, cur);
      });
    });
    const choke_points = [...agg.values()]
      .map(a => ({
        node_id: a.node_id,
        kind: a.kind,
        label: a.label,
        paths_broken: a.paths.size,
        priority_score: Math.min(100, a.maxScore + Math.min(5, a.paths.size) * 5),
        recommendation:
          a.kind === "credential" || a.kind === "document"
            ? "Отозвать/сменить скомпрометированные учётные данные, удалить файл из открытого доступа и очистить метаданные."
            : "Установить обновления безопасности / закрыть лишние порты и усилить периметровую фильтрацию.",
        finding_ids: [...a.findings],
      }))
      .sort((a, b) => b.paths_broken - a.paths_broken || b.priority_score - a.priority_score)
      .slice(0, 5);
    return {
      paths,
      choke_points,
      summary: {
        total_paths: paths.length,
        critical_or_high: paths.filter(p => p.severity === "critical" || p.severity === "high").length,
        choke_points: choke_points.length,
        max_score: paths.length ? Math.max(...paths.map(p => p.score)) : 0,
      },
    };
  }
  const CHAIN_RANK = { forest: 6, domain: 5, host: 4, share: 3, printer: 3, pc: 2 };
  function chainOf(id, a) {
    const snap = snapshot(id);
    let start = a.node;
    if (!start) {
      const f = snap.findings.find(x => x.id === +(a.from_id ?? a.id));
      if (!f) throw { code: "not_found", message: "Находка " + (a.from_id ?? a.id) + " не найдена" };
      const d = f.doc || (f.rel && f.rel.docs && f.rel.docs[0]);
      start = d
        ? "doc:" + d
        : f.rel && f.rel.pcs && f.rel.pcs[0]
          ? "pc:" + f.rel.pcs[0]
          : f.rel && f.rel.people && f.rel.people[0]
            ? "person:" + f.rel.people[0]
            : "host:" + f.host;
    }
    const g = graphOf(snap);
    const node = idn => g.nodes.find(n => n.id === idn);
    const prev = { [start]: null },
      q = [start];
    while (q.length) {
      const cur = q.shift();
      g.edges.forEach(e => {
        const nx = e.from === cur ? e.to : e.to === cur ? e.from : null;
        if (nx && !(nx in prev)) {
          prev[nx] = { from: cur, via: e.kind, reverse: e.to === cur };
          q.push(nx);
        }
      });
    }
    const targets = Object.keys(prev)
      .filter(k => k !== start && CHAIN_RANK[(node(k) || {}).kind])
      .sort((x, y) => CHAIN_RANK[node(y).kind] - CHAIN_RANK[node(x).kind])
      .slice(0, Math.max(1, Math.min(10, +a.limit || 3)));
    const chains = targets.map(t => {
      const steps = [];
      for (let k = t; k; k = prev[k] && prev[k].from)
        steps.unshift({
          node: node(k),
          via: prev[k] ? prev[k].via : null,
          reverse: prev[k] ? prev[k].reverse : false,
        });
      return { steps, target_kind: node(t).kind, hops: steps.length - 1 };
    });
    return { start, found: !!node(start), chains };
  }

  // ================= infrastructure: infra_get records derived from the project's hosts =================
  // Same kinds and shapes as the core's `infra` table (docs/API.md → "Инфраструктура"). Records exist only
  // after a scan reached the network stage; the level decides what ran: names/SaaS/CT for any profile,
  // enumeration and certificates for the standard one, NSEC for the full one.
  const EMPTY_INFRA = () => ({
    saas: [],
    tenant: [],
    mail_policy: [],
    cert: [],
    ct: [],
    cdn: [],
    origin: [],
    role: [],
    ptr: [],
    dns_enum: [],
    oos: [],
  });
  // Host sources of the enumeration modules (snapshot hosts[].source).
  const ENUM_SRC = /^(bruteforce|permute|doc_token:|ptr|nsec|tls_san)/;
  const LVL = { external: 1, target: 2, active: 3 };
  function infraLevel(st, extra) {
    let lv = LVL[extra] || 0;
    (st.scans || []).forEach(s => {
      if (s.status !== "done") return;
      lv = Math.max(lv, s.active || s.profile_id === "full" ? 3 : s.profile_id === "passive" ? 1 : 2);
    });
    if (RUN && RUN.project === st.project.id && RUN.stage > STAGES.findIndex(x => x.id === "network"))
      lv = Math.max(lv, LVL[RUN.level] || 0);
    return lv;
  }
  const hexOf = (seed, n) => {
    let o = "",
      x = hash(seed) || 1;
    while (o.length < n) {
      x = (Math.imul(x, 1103515245) + 12345) >>> 0;
      o += x.toString(16).padStart(8, "0");
    }
    return o.slice(0, n).toUpperCase();
  };
  // Entra ID tenant id of a domain (stable, uuid format).
  function tenantId(dom) {
    const h = hexOf("tenant:" + dom, 32).toLowerCase();
    return `${h.slice(0, 8)}-${h.slice(8, 12)}-4${h.slice(13, 16)}-9${h.slice(17, 20)}-${h.slice(20, 32)}`;
  }
  const epochOf = d => Math.round(Date.parse(d + "T23:59:59Z") / 1000);
  const daysTo = d => Math.round((Date.parse(d + "T00:00:00Z") - Date.parse(TODAY + "T00:00:00Z")) / 864e5);
  const ISSUER_ORG = {
    "Let's Encrypt R11": ["Let's Encrypt", "http://r11.i.lencr.org/"],
    "Cloudflare Inc ECC CA-3": ["Cloudflare, Inc.", "http://cacerts.digicert.com/CloudflareIncECCCA-3.crt"],
    "Sectigo RSA Domain Validation Secure Server CA": [
      "Sectigo Limited",
      "http://crt.sectigo.com/SectigoRSADomainValidationSecureServerCA.crt",
    ],
    "GlobalSign GCC R3 DV TLS CA 2020": [
      "GlobalSign nv-sa",
      "http://secure.globalsign.com/cacert/gsgccr3dvtlsca2020.crt",
    ],
  };
  function infraOf(st, extra) {
    const out = EMPTY_INFRA();
    if (!st || !st.project || !(st.hosts || []).length) return out;
    const lv = infraLevel(st, extra);
    if (!lv) return out;
    const dom = st.project.domain || st.project.name,
      base = dom.split(".")[0];
    const ext = st.hosts.filter(h => !h.internal);
    const fnd = st.findings || [];
    const inScope = n => scopeCheck(st.scope, n, st.hosts).ok;
    const lastScan = (st.scans || []).filter(s => s.status === "done").slice(-1)[0] || {};
    const at = lastScan.finished_at || `${TODAY}T12:00:00`;
    const client = (st.scope && st.scope.client) || st.project.client || dom;
    // Roles and CDN labels: the same values as hosts[].roles/priority/cdn.
    ext
      .filter(h => (h.roles || []).length)
      .forEach(h => {
        const r = hostRoles(h.name, dom);
        const alive = (h.services || []).length > 0;
        const sev = !alive
          ? "info"
          : r.roles.some(x => x === "admin" || x === "database")
            ? "high"
            : r.roles.some(x => ["dev_stage", "remote_access", "vcs_ci", "monitoring", "storage"].includes(x))
              ? "warn"
              : "info";
        out.role.push({
          host: h.name,
          roles: r.roles,
          tags: r.tags,
          priority: r.priority,
          alive,
          severity: sev,
        });
      });
    ext.filter(h => h.cdn).forEach(h => out.cdn.push(clone(h.cdn)));
    // SaaS by TXT verification records; a Microsoft 365 tenant where the file host redirects to SharePoint or
    // an AD FS host exists.
    const fileHost = ext.find(h => h.role === "Файловый" && inScope(h.name));
    const sts = ext.find(h => h.source === "m365");
    const m365 = !!(fileHost || sts);
    const extra3 = [
      ["atlassian", "Atlassian", "collaboration", "atlassian-domain-verification="],
      ["docusign", "DocuSign", "docs", "docusign="],
      ["zoom", "Zoom", "collaboration", "ZOOM_verify_"],
      ["slack", "Slack", "collaboration", "slack-domain-verification="],
    ];
    const hits = [
      {
        id: "google",
        name: "Google",
        category: "productivity",
        evidence: "txt",
        record: `google-site-verification=${hexOf("g:" + dom, 22)}`,
      },
    ];
    if (m365)
      hits.unshift({
        id: "microsoft365",
        name: "Microsoft 365",
        category: "productivity",
        evidence: "txt",
        record: `MS=ms${(hash("ms:" + dom) % 90000000) + 10000000}`,
      });
    [extra3[hash(dom) % 4], extra3[(hash(dom) + 1) % 4]].forEach(([id, name, category, pre]) =>
      hits.push({
        id,
        name,
        category,
        evidence: "txt",
        record: `${pre}${hexOf(id + dom, 16).toLowerCase()}`,
      }),
    );
    out.saas.push({
      domain: dom,
      hits,
      unknown: [`yandex-verification: ${hexOf("y:" + dom, 16).toLowerCase()}`],
    });
    const onms = `${base.replace(/[^a-z0-9]/g, "")}.onmicrosoft.com`;
    if (m365) {
      const fed = !!sts;
      out.tenant.push({
        domain: dom,
        exists: true,
        openid: {
          tenant_id: tenantId(dom),
          region_scope: "EU",
          region_sub_scope: null,
          cloud_instance: "microsoftonline.com",
        },
        realm: {
          namespace: fed ? "federated" : "managed",
          domain: dom,
          brand: client,
          auth_url: fed ? `https://${sts.name}/adfs/ls/?username=user%40${dom}` : null,
          protocol: fed ? "WSTrust" : null,
          cloud_instance: "microsoftonline.com",
        },
        federation_host: fed ? sts.name : null,
        adfs: fed,
        tenant_domains: [dom, onms, `${base}.example.net`],
        onmicrosoft: [onms],
        errors: [],
      });
      [`${base}.example.net`]
        .filter(d => !inScope(d))
        .forEach(d =>
          out.oos.push({
            host: d,
            kind: "tenant_domain",
            via: onms,
            why: "domain of the same Microsoft 365 tenant",
            why_key: "oos.why.tenant_domain",
          }),
        );
    }
    // Mail policies: no MTA-STS/TLS-RPT/BIMI; CAA lists the CAs of the project's certificates.
    const dnssec = fnd.some(f => /DNSSEC/.test(f.title)) ? "unsigned" : "unknown";
    const issues = [
      {
        id: "mta_sts_missing",
        sev: "info",
        title: "Нет MTA-STS: доставка почты на домен допускает понижение TLS",
        detail: `Нет записи _mta-sts.${dom}.`,
      },
      {
        id: "tls_rpt_missing",
        sev: "info",
        title: "Нет TLS-RPT: сбои TLS при доставке почты не отслеживаются",
        detail: `Нет записи _smtp._tls.${dom}.`,
      },
    ];
    if (dnssec === "unsigned")
      issues.push({
        id: "dnssec_unsigned",
        sev: "low",
        title: "DNSSEC не включён: ответы DNS можно подделать",
        detail: `Нет записей DS/DNSKEY у ${dom}.`,
      });
    out.mail_policy.push({
      domain: dom,
      bimi: null,
      mta_sts: null,
      mta_sts_policy: null,
      tls_rpt: null,
      caa: ["sectigo.com", "letsencrypt.org", "globalsign.com", "digicert.com"].map(v => ({
        flags: 0,
        tag: "issue",
        value: v,
      })),
      dnssec,
      issues,
    });
    // Certificate history (CT): first appearance and issuers of hosts with TLS; dangling names whose
    // certificates stopped being renewed; organisations from O=.
    const withTls = ext.filter(h => h.tls);
    out.ct.push({
      domain: dom,
      certs: withTls.length * 4 + 6,
      timeline: withTls.map(h => {
        const first = `20${19 + (hash(h.name) % 5)}-0${1 + (hash(h.name) % 9)}-1${hash(h.name) % 9}`;
        return {
          host: h.name,
          first_seen: epochOf(first),
          last_expiry: epochOf(h.tls.not_after),
          cert_count: 2 + (hash(h.name) % 6),
          issuers: [
            {
              issuer: h.tls.issuer,
              from: epochOf(first),
              to: epochOf(h.tls.not_after),
              certs: 2 + (hash(h.name) % 6),
            },
          ],
          ca_changes: 0,
        };
      }),
      abandoned: ext
        .filter(h => /^CNAME → /.test(h.ip))
        .map(h => ({
          host: h.name,
          last_expiry: epochOf("2025-08-14"),
          days_since_expiry: -daysTo("2025-08-14"),
          last_issuer: "Let's Encrypt R3",
          cert_count: 3,
        })),
      orgs: { [client]: withTls.length + 2 },
    });
    const sister = `${base}-trade.example`;
    if (!inScope(sister))
      out.oos.push({
        host: sister,
        kind: "org_pivot",
        via: `O=${client}`,
        why: "certificates with the same organisation (O=)",
        why_key: "oos.why.org_pivot",
      });
    // Origin candidates behind a CDN: addresses of in-scope names from DNS (apex, MX), ranked.
    const behind = ext.filter(h => h.cdn && h.cdn.kind === "cdn");
    if (behind.length) {
      const cand = ext.filter(h => !h.cdn && ip4(h.ip) != null && (h.name === dom || h.role === "Почта"));
      const nets = cand.map(h => h.ip.split(".").slice(0, 3).join("."));
      out.origin.push({
        cdn: behind[0].cdn.name,
        candidates: cand.map(h => {
          const mx = h.role === "Почта";
          const same = nets.filter(n => n === h.ip.split(".").slice(0, 3).join(".")).length > 1;
          return {
            ip: h.ip,
            score: (mx ? 15 : 25) + (same ? 10 : 0),
            sources: [{ kind: mx ? "mx" : "subdomain", detail: h.name }],
            class: null,
            reasons: [mx ? "mx" : "subdomain"].concat(same ? ["same_net"] : []),
          };
        }),
        dropped: [],
      });
    }
    if (lv < 2) return out;
    // Standard level: enumeration summary, PTR of in-scope addresses, certificates of open TLS ports.
    const zone = ext.filter(h => h.name.endsWith("." + dom));
    const brute = st.hosts.filter(h => h.source === "bruteforce").length;
    out.dns_enum.push({
      domain: dom,
      wordlist: lv === 3 ? "top-5000" : "top-1500",
      headless: false,
      brute: {
        tried: lv === 3 ? 5000 : 1500,
        hits: Math.max(brute, zone.filter(h => ip4(h.ip) != null).length),
        wildcard_levels: [],
        wildcard_filtered: 0,
        unverified: 0,
        failed: 2,
        final_rps: 40,
        lowest_rps: 25,
        throttled: false,
      },
      permute: {
        generated: 380 + (hash(dom) % 120),
        hits: st.hosts.filter(h => h.source === "permute").length,
        via_docs: st.hosts.filter(h => /^doc_token:/.test(h.source || "")).length,
      },
      ...(lv === 3
        ? {
            nsec: {
              signing: dnssec === "unsigned" ? "unsigned" : "unknown",
              names: 0,
              complete: false,
              stopped: "not_signed",
              server: (ext.find(h => h.role === "DNS") || {}).name || null,
              queries: 2,
            },
          }
        : {}),
    });
    const byIp = new Map();
    ext
      .filter(h => ip4(h.ip) != null && !h.cdn && inScope(h.name) && inScope(h.ip))
      .forEach(h => byIp.set(h.ip, (byIp.get(h.ip) || []).concat(h.name)));
    byIp.forEach((hs, ip) =>
      out.ptr.push({
        ip,
        names: [],
        forward_confirmed: null,
        hosting: hs.length > 1 ? "unknown" : "dedicated",
        signals: [],
        hosts: hs,
      }),
    );
    ext
      .filter(
        h =>
          h.tls && ip4(h.ip) != null && inScope(h.name) && (h.services || []).some(x => /^443\//.test(x[0])),
      )
      .forEach(h => {
        const t = h.tls,
          left = daysTo(t.not_after),
          ec = /ECC/.test(t.issuer),
          le = /Let's Encrypt/.test(t.issuer);
        const [org, aia] = ISSUER_ORG[t.issuer] || ["", ""];
        const nb = new Date(Date.parse(t.not_after + "T00:00:00Z") - (le ? 90 : 365) * 864e5)
          .toISOString()
          .slice(0, 10);
        const exp = fnd.find(
          f => f.host === h.name && (f.provenance || {}).rule === "infra.cert_expires_soon",
        );
        out.cert.push({
          host: h.name,
          port: 443,
          mode: "tls",
          ip: h.ip,
          sni: h.name,
          starttls: null,
          version: /IIS/.test(h.tech || "") ? "TLSv1_2" : "TLSv1_3",
          cipher: /IIS/.test(h.tech || "")
            ? "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
            : "TLS13_AES_256_GCM_SHA384",
          alpn: /IIS/.test(h.tech || "") ? null : "h2",
          ocsp_stapled: true,
          error: null,
          chain: [
            {
              subject: {
                cn: t.cn,
                o: null,
                ou: [],
                l: null,
                st: null,
                c: null,
                email: null,
                text: `CN=${t.cn}`,
              },
              issuer: {
                cn: t.issuer,
                o: org || null,
                ou: [],
                l: null,
                st: null,
                c: "US",
                email: null,
                text: `C=US, O=${org}, CN=${t.issuer}`,
              },
              serial: hexOf("sn:" + h.name, 32),
              not_before: epochOf(nb),
              not_after: epochOf(t.not_after),
              san_dns: (t.san || []).slice(),
              san_ip: [],
              san_email: [],
              san_uri: [],
              sha256: hexOf("fp:" + h.name, 64),
              spki_sha256: hexOf("spki:" + h.name, 64),
              sig_alg: ec ? "ecdsa-with-SHA256" : "sha256WithRSAEncryption",
              sig_hash: "sha256",
              key_type: ec ? "EC" : "RSA",
              key_bits: ec ? 256 : 2048,
              is_ca: false,
              self_issued: false,
              ski: hexOf("ski:" + h.name, 40),
              aki: hexOf("aki:" + t.issuer, 40),
              crl_urls: [],
              ocsp_urls: [aia.replace(/\/[^/]*$/, "/").replace("cacerts", "ocsp")],
              ca_issuer_urls: [aia],
            },
          ],
          trust: { status: "trusted" },
          hostname_match: true,
          days_left: left,
          issues: exp ? [{ code: "cert_expires_soon", severity: exp.sev, detail: `${left} days left` }] : [],
          pki: [],
          scan: lastScan.id || null,
          at,
        });
      });
    return out;
  }
  // =================
  // own: true only with a proven link to the client: an A record of an in-scope domain, or a redirect from an
  // in-scope
  // host to a tenant named after the client. blocked: cannot be added to the scope (name is free, shared CDN,
  // government service).
  function oosOf(st) {
    if (!st || !st.project || !(st.hosts || []).length) return [];
    const dom = st.project.domain || st.project.name,
      base = dom.split(".")[0];
    const dec = st.oos_dec || {};
    const out = [];
    const inScope = h => scopeCheck(st.scope, h, st.hosts).ok;
    const add = o => {
      if (out.some(x => x.host === o.host)) return;
      const decision = dec[o.host] || "new";
      if (decision === "new" && inScope(o.host)) return; // Already covered by the scope: not a candidate.
      // Exclusions win over targets: a candidate from the exclusions cannot be added to the scope.
      if (!o.blocked && scopeCheck(st.scope, o.host, st.hosts).code === "excluded")
        o = { ...o, blocked: "В исключениях скоупа: сначала уберите исключение на экране «Скоуп»" };
      out.push({
        id: "oos-" + hash(o.host).toString(36),
        n: null,
        finding: null,
        blocked: null,
        ...o,
        decision,
      });
    };
    const ext = st.hosts.filter(h => !h.internal);
    // 1. Dangling CNAME: the name is free, must not be scanned.
    ext
      .filter(h => /^CNAME → /.test(h.ip))
      .forEach(h => {
        const f = st.findings.find(x => x.host === h.name && x.category === "dns");
        add({
          host: h.ip.replace(/^CNAME → /, ""),
          kind: "cname",
          via: h.name,
          why: `CNAME с ${h.name}`,
          own: false,
          finding: f ? f.id : null,
          hint: "Ресурс не существует (NXDOMAIN): владелец не заказчик",
          blocked: `Имя свободно, не сканировать${f ? `, см. находку №${f.id}` : ""}`,
        });
      });
    // 2. Cloud addresses of in-scope hosts: an A record of the client's domain (own); shared CDN cannot be
    // added.
    const fresh = h => !inScope(h) || !!dec[h]; // Out of scope or already decided (a candidate added to the scope stays in the list).
    ext
      .filter(h => h.cloud && h.cloud !== "-" && ip4(h.ip) != null && inScope(h.name) && fresh(h.ip))
      .forEach(h => {
        if (/cloudflare|akamai|fastly/i.test(h.cloud))
          add({
            host: h.ip,
            kind: "cdn",
            via: h.name,
            why: `A-запись ${h.name} → ${h.cloud}`,
            own: false,
            hint: "Общий адрес CDN, на нём сайты других компаний",
            blocked: "Общий IP CDN, не сканировать",
          });
        else
          add({
            host: h.ip,
            kind: "ip",
            via: h.name,
            why: `A-запись ${h.name} (${h.cloud}) вне сетей скоупа`,
            own: true,
            hint: "Адрес облака: уточните у заказчика, что он закреплён за ним",
          });
      });
    // 3. Addresses of own hosts outside scope networks: single IP only (shared hosting: no /24 suggestion).
    const ips = new Map();
    ext
      .filter(h => (!h.cloud || h.cloud === "-") && ip4(h.ip) != null && inScope(h.name) && fresh(h.ip))
      .forEach(h => ips.set(h.ip, (ips.get(h.ip) || []).concat(h.name)));
    ips.forEach((hs, ip) =>
      add({
        host: ip,
        kind: "ip",
        via: hs[0],
        n: hs.length,
        shared: true,
        why: `A-запись ${hs.length} ${hs.length === 1 ? "хоста" : "хостов"} из скоупа (${hs.slice(0, 2).join(", ")}${hs.length > 2 ? "…" : ""}) вне сетей скоупа`,
        own: false,
        hint: "Возможен общий хостинг: на этом IP могут быть сайты других владельцев. В скоуп добавляется только этот адрес, не сеть: подтвердите у заказчика (whois/RDAP)",
      }),
    );
    // 3b. Host names not covered by the scope (CT logs, documents): as the core's oos list; the bulk
    // "add to scope and scan" action works on these.
    ext
      .filter(
        h =>
          /^[a-z0-9-]+(\.[a-z0-9-]+)+$/i.test(h.name) &&
          ip4(h.name) == null &&
          (!inScope(h.name) || !!dec[String(h.name).toLowerCase()]),
      )
      .forEach(h =>
        add({
          host: String(h.name).toLowerCase(),
          kind: "link",
          via: null,
          why: "Имя в сертификатах (crt.sh)",
          own: false,
          hint: "Имя из CT-логов вне скоупа: владелец не подтверждён, уточните у владельца",
        }),
      );
    // 4. File host redirecting to a Microsoft 365 tenant named after the client.
    const fh = ext.find(h => h.role === "Файловый" && inScope(h.name));
    if (fh)
      add({
        host: `${base}.sharepoint.com`,
        kind: "redirect",
        via: fh.name,
        why: "Домен того же арендатора Microsoft 365",
        own: true,
        hint: "Домен организации вне скоупа: подтвердите у заказчика",
      });
    // 5. Look-alike domain in document text.
    const an = (st.docs || []).filter(d => d.status === "analyzed" && ["pdf", "docx", "doc"].includes(d.ext));
    // Look-alike of the target domain, kept in the reserved .example zone.
    const sim = dom.replace(/^([^.]+)\./, "$1-online.");
    const simN = an.filter(d => hash(d.name) % 6 === 0).length;
    if (simN)
      add({
        host: sim,
        kind: "link",
        via: null,
        why: "Хост в документах (метаданные)",
        why_msg: docWhyMsg,
        own: false,
        hint: "Хост из метаданных или текста документов, владелец не подтверждён",
        hint_msg: { code: "oos.doc_hint", params: {} },
      });
    // 6. Third-party script CDN (WordPress sites).
    const wp = ext.find(h => /WordPress/.test(h.tech || ""));
    if (wp)
      add({
        host: "cdn.jsdelivr.net",
        kind: "cdn",
        via: wp.name,
        why: "Домен из CSP / карты исходников сайта",
        own: false,
        hint: "Хост из политики CSP или source map вне скоупа: запросы к нему не выполнялись, владелец не подтверждён",
        blocked: "Общий IP CDN, не сканировать",
      });
    // 7. Links to the government procurement service from tender documents.
    const tn = an.filter(d => /тендер/i.test(d.title || d.name)).length;
    if (tn)
      add({
        host: "prozorro.gov.ua",
        kind: "link",
        via: null,
        why: "Хост в документах (метаданные)",
        why_msg: docWhyMsg,
        own: false,
        hint: "Хост из метаданных или текста документов, владелец не подтверждён",
        hint_msg: { code: "oos.doc_hint", params: {} },
      });
    // 8. Infrastructure candidates: tenant domains, O= pivot, certificate SAN…, no request was sent to
    // any of them.
    const OOS_WHY = {
      san: ["Имя в SAN сертификата", "Чужое имя в сертификате хоста из скоупа: владелец не подтверждён"],
      org_pivot: [
        "Сертификаты с той же организацией (O=)",
        "Возможный сестринский домен: подтвердите у заказчика",
      ],
      tenant_domain: [
        "Домен того же арендатора Microsoft 365",
        "Домен организации вне скоупа: подтвердите у заказчика",
      ],
      origin_ip: [
        "Возможный исходный IP за CDN",
        "Кандидат для проверки: добавляйте в скоуп только после подтверждения владельца",
      ],
      ptr: ["PTR-имя адреса из скоупа", "Имя из обратной зоны вне скоупа: владелец не подтверждён"],
      federation: ["Хост федерации (AD FS)", "Хост входа арендатора вне скоупа: владелец не подтверждён"],
    };
    const OOS_CODE = {
      san: "san_why",
      org_pivot: "org_why",
      tenant_domain: "tenant_why",
      origin_ip: "origin_why",
      ptr: "ptr_why",
      federation: "adfs_why",
    };
    infraOf(st).oos.forEach(o => {
      const [why, hint] = OOS_WHY[o.kind] || OOS_WHY.federation;
      add({
        // "{why} ({via})" has no letters of its own: the core sets this message by hand too.
        why_msg: {
          code: "oos.via",
          params: {
            why: { code: "oos." + (OOS_CODE[o.kind] || "adfs_why"), params: {}, text: why },
            via: o.via,
          },
        },
        host: o.host,
        kind: o.kind === "origin_ip" ? "ip" : "link",
        via: o.via,
        why: `${why} (${o.via})`,
        why_key: o.why_key,
        source: o.kind,
        own: false,
        hint,
      });
    });
    // As the core: known texts carry `<field>_msg` for the UI language.
    out.forEach(o => ["why", "hint", "blocked"].forEach(k => o[k] && !o[`${k}_msg`] && demoMsg(o, k)));
    return out;
  }
  // Matches a Russian core text against the `core.*` templates of the RU dictionary the QA harness passes
  // (window.FOCA_DEMO_UI.ru), like foca_engine::i18n::classify (most fixed text wins, one nesting level).
  let demoTpl = null;
  function demoClassify(text, depth = 0) {
    const ru = typeof window !== "undefined" && window.FOCA_DEMO_UI && window.FOCA_DEMO_UI.ru;
    if (!ru || !text) return null;
    if (!demoTpl)
      demoTpl = Object.entries(ru)
        .filter(
          ([k, v]) =>
            /^core\./.test(k) && !/^core\.(wordlist|device|plural)\./.test(k) && typeof v === "string",
        )
        .map(([k, v]) => {
          const names = [...v.matchAll(/\{([a-z_]+)\}/g)].map(m => m[1]);
          const fixed = v.replace(/\{[a-z_]+\}/g, "");
          const re = new RegExp(
            "^" +
              v
                .split(/\{[a-z_]+\}/)
                .map(x => x.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"))
                .join("(.+?)") +
              "$",
            "s",
          );
          return { code: k.slice(5), names, re, lit: fixed.length, ok: /\p{L}/u.test(fixed) };
        })
        .filter(t => t.ok)
        .sort((a, b) => b.lit - a.lit);
    for (const t of demoTpl) {
      const m = text.match(t.re);
      if (!m) continue;
      const params = {};
      t.names.forEach((n, i) => {
        const v = m[i + 1];
        const sub = depth < 1 && v.length < text.length ? demoClassify(v, depth + 1) : null;
        params[n] = sub ? { ...sub, text: v } : v;
      });
      return { code: t.code, params };
    }
    return null;
  }
  function demoMsg(o, k) {
    const m = demoClassify(o[k]);
    if (m) o[`${k}_msg`] = m;
  }

  // ================= scan events (emitter; under Tauri: listen("scan://event")) =================
  // Semantics (docs/API.md, "Scan: retry, resume, restart"): scans are INCREMENTAL, stages add and refine
  // data but
  // never erase it; user triage (status, sev, notes, tags, photos) and document deletions are preserved;
  // resume (resume_from) continues the same history record; a scan running during an app restart is recorded
  // as stopped/restart.
  const listeners = new Set();
  const emit = ev =>
    listeners.forEach(fn => {
      try {
        fn(ev);
      } catch (e) {
        console.error(e);
      }
    });
  let RUN = null;
  const TARGET_MODS = ["dns", "docs", "alive", "subdomains", "tls"];
  const profOf = p => (p && PROFILES[p] ? p : Object.keys(PROFILES).find(k => PROFILES[k] === p) || "std");
  // Access level: external, external sources only, target, requests to the target (Standard), active: the
  // active phase.
  const levelOf = (prof, mods, active) =>
    active
      ? "active"
      : prof === "std" || prof === "full" || mods.some(m => TARGET_MODS.includes(m))
        ? "target"
        : "external";
  const PROFILE_MIN = { full: 74, passive: 6, std: 24, custom: 24 };

  // Outcome the stages lead the project to: the first scan yields data generated from the targets
  // (deterministic: seed = domain, scan id); a repeat scan is "no changes" (the demo does not simulate site
  // changes).
  function buildFinal(st, prof, active, id, started) {
    if (st.scans.some(s => s.status === "done")) return clone(st);
    const settings = load().settings;
    const dom = (st.scope.targets.find(t => t.type === "domain") || { v: st.project.name }).v;
    const seed = hash(dom);
    const R = rng(seed);
    const spec = {
      id: st.project.id,
      name: dom,
      client: st.project.client,
      seed,
      ndocs: prof === "passive" ? 8 + R.int(0, 8) : 24 + R.int(0, 30),
      years: [2018, 2025],
      created_at: st.project.created_at,
      scope: st.scope,
      npeople: 3 + R.int(0, 3),
      depts: ["buh", "it", "hr", "sales", "mkt", "law"].slice(0, 3 + R.int(0, 3)),
      web: [dom],
      ips: [`193.${R.int(10, 250)}.${R.int(0, 250)}.${R.int(2, 250)}`],
      extra_hosts: [
        {
          name: `mail.${dom}`,
          ip: `193.${R.int(10, 250)}.${R.int(0, 250)}.${R.int(2, 250)}`,
          role: "Почта",
          tech: "-",
          source: "DNS",
        },
      ],
      tech: [R.pick(["nginx 1.14.0, WordPress 5.8", "Apache 2.4.57", "nginx 1.24.0"])],
      sw_allow: null,
      gps_places: [["Київ", 50.45, 30.52]],
      wayback: prof === "passive",
      dmarc: R.pick(["none", "reject"]),
      fileserver: R.chance(0.5) ? `\\\\FS01\\share` : null,
      printer: null,
      scans: [{ id, profile_id: prof, active, started_at: started, minutes: 0, trigger: "manual" }],
    };
    const final = buildSmall(spec, settings);
    final.scope = st.scope;
    final.project = st.project;
    final.reports = st.reports;
    return final;
  }

  // Pre-launch checks: one rule for a new scan, resume and "Start over" (docs/API.md, "scan_start").
  function validateStart(st, args, prof, mods, active) {
    // No confirmations: any profile starts immediately; only the scope (targets and exclusions) is checked.
    const R = RULES(),
      lvl = levelOf(prof, mods, active);
    const scopeT = st.scope.targets || [];
    // Targets come from the CURRENT scope; `targets` narrows the selection; at the external level
    // out-of-scope targets are allowed (external sources only).
    const req =
      Array.isArray(args.targets) && args.targets.length ? args.targets.map(String) : scopeT.map(t => t.v);
    if (lvl === "external") return { lvl, targets: req };
    const bad = [];
    req.forEach(v => {
      const t = scopeT.find(x => String(x.v).toLowerCase() === v.toLowerCase());
      if (!t) {
        if (R.scope.entry(v).k !== "none") bad.push(`${v}: нет в скоупе`);
        return;
      }
      const ck = R.scope.checkTarget(st.scope, t, { hosts: st.hosts });
      if (ck.net && !ck.ok) bad.push(`${v} (${ck.reason})`);
    });
    if (bad.length) {
      const e = apiErr("out_of_scope", `Цели вне скоупа: ${bad.join("; ")}`, {
        code: "scan.targets_oos",
        params: { list: bad.join("; ") },
      });
      e.targets = bad;
      throw e;
    }
    return { lvl, targets: req };
  }

  function scanStart(args = {}) {
    const st = P(args.project || load().settings.last_project);
    if (RUN) throw apiErr("busy", "Скан уже идёт");
    const prof = profOf(args.profile);
    const mods = args.modules || [];
    const active = !!args.active || prof === "full" || mods.some(m => ACTIVE_MODULES.includes(m));
    const prevStop = args.resume_from
      ? st.scans.find(s => s.id === args.resume_from && s.status === "stopped")
      : null;
    if (args.resume_from && !prevStop)
      throw apiErr("not_found", `Остановленный скан ${args.resume_from} не найден`);
    const v = validateStart(st, args, prof, mods, active);
    const settings = load().settings;
    // Resume keeps the same record: the id is preserved; the stopped record is replaced by the result or a
    // new stop.
    const id = prevStop ? prevStop.id : `${st.project.id}-s${st.scans.length + 1}-${Date.now().toString(36)}`;
    const started = prevStop
      ? prevStop.started_at
      : args.now || new Date(Date.UTC(2026, 10, 20, 12, 0)).toISOString().slice(0, 19);
    if (prevStop) st.scans = st.scans.filter(s => s !== prevStop);
    const final = buildFinal(st, prof, active, id, started);
    const fz = settings.fuzz || {},
      fzArgs = args.fuzz || {};
    const fuzzOn = active && (prof !== "custom" || mods.includes("fuzz"));
    const fuzz = {
      on: fuzzOn,
      modules: fzArgs.modules || fz.modules || [],
      rate: fzArgs.rate || fz.rate || 5,
      checked: 0,
      found: 0,
      filtered: 0,
      planned: 0,
    };
    fuzz.planned = Math.min(
      fz.max_requests || 3000,
      fuzz.modules.reduce((a, m) => a + (FZ_PER[m] || 0), 0),
    );
    RUN = {
      fuzz,
      id,
      project: st.project.id,
      profile: prof,
      active,
      level: v.lvl,
      stage: 0,
      progress: 0,
      paused: false,
      started,
      final,
      targets: v.targets,
      modules: mods,
      resumed: !!prevStop,
      egress: egressLabel(settings),
      sources: SOURCES.filter(x => !(x.active && prof === "passive")).map(x => ({
        id: x.id,
        name: x.name,
        status:
          x.id === "fuzz"
            ? fuzzOn
              ? "wait"
              : "off"
            : x.id === "ports"
              ? active && (prof !== "custom" || mods.includes("ports"))
                ? "wait"
                : "off"
              : INFRA_SRC.includes(x.id)
                ? (prof !== "custom" || mods.includes(x.id)) &&
                  ((settings.sources || {})[x.id] || {}).enabled !== false
                  ? "wait"
                  : "off"
                : sourceStatus(x, settings),
      })),
    };
    // A narrowed run: only the stages of the chosen items; sources outside them are off.
    {
      const only = args.only || (prevStop && prevStop.only) || null;
      RUN.sel = selStages(only);
      RUN.only = RUN.sel ? only.slice() : null;
      if (RUN.sel)
        RUN.sources.forEach(x => {
          if (!selCovers(RUN.only, x.id)) x.status = "off";
        });
    }
    // Startpage showed a captcha in the embedded browser: "Check required" + "Pass the check".
    {
      const sp = RUN.sources.find(x => x.id === "startpage");
      if (sp && sp.status === "ok")
        Object.assign(sp, {
          status: "blocked",
          n: 0,
          error: "капча / заблокировано: поисковик показал капчу",
          // message code + params as the core sends them (the UI renders locales/*/ui/core.json)
          error_msg: {
            code: "src.blocked",
            params: { why: { code: "src.captcha", params: {}, text: "поисковик показал капчу" } },
          },
          verify_url: "https://www.startpage.com/",
        });
    }
    emit({
      type: "started",
      scan_id: id,
      project: st.project.id,
      profile: PROFILES[prof],
      profile_id: prof,
      active,
      egress: RUN.egress,
      targets: v.targets,
      resumed: !!prevStop,
      stages: RUN.sel ? RUN.sel.map(k => STAGES[k].id) : null,
    });
    RUN.sources.forEach(s => emit({ type: "source", scan_id: id, ...s }));
    if (prevStop && prevStop.progress) {
      // From the stop point: stages before `stage` are applied immediately (idempotent: already applied data
      // does not change).
      RUN.progress = prevStop.progress;
      const stg = Math.min(
        STAGES.length - 1,
        Math.max(
          0,
          STAGES.findIndex(x => x.id === prevStop.stage),
        ),
      );
      for (let i = 0; i < stg; i++) if (!RUN.sel || RUN.sel.includes(i)) applyStage(i, true);
      RUN.stage = stg;
      emit({ type: "stage", scan_id: id, stage: STAGES[stg].id, label: STAGES[stg].label, index: stg });
      emit({ type: "progress", scan_id: id, progress: RUN.progress, stage: STAGES[stg].id });
      emit({ type: "db", scan_id: id, project: st.project.id, kind: STAGES[stg].id });
    }
    const fromIdx = RUN.sel ? RUN.sel[0] : STAGES.findIndex(x => x.id === args.from_stage);
    if (!prevStop && fromIdx > 0) {
      // Follow-up run of queued restarts: starts at the earliest stage they belong to; a narrowed run
      // leaves the stages outside its selection untouched.
      if (!RUN.sel) for (let i = 0; i < fromIdx; i++) applyStage(i, true);
      RUN.stage = fromIdx;
      RUN.progress = stagePct(fromIdx);
      emit({
        type: "stage",
        scan_id: id,
        stage: STAGES[fromIdx].id,
        label: STAGES[fromIdx].label,
        index: fromIdx,
      });
    }
    persistRun();
    tick();
    return {
      scan_id: id,
      profile: PROFILES[prof],
      profile_id: prof,
      active,
      egress: RUN.egress,
      targets: v.targets,
      resumed: !!prevStop,
      stages: RUN.sel ? RUN.sel.map(k => STAGES[k].id) : null,
    };
  }
  let tickT = null;
  const TICK_MS = 120;
  // A single core step (timer and the QA fast-forward _ff).
  function step() {
    const held = RUN.held || new Set(),
      cur = STAGES[RUN.stage].id;
    // Held by the user (scan_control): the stage, or brute force while it runs, does not move.
    if (held.has(`stage:${cur}`)) return true;
    if (cur === "network" && RUN.substep && ["brute", "permute"].includes(RUN.substep.id)) {
      if (held.has(`step:${RUN.substep.id}`) || held.has("source:subdomains")) return true;
    }
    const n = RUN.sel ? RUN.sel.length : STAGES.length,
      per = 100 / n,
      slot = RUN.sel ? RUN.sel.indexOf(RUN.stage) : RUN.stage;
    // A skipped stage ends at once (its remaining work is dropped).
    if (RUN.skipStages && RUN.skipStages.has(cur)) {
      RUN.skipStages.delete(cur);
      RUN.progress = Math.min(100, Math.ceil((slot + 1) * per));
    }
    RUN.progress = Math.min(100, RUN.progress + 2);
    const stage = stageAt(RUN.progress);
    if (stage !== RUN.stage) {
      applyStage(RUN.stage);
      RUN.stage = stage;
      emit({
        type: "stage",
        scan_id: RUN.id,
        stage: STAGES[stage].id,
        label: STAGES[stage].label,
        index: stage,
      });
    }
    emit({ type: "progress", scan_id: RUN.id, progress: RUN.progress, stage: STAGES[RUN.stage].id });
    if (STAGES[RUN.stage].id === "network") subTick();
    if (STAGES[RUN.stage].id === "fuzz") fuzzTick();
    if (HOST_STAGES.includes(STAGES[RUN.stage].id)) hostsTick(STAGES[RUN.stage].id);
    if (RUN.progress >= 100) {
      finishScan();
      return false;
    }
    if (RUN.progress % 10 === 0) persistRun();
    return true;
  }
  // ---- per-item controls (scan_control), mirroring the core's capability table ----
  const DEMO_SEARCH_SRC = () =>
    (RUN ? RUN.sources : [])
      .map(x => x.id)
      .filter(
        x => ![...INFRA_SRC, ...RECON_SRC, "ports", "fuzz", "dns", "internetdb", "plugins"].includes(x),
      );
  function controlOwner(kind, id) {
    const at = s => STAGES.findIndex(x => x.id === s);
    if (kind === "stage") return at(id) >= 0 ? at(id) : null;
    if (kind === "step") return ["brute", "permute"].includes(id) ? at("network") : null;
    if (kind !== "source") return null;
    if (INFRA_SRC.includes(id)) return at("network");
    if (id === "ports") return at("ports");
    if (RECON_SRC.includes(id)) return at("recon");
    if (id === "fuzz") return at("fuzz");
    return DEMO_SEARCH_SRC().includes(id) ? 0 : null;
  }
  const ALL_ACTIONS = ["pause", "resume", "skip", "restart"];
  const controlActions = (kind, id) =>
    kind === "stage" || kind === "step" || (kind === "source" && INFRA_SRC.includes(id))
      ? ALL_ACTIONS
      : kind === "source"
        ? ["skip", "restart"]
        : [];
  function controlCaps() {
    const m = { "stage:*": ALL_ACTIONS };
    ["brute", "permute"].forEach(s => (m[`step:${s}`] = ALL_ACTIONS));
    [...DEMO_SEARCH_SRC(), ...RECON_SRC, ...INFRA_SRC, "ports", "fuzz"].forEach(
      s => (m[`source:${s}`] = controlActions("source", s)),
    );
    return m;
  }
  function scanControl({ kind, id, action } = {}) {
    const owner = controlOwner(kind, id);
    if (owner == null) throw apiErr("not_found", `нет элемента скана ${kind}:${id}`);
    const res = (ok, state, reason) => ({ ok, state, reason });
    if (!controlActions(kind, id).includes(action)) return res(false, "", "unsupported");
    if (!RUN) return res(false, "", "no_scan");
    RUN.held = RUN.held || new Set();
    const key = `${kind}:${id}`,
      cur = RUN.stage,
      done = cur > owner;
    const note = state => {
      emit({ type: "control", scan_id: RUN.id, project: RUN.project, kind, id, state });
      return res(true, state, "");
    };
    if (action === "pause" || action === "resume") {
      if (done) return res(false, "", "finished");
      if (action === "pause") RUN.held.add(key);
      else RUN.held.delete(key);
      return note(action === "pause" ? "paused" : "running");
    }
    if (action === "skip") {
      if (done) return res(false, "", "finished");
      RUN.held.delete(key);
      if (kind === "stage") (RUN.skipStages = RUN.skipStages || new Set()).add(id);
      else if (!COMMANDS.scan_skip_source({ id }).ok) return res(false, "", "finished");
      return note("skipped");
    }
    if (cur < owner) return res(false, "", "pending");
    const live = cur === owner && (kind !== "source" || (cur === 0 && DORK_LIKE.includes(id)));
    if (!live) {
      RUN.followup = RUN.followup || [];
      if (!RUN.followup.includes(key)) RUN.followup.push(key);
      return note("queued");
    }
    RUN.held.delete(key);
    if (kind === "stage") RUN.progress = stagePct(cur);
    if (kind === "step" && id === "brute") RUN.skipBrute = false;
    if (kind === "source") {
      const x = RUN.sources.find(s => s.id === id);
      if (x) {
        Object.assign(x, { status: "running", error: null });
        emit({ type: "source", scan_id: RUN.id, ...x });
      }
    }
    return note("restarting");
  }
  const DORK_LIKE = [
    "arquivo",
    "otx_url",
    "urlscan",
    "hudson",
    "ddg",
    "bing",
    "mojeek",
    "startpage",
    "brave_web",
    "yahoo",
    "searx_pool",
  ];
  // Network stage sub-steps (like the core's `substep` events): DNS, resolution, takeover checks, then brute
  // force and permutations with live counters for standard/full profiles.
  const SUB_PLAN = { dns: 2, resolve: 24, takeover: 24, brute: 1500, permute: 1200, liveness: 24 };
  function subEmit(id, state, done) {
    const total = SUB_PLAN[id];
    // Brute force through the phone's VPN resolver is slow in the demo: ETA + "Skip brute force".
    const slow = id === "brute" && state === "running" && !RUN.skipBrute;
    const eta = slow ? Math.round(((total - done) / Math.max(1, done || 40)) * 60) : null;
    const x = { stage: "network", id, state, done, total, eta_s: eta, slow };
    if (slow && !RUN.slowWarned) {
      RUN.slowWarned = true;
      emit({
        type: "warning",
        scan_id: RUN.id,
        code: "dns.slow",
        message: `DNS медленный (VPN?): перебор займёт ~${Math.max(1, Math.ceil(eta / 60))} мин`,
      });
    }
    RUN.substep = state === "running" ? x : null;
    emit({ type: "substep", scan_id: RUN.id, ...x });
  }
  function subTick() {
    const i = STAGES.findIndex(x => x.id === "network"),
      per = RUN.sel ? 100 / RUN.sel.length : 100 / STAGES.length,
      at = RUN.sel ? RUN.sel.indexOf(i) : i;
    const frac = Math.max(0, Math.min(0.999, (RUN.progress - at * per) / per));
    let ids = RUN.level === "external" ? ["dns", "resolve", "takeover"] : Object.keys(SUB_PLAN);
    // a narrowed run of chosen resolver steps runs those steps alone (like the core)
    const only = RUN.only || [];
    if (RUN.sel && !only.includes("stage:network") && !only.includes("source:subdomains"))
      ids = ids.filter(x => only.includes(`step:${x}`));
    if (!ids.length) return;
    const k = Math.floor(frac * ids.length),
      id = ids[k],
      part = frac * ids.length - k;
    const cur = RUN.substep;
    if (cur && cur.id !== id)
      subEmit(cur.id, cur.id === "brute" && RUN.skipBrute ? "skipped" : "done", SUB_PLAN[cur.id]);
    if (id === "brute" && RUN.skipBrute) return;
    subEmit(id, "running", Math.round(SUB_PLAN[id] * part));
  }
  function subDone() {
    const cur = RUN && RUN.substep;
    if (cur) subEmit(cur.id, "done", SUB_PLAN[cur.id]);
  }
  // Hosts worked on at once in the ports, recon and site discovery stages (like the core's `hosts`
  // sub-step): up to settings.net.hosts_parallel names run together, the rest wait.
  const HOST_STAGES = ["ports", "recon", "fuzz"];
  function stageHosts(sid) {
    const names = ((RUN.final && RUN.final.hosts) || []).map(h => h.name).filter(Boolean);
    return names.slice(0, sid === "ports" ? 7 : 3);
  }
  function hostsEmit(sid, state, done, running) {
    const total = stageHosts(sid).length;
    const x = { stage: sid, id: "hosts", state, done, total, eta_s: null, slow: false, running };
    RUN.substep = state === "running" ? x : null;
    emit({ type: "substep", scan_id: RUN.id, ...x });
  }
  function hostsTick(sid) {
    const names = stageHosts(sid);
    if (!names.length || RUN.level !== "active") return;
    const i = STAGES.findIndex(x => x.id === sid),
      per = RUN.sel ? 100 / RUN.sel.length : 100 / STAGES.length,
      at = RUN.sel ? RUN.sel.indexOf(i) : i;
    if (at < 0) return;
    const frac = Math.max(0, Math.min(0.999, (RUN.progress - at * per) / per));
    const par = Math.max(1, Math.min(8, +((load().settings.net || {}).hosts_parallel || 4)));
    const done = Math.min(names.length, Math.floor(frac * names.length));
    hostsEmit(sid, "running", done, names.slice(done, done + par));
  }
  function hostsDone(sid) {
    const cur = RUN && RUN.substep;
    if (cur && cur.id === "hosts" && cur.stage === sid) hostsEmit(sid, "done", cur.total, []);
  }
  // Site file search in the demo: fuzzing counters grow during the fuzz stage (like the core's fuzz source
  // events).
  function fuzzSrc() {
    return (RUN.sources || []).find(x => x.id === "fuzz");
  }
  function fuzzEmit(extra) {
    const x = fuzzSrc(),
      z = RUN.fuzz;
    if (!x) return;
    Object.assign(
      x,
      {
        n: z.found,
        checked: z.checked,
        found: z.found,
        filtered: z.filtered,
        planned: z.planned,
        requests: z.checked + 9,
      },
      extra || {},
    );
    emit({ type: "source", scan_id: RUN.id, ...x });
  }
  function fuzzTick() {
    const z = RUN.fuzz,
      x = fuzzSrc();
    if (!z || !z.on || !x || !["wait", "running"].includes(x.status)) return;
    z.checked = Math.min(z.planned, z.checked + Math.ceil(z.planned / 7));
    z.filtered = Math.round(z.checked * 0.97);
    z.found = Math.min(4, Math.floor((z.checked / Math.max(1, z.planned)) * 5));
    fuzzEmit({ status: "running", host: "https://contoso.example/", hosts: 2, host_index: 0 });
  }
  function fuzzDone() {
    const z = RUN.fuzz,
      x = fuzzSrc();
    if (!z || !z.on || !x || !["wait", "running"].includes(x.status)) return;
    z.checked = z.planned;
    z.filtered = Math.round(z.planned * 0.97);
    z.found = 4;
    fuzzEmit({ status: "ok", detail: "перебор завершён", documents: 3, stop: { kind: "completed" } });
  }
  function tick() {
    clearTimeout(tickT);
    if (!RUN) return;
    tickT = setTimeout(() => {
      if (!RUN) return;
      if (RUN.paused) return tick();
      if (step()) tick();
    }, TICK_MS);
  }
  // ---- merging stage results into the project: known data stays, new data is added, nothing is removed ----
  const stripDoc = d => ({
    ...clone(d),
    status: "downloaded",
    author: null,
    last_modified_by: null,
    software: null,
    created_at: null,
    modified_at: null,
    folder: null,
    printer: null,
    company: null,
    camera: null,
    gps: null,
    revisions: [],
    rdp: null,
    lnk: null,
    flags: [],
    thumb_diff: false,
  });
  const USER_FIELDS = ["status", "sev", "notes", "tags", "photos"]; // User triage is never overwritten by a scan.
  function mergeBy(cur, add, key, onNew, keepUser) {
    cur = cur || [];
    const by = new Map(cur.map(x => [x[key], x]));
    (add || []).forEach(x => {
      const c = by.get(x[key]);
      if (!c) {
        const n = clone(x);
        cur.push(n);
        by.set(x[key], n);
        if (onNew) onNew(n);
        return;
      }
      const keep = {};
      (keepUser || []).forEach(k => {
        if (k in c) keep[k] = c[k];
      });
      Object.assign(c, clone(x), keep);
    });
    return cur;
  }
  function mergeDocs(st, list, withMeta) {
    const by = new Map(st.docs.map(d => [d.id, d]));
    (list || []).forEach(d => {
      const c = by.get(d.id);
      if (!c) {
        const n = withMeta || d.status !== "analyzed" ? clone(d) : stripDoc(d);
        st.docs.push(n);
        by.set(d.id, n);
        return;
      }
      // Parsing reached an already known document: metadata is added; the "deleted" flag and the first scan
      // stay.
      if (withMeta && c.status !== "analyzed" && d.status === "analyzed")
        Object.assign(c, clone(d), { deleted: c.deleted, first_scan: c.first_scan || d.first_scan });
    });
    st.docs.sort((a, b) => a.id - b.id);
  }
  const ENT_KEY = {
    people: "login",
    software: "id",
    paths: "path",
    printers: "name",
    pcs: "name",
    gps: "doc",
    emails: "addr",
    patterns: "p",
    secrets: "id",
  };
  // A narrowed run (`scan_start { only }`, follow-up of chosen items), like the core's `Selection`: a
  // search source or stage brings the document pipeline, any other item only its own stage; the
  // report always runs. Returns the stage indices the run executes, or null for a full scan.
  function selStages(only) {
    if (!Array.isArray(only) || !only.length) return null;
    const at = x => STAGES.findIndex(y => y.id === x),
      analysis = at("analysis"),
      run = new Set();
    only.forEach(key => {
      const [kind, id] = String(key).split(":");
      const k = controlOwner(kind, id);
      if (k == null) return;
      if (k <= analysis) for (let j = k; j <= analysis; j++) run.add(j);
      else run.add(k);
    });
    if (!run.size) return null;
    run.add(at("report"));
    return [...run].sort((a, b) => a - b);
  }
  // A source takes part in a narrowed run: its stage was chosen whole, or the source itself (the
  // subdomain source also through one of its steps).
  function selCovers(only, src) {
    const has = k => only.includes(k);
    if (src === "subdomains" && (has("step:brute") || has("step:permute"))) return true;
    if (src === "dns") return selStages(only).includes(0);
    const owner = controlOwner("source", src);
    if (owner == null) return has("stage:network");
    return has(`stage:${STAGES[owner].id}`) || has(`source:${src}`);
  }
  // Percent at which stage i starts (a narrowed run spreads the scale over its stages).
  function stagePct(i) {
    if (!RUN.sel) return Math.floor(i * (100 / STAGES.length));
    return Math.floor(RUN.sel.filter(k => k < i).length * (100 / RUN.sel.length));
  }
  // Stage at a progress value.
  function stageAt(progress) {
    if (!RUN.sel) return Math.min(STAGES.length - 1, Math.floor(progress / (100 / STAGES.length)));
    const n = RUN.sel.length;
    return RUN.sel[Math.min(n - 1, Math.floor(progress / (100 / n)))];
  }
  function applyStage(i, quiet) {
    const st = P(RUN.project),
      FN = RUN.final;
    const sid = STAGES[i].id;
    if (sid === "download") mergeDocs(st, FN.docs, false);
    if (sid === "meta") {
      mergeDocs(st, FN.docs, true);
      Object.entries(ENT_KEY).forEach(([k, key]) => {
        st[k] = mergeBy(st[k], FN[k], key);
      });
      if (FN.all_people && !st.all_people) st.all_people = clone(FN.all_people);
      st.events = deriveEvents(st);
    }
    if (sid === "analysis")
      st.findings = mergeBy(
        st.findings,
        FN.findings,
        "id",
        f =>
          emit({
            type: "finding",
            scan_id: RUN.id,
            finding: {
              id: f.id,
              title: f.title,
              sev: f.sev,
              host: f.host,
              rule: (f.provenance && f.provenance.rule) || "",
            },
          }),
        USER_FIELDS,
      );
    if (sid === "network") {
      if (!quiet) subDone();
      st.hosts = mergeBy(st.hosts, FN.hosts, "name");
      st.leaks = { ...(FN.leaks || {}), ...(st.leaks || {}) };
      if (!quiet) {
        // Enumeration: new hosts found by brute force/permutations/PTR/NSEC; TLS: inspected certificates.
        const inf = infraOf(st, RUN.level);
        const n = {
          subdomains: (st.hosts || []).filter(h => ENUM_SRC.test(h.source || "")).length,
          tls: inf.cert.length,
        };
        INFRA_SRC.forEach(k => {
          const x = (RUN.sources || []).find(y => y.id === k);
          if (x && ["wait", "running"].includes(x.status)) {
            Object.assign(x, { status: "ok", n: n[k] });
            emit({ type: "source", scan_id: RUN.id, ...x });
          }
        });
      }
    }
    if (sid === "recon") {
      const rc = FN.recon || emptyRecon();
      if (RUN.level === "external") {
        rc.level = "external";
        rc.sites.forEach(x => {
          x.via = "archive";
        });
        rc.buckets.forEach(b => {
          b.status = "unchecked";
        });
      }
      st.recon = clone(rc);
      st.recon.scan = RUN.id;
      if (!quiet)
        RECON_SRC.forEach(k => {
          const x = (RUN.sources || []).find(y => y.id === k),
            r = rc.sources[k];
          if (x && r && x.status !== "off") {
            Object.assign(x, { status: r.status, n: r.n, error: r.error });
            emit({ type: "source", scan_id: RUN.id, ...x });
          }
        });
    }
    if (sid === "ports" && !quiet) {
      const x = (RUN.sources || []).find(y => y.id === "ports");
      if (x && ["wait", "running"].includes(x.status)) {
        Object.assign(x, {
          status: "ok",
          n: (FN.hosts || []).reduce((a, h) => a + (h.services || []).length, 0),
        });
        emit({ type: "source", scan_id: RUN.id, ...x });
      }
    }
    if (sid === "fuzz" && !quiet && RUN.fuzz) fuzzDone();
    if (HOST_STAGES.includes(sid) && !quiet) hostsDone(sid);
    if (!quiet) {
      persistRun();
      emit({ type: "db", scan_id: RUN.id, project: RUN.project, kind: sid });
    }
  }
  // History record: one rule for done and stopped (countsOf: snapshot, counters, growth in this scan).
  function scanRecord(st, status, reason) {
    const snap = stateSnap(st),
      prev = st.scans[st.scans.length - 1];
    const M = PROFILE_MIN[RUN.profile] || 24;
    const minutes = status === "done" ? M : Math.max(1, Math.round((RUN.progress / 100) * M));
    const rec = {
      id: RUN.id,
      profile_id: RUN.profile,
      profile: PROFILES[RUN.profile],
      active: RUN.active,
      trigger: "manual",
      status,
      reason: reason || null,
      started_at: RUN.started,
      finished_at: addMin(RUN.started, minutes),
      minutes,
      targets: RUN.targets || st.scope.targets.map(t => t.v),
      modules: RUN.modules || [],
      egress: RUN.egress,
      sources: RUN.sources || [],
      ...countsOf(snap, prev ? prev.snapshot : null),
    };
    if (status === "stopped") {
      rec.progress = RUN.progress;
      rec.stage = STAGES[RUN.stage].id;
    }
    // a narrowed run: the chosen items and the stages it executed
    if (RUN.sel) {
      rec.only = RUN.only.slice();
      rec.stages = RUN.sel.map(k => STAGES[k].id);
    }
    return rec;
  }
  function finishScan() {
    const st = P(RUN.project);
    // All stages of the run (idempotent): the outcome does not depend on where the scan was resumed.
    STAGES.forEach((_, k) => (!RUN.sel || RUN.sel.includes(k)) && applyStage(k, true));
    st.docs.forEach(d => {
      if (!d.first_scan) d.first_scan = RUN.id;
    });
    st.hosts.forEach(h => {
      if (!h.first_scan) h.first_scan = RUN.id;
    });
    st.findings.forEach(f => {
      if (!f.first_scan) f.first_scan = RUN.id;
    });
    st.hosts.forEach(h => {
      h.sev = hostSev(st, h);
    });
    const rec = scanRecord(st, "done");
    st.scans.push(rec);
    const id = RUN.id,
      followup = RUN.followup || [];
    RUN = null;
    clearTimeout(tickT);
    persistRun();
    emit({
      type: "done",
      scan_id: id,
      project: st.project.id,
      scan: summaryScan(rec),
      alerts_fired: 0,
      followup,
    });
  }
  const summaryScan = s => {
    const { snapshot, ...rest } = s;
    return rest;
  };
  // Like the core, results found so far carry the scan id at once (not only when the scan finishes).
  function stampFirstScan(st, id) {
    ["docs", "hosts", "findings"].forEach(k =>
      (st[k] || []).forEach(x => {
        if (!x.first_scan) x.first_scan = id;
      }),
    );
  }
  function scanStop(reason = "user") {
    if (!RUN) return { ok: false };
    const st = P(RUN.project);
    const id = RUN.id;
    stampFirstScan(st, id);
    st.scans.push(scanRecord(st, "stopped", reason)); // progress/stage, for resuming (scan_start { resume_from }).
    RUN = null;
    clearTimeout(tickT);
    persistRun();
    emit({ type: "stopped", scan_id: id, project: st.project.id, reason });
    return { ok: true };
  }
  // request_log_clear (docs/API.md): the demo log is rebuilt from the scans on every read, so a clear
  // is kept as a rule: rows of the listed scans (those that existed then), optionally only before a
  // time. A scan started later is never covered. Rows of the running scan stay, like in the core.
  const reqLogGone = (st, r) =>
    (st.reqlog_cut || []).some(
      c => c.scans.includes(r.scan_id) && (!c.before || String(r.time).slice(0, 19) < c.before),
    );
  function reqLogClear({ project, scan_id, days, before, dry_run } = {}) {
    const st = P(project || load().settings.last_project);
    const run = RUN && RUN.project === st.project.id ? RUN.id : null;
    if (scan_id && scan_id === run)
      throw apiErr("busy", "Скан ещё идёт: его журнал запросов можно очистить после завершения", {
        code: "reqlog.scan_running",
        params: {},
      });
    if (days === 0) throw apiErr("bad_args", "days: не меньше 1");
    const cut =
      before ||
      (days
        ? new Date(Date.UTC(2026, 10, 20, 12, 0) - Math.min(days, 36500) * 86400000)
            .toISOString()
            .slice(0, 19)
        : null);
    const rows = COMMANDS.request_log_get({ project: st.project.id, limit: 1e9 }).filter(
      r => (!scan_id || r.scan_id === scan_id) && (!cut || String(r.time).slice(0, 19) < cut),
    );
    const kept = scan_id ? 0 : rows.filter(r => r.scan_id === run).length;
    const scans = [...new Set(rows.map(r => r.scan_id))].filter(id => id !== run);
    if (!dry_run && scans.length) {
      st.reqlog_cut = [...(st.reqlog_cut || []), { scans, before: cut }];
      save();
    }
    return { ok: true, removed: rows.length - kept, kept_running: kept, dry_run: !!dry_run };
  }
  // scan_delete (docs/API.md): erases one scan and what only it produced, like the core. An item first
  // seen in the scan stays when a later scan still listed it (its snapshot) and moves to that scan;
  // the rest goes. A running or paused scan is cancelled first.
  function scanDelete({ project, scan_id: sid, dry_run } = {}) {
    const st = P(project || load().settings.last_project);
    const isRun = !!(RUN && RUN.project === st.project.id && RUN.id === sid);
    const idx = st.scans.findIndex(x => x.id === sid);
    if (!isRun && idx < 0) throw apiErr("not_found", `Скан ${sid} не найден`);
    const mine = x => x.first_scan === sid || (isRun && !x.first_scan);
    const requests = COMMANDS.request_log_get({ project: st.project.id }).filter(
      r => r.scan_id === sid,
    ).length;
    if (dry_run)
      return {
        ok: true,
        scan_id: sid,
        dry_run: true,
        docs: st.docs.filter(mine).length,
        findings: st.findings.filter(mine).length,
        hosts: st.hosts.filter(mine).length,
        requests,
        files: 0,
      };
    if (RUN && RUN.project === st.project.id && !isRun)
      throw apiErr("busy", "Сначала остановите текущий скан проекта");
    if (isRun) {
      RUN = null;
      clearTimeout(tickT);
      persistRun();
    }
    const later = idx < 0 ? [] : st.scans.slice(idx + 1);
    const listed = has => (later.find(has) || {}).id;
    const settle = (arr, key) => {
      const gone = [];
      const keep = (arr || []).filter(x => {
        if (!mine(x)) return true;
        const next = listed(sc => key(sc.snapshot || EMPTY_SNAP, x));
        if (next) x.first_scan = next;
        else gone.push(x);
        return !!next;
      });
      return [keep, gone];
    };
    const [docs, goneDocs] = settle(st.docs, (sn, d) => (sn.docs || []).includes(d.id));
    const [hosts, goneHosts] = settle(st.hosts, (sn, h) => h.name in (sn.hosts || {}));
    const [finds, goneFinds] = settle(st.findings, (sn, f) => String(f.id) in (sn.findings || {}));
    const gd = new Set(goneDocs.map(d => d.id)),
      gh = new Set(goneHosts.map(h => h.name)),
      gf = new Set(goneFinds.map(f => String(f.id)));
    st.docs = docs;
    st.hosts = hosts;
    st.findings = finds.filter(f => !(f.doc != null && gd.has(f.doc)));
    st.findings.forEach(f => {
      if (f.fixed_scan !== sid) return;
      const reopened = (f.tags || []).includes("reopened");
      if (later[0] && !reopened) f.fixed_scan = later[0].id;
      else {
        f.status = "new";
        f.fixed_scan = null;
        f.tags = (f.tags || []).filter(t => t !== "reopened");
      }
    });
    // Entities extracted from the deleted documents.
    Object.keys(ENT_KEY).forEach(k => {
      if (!Array.isArray(st[k])) return;
      st[k] = st[k].filter(e => {
        if (k === "gps") return !gd.has(e.doc);
        if (!Array.isArray(e.docs)) return true;
        const had = e.docs.length;
        e.docs = e.docs.filter(d => !gd.has(typeof d === "object" ? d.id : d));
        return !had || e.docs.length > 0;
      });
    });
    st.events = deriveEvents(st);
    const people = new Set(goneDocs.map(d => d.author).filter(Boolean));
    st.docs.forEach(d => people.delete(d.author));
    st.scans = st.scans.filter(x => x.id !== sid);
    let prev = idx > 0 ? st.scans[idx - 1].snapshot : null;
    st.scans.forEach((x, i) => {
      if (i < Math.max(0, idx)) return;
      const sn = x.snapshot || clone(EMPTY_SNAP);
      sn.docs = (sn.docs || []).filter(d => !gd.has(d));
      sn.people = (sn.people || []).filter(p => !people.has(p));
      gh.forEach(h => delete (sn.hosts || {})[h]);
      gf.forEach(f => delete (sn.findings || {})[f]);
      const { snapshot, ...counts } = countsOf(sn, prev);
      Object.assign(x, i === idx ? counts : { ...counts, new_findings: x.new_findings, added: x.added });
      x.snapshot = snapshot;
      prev = sn;
    });
    save();
    if (isRun) emit({ type: "stopped", scan_id: sid, project: st.project.id, reason: "deleted" });
    return {
      ok: true,
      scan_id: sid,
      dry_run: false,
      docs: goneDocs.length,
      findings: goneFinds.length,
      hosts: goneHosts.length,
      requests,
      files: goneDocs.filter(d => d.status !== "error").length,
    };
  }
  // The running scan is kept in state (STATE.run) so that after an app restart it can be recorded as
  // interrupted.
  function persistRun() {
    const S = load();
    if (RUN) {
      const { final, ...r } = RUN;
      S.run = clone(r);
    } else delete S.run;
    save();
  }
  function recoverRun() {
    const r = STATE.run;
    delete STATE.run;
    const st = r && STATE.projects[r.project];
    if (!st) return;
    RUN = { ...r, paused: false };
    stampFirstScan(st, r.id);
    st.scans = st.scans.filter(s => s.id !== r.id);
    st.scans.push(scanRecord(st, "stopped", "restart"));
    RUN = null;
    save();
  }
  const scanStatus = forProject =>
    !RUN || (forProject && RUN.project !== forProject)
      ? { running: false }
      : {
          running: true,
          scan_id: RUN.id,
          project: RUN.project,
          profile: PROFILES[RUN.profile],
          profile_id: RUN.profile,
          active: RUN.active,
          level: RUN.level,
          progress: RUN.progress,
          stage: STAGES[RUN.stage].id,
          paused: RUN.paused,
          targets: RUN.targets,
          modules: RUN.modules,
          started_at: RUN.started,
          resumed: !!RUN.resumed,
          egress: RUN.egress,
          substep: RUN.substep || null,
          controls: controlCaps(),
          held: [...(RUN.held || [])].sort(),
          followup: RUN.followup || [],
          only: RUN.only || [],
          stages: RUN.sel ? RUN.sel.map(k => STAGES[k].id) : null,
        };

  // ================= commands (names = Tauri commands) =================
  const SNAP_KEYS = [
    "project",
    "scope",
    "docs",
    "people",
    "emails",
    "patterns",
    "hosts",
    "pcs",
    "software",
    "paths",
    "printers",
    "secrets",
    "findings",
    "gps",
    "events",
    "scans",
    "reports",
    "leaks",
  ];
  // Derived entities are computed from LIVE documents (excluding deleted ones) on every snapshot, so they
  // survive reloads.
  function liveView(o) {
    const del = new Set(o.docs.filter(d => d.deleted).map(d => d.id));
    if (!del.size) return;
    const an = o.docs.filter(d => !d.deleted && d.status === "analyzed");
    const sw = countBy(an, d => d.software),
      pr = countBy(an, d => d.printer),
      fo = countBy(an, d => d.folder),
      au = countBy(an, d => d.author);
    o.software = o.software.map(s => ({ ...s, docs: sw.get(s.id) || 0 })).filter(s => s.docs > 0);
    o.printers = o.printers.map(p => ({ ...p, docs: pr.get(p.name) || 0 })).filter(p => p.docs > 0);
    o.paths = o.paths.map(p => ({ ...p, docs: fo.get(p.path) || 0 })).filter(p => p.docs > 0);
    o.people.forEach(p => {
      if (p.src_kind === "meta") p.docs = au.get(p.login) || 0;
      else if (del.has(p.src_doc)) p.src_deleted = true;
    });
    const pcOf = l => (o.people.find(x => x.login === l) || {}).pc;
    o.pcs.forEach(p => {
      p.docs = an.filter(
        d =>
          pcOf(d.author) === p.name ||
          (d.folder || "").includes(p.name) ||
          (d.printer || "").includes(p.name) ||
          (d.rdp && d.rdp.gateway === p.name) ||
          (d.lnk && d.lnk.machine === p.name),
      ).length;
    });
    o.gps = o.gps.filter(g => !del.has(g.doc));
    o.secrets = o.secrets.filter(x => !del.has(x.doc));
    o.events = o.events.filter(e => !e.ref || e.ref.type !== "doc" || !del.has(e.ref.id));
  }
  // Document secrets and {{s:…}} fragments in evidence reach the UI only as masks; the value comes from
  // secret_reveal.
  const maskOf = v => {
    v = String(v ?? "");
    return v.length > 10 ? v.slice(0, 3) + "••••••••" + v.slice(-2) : "••••••••";
  };
  // Standards of the finding rules used by the demo: a copy of crates/foca-analysis/signatures/standards.toml
  // (fields: MITRE ATT&CK v20 | CWE | OWASP Top 10:2025 | WSTG | ISO/IEC 27001 | NIST SP 800-53 = НД ТЗІ 3.6-006-24 |
  // privacy | НД ТЗІ 2.5-004-99 | НД ТЗІ 3.7-003-05); cwe_top25 = CWE ids in the 2025 CWE Top 25.
  // The core attaches the same object to every finding (snapshot, finding_get); unmapped rules → null.
  const STD_KEYS = ["mitre", "cwe", "owasp", "wstg", "iso27001", "nist", "privacy", "ndtzi", "kszi"];
  const CWE_TOP25 =
    "79 89 352 862 787 22 416 125 78 94 120 434 476 121 502 122 863 20 284 200 306 918 77 639 770"
      .split(" ")
      .map(n => "CWE-" + n);
  const DEMO_STANDARDS = {
    revisions: "T1213|CWE-212|||8.10 8.12|AC-22|||6.1.2.5",
    thumbnail: "|CWE-212|||8.10 8.12|AC-22|||6.1.2.5",
    gps: "T1591.001|CWE-359|A01:2025||5.34 8.12|AC-22 SI-12(1)|gdpr-5-1-c gdpr-5-1-f gdpr-32 ua2297-6 ua2297-24||6.1.2.5",
    pii: "T1213|CWE-359|A01:2025||5.34 8.11 8.12|AC-22 SI-12(1)|gdpr-5-1-c gdpr-5-1-f gdpr-32 ua2297-6 ua2297-24||6.1.2.5",
    secret: "T1552.001|CWE-798|A07:2025|WSTG-INFO-01|5.17 8.12|IA-5(7)||НИ|6.1.2.5",
    "doc.bad_redaction": "T1213|CWE-212|||8.11 8.12|AC-22|||6.1.2.5",
    "doc.hidden_content": "T1213|CWE-212|||8.10 8.12|AC-22|||6.1.2.5",
    "doc.pdf_removed_text": "T1213|CWE-212|||8.10 8.12|AC-22|||6.1.2.5",
    "doc.pdf_revision_authors":
      "|CWE-212|||8.10|AC-22 SI-12(1)|gdpr-5-1-c gdpr-5-1-f gdpr-32 ua2297-6 ua2297-24||6.1.2.7",
    "doc.modified_after_signing": "T1565.001||||8.24|||ЦВ НА|6.1.2.5",
    "doc.signer_identity":
      "T1589.001||||5.34|SI-12(1)|gdpr-5-1-c gdpr-5-1-f gdpr-32 ua2297-6 ua2297-24||6.1.2.7",
    "doc.signature_tsa_gap": "||||8.24|||НА|",
    "doc.data_connection": "T1590|CWE-497|A01:2025||8.12|AC-22|||6.1.2.4",
    "doc.lnk_host_mac": "T1592.001|CWE-497|A01:2025||8.12|AC-22|||6.1.2.4",
    "doc.lnk_unc_path": "T1135|CWE-497|A01:2025||8.12|AC-22|||6.1.2.4",
    "doc.lineage": "||||5.9 5.12||||6.1.2.5",
    "mail.internal_relay": "T1590.005|CWE-497|A01:2025||8.12 8.21|AC-22|||6.1.2.4",
    "mail.originating_ip": "|CWE-497|A01:2025||8.21|AC-22|||6.1.2.4",
    "mail.reply_to_mismatch": "T1566||||6.3|AT-2(3)|||6.1.2.7",
    "pim.contact_pii":
      "|CWE-359|A01:2025||5.34 8.12|AC-22 SI-12(1)|gdpr-5-1-c gdpr-5-1-f gdpr-32 ua2297-6 ua2297-24||6.1.2.7",
    "media.device_serial": "T1592.001||||8.12|AC-22|||6.1.2.4",
    "zip.path_traversal": "|CWE-22|A01:2025||8.7|SI-10|||",
    "net.internal_map": "T1590||||8.12 8.22||||6.1.2.4",
    "org.structure": "||||8.12||||6.1.2.7",
    "sw.kev": "|CWE-1104|A03:2025||8.8|RA-5 SI-2|||6.6",
    "recon.web.hsts_missing": "T1557|CWE-319|A04:2025|WSTG-CONF-07|8.24|SC-8||КВ|",
  };
  const standardsOf = rule => {
    const enc = DEMO_STANDARDS[rule];
    if (!enc) return null;
    const parts = enc.split("|");
    const s = Object.fromEntries(STD_KEYS.map((k, i) => [k, parts[i] ? parts[i].split(" ") : []]));
    s.cwe_top25 = s.cwe.filter(c => CWE_TOP25.includes(c));
    return s;
  };
  const SECRET_RX = /\{\{s:([\s\S]*?)\}\}/g;
  function maskSecrets(o) {
    o.secrets.forEach(x => {
      x.mask = maskOf(x.value);
      delete x.value;
    });
    o.findings.forEach(f => {
      let k = 0;
      const refs = [];
      f.evidence = String(f.evidence || "").replace(SECRET_RX, (_, v) => {
        refs.push(`f${f.id}:${k++}`);
        return `{{s:${maskOf(v)}}}`;
      });
      f.secret_refs = refs;
      f.standards = standardsOf((f.provenance || {}).rule);
    });
  }
  const publicSettings = () => {
    const s = clone(load().settings);
    if (s.sec) {
      delete s.sec.pin_hash;
      delete s.sec.panic_hash;
      s.sec.pin_set = !!load().settings.sec.pin_hash;
    }
    return s;
  };
  const snapshot = id => {
    const st = P(id);
    const out = {};
    SNAP_KEYS.forEach(k => {
      out[k] = clone(st[k] ?? (k === "leaks" ? {} : []));
    });
    liveView(out);
    out.hosts.forEach(h => {
      delete h.tech_s1;
    }); // Internal generator field (fingerprint history), not part of the contract.
    out.docs.forEach(d => {
      d.cleaned = (st.cleaned || {})[d.id] || null;
    });
    maskSecrets(out);
    out.settings = publicSettings();
    out.scan = scanStatus(id);
    out.oos = oosOf(st);
    out.recon = clone(st.recon || emptyRecon());
    return out;
  };
  // ---- report: result snapshot at build time; risk is computed over the included findings ----
  function reportResult(st, opts) {
    const R = RULES();
    const sel = R.reportSelect(st.findings, opts, opts.picked || []);
    const counts = Object.fromEntries(
      ["crit", "high", "warn", "low", "info"].map(k => [k, sel.main.filter(f => f.sev === k).length]),
    );
    const risk = R.analyzedScans(st.scans) ? R.riskScore(sel.main) : null;
    const sec = opts.sections || {};
    // Same formula as foca-report `pages_estimate`: the short summary lists findings as table rows.
    const pw =
      opts.tpl_id === "brief"
        ? [1, 0.5, 0.5, 0.04, 0.03, 2, 2, 3, 6, 2, 1]
        : [3, 2, 2, 1.6, 0.5, 4, 5, 6, 12, 4, 2];
    const pages = ["csv", "json"].includes(opts.fmt)
      ? null
      : Math.max(
          pw[10],
          Math.round(
            pw[0] +
              (sec.summary !== false ? pw[1] : 0) +
              (sec.scope !== false ? pw[2] : 0) +
              (sec.findings !== false ? sel.main.length * pw[3] : 0) +
              (sec.fixed ? sel.fixed.length * pw[4] : 0) +
              (sec.people ? pw[5] : 0) +
              (sec.infra ? pw[6] : 0) +
              (sec.docs ? pw[7] : 0) +
              (sec.log ? pw[8] : 0) +
              (sec.appx ? pw[9] : 0),
          ),
        );
    return {
      finding_ids: sel.main.map(f => f.id),
      fixed_ids: sec.fixed === false ? [] : sel.fixed.map(f => f.id),
      counts,
      total: sel.main.length,
      risk,
      risk_level: R.riskLevel(risk, counts.crit > 0),
      pages,
      project_risk: riskOf(st),
      at_scan: (st.scans[st.scans.length - 1] || {}).id || null,
    };
  }
  const kbStr = k =>
    k >= 1024
      ? `${(k / 1024).toFixed(1).replace(".", ",")}\u00a0МБ`
      : `${Math.max(1, Math.round(k))}\u00a0КБ`;
  // Report templates of report_templates / report_build.template (same ids and texts as the core).
  const REPORT_TEMPLATES = {
    UA: [
      [
        "full",
        "Повний звіт",
        "Обкладинка, резюме, скоуп, усі знахідки з доказами, інфраструктура, діаграми та додатки.",
      ],
      [
        "executive",
        "Для керівництва (1 сторінка)",
        "Ризик-скор, п'ять головних знахідок простою мовою і три першочергові дії, без технічних таблиць.",
      ],
      [
        "compliance",
        "КСЗІ / Відповідність",
        "Знахідки × стандарти: MITRE ATT&CK v20, CWE, OWASP Top 10:2025, ISO/IEC 27001, заходи НД ТЗІ 3.6-006-24 / NIST SP 800-53, захист персональних даних; послуги НД ТЗІ 2.5-004-99 та етапи НД ТЗІ 3.7-003-05 для систем, атестованих за КСЗІ; із застереженням аудитора.",
      ],
      [
        "lab",
        "Лабораторна робота",
        "Мета, методика, вихідні дані, хід дослідження, таблиця знахідок зі стандартами, висновки; поля «Виконав / Перевірив».",
      ],
    ],
    RU: [
      [
        "full",
        "Полный отчёт",
        "Обложка, резюме, скоуп, все находки с доказательствами, инфраструктура, диаграммы и приложения.",
      ],
      [
        "executive",
        "Для руководства (1 страница)",
        "Риск-скор, пять главных находок простым языком и три первоочередных действия, без технических таблиц.",
      ],
      [
        "compliance",
        "КСЗИ / Соответствие",
        "Находки × стандарты: MITRE ATT&CK v20, CWE, OWASP Top 10:2025, ISO/IEC 27001, меры НД ТЗІ 3.6-006-24 / NIST SP 800-53, защита персональных данных; услуги НД ТЗІ 2.5-004-99 и этапы НД ТЗІ 3.7-003-05 для систем, аттестованных по КСЗИ; с оговоркой аудитора.",
      ],
      [
        "lab",
        "Лабораторная работа",
        "Цель, методика, исходные данные, ход исследования, таблица находок со стандартами, выводы; поля «Выполнил / Проверил».",
      ],
    ],
    EN: [
      [
        "full",
        "Full report",
        "Cover, summary, scope, all findings with evidence, infrastructure, diagrams and appendices.",
      ],
      [
        "executive",
        "Executive (1 page)",
        "Risk score, top five findings in plain language and three priority actions: no technical tables.",
      ],
      [
        "compliance",
        "КСЗІ / Compliance",
        "Findings × standards: MITRE ATT&CK v20, CWE, OWASP Top 10:2025, ISO/IEC 27001, НД ТЗІ 3.6-006-24 / NIST SP 800-53 measures, personal data protection; НД ТЗІ 2.5-004-99 services and НД ТЗІ 3.7-003-05 stages for systems certified under КСЗІ; with the auditor's disclaimer.",
      ],
      [
        "lab",
        "Laboratory work",
        'Goal, method, input data, course of the study, findings with standards, conclusions; "Performed / Checked by" fields.',
      ],
    ],
  };
  const reportTemplates = lang => {
    const l = String(lang || "RU").toUpperCase();
    const key = l === "UK" || l === "UA" ? "UA" : l === "EN" ? "EN" : "RU";
    return REPORT_TEMPLATES[key].map(([id, title, description]) => ({ id, title, description }));
  };
  const reportSize = (st, opts, res) =>
    opts.fmt === "pdf"
      ? kbStr(180 * res.pages + 300)
      : opts.fmt === "html"
        ? kbStr(90 * res.pages + 200)
        : opts.fmt === "md"
          ? kbStr(2 + res.total * 1.2)
          : kbStr(20 + st.docs.filter(d => !d.deleted).length * 0.4 + res.total * 2);
  // Report file name: language → prefix; CSV/JSON have no language ("Data_…"); the version counter is per
  // project.
  const reportName = (st, lang, fmt) => {
    const n =
      st.reports.reduce(
        (a, r) => Math.max(a, +((String(r.name).match(/_v(\d+)\.[a-z]+$/) || [])[1] || 0)),
        0,
      ) + 1;
    const pre =
      fmt === "csv" || fmt === "json"
        ? "Data"
        : lang === "UA"
          ? "Звіт_пентест"
          : lang === "EN"
            ? "Pentest_report"
            : "Отчёт_пентест";
    return `${pre}_${st.project.name}_v${n}.${fmt}`;
  };
  function demoWordlist(st, a = {}) {
    const kind = String(a.kind || "logins")
      .trim()
      .toLowerCase();
    if (kind !== "logins" && kind !== "context") throw apiErr("bad_args", `вид словаря ${kind}`);
    const lower = a.lowercase !== false;
    const limit = Math.max(1, Math.min(500, Number(a.limit || 100)));
    const years = a.include_years === false ? [] : ["2024", "2025", "2026"];
    let ad = a.ad_domain ? String(a.ad_domain).trim().toUpperCase().replace(/\\+$/, "") : null;
    if (!ad) {
      for (const p of st.people || []) {
        const m = String(p.login || "").match(/^([A-Za-z0-9_-]{2,15})\\[^\\\s]+$/);
        if (m) {
          ad = m[1].toUpperCase();
          break;
        }
      }
    }
    const fmtCase = s => (lower ? s.toLowerCase() : s);
    if (kind === "logins") {
      const set = new Set();
      const patMap = new Map();
      const addPat = (id, label, v) => {
        if (!v) return;
        const f = fmtCase(v);
        set.add(f);
        if (!patMap.has(id)) patMap.set(id, { id, label, items: new Set() });
        patMap.get(id).items.add(f);
        if (ad && !f.includes("\\") && !f.includes("@")) {
          const df = `${lower ? ad.toLowerCase() : ad}\\${f}`;
          set.add(df);
          if (!patMap.has("{DOMAIN}\\{login}")) {
            patMap.set("{DOMAIN}\\{login}", {
              id: "{DOMAIN}\\{login}",
              label: `${ad}\\i.petrov`,
              items: new Set(),
            });
          }
          patMap.get("{DOMAIN}\\{login}").items.add(df);
        }
      };
      for (const p of st.people || []) {
        if (p.service && !a.include_service) continue;
        const base = String(p.login || "")
          .split("\\")
          .pop();
        if (base) set.add(fmtCase(base));
        const parts = base.split(/[._]/).filter(Boolean);
        if (parts.length >= 2) {
          const [a0, b0] = parts;
          const fi = a0[0] || "";
          addPat("{f}.{last}", "i.petrov", `${fi}.${b0}`);
          addPat("{first}.{last}", "ivan.petrov", `${a0}.${b0}`);
          addPat("{f}{last}", "ipetrov", `${fi}${b0}`);
          addPat("{first}{last}", "ivanpetrov", `${a0}${b0}`);
          addPat("{last}_{f}", "petrov_i", `${b0}_${fi}`);
        }
      }
      const full = [...set].sort();
      const items = full.slice(0, limit);
      const patterns = [...patMap.values()].map(x => ({
        id: x.id,
        label: x.label,
        count: x.items.size,
        examples: [...x.items].sort().slice(0, 4),
      }));
      return { kind, count: items.length, total: full.length, ad_domain: ad, patterns, items };
    }
    const stems = new Set();
    const addStem = s => {
      for (const w of String(s || "")
        .toLowerCase()
        .split(/[^a-z0-9-]+/)) {
        const t = w.replace(/^-+|-+$/g, "");
        if (t.length >= 3 && t.length <= 24) stems.add(t);
      }
    };
    addStem(st.project && st.project.name);
    addStem(st.scope && st.scope.client);
    (st.hosts || []).slice(0, 8).forEach(h => addStem(String(h.name || "").split(".")[0]));
    (st.pcs || []).slice(0, 8).forEach(pc => addStem(String(pc.name || "").split(".")[0]));
    const ctx = new Set();
    for (const s of [...stems].slice(0, 20)) {
      ctx.add(fmtCase(s));
      ctx.add(fmtCase(`${s}123`));
      ctx.add(fmtCase(`${s}!`));
      for (const y of years) {
        ctx.add(fmtCase(`${s}${y}`));
        ctx.add(fmtCase(`${s}${y}!`));
      }
    }
    const full = [...ctx].sort();
    const items = full.slice(0, limit);
    return { kind, count: items.length, total: full.length, ad_domain: ad, patterns: [], items };
  }
  // ---- export: file name and size come from the core; contents are built from the same snapshot data ----
  const EXPORT_EXT = {
    dict: "txt",
    csv: "csv",
    json: "json",
    maltego: "csv",
    md: "md",
    httpx: "txt",
    nuclei: "txt",
    stix: "json",
  };
  function exportBuild(st, a) {
    const fmt = a.fmt || "csv",
      o = a.opts || {},
      kind = a.kind || "all";
    const live = st.docs.filter(d => !d.deleted);
    const n = Array.isArray(o.items)
      ? o.items.length
      : ({
          findings: st.findings.length,
          users: st.people.length,
          emails: st.emails.length,
          paths: st.paths.length,
          software: st.software.length,
          hosts: st.hosts.length,
          docs: live.length,
          log: live.length * 2,
        }[kind] ?? live.length + st.findings.length + st.people.length + st.hosts.length);
    const ext =
      fmt === "maltego" && o.mal === "graphml"
        ? "graphml"
        : fmt === "md" && o.md !== "one"
          ? "zip"
          : EXPORT_EXT[fmt] || "csv";
    const slug =
      {
        findings: "findings",
        users: "users",
        emails: "emails",
        paths: "paths",
        software: "software",
        hosts: "hosts",
        docs: "documents",
        log: "requests-log",
        all: "project",
      }[kind] || "export";
    const labelSlug =
      fmt === "dict"
        ? "dict-" + (o.dict || "users")
        : fmt === "stix" || fmt === "httpx" || fmt === "nuclei"
          ? fmt
          : slug;
    const name = `${st.project.name.replace(/\..*$/, "")}_${labelSlug}_${TODAY}.${ext}`;
    const per =
      { dict: 0.02, csv: 0.25, json: 0.6, maltego: 0.3, md: 0.9, stix: 0.8, httpx: 0.05, nuclei: 0.08 }[
        fmt
      ] || 0.3;
    return {
      name,
      path: `Download/FOCA-rs/${name}`,
      size: kbStr(n * per * (kind === "log" ? 0.4 : 1) + 2),
      count: n,
      secrets: fmt === "stix" ? false : !!o.secrets,
      pii_redacted: fmt === "stix" ? true : !!o.pii,
    };
  }
  // ---- i18n_bundle: synced from locales/{en,ru,uk}/ui.json ----
  const DEMO_I18N_UI = {
    en: {
      "app.name": "FOCA-rs",
      "app.active_mode": "ACTIVE MODE",
      "app.offline": "Offline: showing saved data",
      "app.secrets_open": "Secrets unlocked",
      "app.secrets_close": "Close",
      "app.secrets_close_aria": "Lock access to secrets",
      "app.secrets_hidden": "Secrets hidden",
      "app.back": "Back",
      "app.menu": "Menu",
      "app.search": "Search",
      "app.nav_aria": "Project sections",
      "app.mini_open_aria": "Open scan screen",
      "app.copied": "Copied · clipboard clears in 30 s",
      "nav.overview": "Overview",
      "nav.findings": "Findings",
      "nav.data": "Data",
      "nav.reports": "Reports",
      "menu.projects": "All projects",
      "menu.projects_sub": "Switch or import project",
      "menu.scope": "Scope",
      "menu.rules": "Search rules",
      "menu.rules_sub": "Custom patterns and built-in presets",
      "menu.offline": "Analyze files offline",
      "menu.offline_sub": "Folder, files or ZIP from device",
      "menu.ai": "AI summary",
      "menu.ai_sub": "Cloud summary with redaction",
      "menu.settings": "Settings",
      "menu.theme_light": "Light theme",
      "menu.theme_dark": "Dark theme",
      "menu.demo": "Demo screen states",
      "menu.demo_sub": "Empty, loading, error, offline",
      "menu.help": "Help",
      "sev.crit": "Critical",
      "sev.high": "High",
      "sev.warn": "Medium",
      "sev.low": "Low",
      "sev.info": "Info",
      "sev.ok": "OK",
      "doc_status.analyzed": "Analyzed",
      "doc_status.downloaded": "Downloaded",
      "doc_status.queued": "Queued",
      "doc_status.error": "Error 403",
      "common.empty": "Nothing here yet",
      "common.error_title": "Failed to load",
      "common.error_text": "Check your connection and try again.",
      "common.retry": "Retry",
      "common.cancel": "Cancel",
      "common.save": "Save",
      "common.close": "Close",
      "common.delete": "Delete",
      "common.open": "Open",
      "common.add": "Add",
      "common.done": "Done",
      "common.refresh": "Refresh",
      "common.details": "Details",
      "common.loading": "Loading…",
      "common.yes": "Yes",
      "common.no": "No",
      "common.all": "All",
      "common.found": "Found",
      "common.nothing_found": "Nothing found",
      "common.see_also": "See also",
      "common.demo_confirm": "Demo: confirm",
      "common.confirm_finger": "Confirm with biometrics",
      "common.confirm_finger_sub": "To {what}, touch the fingerprint sensor.",
      "common.confirm_finger_note":
        "Secrets stay unlocked for {minutes} min. Until you leave the app or lock the device.",
      "common.show_secret": "reveal secret",
      "overview.title": "Overview",
      "overview.new_scan": "New scan",
      "overview.start_scan": "Start scan",
      "overview.add_target": "Add target",
      "overview.empty_title": "No targets yet",
      "overview.empty_text": "Add a domain, URL, IP or CIDR range to start reconnaissance.",
      "overview.scan_running": "Scan in progress",
      "overview.scan_never": "No scan run yet",
      "overview.scan_no_data": "No project data yet",
      "overview.scan_done": "Scan completed",
      "overview.scan_stopped": "Scan stopped",
      "overview.profile_fmt": "profile «{profile}»",
      "overview.active_tag": "active",
      "overview.other_scan": "Scanning project «{name}». Start a new scan here after it finishes or stops.",
      "overview.open_project": "Open project",
      "overview.opening_project": "Opening project…",
      "overview.project": "Project",
      "projects.title": "Projects",
      "projects.new": "New project",
      "projects.import_enc": "Import .foca.enc",
      "projects.export_enc": "Export .foca.enc (encrypted)",
      "projects.export_enc_sub": "PBKDF2 + ChaCha20-Poly1305 container",
      "projects.password": "Container password",
      "projects.include_files": "Include downloaded documents",
      "launch.title": "New scan",
      "launch.targets_placeholder": "Domain (example.com, *.example.com), URL (http/https), IP or CIDR",
      "launch.email_hint": "To search by corporate domain, enter the domain itself (e.g. {domain})",
      "launch.profile_passive": "Passive",
      "launch.profile_std": "Standard",
      "launch.profile_full": "Full",
      "launch.profile_custom": "Custom",
      "settings.title": "Settings",
      "settings.sec_scan": "Scanning",
      "settings.sec_device": "Device",
      "settings.sec_app": "Application",
      "settings.sec_info": "Info",
      "settings.keys": "API keys",
      "settings.sources": "Sources",
      "settings.wordlists": "Wordlists",
      "settings.signatures": "Signature databases",
      "settings.plugins": "Plugins",
      "settings.ai": "Cloud AI assistant",
      "settings.network": "Network & proxy",
      "settings.power": "Traffic & power",
      "settings.background": "Background execution",
      "settings.alerts": "Alerts & monitoring",
      "settings.security": "Security",
      "settings.appearance": "Appearance",
      "settings.appearance_sub": "{theme} theme · {lang} · font {fs}%",
      "settings.debug": "Debug & diagnostics",
      "settings.about": "About",
      "settings.licenses": "Licenses & third-party components",
      "settings.help": "Help",
      "settings.help_sub": "Offline guide and glossary",
      "look.title": "Appearance",
      "look.theme": "Theme",
      "look.theme_system": "System",
      "look.theme_dark": "Dark",
      "look.theme_light": "Light",
      "look.lang": "Interface language",
      "look.lang_auto": "System (auto)",
      "look.lang_en": "English",
      "look.lang_ru": "Русский",
      "look.lang_uk": "Українська",
      "look.lang_auto_hint":
        "Follows device locale ({resolved}); unsupported system languages fall back to English. Report language can still be overridden in the report builder.",
      "look.lang_manual_hint":
        "Interface, alerts and default report templates use {resolved}. Report language can still be overridden in the report builder.",
      "look.lang_switched": "Language: {label}",
      "look.font_size": "Font size",
      "look.density": "Density",
      "look.density_compact": "Compact",
      "look.density_normal": "Normal",
      "look.density_airy": "Airy",
      "look.preview": "Preview",
      "look.sample_finding": "Sample finding",
      "look.sample_sub": "host · source",
      "help.title": "Help",
      "help.sub": "works offline",
      "help.search_placeholder": 'Search: "captcha", "threads", "Tor"…',
      "help.search_aria": "Search help",
      "help.empty_text": 'Try another word: "captcha", "background", "key", "scope".',
      "help.not_found": "Article not found",
      "help.not_found_text": "Open the Help section and find what you need via search.",
      "help.offline_note": "Help works completely offline.",
      "help.glossary": "Glossary",
      "help.extra_key_group": "Additional, with API key",
      "help.pill_active": "active",
      "help.pill_passive": "passive",
      "help.help_aria": "Help",
      "help.rec_pill": "recommended {min}-{max}{unit}",
      "help.dec_aria": "Decrease: {label}",
      "help.inc_aria": "Increase: {label}",
      "help.err_empty": "Enter a number from {min} to {max}",
      "help.err_int": "Whole integer only, no letters or decimals",
      "help.err_min": "Minimum {min}{unit}{why}",
      "help.err_max": "Maximum {max}{unit}{why}",
      "ai.title": "Cloud AI assistant",
      "ai.summary_title": "AI summary",
      "ai.provider": "Provider",
      "ai.model": "Model",
      "ai.refresh_models": "Refresh models",
      "ai.thinking": "Thinking / reasoning",
      "ai.generate": "Generate summary",
      "ai.thoughts": "Model reasoning",
      "insights.attack_paths": "Attack Paths",
      "insights.choke_points": "Remediation Choke Points",
      "insights.no_paths": "No multi-step compromise chains detected yet.",
      "signatures.title": "Signature databases",
      "signatures.update": "Check & update",
      "signatures.import": "Import bundle",
      "signatures.rollback": "Rollback",
      "licenses.title": "Licenses & components",
      "licenses.tab_data": "Data & assets",
      "licenses.tab_rust": "Rust crates",
      "licenses.tab_android": "Android libs",
      "licenses.tab_texts": "License texts",
      "licenses.search_placeholder": "Filter by name, crate or license…",
      "licenses.flavor_foss": "FOSS (GPL-3.0 / F-Droid clean, no ML Kit)",
      "licenses.flavor_play": "Play (includes Google ML Kit OCR)",
      "about.title": "About",
      "about.version": "Version",
      "about.build": "Build flavor",
      "about.license": "License",
      "about.repo": "Source code",
      "about.licenses_row": "Licenses & third-party components",
      "about.licenses_sub": "Rust crates, Android libraries, datasets and full license texts",
    },
    ru: {
      "app.name": "FOCA-rs",
      "app.active_mode": "АКТИВНЫЙ РЕЖИМ",
      "app.offline": "Нет сети: показаны сохранённые данные",
      "app.secrets_open": "Секреты открыты",
      "app.secrets_close": "Закрыть",
      "app.secrets_close_aria": "Закрыть доступ к секретам",
      "app.secrets_hidden": "Секреты скрыты",
      "app.back": "Назад",
      "app.menu": "Меню",
      "app.search": "Поиск",
      "app.nav_aria": "Разделы проекта",
      "app.mini_open_aria": "Открыть экран скана",
      "app.copied": "Скопировано · буфер очистится через 30 с",
      "nav.overview": "Обзор",
      "nav.findings": "Находки",
      "nav.data": "Данные",
      "nav.reports": "Отчёты",
      "menu.projects": "Все проекты",
      "menu.projects_sub": "Сменить или импортировать проект",
      "menu.scope": "Скоуп",
      "menu.rules": "Правила поиска",
      "menu.rules_sub": "Свои шаблоны и готовые наборы",
      "menu.offline": "Разобрать файлы без сети",
      "menu.offline_sub": "Папка, файлы или ZIP с телефона",
      "menu.ai": "ИИ-сводка",
      "menu.ai_sub": "Облачная сводка с редакцией секретов",
      "menu.settings": "Настройки",
      "menu.theme_light": "Светлая тема",
      "menu.theme_dark": "Тёмная тема",
      "menu.demo": "Демо-состояния экранов",
      "menu.demo_sub": "Пусто, загрузка, ошибка, нет сети",
      "menu.help": "Помощь",
      "sev.crit": "Критический",
      "sev.high": "Высокий",
      "sev.warn": "Средний",
      "sev.low": "Низкий",
      "sev.info": "Инфо",
      "sev.ok": "Норма",
      "doc_status.analyzed": "Проанализирован",
      "doc_status.downloaded": "Скачан",
      "doc_status.queued": "В очереди",
      "doc_status.error": "Ошибка 403",
      "common.empty": "Пока пусто",
      "common.error_title": "Не удалось загрузить",
      "common.error_text": "Проверьте подключение и попробуйте снова.",
      "common.retry": "Повторить",
      "common.cancel": "Отмена",
      "common.save": "Сохранить",
      "common.close": "Закрыть",
      "common.delete": "Удалить",
      "common.open": "Открыть",
      "common.add": "Добавить",
      "common.done": "Готово",
      "common.refresh": "Обновить",
      "common.details": "Подробнее",
      "common.loading": "Загрузка…",
      "common.yes": "Да",
      "common.no": "Нет",
      "common.all": "Все",
      "common.found": "Найдено",
      "common.nothing_found": "Ничего не нашлось",
      "common.see_also": "См. также",
      "common.demo_confirm": "Демо: подтвердить",
      "common.confirm_finger": "Подтвердите отпечатком",
      "common.confirm_finger_sub": "Чтобы {what}, приложите палец к сканеру.",
      "common.confirm_finger_note":
        "Секреты будут открыты {minutes} мин. До ухода из приложения или до блокировки.",
      "common.show_secret": "показать секрет",
      "overview.title": "Обзор",
      "overview.new_scan": "Новый скан",
      "overview.start_scan": "Начать скан",
      "overview.add_target": "Добавить цель",
      "overview.empty_title": "Целей пока нет",
      "overview.empty_text": "Добавьте домен, URL, IP или сеть CIDR, чтобы начать разведку.",
      "overview.scan_running": "Скан идёт",
      "overview.scan_never": "Скан не запускался",
      "overview.scan_no_data": "Данных по проекту пока нет",
      "overview.scan_done": "Скан завершён",
      "overview.scan_stopped": "Скан остановлен",
      "overview.profile_fmt": "профиль «{profile}»",
      "overview.active_tag": "активный",
      "overview.other_scan":
        "Идёт скан проекта «{name}». Новый скан здесь: после его завершения или остановки.",
      "overview.open_project": "Открыть проект",
      "overview.opening_project": "Открываем проект…",
      "overview.project": "Проект",
      "projects.title": "Проекты",
      "projects.new": "Новый проект",
      "projects.import_enc": "Импорт .foca.enc",
      "projects.export_enc": "Экспорт .foca.enc (зашифрованный)",
      "projects.export_enc_sub": "Контейнер PBKDF2 + ChaCha20-Poly1305",
      "projects.password": "Пароль контейнера",
      "projects.include_files": "Включить скачанные документы",
      "launch.title": "Новый скан",
      "launch.targets_placeholder": "Домен (example.com, *.example.com), URL (http/https), IP или CIDR",
      "launch.email_hint": "Для поиска по домену организации введите сам домен (например, {domain})",
      "launch.profile_passive": "Пассивный",
      "launch.profile_std": "Стандартный",
      "launch.profile_full": "Полный",
      "launch.profile_custom": "Свой",
      "settings.title": "Настройки",
      "settings.sec_scan": "Сканирование",
      "settings.sec_device": "Устройство",
      "settings.sec_app": "Приложение",
      "settings.sec_info": "Сведения",
      "settings.keys": "Ключи API",
      "settings.sources": "Источники",
      "settings.wordlists": "Словари",
      "settings.signatures": "Базы сигнатур",
      "settings.plugins": "Плагины",
      "settings.ai": "Облачный ИИ-ассистент",
      "settings.network": "Сеть и прокси",
      "settings.power": "Трафик и питание",
      "settings.background": "Работа в фоне",
      "settings.alerts": "Алерты и мониторинг",
      "settings.security": "Безопасность",
      "settings.appearance": "Внешний вид",
      "settings.appearance_sub": "{theme} тема · {lang} · шрифт {fs}%",
      "settings.debug": "Отладка и диагностика",
      "settings.about": "О программе",
      "settings.licenses": "Лицензии и сторонние компоненты",
      "settings.help": "Помощь",
      "settings.help_sub": "Офлайн-справка и глоссарий",
      "look.title": "Внешний вид",
      "look.theme": "Тема",
      "look.theme_system": "Системная",
      "look.theme_dark": "Тёмная",
      "look.theme_light": "Светлая",
      "look.lang": "Язык интерфейса",
      "look.lang_auto": "Системный (авто)",
      "look.lang_en": "English",
      "look.lang_ru": "Русский",
      "look.lang_uk": "Українська",
      "look.lang_auto_hint":
        "Определяется по языку телефона ({resolved}); неподдерживаемые языки системы переключаются на English. Язык отчёта всегда можно выбрать отдельно в конструкторе.",
      "look.lang_manual_hint":
        "Интерфейс, оповещения и шаблоны отчётов используют {resolved}. Язык отчёта также можно выбрать отдельно в конструкторе.",
      "look.lang_switched": "Язык: {label}",
      "look.font_size": "Размер шрифта",
      "look.density": "Плотность",
      "look.density_compact": "Компактная",
      "look.density_normal": "Обычная",
      "look.density_airy": "Свободная",
      "look.preview": "Предпросмотр",
      "look.sample_finding": "Пример находки",
      "look.sample_sub": "хост · источник",
      "help.title": "Помощь",
      "help.sub": "работает без интернета",
      "help.search_placeholder": "Поиск: «капча», «потоки», «Tor»…",
      "help.search_aria": "Поиск по справке",
      "help.empty_text": "Попробуйте другое слово: «капча», «фон», «ключ», «скоуп».",
      "help.not_found": "Статья не найдена",
      "help.not_found_text": "Откройте раздел «Помощь» и найдите нужное через поиск.",
      "help.offline_note": "Справка работает без интернета.",
      "help.glossary": "Глоссарий",
      "help.extra_key_group": "Дополнительно, с ключом",
      "help.pill_active": "активный",
      "help.pill_passive": "пассивный",
      "help.help_aria": "Справка",
      "help.rec_pill": "рекомендуем {min}-{max}{unit}",
      "help.dec_aria": "Уменьшить: {label}",
      "help.inc_aria": "Увеличить: {label}",
      "help.err_empty": "Введите число от {min} до {max}",
      "help.err_int": "Только целое число, без букв и дробей",
      "help.err_min": "Минимум {min}{unit}{why}",
      "help.err_max": "Максимум {max}{unit}{why}",
      "ai.title": "Облачный ИИ-ассистент",
      "ai.summary_title": "ИИ-сводка",
      "ai.provider": "Провайдер",
      "ai.model": "Модель",
      "ai.refresh_models": "Обновить модели",
      "ai.thinking": "Рассуждения (Thinking)",
      "ai.generate": "Сформировать сводку",
      "ai.thoughts": "Ход рассуждений модели",
      "insights.attack_paths": "Пути компрометации",
      "insights.choke_points": "Ключевые точки блокировки",
      "insights.no_paths": "Многошаговых цепочек компрометации пока не выявлено.",
      "signatures.title": "Базы сигнатур",
      "signatures.update": "Проверить и обновить",
      "signatures.import": "Импортировать пакет",
      "signatures.rollback": "Откатить",
      "licenses.title": "Лицензии и компоненты",
      "licenses.tab_data": "Данные и ресурсы",
      "licenses.tab_rust": "Rust-библиотеки",
      "licenses.tab_android": "Android-библиотеки",
      "licenses.tab_texts": "Тексты лицензий",
      "licenses.search_placeholder": "Фильтр по названию, крейту или лицензии…",
      "licenses.flavor_foss": "FOSS (чистая GPL-3.0 / F-Droid, без ML Kit)",
      "licenses.flavor_play": "Play (с Google ML Kit OCR)",
      "about.title": "О программе",
      "about.version": "Версия",
      "about.build": "Вариант сборки",
      "about.license": "Лицензия",
      "about.repo": "Исходный код",
      "about.licenses_row": "Лицензии и сторонние компоненты",
      "about.licenses_sub": "Rust-крейты, Android-библиотеки, базы данных и полные тексты лицензий",
    },
    uk: {
      "app.name": "FOCA-rs",
      "app.active_mode": "АКТИВНИЙ РЕЖИМ",
      "app.offline": "Немає мережі: показано збережені дані",
      "app.secrets_open": "Секрети відкрито",
      "app.secrets_close": "Закрити",
      "app.secrets_close_aria": "Закрити доступ до секретів",
      "app.secrets_hidden": "Секрети приховано",
      "app.back": "Назад",
      "app.menu": "Меню",
      "app.search": "Пошук",
      "app.nav_aria": "Розділи проєкту",
      "app.mini_open_aria": "Відкрити екран скану",
      "app.copied": "Скопійовано · буфер очиститься за 30 с",
      "nav.overview": "Огляд",
      "nav.findings": "Знахідки",
      "nav.data": "Дані",
      "nav.reports": "Звіти",
      "menu.projects": "Усі проєкти",
      "menu.projects_sub": "Змінити або імпортувати проєкт",
      "menu.scope": "Скоуп",
      "menu.rules": "Правила пошуку",
      "menu.rules_sub": "Власні шаблони та готові набори",
      "menu.offline": "Розібрати файли без мережі",
      "menu.offline_sub": "Тека, файли або ZIP із пристрою",
      "menu.ai": "ШІ-зведення",
      "menu.ai_sub": "Хмарне зведення з маскуванням секретів",
      "menu.settings": "Налаштування",
      "menu.theme_light": "Світла тема",
      "menu.theme_dark": "Темна тема",
      "menu.demo": "Демо-стани екранів",
      "menu.demo_sub": "Порожньо, завантаження, помилка, немає мережі",
      "menu.help": "Допомога",
      "sev.crit": "Критичний",
      "sev.high": "Високий",
      "sev.warn": "Середній",
      "sev.low": "Низький",
      "sev.info": "Інфо",
      "sev.ok": "Норма",
      "doc_status.analyzed": "Проаналізовано",
      "doc_status.downloaded": "Завантажено",
      "doc_status.queued": "У черзі",
      "doc_status.error": "Помилка 403",
      "common.empty": "Поки порожньо",
      "common.error_title": "Не вдалося завантажити",
      "common.error_text": "Перевірте підключення і спробуйте ще раз.",
      "common.retry": "Повторити",
      "common.cancel": "Скасувати",
      "common.save": "Зберегти",
      "common.close": "Закрити",
      "common.delete": "Видалити",
      "common.open": "Відкрити",
      "common.add": "Додати",
      "common.done": "Готово",
      "common.refresh": "Оновити",
      "common.details": "Докладніше",
      "common.loading": "Завантаження…",
      "common.yes": "Так",
      "common.no": "Ні",
      "common.all": "Усі",
      "common.found": "Знайдено",
      "common.nothing_found": "Нічого не знайдено",
      "common.see_also": "Див. також",
      "common.demo_confirm": "Демо: підтвердити",
      "common.confirm_finger": "Підтвердьте відбитком",
      "common.confirm_finger_sub": "Щоб {what}, прикладіть палець до сканера.",
      "common.confirm_finger_note":
        "Секрети будуть відкриті {minutes} хв. До виходу із застосунку або блокування.",
      "common.show_secret": "показати секрет",
      "overview.title": "Огляд",
      "overview.new_scan": "Новий скан",
      "overview.start_scan": "Почати скан",
      "overview.add_target": "Додати ціль",
      "overview.empty_title": "Цілей поки немає",
      "overview.empty_text": "Додайте домен, URL, IP або мережу CIDR, щоб розпочати розвідку.",
      "overview.scan_running": "Триває скан",
      "overview.scan_never": "Скан не запускався",
      "overview.scan_no_data": "Даних щодо проєкту поки немає",
      "overview.scan_done": "Скан завершено",
      "overview.scan_stopped": "Скан зупинено",
      "overview.profile_fmt": "профіль «{profile}»",
      "overview.active_tag": "активний",
      "overview.other_scan":
        "Триває скан проєкту «{name}». Новий скан тут: після його завершення або зупинки.",
      "overview.open_project": "Відкрити проєкт",
      "overview.opening_project": "Відкриваємо проєкт…",
      "overview.project": "Проєкт",
      "projects.title": "Проєкти",
      "projects.new": "Новий проєкт",
      "projects.import_enc": "Імпорт .foca.enc",
      "projects.export_enc": "Експорт .foca.enc (зашифрований)",
      "projects.export_enc_sub": "Контейнер PBKDF2 + ChaCha20-Poly1305",
      "projects.password": "Пароль контейнера",
      "projects.include_files": "Включити завантажені документи",
      "launch.title": "Новий скан",
      "launch.targets_placeholder": "Домен (example.com, *.example.com), URL (http/https), IP або CIDR",
      "launch.email_hint": "Для пошуку за доменом організації введіть сам домен (наприклад, {domain})",
      "launch.profile_passive": "Пасивний",
      "launch.profile_std": "Стандартний",
      "launch.profile_full": "Повний",
      "launch.profile_custom": "Власний",
      "settings.title": "Налаштування",
      "settings.sec_scan": "Сканування",
      "settings.sec_device": "Пристрій",
      "settings.sec_app": "Застосунок",
      "settings.sec_info": "Відомості",
      "settings.keys": "Ключі API",
      "settings.sources": "Джерела",
      "settings.wordlists": "Словники",
      "settings.signatures": "Бази сигнатур",
      "settings.plugins": "Плагіни",
      "settings.ai": "Хмарний ШІ-помічник",
      "settings.network": "Мережа та проксі",
      "settings.power": "Трафік і живлення",
      "settings.background": "Робота у фоні",
      "settings.alerts": "Алерти та моніторинг",
      "settings.security": "Безпека",
      "settings.appearance": "Зовнішній вигляд",
      "settings.appearance_sub": "{theme} тема · {lang} · шрифт {fs}%",
      "settings.debug": "Відлагодження та діагностика",
      "settings.about": "Про програму",
      "settings.licenses": "Ліцензії та сторонні компоненти",
      "settings.help": "Допомога",
      "settings.help_sub": "Офлайн-довідка та глосарій",
      "look.title": "Зовнішній вигляд",
      "look.theme": "Тема",
      "look.theme_system": "Системна",
      "look.theme_dark": "Темна",
      "look.theme_light": "Світла",
      "look.lang": "Мова інтерфейсу",
      "look.lang_auto": "Системна (авто)",
      "look.lang_en": "English",
      "look.lang_ru": "Русский",
      "look.lang_uk": "Українська",
      "look.lang_auto_hint":
        "Визначається за мовою пристрою ({resolved}); непідтримувані мови системи перемикаються на English. Мову звіту завжди можна обрати окремо в конструкторі.",
      "look.lang_manual_hint":
        "Інтерфейс, сповіщення та шаблони звітів використовують {resolved}. Мову звіту також можна обрати окремо в конструкторі.",
      "look.lang_switched": "Мова: {label}",
      "look.font_size": "Розмір шрифту",
      "look.density": "Щільність",
      "look.density_compact": "Компактна",
      "look.density_normal": "Звичайна",
      "look.density_airy": "Вільна",
      "look.preview": "Попередній перегляд",
      "look.sample_finding": "Приклад знахідки",
      "look.sample_sub": "хост · джерело",
      "help.title": "Допомога",
      "help.sub": "працює без інтернету",
      "help.search_placeholder": "Пошук: «капча», «потоки», «Tor»…",
      "help.search_aria": "Пошук у довідці",
      "help.empty_text": "Спробуйте інше слово: «капча», «фон», «ключ», «скоуп».",
      "help.not_found": "Статтю не знайдено",
      "help.not_found_text": "Відкрийте розділ «Допомога» і знайдіть потрібне через пошук.",
      "help.offline_note": "Довідка працює без інтернету.",
      "help.glossary": "Глосарій",
      "help.extra_key_group": "Додатково, з ключем",
      "help.pill_active": "активний",
      "help.pill_passive": "пасивний",
      "help.help_aria": "Довідка",
      "help.rec_pill": "рекомендуємо {min}-{max}{unit}",
      "help.dec_aria": "Зменшити: {label}",
      "help.inc_aria": "Збільшити: {label}",
      "help.err_empty": "Введіть число від {min} до {max}",
      "help.err_int": "Лише ціле число, без літер і дробів",
      "help.err_min": "Мінімум {min}{unit}{why}",
      "help.err_max": "Максимум {max}{unit}{why}",
      "ai.title": "Хмарний ШІ-помічник",
      "ai.summary_title": "ШІ-зведення",
      "ai.provider": "Провайдер",
      "ai.model": "Модель",
      "ai.refresh_models": "Оновити моделі",
      "ai.thinking": "Міркування (Thinking)",
      "ai.generate": "Сформувати зведення",
      "ai.thoughts": "Хід міркувань моделі",
      "insights.attack_paths": "Шляхи компрометації",
      "insights.choke_points": "Ключові точки блокування",
      "insights.no_paths": "Багатокрокових ланцюжків компрометації поки не виявлено.",
      "signatures.title": "Бази сигнатур",
      "signatures.update": "Перевірити та оновити",
      "signatures.import": "Імпортувати пакет",
      "signatures.rollback": "Відкотити",
      "licenses.title": "Ліцензії та компоненти",
      "licenses.tab_data": "Дані та ресурси",
      "licenses.tab_rust": "Rust-бібліотеки",
      "licenses.tab_android": "Android-бібліотеки",
      "licenses.tab_texts": "Тексти ліцензій",
      "licenses.search_placeholder": "Фільтр за назвою, крейтом або ліцензією…",
      "licenses.flavor_foss": "FOSS (чиста GPL-3.0 / F-Droid, без ML Kit)",
      "licenses.flavor_play": "Play (з Google ML Kit OCR)",
      "about.title": "Про програму",
      "about.version": "Версія",
      "about.build": "Варіант збірки",
      "about.license": "Ліцензія",
      "about.repo": "Вихідний код",
      "about.licenses_row": "Ліцензії та сторонні компоненти",
      "about.licenses_sub": "Rust-крейти, Android-бібліотеки, бази даних і повні тексти ліцензій",
    },
  };
  // Default name of the reference case in the effective UI language (the core does the same).
  const demoCaseName = () =>
    ({ uk: "Еталонний кейс", en: "Reference case", ru: "Эталонный кейс" })[
      demoResolveLang(load().settings?.lang ?? "auto", demoDeviceLocale).lang
    ];
  // Device locale of the last i18n_bundle call: language-dependent commands resolve "auto" through it.
  let demoDeviceLocale = "";
  const demoResolveLang = (rawSetting, deviceLocale) => {
    const norm = v => {
      const low = String(v || "")
        .trim()
        .toLowerCase();
      if (!low || low === "auto") return "auto";
      const h = low.split(/[-_]/)[0];
      if (h === "ru" || h === "rus") return "ru";
      if (h === "uk" || h === "ua" || h === "ukr") return "uk";
      if (h === "en" || h === "eng") return "en";
      return "auto";
    };
    const setting = norm(rawSetting);
    let resolved = setting;
    if (resolved === "auto") {
      const dh = String(deviceLocale || "en")
        .trim()
        .toLowerCase()
        .split(/[-_]/)[0];
      resolved = dh === "uk" || dh === "ua" ? "uk" : dh === "ru" ? "ru" : "en";
    }
    return { setting, lang: resolved, ui_code: resolved === "uk" ? "UA" : resolved === "en" ? "EN" : "RU" };
  };
  // ---- i18n_bundle().findings: the report catalog (injected by the QA harness as window.FOCA_DEMO_FINDINGS,
  // see qa/demo-locales.mjs) plus translations of demo-only texts that the core never writes. [ru, en, uk] ----
  const DEMO_FINDING_TEXTS = [
    ["В документе {} найдено: {}.", "Found in document {0}: {1}.", "У документі {0} знайдено: {1}."],
    [
      "Сменить секрет, удалить документ с сайта.",
      "Rotate the secret and remove the document from the site.",
      "Змінити секрет і прибрати документ із сайту.",
    ],
    [
      "Jenkins {} доступен из интернета без авторизации",
      "Jenkins {0} reachable from the internet without authentication",
      "Jenkins {0} доступний з інтернету без авторизації",
    ],
    [
      "Пароль в тексте документа (connection string)",
      "Password in document text (connection string)",
      "Пароль у тексті документа (connection string)",
    ],
    [
      "{} (EOL) у {n} {w}, {n} CVE",
      "{0} (EOL) in {1:document|documents|documents}, {2} CVEs",
      "{0} (EOL) у {1:документі|документах|документах}, {2} CVE",
    ],
    ["{} устарел ({n}), {n} CVE", "{0} is outdated ({1}), {2} CVEs", "{0} застарів ({1}), {2} CVE"],
    [
      "Ключ доступа AWS в комментарии таблицы",
      "AWS access key in a spreadsheet comment",
      "Ключ доступу AWS у коментарі таблиці",
    ],
    [
      "Имена внутренних серверов раскрыты в .rdp-файле",
      "Internal server names exposed in an .rdp file",
      "Імена внутрішніх серверів розкрито в .rdp-файлі",
    ],
    [
      "GPS-координаты промышленного объекта в фото",
      "GPS coordinates of an industrial site in a photo",
      "GPS-координати промислового об'єкта у фото",
    ],
    [
      "Исправления в docx: удалённые суммы договора",
      "Tracked changes in docx: deleted contract amounts",
      "Виправлення в docx: видалені суми договору",
    ],
    [
      "DNSSEC не настроен для зоны",
      "DNSSEC is not configured for the zone",
      "DNSSEC не налаштовано для зони",
    ],
    ["{}: версия уязвима к {}", "{0}: version vulnerable to {1}", "{0}: версія вразлива до {1}"],
    ["{} и плагины устарели", "{0} and plugins are outdated", "{0} і плагіни застаріли"],
    [
      "Адрес сотрудника найден в утечке паролей",
      "Employee address found in a password leak",
      "Адресу співробітника знайдено у витоку паролів",
    ],
    [
      "Cookie без флагов Secure и HttpOnly, нет HSTS",
      "Cookie without Secure and HttpOnly flags, no HSTS",
      "Cookie без прапорців Secure і HttpOnly, немає HSTS",
    ],
    ["Включён TLS 1.0 на портале", "TLS 1.0 enabled on the portal", "Увімкнено TLS 1.0 на порталі"],
    [
      "Арендатор Microsoft 365 с федерацией AD FS: {}",
      "Microsoft 365 tenant federated with AD FS: {0}",
      "Тенант Microsoft 365 з федерацією AD FS: {0}",
    ],
    [
      "Оргструктура восстанавливается по документам: {n} {w}",
      "Org structure can be rebuilt from documents: {0:department|departments|departments}",
      "Оргструктура відновлюється з документів: {0:відділ|відділи|відділів}",
    ],
    [
      "Схема внутренней сети: домен {}, {n} {w}, {n} рабочих {w}",
      "Internal network layout: domain {0}, {1:server|servers|servers}, {2:workstation|workstations|workstations}",
      "Схема внутрішньої мережі: домен {0}, {1:сервер|сервери|серверів}, {2:робоча станція|робочі станції|робочих станцій}",
    ],
    ["Нет заголовка HSTS на {}", "No HSTS header on {0}", "Немає заголовка HSTS на {0}"],
    [
      "CSP разрешает 'unsafe-inline' на {}",
      "CSP allows 'unsafe-inline' on {0}",
      "CSP дозволяє 'unsafe-inline' на {0}",
    ],
    ["API-токен в документе", "API token in a document", "API-токен у документі"],
    ["Устаревшее ПО веб-сервера: {}", "Outdated web server software: {0}", "Застаріле ПЗ вебсервера: {0}"],
    [
      "Даты PDF и XMP расходятся: «{}»",
      "PDF and XMP dates differ: «{0}»",
      "Дати PDF і XMP розходяться: «{0}»",
    ],
    ["Даты PDF и XMP расходятся", "PDF and XMP dates differ", "Дати PDF і XMP розходяться"],
    [
      "По кэшу баннеров Shodan сервер {} ({}) отвечает на /owa и /autodiscover. Сборка уязвима к цепочке ProxyShell: обход аутентификации, повышение привилегий и запись произвольного файла. Хост в исключениях скоупа: к нему не обращались, версия взята только из внешнего кэша.",
      "Per the Shodan banner cache, the {0} server ({1}) answers on /owa and /autodiscover. The build is vulnerable to the ProxyShell chain: authentication bypass, privilege escalation and arbitrary file write. The host is excluded from the scope: it was not contacted, the version comes only from the external cache.",
      "За кешем банерів Shodan сервер {0} ({1}) відповідає на /owa і /autodiscover. Збірка вразлива до ланцюжка ProxyShell: обхід автентифікації, підвищення привілеїв і запис довільного файлу. Хост у винятках скоупу: до нього не зверталися, версію взято лише із зовнішнього кешу.",
    ],
    [
      "Срочно установить последний CU и Security Update для {}, проверить каталоги aspnet_client и FrontEnd на веб-шеллы, ограничить доступ к /autodiscover и /mapi с внешних адресов.",
      "Install the latest CU and Security Update for {0} urgently, check the aspnet_client and FrontEnd folders for web shells, restrict access to /autodiscover and /mapi from external addresses.",
      "Терміново встановити останній CU і Security Update для {0}, перевірити каталоги aspnet_client і FrontEnd на вебшели, обмежити доступ до /autodiscover і /mapi із зовнішніх адрес.",
    ],
    [
      "Поля Author, LastModifiedBy и пути шаблонов в {n} документах раскрывают логины сотрудников и структуру файловых ресурсов ({}).",
      "Author and LastModifiedBy fields and template paths in {0} documents reveal employee logins and the file share layout ({1}).",
      "Поля Author, LastModifiedBy і шляхи шаблонів у {0} документах розкривають логіни співробітників і структуру файлових ресурсів ({1}).",
    ],
    [
      "Опубликованы {n} {w} одного документа: «{}»",
      "{0:version|versions|versions} of one document published: «{1}»",
      "Опубліковано {0:версію|версії|версій} одного документа: «{1}»",
    ],
  ];
  // Finding sources and host roles of the demo data that the core does not use. [ru, en, uk]
  const DEMO_SOURCES = [
    ["Shodan (кэш баннеров)", "Shodan (banner cache)", "Shodan (кеш банерів)"],
    ["ПО → CVE", "Software → CVE", "ПЗ → CVE"],
    ["Отпечаток ПО", "Software fingerprint", "Відбиток ПЗ"],
    [
      "Отпечаток ПО (Shodan InternetDB)",
      "Software fingerprint (Shodan InternetDB)",
      "Відбиток ПЗ (Shodan InternetDB)",
    ],
    ["Утечки (HIBP)", "Leaks (HIBP)", "Витоки (HIBP)"],
    ["HTTP-заголовки", "HTTP headers", "HTTP-заголовки"],
    ["Shodan InternetDB (баннер TLS)", "Shodan InternetDB (TLS banner)", "Shodan InternetDB (банер TLS)"],
  ];
  const DEMO_ROLES = [
    ["Портал", "Portal", "Портал"],
    ["Файловый", "File server", "Файловий"],
    ["Тестовый", "Test", "Тестовий"],
    ["Вход (AD FS)", "Sign-in (AD FS)", "Вхід (AD FS)"],
  ];
  const demoFindingsBundle = lang => {
    if (lang !== "en" && lang !== "uk") return null;
    const col = lang === "en" ? 1 : 2;
    const base =
      (typeof window !== "undefined" && window.FOCA_DEMO_FINDINGS && window.FOCA_DEMO_FINDINGS[lang]) || {};
    const pairs = rows => Object.fromEntries(rows.map(r => [r[0], r[col]]));
    return {
      // Demo texts first: the generic templates of the catalog would otherwise catch them.
      catalog: [
        ...DEMO_FINDING_TEXTS.map((r, i) => ({
          id: `demo${i + 1}`,
          rules: "*",
          pattern: r[0],
          text: r[col],
        })),
        ...(base.catalog || []),
      ],
      terms: base.terms || [],
      roles: { ...pairs(DEMO_ROLES), ...(base.roles || {}) },
      tech_cats: base.tech_cats || {},
      host_sources: base.host_sources || {},
      sources: { ...pairs(DEMO_SOURCES), ...(base.sources || {}) },
    };
  };
  const demoHelpBundle = lang => {
    // QA harness (qa/shoot.mjs) passes the real bundle from locales/<lang>/help.json.
    const full = typeof window !== "undefined" && window.FOCA_DEMO_HELP && window.FOCA_DEMO_HELP[lang];
    if (full) return full;
    const isEn = lang === "en";
    const isUk = lang === "uk";
    return {
      sections: isEn
        ? {
            start: "Getting started",
            problem: "Troubleshooting",
            set: "Settings",
            docs: "Documents & forensics",
            ref: "Reference",
          }
        : isUk
          ? {
              start: "З чого почати",
              problem: "Часті проблеми",
              set: "Налаштування",
              docs: "Документи та форензика",
              ref: "Довідник",
            }
          : {
              start: "С чего начать",
              problem: "Частые проблемы",
              set: "Настройки",
              docs: "Документы и форензика",
              ref: "Справочник",
            },
      acc: isEn
        ? {
            free: "no key",
            web: "no key · built-in browser",
            opt: "no key · higher limit with key",
            target: "no key · contacts target",
            dns: "no key · target DNS",
            key: "key required",
          }
        : isUk
          ? {
              free: "без ключа",
              web: "без ключа · вбудований браузер",
              opt: "без ключа · вищий ліміт із ключем",
              target: "без ключа · звертається до цілі",
              dns: "без ключа · DNS цілі",
              key: "потрібен ключ",
            }
          : {
              free: "без ключа",
              web: "без ключа · встроенный браузер",
              opt: "без ключа · с ключом лимит выше",
              target: "без ключа · обращается к цели",
              dns: "без ключа · запросы к DNS цели",
              key: "нужен ключ",
            },
      screens_lead: isEn
        ? "Bottom tabs: Overview, Findings, Data, Reports."
        : isUk
          ? "Нижня навігація: Огляд, Знахідки, Дані, Звіти."
          : "Нижняя навигация: Обзор, Находки, Данные, Отчёты.",
      screens: [
        [
          isEn ? "Projects" : isUk ? "Проєкти" : "Проекты",
          isEn
            ? "Project list and encrypted .foca.enc bundles."
            : isUk
              ? "Список проєктів і зашифровані контейнери .foca.enc."
              : "Список проектов и зашифрованные контейнеры .foca.enc.",
        ],
      ],
      glossary: [
        [
          isEn ? "Scope" : "Скоуп",
          isEn
            ? "Authorized targets and exclusions."
            : isUk
              ? "Дозволені цілі та винятки."
              : "Разрешённые цели и исключения.",
        ],
      ],
      profiles_html: "<p>Passive / Standard / Full / Custom</p>",
      articles: [
        {
          id: "first-scan",
          sec: "start",
          icon: "play",
          t: isEn ? "First scan" : isUk ? "Перший скан" : "Первый скан",
          sub: isEn
            ? "add targets and launch"
            : isUk
              ? "додати цілі та запустити"
              : "добавить цели и запустить",
          go: [isEn ? "New scan" : isUk ? "Новий скан" : "Новый скан", "/new"],
          rel: ["scope-help"],
          body: "<p>Demo help article.</p>",
        },
        {
          id: "scope-help",
          sec: "set",
          icon: "target",
          t: isEn ? "Scope" : "Скоуп",
          sub: isEn ? "targets and exclusions" : isUk ? "цілі та винятки" : "цели и исключения",
          go: [isEn ? "Open scope" : isUk ? "Відкрити скоуп" : "Открыть скоуп", "/p/scope"],
          rel: ["first-scan"],
          body: "<p>Demo scope article.</p>",
        },
        {
          id: "cloud-ai",
          sec: "set",
          icon: "spark",
          t: isEn ? "Cloud AI & Thinking" : isUk ? "Хмарний ШІ та Thinking" : "Облачный ИИ и Thinking",
          sub: isEn
            ? "live models & reasoning controls"
            : isUk
              ? "живий список моделей і міркування"
              : "живой список моделей и рассуждения",
          go: [isEn ? "AI settings" : isUk ? "Налаштування ШІ" : "Настройки ИИ", "/settings/ai"],
          act: [isEn ? "Open AI" : isUk ? "Відкрити ШІ" : "Открыть ИИ", "go:/p/ai", "spark"],
          rel: ["first-scan"],
          body: "<p>Demo cloud AI article.</p>",
        },
        {
          id: "screens",
          sec: "ref",
          icon: "app",
          t: isEn ? "App screens" : isUk ? "Екрани застосунку" : "Экраны приложения",
          sub: "1",
          body: "",
        },
        {
          id: "profiles",
          sec: "ref",
          icon: "scan",
          t: isEn ? "Profiles & sources" : isUk ? "Профілі та джерела" : "Профили и источники",
          sub: "",
          body: "",
        },
        {
          id: "glossary",
          sec: "ref",
          icon: "note",
          t: isEn ? "Glossary" : isUk ? "Глосарій" : "Глоссарий",
          sub: "1",
          body: "",
        },
      ],
    };
  };

  // ---- AI summary: the core assembles the prompt and strips data according to filters; the UI shows it as
  // is ----
  // Language-neutral placeholders (services/ai_text.rs): a model keeps ASCII tokens intact.
  const AI_TAGS = ["SECRET", "EMAIL", "NAME", "CLIENT", "INTERNAL-IP"];
  // Fixed prompt wording per language, the same as PromptText in services/ai_text.rs.
  const AI_PROMPT = {
    ru: {
      project: "Проект",
      domain: "домен",
      scan: "Скан {date}, профиль «{profile}»{active}. Документов: {docs}, хостов: {hosts}, людей: {people}.",
      active: " (активный)",
      no_scans: "Сканов ещё не было.",
      top: "Находки (критичные и высокие):",
      no_top: "Критичных и высоких находок нет.",
      many_hosts: "несколько хостов",
      medium: "Средние",
      people: "Люди",
      internal: "Внутренние имена",
      evidence: "Доказательство",
      task: "Задача: кратко опиши ключевые риски и дай приоритетные рекомендации. Пиши на русском языке.",
      risks: "Ключевые риски",
      recs: "Рекомендации",
      none: "Актуальных находок нет",
      none_scans: ": сканов ещё не было",
      first_scan: "Проведите пассивный скан и проверьте документы перед публикацией.",
      day: "В течение 24 часов",
      week: "В течение недели",
      process: "Процесс",
      process_docs: "очищать метаданные перед публикацией документов, ",
      rescan: "провести повторный скан для проверки исправлений.",
      thoughts: "Оцениваю {n} актуальных находок, группирую критичные утечки по приоритету (режим: {mode}).",
    },
    uk: {
      project: "Проєкт",
      domain: "домен",
      scan: "Скан {date}, профіль «{profile}»{active}. Документів: {docs}, хостів: {hosts}, людей: {people}.",
      active: " (активний)",
      no_scans: "Сканувань ще не було.",
      top: "Знахідки (критичні та високі):",
      no_top: "Критичних і високих знахідок немає.",
      many_hosts: "кілька хостів",
      medium: "Середні",
      people: "Люди",
      internal: "Внутрішні імена",
      evidence: "Доказ",
      task: "Завдання: стисло опиши ключові ризики й дай пріоритетні рекомендації. Пиши українською мовою.",
      risks: "Ключові ризики",
      recs: "Рекомендації",
      none: "Актуальних знахідок немає",
      none_scans: ": сканувань ще не було",
      first_scan: "Проведіть пасивний скан і перевірте документи перед публікацією.",
      day: "Протягом 24 годин",
      week: "Протягом тижня",
      process: "Процес",
      process_docs: "очищати метадані перед публікацією документів, ",
      rescan: "провести повторний скан для перевірки виправлень.",
      thoughts: "Оцінюю {n} актуальних знахідок, групую критичні витоки за пріоритетом (режим: {mode}).",
    },
    en: {
      project: "Project",
      domain: "domain",
      scan: 'Scan {date}, profile "{profile}"{active}. Documents: {docs}, hosts: {hosts}, people: {people}.',
      active: " (active)",
      no_scans: "No scans yet.",
      top: "Findings (critical and high):",
      no_top: "No critical or high findings.",
      many_hosts: "several hosts",
      medium: "Medium",
      people: "People",
      internal: "Internal names",
      evidence: "Evidence",
      task: "Task: briefly describe the key risks and give prioritized recommendations. Write in English.",
      risks: "Key risks",
      recs: "Recommendations",
      none: "No current findings",
      none_scans: ": no scans yet",
      first_scan: "Run a passive scan and check documents before publishing them.",
      day: "Within 24 hours",
      week: "Within a week",
      process: "Process",
      process_docs: "clean metadata before publishing documents, ",
      rescan: "run a repeat scan to verify the fixes.",
      thoughts: "Weighing {n} current findings, grouping critical leaks by priority (mode: {mode}).",
    },
  };
  const aiLang = o =>
    ["ru", "uk", "en"].includes(o && o.lang)
      ? o.lang
      : demoResolveLang(load().settings?.lang ?? "auto", demoDeviceLocale).lang;
  // Running ai_summarize per project (single flight, like Core.ai_jobs) and its cancel hook.
  const aiJobs = new Map();
  // Simulated provider latency; 0 resolves at once (contract dumps, invariants).
  let aiDelayMs = 1200;
  const AI_HOSTS = {
    openai: "api.openai.com",
    anthropic: "api.anthropic.com",
    gemini: "generativelanguage.googleapis.com",
    deepseek: "api.deepseek.com",
    xai: "api.x.ai",
    mistral: "api.mistral.ai",
    groq: "api.groq.com",
    together: "api.together.xyz",
    openrouter: "openrouter.ai",
  };
  // Demo-only simulated `/models` response (no real network in offline demo mode).
  // In the real app (Rust engine), models are fetched live from the user's provider API.
  const DEMO_AI_MODELS = {
    openai: [
      {
        id: "gpt-6.2-astra",
        label: "GPT-6.2 Astra",
        thinking: true,
        adaptive_thinking: false,
        manual_thinking: false,
        context_window: 400000,
        max_output_tokens: 128000,
      },
      {
        id: "gpt-5.4-mini",
        label: "GPT-5.4 Mini",
        thinking: true,
        adaptive_thinking: false,
        manual_thinking: false,
        context_window: 400000,
        max_output_tokens: 64000,
      },
    ],
    anthropic: [
      {
        id: "claude-opus-5-5",
        label: "Claude Opus 5.5",
        thinking: true,
        adaptive_thinking: true,
        manual_thinking: false,
        context_window: 1000000,
        max_output_tokens: 64000,
      },
      {
        id: "claude-sonnet-5-5",
        label: "Claude Sonnet 5.5",
        thinking: true,
        adaptive_thinking: true,
        manual_thinking: false,
        context_window: 1000000,
        max_output_tokens: 64000,
      },
    ],
    gemini: [
      {
        id: "gemini-4-hydrogen",
        label: "Gemini 4 Hydrogen",
        thinking: true,
        adaptive_thinking: false,
        manual_thinking: false,
        context_window: 1048576,
        max_output_tokens: 65536,
      },
      {
        id: "gemini-3.8-flash",
        label: "Gemini 3.8 Flash",
        thinking: true,
        adaptive_thinking: false,
        manual_thinking: false,
        context_window: 1048576,
        max_output_tokens: 65536,
      },
    ],
    deepseek: [
      {
        id: "deepseek-v4-pro",
        label: "DeepSeek V4 Pro",
        thinking: true,
        adaptive_thinking: false,
        manual_thinking: false,
        context_window: 256000,
        max_output_tokens: 64000,
      },
      {
        id: "deepseek-chat",
        label: "DeepSeek Chat",
        thinking: true,
        adaptive_thinking: false,
        manual_thinking: false,
        context_window: 128000,
        max_output_tokens: 8192,
      },
    ],
    xai: [
      {
        id: "grok-4.7",
        label: "Grok 4.7",
        thinking: true,
        adaptive_thinking: false,
        manual_thinking: false,
        context_window: 256000,
        max_output_tokens: 64000,
      },
    ],
    mistral: [
      {
        id: "mistral-large-latest",
        label: "Mistral Large (latest)",
        thinking: true,
        adaptive_thinking: false,
        manual_thinking: false,
        context_window: 256000,
        max_output_tokens: 32000,
      },
      {
        id: "mistral-small-latest",
        label: "Mistral Small (latest)",
        thinking: true,
        adaptive_thinking: false,
        manual_thinking: false,
        context_window: 128000,
        max_output_tokens: 32000,
      },
    ],
    groq: [
      {
        id: "openai/gpt-oss-120b",
        label: "GPT-OSS 120B (Groq)",
        thinking: true,
        adaptive_thinking: false,
        manual_thinking: false,
        context_window: 131072,
        max_output_tokens: 32768,
      },
    ],
    together: [
      {
        id: "deepseek-ai/DeepSeek-V4",
        label: "DeepSeek V4 (Together)",
        thinking: true,
        adaptive_thinking: false,
        manual_thinking: false,
        context_window: 131072,
        max_output_tokens: 32768,
      },
    ],
    openrouter: [
      {
        id: "openrouter/auto",
        label: "OpenRouter Auto",
        thinking: true,
        adaptive_thinking: false,
        manual_thinking: false,
        context_window: 200000,
        max_output_tokens: 32000,
      },
    ],
    custom: [
      {
        id: "custom-model",
        label: "custom-model",
        thinking: null,
        adaptive_thinking: false,
        manual_thinking: false,
        context_window: null,
        max_output_tokens: null,
      },
    ],
  };
  function aiEndpointDemo(provRaw, baseUrlOverride) {
    const raw = String(provRaw || "deepseek")
      .trim()
      .toLowerCase();
    const provider = !raw || raw === "local" ? "deepseek" : raw;
    if (provider === "custom") {
      const u = String(baseUrlOverride || (load().settings.ai || {}).base_url || "").trim();
      try {
        const parsed = new URL(u);
        if ((parsed.protocol !== "http:" && parsed.protocol !== "https:") || !parsed.hostname) throw 0;
        return { provider: "custom", host: parsed.hostname, ok: true };
      } catch (e) {
        return { provider: "custom", host: "", ok: false };
      }
    }
    if (!AI_HOSTS[provider]) throw apiErr("unavailable", `Неизвестный ИИ-провайдер: ${provider}`);
    return { provider, host: AI_HOSTS[provider], ok: true };
  }
  function aiPreview(st, o = {}) {
    const R = RULES(),
      ai = load().settings.ai || {};
    const red = {
      secrets: true,
      pii: true,
      client: true,
      evid: false,
      ...(ai.redact || {}),
      ...(o.redact || {}),
    };
    const dom = st.project.domain || st.project.name || "",
      client = st.scope.client || st.project.client || "";
    const lang = aiLang(o),
      T = AI_PROMPT[lang];
    const marks = Object.fromEntries(AI_TAGS.map(k => [k, 0]));
    const M = (v, tag, on) => {
      if (!on) return v;
      marks[tag.replace("-DOMAIN", "")]++;
      return `[${tag}]`;
    };
    const repl = (s, needle, tag) => {
      if (!needle) return s;
      const parts = String(s).split(needle);
      if (parts.length > 1) marks[tag.replace("-DOMAIN", "")] += parts.length - 1;
      return parts.join(`[${tag}]`);
    };
    const txt = s => {
      let out = String(s || "");
      if (red.client) {
        out = repl(out, dom, "CLIENT-DOMAIN");
        out = repl(out, client, "CLIENT");
      }
      return out;
    };
    const host = h =>
      !h || h === "-"
        ? T.many_hosts
        : red.client && dom && (h === dom || h.endsWith("." + dom))
          ? h.slice(0, h.length - dom.length) + M(dom, "CLIENT-DOMAIN", true)
          : h;
    const secOf = f => [...String(f.evidence || "").matchAll(SECRET_RX)].map(m => m[1]);
    const live = st.findings
      .filter(R.isLive)
      .slice()
      .sort((a, b) => R.SEV_RANK[b.sev] - R.SEV_RANK[a.sev] || a.id - b.id);
    const top = live.filter(f => f.sev === "crit" || f.sev === "high").slice(0, 6),
      mid = live.filter(f => f.sev === "warn");
    const ppl = st.emails.filter(e => e.found && !e.role && e.name).slice(0, 2),
      srv = st.pcs.filter(p => p.kind === "server").slice(0, 3);
    const l = st.scans[st.scans.length - 1],
      live_docs = st.docs.filter(d => !d.deleted);
    const fmtD = s => (s ? `${s.slice(8, 10)}.${s.slice(5, 7)}.${s.slice(0, 4)}, ${s.slice(11, 16)}` : "");
    const lines = [
      `${T.project}: ${client ? M(client, "CLIENT", red.client) : "-"}${dom ? `, ${T.domain} ${M(dom, "CLIENT-DOMAIN", red.client)}` : ""}`,
      l
        ? T.scan
            .replace("{date}", fmtD(l.finished_at))
            .replace("{profile}", l.profile)
            .replace("{active}", l.active ? T.active : "")
            .replace("{docs}", live_docs.length)
            .replace("{hosts}", st.hosts.length)
            .replace("{people}", st.people.length)
        : T.no_scans,
      ``,
      top.length ? T.top : T.no_top,
      ...top.map(
        (f, i) =>
          `${i + 1}. ${txt(f.title)}, ${host(f.host)}${secOf(f).length ? `: ${M(secOf(f)[0], "SECRET", red.secrets)}` : ""}`,
      ),
      ...(mid.length ? [``, `${T.medium}: ${mid.map(f => txt(f.title)).join("; ")}.`] : []),
      ...(ppl.length
        ? [
            ``,
            `${T.people}: ${ppl.map(e => `${M(e.name, "NAME", red.pii)} (${M(e.addr, "EMAIL", red.pii)})`).join(", ")}.`,
          ]
        : []),
      ...(srv.length
        ? [
            `${T.internal}: ${srv.map(p => p.name + (p.ip && /^\d+\.\d+\.\d+\.\d+$/.test(p.ip) ? ` (${M(p.ip, "INTERNAL-IP", red.secrets)})` : "")).join(", ")}.`,
          ]
        : []),
      ...(red.evid && top[0] && top[0].evidence
        ? [
            ``,
            `${T.evidence} (${txt(top[0].title)}): ${top[0].evidence
              .split("\n")
              .slice(0, 3)
              .map(s => txt(s).replace(SECRET_RX, (_, v) => M(v, "SECRET", red.secrets)))
              .join("; ")}`,
          ]
        : []),
      ``,
      T.task,
    ];
    const text = lines.join("\n");
    const ep = aiEndpointDemo(o.provider || ai.provider, o.base_url);
    return {
      id: `aip-${hash(text + JSON.stringify(red)).toString(36)}`,
      text,
      lang,
      tokens: Math.round(text.length / 3.2 / 10) * 10 + 180,
      redacted: marks.SECRET,
      marks,
      redact: red,
      provider: ep.provider,
      model: String(o.model || ai.model || "").trim(),
      host: ep.host,
    };
  }
  function aiSummarize(st, o = {}) {
    const opts = o.opts || {};
    const p = aiPreview(st, opts);
    if (o.preview_id && o.preview_id !== p.id)
      throw apiErr("stale_preview", "Данные проекта изменились: обновите предпросмотр");
    const ep = aiEndpointDemo(opts.provider || p.provider, opts.base_url);
    if (!ep.ok) throw apiErr("bad_input", "Укажите корректный URL OpenAI-совместимого API (https://…)");
    const chosenModel =
      String(opts.model || p.model || "").trim() ||
      (DEMO_AI_MODELS[ep.provider] || DEMO_AI_MODELS.deepseek)[0].id;
    const T = AI_PROMPT[p.lang];
    const R = RULES(),
      first = s =>
        String(s || "")
          .split(/(?<=[.!?])\s/)[0]
          .replace(/[.!?]$/, "");
    const live = st.findings
      .filter(R.isLive)
      .slice()
      .sort((a, b) => R.SEV_RANK[b.sev] - R.SEV_RANK[a.sev] || a.id - b.id);
    const clean = s => String(s || "").replace(SECRET_RX, "[SECRET]");
    let md;
    if (!live.length)
      md = `## ${T.risks}\n${T.none}${st.scans.length ? "" : T.none_scans}.\n\n## ${T.recs}\n1. ${T.first_scan}`;
    else {
      const crit = live.filter(f => f.sev === "crit"),
        soon = live.filter(f => f.sev === "high" || f.sev === "warn"),
        docsF = live.some(f => f.category === "docs");
      md = [
        `## ${T.risks}`,
        ...live.slice(0, 5).map((f, i) => `${i + 1}. **${clean(f.title)}.** ${clean(first(f.description))}.`),
        ``,
        `## ${T.recs}`,
        ...(crit.length
          ? [
              `- **${T.day}:** ${crit
                .slice(0, 4)
                .map(f => first(f.recommendation).toLowerCase())
                .join("; ")}.`,
            ]
          : []),
        ...(soon.length
          ? [
              `- **${T.week}:** ${soon
                .slice(0, 4)
                .map(f => first(f.recommendation).toLowerCase())
                .join("; ")}.`,
            ]
          : []),
        `- **${T.process}:** ${docsF ? T.process_docs : ""}${T.rescan}`,
      ].join("\n");
    }
    const aiCfg = load().settings.ai || {};
    const showThoughts = !!(opts.show_thoughts ?? aiCfg.show_thoughts);
    const thinking = String(opts.thinking || aiCfg.thinking || "auto");
    const thoughts =
      showThoughts && thinking !== "off"
        ? T.thoughts.replace("{n}", live.length).replace("{mode}", thinking)
        : "";
    const created = new Date().toISOString().replace(/\.\d+Z$/, "Z");
    const entry = {
      id: `ai-${hash(created + md + Math.random()).toString(36)}`,
      text: md,
      thoughts,
      provider: ep.provider,
      model: chosenModel,
      lang: p.lang,
      created,
      tokens_in: p.tokens,
      tokens_out: Math.round(md.length / 3.6),
      tokens_thoughts: thoughts ? Math.round(thoughts.length / 3.6) : 0,
    };
    return { entry, preview_id: p.id };
  }
  // Summary history per project (the core keeps it in the project DB: ai_summaries + ai_summary).
  const aiHist = pid => {
    const s = load();
    s.aiHist = s.aiHist || {};
    return (s.aiHist[pid] = s.aiHist[pid] || { items: [], report_id: null });
  };
  const aiHistOut = pid => {
    const h = aiHist(pid);
    return { items: h.items.map(e => ({ ...e })), report_id: h.report_id, running: aiJobs.has(pid) };
  };
  function aiSummarizeRun(pid, o) {
    const k = (load().settings.keys || {}).ai;
    if (!k || k.status !== "ok") throw apiErr("no_key", "Нет ключа ИИ-провайдера");
    if (aiJobs.has(pid)) throw apiErr("busy", "ИИ-сводка по этому проекту уже формируется");
    const { entry, preview_id } = aiSummarize(P(pid), o);
    const finish = () => {
      const h = aiHist(pid);
      h.items.unshift(entry);
      h.items = h.items.slice(0, 50);
      h.report_id = entry.id;
      save();
      const { text, ...rest } = entry;
      return { ...rest, md: text, preview_id, source_badge: "Cloud API" };
    };
    if (!aiDelayMs) return finish();
    return new Promise((resolve, reject) => {
      const t = setTimeout(() => {
        aiJobs.delete(pid);
        resolve(finish());
      }, aiDelayMs);
      aiJobs.set(pid, () => {
        clearTimeout(t);
        aiJobs.delete(pid);
        reject(apiErr("cancelled", "Запрос к ИИ отменён"));
      });
    });
  }

  // ---- metadata cleaning of a document copy ----
  // Document hygiene (hygiene_get, docs/API.md → "Гигиена документов"): the same scoring as foca-meta
  // grade_document: penalties crit 40 / high 20 / warn 10 / low 4, any critical issue caps the grade at E.
  const HY_PEN = { crit: 40, high: 20, warn: 10, low: 4, info: 0 };
  const HY_SEV = { crit: 0, high: 1, warn: 2, low: 3, info: 4 };
  const HY_CLEANABLE = ["docx", "xlsx", "pptx", "odt", "ods", "odp", "odg", "pdf", "jpg", "jpeg", "png"];
  const HY_FORMAT = {
    jpg: "jpeg",
    jpeg: "jpeg",
    heic: "other",
    mp4: "other",
    zip: "other",
    ics: "other",
    vcf: "other",
  };
  const gradeOf = score =>
    score >= 90 ? "A" : score >= 75 ? "B" : score >= 60 ? "C" : score >= 40 ? "D" : score >= 20 ? "E" : "F";
  const GRADES = ["A", "B", "C", "D", "E", "F"];
  function hygieneDoc(st, d) {
    const cleanable = HY_CLEANABLE.includes(d.ext);
    const issues = [];
    const add = (code, severity, count, samples, fix, auto, params) => {
      const it = { code, severity, count, fix: { code: fix, auto: cleanable && auto } };
      if (samples && samples.length) it.samples = samples.slice(0, 3);
      if (params) it.fix.params = params;
      issues.push(it);
    };
    const people = [...new Set([d.author, d.last_modified_by].filter(Boolean))];
    if (people.length) add("people", "high", people.length, people, "clean_metadata", true);
    if (d.folder && /^\\\\/.test(d.folder))
      add("network_paths", "high", 1, [d.folder], "clean_metadata", true);
    else if (d.folder) add("local_paths", "warn", 1, [d.folder], "clean_metadata", true);
    if (d.company) add("company", "warn", 1, [d.company], "clean_metadata", true);
    if (d.printer) add("printers", "warn", 1, [d.printer], "clean_metadata", true);
    const rev = d.revisions || [];
    const com = rev.filter(r => r.kind === "com").length,
      trk = rev.length - com;
    if (com) add("comments", "warn", com, null, "resolve_comments", false, { count: String(com) });
    if (trk)
      add("tracked_changes", "warn", trk, null, "accept_tracked_changes", false, { count: String(trk) });
    if (d.ext === "pdf" && rev.length) add("pdf_revisions", "high", rev.length, null, "rewrite_pdf", true);
    if (d.gps) add("gps", "high", 1, null, "clean_metadata", true);
    if (d.camera) add("camera", "low", 1, [d.camera], "clean_metadata", true);
    if (d.thumb_diff) add("thumbnail_mismatch", "high", 1, null, "regenerate_thumbnail", true);
    const sec = (st.secrets || []).filter(s => s.doc === d.id);
    if (sec.length) {
      const kinds = [...new Set(sec.map(s => s.type || s.kind || "ключ"))].join(", ");
      add("secrets", "crit", sec.length, null, "revoke_secret", false, { kinds });
    }
    if ((d.flags || []).includes("pii"))
      add("pii", "warn", 1, null, "review_pii", false, { kinds: "телефон, e-mail" });
    if (d.signed)
      issues.push({
        code: "signed",
        severity: "info",
        count: 1,
        fix: { code: "resign_after_cleaning", auto: false },
      });
    if (d.software) add("software", "low", 1, [String(d.software)], "clean_metadata", true);
    if (d.created_at || d.modified_at) add("edit_history", "low", 1, null, "clean_metadata", true);
    issues.sort((a, b) => HY_SEV[a.severity] - HY_SEV[b.severity]);
    const pen = issues.reduce((n, i) => n + HY_PEN[i.severity], 0);
    const score = Math.max(0, 100 - pen);
    let grade = gradeOf(score);
    if (issues.some(i => i.severity === "crit") && GRADES.indexOf(grade) < 4) grade = "E";
    return {
      id: d.id,
      name: d.name,
      ext: d.ext,
      grade,
      score,
      format: HY_FORMAT[d.ext] || d.ext,
      cleanable,
      issues,
    };
  }
  function hygieneSet(docs) {
    const by_grade = {};
    const agg = new Map();
    docs.forEach(r => {
      by_grade[r.grade] = (by_grade[r.grade] || 0) + 1;
      r.issues.forEach(i => {
        if (i.severity === "info") return;
        const a = agg.get(i.code) || { code: i.code, severity: i.severity, documents: 0, fix: i.fix.code };
        a.documents++;
        agg.set(i.code, a);
      });
    });
    const worst = docs.length ? GRADES[Math.max(...docs.map(r => GRADES.indexOf(r.grade)))] : null;
    const score = docs.length ? Math.round(docs.reduce((n, r) => n + r.score, 0) / docs.length) : 100;
    let gi = GRADES.indexOf(gradeOf(score));
    if (worst) gi = Math.max(gi, GRADES.indexOf(worst) - 1);
    const issues = [...agg.values()].sort(
      (a, b) => b.documents - a.documents || HY_SEV[a.severity] - HY_SEV[b.severity],
    );
    return { grade: GRADES[gi], score, documents: docs.length, worst, by_grade, issues };
  }
  function hygieneGet(st, ids) {
    const want = ids && ids.length ? new Set(ids.map(Number)) : null;
    const docs = st.docs
      .filter(d => !d.deleted && d.status === "analyzed" && (!want || want.has(d.id)))
      .map(d => hygieneDoc(st, d));
    return { set: hygieneSet(docs), docs };
  }
  const SHARED_QUEUE = [];
  // A shared file (Android share sheet → platform_shared_files) has no project in the demo: a synthetic
  // contract with a signature and PDF revisions shows every part of the before/after screen.
  const SHARED_DEMO = {
    id: 0,
    name: "Договір_оренди_2026.pdf",
    ext: "pdf",
    author: "o.kovalenko",
    last_modified_by: "a.bondar",
    company: "ТОВ «Контосо Енерджі»",
    folder: "\\\\SRV-FILE01\\Buh\\Договори",
    software: "Microsoft Word 2016",
    created_at: "2026-02-03T09:12:00",
    modified_at: "2026-02-05T18:40:00",
    revisions: [{ kind: "del", who: "a.bondar", at: "2026-02-05T18:31:00", text: "" }],
    flags: [],
    signed: true,
  };
  function verifyOf(d, r) {
    const ch = (field, before, change, sensitive, after) => {
      const c = { field, before: String(before), change, sensitive };
      if (after !== undefined) c.after = String(after);
      return c;
    };
    const changes = [];
    if (d.author) changes.push(ch("author", d.author, "removed", true));
    if (d.last_modified_by) changes.push(ch("people.last_modified_by", d.last_modified_by, "removed", true));
    if (d.company) changes.push(ch("company", d.company, "removed", true));
    if (d.folder) changes.push(ch("paths", d.folder, "removed", true));
    if (d.printer) changes.push(ch("printer", d.printer, "removed", true));
    if (d.software) changes.push(ch("software", d.software, "removed", true));
    if (d.created_at) changes.push(ch("created", d.created_at.replace("T", " "), "removed", true));
    if (d.modified_at) changes.push(ch("modified", d.modified_at.replace("T", " "), "removed", true));
    if (d.gps) changes.push(ch("gps", `${d.gps.lat}, ${d.gps.lon}`, "removed", true));
    if (d.camera) changes.push(ch("camera", d.camera, "removed", true));
    if (d.thumb_diff) changes.push(ch("thumbnail", "есть", "removed", true));
    if (d.ext === "pdf") changes.push(ch("stats.pages", 2, "kept", false, 2));
    const warnings = [];
    if (d.ext === "pdf" && (d.revisions || []).length)
      warnings.push({ code: "revisions_collapsed", count: d.revisions.length });
    if (d.ext === "pdf" && d.id === 0) warnings.push({ code: "signature_removed", count: 1 });
    if (d.thumb_diff) warnings.push({ code: "thumbnail_removed" });
    const v = { valid: true, remaining: 0, clean: true, changes, warnings };
    if (d.ext === "pdf") Object.assign(v, { pages_before: 2, pages_after: 2, text_preserved: true });
    return r ? Object.assign(v, r) : v;
  }
  function docClean(st, ids) {
    st.cleaned = st.cleaned || {};
    return ids.map(id => {
      const d = st.docs.find(x => x.id === id);
      if (!d) throw apiErr("not_found", `Документ ${id} не найден`);
      const removed = [];
      if (d.author || d.last_modified_by) removed.push("author");
      if (d.company) removed.push("company");
      if (d.folder) removed.push("path");
      if (d.printer) removed.push("printer");
      if (d.gps) removed.push("gps");
      if (d.camera) removed.push("camera");
      if ((d.revisions || []).length) removed.push("revisions");
      if (d.software) removed.push("software");
      if (d.thumb_diff) removed.push("thumbnail");
      const manual = (st.secrets || [])
        .filter(s => s.doc === id)
        .map(s => ({ kind: "secret", where: s.where })); // A secret in the text cannot be removed as metadata.
      const cleanable = HY_CLEANABLE.includes(d.ext);
      if (!cleanable)
        manual.push({ kind: "format", where: `формат ${d.ext}: очистка метаданных не поддерживается` });
      const before = hygieneDoc(st, d);
      // Comments, tracked changes, PII and secrets are content: they stay in the clean copy (PDF revisions go).
      const after = cleanable
        ? hygieneDoc(st, {
            id: d.id,
            name: d.name,
            ext: d.ext,
            flags: (d.flags || []).filter(f => f === "pii"),
            revisions: d.ext === "pdf" ? [] : d.revisions || [],
          })
        : null;
      const name = d.name.replace(/(\.[^.]+)$/, "_clean$1");
      const r = {
        id,
        name,
        path: cleanable ? `/demo/clean/${st.id}/${name}` : null,
        removed,
        manual,
        at: `${TODAY}T12:00:00`,
        clean: !manual.length,
        verify: cleanable ? verifyOf(d) : null,
        grade_before: before.grade,
        grade_after: after ? after.grade : null,
        size: cleanable ? Math.max(1, Math.round(d.size * 0.93)) * 1024 : null,
      };
      st.cleaned[id] = { at: r.at, name: r.name, manual: manual.length };
      return r;
    });
  }
  // What the cleaner leaves of a document: no people, paths or history; comments and tracked changes stay.
  const SHARED_AFTER = { flags: [], revisions: [] };
  function sharedHygiene(name) {
    const d = { ...SHARED_DEMO, name: name || SHARED_DEMO.name };
    const r = hygieneDoc({ secrets: [] }, d);
    r.id = null;
    return { set: hygieneSet([r]), docs: [r] };
  }
  function sharedClean(name) {
    const d = { ...SHARED_DEMO, name: name || SHARED_DEMO.name };
    const cname = d.name.replace(/(\.[^.]+)$/, "_clean$1");
    const before = hygieneDoc({ secrets: [] }, d);
    const after = hygieneDoc({ secrets: [] }, { ...SHARED_AFTER, id: 0, name: d.name, ext: d.ext });
    return {
      id: null,
      name: cname,
      source: d.name,
      path: `/demo/clean/shared/${cname}`,
      removed: ["author", "people", "company", "paths", "software", "created", "modified"],
      manual: [],
      at: `${TODAY}T12:00:00`,
      clean: true,
      verify: verifyOf(d),
      grade_before: before.grade,
      grade_after: after.grade,
      size: 214 * 1024,
    };
  }
  const touchFinding = (st, id) => {
    const f = st.findings.find(x => x.id === +id);
    if (!f) throw apiErr("not_found", `Находка ${id} не найдена`);
    return f;
  };
  const newProjectState = (id, a) => ({
    id,
    project: {
      id,
      name: a.name || (a.targets && a.targets[0]) || id,
      client: a.client || "",
      domain: a.name,
      created_at: a.now || "2026-11-20T12:00:00",
      archived: false,
      notes: "",
    },
    scope: {
      client: a.client || "",
      contact: "",
      phone: "",
      basis: "",
      targets: (a.targets || []).map(t =>
        typeof t === "string"
          ? {
              v: t,
              type: /\/\d+$/.test(t)
                ? "cidr"
                : /^\d+\.\d+\.\d+\.\d+$/.test(t)
                  ? "ip"
                  : /^\*\./.test(t)
                    ? "wild"
                    : /\./.test(t)
                      ? "domain"
                      : "org",
            }
          : { v: t.v, type: t.type },
      ),
      excl: a.excludes || [],
    },
    docs: [],
    people: [],
    emails: [],
    patterns: [],
    hosts: [],
    pcs: [],
    software: [],
    paths: [],
    printers: [],
    secrets: [],
    findings: [],
    gps: [],
    events: [],
    scans: [],
    reports: [],
    leaks: {},
  });

  // ---- 1.3: full-text search in the demo (docs_search) ----
  // Document texts for the story documents; other documents are searched by name, title and the text of
  // their forensic records. Masked values are written as {{s:…}} like the core's snippets.
  const DEMO_TEXT = {
    "Договір_постачання_ТЕС-2_v3.docx": {
      text: "ДОГОВІР ПОСТАЧАННЯ № 14/03-24. ТОВ «Контосо Енерджі» (код ЄДРПОУ {{s:••••••89}}) та ТОВ «Енергобуд» уклали цей договір про постачання обладнання для ТЕС-2. Ціна договору становить 16 900 000 грн. Оплата на рахунок IBAN {{s:••••••••••••••••••••••••4417}} протягом 10 банківських днів. Знижка 8% погоджена усно з ТОВ «Енергобуд», у договір не вносити.",
      masked: ["pii:edrpou", "pii:iban"],
    },
    "Технічні_умови_підключення.pdf": {
      text: "ТЕХНІЧНІ УМОВИ на приєднання до електричних мереж ТОВ «Контосо Енерджі». Потужність приєднання: 1,6 МВт. Резервна лінія: ПС-35 «Західна», вул. Промислова, 12. Тел. чергового диспетчера: {{s:+380 67 ••• •• 14}}. Схема підключення: https://contosoexample.blob.core.windows.net/scada/tes2-scheme.zip?sv=2021-08-06&sp=r&sig={{s:••••••••}}. Погоджено: головний енергетик П. Т. Приклад.",
      masked: ["pii:phone", "secret:azure_sas"],
    },
    "Перелік_обладнання_ТЕС-2.xlsx": {
      text: "Перелік обладнання ТЕС-2. Трансформатор ТДН-16000/110, вимикач ВГТ-110, релейний захист. Закупівельна ціна; Знижка постачальника; Маржа, %. Ціна закупівлі, грн; Постачальник. Сводна таблиця з бази Billing (SRV-SQL02).",
      masked: [],
    },
    "Звіт_по_споживанню_2019.xlsx": {
      text: "Звіт по споживанню електроенергії за 2019 рік. Споживач, адреса, лічильник, IBAN {{s:UA •••••••••••••••••••••••••0417}}, картка {{s:•••• •••• •••• 4471}}. Разом спожито 18 422 МВт·год.",
      masked: ["pii:iban", "pii:card"],
    },
    "Re_Тендер_ТЕС-2_уточнення.eml": {
      text: "Re: Тендер ТЕС-2, уточнення. Доброго дня! Надсилаю оновлений кошторис ТЕС-2, прохання відповідати на особисту пошту. З повагою, Сергій Лисенко, відділ продажів, моб. {{s:+380 67 ••• •• 31}}.",
      masked: ["pii:phone"],
    },
    "Нарада_ТЕС-2_графік.ics": {
      text: "Нарада: графік робіт ТЕС-2. Microsoft Teams; переговорна 3.12. Організатор i.petrenko@contoso.example. Приєднатися: https://teams.microsoft.com/l/meetup-join/19%3ameeting_NjA••••••@thread.v2/0",
      masked: [],
    },
  };
  function demoDocText(st, d) {
    const t = demoByName(DEMO_TEXT, d.name);
    if (t) return demoEnOut(t);
    const fx = demoEnOut(demoByName(CONTOSO_FX, d.name));
    const parts = [d.title || "", ...(d.revisions || []).map(r => r.text)];
    if (fx) {
      fx.hidden_content.forEach(h => parts.push(h.text));
      fx.pdf_revisions.forEach(r => parts.push(...(r.removed_text || []), ...(r.added_text || [])));
      Object.values(fx.fields).forEach(v => parts.push(v));
    }
    return { text: parts.filter(Boolean).join(". "), masked: [] };
  }
  /** Snippet like foca-store: ~180 chars around the first match, {{h:…}} highlights, {{s:…}} kept whole. */
  function demoSnippet(text, terms) {
    const low = text.toLowerCase();
    let at = -1;
    for (const t of terms) {
      const i = low.indexOf(t);
      if (i >= 0 && (at < 0 || i < at)) at = i;
    }
    if (at < 0) return null;
    const toks = [...text.matchAll(/\{\{s:[^}]*\}\}/g)].map(m => [m.index, m.index + m[0].length]);
    const fix = (p, end) => {
      for (const [a, b] of toks) if (p > a && p < b) return end ? b : a;
      return p;
    };
    const from = fix(Math.max(0, at - 70), false),
      to = fix(Math.min(text.length, at + 110), true);
    const re = new RegExp(terms.map(t => t.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")).join("|"), "gi");
    const body = text
      .slice(from, to)
      .split(/(\{\{s:[^}]*\}\})/)
      .map(p => (/^\{\{s:/.test(p) ? p : p.replace(re, m => `{{h:${m}}}`)))
      .join("");
    return (from > 0 ? "…" : "") + body + (to < text.length ? "…" : "");
  }

  // ---- 1.3: user rule patterns and the offline import in the demo ----
  /** Rust regex syntax of the core → JS: named groups (?P<v>…) and a leading (?i) flag. */
  /** UTF-8 byte length (rules_test reports byte offsets like the core). */
  const utf8Len = str => {
    let n = 0;
    for (const ch of str) {
      const c = ch.codePointAt(0);
      n += c < 0x80 ? 1 : c < 0x800 ? 2 : c < 0x10000 ? 3 : 4;
    }
    return n;
  };
  // JS \b is ASCII-only even with the u flag; the core's (Rust) \b is Unicode-aware.
  const UB = "(?:(?<=[\\p{L}\\p{N}_])(?![\\p{L}\\p{N}_])|(?<![\\p{L}\\p{N}_])(?=[\\p{L}\\p{N}_]))";
  const demoPattern = p =>
    String(p)
      .replace(/\(\?P</g, "(?<")
      .replace(/^\(\?i\)/, "")
      .replace(/(^|[^\\])\\b/g, (m, pre) => pre + UB);
  // What the demo folder picker "copies": the story documents in the extended formats.
  const DEMO_PICK = [
    "Технічні_умови_підключення.pdf",
    "Перелік_обладнання_ТЕС-2.xlsx",
    "Звіти.lnk",
    "Re_Тендер_ТЕС-2_уточнення.eml",
    "Нарада_ТЕС-2_графік.ics",
    "Контакти_відділу_продажів.vcf",
    "IMG_4131.mp4",
    "Тендер_ТЕС-2_додатки.zip",
  ];
  /**
   * Offline import: a new project (or the given one) gets copies of the picked story documents, their
   * entities and forensic findings. Unknown paths are reported as skipped "bad_data": nothing is fetched.
   */
  function importOffline(a = {}) {
    const S = load();
    const src = S.projects.contoso;
    const names = (a.paths || []).map(p => String(p).split(/[\\/]/).pop());
    const known = names.filter(n => src && src.docs.some(d => d.name === n));
    const skipped = names.filter(n => !known.includes(n)).map(name => ({ name, reason: "bad_data" }));
    let id = a.project;
    if (!id) {
      const base =
        (a.name || "offline")
          .toLowerCase()
          .replace(/[^a-z0-9а-яіїє.-]+/gi, "-")
          .slice(0, 40) || "offline";
      id = base;
      let k = 2;
      while (S.projects[id]) id = `${base}-${k++}`;
      S.projects[id] = newProjectState(id, {
        name: a.name || "Офлайн-разбор",
        targets: a.domain ? [a.domain] : [],
      });
      S.order.unshift(id);
    }
    const st = S.projects[id];
    if (!st) throw apiErr("not_found", `Проект ${id} не найден`);
    let next = st.docs.reduce((m, d) => Math.max(m, d.id), 0);
    const ids = [];
    let duplicates = 0;
    known.forEach(n => {
      if (st.docs.some(d => d.name === n)) {
        duplicates++;
        return;
      }
      const d = clone(src.docs.find(x => x.name === n));
      Object.assign(d, { id: ++next, url: `file:///${n}`, host: "-", first_scan: null, deleted: false });
      st.docs.push(d);
      ids.push(d.id);
    });
    if (ids.length) {
      st.all_people = clone(src.all_people || []);
      st.secrets = st.secrets || [];
      deriveFlags(st);
      st.extra_pcs = clone(src.extra_pcs || []);
      deriveEntities(st, { text_people: [] });
      st.email_found = {};
      st.role_mails = [];
      deriveEmails(st, { domain: a.domain || "contoso.example" });
      const have = new Set(st.findings.map(f => f.title));
      const add = contosoFxFindings(st, null).filter(o => !have.has(o.title));
      let fid = st.findings.reduce((m, f) => Math.max(m, f.id), 0);
      add.forEach(o => st.findings.push(findTpl(st, { ...o, id: ++fid, host: "-", url: null })));
    }
    save();
    const bytes = ids.reduce((s, i) => s + (st.docs.find(d => d.id === i).size || 0) * 1024, 0);
    return {
      project: id,
      imported: ids.length,
      ids,
      duplicates,
      skipped,
      errors: [],
      cancelled: false,
      bytes,
    };
  }
  // Quick tools and the scan queue (docs/API.md → "Быстрые инструменты" / "Очередь сканов"):
  // minimal stubs with the core's response shapes; the demo queue does not drive scans.
  const DEMO_QUEUE = { items: [], paused: false, pause_reason: null, seq: 0 };
  function queueView() {
    const q = DEMO_QUEUE;
    const fin = s => ["done", "stopped", "error"].includes(s);
    const done = q.items.filter(i => fin(i.status)).length;
    const cur = q.items.findIndex(i => i.status === "running");
    const total = q.items.length;
    return {
      items: q.items.map(i => ({ ...i })),
      total,
      done,
      pending: q.items.filter(i => i.status === "pending").length,
      index: cur >= 0 ? cur : Math.min(done, Math.max(total - 1, 0)),
      current:
        cur >= 0
          ? {
              id: q.items[cur].id,
              project: q.items[cur].project,
              name: q.items[cur].name,
              index: cur,
              scan_id: q.items[cur].scan_id,
              progress: q.items[cur].progress,
            }
          : null,
      percent: total ? Math.floor((done * 100) / total) : 0,
      paused: q.paused,
      pause_reason: q.pause_reason,
      running: cur >= 0,
      waiting: false,
    };
  }
  const toolTiming = { partial: false, elapsed_ms: 40, requests: [] };
  // Quick tools request ring (tool_log): in memory like the core, newest last, 200 records.
  const TOOL_LOG = [];
  function toolLog(tool, method, url, host, status) {
    const target = tool === "host";
    TOOL_LOG.push({
      time: new Date(Date.UTC(2026, 10, 20, 12, 0) + TOOL_LOG.length * 1000).toISOString(),
      module: "toolbox",
      method,
      url,
      host,
      status,
      bytes: status ? 512 : 0,
      active: target,
      access: target ? "target" : "passive",
      blocked: false,
      error: null,
      tool,
    });
    if (TOOL_LOG.length > 200) TOOL_LOG.shift();
  }
  function toolFile(name) {
    const n = String(name || "Отчёт_2026.docx")
      .split(/[\\/]/)
      .pop();
    const ext = (n.split(".").pop() || "").toLowerCase();
    const h = sharedHygiene(n).docs[0];
    return {
      name: n,
      ext,
      size: 214 * 1024,
      sha256: "9f2c".padEnd(64, "0"),
      format: ext,
      metadata: {
        author: "Олена Коваль",
        company: "ТОВ «Приклад»",
        application: "Microsoft Office Word",
        created: `${TODAY}T09:12:00`,
        modified: `${TODAY}T11:40:00`,
        software: ["Microsoft Office Word"],
      },
      forensics: { comments: 2, revisions: 5, has_macros: false, encrypted: false, hidden_content: [] },
      pii: [],
      bad_redactions: [],
      secrets: [],
      findings: [
        {
          rule: "author",
          title: "Автор документа в метаданных",
          sev: "low",
          evidence: "author: Олена Коваль",
        },
      ],
      grade: { grade: h.grade, score: h.score, format: h.format, cleanable: h.cleanable, issues: h.issues },
      cleanable: true,
      clean_with: { cmd: "doc_clean", args: { path: `/demo/cache/${n}`, name: n } },
      error: null,
      ...toolTiming,
    };
  }
  const COMMANDS = {
    project_list: () => load().order.map(id => summary(P(id))),
    project_snapshot: ({ id }) => snapshot(id),
    project_open: ({ id }) => {
      // A reference case is never restored as the last opened project (like the core).
      if (!P(id).project.reference) load().settings.last_project = id;
      save();
      return snapshot(id);
    },
    project_create: (a = {}) => {
      const S = load();
      const base = (a.name || (a.targets && a.targets[0]) || "project")
        .toLowerCase()
        .replace(/[^a-z0-9а-яіїє.-]+/gi, "-")
        .slice(0, 40);
      let id = base,
        k = 2;
      while (S.projects[id]) id = `${base}-${k++}`;
      S.projects[id] = newProjectState(id, a);
      S.order.unshift(id);
      save();
      return summary(S.projects[id]);
    },
    project_update: ({ id, patch }) => {
      const st = P(id);
      ["name", "client", "notes", "archived"].forEach(k => {
        if (patch && k in patch) st.project[k] = patch[k];
      });
      if (patch && patch.client != null) st.scope.client = patch.client;
      save();
      return summary(st);
    },
    project_duplicate: ({ id }) => {
      const src = P(id);
      const S = load();
      let nid = id + "-copy",
        k = 2;
      while (S.projects[nid]) nid = `${id}-copy${k++}`;
      const st = newProjectState(nid, {
        name: src.project.name,
        client: src.project.client + " (копия)",
        targets: [],
        excludes: src.scope.excl,
      });
      st.scope = { ...clone(src.scope), client: st.project.client };
      S.projects[nid] = st;
      S.order.splice(S.order.indexOf(id) + 1, 0, nid);
      save();
      return summary(st);
    },
    project_delete: ({ id }) => {
      const S = load();
      P(id);
      delete S.projects[id];
      S.order = S.order.filter(x => x !== id);
      if (S.settings.last_project === id) S.settings.last_project = S.order[0] || null;
      save();
      return { ok: true };
    },
    project_export_encrypted: ({ project, id, password, include_files = false }) => {
      const pw = String(password || "");
      if (pw.length < 6) throw apiErr("bad_args", "Пароль контейнера должен содержать минимум 6 символов");
      const st = P(project || id);
      const name = `${st.project.name.replace(/[^a-z0-9._-]+/gi, "_")}_2026-11-24.foca.enc`;
      const path = `/demo/exports/${name}`;
      const dbSha = sha("db:" + st.project.id + ":" + st.findings.length + ":" + st.docs.length);
      const inputsSha = sha("inputs:" + dbSha + ":" + (include_files ? "1" : "0"));
      const counts = {
        docs: st.docs.length,
        findings: st.findings.length,
        hosts: st.hosts.length,
        people: st.people.length,
        scans: st.scans.length,
      };
      const manifest = {
        schema: "foca-bundle-manifest/v1",
        project_id: st.project.id,
        project_name: st.project.name,
        client: st.project.client,
        exported_at: "2026-11-24T12:00:00",
        db_sha256: dbSha,
        inputs_sha256: inputsSha,
        counts,
        files: include_files
          ? st.docs.slice(0, 3).map((d, i) => ({
              rel_path: `files/${String(i + 1).padStart(4, "0")}_${d.name}`,
              orig_path: `/demo/files/${d.name}`,
              sha256: sha("file:" + d.name),
              size: (d.size || 10) * 1024,
            }))
          : [],
      };
      const S = load();
      S._bundles = S._bundles || {};
      S._bundles[path] = { src: st.project.id, pwHash: sha("pw:" + pw), manifest };
      return {
        name,
        path,
        size: 16384 + st.docs.length * 512,
        sha256: sha("enc:" + name + ":" + inputsSha),
        inputs_sha256: inputsSha,
        include_files: !!include_files,
        signed: false,
        counts,
      };
    },
    project_import_encrypted: ({ path, password, new_name }) => {
      const S = load();
      const rec = (S._bundles || {})[path];
      if (!rec) throw apiErr("not_found", `Файл контейнера не найден: ${path}`);
      if (rec.pwHash !== sha("pw:" + String(password || "")))
        throw apiErr("bad_password", "Неверный пароль для расшифровки .foca.enc");
      const src = P(rec.src);
      let nid = `${src.project.id}-imp`,
        k = 2;
      while (S.projects[nid]) nid = `${src.project.id}-imp${k++}`;
      const copy = clone(src);
      copy.project.id = nid;
      if (new_name && String(new_name).trim()) copy.project.name = String(new_name).trim();
      S.projects[nid] = copy;
      S.order.unshift(nid);
      save();
      return {
        project: summary(copy),
        custody: clone(rec.manifest),
        verified_signature: null,
        files_restored: (rec.manifest.files || []).length,
      };
    },
    scope_get: ({ id }) => clone(P(id).scope),
    // Like the core: legacy fields (allow_active, target `active`) are ignored.
    scope_set: ({ id, scope }) => {
      const st = P(id);
      const sc = clone(scope);
      delete sc.allow_active;
      if (Array.isArray(sc.targets)) sc.targets = sc.targets.map(t => ({ v: t.v, type: t.type }));
      Object.assign(st.scope, sc);
      save();
      return clone(st.scope);
    },
    // Bulk add of out-of-scope names (as scope_bulk.rs): exclusions win; addresses on a CDN, a cloud or a shared
    // hosting are recorded as "no probe": the port scan never touches them. dry_run stores nothing.
    scope_add_hosts: ({ project, hosts, dry_run }) => {
      const st = P(project);
      const list = Array.isArray(hosts) ? hosts.map(h => String(h)) : [];
      if (!list.length) throw apiErr("bad_args", "Нужен список hosts");
      if (list.length > 500) throw apiErr("bad_args", "Не больше 500 имён за раз");
      const norm = h =>
        String(h)
          .trim()
          .toLowerCase()
          .replace(/^[a-z][a-z0-9+.-]*:\/\//, "")
          .split(/[/?#\s]/)[0]
          .replace(/\.$/, "");
      const req = new Set(list.map(norm));
      const seen = new Set();
      const out = { added: [], skipped: [], no_probe: [] };
      const skip = (host, code, reason) => out.skipped.push({ host, code, reason });
      for (const raw of list) {
        const h = norm(raw);
        if (seen.has(h)) {
          skip(h, "duplicate", "повтор в списке");
          continue;
        }
        seen.add(h);
        if (!/^[a-z0-9-]+(\.[a-z0-9-]+)+$/.test(h) || ip4(h) != null) {
          skip(h, "invalid", "не имя хоста");
          continue;
        }
        const ck = scopeCheck(st.scope, h, st.hosts);
        if (ck.code === "excluded") {
          skip(h, "excluded", ck.reason || "в исключениях");
          continue;
        }
        if (ck.ok) {
          skip(h, "already_in_scope", "уже в скоупе");
          continue;
        }
        const host = (st.hosts || []).find(x => String(x.name).toLowerCase() === h);
        const ip = host && ip4(host.ip) != null ? host.ip : null;
        if (ip) {
          const cloud = host.cloud && host.cloud !== "-" ? host.cloud : "";
          const shared = (st.hosts || []).some(
            x =>
              x.ip === ip &&
              String(x.name).toLowerCase() !== h &&
              !req.has(String(x.name).toLowerCase()) &&
              !scopeCheck(st.scope, x.name, st.hosts).ok,
          );
          const kind = cloud
            ? /cloudflare|akamai|fastly/i.test(cloud)
              ? "cdn"
              : "cloud"
            : shared
              ? "shared"
              : "";
          if (kind) {
            const label = { cdn: "CDN", cloud: "облако", shared: "общий хостинг" }[kind];
            out.no_probe.push({
              host: h,
              ip,
              provider: cloud || "-",
              kind,
              reason: cloud ? `${cloud} (${label})` : `${label}: на адресе есть сайты других владельцев`,
            });
          }
        }
        out.added.push(h);
      }
      if (dry_run) return { ...out, scope: clone(st.scope), dry_run: true };
      if (out.added.length) {
        st.oos_dec = st.oos_dec || {};
        st.no_probe = st.no_probe || { hosts: [], ips: {} };
        for (const h of out.added) {
          st.scope.targets.push({ v: h, type: "domain" });
          st.oos_dec[h] = "scope";
          if (!st.no_probe.hosts.includes(h)) st.no_probe.hosts.push(h);
        }
        for (const x of out.no_probe) st.no_probe.ips[x.ip] = x.reason;
        save();
      }
      return { ...out, scope: clone(st.scope), dry_run: false };
    },
    scan_start: a => scanStart(a),
    scan_stop: ({ reason } = {}) => scanStop(reason),
    scan_delete: a => scanDelete(a),
    scan_pause: () => {
      if (RUN) RUN.paused = true;
      return { ok: !!RUN };
    },
    scan_resume: () => {
      if (RUN) {
        RUN.paused = false;
        tick();
      }
      return { ok: !!RUN };
    },
    scan_status: () => scanStatus(),
    scan_skip_source: ({ id } = {}) => {
      if (id === "fuzz") {
        // "Stop fuzzing": before and during the site file search stage.
        const x = RUN && fuzzSrc();
        if (
          !x ||
          RUN.stage > STAGES.findIndex(s => s.id === "fuzz") ||
          !["wait", "running"].includes(x.status)
        )
          return { ok: false };
        fuzzEmit({
          status: "stopped",
          detail: "перебор остановлен пользователем",
          documents: RUN.fuzz.checked ? 1 : 0,
          stop: { kind: "cancelled" },
        });
        return { ok: true };
      }
      if (id === "brute" || id === "permute") {
        // Brute force / permutations alone: until the end of the network stage.
        if (!RUN || RUN.stage > STAGES.findIndex(s => s.id === "network")) return { ok: false };
        if (id === "brute") RUN.skipBrute = true;
        if (RUN.substep && RUN.substep.id === id) subEmit(id, "skipped", RUN.substep.done);
        return { ok: true };
      }
      if (INFRA_SRC.includes(id)) {
        // Subdomain enumeration / TLS inspection: until the end of the ports stage, while not answered.
        const x = RUN && (RUN.sources || []).find(s => s.id === id);
        if (
          !x ||
          RUN.stage > STAGES.findIndex(s => s.id === "ports") ||
          !["wait", "running"].includes(x.status)
        )
          return { ok: false };
        x.status = "skipped";
        emit({ type: "source", scan_id: RUN.id, ...x });
        return { ok: true };
      }
      if (!RUN || RUN.stage > 0) return { ok: false };
      const x = (RUN.sources || []).find(s => s.id === id && s.status === "ok");
      if (!x) return { ok: false };
      x.status = "skipped";
      emit({ type: "source", scan_id: RUN.id, ...x });
      return { ok: true };
    },
    scan_control: a => scanControl(a),
    // Retrying a source after manual verification: search stage only.
    scan_retry_source: ({ id } = {}) => {
      if (!["startpage", "mojeek", "brave_web", "yahoo"].includes(id))
        throw apiErr(
          "not_found",
          `источник ${id} нельзя повторить: только поисковики через встроенный браузер`,
        );
      if (!RUN || RUN.stage > 0)
        return {
          ok: false,
          reason: "Этап поиска уже закончился: проверка сохранена, следующий скан её использует",
          reason_msg: { code: "scan.retry_later", params: {} },
        };
      const x = (RUN.sources || []).find(s => s.id === id);
      if (!x) return { ok: false, reason: "Источник не опрашивается в этом скане" };
      Object.assign(x, { status: "running", error: null, verify_url: undefined });
      emit({ type: "source", scan_id: RUN.id, ...x, timeout_s: 90, deadline_ms: Date.now() + 90000 });
      setTimeout(() => {
        if (!RUN) return;
        Object.assign(x, { status: "ok", n: 3 });
        emit({ type: "source", scan_id: RUN.id, ...x });
      }, 600);
      return { ok: true };
    },
    // ---- Debug tab: plausible stubs ----
    logs_get: ({ limit, level, source } = {}) => {
      const rank = { error: 3, warn: 2, info: 1, debug: 0 },
        min = rank[level] || 0;
      const all = demoLogs().filter(
        e => (rank[e.level] || 0) >= min && (!source || source === "all" || e.source === source),
      );
      return all.slice(-(limit || 500));
    },
    logs_clear: () => {
      load().logs_cleared = true;
      save();
      return { ok: true, files: 3, demo: true };
    },
    logs_export: () => ({
      name: "FOCA-rs_logs_20261120120000.zip",
      path: "Download/FOCA-rs/FOCA-rs_logs_20261120120000.zip",
      size: 48213,
      files: 4,
      demo: true,
    }),
    crash_list: () =>
      load().logs_cleared
        ? []
        : [
            {
              name: "crash-20261119-221405-118.txt",
              size: 2140,
              kind: "rust",
              title:
                "паника в потоке «tokio-runtime-worker»: index out of bounds: the len is 0 but the index is 0",
            },
          ],
    crash_get: ({ name } = {}) => ({
      name,
      text: "FOCA-rs 0.9.0-beta (a3f9c2e)\nпаника в потоке «tokio-runtime-worker»: index out of bounds: the len is 0 but the index is 0\n  at crates/foca-meta/src/pdf.rs:412:17\n\nstack backtrace:\n   0: foca_meta::pdf::xref\n   1: foca_meta::pdf::parse\n   2: foca_engine::scan::analyze_doc\n",
      demo: true,
    }),
    // Debug → Search: dork engine journal and the embedded browser fingerprint (demo data).
    search_journal: () => ({
      engines: {
        startpage: {
          requests: 3,
          answered: 2,
          links: 31,
          captchas: 1,
          cached: 0,
          moved: 2,
          taken_over: 0,
          blocked: true,
        },
        brave_web: {
          requests: 5,
          answered: 5,
          links: 44,
          captchas: 0,
          cached: 1,
          moved: 0,
          taken_over: 2,
          blocked: false,
        },
        yahoo: {
          requests: 2,
          answered: 2,
          links: 17,
          captchas: 0,
          cached: 0,
          moved: 0,
          taken_over: 0,
          blocked: false,
        },
        searx_pool: {
          requests: 2,
          answered: 2,
          links: 21,
          captchas: 0,
          cached: 0,
          moved: 0,
          taken_over: 0,
          blocked: false,
        },
      },
    }),
    search_fingerprint: () => ({
      ok: true,
      demo: true,
      issues: [],
      fp: {
        userAgent:
          "Mozilla/5.0 (Linux; Android 15; 23078PND5G Build/AQ3A.240912.001) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.7680.65 Mobile Safari/537.36",
        uaBrands: "Chromium 146, Android WebView 146, Not-A.Brand 24",
        uaMobile: true,
        uaPlatform: "Android",
        uaModel: "23078PND5G",
        visibilityState: "visible",
        rafPerSecond: 60,
        webdriver: false,
        innerWidth: 393,
        innerHeight: 851,
        screen: "393x873",
        devicePixelRatio: 2.75,
        maxTouchPoints: 5,
        languages: "uk-UA,uk,ru,en-US",
        platform: "Linux armv81",
        timezone: "Europe/Kyiv",
      },
    }),
    search_fingerprint_page: () => ({
      name: "FOCA-rs_fingerprint.html",
      path: "Download/FOCA-rs/FOCA-rs_fingerprint.html",
      demo: true,
    }),
    search_captcha_test: ({ engine = "startpage" } = {}) => ({
      ok: true,
      supported: true,
      demo: true,
      engine,
      kind: "results",
      signals: {
        widget_script: false,
        challenge_iframe: false,
        challenge_form: false,
        challenge_dom_attr: false,
        challenge_url: false,
        blocked_status: false,
        has_results: true,
      },
      status: 200,
      url: `https://example.invalid/${engine}`,
    }),
    request_log_get: ({ project, limit, only_active } = {}) => {
      const st = P(project || load().settings.last_project);
      const out = [];
      let id = 1;
      (st.scans || []).forEach(sc => {
        const t0 = sc.started_at || "2026-11-19T21:00:00";
        out.push({
          id: id++,
          time: t0,
          scan_id: sc.id,
          module: "crt",
          method: "GET",
          url: `https://crt.sh/?q=%25.${st.project.domain || st.project.name}&output=json`,
          host: "crt.sh",
          status: 200,
          bytes: 48211,
          access: "passive",
          blocked: false,
          error: null,
        });
        out.push({
          id: id++,
          time: t0,
          scan_id: sc.id,
          module: "wayback",
          method: "GET",
          url: `https://web.archive.org/cdx/search/cdx?url=${st.project.domain || st.project.name}&matchType=domain&limit=5000&key=[СЕКРЕТ]`,
          host: "web.archive.org",
          status: 200,
          bytes: 912004,
          access: "passive",
          blocked: false,
          error: null,
        });
        (st.docs || [])
          .filter(d => d.url && !d.deleted)
          .slice(0, 18)
          .forEach(d => {
            const h = String(d.url)
              .replace(/^https?:\/\//, "")
              .split("/")[0];
            out.push({
              id: id++,
              time: t0,
              scan_id: sc.id,
              module: "docs",
              method: "GET",
              url: d.url,
              host: h,
              status: 200,
              bytes: Math.round((d.size_kb || 120) * 1024),
              access: "target",
              blocked: false,
              error: null,
            });
          });
        if (sc.active)
          (st.hosts || [])
            .filter(h => !h.internal)
            .slice(0, 6)
            .forEach((h, j) =>
              out.push({
                id: id++,
                time: t0,
                scan_id: sc.id,
                module: "fuzz",
                method: "GET",
                url: `https://${h.name}/${[".git/HEAD", "upload/docs/", "web.config.bak", ".env", "backup.zip", "docs/"][j]}`,
                host: h.name,
                status: j < 3 ? 200 : 404,
                bytes: j < 3 ? 1840 : 162,
                access: "active",
                blocked: false,
                error: null,
              }),
            );
        (st.scope.excl || []).slice(0, 1).forEach(x =>
          out.push({
            id: id++,
            time: t0,
            scan_id: sc.id,
            module: "docs",
            method: "GET",
            url: `https://${x}/owa/`,
            host: x,
            status: null,
            bytes: 0,
            access: "target",
            blocked: true,
            error: "out_of_scope: excluded",
          }),
        );
      });
      return out
        .filter(r => (!only_active || r.access !== "passive") && !reqLogGone(st, r))
        .reverse()
        .slice(0, limit || 500);
    },
    request_log_clear: a => reqLogClear(a),
    app_info: () => ({
      version: "0.9.0-beta",
      commit: "a3f9c2e",
      data_mb: 184.2,
      log_level: (load().settings.debug || {}).level || "info",
      demo: true,
    }),
    terms_get: () => {
      const t = load().terms;
      return {
        version: "1",
        accepted: !!t && t.terms_version === "1",
        accepted_version: t ? t.terms_version : null,
        accepted_at: t ? t.accepted_at : null,
      };
    },
    terms_accept: ({ version } = {}) => {
      if (version !== "1") throw apiErr("bad_args", "Версия условий устарела: откройте их заново");
      load().terms = { terms_version: "1", accepted_at: "2026-11-20T12:00:00" };
      save();
      return COMMANDS.terms_get();
    },
    demo_first_run: () => {
      load().terms = null;
      save();
      return { ok: true };
    },
    platform_permissions_status: () => {
      const u = load().settings.ui || {};
      return {
        notifications: !!u.demo_notif,
        notifications_runtime: true,
        notifications_blocked: false,
        battery: !!(u.battery || {}).excluded,
        oem: "xiaomi",
        manufacturer: "Xiaomi",
        brand: "Redmi",
        sdk: 36,
        demo: true,
      };
    },
    // Background status of the native layer (fixed demo device: Xiaomi / HyperOS).
    platform_bg_status: () => {
      const u = load().settings.ui || {};
      const hide = (u.demo_bg || {}).hide_recents;
      return {
        oem: "xiaomi",
        autostart: (u.demo_bg || {}).autostart || "off",
        // A state set by a scenario wins; otherwise the flag the Settings screen keeps.
        battery_unrestricted:
          (u.demo_bg || {}).battery === "unknown"
            ? null
            : typeof (u.demo_bg || {}).battery === "boolean"
              ? u.demo_bg.battery
              : !!(u.battery || {}).excluded,
        hide_recents: typeof hide === "boolean" ? hide : true,
        hide_recents_default: true,
        hide_recents_chosen: typeof hide === "boolean",
        demo: true,
      };
    },
    platform_bg_set: ({ hide_recents, demo_autostart, demo_battery } = {}) => {
      const S = load();
      const u = (S.settings.ui = { ...(S.settings.ui || {}) });
      if (typeof hide_recents === "boolean") u.demo_bg = { ...(u.demo_bg || {}), hide_recents };
      // Demo only: the "Enable autostart" button pretends the user switched it on in the system screen;
      // scenarios also set off/unknown and the battery state (true/false/"unknown").
      if (["on", "off", "unknown"].includes(demo_autostart))
        u.demo_bg = { ...(u.demo_bg || {}), autostart: demo_autostart };
      if (demo_battery === "unknown" || typeof demo_battery === "boolean" || demo_battery === null)
        u.demo_bg = { ...(u.demo_bg || {}), battery: demo_battery };
      save();
      return COMMANDS.platform_bg_status();
    },
    platform_request_notifications: () => {
      const S = load();
      S.settings.ui = { ...(S.settings.ui || {}), demo_notif: true };
      save();
      return { enabled: true, granted: true, action: "requested", demo: true };
    },
    platform_exit: () => ({ ok: true, demo: true }),
    // No native clipboard in the browser demo (like desktop): the UI falls back to navigator.clipboard.
    platform_clipboard_read: () => ({ ok: false, unsupported: true, text: "", available: false, demo: true }),
    platform_clipboard_write: () => ({ ok: false, unsupported: true, demo: true }),
    platform_clipboard_clear: () => ({ ok: false, unsupported: true, cleared: false, demo: true }),
    // Mirrors the native tri-state reply. The demo answers "done"; QA scenarios pick another outcome
    // via `demo_state` (done | cancelled | failed | not_solved) to exercise the UI paths.
    platform_verify_search: ({ url, demo_state } = {}) => {
      const state = ["done", "cancelled", "failed", "not_solved"].includes(demo_state) ? demo_state : "done";
      return { state, ok: state === "done", closed: state !== "done", demo: true, url };
    },
    platform_device_info: () => ({
      demo: true,
      manufacturer: "Xiaomi",
      brand: "Redmi",
      model: "Redmi Note 13 Pro",
      release: "16",
      sdk: 36,
      rom: "HyperOS 2.0",
      abi: "arm64-v8a, armeabi-v7a",
      app_version: "2.0.0-beta.3",
      flavor: "foss",
      mem_total_mb: 7642,
      mem_avail_mb: 2318,
      disk_free_mb: 41210,
      service_running: !!RUN,
      battery_ignoring: !!((load().settings.ui || {}).battery || {}).excluded,
      notifications: !!(load().settings.ui || {}).demo_notif,
      tz: "Europe/Kyiv",
      locale: (typeof navigator !== "undefined" && navigator.language) || "ru-RU",
      net: true,
      vpn: false,
    }),
    finding_set_status: ({ project, id, status }) => {
      const st = P(project);
      const f = touchFinding(st, id);
      if (!["new", "confirmed", "false", "accepted", "fixed"].includes(status))
        throw apiErr("bad_status", status);
      f.status = status;
      save();
      return clone(f);
    },
    finding_update: ({ project, id, patch }) => {
      const st = P(project);
      const f = touchFinding(st, id);
      ["sev", "notes", "tags", "photos", "status"].forEach(k => {
        if (patch && k in patch) f[k] = clone(patch[k]);
      });
      save();
      return clone(f);
    },
    doc_delete: ({ project, ids }) => {
      const st = P(project);
      let n = 0;
      st.docs.forEach(d => {
        if (ids.includes(d.id) && !d.deleted) {
          d.deleted = true;
          n++;
        }
      });
      save();
      return { deleted: n };
    },
    doc_restore: ({ project, ids }) => {
      const st = P(project);
      let n = 0;
      st.docs.forEach(d => {
        if (ids.includes(d.id) && d.deleted) {
          d.deleted = false;
          n++;
        }
      });
      save();
      return { restored: n };
    },
    settings_get: () => publicSettings(),
    settings_set: ({ patch }) => {
      const s = load().settings;
      const merge = (a, b) => {
        Object.keys(b || {}).forEach(k => {
          if (b[k] && typeof b[k] === "object" && !Array.isArray(b[k]) && a[k] && typeof a[k] === "object")
            merge(a[k], b[k]);
          else a[k] = b[k];
        });
      };
      if (patch && patch.sec) {
        delete patch.sec.pin_hash;
        delete patch.sec.panic_hash;
      }
      if (patch && patch.alerts) {
        for (const f of ["token", "bot_token", "tg_token", "url", "webhook_url", "secret"])
          delete patch.alerts[f];
        for (const sub of ["telegram", "webhook"]) {
          if (patch.alerts[sub] && typeof patch.alerts[sub] === "object") {
            for (const f of ["token", "bot_token", "url", "webhook_url", "value", "secret", "key"])
              delete patch.alerts[sub][f];
          }
        }
      }
      merge(s, patch);
      save();
      return publicSettings();
    },
    key_set: ({ service, value }) => {
      const s = load().settings;
      const v = String(value || "");
      s.keys[service] = {
        ...(s.keys[service] || {}),
        status: v ? "ok" : "none",
        mask: v.length > 8 ? v.slice(0, 4) + "…" + v.slice(-4) : v ? "••••" : "",
        error: undefined,
      };
      save();
      return clone(s.keys[service]);
    },
    key_delete: ({ service }) => {
      const s = load().settings;
      s.keys[service] = { status: "none", mask: "" };
      save();
      return clone(s.keys[service]);
    },
    net_check: () => {
      const n = load().settings.net;
      const canary = { tcp_intercept: false, dns_hijack: false, tls_mitm: false, unreliable: false };
      if (n.proxy_on) {
        const isV2 = n.preset === "v2ray" || /10808/.test(n.addr || "");
        return {
          ok: true,
          out_ip: n.out_ip || "198.51.100.200",
          country: n.out_country || "Германия",
          via: n.label || (isV2 ? "v2rayNG" : "Orbot (Tor)"),
          latency_ms: isV2 ? 68 : 240,
          org: isV2 ? "Hetzner Online GmbH" : "Tor Exit Node",
          ip_kind: isV2 ? "datacenter" : "tor",
          canary,
        };
      }
      return {
        ok: true,
        out_ip: "198.51.100.201",
        country: "Украина",
        via: "Напрямую",
        latency_ms: 28,
        org: "Ukrtelecom JSC",
        ip_kind: "residential",
        canary,
      };
    },
    net_proxy_check: ({ proxy, addr, type } = {}) => {
      const n = load().settings.net;
      const eff = proxy || (addr ? `${type === "http" ? "http" : "socks5h"}://${addr}` : "");
      if (eff === "direct" || (!eff && !n.proxy_on)) {
        return {
          ok: true,
          latency_ms: 28,
          out_ip: "198.51.100.201",
          country: "Украина",
          org: "Ukrtelecom JSC",
          ip_kind: "residential",
        };
      }
      if (/:9$/.test(eff || n.addr || "")) {
        return {
          ok: false,
          latency_ms: 12,
          out_ip: null,
          country: null,
          org: "",
          ip_kind: "unknown",
          error: "connection refused",
        };
      }
      const isV2 = /10808/.test(eff) || n.preset === "v2ray";
      return {
        ok: true,
        latency_ms: isV2 ? 68 : 240,
        out_ip: "198.51.100.200",
        country: "Германия",
        org: isV2 ? "Hetzner Online GmbH" : "Tor Exit Node",
        ip_kind: isV2 ? "datacenter" : "tor",
      };
    },
    report_list: ({ project }) => clone(P(project).reports),
    // Report templates (docs/API.md → report_templates): ids are fixed, texts follow the UI language.
    report_templates: ({ lang } = {}) => reportTemplates(lang),
    report_build: ({ project, opts = {}, template, custody }) => {
      const st = P(project);
      const id = (st.reports.reduce((a, r) => Math.max(a, r.id), 0) || 0) + 1;
      const fmt = opts.fmt || "pdf";
      const lang = fmt === "csv" || fmt === "json" ? "-" : opts.lang || "RU";
      const wantCustody = !!(custody || opts.custody);
      const o = clone(opts);
      delete o.size;
      delete o.now;
      delete o.custody;
      if (template) {
        const t = reportTemplates(lang).find(x => x.id === template);
        if (!t)
          throw Object.assign(new Error(`неизвестный шаблон отчёта: ${template}`), { code: "bad_args" });
        o.template = template;
        if (template !== "full") {
          o.tpl_id = template;
          o.tpl = t.title;
        }
      }
      o.lang = lang; // Size and time come from the core, not from opts.
      const result = reportResult(st, o);
      const r = {
        id,
        name: reportName(st, lang, fmt),
        tpl: o.tpl || "Полный отчёт пентеста",
        fmt,
        created_at: `${TODAY}T12:00:00`,
        size: reportSize(st, o, result),
        lang,
        opts: o,
        result,
      };
      st.reports.unshift(r);
      st.reportMeta = st.reportMeta || {};
      const digest = demoSha256(`${r.id}:${r.name}:${st.id}:${result.total}:${o.fmt || fmt}`);
      st.reportMeta[r.id] = {
        sha256: digest,
        custody: wantCustody
          ? {
              schema: "foca-custody/v1",
              report_file: r.name,
              report_sha256: digest,
              inputs_sha256: demoSha256(`inputs:${st.id}:${(st.scans || []).length}`),
              report_bytes: Math.max(512, (st.findings || []).length * 140),
              generated_at: `${TODAY}T12:00:00Z`,
              generator: "FOCA-rs demo",
              project: st.name || st.id,
              client: (st.scope && st.scope.client) || "",
              template: o.tpl_id || template || "full",
              format: fmt,
              lang: lang === "-" ? "ru" : lang.toLowerCase(),
              secrets_mode: o.secrets || "hide",
              scope_targets: ((st.scope && st.scope.targets) || []).map(t => t.v),
              scope_excludes: (st.scope && st.scope.excl) || [],
              findings_total: result.total || 0,
              docs_total: (st.docs || []).filter(d => !d.deleted).length,
              requests_total: (st.log || []).length,
              scans: (st.scans || []).map(s => ({
                id: s.id,
                profile: s.profile || s.profile_id || "",
                started_at: s.started_at || "",
                finished_at: s.finished_at || null,
                status: s.status || "done",
                egress: s.egress || "",
              })),
            }
          : null,
      };
      save();
      return clone(r);
    },
    report_delete: ({ project, id }) => {
      const st = P(project);
      st.reports = st.reports.filter(r => r.id !== +id);
      if (st.reportMeta) delete st.reportMeta[+id];
      save();
      return { ok: true };
    },
    report_verify: ({ project, id, name }) => {
      const st = P(project);
      const r = st.reports.find(x => (id != null && x.id === +id) || (name && x.name === name));
      if (!r) throw Object.assign(new Error("Отчёт не найден"), { code: "not_found" });
      const meta = (st.reportMeta && st.reportMeta[r.id]) || null;
      const hash = (meta && meta.sha256) || demoSha256(`${r.id}:${r.name}:${st.id}`);
      const custody = (meta && meta.custody) || null;
      return {
        ok: true,
        id: r.id,
        name: r.name,
        exists: true,
        actual_sha256: hash,
        expected_sha256: hash,
        hash_match: true,
        sidecar_present: true,
        sig_present: Boolean(custody),
        signature_alg: null,
        signature_valid: null,
        key_alias: null,
        key_fingerprint: null,
        signature_own_key: null,
        custody: clone(custody),
        status: "verified_hash",
      };
    },
    signatures_status: () => demoSigStatus(),
    signatures_import: ({ bundle_json, bundle }) => {
      let b = bundle;
      if (!b && typeof bundle_json === "string") {
        try {
          b = JSON.parse(bundle_json);
        } catch (e) {
          throw apiErr("bad_args", "Некорректный JSON пакета сигнатур: " + e.message, {
            code: "sig.bad_json",
            params: { error: e.message },
          });
        }
      }
      if (!b || b.schema !== "foca-sig-bundle/v1" || !b.version || !b.released_at) {
        throw apiErr("bad_args", "Пустая версия или дата выпуска пакета сигнатур", {
          code: "sig.no_version",
          params: {},
        });
      }
      if (!b.signature_ed25519) {
        throw apiErr("bad_signature", "Цифровая подпись Ed25519 пакета сигнатур недействительна", {
          code: "sig.bad_signature",
          params: {},
        });
      }
      const db = load();
      if (db._sigBundle) db._sigPrev = clone(db._sigBundle);
      db._sigBundle = {
        version: String(b.version),
        released_at: String(b.released_at),
        kev_additions: Array.isArray(b.kev_additions) ? b.kev_additions : [],
        cpe_additions: Array.isArray(b.cpe_additions) ? b.cpe_additions : [],
        secret_additions: Array.isArray(b.secret_additions) ? b.secret_additions : [],
        sha256: b.sha256 || demoSha256(String(b.version) + ":" + String(b.released_at)),
      };
      save();
      return demoSigStatus();
    },
    // No network in the demo and nothing is published at the official feed yet: the check honestly
    // ends with `no_update` (like the core on HTTP 404) and is recorded as the last check.
    signatures_update: ({ url } = {}) => {
      const db = load();
      const d = new Date();
      const at = `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
      db._sigCheck = {
        at,
        outcome: "no_update",
        feed_url: url || DEMO_SIG_FEED,
        version: null,
        error: null,
        error_code: null,
      };
      save();
      return demoSigStatus();
    },
    signatures_rollback: () => {
      const db = load();
      if (db._sigPrev) {
        db._sigBundle = clone(db._sigPrev);
        delete db._sigPrev;
      } else {
        delete db._sigBundle;
      }
      save();
      return demoSigStatus();
    },
    plugins_list: () => {
      const db = load();
      const base = [
        {
          id: "certspotter-ext",
          name: "CertSpotter Extended CT",
          version: "2.0.0",
          author: "FOCA-rs Team",
          description: "Пассивный коллектор сертификатов Certificate Transparency (v1 API)",
          kind: "source",
          runtime: "declarative",
          permissions: ["net:passive"],
          sha256: demoSha256("certspotter-ext"),
          enabled: true,
          builtin: true,
          source: "builtin",
          url_template:
            "https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names",
        },
        {
          id: "robots-sitemap-parser",
          name: "Robots & Sitemap Enricher",
          version: "2.0.0",
          author: "FOCA-rs Team",
          description: "Извлечение служебных путей и URL из robots.txt и sitemap.xml",
          kind: "enricher",
          runtime: "declarative",
          permissions: ["net:scoped"],
          sha256: demoSha256("robots-sitemap-parser"),
          enabled: true,
          builtin: true,
          source: "builtin",
          url_template: "https://{domain}/robots.txt",
        },
        {
          id: "ua-gov-edrpou-enricher",
          name: "ЄДРПОУ & КЕП Enricher",
          version: "2.0.0",
          author: "FOCA-rs Team",
          description: "Локальное обогащение карточек организаций по кодам ЄДРПОУ и КЕП (без сети)",
          kind: "enricher",
          runtime: "declarative",
          permissions: ["meta:read"],
          sha256: demoSha256("ua-gov-edrpou-enricher"),
          enabled: true,
          builtin: true,
          source: "builtin",
          url_template: null,
        },
        {
          id: "custom-header-audit",
          name: "Corporate HTTP Header Audit",
          version: "2.0.0",
          author: "FOCA-rs Team",
          description: "Проверка корпоративных заголовков (Strict-Transport-Security / X-Frame-Options)",
          kind: "analyzer",
          runtime: "declarative",
          permissions: ["net:scoped", "meta:read"],
          sha256: demoSha256("custom-header-audit"),
          enabled: false,
          builtin: true,
          source: "builtin",
          url_template: "https://{domain}/",
        },
      ];
      const st = db._corePlugins || {};
      const custom = Object.values(db._customPlugins || {}).map(m => ({
        ...clone(m),
        builtin: false,
        source: "custom",
      }));
      const items = [...base, ...custom].map(p => ({ ...p, enabled: p.id in st ? !!st[p.id] : p.enabled }));
      return {
        items,
        counts: {
          total: items.length,
          enabled: items.filter(x => x.enabled).length,
          builtin: items.filter(x => x.builtin).length,
          custom: items.filter(x => !x.builtin).length,
        },
      };
    },
    plugin_install: ({ manifest }) => {
      let m = manifest;
      if (typeof manifest === "string") {
        try {
          m = JSON.parse(manifest);
        } catch (e) {
          throw apiErr("bad_args", "Манифест плагина: " + e.message);
        }
      }
      if (!m || !m.id || !m.name) throw apiErr("bad_args", "Нужны поля id и name");
      const db = load();
      db._customPlugins = db._customPlugins || {};
      db._corePlugins = db._corePlugins || {};
      const info = {
        id: String(m.id),
        name: String(m.name),
        version: String(m.version || "1.0.0"),
        author: String(m.author || "Custom"),
        description: String(m.description || ""),
        kind: String(m.kind || "analyzer"),
        runtime: String(m.runtime || "declarative"),
        permissions: Array.isArray(m.permissions) ? m.permissions : ["meta:read"],
        sha256: String(m.sha256 || demoSha256(String(m.id))),
        enabled: m.enabled !== false,
        builtin: false,
        source: "custom",
        url_template: m.declarative && m.declarative.url_template ? String(m.declarative.url_template) : null,
      };
      db._customPlugins[info.id] = clone(info);
      db._corePlugins[info.id] = info.enabled;
      save();
      return info;
    },
    plugin_toggle: ({ id, enabled }) => {
      const db = load();
      db._corePlugins = db._corePlugins || {};
      db._corePlugins[id] = !!enabled;
      save();
      const res = COMMANDS.plugins_list().items.find(p => p.id === id);
      if (!res) throw apiErr("not_found", "Плагин не найден: " + id);
      return res;
    },
    plugin_remove: ({ id }) => {
      const db = load();
      if (!db._customPlugins || !db._customPlugins[id])
        throw apiErr("bad_args", "Нельзя удалить встроенный плагин");
      delete db._customPlugins[id];
      if (db._corePlugins) delete db._corePlugins[id];
      save();
      return { ok: true, id };
    },
    plugin_run_test: ({ id, target, passive, sample_body }) => {
      const p = COMMANDS.plugins_list().items.find(x => x.id === id);
      if (!p) throw apiErr("not_found", "Плагин не найден: " + id);
      const tgt = target || "example.test";
      const isPassive = passive !== false;
      const scopedBlocked = isPassive && (p.permissions || []).includes("net:scoped");
      const url = p.url_template ? p.url_template.replace("{domain}", tgt).replace("{target}", tgt) : null;
      return {
        ok: !scopedBlocked,
        id: p.id,
        runtime: p.runtime,
        fuel_used: p.runtime === "wasm" ? 42 : 0,
        hosts: [],
        urls: [],
        findings:
          !scopedBlocked && sample_body && id === "ua-gov-edrpou-enricher"
            ? [{ title: "Код ЄДРПОУ в метаданных / сертификате КЕП", severity: "info", detail: "12345678" }]
            : [],
        blocked_reason: scopedBlocked
          ? "blocked_passive: ADR-0009 запрещает плагину обращаться к цели в пассивном режиме"
          : null,
        http_url: url,
      };
    },
    oos_list: ({ project }) => oosOf(P(project)),
    // Infrastructure records of the infrastructure modules (docs/API.md → infra_get): one array per kind.
    infra_get: a => infraOf(P(a.project)),
    // Analytics (docs/API.md → "Аналитика").
    insights_get: a => insightsOf(P(a.project).project.id, a),
    chain_get: a => chainOf(P(a.project).project.id, a),
    attack_paths_get: a => attackPathsOf(P(a.project).project.id),
    oos_decide: ({ project, id, decision }) => {
      const st = P(project);
      const o = oosOf(st).find(x => x.id === id);
      if (!o) throw apiErr("not_found", `Кандидат ${id} не найден`);
      if (!["new", "scope", "ignored"].includes(decision)) throw apiErr("bad_status", decision);
      if (decision === "scope" && o.blocked) throw apiErr("blocked", o.blocked);
      st.oos_dec = st.oos_dec || {};
      if (decision === "new") delete st.oos_dec[o.host];
      else st.oos_dec[o.host] = decision;
      save();
      return oosOf(st);
    },
    // Atomic: candidate decision + adding the target to the scope; exclusions win: a candidate from the
    // exclusions cannot be added.
    oos_add_to_scope: ({ project, id }) => {
      const st = P(project);
      const o = oosOf(st).find(x => x.id === id);
      if (!o) throw apiErr("not_found", `Кандидат ${id} не найден`);
      if (o.blocked) throw apiErr("blocked", o.blocked);
      if (scopeCheck(st.scope, o.host, st.hosts).code === "excluded")
        throw apiErr("blocked", "Адрес в исключениях скоупа");
      st.oos_dec = st.oos_dec || {};
      st.oos_dec[o.host] = "scope";
      const type = o.kind === "ip" || o.kind === "cdn" ? "ip" : "domain"; // Networks are not added from candidates.
      if (!st.scope.targets.some(t => String(t.v).toLowerCase() === o.host.toLowerCase()))
        st.scope.targets.push({ v: o.host, type });
      save();
      return { scope: clone(st.scope), oos: oosOf(st) };
    },
    // The plain secret value is available only through this command, after biometric confirmation in the UI.
    // id: a number (secrets[].id) or "f<finding id>:<k>".
    secret_reveal: ({ project, id }) => {
      const st = P(project);
      const m = String(id).match(/^f(\d+):(\d+)$/);
      if (m) {
        const f = touchFinding(st, +m[1]);
        const all = [...String(f.evidence || "").matchAll(SECRET_RX)];
        const x = all[+m[2]];
        if (!x) throw apiErr("not_found", `Секрет ${id} не найден`);
        return { id: String(id), value: x[1] };
      }
      const x = (st.secrets || []).find(z => z.id === +id);
      if (!x) throw apiErr("not_found", `Секрет ${id} не найден`);
      return { id: +id, value: x.value };
    },
    secret_hibp_check: ({ project, id }) => {
      const { id: rid, value } = COMMANDS.secret_reveal({ project, id });
      const h = (hash(String(value || "")) >>> 0).toString(16).toUpperCase().padStart(5, "0").slice(0, 5);
      const weak = /pass|123|qwer|admin|secret|contoso/i.test(String(value || ""));
      return { id: rid, pwned: weak, count: weak ? 1842 : 0, prefix: h };
    },
    export_build: ({ project, ...a }) => exportBuild(P(project), a),
    wordlist_preview: ({ project, ...a }) => demoWordlist(P(project), a),
    hygiene_get: ({ project, ids, path, name }) =>
      path ? sharedHygiene(name) : hygieneGet(P(project), ids || []),
    doc_clean: ({ project, ids, path, name }) => {
      if (path) return { cleaned: [sharedClean(name)] };
      const st = P(project);
      const r = docClean(st, [].concat(ids).map(Number));
      save();
      return { cleaned: r };
    },
    tool_file: ({ path, name }) => toolFile(name || path),
    tool_secret: ({ value, hibp_opt_in }) => {
      const v = String(value || "");
      const classes = {
        lower: /[a-zа-я]/.test(v),
        upper: /[A-ZА-Я]/.test(v),
        digit: /\d/.test(v),
        symbol: /[^\p{L}\d\s]/u.test(v),
      };
      const pool =
        (classes.lower ? 26 : 0) +
        (classes.upper ? 26 : 0) +
        (classes.digit ? 10 : 0) +
        (classes.symbol ? 33 : 0);
      const bits = Math.round(v.length * Math.log2(Math.max(pool, 1)) * 10) / 10;
      const score = bits < 28 ? 0 : bits < 36 ? 1 : bits < 60 ? 2 : bits < 80 ? 3 : 4;
      if (hibp_opt_in)
        toolLog(
          "secret",
          "GET",
          "https://api.pwnedpasswords.com/range/[PREFIX]",
          "api.pwnedpasswords.com",
          200,
        );
      return {
        length: v.length,
        classes,
        entropy_bits: bits,
        score,
        strength: ["very_weak", "weak", "fair", "strong", "very_strong"][score],
        crack_time: ["instant", "minutes", "days", "years", "centuries"][score],
        issues: v.length < 12 ? ["short"] : [],
        detected: null,
        mask: v.length > 8 ? `${v.slice(0, 2)}…${v.slice(-2)}` : "••••",
        hibp: hibp_opt_in
          ? {
              status: "ok",
              pwned: /pass|123|qwer|admin|secret/i.test(v),
              count: /pass|123|qwer|admin|secret/i.test(v) ? 142318 : 0,
              prefix: (hash(v) >>> 0).toString(16).toUpperCase().padStart(5, "0").slice(0, 5),
            }
          : { status: "not_requested" },
        ...toolTiming,
      };
    },
    tool_mail_domain: ({ domain }) => {
      const d = String(domain || "contoso.example")
        .split("@")
        .pop()
        .toLowerCase();
      ["TXT", "MX", "TXT"].forEach((t, i) =>
        toolLog("mail", "DNS", `dns://${i === 2 ? "_dmarc." : ""}${d}/${t}`, d, null),
      );
      return {
        domain: d,
        risk: {
          level: "high",
          reasons: ["DMARC p=none только собирает отчёты и не блокирует подделку"],
          spoofable: true,
        },
        mx: [`10 mail.${d}`],
        spf: {
          record: "v=spf1 include:spf.protection.outlook.com ~all",
          all: "~",
          includes: ["spf.protection.outlook.com"],
          redirect: null,
          dns_lookups: 1,
        },
        dmarc: { record: "v=DMARC1; p=none", p: "none", sp: null, pct: 100, rua: [] },
        dkim: { selectors: ["selector1"], checked: 20, wildcard: false },
        bimi: null,
        mta_sts: { record: null, policy: null, fetch: { status: "skipped" } },
        tls_rpt: null,
        caa: [],
        dnssec: "unsigned",
        issues: [
          {
            id: "dmarc_none",
            sev: "warn",
            title: "DMARC p=none: подделка писем от домена возможна",
            detail: "v=DMARC1; p=none",
          },
        ],
        incomplete: [],
        lookups: { done: 30, total: 30 },
        ...toolTiming,
        elapsed_ms: 820,
      };
    },
    tool_host: ({ url, host }) => {
      const input = String(url || host || "contoso.example");
      const h = input
        .replace(/^\w+:\/\//, "")
        .split(/[/:?#]/)[0]
        .toLowerCase();
      toolLog("host", "GET", /^\w+:\/\//.test(input) ? input : `https://${h}/`, h, 200);
      toolLog("host", "TLS", `tls://${h}:443`, h, null);
      return {
        input,
        host: h,
        port: null,
        host_port: h,
        url: `https://${h}/`,
        status: 200,
        headers: { url: `https://${h}/`, https: true, csp_source: "", issues: [] },
        header_issues: [
          { id: "csp_missing", sev: "warn", title: "Нет Content-Security-Policy", detail: `https://${h}/` },
        ],
        technologies: [
          {
            name: "nginx",
            category: "Веб-сервер",
            version: "1.18.0",
            confidence: 100,
            evidence: ["header server: nginx/1.18.0"],
            outdated: null,
            website: null,
          },
        ],
        favicon: {
          url: `https://${h}/favicon.ico`,
          mmh3: -1293291467,
          sha256: "ab".repeat(32),
          md5: "cd".repeat(16),
          size: 1150,
          queries: ["shodan: http.favicon.hash:-1293291467"],
        },
        tls: null,
        steps: {
          page: { status: "ok" },
          tls: { status: "error", error: "демо: TLS не проверяется" },
          favicon: { status: "ok" },
        },
        ...toolTiming,
        elapsed_ms: 1300,
      };
    },
    tool_log: ({ limit } = {}) =>
      TOOL_LOG.slice()
        .reverse()
        .slice(0, limit || 100),
    tool_log_clear: () => ({ ok: true, removed: TOOL_LOG.splice(0).length }),
    queue_add: ({ projects, project, profile, args }) => {
      const ids = projects || (project ? [project] : []);
      if (!ids.length) throw apiErr("bad_args", "нужен список projects");
      const added = [];
      const skipped = [];
      for (const id of ids) {
        const st = P(id);
        if (DEMO_QUEUE.items.some(i => i.project === id && ["pending", "running"].includes(i.status))) {
          skipped.push(id);
          continue;
        }
        const qid = `q${++DEMO_QUEUE.seq}`;
        DEMO_QUEUE.items.push({
          id: qid,
          project: id,
          name: st.name,
          profile: profile || "std",
          status: "pending",
          scan_id: null,
          progress: 0,
          reason: null,
          error: null,
          added_at: `${TODAY}T12:00:00`,
          started_at: null,
          finished_at: null,
        });
        added.push(qid);
      }
      return { ...queueView(), added, skipped };
    },
    queue_list: () => queueView(),
    queue_pause: () => {
      Object.assign(DEMO_QUEUE, { paused: true, pause_reason: "user" });
      return queueView();
    },
    queue_resume: () => {
      Object.assign(DEMO_QUEUE, { paused: false, pause_reason: null });
      return queueView();
    },
    queue_remove: ({ id }) => {
      const n = DEMO_QUEUE.items.length;
      DEMO_QUEUE.items = DEMO_QUEUE.items.filter(i => i.id !== id);
      if (DEMO_QUEUE.items.length === n) throw apiErr("not_found", `элемент очереди ${id} не найден`);
      return queueView();
    },
    queue_clear: ({ stop } = {}) => {
      DEMO_QUEUE.items = DEMO_QUEUE.items.filter(i => !stop && i.status === "running");
      if (!DEMO_QUEUE.items.length) Object.assign(DEMO_QUEUE, { paused: false, pause_reason: null });
      return queueView();
    },
    alert_rules_get: ({ project } = {}) => {
      const S = load();
      const base = clone(S.settings.alerts || defaultSettings().alerts);
      const ovr = project && P(project).alerts ? P(project).alerts : null;
      if (ovr) {
        Object.keys(ovr).forEach(k => {
          if (ovr[k] && typeof ovr[k] === "object" && !Array.isArray(ovr[k]) && base[k])
            base[k] = { ...base[k], ...ovr[k] };
          else base[k] = clone(ovr[k]);
        });
      }
      const ks = S.settings.keys || {};
      const tgOk =
        ks.tg_bot && ks.tg_bot.status === "ok" && String((base.telegram || {}).chat_id || "").trim() !== "";
      const whOk = ks.webhook && ks.webhook.status === "ok";
      base.telegram = { ...(base.telegram || { enabled: false, chat_id: "" }), ready: !!tgOk };
      base.webhook = { ...(base.webhook || { enabled: false, kind: "generic" }), ready: !!whOk };
      base.available_rules = [
        "new_host",
        "new_port",
        "doc_secret",
        "doc_pii",
        "doc_gps",
        "tls_expiry",
        "dangling_cname",
        "ct_new_cert",
        "risk_rise",
      ].map(id => ({ id, is_diff: !["tls_expiry", "dangling_cname", "risk_rise"].includes(id) }));
      const pid = project || S.settings.last_project;
      base.history = pid && S.projects[pid] ? clone(S.projects[pid].alert_history || []) : [];
      return base;
    },
    alert_rules_set: ({ project, patch = {} } = {}) => {
      const clean = clone(patch);
      for (const f of ["token", "bot_token", "tg_token", "url", "webhook_url", "secret"]) delete clean[f];
      for (const sub of ["telegram", "webhook"]) {
        if (clean[sub] && typeof clean[sub] === "object") {
          for (const f of ["token", "bot_token", "url", "webhook_url", "value", "secret", "key"])
            delete clean[sub][f];
        }
      }
      if (
        clean.webhook &&
        clean.webhook.kind &&
        !["slack", "mattermost", "discord", "generic"].includes(clean.webhook.kind)
      )
        throw apiErr("bad_args", `неизвестный тип webhook: ${clean.webhook.kind}`);
      if (project) {
        const st = P(project);
        const cur = st.alerts || {};
        Object.keys(clean).forEach(k => {
          if (clean[k] && typeof clean[k] === "object" && !Array.isArray(clean[k]) && cur[k])
            cur[k] = { ...cur[k], ...clean[k] };
          else cur[k] = clean[k];
        });
        st.alerts = cur;
        save();
      } else {
        COMMANDS.settings_set({ patch: { alerts: clean } });
      }
      return COMMANDS.alert_rules_get({ project });
    },
    alert_test: ({ project, channel } = {}) => {
      const ch = String(channel || "").toLowerCase();
      if (ch !== "telegram" && ch !== "webhook") throw apiErr("bad_args", `неизвестный канал ${ch}`);
      const cfg = COMMANDS.alert_rules_get({ project });
      const S = load();
      const ks = S.settings.keys || {};
      if (ch === "telegram") {
        if (!ks.tg_bot || ks.tg_bot.status !== "ok")
          return {
            ok: false,
            channel: ch,
            status: null,
            attempts: 0,
            sent: 0,
            error: "Токен Telegram-бота не задан",
          };
        if (!String((cfg.telegram || {}).chat_id || "").trim())
          return { ok: false, channel: ch, status: null, attempts: 0, sent: 0, error: "Не указан chat_id" };
      } else if (!ks.webhook || ks.webhook.status !== "ok") {
        return { ok: false, channel: ch, status: null, attempts: 0, sent: 0, error: "URL webhook не задан" };
      }
      return { ok: true, channel: ch, status: 200, attempts: 1, sent: 1, error: null };
    },
    risk_trend_get: ({ project, limit = 30 } = {}) => {
      const st = P(project);
      const pts = (st.scans || [])
        .filter(s => s.finished_at && (s.status === "done" || s.status === "stopped"))
        .map(s => {
          const c = { crit: 0, high: 0, warn: 0, low: 0, info: 0 };
          const fm = (s.snapshot && s.snapshot.findings) || {};
          Object.values(fm).forEach(sev => {
            if (c[sev] != null) c[sev]++;
          });
          const total = c.crit + c.high + c.warn + c.low + c.info;
          const p =
            Math.pow(0.75, c.crit) * Math.pow(0.88, c.high) * Math.pow(0.95, c.warn) * Math.pow(0.98, c.low);
          const risk = Math.max(0, Math.min(100, Math.round(100 * (1 - p))));
          return {
            scan_id: s.id,
            time: s.finished_at || s.started_at,
            risk,
            counts: c,
            total,
            complete: s.status === "done" && !(s.env && s.env.incomplete),
          };
        });
      const sliced = limit > 0 ? pts.slice(-limit) : pts;
      const first = sliced[0];
      const last = sliced[sliced.length - 1];
      const prev = sliced.length >= 2 ? sliced[sliced.length - 2] : null;
      const delta = sliced.length > 1 ? last.risk - first.risk : null;
      const direction = delta == null ? "none" : delta > 0 ? "up" : delta < 0 ? "down" : "flat";
      const peak = sliced.length ? Math.max(...sliced.map(x => x.risk)) : null;
      return {
        points: sliced,
        current: last ? last.risk : null,
        previous: prev ? prev.risk : null,
        delta,
        direction,
        peak,
      };
    },
    i18n_bundle: ({ lang, device_locale, include_help = false } = {}) => {
      if (device_locale) demoDeviceLocale = device_locale;
      const s = load().settings;
      const raw = lang ?? s.lang ?? (s.ui && s.ui.look && s.ui.look.lang) ?? "auto";
      const r = demoResolveLang(raw, device_locale);
      return {
        lang: r.lang,
        ui_code: r.ui_code,
        setting: r.setting,
        // QA harness (qa/shoot.mjs) passes the full dictionary merged from locales/<lang>/.
        ui: {
          ...((typeof window !== "undefined" && window.FOCA_DEMO_UI && window.FOCA_DEMO_UI[r.lang]) ||
            DEMO_I18N_UI[r.lang] ||
            DEMO_I18N_UI.en),
        },
        findings: demoFindingsBundle(r.lang),
        help: include_help ? demoHelpBundle(r.lang) : null,
      };
    },
    licenses_get: () => ({
      schema: "foca-licenses/v1",
      app_license: "GPL-3.0",
      repository: "https://github.com/SinonApp/FOCA-rs",
      counts: {
        data_assets: 5,
        rust_total: 4,
        rust_direct: 4,
        android_total: 3,
        android_play_only: 1,
        license_texts: 3,
      },
      data_assets: [
        {
          name: "FOCA-rs",
          category: "Application",
          license: "GPL-3.0",
          url: "https://github.com/SinonApp/FOCA-rs",
          notes: "Open-source mobile OSINT, document metadata & forensics engine (GNU GPL v3.0).",
        },
        {
          name: "Inter Font",
          category: "Font",
          license: "SIL OFL 1.1",
          url: "https://rsms.me/inter/",
          notes: "Embedded UI typeface, © Rasmus Andersson.",
        },
        {
          name: "Natural Earth 1:110m & 1:50m",
          category: "Dataset",
          license: "Public Domain",
          url: "https://www.naturalearthdata.com/",
          notes: "Offline world country boundaries for the 3D GPS globe.",
        },
        {
          name: "SecLists",
          category: "Wordlists",
          license: "MIT",
          url: "https://github.com/danielmiessler/SecLists",
          notes: "Embedded path/subdomain discovery wordlists, © Daniel Miessler.",
        },
        {
          name: "CISA KEV",
          category: "Dataset",
          license: "Public Domain (U.S. Gov)",
          url: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
          notes: "Filtered offline snapshot (17 U.S.C. § 105).",
        },
      ],
      rust_crates: [
        {
          name: "tauri",
          version: "2.10.3",
          license: "Apache-2.0 OR MIT",
          direct: true,
          repository: "https://github.com/tauri-apps/tauri",
        },
        {
          name: "reqwest",
          version: "0.12.28",
          license: "MIT OR Apache-2.0",
          direct: true,
          repository: "https://github.com/seanmonstar/reqwest",
        },
        {
          name: "hickory-resolver",
          version: "0.25.2",
          license: "MIT OR Apache-2.0",
          direct: true,
          repository: "https://github.com/hickory-dns/hickory-dns",
        },
        {
          name: "ring",
          version: "0.17.14",
          license: "Apache-2.0 AND ISC",
          direct: true,
          repository: "https://github.com/briansmith/ring",
        },
      ],
      android_libs: [
        {
          name: "androidx.webkit:webkit",
          version: "1.14.0",
          license: "Apache-2.0",
          flavor: "both",
          proprietary: false,
          purpose: "WebView proxy & X-Requested-With configuration",
        },
        {
          name: "androidx.work:work-runtime",
          version: "2.10.5",
          license: "Apache-2.0",
          flavor: "both",
          proprietary: false,
          purpose: "Scheduled background monitoring via WorkManager",
        },
        {
          name: "com.google.mlkit:text-recognition",
          version: "16.0.1",
          license: "Google APIs ToS (play flavor only)",
          flavor: "play",
          proprietary: true,
          purpose: "Optional offline OCR in the play flavor (excluded from foss / F-Droid)",
        },
      ],
      license_texts: [
        {
          id: "GPL-3.0",
          name: "GNU General Public License v3.0",
          text: "GNU GENERAL PUBLIC LICENSE Version 3, 29 June 2007.",
        },
        {
          id: "MIT",
          name: "MIT License",
          text: "Permission is hereby granted, free of charge, to any person obtaining a copy of this software.",
        },
        { id: "Apache-2.0", name: "Apache License 2.0", text: "Apache License, Version 2.0, January 2004." },
      ],
    }),
    ai_models_list: ({ provider, base_url } = {}) => {
      const ep = aiEndpointDemo(provider || (load().settings.ai || {}).provider, base_url);
      if (!ep.ok) {
        return {
          provider: "custom",
          host: "",
          models: [],
          source: "bad_url",
          error: "Укажите корректный URL OpenAI-совместимого API (https://… или http://localhost…)",
          error_msg: { code: "ai.bad_url", params: {} },
        };
      }
      const k = (load().settings.keys || {}).ai;
      if (!k || k.status !== "ok") {
        return {
          provider: ep.provider,
          host: ep.host,
          models: [],
          source: "no_key",
          error: "Укажите ключ API, чтобы загрузить список моделей от провайдера",
          error_msg: { code: "ai.models_need_key", params: {} },
        };
      }
      return {
        provider: ep.provider,
        host: ep.host,
        models: (DEMO_AI_MODELS[ep.provider] || []).map(x => ({ ...x })),
        source: "api",
        error: "",
        error_msg: null,
      };
    },
    ai_preview: ({ project, opts }) => aiPreview(P(project), opts || {}),
    ai_summarize: ({ project, preview_id, opts }) => aiSummarizeRun(project, { preview_id, opts }),
    ai_cancel: ({ project }) => {
      const stop = aiJobs.get(project);
      if (stop) stop();
      return { cancelled: !!stop };
    },
    ai_summaries_list: ({ project }) => aiHistOut(project),
    ai_summary_use: ({ project, summary }) => {
      const h = aiHist(project);
      if (!h.items.some(e => e.id === summary)) throw apiErr("not_found", "ИИ-сводка не найдена");
      h.report_id = summary;
      save();
      return aiHistOut(project);
    },
    ai_summary_delete: ({ project, summary }) => {
      const h = aiHist(project);
      const n = h.items.length;
      h.items = h.items.filter(e => e.id !== summary);
      if (h.items.length === n) throw apiErr("not_found", "ИИ-сводка не найдена");
      if (h.report_id === summary) h.report_id = null;
      save();
      return aiHistOut(project);
    },
    pin_set: ({ pin, panic }) => {
      if (!/^\d{4,8}$/.test(String(pin || ""))) throw apiErr("bad_pin", "PIN: 4-8 цифр");
      const s = load().settings.sec;
      s.pin_hash = sha("pin:" + pin);
      if (panic) s.panic_hash = sha("pin:" + panic);
      s.pin = true;
      s.pin_fail = 0;
      save();
      return { ok: true };
    },
    pin_check: ({ pin }) => {
      const s = load().settings.sec;
      if (!s.pin_hash) return { ok: true, panic: false, attempts_left: 5 };
      const h = sha("pin:" + pin);
      if (s.panic_hash && h === s.panic_hash) {
        COMMANDS.wipe_all({ confirm: "WIPE" });
        return { ok: true, panic: true, attempts_left: 5 };
      }
      if (h === s.pin_hash) {
        s.pin_fail = 0;
        save();
        return { ok: true, panic: false, attempts_left: 5 };
      }
      s.pin_fail = (s.pin_fail || 0) + 1;
      save();
      return { ok: false, panic: false, attempts_left: Math.max(0, 5 - s.pin_fail) };
    },
    // Wipe all data (panic PIN, "Delete everything"): projects, keys, settings.
    wipe_all: ({ confirm } = {}) => {
      if (confirm !== "WIPE") throw apiErr("bad_confirm", "Нужно подтверждение");
      RUN = null;
      clearTimeout(tickT);
      TOOL_LOG.length = 0;
      const S = load();
      S.projects = {};
      S.order = [];
      S.settings = defaultSettings();
      S.settings.last_project = null;
      delete S.run;
      S.terms = null;
      save();
      return { ok: true };
    },
    finding_photo_add: ({ project, id, name, from }) => {
      const st = P(project);
      const f = touchFinding(st, id);
      f.photos = (f.photos || []).concat({
        name: name || `IMG_${TODAY.replace(/-/g, "")}.jpg`,
        time: "20.11, 12:00",
        from: from || "камера",
      });
      save();
      return clone(f);
    },
    finding_playbook: ({ project, id, lang }) => {
      const st = P(project);
      const f = touchFinding(st, id);
      // Like the core: an explicit lang wins, otherwise the effective UI language (auto = device locale).
      const l = lang
        ? demoResolveLang(String(lang).toUpperCase() === "UA" ? "uk" : lang, demoDeviceLocale).lang
        : demoResolveLang(
            load().settings?.lang ?? load().settings?.ui?.look?.lang ?? "auto",
            demoDeviceLocale,
          ).lang;
      const safeHost =
        String(f.host || "target.example").replace(/[^A-Za-z0-9.:_-]/g, "") || "target.example";
      const safeUrl = (f.url && /^https?:\/\//i.test(f.url) ? f.url : `https://${safeHost}/`).replace(
        /[\s"'`$;&|<>]/g,
        "",
      );
      const rule = f.provenance?.rule || "";
      const refs = rule && DEMO_STANDARDS[rule] ? [rule] : [];
      const titles = {
        uk: `Перевірка та усунення знахідки на ${safeHost}`,
        ru: `Проверка и устранение находки на ${safeHost}`,
        en: `Remediate security finding on ${safeHost}`,
      };
      const summaries = {
        uk: `План дій для ${f.title} (${safeHost}).`,
        ru: `План действий для ${f.title} (${safeHost}).`,
        en: `Actionable steps for ${f.title} (${safeHost}).`,
      };
      return {
        id: f.id,
        host: f.host,
        rule,
        playbook_key: rule || f.category || "general",
        lang: l,
        title: titles[l],
        summary: summaries[l],
        effort: "quick",
        steps: [
          {
            step: 1,
            title:
              l === "en"
                ? "Confirm context and restrict exposure"
                : l === "uk"
                  ? "Підтвердити контекст і обмежити доступ"
                  : "Подтвердить контекст и ограничить доступ",
            action: f.recommendation || summaries[l],
            command: `curl -sI "${safeUrl}"`,
            owner: "SecOps / DevOps",
          },
          {
            step: 2,
            title:
              l === "en"
                ? "Verify remediation and re-scan"
                : l === "uk"
                  ? "Перевірити виправлення й повторити сканування"
                  : "Проверить исправление и пересканировать",
            action: summaries[l],
            owner: "IT / SecOps",
          },
        ],
        verify: [
          l === "en"
            ? `Verify ${safeUrl} no longer reproduces ${rule || "finding"} and re-scan.`
            : l === "uk"
              ? `Перевірити ${safeUrl} і повторити сканування у FOCA-rs.`
              : `Проверить ${safeUrl} и выполнить повторный скан в FOCA-rs.`,
        ],
        references: refs,
        disclaimer:
          l === "en"
            ? "Run active verification checks strictly within authorized scope."
            : l === "uk"
              ? "Виконуйте активні перевірки лише в межах погодженого скоупу."
              : "Выполняйте активные проверки только в согласованном скоупе.",
      };
    },
    // Android platform (docs/API.md, "Platform commands"): stubs in the demo; screens show their own demo
    // sheets.
    platform_share: ({ name, path } = {}) => ({
      ok: true,
      demo: true,
      name:
        name ||
        String(path || "")
          .split("/")
          .pop(),
    }),
    platform_save: ({ name, path } = {}) => ({
      ok: true,
      demo: true,
      path: `Download/FOCA-rs/${
        name ||
        String(path || "")
          .split("/")
          .pop()
      }`,
    }),
    // Direct PDF export (Android renders the HTML report off-screen into <exports>/<stem>.pdf).
    platform_pdf: ({ project, report, name } = {}) => {
      const st = P(project);
      const r = st.reports.find(x => x.id === +report);
      if (!r) throw Object.assign(new Error("Отчёт не найден"), { code: "not_found" });
      const stem = String(name || r.name).replace(/\.[^.]+$/, "");
      return { ok: true, demo: true, path: `exports/${stem}.pdf`, name: `${stem}.pdf`, size: 184320 };
    },
    platform_biometric: () => ({ ok: true, available: true, demo: true }),
    // Demo of the Android share sheet: demo_share queues a synthetic shared file, platform_shared_files hands
    // the queue out once (like the native side).
    platform_shared_files: () => {
      const files = SHARED_QUEUE.splice(0);
      return { files, skipped: 0, truncated: false };
    },
    demo_share: ({ name } = {}) => {
      const n = name || SHARED_DEMO.name;
      SHARED_QUEUE.push({ path: "/demo/shared/" + n, name: n, size: 230 * 1024, mime: "application/pdf" });
      return { ok: true, queued: SHARED_QUEUE.length };
    },
    platform_secure: ({ on } = {}) => ({ ok: true, applied: false, on: !!on, demo: true }),
    platform_battery_status: () => {
      const b = (load().settings.ui || {}).battery || {};
      return {
        ignoring: !!b.excluded,
        supported: false,
        demo: true,
        oem: "xiaomi",
        label: "Xiaomi 14 · HyperOS 1.0 (Android 14)",
        notifications: true,
      };
    },
    platform_battery_settings: ({ what } = {}) => ({ opened: null, demo: true, what: what || "battery" }),
    platform_notifications: () => ({ enabled: true, demo: true }),
    // No system file picker in the demo; screens show their own demo lists.
    platform_pick_files: () => ({ ok: false, cancelled: true, files: [], demo: true }),
    platform_pick_image: () => ({ ok: false, cancelled: true, files: [], demo: true }),
    doc_file: ({ project, id }) => {
      const d = P(project).docs.find(x => x.id === +id);
      if (!d) throw apiErr("not_found", `Документ ${id} не найден`);
      return { path: `files/${project}/${d.name}`, name: d.name, size: (d.size || 0) * 1024, demo: true };
    },
    doc_import: () => ({ imported: 0, ids: [], demo: true }),
    // ---- 1.3: offline import, full-text search, user rules, document forensics (docs/API.md) ----
    // The demo has no file system: the demo folder picker returns copies of the story documents, and the
    // import builds a project from them (no network, like the core).
    import_offline: (a = {}) => importOffline(a),
    // Built-in reference case (docs/API.md → demo_case_import): the demo imports twelve of its own documents.
    demo_case_import: ({ name } = {}) => {
      const docs = ((load().projects.contoso || {}).docs || []).slice(0, 12).map(d => d.name);
      const r = importOffline({ name: name || demoCaseName(), domain: "example.test", paths: docs });
      if (r.project) {
        P(r.project).project.reference = true;
        save();
      }
      return { ...r, demo_case: true };
    },
    import_cancel: () => ({ ok: false }),
    platform_pick_folder: () => ({
      ok: true,
      cancelled: false,
      files: DEMO_PICK.map(n => ({ path: `files/picked/${n}`, name: n, size: 4096, mime: "" })),
      skipped: 1,
      truncated: false,
      bytes: DEMO_PICK.length * 4096,
      demo: true,
    }),
    platform_pick_clear: () => ({ ok: true, removed: 0, demo: true }),
    docs_search: ({ project, q, limit, offset, include_deleted } = {}) => {
      const st = P(project || load().settings.last_project);
      const query = String(q || "").trim();
      const terms = query
        .toLowerCase()
        .split(/\s+/)
        .map(t => t.replace(/^[-"]+|["*]+$/g, ""))
        .filter(t => t.length > 1)
        .slice(0, 16);
      const all = [];
      if (terms.length)
        st.docs.forEach(d => {
          if (d.deleted && !include_deleted) return;
          const name = String(d.name).toLowerCase();
          const inName = terms.every(t => name.includes(t));
          const tx = d.status === "analyzed" ? demoDocText(st, d) : { text: "", masked: [] };
          const inText = terms.every(t => tx.text.toLowerCase().includes(t));
          if (!inName && !inText) return;
          const snippet = (inText && demoSnippet(tx.text, terms)) || `{{h:${d.name}}}`;
          all.push({
            doc: d.id,
            name: d.name,
            url: d.url || "",
            snippet,
            in_name: inName,
            masked: /\{\{s:/.test(snippet) ? tx.masked.slice() : [],
            rank: (inName ? -4 : 0) - (inText ? 1 : 0) - d.id / 1e6,
            deleted: !!d.deleted,
          });
        });
      all.sort((x, y) => x.rank - y.rank);
      const from = Math.max(0, offset || 0),
        n = Math.max(1, Math.min(200, limit || 50));
      return { total: all.length, query, hits: all.slice(from, from + n) };
    },
    rules_get: () => ({
      presets: DEMO_RULE_PRESETS,
      config: load().demo_rules || { presets: ["ua-gov"], rules: [] },
    }),
    rules_set: (a = {}) => {
      const c = a.config || { presets: a.presets || [], rules: a.rules || [] };
      const errs = [];
      // Same message format as the core (foca-store rule_errors): "user:<id>: <message>".
      (c.rules || []).forEach(r => {
        const pre = `user:${r.id}: `;
        if (!String(r.pattern || "").trim()) errs.push(pre + "пустой шаблон");
        else if (String(r.pattern).length > 512) errs.push(pre + "шаблон длиннее 512 символов");
        else
          try {
            if (new RegExp(demoPattern(r.pattern), "u").test(""))
              errs.push(pre + "шаблон совпадает с пустой строкой");
          } catch (e) {
            errs.push(pre + `ошибка в шаблоне: ${e.message || e}`);
          }
      });
      if ((c.rules || []).length > 64) errs.push("не больше 64 правил");
      if (errs.length) throw apiErr("bad_args", errs.join("; "));
      const db = load();
      db.demo_rules = { presets: c.presets || [], rules: c.rules || [] };
      save();
      return { config: db.demo_rules, new_findings: 0 };
    },
    rules_test: ({ pattern, case_insensitive = true, text = "" } = {}) => {
      let re;
      try {
        re = new RegExp(demoPattern(pattern || "(?!)"), case_insensitive ? "giu" : "gu");
      } catch (e) {
        throw apiErr("bad_args", `ошибка в шаблоне: ${e.message || e}`);
      }
      if (re.test("")) throw apiErr("bad_args", "шаблон совпадает с пустой строкой");
      re.lastIndex = 0;
      const hits = [];
      for (const m of String(text).matchAll(re)) {
        if (!m[0] || hits.length >= 50) break;
        const v = (m.groups && m.groups.v) || m[0];
        const start = utf8Len(String(text).slice(0, m.index));
        hits.push({
          start,
          end: start + utf8Len(m[0]),
          value: v.length > 4 ? "••••" + v.slice(-2) : "••••",
        });
      }
      return { count: hits.length, hits };
    },
    doc_get: ({ project, id } = {}) => {
      const d = P(project || load().settings.last_project).docs.find(x => x.id === +id);
      if (!d) throw apiErr("not_found", `Документ ${id} не найден`);
      if (d.status !== "analyzed") return { doc: d, format: null, forensics: null };
      return { doc: d, format: d.ext, forensics: demoEnOut(clone(fxRec(demoByName(CONTOSO_FX, d.name)))) };
    },
    // ---- site file search (foca-fuzz): estimate and wordlists (docs/API.md) ----
    fuzz_estimate: ({ project, modules, rate, wordlists } = {}) => {
      const st = P(project || load().settings.last_project),
        fz = load().settings.fuzz || {};
      const mods = modules || fz.modules || [],
        r = Math.max(0.5, Math.min(20, rate || fz.rate || 5)),
        budget = fz.max_requests || 3000;
      const hosts = (st.scope.targets || [])
        .filter(
          t =>
            ["domain", "url"].includes(t.type) &&
            RULES().scope.checkTarget(st.scope, t, { hosts: st.hosts }).ok,
        )
        .map(t => (t.type === "url" ? t.v : `https://${t.v}/`))
        .slice(0, fz.max_hosts || 3);
      const per = {};
      mods.forEach(m => {
        per[m] = (FZ_PER[m] || 0) * hosts.length;
      });
      if ((wordlists || fz.wordlists || []).length) per.content = 900 * hosts.length;
      const cand = Object.values(per).reduce((a, b) => a + b, 0),
        cal = hosts.length * 3 * 6,
        total = cand + cal,
        requests = Math.min(total, budget);
      return {
        hosts,
        candidates: cand,
        calibration: cal,
        requests,
        seconds: Math.min((fz.max_time_min || 20) * 60, Math.ceil(requests / r)),
        capped_by_budget: total > budget,
        per_module: per,
        skipped_excluded: 0,
        rate: r,
        max_requests: budget,
        max_time_min: fz.max_time_min || 20,
        note: hosts.length
          ? "без учёта кандидатов, появляющихся по ходу (варианты найденного, листинги, .DS_Store)"
          : "нет веб-адресов в скоупе",
        note_msg: { code: hosts.length ? "fuzz.estimate_note" : "fuzz.no_urls", params: {} },
      };
    },
    wordlists_list: () => {
      const S = load(),
        w = (S.wordlists = S.wordlists || { downloaded: [], custom: [] });
      const items = WL_BUILTIN.map(([id, name, src, lines, size]) => ({
        id,
        kind: "builtin",
        name,
        source: "SecLists/" + src,
        lines,
        size,
        downloaded: true,
      }))
        .concat(
          WL_REMOTE.map(([id, name, src, lines, size]) => ({
            id,
            kind: "remote",
            name,
            source: "SecLists/" + src,
            lines,
            size,
            sha256: "закреплён в сборке",
            downloaded: w.downloaded.includes(id),
          })),
        )
        .concat(
          w.custom.map(c => ({
            id: c.id,
            kind: "custom",
            name: c.name,
            source: "свой",
            lines: c.lines,
            size: c.size,
            downloaded: true,
          })),
        );
      return {
        items,
        selected: clone((S.settings.fuzz || {}).wordlists || []),
        seclists_commit: "1a89b46c204032247592a1626e29f841cb0fe2a5",
        modules: FZ_MODULES.map(([id, name, desc]) => ({ id, name, desc })),
      };
    },
    wordlists_download: ({ id } = {}) => {
      const l = WL_REMOTE.find(x => x[0] === id);
      if (!l) throw apiErr("not_found", `нет словаря «${id}» для загрузки`);
      const w = (load().wordlists = load().wordlists || { downloaded: [], custom: [] });
      if (!w.downloaded.includes(id)) w.downloaded.push(id);
      save();
      return { ok: true, id, size: l[4], lines: l[3], demo: true };
    },
    wordlists_import: ({ path, name } = {}) => {
      if (!path) throw apiErr("bad_args", "нет пути");
      const w = (load().wordlists = load().wordlists || { downloaded: [], custom: [] });
      const nm = String(name || String(path).split("/").pop() || "custom.txt")
        .replace(/[^\p{L}\p{N}._-]+/gu, "_")
        .replace(/^\.+/, "")
        .replace(/(\.txt)?$/, ".txt");
      const rec = { id: "custom:" + nm, name: nm, lines: 120, size: 1480 };
      w.custom = w.custom.filter(c => c.id !== rec.id).concat(rec);
      save();
      return { ok: true, id: rec.id, name: nm, lines: rec.lines, dropped: 0, size: rec.size, demo: true };
    },
    wordlists_delete: ({ id } = {}) => {
      if (WL_BUILTIN.some(x => x[0] === id)) throw apiErr("bad_args", "встроенный словарь нельзя удалить");
      const S = load(),
        w = (S.wordlists = S.wordlists || { downloaded: [], custom: [] });
      const had = w.downloaded.includes(id) || w.custom.some(c => c.id === id);
      w.downloaded = w.downloaded.filter(x => x !== id);
      w.custom = w.custom.filter(c => c.id !== id);
      if (S.settings.fuzz)
        S.settings.fuzz.wordlists = (S.settings.fuzz.wordlists || []).filter(x => x !== id);
      save();
      return { ok: had };
    },
    demo_reset: () => {
      RUN = null;
      clearTimeout(tickT);
      try {
        store && store.removeItem(STORE_KEY);
      } catch (e) {}
      STATE = generate();
      return { ok: true };
    },
  };

  const SHA_K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
  ];
  function utf8Bytes(str) {
    const out = [];
    const s = String(str);
    for (let i = 0; i < s.length; i++) {
      let c = s.charCodeAt(i);
      if (c < 0x80) out.push(c);
      else if (c < 0x800) out.push(0xc0 | (c >> 6), 0x80 | (c & 63));
      else if (c >= 0xd800 && c <= 0xdbff && i + 1 < s.length) {
        const c2 = s.charCodeAt(++i);
        c = 0x10000 + ((c & 0x3ff) << 10) + (c2 & 0x3ff);
        out.push(0xf0 | (c >> 18), 0x80 | ((c >> 12) & 63), 0x80 | ((c >> 6) & 63), 0x80 | (c & 63));
      } else out.push(0xe0 | (c >> 12), 0x80 | ((c >> 6) & 63), 0x80 | (c & 63));
    }
    return out;
  }
  // Signature database status, same shape as the core (sigbundle.rs SigStatus). The built-in numbers
  // match crates/foca-analysis/signatures: kev.tsv.gz header (total 1790, kept 924), 54 KEV product
  // groups, 54 software + 19 OS signatures, 24 secret rules and the standards.toml mapping.
  const DEMO_SIG_FEED = "https://github.com/SinonApp/FOCA-rs/releases/download/signatures/signatures.bundle";
  const DEMO_SIG_BUILTIN = {
    version: "2026.11.20",
    released: "2026-11-20",
    total: 1790,
    used: 924,
    products: 54,
    software: 54,
    os: 19,
    secrets: 24,
    std_rules: 74,
    std_refs: 438,
  };
  const DEMO_SIG_FRAMEWORKS = [
    ["owasp", "OWASP Top 10:2025"],
    ["mitre", "MITRE ATT&CK v20"],
    ["cwe", "CWE (Top 25 2025)"],
    ["ndtzi36", "НД ТЗІ 3.6-006-24"],
    ["nist", "NIST SP 800-53 Rev. 5"],
    ["iso27001", "ISO/IEC 27001:2022"],
    ["wstg", "OWASP WSTG v4.2"],
    ["privacy", "GDPR"],
    ["privacy", "2297-VI"],
    ["kszi", "НД ТЗІ 2.5-004-99, 3.7-003-05", true],
  ];
  function demoSigStatus() {
    const db = load();
    const cur = db._sigBundle || null;
    const B = DEMO_SIG_BUILTIN;
    // Demo bundles only add CVEs that are not in the built-in snapshot.
    const newKev = cur ? new Set((cur.kev_additions || []).map(k => k && k.cve).filter(Boolean)).size : 0;
    const extraSecrets = cur ? (cur.secret_additions || []).length : 0;
    const released = new Date(B.released + "T00:00:00");
    const now = new Date();
    const today = new Date(now.getFullYear(), now.getMonth(), now.getDate());
    const age = Math.max(0, Math.round((today - released) / 86400000));
    return {
      schema: "foca-sig-bundle/v1",
      version: cur ? cur.version : B.version,
      updated_at: cur ? cur.released_at : B.released,
      source: cur ? "bundle" : "builtin",
      sha256: cur ? cur.sha256 : demoSha256("builtin-kev-2026.11.20"),
      pubkey_ed25519: "ad790ce1bc10393132f13c767f8e71149ff88605fe35342a76526c20d3daa246",
      signature_valid: true,
      can_rollback: Boolean(cur || db._sigPrev),
      counts: {
        cpe: B.software + B.os,
        cve: B.used + newKev,
        secrets: B.secrets + extraSecrets,
        standards: B.std_refs,
      },
      added_kev: cur ? (cur.kev_additions || []).length : 0,
      added_cpe: cur ? (cur.cpe_additions || []).length : 0,
      added_secrets: extraSecrets,
      kev: {
        catalog: B.version,
        released: B.released,
        total: B.total,
        used: B.used + newKev,
        products: B.products,
        age_days: age,
        stale: age > 30,
      },
      software: { software: B.software, os: B.os },
      std_map: {
        rules: B.std_rules,
        refs: B.std_refs,
        frameworks: DEMO_SIG_FRAMEWORKS.map(([id, label, legacy]) => ({ id, label, legacy: !!legacy })),
      },
      feed_url: DEMO_SIG_FEED,
      last_check: db._sigCheck ? clone(db._sigCheck) : null,
    };
  }
  function demoSha256(str) {
    const bytes = utf8Bytes(str);
    const l = bytes.length * 8;
    bytes.push(0x80);
    while (bytes.length % 64 !== 56) bytes.push(0);
    for (let i = 7; i >= 0; i--) bytes.push((i < 4 ? Math.floor(l / 2 ** (i * 8)) : 0) & 255);
    const h = [
      0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    ];
    const r = (v, n) => (v >>> n) | (v << (32 - n));
    for (let i = 0; i < bytes.length; i += 64) {
      const w = new Array(64);
      for (let t = 0; t < 16; t++) {
        w[t] =
          (bytes[i + t * 4] << 24) |
          (bytes[i + t * 4 + 1] << 16) |
          (bytes[i + t * 4 + 2] << 8) |
          bytes[i + t * 4 + 3];
      }
      for (let t = 16; t < 64; t++) {
        const s0 = r(w[t - 15], 7) ^ r(w[t - 15], 18) ^ (w[t - 15] >>> 3);
        const s1 = r(w[t - 2], 17) ^ r(w[t - 2], 19) ^ (w[t - 2] >>> 10);
        w[t] = (w[t - 16] + s0 + w[t - 7] + s1) | 0;
      }
      let [a, b, c, d, e, f, g, hh] = h;
      for (let t = 0; t < 64; t++) {
        const t1 = (hh + (r(e, 6) ^ r(e, 11) ^ r(e, 25)) + ((e & f) ^ (~e & g)) + SHA_K[t] + w[t]) | 0;
        const t2 = ((r(a, 2) ^ r(a, 13) ^ r(a, 22)) + ((a & b) ^ (a & c) ^ (b & c))) | 0;
        [hh, g, f, e, d, c, b, a] = [g, f, e, (d + t1) | 0, c, b, a, (t1 + t2) | 0];
      }
      [a, b, c, d, e, f, g, hh].forEach((x, idx) => (h[idx] = (h[idx] + x) | 0));
    }
    return h.map(x => (x >>> 0).toString(16).padStart(8, "0")).join("");
  }

  const backend = {
    version: GEN_VERSION,
    TODAY,
    PROFILES,
    STAGES,
    SOURCES,
    SOFTWARE,
    invoke(cmd, args = {}) {
      const fn = COMMANDS[cmd];
      if (!fn) return Promise.reject(apiErr("unknown_command", cmd));
      try {
        return Promise.resolve(fn(args));
      } catch (e) {
        return Promise.reject(e);
      }
    },
    // Synchronous call, only for the first snapshot load in the browser (screens read data when their scripts
    // load).
    invokeSync(cmd, args = {}) {
      return COMMANDS[cmd](args);
    },
    listen(fn) {
      listeners.add(fn);
      return () => listeners.delete(fn);
    },
    // For QA: simulated AI provider latency in ms (0 answers at once); returns the previous value.
    _aiDelay(ms) {
      const was = aiDelayMs;
      aiDelayMs = Math.max(0, Number(ms) || 0);
      return was;
    },
    // For qa/data-invariants.mjs.
    // For QA: instantly run n steps of the running scan (like the timer, without waiting).
    _ff(n = 1) {
      for (let k = 0; k < n && RUN; k++) {
        if (RUN.paused) break;
        if (!step()) break;
      }
      return { running: !!RUN, progress: RUN ? RUN.progress : 100 };
    },
    // For QA: "app restart": the running scan is lost exactly as when the process is unloaded (state is
    // re-read from storage).
    _restart() {
      clearTimeout(tickT);
      if (RUN) persistRun();
      RUN = null;
      const raw = JSON.stringify(STATE);
      STATE = JSON.parse(raw);
      if (STATE.run) recoverRun();
      return { ok: true };
    },
    _oos: oosOf,
    _infra: infraOf,
    _state: () => load(),
    _generate: generate,
    _scope: { check: scopeCheck },
    _risk: riskOf,
    _swEol: swEol,
  };
  root.FOCA_DEMO_BACKEND = backend;
})(typeof window !== "undefined" ? window : globalThis);
