// Data tab.
// Routes: /p/data, /p/data/:seg
// (docs|people|emails|hosts|certs|mailpol|saas|software|secrets|paths|printers|tech|site|js|cloud|code),
// /p/entity/:type/:id (person|host|pc|software|printer|path|email).
// The Documents segment and the document card live in docs.js (F.dataDocs, /p/doc/:id); infrastructure
// segments (certs, mailpol, saas) and the host certificate block: in infra.js (F.infra).
// Exports for other screens: F.demoData, F.dataTrail (breadcrumbs), F.dataEntityPath(type, id).
(function () {
  const F = window.FOCA,
    { ic, esc, ui } = F;
  const demo = window.DEMO;
  const enc = encodeURIComponent;

  F.addIcons &&
    F.addIcons(`
<symbol id="i-dt-cert" viewBox="0 0 16 16"><rect x="2.5" y="2.5" width="11" height="8"
  rx="1"/><path d="M5 5.5h6M5 7.5h3.5"/><circle cx="10.5" cy="11.5"
  r="1.8"/><path d="m9.6 13 -.6 1.8 1.5-.6 1.5.6-.6-1.8"/></symbol>
<symbol id="i-dt-leak"
  viewBox="0 0 16 16"><path d="M8 2.5c2.2 2.8 3.8 5 3.8 7a3.8 3.8 0 0 1-7.6 0c0-2 1.6-4.2 3.8-7z"/><path d="M6.5 10.2a1.6 1.6 0 0 0 1.5 1.5"/></symbol>
<symbol id="i-dt-crumb" viewBox="0 0 16 16"><path d="m6 4 4 4-4 4"/></symbol>`);

  // ================= utilities =================
  const plural = (n, one, few, many) => {
    const a = n % 10,
      b = n % 100;
    return `${n} ${a === 1 && b !== 11 ? one : a >= 2 && a <= 4 && (b < 12 || b > 14) ? few : many}`;
  };
  const ini = name =>
    name
      .split(/\s+/)
      .map(w => w[0])
      .join("")
      .slice(0, 2)
      .toUpperCase();
  const avatar = (p, cls = "") =>
    `<div class="avatar ${cls}" style="background:${p.color}" aria-hidden="true">${esc(ini(p.name))}</div>`;
  const fmtSize = kb =>
    kb < 1024
      ? `${kb}${esc(F.t("data.kb", " КБ"))}`
      : `${(kb / 1024).toFixed(1).replace(".", ",")}${esc(F.t("data.mb", " МБ"))}`;
  const SEVC = {
    crit: "var(--crit)",
    high: "var(--bad)",
    warn: "var(--warn)",
    low: "var(--accent)",
    info: "var(--text-3)",
    ok: "var(--ok)",
  };
  const SEVORD = { crit: 0, high: 1, warn: 2, low: 3, info: 4, ok: 5 };
  F.dataUtil = { plural, ini, avatar, fmtSize, SEVC };

  // ================= tab data, from the shared layer (F.db, F.sel selectors) =================
  const dmy = iso => (iso ? iso.split("-").reverse().join(".") : "-");
  let DOMAIN, people, emails, roleMail, patterns, hibp, secrets, SWX;
  const LD = () => F.sel.docsLive(); // Documents excluding deleted ones.
  const personDocs = login => F.sel.docsLive().filter(d => d.user.login === login);
  const SECT = () => ({
    conn: [F.t("data.connection_string", "Строка подключения"), "db"],
    pass: [F.t("data.password", "Пароль"), "lock"],
    api: [F.t("data.api_key_token", "API-ключ / токен"), "key"],
    host: [F.t("data.internal_host_ip", "Внутренний хост / IP"), "net"],
  });

  const pcsAll = () => F.db.pcs.map(p => p.name);
  let lastPid = null;
  const sync = () => {
    const pid = F.db.project && F.db.project.id;
    if (pid !== lastPid) {
      lastPid = pid;
      // `state` is declared below this first sync() call, so reach it through F.state.
      const st = F.state.data;
      if (st && st.hibpRes) st.hibpRes = {};
    }
    DOMAIN = (F.db.project && F.db.project.domain) || "";
    people = F.db.people;
    emails = F.db.emails.filter(e => !e.role);
    roleMail = F.db.emails.filter(e => e.role);
    patterns = F.db.patterns;
    // Breaches are shown only with a working HIBP key (one key status for the whole app).
    const k = ((F.db.settings || {}).keys || {}).hibp;
    hibp = k && k.status === "ok" ? F.db.leaks : {};
    // Secrets of deleted documents are neither shown nor counted.
    const gone = new Set(F.db.docs.filter(d => d.deleted).map(d => d.id));
    secrets = F.db.secrets.filter(s => !gone.has(s.doc));
    SWX = Object.fromEntries(
      F.db.software.map(s => [
        s.name,
        {
          eol: s.eol_date ? dmy(s.eol_date) : s.eol ? F.t("data.date_unknown", "дата неизвестна") : "-",
          cves: s.cves || [],
        },
      ]),
    );
    F.demoData = { people, emails, roleMail, patterns, hibp, secrets, SECT: SECT(), SWX, pcsAll, hostInfo };
  };
  const hostByName = n => demo.hosts.find(h => h.name.toLowerCase() === String(n).toLowerCase());
  const isInternal = h => !!h.internal || /^(SRV|NAS)/.test(h.name);
  // Host network details come from the DNS stage data (h.dns, h.asn, h.tls); nothing is inferred from the
  // host name.
  function hostInfo(host) {
    const ip = String(host.ip || "").split(" ")[0];
    const tech = !host.tech || host.tech === "-" ? [] : host.tech.split(/,\s*/);
    let tls = null;
    // The core sends { port, version, issuer, not_after (epoch s), days_left, issues }; the demo: an ISO date
    // with cn/san. Both go through F.infra.tlsSummary.
    const t = host.tls && F.infra ? F.infra.tlsSummary(host.tls, F.sel.scope.today) : null;
    if (t) {
      const left = t.left;
      tls = {
        cn: t.cn || host.name,
        iss: t.iss,
        till: `${dmy(t.iso)}${left >= 0 && left <= 30 ? ` ${esc(F.t("data.in", "· через"))} ${plural(left, F.t("data.day", "день"), F.t("data.days", "дня"), F.t("data.day_many", "дней"))}` : left < 0 ? F.t("data.expired", " · истёк") : ""}`,
        san: t.san || "-",
        warn: left <= 30,
      };
    }
    // Ports from our own scan / InternetDB cache (h.ports) are shown in the Ports block; Services shows the
    // rest (UDP, etc.).
    const pk = new Set((host.ports || []).map(p => `${p.port}/${p.proto || "tcp"}`));
    return {
      ip,
      asn: host.asn || "-",
      dns: host.dns || [],
      tech,
      svc: (host.services || []).filter(s => !pk.has(s[0])),
      tls,
    };
  }
  // Ports: open ports, banners and versions; the source is either "scan" (active ports module) or "InternetDB
  // cache".
  function portsBlock(host) {
    const ps = host.ports || [],
      sc = host.ports_scan;
    if (!ps.length && !sc) return "";
    const sum =
      sc && sc.unreliable
        ? `<div class="banner warn dt-ports-unrel">${ic("alert")}<div>${esc(F.t("data.port_scan_unreliable_device", "Скан портов недостоверен: сеть устройства (VPN, AdGuard, прокси) принимает соединения на любом порту. Открытые порты по скану не записаны. Отключите локальный VPN или добавьте FOCA-rs в исключения и повторите скан."))} <button class="sec-a"
          data-act="go:/help/ports-unreliable">${esc(F.t("common.details", "Подробнее"))}</button></div></div>`
        : sc && sc.no_probe
          ? `<div class="banner info dt-ports-np">${ic("server")}<div>${esc(F.t("oos.bulk.np_host", { r: sc.no_probe }, "Порты не сканировались: адрес {r}. Хост добавлен в скоуп только как имя."))}</div></div>`
          : sc
            ? `<div class="s dt-ports-sum">${ic("server")}${F.t("data.port_scan_spec_at_open_open", { spec: esc(sc.spec || ""), at: sc.at ? " · " + esc(String(sc.at).slice(0, 10).split("-").reverse().join(".")) : "", open: sc.open, closed: sc.closed }, "Скан портов {spec}{at}: открыто {open}, закрыто {closed}, фильтруется")} ${sc.filtered}${sc.ms ? ` ${F.t("data.sec_s", { sec: (sc.ms / 1000).toFixed(1).replace(".", ",") }, "· {sec} с")}` : ""}${sc.cancelled ? F.t("data.interrupted", " · прерван") : ""}</div>`
            : `<div class="s dt-ports-sum">${ic("info")}${esc(F.t("data.no_own_port_scan_only_shodan", "Своего скана портов не было. Только кэш Shodan InternetDB (профиль «Полный» проверяет порты сам)."))}</div>`;
    const row = port => {
      const ver = [port.product, port.version].filter(Boolean).join(" ");
      const pills = [
        port.source === "scan"
          ? `<span class="pill ok">${esc(F.t("data.scan", "скан"))}</span>`
          : `<span class="pill mute">${esc(F.t("data.internetdb_cache", "кэш InternetDB"))}</span>`,
        port.unconfirmed
          ? `<span class="pill warn">${esc(F.t("data.not_confirmed_scan", "не подтверждён сканом"))}</span>`
          : "",
        port.sensitive
          ? `<span class="pill bad">${ic("alert")}${esc(port.sensitive)} ${esc(F.t("data.from_internet", "из интернета"))}</span>`
          : "",
        port.source === "scan" && port.confirmed === false && !port.banner
          ? `<span class="pill mute">${esc(F.t("data.protocol_not_confirmed", "протокол не подтверждён"))}</span>`
          : "",
        port.outdated ? `<span class="pill warn">${esc(F.t("data.outdated", "устарело"))}</span>` : "",
        port.tls ? `<span class="pill info">${ic("lock")}TLS</span>` : "",
      ].join("");
      const sub = [
        ver && ver !== port.banner ? esc(ver) : "",
        port.banner ? `<span class="mono">${esc(port.banner)}</span>` : "",
        (port.cert_names || []).length ? `<span class="mono">${esc(port.cert_names.join(", "))}</span>` : "",
        port.outdated ? esc(port.outdated) : "",
      ]
        .filter(Boolean)
        .join(" · ");
      return `<div class="row dt-svc dt-port-row"><span class="dt-port mono">${port.port}/${esc(port.proto || "tcp")}</span><div class="body"><div class="t">${esc(port.service || "-")}</div>${sub ? `<div class="s dt-port-s">${sub}</div>` : ""}<div class="dt-port-p">${pills}</div></div></div>`;
    };
    return (
      ui.secH(F.t("data.ports", "Порты"), ps.length) +
      sum +
      (ps.length
        ? `<div class="list">${ps.map(row).join("")}</div>`
        : `<div class="s">${esc(F.t("data.no_open_ports_found", "Открытых портов не найдено."))}</div>`)
    );
  }
  // NetBIOS domain: from .rdp files (DOMAIN\\user), otherwise from the project's domain name.
  const netbios = () => {
    const r = F.db.docs.find(d => d.rdp && /\\/.test(d.rdp.username || ""));
    return r
      ? r.rdp.username.split("\\")[0]
      : String(DOMAIN || "")
          .split(".")[0]
          .split("-")[0]
          .toUpperCase();
  };
  // Host scope status: scope exclusion / out of scope / in scope.
  const scopePill = name => {
    const c = F.sel.scope.check(name);
    return c.excluded
      ? `<span class="pill warn">${ic("alert")}${esc(F.t("data.excluded_from_scope", "В исключениях скоупа"))}</span>`
      : !c.ok
        ? `<span class="pill mute">${ic("info")}${esc(F.t("data.out_scope", "Вне скоупа"))}</span>`
        : "";
  };

  // Infrastructure pills of a host (infra.js): roles, check priority, discovery source, CDN/cloud.
  const infraPills = h =>
    F.infra ? F.infra.roleChips(h) + F.infra.priorityPill(h) + F.infra.srcPill(h) + F.infra.cdnPill(h) : "";

  sync();
  F.on("db", sync);

  // ================= breadcrumbs (trail of visited cards) =================
  const state = (F.state.data = F.state.data || {
    seg: "docs",
    sort: {},
    trail: [],
    pending: false,
    replace: false,
    revealed: new Set(),
    hibpRes: {},
    mailF: "all",
  });
  F.dataTrail = {
    // Call from a card's render(): updates the trail.
    visit(path, label, icon) {
      // Following a relation forward always adds a new link (trail = screen stack); going back or tapping a
      // breadcrumb truncates to the last occurrence.
      const t = state.trail,
        i = t.map(x => x.path).lastIndexOf(path);
      if (state.replace && t.length) {
        t[t.length - 1] = { path, label, icon };
      } else if (state.pending && t.length) {
        if (t[t.length - 1].path !== path) t.push({ path, label, icon });
      } else if (i >= 0) {
        state.trail = t.slice(0, i + 1);
        state.trail[i].label = label;
      } else state.trail = [{ path, label, icon }];
      state.pending = false;
      state.replace = false;
    },
    html() {
      const t = state.trail;
      if (t.length < 2) return "";
      return `<nav class="dt-crumbs" aria-label="${esc(F.t("data.visited_cards", "Пройденные карточки"))}"><ol>${t
        .map((c, i) =>
          i === t.length - 1
            ? `<li><span class="dt-crumb cur"
              aria-current="page">${ic(c.icon)}<span>${esc(c.label)}</span></span></li>`
            : `<li><button class="dt-crumb" data-act="dt-crumb:${i}"
              aria-label="${F.t("data.back_label", { label: esc(c.label) }, "Вернуться: {label}")}">${ic(c.icon)}<span>${esc(c.label)}</span></button>${ic("dt-crumb", "dt-sep")}</li>`,
        )
        .join("")}</ol></nav>`;
    },
    mount(page) {
      const n = page.querySelector(".dt-crumbs");
      if (n) n.scrollLeft = n.scrollWidth;
    },
    replaceNext() {
      state.replace = true;
    },
  };
  F.actions["dt-nav"] = path => {
    state.pending = true;
    F.go(path);
  };
  F.actions["dt-crumb"] = i => {
    const k = state.trail.length - 1 - +i;
    for (let j = 0; j < k; j++) F.back();
  };
  F.dataEntityPath = (type, id) => `/p/entity/${type}/${enc(id)}`;
  const navRow = o => ui.row({ ...o, act: o.path ? `dt-nav:${o.path}` : o.act });

  // ================= segments =================
  const SEGS = () => [
    ["docs", F.t("app.documents", "Документы"), "doc"],
    ["people", F.t("app.people", "Люди"), "users"],
    ["emails", "E-mail", "mail"],
    ["hosts", F.t("app.hosts", "Хосты"), "server"],
    // Infrastructure modules (infra_get).
    ["certs", F.t("data.certificates", "Сертификаты"), "lock"],
    ["mailpol", F.t("data.mail_policies", "Почтовые политики"), "mail"],
    ["saas", F.t("data.saas_cdn", "SaaS и CDN"), "db"],
    ["software", F.t("data.software", "ПО"), "app"],
    ["os", F.t("data.os", "ОС"), "monitor"],
    ["secrets", F.t("app.secrets", "Секреты"), "key"],
    ["paths", F.t("data.paths", "Пути"), "path"],
    ["printers", F.t("data.printers", "Принтеры"), "printer"],
    // Site recon (snapshot.recon).
    ["tech", F.t("data.site_technologies", "Технологии сайта"), "app"],
    ["site", F.t("data.site", "Сайт"), "globe"],
    ["js", F.t("data.js_api", "JS и API"), "link"],
    ["cloud", F.t("data.cloud", "Облако"), "db"],
    ["code", F.t("data.code_repositories", "Код в репозиториях"), "hash"],
  ];
  const RC = () => (F.db.raw && F.db.raw.recon) || {};
  const rcN = k => (RC()[k] || []).length;
  const segCount = k =>
    ({
      docs: () => (F.dataDocs ? F.dataDocs.count() : demo.docs.length),
      people: () => people.length,
      emails: () => emails.length + roleMail.length,
      hosts: () => demo.hosts.length,
      software: () => demo.software.length,
      os: () => F.sel.os().length,
      secrets: () => secrets.length,
      paths: () => demo.folders.length,
      printers: () => demo.printers.length,
      tech: () => rcN("tech"),
      site: () =>
        (RC().sites || []).filter(x => x.favicon).length +
        rcN("analytics") +
        rcN("hidden_paths") +
        rcN("sitemap") +
        rcN("security"),
      js: () => rcN("endpoints") + rcN("secrets"),
      cloud: () => rcN("buckets"),
      code: () => ((RC().code || {}).hits || []).length,
      certs: () => (F.infra ? F.infra.counts.certs() : 0),
      mailpol: () => (F.infra ? F.infra.counts.mailpol() : 0),
      saas: () => (F.infra ? F.infra.counts.saas() : 0),
    })[k]();
  const SORTS = () => ({
    os: [
      ["docs", F.t("data.document_count", "По числу документов")],
      ["name", F.t("data.title", "По названию")],
    ],
    people: [
      ["docs", F.t("data.document_count", "По числу документов")],
      ["name", F.t("data.name", "По имени")],
      ["role", F.t("data.department", "По отделу")],
    ],
    hosts: [
      ["sev", F.t("data.severity", "По важности")],
      ["prio", F.t("data.check_priority", "Приоритет проверки")],
      ["name", F.t("data.name", "По имени")],
      ["type", F.t("data.external_then_internal", "Внешние, затем внутренние")],
    ],
    software: [
      ["cve", F.t("data.cve_count", "По числу CVE")],
      ["docs", F.t("data.document_count", "По числу документов")],
      ["name", F.t("data.title", "По названию")],
    ],
    paths: [
      ["docs", F.t("data.document_count", "По числу документов")],
      ["name", F.t("data.path_3", "По пути")],
    ],
    printers: [
      ["docs", F.t("data.document_count", "По числу документов")],
      ["name", F.t("data.title", "По названию")],
    ],
  });
  const sortOf = seg => state.sort[seg] || (SORTS()[seg] ? SORTS()[seg][0][0] : "");
  const sortBar = (seg, n, noun, extra = "") => {
    const so = SORTS()[seg];
    const cur = so.find(x => x[0] === sortOf(seg));
    return `<div class="dt-bar"><span class="dt-bar-n">${noun}</span>${extra}<button class="dt-sortb"
      data-act="dt-sort:${seg}"
      aria-label="${F.t("data.sort_cur", { cur: esc(cur[1]) }, "Сортировка: {cur}")}">${ic("sort")}<span>${esc(cur[1])}</span></button></div>`;
  };
  F.actions["dt-sort"] = seg => {
    if (seg === "docs") return F.dataDocs.sortSheet();
    const cur = sortOf(seg);
    const sorts = SORTS()[seg];
    F.sheet({
      title: F.t("data.sort", "Сортировка"),
      html: sorts
        .map(
          ([k, l]) =>
            `<div class="srow ${cur === k ? "on" : ""}" data-act="dt-sort-set:${seg}:${k}"
              role="button">${ic(cur === k ? "check" : "dot")}<span class="lbl">${l}</span></div>`,
        )
        .join(""),
    });
  };
  F.actions["dt-sort-set"] = a => {
    const [seg, k] = a.split(":");
    state.sort[seg] = k;
    F.closeSheet();
    F.render(true);
  };

  function segChips(cur) {
    return `<div class="dt-segbar"><div class="chips dt-seg" role="tablist"
      aria-label="${esc(F.t("data.data_sections", "Разделы данных"))}">${SEGS()
        .map(
          ([k, l]) =>
            `<button class="chip ${cur === k ? "on" : ""}" role="tab" aria-selected="${cur === k}"
          data-act="dt-seg:${k}">${l}${F.demo.mode === "normal" ? `<span class="c">${segCount(k)}</span>` : ""}</button>`,
        )
        .join("")}</div></div>`;
  }
  F.actions["dt-seg"] = k => {
    if (F.dataDocs && F.dataDocs.selecting()) F.dataDocs.exitSel(true);
    state.seg = k;
    const cur = F.current() || "";
    const path = `/p/data/${k}`;
    if (cur === path) return;
    if (/^\/p\/data(\/|$)/.test(cur)) F.go(path, { replace: true, anim: "none" });
    else F.go(path);
  };

  // ---------- People ----------
  function segPeople() {
    const so = sortOf("people");
    const list = people
      .map(p => ({ p, n: personDocs(p.login).length }))
      .sort((a, b) =>
        so === "name"
          ? a.p.name.localeCompare(b.p.name)
          : so === "role"
            ? a.p.role.localeCompare(b.p.role) || b.n - a.n
            : b.n - a.n || a.p.name.localeCompare(b.p.name),
      );
    return (
      sortBar(
        "people",
        0,
        plural(
          people.length,
          F.t("data.person", "человек"),
          F.t("data.people", "человека"),
          F.t("data.person_many", "человек"),
        ),
        `<button class="dt-sortb" data-act="dt-dict:people"
          aria-label="${esc(F.t("data.export_login_dictionary", "Экспорт словаря логинов"))}">${ic("export")}<span>${esc(F.t("data.login_dictionary", "Словарь логинов"))}</span></button><button class="dt-sortb" data-act="dt-wordlist:logins"
          aria-label="${esc(F.t("data.dictionary_generator", "Генератор словарей"))}">${ic("spark")}<span>${esc(F.t("data.generator", "Генератор"))}</span></button>`,
      ) +
      (org => (org ? org + ui.secH(F.t("data.all_people", "Все люди"), people.length) : ""))(
        F.ins ? F.ins.orgHtml() : "",
      ) +
      `<div class="list">${list.map(({ p, n }) => navRow({ lead: avatar(p), title: esc(p.name), sub: `${esc(p.role)} · <span class="mono">${esc(p.login)}</span>`, tail: n ? `<span class="dt-num">${n}</span><span>${esc(F.t("data.docs", "док."))}</span>` : `<span class="pill mute">${esc(F.t("data.text", "в тексте"))}</span>`, path: F.dataEntityPath("person", p.login) })).join("")}</div>`
    );
  }

  // ---------- E-mail ----------
  function segEmails() {
    const known = emails.filter(e => e.found).length;
    const pt = patterns[0];
    const filter = state.mailF;
    const list = [...emails, ...roleMail].filter(
      e => filter === "all" || (filter === "found" ? e.found : !e.found),
    );
    const pill = e =>
      e.found
        ? `<span class="pill ok">${ic("check")}${esc(F.t("data.found", "Найден"))}</span>`
        : `<span class="pill vio">${ic("graph")}${esc(F.t("data.generated", "Сгенерирован"))}</span>`;
    return `
      ${
        pt
          ? `<div class="card pad dt-pattern">
        <div class="dt-pt-k">${ic("mail")}${esc(F.t("data.address_pattern", "Шаблон адреса"))}</div>
        <div class="dt-pt-v mono">${esc(pt.p)}<wbr>@${esc(DOMAIN)}</div>
        <div class="dt-pt-s">${esc(F.t("data.matches", "Совпадает у"))} <b>${pt.n} ${esc(F.t("app.of", "из"))} ${known}</b> ${esc(F.t("data.known_personal_addresses", "известных личных адресов"))}</div>
        <div class="pbar" role="progressbar" aria-valuenow="${pt.conf}"
          aria-label="${F.t("data.confidence_conf", { conf: pt.conf }, "Уверенность {conf}%")}"><i class="ok" style="width:${pt.conf}%"></i></div>
        <div class="btnrow dt-pt-btns"><button class="btn sm tonal"
          data-act="dt-mail-copy">${ic("copy")}${esc(F.t("data.copy_list", "Скопировать список"))}</button><button class="btn sm"
          data-act="dt-mail-export">${ic("export")}${esc(F.t("data.export_dictionary", "Экспорт словаря"))}</button></div>
      </div>`
          : `<div class="card pad dt-pattern"><div class="dt-pt-k">${ic("mail")}${esc(F.t("data.address_pattern", "Шаблон адреса"))}</div><div class="dt-pt-s">${esc(F.t("data.not_determined_at_least_2_found", "Не определён: нужно хотя бы 2 найденных личных адреса."))}</div><div class="btnrow dt-pt-btns"><button class="btn sm"
            data-act="dt-mail-export">${ic("export")}${esc(F.t("data.export_dictionary", "Экспорт словаря"))}</button></div></div>`
      }
      ${patterns.length ? ui.secH(F.t("data.pattern_variants", "Варианты шаблона"), F.t("data.matches_3", "по совпадениям")) : ""}
      <div class="list">${patterns
        .map(
          p => `<div class="row dt-pv"><div class="body"><div class="t mono">${esc(p.p)}@</div><div class="s">${p.ex ? `${F.t("data.e_g_ex", { ex: esc(p.ex) }, "например, {ex} ·")} ` : ""}${p.n ? plural(p.n, F.t("data.match", "совпадение"), F.t("data.matches_2", "совпадения"), F.t("data.match_many", "совпадений")) : F.t("data.no_matches", "нет совпадений")}</div><div class="pbar"><i style="width:${p.conf}%"
        class="${p.conf > 50 ? "ok" : ""}"></i></div></div><div class="tail"><span class="dt-num">${p.conf}%</span></div></div>`,
        )
        .join("")}</div>
      ${ui.secH(F.t("data.addresses", "Адреса"), list.length)}
      <div class="chips" role="group" aria-label="${esc(F.t("data.address_filter", "Фильтр адресов"))}">${[
        ["all", F.t("common.all", "Все")],
        ["found", F.t("data.found_2", "Найденные")],
        ["gen", F.t("data.generated_2", "Сгенерированные")],
      ]
        .map(
          ([k, l]) =>
            `<button class="chip ${filter === k ? "on" : ""}" data-act="dt-mailf:${k}"
              aria-pressed="${filter === k}">${l}</button>`,
        )
        .join("")}</div>
      ${
        list.length
          ? `<div class="list">${list.map(e => navRow({ lead: ui.leadIcon(e.role ? "users" : "mail", e.found ? "var(--ok)" : "var(--info)"), title: `<span class="dt-addr">${esc(e.addr).replace("@", "<wbr>@")}</span>`, sub: `${pill(e)}<span class="dt-src">${e.role ? F.t("data.role_3", "Служебный · ") : ""}${esc(e.src)}</span>`, path: F.dataEntityPath("email", e.addr) })).join("")}</div>`
          : ui.empty({
              icon: "mail",
              title: F.t("data.no_addresses", "Нет адресов"),
              text: F.t("data.change_filter", "Смените фильтр."),
            })
      }`;
  }
  F.actions["dt-mailf"] = k => {
    state.mailF = k;
    F.render(true);
  };
  // Login dictionary: from the whole People screen or for a single person (name variants).
  F.actions["dt-dict"] = who => {
    if (!F.exportSheet) return F.snack(F.t("data.export_unavailable", "Экспорт недоступен"));
    if (who === "people")
      return F.exportSheet({
        kind: "users",
        fmt: "dict",
        title: F.t("data.login_dictionary", "Словарь логинов"),
        items: people.map(p => p.login),
        subject: F.t("data.logins_projects_people", "Логины людей проекта"),
        count: people.length,
      });
    const person = people.find(u => u.login === who);
    if (!person) return;
    F.exportSheet({
      kind: "users",
      fmt: "dict",
      title: `${esc(F.t("data.dictionary", "Словарь:"))} ${person.name}`,
      items: [person.login],
      subject: `${esc(F.t("data.logins_2", "Логины:"))} ${person.name}`,
      count: 1,
    });
  };
  F.actions["dt-mail-copy"] = () => {
    const t = emails.map(e => e.addr).join("\n");
    F.clipCopy(t);
    F.snack(
      `${esc(F.t("data.copied", "Скопировано:"))} ${plural(emails.length, F.t("data.address", "адрес"), F.t("data.addresses_2", "адреса"), F.t("data.address_many", "адресов"))}${F.clipAutoClear() ? F.t("data.clipboard_clears_30_s", " · буфер очистится через 30 с") : ""}`,
    );
  };
  F.actions["dt-mail-export"] = () => {
    if (F.exportSheet)
      return F.exportSheet({
        kind: "emails",
        title: F.t("data.export_e_mail_dictionary", "Экспорт словаря e-mail"),
        count: emails.length,
      });
    F.snack(
      `${F.t("data.dictionary_n_saved_downloads_txt", { n: plural(emails.length, F.t("data.address", "адрес"), F.t("data.addresses_2", "адреса"), F.t("data.address_many", "адресов")), demo: F.isDemo ? F.t("data.demo", ", демо") : "" }, "Словарь ({n}) сохранён в Загрузки (TXT{demo})")}`,
    );
  };
  let wlBusy = false;
  function openWordlistSheet(kind) {
    const k = kind === "context" ? "context" : "logins";
    if (wlBusy) return;
    wlBusy = true;
    F.api
      .wordlist_preview({ kind: k, limit: 100 })
      .then(r => {
        wlBusy = false;
        const pats = (r.patterns || [])
          .slice(0, 6)
          .map(p => `<span class="chip">${esc(p.id)} (${p.count})</span>`)
          .join("");
        F.sheet({
          title:
            k === "logins"
              ? F.t("data.login_patterns", "Шаблоны логинов")
              : F.t("data.context_dictionary", "Контекстный словарь"),
          html: `
            <div class="seg" role="tablist">
              <button class="${k === "logins" ? "on" : ""}" data-act="dt-wordlist:logins">${esc(F.t("data.logins", "Логины"))}</button>
              <button class="${k === "context" ? "on" : ""}" data-act="dt-wordlist:context">${esc(F.t("data.contextual_txt", "Контекстный (.txt)"))}</button>
            </div>
            <p class="fhint">${r.ad_domain ? `AD NetBIOS: <b class="mono">${esc(r.ad_domain)}</b> · ` : ""}${esc(F.t("data.total_entries", "Всего записей:"))} <b>${esc(r.total)}</b> ${F.t("data.showing_count_secrets_raw", { count: esc(r.count) }, "(показано {count}). Секреты и сырые ПДн исключены.")}</p>
            ${pats ? `<div class="chips wrap" style="margin-bottom:8px">${pats}</div>` : ""}
            <pre class="rp-pre">${esc((r.items || []).slice(0, 40).join("\n"))}</pre>`,
          footer: `<button class="btn" data-act="sheet-close">${esc(F.t("app.secrets_close", "Закрыть"))}</button><button class="btn primary" data-act="dt-wl-export:${k}">${ic("download")}${esc(F.t("data.export_txt", "Экспорт .txt"))}</button>`,
        });
      })
      .catch(e => {
        wlBusy = false;
        F.snack(F.t("data.dictionary_error", "Ошибка словаря: ") + (e.message || e));
      });
  }
  F.actions["dt-wordlist"] = k => openWordlistSheet(k);
  F.actions["dt-wl-export"] = k => {
    const kind = k === "context" ? "context" : "logins";
    F.api.export_build("all", "dict", { dict: kind }).then(
      r => {
        F.closeSheet();
        if (F.isTauri) F.api.platform_save({ path: r.path, name: r.name });
        else
          F.snack(
            `${F.t("data.dictionary_saved_name_count", { name: r.name, count: r.count }, "Словарь сохранён: {name} ({count})")}`,
          );
      },
      e => F.snack(F.t("projects.export_error", "Ошибка экспорта: ") + (e.message || e)),
    );
  };

  // ---------- Hosts ----------
  function segHosts() {
    const so = sortOf("hosts");
    const list = demo.hosts
      .slice()
      .sort((a, b) =>
        so === "name"
          ? a.name.localeCompare(b.name)
          : so === "prio"
            ? (b.priority || 0) - (a.priority || 0) ||
              SEVORD[a.sev] - SEVORD[b.sev] ||
              a.name.localeCompare(b.name)
            : so === "type"
              ? isInternal(a) - isInternal(b) || SEVORD[a.sev] - SEVORD[b.sev]
              : SEVORD[a.sev] - SEVORD[b.sev] || a.name.localeCompare(b.name),
      );
    const row = h =>
      navRow({
        lead: ui.leadIcon(isInternal(h) ? "monitor" : "server", SEVC[h.sev]),
        title: esc(h.name),
        sub: `<span class="mono">${esc(h.ip)}</span> · ${esc(h.role)}<div class="dt-tags">${ui.sev(h.sev)}${infraPills(h)}${h.cloud !== "-" && !h.cdn ? `<span class="pill mute">${ic("globe")}${esc(h.cloud)}</span>` : ""}${isInternal(h) ? `<span class="pill vio">${ic("lock")}${esc(F.t("data.internal", "Внутренний"))}</span>` : scopePill(h.name)}</div>`,
        path: F.dataEntityPath("host", h.name),
      });
    const nInt = demo.hosts.filter(isInternal).length;
    const bar =
      sortBar(
        "hosts",
        0,
        `${plural(demo.hosts.length, F.t("data.host", "хост"), F.t("data.hosts", "хоста"), F.t("data.host_many", "хостов"))} ${F.t("data.nint_internal", { nInt }, "· {nInt} внутр.")}`,
      ) + (F.infra ? F.infra.enumSummary() : "");
    if (so === "type")
      return (
        bar +
        ui.secH(F.t("data.external", "Внешние"), demo.hosts.length - nInt) +
        `<div class="list">${list
          .filter(h => !isInternal(h))
          .map(row)
          .join("")}</div>` +
        ui.secH(F.t("data.internal_from_metadata", "Внутренние (из метаданных)"), nInt) +
        `<div class="list">${list.filter(isInternal).map(row).join("")}</div>`
      );
    return bar + `<div class="list">${list.map(row).join("")}</div>`;
  }

  // ---------- Software ----------
  function segSoftware() {
    const so = sortOf("software");
    const list = demo.software
      .map((s, i) => ({ s, i }))
      .sort((a, b) =>
        so === "name"
          ? a.s.name.localeCompare(b.s.name)
          : so === "docs"
            ? b.s.n - a.s.n
            : b.s.cve - a.s.cve || b.s.n - a.s.n,
      );
    const eol = demo.software.filter(s => s.eol).length;
    return (
      sortBar(
        "software",
        0,
        `${plural(demo.software.length, F.t("data.program", "программа"), F.t("data.programs", "программы"), F.t("data.program_many", "программ"))} ${F.t("data.eol_unsupported", { eol }, "· {eol} без поддержки")}`,
      ) +
      `<div class="list">${list
        .map(({ s, i }) =>
          navRow({
            lead: ui.leadIcon("app", s.eol ? "var(--warn)" : ""),
            title: esc(s.name),
            sub: `${esc(F.t("data.version", "версия"))} <span class="mono">${esc(s.ver)}</span> · ${plural(s.n, F.t("projects.document", "документ"), F.t("projects.documents", "документа"), F.t("projects.document_many", "документов"))}<div class="dt-tags">${s.eol ? `<span class="pill warn">${ic("alert")}${esc(F.t("data.end_support", "Поддержка завершена"))}</span>` : `<span class="pill ok">${ic("check")}${esc(F.t("data.supported", "Поддерживается"))}</span>`}${
              s.cve
                ? `<span class="pill ${s.cve > 10 ? "crit" : "bad"}">${ic("bug")}${s.cve} CVE</span>`
                : `<span class="pill mute"
        title="${esc(F.t("data.no_cve_data_version_not_checked", "Данных CVE для этой версии нет, не проверялось"))}">${esc(F.t("data.cve_no_data", "CVE: нет данных"))}</span>`
            }</div>`,
            path: F.dataEntityPath("software", i),
          }),
        )
        .join("")}</div>`
    );
  }

  // ---------- OS, derived from document metadata ----------
  const OS_IC = {
    windows: "monitor",
    linux: "server",
    ios: "camera",
    android: "camera",
    embedded: "printer",
  };
  function segOs() {
    const so = sortOf("os");
    const l = F.sel
      .os()
      .slice()
      .sort((a, b) => (so === "name" ? a.name.localeCompare(b.name) : b.docs - a.docs));
    return (
      sortBar(
        "os",
        0,
        plural(
          l.length,
          F.t("data.system", "система"),
          F.t("data.systems", "системы"),
          F.t("data.system_many", "систем"),
        ),
      ) +
      `<div class="list">${l.map(o => navRow({ lead: ui.leadIcon(OS_IC[o.family] || "monitor"), title: esc(o.name), sub: `${plural(o.docs, F.t("projects.document", "документ"), F.t("projects.documents", "документа"), F.t("projects.document_many", "документов"))} · ${esc(o.src.join(", "))}`, path: F.dataEntityPath("os", o.id) })).join("")}</div>
      <p class="fhint">${ic("info")} ${esc(F.t("data.os_detected_from_application", "ОС определяется по полям Application/Producer, EXIF Software и служебным файлам (.lnk, .rdp)."))}</p>`
    );
  }

  // ---------- Secrets ----------
  function secretValue(s) {
    const open = state.revealed.has(s.id);
    return `<div class="dt-secv" data-secret-wrap>
      <span class="secret ${open ? "" : "masked"}"
        ${open ? "" : `aria-label="${esc(F.t("data.value_hidden", "Значение скрыто"))}"`}>${esc(s.value)}</span>
      <div class="dt-secb">
        <button class="ib" data-act="dt-sec-${open ? "hide" : "show"}:${s.id}"
          aria-label="${open ? F.t("data.hide_value", "Скрыть значение") : F.t("data.show_value", "Показать значение")}">${ic(open ? "eye-off" : "eye")}</button>
        <button class="ib" data-act="dt-sec-copy:${s.id}"
          aria-label="${esc(F.t("data.copy_value", "Копировать значение"))}">${ic("copy")}</button>
      </div></div>`;
  }
  F.dataSecretValue = secretValue;
  function segSecrets() {
    const order = secrets.slice().sort((a, b) => SEVORD[a.sev] - SEVORD[b.sev]);
    return `<div class="banner info dt-secban"
      role="note">${ic("lock")}<div><b>${esc(F.t("data.secrets_hidden_default", "Секреты скрыты по умолчанию"))}</b><br>${F.t("data.showing_copying_require", { bioMinutes: F.bioMinutes() > 0 ? `${F.t("data.one_fingerprint_unlocks_all", { bioMinutes: F.bioMinutes() }, "; один отпечаток открывает все секреты на {bioMinutes} мин")}` : "" }, "Показ и копирование: после подтверждения отпечатком{bioMinutes}. Буфер обмена очищается через 30 с.")}</div></div>
      <div class="dt-seclist">${order
        .map(s => {
          const d = demo.docs.find(x => x.id === s.doc);
          const [tl, ti] = SECT()[s.type];
          const hb = (state.hibpRes || {})[s.id];
          const hbHtml = hb
            ? hb.err
              ? `<span class="pill warn">${esc(hb.err)}</span>`
              : hb.pwned
                ? `<span class="pill crit">${F.tp("data.hibp_leaked_count_times_prefix", hb.count, { count: esc(hb.count), prefix: esc(hb.prefix) }, "HIBP: утёк ({count} раз · префикс {prefix})|HIBP: утёк ({count} раза · префикс {prefix})|HIBP: утёк ({count} раз · префикс {prefix})")}</span>`
                : `<span class="pill ok">${F.t("data.hibp_not_found_prefix_prefix", { prefix: esc(hb.prefix) }, "HIBP: не найден (префикс {prefix})")}</span>`
            : "";
          return `<div class="card dt-sec sev-${s.sev}">
          <div class="dt-sec-top"><span class="dt-sec-type">${ic(ti)}${tl}</span>${ui.sev(s.sev)}</div>
          ${secretValue(s)}
          <div class="btnrow" style="margin-top:8px">
            <button class="btn sm tonal" data-act="dt-sec-hibp:${s.id}">${ic("shield")}${esc(F.t("data.check_hibp_sha_1_prefix", "Проверить в HIBP (SHA-1 префикс)"))}</button>
            ${hbHtml}
          </div>
          ${
            d
              ? `<button class="dt-sec-src"
            data-act="go:/p/doc/${d.id}"><span class="ext ${esc(d.ext)}">${esc(d.ext)}</span><span class="dt-sec-srct"><span class="dt-fname">${F.dataDocs ? F.dataDocs.fname(d.name) : esc(d.name)}</span><small>${esc(s.where)}</small></span>${ic("chev", "chev")}</button>`
              : ""
          }
        </div>`;
        })
        .join("")}</div>`;
  }
  // Fingerprint confirmation uses the shared core mechanism (N-minute session, "Secrets revealed · Close"
  // indicator).
  const confirmFinger = (then, what = F.t("core.reveal_secret", "показать секрет"), el) =>
    F.confirmFinger(then, what, el);
  F.dataConfirmFinger = confirmFinger;
  F.onBioClose(() => state.revealed.clear());
  const secById = id => secrets.find(s => s.id === +id);
  F.actions["dt-sec-show"] = id =>
    confirmFinger(() => {
      state.revealed.add(+id);
      F.render(true);
    });
  F.actions["dt-sec-hide"] = id => {
    state.revealed.delete(+id);
    F.render(true);
  };
  F.actions["dt-sec-copy"] = id => {
    const go = () => {
      F.clipCopy(secById(id).value, { sensitive: true });
      F.snack(
        F.clipAutoClear()
          ? F.t("data.secret_copied_clipboard_clears", "Секрет скопирован · буфер очистится через 30 с")
          : F.t("data.secret_copied", "Секрет скопирован"),
        {
          ms: 5000,
        },
      );
    };
    state.revealed.has(+id) ? go() : confirmFinger(go, F.t("data.copy_secret", "скопировать секрет"));
  };
  F.actions["dt-sec-hibp"] = id => {
    const sid = +id;
    F.api.secret_hibp_check(sid).then(
      r => {
        state.hibpRes[sid] = r;
        F.render(true);
      },
      e => {
        state.hibpRes[sid] = { err: e.message || String(e) };
        F.render(true);
      },
    );
  };

  // ---------- Paths, printers ----------
  const pathKind = p =>
    p.startsWith("\\\\")
      ? F.t("data.network_share_unc", "Сетевая папка (UNC)")
      : p.startsWith("/")
        ? F.t("data.macos_path", "Путь macOS")
        : F.t("data.local_windows_path", "Локальный путь Windows");
  const pathUser = p => {
    const m = p.match(/[\\/]Users[\\/]([^\\/]+)/i);
    if (!m) return null;
    return people.find(
      u =>
        u.login.toLowerCase() === m[1].toLowerCase() ||
        u.login.replace(".", "") === m[1].toLowerCase() ||
        (m[1] === "Administrator" && u.login === "admin"),
    );
  };
  const pathHost = p => {
    const m = p.match(/^\\\\([^\\]+)/);
    return m ? m[1] : null;
  };
  const printerHost = n => pathHost(n);
  function segPaths() {
    const so = sortOf("paths");
    const list = demo.folders
      .map((p, i) => ({ p, i, n: LD().filter(d => d.folder === p).length }))
      .sort((a, b) => (so === "name" ? a.p.localeCompare(b.p) : b.n - a.n));
    return (
      sortBar(
        "paths",
        0,
        plural(
          demo.folders.length,
          F.t("data.path", "путь"),
          F.t("data.paths_2", "пути"),
          F.t("data.path_many", "путей"),
        ),
      ) +
      `<div class="list">${list
        .map(({ p, i, n }) => {
          const u = pathUser(p),
            h = pathHost(p);
          return navRow({
            lead: ui.leadIcon(h ? "net" : "path"),
            title: `<span class="mono dt-path">${esc(p)}</span>`,
            sub: `${pathKind(p)}${u ? ` · ${esc(u.login)}` : h ? ` · ${esc(h)}` : ""} · ${plural(n, F.t("projects.document", "документ"), F.t("projects.documents", "документа"), F.t("projects.document_many", "документов"))}`,
            path: F.dataEntityPath("path", i),
          });
        })
        .join("")}</div>`
    );
  }
  function segPrinters() {
    const so = sortOf("printers");
    const list = demo.printers
      .map((p, i) => ({ p, i }))
      .sort((a, b) => (so === "name" ? a.p.name.localeCompare(b.p.name) : b.p.n - a.p.n));
    return (
      sortBar(
        "printers",
        0,
        plural(
          demo.printers.length,
          F.t("data.printer", "принтер"),
          F.t("data.printers_2", "принтера"),
          F.t("data.printer_many", "принтеров"),
        ),
      ) +
      `<div class="list">${list
        .map(({ p, i }) => {
          const h = printerHost(p.name);
          return navRow({
            lead: ui.leadIcon("printer"),
            title: esc(p.name.replace(/^\\\\[^\\]+\\/, "")),
            sub: `${h ? `${esc(F.t("data.network_2", "Сетевой ·"))} ${esc(h)}` : /PDF/.test(p.name) ? F.t("data.virtual", "Виртуальный") : F.t("data.local", "Локальный")} · ${plural(p.n, F.t("projects.document", "документ"), F.t("projects.documents", "документа"), F.t("projects.document_many", "документов"))}`,
            path: F.dataEntityPath("printer", i),
          });
        })
        .join("")}</div>`
    );
  }

  // ---------- Site recon (snapshot.recon): plain lists, secrets masked only ----------
  const viaTxt = () => ({
    archive: F.t("data.from_archived_copy_wayback", "по архивной копии (Wayback)"),
    site: F.t("data.from_site", "с сайта"),
  });
  const rcCopy = [];
  const copyBtn = (txt, label) => {
    rcCopy.push(txt);
    return `<button class="ib" data-act="dt-rc-copy:${rcCopy.length - 1}"
      aria-label="${esc(label)}">${ic("copy")}</button>`;
  };
  F.actions["dt-rc-copy"] = i => {
    const t = rcCopy[+i];
    if (t != null && F.actions.copy) F.actions.copy(t);
  };
  const rcFoot = () => {
    const r = RC();
    return r.at
      ? `<p class="fhint">${ic("info")} ${F.t("data.reconnaissance_time_passive", { time: esc(String(r.at).slice(0, 16).replace("T", " ")), passive: r.level === "external" ? F.t("data.passive_no_requests_site", " · пассивно, к сайту запросов не было") : "" }, "Разведка: {time}{passive}.")}</p>`
      : "";
  };
  function segTech() {
    const list = (RC().tech || [])
      .slice()
      .sort(
        (a, b) =>
          !!b.outdated - !!a.outdated || a.category.localeCompare(b.category) || a.name.localeCompare(b.name),
      );
    const old = list.filter(t => t.outdated).length;
    return (
      `<div class="dt-bar"><span class="dt-bar-n">${plural(list.length, F.t("data.technology", "технология"), F.t("data.technologies", "технологии"), F.t("data.technology_many", "технологий"))} ${F.t("data.old_outdated", { old }, "· {old} устарело")}</span></div>
      <div class="list">${list
        .map(t =>
          ui.row({
            lead: ui.leadIcon("app", t.outdated ? "var(--warn)" : ""),
            title: esc(t.name) + (t.version ? ` <span class="mono">${esc(t.version)}</span>` : ""),
            sub: `${esc(t.category)} · ${esc(t.host)}<div class="dt-tags">${t.outdated ? `<span class="pill warn">${ic("alert")}${esc(F.t("data.outdated_2", "Устарело"))}</span><span class="muted">${esc(t.outdated)}</span>` : t.version ? `<span class="pill ok">${ic("check")}${esc(F.t("data.current_branch", "Актуальная ветка"))}</span>` : `<span class="pill mute">${esc(F.t("data.version_unknown", "Версия не определена"))}</span>`}</div>`,
          }),
        )
        .join("")}</div>` + rcFoot()
    );
  }
  function segSite() {
    const recon = RC();
    rcCopy.length = 0;
    let html = "";
    (recon.sites || [])
      .filter(x => x.favicon)
      .forEach(x => {
        const f = x.favicon;
        html +=
          ui.secH(`Favicon · ${x.host}`) +
          `<div class="list">${ui.row({ lead: ui.leadIcon("hash"), title: `<span class="mono">mmh3 ${esc(String(f.mmh3))}</span>`, sub: `${esc(viaTxt()[x.via] || "")} · <span class="mono dt-path">${esc(f.url)}</span>`, tail: copyBtn(String(f.mmh3), F.t("data.copy_hash", "Копировать хэш")) })}
        ${(f.queries || []).map(q => ui.row({ lead: ui.leadIcon("search"), title: { shodan: "Shodan", fofa: "FOFA", censys: "Censys" }[q.engine] || esc(q.engine), sub: `<span class="mono dt-path">${esc(q.q)}</span>`, tail: copyBtn(q.q, `${esc(F.t("data.copy_query", "Копировать запрос"))} ${q.engine}`) })).join("")}</div>`;
      });
    if ((recon.analytics || []).length)
      html +=
        ui.secH(F.t("data.analytics_id", "ID аналитики"), recon.analytics.length) +
        `<div class="list">${recon.analytics.map(a => ui.row({ lead: ui.leadIcon("hash"), title: `<span class="mono">${esc(a.id)}</span>`, sub: `${esc(a.kind)} ${F.t("data.host_id_reveals_other_sites", { host: esc(a.host) }, "· {host} · по ID ищутся другие сайты владельца")}`, tail: copyBtn(a.id, F.t("data.copy_id", "Копировать ID")) })).join("")}</div>`;
    if ((recon.hidden_paths || []).length)
      html +=
        ui.secH(F.t("data.hidden_paths_robots_txt", "Скрытые пути (robots.txt)"), recon.hidden_paths.length) +
        `<div class="list">${recon.hidden_paths.map(p => ui.row({ lead: ui.leadIcon("path"), title: `<span class="mono dt-path">${esc(p.path)}</span>`, sub: `${esc(p.reason)} · ${esc(p.host)}` })).join("")}</div>`;
    if ((recon.sitemap || []).length)
      html +=
        ui.secH(
          F.t("data.urls_from_sitemap", "URL из sitemap"),
          recon.sitemap_total > recon.sitemap.length
            ? `${recon.sitemap.length} ${esc(F.t("app.of", "из"))} ${recon.sitemap_total}`
            : recon.sitemap.length,
        ) +
        `<div class="list">${recon.sitemap
          .slice(0, 100)
          .map(u =>
            ui.row({
              lead: ui.leadIcon("link"),
              title: `<span class="mono dt-path">${esc(u.loc)}</span>`,
              sub: u.lastmod ? `${esc(F.t("data.modified", "изменён"))} ${esc(u.lastmod)}` : "",
            }),
          )
          .join("")}</div>`;
    (recon.security || []).forEach(x => {
      html +=
        ui.secH(`security.txt · ${x.host}`) +
        `<div class="list">${[...(x.contacts || []), ...(x.policy || []).map(p => F.t("data.policy", "Политика: ") + p)].map(c => ui.row({ lead: ui.leadIcon("mail"), title: esc(c), tail: copyBtn(c.replace(/^mailto:/, "").replace(/^Политика: /, ""), F.t("data.copy", "Копировать")) })).join("")}</div>${x.expires ? `<small class="muted">${esc(F.t("data.valid_until", "Действует до"))} ${esc(x.expires.slice(0, 10))}</small>` : ""}`;
    });
    if (!(recon.security || []).length && recon.sources && recon.sources.wellknown)
      html += `<p class="fhint">${ic("info")} ${esc(F.t("data.security_txt_not_found_archive", "security.txt в архиве не найден."))}</p>`;
    return html + rcFoot();
  }
  function segJs() {
    const recon = RC();
    let html = "";
    if ((recon.secrets || []).length)
      html +=
        `<div class="banner info dt-secban"
          role="note">${ic("lock")}<div><b>${esc(F.t("data.secrets_javascript_masked_only", "Секреты в JavaScript: только маска"))}</b><br>${esc(F.t("data.value_not_stored_project_verify", "Значение не сохраняется в проекте; проверьте и отзовите ключ у владельца сайта."))}</div></div>` +
        `<div class="list">${recon.secrets.map(x => ui.row({ lead: ui.leadIcon("key", SEVC[x.sev]), title: `${esc(x.title)} <span class="mono">${esc(x.mask)}</span>`, sub: `${esc(x.source)}${x.line ? ` ${esc(F.t("data.line", "· строка"))} ${x.line}` : ""}<div class="dt-tags">${ui.sev(x.sev)}</div>` })).join("")}</div>`;
    if ((recon.endpoints || []).length)
      html +=
        ui.secH(
          F.t("data.endpoints", "Эндпоинты"),
          recon.endpoints_total > recon.endpoints.length
            ? `${recon.endpoints.length} ${esc(F.t("app.of", "из"))} ${recon.endpoints_total}`
            : recon.endpoints.length,
        ) +
        `<div class="list">${recon.endpoints
          .slice(0, 150)
          .map(e =>
            ui.row({
              lead: ui.leadIcon("link"),
              title: `<span class="mono dt-path">${e.method ? esc(e.method) + " " : ""}${esc(e.url)}</span>`,
              sub: `${esc(e.kind)} · ${esc(e.source)}`,
            }),
          )
          .join("")}</div>`;
    return html + rcFoot();
  }
  const BST = () => ({
    public: ["bad", "alert", F.t("data.public_listing", "Открытый листинг")],
    closed: ["ok", "lock", F.t("data.closed", "Закрыт")],
    not_found: ["mute", "x", F.t("data.does_not_exist", "Не существует")],
    unknown: ["mute", "info", F.t("data.could_not_check", "Не удалось проверить")],
    unchecked: ["mute", "dot", F.t("data.not_checked", "Не проверялся")],
  });
  function segCloud() {
    const list = RC().buckets || [];
    return (
      `<div class="list">${list
        .map(b => {
          const [c, i, t] = BST()[b.status] || BST().unknown;
          return ui.row({
            lead: ui.leadIcon("db", b.status === "public" ? "var(--bad)" : ""),
            title: `<span class="mono">${esc(b.name)}</span>`,
            sub: `${esc(b.label)}${b.keys != null ? ` ${esc(F.t("data.objects", "· объектов:"))} ${b.keys}` : ""}<div class="dt-tags"><span class="pill ${c}">${ic(i)}${t}</span></div>`,
          });
        })
        .join("")}</div>` +
      (list.some(b => b.status === "unchecked")
        ? `<p class="fhint">${ic("info")} ${esc(F.t("data.storage_listing_checked_only", "Листинг хранилищ проверяется только в профиле «Полный» (активная фаза); здесь: ссылки из страниц и документов."))}</p>`
        : "") +
      rcFoot()
    );
  }
  function segCode() {
    const c = RC().code || { hits: [] };
    return `<div class="dt-bar"><span class="dt-bar-n">${F.t("data.grep_app_query_total", { query: esc(c.query || "") }, "grep.app · «{query}» · всего")} ${esc(String(c.total || 0))}</span></div><div class="list">${(c.hits || []).map(x => ui.row({ lead: ui.leadIcon("hash"), title: `${esc(x.repo)}`, sub: `<span class="mono dt-path">${esc(x.path)}</span>${(x.lines || []).map(l => `<div class="mono muted">${l.line}: ${esc(l.text)}</div>`).join("")}` })).join("")}</div>
      <p class="fhint">${ic("info")} ${esc(F.t("data.domain_mentions_public", "Упоминания домена в публичных репозиториях: конфиги, ключи, старые копии сайта. Проверьте вручную на GitHub/GitLab."))}</p>`;
  }
  // Empty recon states come with a reason (source status).
  function rcEmpty(seg) {
    const recon = RC(),
      src = recon.sources || {};
    const why = id => {
      const x = src[id];
      if (!x)
        return recon.at
          ? F.t(
              "data.source_was_not_queried_last_scan",
              "Источник не опрашивался в последнем скане (выключен или не выбран модуль «Разведка сайта»).",
            )
          : F.t(
              "data.no_reconnaissance_yet_run_scan",
              "Разведка ещё не проводилась. Запустите скан с модулем «Разведка сайта».",
            );
      if (x.status === "blocked")
        return F.t(
          "data.grep_app_enabled_bot_protection",
          "grep.app включил защиту от ботов (челлендж). Повторите позже или откройте grep.app в браузере.",
        );
      if (x.status === "timeout")
        return F.t("data.source_did_not_respond_time", "Источник не ответил за отведённое время.");
      if (x.status === "skipped")
        return F.t("data.source_was_skipped_last_scan", "Источник пропущен в последнем скане.");
      if (x.status === "error")
        return `${F.t("data.source_error_error", { error: x.error || F.t("data.no_response", "нет ответа") }, "Ошибка источника: {error}.")}`;
      return null;
    };
    const base = {
      tech: [
        "app",
        F.t("data.no_technologies_detected", "Технологии не определены"),
        why("recon") ||
          F.t(
            "data.no_signs_known_technologies_home",
            "На главной не нашлось признаков известных технологий.",
          ),
      ],
      site: [
        "globe",
        F.t("data.no_site_information", "Сведений о сайте нет"),
        why("recon") ||
          why("wellknown") ||
          F.t(
            "data.favicon_analytics_ids_robots_txt",
            "Favicon, ID аналитики, robots.txt, sitemap и security.txt не найдены.",
          ),
      ],
      js: [
        "link",
        F.t("data.no_endpoints_or_secrets", "Эндпоинтов и секретов нет"),
        why("recon") ||
          F.t(
            "data.no_api_addresses_or_keys_home",
            "В скриптах главной не нашлось адресов API и ключей, это хорошо.",
          ),
      ],
      cloud: [
        "db",
        F.t("data.no_cloud_storage_found", "Облачных хранилищ не найдено"),
        why("buckets") ||
          F.t(
            "data.pages_document_links_contain_no",
            "В страницах и ссылках документов нет адресов S3/GCS/Azure и др.",
          ),
      ],
      code: [
        "hash",
        F.t("data.no_mentions_code", "Упоминаний в коде нет"),
        why("grepapp") ||
          F.t("data.grep_app_did_not_find_domain", "grep.app не нашёл домен в публичных репозиториях."),
      ],
    }[seg];
    return { icon: base[0], title: base[1], text: base[2] };
  }

  const SEGR = {
    tech: segTech,
    site: segSite,
    js: segJs,
    cloud: segCloud,
    code: segCode,
    people: segPeople,
    emails: segEmails,
    hosts: segHosts,
    software: segSoftware,
    os: segOs,
    secrets: segSecrets,
    paths: segPaths,
    printers: segPrinters,
    certs: () => F.infra.seg.certs(),
    mailpol: () => F.infra.seg.mailpol(),
    saas: () => F.infra.seg.saas(),
  };
  const SEG_EMPTY_BASE = () => ({
    docs: {
      icon: "doc",
      title: F.t("data.no_documents_found", "Документы не найдены"),
      text: F.t(
        "data.run_scan_foca_will_find",
        "Запустите скан: FOCA найдёт опубликованные документы через поисковики и веб-краулер.",
      ),
    },
    people: {
      icon: "users",
      title: F.t("data.no_people_yet", "Людей пока нет"),
      text: F.t("data.they_appear_from_document", "Появятся из метаданных и текста документов."),
    },
    emails: {
      icon: "mail",
      title: F.t("data.no_addresses_yet", "Адресов пока нет"),
      text: F.t(
        "data.pattern_determined_once_at_least",
        "Шаблон определится, когда найдутся хотя бы 2 личных адреса.",
      ),
    },
    hosts: {
      icon: "server",
      title: F.t("data.no_hosts_yet", "Хостов пока нет"),
      text: F.t("data.they_appear_after_dns_stage_from", "Появятся после этапа DNS и из метаданных."),
    },
    software: {
      icon: "app",
      title: F.t("data.no_software_detected", "ПО не определено"),
      text: F.t("data.programs_extracted_from_document", "Программы извлекаются из метаданных документов."),
    },
    os: {
      icon: "monitor",
      title: F.t("data.no_os_detected", "ОС не определены"),
      text: F.t(
        "data.operating_systems_detected_from",
        "Операционные системы определяются по метаданным разобранных документов.",
      ),
    },
    secrets: {
      icon: "key",
      title: F.t("data.no_secrets_found", "Секретов не найдено"),
      text: F.t("data.thats_good_document_text", "Это хорошо: в тексте документов нет паролей и ключей."),
    },
    paths: {
      icon: "path",
      title: F.t("data.no_paths_yet", "Путей пока нет"),
      text: F.t("data.file_paths_extracted_from", "Пути к файлам извлекаются из метаданных."),
    },
    printers: {
      icon: "printer",
      title: F.t("data.no_printers_yet", "Принтеров пока нет"),
      text: F.t("data.they_appear_from_metadata", "Появятся из метаданных напечатанных документов."),
    },
    certs: {
      icon: "lock",
      title: F.t("data.no_certificates", "Сертификатов нет"),
      text: F.t(
        "data.certificates_checked_standard",
        "Сертификаты проверяются в профилях «Стандартный» и «Полный» на открытых TLS-портах хостов скоупа.",
      ),
    },
    mailpol: {
      icon: "mail",
      title: F.t("data.no_mail_policies", "Почтовых политик нет"),
      text: F.t(
        "data.mta_sts_tls_rpt_bimi_caa_dnssec",
        "MTA-STS, TLS-RPT, BIMI, CAA и DNSSEC проверяются по DNS на этапе «Сеть и DNS».",
      ),
    },
    saas: {
      icon: "db",
      title: F.t("data.no_services_detected", "Сервисы не определены"),
      text: F.t(
        "data.saas_microsoft_365_tenant_cdn",
        "SaaS, арендатор Microsoft 365 и CDN определяются по DNS-записям на этапе «Сеть и DNS».",
      ),
    },
  });
  const SEG_EMPTY = {};
  Object.keys(SEG_EMPTY_BASE()).forEach(k =>
    Object.defineProperty(SEG_EMPTY, k, { get: () => SEG_EMPTY_BASE()[k], enumerable: true }),
  );
  ["tech", "site", "js", "cloud", "code"].forEach(k =>
    Object.defineProperty(SEG_EMPTY, k, { get: () => rcEmpty(k), enumerable: true }),
  );

  const segRoute = {
    title: () => F.t("nav.data", "Данные"),
    tab: "data",
    search: () => F.t("data.search_data", "Поиск по данным"),
    // During a scan api.js re-reads the snapshot on progress (db kind "scan"), so lists and counters grow
    // live.
    live: (kind, ev) => kind === "db" && ev.kind === "scan" && !!(F.scan && F.scan.running),
    actions: p => {
      const seg = p.seg || state.seg;
      if (seg === "docs" && F.dataDocs) return F.dataDocs.actions();
      return F.defaultActions;
    },
    render: params => {
      const renderSegment = seg => {
        if (seg !== "docs") return SEGR[seg]();
        return F.dataDocs ? F.dataDocs.render() : "";
      };
      const seg = SEGS().some(s => s[0] === params.seg) ? params.seg : state.seg;
      state.seg = seg;
      // An empty segment (new project, no data) shows a proper empty state, not an empty list.
      const body = F.withStates(
        () =>
          !segCount(seg)
            ? ui.empty(
                F.sel.scans().length
                  ? SEG_EMPTY[seg]
                  : {
                      ...SEG_EMPTY[seg],
                      text: F.t(
                        "data.no_scans_yet_data_appears_after",
                        "Сканов ещё не было. Данные появятся после первого скана.",
                      ),
                      action: `<button class="btn primary"
                        data-act="go:/new">${ic("play")}${esc(F.t("overview.new_scan", "Новый скан"))}</button>`,
                    },
              )
            : renderSegment(seg),
        { loading: seg === "secrets" ? "cards" : "list", empty: SEG_EMPTY[seg] },
      );
      const sel = seg === "docs" && F.dataDocs && F.dataDocs.selecting();
      return (sel ? "" : segChips(seg)) + `<div class="dt-segbody">${body}</div>`;
    },
    mount: (page, p) => {
      const seg = state.seg;
      const c = page.querySelector(".dt-seg .chip.on");
      const bar = page.querySelector(".dt-seg");
      if (c && bar) bar.scrollLeft = Math.max(0, c.offsetLeft - (bar.clientWidth - c.offsetWidth) / 2);
      if (seg === "docs" && F.dataDocs) F.dataDocs.mount(page);
      else document.body.classList.remove("dt-selecting");
    },
    unmount: () => {
      if (F.dataDocs) F.dataDocs.unmount();
    },
  };
  F.route("/p/data", segRoute);
  F.route("/p/data/:seg", segRoute);

  // ================= GENERIC ENTITY CARD =================
  const TYPES = () => ({
    person: [F.t("data.person_2", "Человек"), "user"],
    host: [F.t("data.host_2", "Хост"), "server"],
    pc: [F.t("data.computer", "Компьютер"), "monitor"],
    software: [F.t("data.software", "ПО"), "app"],
    printer: [F.t("data.printer_2", "Принтер"), "printer"],
    path: [F.t("data.path_2", "Путь"), "path"],
    email: ["E-mail", "mail"],
    doc: [F.t("app.document", "Документ"), "doc"],
    os: [F.t("data.os", "ОС"), "monitor"],
  });
  const kvr = (k, v, copy) =>
    `<div class="kvr"><div class="k">${k}</div><div class="v">${v}</div>${
      copy
        ? `<div class="kva"><button class="ib"
      data-act="copy:${esc(copy)}"
      aria-label="${F.t("data.copy_k", { k: esc(k) }, "Копировать: {k}")}">${ic("copy")}</button></div>`
        : ""
    }</div>`;
  const kvLink = (k, v, path) =>
    `<div class="kvr tap" data-act="dt-nav:${esc(path)}"
      role="link"><div class="k">${k}</div><div class="v dt-link">${v}</div>${ic("chev", "chev")}</div>`;
  const docRow = d =>
    navRow({
      lead: `<span class="ext ${esc(d.ext)}">${esc(d.ext)}</span>`,
      title: F.dataDocs ? F.dataDocs.fname(d.name) : esc(d.name),
      sub: `${esc(d.user.login)} · ${esc(d.created.slice(0, 10))} · ${fmtSize(d.size)}`,
      path: `/p/doc/${d.id}`,
    });
  const docsBlock = (docs, title = F.t("app.documents", "Документы"), filt) => {
    if (!docs.length) return "";
    const more =
      docs.length > 5 && filt
        ? `<button class="sec-a"
          data-act="dt-docs-filter:${esc(JSON.stringify(filt))}">${esc(F.t("common.all", "Все"))} ${docs.length}</button>`
        : "";
    return (
      ui.secH(title, docs.length, more) + `<div class="list">${docs.slice(0, 5).map(docRow).join("")}</div>`
    );
  };
  F.actions["dt-docs-filter"] = j => {
    const f = JSON.parse(j);
    if (F.dataDocs) F.dataDocs.setFilter(f);
    state.seg = "docs";
    F.go("/p/data/docs");
  };
  const findRows = list =>
    list.length
      ? `<div class="list">${list.map(f => ui.row({ lead: ui.leadIcon(f.sev === "crit" || f.sev === "high" ? "alert" : "info", SEVC[f.sev]), title: esc(f.title), sub: `${ui.sev(f.sev)}`, act: `go:/p/finding/${f.id}` })).join("")}</div>`
      : "";
  const personRow = p =>
    navRow({
      lead: avatar(p),
      title: esc(p.name),
      sub: `${esc(p.role)} · <span class="mono">${esc(p.login)}</span>`,
      path: F.dataEntityPath("person", p.login),
    });
  const relGroup = (title, icon, items) =>
    items.length
      ? `<div class="dt-relg ${items.length > 4 ? "cut" : ""}"><div class="dt-relh">${ic(icon)}${title}<span class="muted">${items.length}</span></div><div class="list">${items.join("")}${
          items.length > 4
            ? `<button class="dt-relmore"
        data-act="dt-relmore"
        aria-expanded="false">${ic("chev-down")}<span>${esc(F.t("data.show_more", "Показать ещё"))} ${items.length - 4}</span></button>`
            : ""
        }</div></div>`
      : "";
  F.actions["dt-relmore"] = (_, el) => {
    const g = el.closest(".dt-relg");
    const open = g.classList.toggle("open");
    el.setAttribute("aria-expanded", open);
    el.querySelector("span").textContent = open
      ? F.t("data.collapse", "Свернуть")
      : `${esc(F.t("data.show_more", "Показать ещё"))} ${g.querySelectorAll(".row").length - 4}`;
    el.querySelector("use").setAttribute("href", open ? "#i-chev-up" : "#i-chev-down");
  };
  const uniq = a => [...new Set(a)];
  const swIdx = s => demo.software.indexOf(s);
  const relFrom = docs => {
    const sws = uniq(docs.map(d => d.sw));
    const hosts = uniq(docs.map(d => d.host));
    const prs = uniq(docs.map(d => d.printer).filter(x => x !== "-"));
    const fol = uniq(docs.map(d => d.folder).filter(x => x !== "-"));
    return {
      sw: sws.map(s =>
        navRow({
          lead: ui.leadIcon("app", s.eol ? "var(--warn)" : ""),
          title: esc(s.name),
          sub: `${docs.filter(d => d.sw === s).length} ${esc(F.t("data.docs", "док."))}${s.eol ? F.t("data.unsupported", " · без поддержки") : ""}`,
          path: F.dataEntityPath("software", swIdx(s)),
        }),
      ),
      hosts: hosts.map(h =>
        navRow({
          lead: ui.leadIcon("server"),
          title: esc(h),
          sub: `${docs.filter(d => d.host === h).length} ${esc(F.t("data.docs", "док."))}`,
          path: F.dataEntityPath("host", h),
        }),
      ),
      printers: prs.map(n =>
        navRow({
          lead: ui.leadIcon("printer"),
          title: esc(n.replace(/^\\\\[^\\]+\\/, "")),
          sub: `${docs.filter(d => d.printer === n).length} ${esc(F.t("data.docs", "док."))}`,
          path: F.dataEntityPath(
            "printer",
            demo.printers.findIndex(p => p.name === n),
          ),
        }),
      ),
      paths: fol.map(p =>
        navRow({
          lead: ui.leadIcon("path"),
          title: `<span class="mono dt-path">${esc(p)}</span>`,
          sub: `${docs.filter(d => d.folder === p).length} ${esc(F.t("data.docs", "док."))}`,
          path: F.dataEntityPath("path", demo.folders.indexOf(p)),
        }),
      ),
    };
  };
  const pcRow = pc =>
    navRow({
      lead: ui.leadIcon(/^SRV|MAIL/.test(pc) ? "server" : "monitor"),
      title: esc(pc),
      sub: /^SRV|MAIL/.test(pc)
        ? F.t("data.server_internal", "Сервер (внутренний)")
        : F.t("data.workstation", "Рабочая станция"),
      path: F.dataEntityPath("pc", pc),
    });

  function head({ lead, name, type, pills = "", facts = [] }) {
    return `<div class="card pad dt-ehead">
      <div class="dt-eh-top">${lead}<div class="dt-eh-t"><span class="dt-eh-type">${esc(TYPES()[type][0])}</span><h1 class="dt-eh-name">${name}</h1>${pills ? `<div class="dt-tags">${pills}</div>` : ""}</div></div>
      ${facts.length ? `<div class="dt-facts">${facts.map(([k, v]) => `<div class="dt-fact"><span class="k">${k}</span><span class="v">${v}</span></div>`).join("")}</div>` : ""}
    </div>`;
  }
  const searchBtns = (q, filt) => `<div class="btnrow dt-findby">
      <button class="btn tonal" data-act="dt-search:${esc(q)}">${ic("search")}${esc(F.t("data.search", "Искать по этому"))}</button>
      ${
        filt
          ? `<button class="btn"
        data-act="dt-docs-filter:${esc(JSON.stringify(filt))}">${ic("filter")}${esc(F.t("app.documents", "Документы"))}</button>`
          : ""
      }
      ${(() => {
        const cp = F.cur && F.cur.p;
        if (
          !cp ||
          !["person", "host", "pc", "software"].includes(cp.type) ||
          !F.routes.some(r => r.pattern === "/p/graph/:type/:id")
        )
          return "";
        // "Relation graph" button only if the node is in the graph (F.sel.graph) and has neighbours.
        let sw = null;
        if (cp.type === "software")
          sw = /^\d+$/.test(cp.id) ? demo.software[+cp.id] : F.sel.entity("software", cp.id);
        // A PC and a host with the same name share one graph node.
        const twinType = { pc: "host", host: "pc" }[cp.type];
        const graph =
          cp.type === "software"
            ? sw && F.sel.graph("software", sw.id)
            : F.sel.graph(cp.type, cp.id) || (twinType ? F.sel.graph(twinType, cp.id) : null);
        if (!graph || !graph.neighbors.length) return "";
        const gid = cp.type === "software" ? demo.software.indexOf(sw) : cp.id;
        return `<button class="btn"
          data-act="go:/p/graph/${graph.node.type === "pc" || graph.node.type === "host" ? (F.sel.entity("host", cp.id) ? "host" : "pc") : cp.type}/${encodeURIComponent(gid)}">${ic("graph")}${esc(F.t("data.relationship_graph", "Граф связей"))}</button>`;
      })()}</div>`;
  F.actions["dt-search"] = q => {
    F.state.searchQ = q;
    F.go("/p/search");
    const inp = F.page() && F.page().querySelector("#gq");
    if (inp) {
      inp.value = q;
      inp.dispatchEvent(new Event("input"));
    }
  };

  function hourChart(docs) {
    const hours = Array(24).fill(0);
    docs.forEach(d => {
      const m = d.created.match(/ (\d+):/);
      if (m) hours[+m[1]]++;
    });
    const max = Math.max(...hours);
    if (!max)
      return `<p class="lead">${esc(F.t("data.no_data_document_creation_times", "Нет данных о времени создания документов."))}</p>`;
    const peak = hours.indexOf(max);
    const late = hours.slice(19).reduce((a, b) => a + b, 0) + hours.slice(0, 8).reduce((a, b) => a + b, 0);
    return `<div class="card pad dt-hours"><div class="dt-hbars" role="img"
      aria-label="${F.t("data.activity_hour_peak_at_peak_00", { peak, late }, "Активность по часам: пик в {peak}:00, вне рабочего времени {late} док.")}">${hours
        .map(
          (v, i) => `<i style="height:${Math.max(4, (v / max) * 100)}%"
      class="${i < 8 || i >= 19 ? "off" : ""} ${v === max ? "pk" : ""}"></i>`,
        )
        .join("")}</div>
      <div class="dt-haxis"
        aria-hidden="true"><span>0</span><span>6</span><span>12</span><span>18</span><span>24</span></div>
      <div class="dt-hleg"
        aria-hidden="true"><span><i></i>8:00-19:00</span><span><i class="off"></i>${esc(F.t("data.outside_working_hours", "Вне рабочего времени"))}</span></div>
      <p class="dt-hnote">${F.t("data.peak_peak_00_next_00_late_based", { peak, next: peak + 1, late: late ? ` ${F.t("data.late_outside_working_hours", { late: plural(late, F.t("projects.document", "документ"), F.t("projects.documents", "документа"), F.t("projects.document_many", "документов")) }, "· {late} вне рабочего времени")}` : "" }, "Пик: {peak}:00-{next}:00{late}. По времени создания документов.")}</p></div>`;
  }

  // ---------- per-type renderers ----------
  function rPerson(id) {
    const person = people.find(u => u.login === id);
    if (!person) return null;
    const docs = personDocs(person.login);
    const parts = person.name.split(" ");
    const variants = uniq([
      person.name,
      parts.length > 1 ? `${parts[1]} ${parts[0][0]}.` : person.name,
      person.login,
      person.login.replace(/(^|\.)([a-z])/g, (m, a, b) => a + b.toUpperCase()),
      `${netbios()}\\${person.login}`,
    ]);
    const myMails = [...emails, ...roleMail].filter(e => e.login === person.login);
    const leaks = hibp[person.login] || [];
    const rel = relFrom(docs);
    const fnd = F.sel.related("person", person.login).findings; // Via rel.people and via the person's documents.
    const colleagues = people.filter(u => u.role === person.role && u.login !== person.login);
    return {
      label: person.name,
      icon: "user",
      html:
        head({
          lead: avatar(person, "dt-ava-l"),
          name: esc(person.name),
          type: "person",
          pills: `<span class="pill mute">${esc(person.role)}</span>${leaks.length ? `<span class="pill crit">${ic("dt-leak")}${esc(F.t("data.leaks_2", "В утечках:"))} ${leaks.length}</span>` : ""}`,
          facts: [
            [F.t("data.login", "Логин"), `<span class="mono">${esc(person.login)}</span>`],
            [F.t("data.pc", "ПК"), esc(person.pc)],
            [F.t("data.documents_count", "Документов"), docs.length || "-"],
            [F.t("data.source", "Источник"), esc(person.src)],
          ],
        }) +
        searchBtns(person.login, docs.length ? { author: [person.login] } : null) +
        ui.secH(
          F.t("data.name_variants", "Варианты имени"),
          "",
          `<button class="sec-a" data-act="dt-dict:${esc(person.login)}">${esc(F.t("data.login_dictionary", "Словарь логинов"))}</button>`,
        ) +
        `<div class="chips wrap dt-variants">${variants
          .map(
            v => `<button class="chip"
          data-act="copy:${esc(v)}"
          aria-label="${F.t("data.copy_v", { v: esc(v) }, "Копировать: {v}")}">${esc(v)}${ic("copy")}</button>`,
          )
          .join("")}</div>` +
        (myMails.length
          ? ui.secH("E-mail") +
            `<div class="list">${myMails.map(e => navRow({ lead: ui.leadIcon("mail", e.found ? "var(--ok)" : "var(--info)"), title: esc(e.addr), sub: e.found ? `<span class="pill ok">${ic("check")}${esc(F.t("data.found", "Найден"))}</span> ${esc(e.src)}` : `<span class="pill vio">${ic("graph")}${esc(F.t("data.generated", "Сгенерирован"))}</span> ${esc(F.t("data.from_pattern", "по шаблону"))}`, path: F.dataEntityPath("email", e.addr) })).join("")}</div>`
          : "") +
        (person.pc !== "-"
          ? ui.secH(F.t("data.computer", "Компьютер")) + `<div class="list">${pcRow(person.pc)}</div>`
          : "") +
        docsBlock(docs, F.t("app.documents", "Документы"), { author: [person.login] }) +
        (docs.length ? ui.secH(F.t("data.activity_hours", "Часы активности")) + hourChart(docs) : "") +
        ui.secH(F.t("data.leaks", "Утечки"), "HIBP") +
        leakBlock(leaks, F.t("data.address_not_found_known_leaks", "Адрес не найден в известных утечках")) +
        (fnd.length ? ui.secH(F.t("nav.findings", "Находки"), fnd.length) + findRows(fnd) : "") +
        relatedBlock({
          [F.t("data.software", "ПО")]: ["app", rel.sw],
          [F.t("data.rel_hosts", "Хосты")]: ["server", rel.hosts],
          [F.t("data.printers", "Принтеры")]: ["printer", rel.printers],
          [F.t("data.paths", "Пути")]: ["path", rel.paths],
          [F.t("data.department_colleagues", "Коллеги из отдела")]: ["users", colleagues.map(personRow)],
        }),
    };
  }
  // Breaches only with a working HIBP key; otherwise say plainly that a key is needed.
  const hibpOk = () => {
    const k = ((F.db.settings || {}).keys || {}).hibp;
    return !!(k && k.status === "ok");
  };
  const leakBlock = (leaks, okText) =>
    !hibpOk()
      ? `<div class="card pad dt-ok dt-nokey">${ic("key")}<span>${esc(F.t("data.leak_check_unavailable_hibp_key", "Проверка утечек недоступна: нужен ключ HIBP."))} <button class="btn text sm"
        data-act="dt-hibp-key">${esc(F.t("data.add_key", "Указать ключ"))}</button></span></div>`
      : leaks.length
        ? `<div class="list">${leaks.map(l => ui.row({ lead: ui.leadIcon("dt-leak", "var(--crit)"), title: esc(l.name), sub: `${esc(l.date)} · ${esc(l.data)}` })).join("")}</div>`
        : `<div class="card pad dt-ok">${ic("check")}${okText}</div>`;
  F.actions["dt-hibp-key"] = () => {
    if (F.openKeySheet) F.openKeySheet("hibp");
    else F.go("/settings/keys");
  };
  function relatedBlock(groups) {
    const g = Object.entries(groups)
      .map(([t, [i, items]]) => relGroup(t, i, items))
      .join("");
    return g ? ui.secH(F.t("data.related", "Связанное")) + `<div class="dt-rel">${g}</div>` : "";
  }

  /** Banner on a host card: internal host, excluded from scope, or out of scope. */
  function hostBanner(h, sc, internal, docs, fnd) {
    if (internal)
      return `<div class="banner warn dt-gap">${ic("info")}<div>${F.t("data.internal_host_source_clients", { source: h.source ? ` ${esc(F.t("data.source_2", "· источник:"))} ${esc(h.source)}` : docs.length ? F.t("data.found_document_metadata", ", найден в метаданных документов") : "" }, "Внутренний хост{source}. Внутреннюю сеть заказчика не сканировали.")}</div></div>`;
    if (sc.excluded)
      return `<div class="banner warn dt-gap">${ic("alert")}<div><b>${esc(F.t("data.excluded_from_scope", "В исключениях скоупа"))}</b> ${esc(F.t("data.rule", "(правило"))} <span class="mono">${esc(sc.excluded)}</span>). ${hostTouched(h, fnd)}</div></div>`;
    if (!sc.ok)
      return `<div class="banner info dt-gap">${ic("info")}<div><b>${esc(F.t("data.out_scope_2", "Вне скоупа."))}</b> ${esc(F.t("data.no_active_checks_run_against", "Активные проверки хоста не проводятся."))}</div></div>`;
    return "";
  }
  /** Which metadata fields mention PC `id`. */
  function pcFields(id, docs, pe) {
    if (docs.some(d => d.lnk && d.lnk.machine === id))
      return F.t("data.lnk_shortcut_machine_name", "Ярлык .lnk: имя машины");
    if (docs.some(d => d.rdp && d.rdp.gateway === id))
      return F.t("data.rdp_file_server_address", "Файл .rdp: адрес сервера");
    if (docs.length)
      return F.t("data.lastmodifiedby_company_template", "LastModifiedBy, Company, путь шаблона");
    return esc((pe && pe.source) || "-");
  }
  // The excluded-host note is based on where the data came from, not only on the current scope.
  function hostTouched(h, fnd) {
    const act = (fnd || []).filter(f => {
      const raw = (F.db.findings || []).find(x => x.id === f.id);
      return raw && raw.active;
    });
    const svc = (h.services || []).length;
    if (act.length || svc) {
      const t0 = act.length ? ((F.db.findings || []).find(x => x.id === act[0].id) || {}).time : null;
      const sc = t0 ? { at: t0 } : null;
      return `${F.t("data.host_excluded_after_scan_detail", { detail: act.length ? `${plural(act.length, F.t("data.finding_obtained", "находка получена"), F.t("data.findings_obtained", "находки получены"), F.t("data.finding_obtained_many", "находок получено"))} ${esc(F.t("data.active_modules", "активными модулями"))}${sc && sc.at ? " " + esc(String(sc.at).slice(0, 10).split("-").reverse().join(".")) : ""}` : F.t("data.services_found_scan", "сервисы найдены сканом") }, "Хост исключён после скана: {detail}. Новые запросы к хосту не отправляются.")}`;
    }
    return `${F.t("data.host_was_not_contacted", { source: h.source ? ` · ${esc(h.source)}` : "" }, "К хосту не обращались: сведения только из внешних источников{source}.")}`;
  }
  function rHost(id) {
    const host = hostByName(id);
    // Host findings follow the same rule as the PC card and F.sel.related (by finding host and via rel.pcs
    // relations).
    const relF = new Set(((F.sel.related("host", id) || {}).findings || []).map(f => f.id));
    const fnd = (F.demoFindings || []).filter(
      f => f.host.toLowerCase() === String(id).toLowerCase() || relF.has(f.id),
    );
    const sc = F.sel.scope.check(id);
    if (!host) {
      // A host mentioned only in a finding (e.g. ns2) gets a minimal card.
      return {
        label: id,
        icon: "server",
        html:
          head({
            lead: ui.leadIcon("server"),
            name: esc(id),
            type: "host",
            facts: [[F.t("data.source", "Источник"), F.t("nav.findings", "Находки")]],
          }) +
          searchBtns(id) +
          (fnd.length
            ? ui.secH(F.t("nav.findings", "Находки"), fnd.length) + findRows(fnd)
            : ui.empty({
                icon: "server",
                title: F.t("data.little_information", "Сведений мало"),
                text: F.t(
                  "data.host_mentioned_results_but_was",
                  "Хост упомянут в результатах, но не сканировался.",
                ),
              })),
      };
    }
    const info = hostInfo(host);
    const internal = isInternal(host);
    const docs = LD().filter(
      d =>
        d.host === host.name ||
        d.folder.includes("\\" + host.name + "\\") ||
        d.printer.includes("\\" + host.name + "\\"),
    );
    const users = uniq(docs.map(d => d.user.login))
      .map(l => people.find(p => p.login === l))
      .filter(Boolean);
    const sameNet = demo.hosts.filter(
      x =>
        x !== host &&
        !isInternal(x) &&
        !internal &&
        x.ip.split(".").slice(0, 3).join(".") === host.ip.split(".").slice(0, 3).join("."),
    );
    const pcUsers = people.filter(p => p.pc === host.name);
    return {
      label: host.name,
      icon: internal ? "monitor" : "server",
      html:
        head({
          lead: ui.leadIcon(internal ? "monitor" : "server", SEVC[host.sev]),
          name: esc(host.name),
          type: "host",
          pills: `${ui.sev(fnd.reduce((m, f) => ((SEVORD[f.sev] ?? 9) < (SEVORD[m] ?? 9) ? f.sev : m), host.sev))}<span class="pill mute">${esc(host.role)}</span>${infraPills(host)}${internal ? `<span class="pill vio">${ic("lock")}${esc(F.t("data.internal", "Внутренний"))}</span>` : scopePill(host.name)}`,
          facts: [
            ["IP", `<span class="mono">${esc(host.ip)}</span>`],
            [F.t("data.cloud", "Облако"), esc(host.cloud)],
            [F.t("data.documents_count", "Документов"), docs.length || "-"],
            [F.t("data.findings_count", "Находок"), fnd.length || "-"],
          ],
        }) +
        searchBtns(host.name, LD().some(d => d.host === host.name) ? { host: [host.name] } : null) +
        hostBanner(host, sc, internal, docs, fnd) +
        (info.dns.length
          ? ui.secH(F.t("data.dns_records", "DNS-записи")) +
            `<div class="list">${info.dns
              .map(
                ([
                  t,
                  v,
                  n,
                ]) => `<div class="row dt-dns"><span class="dt-rr">${t}</span><div class="body"><div class="t mono">${esc(v)}</div>${n ? `<div class="s">${esc(n)}</div>` : ""}</div><button class="ib"
              data-act="copy:${esc(v)}"
              aria-label="${F.t("data.copy_record_t", { t }, "Копировать запись {t}")}">${ic("copy")}</button></div>`,
              )
              .join("")}</div>`
          : "") +
        ui.secH(F.t("data.network", "Сеть")) +
        `<div class="kv">${kvr("IP", `<span class="mono">${esc(host.ip)}</span>`, info.ip !== "-" ? info.ip : "")}${kvr("ASN", esc(info.asn))}${kvr(F.t("data.cloud", "Облако"), esc(host.cloud))}${kvr(F.t("data.role", "Роль"), esc(host.role))}${host.source ? kvr(F.t("data.source", "Источник"), esc(F.infra ? F.infra.srcLabel(host.source) : host.source)) : ""}${host.cdn ? kvr(F.t("data.cdn_cloud", "CDN / облако"), `${esc(host.cdn.name || host.cdn.provider)} · <span class="mono">${esc(host.cdn.prefix || "")}</span>`) : ""}${(host.priority || 0) > 0 ? kvr(F.t("data.check_priority", "Приоритет проверки"), `${host.priority} ${esc(F.t("data.100", "из 100"))}`) : ""}</div>` +
        (info.tech.length
          ? ui.secH(F.t("data.technologies_2", "Технологии")) +
            `<div class="chips wrap">${info.tech.map(t => `<span class="chip">${esc(t)}</span>`).join("")}</div>`
          : "") +
        (F.infra && F.infra.certsOf(host.name).length
          ? F.infra.certBlock(host.name)
          : info.tls
            ? ui.secH(F.t("data.tls_certificate", "TLS-сертификат")) +
              `<div class="kv">${kvr(F.t("data.subject", "Субъект"), `<span class="mono">CN=${esc(info.tls.cn)}</span>`)}${kvr(F.t("data.issuer", "Издатель"), esc(info.tls.iss))}${kvr(F.t("data.valid_until", "Действует до"), info.tls.warn ? `<span class="dt-warn">${ic("alert")}${esc(info.tls.till)}</span>` : esc(info.tls.till))}${kvr("SAN", `<span class="mono">${esc(info.tls.san)}</span>`)}</div>`
            : "") +
        (F.ins ? F.ins.webAuditHost(host.name) : "") +
        portsBlock(host) +
        (info.svc.length
          ? ui.secH(F.t("data.services", "Сервисы"), info.svc.length) +
            `<div class="list">${info.svc.map(([p, s, b]) => `<div class="row dt-svc"><span class="dt-port mono">${p}</span><div class="body"><div class="t">${esc(s)}</div><div class="s">${esc(b)}</div></div></div>`).join("")}</div>`
          : "") +
        (fnd.length ? ui.secH(F.t("nav.findings", "Находки"), fnd.length) + findRows(fnd) : "") +
        docsBlock(
          docs,
          internal
            ? F.t("data.where_appears", "Где встречается")
            : F.t("data.documents_from_host", "Документы с хоста"),
          LD().some(d => d.host === host.name) ? { host: [host.name] } : null,
        ) +
        relatedBlock({
          [F.t("data.rel_people", "Люди")]: ["users", users.slice(0, 6).map(personRow)],
          [F.t("data.users_pc", "Пользователи этого ПК")]: ["user", pcUsers.map(personRow)],
          [F.t("data.same_subnet", "Та же подсеть")]: [
            "net",
            sameNet.map(x =>
              navRow({
                lead: ui.leadIcon("server", SEVC[x.sev]),
                title: esc(x.name),
                sub: `<span class="mono">${esc(x.ip)}</span>`,
                path: F.dataEntityPath("host", x.name),
              }),
            ),
          ],
        }),
    };
  }

  function rPc(id) {
    const users = people.filter(p => p.pc === id);
    const docs = LD().filter(d => d.user.pc === id || d.folder.includes("\\" + id + "\\"));
    const host = hostByName(id);
    const fnd = F.sel.related("pc", id).findings;
    const rel = relFrom(docs);
    const pe = F.sel.entity("pc", id);
    const server = pe ? pe.kind === "server" : /^SRV|MAIL/.test(id);
    return {
      label: id,
      icon: server ? "server" : "monitor",
      html:
        head({
          lead: ui.leadIcon(server ? "server" : "monitor"),
          name: esc(id),
          type: "pc",
          pills: `<span class="pill mute">${server ? F.t("data.server", "Сервер") : F.t("data.workstation", "Рабочая станция")}</span><span class="pill vio">${ic("lock")}${esc(F.t("data.internal", "Внутренний"))}</span>`,
          facts: [
            [F.t("data.users_count", "Пользователей"), users.length || "-"],
            [F.t("data.documents_count", "Документов"), docs.length || "-"],
            [F.t("data.findings_count", "Находок"), fnd.length || "-"],
            [F.t("data.source", "Источник"), esc((pe && pe.source) || F.t("data.metadata", "Метаданные"))],
          ],
        }) +
        searchBtns(id) +
        ui.secH(F.t("data.where_appears", "Где встречается")) +
        `<div class="kv">${kvr(F.t("data.pc_name", "Имя ПК"), `<span class="mono">${esc(id)}</span>`, id)}${kvr(F.t("data.fields", "Поля"), pcFields(id, docs, pe))}${kvr(F.t("data.domain", "Домен"), esc(netbios()))}</div>` +
        (host
          ? `<div class="list dt-gap">${navRow({ lead: ui.leadIcon("server"), title: `${esc(F.t("data.host_card", "Карточка хоста"))} ${esc(host.name)}`, sub: esc(host.ip), path: F.dataEntityPath("host", host.name) })}</div>`
          : "") +
        (users.length
          ? ui.secH(F.t("data.users", "Пользователи")) +
            `<div class="list">${users.map(personRow).join("")}</div>`
          : "") +
        (fnd.length ? ui.secH(F.t("nav.findings", "Находки"), fnd.length) + findRows(fnd) : "") +
        docsBlock(
          docs,
          F.t("data.documents_from_pc", "Документы с этого ПК"),
          users.length ? { author: users.map(u => u.login) } : null,
        ) +
        relatedBlock({
          [F.t("data.software", "ПО")]: ["app", rel.sw],
          [F.t("data.printers", "Принтеры")]: ["printer", rel.printers],
          [F.t("data.paths", "Пути")]: ["path", rel.paths],
        }),
    };
  }

  function rSoftware(id) {
    const sw = /^\d+$/.test(id) ? demo.software[+id] : demo.software.find(x => x.id === id || x.name === id); // Also by id (API.md, F.sel.entity).
    if (!sw) return null;
    const swx = SWX[sw.name] || { eol: "-", cves: [] };
    const docs = LD().filter(d => d.sw === sw);
    const users = uniq(docs.map(d => d.user.login))
      .map(l => people.find(p => p.login === l))
      .filter(Boolean);
    const pcs = uniq(users.map(u => u.pc).filter(p => p && p !== "-"));
    const others = demo.software.filter(
      o => o !== sw && o.name.split(" ").slice(0, 2).join(" ") === sw.name.split(" ").slice(0, 2).join(" "),
    );
    return {
      label: sw.name,
      icon: "app",
      html:
        head({
          lead: ui.leadIcon("app", sw.eol ? "var(--warn)" : ""),
          name: esc(sw.name),
          type: "software",
          pills:
            (sw.eol
              ? `<span class="pill warn">${ic("alert")}${esc(F.t("data.end_support", "Поддержка завершена"))}</span>`
              : `<span class="pill ok">${ic("check")}${esc(F.t("data.supported", "Поддерживается"))}</span>`) +
            (sw.cve ? `<span class="pill crit">${ic("bug")}${sw.cve} CVE</span>` : ""),
          facts: [
            [F.t("about.version", "Версия"), `<span class="mono">${esc(sw.ver)}</span>`],
            [F.t("data.documents_count", "Документов"), sw.n],
            [F.t("data.eol_date", "Конец поддержки"), esc(swx.eol)],
            [F.t("data.users_count", "Пользователей"), users.length],
          ],
        }) +
        searchBtns(sw.name, { sw: [sw.name] }) +
        (swx.cves.length
          ? ui.secH(F.t("data.vulnerabilities", "Уязвимости"), sw.cve) +
            `<div class="list">${swx.cves
              .map(([c, v]) =>
                ui.row({
                  lead: ui.leadIcon("bug", v >= 9 ? "var(--crit)" : "var(--bad)"),
                  title: `<span class="mono">${esc(c)}</span>`,
                  sub: `CVSS ${v.toFixed(1)} · ${v >= 9 ? F.t("data.critical", "критическая") : F.t("data.high", "высокая")}`,
                  tail: `<button class="ib"
              data-act="copy:${esc(c)}"
              aria-label="${F.t("data.copy_c", { c: esc(c) }, "Копировать {c}")}">${ic("copy")}</button>`,
                }),
              )
              .join(
                "",
              )}${sw.cve > swx.cves.length ? `<div class="row"><div class="body"><div class="s">${F.t("data.n_more_local_cve_database", { n: sw.cve - swx.cves.length }, "и ещё {n} в локальной базе CVE")}</div></div></div>` : ""}</div>`
          : "") +
        docsBlock(docs, F.t("app.documents", "Документы"), { sw: [sw.name] }) +
        relatedBlock({
          [F.t("data.rel_people", "Люди")]: ["users", users.slice(0, 8).map(personRow)],
          [F.t("data.rel_computers", "Компьютеры")]: ["monitor", pcs.map(pcRow)],
          [F.t("data.other_versions", "Другие версии")]: [
            "app",
            others.map(o =>
              navRow({
                lead: ui.leadIcon("app"),
                title: esc(o.name),
                sub: `${esc(F.t("data.version", "версия"))} ${esc(o.ver)}`,
                path: F.dataEntityPath("software", swIdx(o)),
              }),
            ),
          ],
        }),
    };
  }

  function rPrinter(id) {
    const printer = /^\d+$/.test(id) ? demo.printers[+id] : demo.printers.find(x => x.name === id);
    if (!printer) return null;
    const docs = LD().filter(d => d.printer === printer.name);
    const host = printerHost(printer.name);
    const users = uniq(docs.map(d => d.user.login))
      .map(l => people.find(x => x.login === l))
      .filter(Boolean);
    return {
      label: printer.name.replace(/^\\\\[^\\]+\\/, ""),
      icon: "printer",
      html:
        head({
          lead: ui.leadIcon("printer"),
          name: esc(printer.name.replace(/^\\\\[^\\]+\\/, "")),
          type: "printer",
          pills: `<span class="pill mute">${host ? F.t("data.network_3", "Сетевой") : /PDF/.test(printer.name) ? F.t("data.virtual", "Виртуальный") : F.t("data.local", "Локальный")}</span>`,
          facts: [
            [F.t("data.documents_count", "Документов"), printer.n],
            [F.t("data.print_server", "Сервер печати"), host ? esc(host) : "-"],
          ],
        }) +
        searchBtns(printer.name) +
        ui.secH(F.t("data.where_appears", "Где встречается")) +
        `<div class="kv">${kvr(F.t("data.full_name", "Полное имя"), `<span class="mono">${esc(printer.name)}</span>`, printer.name)}${host ? kvLink(F.t("data.server", "Сервер"), esc(host), F.dataEntityPath("host", host)) : ""}${kvr(F.t("data.field", "Поле"), F.t("data.printer_docx_xlsx_metadata", "Printer (метаданные docx/xlsx)"))}</div>` +
        docsBlock(docs, F.t("app.documents", "Документы"), null) +
        relatedBlock({
          [F.t("data.rel_people", "Люди")]: ["users", users.map(personRow)],
          [F.t("data.rel_computers", "Компьютеры")]: [
            "monitor",
            uniq(users.map(u => u.pc).filter(x => x !== "-")).map(pcRow),
          ],
        }),
    };
  }

  function rPath(id) {
    const path = /^\d+$/.test(id) ? demo.folders[+id] : id;
    const docs = LD().filter(d => d.folder === path);
    const user = pathUser(path),
      host = pathHost(path);
    return {
      label: path.split(/[\\/]/).filter(Boolean).pop() || path,
      icon: "path",
      html:
        head({
          lead: ui.leadIcon(host ? "net" : "path"),
          name: `<span class="mono dt-path">${esc(path)}</span>`,
          type: "path",
          pills: `<span class="pill mute">${pathKind(path)}</span>`,
          facts: [
            [F.t("data.documents_count", "Документов"), docs.length || "-"],
            [F.t("data.user", "Пользователь"), user ? esc(user.login) : "-"],
          ],
        }) +
        searchBtns(path) +
        ui.secH(F.t("data.where_appears", "Где встречается")) +
        `<div class="kv">${kvr(F.t("data.path_2", "Путь"), `<span class="mono">${esc(path)}</span>`, path)}${host ? kvLink(F.t("data.server", "Сервер"), esc(host), F.dataEntityPath(hostByName(host) ? "host" : "pc", host)) : ""}${user ? kvLink(F.t("data.user", "Пользователь"), esc(user.name), F.dataEntityPath("person", user.login)) : ""}${kvr(F.t("data.field", "Поле"), F.t("data.template_file_path_metadata", "Template / путь к файлу в метаданных"))}</div>` +
        docsBlock(docs, F.t("app.documents", "Документы"), null) +
        relatedBlock({
          [F.t("data.rel_people", "Люди")]: [
            "users",
            uniq(docs.map(d => d.user.login))
              .map(l => people.find(x => x.login === l))
              .filter(Boolean)
              .slice(0, 6)
              .map(personRow),
          ],
        }),
    };
  }

  function rEmail(id) {
    const email = [...emails, ...roleMail].find(x => x.addr === id);
    if (!email) return null;
    const person = email.login && people.find(x => x.login === email.login);
    const leaks = (email.login && hibp[email.login]) || [];
    return {
      label: email.addr,
      icon: "mail",
      html:
        head({
          lead: ui.leadIcon("mail", email.found ? "var(--ok)" : "var(--info)"),
          name: `<span class="dt-addr">${esc(email.addr).replace("@", "<wbr>@")}</span>`,
          type: "email",
          pills:
            (email.found
              ? `<span class="pill ok">${ic("check")}${esc(F.t("data.found", "Найден"))}</span>`
              : `<span class="pill vio">${ic("graph")}${esc(F.t("data.generated", "Сгенерирован"))}</span>`) +
            (email.role ? `<span class="pill mute">${esc(F.t("data.role_2", "Служебный"))}</span>` : ""),
          facts: [
            [F.t("data.source", "Источник"), esc(email.src)],
            [F.t("data.leaks_count", "Утечек"), leaks.length || "-"],
          ],
        }) +
        `<div class="btnrow dt-findby"><button class="btn tonal"
          data-act="copy:${esc(email.addr)}">${ic("copy")}${esc(F.t("data.copy", "Копировать"))}</button><button class="btn"
          data-act="dt-search:${esc(email.addr.split("@")[0])}">${ic("search")}${esc(F.t("data.search", "Искать по этому"))}</button></div>` +
        (!email.found && patterns[0]
          ? `<div class="banner info dt-gap">${ic("info")}<div>${esc(F.t("data.address_never_appeared_sources", "Адрес не встречался в источниках, построен по шаблону"))} <span class="mono">${esc(patterns[0].p)}@</span> ${F.t("data.conf_confidence", { conf: patterns[0].conf }, "с уверенностью {conf}%.")}</div></div>`
          : "") +
        ui.secH(F.t("data.leaks", "Утечки"), "HIBP") +
        leakBlock(leaks, F.t("data.not_found_known_leaks", "Не найден в известных утечках")) +
        relatedBlock({
          [F.t("data.rel_owner", "Владелец")]: ["user", person ? [personRow(person)] : []],
          [F.t("data.domain", "Домен")]: [
            "domain",
            [
              navRow({
                lead: ui.leadIcon("domain"),
                title: esc(email.addr.split("@")[1]),
                sub: "MX, SPF, DMARC",
                path: F.dataEntityPath("host", email.addr.split("@")[1]),
              }),
            ],
          ],
        }),
    };
  }

  function rOs(id) {
    const os = F.sel.os().find(x => x.id === id || x.name === id);
    if (!os) return null;
    const docs = os.doc_ids.map(i => F.sel.entity("doc", i)).filter(Boolean);
    const users = uniq(docs.map(d => d.author).filter(Boolean))
      .map(l => people.find(x => x.login === l))
      .filter(Boolean);
    const sws = uniq(docs.map(d => d.sw).filter(s => s && !s.none));
    return {
      label: os.name,
      icon: "monitor",
      html:
        head({
          lead: ui.leadIcon(OS_IC[os.family] || "monitor"),
          name: esc(os.name),
          type: "os",
          pills: os.src.map(s => `<span class="pill mute">${esc(s)}</span>`).join(""),
          facts: [
            [F.t("data.documents_count", "Документов"), docs.length],
            [F.t("data.users_count", "Пользователей"), users.length || "-"],
            [F.t("data.programs_count", "Программ"), sws.length || "-"],
          ],
        }) +
        ui.secH(F.t("data.how_detected", "Как определено")) +
        `<div class="kv">${kvr(F.t("data.fields", "Поля"), esc(os.src.join(", ")))}${sws.length ? kvr(F.t("data.programs_2", "Программы"), esc(sws.map(s => s.name).join(", "))) : ""}</div>` +
        docsBlock(docs, F.t("app.documents", "Документы"), null) +
        relatedBlock({
          [F.t("data.rel_people", "Люди")]: ["users", users.slice(0, 8).map(personRow)],
          [F.t("data.software", "ПО")]: [
            "app",
            sws.map(s =>
              navRow({
                lead: ui.leadIcon("app", s.eol ? "var(--warn)" : ""),
                title: esc(s.name),
                sub: `${esc(F.t("data.version", "версия"))} ${esc(s.ver)}`,
                path: F.dataEntityPath("software", swIdx(s)),
              }),
            ),
          ],
        }),
    };
  }
  const RENDER = {
    person: rPerson,
    host: rHost,
    pc: rPc,
    software: rSoftware,
    printer: rPrinter,
    path: rPath,
    email: rEmail,
    os: rOs,
  };
  const resolve = p => {
    const fn = RENDER[p.type];
    return fn ? fn(p.id) : null;
  };
  F.route("/p/entity/:type/:id", {
    title: p => (TYPES()[p.type] || [F.t("app.card", "Карточка")])[0],
    back: true,
    tab: "data",
    actions: p => [
      { icon: "share", act: `dt-ent-share:${p.type}`, label: F.t("data.share_card", "Поделиться карточкой") },
      { icon: "more", act: "menu", label: F.t("app.menu", "Меню") },
    ],
    render: params =>
      F.withStates(
        () => {
          const r = resolve(params);
          if (!r)
            return ui.empty({
              icon: (TYPES()[params.type] || ["", "search"])[1],
              title: F.t("data.not_found", "Не найдено"),
              text: F.t("data.entity_not_project_data", "Сущность отсутствует в данных проекта."),
              action: `<button class="btn tonal" data-act="back">${esc(F.t("app.back", "Назад"))}</button>`,
            });
          F.dataTrail.visit(F.current(), r.label, r.icon);
          return F.dataTrail.html() + r.html;
        },
        {
          loading: "cards",
          empty: {
            icon: (TYPES()[params.type] || ["", "search"])[1],
            title: F.t("data.no_data_yet", "Данных пока нет"),
            text: F.t("data.card_fills_after_scan", "Карточка заполнится после скана."),
          },
        },
      ),
    mount: page => F.dataTrail.mount(page),
  });
  // Share a card: person → users dictionary/table, host → hosts, software → software (Markdown, no secrets).
  const ENT_KIND = { person: "users", host: "hosts", software: "software", email: "emails", path: "paths" };
  F.actions["dt-ent-share"] = type => {
    if (F.isDemo) {
      F.snack(F.t("data.card_exported_pdf_without", "Карточка экспортирована в PDF без секретов (демо)"));
      return;
    }
    const params = F.cur && F.cur.p,
      kind = ENT_KIND[type || (params && params.type)] || "findings";
    const items = params && params.id ? [F.decode(params.id)] : undefined;
    F.api
      .export_build(kind, "md", { items, secrets: false })
      .then(r => F.api.platform_share({ path: r.path, name: r.name, mime: "text/markdown" }))
      .then(
        r => {
          if (r && r.ok) F.snack(`${esc(F.t("data.sharing", "Отправка:"))} ${r.name}`);
        },
        e => F.snack(F.t("data.could_not_share", "Не удалось поделиться: ") + (e.message || e)),
      );
  };
})();
