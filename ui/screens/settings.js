// Settings screens (CSS prefix st-).
// Routes: /settings, /settings/keys, /settings/network, /settings/power, /settings/security,
// /settings/battery,
// /settings/appearance, /settings/about, /settings/signatures, /lock (lock screen, demo PIN 1234).
// /settings/plugins and /settings/ai are separate screens in v2.js (only linked from here).
(function () {
  const F = window.FOCA,
    { ic, esc, ui } = F;
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
  // Escapes a translated string, then restores the [b]/[code] markers as markup.
  const rich = s => esc(s).replace(/\[(\/?)(b|code)\]/g, "<$1$2>");

  F.addIcons(`
<symbol id="i-st-del"
  viewBox="0 0 16 16"><path d="M5.5 3.5h8a1 1 0 0 1 1 1v7a1 1 0 0 1-1 1h-8L1.5 8z"/><path d="m8 6 4 4M12 6l-4 4"/></symbol>
<symbol id="i-st-wifi"
  viewBox="0 0 16 16"><path d="M1.5 6a9.5 9.5 0 0 1 13 0M3.7 8.5a6.3 6.3 0 0 1 8.6 0M5.9 11a3.2 3.2 0 0 1 4.2 0M8 13.3h.01"/></symbol>
<symbol id="i-st-temp"
  viewBox="0 0 16 16"><path d="M6.5 9.3V3.5a1.5 1.5 0 0 1 3 0v5.8a3 3 0 1 1-3 0z"/><path d="M8 7v4.5"/></symbol>
<symbol id="i-st-bolt" viewBox="0 0 16 16"><path d="M9 1.5 3.5 9H8l-1 5.5L12.5 7H8z"/></symbol>
<symbol id="i-st-text"
  viewBox="0 0 16 16"><path d="M2 12.5 5.5 3.5 9 12.5M3.3 9.5h4.4M10.5 8.5c.4-.7 1.1-1 1.9-1 1.1 0 1.6.6 1.6 1.6v3.4M14 10.5h-1.8c-1 0-1.7.4-1.7 1.1s.5 1 1.2 1c1.2 0 2.3-.8 2.3-2.1"/></symbol>
<symbol id="i-st-lang"
  viewBox="0 0 16 16"><path d="M2 3.5h7M5.5 2v1.5M3.5 3.5c.5 2.5 2 4.5 4.5 5.5M7.5 3.5c-.5 2.5-2 4.5-4.5 5.5M8.5 14l3-7 3 7M9.5 12h4"/></symbol>
<symbol id="i-st-rows" viewBox="0 0 16 16"><rect x="2.5" y="2.5" width="11" height="3"
  rx=".8"/><rect x="2.5" y="6.5" width="11" height="3" rx=".8"/><rect x="2.5" y="10.5" width="11" height="3"
  rx=".8"/></symbol>
<symbol id="i-st-sig"
  viewBox="0 0 16 16"><path d="M8 2 13 4v4c0 3-2.2 5-5 6-2.8-1-5-3-5-6V4z"/><path d="M5.8 8h4.4M8 5.8v4.4"/></symbol>
<symbol id="i-st-phone" viewBox="0 0 16 16"><rect x="4.5" y="1.5" width="7" height="13"
  rx="1.5"/><path d="M7 12.5h2"/></symbol>
<symbol id="i-st-ua" viewBox="0 0 16 16"><rect x="2" y="3" width="12" height="10"
  rx="1.2"/><path d="M2 6h12M4 4.5h.01M5.5 4.5h.01M5 8.5l1.5 1.5L5 11.5M8 11.5h3"/></symbol>
<symbol id="i-st-gauge"
  viewBox="0 0 16 16"><path d="M2.5 11a5.5 5.5 0 1 1 11 0"/><path d="m8 11 3-3.5"/></symbol>
<symbol id="i-st-panic" viewBox="0 0 16 16"><circle cx="8" cy="8"
  r="5.5"/><path d="M8 4.8v3.7M8 10.9h.01"/></symbol>
<symbol id="i-st-code"
  viewBox="0 0 16 16"><path d="m5.5 4.5-3.5 3.5 3.5 3.5M10.5 4.5 14 8l-3.5 3.5M9 3l-2 10"/></symbol>`);

  // ================= STATE =================
  const state = (F.state.settings = F.state.settings || {
    keys: {
      brave: { v: "BSAq7Lr2xkP0dZt3ab12", st: "ok", used: 1840, lim: 2000 },
      shodan: { v: "Kx9fT2mQe7Lw4hV1c8e4", st: "ok", used: 61, lim: 100 },
      hibp: { v: "", st: "none" },
      vt: { v: "4b1e0c77a9f2d63e5f10", st: "err", err: "401 Unauthorized: ключ отозван" },
      st: { v: "Y3pR8sN1kW6qZ0m2d9f0", st: "ok", used: 22, lim: 50 },
      urlscan: { v: "", st: "none" },
      censys: { v: "", st: "none" },
      github: { v: "ghp_Wm2Qx8rT0pL4kZ7aNn33", st: "ok", used: 312, lim: 5000, per: "ч" },
      ai: { v: "sk-ds-91fA2bQ7hL0xV5", st: "ok", used: 0, lim: 0, note: "DeepSeek · баланс $4,20" },
    },
    net: {
      proxyOn: true,
      ptype: "socks5",
      addr: "127.0.0.1:9050",
      orbot: true,
      ua: "chrome",
      uaCustom: "",
      threads: 8,
      rps: 10,
      hostsParallel: 4,
      timeout: 15,
      retries: 2,
      kill: true,
      dns: "system",
      dnsCustom: "9.9.9.9",
    },
    power: {
      wifiOnly: true,
      limOn: true,
      mobLimit: 1000,
      battOn: true,
      batt: 20,
      heat: true,
      chargeOnly: false,
      period: "month",
    },
    sec: {
      pin: true,
      bio: true,
      autolock: "5",
      hide: true,
      clip: true,
      panic: false,
      autodel: true,
      autodelDays: "30",
    },
    battery: { excluded: false, oem: "xiaomi", done: {} },
    look: {
      theme: (() => {
        try {
          return localStorage.getItem("st-theme") || "dark";
        } catch (e) {
          return "dark";
        }
      })(),
      lang: "AUTO",
      density: "normal",
    },
    sig: { auto: true, updating: false, updated: "18.11.2026, 09:12" },
  });
  const get = path => path.split(".").reduce((o, k) => o[k], state);
  const set = (path, v) => {
    const ks = path.split(".");
    const last = ks.pop();
    ks.reduce((o, k) => o[k], state)[last] = v;
  };
  // Persistence: everything changed on the settings screens is sent to the core via F.api.settings_set
  // (survives reloads).
  // net/power/sec are core Settings sections (state.* is a view over F.db.settings); battery/look/sig live in
  // settings.ui.
  const UI_SECS = ["battery", "look", "sig"];
  const clone = o => JSON.parse(JSON.stringify(o));
  const persistT = {};
  const persist = (path, delay = 0) => {
    const sec = String(path).split(".")[0];
    const go = () => {
      if (["net", "power", "sec"].includes(sec))
        F.api.settings_set({ [sec]: clone(F.db.settings[sec] || {}) });
      else if (UI_SECS.includes(sec))
        F.api.settings_set({ ui: { [sec]: clone({ ...state[sec], updating: undefined, pct: undefined }) } });
    };
    clearTimeout(persistT[sec]);
    if (delay) persistT[sec] = setTimeout(go, delay);
    else go();
  };
  // UI-only sections come from settings.ui (after a page reload).
  const ui0 = (F.db.settings || {}).ui || {};
  UI_SECS.forEach(k => {
    if (ui0[k] && state[k]) Object.assign(state[k], ui0[k], k === "sig" ? { updating: false } : {});
  });
  // The interface language lives in the top-level `lang` setting ("auto" = follow the phone). Older builds
  // also wrote settings.ui.look.lang, and a stale copy there ("RU") highlighted Russian on a Ukrainian
  // interface, so the picker always reads the active setting.
  const langLook = () => {
    const raw = F.i18n ? F.i18n.setting() : (F.db.settings || {}).lang;
    const code = F.i18n ? F.i18n.normalize(raw) : String(raw || "auto").toLowerCase();
    return code === "uk" ? "UA" : code === "en" ? "EN" : code === "ru" ? "RU" : "AUTO";
  };
  state.look.lang = langLook();
  // Language name inside the UI language (nominative), e.g. "українська" / "Ukrainian".
  const langName = code =>
    F.t(`look.lang_name_${code}`, { uk: "украинский", en: "английский", ru: "русский" }[code]);
  // Language the phone asks for (unsupported system languages fall back to English, as in the core).
  const deviceLang = () => {
    if (!F.i18n) return "ru";
    if (F.i18n.setting() === "auto") return F.i18n.lang();
    const d = F.i18n.normalize(F.i18n.detectDeviceLocale());
    return d === "auto" ? "en" : d;
  };
  const systemLabel = () =>
    F.t("look.lang_system", { lang: langName(deviceLang()) }, "Как в системе ({lang})");

  // ================= SHARED BLOCKS =================
  // Toggle row: the whole row (≥ 48 px) is the tap target; the switch itself triggers the same action.
  const tRow = (path, title, sub = "", lead = "", extra = "") =>
    `<div class="row tap st-tr ${extra}"
      data-act="st-t:${path}">${lead}<div class="body"><div class="t">${title}</div>${sub ? `<div class="s">${sub}</div>` : ""}</div><div class="tail">${ui.toggle(get(path), "st-t:" + path, `aria-label="${esc(title.replace(/<[^>]+>/g, ""))}"`)}</div></div>`;
  // "Block screenshots" is opt-in and lives straight in core settings (sec.block_shots, missing = off):
  // the legacy sec.hide flag defaulted to on, so it is not reused.
  const shotsOn = () => ((F.db.settings || {}).sec || {}).block_shots === true;
  const shotsRow = () => {
    const title = F.t("settings.block_shots", "Запретить скриншоты");
    return `<div class="row tap st-tr" data-act="st-shots">${ui.leadIcon("eye-off")}<div class="body"><div class="t">${esc(title)}</div><div class="s">${esc(F.t("settings.block_shots_sub", "Скриншоты и запись экрана запрещены, в списке недавних приложений, пустой экран"))}</div></div><div class="tail">${ui.toggle(shotsOn(), "st-shots", `aria-label="${esc(title)}"`)}</div></div>`;
  };
  const seg = (path, opts, label = "") =>
    `<div class="seg st-seg" role="radiogroup"
      ${label ? `aria-label="${esc(label)}"` : ""}>${opts
        .map(
          ([v, l]) => `<button class="${String(get(path)) === String(v) ? "on" : ""}"
      role="radio" aria-checked="${String(get(path)) === String(v)}"
      data-act="st-set:${path}:${v}">${l}</button>`,
        )
        .join("")}</div>`;
  // Numeric input with ± (F.numField from help.js); applied on blur/Enter and saved to the core.
  // `lim` names the setting in F.limits (ui/js/limits.js): hard minimum, recommendation, warnings.
  const nf = (path, label, unit, lim, note, help, step = 1, extra = {}) =>
    F.numField({
      id: path.replace(".", "-"),
      label,
      unit,
      lim,
      step,
      note,
      help,
      whyMin: extra.whyMin,
      riskCtx: extra.riskCtx,
      get: () => +get(path),
      set: v => {
        set(path, v);
        persist(path, 300);
        updPresets();
        if (extra.after) extra.after(v);
      },
    });
  // Network presets (all inside the recommended ranges of F.limits).
  const PRESETS = [
    ["soft", "Бережно", "мобильный · Tor", { threads: 2, rps: 3, timeout: 30 }],
    ["normal", "Обычно", "Wi-Fi", { threads: 6, rps: 8, timeout: 15 }],
    ["fast", "Быстро", "свой сервер", { threads: 16, rps: 20, timeout: 10 }],
  ];
  const presetOn = () =>
    (PRESETS.find(([, , , v]) => Object.entries(v).every(([k, x]) => +state.net[k] === x)) || [])[0];
  const presetsHTML = () => {
    const cur = presetOn();
    return PRESETS.map(
      ([id, t, sub, v]) =>
        `<button class="${cur === id ? "on" : ""}" role="radio" aria-checked="${cur === id}"
          data-act="st-preset:${id}"><b>${esc(F.t(`settings.preset_${id}`, t))}</b><small>${esc(F.t(`settings.preset_${id}_sub`, sub))}</small><small>${v.threads} · ${esc(F.t("settings.preset_line", { rps: v.rps, timeout: v.timeout }, "{rps}/с · {timeout} с"))}</small></button>`,
    ).join("");
  };
  const updPresets = () => {
    const el = document.getElementById("st-presets");
    if (el) el.innerHTML = presetsHTML();
  };
  F.actions["st-preset"] = id => {
    const p = PRESETS.find(x => x[0] === id);
    if (!p) return;
    const old = { threads: state.net.threads, rps: state.net.rps, timeout: state.net.timeout };
    Object.entries(p[3]).forEach(([k, v]) => set("net." + k, v));
    persist("net");
    F.render(true);
    F.snack(
      F.tp(
        "settings.preset_applied",
        p[3].threads,
        {
          name: F.t(`settings.preset_${p[0]}`, p[1]),
          threads: p[3].threads,
          rps: p[3].rps,
          timeout: p[3].timeout,
        },
        "Пресет «{name}»: {threads} поток, {rps} запр/с, таймаут {timeout} с|Пресет «{name}»: {threads} потока, {rps} запр/с, таймаут {timeout} с|Пресет «{name}»: {threads} потоков, {rps} запр/с, таймаут {timeout} с",
      ),
      {
        action: () => {
          Object.entries(old).forEach(([k, v]) => set("net." + k, v));
          persist("net");
          F.render(true);
        },
      },
    );
  };
  const h3 = (t, extra = "") =>
    `<h3 class="sub-h st-h3">${t}${extra ? `<span class="muted">${extra}</span>` : ""}</h3>`;
  const pg = (page, ...cls) => page.classList.add("st-pg", ...cls);
  const goSafe = path => {
    if (F.routes.some(r => r.rx.test(path))) F.go(path);
    else F.snack(F.t("settings.next_version", "Раздел появится в следующей версии"));
  };

  Object.assign(F.actions, {
    "st-t": (path, el) => {
      const row = el && el.closest(".st-tr");
      if (row && row.classList.contains("st-dis")) return;
      // Turning off the kill switch or the proxy exposes the real IP, so it requires hold-to-confirm.
      if ((path === "net.kill" || path === "net.proxyOn") && get(path)) return confirmNetOff(path);
      if (path === "sec.panic" && !get(path)) return F.actions["st-panic-setup"]();
      // Leaving mobile data without any cap is allowed, after a one-time confirmation.
      if (mobileUnlimitedAfter(path)) return confirmMobileUnlimited(path);
      set(path, !get(path));
      persist(path);
      const tg = el && (el.classList.contains("toggle") ? el : el.querySelector(".toggle"));
      if (tg) F.actions.toggle(null, tg);
      F.state.stRerender !== false && setTimeout(() => F.render(true), 120);
    },
    "st-shots": (_a, el) => {
      const on = !shotsOn();
      F.db.settings = F.db.settings || {};
      F.db.settings.sec = { ...(F.db.settings.sec || {}), block_shots: on };
      F.api.settings_set({ sec: { block_shots: on } });
      const tg = el && (el.classList.contains("toggle") ? el : el.querySelector(".toggle"));
      if (tg) F.actions.toggle(null, tg);
      F.state.stRerender !== false && setTimeout(() => F.render(true), 120);
    },
    "st-set": a => {
      const [path, v] = a.split(/:(.*)/s);
      set(path, /^-?\d+(\.\d+)?$/.test(v) ? +v : v);
      persist(path);
      F.render(true);
    },
    "st-net-off": path => {
      set(path, false);
      persist(path);
      F.closeSheet();
      F.render(true);
      F.snack(
        path === "net.kill"
          ? F.t("settings.kill_off", "Защита от утечки IP выключена")
          : F.t("settings.proxy_off", "Прокси выключен: запросы пойдут с вашего IP"),
        {
          action: () => {
            set(path, true);
            persist(path);
            F.render(true);
          },
        },
      );
    },
    "st-go": path => goSafe(path),
    "st-android": what => {
      // Data values name Android screens in Russian (they are passed to the platform as is).
      const androidL = w =>
        ({
          "Сеть → Частный DNS": F.t("settings.android_0", "Сеть → Частный DNS"),
          Приложения: F.t("settings.android_1", "Приложения"),
          "Контроль активности": F.t("settings.android_2", "Контроль активности"),
          "Другие разрешения": F.t("settings.android_3", "Другие разрешения"),
          Аккумулятор: F.t("settings.android_4", "Аккумулятор"),
          "Ограничения в фоне": F.t("settings.android_5", "Ограничения в фоне"),
          Батарея: F.t("settings.android_6", "Батарея"),
          Уведомления: F.t("settings.android_7", "Уведомления"),
        })[w] || w;
      if (F.isTauri) androidOpen(what);
      else
        F.snack(
          F.t(
            "settings.android_settings",
            { what: androidL(what) || F.t("settings.android_settings_app", "приложение") },
            "Откроются системные настройки Android: {what}",
          ),
        );
    },
  });

  // `true` when toggling `path` would leave scans on mobile data with no traffic limit.
  function mobileUnlimitedAfter(path) {
    const p = state.power;
    const noCap = !p.limOn || !(+p.mobLimit > 0);
    if (path === "power.limOn") return p.limOn && !p.wifiOnly;
    if (path === "power.wifiOnly") return p.wifiOnly && noCap;
    return false;
  }
  function confirmMobileUnlimited(path) {
    F.sheet({
      title: F.t("limits.confirm_title", "Применить рискованное значение?"),
      html: `<div class="banner warn">${ic("alert")}<div><b>${esc(F.t("limits.mob_unlimited", "Мобильный трафик без лимита"))}</b> ${esc(F.limits.warning("power.mob_limit", 0))}</div></div>
        <p class="fhint st-hint">${ic("info")}${esc(F.t("limits.confirm_hint", "Значение сохранится, предупреждение останется у поля. Вернуть безопасное значение можно в любой момент."))}</p>`,
      footer: `<button class="btn" data-act="sheet-close">${esc(F.t("common.cancel", "Отмена"))}</button><button class="btn primary"
        data-act="st-mob-unlim:${path}">${esc(F.t("limits.confirm_apply", "Применить"))}</button>`,
    });
  }
  F.actions["st-mob-unlim"] = path => {
    F.closeSheet();
    set(path, !get(path));
    persist(path);
    F.render(true);
  };
  function confirmNetOff(path) {
    const kill = path === "net.kill";
    F.sheet({
      title: kill
        ? F.t("settings.kill_off_q", "Выключить защиту от утечки IP?")
        : F.t("settings.proxy_off_q", "Выключить прокси?"),
      html: `<div class="banner crit">${ic("alert")}<div><b>${esc(F.t("settings.real_ip_warn", "Запросы сканера пойдут с вашего реального IP."))}</b> ${esc(kill ? F.t("settings.kill_off_warn", "Если VPN или прокси отвалится, скан продолжится напрямую и засветит адрес.") : F.t("settings.proxy_off_warn", "Цель и источники увидят адрес вашего устройства и оператора."))}</div></div>
        <p class="fhint st-hint">${ic("info")}${esc(F.t("settings.hold_hint", "Нажмите и удерживайте «Выключить» 1 секунду. Включить обратно можно в любой момент на этом экране."))}</p>`,
      footer: `<button class="btn"
        data-act="sheet-close">${esc(F.t("common.cancel", "Отмена"))}</button><button class="btn danger hold" data-hold="st-net-off:${path}"
        aria-label="${esc(F.t("settings.turn_off_hold", "Выключить: удерживайте"))}"><span class="hold-fill"></span>${ic("stop")}${esc(F.t("settings.turn_off", "Выключить"))}</button>`,
    });
  }
  // Fingerprint confirmation inside an open sheet (the key sheet must stay open: it holds the typed value).
  // There is one mechanism for the whole app, F.confirmFinger in core.js (N-minute session, "Secrets
  // revealed" indicator).
  F.stConfirmInline = (el, then, what = F.t("settings.show_value", "показать значение")) =>
    F.confirmFinger(then, what, el);

  // ================= ROOT /settings =================
  const keyStats = () => {
    const v = Object.values(state.keys);
    return {
      ok: v.filter(k => k.st === "ok").length,
      err: v.filter(k => k.st === "err").length,
      none: v.filter(k => k.st === "none").length,
    };
  };
  const THEME_L = () => ({
    system: F.t("look.theme_system", "Системная"),
    dark: F.t("look.theme_dark", "Тёмная"),
    light: F.t("look.theme_light", "Светлая"),
  });
  const LANG_L = () => ({
    get AUTO() {
      return systemLabel();
    },
    RU: F.t("look.lang_ru", "Русский"),
    UA: F.t("look.lang_uk", "Українська"),
    EN: F.t("look.lang_en", "English"),
  });
  function renderRoot() {
    const k = keyStats(),
      n = state.net,
      power = state.power,
      sec = state.sec;
    const item = (icon, color, title, sub, path, pill = "") =>
      ui.row({
        lead: ui.leadIcon(icon, color),
        title,
        sub: sub + (pill ? `<div class="st-rpill">${pill}</div>` : ""),
        act: `st-go:${path}`,
      });
    return `
      ${ui.secH(F.t("settings.sec_sources", "Источники данных"))}
      <div class="list">
        ${item("key", "var(--accent)", F.t("settings.keys_opt", "Ключи API (необязательно)"), [F.t("settings.keys_ok", { n: k.ok }, "работают: {n}"), k.err ? F.t("settings.keys_err", { n: k.err }, "с ошибкой: {n}") : "", k.none ? F.t("settings.keys_none", { n: k.none }, "не указаны: {n}") : ""].filter(Boolean).join(" · "), "/settings/keys", k.err ? `<span class="pill bad">${ic("alert")}${esc(F.t("settings.err_pill", "Ошибка"))}</span>` : "")}
        ${item("search", "var(--accent)", F.t("settings.sources", "Источники"), F.t("settings.sources_sub", "Что опрашивает поиск: архивы, поддомены, дорки: без ключа"), "/settings/sources")}
        ${item("globe", "var(--accent)", F.t("settings.crawl", "Обход сайта"), F.t("settings.crawl_sub", "Глубина, лимиты, файлы во внешних хранилищах, фото для EXIF"), "/settings/crawl")}
        ${item("folder", "var(--accent)", F.t("settings.wordlists", "Словари"), F.t("settings.wordlists_sub", "Поиск забытых файлов на сайте: встроенные, большие, свои; скорость и бюджет"), "/settings/wordlists")}
        ${item("st-sig", "var(--ok)", F.t("settings.sigs_ocr", "Базы сигнатур и OCR"), `${F.t("settings.sigs_sub", "ПО, CVE, секреты")} · ${((F.db.settings || {}).ocr || {}).enabled ? F.t("settings.ocr_on", "Офлайн-OCR вкл.") : F.t("settings.ocr_off", "Офлайн-OCR выкл.")}`, "/settings/signatures")}
        ${item("plug", "var(--info)", F.t("settings.plugins", "Плагины"), F.t("settings.plugins_sub", "Дополнительные модули и источники"), "/settings/plugins")}
        ${item("spark", "var(--info)", F.t("settings.ai_item", "ИИ-сводка"), "OpenAI, Anthropic, Gemini, DeepSeek, Grok, Groq, Mistral, OpenRouter…", "/settings/ai")}
      </div>
      ${ui.secH(F.t("settings.sec_net_dev", "Сеть и устройство"))}
      <div class="list">
        ${item("net", "var(--accent)", F.t("settings.network", "Сеть и прокси"), `${n.proxyOn ? (n.orbot ? F.t("settings.via_orbot", "Через Orbot (Tor)") : n.ptype.toUpperCase() + " · " + esc(n.addr)) : F.t("settings.no_proxy", "Без прокси")} · ${plural(n.threads, "settings.pl_thread", "поток", "потока", "потоков")}`, "/settings/network")}
        ${item("st-gauge", "var(--accent)", F.t("settings.power", "Трафик и питание"), `${power.wifiOnly ? F.t("settings.heavy_wifi", "Тяжёлые модули только по Wi-Fi") : F.t("settings.any_net", "Любая сеть")}${power.limOn ? ` · ${F.t("settings.limit_mb", { n: fmtN(power.mobLimit) }, "лимит {n} МБ")}` : ""}`, "/settings/power")}
        ${item("battery", state.battery.excluded ? "var(--ok)" : "var(--warn)", F.t("settings.background", "Работа в фоне"), state.battery.excluded ? F.t("settings.batt_excluded", "Исключено из оптимизации батареи") : F.t("settings.batt_may_stop", "Android может остановить долгий скан"), "/settings/battery", state.battery.excluded ? "" : `<span class="pill warn">${ic("alert")}${esc(F.t("settings.configure", "Настроить"))}</span>`)}
      </div>
      ${ui.secH(F.t("settings.sec_app", "Приложение"))}
      <div class="list">
        ${item("lock", "var(--ok)", F.t("settings.security", "Безопасность"), `${sec.pin ? "PIN" : F.t("settings.no_pin", "Без PIN")}${sec.bio ? " + " + F.t("settings.fingerprint_l", "отпечаток") : ""} · ${sec.autolock === "0" ? F.t("settings.autolock_now", "автоблокировка сразу") : F.t("settings.autolock_min", { n: sec.autolock }, "автоблокировка через {n} мин")}`, "/settings/security")}
        ${item("theme", "", F.t("settings.appearance", "Внешний вид"), F.t("settings.appearance_sub", { theme: THEME_L()[state.look.theme] || state.look.theme, lang: LANG_L()[langLook()] || langLook(), fs: Math.round(curFs() * 100) }), "/settings/appearance")}
        ${item("bug", "", F.t("settings.debug", "Отладка"), F.t("settings.debug_sub", "Журналы, запросы, сбои, устройство"), "/settings/debug")}
        ${item("info", "var(--accent)", F.t("settings.help", "Помощь"), F.t("settings.help_sub", "Офлайн-справка и глоссарий"), "/help")}
        ${item("info", "", F.t("settings.about", "О программе"), `FOCA-rs ${aboutMeta.version || "2.0.0-beta.3"} · GPL-3.0`, "/settings/about", F.betaChip ? F.betaChip() : "")}
      </div>`;
  }
  F.route("/settings", {
    title: () => F.t("settings.title", "Настройки"),
    sub: "FOCA-rs",
    nav: false,
    actions: [],
    hideMini: true,
    render: () =>
      F.withStates(renderRoot, {
        loading: "list",
        error: {
          title: F.t("settings.unavail_title", "Настройки недоступны"),
          text: F.t("settings.unavail_text", "Не удалось прочитать защищённое хранилище. Попробуйте снова."),
        },
        empty: {
          icon: "gear",
          title: F.t("settings.empty_title", "Нет разделов"),
          text: F.t("settings.empty_text", "Разделы настроек появятся после обновления."),
        },
      }),
    mount: page => pg(page),
  });

  // ================= API KEYS =================
  const KEYS = [
    [
      "brave",
      "Brave Search API",
      "Необязательно: ещё один поисковик для дорков, без капч. Brave требует карту: бесплатного тарифа нет, каждый тариф даёт кредит $5 в месяц (около 1000 запросов)",
      "https://brave.com/search/api/",
      "Зарегистрируйтесь на brave.com/search/api, привяжите карту (кредит $5 в месяц покрывает около 1000 запросов) и скопируйте ключ из раздела API Keys. Кончился лимит: источник остановится до следующего месяца.",
    ],
    [
      "searx",
      "SearXNG",
      "Свой экземпляр SearXNG: спрашивается раньше публичных. Можно несколько адресов через запятую",
      "https://docs.searxng.org/admin/installation-docker.html",
      "Поднимите SearXNG (docker) на своём сервере, включите формат json в settings.yml и укажите адрес https://… с публичным именем. Подробнее: docs/user/searxng.md.",
    ],
    [
      "shodan",
      "Shodan",
      "Порты и баннеры без обращения к цели",
      "https://account.shodan.io/",
      "Войдите в account.shodan.io: ключ показан на главной странице аккаунта.",
    ],
    [
      "hibp",
      "Have I Been Pwned",
      "Утечки по e-mail домена",
      "https://haveibeenpwned.com/API/Key",
      "Купите подписку на haveibeenpwned.com/API/Key, ключ придёт на почту.",
    ],
    [
      "vt",
      "VirusTotal",
      "Поддомены, история DNS, файлы",
      "https://www.virustotal.com/gui/my-apikey",
      "Профиль на virustotal.com → API key. Бесплатно: 500 запросов в сутки.",
    ],
    [
      "st",
      "SecurityTrails",
      "История DNS и поддомены",
      "https://securitytrails.com/app/account/credentials",
      "Аккаунт securitytrails.com → Credentials → API Key.",
    ],
    [
      "urlscan",
      "URLScan",
      "Снимки страниц и технологии",
      "https://urlscan.io/user/profile/",
      "urlscan.io → Profile → API Keys → Create new API key.",
    ],
    [
      "censys",
      "Censys",
      "Сертификаты и сервисы",
      "https://search.censys.io/account/api",
      "search.censys.io → Account → API: нужны API ID и Secret через двоеточие.",
    ],
    [
      "github",
      "GitHub",
      "Утечки кода и секретов в репозиториях",
      "https://github.com/settings/tokens",
      "GitHub → Settings → Developer settings → Fine-grained token, только чтение публичных репозиториев.",
    ],
    [
      "otx",
      "AlienVault OTX",
      "Опционально: ускоряет passive DNS и URL-списки",
      "https://otx.alienvault.com/api",
      "otx.alienvault.com → Settings → API Key. Источник работает и без ключа.",
    ],
    [
      "ai",
      "DeepSeek / OpenAI",
      "ИИ-сводка по находкам",
      "https://platform.deepseek.com/api_keys",
      "platform.deepseek.com или platform.openai.com → API keys → Create. В сводку не передаются секреты.",
    ],
  ];
  const mask = v => (v ? "••••" + v.slice(-4) : "");
  const keyStatus = k =>
    k.st === "ok"
      ? `<span class="pill ok">${ic("check")}${esc(F.t("settings.k_works", "Работает"))}</span>`
      : k.st === "err"
        ? `<span class="pill bad">${ic("alert")}${esc(F.t("settings.err_pill", "Ошибка"))}</span>`
        : `<span class="pill mute">${ic("dot")}${esc(F.t("settings.k_not_set", "Не указан"))}</span>`;
  // Quota period: the core and demo use Russian unit abbreviations.
  const perL = p =>
    ({
      ч: F.t("settings.per_hour", "ч"),
      мес: F.t("settings.per_month", "мес"),
      сут: F.t("settings.per_day", "сут"),
    })[p || "мес"] || p;
  const keyLimit = k =>
    k.st === "ok"
      ? k.note
        ? k.note
        : F.t(
            "settings.k_limit",
            { used: fmtN(k.used), lim: fmtN(k.lim), per: perL(k.per) },
            "лимит {used} / {lim} в {per}",
          )
      : k.st === "err"
        ? k.err
        : "";
  function renderKeys() {
    const st = keyStats();
    return `
      <div class="banner info">${ic("shield")}<div>${esc(F.t("settings.keys_banner_a", "Ключи хранятся в защищённом хранилище Android (Keystore) и"))} <b>${esc(F.t("settings.keys_banner_b", "не попадают в экспорт"))}</b>${esc(F.t("settings.keys_banner_c", ", отчёты и резервные копии."))}</div></div>
      ${ui.secH(F.t("settings.services", "Сервисы"), F.t("settings.services_ok", { ok: st.ok, n: KEYS.length }, "работают: {ok} из {n}"))}
      <div class="list st-keys">${KEYS.map(([id, name, what0]) => {
        const what = F.t(`settings.key_${id}_what`, what0);
        const k = state.keys[id];
        return `
        <div class="row tap st-key" data-act="st-key:${id}">
          ${ui.leadIcon("key", k.st === "ok" ? "var(--ok)" : k.st === "err" ? "var(--bad)" : "")}
          <div class="body"><div class="t">${name}</div>
            <div class="st-key-m">${keyStatus(k)}${k.v ? `<span class="mono st-mask">${mask(k.v)}</span>` : ""}</div>
            <div class="s">${esc(keyLimit(k) || what)}</div></div>
          ${ic("chev", "chev")}
        </div>`;
      }).join("")}</div>
      <p class="fhint st-hint">${ic("info")}${esc(F.t("settings.keys_hint", "Ключи необязательны: без них работают поисковики, архивы, поддомены и разведка. Добавили ключ: источник включается сам, отдельно включать его не нужно."))}</p>`;
  }
  F.route("/settings/keys", {
    title: () => F.t("settings.keys", "Ключи API"),
    sub: () => F.t("settings.optional", "Необязательно"),
    nav: false,
    back: true,
    actions: [],
    hideMini: true,
    render: () =>
      F.withStates(renderKeys, {
        loading: "list",
        empty: {
          icon: "key",
          title: F.t("settings.keys_empty_title", "Ключей пока нет"),
          text: F.t(
            "settings.keys_empty_text",
            "Добавьте ключи Shodan, VirusTotal и других сервисов, чтобы расширить разведку.",
          ),
        },
        error: {
          title: F.t("settings.keys_store_title", "Хранилище ключей недоступно"),
          text: F.t(
            "settings.keys_store_text",
            "Android Keystore не ответил. Разблокируйте устройство и повторите.",
          ),
        },
      }),
    mount: page => pg(page),
  });
  let chkT = null;
  // Result of key_check for Brave (monthly quota) and own SearXNG (JSON answer per instance).
  function keyCheckHTML(id, r) {
    const why = {
      rejected: F.t("settings.kc_rejected", "Ключ отклонён (HTTP 401/403)"),
      limit: F.t(
        "settings.kc_limit",
        "Лимит запросов исчерпан (HTTP 429): подождите или проверьте кредит в кабинете",
      ),
      json_off: F.t("settings.kc_json_off", "Экземпляр не отдаёт JSON: включите формат json в settings.yml"),
      bad_url: F.t("settings.kc_bad_url", "Нужен адрес https:// с публичным именем"),
      unreachable: F.t("settings.kc_unreachable", "Сервис не отвечает"),
      nokey: F.t("settings.paste_first", "Сначала вставьте ключ"),
    };
    if (r.ok && id === "brave") {
      const left =
        r.remaining != null && r.limit
          ? " · " +
            F.t(
              "settings.kc_quota",
              { left: fmtN(r.remaining), lim: fmtN(r.limit) },
              "осталось {left} из {lim} запросов в месяц",
            )
          : "";
      return `<span class="ok">${ic("check")}${esc(F.t("settings.key_works", "Ключ работает") + left)}</span>`;
    }
    if (id === "searx" && Array.isArray(r.instances) && r.instances.length) {
      return r.instances
        .map(x =>
          x.ok
            ? `<span class="ok">${ic("check")}${esc(x.url)}: ${esc(F.t("settings.kc_searx_ok", { n: x.results || 0 }, "отвечает JSON, результатов: {n}"))}</span>`
            : `<span class="bad">${ic("alert")}${esc(x.url)}: ${esc(why[x.code] || (x.status ? "HTTP " + x.status : x.code))}</span>`,
        )
        .join("<br>");
    }
    return `<span class="bad">${ic("alert")}${esc(why[r.code] || (r.status ? "HTTP " + r.status : r.code || "?"))}</span>`;
  }
  Object.assign(F.actions, {
    "st-key": id => {
      const [, name, what0, , how0] = KEYS.find(k => k[0] === id);
      const what = F.t(`settings.key_${id}_what`, what0),
        how = F.t(`settings.key_${id}_how`, how0);
      const k = state.keys[id];
      F.sheet({
        title: name,
        cls: "st-sheet",
        html: `<p class="lead st-klead">${esc(what)}</p>
          <label class="flabel" for="st-kv">${esc(id === "searx" ? F.t("settings.searx_urls", "Адреса экземпляров") : F.t("settings.api_key", "Ключ API"))}</label>
          <div class="field st-kfield" data-secret-wrap>${ic("key")}<input id="st-kv"
            data-secret-input type="password" value="${esc(k.v)}" placeholder="${esc(F.t("settings.paste_key_ph", "Вставьте ключ"))}"
            autocomplete="off" autocapitalize="off" spellcheck="false"><button class="ib" data-act="st-kpaste"
            aria-label="${esc(F.t("settings.paste_clip", "Вставить из буфера"))}">${ic("paste")}</button><button class="ib" data-act="st-keye"
            aria-label="${esc(F.t("settings.show_key", "Показать ключ"))}">${ic("eye")}</button></div>
          <div id="st-kres"
            class="st-kres">${k.st === "ok" ? `<span class="ok">${ic("check")}${esc(keyLimit(k))}</span>` : k.st === "err" ? `<span class="bad">${ic("alert")}${esc(k.err)}</span>` : ""}</div>
          <button class="btn tonal block st-kcheck"
            data-act="st-kcheck:${id}">${ic("refresh")}${esc(id === "searx" ? F.t("settings.test_searx", "Проверить экземпляры") : F.t("settings.check_key", "Проверить ключ"))}</button>
          <div class="srow st-khow"
            data-act="st-khow:${id}">${ic("link")}<span class="lbl">${esc(F.t("settings.how_get_key", "Как получить ключ"))}<small>${esc(how)}</small></span>${ic("open")}</div>`,
        footer: `${
          k.v
            ? `<button class="btn danger-o st-danger-t"
          data-act="st-kdel:${id}">${ic("x")}${esc(F.t("common.delete", "Удалить"))}</button>`
            : `<button class="btn"
          data-act="sheet-close">${esc(F.t("common.cancel", "Отмена"))}</button>`
        }<button class="btn primary"
          data-act="st-ksave:${id}">${ic("check")}${esc(F.t("common.save", "Сохранить"))}</button>`,
        onClose: () => clearTimeout(chkT),
      });
    },
    "st-kpaste": async () => {
      const r = await F.clipRead();
      const t = r.text.trim();
      const i = document.getElementById("st-kv");
      // The browser demo has no clipboard access by default: a sample key stands in.
      if (!t && !F.isDemo) {
        F.snack(
          r.ok
            ? F.t("settings.clip_empty", "Буфер обмена пуст")
            : F.t("settings.clip_unreadable", "Не удалось прочитать буфер обмена: вставьте ключ вручную"),
        );
        return;
      }
      if (!i) return;
      i.value = t || "hP3xN8qL2vR7tY0wK5zab9";
      // The key must not stay in the clipboard after it has been pasted.
      const cleared = t ? await F.clipClear() : false;
      F.snack(
        cleared
          ? F.t("settings.pasted_cleared", "Вставлено из буфера · буфер очищен")
          : F.t("settings.pasted", "Вставлено из буфера"),
      );
    },
    "st-keye": (_, el) => {
      const i = document.getElementById("st-kv");
      const show = i.type === "password";
      const flip = () => {
        i.type = show ? "text" : "password";
        el.innerHTML = ic(show ? "eye-off" : "eye");
        el.setAttribute(
          "aria-label",
          show ? F.t("settings.hide_key", "Скрыть ключ") : F.t("settings.show_key", "Показать ключ"),
        );
      };
      if (show) F.stConfirmInline(el, flip, F.t("settings.show_api_key", "показать ключ API"));
      else flip();
    },
    "st-kcheck": (id, el) => {
      const value = document.getElementById("st-kv").value.trim();
      const res = document.getElementById("st-kres");
      if (!value) {
        res.innerHTML = `<span class="bad">${ic("alert")}${esc(F.t("settings.paste_first", "Сначала вставьте ключ"))}</span>`;
        return;
      }
      el.disabled = true;
      el.innerHTML = `${ic("spin", "spin")}${esc(F.t("settings.checking", "Проверяем…"))}`;
      res.innerHTML = "";
      clearTimeout(chkT);
      chkT = setTimeout(() => {
        // Brave and own SearXNG are checked by the core with a real request.
        if (id === "brave" || id === "searx") {
          const saved = state.keys[id] && state.keys[id].v === value;
          Promise.resolve(F.api.key_check(id, saved && !F.isDemo ? "" : value)).then(
            r => {
              res.innerHTML = keyCheckHTML(id, r || {});
              el.disabled = false;
              el.innerHTML = `${ic("refresh")}${esc(F.t("settings.check_again", "Проверить ещё раз"))}`;
            },
            e => {
              res.innerHTML = `<span class="bad">${ic("alert")}${esc(e.message || String(e))}</span>`;
              el.disabled = false;
              el.innerHTML = `${ic("refresh")}${esc(F.t("settings.check_again", "Проверить ещё раз"))}`;
            },
          );
          return;
        }
        if (!F.isDemo) {
          // The core has no separate key check: validate the format now, the key itself on the first
          // scan request.
          res.innerHTML =
            value.length < 8
              ? `<span class="bad">${ic("alert")}${esc(F.t("settings.too_short", "Слишком короткий ключ"))}</span>`
              : `<span class="ok">${ic("check")}${esc(F.t("settings.format_ok", "Формат подходит: сервис проверит ключ при первом запросе скана"))}</span>`;
          el.disabled = false;
          el.innerHTML = `${ic("refresh")}${esc(F.t("settings.check_again", "Проверить ещё раз"))}`;
          return;
        }
        const bad =
          (state.keys[id] && state.keys[id].st === "err" && value === state.keys[id].v) || value.length < 12;
        const k = state.keys[id] || {};
        res.innerHTML = bad
          ? `<span class="bad">${ic("alert")}${value.length < 12 ? F.t("settings.bad_format", "Неверный формат ключа") : esc(k.err || F.t("settings.revoked_demo", "401 Unauthorized: ключ отозван"))}</span>`
          : `<span class="ok">${ic("check")}${esc(F.t("settings.key_works", "Ключ работает"))}${k.note ? " · " + esc(k.note) : k.lim ? esc(" · " + F.t("settings.key_avail", { left: fmtN(Math.max(0, k.lim - (k.used || 0))), lim: fmtN(k.lim), req: k.lim % 10 === 1 && k.lim % 100 !== 11 ? F.t("settings.req_gen_one", "запроса") : F.t("settings.req_gen_many", "запросов"), per: perL(k.per) }, "доступно {left} из {lim} {req} в {per}")) : ""}</span>`;
        el.disabled = false;
        el.innerHTML = `${ic("refresh")}${esc(F.t("settings.check_again", "Проверить ещё раз"))}`;
      }, 1300);
    },
    // Opens the provider page in the system browser (platform_open_url); when the platform cannot open it,
    // falls back to copying the link (like external links in findings).
    "st-khow": id => {
      const [, , , url] = KEYS.find(k => k[0] === id);
      if (F.isDemo)
        return F.snack(
          F.t(
            "settings.open_in_browser",
            { url: url.replace(/^https:\/\//, "") },
            "Откроется в браузере: {url}",
          ),
        );
      const copyLink = () => {
        F.clipWrite(url);
        F.snack(
          F.t(
            "settings.link_copied",
            { url: url.replace(/^https:\/\//, "") },
            "Ссылка скопирована: откройте её в браузере: {url}",
          ),
          {
            ms: 6000,
          },
        );
      };
      // Only the app has a system browser to hand the link to; the browser build keeps the copy.
      if (!F.isTauri || !F.api || typeof F.api.open_url !== "function") return copyLink();
      let p;
      try {
        p = F.api.open_url(url);
      } catch (e) {
        return copyLink();
      }
      Promise.resolve(p).then(r => {
        if (r && r.ok === false) copyLink();
      }, copyLink);
    },
    "st-ksave": id => {
      const keySnack = id =>
        (F.SOURCE_LIST || []).some(x => x[0] === id && x[2] === "key")
          ? F.t("settings.key_saved_on", "Ключ сохранён: источник включён")
          : F.t("settings.key_saved", "Ключ сохранён в защищённом хранилище");
      const value = document.getElementById("st-kv").value.trim();
      const k = state.keys[id];
      if (!value) {
        F.snack(F.t("settings.key_empty", "Ключ пустой: нечего сохранять"));
        return;
      }
      const changed = value !== k.v;
      // The field shows the saved key's mask (the core never returns the value): with no changes there is
      // nothing to
      // save, otherwise the mask would overwrite the key.
      if (!changed && !F.isDemo) {
        F.closeSheet();
        return;
      }
      if (!F.isDemo) {
        F.api.key_set(id, value).then(
          () => {
            if (F.sourceKeyAdded) F.sourceKeyAdded(id);
            F.render(true);
            F.snack(keySnack(id));
          },
          e => F.snack(F.t("settings.key_save_fail", "Не удалось сохранить ключ: ") + (e.message || e)),
        );
        F.closeSheet();
        return;
      }
      k.v = value;
      if (changed) Object.assign(k, { st: "ok", used: 0, lim: k.lim || 1000, err: "" });
      F.api.key_set(id, value); // Single key status shared by the wizard, the scan and the data screens.
      if (F.sourceKeyAdded) F.sourceKeyAdded(id); // Adding a key enables the source automatically.
      F.closeSheet();
      F.render(true);
      F.snack(keySnack(id));
    },
    "st-kdel": id => {
      const k = state.keys[id];
      // No Undo: the core deletes the key from secure storage and the UI only ever holds its mask.
      Object.assign(k, { v: "", st: "none" });
      F.api.key_delete(id);
      F.closeSheet();
      F.render(true);
      F.snack(F.t("settings.key_deleted", "Ключ удалён"));
    },
  });
  /** API key sheet on top of any screen (launch wizard, scan sources): F.openKeySheet("censys"). */
  F.openKeySheet = service => {
    if (!KEYS.some(k => k[0] === service)) {
      F.snack(F.t("settings.unknown_service", "Неизвестный сервис: ") + service);
      return;
    }
    F.actions["st-key"](service);
  };

  // ================= NETWORK =================
  // Profiles as in the core (foca-net::ua): the Chrome/Firefox version is derived from the date (every 4
  // weeks,
  // every 2 since 2026-08); the core's fresh net.ua_versions cache takes precedence.
  const UA_CH = [
      [133, "2025-02-04", 28],
      [145, "2026-01-28", 28],
      [152, "2026-08-12", 14],
    ],
    UA_FF = [
      [135, "2025-02-04", 28],
      [147, "2026-01-13", 28],
      [154, "2026-08-18", 14],
    ];
  const uaMajor = (an, t) => {
    let a = an[0];
    an.forEach(x => {
      if (Date.parse(x[1]) <= t) a = x;
    });
    return a[0] + Math.floor(Math.max(0, t - Date.parse(a[1])) / 864e5 / a[2]);
  };
  function uaStr(id, custom) {
    const now = Date.now(),
      cache = (F.db.settings.net || {}).ua_versions || {},
      fresh = cache.fetched > 0 && now / 1000 - cache.fetched < 7 * 86400;
    const pick = (v, calc) => (v ? (fresh ? v : Math.max(v, calc)) : calc);
    const ch = pick(cache.chrome, uaMajor(UA_CH, now)),
      ff = pick(cache.firefox, uaMajor(UA_FF, now));
    const date = new Date(now),
      year = date.getUTCFullYear(),
      sept = date >= new Date(Date.UTC(year, 8, 15));
    const sf = date < new Date(Date.UTC(2025, 8, 15)) ? "18.3" : 26 + (year - 2025) - (sept ? 0 : 1) + ".0";
    return {
      chrome: [
        F.t("settings.ua_auto", { v: ch }, "Авто: свежий Chrome {v} · Windows"),
        `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${ch}.0.0.0 Safari/537.36`,
      ],
      chrome_android: [
        `Chrome ${ch} · Android`,
        `Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${ch}.0.0.0 Mobile Safari/537.36`,
      ],
      firefox: [
        `Firefox ${ff} · Windows`,
        `Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:${ff}.0) Gecko/20100101 Firefox/${ff}.0`,
      ],
      safari: [
        `Safari ${sf.replace(/\.0$/, "")} · macOS`,
        `Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/${sf} Safari/605.1.15`,
      ],
      honest: [F.t("settings.ua_honest", "Честный FOCA-rs"), "FOCA-rs/" + (F.APP_VERSION || "2.0.0-beta.3")],
      custom: [F.t("settings.custom", "Свой"), custom || ""],
    }[id];
  }
  const UA_IDS = ["chrome", "chrome_android", "firefox", "safari", "honest", "custom"];
  const uaCur = v =>
    ({ auto: "chrome", random: "chrome", foca: "honest" })[v] || (UA_IDS.includes(v) ? v : "chrome"); // Legacy values stay compatible.
  const ipKindLabel = k =>
    ({
      tor: "Tor",
      datacenter: F.t("settings.ip_dc", "дата-центр"),
      vpn: "VPN",
      residential: F.t("settings.ip_res", "домашний / ISP"),
      unknown: F.t("settings.ip_unknown", "тип не определён"),
    })[k] || k;
  // The Orbot profile hides the address field, so it applies only with the Orbot flag set: the core's default
  // settings carry `preset: "orbot"` with `orbot: false`, and a proxy enabled over the API (address only) must
  // stay visible and editable.
  const proxyPresetOf = n =>
    n.preset === "orbot" && !n.orbot ? "custom" : n.preset || (n.orbot ? "orbot" : "custom");
  function renderNet() {
    const n = state.net;
    const pPreset = proxyPresetOf(n);
    const grp = n.groups || { search: "", recon: "", target: "" };
    return `
      ${h3(F.t("settings.proxy", "Прокси"))}
      <div class="list">
        ${tRow("net.proxyOn", F.t("settings.use_proxy", "Использовать прокси"), F.t("settings.use_proxy_sub", "Весь HTTP/TCP трафик сканера идёт через выбранный прокси"), ui.leadIcon("shield", n.proxyOn ? "var(--ok)" : ""))}
        ${
          n.proxyOn
            ? `<div class="st-in">
          <div class="st-pad">
            <div class="seg st-seg" role="radiogroup" aria-label="${esc(F.t("settings.proxy_profile", "Профиль прокси"))}">${[
              ["orbot", "Orbot (Tor)"],
              ["v2ray", "v2rayNG"],
              ["custom", F.t("settings.custom", "Свой")],
            ]
              .map(
                ([v, l]) => `<button class="${pPreset === v ? "on" : ""}" role="radio"
                  aria-checked="${pPreset === v}" data-act="st-ppreset:${v}">${l}</button>`,
              )
              .join("")}</div>
            ${
              pPreset === "orbot"
                ? `<p class="fhint">${esc(n.orbot ? F.t("settings.orbot_line", "SOCKS5 127.0.0.1:9050 · приложение Orbot") : F.t("settings.orbot_hint", "Укажите Orbot или переключитесь на другой профиль"))}</p>`
                : pPreset === "v2ray"
                  ? `<p class="fhint">${esc(F.t("settings.v2ray_hint", "Внешний локальный прокси v2rayNG в режиме proxy-only (по умолчанию SOCKS5 127.0.0.1:10808; встроенного клиента нет)."))}</p>`
                  : ""
            }
          </div>
          ${
            pPreset === "orbot"
              ? ""
              : `<div class="st-pad">${seg(
                  "net.ptype",
                  [
                    ["http", "HTTP"],
                    ["socks5", "SOCKS5"],
                  ],
                  F.t("settings.proxy_type", "Тип прокси"),
                )}
            <label class="flabel" for="st-paddr">${esc(F.t("settings.addr_port", "Адрес и порт"))}</label>
            <div class="field">${ic("server")}<input id="st-paddr" data-path="net.addr"
              value="${esc(n.addr)}" placeholder="${pPreset === "v2ray" ? "127.0.0.1:10808" : "host:port"}" autocapitalize="off" spellcheck="false"
              inputmode="url"></div></div>`
          }
          <div class="st-pad">
            <label class="flabel">${esc(F.t("settings.group_proxy", "Прокси по группам HTTP-источников (опционально)"))}</label>
            <label class="flabel st-sublabel" for="st-grp-search">${esc(F.t("settings.grp_search_l", "Поиск"))}</label>
            <div class="field"><input id="st-grp-search" data-path="net.groups.search"
              value="${esc(grp.search || "")}" placeholder="${esc(F.t("settings.grp_search_ph", "socks5h://127.0.0.1:10808 или direct"))}"
              autocapitalize="off" spellcheck="false" inputmode="url"></div>
            <label class="flabel st-sublabel" for="st-grp-recon">${esc(F.t("settings.grp_recon_l", "Разведка"))}</label>
            <div class="field"><input id="st-grp-recon" data-path="net.groups.recon"
              value="${esc(grp.recon || "")}" placeholder="${esc(F.t("settings.grp_recon_ph", "пусто = общий прокси"))}"
              autocapitalize="off" spellcheck="false" inputmode="url"></div>
            <label class="flabel st-sublabel" for="st-grp-target">${esc(F.t("settings.grp_target_l", "Запросы к цели"))}</label>
            <div class="field"><input id="st-grp-target" data-path="net.groups.target"
              value="${esc(grp.target || "")}" placeholder="${esc(F.t("settings.grp_target_ph", "пусто = общий прокси"))}"
              autocapitalize="off" spellcheck="false" inputmode="url"></div>
            <p class="fhint">${ic("info")}${esc(F.t("settings.grp_hint", "Группы задают отдельный прокси для разных HTTP-источников. Встроенный браузер для дорков использует один общий прокси на всё приложение (ограничение Android)."))}</p>
          </div>
          <div class="st-pad st-pchk">
            <button class="btn tonal block" data-act="st-pcheck">${ic("refresh")}${esc(F.t("settings.check_proxy", "Проверить прокси и сеть"))}</button>
            <button class="btn block st-mt" data-act="st-gpcheck">${ic("server")}${esc(F.t("settings.check_proxy_addr", "Проверить прокси по указанному адресу"))}</button>
            <div class="st-kres" id="st-pres"></div>
          </div>
        </div>`
            : ""
        }
        ${tRow("net.kill", F.t("settings.kill_title", "Защита от утечки IP"), (F.db.settings.net || {}).kill_action === "pause" ? F.t("settings.kill_pause", "Если VPN или прокси отвалился, скан встаёт на паузу, чтобы не засветить реальный IP") : F.t("settings.kill_stop", "Если VPN или прокси отвалился, скан останавливается, продолжить можно после восстановления туннеля"), ui.leadIcon("stop", n.kill ? "var(--crit)" : ""))}
      </div>

      ${h3("User-Agent")}
      <div class="list st-radios" role="radiogroup" id="st-ualist">${UA_IDS.map(id => {
        const on = uaCur(n.ua) === id,
          t = uaStr(id)[0];
        return `
        <div class="row tap st-radio ${on ? "on" : ""}" role="radio" aria-checked="${on}"
          data-act="st-set:net.ua:${id}"><span class="radio st-rb"></span><div class="body"><div class="t">${t}</div></div></div>`;
      }).join("")}</div>
      ${
        uaCur(n.ua) === "custom"
          ? `<div class="field st-uaf">${ic("st-ua")}<input id="st-uac"
        data-path="net.uaCustom" value="${esc(n.uaCustom)}" placeholder="${esc(F.t("settings.ua_ph", "Строка User-Agent"))}"
        autocapitalize="off" spellcheck="false"></div>`
          : ""
      }
      <div class="st-pad"><div class="s">${esc(F.t("settings.ua_final", "Итоговая строка"))}${uaCur(n.ua) === "honest" || uaCur(n.ua) === "custom" ? "" : esc(" · " + (uaCur(n.ua).startsWith("chrome") ? F.t("settings.ua_hdrs_ch", "с ней: согласованные Accept, Accept-Language и Sec-CH-UA") : F.t("settings.ua_hdrs", "с ней: согласованные Accept, Accept-Language")))}:</div><div class="s mono"
        id="st-uafinal">${esc(uaStr(uaCur(n.ua), n.uaCustom)[1] || "-")}</div><div class="s">${esc(F.t("settings.ua_webview", "Встроенный браузер (поисковики): настоящая версия WebView"))}</div></div>

      ${h3(F.t("settings.speed", "Скорость"))}
      <div class="nf-pre" id="st-presets" role="radiogroup"
        aria-label="${esc(F.t("settings.speed_preset", "Пресет скорости"))}">${presetsHTML()}</div>
      <div class="card nfs st-nfs">
        ${nf("net.threads", F.t("settings.threads", "Потоков"), "", "net.threads", F.t("settings.threads_note", "больше: риск бана"), "set-threads", 1, { whyMin: F.t("settings.threads_min", "нужен хотя бы один поток") })}
        ${nf("net.rps", F.t("settings.rps", "Запросов в сек."), F.t("settings.unit_per_s", "/с"), "net.rps", F.t("settings.rps_note", "общий предел на все источники"), "set-rps")}
        ${nf("net.hostsParallel", F.t("settings.hosts_parallel", "Хостов одновременно"), "", "net.hosts_parallel", F.t("settings.hosts_parallel_note", "1: по очереди"), "set-hosts-parallel", 1, { whyMin: F.t("settings.hosts_parallel_min", "нужен хотя бы один хост") })}
        ${nf("net.timeout", F.t("settings.timeout", "Таймаут"), F.t("settings.unit_s", "с"), "net.timeout", F.t("settings.timeout_note", "для Tor: 60"), "set-timeout")}
        ${nf("net.retries", F.t("settings.retries", "Повторов"), "", "net.retries", F.t("settings.retries_note", "при обрыве"), "set-retries")}
      </div>
      <p class="fhint st-hint">${ic("info")}${esc(F.t("settings.nf_hint", "Нажмите на число: откроется клавиатура. Значение применяется, когда вы уходите из поля или нажимаете «Готово». Выше рекомендованного: предупреждение у поля, рискованные значения нужно подтвердить."))}</p>

      ${h3("DNS")}
      <div class="kv">
        <div class="kvr"><div class="k">${esc(F.t("settings.resolver", "Резолвер"))}</div><div class="v">${n.dns === "custom" && n.dnsCustom ? `<span class="mono">${esc(n.dnsCustom)}</span>` : F.t("settings.resolver_sys", "Системный резолвер Android")}</div></div>
      </div>
      <div class="banner info st-dnsw">${ic("info")}<div><b>${esc(F.t("settings.pdns_b", "Если включён «Частный DNS» Android"))}</b>${esc(F.t("settings.pdns_text", ", он влияет только на системный резолвер (обычные запросы имён через DNS-over-TLS). Перенос зоны (AXFR) и запросы к NS цели сканер делает своим DNS-клиентом напрямую. По TCP/UDP 53, мимо «Частного DNS». Такие запросы может блокировать мобильный оператор, публичный Wi-Fi или VPN: если AXFR не проходит, проверьте сеть или туннель."))}</div></div>
      ${seg(
        "net.dns",
        [
          ["system", F.t("settings.sys", "Системный")],
          ["custom", F.t("settings.custom_resolver", "Свой резолвер")],
        ],
        F.t("settings.resolver", "Резолвер"),
      )}
      ${
        n.dns === "custom"
          ? `<div class="field">${ic("domain")}<input data-path="net.dnsCustom"
        value="${esc(n.dnsCustom)}" placeholder="${esc(F.t("settings.resolver_ip_ph", "IP резолвера"))}" inputmode="decimal"></div>`
          : ""
      }
      <button class="btn block st-mt"
        data-act="st-android:Сеть → Частный DNS">${ic("open")}${esc(F.t("settings.open_android", "Открыть настройки Android"))}</button>
      ${portsSettings()}
      ${h3(F.t("settings.engines", "Поисковики (дорки)"))}
      <div class="card pad st-prep"><p class="muted">${esc(F.t("settings.prep_text", "Откроет Startpage, Brave, Yahoo и Mojeek по очереди в видимом окне. Если поисковик попросит проверку или согласие на cookies, пройдите их сами. Куки сохранятся, и дорки в сканах дольше пойдут без капчи. Автоматического решения капчи нет."))}</p>
        <button class="btn block tonal"
          data-act="st-prep-engines">${ic("search")}${esc(F.t("settings.prep_engines", "Подготовить поисковики"))}</button>
        <button class="btn block st-mt"
          data-act="st-captcha-test">${ic("shield")}${esc(F.t("settings.captcha_test", "Проверить капчу движка (ручной тест)"))}</button>
        <div class="st-kres" id="st-cap-res"></div>
        <p class="fhint">${ic("info")}${esc(F.t("settings.captcha_hint", "Ручной разовый тест выбранного движка (не запускается автоматически перед сканом, чтобы не тратить лимиты IP)."))}</p></div>`;
  }
  // Port scan (active ports module, Full profile): top 100 / top 1000 / custom list, settings.ports.
  const PS = () => Object.assign({ top: 100, list: "", max_hosts: 20 }, (F.db.settings || {}).ports || {});
  function portsSettings() {
    const ports = PS(),
      mode = ports.top >= 1000 ? 1000 : ports.top === 0 ? 0 : 100;
    return `${h3(F.t("settings.portscan", "Скан портов"))}
      <p class="fhint">${esc(F.t("settings.ports_hint", { n: ports.max_hosts }, "Только профиль «Полный» (или «Свой» с модулем «Скан портов») и только живые хосты из скоупа, до {n} за скан. Мастер запуска может выбрать топ-100/1000 для одного скана."))}</p>
      <div class="seg" role="radiogroup" aria-label="${esc(F.t("settings.ports_default", "Порты по умолчанию"))}">${[
        [100, F.t("settings.top100", "Топ-100")],
        [1000, F.t("settings.top1000", "Топ-1000")],
        [0, F.t("settings.own_list", "Свой список")],
      ]
        .map(
          ([v, t]) =>
            `<button class="${mode === v ? "on" : ""}" role="radio" aria-checked="${mode === v}"
              data-act="st-ports-top:${v}">${t}</button>`,
        )
        .join("")}</div>
      ${
        mode === 0
          ? `<div class="field st-mt">${ic("server")}<input id="st-ports-list"
        value="${esc(ports.list || "")}" placeholder="22,80,443,8000-8100" inputmode="text"
          autocapitalize="off"
        spellcheck="false"
        aria-label="${esc(F.t("settings.own_ports_aria", "Свой список портов"))}"></div><p class="fhint">${esc(F.t("settings.ports_list_hint", "Через запятую, диапазоны. Через дефис (не больше 65535 портов)."))}</p>`
          : ""
      }`;
  }
  F.actions["st-ports-top"] = v => {
    F.api.settings_set({ ports: { top: +v } }).then(() => F.render(true));
  };
  document.addEventListener("change", e => {
    if (e.target && e.target.id === "st-ports-list")
      F.api.settings_set({ ports: { list: e.target.value.trim() } });
  });
  F.route("/settings/network", {
    title: () => F.t("settings.network", "Сеть и прокси"),
    sub: () => F.t("settings.title", "Настройки"),
    nav: false,
    back: true,
    actions: [],
    hideMini: true,
    render: () => F.withStates(renderNet, { loading: "cards" }),
    mount: page => {
      pg(page);
      bindInputs(page);
    },
  });
  function bindInputs(page) {
    page.querySelectorAll("input[data-path]").forEach(i =>
      i.addEventListener("input", () => {
        set(i.dataset.path, i.value);
        persist(i.dataset.path, 500);
        if (i.id === "st-uac") {
          const f = document.getElementById("st-uafinal");
          if (f) f.textContent = i.value || "-";
        }
      }),
    );
  }
  // "Prepare search engines": opens each dork engine in a visible window one by one (to get cookies in
  // advance).
  const PREP = [
    ["https://www.startpage.com/", "Startpage"],
    ["https://search.brave.com/", "Brave Search"],
    ["https://search.yahoo.com/", "Yahoo"],
    ["https://www.mojeek.com/", "Mojeek"],
  ];
  F.actions["st-prep-engines"] = async () => {
    let n = 0;
    const missed = [];
    for (const [url, name] of PREP) {
      let res;
      try {
        res = await F.api.platform_verify_search({
          url,
          title: F.t(
            "settings.prep_title",
            { name, i: n + missed.length + 1, n: PREP.length },
            "{name} ({i} из {n})",
          ),
        });
      } catch (e) {
        F.snack(F.t("settings.engine_open_fail", "Не удалось открыть поисковик: ") + (e.message || e));
        return;
      }
      const state = F.verifyState(res);
      if (state === "unsupported") {
        F.snack(
          (res && res.error) ||
            F.t("settings.prep_phone_only", "Подготовить поисковики можно только в приложении на телефоне"),
        );
        return;
      }
      // Only a solved page counts; Cancel stops the whole round.
      if (state === "cancelled") {
        F.snack(F.t("settings.prep_cancelled", { n }, "Подготовка прервана. Подготовлено поисковиков: {n}"), {
          ms: 5000,
        });
        return;
      }
      if (state === "done") n++;
      else missed.push(name);
    }
    F.snack(
      missed.length
        ? F.t(
            "settings.prep_partial",
            { n, total: PREP.length, names: missed.join(", ") },
            "Подготовлено поисковиков: {n} из {total}. Не прошли проверку: {names}",
          )
        : F.t("settings.prep_done", { n }, "Поисковиков подготовлено: {n}, куки сохранены"),
      { ms: 5000 },
    );
  };
  F.actions["st-ppreset"] = p => {
    if (p === "orbot") {
      set("net.preset", "orbot");
      set("net.orbot", true);
      set("net.ptype", "socks5");
      set("net.addr", "127.0.0.1:9050");
      set("net.label", "Orbot (Tor)");
    } else if (p === "v2ray") {
      set("net.preset", "v2ray");
      set("net.orbot", false);
      set("net.ptype", "socks5");
      set("net.addr", "127.0.0.1:10808");
      set("net.label", "v2rayNG");
    } else {
      set("net.preset", "custom");
      set("net.orbot", false);
      if (state.net.label === "Orbot (Tor)" || state.net.label === "v2rayNG") {
        set("net.label", F.t("settings.own_proxy", "Свой прокси"));
      }
    }
    persist("net");
    F.render(true);
  };
  F.actions["st-captcha-test"] = async (_, el) => {
    const out = document.getElementById("st-cap-res");
    el.disabled = true;
    el.innerHTML = `${ic("spin", "spin")}${esc(F.t("settings.checking_sp", "Проверяем Startpage…"))}`;
    if (out) out.innerHTML = "";
    try {
      const r = await F.api.search_captcha_test({ engine: "startpage" });
      if (!el.isConnected) return;
      el.disabled = false;
      el.innerHTML = `${ic("shield")}${esc(F.t("settings.captcha_test", "Проверить капчу движка (ручной тест)"))}`;
      if (!r || !r.supported) {
        if (out)
          out.innerHTML = `<span class="bad">${ic("alert")}${esc((r && r.error) || F.t("settings.webview_only", "Доступно только в Android WebView"))}</span>`;
        return;
      }
      const cls = r.kind === "results" ? "ok" : "bad";
      const lbl =
        {
          results: F.t("settings.cap_results", "Выдача доступна"),
          verify: F.t("settings.cap_verify", "JS-проверка"),
          captcha: F.t("settings.cap_captcha", "Показана капча"),
          blocked: F.t("settings.cap_blocked", "IP заблокирован"),
        }[r.kind] || r.kind;
      if (out) {
        out.innerHTML = `<span class="${cls}">${ic(r.kind === "results" ? "check" : "alert")}${esc(r.engine)}: ${esc(lbl)}${r.status ? " (HTTP " + esc(r.status) + ")" : ""}</span>`;
      }
    } catch (e) {
      if (!el.isConnected) return;
      el.disabled = false;
      el.innerHTML = `${ic("shield")}${esc(F.t("settings.captcha_test", "Проверить капчу движка (ручной тест)"))}`;
      if (out) out.innerHTML = `<span class="bad">${ic("alert")}${esc(e.message || e)}</span>`;
    }
  };
  F.actions["st-gpcheck"] = (_, el) => {
    const res = document.getElementById("st-pres");
    el.disabled = true;
    el.innerHTML = `${ic("spin", "spin")}${esc(F.t("settings.checking_addr", "Проверяем адрес…"))}`;
    if (res) res.innerHTML = "";
    F.api
      .net_proxy_check({ type: state.net.ptype, addr: state.net.addr })
      .then(r => {
        if (!el.isConnected) return;
        el.disabled = false;
        el.innerHTML = `${ic("server")}${esc(F.t("settings.check_proxy_addr", "Проверить прокси по указанному адресу"))}`;
        if (res) {
          res.innerHTML = r.ok
            ? `<span class="ok">${ic("check")}<b class="mono">${esc(r.out_ip || "-")}</b> · ${esc(r.country || "-")} · ${esc(r.latency_ms)} ${esc(F.t("settings.ms", "мс"))} · ${esc(ipKindLabel(r.ip_kind))}${r.org ? " (" + esc(r.org) + ")" : ""}</span>`
            : `<span class="bad">${ic("alert")}${esc(r.error || F.t("settings.proxy_noresp", "Прокси не отвечает"))}</span>`;
        }
      })
      .catch(e => {
        if (!el.isConnected) return;
        el.disabled = false;
        el.innerHTML = `${ic("server")}${esc(F.t("settings.check_proxy_addr", "Проверить прокси по указанному адресу"))}`;
        if (res) res.innerHTML = `<span class="bad">${ic("alert")}${esc(e.message || e)}</span>`;
      });
  };
  let pT = null;
  F.actions["st-pcheck"] = (_, el) => {
    const res = document.getElementById("st-pres");
    el.disabled = true;
    el.innerHTML = `${ic("spin", "spin")}${esc(F.t("settings.checking", "Проверяем…"))}`;
    res.innerHTML = "";
    clearTimeout(pT);
    pT = setTimeout(() => {
      F.api
        .net_check()
        .then(r => {
          if (!el.isConnected) return;
          el.disabled = false;
          el.innerHTML = `${ic("refresh")}${esc(F.t("settings.check_again", "Проверить ещё раз"))}`;
          if (r.ok) {
            const cFlags = [];
            if (r.canary && r.canary.tcp_intercept)
              cFlags.push(F.t("settings.tcp_intercept", "TCP-перехват"));
            if (r.canary && r.canary.dns_hijack) cFlags.push(F.t("settings.dns_hijack", "подмена DNS"));
            if (r.canary && r.canary.tls_mitm) cFlags.push("TLS MITM");
            const cw = cFlags.length ? ` · ⚠ ${cFlags.join(", ")}` : "";
            res.innerHTML = `<span class="ok">${ic("check")}${esc(F.t("settings.works_exit_ip", "Работает · выходной IP"))} <b class="mono">${esc(r.out_ip)}</b> · ${esc(r.country || "-")} · ${esc(r.via)} · ${esc(r.latency_ms ?? "-")} ${esc(F.t("settings.ms", "мс"))} · ${esc(ipKindLabel(r.ip_kind || "unknown"))}${esc(cw)}</span>`;
          } else {
            res.innerHTML = `<span class="bad">${ic("alert")}${esc(r.error || F.t("settings.proxy_noresp", "Прокси не отвечает"))}</span>`;
          }
        })
        .catch(e => {
          if (!el.isConnected) return;
          el.disabled = false;
          el.innerHTML = `${ic("refresh")}${esc(F.t("settings.check_again", "Проверить ещё раз"))}`;
          res.innerHTML = `<span class="bad">${ic("alert")}${esc(e.message)}</span>`;
        });
    }, 900);
  };

  // ================= TRAFFIC AND POWER =================
  // The traffic counter comes from project scans (F.db.scans) and downloaded documents: file sizes plus
  // module requests.
  // The active module (site file search) counts only for active scans; with "Wi-Fi only" heavy modules run
  // over Wi-Fi.
  // Month names follow the UI language (standalone form, capitalized).
  const monthName = i => {
    const s = new Date(Date.UTC(2020, i, 15)).toLocaleString(numLoc(), { month: "long", timeZone: "UTC" });
    return s.charAt(0).toUpperCase() + s.slice(1);
  };
  const HEAVY = new Set(["Скачивание документов", "Поиск на сайте"]);
  // Module names stay Russian internally (HEAVY keys); translated only for display.
  const modL = k =>
    ({
      "Скачивание документов": F.t("settings.mod_download", "Скачивание документов"),
      "Поисковики и архивы": F.t("settings.mod_search", "Поисковики и архивы"),
      "DNS и CT": F.t("settings.mod_dns", "DNS и CT"),
      "Поиск на сайте": F.t("settings.mod_site", "Поиск на сайте"),
    })[k] || k;
  function scanTraffic(s) {
    const dl =
      F.sel
        .docsLive()
        .filter(d => d.first_scan === s.id && ["analyzed", "downloaded"].includes(d.status_code))
        .reduce((a, d) => a + d.size, 0) / 1024;
    const mods = [
      ["Скачивание документов", dl],
      ["Поисковики и архивы", (s.sources || []).filter(x => x.status === "ok").length * 1.8],
      ["DNS и CT", (s.hosts || 0) * 0.05 + 0.5],
    ];
    if (s.active) mods.push(["Поиск на сайте", Math.min(3, s.hosts || 0) * 1.2]);
    return mods;
  }
  function traffic(period) {
    const month = F.sel.scope.today.slice(0, 7);
    const scans =
      period === "scan"
        ? [F.sel.lastScan()].filter(Boolean)
        : F.db.scans.filter(s => (s.started_at || "").slice(0, 7) === month);
    const acc = new Map();
    scans.forEach(s => scanTraffic(s).forEach(([k, v]) => acc.set(k, (acc.get(k) || 0) + v)));
    const total = [...acc.values()].reduce((a, b) => a + b, 0);
    const wifiOnly = state.power.wifiOnly;
    let mob = 0;
    acc.forEach((v, k) => {
      mob += wifiOnly ? (HEAVY.has(k) ? 0 : v) : v * 0.3;
    });
    const mods = [...acc.entries()]
      .filter(([, v]) => v > 0)
      .sort((a, b) => b[1] - a[1])
      .map(([k, v]) => [k, total ? Math.max(1, Math.round((v / total) * 100)) : 0]);
    const last = F.sel.lastScan();
    const when =
      period === "scan"
        ? last
          ? `${F.fmt.dmy(last.started_at).slice(0, 5)}, ${last.started_at.slice(11, 16)}-${last.finished_at.slice(11, 16)}`
          : "-"
        : F.t("settings.since_date", { d: `01.${month.slice(5)}.${month.slice(0, 4)}` }, "с {d}");
    return {
      mob: Math.round(mob),
      wifi: Math.round(total - mob),
      mods,
      when,
      n: scans.length,
      monthName: monthName(+month.slice(5) - 1),
    };
  }
  const mb = n =>
    n >= 1024
      ? (n / 1024).toFixed(1).replace(".", isEn() ? "." : ",") + "\u00a0" + F.t("settings.gb", "ГБ")
      : n + "\u00a0" + F.t("settings.mb", "МБ");
  // Mobile data measured by the core this calendar month (mobile_usage); null until loaded.
  let mobUsage = null,
    mobUsageKey = "";
  function loadMobUsage() {
    if (!F.api.mobile_usage) return;
    F.api.mobile_usage().then(
      u => {
        const k = JSON.stringify(u || null);
        // a re-render mounts the screen again: re-render only when the counter changed
        if (!u || k === mobUsageKey) return;
        mobUsageKey = k;
        mobUsage = u;
        F.render(true);
      },
      () => {},
    );
  }
  const mbx = n => {
    const v = Math.round((+n || 0) * 10) / 10;
    return v >= 1024
      ? mb(v)
      : String(v).replace(".", isEn() ? "." : ",") + "\u00a0" + F.t("settings.mb", "МБ");
  };
  function renderPower() {
    const power = state.power;
    const usage = traffic(power.period);
    const tm = traffic("month");
    // the core's counter wins over the estimate from scan history
    const monthMob = mobUsage ? +mobUsage.used_mb || 0 : tm.mob;
    // 0 MB or the switch off = no mobile traffic limit
    const capped = power.limOn && +power.mobLimit > 0;
    const pct = capped ? Math.min(100, Math.round((monthMob / power.mobLimit) * 100)) : 0;
    const mobReached = capped && monthMob >= +power.mobLimit;
    return `
      ${h3(F.t("settings.traffic_counter", "Счётчик трафика"))}
      ${seg(
        "power.period",
        [
          ["scan", F.t("settings.last_scan", "Последний скан")],
          ["month", usage.monthName],
        ],
        F.t("settings.period", "Период"),
      )}
      ${
        usage.n
          ? `<div class="grid g2 st-tstats">
        <div class="card stat"><div class="k">${ic("st-phone")}${esc(F.t("settings.mobile", "Мобильный"))}</div><div class="v">${power.period === "month" && mobUsage ? mbx(monthMob) : mb(usage.mob)}</div><div class="d">${capped ? F.t("settings.pct_limit", { pct }, "{pct}% лимита за месяц") : F.t("settings.no_limit", "без лимита")}</div></div>
        <div class="card stat"><div class="k">${ic("st-wifi")}Wi-Fi</div><div class="v">${mb(usage.wifi)}</div><div class="d">${esc(usage.when)}</div></div>
      </div>
      ${
        capped
          ? `<div class="card pad st-lim"><div class="st-lim-h"><span>${esc(F.t("settings.mob_month", "Мобильный трафик за месяц"))}</span><b>${F.t("settings.a_of_b", { a: mbx(monthMob), b: mb(power.mobLimit) }, "{a} из {b}")}</b></div><div class="pbar"><i style="width:${Math.min(100, (monthMob / power.mobLimit) * 100)}%"
        class="${monthMob / power.mobLimit > 0.8 ? "st-pw" : ""}"></i></div></div>`
          : ""
      }
      <div class="list st-mods">${usage.mods.map(([n, v]) => `<div class="st-mod"><span class="st-mod-n">${esc(modL(n))}</span><span class="st-mod-b"><i style="width:${v}%"></i></span><span class="st-mod-v">${v}%</span></div>`).join("")}</div>`
          : `<div class="card pad st-lim">${ic("info")} ${esc(power.period === "scan" ? F.t("settings.no_scans_yet", "Сканов в проекте ещё не было. Счётчик начнёт считать после первого скана.") : F.t("settings.no_scans_month", "В этом месяце сканов не было."))}</div>`
      }

      ${h3(F.t("settings.net_h", "Сеть"))}
      <div class="list">
        ${tRow("power.wifiOnly", F.t("settings.wifi_only", "Только Wi-Fi для тяжёлых модулей"), F.t("settings.wifi_only_sub", "Скачивание документов и поиск на сайте. Пауза в мобильной сети"), ui.leadIcon("st-wifi"))}
        ${tRow("power.limOn", F.t("settings.mob_limit", "Лимит мобильного трафика"), F.t("settings.mob_limit_sub", "При достижении: пауза и уведомление"), ui.leadIcon("st-phone"))}
        ${!power.limOn && !power.wifiOnly ? `<div class="st-in st-pad nf-warn st-mob-warn" role="status">${ic("alert")}<span>${esc(F.limits.warning("power.mob_limit", 0))}</span></div>` : ""}
        ${power.limOn ? `<div class="st-in nfs st-steps2">${nf("power.mobLimit", F.t("settings.limit_month", "Лимит в месяц"), F.t("settings.mb", "МБ"), "power.mob_limit", F.t("settings.of_mobile", "мобильного трафика"), "set-limits", 100, { riskCtx: () => ({ zeroRisky: !state.power.wifiOnly }) })}</div>` : ""}
        ${mobUsage ? `<div class="st-in st-pad st-mob-used${mobReached ? " nf-warn" : ""}" role="status">${ic(mobReached ? "alert" : "st-phone")}<span>${esc(capped ? F.t("settings.mob_used_of", { a: mbx(monthMob), b: mb(power.mobLimit) }, "Мобильный трафик в этом месяце: {a} из {b}") : F.t("settings.mob_used", { a: mbx(monthMob) }, "Мобильный трафик в этом месяце: {a}"))}${mobReached ? " · " + esc(F.t("settings.mob_used_reached", "лимит достигнут, скан ждёт Wi-Fi")) : ""}</span></div>` : ""}
      </div>

      ${h3(F.t("settings.power_h", "Питание"))}
      <div class="list">
        ${tRow("power.battOn", F.t("settings.batt_pause", "Пауза при низком заряде"), power.battOn ? F.t("settings.batt_pause_on", { n: power.batt }, "Ниже {n}%: скан встанет на паузу и продолжится на зарядке") : F.t("settings.batt_pause_off", "Скан работает до выключения телефона"), ui.leadIcon("battery"))}
        ${
          power.battOn
            ? `<div class="st-in st-pad st-slider">
          <div class="st-sl-h"><span>${esc(F.t("settings.batt_threshold", "Порог заряда"))}</span><b id="st-batt-v">${power.batt}%</b></div>
          <input type="range" min="5" max="50" step="5" value="${power.batt}" data-range="power.batt"
            aria-label="${esc(F.t("settings.batt_threshold_aria", "Порог заряда, %"))}">
          <div class="st-sl-s"><span>5%</span><span>50%</span></div></div>
          <div class="st-in nfs">${nf("power.batt", F.t("limits.manual", "Своё значение"), "%", "power.batt", F.t("settings.batt_manual_note", "любой порог от 1 до 100%"), "set-limits", 1, { after: () => F.render(true) })}</div>`
            : ""
        }
        ${tRow("power.heat", F.t("settings.heat", "Пауза при перегреве"), F.t("settings.heat_sub", "Выше 42 °C: пауза, продолжение после остывания"), ui.leadIcon("st-temp"))}
        ${tRow("power.chargeOnly", F.t("settings.charge_only", "Тяжёлые модули только на зарядке"), "", ui.leadIcon("st-bolt"))}
        ${tRow("power.autoResume", F.t("settings.auto_resume", "Продолжать прерванный скан автоматически"), F.t("settings.auto_resume_sub", "Если система выгрузила приложение во время скана, при следующем открытии он продолжится с места остановки"), ui.leadIcon("refresh"))}
      </div>`;
  }
  F.route("/settings/power", {
    title: () => F.t("settings.power", "Трафик и питание"),
    sub: () => F.t("settings.title", "Настройки"),
    nav: false,
    back: true,
    actions: [],
    hideMini: true,
    render: () =>
      F.withStates(renderPower, {
        loading: "cards",
        empty: {
          icon: "st-gauge",
          title: F.t("settings.traffic_empty", "Трафика пока нет"),
          text: F.t("settings.traffic_empty_text", "Счётчик начнёт считать после первого скана."),
        },
      }),
    mount: page => {
      pg(page);
      bindRanges(page);
      loadMobUsage();
    },
  });
  function bindRanges(page) {
    page.querySelectorAll("input[data-range]").forEach(r => {
      const paint = () => r.style.setProperty("--p", ((r.value - r.min) / (r.max - r.min)) * 100 + "%");
      paint();
      r.addEventListener("input", () => {
        set(r.dataset.range, +r.value);
        paint();
        const v = page.querySelector("#st-batt-v");
        if (v) v.textContent = r.value + "%";
      });
      r.addEventListener("change", () => {
        persist(r.dataset.range);
        F.render(true);
      });
    });
  }

  // ================= SECURITY =================
  function renderSec() {
    const sec = state.sec;
    return `
      ${h3(F.t("settings.login_h", "Вход"))}
      <div class="list">
        ${tRow("sec.pin", F.t("settings.pin_code", "PIN-код"), sec.pin ? (pinSet() ? F.t("settings.pin_set", "Установлен · запрашивается при входе") : F.t("settings.pin_unset", "Не задан: нажмите «Сменить PIN»")) : F.t("settings.pin_off", "Приложение открывается без проверки"), ui.leadIcon("lock", sec.pin && pinSet() ? "var(--ok)" : sec.pin ? "var(--warn)" : ""))}
        ${
          sec.pin
            ? `<div class="row tap st-sub"
          data-act="st-pinchange"><div class="body"><div class="t">${esc(F.t("settings.change_pin", "Сменить PIN"))}</div></div>${ic("chev", "chev")}</div>`
            : ""
        }
        ${tRow("sec.bio", F.t("settings.bio", "Биометрия"), F.t("settings.bio_sub", "Отпечаток или лицо вместо PIN"), ui.leadIcon("finger"), sec.pin ? "" : "st-dis")}
      </div>
      <label class="flabel">${esc(F.t("settings.autolock", "Автоблокировка"))}</label>
      <div class="chips wrap st-chips" role="radiogroup">${[
        ["0", F.t("settings.immediately", "Сразу")],
        ["1", F.t("settings.min_n", { n: 1 }, "{n} мин")],
        ["5", F.t("settings.min_n", { n: 5 }, "{n} мин")],
        ["15", F.t("settings.min_n", { n: 15 }, "{n} мин")],
        ["30", F.t("settings.min_n", { n: 30 }, "{n} мин")],
      ]
        .map(
          ([v, l]) =>
            `<button class="chip ${sec.autolock === v ? "on" : ""}" role="radio"
              aria-checked="${sec.autolock === v}" data-act="st-set:sec.autolock:${v}">${l}</button>`,
        )
        .join("")}</div>
      <label class="flabel" id="st-rvl">${esc(F.t("settings.secrets_after", "Секреты после отпечатка"))}</label>
      <div class="chips wrap st-chips" role="radiogroup" aria-labelledby="st-rvl">${[
        ["0", F.t("settings.ask_each", "Спрашивать каждый раз")],
        ["1", F.t("settings.min_n_sp", { n: 1 }, "{n} мин")],
        ["2", F.t("settings.min_n_sp", { n: 2 }, "{n} мин")],
        ["5", F.t("settings.min_n_sp", { n: 5 }, "{n} мин")],
      ]
        .map(([v, l]) => {
          const on = String(F.bioMinutes()) === v;
          return `<button class="chip ${on ? "on" : ""}" role="radio" aria-checked="${on}"
            data-act="st-reveal:${v}">${l}</button>`;
        })
        .join("")}</div>
      <p class="fhint st-hint">${ic("info")}${esc(F.t("settings.secrets_hint", "Один отпечаток открывает секреты документов, доказательства в находках и ключи API на это время. Доступ закрывается кнопкой «Закрыть» в полосе «Секреты открыты», при уходе приложения в фон и при блокировке."))}</p>
      <button class="btn tonal block" data-act="go:/lock">${ic("lock")}${esc(F.t("settings.show_lock", "Показать экран блокировки"))}</button>

      ${h3(F.t("settings.privacy", "Приватность"))}
      <div class="list">
        ${shotsRow()}
        ${tRow("sec.clip", F.t("settings.clip_clear", "Очищать буфер через 30 с"), F.t("settings.clip_clear_sub", "После копирования паролей, ключей и e-mail"), ui.leadIcon("copy"))}
      </div>

      ${h3(F.t("settings.data_h", "Данные"))}
      <div class="list">
        <div class="row tap"
          data-act="st-enc">${ui.leadIcon("shield", "var(--ok)")}<div class="body"><div class="t">${esc(F.t("settings.enc", "Шифрование проектов"))}</div><div class="s">AES-256-GCM · ${esc(F.t("settings.enc_sub", "ключ в Android Keystore"))}<div class="st-rpill"><span class="pill ok">${ic("check")}${esc(F.t("settings.enabled", "Включено"))}</span></div></div></div>${ic("chev", "chev")}</div>
        ${tRow("sec.panic", F.t("settings.panic", "Паник-PIN"), sec.panic ? F.t("settings.panic_on", "Задан · ввод на экране блокировки стирает все данные") : F.t("settings.panic_off", "Отдельный PIN, который безвозвратно стирает все проекты"), ui.leadIcon("st-panic", sec.panic ? "var(--crit)" : ""))}
        ${tRow("sec.autodel", F.t("settings.autodel", "Автоудаление неактивных проектов"), sec.autodel ? (sec.autodelDays === "365" ? F.t("settings.autodel_year", "Проект удаляется через год после последнего скана") : F.tp("settings.autodel_days", sec.autodelDays, { n: sec.autodelDays }, "Проект удаляется через {n} день после последнего скана|Проект удаляется через {n} дня после последнего скана|Проект удаляется через {n} дней после последнего скана")) : F.t("settings.autodel_off", "Проекты хранятся, пока вы их не удалите"), ui.leadIcon("clock"))}
        ${
          sec.autodel
            ? `<div class="st-in st-pad"><div class="chips wrap st-chips" role="radiogroup">${[
                ["7", F.tp("settings.days_n", 7, { n: 7 }, "{n} день|{n} дня|{n} дней")],
                ["30", F.tp("settings.days_n", 30, { n: 30 }, "{n} день|{n} дня|{n} дней")],
                ["90", F.tp("settings.days_n", 90, { n: 90 }, "{n} день|{n} дня|{n} дней")],
                ["365", F.t("settings.year", "Год")],
              ]
                .map(
                  ([v, l]) =>
                    `<button class="chip ${sec.autodelDays === v ? "on" : ""}"
                      role="radio" aria-checked="${sec.autodelDays === v}"
                      data-act="st-set:sec.autodelDays:${v}">${l}</button>`,
                )
                .join("")}</div></div>`
            : ""
        }
      </div>

      <div class="card pad st-danger">
        <div class="st-danger-h">${ic("alert")}<b>${esc(F.t("settings.wipe_title", "Безопасно удалить все данные"))}</b></div>
        <p>${esc(F.t("settings.wipe_text", "Все проекты, документы, ключи API и журналы будут перезаписаны и удалены. Восстановить их будет невозможно."))}</p>
        <button class="btn danger block hold"
          data-hold="st-wipe"><span class="hold-fill"></span>${ic("eraser")}${esc(F.t("settings.wipe_hold", "Удерживайте, чтобы удалить"))}</button>
      </div>`;
  }
  F.route("/settings/security", {
    title: () => F.t("settings.security", "Безопасность"),
    sub: () => F.t("settings.title", "Настройки"),
    nav: false,
    back: true,
    actions: [],
    hideMini: true,
    render: () => F.withStates(renderSec, { loading: "cards" }),
    mount: page => pg(page),
  });
  Object.assign(F.actions, {
    "st-reveal": v => {
      F.bioClose();
      F.api.settings_set({ sec: { reveal_min: +v } });
      F.render(true);
    },
    "st-pinchange": () => {
      LK.mode = "change";
      F.go("/lock");
    },
    // Panic PIN: the core stores it only together with the main PIN (pin_set(pin, panic)), so the dialog
    // asks for the current PIN, checks it, then saves both.
    "st-panic-setup": () => {
      if (!pinSet()) {
        F.snack(F.t("settings.set_pin_first", "Сначала задайте PIN-код приложения"));
        return;
      }
      const fld = (id, label) =>
        `<label class="flabel" for="${id}">${label}</label><div class="field">${ic("lock")}<input id="${id}"
          type="password" inputmode="numeric" maxlength="4" autocomplete="off" aria-label="${label}"></div>`;
      F.sheet({
        title: F.t("settings.panic", "Паник-PIN"),
        cls: "st-sheet",
        html: `<p class="lead">${esc(F.t("settings.panic_lead", "Ввод паник-PIN на экране блокировки безвозвратно стирает все проекты, ключи и настройки."))}</p>
          ${fld("st-pp-cur", F.t("settings.cur_pin", "Текущий PIN"))}${fld("st-pp-new", F.t("settings.panic_new", "Паник-PIN (4 цифры)"))}${fld("st-pp-rep", F.t("settings.panic_rep", "Повторите паник-PIN"))}
          <p class="fhint" id="st-pp-msg" role="status"></p>`,
        footer: `<button class="btn" data-act="sheet-close">${esc(F.t("common.cancel", "Отмена"))}</button><button class="btn danger"
          data-act="st-panic-save">${ic("check")}${esc(F.t("common.save", "Сохранить"))}</button>`,
      });
    },
    "st-panic-save": () => {
      const v = id => (document.getElementById(id) || {}).value || "";
      const msg = t => {
        const m = document.getElementById("st-pp-msg");
        if (m) m.textContent = t;
      };
      const cur = v("st-pp-cur"),
        np = v("st-pp-new"),
        rep = v("st-pp-rep");
      if (!/^\d{4}$/.test(cur) || !/^\d{4}$/.test(np))
        return msg(F.t("settings.pin4", "PIN и паник-PIN: по 4 цифры"));
      if (np !== rep) return msg(F.t("settings.panic_mismatch", "Паник-PIN не совпал с повтором"));
      if (np === cur) return msg(F.t("settings.panic_same", "Паник-PIN должен отличаться от PIN-кода"));
      F.api
        .pin_check(cur)
        .then(r => {
          if (!r || !r.ok || r.panic)
            throw new Error(
              r && r.locked
                ? F.t("settings.too_many", "слишком много попыток")
                : F.t("settings.wrong_pin", "неверный PIN"),
            );
          return F.api.pin_set(cur, np);
        })
        .then(() => F.api.settings_set({ sec: { panic: true } }))
        .then(
          () => {
            state.sec.panic = true;
            F.closeSheet();
            F.render(true);
            F.snack(F.t("settings.panic_saved", "Паник-PIN задан"));
          },
          e => msg(F.t("settings.failed", "Не удалось: ") + (e.message || e)),
        );
    },
    "st-enc": () =>
      F.sheet({
        title: F.t("settings.enc", "Шифрование проектов"),
        cls: "st-sheet",
        html: `<div class="kv"><div class="kvr"><div class="k">${esc(F.t("settings.enc_alg", "Алгоритм"))}</div><div class="v">AES-256-GCM</div></div><div class="kvr"><div class="k">${esc(F.t("settings.enc_key", "Ключ"))}</div><div class="v">${esc(F.t("settings.enc_hw", "Android Keystore, аппаратно (StrongBox)"))}</div></div><div class="kvr"><div class="k">${esc(F.t("settings.enc_what", "Что шифруется"))}</div><div class="v">${esc(F.t("settings.enc_what_v", "База проекта, скачанные документы, доказательства, заметки и фото"))}</div></div><div class="kvr"><div class="k">${esc(F.t("settings.enc_export", "Экспорт .foca"))}</div><div class="v">${esc(F.t("settings.enc_export_v", "Отдельный пароль при экспорте"))}</div></div></div>
        <p class="fhint st-hint">${ic("info")}${esc(F.t("settings.enc_hint", "Шифрование нельзя отключить: в проектах хранятся персональные данные и секреты заказчика."))}</p>`,
      }),
    // "Delete everything": the demo only shows a message; with the core, wipe_all after hold-to-confirm
    // (secure wipe).
    "st-wipe": () => {
      if (F.isDemo) return F.snack(F.t("settings.wipe_demo", "Демо: все данные были бы безопасно удалены"));
      F.sheet({
        title: F.t("settings.wipe_q", "Удалить все данные?"),
        cls: "st-sheet",
        html: `<p class="lead">${esc(F.t("settings.wipe_lead", "Будут безопасно удалены все проекты, документы, ключи API и настройки. Отменить нельзя."))}</p>`,
        footer: `<button class="btn"
          data-act="sheet-close">${esc(F.t("common.cancel", "Отмена"))}</button><button class="btn danger hold"
          data-hold="st-wipe-go"><span class="hold-fill"></span>${ic("trash")}${esc(F.t("settings.hold", "Удерживайте"))}</button>`,
      });
    },
    "st-wipe-go": () => {
      F.closeSheet();
      F.api.wipe_all().then(
        () => {
          F.reset(["/projects"]);
          F.snack(F.t("settings.wiped", "Все данные удалены"));
        },
        e => F.snack(F.t("settings.failed", "Не удалось: ") + (e.message || e)),
      );
    },
  });

  // ---------- LOCK SCREEN /lock ----------
  const PIN = "1234"; // Demo only: the demo backend has no default PIN, so the screen checks against this sample.
  const pinSet = () => !!((F.db.settings || {}).sec || {}).pin_set;
  const LK = (F.state.lock = F.state.lock || { mode: "unlock", tries: 5 });
  let lockEl = null,
    lockKey = null,
    pinv = "",
    newPin = "";
  function lockTitle() {
    if (LK.mode !== "change") return F.t("settings.enter_pin", "Введите PIN");
    if (newPin) return F.t("settings.repeat_new_pin", "Повторите новый PIN");
    return pinv === null ? "" : F.t("settings.enter_new_pin", "Введите новый PIN");
  }
  function lockMessage() {
    if (LK.tries < 5)
      return F.t("settings.wrong_pin_left", { n: LK.tries }, "Неверный PIN · осталось попыток: {n}");
    if (LK.mode === "change") return F.t("settings.new_then_repeat", "Сначала новый PIN, затем повтор");
    return F.isDemo && !pinSet() ? F.t("settings.demo_pin", "Демо PIN: 1234") : "";
  }
  function lockHtml() {
    const ttl = lockTitle();
    return `<div class="lock show st-lock" role="dialog" aria-modal="true" aria-label="${esc(F.t("settings.lock_aria", "Экран блокировки"))}">
      <div class="st-lk-top">
        <img class="st-lk-logo" src="icon.png" alt="">
        <div class="st-lk-app">FOCA-rs</div>
        <div class="st-lk-t" id="st-lk-t">${ttl}</div>
        <div class="st-dots" id="st-dots"
          aria-live="polite">${[0, 1, 2, 3].map(i => `<i class="${i < pinv.length ? "on" : ""}"></i>`).join("")}</div>
        <div class="st-lk-msg"
          id="st-lk-msg">${lockMessage()}</div>
      </div>
      <div class="st-pad-keys" role="group" aria-label="${esc(F.t("settings.keypad_aria", "Цифровая клавиатура"))}">
        ${[1, 2, 3, 4, 5, 6, 7, 8, 9]
          .map(
            d => `<button class="st-kb"
          data-act="st-lk:${d}"><b>${d}</b></button>`,
          )
          .join("")}
        ${
          // Setting or changing a PIN has nothing to do with the fingerprint: keep the cell empty there.
          LK.mode === "change"
            ? `<span class="st-kb st-kb-gap" aria-hidden="true"></span>`
            : `<button class="st-kb st-kb-ic" data-act="st-lk-bio" aria-label="${esc(F.t("settings.bio_login", "Войти по отпечатку"))}"
          ${state.sec.bio ? "" : "disabled"}>${ic("finger")}</button>`
        }
        <button class="st-kb" data-act="st-lk:0"><b>0</b></button>
        <button class="st-kb st-kb-ic" data-act="st-lk-del"
          aria-label="${esc(F.t("settings.del_digit", "Стереть цифру"))}">${ic("st-del")}</button>
      </div>
      ${
        LK.mode === "change"
          ? `<button class="btn text st-lk-cancel"
        data-act="st-lk-cancel">${esc(F.t("common.cancel", "Отмена"))}</button>`
          : `<button class="btn text st-lk-cancel"
        data-act="st-lk-forgot">${esc(F.t("settings.forgot_pin", "Забыли PIN?"))}</button>`
      }
    </div>`;
  }
  const drawDots = () => {
    if (!lockEl) return;
    lockEl.querySelectorAll("#st-dots i").forEach((d, i) => d.classList.toggle("on", i < pinv.length));
  };
  const lockMsg = (t, cls = "") => {
    const m = lockEl && lockEl.querySelector("#st-lk-msg");
    if (m) {
      m.textContent = t;
      m.className = "st-lk-msg " + cls;
    }
  };
  const unlockDone = txt => {
    lockEl.classList.add("st-ok");
    lockMsg(txt || F.t("settings.unlocked", "Разблокировано"), "ok");
    setTimeout(() => {
      LK.tries = 5;
      if (F.current() === "/lock") {
        // Lift the navigation gate while leaving the lock screen, then replay the navigation that was
        // requested while locked (e.g. a notification tap opening a project).
        LK.mode = "open";
        const queued = F.lockQueue.take();
        F.onBack(null);
        F.back();
        if (F.current() === "/lock") F.reset(["/settings", "/settings/security"]);
        if (queued) queued();
      }
      LK.mode = "unlock";
    }, 450);
  };
  function press(digit) {
    if (!lockEl || pinv.length >= 4 || lockEl.classList.contains("st-ok")) return;
    if (LK.tries <= 0) {
      lockMsg(F.t("settings.wait30", "Слишком много попыток · подождите 30 с"), "bad");
      return;
    }
    pinv += digit;
    drawDots();
    if (pinv.length < 4) return;
    setTimeout(() => {
      if (LK.mode === "change") {
        if (!newPin) {
          newPin = pinv;
          pinv = "";
          drawDots();
          lockEl.querySelector("#st-lk-t").textContent = F.t(
            "settings.repeat_new_pin",
            "Повторите новый PIN",
          );
          lockMsg(F.t("settings.enter_again", "Введите ещё раз для подтверждения"));
          return;
        }
        if (pinv === newPin) {
          const pin = pinv;
          // First PIN on this device: say "set", not "changed".
          const first = !pinSet();
          const doneMsg = () =>
            first
              ? [
                  F.t("settings.pin_set_first", "PIN задан"),
                  F.t("settings.pin_code_set_first", "PIN-код задан"),
                ]
              : [
                  F.t("settings.pin_changed", "PIN изменён"),
                  F.t("settings.pin_code_changed", "PIN-код изменён"),
                ];
          newPin = "";
          pinv = "";
          if (F.isDemo && !F.api.pin_set) {
            unlockDone(doneMsg()[0]);
            F.snack(doneMsg()[1]);
            return;
          }
          F.api
            .pin_set(pin)
            .then(() => F.api.settings_get())
            .then(
              st => {
                Object.assign(F.db.settings.sec, st.sec || {});
                unlockDone(doneMsg()[0]);
                F.snack(doneMsg()[1]);
              },
              e => {
                shake();
                lockMsg(
                  F.t("settings.pin_save_fail", "Не удалось сохранить PIN: ") + (e.message || e),
                  "bad",
                );
              },
            );
          return;
        }
        newPin = "";
        pinv = "";
        shake();
        lockEl.querySelector("#st-lk-t").textContent = F.t("settings.enter_new_pin", "Введите новый PIN");
        lockMsg(F.t("settings.pin_mismatch", "PIN не совпал: начните заново"), "bad");
        return;
      }
      if (!F.isDemo || pinSet()) {
        // Core: pin_check (hash, attempt counter, panic PIN → wipe_all).
        const pin = pinv;
        pinv = "";
        F.api.pin_check(pin).then(
          r => {
            if (r.ok && r.panic) {
              F.api.wipe_all().catch(() => {});
              F.lockQueue.take(); // Panic PIN: drop the queued navigation, the data is being wiped.
              unlockDone();
              setTimeout(() => F.reset(["/projects"]), 500);
              return;
            }
            if (r.ok) {
              unlockDone();
              return;
            }
            LK.tries = r.attempts_left ?? LK.tries - 1;
            shake();
            lockMsg(
              LK.tries > 0
                ? F.t("settings.wrong_pin_left", { n: LK.tries }, "Неверный PIN · осталось попыток: {n}")
                : F.t("settings.too_many_wait", "Слишком много попыток · подождите"),
              "bad",
            );
          },
          e => {
            shake();
            lockMsg(F.t("settings.error_p", "Ошибка: ") + (e.message || e), "bad");
          },
        );
        return;
      }
      if (pinv === PIN) {
        unlockDone();
        pinv = "";
        return;
      }
      LK.tries--;
      pinv = "";
      shake();
      lockMsg(
        LK.tries > 0
          ? F.t("settings.wrong_pin_left", { n: LK.tries }, "Неверный PIN · осталось попыток: {n}")
          : F.t("settings.wait30", "Слишком много попыток · подождите 30 с"),
        "bad",
      );
      if (LK.tries <= 0)
        setTimeout(() => {
          LK.tries = 5;
          lockMsg(F.t("settings.retry_demo", "Можно попробовать снова · демо PIN: 1234"));
        }, 30000);
    }, 140);
  }
  const shake = () => {
    const d = lockEl.querySelector(".st-lk-top");
    d.classList.remove("st-shake");
    void d.offsetWidth;
    d.classList.add("st-shake");
    try {
      navigator.vibrate && navigator.vibrate([40, 40, 40]);
    } catch (e) {}
    setTimeout(() => drawDots(), 0);
  };
  // Locked = the lock screen is on top and asks for the PIN (not the set/change PIN flow).
  F.isLocked = () => F.current() === "/lock" && LK.mode === "unlock";
  F.route("/lock", {
    title: "",
    sub: "",
    nav: false,
    back: false,
    actions: [],
    hideMini: true,
    render: () => `<div class="st-lock-under"></div>`,
    mount() {
      F.bioClose(); // Locking closes the secret reveal session.
      pinv = "";
      newPin = "";
      if (!F.isDemo && !pinSet()) LK.mode = "change"; // No PIN set yet: the screen offers to set one.
      if (lockEl) lockEl.remove();
      document.body.insertAdjacentHTML("beforeend", lockHtml());
      lockEl = document.body.lastElementChild;
      F.onBack(() => {
        if (LK.mode === "change") {
          F.actions["st-lk-cancel"]();
          return true;
        }
        lockMsg(F.t("settings.pin_to_continue", "Введите PIN, чтобы продолжить"));
        return true;
      });
      // A re-render mounts the screen again without unmount: drop the previous listener first.
      if (lockKey) document.removeEventListener("keydown", lockKey);
      lockKey = e => {
        if (/^\d$/.test(e.key)) press(e.key);
        else if (e.key === "Backspace") F.actions["st-lk-del"]();
      };
      document.addEventListener("keydown", lockKey);
    },
    unmount() {
      if (lockEl) {
        const el = lockEl;
        el.classList.add("st-out");
        setTimeout(() => el.remove(), 200);
        lockEl = null;
      }
      document.removeEventListener("keydown", lockKey);
      LK.mode = "unlock";
    },
  });
  // ---------- AUTOLOCK (sec.autolock, minutes; "0" = on every return to the app) ----------
  // Inactivity timer while the app is in the foreground plus a check when it comes back from background.
  let lastActive = Date.now(),
    hiddenAt = 0;
  const NO_LOCK = /^\/(lock|terms|welcome)$/;
  const autolockMs = () => {
    const v = ((F.db.settings || {}).sec || {}).autolock;
    const m = v == null || v === "" ? 5 : +v;
    return Number.isFinite(m) && m >= 0 ? m * 60000 : 5 * 60000;
  };
  const lockNow = () => {
    if (!pinSet() || !F.current || NO_LOCK.test(F.current() || "")) return false;
    F.closeSheet && F.closeSheet();
    LK.mode = "unlock";
    F.go("/lock");
    return true;
  };
  F.autolock = {
    lockNow,
    // Exposed for checks: shifts the activity clock back by `ms`, then runs the timer once.
    _idle: ms => {
      lastActive -= ms;
      return tick();
    },
    _resume: awayMs => {
      hiddenAt = Date.now() - awayMs;
      return resume();
    },
  };
  const tick = () => {
    const ms = autolockMs();
    if (ms > 0 && !document.hidden && Date.now() - lastActive >= ms) {
      lastActive = Date.now();
      return lockNow();
    }
    return false;
  };
  const resume = () => {
    const away = hiddenAt ? Date.now() - hiddenAt : 0;
    hiddenAt = 0;
    lastActive = Date.now();
    return away > 0 && away >= autolockMs() ? lockNow() : false;
  };
  ["pointerdown", "keydown", "touchstart", "wheel"].forEach(ev =>
    document.addEventListener(ev, () => (lastActive = Date.now()), { capture: true, passive: true }),
  );
  document.addEventListener("visibilitychange", () => {
    if (document.hidden) hiddenAt = Date.now();
    else resume();
  });
  setInterval(tick, 15000);

  Object.assign(F.actions, {
    "st-lk": d => press(d),
    "st-lk-del": () => {
      pinv = pinv.slice(0, -1);
      drawDots();
    },
    "st-lk-bio": () => {
      if (!lockEl) return;
      const iconEl = lockEl.querySelector(".st-kb-ic");
      iconEl.classList.add("st-scan");
      lockMsg(F.t("settings.touch_sensor", "Приложите палец к сканеру…"));
      if (!F.isDemo && F.api.platform_biometric) {
        F.api.platform_biometric({ title: F.t("settings.unlock_title", "Разблокировать FOCA-rs") }).then(
          r => {
            iconEl.classList.remove("st-scan");
            if (r && r.ok) unlockDone(F.t("settings.finger_ok", "Отпечаток распознан"));
            else
              lockMsg(
                r && r.available === false
                  ? F.t("settings.finger_na", "Отпечаток недоступен: введите PIN")
                  : F.t("settings.finger_bad", "Не распознан: введите PIN"),
                "bad",
              );
          },
          () => {
            iconEl.classList.remove("st-scan");
            lockMsg(F.t("settings.finger_na", "Отпечаток недоступен: введите PIN"), "bad");
          },
        );
        return;
      }
      setTimeout(() => {
        iconEl.classList.remove("st-scan");
        unlockDone(F.t("settings.finger_ok", "Отпечаток распознан"));
      }, 1100);
    },
    "st-lk-cancel": () => {
      F.onBack(null);
      LK.mode = "unlock";
      F.back();
    },
    "st-lk-forgot": () =>
      lockMsg(
        F.t("settings.forgot_text", "Сброс PIN стирает все проекты. Так защищены данные заказчика"),
        "bad",
      ),
  });

  // ================= BACKGROUND WORK (BATTERY) =================
  const OEM = {
    xiaomi: {
      l: "Xiaomi · HyperOS",
      steps: [
        [
          "Автозапуск",
          "Настройки › Приложения › Все приложения › FOCA-rs › Автозапуск, включить",
          "Приложения",
          "autostart",
        ],
        [
          "Контроль активности",
          "Там же › Контроль активности (Экономия заряда) › Нет ограничений",
          "Контроль активности",
          "battery",
        ],
        [
          "Закрепить в «Недавних»",
          "Откройте «Недавние», зажмите карточку FOCA-rs и нажмите замок. Нужно, только если скрытие из «Недавних» выключено.",
          "",
          "recents_pin",
        ],
        [
          "Фоновые всплывающие окна",
          "Другие разрешения › Отображать всплывающие окна в фоне. Разрешить (для уведомления о паузе)",
          "Другие разрешения",
        ],
      ],
    },
    samsung: {
      l: "Samsung · One UI",
      steps: [
        [
          "Без ограничений",
          "Настройки › Приложения › FOCA-rs › Аккумулятор › Без ограничений",
          "Аккумулятор",
          "battery",
        ],
        [
          "Убрать из спящих",
          "Настройки › Обслуживание устройства › Аккумулятор › Ограничения в фоновом режиме › Неспящие приложения, добавить FOCA-rs",
          "Ограничения в фоне",
        ],
        ["Отключить «Перевод неиспользуемых в спящий режим»", "Там же: выключить переключатель", ""],
      ],
    },
    pixel: {
      get l() {
        return F.t("settings.oem_pixel", "Pixel / чистый Android");
      },
      steps: [
        [
          "Без ограничений",
          "Настройки › Приложения › FOCA-rs › Использование батареи приложением › Без ограничений",
          "Батарея",
          "battery",
        ],
        [
          "Уведомления",
          "Разрешите уведомления: по ним Android понимает, что скан идёт в фоне",
          "Уведомления",
          "notif",
        ],
      ],
    },
  };
  function renderBattery() {
    const battery = state.battery;
    const oem = OEM[battery.oem];
    const done = battery.done[battery.oem] || {};
    // A step counts when its detected state is on, or (state not detectable) when marked by hand.
    const states = oem.steps.map(st => stepState(st[3]));
    const n = oem.steps.filter(
      (_, i) => states[i] === "on" || states[i] === "na" || (states[i] !== "off" && done[i]),
    ).length;
    return `
      ${
        battery.excluded
          ? `<div class="banner st-okb">${ic("check")}<div><b>${esc(F.t("settings.batt_ok_b", "Исключено из оптимизации батареи."))}</b> ${esc(F.t("settings.batt_ok_text", "Скан работает в фоне с постоянным уведомлением «Скан идёт». Прошивки вроде HyperOS, MIUI и One UI всё равно могут его остановить, если не снять их собственные ограничения батареи,. Выполните шаги для вашей прошивки ниже."))}</div></div>`
          : `<div class="banner warn">${ic("battery")}<div><b>${esc(F.t("settings.batt_no_b", "Не исключено из оптимизации батареи."))}</b> ${esc(F.t("settings.batt_no_text", "Скан идёт в фоне с постоянным уведомлением, но Android может остановить его, когда экран выключен. Исключите приложение и выполните шаги для вашей прошивки."))}</div></div>`
      }
      <button class="btn ${battery.excluded ? "" : "primary"} block"
        data-act="st-bopen">${ic("open")}${esc(battery.excluded ? F.t("settings.open_android", "Открыть настройки Android") : F.t("settings.exclude_android", "Исключить в настройках Android"))}</button>
      <div class="list st-mt">${(() => {
        const pm = (F.state.perms && F.state.perms.st) || {};
        const on = pm.notifications !== false;
        return ui.row({
          lead: ui.leadIcon("bell", on ? "var(--ok)" : "var(--warn)"),
          title: F.t("settings.notifs", "Уведомления"),
          sub: on
            ? F.t("settings.notifs_on", "Разрешены: прогресс скана виден в фоне")
            : F.t("settings.notifs_off", "Не разрешены: Android может остановить фоновый скан"),
          tail: on
            ? `<span class="pill ok">${ic("check")}${esc(F.t("settings.granted", "Выдано"))}</span>`
            : `<button class="btn sm tonal" data-act="st-notif">${esc(F.t("settings.allow", "Разрешить"))}</button>`,
        });
      })()}</div>
      ${hideRecentsRow()}

      ${h3(F.t("settings.firmware", "Прошивка"), F.t("settings.done_n_of", { n, m: oem.steps.length }, "выполнено {n} из {m}"))}
      <div class="chips wrap st-chips" role="radiogroup">${Object.entries(OEM)
        .map(
          ([k, v]) =>
            `<button class="chip ${battery.oem === k ? "on" : ""}" role="radio"
              aria-checked="${battery.oem === k}" data-act="st-set:battery.oem:${k}">${v.l}</button>`,
        )
        .join("")}</div>
      <p class="fhint st-hint st-detect">${ic("st-phone")}${esc(F.t("settings.detected", "Определено:"))} ${esc(battDetected || "Xiaomi 14 · HyperOS 1.0 (Android 14)")}</p>
      <ol class="st-howto">${oem.steps
        .map(([t, d, a], i) => {
          const sv = states[i];
          // Detected steps show the real state; "Done" by hand only where the system does not tell us.
          const manual = sv !== "on" && sv !== "off" && sv !== "na";
          const ok = sv === "on" || sv === "na" || (manual && done[i]);
          const pill =
            sv === "na"
              ? `<span class="pill mute st-hst">${esc(F.t("settings.step_not_needed", "Не нужно"))}</span>`
              : sv === "on"
                ? `<span class="pill ok st-hst">${ic("check")}${esc(F.t("settings.step_on", "Включено"))}</span>`
                : sv === "off"
                  ? `<span class="pill warn st-hst">${ic("x")}${esc(F.t("settings.step_off", "Выключено"))}</span>`
                  : sv === "unknown"
                    ? `<span class="pill mute st-hst">?&nbsp;${esc(F.t("settings.step_unknown", "Не удалось определить"))}</span>`
                    : "";
          return `
        <li class="card st-hs ${ok ? "done" : ""}" data-step="${i}" data-state="${sv || "manual"}">
          <span class="st-hn">${ok ? ic("check") : i + 1}</span>
          <div class="st-hb"><b>${esc(F.t(`settings.oem_${battery.oem}_${i}_t`, t))}</b>${pill}<p>${esc(sv === "na" ? F.t(`settings.oem_${battery.oem}_${i}_alt`, d) : F.t(`settings.oem_${battery.oem}_${i}_d`, d)).replace(/ › /g, ` <span class="st-sep">›</span> `)}</p>
            <div class="st-ha">${
              a
                ? `<button class="btn sm tonal"
              data-act="st-android:${esc(a)}">${ic("open")}${esc(F.t("common.open", "Открыть"))}</button>`
                : ""
            }${
              manual
                ? `<button class="btn sm"
              data-act="st-bdone:${i}">${done[i] ? F.t("settings.undo", "Отменить") : `${ic("check")}${esc(F.t("settings.done_btn", "Готово"))}`}</button>`
                : ""
            }</div>
          </div>
        </li>`;
        })
        .join("")}</ol>
`;
  }
  // Native background status (platform_bg_status): hide-from-Recents toggle, OEM autostart, battery.
  let bgSt = null;
  // State of a firmware step the app can read: "on" | "off" | "unknown"; null = not detectable (manual).
  const stepState = det => {
    if (det === "autostart") {
      const v = bgSt && bgSt.autostart;
      return v === "on" || v === "off" ? v : "unknown";
    }
    if (det === "battery") {
      // Native status first (null there = could not tell); without it the platform_battery_status flag.
      const v = bgSt ? bgSt.battery_unrestricted : state.battery.excluded;
      return typeof v === "boolean" ? (v ? "on" : "off") : "unknown";
    }
    // Locking the card in Recents is the alternative to hiding it: not needed while hiding is on.
    if (det === "recents_pin") return bgSt && bgSt.hide_recents === true ? "na" : null;
    if (det === "notif") {
      const v = ((F.state.perms && F.state.perms.st) || {}).notifications;
      return typeof v === "boolean" ? (v ? "on" : "off") : "unknown";
    }
    return null;
  };
  const bgRefresh = () => {
    if (!F.api.platform_bg_status) return;
    F.api.platform_bg_status().then(
      st => {
        const was = JSON.stringify(bgSt);
        bgSt = st || null;
        if (was === JSON.stringify(bgSt)) return;
        if (F.current() === "/settings/battery") F.render(true);
        // Launch screen: patch only the hint block, a full render would disturb the wizard.
        const el = document.getElementById("la-bg");
        if (el && F.launchBgHint) el.innerHTML = F.launchBgHint();
      },
      () => {},
    );
  };
  // OEM background helper: autostart and battery status with buttons to the system screens, plus the tip to
  // lock the card in Recents. Shown on firmwares known to kill swiped-away apps (Settings › Background and
  // the launch screen through F.bgSetup).
  const autostartL = v =>
    v === "on"
      ? F.t("settings.bg_auto_on", "включён")
      : v === "off"
        ? F.t("settings.bg_auto_off", "выключен: прошивка может не дать скану продолжиться")
        : F.t("settings.bg_auto_unknown", "не удалось определить: проверьте вручную");
  function bgCard(where) {
    const st = bgSt;
    if (!st || !st.oem || st.oem === "other") return "";
    const auto = st.autostart || "unknown";
    const batt = st.battery_unrestricted === true;
    const ok = txt => `<span class="pill ok">${ic("check")}${esc(txt)}</span>`;
    const btn = (act, txt) => `<button class="btn sm tonal" data-act="${act}">${esc(txt)}</button>`;
    return `<div class="card bg-setup st-mt" data-where="${esc(where)}">
      ${ui.row({
        lead: ui.leadIcon("refresh", auto === "on" ? "var(--ok)" : "var(--warn)"),
        title: esc(F.t("settings.bg_autostart", "Автозапуск")),
        sub: esc(autostartL(auto)),
        tail:
          auto === "on"
            ? ok(F.t("settings.granted", "Выдано"))
            : btn("st-bg-auto", F.t("settings.bg_auto_btn", "Включить автозапуск")),
      })}
      ${ui.row({
        lead: ui.leadIcon("battery", batt ? "var(--ok)" : "var(--warn)"),
        title: esc(F.t("settings.bg_battery", "Ограничения батареи")),
        sub: esc(
          batt
            ? F.t("settings.bg_batt_off", "Сняты: приложение исключено из оптимизации батареи")
            : F.t("settings.bg_batt_on", "Действуют: Android может остановить долгий скан"),
        ),
        tail: batt
          ? ok(F.t("settings.bg_batt_removed", "Сняты"))
          : btn("st-bg-batt", F.t("settings.bg_batt_btn", "Снять ограничения")),
      })}
      </div>
    ${
      // Hiding from Recents and locking the card are alternatives: the tip only when hiding is off.
      st.hide_recents === false
        ? `<p class="fhint st-hint bg-tip">${ic("lock")}${esc(F.t("settings.bg_lock_tip", "Закрепите FOCA-rs в «Недавних»: зажмите карточку и нажмите замок."))}</p>`
        : ""
    }`;
  }
  F.bgSetup = {
    refresh: () => bgRefresh(),
    // Launch screen: the card only when something is still missing on such a firmware.
    launchCard: () =>
      bgSt &&
      bgSt.oem &&
      bgSt.oem !== "other" &&
      (bgSt.autostart !== "on" || bgSt.battery_unrestricted !== true)
        ? bgCard("launch")
        : "",
  };
  const bgAfter = () => setTimeout(bgRefresh, 800);
  F.actions["st-bg-auto"] = () => {
    if (F.isTauri) return androidOpen("autostart").then(bgAfter);
    F.snack(F.t("settings.bg_auto_demo", "Откроются настройки Android: Автозапуск"));
    F.api.platform_bg_set({ demo_autostart: "on" }).then(st => {
      bgSt = st;
      F.render(true);
    });
  };
  F.actions["st-bg-batt"] = () => {
    if (F.isTauri) return androidOpen("battery").then(bgAfter);
    F.actions["st-bopen"]();
    setTimeout(bgRefresh, 1700);
  };
  // "Hide from Recents during scans": the choice lives in the native layer (it acts in onPause/onStop
  // without the core); the default is on for firmwares that kill swiped-away apps.
  function hideRecentsRow() {
    if (!bgSt || typeof bgSt.hide_recents !== "boolean") return "";
    const title = F.t("settings.hide_recents", "Скрывать из «Недавних» во время скана");
    const sub = F.t(
      "settings.hide_recents_sub",
      "Пока идёт скан и приложение свёрнуто, его карточки нет в «Недавних», её нельзя смахнуть или очистить вместе со всеми. Вернуться: через уведомление скана или значок приложения.",
    );
    return `<div class="list st-mt"><div class="row tap st-tr" data-act="st-hide-recents">${ui.leadIcon("eye-off")}<div class="body"><div class="t">${esc(title)}</div><div class="s">${esc(sub)}</div></div><div class="tail">${ui.toggle(bgSt.hide_recents, "st-hide-recents", `aria-label="${esc(title)}"`)}</div></div></div>`;
  }
  F.actions["st-hide-recents"] = (_a, el) => {
    if (!bgSt || !F.api.platform_bg_set) return;
    const on = !bgSt.hide_recents;
    bgSt = { ...bgSt, hide_recents: on };
    const tg = el && (el.classList.contains("toggle") ? el : el.querySelector(".toggle"));
    if (tg) F.actions.toggle(null, tg);
    F.api.platform_bg_set({ hide_recents: on }).then(
      st => {
        if (st && typeof st.hide_recents === "boolean") bgSt = st;
        setTimeout(() => F.current() === "/settings/battery" && F.render(true), 120);
      },
      e => {
        bgSt = { ...bgSt, hide_recents: !on };
        F.snack(F.t("settings.bg_save_fail", { err: e.message }, "Не удалось сохранить: {err}"));
        F.render(true);
      },
    );
  };
  // In the app: the real battery optimization status and OEM (platform_battery_status); buttons open system
  // screens (platform_battery_settings); the status is re-read when the app regains focus.
  let battDetected = null,
    oemDetected = false;
  const battRefresh = () => {
    bgRefresh();
    if (F.api.platform_permissions_status)
      F.api.platform_permissions_status().then(
        st => {
          const was = JSON.stringify((F.state.perms || {}).st || {});
          F.state.perms = F.state.perms || {};
          F.state.perms.st = st || {};
          if (was !== JSON.stringify(st || {}) && F.current() === "/settings/battery") F.render(true);
        },
        () => {},
      );
    if (!F.isTauri || !F.api.platform_battery_status) return;
    F.api.platform_battery_status().then(
      st => {
        if (!st) return;
        let ch = false;
        if (st.label && st.label !== battDetected) {
          battDetected = st.label;
          ch = true;
        }
        if (!oemDetected && st.oem && st.oem !== state.battery.oem) {
          state.battery.oem = st.oem;
          ch = true;
        }
        oemDetected = true;
        if (typeof st.ignoring === "boolean" && st.ignoring !== state.battery.excluded) {
          state.battery.excluded = st.ignoring;
          persist("battery");
          ch = true;
        }
        if (ch && F.current() === "/settings/battery") F.render(true);
      },
      () => {},
    );
  };
  document.addEventListener("visibilitychange", () => {
    if (!document.hidden && F.current && F.current() === "/settings/battery") battRefresh();
  });
  F.actions["st-notif"] = () =>
    F.api.platform_request_notifications().then(
      () => setTimeout(battRefresh, 500),
      e => F.snack(F.t("settings.req_fail", "Не удалось запросить: ") + e.message),
    );
  const androidOpen = what =>
    F.api.platform_battery_settings(what).then(
      r => {
        if (!r || !r.opened)
          F.snack(
            F.t("settings.android_open_fail", "Не удалось открыть настройки Android, откройте их вручную"),
          );
      },
      e => F.snack(F.t("settings.settings_open_fail", "Не удалось открыть настройки: ") + e.message),
    );
  document.addEventListener("visibilitychange", () => {
    if (!document.hidden && F.current && /^\/(settings\/battery|new)$/.test(F.current() || "")) bgRefresh();
  });
  F.route("/settings/battery", {
    title: () => F.t("settings.background", "Работа в фоне"),
    sub: () => F.t("settings.title", "Настройки"),
    nav: false,
    back: true,
    actions: [],
    hideMini: true,
    render: () => F.withStates(renderBattery, { loading: "cards" }),
    mount: page => {
      pg(page);
      battRefresh();
    },
  });
  Object.assign(F.actions, {
    "st-bopen": () => {
      if (F.isTauri) {
        androidOpen("battery");
        return;
      }
      F.snack(F.t("settings.batt_opt_demo", "Откроются настройки Android: Оптимизация батареи"));
      setTimeout(() => {
        state.battery.excluded = true;
        persist("battery");
        if (F.current() === "/settings/battery") F.render(true);
      }, 1600);
    },
    "st-bdone": i => {
      const d = (state.battery.done[state.battery.oem] = state.battery.done[state.battery.oem] || {});
      d[i] = !d[i];
      persist("battery");
      F.render(true);
    },
  });

  // ================= APPEARANCE =================
  const curFs = () => parseFloat(getComputedStyle(document.documentElement).getPropertyValue("--fs")) || 1;
  const applyDensity = d => {
    const h = document.documentElement;
    h.classList.toggle("st-dense", d === "compact");
    h.classList.toggle("st-airy", d === "airy");
  };
  const sysDark = () => {
    try {
      return matchMedia("(prefers-color-scheme: dark)").matches;
    } catch (e) {
      return true;
    }
  };
  applyDensity(state.look.density);
  function renderLook() {
    const look = state.look;
    const fs = curFs();
    const th = (id, name) => `<button class="st-th ${look.theme === id ? "on" : ""}" role="radio"
      aria-checked="${look.theme === id}" data-act="st-theme:${id}">
        <span class="st-th-p st-th-${id}"><i></i><i></i><i></i></span><span class="st-th-l">${name}</span></button>`;
    look.lang = langLook();
    const active = F.i18n ? F.i18n.lang() : "ru";
    return `
      ${h3(F.t("look.theme", "Тема"))}
      <div class="st-themes" role="radiogroup"
        aria-label="${esc(F.t("look.theme", "Тема"))}">${th("system", F.t("look.theme_system", "Системная"))}${th("dark", F.t("look.theme_dark", "Тёмная"))}${th("light", F.t("look.theme_light", "Светлая"))}</div>

      ${h3(F.t("look.lang", "Язык интерфейса"))}
      ${seg(
        "look.lang",
        [
          ["AUTO", esc(systemLabel())],
          ["UA", "Українська"],
          ["EN", "English"],
          ["RU", "Русский"],
        ],
        F.t("look.lang", "Язык интерфейса"),
      ).replace('class="seg st-seg"', 'class="seg st-seg st-lang"')}
      <p class="fhint st-hint">${ic("info")}${esc(
        F.t(look.lang === "AUTO" ? "look.lang_auto_hint" : "look.lang_manual_hint", {
          lang: F.t(
            `look.lang_in_${active}`,
            { uk: "украинский язык", en: "английский язык", ru: "русский язык" }[active],
          ),
        }),
      )}</p>

      ${h3(F.t("look.font_size", "Размер шрифта"))}
      <div class="card pad st-slider">
        <div class="st-sl-h"><span class="st-aa">${ic("st-text")}</span><b id="st-fs-v">${Math.round(fs * 100)}%</b></div>
        <input type="range" min="0.9" max="1.3" step="0.05"
          value="${Math.min(1.3, Math.max(0.9, fs))}" id="st-fs" aria-label="${esc(F.t("look.font_size", "Размер шрифта"))}">
        <div class="st-sl-s"><span>90%</span><span>100%</span><span>130%</span></div>
      </div>
      <div class="list st-preview" aria-label="${esc(F.t("look.preview", "Предпросмотр"))}">
        ${(() => {
          const finding = F.db.findings
            .slice()
            .sort((a, b) => F.sel.SEV_ORD.indexOf(a.sev) - F.sel.SEV_ORD.indexOf(b.sev))[0];
          const doc = F.sel.docsLive().find(x => x.status_code === "analyzed");
          return (
            (finding
              ? ui.row({
                  lead: ui.leadIcon("alert", "var(--crit)"),
                  title: esc(finding.title),
                  sub: `${esc(finding.host)} · ${esc(finding.source)}`,
                  tail: ui.sev(finding.sev),
                })
              : ui.row({
                  lead: ui.leadIcon("alert", "var(--crit)"),
                  title: F.t("look.sample_finding", "Пример находки"),
                  sub: F.t("look.sample_sub", "хост · источник"),
                  tail: ui.sev("crit"),
                })) +
            (doc
              ? ui.row({
                  lead: `<span class="ext ${esc(doc.ext)}">${esc(doc.ext)}</span>`,
                  title: esc(doc.name),
                  sub: `${esc(doc.user.login)} · ${doc.size}\u00a0${esc(F.t("settings.kb", "КБ"))}`,
                })
              : ui.row({
                  lead: `<span class="ext docx">docx</span>`,
                  title: F.t("settings.sample_doc", "Пример_документа.docx"),
                  sub: F.t("settings.sample_doc_sub", "автор · 120 КБ"),
                }))
          );
        })()}
      </div>
      <button class="btn text st-reset" data-act="st-fs-reset">${ic("refresh")}${esc(F.t("settings.fs_reset", "Сбросить до 100%"))}</button>

      ${h3(F.t("settings.density", "Плотность списков"))}
      ${seg(
        "look.density",
        [
          ["compact", F.t("settings.dens_compact", "Компактно")],
          ["normal", F.t("settings.dens_normal", "Обычно")],
          ["airy", F.t("settings.dens_airy", "Просторно")],
        ],
        F.t("settings.density", "Плотность списков"),
      )}`;
  }
  F.route("/settings/appearance", {
    title: () => F.t("look.title", "Внешний вид"),
    sub: () => F.t("settings.title", "Настройки"),
    nav: false,
    back: true,
    actions: [],
    hideMini: true,
    render: () => F.withStates(renderLook, { loading: "cards" }),
    mount(page) {
      pg(page);
      const r = page.querySelector("#st-fs");
      if (!r) return;
      const paint = () => r.style.setProperty("--p", ((r.value - r.min) / (r.max - r.min)) * 100 + "%");
      paint();
      r.addEventListener("input", () => {
        document.documentElement.style.setProperty("--fs", r.value);
        page.querySelector("#st-fs-v").textContent = Math.round(r.value * 100) + "%";
        paint();
      });
    },
  });
  Object.assign(F.actions, {
    "st-theme": id => {
      state.look.theme = id;
      persist("look");
      try {
        localStorage.setItem("st-theme", id);
      } catch (e) {}
      F.setTheme(id === "system" ? (sysDark() ? "dark" : "light") : id);
      F.render(true);
    },
    "st-fs-reset": () => {
      document.documentElement.style.setProperty("--fs", 1);
      F.render(true);
    },
  });
  const _st = F.actions["st-set"];
  F.actions["st-set"] = a => {
    // Language: switch the active setting first (setLang stores it synchronously), so the render inside
    // st-set already highlights the new choice.
    const lang = a.startsWith("look.lang:") && F.i18n ? a.slice("look.lang:".length) : null;
    const done = lang ? F.i18n.setLang(lang === "AUTO" ? "auto" : lang) : null;
    _st(a);
    if (a.startsWith("look.density")) applyDensity(state.look.density);
    if (done)
      done.then(() => {
        F.snack(F.t("look.lang_switched", { label: LANG_L()[lang] || lang }));
      });
  };

  // ================= ABOUT & LICENSES =================
  const CHANGES = [
    [
      "2.0.0-beta.3",
      "2026-11-27",
      [
        "Облачный ИИ с живым списком моделей у 10 провайдеров и настройками рассуждений (Thinking)",
        "Пути компрометации (Attack Paths) и ключевые точки блокировки (Choke Points)",
        "Система плагинов с песочницей и подписанные базы сигнатур с откатом",
        "Шифрованный контейнер проекта .foca.enc (PBKDF2 + ChaCha20-Poly1305) и CLI foca run scenario.toml",
        "Живая локализация интерфейса (EN / RU / UA + автоязык устройства) и сборки Android foss / play",
      ],
    ],
    [
      "1.1.0",
      "2026-11-19",
      [
        "Мобильный интерфейс с вкладками проекта, мини-панелью скана и графом связей",
        "Отчёты HTML, DOCX, Markdown, CSV, JSON, STIX 2.1 с Chain of Custody",
        "Форензика документов, КЕП/подписи, маскирование ПДн и офлайн-импорт",
      ],
    ],
  ];
  // Texts are keyed by the release without the pre-release suffix (2.0.0-beta.3 → chg_2_0_0_*).
  const chgL = (v, i, x) => F.t(`settings.chg_${v.split("-")[0].replace(/\./g, "_")}_${i}`, x);
  const aboutMeta = (F.state.aboutMeta = F.state.aboutMeta || {
    version: "2.0.0-beta.3",
    flavor: "foss",
    loaded: false,
  });
  function loadAboutMeta() {
    if (aboutMeta.loaded || !F.api || !F.api.platform_device_info) return;
    aboutMeta.loaded = true;
    F.api
      .platform_device_info()
      .then(di => {
        if (!di) return;
        if (di.app_version) aboutMeta.version = di.app_version;
        if (di.flavor) aboutMeta.flavor = di.flavor;
        if (F.cur && (F.cur.path === "/settings/about" || F.cur.path === "/settings") && F.render)
          F.render(true);
      })
      .catch(() => {});
  }
  function renderAbout() {
    loadAboutMeta();
    const flavorLabel =
      aboutMeta.flavor === "play"
        ? F.t("licenses.flavor_play", "Play (с Google ML Kit OCR)")
        : F.t("licenses.flavor_foss", "FOSS (чистая GPL-3.0 / F-Droid, без ML Kit)");
    return `
      <div class="st-about">
        <img src="icon.png" alt="" class="st-ab-logo">
        <h2>FOCA-rs</h2>
        <p>${esc(F.t("settings.about_tagline", "OSINT, метаданные документов, форензика и аудит поверхности атаки"))}</p>
        <div class="st-ab-v" id="st-ab-v"
          title="${esc(F.t("settings.long_press_debug", "Долгое нажатие: отладка"))}"><span class="pill info">${esc(F.t("about.version", "Версия"))} ${esc(aboutMeta.version)}</span>${F.betaChip ? F.betaChip() : ""}<span class="pill ${aboutMeta.flavor === "play" ? "warn" : "ok"}">${esc(aboutMeta.flavor.toUpperCase())}</span></div>
      </div>
      <div class="banner warn">${ic("alert")}<div><b>${esc(F.t("settings.legal_b", "Используйте только с разрешения владельца системы."))}</b> ${esc(F.t("settings.legal_text", "Разведка и сканирование без письменного согласия могут нарушать закон (ст. 361 УК Украины и аналоги в других странах)."))}</div></div>
      <div class="list">
        ${ui.row({ lead: ui.leadIcon("history"), title: F.t("settings.changelog", "Журнал изменений"), sub: `${CHANGES[0][0]} (${CHANGES[0][1]})`, act: "st-changes" })}
        ${ui.row({ lead: ui.leadIcon("contract"), title: F.t("settings.terms", "Условия использования"), sub: F.t("settings.terms_sub", "Отказ от ответственности · только чтение"), act: "go:/settings/terms" })}
        ${ui.row({ lead: ui.leadIcon("contract", "var(--accent)"), title: F.t("about.licenses_row", "Лицензии и сторонние компоненты"), sub: F.t("about.licenses_sub", "Rust-крейты, Android-библиотеки, базы данных и полные тексты лицензий"), act: "go:/settings/licenses" })}
        ${ui.row({ lead: ui.leadIcon("shield"), title: F.t("about.build", "Вариант сборки"), sub: esc(flavorLabel) })}
        ${ui.row({ lead: ui.leadIcon("st-code"), title: F.t("about.repo", "Исходный код"), sub: "github.com/SinonApp/FOCA-rs", act: "st-src" })}
        ${F.reportProblem ? ui.row({ lead: ui.leadIcon("bug", "var(--warn)"), title: F.t("beta.report", "Сообщить о проблеме"), sub: F.t("beta.report_sub", "Журналы в Download/FOCA-rs и форма issue на GitHub"), act: "beta-report-about" }) : ""}
      </div>
      ${ui.secH(F.t("settings.whats_new", { v: CHANGES[0][0] }, "Что нового в {v}"))}
      <div class="card pad st-chg"><ul>${CHANGES[0][2].map((x, i) => `<li>${esc(chgL(CHANGES[0][0], i, x))}</li>`).join("")}</ul></div>
      <p class="fhint st-hint st-copy">${esc(F.t("settings.free_sw", "FOCA-rs: свободное ПО (GNU GPL v3.0): github.com/SinonApp/FOCA-rs."))}</p>`;
  }
  F.route("/settings/about", {
    title: () => F.t("about.title", "О программе"),
    sub: () => F.t("settings.title", "Настройки"),
    nav: false,
    back: true,
    actions: [],
    hideMini: true,
    render: () => F.withStates(renderAbout, { loading: "cards" }),
    mount: page => {
      pg(page);
      const versionEl = page.querySelector("#st-ab-v");
      let holdTimer = null;
      if (versionEl) {
        const off = () => clearTimeout(holdTimer);
        versionEl.addEventListener("pointerdown", () => {
          off();
          holdTimer = setTimeout(() => {
            try {
              navigator.vibrate && navigator.vibrate(30);
            } catch (e) {}
            F.go("/settings/debug");
          }, 900);
        });
        ["pointerup", "pointerleave", "pointercancel"].forEach(ev => versionEl.addEventListener(ev, off));
      }
    },
  });

  const licState = (F.state.licenses = F.state.licenses || {
    tab: "data",
    q: "",
    licFilter: "all",
    directOnly: false,
    data: null,
    loading: false,
    error: false,
  });
  function ensureLicenses() {
    if (licState.data || licState.loading || !F.api || !F.api.licenses_get) return;
    licState.loading = true;
    F.api
      .licenses_get()
      .then(d => {
        licState.data = d;
        licState.loading = false;
        licState.error = !d;
        if (F.cur && F.cur.path === "/settings/licenses" && F.render) F.render(true);
      })
      .catch(() => {
        licState.loading = false;
        licState.error = true;
        if (F.cur && F.cur.path === "/settings/licenses" && F.render) F.render(true);
      });
  }
  function renderLicList(d) {
    const q = licState.q.trim().toLowerCase();
    const lf = licState.licFilter;
    const matchLic = l =>
      lf === "all" ||
      String(l || "")
        .toLowerCase()
        .includes(lf.toLowerCase());
    if (licState.tab === "data") {
      const items = (d.data_assets || []).filter(
        x =>
          matchLic(x.license) &&
          (!q || `${x.name} ${x.category} ${x.license} ${x.notes}`.toLowerCase().includes(q)),
      );
      if (!items.length)
        return ui.empty({ icon: "search", title: F.t("common.nothing_found", "Ничего не нашлось") });
      return `<div class="list">${items
        .map(x =>
          ui.row({
            title: esc(x.name),
            sub: `${esc(x.category)} · ${esc(x.notes)}`,
            tail: `<span class="pill mute">${esc(x.license)}</span>`,
          }),
        )
        .join("")}</div>`;
    }
    if (licState.tab === "rust") {
      const items = (d.rust_crates || []).filter(
        x =>
          (!licState.directOnly || x.direct) &&
          matchLic(x.license) &&
          (!q || `${x.name} ${x.version} ${x.license}`.toLowerCase().includes(q)),
      );
      const shown = items.slice(0, 200);
      if (!shown.length)
        return ui.empty({ icon: "search", title: F.t("common.nothing_found", "Ничего не нашлось") });
      return `<p class="fhint st-hint">${items.length} / ${(d.rust_crates || []).length}${items.length > shown.length ? esc(" " + F.t("settings.shown_first", { n: shown.length }, "(показаны первые {n}; уточните поиск)")) : ""}</p>
        <div class="list">${shown
          .map(x =>
            ui.row({
              title: `${esc(x.name)} <span class="muted">${esc(x.version)}</span>`,
              sub: x.repository ? esc(x.repository) : "",
              tail: `${x.direct ? `<span class="pill info">direct</span>` : ""}<span class="pill mute">${esc(x.license)}</span>`,
            }),
          )
          .join("")}</div>`;
    }
    if (licState.tab === "android") {
      const items = (d.android_libs || []).filter(
        x =>
          matchLic(x.license) &&
          (!q || `${x.name} ${x.version} ${x.license} ${x.purpose} ${x.flavor}`.toLowerCase().includes(q)),
      );
      if (!items.length)
        return ui.empty({ icon: "search", title: F.t("common.nothing_found", "Ничего не нашлось") });
      return `<div class="list">${items
        .map(x =>
          ui.row({
            title: `${esc(x.name)} <span class="muted">${esc(x.version)}</span>`,
            sub: esc(x.purpose || ""),
            tail: `<span class="pill ${x.flavor === "play" ? "warn" : "ok"}">${esc(x.flavor)}</span><span class="pill mute">${esc(x.license)}</span>`,
          }),
        )
        .join("")}</div>`;
    }
    const texts = (d.license_texts || []).filter(
      x => !q || `${x.id} ${x.name} ${x.text}`.toLowerCase().includes(q),
    );
    if (!texts.length)
      return ui.empty({ icon: "search", title: F.t("common.nothing_found", "Ничего не нашлось") });
    return texts
      .map(
        x =>
          `<details class="card pad st-lic-det"><summary><b>${esc(x.id)}</b> <span class="muted">${esc(x.name)}</span></summary><pre class="st-lic-pre">${esc(x.text)}</pre></details>`,
      )
      .join("");
  }
  function renderLicenses() {
    if (!licState.data) {
      ensureLicenses();
      return licState.error ? ui.error() : ui.skeletonList(8);
    }
    const d = licState.data;
    const c = d.counts || {};
    const tabs = [
      ["data", F.t("licenses.tab_data", "Данные и ресурсы"), c.data_assets || 0],
      ["rust", F.t("licenses.tab_rust", "Rust-библиотеки"), c.rust_total || 0],
      ["android", F.t("licenses.tab_android", "Android-библиотеки"), c.android_total || 0],
      ["texts", F.t("licenses.tab_texts", "Тексты лицензий"), c.license_texts || 0],
    ];
    const filters = ["all", "GPL-3.0", "MIT", "Apache-2.0", "BSD", "MPL-2.0", "Unicode-3.0", "OFL"];
    return `
      <div class="st-lic-tabs" role="tablist">${tabs
        .map(
          ([id, lbl, cnt]) =>
            `<button class="chip ${licState.tab === id ? "on" : ""}" role="tab" aria-selected="${licState.tab === id}" data-act="st-lic-tab:${id}">${esc(lbl)} <span class="muted">${cnt}</span></button>`,
        )
        .join("")}</div>
      <div class="field hl-search">${ic("search")}<input id="st-lic-q" type="search"
        placeholder="${esc(F.t("licenses.search_placeholder", "Фильтр по названию, крейту или лицензии…"))}" value="${esc(licState.q)}" autocomplete="off"></div>
      ${
        licState.tab !== "texts"
          ? `<div class="st-lic-chips">${filters
              .map(
                f =>
                  `<button class="chip sm ${licState.licFilter === f ? "on" : ""}" data-act="st-lic-flt:${f}">${f === "all" ? esc(F.t("common.all", "Все")) : esc(f)}</button>`,
              )
              .join("")}${
              licState.tab === "rust"
                ? `<button class="chip sm ${licState.directOnly ? "on" : ""}" data-act="st-lic-dir">direct (${c.rust_direct || 0})</button>`
                : ""
            }</div>`
          : ""
      }
      <div id="st-lic-body">${renderLicList(d)}</div>`;
  }
  F.route("/settings/licenses", {
    title: () => F.t("licenses.title", "Лицензии и компоненты"),
    sub: () => F.t("about.title", "О программе"),
    nav: false,
    back: true,
    actions: [],
    hideMini: true,
    render: () => F.withStates(renderLicenses, { loading: "list" }),
    mount: page => {
      pg(page);
      const inp = page.querySelector("#st-lic-q");
      if (!inp) return;
      inp.addEventListener("input", () => {
        licState.q = inp.value;
        const body = page.querySelector("#st-lic-body");
        if (body && licState.data) body.innerHTML = renderLicList(licState.data);
      });
    },
  });
  Object.assign(F.actions, {
    "st-src": () => F.snack("https://github.com/SinonApp/FOCA-rs"),
    "st-changes": () =>
      F.sheet({
        title: F.t("settings.changelog", "Журнал изменений"),
        cls: "st-sheet",
        full: true,
        html: CHANGES.map(
          ([v, d, items]) =>
            `<div class="st-cl"><div class="st-cl-h"><b>${v}</b><span class="muted">${d}</span></div><ul>${items.map((x, i) => `<li>${esc(chgL(v, i, x))}</li>`).join("")}</ul></div>`,
        ).join(""),
      }),
    "st-lic": () => F.go("/settings/licenses"),
    "st-lic-tab": id => {
      licState.tab = id;
      F.render(true);
    },
    "st-lic-flt": f => {
      licState.licFilter = f;
      F.render(true);
    },
    "st-lic-dir": () => {
      licState.directOnly = !licState.directOnly;
      F.render(true);
    },
  });

  // ================= SIGNATURE DATABASES =================
  const sigState = (F.state.sigBundle = F.state.sigBundle || {
    data: null,
    loading: false,
    busy: false,
    error: "",
  });
  function loadSigStatus(force = false) {
    if (!F.api || !F.api.signatures_status) return;
    if (sigState.loading || (sigState.data && !force)) return;
    sigState.loading = true;
    sigState.error = "";
    F.api.signatures_status().then(
      d => {
        sigState.data = d;
        sigState.loading = false;
        if (F.cur && F.cur.path === "/settings/signatures" && F.render) F.render(true);
      },
      e => {
        sigState.loading = false;
        sigState.error = (e && e.message) || String(e || "error");
        if (F.cur && F.cur.path === "/settings/signatures" && F.render) F.render(true);
      },
    );
  }
  const shortHex = s => {
    const v = String(s || "");
    return v.length > 20 ? `${v.slice(0, 10)}…${v.slice(-8)}` : v || "-";
  };
  // Dates in the app format (20.11.2026) never break inside: hyphens and spaces stay on one line.
  const sigDate = iso => `<span class="st-nw">${esc(F.fmt.dmy(String(iso || "")) || "-")}</span>`;
  // Escapes `text` and keeps hyphenated document codes (800-53, 2.5-004-99) on one line, so a line
  // break falls between words, never inside a code.
  const noBreakCodes = text =>
    String(text)
      .split(" ")
      .map(w => (w.includes("-") ? `<span class="st-nw">${esc(w)}</span>` : esc(w)))
      .join(" ");
  const sigAge = days =>
    days === 0
      ? F.t("settings.sig_today", "сегодня")
      : F.tp("settings.days_ago", days, { n: days }, "{n} день назад|{n} дня назад|{n} дней назад");
  // Last update check: local time and outcome in words; "never" before the first check.
  function sigLastCheck(c) {
    if (!c || !c.outcome) return esc(F.t("settings.sig_never", "ещё не проверялось"));
    const at = F.fmt.dmyhm(String(c.at || ""));
    const what =
      c.outcome === "installed"
        ? F.t("settings.sig_out_installed", { v: c.version || "" }, "установлена версия {v}")
        : c.outcome === "up_to_date"
          ? F.t("settings.sig_out_up_to_date", "новее нет, база актуальна")
          : c.outcome === "no_update"
            ? F.t("settings.sig_out_no_update", "новая база ещё не опубликована")
            : F.t("settings.sig_out_failed", { e: F.coreMsg(c.error || "", c.error_msg) }, "ошибка: {e}");
    return `<span class="st-nw">${esc(at)}&nbsp;·</span> ${esc(what)}`;
  }
  function renderSig() {
    loadAboutMeta();
    const d = sigState.data;
    if (!d) {
      loadSigStatus(false);
      if (sigState.error) return ui.error({ text: sigState.error, retry: "st-sigref" });
      return ui.skeletonCards(3);
    }
    const ocr = (F.db.settings || {}).ocr || { enabled: false, max_pages: 10, max_mb: 15 };
    const cnt = d.counts || {};
    const kev = d.kev || {};
    const sw = d.software || {};
    const sm = d.std_map || {};
    const fmtInt = n => F.fmtNum(Number(n || 0));
    const isFoss = aboutMeta.flavor === "foss";
    const bundle = d.source === "bundle";
    const line = html => `<span class="st-sigl">${html}</span>`;
    // Labels come from the core mapping; Ukrainian document names use the UI spelling (ND TZI in EN).
    const fwLabel = f => {
      const label = String(f.label || "").replace(/НД ТЗІ/g, F.t("findings.std.ndtzi", "НД ТЗІ"));
      return f.legacy ? F.t("settings.std_legacy", { label }, "{label} (устаревшие, КСЗИ)") : label;
    };
    const rows = [
      [
        "app",
        F.t("settings.sig_sw", "ПО и ОС"),
        line(
          esc(
            F.tp(
              "settings.n_sigs",
              cnt.cpe,
              { n: fmtInt(cnt.cpe) },
              "{n} сигнатура|{n} сигнатуры|{n} сигнатур",
            ),
          ),
        ) +
          line(
            esc(
              F.t(
                "settings.sig_sw_split",
                { sw: fmtInt(sw.software), os: fmtInt(sw.os) },
                "ПО: {sw}, ОС: {os}",
              ),
            ),
          ),
      ],
      [
        "bug",
        F.t("settings.sig_kev", "CISA KEV: эксплуатируемые уязвимости"),
        line(
          esc(
            F.t(
              "settings.sig_kev_used",
              { used: fmtInt(kev.used), total: fmtInt(kev.total) },
              "Для сопоставления: {used} из {total} в каталоге",
            ),
          ),
        ) +
          line(
            `${F.t("settings.sig_kev_date", { date: sigDate(kev.released) }, "Каталог от {date}")}${
              kev.age_days == null ? "" : `&nbsp;· <span class="st-nw">${esc(sigAge(kev.age_days))}</span>`
            }`,
          ),
      ],
      [
        "key",
        F.t("settings.sig_secrets", "Секреты"),
        line(
          esc(
            F.tp(
              "settings.n_rules",
              cnt.secrets,
              { n: fmtInt(cnt.secrets) },
              "{n} правило|{n} правила|{n} правил",
            ) +
              (d.added_secrets
                ? " " + F.t("settings.incl_bundle", { n: d.added_secrets }, "(в т. ч. {n} из пакета)")
                : ""),
          ),
        ),
      ],
      [
        "shield",
        F.t("settings.sig_std", "Стандарты"),
        line(
          esc(
            `${F.tp("settings.n_maps", sm.refs, { n: fmtInt(sm.refs) }, "{n} сопоставление|{n} сопоставления|{n} сопоставлений")} · ${F.tp(
              "settings.n_finding_rules",
              sm.rules,
              { n: fmtInt(sm.rules) },
              "{n} правило находок|{n} правила находок|{n} правил находок",
            )}`,
          ),
        ) + line(noBreakCodes((sm.frameworks || []).map(fwLabel).join(", "))),
      ],
    ];
    // Offline NVD CVE table: snapshot date and CVE counts per group.
    const nvd = d.nvd || {};
    if (nvd.cves)
      rows.push([
        "bug",
        F.t("settings.sig_nvd", "CVE (NVD)"),
        line(
          esc(
            F.t(
              "settings.sig_nvd_line",
              { n: fmtInt(nvd.cves), date: nvd.snapshot || "-" },
              "{n} CVE · снимок NVD {date}",
            ),
          ),
        ) +
          line(
            esc(
              F.t(
                "settings.sig_nvd_groups",
                {
                  site: fmtInt(nvd.site),
                  plugin: fmtInt(nvd.plugin),
                  doc: fmtInt(nvd.doc),
                  os: fmtInt(nvd.os),
                },
                "сайт: {site} · плагины: {plugin} · ПО документов: {doc} · ОС: {os}",
              ),
            ),
          ) +
          ((d.skipped_tables || []).length
            ? line(
                esc(
                  F.t(
                    "settings.sig_skipped",
                    { list: d.skipped_tables.join(", ") },
                    "Пропущены таблицы новой версии: {list}",
                  ),
                ),
              )
            : ""),
      ]);
    // Ingested upstream tables: records the core really loaded and the upstream pin.
    const tables = d.tables || [];
    if (tables.length)
      rows.push([
        "db",
        F.t("settings.sig_tables", "Внешние источники"),
        tables
          .map(t =>
            line(
              `${esc(
                F.t(
                  "settings.sig_tbl_line",
                  { label: F.t("signatures.tbl." + t.id, t.id), n: fmtInt(t.records) },
                  "{label}: {n}",
                ),
              )}&nbsp;· <span class="st-nw">${esc(t.version || "-")}</span>`,
            ),
          )
          .join(""),
      ]);
    const title = sigState.busy
      ? F.t("settings.running", "Выполняется…")
      : F.t("settings.version_v", { v: d.version || "-" }, "Версия {v}");
    return `
      <div class="card pad st-sigtop">
        <div class="st-sigtop-b">
          ${ui.leadIcon("st-sig", d.signature_valid ? "var(--ok)" : "var(--bad)")}
          <div class="st-sigtop-t">
            <b>${esc(title)}</b>
            <span>${esc(bundle ? F.t("settings.signed_bundle", "Подписанный пакет") : F.t("settings.builtin_db", "Встроенная база"))}&nbsp;· ${sigDate(d.updated_at)}</span>
          </div>
          ${bundle ? `<span class="pill ${d.signature_valid ? "ok" : "bad"} st-sigpill">${d.signature_valid ? "Ed25519 OK" : esc(F.t("settings.not_verified", "Не проверено"))}</span>` : ""}
        </div>
        ${
          kev.stale
            ? `<div class="banner warn st-sigstale">${ic("alert")}<div>${F.t(
                "settings.sig_stale",
                { date: sigDate(kev.released), age: esc(sigAge(kev.age_days)) },
                "Каталог CISA KEV от {date} устарел ({age}). Проверьте обновления.",
              )}</div></div>`
            : ""
        }
        <div class="kv st-sigkv">
          <div class="kvr"><div class="k">${esc(F.t("settings.sig_last_check", "Последняя проверка"))}</div><div class="v" id="st-siglast">${sigLastCheck(d.last_check)}</div></div>
          <div class="kvr"><div class="k">SHA-256</div><div class="v mono">${esc(shortHex(d.sha256))}</div></div>
          <div class="kvr"><div class="k">${esc(F.t("settings.ed_key", "Ключ Ed25519"))}</div><div class="v mono">${esc(shortHex(d.pubkey_ed25519))}</div></div>
        </div>
        <div class="btnrow">
          <button class="btn primary" data-act="st-sigupd" ${sigState.busy ? "disabled" : ""}>${ic(sigState.busy ? "spin" : "refresh", sigState.busy ? "spin" : "")}${esc(F.t("signatures.update", "Проверить обновления"))}</button>
          <button class="btn tonal" data-act="st-sigimp" ${sigState.busy ? "disabled" : ""}>${ic("download")}${esc(F.t("signatures.import", "Импортировать пакет"))}</button>
          ${d.can_rollback ? `<button class="btn" data-act="st-sigrb" ${sigState.busy ? "disabled" : ""}>${ic("history")}${esc(F.t("signatures.rollback", "Откатить"))}</button>` : ""}
        </div>
      </div>
      ${ui.secH(F.t("settings.db_contents", "Содержимое базы"), rows.length)}
      <div class="list st-siglist">${rows.map(([i, t, sub]) => ui.row({ lead: ui.leadIcon(i), title: t, sub })).join("")}</div>

      ${ui.secH(F.t("settings.ocr_h", "Офлайн-OCR сканов (Android ML Kit)"))}
      ${isFoss ? `<div class="banner info">${ic("info")}<div>${rich(F.t("settings.foss_ocr", "Сборка [b]foss[/b] (GPL-3.0 / F-Droid) не содержит проприетарного Google ML Kit: на устройстве OCR возвращает [code]unavailable_in_foss_build[/code]. Для офлайн-OCR используйте флейвор [b]play[/b]."))}</div></div>` : ""}
      <div class="list">
        <div class="row">
          ${ui.leadIcon("doc", ocr.enabled ? "var(--ok)" : "")}
          <div class="body">
            <div class="t">${esc(F.t("settings.ocr_t", "Распознавать текст в сканах PDF и фото"))}</div>
            <div class="s">${esc(F.t("settings.ocr_s", "Запускается 100% локально на устройстве (ML Kit Text Recognition во флейворе play), только когда в файле нет текстового слоя (< 40 символов)"))}</div>
          </div>
          <div class="tail">${ui.toggle(!!ocr.enabled, "st-ocr-tog", `aria-label="${esc(F.t("settings.ocr_aria", "Офлайн-OCR сканов"))}"`)}</div>
        </div>
      </div>
      <div class="card nfs st-nfs">${["max_pages", "max_mb"]
        .map(k =>
          F.numField({
            id: "ocr-" + k,
            label:
              k === "max_pages"
                ? esc(F.t("settings.ocr_pages", "Максимум страниц PDF для OCR"))
                : esc(F.t("settings.ocr_mb", "Максимальный размер файла для OCR")),
            unit: k === "max_pages" ? F.t("settings.pages_unit", "стр.") : F.t("settings.mb", "МБ"),
            lim: "ocr." + k,
            step: 5,
            get: () => +(ocr[k] || (k === "max_pages" ? 10 : 15)),
            set: v => F.api.settings_set({ ocr: { [k]: v } }).then(() => F.render(true)),
          }),
        )
        .join("")}</div>
      <p class="fhint st-hint">${ic("lock")}${esc(F.t("settings.ocr_hint", "По умолчанию выключено для экономии батареи. Распознанный текст индексируется в FTS5 и проверяется детектором ПДн с обязательной маскировкой."))}</p>`;
  }
  F.route("/settings/signatures", {
    title: () => F.t("signatures.title", "Базы сигнатур"),
    sub: () => F.t("settings.title", "Настройки"),
    nav: false,
    back: true,
    actions: [],
    hideMini: true,
    render: () =>
      F.withStates(renderSig, {
        loading: "list",
        empty: {
          icon: "st-sig",
          title: F.t("settings.sig_empty", "Базы не загружены"),
          text: F.t(
            "settings.sig_empty_text",
            "Загрузите подписанный пакет сигнатур ПО, CVE и правил поиска секретов.",
          ),
          action: `<button class="btn primary" data-act="st-sigupd">${ic("refresh")}${esc(F.t("signatures.update", "Проверить обновления"))}</button>`,
        },
      }),
    mount: page => pg(page),
  });
  Object.assign(F.actions, {
    "st-sigref": () => {
      loadSigStatus(true);
    },
    "st-sigupd": () => {
      if (!F.api || !F.api.signatures_update || sigState.busy) return;
      sigState.busy = true;
      F.render(true);
      const done = () => {
        sigState.busy = false;
        if (F.current() === "/settings/signatures") F.render(true);
      };
      F.api.signatures_update().then(
        d => {
          sigState.data = d;
          const c = d.last_check || {},
            v = d.version || "";
          F.snack(
            c.outcome === "installed"
              ? F.t("settings.sig_snack_installed", { v }, "Установлена база сигнатур {v}")
              : c.outcome === "up_to_date"
                ? F.t("settings.sig_snack_up_to_date", { v }, "Обновлений нет: версия {v} актуальна")
                : F.t(
                    "settings.sig_snack_no_update",
                    { v },
                    "Новая база ещё не опубликована. Используется текущая версия {v}",
                  ),
          );
          done();
        },
        e => {
          // The failed check is recorded by the core: reload the status to show it.
          loadSigStatus(true);
          F.snack(
            F.t(
              "settings.sig_snack_failed",
              { e: F.coreMsg((e && e.message) || String(e || ""), e && e.message_msg) },
              "Проверка не удалась: {e}",
            ),
          );
          done();
        },
      );
    },
    "st-sigimp": () => {
      F.sheet({
        title: F.t("signatures.import", "Импортировать пакет сигнатур"),
        html: `<p class="fhint">${rich(F.t("settings.bundle_hint", "Вставьте JSON подписанного пакета (схема [code]foca-sig-bundle/v2[/code], SHA-256 и подпись Ed25519 проверяются до применения)."))}</p>
          <textarea id="st-sig-json" class="in mono" rows="8" placeholder='{"schema":"foca-sig-bundle/v2",...}'></textarea>`,
        footer: `<button class="btn" data-act="sheet-close">${esc(F.t("common.cancel", "Отмена"))}</button><button class="btn primary" data-act="st-sigimp-go">${ic("check")}${esc(F.t("signatures.import", "Импортировать"))}</button>`,
      });
    },
    "st-sigimp-go": () => {
      const ta = document.getElementById("st-sig-json");
      const raw = ta ? ta.value.trim() : "";
      if (!raw) {
        F.snack(F.t("settings.paste_bundle", "Вставьте JSON пакета сигнатур"));
        return;
      }
      sigState.busy = true;
      F.api.signatures_import(raw).then(
        d => {
          sigState.busy = false;
          sigState.data = d;
          F.closeSheet();
          F.snack(
            F.t("settings.bundle_ok", { v: d.version || "" }, "Пакет сигнатур {v} установлен и проверен"),
          );
          if (F.current() === "/settings/signatures") F.render(true);
        },
        e => {
          sigState.busy = false;
          F.snack((e && e.message) || F.t("settings.bundle_bad", "Неверная подпись или формат пакета"));
        },
      );
    },
    "st-sigrb": () => {
      if (!F.api || !F.api.signatures_rollback || sigState.busy) return;
      sigState.busy = true;
      F.render(true);
      F.api.signatures_rollback().then(
        d => {
          sigState.busy = false;
          sigState.data = d;
          F.snack(
            F.t("settings.rollback_ok", { v: (d && d.version) || "builtin" }, "Выполнен откат к версии {v}"),
          );
          if (F.current() === "/settings/signatures") F.render(true);
        },
        e => {
          sigState.busy = false;
          F.snack((e && e.message) || F.t("settings.rollback_fail", "Не удалось выполнить откат"));
          if (F.current() === "/settings/signatures") F.render(true);
        },
      );
    },
    "st-ocr-tog": () => {
      const cur = ((F.db.settings || {}).ocr || {}).enabled;
      F.api.settings_set({ ocr: { enabled: !cur } }).then(() => F.render(true));
    },
  });
})();
