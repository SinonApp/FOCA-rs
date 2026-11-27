/*
 * FOCA-rs UI core (mobile only).
 * Screens live in separate files under /screens and register themselves via FOCA.route(...).
 * Button actions: data-act="name:argument" → FOCA.actions[name](arg, el, event).
 */
(function () {
  const F = (window.FOCA = window.FOCA || {});
  const $ = (s, r = document) => r.querySelector(s);
  const $$ = (s, r = document) => [...r.querySelectorAll(s)];
  const esc = s =>
    String(s ?? "").replace(/[&<>"]/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[c]);
  const ic = (n, cls = "") => `<svg class="i ${cls}" aria-hidden="true"><use href="#i-${n}"/></svg>`;
  F.$ = $;
  F.$$ = $$;
  F.esc = esc;
  // decodeURIComponent that keeps the raw text on malformed escapes (e.g. a stray "%" in a URL).
  F.decode = s => {
    try {
      return decodeURIComponent(s);
    } catch (e) {
      return String(s ?? "");
    }
  };
  F.ic = ic;
  F.actions = F.actions || {};
  // ⋮ menu items: { id, icon, label, sub, act, order, chev, show() }; screens may append their own
  // (F.menuItems.push(...)). icon/label/sub may be functions evaluated when the menu opens.
  F.menuItems = F.menuItems || [];
  F.routes = [];
  F.state = F.state || {};

  // ---------- localization (EN / RU / UA + auto device locale, loaded via IPC i18n_bundle) ----------
  const i18nState = {
    lang: "ru",
    setting: "auto",
    uiCode: "RU",
    dict: {},
    helpCache: {},
    helpLoading: {},
  };
  const normLangCode = raw => {
    const low = String(raw || "")
      .trim()
      .toLowerCase();
    if (!low || low === "auto") return "auto";
    const head = low.split(/[-_]/)[0];
    if (head === "ru" || head === "rus") return "ru";
    if (head === "uk" || head === "ua" || head === "ukr") return "uk";
    if (head === "en" || head === "eng") return "en";
    return "en";
  };
  const uiCodeOf = lang => (lang === "uk" ? "UA" : lang === "en" ? "EN" : "RU");
  const detectDeviceLocale = () => {
    try {
      const env = globalThis.process && globalThis.process.env;
      if (env && env.FOCA_LANG) return env.FOCA_LANG;
    } catch (e) {}
    if (F.state.deviceLocale) return F.state.deviceLocale;
    if (typeof navigator !== "undefined") {
      const langs =
        navigator.languages && navigator.languages.length ? navigator.languages : [navigator.language];
      if (langs[0]) return langs[0];
    }
    // Bare Node QA harness fallback keeps existing QA checks backward compatible.
    return "ru-RU";
  };
  const fmtVars = (tpl, params) => {
    if (!params) return tpl;
    return String(tpl).replace(/\{([a-zA-Z0-9_]+)\}/g, (_, k) =>
      k in params && params[k] != null ? String(params[k]) : `{${k}}`,
    );
  };
  /** Translates a UI key with optional `{param}` interpolation and optional default fallback. */
  F.t = (key, params, fallback) => {
    if (typeof params === "string" && fallback === undefined) {
      fallback = params;
      params = null;
    }
    const raw =
      Object.prototype.hasOwnProperty.call(i18nState.dict, key) && i18nState.dict[key] != null
        ? i18nState.dict[key]
        : (fallback ?? key);
    return fmtVars(raw, params);
  };
  /**
   * Renders a text produced by the core in the UI language. `msg` is the `{ code, params }` the core
   * sends next to the Russian text (`error_msg`, `detail_msg`, …); parameters may nest messages and
   * `join` lists notes separated by "; ". Unknown codes fall back to the original text.
   */
  F.coreMsg = (text, msg) => {
    const raw = text == null ? "" : String(text);
    if (!msg || typeof msg !== "object" || !msg.code) return raw;
    if (msg.code === "join") return (msg.parts || []).map(p => F.coreMsg(p && p.text, p)).join("; ");
    const params = {};
    Object.entries(msg.params || {}).forEach(([k, v]) => {
      params[k] = v && typeof v === "object" ? F.coreMsg(v.text, v) : v;
    });
    return F.t(`core.${msg.code}`, params, raw);
  };
  /** Pluralizes `n`: Slavic 1/2-4/5+ rules for ru/uk, 1/other for en. */
  F.plural = (n, one, few, many) => {
    const forms = Array.isArray(one) ? one : [one, few, many];
    const abs = Math.abs(Number(n) || 0);
    if (i18nState.lang === "en") return `${n} ${abs === 1 ? forms[0] : (forms[1] ?? forms[2] ?? forms[0])}`;
    const a = abs % 10,
      b = abs % 100;
    const form =
      a === 1 && b !== 11
        ? forms[0]
        : a >= 2 && a <= 4 && (b < 12 || b > 14)
          ? forms[1]
          : (forms[2] ?? forms[1]);
    return `${n} ${form}`;
  };
  /** Index of the plural form of `n`: 0 one, 1 few, 2 many (ru/uk); 0 one, 1 other (en). */
  F.pluralIndex = n => {
    const abs = Math.abs(Number(n) || 0);
    if (i18nState.lang === "en") return abs === 1 ? 0 : 1;
    const a = abs % 10,
      b = abs % 100;
    return a === 1 && b !== 11 ? 0 : a >= 2 && a <= 4 && (b < 12 || b > 14) ? 1 : 2;
  };
  /**
   * Translates a template whose dictionary value lists the plural variants as "one|few|many" (ru/uk) or
   * "one|other" (en), picks the variant for `count` and interpolates `params`. Numbers in `params` are shown
   * with the locale's grouping (87 663).
   */
  F.tp = (key, count, params, fallback) => {
    const p = {};
    Object.entries(params || {}).forEach(([k, v]) => {
      p[k] = typeof v === "number" && Number.isFinite(v) ? F.fmtNum(v) : v;
    });
    const forms = String(F.t(key, p, fallback)).split("|");
    const i = F.pluralIndex(count);
    return forms[Math.min(i, forms.length - 1)];
  };
  /** Number with the grouping of the UI language (non-breaking space in ru/uk). */
  F.fmtNum = n =>
    Number(n)
      .toLocaleString(i18nState.lang === "en" ? "en-US" : i18nState.lang === "uk" ? "uk-UA" : "ru-RU")
      .replace(/\u202f|\u00a0/g, "\u00a0");
  const syncStaticChrome = () => {
    if (typeof document === "undefined" || !document.documentElement) return;
    document.documentElement.lang = i18nState.lang;
    const ab = $("#activebar");
    if (ab) {
      const ip = $("#ab-ip");
      const ipTxt = ip ? ip.textContent : "";
      ab.innerHTML = `${ic("alert")}${esc(F.t("app.active_mode", "АКТИВНЫЙ РЕЖИМ"))}<span class="ip" id="ab-ip">${esc(ipTxt)}</span>`;
    }
    const off = $("#offline");
    if (off)
      off.innerHTML = `${ic("wifi-off")}${esc(F.t("app.offline", "Нет сети: показаны сохранённые данные"))}`;
    const biT = $("#bi-t");
    if (biT) biT.textContent = F.t("app.secrets_open", "Секреты открыты");
    const biBtn = $("#bioind button");
    if (biBtn) {
      biBtn.textContent = F.t("app.secrets_close", "Закрыть");
      biBtn.setAttribute("aria-label", F.t("app.secrets_close_aria", "Закрыть доступ к секретам"));
    }
    const tbBack = $("#tb-back");
    if (tbBack) tbBack.setAttribute("aria-label", F.t("app.back", "Назад"));
    const mini = $("#mini");
    if (mini) mini.setAttribute("aria-label", F.t("app.mini_open_aria", "Открыть экран скана"));
    const navEl = $("#nav");
    if (navEl) navEl.setAttribute("aria-label", F.t("app.nav_aria", "Разделы проекта"));
  };
  F.i18n = {
    lang: () => i18nState.lang,
    setting: () => i18nState.setting,
    uiCode: () => i18nState.uiCode,
    normalize: normLangCode,
    detectDeviceLocale,
    help: () => i18nState.helpCache[i18nState.lang] || null,
    applyBundle(bundle, { silent = false } = {}) {
      if (!bundle || typeof bundle !== "object") return;
      if (bundle.lang) i18nState.lang = bundle.lang;
      if (bundle.setting) i18nState.setting = bundle.setting;
      i18nState.uiCode = bundle.ui_code || uiCodeOf(i18nState.lang);
      // Native notifications and the verify screen follow the UI language.
      try {
        if (window.FocaNative && FocaNative.setLang) FocaNative.setLang(i18nState.lang);
      } catch (_) {}
      if (bundle.ui && typeof bundle.ui === "object") i18nState.dict = bundle.ui;
      // Finding texts written by the core in Russian are rendered from this catalog (ui/js/ftext.js).
      if (F.ftext) F.ftext.setCatalog(i18nState.lang, bundle.findings || null);
      if (bundle.help && typeof bundle.help === "object") i18nState.helpCache[i18nState.lang] = bundle.help;
      syncStaticChrome();
      if (!silent) {
        if (F.emit) F.emit("i18n", { lang: i18nState.lang, setting: i18nState.setting });
        if (F.cur && F.render) F.render(true);
      }
    },
    load(setting, { includeHelp = false, deviceLocale, silent = false } = {}) {
      if (!F.api || !F.api.i18n_bundle) return Promise.resolve(null);
      return F.api
        .i18n_bundle({
          lang: setting ?? i18nState.setting,
          device_locale: deviceLocale || detectDeviceLocale(),
          include_help: !!includeHelp,
        })
        .then(bundle => {
          F.i18n.applyBundle(bundle, { silent });
          return bundle;
        });
    },
    loadHelp() {
      const lang = i18nState.lang;
      if (i18nState.helpCache[lang]) return Promise.resolve(i18nState.helpCache[lang]);
      if (i18nState.helpLoading[lang]) return i18nState.helpLoading[lang];
      if (!F.api || !F.api.i18n_bundle) return Promise.resolve(null);
      const p = F.api
        .i18n_bundle({ lang, device_locale: detectDeviceLocale(), include_help: true })
        .then(bundle => {
          delete i18nState.helpLoading[lang];
          if (bundle && bundle.help) i18nState.helpCache[bundle.lang || lang] = bundle.help;
          return (bundle && bundle.help) || null;
        })
        .catch(e => {
          delete i18nState.helpLoading[lang];
          throw e;
        });
      i18nState.helpLoading[lang] = p;
      return p;
    },
    setLang(rawSetting) {
      const setting = normLangCode(rawSetting);
      i18nState.setting = setting;
      const uiLook = setting === "auto" ? "AUTO" : uiCodeOf(setting);
      const saveP =
        F.api && F.api.settings_set
          ? F.api.settings_set({ lang: setting, ui: { look: { lang: uiLook } } })
          : Promise.resolve();
      return saveP.then(() => F.i18n.load(setting, { includeHelp: !!i18nState.helpCache[i18nState.lang] }));
    },
  };

  // ---------- theme and system bars ----------
  F.setTheme = t => {
    document.documentElement.dataset.theme = t;
    try {
      localStorage.setItem("theme", t);
    } catch (e) {}
    const bar = getComputedStyle(document.documentElement).getPropertyValue("--bar").trim();
    const m = $('meta[name="theme-color"]');
    if (m) m.content = bar;
    try {
      window.FocaNative && FocaNative.setBars(t === "dark", bar);
    } catch (e) {}
  };
  // The native side calls window.__setInsets(top, bottom, left, right) with CSS pixel values.
  window.__setInsets = (t, b, l, r) => {
    const s = document.documentElement.style;
    s.setProperty("--native-top", (t | 0) + "px");
    s.setProperty("--native-bottom", (b | 0) + "px");
    s.setProperty("--native-left", (l | 0) + "px");
    s.setProperty("--native-right", (r | 0) + "px");
  };

  // ---------- demo state switcher (to preview empty / loading / error / offline states) ----------
  F.demo = { mode: "normal" }; // normal | empty | loading | error
  F.setDemoMode = m => {
    F.demo.mode = m;
    F.render(true);
  };
  // Network change: shows the banner and emits bus event "net" {online} (a scan pauses and resumes on its
  // own).
  F.setOffline = on => {
    const was = !!F.state.offline;
    F.state.offline = !!on;
    $("#offline").classList.toggle("show", !!on);
    if (was !== !!on && F.emit) F.emit("net", { online: !on });
  };

  // ---------- reusable UI building blocks ----------
  F.ui = {
    empty: ({ icon = "search", title, text = "", action = "" } = {}) =>
      `<div class="empty"><div class="em-ic">${ic(icon)}</div><h3>${esc(title ?? F.t("common.empty", "Пока пусто"))}</h3>${text ? `<p>${esc(text)}</p>` : ""}${action}</div>`,
    error: ({ title, text, retry = "retry" } = {}) =>
      `<div class="empty"><div class="em-ic"
        style="color:var(--bad)">${ic("alert")}</div><h3>${esc(title ?? F.t("common.error_title", "Не удалось загрузить"))}</h3><p>${esc(text ?? F.t("common.error_text", "Проверьте подключение и попробуйте снова."))}</p><button class="btn tonal"
        data-act="${retry}">${ic("refresh")}${esc(F.t("common.retry", "Повторить"))}</button></div>`,
    skeletonList: (n = 6) =>
      `<div class="list">${Array.from(
        { length: n },
        () => `<div class="skrow"><div class="skel"
        style="width:36px;height:36px;border-radius:10px"></div><div style="flex:1"><div class="skel"
        style="height:14px;width:70%"></div><div class="skel"
        style="height:11px;width:45%;margin-top:8px"></div></div></div>`,
      ).join("")}</div>`,
    skeletonCards: (n = 3) =>
      Array.from(
        { length: n },
        () =>
          `<div class="card pad" style="margin-bottom:10px"><div class="skel"
            style="height:16px;width:50%"></div><div class="skel"
            style="height:12px;width:85%;margin-top:12px"></div><div class="skel"
            style="height:12px;width:65%;margin-top:8px"></div></div>`,
      ).join(""),
    secH: (title, extra = "", action = "") =>
      `<div class="sec-h"><h2>${esc(title)}</h2>${extra ? `<span class="muted">${extra}</span>` : ""}${action}</div>`,
    row: ({ lead = "", title, sub = "", tail = "", act = "", chev = !!act, cls = "", attrs = "" }) =>
      `<div class="row ${act ? "tap" : ""} ${cls}"
        ${act ? `data-act="${esc(act)}"` : ""} ${attrs}>${lead}<div class="body"><div class="t">${title}</div>${sub ? `<div class="s">${sub}</div>` : ""}</div>${tail ? `<div class="tail">${tail}</div>` : ""}${chev ? ic("chev", "chev") : ""}</div>`,
    leadIcon: (name, color = "") =>
      `<div class="lead-ic"
        ${color ? `style="color:${color};background:color-mix(in srgb, ${color} 15%, transparent)"` : ""}>${ic(name)}</div>`,
    toggle: (on, act = "toggle", attrs = "") =>
      `<button class="toggle ${on ? "on" : ""}" role="switch" aria-checked="${!!on}" data-act="${act}"
        ${attrs}></button>`,
    sev: s =>
      ({
        crit: `<span class="pill crit">${ic("alert")}${esc(F.t("sev.crit", "Критический"))}</span>`,
        high: `<span class="pill bad">${ic("alert")}${esc(F.t("sev.high", "Высокий"))}</span>`,
        warn: `<span class="pill warn">${ic("info")}${esc(F.t("sev.warn", "Средний"))}</span>`,
        low: `<span class="pill info">${ic("info")}${esc(F.t("sev.low", "Низкий"))}</span>`,
        info: `<span class="pill mute">${ic("info")}${esc(F.t("sev.info", "Инфо"))}</span>`,
        ok: `<span class="pill ok">${ic("check")}${esc(F.t("sev.ok", "Норма"))}</span>`,
      })[s] || "",
    check: (on, label, act = "toggle-check", sub = "") =>
      `<div class="checkrow ${on ? "on" : ""}" role="checkbox" aria-checked="${!!on}"
        data-act="${act}"><span class="cb">${ic("check")}</span><span class="lbl">${label}${sub ? `<small>${sub}</small>` : ""}</span></div>`,
    secret: (val, id) => `<span class="secret masked" data-secret="${id || ""}">${esc(val)}</span>`,
    /**
     * Themed replacement of a native <select>: a field-like button that opens F.choose. It keeps the
     * select contract for screen code: `.value` holds the value and a `change` event bubbles on pick.
     * @param {{id: string, value: string, options: Array<{v: string, t: string, s?: string}>, title?: string, attrs?: string, cls?: string}} o
     */
    select: ({ id, value, options, title = "", attrs = "", cls = "" }) => {
      pickReg[id] = { options, title };
      const cur = options.find(o => String(o.v) === String(value)) || options[0] || { v: "", t: "" };
      return `<button type="button" class="pick ${cls}" id="${esc(id)}" value="${esc(String(cur.v))}"
        data-act="pick:${esc(id)}" aria-haspopup="dialog" ${attrs}><span class="pk-b"><span
        class="pk-t">${esc(cur.t)}</span>${cur.s ? `<span class="pk-s">${esc(cur.s)}</span>` : ""}</span>${ic("chev-down", "pk-c")}</button>`;
    },
  };
  // Options of the F.ui.select buttons on screen, by element id (refreshed on every render).
  const pickReg = {};
  /**
   * Wraps a screen renderer: the screen draws its normal state, the core substitutes demo states.
   * @param {Function} normal Renders the normal state.
   * @param {{empty?: object, loading?: string, error?: object}} [states]
   */
  F.withStates = (normal, { empty, loading = "list", error } = {}) => {
    const m = F.demo.mode;
    if (m === "loading") return loading === "cards" ? F.ui.skeletonCards() : F.ui.skeletonList();
    if (m === "error") return F.ui.error(error || {});
    if (m === "empty") return F.ui.empty(empty || {});
    return typeof normal === "function" ? normal() : normal;
  };

  // ---------- stack-based router ----------
  // F.route("/p/findings", { title, sub, tab, render(params), mount(page, params), fab, actions, search,
  // back, nav }). fab = { icon, label, act, compact, until }: with `until` (a selector) the FAB stays
  // hidden while that element is on screen, so it never sits on top of the same inline control.
  F.route = (pattern, def) => {
    const keys = [];
    const rx = new RegExp("^" + pattern.replace(/:(\w+)/g, (_, k) => (keys.push(k), "([^/]+)")) + "$");
    F.routes.push({ pattern, rx, keys, ...def });
  };
  F.tabs = []; // [{ id, path, icon, label, badge? }]
  F.setTabs = t => {
    F.tabs = t;
  };
  let stack = []; // Paths.
  const match = path => {
    for (const r of F.routes) {
      const m = path.match(r.rx);
      if (m) {
        const p = {};
        r.keys.forEach((k, i) => (p[k] = F.decode(m[i + 1])));
        return { r, p };
      }
    }
    return null;
  };
  F.current = () => stack[stack.length - 1];
  // Scroll memory: the position of each screen in the stack (page and inner scrollers with an id or
  // data-scroll-key), saved when a screen is covered and restored when Back returns to it. Tab roots are
  // also remembered by path, since tab switches rebuild the stack.
  let scrollMem = [];
  const tabMem = {};
  const isTab = path => F.tabs.some(t => t.path === path);
  const readScroll = () => {
    if (!curPage) return null;
    const inner = [];
    curPage.querySelectorAll("[id], [data-scroll-key]").forEach(el => {
      if (el.scrollTop > 0 || el.scrollLeft > 0) {
        const key = el.dataset.scrollKey
          ? `[data-scroll-key="${el.dataset.scrollKey}"]`
          : `#${CSS.escape(el.id)}`;
        inner.push([key, el.scrollTop, el.scrollLeft]);
      }
    });
    return { path: F.current(), y: curPage.scrollTop, inner };
  };
  const saveScroll = () => {
    const pos = readScroll();
    if (!pos) return;
    scrollMem[stack.length - 1] = pos;
    if (isTab(pos.path)) tabMem[pos.path] = pos;
  };
  let restoreTimer = null;
  // Screens may re-render once their data arrives (async IPC), so the position is re-applied for a short
  // while unless the user scrolls first.
  const restoreScroll = () => {
    clearTimeout(restoreTimer);
    const depth = stack.length,
      path = F.current();
    const saved = scrollMem[depth - 1];
    const pos = saved && saved.path === path ? saved : isTab(path) ? tabMem[path] : null;
    scrollMem.length = depth;
    if (!pos || (!pos.y && !pos.inner.length)) return;
    let userMoved = false;
    const stop = () => (userMoved = true);
    const opts = { passive: true, capture: true };
    ["wheel", "touchstart", "keydown"].forEach(e => window.addEventListener(e, stop, opts));
    const delays = [0, 60, 150, 300, 600, 1000, 1600];
    const apply = i => {
      if (userMoved || stack.length !== depth || F.current() !== path || !curPage) {
        ["wheel", "touchstart", "keydown"].forEach(e => window.removeEventListener(e, stop, opts));
        return;
      }
      if (Math.abs(curPage.scrollTop - pos.y) > 1) curPage.scrollTop = pos.y;
      pos.inner.forEach(([key, y, x]) => {
        const el = curPage.querySelector(key);
        if (el) {
          el.scrollTop = y;
          el.scrollLeft = x;
        }
      });
      if (i + 1 < delays.length) restoreTimer = setTimeout(() => apply(i + 1), delays[i + 1] - delays[i]);
      else ["wheel", "touchstart", "keydown"].forEach(e => window.removeEventListener(e, stop, opts));
    };
    apply(0);
  };
  F.stack = () => stack.slice(); // Copy of the path stack (e.g. to return to an already open screen via F.back(n)).
  F.stackHas = path => stack.includes(path);
  // Browser history serves only as a trap for the system Back button: while there is somewhere to go back to
  // (screen stack or an open sheet), one extra history entry is kept.
  let trapped = false;
  const syncTrap = () => {
    const need =
      stack.length > 1 ||
      !!sheetOpen ||
      !!pickOpen ||
      !!backHook ||
      !!(stack.length === 1 && F.parentOf && F.parentOf(stack[0]));
    if (need && !trapped) {
      history.pushState({ trap: 1 }, "", location.href);
      trapped = true;
    } else if (!need && trapped) {
      trapped = false;
      ignorePop = true;
      history.back();
    }
  };
  /**
   * Navigates to a path, pushing it onto the screen stack (or replacing the top entry).
   * @param {string} path
   * @param {{replace?: boolean, anim?: string}} [opts]
   */
  // Lock screen gate: while the PIN lock is up, navigation from anywhere (notification routes pushed by
  // MainActivity, async callbacks, screen actions) is queued and replayed only after a successful unlock.
  // The lock screen sets F.isLocked; F.lockQueue.take() hands the queued navigation to the unlock code.
  F.isLocked = () => false;
  let lockQueued = null;
  const lockGate = (leadsToLock, run) => {
    if (leadsToLock || !F.isLocked()) return false;
    lockQueued = run;
    return true;
  };
  F.lockQueue = {
    take: () => {
      const q = lockQueued;
      lockQueued = null;
      return q;
    },
    peek: () => lockQueued,
  };
  F.go = (path, opts = {}) => {
    if (lockGate(path === "/lock", () => F.go(path, opts))) return;
    const { replace = false, anim = "fwd" } = opts;
    closeSheet(true);
    if (!replace) saveScroll();
    if (replace) stack[stack.length - 1] = path;
    else stack.push(path);
    scrollMem.length = stack.length - 1; // A newly opened screen starts at the top.
    render(anim);
    syncTrap();
  };
  /** Replaces the whole screen stack with `paths` and renders the last one. */
  F.reset = (paths, anim = "fade") => {
    if (lockGate(paths[paths.length - 1] === "/lock", () => F.reset(paths, anim))) return;
    closeSheet(true);
    stack = paths.slice();
    scrollMem = [];
    render(anim);
    syncTrap();
  };
  /** Switches to a project tab. */
  F.tab = path => {
    if (lockGate(false, () => F.tab(path))) return;
    // Switching tabs: stack = [projects root?, tab].
    closeSheet(true);
    saveScroll();
    const i = stack.findIndex(p => F.tabs.some(t => t.path === p));
    stack = i >= 0 ? stack.slice(0, i) : stack.slice();
    stack.push(path);
    scrollMem.length = stack.length - 1;
    render("fade");
    syncTrap();
  };
  // A screen can intercept Back (e.g. to leave selection mode): F.onBack(() => { ...; return true; })
  let backHook = null;
  F.onBack = fn => {
    backHook = fn;
    syncTrap();
  };
  const runBackHook = () => {
    if (backHook) {
      const h = backHook;
      if (h() === true) return true;
    }
    return false;
  };
  /**
   * Back navigation (top bar button, Android gesture/button via MainActivity → FOCA.back()), in order:
   * overlay above a sheet → sheet/menu → screen hook (selection mode, preview) → previous screen of this
   * stack (not browser history) → logical parent. Returns false only when there is nowhere to go (project
   * list, terms, lock screen), in which case Android minimizes the app.
   * @param {number} [n=1] Number of screens to go back.
   * @returns {boolean}
   */
  F.back = (n = 1) => {
    if (n > 1) {
      if (F.isLocked()) return false; // Multi-step back would pop the lock screen without the PIN.
      closeSheet(true);
      backHook = null;
      const k = Math.min(n, stack.length - 1);
      if (k > 0) {
        stack.splice(stack.length - k, k);
        render("back");
        restoreScroll();
      }
      syncTrap();
      return k > 0;
    }
    const ov = document.querySelector(".finger-ov");
    if (ov) {
      ov.remove();
      return true;
    }
    if (closePick()) return true;
    if (closeSheet(true)) {
      syncTrap();
      return true;
    }
    const cur = F.current();
    // Terms of use and the permissions step: Back only minimizes the app (it neither declines nor bypasses
    // consent, and never jumps forward to the next first-run screen).
    if (cur === "/terms" || cur === "/permissions") {
      syncTrap();
      return false;
    }
    if (runBackHook()) {
      syncTrap();
      return true;
    }
    // A project tab other than Overview goes back to Overview, like Android bottom navigation: tabs do not
    // pile up in the stack.
    if (
      cur !== "/p/overview" &&
      F.tabs.some(t => t.path === cur) &&
      stack[stack.length - 2] !== "/p/overview"
    ) {
      stack.splice(stack.length - 1, 1, ...(stack.length > 1 ? [] : ["/projects"]), "/p/overview");
      render("back");
      restoreScroll();
      syncTrap();
      return true;
    }
    if (stack.length > 1) {
      stack.pop();
      render("back");
      restoreScroll();
      syncTrap();
      return true;
    }
    const up = F.parentOf(F.current());
    if (up) {
      stack = up;
      scrollMem = [];
      render("back");
      restoreScroll();
      syncTrap();
      return true;
    }
    syncTrap();
    return false;
  };
  /** Logical parent of a screen, used when the stack holds a single screen (deep link, Android notification). */
  F.parentOf = path => {
    if (
      !path ||
      path === "/projects" ||
      path === "/welcome" ||
      path === "/lock" ||
      path === "/terms" ||
      path === "/permissions"
    )
      return null;
    if (path === "/p/overview") return ["/projects"];
    if (path === "/new") return F.project ? ["/projects", "/p/overview"] : ["/projects"];
    if (path.startsWith("/p/")) return ["/projects", "/p/overview"];
    if (path === "/settings") return ["/projects"];
    if (path.startsWith("/settings/")) return ["/projects", "/settings"];
    return ["/projects"];
  };
  window.addEventListener("popstate", () => {
    if (ignorePop) {
      ignorePop = false;
      return;
    }
    trapped = false;
    F.back(); // Same chain as the Android Back button and the top bar button.
  });

  // Top bar title and subtitle are cut with an ellipsis on narrow screens: the full text goes to the title.
  const setBarText = (title, sub) => {
    const t = $("#tb-t"),
      st = $("#tb-s");
    t.textContent = title || "";
    t.title = title || "";
    st.textContent = sub || "";
    st.title = sub || "";
    st.hidden = !sub;
  };
  let curPage = null;
  function render(anim) {
    const path = F.current();
    const mm = match(path);
    if (!mm) {
      console.warn("нет маршрута", path);
      return;
    }
    if (F.cur && F.cur.path !== path) {
      if (F.cur.r.unmount) {
        try {
          F.cur.r.unmount(curPage, F.cur.p);
        } catch (e) {
          console.error(e);
        }
      }
      backHook = null;
      F.clearOverlay();
    }
    const { r: route, p: params } = mm;
    const prevPath = F.cur && F.cur.path;
    F.cur = { r: route, p: params, path };
    // The router does not touch location.hash, so screens follow navigation through this event.
    if (prevPath !== path && F.emit) setTimeout(() => F.emit("route", { path, prev: prevPath || null }), 0);
    // Top bar.
    const title = typeof route.title === "function" ? route.title(params) : route.title;
    const sub =
      typeof route.sub === "function" ? route.sub(params) : (route.sub ?? (F.project ? F.project.name : ""));
    const showBack = route.back ?? (stack.length > 1 && !F.tabs.some(t => t.path === path));
    document.body.classList.toggle("no-topbar", route.topbar === false);
    $("#tb-back").hidden = !showBack;
    $("#tb-logo").hidden = showBack;
    setBarText(title, sub);
    const acts =
      (typeof route.actions === "function" ? route.actions(params) : route.actions) || F.defaultActions || [];
    $("#tb-acts").innerHTML = acts
      .map(a => {
        const lbl = typeof a.label === "function" ? a.label() : a.label || "";
        return `<button class="ib" data-act="${a.act}" aria-label="${esc(lbl)}"
            title="${esc(lbl)}">${ic(a.icon)}${a.badge ? `<span class="badge">${a.badge}</span>` : ""}</button>`;
      })
      .join("");
    // Navigation.
    const navOpt = typeof route.nav === "function" ? route.nav(params) : route.nav; // nav/hideMini may be functions (e.g. to hide tabs inside the wizard).
    const showNav = navOpt !== false && F.tabs.length && F.project;
    const nav = $("#nav");
    nav.classList.toggle("show", !!showNav);
    $("#navpad").classList.toggle("hide", !!showNav);
    nav.style.setProperty("--tabs", F.tabs.length);
    nav.innerHTML = F.tabs
      .map(t => {
        const lbl = typeof t.label === "function" ? t.label() : t.label;
        return `<button class="${(route.tab || "") === t.id ? "on" : ""}" data-tab="${t.path}"
            aria-label="${esc(lbl)}">${ic(t.icon)}<span>${esc(lbl)}</span></button>`;
      })
      .join("");
    // Bottom search bar.
    $("#searchpill").classList.toggle("show", !!route.search);
    if (route.search)
      $("#searchpill span").textContent =
        typeof route.search === "function"
          ? route.search(params)
          : typeof route.search === "string"
            ? route.search
            : F.t("app.search", "Поиск");
    // Page.
    const vp = $("#viewport");
    const page = document.createElement("div");
    page.className = "page";
    page.innerHTML = route.render ? route.render(params) : "";
    // In empty/error states the FAB does not duplicate the placeholder's own button.
    const stub =
      page.firstElementChild &&
      page.firstElementChild.classList.contains("empty") &&
      page.children.length === 1;
    const fab = stub ? null : typeof route.fab === "function" ? route.fab(params) : route.fab;
    page.style.setProperty("--fab-space", fab ? "76px" : "0px");
    if (curPage && anim && anim !== "none") {
      const old = curPage;
      if (anim === "fade") {
        old.remove();
        page.classList.add("fade");
      } else {
        old.classList.add(anim === "back" ? "leave-back" : "leave-fwd");
        page.classList.add(anim === "back" ? "enter-back" : "enter-fwd");
        setTimeout(() => old.remove(), 230);
      }
    } else if (curPage) curPage.remove();
    vp.appendChild(page);
    curPage = page;
    // FAB
    const fb = $("#fab");
    if (fab) {
      fb.classList.add("show");
      // compact: icon only from the start (screens whose first view has headers near the bottom edge).
      fb.classList.toggle("small", !!fab.compact);
      fb.dataset.act = fab.act;
      fb.innerHTML = `${ic(fab.icon)}<span class="fab-l">${esc(fab.label)}</span>`;
      fb.setAttribute("aria-label", fab.label);
    } else fb.classList.remove("show");
    const fabAway = () => {
      const el = fab && fab.until && page.querySelector(fab.until);
      let seen = false;
      if (el) {
        const r = el.getBoundingClientRect(),
          pr = page.getBoundingClientRect();
        seen = r.height > 0 && r.bottom > pr.top && r.top < pr.bottom;
      }
      fb.classList.toggle("away", seen);
    };
    let lastY = 0;
    page.addEventListener(
      "scroll",
      () => {
        // A page that is sliding out can still fire scroll (its scrollTop gets clamped) and would
        // apply its own FAB rules over the new screen's.
        if (page !== curPage) return;
        const y = page.scrollTop;
        if (fab && !fab.compact) fb.classList.toggle("small", y > 40 && y > lastY);
        lastY = y;
        fabAway();
        syncMini();
      },
      { passive: true },
    );
    updateChrome();
    if (route.mount) route.mount(page, params);
    fabAway();
    syncMini();
    placeSnack(); // mount may have added or changed the sticky footer (no-pb, selection bar).
  }
  // ---------- slot for previews/banners above the page (cleared when leaving the screen) ----------
  // const slot = F.overlaySlot(); slot.appendChild(el): elements are positioned inside #viewport.
  F.overlaySlot = () => $("#overlay-slot");
  F.clearOverlay = () => {
    const s = $("#overlay-slot");
    if (s) s.innerHTML = "";
  };
  /**
   * Re-renders the current screen.
   * @param {boolean} [soft] Keep the scroll position and skip the transition animation.
   */
  // Scroll anchor of a soft re-render: the first row still visible at the top of the page (rows carry
  // data-id or an id), with its offset, so rows inserted above it (sort "new" during a scan) do not
  // push the user's place down or back to the top.
  const anchorSel = el => {
    if (el.dataset.id) {
      const cls = [...el.classList].find(c => c !== "row" && c !== "tap" && c !== "sel" && c !== "on");
      return `${cls ? "." + CSS.escape(cls) : ""}[data-id="${CSS.escape(el.dataset.id)}"]`;
    }
    return el.id ? `#${CSS.escape(el.id)}` : null;
  };
  const readAnchor = page => {
    if (!page || page.scrollTop <= 0) return null;
    const top = page.getBoundingClientRect().top;
    for (const el of page.querySelectorAll("[data-id], .row[id], [data-anc][id]")) {
      const r = el.getBoundingClientRect();
      if (r.height > 0 && r.bottom > top + 1) {
        const sel = anchorSel(el);
        return sel ? { sel, off: r.top - top } : null;
      }
    }
    return null;
  };
  /**
   * Re-renders the current screen.
   * @param {boolean} [soft] Keep the scroll position (page, inner scrollers and the first visible row)
   *   and skip the transition animation.
   */
  F.render = soft => {
    if (!soft || !curPage) return render("none");
    const y = curPage.scrollTop;
    const anchor = readAnchor(curPage);
    const pos = readScroll();
    render("none");
    if (!curPage) return;
    curPage.scrollTop = y;
    if (anchor) {
      const el = curPage.querySelector(anchor.sel);
      if (el) {
        const d = el.getBoundingClientRect().top - curPage.getBoundingClientRect().top - anchor.off;
        if (Math.abs(d) >= 1) curPage.scrollTop = curPage.scrollTop + d;
      }
    }
    (pos ? pos.inner : []).forEach(([key, iy, ix]) => {
      const el = curPage.querySelector(key);
      if (el) {
        el.scrollTop = iy;
        el.scrollLeft = ix;
      }
    });
  };
  F.page = () => curPage;
  /** Updates the current screen's top bar title/subtitle without re-rendering the page. */
  F.refreshBar = () => {
    if (!F.cur) return;
    const { r, p } = F.cur;
    const t = typeof r.title === "function" ? r.title(p) : r.title;
    const s = typeof r.sub === "function" ? r.sub(p) : (r.sub ?? (F.project ? F.project.name : ""));
    setBarText(t, s);
  };

  // ---------- live screens ----------
  // def.onData(kind, ev): the screen updates itself in place; def.live: true | (kind, ev) => bool makes the
  // core call F.render(true).
  // kind: "scan" (scan events), "db" (data changed: {kind}), "net" ({online}). Re-renders are throttled (at
  // most 2-3 per second).
  let liveT = null,
    liveLast = null;
  // Live re-renders wait while the user touches or scrolls the page (and LIVE_QUIET_MS after it): a
  // re-render replaces the page element, which would cut a fling short and move the list under the finger.
  const LIVE_QUIET_MS = 500;
  let touching = false,
    lastUserMove = 0;
  const userMoved = () => (lastUserMove = Date.now());
  const capt = { passive: true, capture: true };
  window.addEventListener("touchstart", () => ((touching = true), userMoved()), capt);
  ["touchend", "touchcancel"].forEach(e =>
    window.addEventListener(e, () => ((touching = false), userMoved()), capt),
  );
  ["wheel", "touchmove"].forEach(e => window.addEventListener(e, userMoved, capt));
  // Scroll events do not bubble: the capture listener sees the page and inner scrollers.
  document.addEventListener("scroll", userMoved, capt);
  const userBusy = () => touching || Date.now() - lastUserMove < LIVE_QUIET_MS;
  F.liveQuiet = { ms: LIVE_QUIET_MS, busy: userBusy };
  // Soft re-render of the current screen through the same throttle and touch deferral as live screens
  // (scan stage results re-render every screen, also those without a live rule).
  F.liveRender = (kind, ev) => liveRefresh(kind || "db", ev, true);
  function liveRefresh(kind, ev, force) {
    const route = F.cur && F.cur.r;
    if (!route) return;
    ev = ev || {};
    if (route.onData && !force) {
      try {
        route.onData(kind, ev);
      } catch (e) {
        console.error(e);
      }
      return;
    }
    const want = force || (typeof route.live === "function" ? route.live(kind, ev) : route.live === true);
    if (!want) return;
    if (liveT) {
      liveLast = [kind, ev, force || (liveLast && liveLast[2])];
      return;
    }
    if (userBusy()) {
      liveLast = [kind, ev, force];
      const wait = touching ? LIVE_QUIET_MS : Math.max(50, LIVE_QUIET_MS - (Date.now() - lastUserMove));
      liveT = setTimeout(() => {
        liveT = null;
        if (liveLast) {
          const [k, e, f] = liveLast;
          liveLast = null;
          liveRefresh(k, e, f);
        }
      }, wait);
      return;
    }
    F.render(true);
    liveT = setTimeout(() => {
      liveT = null;
      if (liveLast) {
        const [k, e, f] = liveLast;
        liveLast = null;
        liveRefresh(k, e, f);
      }
    }, 350);
  }

  // ---------- global chrome: active mode, scan mini bar, bottom padding ----------
  // The floating scan bar is hidden where it would repeat the page: routes with hideMini, while the
  // element named by route.miniUntil (the overview scan card) is on screen, and in selection mode (its
  // action bar owns the bottom edge).
  const onScreen = sel => {
    const el = sel && curPage && curPage.querySelector(sel);
    if (!el) return false;
    const r = el.getBoundingClientRect(),
      pr = curPage.getBoundingClientRect();
    return r.height > 0 && r.bottom > pr.top && r.top < pr.bottom;
  };
  const miniWanted = () => {
    const scan = F.scan,
      route = F.cur && F.cur.r;
    if (!scan || !scan.running || !route) return false;
    if (typeof route.hideMini === "function" ? route.hideMini(F.cur.p) : route.hideMini) return false;
    if (document.body.classList.contains("dt-selecting")) return false;
    const until = typeof route.miniUntil === "function" ? route.miniUntil(F.cur.p) : route.miniUntil;
    return !onScreen(until);
  };
  const syncMini = () => {
    const mini = $("#mini");
    if (mini) mini.classList.toggle("show", !!miniWanted());
  };
  F.syncMini = syncMini;
  function updateChrome() {
    const scan = F.scan;
    const mini = $("#mini");
    mini.classList.toggle("show", !!miniWanted());
    mini.classList.toggle("active-mode", !!(scan && scan.active));
    if (scan) {
      $("#mi-t").textContent = scan.paused
        ? scan.pauseLabel || F.t("projects.scan_paused", "Скан на паузе")
        : scan.stageLabel || F.t("core.scan_running", "Скан идёт");
      $("#mi-s").textContent = scan.summary || "";
      $("#mi-pb").style.width = (scan.progress || 0) + "%";
      $("#mi-pp").innerHTML = ic(scan.paused ? "play" : "pause");
      $("#mi-pp").setAttribute(
        "aria-label",
        scan.paused ? F.t("core.resume", "Продолжить") : F.t("core.pause", "Пауза"),
      );
    }
    const ab = $("#activebar");
    ab.classList.toggle("show", !!(scan && scan.running && scan.active));
    if (scan) $("#ab-ip").textContent = scan.egress || "";
    // Large system font (1rem ≥ 21px): compact chrome variants (single-line mini bar, etc.).
    const remPx = parseFloat(getComputedStyle(document.documentElement).fontSize) || 14;
    document.documentElement.classList.toggle("fs-lg", remPx >= 21);
    placeSnack();
    $("#fab").style.bottom = 16 + "px";
  }
  F.updateChrome = updateChrome;
  // The snackbar sits above the topmost element pinned to the bottom of the screen: navigation, mini bar,
  // search bar, FAB, the page's sticky footer (.foot), the selection bar (.selbar), an open sheet's footer or
  // any
  // [data-snack-above]. This keeps "Undo" from landing where the user just tapped.
  const SNACK_ANCHORS =
    "#nav.show, #mini.show, #searchpill.show, #fab.show, .selbar, [data-snack-above], .sheet.show .sh-f, .finger-ov .btnrow";
  function placeSnack() {
    const viewH = window.innerHeight;
    let top = viewH;
    const navpad = $("#navpad");
    if (navpad && !navpad.classList.contains("hide"))
      top = Math.min(top, navpad.getBoundingClientRect().top || viewH);
    const cands = $$(SNACK_ANCHORS);
    const pg = curPage;
    if (pg && pg.isConnected) {
      const pb = pg.getBoundingClientRect().bottom;
      pg.querySelectorAll(".foot").forEach(f => {
        const q = f.getBoundingClientRect();
        if (q.height && q.bottom >= pb - 40 && q.top < pb) cands.push(f);
      });
    }
    for (const el of cands) {
      if (el.closest(".page") && el.closest(".page") !== pg) continue; // Page that is being left.
      const cs = getComputedStyle(el);
      if (cs.display === "none" || cs.visibility === "hidden") continue;
      const rect = el.getBoundingClientRect();
      if (!rect.height || rect.top >= viewH || rect.bottom < viewH * 0.5) continue; // Only elements pinned to the bottom.
      top = Math.min(top, rect.top);
    }
    document.documentElement.style.setProperty(
      "--snack-bottom",
      Math.max(12, Math.round(viewH - top + 8)) + "px",
    );
    // An open sheet holds the fields the user is filling in: show the snackbar in the free space above it.
    const sheet = $(".sheet.show"),
      snackEl = $("#snack");
    const above = sheet && sheet.getBoundingClientRect().top;
    if (snackEl) snackEl.classList.toggle("at-top", !!sheet && above >= 120);
  }
  F.placeSnack = placeSnack;

  // ---------- sheets ----------
  let sheetOpen = null;
  let pickOpen = null; // F.choose panel, see "option picker" below.
  let ignorePop = false;
  /**
   * Opens a bottom sheet.
   * @param {{title?: string, html?: string, footer?: string, full?: boolean, onMount?: Function, onClose?: Function, cls?: string}} opts
   */
  F.sheet = ({ title = "", html = "", footer = "", full = false, onMount, onClose, cls = "" } = {}) => {
    closeSheet(true);
    const scrim = document.createElement("div");
    scrim.className = "scrim";
    const sh = document.createElement("div");
    sh.className = `sheet ${full ? "full" : ""} ${cls}`;
    sh.setAttribute("role", "dialog");
    sh.setAttribute("aria-modal", "true");
    sh.innerHTML = `<div class="sh-grab"><i></i></div>${
      title
        ? `<div class="sh-h"><h3>${esc(title)}</h3><button class="ib"
      data-act="sheet-close"
      aria-label="${esc(F.t("app.secrets_close", "Закрыть"))}">${ic("x")}</button></div>`
        : ""
    }<div class="sh-b">${html}</div>${footer ? `<div class="sh-f">${footer}</div>` : ""}`;
    document.body.append(scrim, sh);
    requestAnimationFrame(() => {
      scrim.classList.add("show");
      sh.classList.add("show");
    });
    scrim.addEventListener("click", () => F.closeSheet());
    // Drag by the handle.
    const grab = sh.querySelector(".sh-grab");
    let y0 = null,
      dy = 0;
    grab.addEventListener("pointerdown", e => {
      y0 = e.clientY;
      dy = 0;
      sh.classList.add("dragging");
      grab.setPointerCapture(e.pointerId);
    });
    grab.addEventListener("pointermove", e => {
      if (y0 == null) return;
      dy = Math.max(0, e.clientY - y0);
      sh.style.transform = `translateY(${dy}px)`;
    });
    grab.addEventListener("pointerup", () => {
      sh.classList.remove("dragging");
      sh.style.transform = "";
      if (dy > 90) F.closeSheet();
      y0 = null;
    });
    sheetOpen = { scrim, sh, onClose };
    syncTrap();
    setTimeout(placeSnack, 260); // A snackbar shown before the sheet is lifted above the sheet's buttons.
    if (onMount) onMount(sh);
    return sh;
  };
  function closeSheet(silent, fromPop) {
    if (!sheetOpen) return false;
    const { scrim, sh, onClose } = sheetOpen;
    sheetOpen = null;
    scrim.classList.remove("show");
    sh.classList.remove("show");
    setTimeout(() => {
      scrim.remove();
      sh.remove();
    }, 250);
    if (onClose) onClose();
    setTimeout(placeSnack, 260);
    return true;
  }
  F.closeSheet = () => {
    closeSheet(true);
    syncTrap();
  };
  F.actions["sheet-close"] = () => F.closeSheet();

  // ---------- option picker ----------
  // Own bottom panel above everything (also above an open sheet, so pickers work inside filter sheets).
  const closePick = () => {
    if (!pickOpen) return false;
    const { scrim, sh, back } = pickOpen;
    pickOpen = null;
    scrim.classList.remove("show");
    sh.classList.remove("show");
    setTimeout(() => {
      scrim.remove();
      sh.remove();
    }, 250);
    if (back && back.isConnected) back.focus({ preventScroll: true });
    syncTrap();
    return true;
  };
  /**
   * Opens a themed single-choice list.
   * @param {{title?: string, value?: string, options: Array<{v: string, t: string, s?: string}>, onPick: Function, back?: Element}} o
   */
  F.choose = ({ title = "", value, options, onPick, back }) => {
    closePick();
    const scrim = document.createElement("div");
    scrim.className = "scrim pick-scrim";
    const sh = document.createElement("div");
    sh.className = "sheet pick-sh";
    sh.setAttribute("role", "dialog");
    sh.setAttribute("aria-modal", "true");
    if (title) sh.setAttribute("aria-label", title);
    sh.innerHTML = `<div class="sh-grab"><i></i></div>${
      title
        ? `<div class="sh-h"><h3>${esc(title)}</h3><button class="ib" data-pk-x
      aria-label="${esc(F.t("app.secrets_close", "Закрыть"))}">${ic("x")}</button></div>`
        : ""
    }<div class="sh-b"><div class="list pk-list" role="radiogroup">${options
      .map((o, i) => {
        const on = String(o.v) === String(value);
        return `<div class="row tap pk-o ${on ? "on" : ""}" role="radio" aria-checked="${on}" tabindex="0"
          data-pk="${i}"><span class="radio"></span><div class="body"><div class="t">${esc(o.t)}</div>${o.s ? `<div class="s">${esc(o.s)}</div>` : ""}</div></div>`;
      })
      .join("")}</div></div>`;
    document.body.append(scrim, sh);
    pickOpen = { scrim, sh, back };
    syncTrap();
    requestAnimationFrame(() => {
      scrim.classList.add("show");
      sh.classList.add("show");
      const on = sh.querySelector(".pk-o.on") || sh.querySelector(".pk-o");
      if (on) {
        on.scrollIntoView({ block: "nearest" });
        on.focus({ preventScroll: true });
      }
    });
    scrim.addEventListener("click", closePick);
    const x = sh.querySelector("[data-pk-x]");
    if (x) x.addEventListener("click", closePick);
    const pick = el => {
      const o = options[+el.dataset.pk];
      closePick();
      if (o && onPick) onPick(o.v);
    };
    sh.addEventListener("click", e => {
      const el = e.target.closest("[data-pk]");
      if (el) pick(el);
    });
    sh.addEventListener("keydown", e => {
      const el = e.target.closest("[data-pk]");
      if (e.key === "Escape") closePick();
      else if (el && (e.key === "Enter" || e.key === " ")) {
        e.preventDefault();
        pick(el);
      }
    });
    return sh;
  };
  F.closePick = closePick;
  /** Sets an F.ui.select field without a change event (e.g. "Reset" in a filter sheet). */
  F.pickSet = (el, v) => {
    if (!el) return;
    const reg = pickReg[el.id];
    const o = reg && reg.options.find(x => String(x.v) === String(v));
    el.value = String(v);
    const t = el.querySelector(".pk-t"),
      sub = el.querySelector(".pk-s");
    if (o && t) t.textContent = o.t;
    if (sub) sub.textContent = (o && o.s) || "";
  };
  F.actions.pick = (id, el) => {
    const reg = pickReg[id];
    if (!reg || !el) return;
    F.choose({
      title: reg.title,
      value: el.value,
      options: reg.options,
      back: el,
      onPick: v => {
        if (String(v) === String(el.value)) return;
        F.pickSet(el, v);
        el.dispatchEvent(new Event("change", { bubbles: true }));
      },
    });
  };

  // ---------- snackbar ----------
  let snT;
  /**
   * Shows a snackbar.
   * @param {string} text
   * @param {{action?: Function, label?: string, ms?: number}} [opts] Optional action button (Undo by default).
   */
  // Plain notices go away after 3 s; with an action (Undo) the user gets 5 s. A tap on the text dismisses it.
  F.snack = (text, { action, label = F.t("core.undo", "Отменить"), ms } = {}) => {
    if (ms == null) ms = action ? 5000 : 3000;
    const snackEl = $("#snack");
    snackEl.innerHTML = `<span class="sn-t">${esc(text)}</span>${action ? `<button class="sn-a">${esc(label)}</button>` : ""}`;
    snackEl.querySelector(".sn-t").onclick = () => snackEl.classList.remove("show");
    if (action)
      snackEl.querySelector(".sn-a").onclick = () => {
        snackEl.classList.remove("show");
        action();
      };
    updateChrome();
    snackEl.classList.add("show");
    clearTimeout(snT);
    snT = setTimeout(() => snackEl.classList.remove("show"), ms);
    // Bottom bars may appear or change right after an action (re-render, sheet); recompute the position.
    requestAnimationFrame(() => requestAnimationFrame(placeSnack));
    setTimeout(placeSnack, 260);
  };

  // ---------- fingerprint session: revealing secrets ----------
  // One mechanism for document secrets, finding evidence and API keys (like BiometricPrompt +
  // setUserAuthenticationParameters(timeout)): after a fingerprint confirmation, secrets stay revealed
  // without re-prompting for N minutes (Settings → Security, 2 by default).
  // The session ends via the "Close" button in the indicator, on timeout, when the app goes to background and
  // on the lock screen.
  // F.confirmFinger(then, what, el): el is an element inside an open sheet (confirmation is shown on top, the
  // sheet stays open).
  // F.onBioClose(fn): a screen hides revealed values (fn is called when the session closes).
  const bio = { until: 0, t: null, subs: [] };
  F.bioMinutes = () => {
    const s = F.db && F.db.settings && F.db.settings.sec;
    const m = s && s.reveal_min;
    return m == null || m === "" || isNaN(+m) ? 2 : +m;
  };
  F.bioOpen = () => Date.now() < bio.until;
  F.onBioClose = fn => {
    if (!bio.subs.includes(fn)) bio.subs.push(fn);
  };
  const fmtLeft = ms => {
    const s = Math.max(0, Math.ceil(ms / 1000));
    return `${Math.floor(s / 60)}:${String(s % 60).padStart(2, "0")}`;
  };
  function bioTick() {
    const el = $("#bioind");
    if (!el) return;
    const left = bio.until - Date.now();
    if (left <= 0) {
      if (bio.until) F.bioClose();
      return;
    }
    $("#bi-t").textContent = `${F.t("core.secrets_open", "Секреты открыты ·")} ${fmtLeft(left)}`;
  }
  F.bioClose = () => {
    const was = !!bio.until;
    bio.until = 0;
    clearInterval(bio.t);
    bio.t = null;
    const el = $("#bioind");
    if (el) el.classList.remove("show");
    if (!was) return;
    bio.subs.forEach(fn => {
      try {
        fn();
      } catch (e) {
        console.error(e);
      }
    });
    // Hide everything revealed on screen (blurred values, key fields).
    $$(".secret:not(.masked)").forEach(s => s.classList.add("masked"));
    $$("input[data-secret-input]").forEach(i => {
      i.type = "password";
    });
    if (curPage) F.render(true);
    updateChrome();
  };
  const bioStart = () => {
    const m = F.bioMinutes();
    if (!(m > 0)) return;
    bio.until = Date.now() + m * 60000;
    const el = $("#bioind");
    if (el) el.classList.add("show");
    clearInterval(bio.t);
    bio.t = setInterval(bioTick, 1000);
    bioTick();
    updateChrome();
  };
  // The app uses the system BiometricPrompt (platform_biometric); without biometrics, or when it is locked
  // out, the app PIN is used. If el is inside an open sheet, the PIN prompt is shown on top of it (sheet
  // input is kept).
  const pinFallback = (ok, what, el) => {
    const sec = (F.db && F.db.settings && F.db.settings.sec) || {};
    const sh = el && el.closest && el.closest(".sheet");
    const show = (title, body, btns, onMount) => {
      if (sh) {
        const box = document.createElement("div");
        box.className = "finger-ov st-finger";
        box.innerHTML = `<div class="finger-in st-finger-in" role="dialog" aria-modal="true"
          aria-label="${esc(title)}"><b>${esc(title)}</b>${body}<div class="btnrow">${btns.replace('data-act="sheet-close"', 'data-act="bio-ov-close"')}</div></div>`;
        sh.appendChild(box);
        F.actions["bio-ov-close"] = () => box.remove();
        if (onMount) onMount(box);
        return () => box.remove();
      }
      F.sheet({ title, html: body, footer: btns, onMount });
      return () => F.closeSheet();
    };
    if (!sec.pin_set) {
      const close = show(
        F.t("core.biometrics_unavailable", "Биометрия недоступна"),
        `<p>${F.t("core.what_fingerprint_or_app_pin", { what: esc(what) }, "Чтобы {what}, нужен отпечаток или PIN приложения. Биометрия на устройстве не настроена. Задайте PIN в «Настройки → Безопасность».")}</p>`,
        `<button class="btn" data-act="sheet-close">${esc(F.t("common.cancel", "Отмена"))}</button><button class="btn primary"
          data-act="bio-pin-setup">${esc(F.t("core.set_up_pin", "Настроить PIN"))}</button>`,
      );
      F.actions["bio-pin-setup"] = () => {
        close();
        if (sh) F.closeSheet();
        F.go("/settings/security");
      };
      return;
    }
    const close = show(
      F.t("core.enter_pin", "Введите PIN"),
      `<p>${F.t("core.what_enter_app_pin", { what: esc(what) }, "Чтобы {what}, введите PIN приложения.")}</p><div class="field">${ic("lock")}<input id="bio-pin"
        type="password" inputmode="numeric" maxlength="8" autocomplete="off"
        aria-label="PIN"></div><p class="fhint" id="bio-pin-msg" role="status"></p>`,
      `<button class="btn" data-act="sheet-close">${esc(F.t("common.cancel", "Отмена"))}</button><button class="btn primary"
        data-act="bio-pin-ok">${esc(F.t("core.confirm", "Подтвердить"))}</button>`,
      root => {
        const i = root.querySelector("#bio-pin");
        if (i) {
          i.focus();
          i.addEventListener("keydown", e => {
            if (e.key === "Enter") F.actions["bio-pin-ok"]();
          });
        }
      },
    );
    F.actions["bio-pin-ok"] = () => {
      const i = $("#bio-pin"),
        msg = $("#bio-pin-msg");
      if (!i) return;
      F.api.pin_check(i.value).then(
        r => {
          if (r && r.panic) {
            location.reload();
            return;
          }
          if (r && r.ok) {
            close();
            ok();
            return;
          }
          i.value = "";
          if (msg)
            msg.textContent =
              r && r.attempts_left != null
                ? `${F.t("core.wrong_pin_attempts_left", "Неверный PIN · осталось попыток:")} ${r.attempts_left}`
                : F.t("core.wrong_pin", "Неверный PIN");
        },
        e => {
          if (msg)
            msg.textContent = F.t("core.could_not_verify_pin", "Не удалось проверить PIN: ") + e.message;
        },
      );
    };
  };
  /**
   * Runs `then` after fingerprint (or PIN) confirmation, unless a confirmation session is already open.
   * @param {Function} then
   * @param {string} [what] Purpose shown in the prompt.
   * @param {Element} [el] Element inside an open sheet; the prompt is shown on top of that sheet.
   */
  F.confirmFinger = (then, what = F.t("core.reveal_secret", "показать секрет"), el) => {
    if (F.bioOpen()) {
      then();
      return;
    }
    const ok = () => {
      bioStart();
      then();
    };
    if (F.isTauri && F.api && F.api.platform_biometric) {
      F.api
        .platform_biometric({
          title: F.t("core.confirm_fingerprint", "Подтвердите отпечатком"),
          subtitle: F.t("core.to_what", { what }, "Чтобы {what}"),
        })
        .then(
          r => {
            if (r && r.ok) ok();
            else if (!r || r.available === false) pinFallback(ok, what, el);
          },
          () => pinFallback(ok, what, el),
        );
      return;
    }
    const minutes = F.bioMinutes();
    const note =
      minutes > 0
        ? `${F.t("core.secrets_will_stay_open_minutes", { minutes }, "Секреты будут открыты {minutes} мин. До ухода из приложения или до блокировки.")}`
        : "";
    const sh = el && el.closest && el.closest(".sheet");
    if (sh) {
      // On top of an open sheet (e.g. the key sheet, so the typed value is not lost).
      const box = document.createElement("div");
      box.className = "finger-ov st-finger";
      box.innerHTML = `<div class="finger-in st-finger-in" role="dialog" aria-modal="true"
        aria-label="${esc(F.t("core.fingerprint_confirmation", "Подтверждение отпечатком"))}"><div class="finger-ic">${ic("finger")}</div><b>${esc(F.t("core.confirm_fingerprint", "Подтвердите отпечатком"))}</b><span>${F.t("core.what_place_your_finger_sensor", { what: esc(what) }, "Чтобы {what}, приложите палец к сканеру.")}${note ? `<small>${esc(note)}</small>` : ""}</span><div class="btnrow"><button class="btn"
        data-act="st-finger-no">${esc(F.t("common.cancel", "Отмена"))}</button><button class="btn primary"
        data-act="st-finger-ok">${esc(F.t("common.demo_confirm", "Демо: подтвердить"))}</button></div></div>`;
      sh.appendChild(box);
      placeSnack();
      F.actions["st-finger-no"] = () => box.remove();
      F.actions["st-finger-ok"] = () => {
        box.remove();
        ok();
      };
      return;
    }
    F.sheet({
      cls: "finger-sheet",
      html: `<div class="finger-b dt-finger"><div class="finger-ic">${ic("finger")}</div><h3>${esc(F.t("core.confirm_fingerprint", "Подтвердите отпечатком"))}</h3><p>${F.t("core.what_place_your_finger_sensor", { what: esc(what) }, "Чтобы {what}, приложите палец к сканеру.")}</p>${note ? `<p class="finger-note">${esc(note)}</p>` : ""}</div>`,
      footer: `<button class="btn" data-act="sheet-close">${esc(F.t("common.cancel", "Отмена"))}</button><button class="btn primary"
        data-act="dt-finger-ok">${esc(F.t("common.demo_confirm", "Демо: подтвердить"))}</button>`,
      onMount: () => {
        F.actions["dt-finger-ok"] = () => {
          F.closeSheet();
          ok();
        };
      },
    });
  };
  F.actions["bio-close"] = () => {
    F.bioClose();
    F.snack(F.t("app.secrets_hidden", "Секреты скрыты"));
  };

  // ---------- hold-to-confirm (destructive actions only: delete, wipe) ----------
  // <button class="btn danger hold" data-hold="name:arg"><span class="hold-fill"></span>Text</button>
  let holdT;
  document.addEventListener("pointerdown", e => {
    const h = e.target.closest("[data-hold]");
    if (!h || h.disabled) return;
    h.classList.add("holding");
    holdT = setTimeout(() => {
      h.classList.remove("holding");
      try {
        navigator.vibrate && navigator.vibrate(30);
      } catch (x) {}
      const [n, a] = h.dataset.hold.split(/:(.*)/s);
      F.actions[n] && F.actions[n](a, h);
    }, 1200);
  });
  ["pointerup", "pointerleave", "pointercancel"].forEach(ev =>
    document.addEventListener(
      ev,
      () => {
        clearTimeout(holdT);
        $$(".holding").forEach(x => x.classList.remove("holding"));
      },
      true,
    ),
  );

  // ---------- shared actions ----------
  Object.assign(F.actions, {
    go: path => F.go(path),
    back: () => F.back(),
    toggle: (_, el) => {
      el.classList.toggle("on");
      el.setAttribute("aria-checked", el.classList.contains("on"));
    },
    chip: (_, el) => el.classList.toggle("on"),
    "toggle-check": (_, el) => {
      el.classList.toggle("on");
      el.setAttribute("aria-checked", el.classList.contains("on"));
    },
    retry: () => {
      F.demo.mode = "normal";
      F.render(true);
    },
    reveal: (id, el) => {
      // Reveal a secret (in the app, after biometric confirmation).
      const s =
        el.closest("[data-secret-wrap]")?.querySelector(".secret") ||
        el.parentElement.querySelector(".secret");
      if (s) {
        s.classList.toggle("masked");
        el.innerHTML = ic(s.classList.contains("masked") ? "eye" : "eye-off");
      }
    },
    copy: txt => {
      F.clipCopy(txt);
      F.snack(
        F.clipAutoClear()
          ? F.t("app.copied", "Скопировано · буфер очистится через 30\u00a0с")
          : F.t("app.copied_plain", "Скопировано"),
      );
    },
    theme: () => F.setTheme(document.documentElement.dataset.theme === "dark" ? "light" : "dark"),
    "mini-open": () => F.go("/p/scan"),
    "mini-pp": () => {
      if (!F.scan) return;
      const a = F.actions[F.scan.paused ? "scan-resume" : "scan-pause"];
      if (a) a();
      else {
        F.scan.paused = !F.scan.paused;
        updateChrome();
      }
    },
    search: () => F.go("/p/search"),
  });

  document.addEventListener("click", e => {
    const tabEl = e.target.closest("[data-tab]");
    if (tabEl) {
      if (tabEl.dataset.tab !== F.current()) F.tab(tabEl.dataset.tab);
      else {
        render("none");
        if (curPage) curPage.scrollTo({ top: 0, behavior: "smooth" });
      }
      return;
    }
    const actEl = e.target.closest("[data-act]");
    if (!actEl || actEl.disabled) return;
    const [name, arg] = actEl.dataset.act.split(/:(.*)/s);
    const fn = F.actions[name];
    if (fn) {
      e.preventDefault();
      fn(arg, actEl, e);
    } else console.warn("нет действия", name);
  });
  document.addEventListener("contextmenu", e => {
    if (!e.target.closest("input,textarea,.v")) e.preventDefault();
  });

  // ---------- clipboard ----------
  // The Android WebView never grants the async Clipboard API read (navigator.clipboard.readText()
  // rejects), so under Tauri the clipboard goes through the native ClipboardManager
  // (platform_clipboard_*). Desktop and `foca serve` answer `unsupported` and the browser demo has no
  // native layer: both fall back to navigator.clipboard.
  // Copying secrets: when "Clear clipboard after 30 s" is on (sec.clip, default on), the clipboard is wiped
  // after 30 s unless it already holds something else.
  F.CLIP_CLEAR_MS = 30000;
  F.clipAutoClear = () => (((F.db && F.db.settings) || {}).sec || {}).clip !== false;
  let clipT = null;
  // Native call: resolves the reply, or null when there is no native clipboard (browser, desktop).
  const clipNative = (cmd, args) =>
    F.isTauri && F.api && F.api[cmd]
      ? F.api[cmd](args).then(
          r => (r && r.unsupported ? null : r || {}),
          () => null,
        )
      : Promise.resolve(null);
  // Reads the clipboard: { ok, text, error? }. `ok: false` means the clipboard could not be read
  // (permission, no focus, ROM privacy setting), as opposed to an empty clipboard ({ ok: true, text: "" }).
  F.clipRead = () =>
    clipNative("platform_clipboard_read", {}).then(r => {
      if (r) return { ok: r.ok !== false, text: String(r.text || ""), error: r.error || null };
      const cb = navigator.clipboard;
      if (!cb || !cb.readText) return { ok: false, text: "", error: "unsupported" };
      return Promise.resolve()
        .then(() => cb.readText())
        .then(
          t => ({ ok: true, text: String(t || ""), error: null }),
          e => ({ ok: false, text: "", error: (e && e.name) || "denied" }),
        );
    });
  // Writes text: resolves true when it reached the clipboard. `sensitive` hides the value in the
  // Android 13+ copy preview; `clearAfter` (ms) lets the native layer schedule the conditional clear.
  F.clipWrite = (txt, { sensitive = false, clearAfter = 0 } = {}) => {
    const s = String(txt == null ? "" : txt);
    return clipNative("platform_clipboard_write", {
      text: s,
      sensitive: !!sensitive,
      clear_after_ms: clearAfter,
    }).then(r => {
      if (r) return r.ok !== false ? { ok: true, native: true } : { ok: false, native: true };
      try {
        const p = navigator.clipboard && navigator.clipboard.writeText(s);
        if (!p) return { ok: false };
        return Promise.resolve(p).then(
          () => ({ ok: true }),
          () => ({ ok: false }),
        );
      } catch (e) {
        return { ok: false };
      }
    });
  };
  // Wipes the clipboard; with `expected` only while it still holds that value. Resolves true if cleared.
  F.clipClear = expected =>
    clipNative("platform_clipboard_clear", expected == null ? {} : { expected: String(expected) }).then(r => {
      if (r) return !!r.cleared;
      const cb = navigator.clipboard;
      if (!cb || !cb.writeText) return false;
      const wipe = () => Promise.resolve(cb.writeText("")).then(() => true);
      if (expected == null || !cb.readText) return wipe().catch(() => false);
      return Promise.resolve()
        .then(() => cb.readText())
        .then(cur => (cur === expected ? wipe() : false), wipe)
        .catch(() => false);
    });
  // Copies with the auto-clear policy; `sensitive` for keys and secrets. Resolves like F.clipWrite.
  F.clipCopy = (txt, { sensitive = false } = {}) => {
    const s = String(txt == null ? "" : txt);
    const auto = F.clipAutoClear();
    clearTimeout(clipT);
    clipT = null;
    return F.clipWrite(s, { sensitive, clearAfter: auto ? F.CLIP_CLEAR_MS : 0 }).then(r => {
      // The native layer runs the timer itself (WebView timers may be throttled in the background).
      if (auto && !r.native) clipT = setTimeout(() => F.clipClear(s), F.CLIP_CLEAR_MS);
      return r;
    });
  };

  // ---------- local text files ----------
  // Picks a small text file (targets list, plugin manifest) and reads it in the WebView. The core has no
  // command that returns the text of a picked file, so the system chooser of <input type=file> is used.
  F.pickTextFile = ({ accept = ".txt,.csv,text/plain,text/csv", maxBytes = 1024 * 1024 } = {}) =>
    new Promise((resolve, reject) => {
      const inp = document.createElement("input");
      inp.type = "file";
      inp.accept = accept;
      inp.onchange = () => {
        const f = inp.files && inp.files[0];
        if (!f) return resolve(null);
        if (f.size > maxBytes)
          return reject(
            new Error(
              `${F.t("core.file_larger_than_maxbytes_kb", { maxBytes: Math.round(maxBytes / 1024) }, "файл больше {maxBytes} КБ")}`,
            ),
          );
        f.text().then(text => resolve({ name: f.name, size: f.size, text }), reject);
      };
      inp.click();
    });

  // ---------- startup ----------
  F.boot = (startPath, overlay) => {
    try {
      const savedTheme = localStorage.getItem("theme");
      F.setTheme(savedTheme || "dark");
    } catch (e) {
      F.setTheme("dark");
    }
    // An overlay route (the lock screen) opens on top of the start screen, so unlocking returns to it.
    stack = overlay && overlay !== startPath ? [startPath, overlay] : [startPath];
    window.addEventListener("online", () => F.setOffline(false));
    window.addEventListener("offline", () => F.setOffline(true));
    new ResizeObserver(() => updateChrome()).observe(document.body);
    // Live screens: a data/scan event re-renders the current screen without losing scroll position.
    if (F.on) {
      F.on("scan", ev => liveRefresh("scan", ev), { late: true });
      F.on("db", d => liveRefresh("db", d), { late: true });
      F.on("net", d => liveRefresh("net", d), { late: true });
    }
    // The fingerprint session closes when the app goes to background.
    document.addEventListener("visibilitychange", () => {
      if (document.hidden) F.bioClose();
    });
    render("none");
    // Opened via a deep link or notification: set the trap so that system Back leads to the parent
    // (F.parentOf) instead of closing the app.
    syncTrap();
    if (F.flushNotices) F.flushNotices();
    try {
      window.FocaNative && FocaNative.ready();
    } catch (e) {}
  };
})();
