/*
 * FOCA-rs UI ↔ core bridge (contract: docs/API.md).
 * F.api.*: asynchronous commands (names = Tauri commands). Under Tauri → window.__TAURI__.core.invoke,
 * otherwise the demo backend.
 * F.db: snapshot of the current project (project_snapshot), hydrated into the shape screens read.
 * F.on/F.off/F.emit: event bus, "db" {kind} after data changes, "scan" {type, …} for scan events.
 * Legacy names (window.DEMO, F.demoFindings, F.demoProjects, F.project, F.state.scope, F.state.settings…) are
 * aliases onto F.db.
 */
(function () {
  const F = window.FOCA;
  const TAURI = !!(window.__TAURI__ && window.__TAURI__.core && window.__TAURI__.core.invoke);
  const demoBackend = window.FOCA_DEMO_BACKEND;
  // UI dictionary lookup; the bare QA harness loads this file without core.js, so fall back to the RU text.
  const tr = (key, fb) => (window.FOCA && typeof window.FOCA.t === "function" ? window.FOCA.t(key, fb) : fb);
  F.isTauri = TAURI;
  // The demo backend is active (browser without the core): only then are demo tools visible (the "Demo
  // states" menu, "Reset demo data", demo PIN hints, "Demo: …" buttons, "demo" badges).
  F.isDemo = !TAURI && !!demoBackend;

  // Outcome of platform_verify_search: "done" | "cancelled" | "failed" | "not_solved" | "unsupported".
  // Only "done" (Done on a page without the engine's challenge) means the engine accepts us; an answer
  // without `state` is never treated as solved.
  F.verifyState = r => {
    if (!r || r.unsupported) return "unsupported";
    if (["done", "cancelled", "failed", "not_solved"].includes(r.state)) return r.state;
    return r.ok === false ? "unsupported" : "cancelled";
  };
  // Short snack text for a check that did not pass (the engine stays blocked).
  F.verifyStateMsg = (state, name) => {
    if (state === "failed")
      return F.t(
        "scan.verify_st_failed",
        { name },
        "«{name}»: страница проверки не загрузилась. Проверьте связь или прокси и попробуйте ещё раз",
      );
    if (state === "not_solved")
      return F.t(
        "scan.verify_st_not_solved",
        { name },
        "«{name}»: проверка ещё не пройдена, поисковик всё ещё показывает капчу. Попробуйте ещё раз",
      );
    return F.t(
      "scan.verify_st_cancelled",
      { name },
      "«{name}»: проверка отменена, поисковик пока заблокирован. Пройти её можно позже",
    );
  };

  // ================= event bus =================
  const bus = {};
  F.on = (ev, fn, { late = false } = {}) => {
    (bus[ev] = bus[ev] || []).push({ fn, late });
    return () => F.off(ev, fn);
  };
  F.off = (ev, fn) => {
    bus[ev] = (bus[ev] || []).filter(x => x.fn !== fn);
  };
  F.emit = (ev, detail = {}) => {
    const l = bus[ev] || [];
    [...l.filter(x => !x.late), ...l.filter(x => x.late)].forEach(x => {
      try {
        x.fn(detail);
      } catch (e) {
        console.error(e);
      }
    });
  };

  // ================= formatting =================
  const pad = n => String(n).padStart(2, "0");
  const dmy = isoS => (isoS ? `${isoS.slice(8, 10)}.${isoS.slice(5, 7)}.${isoS.slice(0, 4)}` : "");
  const dmyhm = (isoS, sep = " ") => (isoS ? `${dmy(isoS)}${sep}${isoS.slice(11, 16)}` : "");
  const fakeSha = s => {
    let h = 2166136261 >>> 0,
      out = "";
    for (let k = 0; k < 8; k++) {
      for (const c of s + k) h = Math.imul(h ^ c.charCodeAt(0), 16777619) >>> 0;
      out += h.toString(16).padStart(8, "0");
    }
    return out;
  };
  F.fmt = Object.assign(F.fmt || {}, { dmy, dmyhm, pad });

  // ================= hydrate: snapshot JSON → screen objects =================
  const STATUS = () => ({
    analyzed: [tr("doc_status.analyzed", "Проанализирован"), "ok"],
    downloaded: [tr("doc_status.downloaded", "Скачан"), "info"],
    queued: [tr("doc_status.queued", "В очереди"), "mute"],
    // Generic label: the core may not say what failed (older cores have no error_kind).
    error: [tr("api.doc_status_error", "Ошибка обработки"), "bad"],
  });
  // Label of a failed document by doc.error_kind: "parse" = the downloaded/imported file could not be
  // processed, "download"/"http" = the file could not be fetched.
  const ERROR_LABEL = () => ({
    parse: tr("api.doc_status_parse_error", "Ошибка разбора"),
    download: tr("api.doc_status_load_error", "Ошибка загрузки"),
    http: tr("api.doc_status_load_error", "Ошибка загрузки"),
  });
  /** Display label of a document status code, in the current UI language. */
  F.docStatusLabel = (code, kind) =>
    (code === "error" && kind && ERROR_LABEL()[kind]) || (STATUS()[code] || [code])[0];
  const NOMETA = Object.freeze({
    login: "-",
    get name() {
      return tr("api.no_metadata", "Нет метаданных");
    },
    role: "",
    pc: "-",
    color: "#64748b",
    nometa: true,
  });
  const NOSW = Object.freeze({
    id: null,
    name: "-",
    ver: "",
    eol: false,
    cve: 0,
    n: 0,
    cves: [],
    none: true,
  });
  const SCOPE = (F.state.scope = F.state.scope || {}); // A single object for the whole lifetime (launch.js keeps a reference).
  const SETTINGS_VIEW = (F.state.settings = F.state.settings || {});
  const REPORTS_VIEW = (F.state.reports = F.state.reports || { history: [], d: null });

  function hydrate(snap) {
    const db = { raw: snap };
    db.project = snap.project || null;
    // The scope is the same object as F.state.scope (edits in launch.js are immediately visible to
    // selectors).
    Object.keys(SCOPE).forEach(k => delete SCOPE[k]);
    Object.assign(
      SCOPE,
      { client: "", contact: "", phone: "", basis: "", targets: [], excl: [] },
      snap.scope || {},
    );
    delete SCOPE.allow_active; // Legacy field, no longer used.
    db.scope = SCOPE;
    db.settings = snap.settings || {};
    // Where a person or address was found (`src`) is a core text too.
    const srcText = t => FT.field(t, "people-source");
    db.people = (snap.people || []).map(p =>
      localized({ ...p, pc: p.pc || "-" }, { role: FT.role, src: srcText }),
    );
    const pBy = Object.fromEntries(db.people.map(p => [p.login, p]));
    db.software = (snap.software || []).map(s => ({ ...s, n: s.docs }));
    const sBy = Object.fromEntries(db.software.map(s => [s.id, s]));
    db.docs = (snap.docs || []).map(doc => {
      const stc = (STATUS()[doc.status] || [doc.status, "mute"])[1];
      const view = {
        ...doc,
        // Why processing failed, when the core reports it (HTTP status and/or reason); never a guessed code.
        err:
          doc.status === "error"
            ? [doc.http_status ? `HTTP ${doc.http_status}` : "", doc.error_reason || doc.error || ""]
                .filter(x => x && typeof x === "string")
                .join(" · ")
            : "",
        status_code: doc.status,
        stc,
        user:
          pBy[doc.author] ||
          (doc.author
            ? { login: doc.author, name: doc.author, role: "", pc: "-", color: "#64748b" }
            : NOMETA),
        sw: sBy[doc.software] || NOSW,
        created: dmyhm(doc.created_at),
        modified: dmyhm(doc.modified_at),
        year: doc.created_at ? +doc.created_at.slice(0, 4) : null,
        folder: doc.folder || "-",
        printer: doc.printer || "-",
        findings: doc.flags || [],
      };
      // The status label is read in the current language (an in-app language switch keeps the snapshot);
      // filters and counts use status_code.
      delete view.status;
      Object.defineProperty(view, "status", {
        get: () => F.docStatusLabel(view.status_code, view.error_kind),
        set: () => {}, // Derived from status_code; old label writes are ignored.
        enumerable: true,
        configurable: true,
      });
      return view;
    });
    const dBy = Object.fromEntries(db.docs.map(d => [d.id, d]));
    db.emails = (snap.emails || []).map(e => localized({ ...e }, { src: srcText }));
    db.phones = snap.phones || [];
    db.patterns = snap.patterns || [];
    db.hosts = (snap.hosts || []).map(hostView);
    db.pcs = (snap.pcs || []).map(x => localized({ ...x }, { source: FT.hostSource }));
    db.paths = snap.paths || [];
    db.printers = (snap.printers || []).map(p => ({ ...p, n: p.docs }));
    db.secrets = (snap.secrets || []).map(x => secretView(x));
    db.leaks = snap.leaks || {};
    db.findings = (snap.findings || []).map(f => hydrateFinding(f, dBy));
    db.gps = (snap.gps || []).map(g => ({ ...g, date: dmyhm(g.taken_at) }));
    // Timeline texts: the core sends `<field>_msg` next to its Russian text.
    const coreText = (t, m) => (F.coreMsg ? F.coreMsg(t, m) : t);
    db.events = (snap.events || []).map(e =>
      localized(
        { ...e },
        { k: t => coreText(t, e.k_msg), t: t => coreText(t, e.t_msg), s: t => coreText(t, e.s_msg) },
      ),
    );
    db.scans = (snap.scans || []).map(s =>
      localized(
        {
          ...s,
          date: dmyhm(s.finished_at, ", "),
          dur: `${Math.floor(s.minutes / 60) ? Math.floor(s.minutes / 60) + ":" + pad(s.minutes % 60) : s.minutes}:00`,
        },
        { profile: p => F.profileLabel(p, s.profile_id) },
      ),
    );
    db.reports = (snap.reports || []).map(r => ({ ...r, date: dmyhm(r.created_at, ", ") }));
    db.scan = snap.scan || { running: false };
    db.oos = snap.oos || []; // Out-of-scope candidates (decision: new|scope|ignored).
    return db;
  }
  // ---- core texts in the UI language: the snapshot keeps the Russian text the core wrote; screens read it
  // through getters, so an in-app language switch re-renders without a reload (F.ftext, ui/js/ftext.js).
  // Writes replace the stored text (user edits are shown as typed). ----
  const FT = {
    field: (s, rule) => (F.ftext ? F.ftext.field(s, rule) : s),
    recommendation: (s, rule) => (F.ftext ? F.ftext.recommendation(s, rule) : s),
    source: s => (F.ftext ? F.ftext.source(s) : s),
    role: s => (F.ftext ? F.ftext.role(s) : s),
    hostSource: s => (F.ftext ? F.ftext.hostSource(s) : s),
  };
  function localized(o, map) {
    const raw = {};
    Object.entries(map).forEach(([k, tr]) => {
      raw[k] = o[k];
      Object.defineProperty(o, k, {
        enumerable: true,
        configurable: true,
        get: () => (typeof raw[k] === "string" ? tr(raw[k]) : raw[k]),
        set: v => {
          raw[k] = v;
        },
      });
    });
    return o;
  }
  // Scan profile label: the core writes it in Russian next to `profile_id`.
  const PROFILE_IDS = { Пассивный: "passive", Стандартный: "std", Полный: "full", Свой: "custom" };
  F.profileLabel = (label, id) => {
    const pid = id || PROFILE_IDS[label];
    return !pid || !F.i18n || F.i18n.lang() === "ru" ? label : tr("launch.profile_" + pid, label);
  };
  const hostView = h => localized({ ...h }, { role: FT.role, source: FT.hostSource });
  function hydrateFinding(f, dBy) {
    const doc = f.doc ? (dBy || {})[f.doc] : null;
    const time = f.time ? f.time.slice(0, 16).replace("T", " ") : "";
    const rule = (f.provenance && f.provenance.rule) || "";
    return evidenceView(
      localized(
        {
          ...f,
          time,
          rel: { people: [], pcs: [], docs: [], ...(f.rel || {}) },
          provenance: {
            get source() {
              return FT.source(f.source);
            },
            url: doc ? doc.url : f.url || (f.host !== "-" ? "https://" + f.host + "/" : "-"),
            time: f.time ? dmyhm(f.time, ", ") : "",
            sha256: doc
              ? doc.sha256 || (TAURI ? "" : fakeSha(doc.name))
              : f.request && !TAURI
                ? fakeSha(f.request)
                : "",
            request: f.request || "",
            doc: doc ? doc.id : null,
            // Core rule id (e.g. "infra.cert_expired", "mail-caa_missing"): the finding card explains the code.
            rule,
          },
        },
        {
          title: s => FT.field(s, rule),
          description: s => FT.field(s, rule),
          recommendation: s => FT.recommendation(s, rule),
          source: FT.source,
        },
      ),
      rule,
    );
  }
  // ---- secrets: the snapshot carries only a mask; the plain value comes from secret_reveal and lives in
  // memory while the confirmation session is open (F.bioOpen from core.js) or a screen revealed it after a
  // fingerprint ----
  const REVEALED = new Map();
  let localUnlock = 0; // Unlock window after confirmation in the legacy fingerprint sheets (F.dataConfirmFinger).
  const unlocked = () => (F.bioOpen && F.bioOpen()) || Date.now() < localUnlock;
  const pend = new Set();
  function revealed(key) {
    key = String(key);
    if (REVEALED.has(key)) return REVEALED.get(key);
    if (!TAURI) {
      try {
        const r = demoBackend.invokeSync("secret_reveal", {
          project: cur(),
          id: /^\d+$/.test(key) ? +key : key,
        });
        REVEALED.set(key, r.value);
        return r.value;
      } catch (e) {
        return null;
      }
    }
    if (!pend.has(key)) {
      pend.add(key);
      call("secret_reveal", { project: cur(), id: /^\d+$/.test(key) ? +key : key }).then(
        r => {
          REVEALED.set(key, r.value);
          pend.delete(key);
          if (F.render) F.render(true);
        },
        () => pend.delete(key),
      );
    }
    return null;
  }
  function secretView(x) {
    // `where` is a core text ("текст, строка 4", "поле password", …) translated like secret findings.
    const o = localized({ ...x }, { where: w => FT.field(w, "secret") });
    delete o.value;
    const dataOpen = () => {
      const S = F.state.data;
      return !!(S && S.revealed && S.revealed.has && S.revealed.has(x.id));
    }; // data.js revealed the value after a fingerprint.
    Object.defineProperty(o, "value", {
      enumerable: true,
      configurable: true,
      get: () => (unlocked() || dataOpen() ? (revealed(x.id) ?? x.mask) : x.mask),
    });
    return o;
  }
  function evidenceView(f, rule) {
    let masked = f.evidence || "";
    const refs = f.secret_refs || [];
    Object.defineProperty(f, "evidence", {
      enumerable: true,
      configurable: true,
      get: () => {
        if (!refs.length || !unlocked()) return FT.field(masked, rule || "");
        let k = 0;
        // Revealed values are data: translate the masked text first, then put the values in.
        return FT.field(masked, rule || "").replace(/\{\{s:([\s\S]*?)\}\}/g, (m0, mv) => {
          const v = revealed(refs[k++]);
          return `{{s:${v ?? mv}}}`;
        });
      },
      set: v => {
        masked = v || "";
      },
    });
    return f;
  }
  if (F.onBioClose)
    F.onBioClose(() => {
      REVEALED.clear();
      localUnlock = 0;
    });
  // Legacy fingerprint sheets (data.js / findings.js): open a 2-minute window after confirmation.
  let dcf = null;
  Object.defineProperty(F, "dataConfirmFinger", {
    configurable: true,
    get: () => dcf,
    set: fn => {
      dcf =
        typeof fn === "function"
          ? (then, what, el) =>
              fn(
                () => {
                  localUnlock = Date.now() + 120000;
                  then();
                },
                what,
                el,
              )
          : fn;
    },
  });

  // Settings: the view used by settings.js (legacy field names) on top of F.db.settings: a single source of
  // truth.
  const KEY_ST = { ok: "ok", none: "none", error: "err" };
  const KEY_ST_BACK = { ok: "ok", none: "none", err: "error" };
  function bindView(view, src, map) {
    Object.keys(view).forEach(k => delete view[k]);
    Object.entries(map).forEach(([k, path]) => {
      Object.defineProperty(view, k, {
        enumerable: true,
        configurable: true,
        get: () => (typeof path === "function" ? path() : src[path]),
        set: v => {
          if (typeof path !== "function") src[path] = v;
        },
      });
    });
    return view;
  }
  function settingsView(s) {
    const view = SETTINGS_VIEW;
    // Sections are created inside `s` itself, so screen edits (view setters) land in F.db.settings.
    const net = (s.net = s.net || {}),
      pw = (s.power = s.power || {}),
      sec = (s.sec = s.sec || {});
    s.keys = s.keys || {};
    const keys = {};
    Object.entries(s.keys || {}).forEach(([id, k]) => {
      keys[id] = {};
      Object.defineProperties(keys[id], {
        v: {
          enumerable: true,
          get: () => k.mask || "",
          set: x => {
            k.mask = x;
          },
        },
        st: {
          enumerable: true,
          get: () => KEY_ST[k.status] || "none",
          set: x => {
            k.status = KEY_ST_BACK[x] || x;
          },
        },
        used: {
          enumerable: true,
          get: () => k.used,
          set: x => {
            k.used = x;
          },
        },
        lim: {
          enumerable: true,
          get: () => k.limit,
          set: x => {
            k.limit = x;
          },
        },
        err: {
          enumerable: true,
          get: () => k.error,
          set: x => {
            k.error = x;
          },
        },
        per: {
          enumerable: true,
          get: () => k.per,
          set: x => {
            k.per = x;
          },
        },
        note: {
          enumerable: true,
          get: () => k.note,
          set: x => {
            k.note = x;
          },
        },
      });
    });
    const keysProxy = new Proxy(keys, {
      set(t, id, val) {
        s.keys[id] = {
          status: KEY_ST_BACK[val.st] || val.st || "none",
          mask: val.v || "",
          used: val.used,
          limit: val.lim,
          error: val.err,
        };
        t[id] = val;
        return true;
      },
    });
    const prev = { battery: view.battery, look: view.look, sig: view.sig },
      ui = s.ui || {};
    Object.keys(view).forEach(k => delete view[k]);
    view.keys = keysProxy;
    net.preset = net.preset || (net.orbot ? "orbot" : "custom");
    net.groups = Object.assign({ search: "", recon: "", target: "" }, net.groups || {});
    view.net = bindView({}, net, {
      proxyOn: "proxy_on",
      preset: "preset",
      ptype: "type",
      addr: "addr",
      orbot: "orbot",
      groups: "groups",
      ua: "ua",
      uaCustom: "ua_custom",
      threads: "threads",
      rps: "rps",
      hostsParallel: "hosts_parallel",
      timeout: "timeout",
      retries: "retries",
      kill: "kill_switch",
      dns: "dns",
      dnsCustom: "dns_custom",
      outIp: "out_ip",
      label: "label",
    });
    view.power = bindView({}, pw, {
      wifiOnly: "wifi_only",
      limOn: "lim_on",
      mobLimit: "mob_limit",
      battOn: "batt_on",
      batt: "batt",
      heat: "heat",
      chargeOnly: "charge_only",
      period: "period",
      autoResume: "auto_resume",
    });
    view.sec = bindView({}, sec, {
      pin: "pin",
      bio: "bio",
      autolock: "autolock",
      hide: "hide",
      clip: "clip",
      panic: "panic",
      autodel: "autodel",
      autodelDays: "autodel_days",
    });
    // UI-only sections (not from the core) survive snapshot reloads.
    let theme = "dark";
    try {
      theme = localStorage.getItem("st-theme") || "dark";
    } catch (e) {}
    // settings.ui (persisted by the core) over the current values: with the real core, settings arrive after
    // screens load.
    view.battery = Object.assign(
      prev.battery || { excluded: false, oem: "xiaomi", done: {} },
      ui.battery || {},
    );
    view.look = Object.assign(prev.look || { theme, lang: "RU", density: "normal" }, ui.look || {});
    view.sig = Object.assign(
      prev.sig || {
        auto: true,
        updating: false,
        updated: TAURI ? tr("api.built_into_app", "встроены в приложение") : "18.11.2026, 09:12",
      },
      ui.sig || {},
      { updating: false },
    );
  }

  // ================= current state =================
  F.db = hydrate({});
  settingsView(F.db.settings); // The settings view exists before the first load (screens read it when they are loaded).
  F.projects = []; // project_list (live array; projects.js reads it as F.demoProjects).
  const legacyProject = s => ({
    id: s.id,
    name: s.name,
    client: s.client,
    lastScan: s.last_scan_at ? dmyhm(s.last_scan_at, ", ") : "",
    risk: s.risk,
    findings: s.findings,
    docs: s.docs,
    scanning: s.scanning,
    progress: s.progress,
    archived: s.archived,
    scans: s.scans,
    lastProfile: s.last_profile,
    // Built-in reference case: kept out of recent projects and never restored on start.
    reference: !!s.reference,
  });
  // The project list is re-read after mutations and emits "db" {kind: "projects"}; /projects re-renders its
  // cards.
  function setProjects(list) {
    F.projects.length = 0;
    list.forEach(s => F.projects.push(legacyProject(s)));
    if (F.cur) F.emit("db", { kind: "projects" });
  }
  // Infrastructure records of the infrastructure modules (infra_get) live next to the snapshot in F.db.infra. They are
  // re-read with every snapshot; "db" {kind: "infra"} is emitted only when they changed (the demo backend is
  // synchronous: an unconditional emit from a screen refresh would loop).
  const INFRA_EMPTY = {
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
  };
  let infraKey = "",
    infraOf = null,
    infraVal = INFRA_EMPTY;
  function loadInfra(id, quiet) {
    if (!id) return;
    run("infra_get", { project: id }).then(
      r => {
        if (!F.db.project || F.db.project.id !== id) return;
        const v = { ...INFRA_EMPTY, ...(r || {}) },
          key = JSON.stringify(v);
        F.db.infra = infraVal = key === infraKey && infraOf === id ? infraVal : v;
        if (key === infraKey && infraOf === id) return;
        infraKey = key;
        infraOf = id;
        if (!quiet) F.emit("db", { kind: "infra" });
      },
      () => {}, // An older core without infra_get: the screens show no infrastructure data.
    );
  }
  function applySnapshot(snap, kind = "project") {
    const prevId = F.db && F.db.project && F.db.project.id;
    F.db = hydrate(snap);
    const id = F.db.project && F.db.project.id;
    F.db.infra = id && id === infraOf && id === prevId ? infraVal : INFRA_EMPTY;
    loadInfra(id, !TAURI);
    settingsView(F.db.settings);
    REPORTS_VIEW.history.length = 0;
    F.db.reports.forEach(r => REPORTS_VIEW.history.push(r));
    if (kind === "project" && F.state.data) F.state.data.trail = [];
    F.emit("db", { kind });
  }

  // ================= command invocation =================
  // Tauri: a single `foca` command → Engine::invoke (src-tauri/src/bridge.rs); a core error { code, message,
  // targets? } becomes an Error with those fields.
  const toErr = e => {
    if (e instanceof Error) return e;
    const o = e && typeof e === "object" ? e : { message: String(e) };
    const text = o.message && F.coreMsg ? F.coreMsg(o.message, o.message_msg) : o.message;
    const er = new Error(text || o.code || tr("api.core_error", "Ошибка ядра"));
    er.code = o.code || "internal";
    if (o.targets) er.targets = o.targets;
    return er;
  };
  const call = (cmd, args) =>
    TAURI
      ? window.__TAURI__.core.invoke("foca", { cmd, args: args || {} }).catch(e => {
          throw toErr(e);
        })
      : demoBackend.invoke(cmd, args || {});
  // In demo mode commands run synchronously, so a screen may re-render right after the call.
  function run(cmd, args, apply) {
    if (TAURI)
      return call(cmd, args).then(r => {
        if (apply) apply(r);
        return r;
      });
    try {
      const r = demoBackend.invokeSync(cmd, args || {});
      if (apply) apply(r);
      return Promise.resolve(r);
    } catch (e) {
      return Promise.reject(e);
    }
  }
  const cur = () => F.db.project && F.db.project.id;
  let netHint = null;
  // Recount entity counters after deleting/restoring documents (numbers are list lengths).
  function recount() {
    const live = F.db.docs.filter(d => !d.deleted && d.status_code === "analyzed");
    const cnt = f => {
      const m = new Map();
      live.forEach(d => {
        const k = f(d);
        if (k) m.set(k, (m.get(k) || 0) + 1);
      });
      return m;
    };
    const sw = cnt(d => d.software),
      pr = cnt(d => d.printer !== "-" && d.printer),
      fo = cnt(d => d.folder !== "-" && d.folder),
      au = cnt(d => d.author);
    F.db.software.forEach(s => {
      s.docs = s.n = sw.get(s.id) || 0;
    });
    F.db.printers.forEach(p => {
      p.docs = p.n = pr.get(p.name) || 0;
    });
    F.db.paths.forEach(p => {
      p.docs = fo.get(p.path) || 0;
    });
    F.db.people.forEach(p => {
      if (p.src_kind === "meta") p.docs = au.get(p.login) || 0;
    });
  }
  const refreshList = () => run("project_list", {}, setProjects);
  const reload = (kind = "data") =>
    cur() ? run("project_snapshot", { id: cur() }, s => applySnapshot(s, kind)) : Promise.resolve();

  F.api = {
    // --- projects ---
    project_list: () => refreshList(),
    project_open: id =>
      run("project_open", { id }, s => {
        applySnapshot(s, "project");
      }).then(r => {
        refreshList();
        return r;
      }),
    project_snapshot: id => run("project_snapshot", { id: id || cur() }),
    project_create: args =>
      run("project_create", args).then(r => {
        refreshList();
        return r;
      }),
    project_update: (id, patch) =>
      run("project_update", { id, patch }).then(r => {
        refreshList();
        if (id === cur()) Object.assign(F.db.project, patch);
        return r;
      }),
    project_duplicate: id =>
      run("project_duplicate", { id }).then(r => {
        refreshList();
        return r;
      }),
    project_delete: id =>
      run("project_delete", { id }).then(r => {
        refreshList();
        return r;
      }),
    project_export_encrypted: (id, password, include_files = false) =>
      run("project_export_encrypted", { project: id || cur(), password, include_files: !!include_files }),
    project_import_encrypted: (path, password, new_name) =>
      run("project_import_encrypted", new_name ? { path, password, new_name } : { path, password }).then(
        r => {
          refreshList();
          return r;
        },
      ),
    // --- scope ---
    scope_get: id => run("scope_get", { id: id || cur() }),
    // With `id` of another project (properties from the project list) a partial patch goes to the core and
    // F.db is left untouched.
    scope_set: (scope, id) => {
      if (id && id !== cur())
        return run("scope_get", { id }).then(sc => run("scope_set", { id, scope: { ...sc, ...scope } }));
      Object.assign(SCOPE, scope);
      F.emit("db", { kind: "scope" });
      return run("scope_set", { id: cur(), scope: { ...SCOPE } }).then(r => reload("scope").then(() => r));
    },
    // Bulk add of out-of-scope names; dry_run returns the plan (skipped names, CDN/cloud addresses held out of
    // the port scan) without storing anything.
    scope_add_hosts: (hosts, dry_run) =>
      run("scope_add_hosts", { project: cur(), hosts, dry_run: !!dry_run }).then(r => {
        if (r.dry_run) return r;
        Object.assign(SCOPE, r.scope);
        F.emit("db", { kind: "scope" });
        return run("oos_list", { project: cur() }).then(o => {
          F.db.oos = o;
          F.emit("db", { kind: "oos" });
          return r;
        });
      }),
    // --- scan (events arrive via F.on("scan")) ---
    scan_start: opts => run("scan_start", { project: cur(), ...opts }),
    scan_stop: reason => run("scan_stop", { reason }),
    // Deletes one scan and everything only it produced (docs/API.md → scan_delete). dryRun: counts only.
    scan_delete: (scanId, dryRun = false) =>
      dryRun
        ? run("scan_delete", { project: cur(), scan_id: scanId, dry_run: true })
        : run("scan_delete", { project: cur(), scan_id: scanId }).then(r =>
            reload("data").then(() => {
              refreshList();
              return r;
            }),
          ),
    // netHint: pause/resume caused by a native network event. Environment pauses are governed by the core's
    // policy and are not a user decision (src-tauri/src/policy.rs).
    scan_pause: () => run("scan_pause", netHint ? { reason: netHint } : {}),
    scan_resume: () => run("scan_resume", netHint ? { reason: netHint } : {}),
    scan_status: () => run("scan_status", {}),
    // "Skip source" (a stuck or slow search source) → a source event with status skipped.
    scan_skip_source: id => run("scan_skip_source", { id }),
    scan_retry_source: id => run("scan_retry_source", { id }),
    scan_control: (kind, id, action) => run("scan_control", { kind, id, action }),
    // Site file search (foca-fuzz): offline estimate and wordlists (docs/API.md).
    fuzz_estimate: (o = {}) => run("fuzz_estimate", { project: cur(), ...o }),
    wordlists_list: () => run("wordlists_list", {}),
    wordlists_download: id => run("wordlists_download", { id, project: cur() || undefined }),
    wordlists_import: (path, name) => run("wordlists_import", { path, name }),
    wordlists_delete: id => run("wordlists_delete", { id }),
    // Engine log (Debug tab): [{ id, t, level, target, msg }]
    // --- out-of-scope candidates ---
    oos_decide: (id, decision) =>
      run("oos_decide", { project: cur(), id, decision }, list => {
        F.db.oos = list;
        F.emit("db", { kind: "oos" });
      }),
    // --- findings ---
    // Mutations: optimistic update of F.db → command → fresh project_list (project cards).
    finding_set_status: (id, status) => {
      const f = F.db.findings.find(x => x.id === +id);
      if (f) f.status = status;
      F.emit("db", { kind: "findings", id: +id });
      return run("finding_set_status", { project: cur(), id: +id, status }, r => {
        if (f && r) f.status = r.status;
      }).then(r => {
        refreshList();
        return r;
      });
    },
    finding_update: (id, patch) => {
      const f = F.db.findings.find(x => x.id === +id);
      if (f) Object.assign(f, patch);
      F.emit("db", { kind: "findings", id: +id });
      return run("finding_update", { project: cur(), id: +id, patch }).then(r => {
        refreshList();
        return r;
      });
    },
    finding_photo_add: (id, photo = {}) =>
      run("finding_photo_add", { project: cur(), id: +id, ...photo }, r => {
        const f = F.db.findings.find(x => x.id === +id);
        if (f && r) f.photos = r.photos;
        F.emit("db", { kind: "findings", id: +id });
      }),
    // --- documents: after delete/restore the snapshot is re-read, the core derives software, people, paths,
    // printers, PCs, GPS, secrets and events from live documents, so the numbers match after a reload as well
    // ---
    doc_delete: ids => {
      ids = [].concat(ids).map(Number);
      F.db.docs.forEach(d => {
        if (ids.includes(d.id)) d.deleted = true;
      });
      recount();
      F.emit("db", { kind: "docs" });
      return run("doc_delete", { project: cur(), ids }).then(r =>
        reload("docs").then(() => {
          refreshList();
          return r;
        }),
      );
    },
    doc_restore: ids => {
      ids = [].concat(ids).map(Number);
      F.db.docs.forEach(d => {
        if (ids.includes(d.id)) d.deleted = false;
      });
      recount();
      F.emit("db", { kind: "docs" });
      return run("doc_restore", { project: cur(), ids }).then(r =>
        reload("docs").then(() => {
          refreshList();
          return r;
        }),
      );
    },
    // Analytics and hygiene (docs/API.md → "Аналитика", "Гигиена документов").
    insights_get: (o = {}) => run("insights_get", { project: cur(), ...o }),
    chain_get: o => run("chain_get", { project: cur(), ...o }),
    attack_paths_get: (o = {}) => run("attack_paths_get", { project: cur(), ...o }),
    // { ids? } for the project, { path, name? } for a file outside any project (Android share sheet).
    hygiene_get: (o = {}) => run("hygiene_get", o.path ? o : { project: cur(), ...o }),
    doc_clean_file: (path, name, options) => run("doc_clean", { path, name, options }),
    doc_clean: (ids, options) =>
      run("doc_clean", { project: cur(), ids: [].concat(ids).map(Number), options }, r => {
        (r.cleaned || []).forEach(c => {
          const d = F.db.docs.find(x => x.id === c.id);
          if (d) d.cleaned = { at: c.at, name: c.name, manual: (c.manual || []).length };
        });
        F.emit("db", { kind: "docs" });
      }),
    // --- secrets: the snapshot holds only a mask; the value is fetched on demand after confirmation ---
    secret_reveal: id =>
      run("secret_reveal", { project: cur(), id }, r => {
        REVEALED.set(String(r.id), r.value);
      }),
    // --- settings, i18n, licenses, signatures, keys, network ---
    i18n_bundle: ({ lang, device_locale, include_help = false } = {}) =>
      run("i18n_bundle", { lang, device_locale, include_help: !!include_help }),
    licenses_get: () => run("licenses_get", {}),
    signatures_status: () => run("signatures_status", {}),
    signatures_import: bundle_json => run("signatures_import", { bundle_json }),
    signatures_update: url => run("signatures_update", url ? { url } : {}),
    signatures_rollback: () => run("signatures_rollback", {}),
    // In-app update (progress arrives as `update` events via F.on("scan")).
    update_status: flavor => run("update_status", { flavor }),
    update_check: (o = {}) => run("update_check", o),
    update_download: flavor => run("update_download", { flavor }),
    update_cancel: () => run("update_cancel", {}),
    // --- export, AI, PIN, full wipe ---
    export_build: (kind, fmt, opts = {}) => run("export_build", { project: cur(), kind, fmt, opts }),
    ai_models_list: (provider, base_url, refresh = false, show_all = false) =>
      run("ai_models_list", { provider, base_url, refresh, show_all }),
    ai_preview: opts => run("ai_preview", { project: cur(), opts }),
    ai_summarize: (preview_id, opts) => run("ai_summarize", { project: cur(), preview_id, opts }),
    ai_cancel: () => run("ai_cancel", { project: cur() }),
    ai_summaries_list: () => run("ai_summaries_list", { project: cur() }),
    cve_list: (q, offset = 0, limit = 50) => run("cve_list", { ...q, offset, limit }),
    ai_summary_use: summary => run("ai_summary_use", { project: cur(), summary }),
    ai_summary_delete: summary => run("ai_summary_delete", { project: cur(), summary }),
    pin_set: (pin, panic) => run("pin_set", { pin, panic }),
    pin_check: pin => run("pin_check", { pin }),
    wipe_all: () =>
      run("wipe_all", { confirm: "WIPE" }).then(r =>
        refreshList()
          .then(() => run("settings_get", {}))
          .then(st => {
            REVEALED.clear();
            applySnapshot({ settings: st }, "reset");
            return r;
          }),
      ),
    oos_add_to_scope: id =>
      run("oos_add_to_scope", { project: cur(), id }, r => {
        Object.assign(SCOPE, r.scope);
        F.db.oos = r.oos;
        F.emit("db", { kind: "scope" });
        F.emit("db", { kind: "oos" });
      }),
    // --- settings and keys ---
    settings_get: () => run("settings_get", {}),
    settings_set: patch =>
      run("settings_set", { patch }, s => {
        Object.assign(F.db.settings, s);
        settingsView(F.db.settings);
        F.emit("db", { kind: "settings" });
      }),
    key_set: (service, value) =>
      run("key_set", { service, value }, k => {
        F.db.settings.keys[service] = k;
        settingsView(F.db.settings);
        F.emit("db", { kind: "settings" });
      }),
    key_delete: service =>
      run("key_delete", { service }, k => {
        F.db.settings.keys[service] = k;
        settingsView(F.db.settings);
        F.emit("db", { kind: "settings" });
      }),
    // Brave key or own SearXNG check: { ok, code, status?, remaining?, limit?, instances? }.
    key_check: (service, value) => run("key_check", value ? { service, value } : { service }),
    // Dork groups postponed after captchas everywhere, and "Retry now".
    dorks_pending: () => run("dorks_pending", { project: cur() }),
    dorks_retry: () => run("dorks_retry", { project: cur() }),
    net_check: () => run("net_check", {}),
    // Monthly mobile data counter: { month, bytes, used_mb, limit_mb, reached, metered }.
    mobile_usage: () => run("mobile_usage", {}),
    net_proxy_check: args => run("net_proxy_check", args || {}),
    // --- reports ---
    report_list: () => run("report_list", { project: cur() }),
    // Report templates of the core (docs/API.md → report_templates): [{ id, title, description }].
    report_templates: lang => run("report_templates", lang ? { lang } : {}),
    // Report logo of Settings → Report (docs/API.md → report_logo_get): { logo: null | { data, mime,
    // name, w, h, bytes } }; set takes { data: "data:image/…;base64,…", name }.
    report_logo_get: () => run("report_logo_get", {}),
    report_logo_set: o => run("report_logo_set", o || {}),
    report_logo_clear: () => run("report_logo_clear", {}),
    // template: fixed-structure core template (executive | compliance | lab); omitted for the full report.
    report_build: (opts, template) =>
      run("report_build", template ? { project: cur(), opts, template } : { project: cur(), opts }, r => {
        const x = { ...r, date: dmyhm(r.created_at, ", ") };
        F.db.reports.unshift(x);
        REPORTS_VIEW.history.unshift(x);
        F.emit("db", { kind: "reports" });
      }),
    report_delete: id => {
      F.db.reports = F.db.reports.filter(r => r.id !== +id);
      return run("report_delete", { project: cur(), id: +id });
    },
    // --- Android platform (docs/API.md, "Platform commands"; stubs in demo mode) ---
    platform_share: o => run("platform_share", { project: cur(), ...o }),
    platform_save: o => run("platform_save", { project: cur(), ...o }),
    platform_print: o => run("platform_print", { project: cur(), ...o }),
    platform_pdf: o => run("platform_pdf", { project: cur(), ...o }),
    // External http/https link in the system browser (Tauri: platform_open_url; browser demo: a new tab).
    open_url: url =>
      /^https?:\/\//i.test(String(url || ""))
        ? TAURI
          ? run("platform_open_url", { url: String(url) })
          : (window.open(String(url), "_blank", "noopener,noreferrer"), Promise.resolve({ ok: true }))
        : Promise.reject({
            code: "bad_args",
            message: tr("api.only_http_https_links_can_opened", "открываются только ссылки http/https"),
          }),
    platform_biometric: o => run("platform_biometric", o || {}),
    platform_secure: on => run("platform_secure", { on: !!on }),
    platform_battery_status: () => run("platform_battery_status", {}),
    platform_battery_settings: what => run("platform_battery_settings", { what: what || "battery" }),
    platform_notifications: () => run("platform_notifications", {}),
    // File (SAF) / photo (photo picker, camera) selection: { ok, cancelled, files: [{ path /* copy in the
    // private folder */, name, size, mime }] }
    platform_pick_files: (o = {}) => run("platform_pick_files", o),
    platform_permissions_status: () => run("platform_permissions_status", {}),
    platform_bg_status: () => run("platform_bg_status", {}),
    platform_bg_set: o => run("platform_bg_set", o || {}),
    // Manual captcha check: { state: done|cancelled|failed|not_solved, ok, closed, detail? } (see
    // F.verifyState); only "done" may mark the engine verified.
    platform_verify_search: o => run("platform_verify_search", o || {}),
    platform_request_notifications: () => run("platform_request_notifications", {}),
    platform_exit: () => run("platform_exit", {}),
    platform_device_info: () => run("platform_device_info", {}),
    // In-app update install (Android): { enabled, can_install, opened } and the PackageInstaller
    // session for a verified APK in the app cache: { ok, code, cert_match, version_code, ... }.
    platform_update_permission: (o = {}) => run("platform_update_permission", o),
    platform_update_install: o => run("platform_update_install", o || {}),
    // Native clipboard (the Android WebView cannot read it): { ok, text, available, error? },
    // { ok, scheduled }, { ok, cleared }; desktop and the demo answer { unsupported: true }.
    platform_clipboard_read: () => run("platform_clipboard_read", {}),
    platform_clipboard_write: o => run("platform_clipboard_write", o || {}),
    platform_clipboard_clear: o => run("platform_clipboard_clear", o || {}),
    // Terms of use (first screen) and the Debug tab.
    terms_get: () => run("terms_get", {}),
    terms_accept: version => run("terms_accept", { version }),
    logs_get: (o = {}) => run("logs_get", o),
    logs_clear: () => run("logs_clear", {}),
    logs_export: (o = {}) => run("logs_export", o),
    crash_list: () => run("crash_list", {}),
    crash_get: name => run("crash_get", { name }),
    request_log_get: (o = {}) => run("request_log_get", { project: cur(), ...o }),
    // { scan_id?, days?, dry_run? } -> { removed, kept_running }: rows of a running scan stay
    request_log_clear: (o = {}) => run("request_log_clear", { project: cur(), ...o }),
    search_journal: () => run("search_journal", {}),
    search_fingerprint: () => run("search_fingerprint", {}),
    search_fingerprint_page: () => run("search_fingerprint_page", {}),
    search_captcha_test: args => run("search_captcha_test", args || {}),
    app_info: () => run("app_info", {}),
    demo_first_run: () => run("demo_first_run", {}),
    platform_pick_image: (o = {}) => run("platform_pick_image", o),
    // Folder selection (SAF tree, copied with limits) and cleanup of the picked copies.
    platform_pick_folder: (o = {}) => run("platform_pick_folder", o),
    platform_pick_clear: () => run("platform_pick_clear", {}),
    // Files shared into the app (Android ACTION_SEND/ACTION_SEND_MULTIPLE), copied into the private cache:
    // { files: [{ path, name, size, mime }], skipped, truncated }; the list is handed out once.
    platform_shared_files: () => run("platform_shared_files", {}),
    // Offline import (files, folders, ZIP; no network), full-text search, user rules, forensics.
    import_offline: (o = {}) => run("import_offline", o),
    // Built-in reference case (docs/API.md → demo_case_import): same result and import events as import_offline.
    demo_case_import: (o = {}) => run("demo_case_import", o),
    import_cancel: () => run("import_cancel", {}),
    // Re-analysis of stored documents (docs/API.md → project_reextract): background job, `reextract` events.
    project_reextract: (o = {}) => run("project_reextract", { project: cur(), ...o }),
    reextract_status: (o = {}) => run("reextract_status", { project: cur(), ...o }),
    reextract_cancel: (o = {}) => run("reextract_cancel", { project: cur(), ...o }),
    docs_search: (q, o = {}) => run("docs_search", { project: cur(), q, ...o }),
    doc_get: id => run("doc_get", { project: cur(), id: +id }),
    rules_get: () => run("rules_get", { project: cur() }),
    rules_set: config => run("rules_set", { project: cur(), config }),
    rules_test: (pattern, text, case_insensitive = true) =>
      run("rules_test", { pattern, text, case_insensitive }),
    // Document file in project storage (for Share/Save): { path, name, size }
    doc_file: id => run("doc_file", { project: cur(), id: +id }),
    // Import local files into the project (no network): copy, metadata, analysis → the snapshot is re-read.
    doc_import: paths =>
      run("doc_import", { project: cur(), paths }).then(r =>
        reload("docs").then(() => {
          refreshList();
          return r;
        }),
      ),
    // Opt-in HIBP check, contextual wordlists, quick tools, scan queue, alerts & risk trend.
    secret_hibp_check: id =>
      run("secret_hibp_check", { project: cur(), id: /^\d+$/.test(String(id)) ? +id : id }),
    wordlist_preview: (o = {}) => run("wordlist_preview", { project: cur(), ...o }),
    tool_file: (o = {}) => run("tool_file", o),
    tool_mail_domain: (o = {}) => run("tool_mail_domain", o),
    tool_host: (o = {}) => run("tool_host", o),
    tool_secret: (o = {}) => run("tool_secret", o),
    tool_log: (o = {}) => run("tool_log", o),
    tool_log_clear: () => run("tool_log_clear", {}),
    queue_add: (o = {}) => run("queue_add", o),
    queue_list: () => run("queue_list", {}),
    queue_pause: () => run("queue_pause", {}),
    queue_resume: () => run("queue_resume", {}),
    queue_remove: id => run("queue_remove", { id }),
    queue_clear: (o = {}) => run("queue_clear", o),
    alert_rules_get: (o = {}) => run("alert_rules_get", o || {}),
    alert_rules_set: (patch, project) => run("alert_rules_set", project ? { project, patch } : { patch }),
    alert_test: (channel, project) => run("alert_test", project ? { project, channel } : { channel }),
    risk_trend_get: (o = {}) => run("risk_trend_get", { project: cur(), ...o }),
    // Remediation playbooks & report custody/signature verification.
    finding_playbook: (id, lang) =>
      run("finding_playbook", lang ? { project: cur(), id: +id, lang } : { project: cur(), id: +id }),
    report_verify: id => run("report_verify", { project: cur(), id: +id }),
    // Sandboxed plugin catalog & execution.
    plugins_list: () => run("plugins_list", {}),
    plugin_install: manifest => run("plugin_install", { manifest }),
    plugin_toggle: (id, enabled) => run("plugin_toggle", { id, enabled: !!enabled }),
    plugin_remove: id => run("plugin_remove", { id }),
    plugin_run_test: (o = {}) => run("plugin_run_test", o),
    // --- internal ---
    reload,
    demo_reset: () => {
      if (TAURI)
        return Promise.reject(
          new Error(tr("api.demo_reset_available_demo_mode", "demo_reset доступен только в демо")),
        );
      return run("demo_reset", {})
        .then(() => refreshList())
        .then(() => F.api.project_open((F.projects[0] || {}).id));
    },
  };

  // ================= scan events =================
  // Core scan state (for screens while scan.js runs its own demo engine).
  F.coreScan = { running: false };
  // The core emits "db" only at the end of a stage, while the counters on Overview, the mini bar, the project
  // list and Data → Documents come from the snapshot and would freeze during downloads. On progress events
  // the
  // snapshot is re-read (at most once per LIVE_MS, without overlapping requests) → F.emit("db") → live
  // screens re-render.
  const LIVE_MS = 1500;
  let liveAt = 0,
    liveBusy = false,
    liveTail = null;
  function liveCounts() {
    const cs = F.coreScan;
    if (!cs.running) return;
    const wait = liveAt + LIVE_MS - Date.now();
    if (liveBusy || wait > 0) {
      if (!liveTail)
        liveTail = setTimeout(
          () => {
            liveTail = null;
            liveCounts();
          },
          Math.max(wait, 200),
        );
      return;
    }
    liveBusy = true;
    liveAt = Date.now();
    const mine = cs.project && cs.project === cur();
    Promise.all([mine ? reload("scan") : null, refreshList()])
      .catch(() => {})
      .then(() => {
        liveBusy = false;
      });
  }
  function onScanEvent(ev) {
    if (!ev) return;
    const cs = F.coreScan;
    if (ev.type === "started")
      Object.assign(cs, {
        running: true,
        project: ev.project,
        scan_id: ev.scan_id,
        profile: ev.profile,
        active: ev.active,
        egress: ev.egress,
        progress: 0,
        stageLabel: tr("api.stage_search", "Поиск"),
      });
    if (ev.type === "stage") cs.stageLabel = ev.label;
    if (ev.type === "progress") cs.progress = ev.progress;
    if (ev.type === "done" || ev.type === "stopped") Object.assign(cs, { running: false, progress: 100 });
    if (ev.type === "db" || ev.type === "done" || ev.type === "stopped") {
      if (ev.project && ev.project === cur()) reload("scan");
      refreshList();
    } else if (ev.type === "progress" && cs.running) liveCounts();
    // Monthly mobile data limit reached during a scan: a snackbar on any screen (the scan screen shows
    // the full banner from the "paused" reason).
    if (ev.type === "mobile_cap" && cs.running && F.snack && F.t)
      F.snack(
        F.t(
          "scan.reason_mobile_cap_text",
          { used: ev.used_mb, limit: ev.limit_mb },
          "Лимит мобильного трафика достигнут: {used} из {limit} МБ в этом месяце. Продолжите в Wi-Fi или увеличьте лимит",
        ),
        { ms: 10000, label: tr("api.mobile_cap_settings", "Лимит"), action: () => F.go("/settings/power") },
      );
    if (ev.type !== "db") F.emit("scan", ev);
  }
  // Native "net" event (src-tauri: network/power monitor + pause policy): { online, transport, vpn, metered,
  // battery, charging, thermal, paused, user_paused, action: { type: "pause"|"resume"|"stop", reason } | null
  // }.
  // The core has already applied the pause; here we only show the "No network" banner ("net" bus event) and
  // update the scan mini bar.
  function onNativeNet(p) {
    if (!p) return;
    F.device = p;
    if (F.setOffline) F.setOffline(!p.online);
    const action = p.action,
      scan = F.scan;
    if (!action || !scan || !scan.running) return;
    if (action.type === "pause" && action.reason !== "offline") {
      if (!scan.paused) scan.pausedAt = Date.now();
      scan.paused = true;
      scan.pauseReason = action.reason;
    } else if (action.type === "resume" && scan.paused && scan.pauseReason !== "user") {
      if (scan.pausedAt) scan.pausedMs = (scan.pausedMs || 0) + Date.now() - scan.pausedAt;
      Object.assign(scan, { paused: false, pauseReason: null, pausedAt: null });
    } else return;
    F.emit("db", { kind: "net" });
    if (F.actions && F.actions["scan-changed"]) F.actions["scan-changed"]();
  }
  // Under Tauri any network change (native, or window online/offline in the WebView) is passed to the core as
  // an "offline" hint.
  if (TAURI && F.setOffline) {
    const so = F.setOffline;
    F.setOffline = on => {
      const prev = netHint;
      netHint = "offline";
      try {
        so(on);
      } finally {
        netHint = prev;
      }
    };
  }
  // Backend notices ({kind, text, project, scan_id}, e.g. a scan interrupted by the system): shown as a
  // snackbar; ones that arrive before the UI has booted wait in a queue (F.flushNotices from F.boot).
  const noticeQ = [];
  F.notice = p => {
    if (!p || !p.text) return;
    F.emit("notice", p);
    if (!(F.cur && F.snack)) return void noticeQ.push(p);
    const scanP = p.kind === "interrupted" && p.project;
    F.snack(F.coreMsg ? F.coreMsg(p.text, p.text_msg) : String(p.text), {
      ms: 8000,
      ...(scanP
        ? {
            label: tr("api.scan", "К скану"),
            action: () =>
              (F.api.project_open ? F.api.project_open(p.project) : Promise.resolve()).then(() =>
                F.go("/p/scan"),
              ),
          }
        : {}),
    });
  };
  F.flushNotices = () => noticeQ.splice(0).forEach(p => setTimeout(() => F.notice(p), 600));
  if (TAURI && window.__TAURI__.event && window.__TAURI__.event.listen) {
    window.__TAURI__.event.listen("scan://event", e => onScanEvent(e.payload));
    window.__TAURI__.event.listen("net", e => onNativeNet(e.payload));
    window.__TAURI__.event.listen("shared", () => F.emit("shared", {}));
    window.__TAURI__.event.listen("notice", e => F.notice(e.payload));
  } else if (demoBackend) demoBackend.listen(onScanEvent);
  // Project switch / scan stage result / reset: re-render the current screen (after screens have refreshed
  // their caches).
  F.on(
    "db",
    d => {
      if (!F.cur || !F.render) return;
      // A scan result arrives often while the user browses: throttled and deferred while touching.
      if (d.kind === "scan" && F.liveRender) F.liveRender("db", d);
      else if (d.kind === "project" || d.kind === "scan" || d.kind === "reset") F.render(true);
    },
    { late: true },
  );

  // ================= first load =================
  // Project restored on start: the last opened one, else the first; never a reference case (it stays out
  // of recent projects, and an old last_project may still point to one).
  function startProject(st) {
    const own = F.projects.filter(p => !p.reference);
    const last = st && st.last_project;
    return own.some(p => p.id === last) ? last : (own[0] || {}).id;
  }
  function boot() {
    if (!TAURI) {
      // Demo: synchronous, so screens already see data when they are loaded.
      try {
        const st = demoBackend.invokeSync("settings_get");
        if (F.i18n) {
          const b = demoBackend.invokeSync("i18n_bundle", {
            lang: st.lang || (st.ui && st.ui.look && st.ui.look.lang) || "auto",
            device_locale: F.i18n.detectDeviceLocale(),
            include_help: false,
          });
          F.i18n.applyBundle(b, { silent: true });
        }
        setProjects(demoBackend.invokeSync("project_list"));
        const id = startProject(st);
        if (id) applySnapshot(demoBackend.invokeSync("project_open", { id }), "init");
      } catch (e) {
        return Promise.reject(e);
      }
      return Promise.resolve();
    }
    const saved = run("settings_get", {});
    return saved
      .then(st => {
        F.db.settings = st || {};
        settingsView(F.db.settings);
        if (!F.i18n) return st;
        const setting = st && (st.lang || (st.ui && st.ui.look && st.ui.look.lang) || "auto");
        const devP =
          F.api && F.api.platform_device_info
            ? F.api
                .platform_device_info()
                .then(di => {
                  if (di && di.locale) F.state.deviceLocale = di.locale;
                  return (di && di.locale) || F.i18n.detectDeviceLocale();
                })
                .catch(() => F.i18n.detectDeviceLocale())
            : Promise.resolve(F.i18n.detectDeviceLocale());
        return devP
          .then(loc => F.i18n.load(setting, { deviceLocale: loc, silent: true }).catch(() => null))
          .then(() => st);
      })
      .then(st =>
        refreshList().then(() => {
          const id = startProject(st);
          return id ? run("project_open", { id }, snap => applySnapshot(snap, "init")) : null;
        }),
      );
  }
  // The demo backend evaluates scope rules and risk with FOCA_RULES (ui/js/sel.js loads after api.js), so the
  // first load is started by sel.js (F._bootDemo), synchronously and before screens are loaded.
  const fail = e => {
    console.error("Не удалось загрузить данные", e);
  };
  // "Scan running" only when the core confirms it. After a UI restart (Android unloaded the WebView/process,
  // auto-resume) the started/source events fired before we subscribed, so the state comes from scan_status;
  // if the core restarted without a scan (kill -9), the UI must not keep showing a stale "running" state.
  let syncBusy = false;
  function syncCore() {
    if (!TAURI || syncBusy) return Promise.resolve();
    syncBusy = true;
    return run("scan_status", {})
      .then(
        st => {
          const cs = F.coreScan,
            was = cs.running;
          st = st || { running: false };
          if (st.running)
            Object.assign(cs, {
              running: true,
              project: st.project,
              scan_id: st.scan_id,
              profile: st.profile,
              active: st.active,
              egress: st.egress,
              progress: st.progress || 0,
            });
          else if (was) cs.running = false;
          F.emit("scan", { type: "sync", status: st });
          if (st.running && !was) liveCounts();
          else if (!st.running && was) {
            if (st.project === cur() || cs.project === cur()) reload("scan");
            refreshList();
          }
        },
        () => {},
      )
      .then(() => {
        syncBusy = false;
      });
  }
  F.syncCore = syncCore;
  if (TAURI) {
    setInterval(() => {
      if (F.coreScan.running || (F.scan && F.scan.running)) syncCore();
    }, 4000);
    document.addEventListener("visibilitychange", () => {
      if (document.visibilityState === "visible") syncCore();
    });
  }
  if (TAURI || window.FOCA_RULES)
    F.dbReady = boot()
      .then(() => {
        syncCore();
      })
      .catch(fail);
  else
    F.dbReady = new Promise(res => {
      F._bootDemo = () => res(boot().catch(fail));
    });

  // ================= aliases for screens (legacy names) =================
  Object.defineProperty(F, "project", {
    configurable: true,
    get() {
      const p = F.db.project;
      if (!p) return null;
      const last = F.db.scans[F.db.scans.length - 1];
      return {
        id: p.id,
        name: p.name,
        client: p.client,
        lastScan: last ? last.date : "-",
        risk: F.sel ? F.sel.risk().score : null,
        lastProfile: last ? last.profile : null,
      };
    },
    set(v) {
      if (v && v.id && v.id !== cur()) F.api.project_open(v.id);
    },
  });
  Object.defineProperty(F, "demoFindings", { configurable: true, get: () => F.db.findings, set() {} });
  Object.defineProperty(F, "demoProjects", { configurable: true, get: () => F.projects, set() {} });
  Object.defineProperty(F, "scanHistory", { configurable: true, get: () => F.db.scans });
  // window.DEMO: the legacy demo data shape, now backed by F.db of the current project.
  const DEMO = {};
  const def = (k, fn) => Object.defineProperty(DEMO, k, { enumerable: true, get: fn });
  def("users", () => F.db.people.filter(p => p.src_kind === "meta"));
  def("software", () => F.db.software);
  def("domains", () => F.db.hosts.filter(h => !h.internal).map(h => h.name));
  def("folders", () => F.db.paths.map(p => p.path));
  def("printers", () => F.db.printers);
  def("docs", () => F.db.docs);
  def("hosts", () => F.db.hosts);
  def("vulns", () =>
    F.db.findings.slice(0, 10).map(f => ({ t: f.title, host: f.host, sev: f.sev, src: f.source })),
  );
  def("emails", () => F.db.emails.filter(e => e.found).map(e => [e.addr, e.src]));
  def("gps", () => F.db.gps);
  window.DEMO = DEMO;
})();
