/*
 * Scan screen.
 * The scan runs in the core (F.api.scan_start / scan_pause / scan_resume / scan_stop); the screen only
 * listens
 * to F.on("scan") events and renders them: stages, sources (key status from settings), the live feed
 * (findings
 * from F.db.findings), active mode, out-of-scope candidates (F.db.oos), stop reasons (texts from
 * F.db.settings) and history (F.db.scans).
 * The global F.scan state feeds the mini bar, Overview and the project list (core.js re-renders them via the
 * live flag).
 */
(function () {
  const F = window.FOCA,
    { ic, esc, ui } = F;
  const demoBackend = window.FOCA_DEMO_BACKEND;

  F.addIcons && F.addIcons('<symbol id="i-scn-skip" viewBox="0 0 16 16"><path d="M4 8h8"/></symbol>');

  // ---------- utilities ----------
  const fmtT = s => {
    s = Math.max(0, Math.floor(s));
    const h = Math.floor(s / 3600),
      m = Math.floor((s % 3600) / 60),
      x = s % 60;
    return (h ? h + ":" + String(m).padStart(2, "0") : m) + ":" + String(x).padStart(2, "0");
  };
  const fmtLeft = s =>
    s < 60 ? F.t("scan.lt_1min", "< 1 мин") : F.t("scan.approx_min", { n: Math.round(s / 60) }, "≈ {n} мин");
  const fmtMin = m =>
    m >= 60
      ? F.t("scan.h_min", { h: Math.floor(m / 60), m: m % 60 }, "{h} ч {m} мин")
      : F.t("scan.min", { m }, "{m} мин");
  const num = n => Math.round(n).toLocaleString(F.i18n.lang() || "ru");
  const clock = d => {
    d = new Date(d);
    return String(d.getHours()).padStart(2, "0") + ":" + String(d.getMinutes()).padStart(2, "0");
  };
  const plural = (n, a, b, c) => {
    const m10 = n % 10,
      m100 = n % 100;
    if (F.i18n.lang() === "en") return n === 1 ? a : b;
    return m10 === 1 && m100 !== 11 ? a : m10 >= 2 && m10 <= 4 && (m100 < 10 || m100 >= 20) ? b : c;
  };
  // Plural form only (no number) with forms from the dictionary: "one|few|many" (EN: "one|other|other").
  const pw = (n, key, forms) => plural(n, ...F.t(key, forms).split("|"));
  // Localized table field: a getter reads F.t(key, original), so tables keep the Russian fallbacks.
  const lzField = (obj, field, key) => {
    const ru = obj[field];
    Object.defineProperty(obj, field, { get: () => F.t(key, ru), enumerable: true, configurable: true });
  };
  const nf = n => `${n}\u00a0${pw(n, "scan.pl_finding", "находка|находки|находок")}`;
  const ofFiles = n =>
    n % 10 === 1 && n % 100 !== 11 ? F.t("scan.of_file_one", "файла") : F.t("scan.of_file_many", "файлов"); // Genitive plural of "file" after an "x/N" counter.
  const setHTML = (el, h) => {
    if (el && el._h !== h) {
      el._h = h;
      el.innerHTML = h;
    }
  };
  const settings = () => F.db.settings || {};
  const curId = () => F.db.project && F.db.project.id;

  // ---------- pipeline (stage labels also arrive in core events) ----------
  const STAGES = [
    { id: "search", label: "Поиск", icon: "search" },
    { id: "download", label: "Загрузка", icon: "download" },
    { id: "meta", label: "Извлечение метаданных", icon: "doc" },
    { id: "analysis", label: "Анализ", icon: "bug" },
    { id: "network", label: "Сеть и DNS", icon: "net" },
    { id: "ports", label: "Порты", icon: "server" },
    { id: "recon", label: "Разведка сайта", icon: "globe" },
    { id: "fuzz", label: "Поиск на сайте", icon: "search" },
    { id: "report", label: "Отчёт", icon: "report" },
  ];
  const SRC_IC = {
    wayback: "history",
    cc: "db",
    crt: "lock",
    crawler: "globe",
    brave: "search",
    searx: "search",
    startpage: "search",
    brave_web: "search",
    dns: "net",
    shodan: "server",
    crtname: "lock",
    scanmalware: "bug",
    certspotter: "lock",
    anubis: "domain",
    hackertarget: "domain",
    rapiddns: "domain",
    subcenter: "domain",
    thc: "domain",
    shodanct: "lock",
    otx_dns: "domain",
    arquivo: "history",
    otx_url: "link",
    urlscan: "link",
    hudson: "bug",
    ddg: "search",
    bing: "search",
    mojeek: "search",
    yahoo: "search",
    searx_pool: "search",
    internetdb: "server",
    fuzz: "folder",
    ports: "server",
    subdomains: "domain",
    tls: "lock",
    recon: "globe",
    webaudit: "shield",
    wellknown: "path",
    buckets: "db",
    grepapp: "hash",
  };
  // Subdomain sources (n counts names, not documents) and dork engines (may hit a captcha).
  const HOST_SRC = [
    "crt",
    "crtname",
    "scanmalware",
    "certspotter",
    "anubis",
    "hackertarget",
    "rapiddns",
    "subcenter",
    "thc",
    "shodanct",
    "otx_dns",
  ];
  const DORK_SRC = ["ddg", "bing", "mojeek", "startpage", "brave_web", "yahoo", "searx_pool"];
  // Opened in the embedded browser (a hidden WebView on Android; Mojeek only if the browser is available).
  const WEB_SRC = ["startpage", "brave_web", "yahoo", "searx_pool"];
  const SEV_IC = {
    crit: ["alert", "var(--crit)"],
    high: ["alert", "var(--bad)"],
    warn: ["info", "var(--warn)"],
    low: ["info", "var(--accent)"],
    info: ["info", "var(--text-3)"],
  };
  STAGES.forEach(s => lzField(s, "label", "scan.stage_" + s.id));
  const OOS_KIND = {
    cname: ["CNAME", "domain"],
    redirect: ["Редирект", "link"],
    link: ["Ссылка", "link"],
    ip: ["IP вне сетей скоупа", "server"],
    cdn: ["CDN", "globe"],
    net: ["Сеть вне скоупа", "net"],
  };
  ["redirect", "link", "ip", "net"].forEach(k => lzField(OOS_KIND[k], 0, "scan.oos_" + k));

  // ---------- stop and pause reasons: texts come from settings ----------
  function reasonOf(k) {
    const net = settings().net || {},
      pw = settings().power || {};
    const killStop = net.kill_action !== "pause";
    const errDoc = (F.db.docs || []).find(d => d.status_code === "downloaded");
    const texts = {
      android: {
        chip: "Android",
        icon: "app",
        color: "var(--warn)",
        title: F.t("scan.reason_android_title", "Android закрыл приложение в фоне"),
        text: F.t(
          "scan.reason_android_text",
          "Система выгрузила FOCA-rs из памяти, пока приложение было свёрнуто. Скан работает через постоянное уведомление; чтобы длинные сканы не прерывались, разрешите работу в фоне без ограничений батареи.",
        ),
      },
      battery: {
        chip: F.t("scan.reason_battery_chip", "Заряд"),
        icon: "battery",
        color: "var(--warn)",
        title: F.t("scan.reason_battery_title", "Низкий заряд батареи"),
        text:
          F.t(
            "scan.reason_battery_text",
            { n: pw.batt ?? "-" },
            "Заряд опустился ниже порога {n} % из настроек.",
          ) +
          " " +
          (pw.batt_action === "pause"
            ? F.t(
                "scan.reason_battery_pause",
                "Скан поставлен на паузу и продолжится, когда телефон поставят на зарядку.",
              )
            : F.t(
                "scan.reason_battery_stop",
                "Скан остановлен, чтобы телефон не разрядился. Подключите зарядку и продолжите.",
              )),
        pause: pw.batt_action === "pause",
        label: F.t("scan.reason_battery_label", "Пауза: низкий заряд"),
      },
      // Overheating (core policy on Android thermal status with "Pause when overheating"), separate from
      // charging.
      thermal: {
        chip: F.t("scan.reason_thermal_chip", "Перегрев"),
        icon: "alert",
        color: "var(--warn)",
        title: F.t("scan.reason_thermal_title", "Телефон перегрелся"),
        text: F.t(
          "scan.reason_thermal_text",
          "Android сообщил о сильном нагреве, а в настройках питания включена пауза при перегреве. Скан продолжится сам, когда телефон остынет; собранное сохранено.",
        ),
        pause: true,
        label: F.t("scan.reason_thermal_label", "Пауза: перегрев"),
      },
      wifi: {
        chip: F.t("scan.reason_wifi_title", "Нет Wi-Fi"),
        icon: "wifi-off",
        color: "var(--warn)",
        title: F.t("scan.reason_wifi_title", "Нет Wi-Fi"),
        text: F.t(
          "scan.reason_wifi_text",
          "В настройках включено «только Wi-Fi», а телефон перешёл на мобильные данные. Скан на паузе, чтобы не расходовать мобильный трафик: он продолжится в сети Wi-Fi.",
        ),
        pause: true,
        label: F.t("scan.reason_wifi_label", "Пауза: нет Wi-Fi"),
      },
      offline: {
        chip: F.t("scan.reason_offline_title", "Нет сети"),
        icon: "wifi-off",
        color: "var(--warn)",
        title: F.t("scan.reason_offline_title", "Нет сети"),
        text: F.t(
          "scan.reason_offline_text",
          "Соединение пропало. Скан на паузе и продолжится сам, когда сеть вернётся.",
        ),
        pause: true,
        label: F.t("scan.reason_offline_label", "Пауза: нет сети"),
      },
      vpn: {
        chip: F.t("scan.reason_vpn_chip", "Обрыв VPN"),
        icon: "shield",
        color: "var(--crit)",
        title: F.t("scan.reason_vpn_title", "Обрыв туннеля: сработала защита от утечки IP"),
        text: F.t(
          "scan.reason_vpn_text",
          {
            tunnel: (net.label || F.t("scan.proxy", "прокси")) + (net.addr ? " (" + net.addr + ")" : ""),
            action: killStop
              ? F.t("scan.ks_stopped", "Защита от утечки IP остановила скан")
              : F.t("scan.ks_paused", "Защита от утечки IP поставила скан на паузу"),
          },
          "Туннель {tunnel} перестал отвечать. {action}, чтобы запросы не ушли к цели с вашего реального IP. Продолжить можно после восстановления туннеля.",
        ),
        pause: !killStop,
        label: F.t("scan.reason_vpn_label", "Пауза: обрыв туннеля"),
      },
      user: {
        chip: F.t("scan.reason_user_chip", "Вручную"),
        icon: "stop",
        color: "var(--text-2)",
        title: F.t("scan.reason_user_title", "Вы остановили скан"),
        text: F.t(
          "scan.reason_user_text",
          "Скан остановлен вручную. Всё собранное сохранено в проекте. Можно продолжить с того же места.",
        ),
      },
      restart: {
        chip: F.t("scan.reason_restart_chip", "Прерван системой"),
        icon: "refresh",
        color: "var(--warn)",
        title: F.t("scan.reason_restart_title", "Скан прерван системой"),
        text: F.t(
          "scan.reason_restart_text",
          "Приложение выгрузили или оно перезапустилось во время скана. Всё, что успели найти и скачать, сохранено в проекте. Продолжите с места остановки.",
        ),
      },
      budget: {
        chip: F.t("scan.reason_budget_chip", "Лимит фона"),
        icon: "clock",
        color: "var(--warn)",
        title: F.t("scan.reason_budget_title", "Лимит времени фона: контрольная точка сохранена"),
        text: F.t(
          "scan.reason_budget_text",
          "Автономный фоновый скан уложился в 8-минутный лимит WorkManager и сохранил контрольную точку. Нажмите «Продолжить с места остановки», чтобы завершить оставшиеся этапы.",
        ),
      },
      workmanager: {
        chip: F.t("scan.reason_wm_chip", "Планировщик"),
        icon: "pause",
        color: "var(--warn)",
        title: F.t("scan.reason_wm_title", "Остановлен планировщиком Android: можно продолжить"),
        text: F.t(
          "scan.reason_wm_text",
          "Система остановила фоновую задачу WorkManager (ограничения сети, заряда или энергосбережения). Собранные данные сохранены: можно продолжить с контрольной точки.",
        ),
      },
      // Error text comes from the core's stopped event (message); the demo shows a sample.
      error: (() => {
        const message = (F.scan && F.scan.stopped && F.scan.stopped.message) || "";
        return F.isDemo && !message
          ? {
              chip: F.t("scan.reason_error_chip", "Ошибка"),
              icon: "alert",
              color: "var(--bad)",
              title: F.t("scan.reason_extract_title", "Ошибка модуля извлечения"),
              text: errDoc
                ? F.t(
                    "scan.reason_extract_text_file",
                    { name: errDoc.name },
                    "Модуль извлечения метаданных аварийно завершился на файле {name}. Остальные данные сохранены.",
                  )
                : F.t(
                    "scan.reason_extract_text",
                    "Модуль извлечения метаданных аварийно завершился. Остальные данные сохранены.",
                  ),
              code: "E-META-017 · zip: invalid central directory",
            }
          : {
              chip: F.t("scan.reason_error_chip", "Ошибка"),
              icon: "alert",
              color: "var(--bad)",
              title: F.t("scan.reason_error_title", "Скан остановлен из-за ошибки"),
              text: F.t(
                "scan.reason_error_text",
                "Этап скана завершился с ошибкой. Всё, что успели собрать, сохранено в проекте. Продолжите с места остановки.",
              ),
              code: message,
            };
      })(),
    };
    return texts[k] || texts.user;
  }
  const REASON_KEYS = ["android", "battery", "wifi", "vpn", "user", "error"];

  // ---------- scan state (filled by core events) ----------
  const blank = () => ({
    running: false,
    paused: false,
    pauseReason: null,
    pauseLabel: "",
    active: false,
    progress: 0,
    stageIdx: -1,
    stageLabel: "",
    summary: "",
    egress: "",
    profile: "",
    profileId: "",
    project: null,
    projectName: "",
    scanId: null,
    startedAt: null,
    pausedAt: null,
    pausedMs: 0,
    sources: [],
    feed: [],
    targets: [],
    stopped: null,
    finished: null,
    substep: null,
    subNotes: {},
    // Crawler counters of the search stage (core `crawl` events and scan_status.crawl).
    crawl: null,
    held: [],
    caps: null,
    followup: [],
    // A narrowed run (follow-up of chosen items): ids of the stages it executes; null for a full scan.
    stages: null,
  });
  F.scan = Object.assign(blank(), F.scan && F.scan.running ? F.scan : {});
  // The core is already scanning (UI restart under Tauri): restore from scan_status / the snapshot.
  function restoreFrom(cs) {
    const idx = cs.stage_index != null ? cs.stage_index : STAGES.findIndex(x => x.id === cs.stage);
    const t0 = cs.started_at ? Date.parse(cs.started_at) : NaN; // Local time without a zone → device time.
    const project = (F.projects || []).find(x => x.id === cs.project);
    Object.assign(F.scan, blank(), {
      running: true,
      paused: !!cs.paused,
      pauseReason: cs.paused ? cs.pause_reason || "user" : null,
      pausedAt: cs.paused ? Date.now() : null,
      active: !!cs.active,
      progress: cs.progress || 0,
      stageIdx: idx,
      profile: cs.profile || "",
      profileId: cs.profile_id || "",
      targets: cs.targets || [],
      modules: cs.modules || [],
      resumed: !!cs.resumed,
      egress: cs.egress || "",
      scanId: cs.scan_id,
      project: cs.project || curId(),
      projectName: project ? project.name : (F.db.project || {}).name || "",
      startedAt: isNaN(t0) ? Date.now() : Math.min(Date.now(), t0),
      sources: (cs.sources || []).map(x => ({ id: x.id, name: x.name, status: x.status })),
      substep: cs.substep || null,
      crawl: cs.crawl || null,
      held: cs.held || [],
      caps: cs.controls || null,
      followup: cs.followup || [],
      stages: cs.stages || null,
    });
  }
  if (F.db.scan && F.db.scan.running && !F.scan.running) restoreFrom(F.db.scan);
  const autoNoted = new Set();
  const elapsed = () => {
    const s = F.scan;
    if (!s.startedAt) return 0;
    const end = s.running ? (s.paused && s.pausedAt ? s.pausedAt : Date.now()) : s.endedAt || Date.now();
    return (end - s.startedAt - s.pausedMs) / 1000;
  };
  const sameProject = () => F.scan.project && F.scan.project === curId();
  const scanRec = id => (F.db.scans || []).find(x => x.id === id);
  const PROFILE_ID = { Пассивный: "passive", Стандартный: "std", Полный: "full", Свой: "custom" };
  // Stage and profile names: the core sends Russian labels; other UI languages use the dictionary.
  const stageName = (i, s = F.scan) =>
    (F.i18n.lang() === "ru" && s.stageNames && s.stageNames[i]) || STAGES[i].label;
  const profName = (s = F.scan) =>
    F.i18n.lang() === "ru" || !s.profileId ? s.profile : F.t("launch.profile_" + s.profileId, s.profile);

  // A narrowed run: stage k is outside the chosen items (`list`: stage ids the run executes).
  const notSelected = (k, list = F.scan.stages) =>
    Array.isArray(list) && list.length > 0 && !list.includes(STAGES[k].id);
  // Position of stage k among the stages the run executes, and their count.
  const stageSlot = (k, list = F.scan.stages) => {
    if (!Array.isArray(list) || !list.length) return { i: k, n: STAGES.length };
    return { i: STAGES.slice(0, k).filter(x => list.includes(x.id)).length, n: list.length };
  };
  function derive() {
    const s = F.scan;
    const i = s.stageIdx;
    const slot = stageSlot(i, s.stages);
    s.stageLabel =
      s.running && i >= 0
        ? F.t("scan.stage_of", { i: slot.i + 1, n: slot.n, name: stageName(i, s) }, "Этап {i} из {n}: {name}")
        : F.t("scan.scan", "Скан");
    s.pauseLabel = s.paused ? reasonOf(s.pauseReason).label || F.t("scan.paused_title", "Скан на паузе") : "";
    if (sameProject()) {
      const N = F.sel.counts();
      s.summary = `${s.progress}% · ${num(N.docs.downloaded)}/${num(N.docs.total)} ${ofFiles(N.docs.total)} · ${nf(s.feed.length)}`;
    } else s.summary = `${s.progress}% · ${s.projectName || ""}`;
  }

  // ---------- core events ----------
  function onScanEvent(ev) {
    if (!ev || ev.local) return;
    const scan = F.scan;
    switch (ev.type) {
      case "started": {
        const pend = F.state.scanPending || {};
        F.state.scanPending = null;
        const project = (F.projects || []).find(x => x.id === ev.project);
        Object.assign(scan, blank(), {
          running: true,
          active: !!ev.active,
          profile: ev.profile,
          profileId: PROFILE_ID[ev.profile] || "",
          egress: ev.egress || "",
          scanId: ev.scan_id,
          project: ev.project,
          projectName: project ? project.name : (F.db.project || {}).name || "",
          startedAt: Date.now(),
          stageIdx: 0,
          targets: ev.targets || pend.targets || ((F.db.scope || {}).targets || []).map(t => t.v),
          modules: pend.modules || [],
          resumed: !!(ev.resumed || pend.resume_from),
          stages: ev.stages || null,
        });
        // Per-item control capabilities come with the core status.
        F.api.scan_status().then(
          st => {
            if (st && st.running && st.scan_id === scan.scanId && st.controls) {
              scan.caps = st.controls;
              refresh();
            }
          },
          () => {},
        );
        break;
      }
      case "source": {
        const existing = scan.sources.find(y => y.id === ev.id),
          entry = {
            id: ev.id,
            name: ev.name,
            status: ev.status,
            n: ev.n,
            error: ev.error_msg ? F.coreMsg(ev.error, ev.error_msg) : ev.error,
            // core text + message code, re-rendered when the UI language changes
            msgs: { error: [ev.error, ev.error_msg], detail: [ev.detail, ev.detail_msg] },
          };
        // Site file search (fuzz): fuzzing counters and stop reason.
        if (ev.id === "fuzz")
          [
            "checked",
            "found",
            "filtered",
            "planned",
            "requests",
            "host",
            "hosts",
            "host_index",
            "detail",
            "documents",
          ].forEach(k => {
            if (ev[k] != null) entry[k] = ev[k];
          });
        if (ev.detail_msg) entry.detail = F.coreMsg(ev.detail, ev.detail_msg);
        // Source deadline comes from the core (timeout_s/deadline_ms in running); a retry does not reset it.
        ["domain", "round", "rounds"].forEach(k => {
          if (ev[k] != null) entry[k] = ev[k];
        });
        if (ev.status === "running" && ev.retry != null && existing && existing.status === "running") {
          entry.retry = ev.retry;
          entry.retryReason = ev.retry_reason || "";
        } else if (ev.status === "running")
          Object.assign(entry, {
            startedAt: Date.now(),
            timeoutS: ev.timeout_s != null ? +ev.timeout_s : null,
            deadlineMs: ev.deadline_ms != null ? +ev.deadline_ms : null,
            retry: 0,
            retryReason: "",
          });
        if (ev.status !== "running") entry.skipping = false;
        // Search engine captcha in the browser: URL for manual verification ("Pass the check" button).
        entry.verifyUrl = ev.status === "blocked" && ev.verify_url ? ev.verify_url : null;
        if (ev.status === "running") Object.assign(entry, { retryAsked: false, verifyDone: false });
        if (existing) Object.assign(existing, entry);
        else scan.sources.push(entry);
        break;
      }
      // State from the core (api.js syncCore: after a UI restart and every 4 s while running).
      case "sync": {
        const st = ev.status || {};
        if (st.running) {
          const same = scan.running && scan.scanId === st.scan_id;
          if (same && st.controls)
            Object.assign(scan, { held: st.held || [], caps: st.controls, followup: st.followup || [] });
          if (same && st.crawl && JSON.stringify(st.crawl) !== JSON.stringify(scan.crawl))
            scan.crawl = st.crawl;
          if (!same) restoreFrom(st);
          else if (JSON.stringify(scan.substep) !== JSON.stringify(st.substep ? subOf(st.substep) : null))
            scan.substep = st.substep ? subOf(st.substep) : null;
          else if (!scan.sources.length && (st.sources || []).length)
            scan.sources = st.sources.map(x => ({ id: x.id, name: x.name, status: x.status }));
          else if (scan.progress >= (st.progress || 0) && !(st.auto && !autoNoted.has(st.scan_id))) return;
          else scan.progress = Math.max(scan.progress, st.progress || 0);
          if (st.auto && !autoNoted.has(st.scan_id)) {
            autoNoted.add(st.scan_id);
            F.snack(F.t("scan.snack_auto_resume", "Скан был прерван системой. Продолжаю с места остановки"), {
              ms: 6000,
            });
          }
        } else if (scan.running) {
          // The core is not running the scan (process unloaded, stopped/restart record): show "interrupted",
          // not "running".
          Object.assign(scan, { running: false, paused: false, endedAt: Date.now() });
          scan.stopped = {
            scanId: scan.scanId,
            project: scan.project,
            reason: "restart",
            message: "",
            progress: scan.progress,
            stageIdx: scan.stageIdx,
          };
        } else return;
        break;
      }
      case "stage":
        scan.stageIdx = ev.index;
        scan.stageNames = scan.stageNames || [];
        scan.stageNames[ev.index] = ev.label;
        break;
      // Per-item control applied by the core (scan_control): hold, skip, restart or queued restart.
      case "control": {
        const key = `${ev.kind}:${ev.id}`;
        scan.held = (scan.held || []).filter(x => x !== key);
        if (ev.state === "paused") scan.held.push(key);
        if (ev.state === "queued" && !(scan.followup || []).includes(key))
          scan.followup = [...(scan.followup || []), key];
        break;
      }
      // Sub-step of a long stage (network: brute force 640/1500, permutations, takeover checks...).
      case "substep":
        if (ev.state === "running" && ev.slow && !(scan.substep && scan.substep.slow) && !scan.slowNoted) {
          scan.slowNoted = true;
          F.snack(slowText(subOf(ev)), { ms: 6000 });
        }
        if (ev.state === "running") scan.substep = subOf(ev);
        else if (!scan.substep || scan.substep.id === ev.id) scan.substep = null;
        // A finished or skipped sub-step with a reason (URL target: subdomains out of scope; download queue
        // summary) keeps it on the stage row.
        if (ev.state !== "running" && ev.reason)
          scan.subNotes = {
            ...(scan.subNotes || {}),
            [ev.id]: { stage: ev.stage, reason: ev.reason, msg: ev.reason_msg || null },
          };
        break;
      // Crawler counters: pages, frontier, documents, storage files, rendered pages and rate state.
      case "crawl": {
        const x = { ...ev };
        delete x.type;
        delete x.scan_id;
        scan.crawl = x;
        break;
      }
      case "progress":
        scan.progress = ev.progress;
        if (ev.total != null) scan.stageN = { stage: ev.stage, done: ev.done, total: ev.total };
        break;
      // Pause/resume from the core (Android environment policy, overheating, "Pause" in the notification).
      case "paused":
        if (!scan.running) return;
        if (!scan.paused) scan.pausedAt = Date.now();
        scan.paused = true;
        scan.pauseReason = ev.reason || scan.pauseReason || "user";
        F.emit("db", { kind: "net" });
        break;
      case "resumed":
        if (!scan.running) return;
        if (scan.paused && scan.pausedAt) scan.pausedMs = (scan.pausedMs || 0) + Date.now() - scan.pausedAt;
        Object.assign(scan, { paused: false, pauseReason: null, pausedAt: null });
        F.emit("db", { kind: "net" });
        break;
      case "finding":
        if (!scan.feed.some(f => f.id === ev.finding.id))
          scan.feed.unshift({
            id: ev.finding.id,
            title: ev.finding.title,
            rule: ev.finding.rule || "",
            sev: ev.finding.sev,
            host: ev.finding.host,
            at: elapsed(),
          });
        break;
      case "done":
        scan.running = false;
        scan.paused = false;
        scan.progress = 100;
        scan.endedAt = Date.now();
        scan.finished = {
          scanId: ev.scan_id,
          project: ev.project,
          followup: ev.followup || scan.followup || [],
          newFindings: ev.scan ? ev.scan.new_findings : scan.feed.length,
        };
        F.snack(
          F.t(
            "scan.snack_done",
            {
              what: scan.finished.newFindings
                ? F.t("scan.snack_done_new", { n: scan.finished.newFindings }, "новых: {n}")
                : F.t("scan.snack_done_none", "новых находок нет"),
            },
            "Скан завершён · {what}",
          ),
          { action: () => F.go("/p/findings"), label: F.t("scan.findings", "Находки"), ms: 6000 },
        );
        break;
      case "stopped":
        scan.running = false;
        scan.paused = false;
        scan.endedAt = Date.now();
        if (ev.reason === "deleted") {
          // scan_delete cancelled the running scan: nothing to resume, the deleting screen refreshes itself
          scan.stopped = null;
          break;
        }
        scan.stopped = {
          scanId: ev.scan_id,
          project: ev.project,
          reason: ev.reason,
          message: ev.message || "",
          progress: scan.progress,
          stageIdx: scan.stageIdx,
        };
        if (ev.reason !== "user") {
          // Automatic stop (kill switch, battery…), shown like the Android notification.
          if (onScan()) F.go("/p/scan-stopped/" + ev.reason, { replace: true });
          else
            F.snack(F.t("scan.snack_stopped", { why: reasonOf(ev.reason).chip }, "Скан остановлен: {why}"), {
              action: () => F.go("/p/scan-stopped/" + ev.reason),
              label: F.t("common.details", "Подробнее"),
              ms: 8000,
            });
        }
        break;
      default:
        return;
    }
    derive();
    stopClockIfIdle();
    F.updateChrome();
  }
  F.on("scan", onScanEvent);
  F.on("i18n", () =>
    (F.scan.sources || []).forEach(x =>
      Object.entries(x.msgs || {}).forEach(([k, [text, msg]]) => {
        if (msg) x[k] = F.coreMsg(text, msg);
      }),
    ),
  );
  // Project data changed (scan stage, project switch): recompute mini bar labels.
  F.on("db", () => {
    derive();
    F.updateChrome();
  });
  derive();

  // ---------- Overview and the project list re-render on events (live mechanism in core.js) ----------
  const LIVE_EV = ["started", "stage", "progress", "done", "stopped", "paused", "resumed"];
  const ov = F.routes.find(r => r.pattern === "/p/overview");
  // Plus "db": during downloads api.js re-reads the snapshot on progress, so file counters grow live.
  if (ov && ov.live == null)
    ov.live = (kind, ev) =>
      (kind === "db" && ev.kind === "scan") || (kind === "scan" && LIVE_EV.includes(ev.type));

  // ---------- scan screen clock (display only) ----------
  let clockT = null;
  const onScan = () => F.cur && F.cur.path === "/p/scan";
  function startClock() {
    if (!clockT)
      clockT = setInterval(() => {
        if (!onScan() || !F.scan.running) return stopClockIfIdle();
        refresh();
      }, 1000);
  }
  function stopClockIfIdle() {
    if (clockT && (!F.scan.running || !onScan())) {
      clearInterval(clockT);
      clockT = null;
    }
  }

  // In-place scan screen update without a re-render (scroll position stays put).
  // A background WebView freezes JS timers, so remaining times are recomputed from the clock on return.
  document.addEventListener("visibilitychange", () => {
    if (!document.hidden && onScan()) refresh();
  });
  function refresh() {
    F.updateChrome();
    if (!onScan()) return;
    if (F.refreshBar) F.refreshBar();
    const page = F.page();
    if (!page) return;
    const isRun = !!page.querySelector("#scn-run");
    if (isRun !== !!F.scan.running) {
      F.render(true);
      return;
    }
    if (!isRun) return;
    keepScroll(page, () => patch(page));
  }
  function keepScroll(page, fn) {
    const top = page.getBoundingClientRect().top;
    let anchor = null,
      off = 0;
    if (page.scrollTop > 0)
      for (const el of page.querySelectorAll("[data-anc]")) {
        const rect = el.getBoundingClientRect();
        if (rect.bottom > top + 1) {
          anchor = el;
          off = rect.top;
          break;
        }
      }
    fn();
    if (anchor && anchor.isConnected) {
      const delta = anchor.getBoundingClientRect().top - off;
      if (Math.abs(delta) > 0.5) page.scrollTop += delta;
    }
  }

  // ---------- stages: numbers come from project data ----------
  const stageStatus = k => {
    const s = F.scan;
    if (notSelected(k)) return "sel";
    if (!s.running) return s.finished ? "done" : "wait";
    return k < s.stageIdx ? "done" : k === s.stageIdx ? "run" : "wait";
  };
  const stageP = k => {
    const slot = stageSlot(k);
    const w = 100 / slot.n;
    return Math.max(0, Math.min(1, (F.scan.progress - slot.i * w) / w));
  };
  function stageCounters(id) {
    if (!sameProject()) return [];
    const counts = F.sel.counts(),
      scan = F.scan;
    switch (id) {
      case "search": {
        // a narrowed run counts only the sources it queries
        const pool = scan.stages ? scan.sources.filter(x => x.status !== "off") : scan.sources;
        if (F.isDemo) {
          const live = pool.filter(x => x.status === "ok").length;
          return [F.t("scan.ctr_sources_demo", { live, n: pool.length }, "источники: {live}/{n}")];
        }
        // Polled sources (answered, error, timeout, skipped, no key) out of all, and which source is pending
        // now.
        // External sources run in parallel, so several may be pending.
        const done = pool.filter(x => !["wait", "running"].includes(x.status)).length,
          runs = pool.filter(x => x.status === "running");
        return [
          F.t("scan.ctr_polled", { done, n: pool.length }, "опрошено {done} из {n}"),
          runs.length
            ? F.t("scan.ctr_waiting", { name: runs[0].name }, "ждём: {name}") +
              (runs.length > 1 ? " " + F.t("scan.ctr_and_more", { n: runs.length - 1 }, "и ещё {n}") : "")
            : "",
        ];
      }
      // Stage counter from the progress event (done/total); the core's download queue is not in the snapshot.
      case "download": {
        const stageCounts =
          scan.stageN && scan.stageN.stage === "download" && scan.stageIdx === 1 ? scan.stageN : null;
        return [
          stageCounts
            ? `${num(stageCounts.done)}/${num(stageCounts.total)} ${ofFiles(stageCounts.total)}`
            : `${num(counts.docs.downloaded)}/${num(counts.docs.total)} ${ofFiles(counts.docs.total)}`,
        ];
      }
      case "meta": {
        const stageCounts =
          scan.stageN && scan.stageN.stage === "meta" && scan.stageIdx === 2 ? scan.stageN : null;
        return [
          stageCounts
            ? F.t(
                "scan.ctr_parsed_of",
                { done: num(stageCounts.done), total: num(stageCounts.total) },
                "{done} из {total} разобрано",
              )
            : F.t("scan.ctr_parsed", { n: num(counts.docs.analyzed) }, "{n} разобрано"),
          `${counts.people.meta} ${pw(counts.people.meta, "scan.pl_author", "автор|автора|авторов")}`,
        ];
      }
      case "analysis":
        return [
          nf(counts.findings.total),
          counts.secrets
            ? `${counts.secrets} ${pw(counts.secrets, "scan.pl_secret", "секрет|секрета|секретов")}`
            : "",
        ];
      case "network":
        return [
          `${counts.hosts.total} ${pw(counts.hosts.total, "scan.pl_host", "хост|хоста|хостов")}`,
          scan.active ? "" : F.t("scan.ctr_no_host_requests", "без обращений к хостам"),
        ];
      case "ports": {
        const portsSrc = scan.sources.find(x => x.id === "ports");
        if (!portsSrc || portsSrc.status === "off") return [F.t("scan.not_in_scan", "не входит в этот скан")];
        // the running hosts are shown by the `hosts` sub-step line
        if (portsSrc.status === "running")
          return [portsSrc.n ? F.t("scan.ctr_open", { n: num(portsSrc.n) }, "открыто {n}") : ""];
        return [
          portsSrc.n != null ? F.t("scan.ctr_open_ports", { n: num(portsSrc.n) }, "открыто портов: {n}") : "",
          portsSrc.error || "",
        ];
      }
      case "fuzz": {
        const fuzzSrc = scan.sources.find(x => x.id === "fuzz");
        if (!fuzzSrc || fuzzSrc.status === "off") return [F.t("scan.not_in_scan", "не входит в этот скан")];
        if (fuzzSrc.checked == null)
          return [
            fuzzSrc.status === "skipped" ? F.t("scan.ctr_fuzz_nohosts", "нет адресов для перебора") : "",
          ];
        return [
          F.t("scan.ctr_checked", { n: num(fuzzSrc.checked) }, "проверено {n}"),
          F.t("scan.ctr_found", { n: num(fuzzSrc.found || 0) }, "найдено {n}"),
          fuzzSrc.filtered
            ? F.t("scan.ctr_filtered", { n: num(fuzzSrc.filtered) }, "отфильтровано калибровкой {n}")
            : "",
        ];
      }
      case "report":
        return [F.t("scan.ctr_report", "сводка, граф связей")];
    }
    return [];
  }
  const statusPill = (st, paused) => {
    if (st === "run")
      return paused
        ? `<span class="pill warn">${ic("pause")}${esc(F.t("scan.pill_pause", "Пауза"))}</span>`
        : `<span class="pill info">${ic("spin", "spin")}${esc(F.t("scan.pill_running", "Идёт"))}</span>`;
    return (
      {
        wait: `<span class="pill mute">${ic("clock")}${esc(F.t("scan.pill_wait", "Ждёт"))}</span>`,
        done: `<span class="pill ok">${ic("check")}${esc(F.t("common.done", "Готово"))}</span>`,
        none: `<span class="pill mute">${ic("scn-skip")}${esc(F.t("scan.pill_none", "Не начат"))}</span>`,
        cut: `<span class="pill warn">${ic("stop")}${esc(F.t("scan.pill_cut", "Прерван"))}</span>`,
        sel: `<span class="pill mute">${ic("scn-skip")}${esc(F.t("scan.pill_sel", "Не выбран"))}</span>`,
      }[st] || ""
    );
  };
  // ---------- sub-steps of the running stage ----------
  const subOf = x => ({
    id: x.id,
    stage: x.stage,
    done: x.done || 0,
    total: x.total || 0,
    etaS: x.eta_s != null ? +x.eta_s : null,
    slow: !!x.slow,
    // hosts worked on at once (the `hosts` sub-step of ports, recon and site discovery)
    running: Array.isArray(x.running) ? x.running.map(String) : null,
  });
  const SUB_LABEL = {
    dns: () => F.t("scan.sub_dns", "DNS-записи доменов"),
    resolve: () => F.t("scan.sub_resolve", "Адреса поддоменов"),
    takeover: () => F.t("scan.sub_takeover", "Проверка висячих CNAME"),
    brute: () => F.t("scan.sub_brute", "Перебор поддоменов"),
    permute: () => F.t("scan.sub_permute", "Перестановки имён"),
    rdap: () => F.t("scan.sub_rdap", "Сети и владельцы (RDAP)"),
    liveness: () => F.t("scan.sub_liveness", "Проверка живости"),
    tls: () => F.t("scan.sub_tls", "Сертификаты TLS"),
    queue: () => F.t("scan.sub_queue", "Очередь загрузки"),
    crawl: () => F.t("scan.sub_crawl", "Обход сайта"),
    storage: () => F.t("scan.sub_storage", "Внешние хранилища"),
    hosts: () => F.t("scan.sub_hosts", "Хосты"),
  };
  const subLabel = id => (SUB_LABEL[id] ? SUB_LABEL[id]() : id);
  // ---------- per-item controls (scan_control): stage, source, sub-step ----------
  const capsOf = (kind, id) => {
    const c = F.scan.caps || {};
    return c[`${kind}:${id}`] || (kind === "stage" ? c["stage:*"] : null) || [];
  };
  const isHeld = key => (F.scan.held || []).includes(key);
  // live: the item is running or waiting (pause/skip make sense); done items only offer a restart.
  function ctlBtns(kind, id, name, live, only, inline) {
    const caps = capsOf(kind, id).filter(a => !only || only.includes(a));
    if (!caps.length || !F.scan.running) return "";
    const held = isHeld(`${kind}:${id}`);
    // Stage rows show a short word next to the icon; inline controls (source rows) stay icon-only with a
    // tooltip and an accessible name.
    const SHORT = {
      pause: () => F.t("scan.ctl_l_pause", "Пауза"),
      resume: () => F.t("scan.ctl_l_resume", "Продолжить"),
      skip: () => F.t("scan.ctl_l_skip", "Пропустить"),
      restart: () => F.t("scan.ctl_l_restart", "Заново"),
    };
    const b = (act, icon, label) =>
      `<button class="btn sm tonal scn-cbtn${inline ? "" : " lbl"}" data-act="scan-ctl:${kind}|${id}|${act}"
        aria-label="${esc(label)}" title="${esc(label)}">${ic(icon)}${inline ? "" : `<span class="scn-cl" aria-hidden="true">${esc(SHORT[act]())}</span>`}</button>`;
    const out = [];
    if (live && caps.includes("pause"))
      out.push(
        held
          ? b("resume", "play", F.t("scan.ctl_resume", { name }, "Продолжить: {name}"))
          : b("pause", "pause", F.t("scan.ctl_pause", { name }, "Пауза: {name}")),
      );
    if (live && caps.includes("skip"))
      out.push(b("skip", "scn-skip", F.t("scan.ctl_skip", { name }, "Пропустить: {name}")));
    if (caps.includes("restart"))
      out.push(b("restart", "refresh", F.t("scan.ctl_restart", { name }, "Перезапустить: {name}")));
    if (!out.length) return "";
    return inline
      ? `<span class="scn-ctlin">${out.join("")}</span>`
      : `<div class="scn-ctlrow" role="group">${out.join("")}</div>`;
  }
  const CTL_REASON = {
    no_scan: () => F.t("scan.ctl_no_scan", "Скан не идёт"),
    finished: () => F.t("scan.ctl_finished", "Уже завершено"),
    pending: () => F.t("scan.ctl_pending", "Ещё не началось: перезапускать нечего"),
    unsupported: () => F.t("scan.ctl_unsupported", "Для этого элемента действие недоступно"),
  };
  const CTL_DONE = {
    paused: () => F.t("scan.ctl_paused", "На паузе, остальной скан идёт дальше"),
    running: () => F.t("scan.ctl_running", "Продолжено"),
    skipped: () => F.t("scan.ctl_skipped", "Пропущено, скан идёт дальше"),
    restarting: () => F.t("scan.ctl_restarting", "Перезапуск в этом скане"),
    queued: () =>
      F.t(
        "scan.ctl_queued",
        "Этап уже прошёл: добавлено в очередь, запустите после скана «Повторить отложенное»",
      ),
  };
  F.actions["scan-ctl"] = arg => {
    const [kind, id, action] = String(arg).split("|");
    F.api.scan_control(kind, id, action).then(
      r => {
        if (r && r.ok) {
          const key = `${kind}:${id}`;
          F.scan.held = (F.scan.held || []).filter(x => x !== key);
          if (r.state === "paused") F.scan.held.push(key);
          if (r.state === "queued" && !(F.scan.followup || []).includes(key))
            F.scan.followup = [...(F.scan.followup || []), key];
          if (r.state === "skipped" && kind === "source") {
            const src = F.scan.sources.find(x => x.id === id);
            if (src && src.status === "running") src.skipping = true;
          }
          F.snack(CTL_DONE[r.state] ? CTL_DONE[r.state]() : r.state);
        } else
          F.snack(CTL_REASON[r && r.reason] ? CTL_REASON[r.reason]() : F.t("scan.ctl_failed", "Не удалось"));
        refresh();
      },
      e => F.snack(F.t("scan.ctl_err", { err: e.message || e }, "Не удалось: {err}")),
    );
  };
  // Follow-up run of the restarts queued after their stage was over: starts at the earliest stage.
  const SRC_STAGE = { subdomains: "network", tls: "network", ports: "ports", fuzz: "fuzz" };
  ["recon", "webaudit", "wellknown", "buckets", "grepapp"].forEach(x => (SRC_STAGE[x] = "recon"));
  function followupStart(items) {
    const idx = id => STAGES.findIndex(x => x.id === id);
    let from = STAGES.length - 1;
    const sources = [];
    items.forEach(key => {
      const [kind, id] = key.split(":");
      const st = kind === "stage" ? id : kind === "step" ? "network" : SRC_STAGE[id] || "search";
      from = Math.min(from, Math.max(0, idx(st)));
      if (kind === "source") sources.push(id);
      if (kind === "step") sources.push("subdomains");
    });
    const only = items.every(k => !k.startsWith("stage:"));
    return { from_stage: STAGES[from].id, sources: only ? [...new Set(sources)] : [], only: items.slice() };
  }
  // Stages a narrowed run of `items` executes (mirrors the core): a search source or stage brings
  // the document pipeline, any other item only its own stage; the report always runs.
  function followupStages(items) {
    const idx = id => STAGES.findIndex(x => x.id === id),
      analysis = idx("analysis"),
      run = new Set([idx("report")]);
    items.forEach(key => {
      const [kind, id] = key.split(":");
      const k = Math.max(
        0,
        idx(kind === "stage" ? id : kind === "step" ? "network" : SRC_STAGE[id] || "search"),
      );
      if (k <= analysis) for (let j = k; j <= analysis; j++) run.add(j);
      else run.add(k);
    });
    return STAGES.filter((x, j) => run.has(j));
  }
  F.actions["scan-followup"] = () => {
    const fin = F.scan.finished,
      rec = fin && scanRec(fin.scanId);
    if (!fin || !(fin.followup || []).length) return;
    const { from_stage, sources, only } = followupStart(fin.followup);
    safeStart({ profile: (rec && rec.profile_id) || "passive", from_stage, sources, only, open: true }).then(
      r => {
        if (r) F.snack(F.t("scan.followup_started", "Повторяем отложенное"));
      },
    );
  };
  // Resolver steps the user can skip alone (scan_skip_source); shown when the resolver is slow.
  const RESOLVER_STEPS = ["brute", "permute"];
  const slowText = x =>
    F.t(
      "scan.dns_slow",
      { min: Math.max(1, Math.ceil((x.etaS || 60) / 60)) },
      "DNS медленный (VPN?): перебор займёт ~{min} мин",
    );
  // Hosts of the stage worked on at once: "Hosts: 3 running, 2 done of 7" and the running names.
  function hostsHTML(x) {
    const run = (x.running || []).length;
    const line = F.t(
      "scan.sub_hosts_line",
      { run: num(run), done: num(Math.min(x.done, x.total)), total: num(x.total) },
      "Хосты: {run} в работе, {done} готово из {total}",
    );
    const names = run ? `<div class="scn-subhosts mono">${esc(x.running.join(", "))}</div>` : "";
    return `<div class="scn-sub" id="scn-sub-hosts">${ic("spin", "spin")}<span>${esc(line)}</span></div>${names}`;
  }
  function subHTML(def) {
    const x = F.scan.substep;
    if (!x || (x.stage && x.stage !== def.id)) return "";
    if (x.id === "hosts") return hostsHTML(x);
    const cnt = x.total ? ` ${num(Math.min(x.done, x.total))}/${num(x.total)}` : "";
    const slow =
      x.slow && RESOLVER_STEPS.includes(x.id)
        ? `<div class="scn-slow" role="status">${ic("alert")}<span>${esc(slowText(x))}</span></div>
          <button class="btn sm tonal scn-sbtn" data-act="scan-skip-step:${x.id}"
            aria-label="${esc(F.t("scan.skip_step_aria", { name: subLabel(x.id) }, "Пропустить: {name}"))}">${ic("scn-skip")}${esc(x.id === "brute" ? F.t("scan.skip_brute", "Пропустить перебор") : F.t("scan.skip_permute", "Пропустить перестановки"))}</button>`
        : "";
    const ctl = RESOLVER_STEPS.includes(x.id) ? ctlBtns("step", x.id, subLabel(x.id), true) : "";
    const held = isHeld(`step:${x.id}`) ? ` · ${F.t("scan.ctl_held", "пауза")}` : "";
    return `<div class="scn-sub" id="scn-sub-${esc(x.id)}">${ic(held ? "pause" : "spin", held ? "" : "spin")}<span>${esc(subLabel(x.id))}${cnt}${esc(held)}</span></div>${slow}${ctl}`;
  }
  // Crawler card of the search stage: counters, rate state and what happens to the rest of the site.
  function crawlHTML(def) {
    const c = F.scan.crawl;
    if (def.id !== "search" || !c) return "";
    const n = v => num(v || 0);
    const parts = [
      F.t("scan.crawl_pages", { n: n(c.pages) }, "страниц {n}"),
      F.t("scan.crawl_queued", { n: n(c.queued) }, "в очереди {n}"),
      F.t("scan.crawl_docs", { n: n(c.docs) }, "документов {n}"),
      F.t("scan.crawl_storage", { n: n(c.storage) }, "в хранилищах {n}"),
    ];
    if (c.images) parts.push(F.t("scan.crawl_images", { n: n(c.images) }, "изображений {n}"));
    if (c.rendered) parts.push(F.t("scan.crawl_rendered", { n: n(c.rendered) }, "отрисовано {n}"));
    const rate =
      c.rate === "stopped"
        ? `<span class="pill bad">${ic("stop")}${esc(F.t("scan.crawl_rate_stopped", { hosts: (c.stopped_hosts || []).join(", ") }, "остановлен из-за 429: {hosts}"))}</span>`
        : c.rate === "slowed"
          ? `<span class="pill warn">${ic("clock")}${esc(F.t("scan.crawl_rate_slowed", "темп снижен: сайт просит реже (429/503)"))}</span>`
          : "";
    const notes = [];
    if (c.resumed) notes.push(F.t("scan.crawl_resumed", "продолжение обхода прошлого скана"));
    if (!c.finished && c.stop)
      notes.push(
        F.t("scan.crawl_rest", { n: n(c.queued) }, "остаток ({n} стр.) продолжится в следующем скане"),
      );
    if (c.render_missing && !c.rendered)
      notes.push(
        F.t("scan.crawl_no_render", "страницы-приложения на JavaScript без браузера: ссылки только из HTML"),
      );
    return `<div class="scn-sub scn-crawl" id="scn-crawl">${ic("globe")}<span>${esc(subLabel("crawl"))}: ${esc(parts.join(" · "))}</span></div>${rate ? `<div class="scn-crawl-r">${rate}</div>` : ""}${notes.map(t => `<div class="scn-subhint">${esc(t)}</div>`).join("")}`;
  }
  // Skipped sub-steps with a reason, grouped by reason: "Brute force, Permutations: skipped: …" + hint.
  function subNotesHTML(def) {
    const notes = Object.entries(F.scan.subNotes || {}).filter(([, n]) => !n.stage || n.stage === def.id);
    if (!notes.length) return "";
    const groups = new Map();
    notes.forEach(([id, n]) => {
      const g = groups.get(n.reason) || { n, ids: [] };
      g.ids.push(id);
      groups.set(n.reason, g);
    });
    return [...groups.values()]
      .map(({ n, ids }) => {
        const why = n.msg ? F.coreMsg(n.reason, n.msg) : n.reason;
        const hint =
          n.msg && n.msg.code === "sub.url_target"
            ? `<div class="scn-subhint">${esc(F.t("scan.sub_hint_add_domain", "Добавьте домен целью, чтобы перебирать поддомены"))}</div>`
            : "";
        return `<div class="scn-sub scn-subskip" id="scn-subskip-${esc(ids.join("-"))}">${ic("info")}<span>${esc(ids.map(subLabel).join(", "))}: ${esc(why)}</span></div>${hint}`;
      })
      .join("");
  }
  F.actions["scan-skip-step"] = id => {
    F.api.scan_skip_source(id).then(
      r => {
        if (r && r.ok) {
          const x = F.scan.substep;
          if (x && x.id === id) x.slow = false;
          F.snack(
            F.t("scan.snack_step_skipped", { name: subLabel(id) }, "«{name}» пропущен, скан идёт дальше"),
          );
        } else F.snack(F.t("scan.step_already", "Этот шаг уже завершён"));
        refresh();
      },
      e => F.snack(F.t("scan.skip_err", { err: e.message || e }, "Не удалось пропустить: {err}")),
    );
  };
  function stageHTML(k, st, opts = {}) {
    const scan = F.scan,
      def = STAGES[k],
      // the whole scan or this stage alone (its own Pause button) is on hold
      paused = (scan.paused || isHeld(`stage:${def.id}`)) && !opts.static;
    const mk =
      {
        run: paused ? ic("pause") : ic("spin", "spin"),
        done: ic("check"),
        cut: ic("stop"),
        sel: ic("scn-skip"),
      }[st] || `<b>${k + 1}</b>`;
    const cnt = (opts.counters || (["wait", "none", "sel"].includes(st) ? [] : stageCounters(def.id))).filter(
      Boolean,
    );
    return `<div class="scn-mk">${mk}</div>
      <div class="scn-sb">
        <div class="scn-st-h"><span class="scn-st-t">${esc(stageName(k, scan))}</span>${statusPill(st, paused)}${!opts.static && st === "done" && scan.running ? ctlBtns("stage", def.id, stageName(k, scan), false, ["restart"], true) : ""}${!opts.static && st === "wait" && scan.running ? ctlBtns("stage", def.id, stageName(k, scan), true, ["skip"], true) : ""}</div>
        ${cnt.length ? `<div class="scn-st-m">${cnt.map(c => `<span>${esc(c)}</span>`).join("")}</div>` : ""}
        ${st === "run" && !opts.static ? subHTML(def) : ""}
        ${(st === "run" || st === "done") && !opts.static ? crawlHTML(def) + subNotesHTML(def) : ""}
        ${!opts.static && st === "run" && scan.running ? ctlBtns("stage", def.id, stageName(k, scan), true) : ""}

        ${st === "run" && !opts.static ? `<div class="pbar scn-pb"><i style="width:${Math.round(stageP(k) * 100)}%"></i></div>` : ""}
      </div>`;
  }
  const stageCls = (st, paused) => `scn-step is-${st}${st === "run" && paused ? " is-paused" : ""}`;

  // ---------- header, controls, active mode ----------
  function headHTML() {
    const scan = F.scan,
      i = scan.stageIdx,
      elapsedS = elapsed();
    const left =
      scan.progress > 3 && !scan.paused ? (elapsedS / scan.progress) * (100 - scan.progress) : null;
    const tg = scan.targets || [];
    return `
      <div class="scn-h1">
        ${ui.leadIcon("target", scan.active ? "var(--active)" : "var(--accent)")}
        <div class="scn-h1b"><div class="scn-tgt">${esc(tg[0] || scan.projectName || "")}</div><div class="scn-h1s">${tg.length > 1 ? `+${tg.length - 1} ${pw(tg.length - 1, "scan.pl_target", "цель|цели|целей")} · ` : ""}${esc(F.t("scan.head_profile", { name: profName(scan) }, "профиль «{name}»"))}${scan.resumed ? " · " + esc(F.t("scan.head_resumed", "продолжение")) : ""}</div></div>
        ${scan.paused ? `<span class="pill warn">${ic("pause")}${esc(F.t("scan.pill_pause", "Пауза"))}</span>` : `<span class="pill info">${ic("spin", "spin")}${esc(F.t("scan.pill_running", "Идёт"))}</span>`}
      </div>
      <div class="scn-big"><b>${scan.progress}<small>%</small></b><span>${i >= 0 ? esc(stageName(i, scan)) : ""}<small>${i >= 0 ? esc(F.t("scan.stage_n_of", { i: stageSlot(i).i + 1, n: stageSlot(i).n }, "этап {i} из {n}")) : ""}</small></span></div>
      <div class="pbar scn-hpb ${scan.paused ? "paused" : ""}"><i style="width:${scan.progress}%"></i></div>
      <div class="scn-meta"><span>${ic("clock")}${esc(F.t("scan.elapsed", { t: fmtT(elapsedS) }, "Прошло {t}"))}</span><span>${esc(scan.paused ? F.t("scan.on_pause", "на паузе") : left != null ? F.t("scan.left", { t: fmtLeft(left) }, "осталось {t}") : F.t("scan.estimating", "оцениваем время…"))}</span>${scan.startedAt ? `<span>${esc(F.t("scan.started_at", { t: clock(scan.startedAt) }, "начат {t}"))}</span>` : ""}</div>`;
  }
  function pauseBanner() {
    const s = F.scan;
    if (!s.paused || !s.pauseReason || s.pauseReason === "user") return "";
    const R = reasonOf(s.pauseReason);
    return `<div class="banner warn scn-pbn"
      id="scn-pbn">${ic(R.icon)}<div><b>${esc(R.label || R.title)}</b><div>${esc(R.text)}</div></div></div>`;
  }
  // "Delete scan" (history sheet, stopped card, paused scan): opens the hold-to-confirm sheet.
  const delBtn = id =>
    `<button class="btn text crit block scn-del" data-act="scan-del:${esc(id)}">${ic("trash")}${esc(F.t("scan.delete_scan", "Удалить скан"))}</button>`;
  function ctlHTML() {
    const s = F.scan;
    return `${pauseBanner()}<div class="btnrow">
        ${
          s.paused
            ? `<button class="btn primary"
          data-act="scan-resume">${ic("play")}${esc(F.t("scan.resume", "Продолжить"))}</button>`
            : `<button class="btn tonal"
          data-act="scan-pause">${ic("pause")}${esc(F.t("scan.pause", "Пауза"))}</button>`
        }
        <button class="btn danger-o scn-stop" data-act="scan-stop">${ic("stop")}${esc(F.t("scan.stop", "Стоп"))}</button>
      </div>${s.paused && s.scanId ? delBtn(s.scanId) : ""}`;
  }
  function killText() {
    const net = settings().net || {};
    if (!net.kill_switch)
      return [
        `${ic("alert")}${esc(F.t("scan.ks_off", "Выключен: при обрыве туннеля запросы пойдут с вашего реального IP"))}`,
        "bad",
      ];
    return [
      `${ic("shield")}${esc(net.kill_action === "pause" && !F.scan.active ? F.t("scan.ks_on_pause", "Включён: при обрыве туннеля скан встанет на паузу") : F.t("scan.ks_on_stop", "Включён: при обрыве туннеля скан остановится"))}`,
      "ok",
    ];
  }
  function activeHTML() {
    const s = F.scan,
      sc = F.sel.scope.info(),
      [kt, kc] = killText();
    return `<div class="scn-ah">${ic("alert")}<div><b>${esc(F.t("scan.active_mode", "Активный режим"))}</b><span>${esc(F.t("scan.active_mode_sub", "Модули обращаются к цели напрямую"))}</span></div></div>
      <div class="scn-akv">
        <div><span>${esc(F.t("scan.egress", "Выходной IP"))}</span><b class="mono">${esc(s.egress)}</b></div>
        <div><span>${esc(F.t("settings.kill_title", "Защита от утечки IP"))}</span><b class="scn-ks ${kc}">${kt}</b></div>
        ${sameProject() ? `        <div><span>${esc(F.t("scan.active_targets", "Цели активной фазы"))}</span><b>${esc(sc.activeTargets.join(", ") || "-")}</b></div>` : ""}
      </div>`;
  }

  // ---------- sources: list from the scan, key status from settings ----------
  const keyOf = id => ((settings().keys || {})[id] ? id : null);
  // Source status comes from core events: wait → running → ok | error | timeout | skipped; nokey/off
  // immediately.
  // The key from settings matters only for nokey/off (added during the scan) and key errors.
  const SLOW_S = 30; // Longer than this: "slow to respond" and the Skip button.
  // Site file search (fuzz): its own statuses and the "Stop fuzzing" button.
  function fuzzState(src) {
    const run = F.scan.running,
      canStop = run && ["wait", "running"].includes(src.status) && !src.skipping;
    const cnt =
      src.checked != null
        ? (src.planned
            ? F.t(
                "scan.fz_checked_of",
                { n: num(src.checked), total: num(src.planned) },
                "проверено {n} из ~{total}",
              )
            : F.t("scan.ctr_checked", { n: num(src.checked) }, "проверено {n}")) +
          " · " +
          F.t("scan.ctr_found", { n: num(src.found || 0) }, "найдено {n}") +
          (src.filtered
            ? " · " + F.t("scan.ctr_filtered", { n: num(src.filtered) }, "отфильтровано калибровкой {n}")
            : "")
        : "";
    const docs = src.documents
      ? " · " + F.t("scan.fz_docs", { n: num(src.documents) }, "документов в загрузку: {n}")
      : "";
    switch (src.status) {
      case "wait":
        return {
          cls: "mute",
          pill: `<span class="pill mute">${ic("clock")}${esc(F.t("scan.pill_queued", "В очереди"))}</span>`,
          sub: F.t("scan.fz_wait", "Запустится на этапе «Поиск на сайте»: после «Сеть и DNS»"),
          fuzzStop: canStop,
        };
      case "running":
        return {
          cls: "run",
          pill: `<span class="pill info">${ic("spin", "spin")}${esc(F.scan.paused ? F.t("scan.pill_pause", "Пауза") : F.t("scan.pill_running", "Идёт"))}</span>`,
          sub: `${cnt || F.t("scan.fz_calib", "Калибровка: проверяем, как сайт отвечает на несуществующие адреса…")}${src.host ? ` · ${src.host}` : ""}`,
          fuzzStop: canStop,
        };
      case "ok":
        return {
          cls: "ok",
          pill: `<span class="pill ok">${ic("check")}${esc(F.t("common.done", "Готово"))}</span>`,
          sub: F.t("scan.fz_done", { cnt }, "Перебор завершён: {cnt}") + docs,
        };
      case "stopped":
        return {
          cls: "warn",
          pill: `<span class="pill warn">${ic("stop")}${esc(F.t("scan.pill_stopped", "Остановлен"))}</span>`,
          sub: `${src.detail ? src.detail[0].toUpperCase() + src.detail.slice(1) : F.t("scan.fz_stopped", "Перебор остановлен")}${cnt ? " · " + cnt : ""}${docs}`,
        };
      case "blocked":
        return {
          cls: "bad",
          pill: `<span class="pill warn">${ic("alert")}${esc(F.t("scan.pill_blocked", "Сайт ограничил запросы"))}</span>`,
          sub: `${F.t("scan.fz_blocked", "Сайт ограничил запросы: перебор остановлен, повторных попыток нет")}${cnt ? " · " + cnt : ""}${docs}`,
        };
      case "skipped":
        return {
          cls: "mute",
          pill: `<span class="pill mute">${ic("scn-skip")}${esc(F.t("scan.skipped", "Пропущен"))}</span>`,
          sub: src.detail
            ? src.detail[0].toUpperCase() + src.detail.slice(1)
            : F.t("scan.skipped", "Пропущен"),
        };
      case "error":
        return {
          cls: "bad",
          pill: `<span class="pill bad">${ic("alert")}${esc(F.t("scan.reason_error_chip", "Ошибка"))}</span>`,
          sub: src.detail || src.error || F.t("scan.fz_error", "Перебор не запустился"),
        };
      case "off":
        return {
          cls: "mute",
          pill: `<span class="pill mute">${ic("scn-skip")}${esc(F.t("scan.pill_off", "Не входит"))}</span>`,
          sub: F.t(
            "scan.fz_off",
            "Только в профиле «Полный» (или «Свой» с модулем) после подтверждения разрешения",
          ),
        };
    }
    return { cls: "mute", pill: "", sub: "" };
  }
  F.actions["scan-stop-fuzz"] = () => {
    const src = F.scan.sources.find(x => x.id === "fuzz");
    F.api.scan_skip_source("fuzz").then(
      r => {
        if (r && r.ok) {
          if (src) src.skipping = true;
          F.snack(F.t("scan.fz_stopping", "Перебор останавливается: найденное сохранится, скан продолжится"));
        } else F.snack(F.t("scan.fz_already", "Перебор уже закончился"));
        refresh();
      },
      e => F.snack(F.t("scan.stop_err", { err: e.message || e }, "Не удалось остановить: {err}")),
    );
  };
  /** Status line for a source that answered successfully. */
  function okSummary(src, key) {
    if (HOST_SRC.includes(src.id))
      return src.n
        ? F.tp("scan.ok_subs", src.n, { n: num(src.n) }, "{n} поддомен|{n} поддомена|{n} поддоменов")
        : F.t("scan.ok_subs_none", "Ответил, поддоменов нет");
    if (src.id === "subdomains")
      return src.n
        ? `${num(src.n)} ${pw(src.n, "scan.pl_new_host", "новый хост|новых хоста|новых хостов")}: ${F.t("scan.ok_brute_how", "перебор, перестановки, PTR")}`
        : F.t("scan.ok_brute_none", "Новых хостов не найдено");
    if (src.id === "tls")
      return src.n
        ? `${num(src.n)} ${pw(src.n, "scan.pl_cert_checked", "сертификат проверен|сертификата проверено|сертификатов проверено")}`
        : F.t("scan.ok_tls_none", "TLS-портов для проверки не нашлось");
    if (src.id === "internetdb")
      return src.n
        ? F.t("scan.ok_idb", { n: num(src.n) }, "данные Shodan по {n} IP")
        : F.t("scan.ok_idb_none", "Ответил, данных по IP нет");
    if (src.id === "crawler") {
      return src.n
        ? F.t(
            "scan.ok_crawl",
            { n: num(src.n), w: pw(src.n, "scan.pl_link", "ссылка|ссылки|ссылок") },
            "{n} {w} на документы",
          )
        : F.t("scan.ok_crawl_none", "Сайт ответил, ссылок на документы нет");
    }
    let text = F.t("scan.ok_nodocs", "Ответил, документов нет");
    if (src.n)
      text = F.tp(
        "scan.ok_results",
        src.n,
        { n: num(src.n) },
        "{n} результат|{n} результата|{n} результатов",
      );
    else if (key) text = F.t("scan.ok_by_key", "По ключу API");
    return text + (src.error ? ` · ${src.error}` : "");
  }
  // Dork block reason from the core: "captcha / blocked: search engine check failed" → "Search engine check failed".
  function dorkWhy(err) {
    const m = String(err || "")
      .replace(/^капча \/ заблокировано:?\s*/i, "")
      .replace(F.t("core.src.blocked", { why: "" }, "капча / заблокировано: ").trim(), "")
      .trim();
    return m
      ? m[0].toUpperCase() + m.slice(1)
      : F.t("scan.dork_blocked", "Поисковик показал капчу или заблокировал запросы");
  }
  function srcState(src) {
    if (src.id === "fuzz") return fuzzState(src);
    const key = keyOf(src.id),
      k = key ? settings().keys[key] : null;
    let st = src.status;
    if (k && (st === "nokey" || st === "off") && k.status === "ok") st = "late";
    if (k && k.status === "error" && (st === "nokey" || st === "error")) st = "keyerr";
    const searching = F.scan.running && F.scan.stageIdx === 0;
    // Subdomain enumeration and TLS inspection can be skipped up to the end of the "Ports" stage.
    const infraSkip = INFRA_SKIP.includes(src.id) && F.scan.running && F.scan.stageIdx <= PORTS_IDX;
    const skip = (searching && SKIPPABLE.includes(src.id)) || infraSkip ? src.id : null;
    switch (st) {
      case "late":
        return {
          cls: "ok",
          pill: `<span class="pill info">${ic("key")}${esc(F.t("scan.pill_key_added", "Ключ добавлен"))}</span>`,
          sub: F.t("scan.key_next_scan", "Подключится в следующем скане"),
        };
      case "wait":
        return {
          cls: "mute",
          pill: `<span class="pill mute">${ic("clock")}${esc(F.t("scan.pill_queued", "В очереди"))}</span>`,
          sub: searching
            ? src.id === "crawler"
              ? F.t("scan.wait_crawler", "Ходит на сайт цели: после внешних источников")
              : F.t("scan.wait_parallel", "Внешние источники опрашиваются по 4 одновременно")
            : src.id === "internetdb" || INFRA_SKIP.includes(src.id)
              ? F.t("scan.wait_network", "Опрашивается на этапе «Сеть и DNS»")
              : F.t("scan.not_polled", "Не опрошен"),
          skip,
        };
      case "running": {
        // The remaining time only displays the core's deadline (deadline_ms against the device clock stays
        // correct
        // after the WebView was frozen in background); "no response" is declared by the core via a timeout
        // event, not by the UI.
        const now = Date.now(),
          sec = src.startedAt ? Math.max(0, Math.floor((now - src.startedAt) / 1000)) : 0;
        const left = src.deadlineMs
          ? Math.max(0, Math.ceil((src.deadlineMs - now) / 1000))
          : src.timeoutS
            ? Math.max(0, src.timeoutS - sec)
            : null;
        const tail =
          (src.retry ? " · " + F.t("scan.retry_n", { n: src.retry }, "повтор {n}") : "") +
          (src.rounds > 1
            ? " · " + F.t("scan.domain_of", { i: src.round, n: src.rounds }, "домен {i} из {n}")
            : "");
        const rest =
          left == null
            ? ""
            : " · " +
              (left > 0
                ? F.t("scan.auto_off_in", { t: fmtT(left) }, "отключится сам через {t}")
                : F.t("scan.finishing", "завершается…"));
        return sec >= SLOW_S
          ? {
              cls: "run",
              pill: `<span class="pill info">${ic("clock")}${esc(F.t("scan.pill_slow", "Долго отвечает"))}</span>`,
              sub: `${F.t("scan.waiting_reply", { t: fmtT(sec) }, "Ждём ответа {t}")}${rest}${tail} · ${F.t("scan.can_skip", "можно пропустить")}`,
              skip,
            }
          : {
              cls: "run",
              pill: `<span class="pill info">${ic("spin", "spin")}${esc(F.t("scan.pill_running", "Идёт"))}</span>`,
              sub: `${WEB_SRC.includes(src.id) ? F.t("scan.web_opening", "Встроенный браузер открывает поисковик") : F.t("scan.req_sent", "Отправлены запросы")}… ${fmtT(sec)}${tail}`,
              skip,
            };
      }
      case "ok":
        return F.isDemo && searching && src.n == null
          ? {
              cls: "run",
              pill: `<span class="pill info">${ic("spin", "spin")}${esc(F.t("scan.pill_running", "Идёт"))}</span>`,
              sub: F.t("scan.req_sent", "Отправлены запросы") + "…",
            }
          : {
              cls: "ok",
              pill: `<span class="pill ok">${ic("check")}OK</span>`,
              sub: okSummary(src, key),
            };
      case "timeout":
      case "error":
        if (searching && src.rounds > 1 && src.round < src.rounds)
          return {
            cls: "run",
            pill: `<span class="pill mute">${ic("clock")}${esc(F.t("scan.pill_next_domain", "Следующий домен"))}</span>`,
            sub: F.t(
              "scan.next_domain_sub",
              {
                what:
                  st === "timeout"
                    ? F.t("scan.no_reply", "Нет ответа")
                    : F.t("scan.reason_error_chip", "Ошибка"),
                domain: src.domain || F.t("scan.domain_n", { n: src.round }, "домену {n}"),
                i: src.round + 1,
                n: src.rounds,
              },
              "{what} по {domain}: опросим для домена {i} из {n}",
            ),
            skip,
          };
        if (st === "error")
          return {
            cls: "bad",
            pill: `<span class="pill bad">${ic("alert")}${esc(F.t("scan.reason_error_chip", "Ошибка"))}</span>`,
            sub: `${src.error || F.t("scan.svc_no_reply", "Сервис не ответил")}: ${F.t("scan.continued_without", "скан продолжен без него")}`,
          };
        return {
          cls: "bad",
          pill: `<span class="pill warn">${ic("clock")}${esc(F.t("scan.no_reply", "Нет ответа"))}</span>`,
          sub: `${src.error || F.t("scan.no_reply_time", "Не ответил вовремя")}: ${F.t("scan.continued_without", "скан продолжен без него")}`,
        };
      case "blocked":
        // The check passed after the search stage: cookies are saved, the source runs on the next scan or
        // after its restart (scan_control); no second "Pass the check" button.
        if (src.verifyUrl && src.verifyDone && !src.retryAsked)
          return {
            cls: "warn",
            pill: `<span class="pill ok">${ic("check")}${esc(F.t("scan.pill_verified", "Проверка пройдена"))}</span>`,
            sub: F.t(
              "scan.verify_next",
              "Проверка пройдена: сработает в следующем скане или после перезапуска источника",
            ),
          };
        if (src.verifyUrl)
          return {
            cls: "bad",
            pill: `<span class="pill warn">${ic("alert")}${esc(F.t("scan.pill_verify", "Нужна проверка"))}</span>`,
            sub: src.retryAsked
              ? F.t("scan.verify_passed", "Проверка пройдена: источник будет опрошен ещё раз в этом скане")
              : `${dorkWhy(src.error)}: ${F.t("scan.verify_do", "пройдите проверку сами (как в браузере), куки сохранятся")}`,
            verify: !src.retryAsked,
          };
        return {
          cls: "bad",
          pill: `<span class="pill warn">${ic("alert")}${esc(F.t("scan.pill_captcha", "Капча / блок"))}</span>`,
          sub: `${DORK_SRC.includes(src.id) ? dorkWhy(src.error) : src.error || F.t("scan.svc_blocked", "Сервис заблокировал запросы")}: ${F.t("scan.no_guarantee", "работает без гарантий, скан продолжен")}`,
        };
      case "unreliable":
        return {
          cls: "warn",
          pill: `<span class="pill warn">${ic("alert")}${esc(F.t("scan.pill_unreliable", "Недостоверно"))}</span>`,
          sub:
            src.error ||
            F.t(
              "scan.ports_unreliable",
              "Скан портов недостоверен: сеть устройства (VPN, AdGuard, прокси) принимает соединения на любом порту. Отключите локальный VPN или добавьте FOCA-rs в исключения",
            ),
          help: "ports-unreliable",
        };
      case "limit":
        return {
          cls: "bad",
          pill: `<span class="pill warn">${ic("clock")}${esc(F.t("scan.pill_limit", "Лимит запросов"))}</span>`,
          sub: `${src.error ? src.error[0].toUpperCase() + src.error.slice(1) : F.t("scan.svc_limited", "Сервис ограничил частоту запросов")}: ${F.t("scan.continued_without", "скан продолжен без него")}`,
        };
      case "unavailable":
        return {
          cls: "mute",
          pill: `<span class="pill mute">${ic("scn-skip")}${esc(F.t("scan.pill_android", "Только в Android"))}</span>`,
          sub: F.t(
            "scan.needs_webview",
            "Нужен встроенный браузер (WebView). Работает в приложении на телефоне",
          ),
        };
      case "skipped_headless":
        return {
          cls: "mute",
          pill: `<span class="pill mute">${ic("scn-skip")}${esc(F.t("scan.pill_headless", "Фоновый режим"))}</span>`,
          sub: F.t(
            "scan.headless_sub",
            "Пропущен в автономном фоновом скане (встроенный браузер недоступен без окна)",
          ),
        };
      case "skipped":
        return {
          cls: "mute",
          pill: `<span class="pill mute">${ic("scn-skip")}${esc(F.t("scan.skipped", "Пропущен"))}</span>`,
          // A core-side skip (e.g. the plugin policy in passive mode) carries its own note.
          sub: src.error
            ? src.error[0].toUpperCase() + src.error.slice(1)
            : F.t("scan.skipped_user", "Пропущен по вашему решению. Скан продолжен без него"),
        };
      case "nokey":
        return { cls: "mute", hide: true, pill: "", sub: "" }; // A paid source without a key is not shown.
      case "off":
        return key && !(k && k.status === "ok")
          ? { cls: "mute", hide: true, pill: "", sub: "" }
          : {
              cls: "mute",
              pill: `<span class="pill mute">${ic("scn-skip")}${esc(F.t("scan.pill_not_connected", "Не подключён"))}</span>`,
              sub: src.error || F.t("scan.off_in_settings", "Выключен в «Настройки → Источники»"),
            };
      case "keyerr":
        return {
          cls: "bad",
          pill: `<span class="pill bad">${ic("alert")}${esc(F.t("scan.pill_key_err", "Ошибка ключа"))}</span>`,
          sub: `${(k && k.error) || F.t("scan.key_rejected", "Ключ не принят сервисом")}: ${F.t("scan.check_keys", "проверьте в «Настройки → Ключи API»")}`,
        };
    }
    return { cls: "mute", pill: "", sub: "" };
  }
  // Source name: the core label in Russian, the Sources dictionary name in other languages.
  const profRec = rec =>
    F.i18n.lang() === "ru" || !rec.profile_id
      ? rec.profile
      : F.t("launch.profile_" + rec.profile_id, rec.profile);
  const sn = src => {
    if (!src || F.i18n.lang() === "ru") return src && src.name;
    const hit = (F.SOURCE_LIST || []).find(x => x[0] === src.id);
    if (hit && F.sourceName) return F.sourceName(hit);
    return F.t("scan.src_" + src.id, src.name);
  };
  const SKIPPABLE = [
    "crt",
    "wayback",
    "cc",
    "brave",
    "searx",
    "crawler",
    ...HOST_SRC.slice(1),
    "arquivo",
    "otx_url",
    "urlscan",
    "hudson",
    ...DORK_SRC,
  ];
  const INFRA_SKIP = ["subdomains", "tls"];
  const PORTS_IDX = STAGES.findIndex(x => x.id === "ports");
  F.actions["scan-skip-src"] = id => {
    const src = F.scan.sources.find(x => x.id === id);
    F.api.scan_skip_source(id).then(
      r => {
        if (r && r.ok) {
          if (src && src.status === "running") src.skipping = true;
          F.snack(
            F.t(
              "scan.snack_src_skipped",
              { name: src ? sn(src) : id },
              "«{name}» пропущен, скан идёт дальше",
            ),
          );
        } else F.snack(F.t("scan.src_already", "Источник уже ответил"));
        refresh();
      },
      e => F.snack(F.t("scan.skip_err", { err: e.message || e }, "Не удалось пропустить: {err}")),
    );
  };
  // "Pass the check": the search engine's visible browser (Android), then the source is retried while the
  // search stage is still running; otherwise cookies are kept for the next scan. Outside Android, a message
  // saying it is unavailable.
  F.actions["scan-verify-src"] = id => {
    const src = F.scan.sources.find(x => x.id === id);
    if (!src || !src.verifyUrl) return;
    F.api.platform_verify_search({ url: src.verifyUrl, title: sn(src) }).then(
      r => {
        const state = F.verifyState(r);
        if (state === "unsupported") {
          F.snack(
            (r && r.error) ||
              F.t("scan.verify_phone_only", "Пройти проверку можно только в приложении на телефоне"),
          );
          return;
        }
        // Cancelled, failed or still unsolved: the engine stays blocked and keeps its "Pass the check" button.
        if (state !== "done") {
          F.snack(F.verifyStateMsg(state, sn(src)), { ms: 6000 });
          refresh();
          return;
        }
        src.verifyDone = true; // Cookies are saved even if this scan can no longer query the source.
        return F.api.scan_retry_source(id).then(x => {
          if (x && x.ok) {
            src.retryAsked = true;
            F.snack(
              F.t("scan.snack_requery", { name: sn(src) }, "«{name}» будет опрошен ещё раз в этом скане"),
            );
          } else F.snack(verifyLaterText(src), { ms: 6000 });
          refresh();
        });
      },
      e =>
        F.snack(F.t("scan.verify_open_err", { err: e.message || e }, "Не удалось открыть проверку: {err}")),
    );
  };
  const verifyLaterText = src =>
    F.t(
      "scan.snack_verify_next",
      { name: sn(src) },
      "«{name}»: проверка пройдена. Сработает в следующем скане или после перезапуска источника",
    );
  // One "Pass the check" button for all engines stuck on a captcha, one by one: visible browser → "Done" →
  // source retry; dorks of engines stuck on a captcha have already been handed to the others.
  const needVerify = () =>
    (F.scan.sources || []).filter(
      x => x.verifyUrl && !x.retryAsked && !x.verifyDone && x.status === "blocked",
    );
  // Dork groups no engine could run (captcha everywhere): postponed per project, retried by the core.
  function dorksHTML() {
    const d = F.scan.dorks;
    if (!d || !d.pending) return "";
    const n = d.pending;
    const when = d.retryAt
      ? F.t(
          "scan.dorks_at",
          {
            time: new Date(d.retryAt).toLocaleTimeString(F.i18n ? F.i18n.lang() : "ru", {
              hour: "2-digit",
              minute: "2-digit",
            }),
          },
          "Следующий повтор около {time}.",
        )
      : F.t("scan.dorks_next", "Повторятся в следующем скане.");
    const title = F.tp
      ? F.tp(
          "scan.dorks_pending",
          n,
          { n },
          "{n} поиск отложен, повторится сам|{n} поиска отложено, повторятся сами|{n} поисков отложено, повторятся сами",
        )
      : F.t("scan.dorks_pending_plain", { n }, "Поисков отложено: {n}");
    return `<div class="banner info scn-dorks">${ic("clock")}<div><b>${esc(title)}</b><div class="s">${esc(F.t("scan.dorks_d", "Все поисковики показали капчу. Капчи мы не решаем: эти запросы повторятся медленно, по одному.") + " " + when)}</div>
      <div class="btnrow"><button class="btn sm tonal" data-act="scan-dorks-retry">${ic("refresh")}${esc(F.t("scan.dorks_retry", "Повторить сейчас"))}</button></div></div></div>`;
  }
  // The running screen patches in place; the idle screen re-renders.
  const redrawDorks = () => {
    if (onScan() && !F.scan.running) F.render(true);
    else refresh();
  };
  // A `dorks` event newer than the request wins over its (older) answer.
  let dorkSeq = 0;
  const loadDorks = () => {
    if (!F.api || typeof F.api.dorks_pending !== "function") return;
    const seq = ++dorkSeq;
    Promise.resolve(F.api.dorks_pending())
      .then(r => {
        if (!r || seq !== dorkSeq) return;
        const prev = F.scan.dorks || {};
        F.scan.dorks = { pending: r.pending || 0, retryAt: r.retry_at || null };
        if (prev.pending !== F.scan.dorks.pending || prev.retryAt !== F.scan.dorks.retryAt) redrawDorks();
      })
      .catch(() => {});
  };
  F.on("scan", ev => {
    if (!ev) return;
    if (ev.type === "dorks") {
      dorkSeq++;
      F.scan.dorks = { pending: ev.pending || 0, retryAt: ev.retry_at || null };
      redrawDorks();
    } else if (ev.type === "started" || ev.type === "done") loadDorks();
  });
  F.on("db", ev => {
    if (ev && ev.kind === "project") loadDorks();
  });
  F.actions["scan-dorks-retry"] = () =>
    Promise.resolve(F.api.dorks_retry()).then(
      r => {
        const mode = (r && r.mode) || "none";
        F.snack(
          mode === "now"
            ? F.t("scan.dorks_now", "Повторяем отложенные поиски")
            : mode === "scan"
              ? F.t("scan.dorks_scan", "Запущен короткий скан: только поисковики для отложенных запросов")
              : mode === "busy"
                ? F.t("scan.dorks_busy", "Идёт другой скан: повтор после него")
                : F.t("scan.dorks_none", "Отложенных поисков нет"),
        );
        if (mode === "scan" && !onScan()) F.go("/p/scan");
        loadDorks();
      },
      e => F.snack(F.t("scan.dorks_err", { err: e.message || e }, "Не удалось повторить: {err}")),
    );

  function verifyAllHTML() {
    const l = needVerify();
    if (!l.length) return "";
    return `<div class="banner warn scn-vall">${ic("alert")}<div><b>${esc(F.t("scan.verify_need", { names: l.map(sn).join(", ") }, "Нужна проверка: {names}"))}</b><div class="s">${esc(F.t("scan.verify_need_d", "Их дорки переданы другим поисковикам и не потеряны. Пройдите проверку один раз. Куки сохранятся, дальше дорки пойдут сами."))}</div>
      <div class="btnrow"><button class="btn sm filled" data-act="scan-verify-all"
        aria-label="${esc(F.t("scan.verify_all_aria", "Пройти проверку во всех поисковиках по очереди"))}">${ic("check")}${esc(F.t("scan.verify_btn", "Пройти проверку"))}${l.length > 1 ? ` (${l.length})` : ""}</button></div></div></div>`;
  }
  F.actions["scan-verify-all"] = async () => {
    const pending = needVerify();
    let passed = 0;
    let solved = 0;
    let miss = null;
    for (const src of pending) {
      let result;
      try {
        result = await F.api.platform_verify_search({
          url: src.verifyUrl,
          title: `${sn(src)} (${F.t("scan.i_of_n", { i: pending.indexOf(src) + 1, n: pending.length }, "{i} из {n}")})`,
        });
      } catch (e) {
        F.snack(F.t("scan.verify_open_err", { err: e.message || e }, "Не удалось открыть проверку: {err}"));
        return;
      }
      const state = F.verifyState(result);
      if (state === "unsupported") {
        F.snack(
          (result && result.error) ||
            F.t("scan.verify_phone_only", "Пройти проверку можно только в приложении на телефоне"),
        );
        return;
      }
      if (state !== "done") {
        // Not verified: the engine stays blocked. Cancel stops the queue; a failed or unsolved page
        // moves on to the next engine.
        miss = [state, src];
        refresh();
        if (state === "cancelled") break;
        continue;
      }
      solved++;
      src.verifyDone = true; // The check passed (cookies saved), even if this scan can no longer retry the source.
      const retried = await F.api.scan_retry_source(src.id).catch(() => null);
      if (retried && retried.ok) {
        src.retryAsked = true;
        passed++;
      }
      refresh();
    }
    if (miss) F.snack(F.verifyStateMsg(miss[0], sn(miss[1])), { ms: 6000 });
    else if (passed)
      F.snack(
        passed > 1
          ? F.t(
              "scan.verify_passed_n",
              { n: passed },
              "Поисковиков после проверки: {n}. Опрос продолжится в этом скане",
            )
          : F.t("scan.verify_passed_one", "Проверка пройдена: поисковик будет опрошен ещё раз"),
        { ms: 5000 },
      );
    else if (solved)
      F.snack(
        F.t(
          "scan.verify_next",
          "Проверка пройдена: сработает в следующем скане или после перезапуска источника",
        ),
        { ms: 5000 },
      );
  };
  function srcRowHTML(src) {
    const st = srcState(src);
    let btn = "";
    if (st.skip && !src.skipping)
      btn = `<button class="btn sm tonal scn-sbtn" data-act="scan-skip-src:${st.skip}"
          aria-label="${esc(F.t("scan.skip_src_aria", { name: sn(src) }, "Пропустить источник: {name}"))}">${ic("scn-skip")}${esc(F.t("scan.skip_src", "Пропустить источник"))}</button>`;
    else if (st.fuzzStop)
      btn = `<button class="btn sm tonal scn-sbtn" data-act="scan-stop-fuzz"
            aria-label="${esc(F.t("scan.stop_fuzz_aria", "Остановить перебор на сайте"))}">${ic("stop")}${esc(F.t("scan.stop_fuzz", "Остановить перебор"))}</button>`;
    else if (st.help)
      btn = `<button class="btn sm tonal scn-sbtn"
              data-act="go:/help/${st.help}">${ic("info")}${esc(F.t("scan.what_to_do", "Что делать"))}</button>`;
    else if (st.verify)
      btn = `<button class="btn sm tonal scn-sbtn" data-act="scan-verify-src:${src.id}"
                aria-label="${esc(F.t("scan.verify_aria", { name: sn(src) }, "Пройти проверку: {name}"))}">${ic("check")}${esc(F.t("scan.verify_btn", "Пройти проверку"))}</button>`;
    const live = ["wait", "running"].includes(src.status) && !src.skipping;
    const ctl = ctlBtns(
      "source",
      src.id,
      sn(src),
      live,
      btn && st.skip ? ["pause", "resume", "restart"] : null,
    );
    return `${ui.leadIcon(SRC_IC[src.id] || "globe", st.cls === "bad" ? "var(--bad)" : st.cls === "ok" ? "var(--ok)" : "")}
      <div class="body"><div class="scn-srh"><span class="t one">${esc(sn(src))}</span>${st.pill}</div><div class="s">${esc(st.sub)}</div>${btn}${ctl}</div>`;
  }
  // Paid sources without a key are not shown on the scan screen at all.
  const visSources = () => (F.scan.sources || []).filter(src => !srcState(src).hide);
  const srcSummary = () => {
    const l = visSources().map(srcState);
    const ok = l.filter(x => x.cls === "ok" || x.cls === "run" || x.cls === "warn").length;
    return F.t("scan.src_ok_of", { ok, n: l.length }, "работают: {ok} из {n}");
  };
  const srcListHTML = () =>
    visSources()
      .map(src => `<div class="row scn-src" id="scn-src-${src.id}" data-anc>${srcRowHTML(src)}</div>`)
      .join("");

  // ---------- live feed: finding data comes from F.db.findings by id ----------
  function feedRowHTML(it, isNew) {
    const known = (F.db.findings || []).find(x => x.id === it.id);
    // Feed entries not yet in the snapshot keep the core text: render it in the UI language here.
    const f = known || { ...it, title: F.ftext ? F.ftext.field(it.title, it.rule || "") : it.title };
    const [icn, col] = SEV_IC[f.sev] || SEV_IC.info;
    const sub = [f.host && f.host !== "-" ? f.host : "", f.source || ""].filter(Boolean).join(" · ");
    return `<div class="row tap scn-fr ${isNew ? "scn-new" : ""}" data-act="go:/p/finding/${it.id}"
      data-anc
      data-fid="${it.id}">${ui.leadIcon(icn, col)}<div class="body"><div class="t">${esc(f.title)}</div><div class="s scn-fs">${ui.sev(f.sev)}<span class="scn-at">${ic("clock")}${fmtT(it.at)}</span></div>${sub ? `<div class="s scn-fsub">${esc(sub)}</div>` : ""}</div>${ic("chev", "chev")}</div>`;
  }
  const FEED_MAX = 6;
  const feedEmpty = () =>
    `<div class="scn-fe">${ic("search")}<span>${esc(F.scan.stageIdx >= 3 ? F.t("scan.feed_none", "Новых находок пока нет. Уже известные в ленту не попадают") : F.t("scan.feed_later", "Новые находки появятся здесь после этапа «Анализ»"))}</span></div>`;

  // ---------- out-of-scope candidates (F.db.oos) ----------
  const oosList = () => F.db.oos || [];
  const oosNew = () => oosList().filter(o => o.decision === "new").length;
  const oosRow = () => {
    const n = oosNew();
    return ui.row({
      lead: ui.leadIcon("link", n ? "var(--warn)" : ""),
      title: esc(F.t("scan.oos_title", "Кандидаты вне скоупа")),
      sub: esc(
        n
          ? F.t("scan.oos_sub", "Редиректы, CNAME, сети и чужие домены")
          : oosList().length
            ? F.t("scan.oos_none_new", "Новых кандидатов нет")
            : F.t("scan.oos_none", "Скан пока ничего не нашёл за пределами скоупа"),
      ),
      tail: n ? `<span class="pill warn">${n}</span>` : "",
      act: "go:/p/out-of-scope",
      attrs: 'id="scn-oos" data-anc',
    });
  };

  function renderRun() {
    const scan = F.scan,
      same = sameProject();
    return `<div id="scn-run">
      ${
        same
          ? ""
          : `<div class="banner info scn-other">${ic("info")}<div>${esc(F.t("scan.other_pre", "Скан идёт в проекте"))} <b>${esc(scan.projectName)}</b>. ${esc(F.t("scan.other_post", "Этапы и находки: в том проекте."))}<div class="btnrow"><button class="btn sm tonal"
        data-act="scan-open-project">${esc(F.t("scan.open_project", "Открыть проект"))}</button></div></div></div>`
      }
      <div class="card pad scn-head ${scan.active ? "is-active" : ""}"
        data-anc><div id="scn-hd">${headHTML()}</div><div id="scn-ctl"
        class="scn-ctl">${ctlHTML()}</div><p class="scn-fg">${ic("app")}<span>${esc(F.t("scan.bg_note", "В фоне скан держит постоянное уведомление Android с кнопками «Пауза» и «Стоп»."))}</span></p></div>
      ${scan.active ? `<div class="card pad scn-active" id="scn-act" data-anc>${activeHTML()}</div>` : ""}
      ${ui.secH(F.t("scan.stages", "Этапы"))}
      <div class="card scn-steps" id="scn-steps">${STAGES.map((d, k) => {
        const st = stageStatus(k);
        return `<div class="${stageCls(st, scan.paused)}" id="scn-st-${d.id}"
          data-anc>${stageHTML(k, st)}</div>`;
      }).join("")}</div>
      ${
        same
          ? `<div class="sec-h" data-anc><h2>${esc(F.t("scan.live_feed", "Живая лента"))}</h2><span class="muted"
            id="scn-fc">${scan.feed.length}</span><button class="sec-a"
            data-act="go:/p/findings">${esc(F.t("common.all", "Все"))}</button></div>
      <div class="list" id="scn-feed">${
        scan.feed.length
          ? scan.feed
              .slice(0, FEED_MAX)
              .map(f => feedRowHTML(f))
              .join("")
          : feedEmpty()
      }</div>`
          : ""
      }
      <div class="sec-h scn-sh" data-anc><h2>${esc(F.t("scan.sources", "Источники"))}</h2><span class="muted"
        id="scn-ss">${srcSummary()}</span></div>
      <div id="scn-vall">${verifyAllHTML()}</div>
      <div id="scn-dork">${dorksHTML()}</div>
      <div class="list" id="scn-src">${srcListHTML()}</div>
      ${same ? `<div class="list scn-oosl">${oosRow()}</div>` : ""}
    </div>`;
  }

  function patch(page) {
    const scan = F.scan,
      $ = q => page.querySelector(q);
    setHTML($("#scn-hd"), headHTML());
    setHTML($("#scn-ctl"), ctlHTML());
    if ($("#scn-act")) setHTML($("#scn-act"), activeHTML());
    STAGES.forEach((d, k) => {
      const el = $("#scn-st-" + d.id);
      if (!el) return;
      const st = stageStatus(k),
        c = stageCls(st, scan.paused);
      if (el.className !== c) el.className = c;
      setHTML(el, stageHTML(k, st));
    });
    const fl = $("#scn-feed");
    if (fl) {
      const have = new Set([...fl.querySelectorAll("[data-fid]")].map(x => x.dataset.fid));
      const fresh = scan.feed.slice(0, FEED_MAX).filter(f => !have.has(String(f.id)));
      if (fresh.length) {
        if (!have.size) fl.innerHTML = "";
        fl.insertAdjacentHTML("afterbegin", fresh.map(f => feedRowHTML(f, true)).join(""));
        [...fl.querySelectorAll("[data-fid]")].slice(FEED_MAX).forEach(x => x.remove());
      } else if (!scan.feed.length) setHTML(fl, feedEmpty());
      setHTML($("#scn-fc"), String(scan.feed.length));
    }
    const sl = $("#scn-src");
    const vis = visSources();
    if (sl && [...sl.children].map(x => x.id).join() !== vis.map(x => "scn-src-" + x.id).join())
      sl.innerHTML = srcListHTML();
    else vis.forEach(src => setHTML($("#scn-src-" + src.id), srcRowHTML(src)));
    setHTML($("#scn-ss"), srcSummary());
    setHTML($("#scn-vall"), verifyAllHTML());
    setHTML($("#scn-dork"), dorksHTML());
    const oo = $("#scn-oos");
    if (oo) {
      const rowHtml = oosRow();
      if (oo._h !== rowHtml) {
        oo.outerHTML = rowHtml;
        const n = $("#scn-oos");
        if (n) n._h = rowHtml;
      }
    }
    const fb = F.$("#fab");
    if (fb && fb.classList.contains("show")) {
      const act = scan.paused ? "scan-resume" : "scan-pause";
      if (fb.dataset.act !== act) {
        fb.dataset.act = act;
        fb.innerHTML = `${ic(scan.paused ? "play" : "pause")}<span class="fab-l">${esc(scan.paused ? F.t("scan.resume", "Продолжить") : F.t("scan.pause", "Пауза"))}</span>`;
        fb.setAttribute(
          "aria-label",
          scan.paused ? F.t("scan.resume", "Продолжить") : F.t("scan.pause", "Пауза"),
        );
      }
    }
  }

  // ---------- screen when no scan is running ----------
  const resultPill = x =>
    x.status === "done"
      ? `<span class="pill ok">${ic("check")}${esc(F.t("scan.pill_finished", "Завершён"))}</span>`
      : `<span class="pill warn">${ic("stop")}${esc(F.t("scan.pill_stopped_why", { why: reasonOf(x.reason).chip }, "Остановлен: {why}"))}</span>`;
  function historyRow(x) {
    return `<div class="row tap scn-hr"
      data-act="scan-history:${esc(x.id)}">${ui.leadIcon("history", x.active ? "var(--active)" : "")}<div class="body"><div class="t">${esc(x.date)}</div><div class="s">«${esc(profRec(x))}»${x.active ? " · " + esc(F.t("scan.active_lc", "активный")) : ""} · ${fmtMin(x.minutes)} · ${nf(x.findings)}</div><div class="scn-hp">${resultPill(x)}</div></div>${ic("chev", "chev")}</div>`;
  }
  function finishedCard() {
    const scan = F.scan;
    if (!scan.finished || scan.finished.project !== curId()) return "";
    const rec = scanRec(scan.finished.scanId);
    if (!rec) return "";
    return `<div class="card pad" id="scn-fin">
      <div class="scn-h1">${ui.leadIcon("check", "var(--ok)")}<div class="scn-h1b"><div class="scn-tgt">${esc(F.t("scan.finished_title", "Скан завершён"))}</div><div class="scn-h1s">${esc(fmtMin(rec.minutes))} · ${esc(F.t("scan.head_profile", { name: profRec(rec) }, "профиль «{name}»"))}${rec.active ? " · " + esc(F.t("scan.active_lc", "активный")) : ""}</div></div></div>
      <div class="grid g3 scn-g">${[
        [F.t("scan.kv_docs", "Документы"), rec.docs],
        [F.t("scan.findings", "Находки"), rec.findings],
        [F.t("scan.kv_hosts", "Хосты"), rec.hosts],
      ]
        .map(([k, v]) => `<div class="stat"><div class="k">${k}</div><div class="v">${num(v)}</div></div>`)
        .join("")}</div>
      <p class="scn-fnew">${rec.new_findings ? `${ic("bug")}${esc(F.t("scan.new_since", "Новых с прошлого скана:"))} <b>${rec.new_findings}</b>` : `${ic("check")}${esc(F.t("scan.new_since_none", "Новых находок с прошлого скана нет"))}`}</p>
      ${
        (scan.finished.followup || []).length
          ? `<div class="banner info scn-fup">${ic("refresh")}<div>${esc(F.t("scan.followup_note", { n: scan.finished.followup.length }, "Отложенных перезапусков: {n}. Их этапы уже прошли"))}<div class="scn-fup-st">${esc(
              F.t(
                "scan.followup_stages",
                {
                  list: followupStages(scan.finished.followup)
                    .map(x => x.label)
                    .join(", "),
                },
                "Запустятся только этапы: {list}. Остальные будут пропущены",
              ),
            )}</div><div class="btnrow"><button class="btn sm filled"
        data-act="scan-followup">${ic("play")}${esc(F.t("scan.followup_btn", "Повторить отложенное"))}</button></div></div></div>`
          : ""
      }
      <div class="btnrow"><button class="btn primary"
        data-act="go:/p/findings">${ic("bug")}${esc(F.t("scan.findings", "Находки"))}</button><button class="btn"
        data-act="go:/p/reports">${ic("report")}${esc(F.t("scan.report", "Отчёт"))}</button></div></div>`;
  }
  function stoppedCard() {
    const st = stoppedInfo();
    if (!st) return "";
    const R = reasonOf(st.reason);
    return `<div class="card pad scn-stopc">
      <div class="scn-h1">${ui.leadIcon(R.icon, R.color)}<div class="scn-h1b"><div class="scn-tgt">${esc(F.t("scan.stopped_at", { p: st.progress }, "Скан остановлен на {p}%"))}</div><div class="scn-h1s">${esc(R.title)}</div></div></div>
      <div class="pbar scn-hpb paused"><i style="width:${st.progress}%"></i></div>
      <div class="btnrow"><button class="btn primary"
        data-act="scan-continue">${ic("play")}${esc(F.t("scan.resume", "Продолжить"))}</button><button class="btn"
        data-act="go:/p/scan-stopped">${esc(F.t("common.details", "Подробнее"))}</button></div>${delBtn(st.scanId)}</div>`;
  }
  function renderIdle() {
    const hist = (F.db.scans || []).slice().reverse();
    const targets = (F.db.scope || {}).targets || [];
    const top = stoppedCard() || finishedCard();
    return `
      ${top}
      ${dorksHTML()}
      <div class="card pad scn-hero ${top ? "scn-gap" : ""}">
        <div class="scn-hero-ic">${ic("scan")}</div>
        <h3>${esc(F.t("scan.idle_title", "Скан сейчас не идёт"))}</h3>
        <p>${
          targets.length
            ? esc(
                F.t(
                  "scan.idle_targets",
                  {
                    list: targets
                      .slice(0, 3)
                      .map(t => t.v)
                      .join(", "),
                    more:
                      targets.length > 3
                        ? " " + F.t("scan.ctr_and_more", { n: targets.length - 3 }, "и ещё {n}")
                        : "",
                  },
                  "Цели проекта: {list}{more}. Выберите профиль и источники на экране нового скана.",
                ),
              )
            : esc(
                F.t(
                  "scan.idle_no_targets",
                  "В проекте пока нет целей. Добавьте их на экране «Скоуп» или на экране нового скана.",
                ),
              )
        }</p>
        <div class="scn-hero-b">
          <button class="btn primary block" data-act="go:/new">${ic("play")}${esc(F.t("launch.title", "Новый скан"))}</button>
          ${
            targets.length
              ? `<button class="btn block"
            data-act="scan-quick">${ic("shield")}${esc(F.t("scan.quick_passive", "Быстрый пассивный скан"))}</button>`
              : `<button class="btn block"
            data-act="go:/p/scope">${ic("target")}${esc(F.t("launch.scope", "Скоуп"))}</button>`
          }
        </div>
      </div>
      <div class="list scn-oosl">${oosRow()}</div>
      ${ui.secH(F.t("scan.history", "История сканов"), hist.length || "")}
      ${hist.length ? `<div class="list">${hist.map(historyRow).join("")}</div>` : `<p class="lead scn-nohist">${esc(F.t("scan.no_history", "Сканов в этом проекте ещё не было."))}</p>`}`;
  }

  // ---------- route /p/scan ----------
  F.route("/p/scan", {
    title: () => F.t("scan.scan", "Скан"),
    back: true,
    hideMini: true,
    nav: false,
    sub: () => {
      if (!F.scan.running) return F.project ? F.project.name : "";
      if (F.scan.paused) return F.scan.pauseLabel || F.t("scan.on_pause_cap", "На паузе");
      // The mode follows the profile: only a passive profile without the active phase is "passive".
      if (F.scan.active) return F.t("scan.active_mode", "Активный режим");
      if (!F.scan.profileId || F.scan.profileId === "passive")
        return F.t("scan.passive_mode", "Пассивный режим");
      return F.t("scan.profile_mode", { profile: profName() }, "Режим: {profile}");
    },
    actions: () => [{ icon: "more", act: "scan-menu", label: F.t("scan.menu", "Меню скана") }],
    fab: () =>
      F.scan.running && F.demo.mode === "normal"
        ? F.scan.paused
          ? { icon: "play", label: F.t("scan.resume", "Продолжить"), act: "scan-resume", until: ".scn-stop" }
          : { icon: "pause", label: F.t("scan.pause", "Пауза"), act: "scan-pause", until: ".scn-stop" }
        : null,
    render: () =>
      F.withStates(() => (F.scan.running ? renderRun() : renderIdle()), {
        loading: "cards",
        empty: {
          icon: "scan",
          title: F.t("scan.empty_title", "Сканов ещё не было"),
          text: F.t(
            "scan.empty_text",
            "Запустите первый скан: здесь появятся этапы, источники и находки в реальном времени.",
          ),
          action: `<button class="btn primary" data-act="go:/new">${ic("play")}${esc(F.t("launch.title", "Новый скан"))}</button>`,
        },
        error: {
          title: F.t("scan.err_title", "Не удалось получить статус скана"),
          text: F.t(
            "scan.err_text",
            "Фоновая служба не ответила. Скан, возможно, продолжается, попробуйте ещё раз.",
          ),
        },
      }),
    mount() {
      if (F.scan.running) startClock();
    },
    unmount() {
      stopClockIfIdle();
    },
    // Scan and data events: in-place updates instead of a full re-render.
    onData(kind, ev) {
      if (kind === "scan" || kind === "net") refresh();
      else if (kind === "db" && ev.kind !== "scan" && ev.kind !== "project") refresh();
    },
  });

  // ---------- actions ----------
  const apiErr = e => {
    if (e && e.code === "out_of_scope") {
      F.snack(F.coreMsg(e.message, e.message_msg), {
        action: () => F.go("/p/scope"),
        label: F.t("launch.scope", "Скоуп"),
        ms: 8000,
      });
      return;
    }
    if (e && e.code === "busy") {
      F.snack(F.t("scan.already_running", "Скан уже идёт: дождитесь окончания или остановите его"), {
        action: () => F.go("/p/scan"),
        label: F.t("common.open", "Открыть"),
        ms: 6000,
      });
      return;
    }
    F.snack(
      F.t(
        "scan.failed",
        { err: (e && e.message) || F.t("scan.core_error", "ошибка ядра") },
        "Не удалось: {err}",
      ),
    );
  };
  // opts: { profile: "passive"|"std"|"full"|"custom", active, modules[], sources[], targets[], resume_from, open }
  F.actions["scan-start"] = opts => {
    opts = opts && typeof opts === "object" ? opts : {};
    const args = {
      profile: opts.profile || "passive",
      active: !!opts.active,
      modules: opts.modules || [],
      sources: opts.sources || [],
    };
    if (Array.isArray(opts.sources_off) && opts.sources_off.length) args.sources_off = opts.sources_off; // Wizard: the disabled sources; all others are on.
    if (opts.targets) args.targets = opts.targets;
    if (opts.resume_from) args.resume_from = opts.resume_from;
    if (opts.from_stage) args.from_stage = opts.from_stage; // Follow-up run of queued restarts.
    if (Array.isArray(opts.only) && opts.only.length) args.only = opts.only; // Run only the stages of these items.
    if (opts.fuzz && typeof opts.fuzz === "object") args.fuzz = opts.fuzz; // Site file search: modules and rate for this run.
    if (opts.ports && typeof opts.ports === "object") args.ports = opts.ports; // Port scan: top 100/1000 for this run.
    if (opts.subdomains && typeof opts.subdomains === "object") args.subdomains = opts.subdomains; // Brute force wordlist (off/top-1500/top-5000/custom).
    if (opts.crawl && typeof opts.crawl === "object") args.crawl = opts.crawl; // Crawler limits, external storage, continue crawl.
    F.state.scanPending = { targets: opts.targets, modules: opts.modules, resume_from: opts.resume_from };
    return F.api.scan_start(args).then(
      r => {
        if (opts.open && !onScan()) F.go("/p/scan");
        else if (onScan()) F.render(true);
        if (onScan()) startClock();
        return r;
      },
      e => {
        F.state.scanPending = null;
        apiErr(e);
        throw e;
      },
    );
  };
  const safeStart = o => F.actions["scan-start"](o).catch(() => {});
  F.actions["scan-quick"] = () => safeStart({ profile: "passive", open: true });
  F.actions["scan-key"] = key => {
    if (F.openKeySheet) F.openKeySheet(key);
    else {
      F.state.openKey = key;
      F.go("/settings/keys");
    }
  };
  F.actions["scan-open-project"] = () => {
    const id = F.scan.project;
    if (id) F.api.project_open(id).then(() => F.render(true));
  };

  function setPause(on, reason) {
    const scan = F.scan;
    if (!scan.running) return Promise.resolve();
    if (on === scan.paused) {
      if (on) {
        scan.pauseReason = reason || scan.pauseReason;
        derive();
        refresh();
      }
      return Promise.resolve();
    }
    return (on ? F.api.scan_pause() : F.api.scan_resume()).then(() => {
      if (on) {
        scan.paused = true;
        scan.pauseReason = reason || "user";
        scan.pausedAt = Date.now();
      } else {
        scan.paused = false;
        if (scan.pausedAt) scan.pausedMs += Date.now() - scan.pausedAt;
        scan.pausedAt = null;
        scan.pauseReason = null;
      }
      derive();
      refresh();
      F.emit("scan", { type: on ? "paused" : "resumed", reason: scan.pauseReason, local: true });
    });
  }
  F.actions["scan-pause"] = () =>
    setPause(true, "user").then(
      () =>
        F.scan.paused && F.snack(F.t("scan.snack_paused", "Скан на паузе: загрузки и запросы остановлены")),
    );
  F.actions["scan-resume"] = () => {
    if (F.scan.pauseReason === "offline" && F.state.offline) {
      F.snack(F.t("scan.still_offline", "Сети по-прежнему нет: скан продолжится сам, когда она появится"));
      return;
    }
    setPause(false);
  };
  F.actions["scan-changed"] = () => refresh();

  // Network loss → pause (reason offline) and auto-resume; tunnel drop → kill switch.
  F.on("net", ({ online }) => {
    const s = F.scan;
    if (!s.running) return;
    if (!online) {
      if (!s.paused) setPause(true, "offline");
    } else if (s.paused && s.pauseReason === "offline")
      setPause(false).then(() => F.snack(F.t("scan.back_online", "Сеть вернулась: скан продолжен")));
  });
  F.actions["scan-vpn-lost"] = () => {
    const s = F.scan,
      net = settings().net || {};
    if (!s.running) return;
    if (!net.kill_switch) {
      F.snack(
        F.t(
          "scan.ks_off_snack",
          "Защита от утечки IP выключена. Запросы пошли бы с реального IP. Включите его в настройках сети",
        ),
        {
          action: () => F.go("/settings/network"),
          label: F.t("scan.net", "Сеть"),
          ms: 7000,
        },
      );
      return;
    }
    if (s.active || net.kill_action !== "pause") F.api.scan_stop("vpn");
    else setPause(true, "vpn");
  };

  F.actions["scan-stop"] = () => {
    const s = F.scan;
    if (!s.running) return;
    const N = sameProject() ? F.sel.counts() : null;
    F.sheet({
      title: F.t("scan.stop_title", "Остановить скан?"),
      html: `<p class="scn-shp">${esc(F.t("scan.stop_saved", "Собранное сохранится в проекте"))}${N ? `: ${num(N.docs.downloaded)} ${esc(pw(N.docs.downloaded, "scan.pl_file", "файл|файла|файлов"))}, ${esc(nf(N.findings.total))}` : ""}. ${esc(F.t("scan.stop_resume_later", "Продолжить можно позже с места остановки."))}</p>
        <div class="banner">${ic("info")}<div>${esc(F.t("scan.stop_hint", "Если нужно просто прерваться, лучше поставить на паузу."))}</div></div>`,
      footer: `<button class="btn"
        data-act="scan-stop-pause">${ic("pause")}${esc(F.t("scan.pause", "Пауза"))}</button><button class="btn danger hold"
        data-hold="scan-stop-go:user"><span class="hold-fill"></span>${ic("stop")}${esc(F.t("scan.hold_stop", "Удерживайте: стоп"))}</button>`,
    });
  };
  F.actions["scan-stop-pause"] = () => {
    F.closeSheet();
    F.actions["scan-pause"]();
  };
  F.actions["scan-stop-go"] = reason => {
    F.closeSheet();
    if (!F.scan.running) {
      F.snack(F.t("scan.already_done", "Скан уже завершён"));
      return;
    }
    const reasonKey = reason || "user",
      info = reasonOf(reasonKey);
    // Reasons configured to pause (charging, Wi-Fi, tunnel with kill_action=pause) pause rather than stop the
    // scan.
    if (info.pause && F.scan.running) {
      setPause(true, reasonKey);
      return;
    }
    F.api.scan_stop(reasonKey).then(() => {
      if (reasonKey === "user") F.go("/p/scan-stopped/" + reasonKey, { replace: onScan() });
    });
  };

  // Stop details: from the current session or from project history (the latest record with status "stopped").
  function stoppedInfo() {
    const s = F.scan;
    if (s.running) return null;
    const last = F.sel.lastScan();
    if (!last || last.status !== "stopped") return null;
    const local = s.stopped && s.stopped.scanId === last.id ? s.stopped : null;
    const idx = STAGES.findIndex(x => x.id === last.stage);
    return {
      scanId: last.id,
      reason: last.reason || "user",
      progress: last.progress ?? (local ? local.progress : 0),
      stageIdx: idx >= 0 ? idx : local ? local.stageIdx : 0,
      rec: last,
    };
  }
  // Resume and "Start over" run immediately with the CURRENT scope (the wizard filters out-of-scope targets).
  const viaWizard = r => r && (r.active || r.profile_id !== "passive");
  F.actions["scan-continue"] = () => {
    const st = stoppedInfo();
    if (!st) {
      F.go("/new");
      return;
    }
    const rec = st.rec;
    const go = () => {
      if (viaWizard(rec) && F.launchRestart)
        return F.launchRestart({ profile: rec.profile_id, modules: rec.modules, resume_from: rec.id });
      safeStart({ profile: rec.profile_id, active: false, resume_from: rec.id, open: false }).then(res => {
        if (!res) return;
        if (!onScan()) F.go("/p/scan", { replace: !!(F.cur && F.cur.path.startsWith("/p/scan-stopped")) });
        F.snack(F.t("launch.started_resume", "Скан продолжен с места остановки"));
      });
    };
    if (st.reason === "vpn")
      F.api
        .net_check()
        .then(n =>
          n && n.ok ? go() : F.snack(F.t("scan.tunnel_dead", "Туннель не отвечает: продолжить нельзя")),
        );
    else go();
  };
  // "Start over" in a single tap, without an "Are you sure?" sheet (collected data and triage stay in the
  // project).
  F.actions["scan-restart"] = () => F.actions["scan-restart-go"]();
  F.actions["scan-restart-go"] = () => {
    F.closeSheet();
    const last = F.sel.lastScan();
    if (viaWizard(last) && F.launchRestart) {
      F.launchRestart({ profile: last.profile_id, modules: last.modules });
      return;
    }
    safeStart({ profile: last ? last.profile_id : "passive" }).then(r => {
      if (r && !onScan()) F.go("/p/scan", { replace: true });
    });
  };
  F.actions["scan-history"] = id => {
    const rec = scanRec(id);
    if (!rec) return;
    const okS = rec.sources.filter(z => z.status === "ok"),
      bad = rec.sources.filter(z => z.status !== "ok");
    F.sheet({
      title: F.t("scan.scan_date", { date: rec.date }, "Скан {date}"),
      html: `<div class="chips wrap">${resultPill(rec)}${rec.active ? `<span class="pill crit">${ic("alert")}${esc(F.t("scan.active_mode", "Активный режим"))}</span>` : `<span class="pill mute">${esc(profRec(rec) || F.t("launch.profile_passive", "Пассивный"))}</span>`}${rec.trigger === "schedule" ? `<span class="pill mute">${ic("clock")}${esc(F.t("scan.scheduled", "По расписанию"))}</span>` : ""}</div>
        <div class="grid g3 scn-g">${[
          [F.t("scan.findings", "Находки"), rec.findings],
          [F.t("scan.kv_docs", "Документы"), rec.docs],
          [F.t("scan.kv_hosts", "Хосты"), rec.hosts],
        ]
          .map(
            ([k, v]) =>
              `<div class="card stat"><div class="k">${k}</div><div class="v">${num(v)}</div></div>`,
          )
          .join("")}</div>
        <div class="kv">
          <div class="kvr"><div class="k">${esc(F.t("scan.kv_profile", "Профиль"))}</div><div class="v">${esc(profRec(rec))}</div></div>
          <div class="kvr"><div class="k">${esc(F.t("scan.kv_duration", "Длительность"))}</div><div class="v">${esc(fmtMin(rec.minutes))}</div></div>
          <div class="kvr"><div class="k">${esc(F.t("scan.kv_new_findings", "Новых находок"))}</div><div class="v">${rec.new_findings}</div></div>
          <div class="kvr"><div class="k">${esc(F.t("scan.kv_targets", "Цели"))}</div><div class="v">${esc(rec.targets.join(", ") || "-")}</div></div>
          <div class="kvr"><div class="k">${esc(F.t("scan.sources", "Источники"))}</div><div class="v">${esc(F.t("scan.kv_src_ok", { ok: okS.length, n: rec.sources.length }, "{ok} из {n} OK"))}${bad.length ? " · " + esc(F.t("scan.kv_src_bad", { list: bad.map(sn).join(", ") }, "без ключа или с ошибкой: {list}")) : ""}</div></div>
          <div class="kvr"><div class="k">${esc(F.t("scan.egress", "Выходной IP"))}</div><div class="v">${esc(rec.egress)}</div></div>
        </div>
        ${delBtn(rec.id)}`,
      footer: `<button class="btn" data-act="sheet-close">${esc(F.t("common.close", "Закрыть"))}</button><button class="btn primary"
        data-act="go:/p/findings">${ic("bug")}${esc(F.t("scan.findings", "Находки"))}</button>`,
    });
  };
  // ---------- delete one scan (scan_delete) ----------
  // The sheet shows what goes, from a dry run of the core; results a later scan also has stay.
  const delCounts = r =>
    [
      [F.t("scan.kv_docs", "Документы"), r.docs],
      [F.t("scan.findings", "Находки"), r.findings],
      [F.t("scan.kv_hosts", "Хосты"), r.hosts],
      [F.t("scan.del_requests", "Записи журнала"), r.requests],
    ]
      .map(
        ([k, n]) =>
          `<div class="kvr"><div class="k">${esc(k)}</div><div class="v">${num(n || 0)}</div></div>`,
      )
      .join("");
  F.actions["scan-del"] = id => {
    const rec = scanRec(id);
    const live = F.scan.running && F.scan.scanId === id;
    const title = rec
      ? F.t("scan.delete_scan_date", { date: rec.date }, "Удалить скан {date}?")
      : F.t("scan.delete_scan_q", "Удалить скан?");
    const open = counts =>
      F.sheet({
        cls: "la-sheet scn-del-sh",
        title,
        html: `<div class="banner crit">${ic("alert")}<div>${esc(live ? F.t("scan.delete_running_text", "Скан будет остановлен и стёрт вместе со всем, что он успел найти: документами и их файлами, находками, хостами и журналом запросов. Отменить нельзя.") : F.t("scan.delete_text", "Скан будет стёрт вместе со всем, что нашёл только он: документами и их файлами, находками, хостами и журналом запросов. Отменить нельзя."))}</div></div>
          ${counts ? `<div class="kv scn-del-g">${delCounts(counts)}</div>` : ""}
          <p class="pj-sh-sub">${esc(F.t("scan.delete_keeps", "То, что нашли и другие сканы, останется вместе с вашими заметками и статусами."))}</p>
          <p class="pj-sh-sub">${esc(F.t("scan.delete_hold", "Чтобы удалить, удерживайте кнопку «Удалить» 1-2 секунды."))}</p>`,
        footer: `<button class="btn"
          data-act="sheet-close">${esc(F.t("common.cancel", "Отмена"))}</button><button class="btn danger hold"
          data-hold="scan-del-go:${esc(id)}"><span class="hold-fill"></span>${ic("trash")}${esc(F.t("common.delete", "Удалить"))}</button>`,
      });
    if (F.closeSheet) F.closeSheet();
    F.api.scan_delete(id, true).then(open, () => open(null));
  };
  F.actions["scan-del-go"] = id => {
    F.closeSheet();
    const s = F.scan;
    F.api.scan_delete(id).then(
      r => {
        if (s.scanId === id) Object.assign(s, { running: false, paused: false, stopped: null });
        if (s.stopped && s.stopped.scanId === id) s.stopped = null;
        if (s.finished && s.finished.scanId === id) s.finished = null;
        if (F.cur && F.cur.path.startsWith("/p/scan-stopped")) F.go("/p/scan", { replace: true });
        else F.render(true);
        F.updateChrome();
        F.snack(
          F.t(
            "scan.deleted_snack",
            { docs: r.docs || 0, findings: r.findings || 0 },
            "Скан удалён: документов {docs}, находок {findings}",
          ),
        );
      },
      e =>
        F.snack(
          F.t("scan.delete_failed", "Не удалось удалить скан: ") + F.coreMsg(e.message || e, e.message_msg),
        ),
    );
  };
  F.actions["scan-menu"] = () => {
    const scan = F.scan;
    F.sheet({
      html: `
        <div class="srow"
          data-act="go:/p/out-of-scope">${ic("link")}<span class="lbl">${esc(F.t("scan.oos_title", "Кандидаты вне скоупа"))}<small>${esc(F.t("scan.n_new", { n: oosNew() }, "новых: {n}"))}</small></span></div>
        <div class="srow" data-act="go:/p/scope">${ic("target")}<span class="lbl">${esc(F.t("launch.scope", "Скоуп"))}</span></div>
        ${
          scan.running && F.isDemo
            ? `
        <div class="srow"
          data-act="scan-demo-stop">${ic("battery")}<span class="lbl">${esc(F.t("scan.demo_stop", "Демо: прервать скан"))}<small>${esc(F.t("scan.demo_stop_sub", "Android, заряд, Wi-Fi, туннель, ошибка"))}</small></span></div>
        <div class="srow"
          data-act="scan-demo-offline">${ic("wifi-off")}<span class="lbl">${esc(F.state.offline ? F.t("scan.demo_online", "Демо: сеть вернулась") : F.t("scan.demo_offline", "Демо: пропала сеть"))}<small>${esc(F.state.offline ? F.t("scan.demo_online_sub", "Скан продолжится сам") : F.t("scan.demo_offline_sub", "Скан встанет на паузу"))}</small></span></div>
        <div class="srow"
          data-act="scan-demo-vpn">${ic("shield")}<span class="lbl">${esc(F.t("scan.demo_vpn", "Демо: обрыв туннеля"))}<small>${esc(F.t("scan.demo_vpn_sub", "Срабатывает защита от утечки IP"))}</small></span></div>`
            : scan.running
              ? ""
              : `
        <div class="srow"
          data-act="go:/p/scan-stopped">${ic("stop")}<span class="lbl">${esc(F.t("scan.stop_reasons", "Причины остановки"))}<small>${esc(F.isDemo ? F.t("scan.stop_reasons_demo", "Как выглядит экран остановки") : F.t("scan.stop_reasons_last", "Последняя остановка скана"))}</small></span></div>`
        }
        <div class="srow"
          data-act="menu">${ic("more")}<span class="lbl">${esc(F.t("scan.main_menu", "Общее меню"))}<small>${esc(F.isDemo ? F.t("scan.main_menu_demo", "Тема, демо-состояния, настройки") : F.t("scan.main_menu_sub", "Проекты, тема, настройки"))}</small></span></div>`,
    });
  };
  F.actions["scan-demo-offline"] = () => {
    F.closeSheet();
    F.setOffline(!F.state.offline);
  };
  F.actions["scan-demo-vpn"] = () => {
    F.closeSheet();
    F.actions["scan-vpn-lost"]();
  };
  F.actions["scan-demo-stop"] = () => {
    F.sheet({
      title: F.t("scan.demo_reason", "Демо: причина остановки"),
      html: REASON_KEYS.map(k => {
        const R = reasonOf(k);
        return `<div class="srow"
          data-act="scan-stop-go:${k}">${ic(R.icon)}<span class="lbl">${esc(R.title)}<small>${esc(R.pause ? F.t("scan.by_settings_pause", "По настройкам: пауза") : F.t("scan.stop_word", "Остановка"))}</small></span></div>`;
      }).join(""),
    });
  };

  // ---------- /p/scan-stopped ----------
  function renderStopped(params) {
    const st = stoppedInfo();
    if (!st && !F.isDemo)
      return ui.empty({
        icon: "scan",
        title: F.t("scan.no_stopped", "Остановленных сканов нет"),
        text: F.sel.lastScan()
          ? F.t("scan.last_ok", "Последний скан проекта завершился штатно, продолжать нечего.")
          : F.t("scan.no_scans_yet", "В этом проекте сканов ещё не было."),
        action: `<button class="btn primary" data-act="go:/p/scan">${ic("scan")}${esc(F.t("scan.scan_screen", "Экран скана"))}</button>`,
      });
    if (!st) {
      // Demo: the project has no stopped scan, so show what the screen looks like for the selected reason.
      const k = REASON_KEYS.includes(params.reason) ? params.reason : F.state.stopPreview || "vpn",
        info = reasonOf(k);
      return `
        <div class="scn-demo"><span class="muted">${esc(F.t("scan.demo_example", "Пример экрана причина остановки:"))}</span><div class="chips wrap">${REASON_KEYS.map(
          key => `<button class="chip ${key === k ? "on" : ""}"
          data-act="scan-reason:${key}">${esc(reasonOf(key).chip)}</button>`,
        ).join("")}</div></div>
        <div class="card pad scn-why" style="--why:${info.color}">
          <div class="scn-why-ic">${ic(info.icon)}</div><h3>${esc(info.title)}</h3><p>${esc(info.text)}</p>
          ${info.code ? `<div class="scn-code mono">${esc(info.code)}</div>` : ""}
          <div class="banner info scn-vb">${ic("info")}<div>${esc(F.sel.lastScan() ? F.t("scan.last_ok_stop", "Последний скан проекта завершился штатно, останавливать нечего.") : F.t("scan.no_scans_yet", "В этом проекте сканов ещё не было."))}</div></div>
          <div class="scn-acts"><button class="btn primary block"
            data-act="go:/p/scan">${ic("scan")}${esc(F.t("scan.scan_screen", "Экран скана"))}</button></div>
        </div>`;
    }
    const info = reasonOf(st.reason),
      rec = st.rec;
    const extra =
      {
        android: `<button class="btn" data-act="go:/settings/battery">${ic("battery")}${esc(F.t("scan.bg_work", "Работа в фоне"))}</button>`,
        budget: `<button class="btn" data-act="go:/settings/battery">${ic("battery")}${esc(F.t("scan.bg_work", "Работа в фоне"))}</button>`,
        workmanager: `<button class="btn" data-act="go:/settings/battery">${ic("battery")}${esc(F.t("scan.bg_work", "Работа в фоне"))}</button>`,
        restart: `<button class="btn"
          data-act="go:/settings/battery">${ic("battery")}${esc(F.t("scan.bg_work", "Работа в фоне"))}</button><button class="btn"
          data-act="scan-autostart">${ic("gear")}${esc(F.t("scan.autostart", "Автозапуск"))}</button>`,
        battery: `<button class="btn"
          data-act="go:/settings/power">${ic("battery")}${esc(F.t("scan.power_settings", "Настройки питания"))}</button>`,
        wifi: `<button class="btn" data-act="go:/settings/power">${ic("gear")}${esc(F.t("scan.traffic_settings", "Настройки трафика"))}</button>`,
        vpn: `<button class="btn" data-act="go:/settings/network">${ic("shield")}${esc(F.t("scan.net_settings", "Настройки сети"))}</button>`,
        user: "",
        error: `<button class="btn"
          data-act="copy:${esc(info.code || "")}">${ic("copy")}${esc(F.t("scan.copy_error", "Скопировать ошибку"))}</button>`,
      }[st.reason] || "";
    const view = STAGES.map((d, j) =>
      notSelected(j, rec.stages) ? "sel" : j < st.stageIdx ? "done" : j === st.stageIdx ? "cut" : "none",
    );
    const okS = rec.sources.filter(z => z.status === "ok").length;
    return `
      <div class="card pad scn-why" style="--why:${info.color}">
        <div class="scn-why-ic">${ic(info.icon)}</div>
        <h3>${esc(info.title)}</h3>
        <p>${esc(info.text)}</p>
        ${info.code ? `<div class="scn-code mono">${esc(info.code)}</div>` : ""}
        <div class="scn-when">${ic("clock")}<span>${esc(F.t("scan.stopped_when", { date: rec.date, dur: fmtMin(rec.minutes), stage: STAGES[Math.max(0, st.stageIdx)].label, p: st.progress }, "Остановлен {date} · через {dur} после запуска · на этапе «{stage}», {p}%"))}</span></div>
        <div class="scn-acts">
          <button class="btn primary block"
            data-act="scan-continue">${ic("play")}${esc(F.t("scan.resume_from_stop", "Продолжить с места остановки"))}</button>
          ${extra ? `<div class="btnrow">${extra}</div>` : ""}
          ${st.reason === "restart" ? `<div class="banner info scn-pin">${ic("info")}<div>${esc(F.t("scan.xiaomi_pin", "На Xiaomi (HyperOS/MIUI) смахивание из «Недавних» останавливает скан. Включите «Скрывать из „Недавних“ во время скана» в Настройках › Работа в фоне или закрепите карточку: зажмите её и нажмите замок."))}</div></div>` : ""}
          <button class="btn text block" data-act="scan-restart">${ic("refresh")}${esc(F.t("scan.restart", "Начать заново"))}</button>
          ${delBtn(st.scanId)}
        </div>
      </div>
      ${ui.secH(F.t("scan.done_so_far", "Что успели"), "", `<span class="muted scn-sgh">${esc(F.t("scan.this_scan", "за этот скан"))}</span>`)}
      <div class="grid g2 scn-sg">${[
        [F.t("scan.new_docs", "Новых документов"), num((rec.added || {}).docs || 0)],
        [F.t("scan.kv_new_findings", "Новых находок"), num((rec.added || {}).findings || 0)],
        [F.t("scan.new_hosts", "Новых хостов"), num((rec.added || {}).hosts || 0)],
        [F.t("scan.src_ok", "Источников OK"), okS + "/" + rec.sources.length],
      ]
        .map(([a, b]) => `<div class="card stat"><div class="k">${a}</div><div class="v">${b}</div></div>`)
        .join("")}</div>
      ${ui.secH(F.t("scan.stages", "Этапы"))}
      <div class="card scn-steps">${view.map((x, j) => `<div class="${stageCls(x, false)}">${stageHTML(j, x, { static: true, counters: [] })}</div>`).join("")}</div>`;
  }
  const stoppedDef = {
    title: () => F.t("scan.stopped_title", "Скан остановлен"),
    back: true,
    nav: false,
    hideMini: true,
    actions: [],
    render: p =>
      F.withStates(() => renderStopped(p), {
        loading: "cards",
        empty: {
          icon: "check",
          title: F.t("scan.not_interrupted", "Скан не прерывался"),
          text: F.t("scan.last_normal", "Последний скан завершился штатно."),
          action: `<button class="btn tonal" data-act="go:/p/scan">${esc(F.t("scan.scan_screen", "Экран скана"))}</button>`,
        },
      }),
  };
  F.route("/p/scan-stopped", stoppedDef);
  F.route("/p/scan-stopped/:reason", stoppedDef);
  F.actions["scan-autostart"] = () =>
    F.api.platform_battery_settings("автозапуск").then(
      r => {
        if (r && r.demo)
          F.snack(F.t("scan.demo_autostart", "Демо: откроется экран автозапуска MIUI/HyperOS"));
        else if (r && r.stub)
          F.snack(F.t("scan.stub_autostart", "Стенд: автозапуск открывается только на телефоне"));
      },
      e =>
        F.snack(
          F.t("scan.settings_open_err", { err: e.message || e }, "Не удалось открыть настройки: {err}"),
        ),
    );
  F.actions["scan-reason"] = k => {
    F.state.stopPreview = k;
    if (F.cur.p.reason) F.go("/p/scan-stopped/" + k, { replace: true });
    else F.render(true);
  };

  // ---------- /p/out-of-scope ----------
  F.state.oosTab = F.state.oosTab || "new";
  // Bulk scope extension: out-of-scope host names (CT, documents, SAN) can be selected and added to the scope
  // with one action, followed by a scan of only those names. CDN/cloud/shared-hosting addresses are added as
  // names only: the core keeps their IPs out of the port scan (scope_add_hosts → no_probe).
  F.state.oosSel = F.state.oosSel || [];
  const oosSel = () => F.state.oosSel;
  const OOS_IP = /^\d{1,3}(\.\d{1,3}){3}$/;
  const bulkOk = c =>
    c.decision === "new" && !c.blocked && !OOS_IP.test(c.host) && /^[a-z0-9-]+(\.[a-z0-9-]+)+$/i.test(c.host);
  // Registrable part of the project domain (example.com, example.com.ua).
  const mainDomain = () => {
    const p = F.db.project || {};
    const parts = String(p.domain || p.name || "")
      .toLowerCase()
      .replace(/^www\./, "")
      .split(".")
      .filter(Boolean);
    if (parts.length <= 2) return parts.join(".");
    const sld = parts[parts.length - 2];
    const cc = parts[parts.length - 1].length === 2;
    return cc && ["com", "net", "org", "gov", "edu", "co", "ac", "in"].includes(sld)
      ? parts.slice(-3).join(".")
      : parts.slice(-2).join(".");
  };
  const subOfMain = h => {
    const m = mainDomain();
    return !!m && (h === m || h.endsWith("." + m));
  };
  function bulkBarHTML(cands) {
    const ok = cands.filter(bulkOk);
    if (!ok.length) return "";
    const subs = ok.filter(c => subOfMain(c.host));
    const sel = oosSel().filter(h => ok.some(c => c.host === h));
    F.state.oosSel = sel;
    return `<div class="card pad scn-bulk">
      <div class="scn-bulk-t">${esc(F.t("oos.bulk.title", "Массовое добавление"))} · ${esc(F.t("oos.bulk.selected", { n: sel.length }, "выбрано {n}"))}</div>
      <div class="btnrow">${
        subs.length
          ? `<button class="btn sm tonal" data-act="oos-sel-all">${ic("check")}${esc(F.t("oos.bulk.all", { d: mainDomain() }, "Все поддомены {d}"))} · ${subs.length}</button>`
          : ""
      }${sel.length ? `<button class="btn sm" data-act="oos-sel-none">${esc(F.t("oos.bulk.none", "Снять выбор"))}</button>` : ""}<button class="btn sm primary" data-act="oos-bulk" ${sel.length ? "" : "disabled"}>${ic("plus")}${esc(F.t("oos.bulk.go", "В скоуп и сканировать"))}</button></div></div>`;
  }
  function oosItemHTML(cand) {
    const [kl, ki] = OOS_KIND[cand.kind] || [F.t("scan.oos_link", "Ссылка"), "link"];
    // Infrastructure candidates name their source (certificate SAN, O=, Microsoft 365 tenant…); no request
    // was ever sent to them.
    const src = cand.source && F.infra ? F.infra.OOS_SRC[cand.source] || cand.source : "";
    const acts =
      cand.decision === "new"
        ? `${
            cand.blocked
              ? ""
              : `<button class="btn sm tonal"
          data-act="oos-add:${cand.id}">${ic("plus")}${esc(F.t("scan.oos_to_scope", "В скоуп"))}</button>`
          }<button class="btn sm"
          data-act="oos-ignore:${cand.id}">${ic("eye-off")}${esc(F.t("scan.oos_ignore", "Игнорировать"))}</button>`
        : `<button class="btn sm" data-act="oos-reset:${cand.id}">${ic("refresh")}${esc(F.t("scan.oos_reset", "Вернуть в новые"))}</button>`;
    const pick = bulkOk(cand)
      ? `<div class="scn-opick">${ui.check(oosSel().includes(cand.host), F.t("oos.bulk.pick", "Выбрать"), `oos-sel:${cand.id}`)}</div>`
      : "";
    return `<div class="card pad scn-oos">${pick}
      <div class="scn-oh">${ui.leadIcon(ki, cand.own ? "var(--warn)" : "")}<div class="scn-ob"><div class="scn-ohost mono">${esc(cand.host)}</div><div class="scn-okind"><span class="pill ${cand.own ? "warn" : "mute"}">${esc(kl)}</span>${src ? `<span class="pill info scn-osrc">${esc(src)}</span><span class="pill warn scn-ounchk">${ic("shield")}${esc(F.t("scan.oos_unchecked", "Не проверялся, вне скоупа"))}</span>` : ""}${cand.own ? `<span class="pill info">${ic("check")}${esc(F.t("scan.oos_own", "Связь с заказчиком"))}</span>` : ""}${cand.decision === "scope" ? `<span class="pill ok">${ic("check")}${esc(F.t("scan.oos_in_scope", "В скоупе"))}</span>` : cand.decision === "ignored" ? `<span class="pill mute">${ic("eye-off")}${esc(F.t("scan.oos_ignored_one", "Игнорируется"))}</span>` : ""}</div></div></div>
      <div class="scn-owhy">${ic("info")}<span>${esc(F.coreMsg(cand.why, cand.why_msg))}</span></div>
      <div class="scn-ohint">${esc(F.coreMsg(cand.hint, cand.hint_msg))}</div>
      ${
        cand.blocked && cand.decision === "new"
          ? `<div class="banner crit scn-oblk">${ic("la-ban")}<div>${esc(F.coreMsg(cand.blocked, cand.blocked_msg))}${
              cand.finding
                ? ` <button class="btn text sm"
        data-act="go:/p/finding/${cand.finding}">${esc(F.t("scan.open_finding", "Открыть находку"))}</button>`
                : ""
            }</div></div>`
          : ""
      }
      <div class="btnrow">${acts}</div></div>`;
  }
  function renderOOS() {
    const tab = F.state.oosTab,
      cands = oosList(),
      cnt = k => cands.filter(o => o.decision === k).length;
    const items = cands.filter(o => o.decision === tab);
    const labels = {
      new: F.t("scan.oos_tab_new", "Новые"),
      scope: F.t("scan.oos_tab_scope", "Добавлены"),
      ignored: F.t("scan.oos_tab_ignored", "Игнорируемые"),
    };
    if (!cands.length)
      return ui.empty({
        icon: "link",
        title: F.t("scan.oos_none_title", "Кандидатов нет"),
        text: F.sel.lastScan()
          ? F.t(
              "scan.oos_none_text",
              "Скан не нашёл ссылок, редиректов, CNAME или сетей за пределами скоупа.",
            )
          : F.t("scan.oos_after_first", "Кандидаты появятся после первого скана."),
      });
    return `
      <p class="lead">${esc(F.t("scan.oos_lead", "Найдено при скане, но за пределами скоупа: редиректы, CNAME, адреса хостов (по одному IP, сеть целиком не предлагается) и ссылки на чужие домены. Активные модули к ним не обращаются, пока вы не добавите их в скоуп."))}</p>
      <div class="seg scn-seg">${Object.entries(labels)
        .map(
          ([k, l]) =>
            `<button class="${tab === k ? "on" : ""}" data-act="oos-tab:${k}">${l} · ${cnt(k)}</button>`,
        )
        .join("")}</div>
      ${tab === "new" ? bulkBarHTML(items) : ""}
      ${items.length ? items.map(oosItemHTML).join("") : ui.empty({ icon: tab === "new" ? "check" : "link", title: tab === "new" ? F.t("scan.oos_all_done", "Все кандидаты разобраны") : F.t("scan.oos_empty", "Здесь пока пусто"), text: tab === "new" ? F.t("scan.oos_next_scan", "Новые появятся во время следующего скана.") : "" })}`;
  }
  F.route("/p/out-of-scope", {
    title: () => F.t("scan.oos_route", "Вне скоупа"),
    back: true,
    nav: false,
    live: (kind, ev) => kind === "db" && ev.kind === "scan",
    render: () =>
      F.withStates(renderOOS, {
        empty: {
          icon: "link",
          title: F.t("scan.oos_none_title", "Кандидатов нет"),
          text: F.t("scan.oos_none_text2", "Скан не нашёл ссылок, редиректов или CNAME за пределами скоупа."),
        },
      }),
  });
  F.actions["oos-tab"] = k => {
    F.state.oosTab = k;
    F.render(true);
  };
  F.actions["oos-sel"] = id => {
    const c = oosList().find(x => x.id === id);
    if (!c || !bulkOk(c)) return;
    const sel = oosSel();
    F.state.oosSel = sel.includes(c.host) ? sel.filter(h => h !== c.host) : sel.concat(c.host);
    F.render(true);
  };
  F.actions["oos-sel-all"] = () => {
    F.state.oosSel = oosList()
      .filter(c => bulkOk(c) && subOfMain(c.host))
      .map(c => c.host);
    F.render(true);
  };
  F.actions["oos-sel-none"] = () => {
    F.state.oosSel = [];
    F.render(true);
  };
  const BULK_PROF = [
    ["passive", "Пассивный"],
    ["std", "Стандартный"],
    ["full", "Полный"],
  ];
  function bulkSheet() {
    const plan = F.state.oosPlan;
    if (!plan) return;
    const prof = F.state.oosBulkProf || "std";
    const list = (arr, fn, max = 20) =>
      arr.slice(0, max).map(fn).join("") +
      (arr.length > max
        ? `<div class="row"><div class="body"><div class="s">${esc(F.t("oos.bulk.more", { n: arr.length - max }, "… ещё {n}"))}</div></div></div>`
        : "");
    const added = plan.added || [],
      skipped = plan.skipped || [],
      np = plan.no_probe || [];
    const html = `
      <div class="scn-bulk-s">${esc(F.t("oos.bulk.add_n", { n: added.length }, "Будут добавлены в скоуп: {n}"))}</div>
      <div class="list scn-bulk-l">${list(added, h => `<div class="row"><div class="body"><div class="t mono">${esc(h)}</div></div></div>`)}</div>
      ${
        np.length
          ? `<div class="banner info scn-gap scn-bulk-cdn">${ic("server")}<div><b>${esc(F.t("oos.bulk.cdn_t", "Без скана портов"))}</b>: ${esc(F.t("oos.bulk.cdn_d", "адреса CDN, облака или общего хостинга принадлежат не заказчику: имена добавятся в скоуп, а сами IP не сканируются."))}
          <div class="list">${list(np, x => `<div class="row"><div class="body"><div class="t mono">${esc(x.ip)}</div><div class="s">${esc(F.coreMsg(x.reason, x.reason_msg))} · ${esc(x.host)}</div></div></div>`, 10)}</div></div></div>`
          : ""
      }
      ${
        skipped.length
          ? `<div class="scn-bulk-s">${esc(F.t("oos.bulk.skip_n", { n: skipped.length }, "Пропущены: {n}"))}</div>
          <div class="list">${list(skipped, x => `<div class="row"><div class="body"><div class="t mono">${esc(x.host)}</div><div class="s">${esc(F.coreMsg(x.reason, x.reason_msg))}</div></div></div>`, 10)}</div>`
          : ""
      }
      <div class="scn-bulk-s">${esc(F.t("oos.bulk.profile", "Профиль скана"))}</div>
      <div class="seg scn-seg">${BULK_PROF.map(([k, l]) => `<button class="${prof === k ? "on" : ""}" data-act="oos-bprof:${k}">${esc(F.t("oos.bulk.prof_" + k, l))}</button>`).join("")}</div>
      ${
        prof === "full"
          ? `<div class="banner warn scn-gap">${ic("alert")}<div><b>${esc(F.t("oos.bulk.active_t", "Профиль «Полный» включает активную фазу."))}</b> ${esc(F.t("oos.bulk.active_d", "Порты, файлы на сайтах, AXFR и NSEC. Это заметно для владельцев целей."))}</div></div>
        <div class="card">${ui.check(false, esc(F.t("oos.bulk.consent", "У меня есть разрешение владельцев на активную проверку этих целей")), "oos-bcons")}</div>`
          : `<div class="banner warn scn-gap">${ic("alert")}<div>${esc(F.t("oos.bulk.owner", "Добавляйте только то, на что есть разрешение владельца."))}</div></div>`
      }`;
    F.sheet({
      title: F.t("oos.bulk.sheet", "Добавить в скоуп и сканировать?"),
      html,
      footer: `<button class="btn" data-act="sheet-close">${esc(F.t("oos.bulk.cancel", "Отмена"))}</button><button class="btn primary" id="oos-bgo"
        data-act="oos-bulk-go" ${!added.length || prof === "full" ? "disabled" : ""}>${ic("plus")}${esc(F.t("oos.bulk.confirm", "Добавить и сканировать"))}</button>`,
    });
  }
  F.actions["oos-bulk"] = () => {
    const hosts = oosSel().slice();
    if (!hosts.length) return;
    F.api.scope_add_hosts(hosts, true).then(plan => {
      F.state.oosPlan = { ...plan, hosts };
      bulkSheet();
    }, apiErr);
  };
  F.actions["oos-bprof"] = k => {
    F.state.oosBulkProf = k;
    bulkSheet();
  };
  F.actions["oos-bcons"] = (_, el) => {
    el.classList.toggle("on");
    el.setAttribute("aria-checked", el.classList.contains("on"));
    const b = document.getElementById("oos-bgo");
    if (b) b.disabled = !el.classList.contains("on") || !((F.state.oosPlan || {}).added || []).length;
  };
  F.actions["oos-bulk-go"] = () => {
    const plan = F.state.oosPlan;
    if (!plan) return;
    const prof = F.state.oosBulkProf || "std";
    F.closeSheet();
    F.api.scope_add_hosts(plan.hosts).then(r => {
      F.state.oosSel = [];
      F.state.oosPlan = null;
      const n = (r.added || []).length;
      F.render(true);
      if (!n) {
        F.snack(F.t("oos.bulk.nothing", "Нечего добавлять: все имена уже в скоупе или в исключениях"));
        return;
      }
      if (F.scan && F.scan.running) {
        F.snack(
          F.t("oos.bulk.busy", { n }, "Добавлено в скоуп: {n}. Скан уже идёт: запустите новый после него"),
          {
            ms: 7000,
          },
        );
        return;
      }
      F.snack(F.t("oos.bulk.started", { n }, "Добавлено в скоуп: {n} · скан запущен"));
      return safeStart({ profile: prof, active: prof === "full", targets: r.added, open: true });
    }, apiErr);
  };
  F.actions["oos-add"] = id => {
    const o = oosList().find(x => x.id === id);
    if (!o || o.blocked) return;
    F.sheet({
      title: F.t("scan.oos_add_title", "Добавить в скоуп?"),
      html: `<div class="kv"><div class="kvr"><div class="k">${esc(F.t("scan.oos_addr", "Адрес"))}</div><div class="v mono">${esc(o.host)}</div></div><div class="kvr"><div class="k">${esc(F.t("scan.oos_why", "Причина"))}</div><div class="v">${esc(F.coreMsg(o.why, o.why_msg))}</div></div></div>
        <div class="banner warn scn-gap">${ic("alert")}<div>${esc(F.t("oos.bulk.owner", "Добавляйте только то, на что есть разрешение владельца."))}${o.own ? "" : ` <b>${esc(F.t("scan.oos_owner_unconfirmed", "Владелец не подтверждён."))}</b>`}</div></div>${o.shared ? `<div class="banner warn scn-gap">${ic("server")}<div><b>${esc(F.t("scan.oos_shared_t", "Возможен общий хостинг."))}</b> ${esc(F.t("scan.oos_shared_d", { host: o.host }, "На этом IP могут работать сайты других владельцев. Добавится только адрес {host}, не сеть."))}</div></div>` : ""}`,
      footer: `<button class="btn" data-act="sheet-close">${esc(F.t("common.cancel", "Отмена"))}</button><button class="btn primary"
        data-act="oos-add-go:${id}">${ic("plus")}${esc(F.t("common.add", "Добавить"))}</button>`,
    });
  };
  F.actions["oos-add-go"] = id => {
    F.closeSheet();
    const cand = oosList().find(x => x.id === id);
    if (!cand) return;
    const prev = (F.db.scope.targets || []).slice();
    // A single core command: decision + adding the target to the scope; exclusions take precedence.
    F.api.oos_add_to_scope(id).then(() => {
      F.render(true);
      F.snack(F.t("scan.oos_added", { host: cand.host }, "{host} добавлен в скоуп"), {
        action: () =>
          F.api
            .scope_set({ targets: prev })
            .then(() => F.api.oos_decide(id, "new"))
            .then(() => F.render(true)),
      });
    }, apiErr);
  };
  F.actions["oos-ignore"] = id =>
    F.api.oos_decide(id, "ignored").then(() => {
      F.render(true);
      F.snack(F.t("scan.oos_hidden", "Кандидат скрыт"), {
        action: () => F.api.oos_decide(id, "new").then(() => F.render(true)),
      });
    });
  F.actions["oos-reset"] = id => {
    const o = oosList().find(x => x.id === id);
    if (!o) return;
    const back = () => F.api.oos_decide(id, "new").then(() => F.render(true));
    if (o.decision === "scope")
      F.api.scope_set({ targets: (F.db.scope.targets || []).filter(t => t.v !== o.host) }).then(back);
    else back();
  };

  // For QA: run n scan steps instantly (demo backend only).
  F.scanDemo = {
    ff: n => (demoBackend && demoBackend._ff ? demoBackend._ff(n) : null),
    stop: r => F.api.scan_stop(r || "user"),
  };
})();
