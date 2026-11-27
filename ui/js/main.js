// FOCA-rs application shell: projects, tabs, Overview, global search, the ⋮ menu and demo states.
(function () {
  const F = window.FOCA,
    { ic, esc, ui } = F;
  // The current project and all of its data live in F.db (js/api.js); derived numbers come from F.sel
  // (js/sel.js). F.project is a getter alias.
  const plural = (n, one, few, many) => F.plural(n, one, few, many);

  // Tabs inside a project (order and set are defined here).
  F.setTabs([
    { id: "overview", path: "/p/overview", icon: "home", label: () => F.t("nav.overview", "Обзор") },
    { id: "findings", path: "/p/findings", icon: "bug", label: () => F.t("nav.findings", "Находки") },
    { id: "data", path: "/p/data", icon: "db", label: () => F.t("nav.data", "Данные") },
    { id: "reports", path: "/p/reports", icon: "report", label: () => F.t("nav.reports", "Отчёты") },
  ]);

  F.defaultActions = [{ icon: "more", act: "menu", label: () => F.t("app.menu", "Меню") }];

  // ---------- ⋮ menu ----------
  // Base list of menu items; screens extend it via F.menuItems.push({...}) with the desired `order`.
  const isDark = () => document.documentElement.dataset.theme === "dark";
  F.menuItems.push(
    {
      id: "projects",
      order: 10,
      icon: "folder",
      label: () => F.t("menu.projects", "Все проекты"),
      sub: () => F.t("menu.projects_sub", "Сменить проект"),
      act: "go:/projects",
      // Not offered on the Projects screen itself.
      show: () => F.current() !== "/projects",
    },
    {
      id: "scope",
      order: 20,
      icon: "target",
      label: () => F.t("menu.scope", "Скоуп"),
      act: "go:/p/scope",
      show: () => !!F.project,
    },
    {
      id: "rules",
      order: 25,
      icon: "filter",
      label: () => F.t("menu.rules", "Правила поиска"),
      sub: () => F.t("menu.rules_sub", "Свои шаблоны и готовые наборы"),
      act: "go:/p/rules",
      show: () => !!F.project,
    },
    {
      id: "offline",
      order: 30,
      icon: "folder",
      label: () => F.t("menu.offline", "Разобрать файлы без сети"),
      sub: () => F.t("menu.offline_sub", "Папка, файлы или ZIP с телефона"),
      act: "go:/import",
    },
    {
      id: "settings",
      order: 50,
      icon: "gear",
      label: () => F.t("menu.settings", "Настройки"),
      act: "go:/settings",
    },
    {
      id: "theme",
      order: 60,
      icon: () => (isDark() ? "sun" : "moon"),
      label: () =>
        isDark() ? F.t("menu.theme_light", "Светлая тема") : F.t("menu.theme_dark", "Тёмная тема"),
      act: "theme-menu",
    },
    {
      id: "demo",
      order: 90,
      icon: "app",
      label: () => F.t("menu.demo", "Демо-состояния экранов"),
      sub: () => F.t("menu.demo_sub", "Пусто, загрузка, ошибка, нет сети"),
      act: "demo-states",
      show: () => !!F.isDemo,
    },
  );
  const val = v => (typeof v === "function" ? v() : v);
  F.actions.menu = () => {
    const items = F.menuItems
      .filter(m => !m.show || m.show())
      .sort((a, b) => (a.order ?? 100) - (b.order ?? 100));
    F.sheet({
      cls: "menu-sheet",
      html: items
        .map(
          m =>
            `<div class="srow"
              data-act="${esc(m.act)}">${ic(val(m.icon))}<span class="lbl">${esc(val(m.label))}${m.sub ? `<small>${esc(val(m.sub))}</small>` : ""}</span>${m.chev ? ic("chev", "srow-chev") : ""}</div>`,
        )
        .join(""),
    });
  };
  F.actions["theme-menu"] = () => {
    F.closeSheet();
    F.actions.theme();
  };
  F.actions["demo-states"] = () => {
    if (!F.isDemo) return; // The real core has no demo tools.
    const mode = F.demo.mode,
      off = !!F.state.offline;
    const opt = (k, l, d) =>
      `<div class="srow ${mode === k ? "on" : ""}"
        data-act="set-demo:${k}">${ic(mode === k ? "check" : "dot")}<span class="lbl">${l}<small>${d}</small></span></div>`;
    F.sheet({
      title: F.t("app.demo_states", "Демо-состояния"),
      html:
        opt("normal", F.t("app.normal", "Обычное"), F.t("app.demo_data", "Демо-данные")) +
        opt("empty", F.t("app.empty", "Пусто"), F.t("app.no_data_section", "Нет данных в разделе")) +
        opt("loading", F.t("app.loading", "Загрузка"), F.t("app.skeletons", "Скелетоны")) +
        opt("error", F.t("app.error", "Ошибка"), F.t("common.error_title", "Не удалось загрузить")) +
        `<div class="srow"
          data-act="set-offline">${ic("wifi-off")}<span class="lbl">${esc(F.t("app.offline_2", "Нет сети"))}<small>${esc(F.t("app.banner_at_top", "Плашка сверху"))}</small></span>${ui.toggle(off, "set-offline")}</div>` +
        (!F.isDemo
          ? ""
          : `<div class="srow"
            data-act="demo-first-run">${ic("flag")}<span class="lbl">${esc(F.t("app.first_run", "Первый запуск"))}<small>${esc(F.t("app.terms_use_permissions", "Условия использования, разрешения, знакомство"))}</small></span></div>`) +
        (!F.isDemo
          ? ""
          : `<div class="srow"
            data-act="demo-reset">${ic("refresh")}<span class="lbl">${esc(F.t("app.reset_demo_data", "Сбросить демо-данные"))}<small>${esc(F.t("app.restore_projects_findings", "Вернуть проекты, находки и настройки к исходным"))}</small></span></div>`),
    });
  };
  F.actions["demo-reset"] = () => {
    F.closeSheet();
    F.api.demo_reset().then(() => {
      F.reset(["/projects"]);
      F.snack(F.t("app.demo_data_reset", "Демо-данные сброшены"));
    });
  };
  F.actions["demo-first-run"] = () => {
    F.closeSheet();
    F.api.demo_first_run().then(() => {
      try {
        localStorage.removeItem("foca-welcomed");
        localStorage.removeItem("foca-perm-done");
      } catch (e) {}
      F.reset(["/terms"]);
    });
  };
  F.actions["set-demo"] = k => {
    F.closeSheet();
    F.setDemoMode(k);
  };
  F.actions["set-offline"] = () => {
    F.setOffline(!F.state.offline);
    F.actions["demo-states"]();
  };

  // ---------- /open/:id: open a project (tap on the Android "Scan finished" / "Time to rescan"
  // notification) ----------
  // /open/:id/scan opens the new-scan wizard for that project right away (the "Time to rescan" reminder).
  let opening = null;
  const openRoute = scan => ({
    title: () => F.t("overview.project", "Проект"),
    back: false,
    render: () =>
      `<div class="card pad">${ic("spin", "spin")} ${esc(F.t("app.opening_project", "Открываем проект…"))}</div>`,
    mount: (page, p) => {
      // Opening re-renders the current screen (db "project" event); with a synchronous backend that would
      // mount this screen again and recurse, so open only once per visit.
      if (opening === p.id) return;
      opening = p.id;
      const done = path => {
        opening = null;
        F.reset(path);
      };
      F.api.project_open(p.id).then(
        () => done(scan ? ["/p/overview", "/new"] : ["/p/overview"]),
        () => done(["/projects"]),
      );
    },
  });
  F.route("/open/:id", openRoute(false));
  F.route("/open/:id/scan", openRoute(true));

  // ---------- Overview ----------
  // The Overview re-renders itself on scan events and data changes via the `live` mechanism in core.js
  // (throttled there); project/scan/reset/init re-renders are triggered by api.js.
  /**
   * Scan state shown on the Overview card: live core events when this project is scanning, otherwise the
   * project_list summary; empty when another project's scan is running.
   */
  function currentScan(otherProject, summary, projectId) {
    if (otherProject) return {};
    if (F.scan && F.scan.running) return F.scan;
    if (summary.running && projectId && summary.project === projectId) {
      return {
        running: true,
        stageLabel: summary.stageLabel,
        summary: `${F.t("app.profile_profile_progress", { profile: F.profileLabel ? F.profileLabel(summary.profile) : summary.profile, progress: summary.progress }, "Профиль «{profile}» · {progress}%")}`,
        progress: summary.progress,
      };
    }
    return {};
  }
  const OV_SCAN = [
    "started",
    "stage",
    "progress",
    "source",
    "finding",
    "done",
    "stopped",
    "paused",
    "resumed",
  ];
  F.route("/p/overview", {
    title: () => F.t("overview.title", "Обзор"),
    tab: "overview",
    // The scan card at the top already shows the progress: the floating bar appears only once it scrolls away.
    miniUntil: "#ov-scan",
    fab: () =>
      F.scan && F.scan.running
        ? null
        : // Icon only: the extended label covered the "Critical findings" header on the first view.
          { icon: "play", label: F.t("overview.new_scan", "Новый скан"), act: "new-scan", compact: true },
    render: () =>
      F.withStates(renderOverview, {
        loading: "cards",
        empty: {
          icon: "target",
          title: F.t("overview.empty_title", "Целей пока нет"),
          text: F.t("overview.empty_text", "Добавьте домен, URL, IP или сеть CIDR, чтобы начать разведку."),
          action: `<button class="btn primary" data-act="go:/new">${ic("plus")}${esc(F.t("overview.add_target", "Добавить цель"))}</button>`,
        },
      }),
    live: (kind, ev) =>
      kind === "scan"
        ? OV_SCAN.includes(ev.type)
        : kind === "db" && !["project", "scan", "reset", "init"].includes(ev.kind),
  });
  F.actions["new-scan"] = () => F.go("/new");

  function renderOverview() {
    const cs = F.coreScan || {};
    // A running scan of another project is never shown as this project's scan: a separate banner links to it.
    const pid = F.project && F.project.id;
    const other =
      F.scan && F.scan.running && F.scan.project && F.scan.project !== pid
        ? F.scan.project
        : (!F.scan || !F.scan.running) && cs.running && cs.project && cs.project !== pid
          ? cs.project
          : null;
    const scan = currentScan(other, cs, pid);
    const otherName = other ? ((F.projects || []).find(p => p.id === other) || { name: other }).name : "";
    const otherCard = other
      ? `<div class="banner info ov-other">${ic("spin", "spin")}<div>${F.t("app.project_othername_being_scanned", { otherName: esc(otherName) }, "Идёт скан проекта «{otherName}». Новый скан здесь: после его завершения или остановки.")}<div class="btnrow"><button class="btn sm tonal"
        data-act="scan-open-project">${esc(F.t("overview.open_project", "Открыть проект"))}</button></div></div></div>`
      : "";
    const ringCircumference = 2 * Math.PI * 30;
    const counts = F.sel.counts(),
      RK = F.sel.risk(),
      last = F.sel.lastScan(),
      sc = F.sel.scope.info();
    const crit = F.db.findings.filter(f => F.sel.isLive(f) && f.sev === "crit");
    const mid = counts.findings.high + counts.findings.warn;
    const RC = { crit: "var(--crit)", warn: "var(--warn)", ok: "var(--ok)", none: "var(--layer-3)" }[RK.cls];
    const scanCard = scan.running
      ? `<div class="card pad tap" id="ov-scan"
        data-act="go:/p/scan"><div style="display:flex;align-items:center;gap:12px">${ic("spin", "spin")}<div style="flex:1;min-width:0"><div style="font-weight:600">${esc(scan.stageLabel || F.t("core.scan_running", "Скан идёт"))}</div><div class="muted"
        style="font-size:.85rem">${esc(scan.summary || "")}</div></div>${ic("chev", "chev")}</div><div class="pbar"
        style="margin-top:12px"><i style="width:${scan.progress || 0}%"></i></div></div>`
      : !last
        ? `<div class="card pad"><div style="display:flex;align-items:center;gap:12px"><div class="lead-ic">${ic("scan")}</div><div style="flex:1;min-width:0"><div style="font-weight:600">${esc(F.t("projects.never_scanned", "Скан не запускался"))}</div><div class="muted"
          style="font-size:.85rem">${esc(F.t("overview.scan_no_data", "Данных по проекту пока нет"))}</div></div></div><div class="btnrow"
          style="margin-top:12px"><button class="btn primary"
          data-act="new-scan">${ic("play")}${esc(F.t("overview.start_scan", "Начать скан"))}</button></div></div>`
        : `<div class="card pad"><div style="display:flex;align-items:center;gap:12px"><div class="lead-ic"
          style="color:var(--${last.status === "done" ? "ok" : "warn"});background:var(--${last.status === "done" ? "ok" : "warn"}-soft)">${ic(last.status === "done" ? "check" : "stop")}</div><div style="flex:1;min-width:0"><div style="font-weight:600">${last.status === "done" ? F.t("app.scan_finished", "Скан завершён") : F.t("overview.scan_stopped", "Скан остановлен")}</div><div class="muted"
          style="font-size:.85rem">${esc(last.date)} ${F.t("app.profile_profile", { profile: esc(last.profile) }, "· профиль «{profile}»")}${last.active ? F.t("app.active", " · активный") : ""}</div></div></div><div class="btnrow"
          style="margin-top:12px"><button class="btn sm tonal"
          data-act="go:/p/scan">${ic("history")}${esc(F.t("common.details", "Подробнее"))}</button><button class="btn sm"
          data-act="new-scan">${ic("refresh")}${esc(F.t("app.rescan", "Пересканировать"))}</button></div></div>`;
    const activeSub = sc.activeTargets.length
      ? `${esc(F.t("app.full_profile", "Профиль «Полный»:"))} ${sc.activeTargets.join(", ")}`
      : F.t("app.no_network_targets_external", "Нет сетевых целей: только внешние источники");
    return `
      ${otherCard}${scanCard}
      <div class="card pad tap" data-act="go:/p/findings"
        style="display:flex;align-items:center;gap:16px;margin-top:10px">
        <div style="position:relative;width:76px;height:76px;flex:none"><svg viewBox="0 0 76 76"
          style="width:76px;height:76px;transform:rotate(-90deg)"><circle cx="38" cy="38" r="30"
          stroke="var(--layer-3)" stroke-width="8" fill="none"/><circle cx="38" cy="38" r="30" stroke="${RC}"
          stroke-width="8" fill="none" stroke-linecap="round"
          stroke-dasharray="${(ringCircumference * (RK.score || 0)) / 100} ${ringCircumference}"/></svg><div style="position:absolute;inset:0;display:grid;place-items:center;font-size:1.35rem;font-weight:600">${RK.score ?? "-"}</div></div>
        <div style="flex:1;min-width:0"><div style="font-weight:600;font-size:1.05rem">${esc(RK.score == null ? F.t("app.risk_no_data", "Риск: нет данных") : RK.title)}</div><div class="muted"
          style="font-size:.88rem;margin-top:2px">${RK.score == null ? F.t("app.appears_after_first_scan", "Появится после первого скана") : F.t("app.crit_mid_findings", { crit: counts.findings.crit, mid }, "критичных: {crit}, высоких и средних: {mid}")}</div></div>${ic("chev", "chev")}
      </div>
      <div class="grid g3" style="margin-top:10px">
        <div class="card stat tap"
          data-act="go:/p/data/docs"><div class="k">${esc(F.t("app.documents", "Документы"))}</div><div class="v">${counts.docs.total}</div><div class="d">${counts.docs.new ? `<b>+${counts.docs.new}</b> ${esc(F.t("app.new", "новых"))}` : `${counts.docs.analyzed} ${esc(F.t("app.analyzed", "разобрано"))}${scan.running && counts.docs.analyzed < counts.docs.total && (F.scan.stageIdx ?? 0) < 2 ? ` ${esc(F.t("app.parsed_at_stage", { n: 3 }, "(разбор на этапе {n})"))}` : ""}`}</div></div>
        <div class="card stat tap"
          data-act="go:/p/data/people"><div class="k">${esc(F.t("app.people", "Люди"))}</div><div class="v">${counts.people.total}</div><div class="d">${counts.people.meta} ${esc(F.t("app.from_metadata", "из метаданных"))}</div></div>
        <div class="card stat tap"
          data-act="go:/p/data/hosts"><div class="k">${esc(F.t("app.hosts", "Хосты"))}</div><div class="v">${counts.hosts.total}</div><div class="d">${counts.hosts.internal} ${esc(F.t("app.internal", "внутренних"))}</div></div>
      </div>
      ${ui.secH(F.t("menu.scope", "Скоуп"), "", `<button class="sec-a" data-act="go:/p/scope">${esc(F.t("app.edit", "Изменить"))}</button>`)}
      <div class="list">
        ${ui.row({ lead: ui.leadIcon("users"), title: esc(sc.client || F.project.client || F.t("app.client_not_specified", "Заказчик не указан")), sub: sc.basis ? esc(sc.basis) : F.t("app.no_authorization_note", "Заметка о разрешении не указана"), act: "go:/p/scope" })}
        ${ui.row({ lead: ui.leadIcon("target"), title: `${plural(sc.nTargets, F.t("projects.target", "цель"), F.t("projects.targets", "цели"), F.t("projects.target_many", "целей"))}, ${plural(sc.nExcl, F.t("app.exclusion", "исключение"), F.t("app.exclusions", "исключения"), F.t("app.exclusion_many", "исключений"))}`, sub: esc((sc.targets || []).map(t => t.v).join(", ") || "-"), act: "go:/p/scope" })}
        ${ui.row({ lead: ui.leadIcon("shield"), title: F.t("app.active_phase", "Активная фаза"), sub: esc(activeSub), act: "go:/p/scope" })}
      </div>
      ${
        crit.length
          ? ui.secH(
              F.t("app.critical_findings", "Критичные находки"),
              crit.length,
              `<button class="sec-a" data-act="go:/p/findings">${esc(F.t("common.all", "Все"))}</button>`,
            ) +
            `<div class="list">${crit
              .slice(0, 4)
              .map(f =>
                ui.row({
                  lead: ui.leadIcon("alert", "var(--crit)"),
                  title: esc(f.title),
                  sub: `${esc(f.host)} · ${esc(f.source || "")}`,
                  act: `go:/p/finding/${f.id}`,
                }),
              )
              .join("")}</div>`
          : ""
      }
      ${ui.secH(F.t("app.quick_links", "Быстрые переходы"))}
      <div class="grid g2">
        ${[
          ["mail", F.t("app.e_mail_pattern", "Шаблон e-mail"), "/p/data/emails"],
          ["key", F.t("app.secrets", "Секреты"), "/p/data/secrets"],
          ["app", F.t("app.outdated_software", "Устаревшее ПО"), "/p/data/software"],
          ["share", F.t("app.reports_export", "Отчёты и экспорт"), "/p/reports"],
        ]
          .map(
            ([i, l, p]) =>
              `<div class="card tap qlink"
                data-act="go:${p}"><div class="qlink-in">${ui.leadIcon(i)}<span>${l}</span></div></div>`,
          )
          .join("")}
      </div>
      ${F.ins ? F.ins.overviewHtml() : ""}`;
  }

  // ---------- global search (opened from the bottom search bar) ----------
  const CHIPS = () => [
    ["all", F.t("app.chip_all", "Всё"), null],
    ["findings", F.t("nav.findings", "Находки"), ["findings"]],
    ["docs", F.t("app.documents", "Документы"), ["docs"]],
    ["people", F.t("app.people", "Люди"), ["people"]],
    ["hosts", F.t("app.hosts", "Хосты"), ["hosts", "pcs"]],
    ["emails", "E-mail", ["emails"]],
  ];
  const SR = () => (F.state.search = F.state.search || { q: "", chip: "all", recent: [] });
  // The search bar opens search in the context of the current tab: from Findings with the Findings chip,
  // from a data segment with that segment's type.
  const CHIP_OF_SEG = { docs: "docs", people: "people", hosts: "hosts", emails: "emails" };
  F.actions.search = () => {
    const cur = F.cur || {};
    const tab = cur.r && cur.r.tab;
    const chip =
      tab === "findings"
        ? "findings"
        : tab === "data"
          ? CHIP_OF_SEG[(cur.p && cur.p.seg) || (F.state.data && F.state.data.seg)] || "all"
          : null;
    if (chip) SR().chip = chip;
    F.go("/p/search");
  };
  F.route("/p/search", {
    title: () => F.t("app.search", "Поиск"),
    nav: false,
    back: true,
    actions: [],
    hideMini: true,
    render: () => `
      <div class="field" style="margin-bottom:12px">${ic("search")}<input id="gq"
        placeholder="${esc(F.t("app.document_person_host_finding_e", "Документ, человек, хост, находка, e-mail"))}" autocomplete="off"></div>
      <div class="chips wrap" id="gchips" role="group"
        aria-label="${esc(F.t("app.result_type", "Тип результатов"))}">${CHIPS()
          .map(
            ([k, l]) => `<button class="chip ${SR().chip === k ? "on" : ""}"
        aria-pressed="${SR().chip === k}" data-act="gchip:${k}">${l}</button>`,
          )
          .join("")}</div>
      <div id="gres"></div>`,
    mount: page => {
      const inp = page.querySelector("#gq");
      const res = page.querySelector("#gres");
      const sec = (t, n, rows, k) =>
        n
          ? ui.secH(
              t,
              n > rows.length ? `${rows.length} ${esc(F.t("app.of", "из"))} ${n}` : "",
              n > rows.length && SR().chip === "all" && k
                ? `<button class="sec-a" data-act="gchip:${k}">${esc(F.t("common.all", "Все"))}</button>`
                : "",
            ) + `<div class="list">${rows.join("")}</div>`
          : "";
      const ST_L = {
        confirmed: ["ok", F.t("app.confirmed", "Подтверждена")],
        false: ["mute", F.t("app.false_positive", "Ложная")],
        accepted: ["warn", F.t("app.risk_accepted", "Риск принят")],
        fixed: ["vio", F.t("app.fixed", "Исправлена")],
      };
      const draw = () => {
        const st = SR();
        st.q = inp.value;
        const query = inp.value.trim();
        if (!query) {
          res.innerHTML =
            (st.recent.length
              ? ui.secH(F.t("app.recent_searches", "Недавние запросы")) +
                `<div class="list">${st.recent.map(x => ui.row({ lead: ui.leadIcon("history"), title: esc(x), act: `gset:${x}`, chev: false })).join("")}</div>`
              : "") +
            ui.secH(F.t("app.tips", "Подсказки")) +
            `<p class="lead">${esc(F.t("app.search_file_name_login_full_name", "Ищите по имени файла, логину, ФИО, хосту, IP, e-mail, названию ПО, CVE или тексту находки."))}</p>`;
          return;
        }
        const kinds = (CHIPS().find(c => c[0] === st.chip) || CHIPS()[0])[2] || F.sel.KINDS;
        const found = F.sel.search(query, kinds);
        const lim = n => (st.chip === "all" ? n : 60); // A type filter shows more results.
        const pcs = found.pcs.filter(p => !found.hosts.some(h => h.name === p.name));
        let html = "";
        html += sec(
          F.t("nav.findings", "Находки"),
          found.findings.length,
          found.findings.slice(0, lim(6)).map(f =>
            ui.row({
              lead: ui.leadIcon(
                "alert",
                { crit: "var(--crit)", high: "var(--bad)", warn: "var(--warn)" }[f.sev] || "",
              ),
              title: esc(f.title),
              sub: `${ui.sev(f.sev)}${ST_L[f.status] ? ` <span class="pill ${ST_L[f.status][0]}">${ST_L[f.status][1]}</span>` : ""} ${esc(f.host)} · ${esc(f.source)}`,
              act: `gopen:/p/finding/${f.id}`,
            }),
          ),
          "findings",
        );
        html += sec(
          F.t("app.documents", "Документы"),
          found.docs.length,
          found.docs.slice(0, lim(5)).map(d =>
            ui.row({
              lead: `<span class="ext ${esc(d.ext)}">${esc(d.ext)}</span>`,
              title: esc(d.name),
              sub: esc(d.user.login),
              act: `gopen:/p/doc/${d.id}`,
            }),
          ),
          "docs",
        );
        html += sec(
          F.t("app.people", "Люди"),
          found.people.length,
          found.people.slice(0, lim(4)).map(u =>
            ui.row({
              lead: `<div class="avatar" style="background:${u.color}">${esc(
                u.name
                  .split(" ")
                  .map(w => w[0])
                  .join("")
                  .slice(0, 2),
              )}</div>`,
              title: esc(u.name),
              sub: esc(u.login),
              act: `gopen:/p/entity/person/${encodeURIComponent(u.login)}`,
            }),
          ),
          "people",
        );
        html += sec(
          F.t("app.hosts", "Хосты"),
          found.hosts.length + pcs.length,
          [
            ...found.hosts.slice(0, lim(4)).map(x =>
              ui.row({
                lead: ui.leadIcon("server"),
                title: esc(x.name),
                sub: esc(x.ip),
                act: `gopen:/p/entity/host/${encodeURIComponent(x.name)}`,
              }),
            ),
            ...pcs.slice(0, lim(3)).map(x =>
              ui.row({
                lead: ui.leadIcon("monitor"),
                title: esc(x.name),
                sub: esc(x.source || ""),
                act: `gopen:/p/entity/pc/${encodeURIComponent(x.name)}`,
              }),
            ),
          ],
          "hosts",
        );
        html += sec(
          "E-mail",
          found.emails.length,
          found.emails.slice(0, lim(5)).map(e =>
            ui.row({
              lead: ui.leadIcon("mail"),
              title: esc(e.addr),
              sub: esc(e.src),
              act: `gopen:/p/entity/email/${encodeURIComponent(e.addr)}`,
            }),
          ),
          "emails",
        );
        // Matches in the document text (docs_search) arrive asynchronously under the other results.
        const withText = st.chip === "all" || st.chip === "docs";
        res.innerHTML =
          (html ||
            ui.empty({
              icon: "search",
              title: F.t("app.nothing_found", "Ничего не найдено"),
              text:
                st.chip === "all"
                  ? F.t("app.try_another_query", "Попробуйте другой запрос.")
                  : F.t("app.try_another_query_or_remove", "Попробуйте другой запрос или уберите фильтр."),
            })) + (withText ? `<div id="gfts"></div>` : "");
        if (withText && F.fx) F.fx.globalText(query, res.querySelector("#gfts"), st.chip === "docs" ? 20 : 4);
      };
      if (F.state.searchQ) {
        SR().q = F.state.searchQ;
        F.state.searchQ = "";
      }
      inp.value = SR().q || "";
      inp.addEventListener("input", draw);
      draw();
      F.actions.gset = x => {
        inp.value = x;
        draw();
      };
      F.actions.gchip = k => {
        SR().chip = k;
        page.querySelectorAll("#gchips .chip").forEach(b => {
          const on = b.dataset.act === "gchip:" + k;
          b.classList.toggle("on", on);
          b.setAttribute("aria-pressed", on);
        });
        draw();
      };
      F.actions.gopen = path => {
        const st = SR(),
          q = inp.value.trim();
        if (q) st.recent = [q, ...st.recent.filter(x => x !== q)].slice(0, 5);
        F.go(path);
      };
      setTimeout(() => inp.focus(), 250);
    },
  });

  F.start = async () => {
    await F.dbReady; // Initial snapshot load (already available in demo mode).
    let start = "/projects";
    try {
      if (!localStorage.getItem("foca-welcomed")) start = "/welcome";
    } catch (e) {}
    start = location.hash.length > 1 ? location.hash.slice(1) : start;
    // Terms of use come before any other screen (including the lock screen): without consent go to /terms.
    if (F.onboardStart) start = await F.onboardStart(start);
    // App protection: with a PIN set the lock screen opens first (terms of use still come before it).
    const pinOn = !!(((F.db && F.db.settings) || {}).sec || {}).pin_set;
    F.boot(start, pinOn && start !== "/terms" && start !== "/welcome" ? "/lock" : null);
  };
})();
