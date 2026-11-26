// Findings screen.
// Routes: /p/findings (list, swipe triage, filters, multi-select) and /p/finding/:id (finding card).
(function () {
  const F = window.FOCA,
    { ic, esc, ui } = F;
  // Label tables keep Russian fallbacks; values are translated on read via F.t("<prefix>.<key>").
  const tt = (prefix, table) =>
    new Proxy(table, {
      get: (o, k) => {
        const v = o[k];
        if (typeof k !== "string" || !Object.prototype.hasOwnProperty.call(o, k)) return v;
        const key = `${prefix}.${k}`;
        if (Array.isArray(v)) return [F.t(key, v[0]), ...v.slice(1)];
        // Status records: the label (l) and the segment name (seg) are translated, pill/icon stay as is.
        if (v && typeof v === "object")
          return { ...v, l: F.t(`${key}.l`, v.l), seg: F.t(`${key}.seg`, v.seg) };
        return F.t(key, v);
      },
    });

  // ================= LOOKUP TABLES =================
  // One-line meaning of a finding code (provenance.rule): infrastructure "infra.<code>" (infra.js) and the
  // document forensics codes (forensics.js) with a link to the document and the help article.
  const codeNote = (rule, doc) => {
    const m = /^infra\.(\w+)$/.exec(rule || "");
    const t = m ? F.infra && F.infra.CODE[m[1]] : F.fx && F.fx.CODE[rule];
    if (!t) return "";
    const help = !m && F.fx.CODE_HELP[rule];
    const toDoc =
      !m && doc
        ? `<button class="btn sm tonal fd-todoc" data-act="go:/p/doc/${doc}">${ic("doc")}${esc(F.t("findings.to_doc", "К документу"))}</button>`
        : "";
    return `<p class="fhint fd-code">${ic("info")}<span>${esc(t)}</span>${help && F.helpBtn ? F.helpBtn(help, F.t("common.details", "Подробнее")) : ""}</p>${toDoc ? `<div class="btnrow fd-todoc-r">${toDoc}</div>` : ""}`;
  };
  const CAT = tt("findings.cat", {
    docs: "Документы и секреты",
    sw: "ПО и CVE",
    dns: "DNS",
    web: "Веб",
    mail: "Почта",
    people: "Люди и e-mail",
    // Infrastructure modules: foca_analysis::infra::RULES categories.
    tls: "TLS и сертификаты",
    cloud: "Облака и SaaS",
    hosts: "Хосты и роли",
  });
  const CAT_IC = {
    docs: "doc",
    sw: "app",
    dns: "domain",
    web: "globe",
    mail: "mail",
    people: "users",
    tls: "lock",
    cloud: "db",
    hosts: "server",
  };
  const SEV = tt("sev", {
    crit: "Критический",
    high: "Высокий",
    warn: "Средний",
    low: "Низкий",
    info: "Инфо",
  });
  const SEV_ORDER = { crit: 0, high: 1, warn: 2, low: 3, info: 4 };
  const ST = tt("findings.st", {
    new: { l: "Новая", seg: "Новые", pill: "info", icon: "dot" },
    confirmed: { l: "Подтверждена", seg: "Подтверждённые", pill: "ok", icon: "check" },
    false: { l: "Ложная", seg: "Ложные", pill: "mute", icon: "x" },
    accepted: { l: "Риск принят", seg: "Принятые", pill: "warn", icon: "flag" },
    fixed: { l: "Исправлена", seg: "Исправленные", pill: "vio", icon: "shield" },
  });
  const ST_HINT = tt("findings.st_hint", {
    new: "Ещё не проверена",
    confirmed: "Уязвимость реальна, пойдёт в отчёт",
    false: "Ложное срабатывание, скрыть из отчёта",
    accepted: "Заказчик принимает риск",
    fixed: "Устранена, подтвердить пересканом",
  });

  const fakeSha = s => {
    let h = 2166136261 >>> 0,
      out = "";
    for (let k = 0; k < 8; k++) {
      for (const c of s + k) h = Math.imul(h ^ c.charCodeAt(0), 16777619) >>> 0;
      out += h.toString(16).padStart(8, "0");
    }
    return out;
  };
  const S0 = "{{s:",
    S1 = "}}"; // Secret marker in evidence.
  // Findings come from the shared data layer (F.db.findings; demo generation in js/demo-backend.js, contract
  // in docs/API.md).
  let ALL = F.db.findings;
  F.on("db", () => {
    ALL = F.db.findings;
  });
  const byId = id => ALL.find(f => f.id === +id);
  const hasEv = f => !!(f.evidence || f.photos.length);
  const fmtTime = t => {
    const m = t.match(/\d+-(\d+)-(\d+) (\d+:\d+)/);
    return m ? `${m[2]}.${m[1]}, ${m[3]}` : t;
  };

  // ================= SCREEN STATE =================
  const blankF = () => ({
    sev: [],
    status: [],
    cat: [],
    source: [],
    host: "",
    tag: "",
    ev: false,
    sort: "sev",
  });
  const state = (F.state.findings = F.state.findings || { seg: "new", f: blankF(), sel: null, order: [] });
  let hintOff = false;
  try {
    hintOff = localStorage.getItem("fd-hint") === "1";
  } catch (e) {}

  const activeCount = f =>
    f.sev.length +
    f.status.length +
    f.cat.length +
    f.source.length +
    (f.host ? 1 : 0) +
    (f.tag ? 1 : 0) +
    (f.ev ? 1 : 0);
  // Mutations go only through F.api (the shared data layer); the report selection is
  // settings.report.picked[project].
  const setSt = (id, st) => F.api.finding_set_status(+id, st);
  const upd = (id, patch) => F.api.finding_update(+id, patch);
  const picked = () => F.sel.reportPicked();
  const setPicked = ids =>
    F.api.settings_set({ report: { picked: { [F.db.project.id]: [...new Set(ids)].map(Number) } } });
  // Apply filters (without the status segment, for counters).
  const applyF = (f, list = ALL) =>
    list.filter(
      x =>
        (!f.sev.length || f.sev.includes(x.sev)) &&
        (!f.status.length || f.status.includes(x.status)) &&
        (!f.cat.length || f.cat.includes(x.category)) &&
        (!f.source.length || f.source.includes(x.source)) &&
        (!f.host || x.host === f.host) &&
        (!f.tag || (x.tags || []).includes(f.tag)) &&
        (!f.ev || hasEv(x)),
    );
  const sortL = (l, s) =>
    l
      .slice()
      .sort((a, b) =>
        s === "time"
          ? b.time.localeCompare(a.time)
          : s === "host"
            ? a.host.localeCompare(b.host) || SEV_ORDER[a.sev] - SEV_ORDER[b.sev]
            : SEV_ORDER[a.sev] - SEV_ORDER[b.sev] || b.time.localeCompare(a.time),
      );
  const visible = () => {
    let l = applyF(state.f);
    if (state.seg !== "all") l = l.filter(x => x.status === state.seg);
    return sortL(l, state.f.sort);
  };

  // ================= LIST =================
  const sevBadge = s => ui.sev(s);
  const stPill = st => `<span class="pill ${ST[st].pill}">${ic(ST[st].icon)}${ST[st].l}</span>`;

  function cardHtml(finding) {
    const sel = state.sel && state.sel.has(finding.id);
    const meta = [];
    if (finding.notes.length)
      meta.push(
        `<span title="${esc(F.t("findings.notes", "Заметки"))}">${ic("note")}${finding.notes.length}</span>`,
      );
    if (finding.photos.length)
      meta.push(
        `<span title="${esc(F.t("findings.photos", "Фото"))}">${ic("camera")}${finding.photos.length}</span>`,
      );
    return `<div class="fd-sw" data-id="${finding.id}">
      <div class="fd-bg fd-bg-r" aria-hidden="true">${ic("check")}<span>${esc(ST.confirmed.l)}</span></div>
      <div class="fd-bg fd-bg-l" aria-hidden="true"><span>${esc(ST.false.l)}</span>${ic("x")}</div>
      <div class="fd-card sev-${finding.sev} ${sel ? "sel" : ""}" role="button" tabindex="0"
        aria-label="${esc(SEV[finding.sev] + ": " + finding.title)}">
        ${state.sel ? `<div class="cbx fd-check" aria-hidden="true">${sel ? ic("check") : ""}</div>` : ""}
        <div class="fd-main">
          <div class="fd-top">${sevBadge(finding.sev)}${state.seg === "all" || finding.status !== state.seg ? stPill(finding.status) : ""}<span class="fd-time">${fmtTime(finding.time)}</span></div>
          <div class="fd-t">${esc(finding.title)}</div>
          <div class="fd-s"><span class="fd-host">${esc(finding.host)}</span><span>· ${esc(finding.source)}</span></div>
          ${meta.length ? `<div class="fd-meta">${meta.join("")}</div>` : ""}
        </div>
      </div>
    </div>`;
  }

  function filterChips() {
    const f = state.f,
      out = [];
    f.sev.forEach(v => out.push([`sev:${v}`, SEV[v]]));
    f.status.forEach(v => out.push([`status:${v}`, ST[v].l]));
    f.cat.forEach(v => out.push([`cat:${v}`, CAT[v]]));
    f.source.forEach(v => out.push([`source:${v}`, v]));
    if (f.host) out.push([`host:`, f.host]);
    if (f.tag) out.push([`tag:`, "#" + tagLabel(f.tag)]);
    if (f.ev) out.push([`ev:`, F.t("findings.with_evidence", "С доказательствами")]);
    if (!out.length) return "";
    return `<div class="factive fd-active"
      aria-label="${esc(F.t("findings.active_filters", "Активные фильтры"))}">${out
        .map(
          ([k, l]) => `<button class="fchip fd-fchip"
      data-act="fd-unf:${esc(k)}"
      aria-label="${esc(F.t("findings.remove_filter", { name: l }, "Убрать фильтр {name}"))}"><span>${esc(l)}</span>${ic("x")}</button>`,
        )
        .join("")}<button class="btn text sm"
      data-act="fd-reset">${esc(F.t("findings.reset", "Сбросить"))}</button></div>`;
  }

  function renderList() {
    if (!ALL.length)
      return ui.empty({
        icon: "bug",
        title: F.sel.scans().length
          ? F.t("findings.empty_title", "Находок нет")
          : F.t("findings.empty_title_scan", "Находок нет: запустите скан"),
        text: F.sel.scans().length
          ? F.t("findings.empty_clean", "Сканы проекта не выявили уязвимостей и утечек.")
          : F.t(
              "findings.empty_text",
              "Здесь появятся уязвимости, утечки и ошибки конфигурации, найденные при разведке.",
            ),
        action: F.sel.scans().length
          ? ""
          : `<button class="btn primary" data-act="go:/new">${ic("play")}${esc(F.t("findings.new_scan", "Новый скан"))}</button>`,
      });
    const base = applyF({ ...state.f, sev: [] }); // For severity counters.
    const segBase = applyF(state.f);
    const segs = [
      ["new", ST.new.seg],
      ["confirmed", F.t("findings.seg_confirmed", "Подтверж&shy;дённые")],
      ["false", ST.false.seg],
      ["all", F.t("common.all", "Все")],
    ];
    const list = visible();
    state.order = list.map(x => x.id);
    const sel = state.sel;
    const counts = Object.keys(SEV)
      .map(k => {
        const n = base.filter(x => x.sev === k && (state.seg === "all" || x.status === state.seg)).length;
        const on = state.f.sev.includes(k);
        return `<button class="fd-sum sev-${k} ${on ? "on" : ""}" data-act="fd-sev:${k}"
          aria-pressed="${on}"><span class="fd-sum-ic">${ic(k === "crit" || k === "high" ? "alert" : "info")}</span><span class="fd-sum-n">${n}</span><span class="fd-sum-l">${SEV[k]}</span></button>`;
      })
      .join("");
    return `
      ${
        sel
          ? `<div class="ctxbar fd-ctx" role="toolbar" aria-label="${esc(F.t("findings.select_mode", "Режим выбора"))}">
        <button class="ib" data-act="fd-sel-exit" aria-label="${esc(F.t("findings.select_exit", "Выйти из выбора"))}">${ic("x")}</button>
        <b class="ctxbar-n fd-ctx-n">${esc(F.t("findings.selected_n", { n: sel.size }, "Выбрано: {n}"))}</b>
        <button class="btn text sm"
          data-act="fd-sel-all">${sel.size === list.length && list.length ? F.t("findings.unselect_all", "Снять все") : F.t("findings.select_all", "Выбрать все")}</button>
      </div>`
          : ""
      }
      ${
        !hintOff && !sel
          ? `<div class="banner info fd-hint"
        role="note">${ic("swipe")}<div class="fd-hint-b"><b>${esc(F.t("findings.hint_title", "Быстрый разбор"))}</b><br>${esc(F.t("findings.hint_text", "Свайп вправо: подтвердить, влево, ложная. Выбрать несколько: кнопка в шапке или долгое нажатие."))}</div><button class="ib"
        data-act="fd-hint-off" aria-label="${esc(F.t("findings.hint_off", "Скрыть подсказку"))}">${ic("x")}</button></div>`
          : ""
      }
      <div class="fd-sums" role="group" aria-label="${esc(F.t("findings.sev_filter", "Фильтр по важности"))}">${counts}</div>
      <div class="fd-segw"><div class="seg fd-seg"
        role="tablist">${segs
          .map(
            ([k, l]) => `<button role="tab" class="${state.seg === k ? "on" : ""}"
        aria-selected="${state.seg === k}"
        data-act="fd-seg:${k}"><span>${l}</span><span class="fd-seg-n">${k === "all" ? segBase.length : segBase.filter(x => x.status === k).length}</span></button>`,
          )
          .join("")}</div></div>
      ${filterChips()}
      ${
        list.length
          ? `<div class="fd-list ${sel ? "selecting" : ""}">${list.map(cardHtml).join("")}</div>`
          : ui.empty({
              icon: state.seg === "false" ? "x" : "filter",
              title: activeCount(state.f)
                ? F.t("findings.none_filtered", "Нет находок по фильтрам")
                : state.seg === "new"
                  ? F.t("findings.none_new", "Новых находок нет")
                  : F.t("findings.empty_here", "Здесь пусто"),
              text: activeCount(state.f)
                ? F.t("findings.change_filters", "Измените или сбросьте фильтры.")
                : state.seg === "new"
                  ? F.t("findings.all_triaged", "Всё разобрано: проверьте вкладку «Все».")
                  : F.t("findings.swipe_new", "Сдвиньте карточки в списке «Новые», чтобы разобрать их."),
              action: activeCount(state.f)
                ? `<button class="btn tonal" data-act="fd-reset">${ic("eraser")}${esc(F.t("findings.reset_filters", "Сбросить фильтры"))}</button>`
                : "",
            })
      }
      ${
        sel
          ? `<div class="selbar fd-selbar" role="toolbar"
            aria-label="${esc(F.t("findings.bulk_aria", "Действия с выбранными"))}"><div class="fd-selgrid">
        ${[
          ["fd-bulk:confirmed", "check", F.t("findings.confirm", "Подтвердить"), "pri ok"],
          ["fd-bulk:false", "x", ST.false.l, "pri"],
          ["fd-bulk-sev", "alert", F.t("findings.severity", "Важность"), ""],
          ["fd-bulk-export", "export", F.t("findings.export", "Экспорт"), ""],
          ["fd-bulk-report", "report", F.t("findings.to_report", "В отчёт"), ""],
        ]
          .map(
            ([a, i, l, c]) =>
              `<button class="${c}" data-act="${a}"
                ${sel.size ? "" : "disabled"}>${ic(i)}<span>${l}</span></button>`,
          )
          .join("")}
      </div></div>`
          : ""
      }`;
  }

  F.route("/p/findings", {
    title: () => F.t("nav.findings", "Находки"),
    tab: "findings",
    search: () => F.t("findings.search", "Поиск по находкам"),
    actions: () =>
      state.sel || !ALL.length
        ? state.sel
          ? []
          : F.defaultActions
        : [
            { icon: "tasks", act: "fd-sel-start", label: F.t("findings.select_many", "Выбрать несколько") },
            {
              icon: "filter",
              act: "fd-filters",
              label: F.t("findings.filters_sort", "Фильтры и сортировка"),
              badge: activeCount(state.f) || "",
            },
            { icon: "more", act: "menu", label: F.t("app.menu", "Меню") },
          ],
    render: () =>
      F.withStates(renderList, {
        loading: "list",
        empty: {
          icon: "bug",
          title: F.t("findings.empty_title_scan", "Находок нет: запустите скан"),
          text: F.t(
            "findings.empty_text",
            "Здесь появятся уязвимости, утечки и ошибки конфигурации, найденные при разведке.",
          ),
          action: `<button class="btn primary" data-act="go:/new">${ic("play")}${esc(F.t("findings.new_scan", "Новый скан"))}</button>`,
        },
      }),
    mount: page => {
      const on = !!state.sel && F.demo.mode === "normal";
      document.body.classList.toggle("fd-selecting", on);
      const bar = page.querySelector(".fd-selbar");
      if (on && bar) {
        const h = bar.offsetHeight;
        page.style.paddingBottom = h + 24 + "px";
        document.body.style.setProperty("--fd-selbar-h", h + "px");
      }
      bindList(page);
    },
  });

  // ---------- gestures: swipe triage and long press ----------
  function bindList(page) {
    const list = page.querySelector(".fd-list");
    if (!list) return;
    let gesture = null,
      suppress = false;
    const TH = () => Math.min(110, list.clientWidth * 0.3);
    list.addEventListener("pointerdown", e => {
      if (e.button > 0) return;
      suppress = false;
      const sw = e.target.closest(".fd-sw");
      if (!sw) return;
      const card = sw.querySelector(".fd-card");
      gesture = {
        sw,
        card,
        id: +sw.dataset.id,
        x0: e.clientX,
        y0: e.clientY,
        dx: 0,
        dir: null,
        pid: e.pointerId,
        lp: null,
      };
      gesture.lp = setTimeout(() => {
        if (!gesture || gesture.dir) return;
        gesture.dir = "long";
        suppress = true;
        try {
          navigator.vibrate && navigator.vibrate(20);
        } catch (x) {}
        longPress(gesture.id);
      }, 500);
    });
    list.addEventListener("pointermove", e => {
      if (!gesture || e.pointerId !== gesture.pid || gesture.dir === "long" || gesture.dir === "v") return;
      const dx = e.clientX - gesture.x0,
        dy = e.clientY - gesture.y0;
      if (!gesture.dir) {
        if (Math.abs(dx) < 10 && Math.abs(dy) < 10) return;
        clearTimeout(gesture.lp);
        if (state.sel || Math.abs(dx) < Math.abs(dy) * 1.3) {
          gesture.dir = "v";
          suppress = true;
          return;
        } // Vertical movement belongs to scrolling and is not a tap.
        gesture.dir = "h";
        suppress = true;
        gesture.sw.classList.add("drag");
        try {
          list.setPointerCapture(e.pointerId);
        } catch (x) {}
      }
      gesture.dx = dx;
      const th = TH(),
        over = Math.abs(dx) >= th;
      gesture.card.style.transform = `translateX(${dx}px)`;
      gesture.sw.classList.toggle("go-r", dx > 0);
      gesture.sw.classList.toggle("go-l", dx < 0);
      if (over !== !!gesture.over) {
        gesture.over = over;
        gesture.sw.classList.toggle("armed", over);
        if (over)
          try {
            navigator.vibrate && navigator.vibrate(10);
          } catch (x) {}
      }
    });
    const end = e => {
      if (!gesture || (e && e.pointerId !== gesture.pid)) return;
      clearTimeout(gesture.lp);
      const cur = gesture;
      gesture = null;
      if (cur.dir !== "h") return;
      cur.sw.classList.remove("drag");
      if (Math.abs(cur.dx) >= TH() && e && e.type === "pointerup")
        commitSwipe(cur.sw, cur.card, cur.id, cur.dx > 0 ? "confirmed" : "false");
      else {
        cur.card.style.transform = "";
        cur.sw.classList.remove("armed");
        setTimeout(() => cur.sw.classList.remove("go-r", "go-l"), 200);
      }
    };
    list.addEventListener("pointerup", end);
    list.addEventListener("pointercancel", end);
    list.addEventListener("click", e => {
      if (suppress) {
        suppress = false;
        e.stopPropagation();
        return;
      }
      const sw = e.target.closest(".fd-sw");
      if (!sw) return;
      const id = +sw.dataset.id;
      if (state.sel) {
        state.sel.has(id) ? state.sel.delete(id) : state.sel.add(id);
        F.render(true);
      } else F.go(`/p/finding/${id}`);
    });
    list.addEventListener("keydown", e => {
      if ((e.key === "Enter" || e.key === " ") && e.target.closest(".fd-card")) {
        e.preventDefault();
        e.target.click();
      }
    });
  }

  function commitSwipe(sw, card, id, st) {
    const f = byId(id);
    const prev = f.status;
    if (prev === st) {
      card.style.transform = "";
      sw.classList.remove("armed", "go-r", "go-l");
      F.snack(F.t("findings.already", { st: ST[st].l }, "Уже «{st}»"));
      return;
    }
    const leaves = state.seg !== "all";
    card.style.transition = "transform .2s ease";
    card.style.transform = `translateX(${st === "confirmed" ? "" : "-"}110%)`;
    setTimeout(() => {
      setSt(id, st);
      if (leaves) {
        sw.style.height = sw.offsetHeight + "px";
        sw.offsetHeight;
        sw.classList.add("collapse");
        sw.style.height = "0px";
        setTimeout(() => F.render(true), 210);
      } else F.render(true);
    }, 200);
    F.snack(
      st === "confirmed"
        ? F.t("findings.confirmed_t", { t: short(f.title) }, "Подтверждена: {t}")
        : F.t("findings.marked_false", "Отмечена как ложная"),
      {
        action: () => {
          setSt(id, prev);
          F.render(true);
        },
      },
    );
  }
  const short = t => (t.length > 34 ? t.slice(0, 32) + "…" : t);

  // ---------- multi-select and system Back interception ----------
  // In selection mode, system Back leaves selection mode (core hook F.onBack).
  function longPress(id) {
    if (state.sel) return;
    state.sel = new Set([id]);
    F.onBack(() => {
      exitSel();
      return true;
    });
    F.render(true);
  }
  function exitSel() {
    state.sel = null;
    document.body.classList.remove("fd-selecting");
    F.onBack(null);
    if (F.cur && F.cur.path === "/p/findings") F.render(true);
  }

  Object.assign(F.actions, {
    "fd-sel-exit": () => exitSel(),
    "fd-sel-all": () => {
      const ids = visible().map(x => x.id);
      state.sel = state.sel.size === ids.length ? new Set() : new Set(ids);
      F.render(true);
    },
    "fd-bulk": st => {
      const items = [...state.sel].map(byId),
        prev = items.map(f => f.status);
      items.forEach(f => setSt(f.id, st));
      exitSel();
      F.snack(`${items.length} ${plural(items.length)} → «${ST[st].l}»`, {
        action: () => {
          items.forEach((f, i) => setSt(f.id, prev[i]));
          F.render(true);
        },
      });
    },
    "fd-bulk-sev": () =>
      F.sheet({
        title: F.t("findings.sev_for", { n: plural(state.sel.size) }, "Важность для {n}"),
        html: Object.keys(SEV)
          .map(
            k =>
              `<div class="srow" data-act="fd-bulk-sev-set:${k}"
                role="button"><span class="fd-sevdot sev-${k}">${ic(k === "crit" || k === "high" ? "alert" : "info")}</span><span class="lbl">${SEV[k]}</span></div>`,
          )
          .join(""),
      }),
    "fd-bulk-sev-set": k => {
      const items = [...state.sel].map(byId),
        prev = items.map(f => f.sev);
      items.forEach(f => upd(f.id, { sev: k }));
      F.closeSheet();
      exitSel();
      F.snack(
        F.t("findings.sev_set_for", { sev: SEV[k], n: plural(items.length) }, "Важность «{sev}» для {n}"),
        {
          action: () => {
            items.forEach((f, i) => upd(f.id, { sev: prev[i] }));
            F.render(true);
          },
        },
      );
    },
    "fd-bulk-export": () => {
      const n = state.sel.size;
      exitSel();
      if (F.exportSheet)
        F.exportSheet({
          title: F.t("findings.export_n", { n: plural(n) }, "Экспорт: {n}"),
          kind: "findings",
          count: n,
        });
      else F.snack(F.t("findings.export_demo", { n: plural(n) }, "Экспорт {n}: готово (демо)"));
    },
    "fd-bulk-report": () => {
      const ids = [...state.sel];
      const before = picked();
      setPicked(before.concat(ids));
      exitSel();
      F.snack(
        F.t(
          "findings.report_added",
          { n: picked().length, k: ids.length },
          "В выборке отчёта: {n} · добавлено {k}",
        ),
        {
          label: F.t("findings.undo", "Отменить"),
          action: () => {
            setPicked(before);
            F.render(true);
          },
        },
      );
    },
    "fd-sel-start": () => {
      const l = visible();
      if (!l.length) return;
      state.sel = new Set();
      F.onBack(() => {
        exitSel();
        return true;
      });
      F.render(true);
    },
  });
  // "N findings" in the genitive (для 1 находки / для 5 находок); English uses one/other.
  // Engine tags are stable English codes (the store maps tags of older versions to them); user tags are
  // shown as typed.
  const TAG_L = () => ({
    secret: F.t("findings.tagc_secret", "секрет"),
    outdated: F.t("findings.tagc_outdated", "устарело"),
    forensics: F.t("findings.tagc_forensics", "форензика"),
    qes: F.t("findings.tagc_qes", "КЭП"),
    pii: F.t("findings.tagc_pii", "персональные данные"),
    kev: "KEV",
    eol: "EOL",
    reopened: F.t("findings.tagc_reopened", "вернулась"),
    out_of_scope: F.t("findings.tagc_out_of_scope", "вне скоупа"),
    archive: F.t("findings.tagc_archive", "архив"),
  });
  const tagLabel = t => {
    const m = /^cdn_edge:(.+)$/.exec(t);
    if (m) return F.t("findings.tagc_cdn_edge", { p: m[1] }, "граница CDN: {p}");
    return TAG_L()[t] || t;
  };
  F.tagLabel = tagLabel;
  const plural = n => F.plural(n, F.t("findings.gen_one", "находки"), F.t("findings.gen_many", "находок"));

  // ---------- list actions ----------
  Object.assign(F.actions, {
    "fd-seg": k => {
      state.seg = k;
      F.render(true);
    },
    "fd-sev": k => {
      const a = state.f.sev;
      a.includes(k) ? a.splice(a.indexOf(k), 1) : a.push(k);
      F.render(true);
    },
    "fd-hint-off": () => {
      hintOff = true;
      try {
        localStorage.setItem("fd-hint", "1");
      } catch (e) {}
      F.render(true);
    },
    "fd-reset": () => {
      const s = state.f.sort;
      state.f = blankF();
      state.f.sort = s;
      F.render(true);
    },
    "fd-unf": k => {
      const [t, v] = k.split(/:(.*)/s);
      if (t === "host") state.f.host = "";
      else if (t === "tag") state.f.tag = "";
      else if (t === "ev") state.f.ev = false;
      else state.f[t] = state.f[t].filter(x => x !== v);
      F.render(true);
    },
    "fd-filters": () => openFilters(),
  });

  // ================= FILTERS AND SORTING =================
  function openFilters() {
    const draft = JSON.parse(JSON.stringify(state.f));
    const sources = [...new Set(ALL.map(x => x.source))].sort();
    const hosts = [...new Set(ALL.map(x => x.host).filter(h => h !== "-"))].sort();
    const chipG = (key, items) =>
      `<div class="chips wrap"
        data-g="${key}">${items
          .map(
            ([v, l]) => `<button class="chip ${draft[key].includes(v) ? "on" : ""}"
        data-v="${esc(v)}" aria-pressed="${draft[key].includes(v)}">${esc(l)}</button>`,
          )
          .join("")}</div>`;
    const html = `
      <div class="flabel">${esc(F.t("findings.sort", "Сортировка"))}</div>
      <div class="seg fd-sortseg">${[
        ["sev", F.t("findings.severity", "Важность")],
        ["time", F.t("findings.time", "Время")],
        ["host", F.t("findings.host", "Хост")],
      ]
        .map(([k, l]) => `<button class="${draft.sort === k ? "on" : ""}" data-sort="${k}">${l}</button>`)
        .join("")}</div>
      <div class="flabel">${esc(F.t("findings.severity", "Важность"))}</div>${chipG("sev", Object.entries(SEV))}
      <div class="flabel">${esc(F.t("findings.status", "Статус"))}</div>${chipG(
        "status",
        Object.keys(ST).map(k => [k, ST[k].l]),
      )}
      <div class="flabel">${esc(F.t("findings.category", "Категория"))}</div>${chipG("cat", Object.entries(CAT))}
      <div class="flabel">${esc(F.t("findings.source", "Источник"))}</div>${chipG(
        "source",
        sources.map(s => [s, s]),
      )}
      <div class="flabel" id="fd-hl">${esc(F.t("findings.host", "Хост"))}</div>
      ${ui.select({
        id: "fd-host",
        value: draft.host || "",
        title: F.t("findings.host", "Хост"),
        attrs: 'aria-labelledby="fd-hl"',
        options: [{ v: "", t: F.t("findings.all_hosts", "Все хосты") }, ...hosts.map(h => ({ v: h, t: h }))],
      })}
      <div class="fd-evrow"><span class="lbl">${esc(F.t("findings.ev_only", "Только с доказательствами"))}<small>${esc(F.t("findings.ev_only_sub", "Есть фрагмент, запрос или фото"))}</small></span>${ui.toggle(draft.ev, "fd-ev-t", `aria-label="${esc(F.t("findings.ev_only", "Только с доказательствами"))}"`)}</div>`;
    F.sheet({
      title: F.t("findings.filters_sort", "Фильтры и сортировка"),
      full: false,
      html,
      footer: `<button class="btn" data-act="fd-f-clear">${esc(F.t("findings.reset", "Сбросить"))}</button><button class="btn primary"
        data-act="fd-f-apply" id="fd-apply">${esc(F.t("findings.show", "Показать"))}</button>`,
      onMount: sh => {
        const upd = () => {
          let l = applyF(draft);
          if (state.seg !== "all") l = l.filter(x => x.status === state.seg);
          const b = sh.querySelector("#fd-apply");
          b.textContent = F.t("findings.show_n", { n: l.length }, "Показать {n}");
          b.disabled = !l.length && state.seg !== "all" ? false : false;
        };
        sh.addEventListener(
          "click",
          e => {
            const chipEl = e.target.closest(".chips .chip");
            if (chipEl) {
              const k = chipEl.parentElement.dataset.g,
                value = chipEl.dataset.v;
              const values = draft[k];
              values.includes(value) ? values.splice(values.indexOf(value), 1) : values.push(value);
              chipEl.classList.toggle("on", values.includes(value));
              chipEl.setAttribute("aria-pressed", values.includes(value));
              upd();
              e.stopPropagation();
              return;
            }
            const sortEl = e.target.closest("[data-sort]");
            if (sortEl) {
              draft.sort = sortEl.dataset.sort;
              sh.querySelectorAll("[data-sort]").forEach(b => b.classList.toggle("on", b === sortEl));
            }
          },
          true,
        );
        sh.querySelector("#fd-host").addEventListener("change", e => {
          draft.host = e.target.value;
          upd();
        });
        F.actions["fd-ev-t"] = (_, el) => {
          draft.ev = !draft.ev;
          el.classList.toggle("on", draft.ev);
          el.setAttribute("aria-checked", draft.ev);
          upd();
        };
        F.actions["fd-f-clear"] = () => {
          const s = draft.sort;
          Object.assign(draft, blankF(), { sort: s });
          sh.querySelectorAll(".chips .chip").forEach(c => {
            c.classList.remove("on");
            c.setAttribute("aria-pressed", "false");
          });
          F.pickSet(sh.querySelector("#fd-host"), "");
          const t = sh.querySelector(".toggle");
          t.classList.remove("on");
          t.setAttribute("aria-checked", "false");
          upd();
        };
        F.actions["fd-f-apply"] = () => {
          state.f = draft;
          F.closeSheet();
          F.render(true);
        };
        upd();
      },
    });
  }

  // ================= FINDING CARD =================
  const navList = id => (state.order.includes(+id) ? state.order : sortL(ALL, "sev").map(x => x.id));
  const neighbors = id => {
    const o = navList(id);
    const i = o.indexOf(+id);
    return i < 0 ? { i: -1, n: o.length } : { i, n: o.length, prev: o[i - 1], next: o[i + 1] };
  };

  // A secret in evidence is revealed the same way as in Data → Secrets: after fingerprint confirmation.
  const revealed = new Set();
  const hibpRes = {};
  F.onBioClose(() => revealed.clear()); // Fingerprint session closed (timeout, background, lock, "Close"): secrets are hidden again.
  // Screenshot blocking (FLAG_SECURE) is the opt-in sec.block_shots setting (missing = off); the legacy sec.hide flag
  // defaulted to on and no longer drives the window, so it must not be read here.
  const hideAdvice = () => ((F.db.settings || {}).sec || {}).block_shots === true;
  function evidenceHtml(f) {
    const parts = f.evidence.split(S0);
    let hasSecret = false;
    const open = revealed.has(f.id);
    const body = parts
      .map((p, i) => {
        if (!i) return esc(p);
        const [sec, rest] = p.split(S1);
        hasSecret = true;
        return (
          `<span class="secret ${open ? "" : "masked"}" data-secret="ev${f.id}">${esc(sec)}</span>` +
          esc(rest || "")
        );
      })
      .join("");
    return `<div class="fd-ev ${open ? "fd-ev-open" : ""}" data-secret-wrap>
      <div class="fd-ev-h"><span>${ic("hash")}${esc(F.t("findings.snippet", "Фрагмент"))}</span>
        ${
          hasSecret
            ? `<button class="ib" data-act="fd-reveal:${f.id}"
          aria-label="${open ? F.t("findings.hide_secret", "Скрыть секрет") : F.t("findings.show_secret", "Показать секрет")}">${ic(open ? "eye-off" : "eye")}</button>`
            : ""
        }
        <button class="ib" data-act="fd-copy-ev:${f.id}"
          aria-label="${esc(F.t("findings.copy_evidence", "Копировать доказательство"))}">${ic("copy")}</button></div>
      <pre class="fd-pre">${body}</pre>
      ${
        hasSecret
          ? `<div class="fd-ev-f">${ic("lock")}<span>${open ? `${F.bioOpen() ? F.t("findings.secret_shown_bio", "Секрет показан до ухода с карточки или до закрытия доступа к секретам.") : F.t("findings.secret_shown", "Секрет показан до ухода с карточки.")} ${hideAdvice() ? F.t("findings.shots_blocked", "Снимки экрана в приложении запрещены.") : F.t("findings.no_shots", "Не делайте скриншоты экрана с открытым значением.")}` : F.bioOpen() ? F.t("findings.secret_hidden_bio", "Секрет скрыт. Доступ к секретам открыт. Показ без повторного отпечатка, при копировании маскируется.") : F.t("findings.secret_hidden", "Секрет скрыт. Показ: после подтверждения отпечатком, при копировании маскируется.")}</span></div>
      <div class="btnrow" style="padding:0 12px 10px">
        <button class="btn sm tonal" data-act="fd-hibp:${f.id}">${ic("shield")}${esc(F.t("findings.hibp_check", "Проверить секрет в HIBP (префикс SHA-1)"))}</button>
        ${
          hibpRes[f.id]
            ? hibpRes[f.id].err
              ? `<span class="pill warn">${esc(hibpRes[f.id].err)}</span>`
              : hibpRes[f.id].pwned
                ? `<span class="pill crit">${esc(F.tp("findings.hibp_leaked", hibpRes[f.id].count, { n: hibpRes[f.id].count, p: hibpRes[f.id].prefix }, "HIBP: утёк ({n} раз · префикс {p})|HIBP: утёк ({n} раза · префикс {p})|HIBP: утёк ({n} раз · префикс {p})"))}</span>`
                : `<span class="pill ok">${esc(F.t("findings.hibp_clean", { p: hibpRes[f.id].prefix }, "HIBP: не найден (префикс {p})"))}</span>`
            : ""
        }
      </div>`
          : ""
      }
    </div>`;
  }

  const kv = (k, v, extra = "") =>
    `<div class="kvr"><div class="k">${k}</div><div class="v">${v}</div>${extra}</div>`;
  const copyBtn = (txt, label) =>
    `<div class="kva"><button class="ib" data-act="copy:${esc(txt)}"
      aria-label="${label}">${ic("copy")}</button></div>`;
  const relRow = o => ui.row({ ...o, act: `fd-rel:${o.path}` });

  // Standards of the finding rule (finding.standards from the core, null when the rule is unmapped):
  // MITRE ATT&CK v20, CWE (+ 2025 Top 25 flag), OWASP Top 10:2025, WSTG v4.2, ISO/IEC 27001:2022 Annex A,
  // NIST SP 800-53 Rev. 5 (same codes as НД ТЗІ 3.6-006-24), personal data law, legacy НД ТЗІ 2.5-004-99 / 3.7-003-05.
  const STD_CHIPS = [
    ["mitre", "ATT&CK", "MITRE ATT&CK v20"],
    ["cwe", "", "CWE"],
    ["owasp", "OWASP", "OWASP Top 10:2025"],
    ["wstg", "", "OWASP WSTG v4.2"],
    ["iso27001", "ISO 27001 A.", "ISO/IEC 27001:2022 (ДСТУ ISO/IEC 27001:2023)"],
    ["nist", "NIST", "NIST SP 800-53 Rev. 5 / НД ТЗІ 3.6-006-24"],
    ["privacy", "", ""],
    ["ndtzi", "НД ТЗІ", "НД ТЗІ 2.5-004-99"],
    ["kszi", "КСЗІ", "НД ТЗІ 3.7-003-05"],
  ];
  const STD_PRIVACY = {
    "gdpr-5-1-c": "GDPR 5(1)(c)",
    "gdpr-5-1-f": "GDPR 5(1)(f)",
    "gdpr-32": "GDPR ст. 32",
    "ua2297-6": "2297-VI ст. 6",
    "ua2297-24": "2297-VI ст. 24",
  };
  function stdChip(s, k, p0, full, v) {
    const p = p0 ? F.t(`findings.std.${k}`, p0) : p0;
    let label = p ? (p.endsWith(".") ? p + v : p + " " + v) : v;
    let title = full ? full + " " + v : v;
    if (k === "privacy") label = title = F.t(`findings.std.pv.${v}`, STD_PRIVACY[v] || v);
    if (k === "cwe" && (s.cwe_top25 || []).includes(v)) {
      label += " · Top 25";
      title += ": " + F.t("findings.std.cwe_top25", "входит в CWE Top 25 (2025)");
    }
    if (k === "ndtzi" || k === "kszi")
      title += ": " + F.t("findings.std.legacy", "для систем, аттестованных по КСЗИ");
    return `<span class="pill mute fd-stdc" title="${esc(title)}">${esc(label)}</span>`;
  }
  function stdChips(f) {
    const s = f && f.standards;
    if (!s) return "";
    const chips = STD_CHIPS.flatMap(([k, p0, full]) =>
      (Array.isArray(s[k]) ? s[k] : []).map(v => stdChip(s, k, p0, full, v)),
    );
    if (!chips.length) return "";
    return `<div class="fd-std"><div class="fd-std-h"><small>${esc(F.t("findings.std", "Стандарты"))}</small>${F.helpBtn ? F.helpBtn("standards", F.t("findings.std_help", "Соответствие стандартам")) : ""}</div><div class="chips wrap fd-stdl">${chips.join("")}</div></div>`;
  }
  function renderDetail(params) {
    const finding = byId(params.id);
    if (!finding)
      return ui.empty({
        icon: "bug",
        title: F.t("findings.not_found", "Находка не найдена"),
        text: F.t("findings.not_found_text", "Возможно, она удалена или относится к другому проекту."),
        action: `<button class="btn tonal" data-act="go:/p/findings">${esc(F.t("findings.to_list", "К списку находок"))}</button>`,
      });
    if (F.dataTrail) F.dataTrail.visit(F.current(), finding.title, "bug"); // A finding is the first link of the "finding → document → author → PC" trail.
    const nb = neighbors(finding.id),
      pv = finding.provenance;
    const srcDoc = pv.doc ? F.db.docs.find(d => d.id === pv.doc) : null;
    const doc = srcDoc && !srcDoc.deleted ? srcDoc : null;
    const related = F.sel.related("finding", finding.id);
    const rel = [
      ...related.people.map(u =>
        relRow({
          lead: `<div class="avatar" style="background:${u.color}">${esc(
            u.name
              .split(" ")
              .map(w => w[0])
              .join("")
              .slice(0, 2),
          )}</div>`,
          title: esc(u.name),
          sub: `${esc(u.login)} · ${esc(u.role)}`,
          path: `/p/entity/person/${encodeURIComponent(u.login)}`,
        }),
      ),
      ...finding.rel.pcs.map(pc => {
        const e = F.sel.entity("pc", pc);
        const srv = e ? e.kind === "server" : /^SRV|MAIL/.test(pc);
        return relRow({
          lead: ui.leadIcon(srv ? "server" : "monitor"),
          title: esc(pc),
          sub: srv
            ? F.t("findings.server_internal", "Сервер (внутренний)")
            : F.t("findings.workstation", "Рабочая станция"),
          path: `/p/entity/pc/${encodeURIComponent(pc)}`,
        });
      }),
      ...related.docs
        .filter(d => d.id !== (doc && doc.id))
        .map(d =>
          relRow({
            lead: `<span class="ext ${esc(d.ext)}">${esc(d.ext)}</span>`,
            title: esc(d.name),
            sub: `${esc(d.user.login)} · ${esc(F.t("findings.kb", { n: d.size }, "{n} КБ"))}`,
            path: `/p/doc/${d.id}`,
          }),
        ),
    ];
    const sc = finding.host !== "-" ? F.sel.scope.check(finding.host) : null;
    // The excluded-host note is based on the finding's origin, not only on the current scope.
    const exclNote = () => {
      const raw = (F.db.findings || []).find(x => x.id === finding.id) || {};
      if (!raw.active)
        return F.t(
          "findings.excl_ext",
          "В исключениях скоупа · находка из внешних источников, к хосту не обращались",
        );
      const at = raw.time ? String(raw.time).slice(0, 10).split("-").reverse().join(".") : "";
      return at
        ? F.t(
            "findings.excl_after_at",
            { at },
            "Хост исключён после скана · находка получена активным модулем {at}, новые запросы не отправляются",
          )
        : F.t(
            "findings.excl_after",
            "Хост исключён после скана · находка получена активным модулем, новые запросы не отправляются",
          );
    };
    const hostRow =
      finding.host !== "-"
        ? `<div class="kvr tap" data-act="fd-rel:/p/entity/host/${encodeURIComponent(finding.host)}"
          role="link"><div class="k">${esc(F.t("findings.host", "Хост"))}</div><div class="v fd-link">${esc(finding.host)}${sc && sc.excluded ? `<div class="fd-scope">${ic("alert")}${esc(exclNote())}</div>` : sc && !sc.ok ? `<div class="fd-scope">${ic("info")}${esc(F.t("findings.out_of_scope", "Вне скоупа"))}</div>` : ""}</div>${ic("chev", "chev")}</div>`
        : kv(F.t("findings.host", "Хост"), F.t("findings.multi_na", "Несколько / не применимо"));
    const inRep = picked().includes(finding.id);
    return `
      ${F.dataTrail ? F.dataTrail.html() : ""}
      <div class="card pad fd-hero sev-${finding.sev}">
        <div class="fd-hero-top">${ui.sev(finding.sev)}<span class="fd-cat">${ic(CAT_IC[finding.category])}${esc(CAT[finding.category])}</span>${inRep ? `<span class="pill info">${ic("report")}${esc(F.t("findings.in_report", "В отчёте"))}</span>` : ""}</div>
        <h1 class="fd-h1">${esc(finding.title)}</h1>
        <button class="fd-status st-${finding.status}" data-act="fd-status:${finding.id}"
          aria-label="${esc(F.t("findings.status_aria", { st: ST[finding.status].l }, "Статус: {st}. Изменить"))}">
          ${ic(ST[finding.status].icon)}<span class="fd-status-l"><small>${esc(F.t("findings.status", "Статус"))}</small>${ST[finding.status].l}</span>${ic("chev-down")}
        </button>
        ${
          finding.cvss != null || finding.cve.length || finding.mitre
            ? `<div class="fd-scores">
          ${finding.cvss != null ? `<span class="fd-cvss sev-${finding.sev}"><b>${finding.cvss.toFixed(1)}</b><small>CVSS 3.1</small></span>` : ""}
          ${finding.cve
            .map(
              c => `<a class="pill info fd-cve" href="#"
            data-act="fd-cve:${esc(c)}">${ic("link")}${esc(c)}</a>`,
            )
            .join("")}
        </div>`
            : ""
        }
        ${finding.mitre ? `<div class="fd-mitre">${ic("target")}<span><small>MITRE ATT&amp;CK</small>${esc(finding.mitre)}</span></div>` : ""}
        ${stdChips(finding)}
      </div>

      <div class="kv fd-kv">${hostRow}${kv(F.t("findings.category", "Категория"), esc(CAT[finding.category] || finding.category))}${kv(F.t("findings.source", "Источник"), esc(finding.source))}${kv(F.t("findings.detected", "Обнаружено"), esc(pv.time))}</div>

      ${ui.secH(F.t("findings.description", "Описание"))}
      <div class="card pad fd-text">${esc(finding.description)}</div>
      ${codeNote(pv.rule, pv.doc)}
      ${F.ins ? F.ins.findingBlock(finding) : ""}

      ${finding.evidence ? ui.secH(F.t("findings.evidence", "Доказательство")) + evidenceHtml(finding) : ""}

      ${ui.secH(F.t("findings.provenance", "Происхождение"), "", `<span class="pill mute fd-prov-p">${ic("shield")}${esc(F.t("findings.chain_kept", "Цепочка сохранена"))}</span>`)}
      <div class="kv fd-kv">
        ${kv(F.t("findings.module", "Модуль"), esc(pv.source))}
        ${kv("URL", `<span class="mono fd-url">${esc(pv.url)}</span>`, pv.url !== "-" ? copyBtn(pv.url, F.t("findings.copy_url", "Копировать URL")) : "")}
        ${kv(F.t("findings.time", "Время"), esc(pv.time))}
        ${pv.request ? kv(F.t("findings.request", "Запрос"), `<span class="mono">${esc(pv.request)}</span>`) : ""}
        ${pv.sha256 ? kv(srcDoc ? F.t("findings.sha_file", "SHA-256 файла") : F.t("findings.sha_resp", "SHA-256 ответа"), `<span class="mono fd-hash">${pv.sha256}</span>`, copyBtn(pv.sha256, F.t("findings.copy_sha", "Копировать SHA-256"))) : ""}
      </div>
      ${
        doc
          ? `<div class="list fd-srcdoc">${relRow({ lead: `<span class="ext ${esc(doc.ext)}">${esc(doc.ext)}</span>`, title: esc(doc.name), sub: `${esc(F.t("findings.src_doc", "Документ-источник"))} · ${esc(doc.created)}`, path: `/p/doc/${doc.id}` })}</div>`
          : srcDoc
            ? `<div class="card pad fd-gone"><div class="fd-gone-h">${ic("alert")}<b>${esc(F.t("findings.src_deleted", "Источник удалён"))}</b></div><p>${esc(F.t("findings.src_deleted_text", { name: srcDoc.name }, "Документ «{name}» удалён из проекта. Хеш и доказательство сохранены, но открыть файл нельзя."))}</p><button class="btn tonal"
              data-act="fd-restore-doc:${srcDoc.id}">${ic("refresh")}${esc(F.t("findings.restore_doc", "Восстановить документ"))}</button></div>`
            : ""
      }

      ${ui.secH(F.t("findings.recommendation", "Рекомендация"), "", `<button class="sec-a" data-act="fd-playbook:${finding.id}">${ic("shield")}${esc(F.t("findings.playbook", "План исправления (Playbook)"))}</button>`)}
      <div class="card pad fd-text fd-rec">${ic("shield")}<span>${esc(finding.recommendation)}</span></div>

      ${rel.length ? ui.secH(F.t("findings.related", "Связанное"), rel.length) + `<div class="list">${rel.join("")}</div>` : ""}

      ${ui.secH(F.t("findings.tags", "Теги"), "", `<button class="sec-a" data-act="fd-tag-add:${finding.id}">${esc(F.t("findings.add", "Добавить"))}</button>`)}
      <div class="chips wrap fd-tags">${
        finding.tags.length
          ? finding.tags
              .map(
                t => `<span class="fd-tagw"><button class="chip fd-tag"
        data-act="fd-tag-filter:${esc(t)}"
        aria-label="${esc(F.t("findings.tag_show", { t: tagLabel(t) }, "Показать находки с тегом {t}"))}">${ic("hash")}${esc(tagLabel(t))}</button><button class="ib fd-tagx"
        data-act="fd-tag-del:${finding.id}:${esc(t)}"
        aria-label="${esc(F.t("findings.tag_del", { t: tagLabel(t) }, "Удалить тег {t}"))}">${ic("x")}</button></span>`,
              )
              .join("")
          : `<span class="muted fd-none">${esc(F.t("findings.no_tags", "Тегов нет"))}</span>`
      }</div>

      ${ui.secH(
        F.t("findings.notes", "Заметки"),
        finding.notes.length || "",
        `<button class="sec-a"
        data-act="fd-note:${finding.id}">${esc(F.t("findings.add", "Добавить"))}</button>`,
      )}
      ${
        finding.notes.length
          ? `<div class="list">${finding.notes
              .map(
                (
                  n,
                  i,
                ) => `<div class="row fd-note"><div class="lead-ic">${ic("note")}</div><div class="body"><div class="fd-note-t">${esc(n.text)}</div><div class="s">${esc(n.who === "Вы" ? F.t("findings.you", "Вы") : n.who)} · ${esc(n.time)}</div></div><button class="ib"
            data-act="fd-note-del:${finding.id}:${i}"
            aria-label="${esc(F.t("findings.del_note", "Удалить заметку"))}">${ic("x")}</button></div>`,
              )
              .join("")}</div>`
          : `<button class="fd-addbox"
            data-act="fd-note:${finding.id}">${ic("note")}<span>${esc(F.t("findings.add_note", "Добавить заметку"))}<small>${esc(F.t("findings.add_note_sub", "Видна только в этом проекте"))}</small></span></button>`
      }

      ${ui.secH(F.t("findings.photos_title", "Фото и изображения"), finding.photos.length || "")}
      <div class="fd-photos">
        ${finding.photos
          .map(
            (ph, i) => `<button class="fd-ph" data-act="fd-ph:${finding.id}:${i}"
          aria-label="${esc(F.t("findings.open_photo", { name: ph.name }, "Открыть {name}"))}"><span class="fd-ph-img ${ph.kind === "cam" ? "cam" : ""}"
          aria-hidden="true"><i></i><i></i><i></i></span><span class="fd-ph-n">${esc(ph.name)}</span><span class="fd-ph-s">${esc(ph.time)}</span></button>`,
          )
          .join("")}
      </div>
      <div class="btnrow fd-phbtns"><button class="btn tonal"
        data-act="fd-photo:${finding.id}:cam">${ic("camera")}${esc(F.t("findings.take_photo", "Сделать фото"))}</button><button class="btn"
        data-act="fd-photo:${finding.id}:gal">${ic("folder")}${esc(F.t("findings.from_gallery", "Из галереи"))}</button></div>

      <div class="pn fd-pn">
        <button class="btn" data-act="fd-nav:${nb.prev || ""}"
          ${nb.prev ? "" : "disabled"} aria-label="${esc(F.t("findings.prev", "Предыдущая находка"))}">${ic("chev-left")}${esc(F.t("findings.prev_short", "Пред."))}</button>
        <span class="muted">${nb.i >= 0 ? esc(F.t("findings.n_of", { i: nb.i + 1, n: nb.n }, "{i} из {n}")) : ""}</span>
        <button class="btn" data-act="fd-nav:${nb.next || ""}"
          ${nb.next ? "" : "disabled"} aria-label="${esc(F.t("findings.next", "Следующая находка"))}">${esc(F.t("findings.next_short", "След."))}${ic("chev")}</button>
      </div>

      <div class="foot fd-foot" role="toolbar" aria-label="${esc(F.t("findings.triage", "Разбор находки"))}">
        <div class="fd-foot-row">
          <button class="btn fd-fb-false ${finding.status === "false" ? "tonal on" : ""}"
            data-act="fd-set:${finding.id}:false"
            aria-pressed="${finding.status === "false"}">${ic("x")}<span>${esc(ST.false.l)}</span></button>
          <button class="btn fd-fb-ok ${finding.status === "confirmed" ? "tonal on" : "primary"}"
            data-act="fd-set:${finding.id}:confirmed"
            aria-pressed="${finding.status === "confirmed"}">${ic("check")}<span>${finding.status === "confirmed" ? ST.confirmed.l : F.t("findings.confirm", "Подтвердить")}</span></button>
          <button class="btn fd-fb-next" data-act="fd-nav:${nb.next || ""}"
            ${nb.next ? "" : "disabled"} aria-label="${esc(F.t("findings.next_aria", "Далее: следующая находка"))}"
            title="${esc(F.t("findings.next", "Следующая находка"))}">${ic("chev")}</button>
        </div>
      </div>`;
  }

  F.route("/p/finding/:id", {
    title: () => F.t("findings.finding", "Находка"),
    back: true,
    tab: "findings",
    hideMini: true,
    sub: p => {
      const nb = neighbors(p.id);
      return nb.i >= 0
        ? `${F.t("findings.n_of", { i: nb.i + 1, n: nb.n }, "{i} из {n}")} · ${F.project.name}`
        : F.project.name;
    },
    actions: p => {
      const nb = neighbors(p.id);
      return [
        {
          icon: "chev-up",
          act: nb.prev ? `fd-nav:${nb.prev}` : "fd-nav:",
          label: F.t("findings.prev", "Предыдущая находка"),
        },
        {
          icon: "chev-down",
          act: nb.next ? `fd-nav:${nb.next}` : "fd-nav:",
          label: F.t("findings.next", "Следующая находка"),
        },
        { icon: "more", act: `fd-more:${p.id}`, label: F.t("findings.more_menu", "Ещё") },
      ];
    },
    render: p =>
      F.withStates(() => renderDetail(p), {
        loading: "cards",
        empty: {
          icon: "bug",
          title: F.t("findings.empty_title_scan", "Находок нет: запустите скан"),
          text: F.t("findings.card_after", "Карточка появится после обнаружения."),
        },
      }),
    mount: (page, p) => {
      const nb = neighbors(p.id);
      F.$$("#tb-acts .ib").forEach((b, i) => {
        if ((i === 0 && !nb.prev) || (i === 1 && !nb.next)) ((b.disabled = true), b.classList.add("fd-dis"));
      });
      if (page.querySelector(".fd-foot")) page.classList.add("no-pb", "fd-dpg");
      if (F.dataTrail) F.dataTrail.mount(page);
    },
    unmount: () => revealed.clear(),
  });

  // ---------- card actions ----------
  const setStatus = (id, st, snack = true) => {
    const f = byId(id),
      prev = f.status;
    if (prev === st) return;
    setSt(id, st);
    F.render(true);
    if (snack)
      F.snack(F.t("findings.status_set", { st: ST[st].l }, "Статус: «{st}»"), {
        action: () => {
          setSt(id, prev);
          F.render(true);
        },
      });
  };
  const nowStr = () => {
    const d = new Date();
    return `${String(d.getDate()).padStart(2, "0")}.${String(d.getMonth() + 1).padStart(2, "0")}, ${String(d.getHours()).padStart(2, "0")}:${String(d.getMinutes()).padStart(2, "0")}`;
  };
  Object.assign(F.actions, {
    "fd-nav": id => {
      if (!id) return;
      const cur = F.cur && +F.cur.p.id;
      const o = navList(cur);
      F.go(`/p/finding/${id}`, { replace: true, anim: o.indexOf(+id) < o.indexOf(cur) ? "back" : "fwd" });
    },
    "fd-set": a => {
      const [id, st] = a.split(":");
      const f = byId(id);
      setStatus(+id, f && f.status === st ? "new" : st);
    },
    "fd-reveal": id => {
      id = +id;
      if (revealed.has(id)) {
        revealed.delete(id);
        F.render(true);
        return;
      }
      F.confirmFinger(
        () => {
          revealed.add(id);
          F.render(true);
        },
        F.t("common.show_secret", "показать секрет"),
      );
    },
    "fd-rel": path => {
      if (F.actions["dt-nav"]) F.actions["dt-nav"](path);
      else F.go(path);
    },
    "fd-restore-doc": id => {
      F.api.doc_restore([+id]);
      F.render(true);
      F.snack(F.t("findings.doc_restored", "Документ восстановлен в проекте"));
    },
    "fd-tag-filter": t => {
      state.f = { ...blankF(), sort: state.f.sort, tag: t };
      state.seg = "all";
      F.go("/p/findings");
    },
    "fd-status": id => {
      const f = byId(id);
      F.sheet({
        title: F.t("findings.status_title", "Статус находки"),
        html: Object.keys(ST)
          .map(
            k =>
              `<div class="srow ${f.status === k ? "on" : ""}"
                data-act="fd-status-set:${id}:${k}"
                role="button"><span class="pill ${ST[k].pill} fd-stic">${ic(ST[k].icon)}</span><span class="lbl">${ST[k].l}<small>${ST_HINT[k]}</small></span>${f.status === k ? ic("check") : ""}</div>`,
          )
          .join(""),
      });
    },
    "fd-status-set": a => {
      const [id, st] = a.split(":");
      F.closeSheet();
      setStatus(+id, st);
    },
    "fd-cve": c =>
      F.sheet({
        title: c,
        html: `<p class="lead"
          style="margin:0 2px 12px">${esc(F.t("findings.cve_note", "Описание уязвимости из локальной базы CVE (офлайн). Открыть в браузере можно только при наличии сети."))}</p><div class="kv">${kv(F.t("findings.identifier", "Идентификатор"), `<span class="mono">${esc(c)}</span>`)}${kv(F.t("findings.source", "Источник"), F.t("findings.nvd_snapshot", "NVD, снимок 15.11.2026"))}${F.isDemo ? kv(F.t("findings.exploit", "Эксплойт"), F.t("findings.poc_known", "Публичный PoC известен")) : ""}</div>`,
        footer: `<button class="btn"
          data-act="copy:${esc(c)}">${ic("copy")}${esc(F.t("findings.copy", "Копировать"))}</button><button class="btn primary"
          data-act="fd-ext:https://nvd.nist.gov/vuln/detail/${esc(c)}">${ic("open")}${esc(F.t("findings.open_nvd", "Открыть NVD"))}</button>`,
      }),
    // External link: with the core, copy to the clipboard (the WebView does not open a browser by itself); in
    // demo mode, show a message.
    "fd-ext": url => {
      F.closeSheet();
      if (F.isDemo) {
        F.snack(F.t("findings.ext_demo", "Откроется во внешнем браузере (демо)"));
        return;
      }
      if (url && F.actions.copy) F.actions.copy(url);
      F.snack(F.t("findings.link_copied", "Ссылка скопирована: откройте её в браузере"));
    },
    "fd-copy-ev": id => {
      const f = byId(id);
      const txt = f.evidence
        .split(S0)
        .map((p, i) => (i ? "••••••" + (p.split(S1)[1] || "") : p))
        .join("");
      F.actions.copy(txt);
    },
    "fd-hibp": id => {
      const f = byId(id);
      if (!f) return;
      const refId = (f.secret_refs && f.secret_refs[0]) || `f${f.id}:0`;
      F.api.secret_hibp_check(refId).then(
        r => {
          hibpRes[f.id] = r;
          F.render(true);
        },
        e => {
          hibpRes[f.id] = { err: e.message || String(e) };
          F.render(true);
        },
      );
    },
    "fd-playbook": id => {
      const f = byId(id);
      if (!f) return;
      F.api
        .finding_playbook(f.id)
        .then(pb => {
          // The core sends effort_label/key_label in the UI language; older cores only the codes.
          const eff =
            pb.effort_label ||
            {
              quick: F.t("findings.effort_quick", "Быстрое исправление"),
              low: F.t("findings.effort_low", "Низкая трудоёмкость"),
              medium: F.t("findings.effort_medium", "Средняя трудоёмкость"),
              high: F.t("findings.effort_high", "Высокая трудоёмкость"),
              planned: F.t("findings.effort_planned", "Плановая работа"),
            }[pb.effort] ||
            pb.effort;
          const keyLabel =
            pb.key_label || (pb.playbook_key === "sw" ? F.t("findings.pb_key_sw", "ПО и версии") : "");
          const verList = pb.verification || pb.verify || [];
          const refList = pb.references || pb.refs || [];
          F.sheet({
            title: pb.title || F.t("findings.pb_title", "План исправления"),
            cls: "fd-sheet",
            html: `<div class="chips wrap" style="margin-bottom:8px">
                ${keyLabel ? `<span class="pill mute">${esc(keyLabel)}</span>` : ""}
                <span class="pill tonal">${esc(eff)}</span>
              </div>
              <p class="lead">${esc(pb.summary || f.recommendation)}</p>
              <h4 class="sub-h">${esc(F.t("findings.pb_steps", "Пошаговый план"))}</h4>
              <div class="list">${(pb.steps || [])
                .map(
                  s => `<div class="row" style="align-items:flex-start"><div class="body">
                    <div class="t"><b>${s.step || s.order}. ${esc(String(s.title || "").replace(/^\s*\d+[.)]\s*/, ""))}</b> ${s.role || s.owner ? `<span class="pill mute">${esc(s.role || s.owner)}</span>` : ""}</div>
                    <div class="s">${esc(s.action || s.detail || "")}</div>
                    ${s.command ? `<pre class="fd-pre" style="margin-top:6px;padding:6px 8px;font-size:12px">${esc(s.command)}</pre>` : ""}
                  </div>${s.command ? `<div class="tail">${copyBtn(s.command, F.t("findings.copy_cmd", "Копировать команду"))}</div>` : ""}</div>`,
                )
                .join("")}</div>
              ${
                verList.length
                  ? `<h4 class="sub-h">${esc(F.t("findings.pb_check", "Чек-лист проверки"))}</h4>
                    <div class="list">${verList.map(v => `<div class="row">${ic("check")}<div class="body"><div class="s">${esc(v)}</div></div></div>`).join("")}</div>`
                  : ""
              }
              ${
                refList.length
                  ? `<h4 class="sub-h">${esc(F.t("findings.pb_std", "Стандарты и ориентиры"))}</h4>
                    <div class="chips wrap">${refList.map(r => `<span class="pill mute">${esc(r)}</span>`).join("")}</div>`
                  : ""
              }
              ${pb.disclaimer ? `<p class="fhint" style="margin-top:10px">${ic("info")} ${esc(pb.disclaimer)}</p>` : ""}`,
            footer: `<button class="btn primary" data-act="sheet-close">${esc(F.t("common.close", "Закрыть"))}</button>`,
          });
        })
        .catch(e =>
          F.snack(F.t("findings.pb_fail", { e: e.message || e }, "Не удалось загрузить плейбук: {e}")),
        );
    },
    "fd-more": id =>
      F.sheet({
        html: `
      <div class="srow"
        data-act="fd-to-report:${id}">${ic("report")}<span class="lbl">${picked().includes(+id) ? F.t("findings.remove_report", "Убрать из отчёта") : F.t("findings.add_report", "Добавить в отчёт")}<small>${esc(F.t("findings.in_sel_sub", { n: picked().length }, "В выборке: {n} · учитывается в конструкторе отчёта"))}</small></span></div>
      <div class="srow"
        data-act="fd-sel-many:${id}">${ic("tasks")}<span class="lbl">${esc(F.t("findings.select_many", "Выбрать несколько"))}<small>${esc(F.t("findings.select_many_sub", "Массовые действия в списке находок"))}</small></span></div>
      <div class="srow"
        data-act="fd-share:${id}">${ic("share")}<span class="lbl">${esc(F.t("findings.share", "Поделиться карточкой"))}<small>${F.isDemo ? F.t("findings.share_demo", "Без секретов, PDF") : F.t("findings.share_md", "Markdown без секретов")}</small></span></div>
      <div class="srow"
        data-act="fd-sev-one:${id}">${ic("alert")}<span class="lbl">${esc(F.t("findings.change_sev", "Изменить важность"))}</span></div>
      <div class="srow"
        data-act="fd-rescan:${id}">${ic("refresh")}<span class="lbl">${esc(F.t("findings.recheck", "Перепроверить"))}<small>${esc(F.t("findings.recheck_sub", "Повторить запрос модуля"))}</small></span></div>`,
      }),
    "fd-to-report": id => {
      id = +id;
      F.closeSheet();
      const before = picked();
      const on = before.includes(id);
      setPicked(on ? before.filter(x => x !== id) : before.concat(id));
      F.render(true);
      F.snack(
        on
          ? F.t("findings.removed_report", "Убрано из выборки отчёта")
          : F.t("findings.added_report", { n: picked().length }, "Добавлено в отчёт · в выборке {n}"),
        {
          label: F.t("findings.undo", "Отменить"),
          action: () => {
            setPicked(before);
            F.render(true);
          },
        },
      );
    },
    // Back to the list: pop the stack if the list is underneath the card, otherwise replace the card (no
    // second Findings screen on the stack).
    "fd-sel-many": id => {
      F.closeSheet();
      state.sel = new Set([+id]);
      state.seg = "all";
      const st = F.stack ? F.stack() : [];
      const i = st.lastIndexOf("/p/findings");
      if (i >= 0) F.back(st.length - 1 - i);
      else F.go("/p/findings", { replace: true, anim: "back" });
      F.onBack(() => {
        exitSel();
        return true;
      });
    },
    // Finding card as Markdown via export_build (kind findings, items=[id], secrets hidden) → system Share.
    "fd-share": id => {
      F.closeSheet();
      if (F.isDemo) {
        F.snack(F.t("findings.pdf_demo", "Карточка экспортирована в PDF (демо)"));
        return;
      }
      F.api
        .export_build("findings", "md", { items: [+id], secrets: false })
        .then(r => F.api.platform_share({ path: r.path, name: r.name, mime: "text/markdown" }))
        .then(
          r => {
            if (r && r.ok) F.snack(F.t("findings.sharing", { name: r.name }, "Отправка: {name}"));
          },
          e => F.snack(F.t("findings.share_fail", { e: e.message || e }, "Не удалось поделиться: {e}")),
        );
    },
    "fd-rescan": () => {
      F.closeSheet();
      F.snack(F.t("findings.rescan_queued", "Перепроверка поставлена в очередь скана"));
    },
    "fd-sev-one": id =>
      F.sheet({
        title: F.t("findings.severity", "Важность"),
        html: Object.keys(SEV)
          .map(
            k =>
              `<div class="srow ${byId(id).sev === k ? "on" : ""}"
                data-act="fd-sev-one-set:${id}:${k}"
                role="button"><span class="fd-sevdot sev-${k}">${ic(k === "crit" || k === "high" ? "alert" : "info")}</span><span class="lbl">${SEV[k]}</span>${byId(id).sev === k ? ic("check") : ""}</div>`,
          )
          .join(""),
      }),
    "fd-sev-one-set": a => {
      const [id, k] = a.split(":");
      const f = byId(id),
        prev = f.sev;
      upd(id, { sev: k });
      F.closeSheet();
      F.render(true);
      F.snack(F.t("findings.sev_set", { sev: SEV[k] }, "Важность: «{sev}»"), {
        action: () => {
          upd(id, { sev: prev });
          F.render(true);
        },
      });
    },
    // Notes.
    "fd-note": id =>
      F.sheet({
        title: F.t("findings.new_note", "Новая заметка"),
        html: `<label class="flabel" for="fd-nt"
          style="margin-top:4px">${esc(F.t("findings.note_text", "Текст заметки"))}</label><div class="field fd-ta"><textarea id="fd-nt" rows="5"
          maxlength="1000"
          placeholder="${esc(F.t("findings.note_ph", "Что проверили, кто подтвердил, что передать заказчику"))}"></textarea></div><div class="fhint"
          id="fd-ntc">0 / 1000</div>`,
        footer: `<button class="btn"
          data-act="sheet-close">${esc(F.t("common.cancel", "Отмена"))}</button><button class="btn primary" data-act="fd-note-save:${id}"
          id="fd-nsave" disabled>${esc(F.t("common.save", "Сохранить"))}</button>`,
        onMount: sh => {
          const t = sh.querySelector("#fd-nt");
          t.addEventListener("input", () => {
            sh.querySelector("#fd-ntc").textContent = `${t.value.length} / 1000`;
            sh.querySelector("#fd-nsave").disabled = !t.value.trim();
          });
          setTimeout(() => t.focus(), 260);
        },
      }),
    "fd-note-save": id => {
      const t = document.querySelector("#fd-nt");
      if (!t || !t.value.trim()) return;
      upd(id, {
        notes: byId(id).notes.concat({
          text: t.value.trim(),
          who: F.t("findings.you", "Вы"),
          time: nowStr(),
        }),
      });
      F.closeSheet();
      F.render(true);
      F.snack(F.t("findings.note_saved", "Заметка сохранена"));
    },
    "fd-note-del": a => {
      const [id, i] = a.split(":");
      const f = byId(id);
      const before = f.notes.slice();
      upd(id, { notes: before.filter((_, k) => k !== +i) });
      F.render(true);
      F.snack(F.t("findings.note_deleted", "Заметка удалена"), {
        action: () => {
          upd(id, { notes: before });
          F.render(true);
        },
      });
    },
    // Photos.
    // Photo evidence: with the core, the system photo picker / camera (platform_pick_image, copy in the
    // private
    // folder) → finding_photo_add copies the file into project storage; in demo mode a record without a file.
    "fd-photo": arg => {
      const [id, kind] = arg.split(":");
      const finding = byId(id);
      const now = new Date();
      const stamp = `${now.getFullYear()}${String(now.getMonth() + 1).padStart(2, "0")}${String(now.getDate()).padStart(2, "0")}_${String(now.getHours()).padStart(2, "0")}${String(now.getMinutes()).padStart(2, "0")}`;
      if (!F.isDemo) {
        F.closeSheet && F.closeSheet();
        F.api
          .platform_pick_image({ camera: kind === "cam" })
          .then(r => {
            const x = r && r.files && r.files[0];
            if (!x) return;
            return F.api
              .finding_photo_add(+id, {
                name: x.name,
                from: kind === "cam" ? F.t("findings.camera", "камера") : F.t("findings.gallery", "галерея"),
                path: x.path,
              })
              .then(() => {
                F.render(true);
                F.snack(
                  kind === "cam"
                    ? F.t("findings.photo_added", "Фото прикреплено")
                    : F.t("findings.image_added", "Изображение добавлено"),
                );
              });
          })
          .catch(e =>
            F.snack(F.t("findings.photo_fail", { e: e.message || e }, "Не удалось добавить фото: {e}")),
          );
        return;
      }
      upd(id, {
        photos: finding.photos.concat({
          name:
            kind === "cam" ? `IMG_${stamp}.jpg` : `${F.t("findings.image_file", "Изображение")}_${stamp}.jpg`,
          time: nowStr(),
          from: kind === "cam" ? F.t("findings.camera", "камера") : F.t("findings.gallery", "галерея"),
          kind,
        }),
      });
      F.render(true);
      F.snack(
        kind === "cam"
          ? F.t("findings.photo_added_demo", "Фото прикреплено (демо камеры)")
          : F.t("findings.image_added_demo", "Изображение добавлено из галереи (демо)"),
      );
    },
    "fd-ph": a => {
      const [id, i] = a.split(":");
      const ph = byId(id).photos[+i];
      F.sheet({
        title: ph.name,
        html: `<div class="fd-ph-big"><span class="fd-ph-img ${ph.kind === "cam" ? "cam" : ""}"><i></i><i></i><i></i></span></div><div class="kv"
          style="margin-top:12px">${kv(F.t("findings.added", "Добавлено"), esc(ph.time))}${F.isDemo ? kv("SHA-256", `<span class="mono fd-hash">${fakeSha(ph.name)}</span>`) : kv(F.t("findings.source", "Источник"), esc(ph.from || "-"))}</div>`,
        footer: `<button class="btn danger"
          data-act="fd-ph-del:${id}:${i}">${ic("x")}${esc(F.t("common.delete", "Удалить"))}</button><button class="btn"
          data-act="sheet-close">${esc(F.t("common.close", "Закрыть"))}</button>`,
      });
    },
    "fd-ph-del": a => {
      const [id, i] = a.split(":");
      const f = byId(id);
      const before = f.photos.slice();
      upd(id, { photos: before.filter((_, k) => k !== +i) });
      F.closeSheet();
      F.render(true);
      F.snack(F.t("findings.photo_deleted", "Фото удалено"), {
        action: () => {
          upd(id, { photos: before });
          F.render(true);
        },
      });
    },
    // Tags.
    "fd-tag-add": id => {
      const f = byId(id);
      const sugg = [
        F.t("findings.tag_report", "в отчёт"),
        F.t("findings.tag_perimeter", "внешний периметр"),
        "RCE",
        F.t("findings.tag_password", "пароль"),
        F.t("findings.tag_cloud", "облако"),
        F.t("findings.tag_mail", "почта"),
        F.t("findings.tag_manual", "проверить вручную"),
        "quick win",
      ].filter(t => !f.tags.includes(t));
      F.sheet({
        title: F.t("findings.add_tag", "Добавить тег"),
        html: `<div class="field">${ic("hash")}<input id="fd-tg" placeholder="${esc(F.t("findings.new_tag", "Новый тег"))}"
          maxlength="32"
          autocomplete="off"></div><div class="flabel">${esc(F.t("findings.frequent", "Часто используемые"))}</div><div class="chips wrap">${sugg
            .map(
              t => `<button class="chip"
          data-act="fd-tag-put:${id}:${esc(t)}">${esc(t)}</button>`,
            )
            .join("")}</div>`,
        footer: `<button class="btn primary block" data-act="fd-tag-put:${id}:">${esc(F.t("findings.add", "Добавить"))}</button>`,
      });
    },
    "fd-tag-put": a => {
      const [id, ...r] = a.split(":");
      let t = r.join(":");
      if (!t) {
        const i = document.querySelector("#fd-tg");
        t = i ? i.value.trim() : "";
      }
      if (!t) return;
      const f = byId(id);
      if (!f.tags.includes(t)) upd(id, { tags: f.tags.concat(t) });
      F.closeSheet();
      F.render(true);
    },
    "fd-tag-del": a => {
      const [id, ...r] = a.split(":");
      const t = r.join(":");
      const f = byId(id);
      const before = f.tags.slice();
      upd(id, { tags: before.filter(x => x !== t) });
      F.render(true);
      F.snack(F.t("findings.tag_deleted", { t }, "Тег «{t}» удалён"), {
        action: () => {
          upd(id, { tags: before });
          F.render(true);
        },
      });
    },
  });
})();
