/*
 * Numeric input field (with direct typing) and the offline Help section (/help, /help/:id).
 * Help articles, screens list and glossary live in `locales/{en,ru,uk}/help.json` and are loaded
 * lazily over IPC (`i18n_bundle { lang, include_help: true }`) only when `/help` opens, keeping
 * the strict WebView CSP untouched and startup light.
 */
(function () {
  const F = window.FOCA;
  const { ic, esc, ui } = F;
  const NF = (F.state.numFields = {});
  const fmt = n => String(n).replace(".", ",");
  const t = (k, p, fb) => (F.t ? F.t(k, p, fb) : (fb ?? k));

  F.helpBtn = (id, label = "") =>
    `<button class="hl-i" data-act="go:/help/${id}"
      aria-label="${esc(t("help.help_aria", "Справка"))}${label ? ": " + esc(label) : ""}">${ic("info")}</button>`;
  const recPill = (d, v) => {
    if (!d.rec) return "";
    const inRec = v >= d.rec[0] && v <= d.rec[1];
    const unit = d.unit && d.unit[0] !== "/" ? "\u00a0" + d.unit : "";
    return `<span class="pill ${inRec ? "ok" : "warn"} nf-rec">${esc(
      t(
        "help.rec_pill",
        { min: fmt(d.rec[0]), max: fmt(d.rec[1]), unit },
        `рекомендуем ${fmt(d.rec[0])}-${fmt(d.rec[1])}${unit}`,
      ),
    )}</span>`;
  };
  F.numField = def => {
    NF[def.id] = def;
    const value = def.get();
    return `<div class="nf" data-nf="${def.id}">
      <div class="nf-top">
        <div class="nf-l"><label for="nf-${def.id}">${def.label}</label>${def.help ? F.helpBtn(def.help, def.label) : ""}${def.sub ? `<small>${def.sub}</small>` : ""}</div>
        <div class="nf-ctl">
          <button class="ib nf-b" data-act="nf-step:${def.id}:-1"
            aria-label="${esc(t("help.dec_aria", { label: def.label }, `Уменьшить: ${def.label}`))}"
              ${value <= def.min ? "disabled" : ""}>${ic("minus")}</button>
          <span class="nf-box"><input id="nf-${def.id}" class="nf-in" type="text"
            inputmode="numeric" pattern="[0-9]*" enterkeyhint="done" autocomplete="off" value="${value}"
            aria-describedby="nf-${def.id}-m"
            data-nf-in="${def.id}">${def.unit ? `<small class="nf-u">${def.unit}</small>` : ""}</span>
          <button class="ib nf-b" data-act="nf-step:${def.id}:1"
            aria-label="${esc(t("help.inc_aria", { label: def.label }, `Увеличить: ${def.label}`))}"
              ${value >= def.max ? "disabled" : ""}>${ic("plus")}</button>
        </div>
      </div>
      <div class="nf-m" id="nf-${def.id}-m"
        aria-live="polite">${recPill(def, value)}${def.note ? `<span class="nf-note">${def.note}</span>` : ""}</div>
      <div class="nf-err" id="nf-${def.id}-e" role="alert" hidden></div>
    </div>`;
  };
  /** Validates raw input; returns null when valid, otherwise the reason text. */
  const why = (d, raw) => {
    const s = String(raw).trim().replace(",", ".");
    if (!s) return t("help.err_empty", { min: d.min, max: d.max }, `Введите число от ${d.min} до ${d.max}`);
    if (!/^-?\d+$/.test(s)) return t("help.err_int", "Только целое число, без букв и дробей");
    const v = +s;
    const unit = d.unit ? "\u00a0" + d.unit : "";
    if (v < d.min)
      return t(
        "help.err_min",
        { min: d.min, unit, why: d.whyMin ? ": " + d.whyMin : "" },
        `Минимум ${d.min}${unit}${d.whyMin ? ": " + d.whyMin : ""}`,
      );
    if (v > d.max)
      return t(
        "help.err_max",
        { max: fmt(d.max), unit, why: d.whyMax ? ": " + d.whyMax : "" },
        `Максимум ${fmt(d.max)}${unit}${d.whyMax ? ": " + d.whyMax : ""}`,
      );
    return null;
  };
  const box = id => document.querySelector(`.nf[data-nf="${id}"]`);
  function show(id, value, err) {
    const el = box(id),
      def = NF[id];
    if (!el || !def) return;
    el.classList.toggle("bad", !!err);
    const errEl = el.querySelector(".nf-err");
    errEl.hidden = !err;
    errEl.innerHTML = err ? `${ic("alert")}${esc(err)}` : "";
    el.querySelector(".nf-in").setAttribute("aria-invalid", err ? "true" : "false");
    if (!err) {
      const msgEl = el.querySelector(".nf-m");
      msgEl.innerHTML = `${recPill(def, value)}${def.note ? `<span class="nf-note">${def.note}</span>` : ""}`;
      const [mi, pl] = el.querySelectorAll(".nf-b");
      mi.disabled = value <= def.min;
      pl.disabled = value >= def.max;
    }
  }
  function apply(id, raw) {
    const def = NF[id];
    if (!def) return false;
    const err = why(def, raw);
    if (err) {
      show(id, null, err);
      return false;
    }
    const value = +String(raw).trim();
    const inp = box(id) && box(id).querySelector(".nf-in");
    if (inp) {
      inp.value = value;
      inp.defaultValue = String(value);
    }
    show(id, value, null);
    if (value !== def.get()) def.set(value);
    return true;
  }
  F.numApply = apply;
  F.actions["nf-step"] = a => {
    const [id, dir] = a.split(":"),
      d = NF[id];
    if (!d) return;
    const inp = box(id) && box(id).querySelector(".nf-in");
    const cur = inp && !why(d, inp.value) ? +inp.value : d.get();
    const v = Math.max(d.min, Math.min(d.max, cur + +dir * (d.step || 1)));
    if (inp) inp.value = v;
    apply(id, v);
  };
  document.addEventListener("keydown", e => {
    const i = e.target.closest && e.target.closest("[data-nf-in]");
    if (!i) return;
    if (e.key === "Enter") {
      e.preventDefault();
      if (apply(i.dataset.nfIn, i.value)) i.blur();
    }
  });
  document.addEventListener("focusout", e => {
    const i = e.target.closest && e.target.closest("[data-nf-in]");
    if (i && i.value !== i.defaultValue) apply(i.dataset.nfIn, i.value);
  });

  // ================= OFFLINE HELP (LAZY-LOADED FROM locales/{en,ru,uk}/help.json VIA IPC) =================
  const helpState = (F.state.help = F.state.help || { q: "", error: false });
  const getHelp = () => (F.i18n && F.i18n.help ? F.i18n.help() : null);
  const ensureHelp = () => {
    if (getHelp()) return;
    if (!F.i18n || !F.i18n.loadHelp) return;
    F.i18n.loadHelp().then(
      data => {
        helpState.error = !data;
        if (F.cur && F.cur.path && F.cur.path.startsWith("/help") && F.render) F.render(true);
      },
      () => {
        helpState.error = true;
        if (F.cur && F.cur.path && F.cur.path.startsWith("/help") && F.render) F.render(true);
      },
    );
  };
  Object.defineProperty(F, "HELP", {
    configurable: true,
    get: () => (getHelp() || {}).articles || [],
  });

  const strip = h =>
    String(h || "")
      .replace(/<[^>]+>/g, " ")
      .replace(/&nbsp;/g, " ")
      .replace(/\s+/g, " ")
      .trim();

  function bodyOf(data, article) {
    const screens = data.screens || [];
    const glossary = data.glossary || [];
    const accMap = data.acc || {};
    if (article.id === "screens")
      return `<p class="hl-lead">${esc(data.screens_lead || "")}</p><dl class="hl-gl">${screens.map(([ti, d]) => `<dt>${esc(ti)}</dt><dd>${esc(d)}</dd>`).join("")}</dl>`;
    if (article.id === "profiles") {
      const sources = F.SOURCE_LIST || [],
        groups = (F.SOURCE_GROUPS || []).concat([
          ["key", t("help.extra_key_group", "Дополнительно, с ключом")],
        ]);
      return `${data.profiles_html || ""}
        ${groups
          .map(
            ([g, gt]) =>
              `<h3>${esc(F.sourceGroupName && g !== "key" ? F.sourceGroupName([g, gt]) : gt)}</h3><div class="hl-srcs">${sources
                .filter(s => s[2] === g)
                .map(
                  s =>
                    `<div class="hl-src"><b>${esc(F.sourceName ? F.sourceName(s) : s[1])}</b><p>${esc(F.sourceDesc ? F.sourceDesc(s) : s[4])}</p><span class="pill ${s[3] === "key" ? "mute" : s[3] === "target" || s[3] === "dns" ? "warn" : "ok"}">${esc(accMap[s[3]] || "")}</span><span class="pill ${s[3] === "target" || s[3] === "dns" ? "warn" : "info"}">${esc(s[3] === "target" || s[3] === "dns" ? t("help.pill_active", "активный") : t("help.pill_passive", "пассивный"))}</span></div>`,
                )
                .join("")}</div>`,
          )
          .join("")}`;
    }
    if (article.id === "glossary")
      return `<dl class="hl-gl">${glossary.map(([ti, d]) => `<dt id="g-${esc(ti)}">${esc(ti)}</dt><dd>${esc(d)}</dd>`).join("")}</dl>`;
    return article.body || "";
  }

  const hrow = a =>
    ui.row({
      lead: ui.leadIcon(a.icon || "info", "var(--accent)"),
      title: esc(a.t),
      sub: esc(a.sub || ""),
      act: `go:/help/${a.id}`,
      chev: true,
    });
  const mark = (s, q) => {
    const i = s.toLowerCase().indexOf(q.toLowerCase());
    if (i < 0) return esc(s);
    return (
      esc(s.slice(0, i)) + "<mark>" + esc(s.slice(i, i + q.length)) + "</mark>" + esc(s.slice(i + q.length))
    );
  };
  const snip = (text, q) => {
    const i = text.toLowerCase().indexOf(q.toLowerCase());
    if (i < 0) return "";
    const a = Math.max(0, i - 40);
    return (a ? "…" : "") + text.slice(a, i + q.length + 60) + "…";
  };

  function search(data, query) {
    query = query.trim();
    if (query.length < 2) return null;
    const ql = query.toLowerCase(),
      res = [];
    (data.articles || []).forEach(article => {
      const text = strip(bodyOf(data, article)),
        inT = (article.t + " " + (article.sub || "")).toLowerCase().includes(ql),
        inB = text.toLowerCase().includes(ql);
      if (inT || inB)
        res.push({
          score: inT ? 0 : 1,
          html: ui.row({
            lead: ui.leadIcon(article.icon || "info", "var(--accent)"),
            title: mark(article.t, query),
            sub: inB ? mark(snip(text, query), query) : esc(article.sub || ""),
            act: `go:/help/${article.id}`,
            chev: true,
          }),
        });
    });
    (data.glossary || []).forEach(([ti, d]) => {
      if ((ti + " " + d).toLowerCase().includes(ql))
        res.push({
          score: ti.toLowerCase().includes(ql) ? 0 : 2,
          html: ui.row({
            lead: ui.leadIcon("note"),
            title: mark(ti, query),
            sub: `${esc(t("help.glossary", "Глоссарий"))} · ${mark(d, query)}`,
            act: "go:/help/glossary",
            chev: true,
          }),
        });
    });
    return res.sort((a, b) => a.score - b.score);
  }

  function homeSecs(data) {
    const secT = data.sections || {};
    const list = data.articles || [];
    return ["start", "problem", "set", "docs", "ref"]
      .map(
        s =>
          `${ui.secH(secT[s] || s)}<div class="list hl-sec">${list
            .filter(a => a.sec === s)
            .map(hrow)
            .join("")}</div>`,
      )
      .join("");
  }

  function resHTML(data) {
    const r = search(data, helpState.q);
    if (!r) return homeSecs(data);
    if (!r.length)
      return ui.empty({
        icon: "search",
        title: t("common.nothing_found", "Ничего не нашлось"),
        text: t("help.empty_text", "Попробуйте другое слово: «капча», «фон», «ключ», «скоуп»."),
      });
    return `${ui.secH(t("common.found", "Найдено"), r.length)}<div class="list hl-res">${r.map(x => x.html).join("")}</div>`;
  }

  function renderHome() {
    const data = getHelp();
    if (!data) {
      ensureHelp();
      return helpState.error ? ui.error() : ui.skeletonList(8);
    }
    return `<div class="field hl-search">${ic("search")}<input id="hl-q" type="search"
      placeholder="${esc(t("help.search_placeholder", "Поиск: «капча», «потоки», «Tor»…"))}" value="${esc(helpState.q)}" autocomplete="off"
      enterkeyhint="search" aria-label="${esc(t("help.search_aria", "Поиск по справке"))}"></div>
      <div id="hl-res" aria-live="polite">${resHTML(data)}</div>`;
  }

  function renderArticle(p) {
    const data = getHelp();
    if (!data) {
      ensureHelp();
      return helpState.error ? ui.error() : ui.skeletonCards(3);
    }
    const list = data.articles || [];
    const article = list.find(x => x.id === p.id);
    if (!article)
      return ui.empty({
        icon: "info",
        title: t("help.not_found", "Статья не найдена"),
        text: t("help.not_found_text", "Откройте раздел «Помощь» и найдите нужное через поиск."),
        action: `<button class="btn tonal" data-act="go:/help">${esc(t("help.title", "Помощь"))}</button>`,
      });
    const rel = (article.rel || []).map(id => list.find(x => x.id === id)).filter(Boolean);
    return `<div class="hl-body">${bodyOf(data, article)}</div>
      ${
        article.go
          ? `<button class="btn primary block hl-go"
        data-act="go:${article.go[1]}">${ic("open")}${esc(article.go[0])}</button>`
          : ""
      }
      ${
        article.act
          ? `<button class="btn ${article.go ? "tonal" : "primary"} block hl-go"
        data-act="${article.act[1]}">${ic(article.act[2] || "open")}${esc(article.act[0])}</button>`
          : ""
      }
      ${rel.length ? `${ui.secH(t("common.see_also", "См. также"))}<div class="list hl-rel">${rel.map(hrow).join("")}</div>` : ""}
      <p class="fhint">${ic("info")}${esc(t("help.offline_note", "Справка работает без интернета."))}</p>`;
  }

  F.route("/help", {
    title: () => t("help.title", "Помощь"),
    sub: () => t("help.sub", "работает без интернета"),
    nav: false,
    back: true,
    actions: [],
    hideMini: true,
    render: () => F.withStates(renderHome, { loading: "list" }),
    mount: page => {
      page.classList.add("hl-pg");
      const i = page.querySelector("#hl-q");
      if (!i) return;
      i.addEventListener("input", () => {
        helpState.q = i.value;
        const data = getHelp();
        const r = page.querySelector("#hl-res");
        if (r && data) r.innerHTML = resHTML(data);
      });
    },
  });
  F.route("/help/:id", {
    title: p => {
      const data = getHelp();
      const a = data && (data.articles || []).find(x => x.id === p.id);
      return a ? a.t : t("help.title", "Помощь");
    },
    sub: p => {
      const data = getHelp();
      const a = data && (data.articles || []).find(x => x.id === p.id);
      return a ? (data.sections || {})[a.sec] || t("help.title", "Помощь") : t("help.title", "Помощь");
    },
    nav: false,
    back: true,
    actions: [],
    hideMini: true,
    render: p => F.withStates(() => renderArticle(p), { loading: "cards" }),
    mount: page => page.classList.add("hl-pg"),
  });
})();
