// Documents list and document card.
// The /p/data/docs segment is rendered by F.dataDocs (called from data.js); the /p/doc/:id route lives here.
(function () {
  const F = window.FOCA,
    { ic, esc, ui } = F;
  const demo = window.DEMO;
  const util = () => F.dataUtil;
  const CHUNK = 40;

  // ================= state =================
  const blank = () => ({
    ext: [],
    author: [],
    sw: [],
    year: [],
    host: [],
    status: [],
    store: [],
    withF: false,
  });
  const state = (F.state.dataDocs = F.state.dataDocs || {
    sort: "date",
    f: blank(),
    shown: CHUNK,
    sel: null,
    deleted: new Set(),
    order: [],
  });
  // The "cleaned" mark comes from the project snapshot (doc.cleaned after F.api.doc_clean), not from a
  // global id set shared by all projects.
  const cleanOf = id => ((F.db.docs || []).find(x => x.id === +id) || {}).cleaned || null;
  const cleanPill = (id, long) => {
    const c = cleanOf(id);
    return !c
      ? ""
      : c.manual
        ? `<span class="pill warn">${ic("alert")}${esc(long ? F.t("docs.clean_secret_left", "Метаданные очищены, в тексте остался секрет") : F.t("docs.clean_partial", "Очищен частично"))}</span>`
        : `<span class="pill ok">${ic("eraser")}${esc(long ? F.t("docs.clean_meta", "Метаданные очищены") : F.t("docs.cleaned", "Очищен"))}</span>`;
  };
  let io = null,
    loading = false;

  const FI_ = () => ({
    secret: ["key", F.t("docs.fi_secret", "Секрет в тексте"), "var(--crit)"],
    gps: ["pin", F.t("docs.fi_gps", "GPS-координаты"), "var(--bad)"],
    path: ["path", F.t("docs.fi_path", "Внутренний путь"), "var(--warn)"],
    revisions: ["history", F.t("docs.fi_revisions", "Исправления и комментарии"), "var(--info)"],
    eol: ["app", F.t("docs.fi_eol", "Устаревшее ПО"), "var(--text-3)"],
    // Signature/redaction/hidden/revision signal and personal data (Doc.flags).
    forensic: ["shield", F.t("docs.fi_forensic", "Форензика: подпись, замазывание, скрытое"), "var(--bad)"],
    pii: ["user", F.t("docs.fi_pii", "Персональные данные"), "var(--warn)"],
  });
  const SORTS = () => [
    ["date", F.t("docs.sort_date_any", "Дата документа или находки: новые сначала")],
    ["date-asc", F.t("docs.sort_date_any_asc", "Дата документа или находки: старые сначала")],
    ["name", F.t("docs.sort_name", "Имя: А → Я")],
    ["size", F.t("docs.sort_size", "Размер: большие сначала")],
    ["findings", F.t("docs.sort_findings", "Больше находок")],
  ];
  const SORT_SHORT = () => ({
    date: F.t("docs.sorts_date", "Новые"),
    "date-asc": F.t("docs.sorts_date_asc", "Старые"),
    name: F.t("docs.sorts_name", "По имени"),
    size: F.t("docs.sorts_size", "По размеру"),
    findings: F.t("docs.sorts_findings", "По находкам"),
  });
  // Filter values are status codes (doc.status_code); labels are translated at render time.
  const STATUS_CODES = ["analyzed", "downloaded", "queued", "error"];
  const statusLabel = code => (F.docStatusLabel ? F.docStatusLabel(code) : code);

  // Date of a document for sorting and the row: the document's own creation date when the metadata
  // stage has read it, otherwise when FOCA-rs found it (start of the scan that queued it), marked as
  // such. Ids grow in discovery order and break ties inside one scan.
  const scanStart = sid => {
    if (!sid) return null;
    const s = (F.db.scans || []).find(x => x.id === sid);
    if (s && s.started_at) return new Date(s.started_at);
    if (F.scan && F.scan.scanId === sid && F.scan.startedAt) return new Date(F.scan.startedAt);
    return null;
  };
  const dateOf = d => {
    if (d.created_at) {
      const t = new Date(d.created_at);
      if (!isNaN(t)) return { t: t.getTime(), kind: "created" };
    }
    const f = scanStart(d.first_scan);
    return f && !isNaN(f) ? { t: f.getTime(), kind: "found" } : null;
  };
  const collator = () =>
    new Intl.Collator(F.i18n ? F.i18n.lang() : "ru", { numeric: true, sensitivity: "base" });
  const byName = (a, b) => collator().compare(a.name, b.name) || a.id - b.id;
  // Unknown dates go last in both directions; same date: discovery order (id), then name.
  const byDate = dir => (a, b) => {
    const x = dateOf(a),
      y = dateOf(b);
    if (!x || !y) return (!x ? 1 : 0) - (!y ? 1 : 0) || byName(a, b);
    return dir * (x.t - y.t) || dir * (a.id - b.id) || byName(a, b);
  };
  const dateLabel = d => {
    const x = dateOf(d);
    if (!x) return "";
    if (x.kind === "created") return d.created.slice(0, 10);
    const t = new Date(x.t);
    const same = new Date().toDateString() === t.toDateString();
    const when = same
      ? `${String(t.getHours()).padStart(2, "0")}:${String(t.getMinutes()).padStart(2, "0")}`
      : F.fmt && F.fmt.dmy
        ? F.fmt.dmy(t.toISOString())
        : t.toLocaleDateString();
    return F.t("docs.found_at", { t: when }, "найден {t}");
  };
  const fname = n => esc(n).replace(/_/g, "_<wbr>");
  const byId = id => demo.docs.find(d => d.id === +id);
  const live = () => demo.docs.filter(d => !d.deleted); // Deletion goes through F.api.doc_delete (the shared data layer).
  const activeCount = f =>
    f.ext.length +
    f.author.length +
    f.sw.length +
    f.year.length +
    f.host.length +
    f.status.length +
    (f.store || []).length +
    (f.withF ? 1 : 0);
  // External storage a document came from (provenance.storage), "" for files from the site itself.
  const storeKey = d => (d.provenance && d.provenance.storage) || "";
  const applyF = (f, list = live()) =>
    list.filter(
      d =>
        (!f.ext.length || f.ext.includes(d.ext)) &&
        (!f.author.length || f.author.includes(d.user.login)) &&
        (!f.sw.length || f.sw.includes(d.sw.name)) &&
        (!f.year.length || f.year.includes(String(d.year))) &&
        (!f.host.length || f.host.includes(d.host)) &&
        (!f.status.length || f.status.includes(d.status_code)) &&
        (!(f.store || []).length || f.store.includes(storeKey(d))) &&
        (!f.withF || d.findings.length),
    );
  /** Comparators for the document sort sheet; anything else sorts by date, newest first. */
  const DOC_SORT = {
    name: byName,
    // Larger first; unknown sizes (0 before the download) last.
    size: (a, b) => (!a.size ? 1 : 0) - (!b.size ? 1 : 0) || b.size - a.size || byName(a, b),
    findings: (a, b) => b.findings.length - a.findings.length || byDate(-1)(a, b),
    "date-asc": byDate(1),
  };
  const byDateDesc = byDate(-1);
  const sortL = (l, s) => l.slice().sort(DOC_SORT[s] || byDateDesc);
  // The chosen sort is kept per project (and survives live re-renders during a scan).
  const syncSort = () => {
    const pid = (F.db.project && F.db.project.id) || "";
    if (state.sortPid === pid) return;
    state.sortPid = pid;
    let s = null;
    try {
      s = localStorage.getItem(`foca-doc-sort:${pid}`);
    } catch (e) {}
    state.sort = s && SORTS().some(x => x[0] === s) ? s : "date";
  };
  const visible = () => {
    syncSort();
    return sortL(applyF(state.f), state.sort);
  };
  const pl = n =>
    F.plural(
      n,
      F.t("docs.doc_one", "документ"),
      F.t("docs.doc_few", "документа"),
      F.t("docs.doc_many", "документов"),
    );

  // ================= document row =================
  const fIcons = d => {
    const FI = FI_();
    return d.findings.some(k => k !== "eol")
      ? `<span class="dt-fi">${d.findings
          .filter(k => k !== "eol")
          .map(k =>
            FI[k]
              ? `<span class="dt-fic" role="img" aria-label="${esc(FI[k][1])}" title="${esc(FI[k][1])}"
                style="color:${FI[k][2]}">${ic(FI[k][0])}</span>`
              : "",
          )
          .join("")}</span>`
      : "";
  };
  // Where the document link came from (Doc.provenance): a crawled page, another document, or a file on
  // public external storage linked from the site.
  const STORAGE_NAME = {
    gdrive: "Google Drive",
    gdocs: "Google Docs",
    onedrive: "OneDrive",
    dropbox: "Dropbox",
    sharepoint: "SharePoint",
  };
  const provShort = p =>
    !p
      ? ""
      : p.storage
        ? STORAGE_NAME[p.storage] || p.storage
        : p.kind === "doc"
          ? F.t("docs.prov_short_doc", "из документа")
          : F.t("docs.prov_short_page", "со страницы");
  function provHTML(p) {
    if (!p) return "";
    const from =
      p.kind === "doc"
        ? p.from_doc
          ? `<a class="dt-link" data-act="dt-nav:/p/doc/${+p.from_doc}">${esc(p.from)}</a>`
          : esc(p.from)
        : `<span class="mono">${esc(F.decode(p.from))}</span>`;
    const line =
      p.kind === "doc"
        ? F.t("docs.prov_doc", { name: "\u0000" }, "Найден в документе «{name}»")
        : F.t("docs.prov_page", { url: "\u0000" }, "Ссылка со страницы {url}");
    const [a, b] = line.split("\u0000");
    const store = p.storage
      ? `<div class="dt-prov-l">${ic("folder")}<span>${esc(F.t("docs.prov_storage", { name: STORAGE_NAME[p.storage] || p.storage }, "Файл во внешнем хранилище {name}: скачан по ссылке с проверяемого сайта"))}</span></div>`
      : "";
    const exp = p.export
      ? `<div class="banner warn dt-prov-exp">${ic("alert")}<div>${esc(F.t("docs.prov_export", "Экспорт Google: метаданные сформировал Google, автор документа по ним не определяется"))}</div></div>`
      : "";
    return `<div class="dt-prov" id="dt-prov">${store}<div class="dt-prov-l">${ic(p.kind === "doc" ? "doc" : "link")}<span>${esc(a || "")}${from}${esc(b || "")}</span></div>${exp}</div>`;
  }
  F.docProvenance = { short: provShort, html: provHTML };
  const stPill = d =>
    d.stc === "ok"
      ? ""
      : `<span class="pill ${d.stc}">${d.stc === "bad" ? ic("alert") : d.stc === "info" ? ic("download") : ic("clock")}${esc(d.status)}</span>`;
  function rowHtml(d) {
    const sel = state.sel && state.sel.has(d.id);
    return `<div class="row tap dt-doc ${sel ? "sel" : ""}" data-id="${d.id}" role="button" tabindex="0"
      aria-label="${esc(d.name)}">
      ${state.sel ? `<span class="cbx dt-check" aria-hidden="true">${sel ? ic("check") : ""}</span>` : ""}
      <span class="ext ${esc(d.ext)}">${esc(d.ext)}</span>
      <div class="body"><span class="ext ${esc(d.ext)} dt-ext-in"
        aria-hidden="true">${esc(d.ext)}</span><div class="t dt-fname">${fname(d.name)}</div>
        <div class="s">${[d.user.login !== "-" ? esc(d.user.login) : "", esc(dateLabel(d)), d.size ? util().fmtSize(d.size) : ""].filter(Boolean).join(" · ")}${d.provenance ? ` · ${esc(provShort(d.provenance))}` : ""}</div>
        ${d.findings.some(k => k !== "eol") || d.stc !== "ok" || cleanOf(d.id) ? `<div class="dt-dmeta">${stPill(d)}${cleanPill(d.id)}${fIcons(d)}</div>` : ""}
      </div>
    </div>`;
  }

  function chipsActive() {
    const f = state.f,
      out = [];
    f.ext.forEach(v => out.push([`ext:${v}`, "." + v]));
    f.author.forEach(v => out.push([`author:${v}`, v]));
    f.sw.forEach(v => out.push([`sw:${v}`, v]));
    f.year.forEach(v => out.push([`year:${v}`, F.t("docs.year_chip", { y: v }, "{y} г.")]));
    f.host.forEach(v => out.push([`host:${v}`, v]));
    f.status.forEach(v => out.push([`status:${v}`, statusLabel(v)]));
    (f.store || []).forEach(v => out.push([`store:${v}`, STORAGE_NAME[v] || v]));
    if (f.withF) out.push(["withF:", F.t("docs.with_findings", "С находками")]);
    if (!out.length) return "";
    return `<div class="factive dt-active"
      aria-label="${esc(F.t("docs.active_filters", "Активные фильтры"))}">${out
        .map(
          ([k, l]) => `<button class="fchip dt-fchip"
      data-act="dd-unf:${esc(k)}"
      aria-label="${esc(F.t("docs.remove_filter", { f: l }, "Убрать фильтр {f}"))}"><span>${esc(l)}</span>${ic("x")}</button>`,
        )
        .join("")}<button class="btn text sm"
      data-act="dd-reset">${esc(F.t("docs.reset", "Сбросить"))}</button></div>`;
  }

  function render() {
    const list = visible();
    state.order = list.map(d => d.id);
    const sel = state.sel;
    const shown = Math.min(state.shown, list.length);
    const all = live().length;
    return `
      ${
        !sel && all
          ? `<button class="fx-ftsb" data-act="go:/p/docs-search">${ic("search")}<span>${esc(F.t("docs.fts", "Поиск по тексту документов"))}</span>${ic("chev", "chev")}</button>`
          : ""
      }
      ${
        sel
          ? `<div class="ctxbar dt-ctx" role="toolbar" aria-label="${esc(F.t("docs.sel_mode", "Режим выбора"))}">
        <button class="ib" data-act="dd-sel-exit" aria-label="${esc(F.t("docs.sel_exit", "Выйти из выбора"))}">${ic("x")}</button>
        <b class="ctxbar-n dt-ctx-n">${esc(F.t("docs.selected", { n: sel.size }, "Выбрано: {n}"))}</b>
        <button class="btn text sm"
          data-act="dd-sel-all">${esc(sel.size === list.length && list.length ? F.t("docs.unselect_all", "Снять все") : F.t("docs.select_all", { n: list.length }, "Выбрать все {n}"))}</button>
      </div>`
          : ""
      }
      <div class="dt-bar"><span class="dt-bar-n">${esc(list.length === all ? pl(all) : F.t("docs.n_of", { n: list.length, total: all }, "{n} из {total}"))}</span>${
        activeCount(state.f) && list.some(d => d.author)
          ? `<button class="dt-sortb"
        data-act="dd-dict"
        aria-label="${esc(F.t("docs.dict_aria", "Словарь логинов авторов выборки"))}">${ic("export")}<span>${esc(F.t("docs.dict", "Логины авторов"))}</span></button>`
          : ""
      }
        <button class="dt-sortb" data-act="dt-sort:docs"
          aria-label="${esc(F.t("docs.sort_aria", { s: SORTS().find(x => x[0] === state.sort)[1] }, "Сортировка: {s}"))}">${ic("sort")}<span>${esc(SORT_SHORT()[state.sort])}</span></button></div>
      ${chipsActive()}
      ${
        list.length
          ? `<div class="list dt-docs" id="dt-docs">${list.slice(0, shown).map(rowHtml).join("")}</div>
        ${
          shown < list.length
            ? `<div class="dt-more" id="dt-more"
              role="status">${ic("spin", "spin")}<span>${esc(F.t("docs.loading_shown", { n: shown, total: list.length }, "Загрузка… показано {n} из {total}"))}</span></div>`
            : list.length > CHUNK
              ? `<div class="dt-end">${esc(F.t("docs.all_shown", { n: pl(list.length) }, "Показаны все {n}"))}</div>`
              : ""
        }`
          : ui.empty({
              icon: "filter",
              title: F.t("docs.none_filtered", "Нет документов по фильтрам"),
              text: F.t("docs.none_filtered_text", "Измените или сбросьте фильтры."),
              action: `<button class="btn tonal" data-act="dd-reset">${esc(F.t("docs.reset_filters", "Сбросить фильтры"))}</button>`,
            })
      }
      ${
        sel
          ? `<div class="selbar dt-selbar" role="toolbar"
            aria-label="${esc(F.t("docs.sel_actions", "Действия с выбранными"))}"><div class="dt-selgrid">
        ${[
          ["dd-bulk:dl", "download", F.t("docs.bulk_dl", "Скачать")],
          ["dd-bulk:clean", "eraser", F.t("docs.bulk_clean", "Очистить")],
          ["dd-bulk:export", "export", F.t("docs.bulk_export", "Экспорт")],
          ["dd-bulk:del", "x", F.t("common.delete", "Удалить")],
        ]
          .map(
            ([a, i, l]) =>
              `<button data-act="${a}"
                ${sel.size ? "" : "disabled"} class="${a.endsWith("del") ? "dng" : ""}">${ic(i)}<span>${esc(l)}</span></button>`,
          )
          .join("")}
      </div></div>`
          : ""
      }`;
  }

  // ---------- incremental loading, gestures ----------
  function loadMore(page) {
    if (loading) return;
    const list = visible();
    if (state.shown >= list.length) return;
    loading = true;
    setTimeout(() => {
      // Simulates chunked loading from the database.
      loading = false;
      const box = page.querySelector("#dt-docs"),
        more = page.querySelector("#dt-more");
      if (!box || !page.isConnected) return;
      const from = state.shown;
      state.shown = Math.min(state.shown + CHUNK, list.length);
      box.insertAdjacentHTML("beforeend", list.slice(from, state.shown).map(rowHtml).join(""));
      if (state.shown >= list.length) {
        if (io) io.disconnect();
        more.outerHTML = `<div class="dt-end">${esc(F.t("docs.all_shown", { n: pl(list.length) }, "Показаны все {n}"))}</div>`;
      } else
        more.querySelector("span").textContent = F.t(
          "docs.loading_shown",
          { n: state.shown, total: list.length },
          "Загрузка… показано {n} из {total}",
        );
    }, 450);
  }
  function mount(page) {
    const on = !!state.sel && F.demo.mode === "normal";
    document.body.classList.toggle("dt-selecting", on);
    const bar = page.querySelector(".dt-selbar");
    // The bar slides in once per selection session; live re-renders during a scan rebuild the page and
    // must not replay the animation (the bar jumped on every update).
    if (bar && state.selBarShown === state.sel) bar.classList.add("no-anim");
    state.selBarShown = state.sel || null;
    if (on && bar) {
      page.style.paddingBottom = bar.offsetHeight + 24 + "px";
      document.body.style.setProperty("--dt-selbar-h", bar.offsetHeight + "px");
    }
    if (io) io.disconnect();
    const more = page.querySelector("#dt-more");
    if (more && "IntersectionObserver" in window) {
      io = new IntersectionObserver(
        es => {
          if (es.some(e => e.isIntersecting)) loadMore(page);
        },
        { root: page, rootMargin: "240px" },
      );
      io.observe(more);
    }
    const list = page.querySelector("#dt-docs");
    if (!list) return;
    let gesture = null,
      suppress = false;
    list.addEventListener("pointerdown", e => {
      if (e.button > 0) return;
      suppress = false;
      const rowEl = e.target.closest(".dt-doc");
      if (!rowEl) return;
      gesture = {
        id: +rowEl.dataset.id,
        x: e.clientX,
        y: e.clientY,
        t: setTimeout(() => {
          suppress = true;
          gesture = null;
          try {
            navigator.vibrate && navigator.vibrate(20);
          } catch (x) {}
          longPress(+rowEl.dataset.id);
        }, 500),
      };
    });
    list.addEventListener("pointermove", e => {
      if (gesture && (Math.abs(e.clientX - gesture.x) > 10 || Math.abs(e.clientY - gesture.y) > 10)) {
        clearTimeout(gesture.t);
        gesture = null;
        suppress = true;
      }
    });
    const end = () => {
      if (gesture) {
        clearTimeout(gesture.t);
        gesture = null;
      }
    };
    list.addEventListener("pointerup", end);
    list.addEventListener("pointercancel", () => {
      end();
      suppress = true;
    });
    list.addEventListener("click", e => {
      if (suppress) {
        suppress = false;
        e.stopPropagation();
        return;
      }
      const r = e.target.closest(".dt-doc");
      if (!r) return;
      const id = +r.dataset.id;
      if (state.sel) {
        state.sel.has(id) ? state.sel.delete(id) : state.sel.add(id);
        F.render(true);
      } else F.go(`/p/doc/${id}`);
    });
    list.addEventListener("keydown", e => {
      if ((e.key === "Enter" || e.key === " ") && e.target.closest(".dt-doc")) {
        e.preventDefault();
        e.target.click();
      }
    });
  }
  function unmount() {
    if (io) {
      io.disconnect();
      io = null;
    }
    document.body.classList.remove("dt-selecting");
    if (state.sel) state.sel = null;
  }

  function longPress(id) {
    if (state.sel) return;
    state.sel = new Set([id]);
    F.onBack(() => {
      exitSel();
      return true;
    });
    F.render(true);
  }
  function exitSel(silent) {
    state.sel = null;
    document.body.classList.remove("dt-selecting");
    F.onBack(null);
    const pg = F.page();
    if (pg) pg.style.paddingBottom = "";
    if (!silent && F.cur && /^\/p\/data/.test(F.cur.path)) F.render(true);
  }

  // ---------- sort and filter sheets ----------
  function sortSheet() {
    F.sheet({
      title: F.t("docs.sort_title", "Сортировка документов"),
      html: SORTS()
        .map(
          ([k, l]) =>
            `<div class="srow ${state.sort === k ? "on" : ""}" data-act="dd-sort:${k}"
            role="button">${ic(state.sort === k ? "check" : "dot")}<span class="lbl">${esc(l)}</span></div>`,
        )
        .join(""),
    });
  }
  function filterSheet() {
    const draft = { ...blank(), ...JSON.parse(JSON.stringify(state.f)) };
    const liveDocs = live();
    const cnt = fn => {
      const m = new Map();
      liveDocs.forEach(x => {
        const k = fn(x);
        m.set(k, (m.get(k) || 0) + 1);
      });
      return [...m.entries()];
    };
    const group = (key, items) =>
      `<div class="chips wrap"
        data-g="${key}">${items
          .map(
            ([v, l, n]) => `<button class="chip ${draft[key].includes(String(v)) ? "on" : ""}"
        data-v="${esc(v)}"
        aria-pressed="${draft[key].includes(String(v))}">${esc(l)}<span class="c">${n}</span></button>`,
          )
          .join("")}</div>`;
    const html = `
      <div class="flabel">${esc(F.t("docs.f_type", "Тип файла"))}</div>${group(
        "ext",
        cnt(x => x.ext)
          .sort((a, b) => b[1] - a[1])
          .map(([k, n]) => [k, "." + k, n]),
      )}
      <div class="flabel">${esc(F.t("docs.f_author", "Автор"))}</div>${group(
        "author",
        cnt(x => x.user.login)
          .sort((a, b) => b[1] - a[1])
          .map(([k, n]) => [k, k, n]),
      )}
      <div class="flabel">${esc(F.t("docs.f_sw", "Программа"))}</div>${group(
        "sw",
        cnt(x => x.sw.name)
          .sort((a, b) => b[1] - a[1])
          .map(([k, n]) => [k, k, n]),
      )}
      <div class="flabel">${esc(F.t("docs.f_year", "Год создания"))}</div>${group(
        "year",
        cnt(x => String(x.year))
          .sort((a, b) => b[0] - a[0])
          .map(([k, n]) => [k, k, n]),
      )}
      <div class="flabel">${esc(F.t("docs.f_host", "Хост"))}</div>${group(
        "host",
        cnt(x => x.host)
          .sort((a, b) => b[1] - a[1])
          .map(([k, n]) => [k, k, n]),
      )}
      ${(() => {
        // Storage providers are not hosts: files from them are grouped here, attributed to the linking site.
        const st = cnt(storeKey).filter(([k]) => k);
        return st.length
          ? `<div class="flabel">${esc(F.t("docs.f_storage", "Внешние хранилища"))}</div>${group(
              "store",
              st.sort((a, b) => b[1] - a[1]).map(([k, n]) => [k, STORAGE_NAME[k] || k, n]),
            )}`
          : "";
      })()}
      <div class="flabel">${esc(F.t("docs.f_status", "Статус загрузки"))}</div>${group(
        "status",
        STATUS_CODES.map(c => [c, statusLabel(c), liveDocs.filter(x => x.status_code === c).length]),
      )}
      <div class="dt-tgrow"><span class="lbl">${esc(F.t("docs.only_findings", "Только с находками"))}<small>${esc(F.t("docs.only_findings_sub", "Секреты, GPS, пути, исправления, форензика, персональные данные, устаревшее ПО"))}</small></span>${ui.toggle(draft.withF, "dd-wf", `aria-label="${esc(F.t("docs.only_findings", "Только с находками"))}"`)}</div>`;
    F.sheet({
      title: F.t("docs.filters_title", "Фильтры документов"),
      html,
      footer: `<button class="btn" data-act="dd-f-clear">${esc(F.t("docs.reset", "Сбросить"))}</button><button class="btn primary"
        data-act="dd-f-apply" id="dd-apply">${esc(F.t("docs.show", "Показать"))}</button>`,
      onMount: sh => {
        const upd = () => {
          const n = applyF(draft).length;
          const b = sh.querySelector("#dd-apply");
          b.textContent = n
            ? F.t("docs.show_n", { n }, "Показать {n}")
            : F.t("docs.no_docs", "Нет документов");
          b.disabled = !n;
        };
        sh.addEventListener(
          "click",
          e => {
            const c = e.target.closest(".chips .chip");
            if (!c) return;
            const k = c.parentElement.dataset.g,
              v = c.dataset.v,
              a = draft[k];
            a.includes(v) ? a.splice(a.indexOf(v), 1) : a.push(v);
            c.classList.toggle("on", a.includes(v));
            c.setAttribute("aria-pressed", a.includes(v));
            upd();
            e.stopPropagation();
          },
          true,
        );
        F.actions["dd-wf"] = (_, el) => {
          draft.withF = !draft.withF;
          el.classList.toggle("on", draft.withF);
          el.setAttribute("aria-checked", draft.withF);
          upd();
        };
        F.actions["dd-f-clear"] = () => {
          Object.assign(draft, blank());
          sh.querySelectorAll(".chips .chip").forEach(c => {
            c.classList.remove("on");
            c.setAttribute("aria-pressed", "false");
          });
          const t = sh.querySelector(".toggle");
          t.classList.remove("on");
          t.setAttribute("aria-checked", "false");
          upd();
        };
        F.actions["dd-f-apply"] = () => {
          state.f = draft;
          state.shown = CHUNK;
          F.closeSheet();
          F.render();
        };
        upd();
      },
    });
  }

  // ---------- list actions ----------
  Object.assign(F.actions, {
    "dd-sort": k => {
      state.sort = k;
      try {
        localStorage.setItem(`foca-doc-sort:${state.sortPid || ""}`, k);
      } catch (e) {}
      state.shown = CHUNK;
      F.closeSheet();
      F.render();
    },
    "dd-filters": () => filterSheet(),
    "dd-reset": () => {
      state.f = blank();
      state.shown = CHUNK;
      F.render();
    },
    "dd-unf": k => {
      const [t, v] = k.split(/:(.*)/s);
      if (t === "withF") state.f.withF = false;
      else state.f[t] = state.f[t].filter(x => x !== v);
      state.shown = CHUNK;
      F.render(true);
    },
    "dd-sel-exit": () => exitSel(),
    // Multi-select can be started from the top bar button, not only by long press.
    "dd-sel-start": () => {
      if (!visible().length) return;
      state.sel = new Set();
      F.onBack(() => {
        exitSel();
        return true;
      });
      F.render(true);
    },
    "dd-sel-all": () => {
      const ids = visible().map(d => d.id);
      state.sel = state.sel.size === ids.length ? new Set() : new Set(ids);
      if (state.sel.size > state.shown) state.shown = Math.min(ids.length, state.shown);
      F.render(true);
    },
    "dd-bulk": kind => {
      const ids = [...state.sel],
        n = ids.length;
      if (kind === "dl") {
        exitSel();
        if (F.isDemo) {
          F.snack(F.t("docs.dl_demo", { n: pl(n) }, "Скачивание {n} в «Загрузки» (демо)"));
          return;
        }
        // Document files from project storage → Downloads (MediaStore Download/FOCA-rs), one by one.
        let ok = 0,
          skip = 0;
        ids
          .reduce(
            (p, id) =>
              p.then(() =>
                F.api
                  .doc_file(id)
                  .then(f => F.api.platform_save({ path: f.path, name: f.name }))
                  .then(
                    r => {
                      if (r && r.ok) ok++;
                    },
                    () => {
                      skip++;
                    },
                  ),
              ),
            Promise.resolve(),
          )
          .then(() =>
            F.snack(
              F.t("docs.dl_saved", { n: pl(ok) }, "Сохранено в «Загрузки»: {n}") +
                (skip ? " · " + F.t("docs.dl_skipped", { n: skip }, "не скачаны: {n}") : ""),
            ),
          );
      } else if (kind === "clean") {
        exitSel();
        F.api.doc_clean(ids, F.hyg ? F.hyg.opts() : undefined).then(
          r =>
            showCleaned(r, F.t("docs.cleaned_many", { n: pl(n) }, "Очищенные копии в папке приложения: {n}")),
          e => F.snack(F.t("docs.clean_fail", { err: e.message || e }, "Не удалось очистить: {err}")),
        );
      } else if (kind === "export") {
        exitSel();
        if (F.exportSheet)
          F.exportSheet({
            kind: "docs",
            ids,
            count: n,
            title: F.t("docs.export_title", { n: pl(n) }, "Экспорт: {n}"),
          });
        else F.snack(F.t("docs.export_done", { n: pl(n) }, "Экспорт {n} в CSV, готово"));
      } else if (kind === "del") {
        F.api.doc_delete(ids);
        exitSel();
        F.snack(F.t("docs.deleted_n", { n: pl(n) }, "Удалено из проекта: {n}"), {
          action: () => {
            F.api.doc_restore(ids);
            F.render(true);
          },
        });
      }
    },
  });

  F.dataDocs = {
    render,
    mount,
    unmount,
    sortSheet,
    fname,
    count: () => live().length,
    selecting: () => !!state.sel,
    exitSel,
    setFilter: f => {
      state.f = { ...blank(), ...f };
      state.shown = CHUNK;
    },
    actions: () =>
      state.sel
        ? []
        : [
            ...(F.isDemo
              ? []
              : [{ icon: "plus", act: "dd-import", label: F.t("docs.add_files", "Добавить свои файлы") }]),
            ...(live().length
              ? [{ icon: "tasks", act: "dd-sel-start", label: F.t("docs.select_many", "Выбрать несколько") }]
              : []),
            {
              icon: "filter",
              act: "dd-filters",
              label: F.t("docs.filters", "Фильтры"),
              badge: activeCount(state.f) || "",
            },
            { icon: "more", act: "menu", label: F.t("app.menu", "Меню") },
          ],
  };

  // ================= DOCUMENT CARD =================
  const fakeSha = s => {
    let h = 2166136261 >>> 0,
      out = "";
    for (let k = 0; k < 8; k++) {
      for (const c of s + k) h = Math.imul(h ^ c.charCodeAt(0), 16777619) >>> 0;
      out += h.toString(16).padStart(8, "0");
    }
    return out;
  };
  const navList = id => (state.order.includes(+id) ? state.order : sortL(live(), state.sort).map(d => d.id));
  const neighbors = id => {
    const o = navList(id);
    const i = o.indexOf(+id);
    return i < 0 ? { i: -1, n: o.length } : { i, n: o.length, prev: o[i - 1], next: o[i + 1] };
  };
  const entityPath = (t, id) => F.dataEntityPath(t, id);
  const copyB = (txt, label) =>
    `<div class="kva"><button class="ib" data-act="copy:${esc(txt)}"
      aria-label="${esc(F.t("docs.copy_label", { l: label }, "Копировать: {l}"))}">${ic("copy")}</button></div>`;
  const kvx = (k, v, copy, path) =>
    `<div class="kvr ${path ? "tap" : ""}"
      ${path ? `data-act="dt-nav:${path}" role="link"` : ""}><div class="k">${esc(k)}</div><div class="v ${path ? "dt-link" : ""}">${v}${path ? ic("chev", "dt-lchev") : ""}</div>${copy ? copyB(copy, k) : ""}</div>`;

  // Revisions and comments come from document metadata (dates never precede creation).
  const revisions = d =>
    (d.revisions || []).map(r => ({ k: r.kind, who: r.who, when: F.fmt.dmyhm(r.at), text: r.text }));
  const REV = () => ({
    del: [F.t("docs.rev_del", "Удалено"), "bad"],
    ins: [F.t("docs.rev_ins", "Вставлено"), "ok"],
    com: [F.t("docs.rev_com", "Комментарий"), "info"],
  });

  // Metadata fields depend on the file type: office/PDF, photo (EXIF), .rdp, .lnk.
  function authorLabel(doc, isImg) {
    if (isImg) return F.t("docs.k_artist", "Автор (Artist)");
    if (doc.ext === "lnk") return F.t("docs.k_owner", "Владелец");
    if (doc.ext === "rdp") return F.t("docs.k_user", "Пользователь");
    return F.t("docs.f_author", "Автор");
  }
  function metaRows(doc, { u: user, modBy, isImg, swI, prI, foI }) {
    const host = kvx(F.t("docs.f_host", "Хост"), esc(doc.host), doc.host, entityPath("host", doc.host));
    const size = kvx(
      F.t("docs.k_size", "Размер"),
      `${util().fmtSize(doc.size)} · .${esc(doc.ext)}`,
      String(doc.size * 1024),
    );
    const author = user.nometa
      ? ""
      : kvx(
          authorLabel(doc, isImg),
          esc(user.name === user.login ? user.login : `${user.name} (${user.login})`),
          user.login,
          entityPath("person", user.login),
        );
    if (doc.rdp)
      return (
        author +
        kvx(
          F.t("docs.k_server_addr", "Адрес сервера"),
          `<span class="mono">${esc(doc.rdp.full_address)}</span>`,
          doc.rdp.full_address,
        ) +
        kvx(
          F.t("docs.k_username", "Имя пользователя"),
          `<span class="mono">${esc(doc.rdp.username)}</span>`,
          doc.rdp.username,
        ) +
        kvx(
          F.t("docs.k_server", "Сервер"),
          `<span class="mono">${esc(doc.rdp.gateway)}</span>`,
          doc.rdp.gateway,
          entityPath("pc", doc.rdp.gateway),
        ) +
        host +
        kvx(F.t("docs.k_mod_server", "Изменён на сервере"), esc(doc.created), doc.created) +
        size
      );
    if (doc.lnk)
      return (
        author +
        kvx(
          F.t("docs.k_target", "Целевой путь"),
          `<span class="mono">${esc(doc.lnk.target)}</span>`,
          doc.lnk.target,
          foI >= 0 ? entityPath("path", foI) : "",
        ) +
        kvx(
          F.t("docs.k_pc", "Компьютер"),
          `<span class="mono">${esc(doc.lnk.machine)}</span>`,
          doc.lnk.machine,
          entityPath("pc", doc.lnk.machine),
        ) +
        kvx(F.t("docs.k_mac", "MAC-адрес"), `<span class="mono">${esc(doc.lnk.mac)}</span>`, doc.lnk.mac) +
        kvx(
          F.t("docs.k_volume", "Серийный номер тома"),
          `<span class="mono">${esc(doc.lnk.volume_serial)}</span>`,
          doc.lnk.volume_serial,
        ) +
        host +
        kvx(F.t("docs.k_created", "Создан"), esc(doc.created), doc.created) +
        size
      );
    const sw = kvx(
      isImg ? F.t("docs.k_sw_device", "ПО / устройство") : F.t("docs.f_sw", "Программа"),
      esc(doc.sw.name) + ` <span class="muted">${esc(doc.sw.ver)}</span>`,
      `${doc.sw.name} ${doc.sw.ver}`,
      entityPath("software", swI),
    );
    if (isImg)
      return (
        author +
        sw +
        (doc.camera ? kvx(F.t("docs.k_camera", "Камера"), esc(doc.camera), doc.camera) : "") +
        host +
        kvx(F.t("docs.k_shot", "Снято"), esc(doc.created), doc.created) +
        size
      );
    const office = doc.sw.kind === "office";
    return (
      author +
      (office && modBy && !modBy.nometa
        ? kvx(
            F.t("docs.k_mod_by", "Изменил"),
            esc(modBy.login),
            modBy.login,
            entityPath("person", modBy.login),
          )
        : "") +
      (user.pc && user.pc !== "-" && office
        ? kvx(
            F.t("docs.k_pc", "Компьютер"),
            `<span class="mono">${esc(user.pc)}</span>`,
            user.pc,
            entityPath("pc", user.pc),
          )
        : "") +
      sw +
      host +
      (doc.folder !== "-"
        ? kvx(
            F.t("docs.k_folder", "Папка"),
            `<span class="mono">${esc(doc.folder)}</span>`,
            doc.folder,
            entityPath("path", foI),
          )
        : "") +
      (doc.printer !== "-"
        ? kvx(F.t("docs.k_printer", "Принтер"), esc(doc.printer), doc.printer, entityPath("printer", prI))
        : "") +
      kvx(F.t("docs.k_created", "Создан"), esc(doc.created), doc.created) +
      (doc.modified ? kvx(F.t("docs.k_modified", "Изменён"), esc(doc.modified), doc.modified) : "") +
      (doc.company ? kvx(F.t("docs.k_company", "Компания"), esc(doc.company), doc.company) : "") +
      ((doc.ext === "docx" || doc.ext === "doc") && /^\\\\/.test(doc.folder)
        ? kvx(
            F.t("docs.k_template", "Шаблон"),
            `<span class="mono">${esc(doc.folder)}\\Normal.dotm</span>`,
            doc.folder + "\\Normal.dotm",
          )
        : "") +
      size
    );
  }

  function renderDoc(params) {
    const doc = byId(params.id);
    if (!doc || doc.deleted)
      return ui.empty({
        icon: "doc",
        title: F.t("docs.not_found", "Документ не найден"),
        text: F.t("docs.not_found_text", "Возможно, он удалён из проекта."),
        action: `<button class="btn tonal" data-act="go:/p/data/docs">${esc(F.t("docs.to_list", "К списку документов"))}</button>`,
      });
    F.dataTrail.visit(F.current(), doc.name, "doc");
    const nb = neighbors(doc.id);
    const user = doc.user;
    const people = (F.demoData && F.demoData.people) || demo.users;
    const fnd = (F.demoFindings || []).filter(f => f.provenance && f.provenance.doc === doc.id);
    const secs = ((F.demoData && F.demoData.secrets) || []).filter(s => s.doc === doc.id);
    const swI = demo.software.indexOf(doc.sw);
    const prI = demo.printers.findIndex(x => x.name === doc.printer);
    const foI = demo.folders.indexOf(doc.folder);
    const sha = doc.sha256 || (F.isDemo ? fakeSha(doc.name) : "-"); // The real SHA-256 comes from the core (doc.sha256).
    const isImg = ["jpg", "png", "tiff", "heic", "mp4", "mov"].includes(doc.ext);
    const gps = doc.gps ? { ...doc.gps, dev: doc.camera || doc.sw.dev || "-" } : null; // GPS only for photos with coordinates.
    const revs = revisions(doc);
    const modBy = (doc.last_modified_by && people.find(x => x.login === doc.last_modified_by)) || user;
    const meta = doc.status_code === "analyzed";
    const NOMETA_TXT = {
      queued: F.t("docs.nometa_queued", "Файл в очереди на загрузку, метаданных пока нет."),
      downloaded: F.t(
        "docs.nometa_downloaded",
        "Файл скачан, но ещё не разобран. Метаданные появятся после этапа «Извлечение метаданных».",
      ),
      // error_kind "download"/"http": the file was never fetched; "parse" or unknown: it could not be processed.
      error:
        doc.error_kind === "download" || doc.error_kind === "http"
          ? doc.err
            ? F.t(
                "docs.nometa_error_why",
                { err: doc.err },
                "Файл не удалось скачать ({err}), метаданных нет.",
              )
            : F.t("docs.nometa_error", "Файл не удалось скачать, метаданных нет.")
          : doc.err
            ? F.t(
                "docs.nometa_proc_why",
                { err: doc.err },
                "Файл не удалось обработать ({err}), метаданных нет.",
              )
            : F.t("docs.nometa_proc", "Файл не удалось обработать, метаданных нет."),
    };
    const FI = FI_(),
      REVL = REV();
    const sameAuthor = user.nometa
      ? []
      : live()
          .filter(x => x.user.login === user.login && x.id !== doc.id)
          .slice(0, 3);
    const SECT = (F.demoData && F.demoData.SECT) || {};
    return `
      ${F.dataTrail.html()}
      <div class="card pad dt-dhero">
        <div class="dt-dh-top"><span class="ext ${esc(doc.ext)} dt-ext-l">${esc(doc.ext)}</span><span class="pill ${doc.stc}">${doc.stc === "ok" ? ic("check") : ic("info")}${esc(doc.status)}</span>${cleanPill(doc.id, true)}</div>
        <h1 class="dt-dh-name">${fname(doc.name)}</h1>
        <div class="dt-dh-s">${util().fmtSize(doc.size)} · ${esc(F.t("docs.created_at", { d: doc.created }, "создан {d}"))}</div>
        <div class="dt-url"><span class="mono">${esc(F.decode(doc.url))}</span><button class="ib"
          data-act="copy:${esc(doc.url)}" aria-label="${esc(F.t("docs.copy_url", "Копировать URL"))}">${ic("copy")}</button></div>
        ${provHTML(doc.provenance)}
        <div class="dt-dbtns">
          <button class="btn primary" data-act="dd-open:${doc.id}">${ic("open")}${esc(F.t("common.open", "Открыть"))}</button>
          <button class="btn tonal" data-act="dd-clean:${doc.id}">${ic("eraser")}${esc(F.t("docs.clean_btn", "Очистить метаданные"))}</button>
          <button class="btn" data-act="dd-share:${doc.id}">${ic("share")}${esc(F.t("docs.share", "Поделиться"))}</button>
        </div>
      </div>

      ${!meta ? `<div class="banner info">${ic("info")}<div>${esc(NOMETA_TXT[doc.status_code] || F.t("docs.nometa", "Метаданных нет."))}</div></div>` : ui.secH(F.t("docs.doc_findings", "Находки в документе"), doc.findings.length + fnd.length || "")}
      ${
        doc.findings.length
          ? `<div class="dt-flags">${doc.findings
              .map(k =>
                FI[k]
                  ? `<span class="dt-flag"
        style="--c:${FI[k][2]}">${ic(FI[k][0])}${esc(FI[k][1])}</span>`
                  : "",
              )
              .join("")}</div>`
          : ""
      }
      ${
        fnd.length
          ? `<div class="list">${fnd.map(f => ui.row({ lead: ui.leadIcon(f.sev === "crit" || f.sev === "high" ? "alert" : "info", util().SEVC[f.sev]), title: esc(f.title), sub: ui.sev(f.sev), act: `go:/p/finding/${f.id}` })).join("")}</div>`
          : meta && !doc.findings.length
            ? `<div class="card pad dt-ok">${ic("check")}${esc(F.t("docs.no_problems", "Проблем в документе не найдено"))}</div>`
            : ""
      }

      ${secs.length ? ui.secH(F.t("docs.secrets", "Секреты"), secs.length) + secs.map(s => `<div class="card dt-sec sev-${s.sev}"><div class="dt-sec-top"><span class="dt-sec-type">${ic((SECT[s.type] || [])[1] || "key")}${esc((SECT[s.type] || [F.t("docs.secret", "Секрет")])[0])}</span>${ui.sev(s.sev)}</div>${F.dataSecretValue(s)}<div class="dt-sec-where">${ic("pin")}${esc(s.where)}</div></div>`).join("") : ""}

      ${meta ? ui.secH(F.t("docs.metadata", "Метаданные")) + `<div class="kv dt-kv">${metaRows(doc, { u: user, modBy, isImg, swI, prI, foI })}</div>` : ""}

      ${F.fx ? F.fx.docBlocks(doc) : ""}
      ${F.ins ? F.ins.docBlocks(doc) : ""}

      ${doc.status_code === "analyzed" || doc.status_code === "downloaded" ? ui.secH(F.t("docs.hash", "Хеш файла")) : ""}
      ${
        doc.status_code === "analyzed" || doc.status_code === "downloaded"
          ? `<div class="card dt-sha" id="dt-sha">
        <div class="dt-sha-k">SHA-256</div>
        <div class="dt-sha-v mono" title="${esc(sha)}">${sha}</div>
        <div class="dt-sha-b"><button class="btn text sm" data-act="dd-sha"
          aria-expanded="false">${ic("chev-down")}<span>${esc(F.t("docs.show_full", "Показать полностью"))}</span></button><button class="ib"
          data-act="copy:${sha}" aria-label="${esc(F.t("docs.copy_sha", "Копировать SHA-256"))}">${ic("copy")}</button></div>
      </div>`
          : ""
      }

      ${
        revs.length
          ? ui.secH(F.t("docs.fi_revisions", "Исправления и комментарии"), revs.length) +
            `<div class="list">${revs
              .map(r => {
                const who = people.find(x => x.login === r.who) || { name: r.who, color: "#64748b" };
                return `<div class="row dt-rev tap" data-act="dt-nav:${entityPath("person", r.who)}"
                  role="link">${util().avatar(who)}<div class="body"><div class="dt-rev-h"><span class="pill ${REVL[r.k][1]}">${esc(REVL[r.k][0])}</span><span class="dt-rev-w">${esc(r.who)} · ${esc(r.when)}</span></div><div class="dt-rev-t ${r.k}">${esc(r.text)}</div></div></div>`;
              })
              .join("")}</div>`
          : ""
      }

      ${
        gps
          ? `${ui.secH(F.t("docs.fi_gps", "GPS-координаты"))}
        <div class="card dt-gps"><div class="dt-map" role="img"
          aria-label="${esc(F.t("docs.map_point", { p: gps.place }, "Точка на карте: {p}"))}"><span class="dt-pin">${ic("pin")}</span></div>
        <div class="kv dt-kv dt-gpskv">${kvx(F.t("docs.k_coords", "Координаты"), `<span class="mono">${gps.lat.toFixed(4)}, ${gps.lon.toFixed(4)}</span>`, `${gps.lat}, ${gps.lon}`)}${kvx(F.t("docs.k_place", "Место"), esc(gps.place), gps.place)}${kvx(F.t("docs.k_shot", "Снято"), esc(doc.created), doc.created)}</div></div>
        ${
          doc.thumb_diff
            ? `${ui.secH(F.t("docs.thumb_title", "Миниатюра EXIF ≠ фото"))}
        <div class="banner warn">${ic("alert")}<div>${esc(F.t("docs.thumb_text", "Встроенная миниатюра отличается от самого снимка: фото обрезали или отредактировали, а исходный кадр остался в EXIF."))}</div></div>
        <div class="dt-thumbs"><figure class="dt-th"><span class="dt-th-img a"
          aria-hidden="true"></span><figcaption>${esc(F.t("docs.thumb_photo", "Фото (опубликовано)"))}</figcaption></figure><figure class="dt-th"><span class="dt-th-img b"
          aria-hidden="true"></span><figcaption>${esc(F.t("docs.thumb_orig", "Миниатюра EXIF (исходник)"))}</figcaption></figure></div>`
            : ""
        }`
          : ""
      }

      ${
        sameAuthor.length
          ? ui.secH(
              F.t("docs.same_author", "Другие документы автора"),
              "",
              `<button class="sec-a"
        data-act="dt-docs-filter:${esc(JSON.stringify({ author: [user.login] }))}">${esc(F.t("common.all", "Все"))}</button>`,
            ) +
            `<div class="list">${sameAuthor.map(x => ui.row({ lead: `<span class="ext ${esc(x.ext)}">${esc(x.ext)}</span>`, title: fname(x.name), sub: `${esc(x.created.slice(0, 10))} · ${util().fmtSize(x.size)}`, act: `dt-nav:/p/doc/${x.id}` })).join("")}</div>`
          : ""
      }

      <div class="pn dt-pn">
        <button class="btn" data-act="dd-nav:${nb.prev || ""}"
          ${nb.prev ? "" : "disabled"} aria-label="${esc(F.t("docs.prev_doc", "Предыдущий документ"))}">${ic("chev-left")}${esc(F.t("docs.prev", "Пред."))}</button>
        <span class="muted">${nb.i >= 0 ? esc(F.t("docs.n_of", { n: nb.i + 1, total: nb.n }, "{n} из {total}")) : ""}</span>
        <button class="btn" data-act="dd-nav:${nb.next || ""}"
          ${nb.next ? "" : "disabled"} aria-label="${esc(F.t("docs.next_doc", "Следующий документ"))}">${esc(F.t("docs.next", "След."))}${ic("chev")}</button>
      </div>`;
  }

  F.route("/p/doc/:id", {
    title: () => F.t("docs.title", "Документ"),
    back: true,
    tab: "data",
    sub: p => {
      const nb = neighbors(p.id);
      return nb.i >= 0
        ? `${F.t("docs.n_of", { n: nb.i + 1, total: nb.n }, "{n} из {total}")} · ${F.project.name}`
        : F.project.name;
    },
    actions: p => {
      const nb = neighbors(p.id);
      return [
        {
          icon: "chev-up",
          act: `dd-nav:${nb.prev || ""}`,
          label: F.t("docs.prev_doc", "Предыдущий документ"),
        },
        {
          icon: "chev-down",
          act: `dd-nav:${nb.next || ""}`,
          label: F.t("docs.next_doc", "Следующий документ"),
        },
        { icon: "more", act: `dd-more:${p.id}`, label: F.t("docs.more", "Ещё") },
      ];
    },
    render: p =>
      F.withStates(() => renderDoc(p), {
        loading: "cards",
        empty: {
          icon: "doc",
          title: F.t("docs.empty", "Документов пока нет"),
          text: F.t("docs.empty_text", "Карточка появится после скачивания документа."),
        },
      }),
    mount: (page, p) => {
      const nb = neighbors(p.id);
      F.$$("#tb-acts .ib").forEach((b, i) => {
        if ((i === 0 && !nb.prev) || (i === 1 && !nb.next)) {
          b.disabled = true;
          b.classList.add("dt-dis");
        }
      });
      F.dataTrail.mount(page);
      if (F.fx) F.fx.mountDoc(page);
    },
  });

  // "Add your own files": system file picker (SAF) → copies in the private folder → doc_import (no network).
  F.actions["dd-import"] = () =>
    F.api
      .platform_pick_files({ multiple: true })
      .then(r => {
        const files = (r && r.files) || [];
        if (!files.length) return;
        F.snack(
          F.tp(
            "docs.parsing_many",
            files.length,
            { n: files.length },
            "Разбор {n} файла…|Разбор {n} файлов…|Разбор {n} файлов…",
          ),
        );
        return F.api.doc_import(files.map(f => f.path)).then(x => {
          F.render(true);
          F.snack(F.t("docs.imported", { n: pl(x.imported || 0) }, "Добавлено в проект: {n}"));
        });
      })
      .catch(e =>
        F.snack(F.t("docs.import_fail", { err: e.message || e }, "Не удалось добавить файлы: {err}")),
      );
  const shareDoc = id =>
    F.api
      .doc_file(id)
      .then(f => F.api.platform_share({ path: f.path, name: f.name }))
      .then(
        r => {
          if (r && r.ok) F.snack(F.t("docs.sending", { name: r.name }, "Отправка: {name}"));
        },
        e =>
          F.snack(
            e.code === "not_found"
              ? F.t("docs.not_downloaded", "Файл документа ещё не скачан")
              : F.t("docs.share_fail", { err: e.message || e }, "Не удалось поделиться: {err}"),
          ),
      );
  // Clean options: the core always strips document properties, people, paths, software and EXIF/GPS; only
  // these three are configurable (doc_clean options, the same as on the hygiene screens).
  const CLEAN_OPTS = () => [
    ["remove_annotation_authors", F.t("docs.co_authors", "Авторы комментариев и исправлений"), "PDF, ODF"],
    ["remove_embedded_files", F.t("docs.co_embedded", "Вложенные файлы"), "PDF"],
    ["remove_javascript", F.t("docs.co_js", "JavaScript и автодействия"), "PDF"],
  ];
  const PHOTO_EXTS = ["jpg", "jpeg", "png", "heic", "heif", "tif", "tiff", "webp"];
  function cleanOptsHtml(d) {
    const base = F.hyg ? F.hyg.opts() : {};
    const always = [
      F.t("docs.always_props", "свойства документа (автор, последний изменивший, компания)"),
      F.t("docs.always_paths", "пути, шаблон, принтер"),
      F.t("docs.always_sw", "программа и версия"),
    ];
    if (PHOTO_EXTS.includes(String(d.ext || "").toLowerCase()))
      always.push(F.t("docs.always_exif", "EXIF, GPS и миниатюра"));
    return `<p class="fhint">${ic("check")}${esc(F.t("docs.always", { list: always.join(", ") }, "Всегда удаляются: {list}."))}</p>
      ${CLEAN_OPTS()
        .map(([k, l, sub]) => ui.check(base[k] !== false, l, `toggle-check:${k}`, sub))
        .join("")}`;
  }
  const readCleanOpts = () => {
    const o = F.hyg ? F.hyg.opts() : {};
    document.querySelectorAll('.sheet [data-act^="toggle-check:"]').forEach(el => {
      o[el.dataset.act.split(":")[1]] = el.classList.contains("on");
    });
    return o;
  };
  // After cleaning: the before/after self-check screen; without it a short note (the copies stay in the
  // app's private folder until the user saves or shares them).
  function showCleaned(r, note) {
    const list = (r && r.cleaned) || [];
    if (F.hyg && list.length) return F.hyg.showResults(list, F.current());
    F.render(true);
    const man = list.filter(c => c.manual && c.manual.length).length;
    F.snack(
      note +
        (man
          ? " · " + F.t("docs.secret_left", { n: man }, "в {n} остался секрет в тексте, правьте вручную")
          : ""),
    );
  }
  Object.assign(F.actions, {
    "dd-nav": id => {
      if (!id) return;
      const cur = F.cur && +F.cur.p.id;
      const o = navList(cur);
      F.dataTrail.replaceNext();
      F.go(`/p/doc/${id}`, { replace: true, anim: o.indexOf(+id) < o.indexOf(cur) ? "back" : "fwd" });
    },
    // "Open": with the core, the system app chooser via Share (file from project storage).
    "dd-open": id => {
      if (F.isDemo) {
        F.snack(F.t("docs.open_demo", "Открывается во внешнем приложении (демо)"));
        return;
      }
      shareDoc(+id);
    },
    "dd-sha": (_, el) => {
      const c = el.closest(".dt-sha");
      const on = c.classList.toggle("full");
      el.setAttribute("aria-expanded", on);
      el.querySelector("span").textContent = on
        ? F.t("docs.collapse", "Свернуть")
        : F.t("docs.show_full", "Показать полностью");
      el.querySelector("use").setAttribute("href", on ? "#i-chev-up" : "#i-chev-down");
    },
    "dd-clean": id => {
      const d = byId(id);
      F.sheet({
        title: F.t("docs.clean_btn", "Очистить метаданные"),
        html: `<p class="lead"
          style="margin:0 2px 8px">${esc(F.t("docs.clean_lead", "Создаётся очищенная копия для передачи заказчику. Оригинал и доказательства в проекте не меняются."))}</p>
          ${cleanOptsHtml(d)}`,
        footer: `<button class="btn"
          data-act="sheet-close">${esc(F.t("common.cancel", "Отмена"))}</button><button class="btn primary"
          data-act="dd-clean-ok:${id}">${ic("eraser")}${esc(F.t("docs.clean_copy", "Очистить копию"))}</button>`,
      });
    },
    "dd-clean-ok": id => {
      const opts = readCleanOpts();
      F.closeSheet();
      F.api.doc_clean([+id], opts).then(
        r => showCleaned(r, F.t("docs.cleaned_one", "Очищенная копия сохранена в папке приложения")),
        e => F.snack(F.t("docs.clean_fail", { err: e.message || e }, "Не удалось очистить: {err}")),
      );
    },
    "dd-share": id =>
      F.sheet({
        title: F.t("docs.share", "Поделиться"),
        html: `
      <div class="srow"
        data-act="dd-share-do:file:${id}">${ic("doc")}<span class="lbl">${esc(F.t("docs.sh_file", "Файл документа"))}<small>${esc(F.t("docs.sh_file_sub", "Оригинал с метаданными"))}</small></span></div>
      <div class="srow"
        data-act="dd-share-do:clean:${id}">${ic("eraser")}<span class="lbl">${esc(F.t("docs.sh_clean", "Очищенная копия"))}<small>${esc(F.t("docs.sh_clean_sub", "Без метаданных"))}</small></span></div>
      <div class="srow"
        data-act="dd-share-do:link:${id}">${ic("link")}<span class="lbl">${esc(F.t("docs.sh_link", "Ссылка на источник"))}<small class="mono">${esc(byId(id).host)}</small></span></div>
      <div class="srow"
        data-act="dd-share-do:card:${id}">${ic("report")}<span class="lbl">${esc(F.isDemo ? F.t("docs.sh_card_pdf", "Карточка в PDF") : F.t("docs.sh_card_md", "Карточка в Markdown"))}<small>${esc(F.t("docs.sh_card_sub", "Метаданные и находки, без секретов"))}</small></span></div>`,
      }),
    // Share a document: file from project storage (doc_file), cleaned copy (doc_clean → path), link (to the
    // clipboard), or card (export_build kind docs, items=[id]) → platform_share.
    "dd-share-do": arg => {
      F.closeSheet();
      if (F.isDemo) {
        F.snack(F.t("docs.share_demo", "Открыто системное меню «Поделиться» (демо)"));
        return;
      }
      const [kind, id] = arg.split(":"),
        doc = byId(id);
      const fail = e =>
        F.snack(F.t("docs.share_fail", { err: e.message || e }, "Не удалось поделиться: {err}"));
      if (kind === "file") return shareDoc(+id);
      if (kind === "link") {
        if (F.actions.copy) F.actions.copy(doc.url || doc.host);
        return F.snack(F.t("docs.link_copied", "Ссылка на источник скопирована"));
      }
      if (kind === "clean")
        return F.api
          .doc_clean([+id])
          .then(r => {
            const c = (r.cleaned || [])[0];
            if (!c || !c.path) throw new Error(F.t("docs.no_clean_copy", "очищенная копия не создана"));
            F.render(true);
            return F.api.platform_share({ path: c.path, name: c.name });
          })
          .catch(fail);
      if (kind === "card")
        return F.api
          .export_build("docs", "md", { items: [+id], secrets: false })
          .then(r => F.api.platform_share({ path: r.path, name: r.name, mime: "text/markdown" }))
          .catch(fail);
    },
    "dd-more": id =>
      F.sheet({
        html: `
      <div class="srow"
        data-act="dd-to-report:${id}">${ic("report")}<span class="lbl">${esc(F.t("docs.to_report", "Добавить в отчёт"))}<small>${esc(F.t("docs.to_report_sub", "Находки документа: в выборку отчёта"))}</small></span></div>
      ${
        F.isDemo
          ? `<div class="srow"
        data-act="dd-more-do:redl">${ic("refresh")}<span class="lbl">${esc(F.t("docs.redl", "Скачать заново"))}<small>${esc(F.t("docs.redl_sub", "Повторить загрузку и анализ"))}</small></span></div>`
          : ""
      }
      <div class="srow" data-act="dd-del:${id}">${ic("x")}<span class="lbl">${esc(F.t("docs.del", "Удалить из проекта"))}</span></div>`,
      }),
    "dd-more-do": k => {
      F.closeSheet();
      F.snack(F.t("docs.queued", "Поставлено в очередь загрузки"));
    },
    // "Add to report" for a document: its findings join the report selection (settings.report.picked).
    "dd-to-report": id => {
      F.closeSheet();
      const ids = F.sel.related("doc", +id).findings.map(f => f.id);
      if (!ids.length) {
        F.snack(
          F.t(
            "docs.no_findings_report",
            "У документа нет находок. В отчёт попадает только раздел «Документы»",
          ),
        );
        return;
      }
      const before = F.sel.reportPicked();
      const pid = F.db.project.id;
      const next = [...new Set(before.concat(ids))];
      // The total comes from the saved selection, not from settings that may not have been updated yet.
      F.api.settings_set({ report: { picked: { [pid]: next } } }).then(
        () =>
          F.snack(
            F.t(
              "docs.report_added",
              { n: ids.length, total: next.length },
              "Находки документа в отчёте: {n} · всего в выборке {total}",
            ),
            {
              action: () =>
                F.api
                  .settings_set({ report: { picked: { [pid]: before } } })
                  .catch(e =>
                    F.snack(
                      F.t("docs.undo_fail", { err: (e && e.message) || e }, "Не удалось отменить: {err}"),
                    ),
                  ),
            },
          ),
        e =>
          F.snack(
            F.t("docs.report_fail", { err: (e && e.message) || e }, "Не удалось добавить в отчёт: {err}"),
          ),
      );
    },
    "dd-dict": () => {
      const logins = [
        ...new Set(
          visible()
            .map(d => d.author)
            .filter(Boolean),
        ),
      ];
      if (F.exportSheet)
        F.exportSheet({
          kind: "users",
          fmt: "dict",
          title: F.t("docs.dict_title", "Словарь авторов выборки"),
          items: logins,
          subject: F.t("docs.dict_subject", { n: logins.length }, "Авторы: {n} из выборки документов"),
          count: logins.length,
        });
    },
    "dd-del": id => {
      F.closeSheet();
      F.api.doc_delete([+id]);
      F.back();
      F.snack(F.t("docs.deleted", "Документ удалён из проекта"), {
        action: () => {
          F.api.doc_restore([+id]);
          F.render(true);
        },
      });
    },
  });
})();
