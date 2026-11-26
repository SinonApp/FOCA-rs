/*
 * Settings → Wordlists: wordlists and parameters for the site file search (foca-fuzz).
 * Built-in lists (SecLists, MIT) are always available; large ones are downloaded on demand (the core
 * verifies
 * size and SHA-256); custom ones are imported via platform_pick_files. Selected wordlists
 * (settings.fuzz.wordlists) are probed at the site root by the "custom wordlist" module.
 * Data: F.api.wordlists_list; parameters: settings.fuzz.
 */
(function () {
  const F = window.FOCA;
  const { ui, ic, esc } = F;
  const state = { data: null, busy: {}, err: "" };
  // Built-in wordlists that modules pick up on their own (not offered for the custom-wordlist module).
  const AUTO = [
    "quickhits",
    "db-backups",
    "dsstore",
    "dns-top5000",
    "ext-most-common",
    "ext-compressed",
    "ext-all",
  ];
  const fz = () => (F.db.settings || {}).fuzz || {};
  const num = n => Number(n || 0).toLocaleString(F.i18n.lang() || "ru");
  const size = n =>
    n >= 1048576
      ? F.t(
          "wordlists.size_mb",
          { n: (n / 1048576).toFixed(1).replace(".", F.i18n.lang() === "en" ? "." : ",") },
          "{n} МБ",
        )
      : F.t("wordlists.size_kb", { n: Math.max(1, Math.round((n || 0) / 1024)) }, "{n} КБ");
  const selected = () => fz().wordlists || [];
  function load(force) {
    if (state.loading || ((state.data || state.err) && !force)) return;
    state.loading = true;
    F.api
      .wordlists_list()
      .then(
        d => {
          state.data = d;
          state.err = "";
        },
        e => {
          state.err = e.message || String(e);
        },
      )
      .then(() => {
        state.loading = false;
        if (F.cur && F.cur.path === "/settings/wordlists") F.render(true);
      });
  }
  /** Numeric input with ± buttons (F.numField from help.js); the value is applied on blur/Enter. */
  const nf = (k, label, unit, min, max, rec, note, whyMax, whyMin, step = 1) =>
    F.numField({
      id: "wl-" + k,
      label,
      unit,
      min,
      max,
      step,
      rec,
      note,
      help: "set-fuzz",
      whyMax,
      whyMin,
      get: () => +(fz()[k] || 0),
      set: v => saveFz({ [k]: v }),
    });
  // Built-in and downloadable wordlist names come from the core in Russian: translate by id.
  const wlName = w =>
    w.kind === "custom" ? w.name : F.t(`core.wordlist.${w.id}.name`, w.name || String(w.id || ""));
  const wlSource = w => (w.kind === "custom" ? F.t("core.wordlist.custom_source", w.source || "") : w.source);
  function row(w) {
    const on = selected().includes(w.id),
      auto = w.kind === "builtin" && (AUTO.includes(w.id) || /^cms-/.test(w.id));
    const busy = state.busy[w.id];
    let tail = "",
      btn = "";
    if (w.kind === "remote" && !w.downloaded)
      btn = `<button class="btn sm tonal" data-act="wl-dl:${esc(w.id)}"
        ${busy ? "disabled" : ""} aria-label="${esc(F.t("wordlists.download_aria", { name: wlName(w) }, "Скачать словарь {name}"))}">${ic(busy ? "spin" : "download", busy ? "spin" : "")}${busy ? esc(F.t("wordlists.downloading", "Скачиваем…")) : esc(F.t("wordlists.download_size", { size: size(w.size) }, "Скачать · {size}"))}</button>`;
    else if (w.kind !== "builtin")
      btn = `<button class="btn sm" data-act="wl-del:${esc(w.id)}"
        aria-label="${esc(F.t("wordlists.delete_aria", { name: wlName(w) }, "Удалить словарь {name}"))}">${ic("trash")}${esc(F.t("common.delete", "Удалить"))}</button>`;
    if (!auto && w.downloaded)
      tail = ui.toggle(
        on,
        `wl-use:${esc(w.id)}`,
        `aria-label="${esc(F.t("wordlists.use_aria", { name: wlName(w) }, "Использовать словарь {name}"))}"`,
      );
    const sub = `${esc(F.tp("wordlists.lines", w.lines, { n: num(w.lines) }, "{n} строка|{n} строки|{n} строк"))} · ${size(w.size)} · ${esc(wlSource(w))}${auto ? `<div class="st-rpill"><span class="pill mute">${ic("check")}${esc(F.t("wordlists.auto_used", "Используется модулями автоматически"))}</span></div>` : on ? `<div class="st-rpill"><span class="pill info">${ic("check")}${esc(F.t("wordlists.root_checked", "Проверяется в корне сайта"))}</span></div>` : ""}${btn ? `<div class="btnrow wl-b">${btn}</div>` : ""}`;
    return ui.row({
      lead: ui.leadIcon(
        w.kind === "custom" ? "doc" : w.kind === "remote" ? "download" : "folder",
        on ? "var(--accent)" : "",
      ),
      title: esc(wlName(w)),
      sub,
      tail,
      attrs: `data-wl="${esc(w.id)}"`,
    });
  }
  function render() {
    load();
    const fuzzCfg = fz(),
      data = state.data;
    const items = data ? data.items : [];
    const grp = k => items.filter(w => w.kind === k);
    const excl = fuzzCfg.exclude_paths || [];
    return `
      <p class="lead st-lead">${esc(F.t("wordlists.lead", "Поиск забытых документов, бэкапов и служебных файлов на сайте заказчика работает в профиле «Полный» (или «Свой» с модулем перебора) по целям скоупа. Здесь: щадящие лимиты по умолчанию и словари."))}</p>
      ${ui.secH(F.t("wordlists.params", "Параметры перебора"))}
      <div class="card nfs st-nfs">
        ${nf("rate", F.t("wordlists.nf_rate", "Скорость"), F.t("wordlists.nf_rate_unit", "/с"), 1, 10, [3, 5], F.t("wordlists.nf_rate_note", "сайт заказчика не должен заметить нагрузку"), F.t("wordlists.nf_rate_why_max", "быстрее перебор по сайту заказчика не идёт"), F.t("wordlists.nf_rate_why_min", "меньше одного запроса в секунду не бывает"))}
        ${nf("max_requests", F.t("wordlists.nf_max_requests", "Бюджет на скан"), F.t("wordlists.nf_max_requests_unit", "запр."), 500, 20000, [2000, 5000], F.t("wordlists.nf_max_requests_note", "общий на все адреса"), F.t("wordlists.nf_max_requests_why_max", "больше: перебор на часы"), F.t("wordlists.nf_max_requests_why_min", "меньше 500: модули не успеют проверить даже типовые пути"), 500)}
        ${nf("max_time_min", F.t("wordlists.nf_max_time_min", "Время на скан, до"), F.t("wordlists.nf_max_time_min_unit", "мин"), 5, 120, [15, 30], F.t("wordlists.nf_max_time_min_note", "потом перебор останавливается сам"), F.t("wordlists.nf_max_time_min_why_max", "дольше двух часов перебор не идёт"), F.t("wordlists.nf_max_time_min_why_min", "за меньшее время перебор почти ничего не проверит"), 5)}
        ${nf("max_hosts", F.t("wordlists.nf_max_hosts", "Адресов за скан"), "", 1, 10, [1, 3], F.t("wordlists.nf_max_hosts_note", "перебираются по очереди"), F.t("wordlists.nf_max_hosts_why_max", "больше 10 адресов за скан не перебирается"), F.t("wordlists.nf_max_hosts_why_min", "нужен хотя бы один адрес"))}
      </div>
      <div class="list">${ui.row({ lead: ui.leadIcon("filter"), title: esc(F.t("wordlists.show_paths", "Показывать все найденные пути")), sub: esc(F.t("wordlists.show_paths_sub", "Находки «Найден путь на сайте» (важность «Инфо»), обычно не нужны")), tail: ui.toggle(!!fuzzCfg.show_paths, "wl-paths", `aria-label="${esc(F.t("wordlists.show_paths", "Показывать все найденные пути"))}"`) })}</div>
      <h3 class="sub-h">${esc(F.t("wordlists.exclude_h", "Не запрашивать пути"))}</h3>
      ${
        excl.length
          ? `<div class="list">${excl
              .map((p, i) =>
                ui.row({
                  lead: ui.leadIcon("la-ban", "var(--bad)"),
                  title: `<span class="mono">${esc(p)}</span>`,
                  sub: esc(F.t("wordlists.exclude_sub", "И всё, что внутри")),
                  tail: `<button class="ib"
        data-act="wl-xdel:${i}"
        aria-label="${esc(F.t("wordlists.exclude_del_aria", { path: p }, "Убрать путь {path}"))}">${ic("x")}</button>`,
                }),
              )
              .join("")}</div>`
          : `<p class="fhint">${esc(F.t("wordlists.exclude_empty", "Путей-исключений нет. Хосты и сети исключаются в скоупе проекта."))}</p>`
      }
      <div class="la-inline wl-inline"><div class="field">${ic("la-ban")}<input id="wl-x"
        placeholder="${esc(F.t("wordlists.exclude_ph", "/private или /admin/"))}" autocapitalize="off" spellcheck="false"
        enterkeyhint="done"></div><button class="btn tonal" data-act="wl-xadd">${esc(F.t("common.add", "Добавить"))}</button></div>
      ${state.err ? `<div class="banner warn">${ic("alert")}<div>${esc(F.t("wordlists.list_err", { err: state.err }, "Список словарей недоступен: {err}"))}</div></div>` : ""}
      ${
        !data
          ? ui.skeletonList(3)
          : `
      ${ui.secH(F.t("wordlists.sec_builtin", "Встроенные"), grp("builtin").length)}
      <div class="list">${grp("builtin").map(row).join("")}</div>
      ${ui.secH(F.t("wordlists.sec_remote", "Большие: скачать"), grp("remote").length)}
      <p class="fhint">${esc(F.t("wordlists.remote_hint", "Скачиваются с GitHub (SecLists, закреплённая версия), не с сайта цели; размер и контрольная сумма проверяются."))}</p>
      <div class="list">${grp("remote").map(row).join("")}</div>
      ${ui.secH(F.t("wordlists.sec_custom", "Свои"), grp("custom").length || "")}
      ${grp("custom").length ? `<div class="list">${grp("custom").map(row).join("")}</div>` : `<p class="fhint">${esc(F.t("wordlists.custom_hint", "Текстовый файл, по слову или пути в строке, до 64 МБ. Пути с «..», параметры и адреса других сайтов отбрасываются."))}</p>`}
      <button class="btn block" data-act="wl-import">${ic("plus")}${esc(F.t("wordlists.import", "Импортировать свой словарь"))}</button>`
      }`;
  }
  F.route("/settings/wordlists", {
    title: () => F.t("wordlists.title", "Словари"),
    sub: () => F.t("wordlists.sub", "Поиск на сайте"),
    nav: false,
    back: true,
    actions: [],
    hideMini: true,
    render: () => F.withStates(render, { loading: "list" }),
    mount: page => {
      page.classList.add("st-pg");
      const x = page.querySelector("#wl-x");
      if (x)
        x.addEventListener("keydown", e => {
          if (e.key === "Enter") {
            e.preventDefault();
            F.actions["wl-xadd"]();
          }
        });
    },
  });
  const saveFz = patch => {
    const s = F.db.settings || (F.db.settings = {});
    s.fuzz = { ...(s.fuzz || {}), ...patch };
    return F.api.settings_set({ fuzz: patch });
  };
  Object.assign(F.actions, {
    "wl-step": a => {
      const [k, d, mn, mx] = a.split(":");
      saveFz({ [k]: Math.max(+mn, Math.min(+mx, (fz()[k] || 0) + +d)) });
      F.render(true);
    },
    "wl-paths": () => {
      saveFz({ show_paths: !fz().show_paths });
      F.render(true);
    },
    "wl-xadd": () => {
      const inp = document.getElementById("wl-x");
      let v = String((inp && inp.value) || "").trim();
      if (!v) {
        if (inp) inp.focus();
        return;
      }
      if (/^https?:\/\//i.test(v)) {
        try {
          v = new URL(v).pathname;
        } catch (e) {
          // Not a URL: keep the input as is.
        }
      }
      if (!v.startsWith("/")) v = "/" + v;
      if (/\.\.|\s/.test(v)) {
        F.snack(F.t("wordlists.snack_bad_path", "Путь без пробелов и «..»"));
        return;
      }
      const cur = (fz().exclude_paths || []).slice();
      if (!cur.includes(v)) cur.push(v);
      saveFz({ exclude_paths: cur });
      F.render(true);
      F.snack(F.t("wordlists.snack_excluded", { path: v }, "«{path}» не будет запрашиваться"));
    },
    "wl-xdel": i => {
      const cur = (fz().exclude_paths || []).slice();
      const x = cur.splice(+i, 1)[0];
      saveFz({ exclude_paths: cur });
      F.render(true);
      F.snack(F.t("wordlists.snack_unexcluded", { path: x }, "«{path}» снова может запрашиваться"), {
        action: () => {
          const now = (fz().exclude_paths || []).slice();
          now.splice(+i, 0, x);
          saveFz({ exclude_paths: now });
          F.render(true);
        },
      });
    },
    "wl-use": id => {
      const cur = selected().slice(),
        i = cur.indexOf(id);
      i >= 0 ? cur.splice(i, 1) : cur.push(id);
      saveFz({ wordlists: cur });
      F.render(true);
    },
    "wl-dl": id => {
      state.busy[id] = true;
      F.render(true);
      F.api
        .wordlists_download(id)
        .then(
          r => {
            F.snack(
              F.tp(
                "wordlists.snack_downloaded",
                r.lines,
                { n: num(r.lines) },
                "Словарь скачан: {n} строка|Словарь скачан: {n} строки|Словарь скачан: {n} строк",
              ),
            );
          },
          e => F.snack(F.t("wordlists.snack_dl_fail", { err: e.message || e }, "Не скачан: {err}")),
        )
        .then(() => {
          delete state.busy[id];
          load(true);
        });
    },
    "wl-del": id => {
      const w = ((state.data || {}).items || []).find(x => x.id === id);
      F.api.wordlists_delete(id).then(
        () => {
          const s = F.db.settings || {};
          if (s.fuzz) s.fuzz.wordlists = (s.fuzz.wordlists || []).filter(x => x !== id);
          F.snack(F.t("wordlists.snack_deleted", { name: w ? wlName(w) : id }, "Словарь «{name}» удалён"));
          load(true);
        },
        e => F.snack(F.t("wordlists.snack_del_fail", { err: e.message || e }, "Не удалось удалить: {err}")),
      );
    },
    "wl-import": () => {
      const imp = (path, name) =>
        F.api.wordlists_import(path, name).then(
          r => {
            saveFz({ wordlists: selected().concat(selected().includes(r.id) ? [] : [r.id]) });
            F.snack(
              F.tp(
                "wordlists.snack_imported",
                r.lines,
                { n: num(r.lines) },
                "Импортировано {n} строка|Импортировано {n} строки|Импортировано {n} строк",
              ) + (r.dropped ? F.t("wordlists.snack_dropped", { n: num(r.dropped) }, ", отброшено {n}") : ""),
            );
            load(true);
          },
          e => F.snack(F.t("wordlists.snack_imp_fail", { err: e.message || e }, "Не импортирован: {err}")),
        );
      if (F.isDemo) return imp("Download/words_contoso.txt", "words_contoso.txt"); // The demo build has no system file picker.
      F.api.platform_pick_files({ multiple: false, mime: "text/*" }).then(
        r => {
          const fl = (r && r.files) || [];
          if (!fl.length) return;
          return imp(fl[0].path, fl[0].name);
        },
        e => F.snack(F.t("wordlists.snack_no_file", { err: e.message || e }, "Файл не выбран: {err}")),
      );
    },
  });
})();
