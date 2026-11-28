// Re-analysis of documents already in the project (core command project_reextract, docs/API.md):
// the sheet with options, progress and the before/after summary, the update banner on the
// overview and the entry points used by the overview and Data > Documents.
(function () {
  const F = window.FOCA,
    { ic, esc, ui } = F;
  // Status per project from reextract_status; refreshed on open, on db events and after a run.
  const ST = (F.state.reextract = F.state.reextract || {
    status: {},
    loading: {},
    sheet: null,
    mode: "stored",
  });
  const pid = () => (F.db.project || {}).id;
  const DISMISS = "foca-reextract-dismiss:";

  const fmtBytes = b => {
    const mb = (b || 0) / (1024 * 1024);
    if (mb < 1) return F.t("reextract.kb", { n: Math.max(1, Math.round((b || 0) / 1024)) }, "{n} КБ");
    const v = mb < 10 ? mb.toFixed(1) : String(Math.round(mb));
    return F.t("reextract.mb", { n: F.i18n && F.i18n.lang() === "en" ? v : v.replace(".", ",") }, "{n} МБ");
  };
  const docsN = n => F.tp("reextract.docs_n", n, { n }, "{n} документ|{n} документа|{n} документов");

  function refresh(id = pid(), rerender = true) {
    if (!id || ST.loading[id]) return Promise.resolve(ST.status[id]);
    ST.loading[id] = true;
    return F.api
      .reextract_status({ project: id })
      .then(
        s => {
          const was = JSON.stringify(ST.status[id] || null);
          ST.status[id] = s;
          if (rerender && was !== JSON.stringify(s) && F.cur && F.cur.path === "/p/overview") F.render(true);
          return s;
        },
        () => null,
      )
      .finally(() => {
        ST.loading[id] = false;
      });
  }
  const status = () => {
    const id = pid();
    if (id && !(id in ST.status)) {
      ST.status[id] = null;
      refresh(id);
    }
    return ST.status[id] || null;
  };
  // Data changed (scan, import, deletion): the outdated count may change.
  F.on("db", ev => {
    if (ev && ["project", "init", "reset", "net"].includes(ev.kind)) return;
    if (F.scan && F.scan.running) return;
    const id = pid();
    if (id && id in ST.status && !(ST.sheet && ST.sheet.running)) refresh(id);
  });

  // ---------- overview: update banner and entry row ----------
  function dismissed(id, rev) {
    try {
      return localStorage.getItem(DISMISS + id) === String(rev);
    } catch (e) {
      return false;
    }
  }
  function bannerHtml() {
    const s = status();
    if (!s || !s.outdated || s.scan_running) return "";
    const n = s.outdated.total || 0;
    const usable = (s.outdated.files || 0) + (s.outdated.missing || 0);
    if (!n || !usable || dismissed(s.project, s.format_rev) || (s.running && s.running.stage)) return "";
    return `<div class="banner info rx-banner" id="rx-banner">${ic("refresh")}<div><div>${esc(
      F.t(
        "reextract.banner",
        { n: docsN(n) },
        "Новая версия извлекает больше данных из документов. Переанализировать {n}?",
      ),
    )}</div><div class="btnrow"><button class="btn sm tonal" data-act="rx-open:outdated">${esc(
      F.t("reextract.btn", "Переанализировать документы"),
    )}</button><button class="btn sm text" data-act="rx-dismiss">${esc(F.t("reextract.not_now", "Не сейчас"))}</button></div></div></div>`;
  }
  function runningRow() {
    const s = status();
    const r = (ST.sheet && ST.sheet.running) || (s && s.running);
    if (!r) return "";
    return ui.row({
      lead: ui.leadIcon("spin"),
      title: esc(F.t("reextract.running_t", "Повторный анализ документов")),
      sub: esc(F.t("reextract.progress", { done: r.done || 0, total: r.total || 0 }, "{done} из {total}")),
      act: "rx-open",
    });
  }
  function overviewRow() {
    const s = status();
    if (!s || !s.docs) return "";
    const running = runningRow();
    if (running) return `<div class="list rx-ov">${running}</div>`;
    const pending = s.pending;
    return `<div class="list rx-ov">${ui.row({
      lead: ui.leadIcon("refresh"),
      title: esc(F.t("reextract.btn", "Переанализировать документы")),
      sub: esc(
        pending
          ? F.t(
              "reextract.pending_sub",
              { done: pending.done || 0, total: pending.total || 0 },
              "Прервано на {done} из {total}: продолжить",
            )
          : F.t("reextract.row_sub", "Без нового поиска, по уже скачанным файлам"),
      ),
      act: "rx-open",
    })}</div>`;
  }

  // ---------- sheet ----------
  function optionHtml(mode, title, sub) {
    const on = ST.mode === mode;
    return `<div class="row tap rx-opt ${on ? "on" : ""}" role="radio" aria-checked="${on}" data-act="rx-mode:${mode}"><span class="radio"></span><div class="body"><div class="t full">${esc(title)}</div><div class="s">${esc(sub)}</div></div></div>`;
  }
  function optionsHtml(s) {
    const sh = ST.sheet;
    const sel = sh.ids && sh.ids.length;
    const o = s.outdated || {};
    const lines = [];
    if (sel) lines.push(F.t("reextract.sel_n", { n: docsN(sh.ids.length) }, "Выбрано: {n}"));
    else if (sh.scope === "outdated" && o.total)
      lines.push(
        F.t(
          "reextract.outdated_only",
          { n: docsN(o.total) },
          "Будут разобраны документы прошлой версии: {n}",
        ),
      );
    else {
      lines.push(
        F.t(
          "reextract.total_files",
          { n: docsN(s.docs || 0), f: s.files || 0 },
          "В проекте {n}, файлы есть у {f}",
        ),
      );
      if (o.total)
        lines.push(F.t("reextract.outdated_n", { n: docsN(o.total) }, "Разобраны прошлой версией: {n}"));
    }
    // The outdated-only run downloads only its own missing files.
    const outdatedScope = !sel && sh.scope === "outdated" && o.total;
    const missing = (outdatedScope ? o.missing : s.missing) || 0;
    const missingBytes = (outdatedScope ? o.missing_bytes : s.missing_bytes) || 0;
    // An explicit selection starts a new run instead of continuing an interrupted one.
    const pending = sel ? null : s.pending;
    return `<p class="lead rx-what">${esc(
      F.t(
        "reextract.explain",
        "Новый поиск не запускается: документы, которые уже есть в проекте, разбираются заново текущей версией, затем пересчитываются люди, контакты и находки. Статусы находок, заметки и удаления сохраняются.",
      ),
    )}</p>
    <div class="kv rx-facts">${lines.map(l => `<div class="kvr"><div class="v">${esc(l)}</div></div>`).join("")}</div>
    ${
      pending
        ? `<div class="banner warn rx-pend">${ic("history")}<div>${esc(
            F.t(
              "reextract.pending",
              { done: pending.done || 0, total: pending.total || 0 },
              "Прошлый запуск прерван на {done} из {total}. Он продолжится с этого места.",
            ),
          )}</div></div>`
        : `<div class="list rx-opts" role="radiogroup" aria-label="${esc(F.t("reextract.mode", "Что разобрать"))}">
      ${optionHtml("stored", F.t("reextract.mode_stored", "Только скачанные файлы"), F.t("reextract.mode_stored_sub", "Без сети. Документы без файла пропускаются."))}
      ${optionHtml(
        "stored_and_missing",
        F.t("reextract.mode_missing", "Скачать недостающие файлы"),
        missing
          ? F.t(
              "reextract.mode_missing_sub",
              { n: docsN(missing), size: fmtBytes(missingBytes) },
              "Ещё {n} по сохранённым ссылкам, около {size}. Скоуп, лимиты и режим «только Wi-Fi» соблюдаются.",
            )
          : F.t("reextract.mode_missing_none", "Все файлы на месте, скачивать нечего."),
      )}
    </div>
    ${
      ST.mode === "stored_and_missing" && missing
        ? `<p class="fhint rx-traffic">${ic("alert")}<span>${esc(
            F.t(
              "reextract.traffic",
              { size: fmtBytes(missingBytes) },
              "Трафик: до {size}. В мобильной сети учитывается лимит из настроек питания.",
            ),
          )}</span></p>`
        : ""
    }`
    }
    ${
      s.scan_running
        ? `<div class="banner warn rx-scan">${ic("scan")}<div>${esc(
            F.t("reextract.scan_busy", "Идёт скан. Повторный анализ можно запустить после его завершения."),
          )}</div></div>`
        : ""
    }`;
  }
  function progressHtml() {
    const r = ST.sheet.running || {};
    const pct = r.total ? Math.round(((r.done || 0) * 100) / r.total) : 0;
    const what =
      r.stage === "analysis"
        ? F.t("reextract.st_analysis", "Пересчёт людей, контактов и находок")
        : r.stage === "download"
          ? F.t("reextract.st_download", { name: r.name || "" }, "Скачивание: {name}")
          : r.name
            ? F.t("reextract.st_file", { name: r.name }, "Разбор: {name}")
            : F.t("reextract.st_start", "Подготовка");
    return `<div class="rx-prog" role="status" aria-live="polite">
      <div class="rx-prog-n"><b>${esc(F.t("reextract.progress", { done: r.done || 0, total: r.total || 0 }, "{done} из {total}"))}</b><span>${pct}%</span></div>
      <div class="pbar"><i style="width:${pct}%"></i></div>
      <div class="s rx-prog-what">${esc(what)}</div>
      <p class="fhint">${ic("info")}<span>${esc(F.t("reextract.bg_note", "Можно закрыть окно: анализ продолжится, итог появится здесь и на обзоре."))}</span></p>
    </div>`;
  }
  const SEV = () => [
    ["crit", F.t("reextract.sev_crit", "Критичные")],
    ["high", F.t("reextract.sev_high", "Высокие")],
    ["warn", F.t("reextract.sev_warn", "Средние")],
    ["low", F.t("reextract.sev_low", "Низкие")],
    ["info", F.t("reextract.sev_info", "Инфо")],
  ];
  function diffRow(label, a, b) {
    const d = (b || 0) - (a || 0);
    const cls = d > 0 ? "up" : d < 0 ? "down" : "same";
    return `<div class="rx-dr"><span class="rx-dl">${esc(label)}</span><span class="rx-dv">${a || 0}</span><span class="rx-da" aria-hidden="true">→</span><span class="rx-dv"><b>${b || 0}</b></span><span class="rx-dd ${cls}">${d > 0 ? "+" + d : d < 0 ? String(d) : "="}</span></div>`;
  }
  function resultHtml(sm) {
    const b = sm.before || {},
      a = sm.after || {};
    const parts = [
      [sm.reparsed, F.t("reextract.r_reparsed", "разобрано заново")],
      [sm.downloaded, F.t("reextract.r_downloaded", "скачано")],
      [sm.no_file, F.t("reextract.r_nofile", "без файла")],
      [sm.failed, F.t("reextract.r_failed", "с ошибкой")],
    ].filter(x => x[0]);
    const block =
      sm.net_blocked === "wifi_only"
        ? F.t(
            "reextract.blocked_wifi",
            "Скачивание пропущено: включён режим «только Wi-Fi», а сейчас мобильная сеть.",
          )
        : sm.net_blocked === "mobile_limit"
          ? F.t(
              "reextract.blocked_limit",
              "Скачивание пропущено: исчерпан месячный лимит мобильного трафика.",
            )
          : "";
    const nf = sm.new_findings || 0;
    return `<div class="banner ok rx-done">${ic("check")}<div><b>${esc(F.t("reextract.done_t", "Готово:"))}</b> ${esc(
      parts.map(([n, l]) => `${n} ${l}`).join(" · ") ||
        F.t("reextract.r_none", "документов для разбора не было"),
    )}</div></div>
    ${block ? `<div class="banner warn">${ic("alert")}<div>${esc(block)}</div></div>` : ""}
    ${ui.secH(F.t("reextract.diff", "До и после"))}
    <div class="card pad rx-diff">
      ${diffRow(F.t("reextract.d_text", "Документы с текстом"), b.text, a.text)}
      ${diffRow(F.t("reextract.d_people", "Люди"), b.people, a.people)}
      ${diffRow(F.t("reextract.d_emails", "E-mail"), b.emails, a.emails)}
      ${diffRow(F.t("reextract.d_phones", "Телефоны"), b.phones, a.phones)}
      ${SEV()
        .map(([k, l]) => diffRow(l, (b.findings || {})[k], (a.findings || {})[k]))
        .join("")}
    </div>
    <p class="fhint rx-fnote">${ic("info")}<span>${esc(
      F.t(
        "reextract.findings_note",
        { added: nf, removed: sm.removed_findings || 0 },
        "Новых находок: {added}. Больше не подтверждаются: {removed} (убраны из списка, счётчиков и отчётов; статус и заметки вернутся, если находка появится снова).",
      ),
    )}</span></p>`;
  }
  function sheetHtml() {
    const sh = ST.sheet;
    if (sh.running) return progressHtml();
    if (sh.result) return resultHtml(sh.result);
    if (sh.error) return `<div class="banner crit">${ic("alert")}<div>${esc(sh.error)}</div></div>`;
    if (!sh.status) return `<div class="rx-load">${ic("spin", "spin")}</div>`;
    return optionsHtml(sh.status);
  }
  function footerHtml() {
    const sh = ST.sheet;
    if (sh.running)
      return `<button class="btn block tonal" data-act="rx-cancel">${ic("stop")}${esc(F.t("reextract.cancel", "Остановить"))}</button>`;
    if (sh.result) {
      const nf = sh.result.new_findings || 0;
      return `<div class="btnrow rx-fbtns"><button class="btn primary" data-act="rx-findings">${ic("alert")}${esc(
        nf
          ? F.t("reextract.open_new", { n: nf }, "Новые находки: {n}")
          : F.t("reextract.open_findings", "Открыть находки"),
      )}</button><button class="btn tonal" data-act="sheet-close">${esc(F.t("reextract.close", "Закрыть"))}</button></div>`;
    }
    const s = sh.status;
    const dis = !s || s.scan_running;
    return `<button class="btn primary block" data-act="rx-start" ${dis ? "disabled" : ""}>${ic("refresh")}${esc(
      s && s.pending && !(sh.ids && sh.ids.length)
        ? F.t("reextract.resume", "Продолжить")
        : F.t("reextract.start", "Начать"),
    )}</button>`;
  }
  function paint() {
    const sh = ST.sheet;
    if (!sh || !sh.el || !sh.el.isConnected) return;
    const body = sh.el.querySelector(".sh-b");
    if (body) body.innerHTML = sheetHtml();
    let foot = sh.el.querySelector(".sh-f");
    if (!foot) {
      foot = document.createElement("div");
      foot.className = "sh-f";
      sh.el.append(foot);
    }
    foot.innerHTML = footerHtml();
  }
  function open(ids, scope) {
    const id = pid();
    if (!id) return;
    const s = ST.status[id];
    const running = s && s.running;
    ST.sheet = {
      project: id,
      ids: ids || null,
      scope: scope || "all",
      status: null,
      running,
      result: null,
      error: null,
    };
    ST.mode = "stored";
    const el = F.sheet({
      title: F.t("reextract.title", "Повторный анализ документов"),
      html: sheetHtml(),
      footer: footerHtml(),
      cls: "rx-sheet",
      onClose: () => {
        if (ST.sheet) ST.sheet.el = null;
      },
    });
    ST.sheet.el = el;
    refresh(id, false).then(st => {
      if (!ST.sheet || ST.sheet.project !== id) return;
      ST.sheet.status = st;
      if (st && st.running) ST.sheet.running = st.running;
      paint();
    });
  }
  F.on("scan", ev => {
    if (!ev || ev.type !== "reextract") return;
    const sh = ST.sheet;
    const prog = { done: ev.done || 0, total: ev.total || 0, name: ev.name || "", stage: ev.stage };
    const st = ST.status[ev.project];
    const end = ["done", "cancelled", "yielded", "error"].includes(ev.stage);
    if (st) st.running = end ? null : prog;
    if (sh && sh.project === ev.project) {
      if (!end) sh.running = prog;
      else {
        sh.running = null;
        if (ev.stage === "done") sh.result = ev.summary || {};
        else if (ev.stage === "error") sh.error = F.coreMsg ? F.coreMsg(ev.error, ev.error_msg) : ev.error;
        else {
          sh.status = null;
          refresh(ev.project, false).then(s => {
            if (ST.sheet === sh) {
              sh.status = s;
              paint();
            }
          });
        }
      }
      paint();
    }
    if (end) {
      if (ev.stage === "done" && (!sh || !sh.el))
        F.snack(
          F.t(
            "reextract.snack_done",
            { n: (ev.summary || {}).new_findings || 0 },
            "Повторный анализ готов, новых находок: {n}",
          ),
          { label: F.t("reextract.open", "Итог"), action: () => open() },
        );
      if (ev.stage === "yielded")
        F.snack(
          F.t(
            "reextract.snack_yield",
            "Повторный анализ приостановлен: начался скан. Продолжите после него.",
          ),
        );
      refresh(ev.project);
    } else if (F.cur && F.cur.path === "/p/overview" && !(sh && sh.el)) {
      const row = document.querySelector(".rx-ov");
      if (row) row.outerHTML = overviewRow();
    }
  });

  Object.assign(F.actions, {
    "rx-open": arg => {
      const st = ST.status[pid()] || {};
      if (arg === "outdated") open(null, "outdated");
      else open(null, st.pending ? "pending" : "all");
    },
    "rx-dismiss": () => {
      const s = status();
      try {
        if (s) localStorage.setItem(DISMISS + s.project, String(s.format_rev));
      } catch (e) {}
      const b = document.getElementById("rx-banner");
      if (b) b.remove();
    },
    "rx-mode": m => {
      ST.mode = m === "stored_and_missing" ? m : "stored";
      paint();
    },
    "rx-start": () => {
      const sh = ST.sheet;
      if (!sh) return;
      const s = sh.status || {};
      const args = { project: sh.project, mode: ST.mode };
      if (sh.ids && sh.ids.length) Object.assign(args, { ids: sh.ids, restart: true });
      else if (sh.scope === "outdated" && !s.pending) args.outdated = true;
      sh.running = { done: (s.pending && s.pending.done) || 0, total: 0, name: "", stage: "start" };
      paint();
      F.api.project_reextract(args).then(
        r => {
          if (ST.sheet === sh && sh.running && !sh.running.total) sh.running.total = r.total || 0;
          paint();
        },
        e => {
          sh.running = null;
          sh.error = F.coreMsg ? F.coreMsg(e.message || String(e), e.message_msg) : e.message || String(e);
          paint();
        },
      );
    },
    "rx-cancel": () => {
      const sh = ST.sheet;
      if (sh) F.api.reextract_cancel({ project: sh.project });
    },
    "rx-findings": () => {
      const sh = ST.sheet;
      const ids = (sh && sh.result && sh.result.new_ids) || [];
      F.closeSheet();
      F.go(ids.length === 1 ? `/p/finding/${ids[0]}` : "/p/findings");
    },
  });

  F.reextract = { bannerHtml, overviewRow, open, refresh, status };
})();
