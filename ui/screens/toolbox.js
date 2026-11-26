// Quick tools without a project (/tools) and multi-project Scan Queue (/queue).
(function () {
  const F = window.FOCA,
    { ic, esc, ui } = F;

  const st = {
    tab: "file",
    busy: false,
    fileRes: null,
    fileErr: null,
    mailDomain: "",
    mailRes: null,
    mailErr: null,
    hostInput: "",
    hostRes: null,
    hostErr: null,
    secInput: "",
    secHibp: false,
    secRes: null,
    secErr: null,
    logList: null,
    queue: null,
    qProfile: "std",
    qSel: new Set(),
  };

  const TABS = [
    ["file", "Файл", "doc"],
    ["mail", "Почта", "mail"],
    ["host", "Хост", "globe"],
    ["secret", "Пароль", "key"],
    ["log", "Журнал", "log"],
  ];

  const riskPill = lvl => {
    const cls = { high: "crit", medium: "warn", low: "ok" }[lvl] || "mute";
    const lbl =
      {
        high: F.t("toolbox.risk_high", "Высокий риск"),
        medium: F.t("toolbox.risk_medium", "Средний риск"),
        low: F.t("toolbox.risk_low", "Низкий риск"),
      }[lvl] || F.t("toolbox.risk_unknown", "Неизвестно");
    return `<span class="pill ${cls}">${esc(lbl)}</span>`;
  };

  function renderFile() {
    const r = st.fileRes;
    return `
      <div class="card pad">
        <b>${esc(F.t("toolbox.file_title", "Проверка файла без проекта"))}</b>
        <p class="fhint">${esc(F.t("toolbox.file_hint", "Метаданные, форензика, ПДн и секреты проверяются локально на устройстве без записи в проекты."))}</p>
        <div class="btnrow">
          <button class="btn primary" data-act="tbx-pick-file" ${st.busy ? "disabled" : ""}>${ic("folder")}${esc(F.t("toolbox.pick_file", "Выбрать файл"))}</button>
          ${F.isDemo ? `<button class="btn tonal" data-act="tbx-demo-file" ${st.busy ? "disabled" : ""}>${ic("doc")}${esc(F.t("toolbox.demo_file", "Пример DOCX"))}</button>` : ""}
        </div>
      </div>
      ${st.fileErr ? `<div class="banner crit tbx-box">${ic("alert")}<div>${esc(st.fileErr)}</div></div>` : ""}
      ${
        r
          ? `<div class="card pad tbx-box">
          <div class="tbx-grade">
            <div class="tbx-gbadge ${r.grade && r.grade.grade <= "B" ? "ok" : r.grade && r.grade.grade <= "D" ? "warn" : "crit"}">${esc((r.grade && r.grade.grade) || "-")}</div>
            <div><b>${esc(r.name)}</b><div class="fhint">${esc(r.format || r.ext || "")} · ${esc((r.size || 0) > 1024 ? F.t("toolbox.size_kb", { n: Math.round(r.size / 1024) }, "{n} КБ") : F.t("toolbox.size_b", { n: r.size || 0 }, "{n} Б"))} · ${esc(F.t("toolbox.elapsed_ms", { n: r.elapsed_ms || 0 }, "{n} мс"))}</div></div>
          </div>
          <div class="kv tbx-kv">
            <div class="kvr"><div class="k">SHA-256</div><div class="v mono">${esc(String(r.sha256 || "").slice(0, 24))}…</div></div>
            <div class="kvr"><div class="k">${esc(F.t("toolbox.findings", "Находок"))}</div><div class="v">${(r.findings || []).length}</div></div>
            <div class="kvr"><div class="k">${esc(F.t("toolbox.pii_secrets", "ПДн / Секреты"))}</div><div class="v">${(r.pii || []).length} / ${(r.secrets || []).length}</div></div>
          </div>
          ${
            r.findings && r.findings.length
              ? `<div class="list tbx-box">${r.findings
                  .slice(0, 8)
                  .map(f =>
                    ui.row({
                      title: esc(F.ftext ? F.ftext.field(f.title, f.rule || "") : f.title),
                      sub: esc(
                        F.ftext && f.description
                          ? F.ftext.field(f.description, f.rule || "")
                          : f.description || f.rule,
                      ),
                      tail: ui.sev(f.sev),
                    }),
                  )
                  .join("")}</div>`
              : ""
          }
          ${
            r.cleanable && r.clean_with
              ? `<div class="btnrow tbx-box"><button class="btn tonal block" data-act="tbx-clean-file">${ic("shield")}${esc(F.t("toolbox.clean_meta", "Очистить метаданные"))}</button></div>`
              : ""
          }
        </div>`
          : ""
      }`;
  }

  function renderMail() {
    const r = st.mailRes;
    return `
      <form class="card pad" id="tbx-mail-form">
        <label class="flabel" for="tbx-mail-in">${esc(F.t("toolbox.mail_label", "Домен или e-mail"))}</label>
        <div class="tbx-row-form">
          <div class="field">${ic("mail")}<input id="tbx-mail-in" value="${esc(st.mailDomain)}" placeholder="example.com" autocapitalize="off" spellcheck="false"></div>
          <button class="btn primary" type="submit" ${st.busy ? "disabled" : ""}>${esc(F.t("toolbox.check", "Проверить"))}</button>
        </div>
        <p class="fhint">${esc(F.t("toolbox.mail_hint", "Проверяет SPF, DMARC, DKIM, BIMI, MTA-STS, TLS-RPT, CAA и DNSSEC через настроенный DoH/прокси."))}</p>
      </form>
      ${st.mailErr ? `<div class="banner crit tbx-box">${ic("alert")}<div>${esc(st.mailErr)}</div></div>` : ""}
      ${
        r
          ? `<div class="card pad tbx-box">
          <div class="tbx-qbar"><b>${esc(r.domain)}</b>${riskPill(r.risk && r.risk.level)}</div>
          ${(r.risk && r.risk.reasons ? r.risk.reasons : []).map(x => `<div class="fhint">• ${esc(x)}</div>`).join("")}
          <div class="kv tbx-kv">
            <div class="kvr"><div class="k">SPF</div><div class="v mono">${esc((r.spf && r.spf.record) || "-")}</div></div>
            <div class="kvr"><div class="k">DMARC</div><div class="v mono">${esc((r.dmarc && r.dmarc.record) || "-")}</div></div>
            <div class="kvr"><div class="k">MTA-STS</div><div class="v">${esc(r.mta_sts && r.mta_sts.record ? F.t("toolbox.present", "есть") : F.t("toolbox.absent", "нет"))}</div></div>
            <div class="kvr"><div class="k">DNSSEC</div><div class="v">${esc(r.dnssec ? F.t("toolbox.yes_lc", "да") : F.t("toolbox.absent", "нет"))}</div></div>
          </div>
          ${
            r.issues && r.issues.length
              ? `<div class="list tbx-box">${r.issues
                  .map(i =>
                    ui.row({ title: esc(i.title), sub: esc(i.detail || ""), tail: ui.sev(i.sev || "info") }),
                  )
                  .join("")}</div>`
              : ""
          }
        </div>`
          : ""
      }`;
  }

  function renderHost() {
    const r = st.hostRes;
    return `
      <form class="card pad" id="tbx-host-form">
        <label class="flabel" for="tbx-host-in">${esc(F.t("toolbox.host_label", "Хост или URL"))}</label>
        <div class="tbx-row-form">
          <div class="field">${ic("globe")}<input id="tbx-host-in" value="${esc(st.hostInput)}" placeholder="https://example.com" autocapitalize="off" spellcheck="false"></div>
          <button class="btn primary" type="submit" ${st.busy ? "disabled" : ""}>${esc(F.t("toolbox.check", "Проверить"))}</button>
        </div>
        <p class="fhint">${esc(F.t("toolbox.host_hint", "Один запрос к указанному хосту: TLS-сертификат, заголовки безопасности, стек технологий и favicon."))}</p>
      </form>
      ${st.hostErr ? `<div class="banner crit tbx-box">${ic("alert")}<div>${esc(st.hostErr)}</div></div>` : ""}
      ${
        r
          ? `<div class="card pad tbx-box">
          <div class="tbx-qbar"><b>${esc(r.host_port || r.host)}</b><span class="pill ${r.status && r.status < 400 ? "ok" : "warn"}">HTTP ${esc(r.status ?? "-")}</span></div>
          <div class="kv tbx-kv">
            <div class="kvr"><div class="k">URL</div><div class="v mono">${esc(r.url || "-")}</div></div>
            ${r.tls && r.tls.leaf ? `<div class="kvr"><div class="k">TLS</div><div class="v">${esc(r.tls.leaf.cn || "")} · ${esc(F.t("toolbox.tls_days_left", { n: r.tls.days_left ?? "-" }, "осталось {n} дн."))}</div></div>` : ""}
            ${r.favicon ? `<div class="kvr"><div class="k">Favicon mmh3</div><div class="v mono">${esc(r.favicon.mmh3)}</div></div>` : ""}
          </div>
          ${
            r.technologies && r.technologies.length
              ? `<div class="tbx-chips">${r.technologies
                  .map(
                    t => `<span class="chip">${esc(t.name)}${t.version ? " " + esc(t.version) : ""}</span>`,
                  )
                  .join("")}</div>`
              : ""
          }
          ${
            r.header_issues && r.header_issues.length
              ? `<div class="list tbx-box">${r.header_issues
                  .map(i =>
                    ui.row({ title: esc(i.title), sub: esc(i.detail || ""), tail: ui.sev(i.sev || "warn") }),
                  )
                  .join("")}</div>`
              : ""
          }
        </div>`
          : ""
      }`;
  }

  function renderSecret() {
    const r = st.secRes;
    return `
      <form class="card pad" id="tbx-sec-form">
        <label class="flabel" for="tbx-sec-in">${esc(F.t("toolbox.sec_label", "Пароль или токен"))}</label>
        <div class="tbx-row-form">
          <div class="field">${ic("key")}<input id="tbx-sec-in" type="password" value="${esc(st.secInput)}" placeholder="${esc(F.t("toolbox.sec_ph", "Введите для проверки"))}" autocomplete="off"></div>
          <button class="btn primary" type="submit" ${st.busy ? "disabled" : ""}>${esc(F.t("toolbox.check", "Проверить"))}</button>
        </div>
        <label class="tbx-opt"><input id="tbx-sec-hibp" type="checkbox" ${st.secHibp ? "checked" : ""}><span>${esc(F.t("toolbox.sec_hibp", "Проверить по базе утечек HIBP (в сеть уйдёт только 5-символьный префикс SHA-1)"))}</span></label>
        <p class="fhint">${esc(F.t("toolbox.sec_hint", "По умолчанию проверка полностью локальна: значение не сохраняется, не логируется и не отправляется."))}</p>
      </form>
      ${st.secErr ? `<div class="banner crit tbx-box">${ic("alert")}<div>${esc(st.secErr)}</div></div>` : ""}
      ${
        r
          ? `<div class="card pad tbx-box">
          <div class="tbx-qbar"><b>${esc(F.t("toolbox.sec_strength", { v: r.strength }, "Оценка: {v}"))}</b><span class="pill ${r.score >= 3 ? "ok" : r.score >= 2 ? "warn" : "crit"}">${esc(F.t("toolbox.bits", { n: r.entropy_bits }, "{n} бит"))}</span></div>
          <div class="kv tbx-kv">
            <div class="kvr"><div class="k">${esc(F.t("toolbox.len_mask", "Длина / маска"))}</div><div class="v">${esc(r.length)} · <span class="mono">${esc(r.mask)}</span></div></div>
            <div class="kvr"><div class="k">${esc(F.t("toolbox.crack_time", "Время подбора"))}</div><div class="v">${esc(r.crack_time)}</div></div>
            <div class="kvr"><div class="k">${esc(F.t("toolbox.hibp_k", "HIBP k-анонимность"))}</div><div class="v">${
              r.hibp && r.hibp.status === "ok"
                ? r.hibp.pwned
                  ? `<span class="pill crit">${esc(F.tp("toolbox.hibp_leaked", r.hibp.count, { n: r.hibp.count, prefix: r.hibp.prefix }, "Утёк ({n} раз · префикс {prefix})|Утёк ({n} раза · префикс {prefix})|Утёк ({n} раз · префикс {prefix})"))}</span>`
                  : `<span class="pill ok">${esc(F.t("toolbox.hibp_clean", { prefix: r.hibp.prefix }, "Не найден · префикс {prefix}"))}</span>`
                : r.hibp && r.hibp.status === "error"
                  ? esc(r.hibp.error || F.t("toolbox.net_error", "ошибка сети"))
                  : esc(F.t("toolbox.hibp_local", "Не запрашивался (локально)"))
            }</div></div>
          </div>
          ${r.detected ? `<div class="banner warn tbx-box">${ic("alert")}<div>${esc(F.t("toolbox.secret_rule", "Совпало правило секретов:"))} <b>${esc(F.ftext ? F.ftext.field(r.detected.title, "secret") : r.detected.title)}</b></div></div>` : ""}
        </div>`
          : ""
      }`;
  }

  function renderLog() {
    const list = st.logList || [];
    if (!list.length)
      return ui.empty({
        icon: "log",
        title: F.t("toolbox.log_empty", "Журнал инструментов пуст"),
        text: F.t(
          "toolbox.log_empty_text",
          "Здесь отображаются сетевые запросы утилит «Почта», «Хост» и opt-in HIBP (пароли и токены маскированы).",
        ),
        action: `<button class="btn tonal" data-act="tbx-reload-log">${ic("refresh")}${esc(F.t("common.refresh", "Обновить"))}</button>`,
      });
    return `<div class="tbx-qbar">${ui.secH(F.t("toolbox.log_requests", "Запросы утилит"), list.length)}<div class="tbx-qbtns"><button class="btn sm tonal" data-act="tbx-reload-log">${ic("refresh")}${esc(F.t("common.refresh", "Обновить"))}</button><button class="btn sm danger-o" data-act="tbx-log-clear">${ic("trash")}${esc(F.t("toolbox.log_clear", "Очистить"))}</button></div></div>
      <div class="list">${list
        .map(r =>
          ui.row({
            lead: ui.leadIcon("log", r.blocked ? "var(--warn)" : "var(--accent)"),
            title: `<span class="mono">${esc(r.method || "GET")} ${esc(r.host || "")}</span>`,
            sub: esc(r.url || ""),
            tail: `<span class="pill ${r.status && r.status < 400 ? "ok" : "warn"}">${esc(r.status || r.error || "-")}</span>`,
          }),
        )
        .join("")}</div>`;
  }

  function renderTools() {
    const tabs = `<div class="tbx-tabs" role="tablist">${TABS.map(
      ([id, label, icon]) =>
        `<button class="chip ${st.tab === id ? "on" : ""}" role="tab" aria-selected="${st.tab === id}" data-act="tbx-tab:${id}">${ic(icon)}${esc(F.t("toolbox.tab_" + id, label))}</button>`,
    ).join("")}</div>`;
    const body = {
      file: renderFile,
      mail: renderMail,
      host: renderHost,
      secret: renderSecret,
      log: renderLog,
    }[st.tab]();
    return tabs + body;
  }

  // Tool journal; a failed load shows an empty list with a message instead of an unhandled rejection
  // (and does not leave logList null, which would refetch on every mount).
  const loadLog = () =>
    F.api.tool_log({ limit: 100 }).then(
      r => {
        st.logList = r || [];
        F.render(true);
      },
      e => {
        st.logList = [];
        F.render(true);
        F.snack(
          F.t(
            "toolbox.log_unavailable",
            { err: (e && e.message) || e },
            "Журнал инструментов недоступен: {err}",
          ),
        );
      },
    );
  F.route("/tools", {
    title: () => F.t("toolbox.tools_title", "Быстрые инструменты"),
    sub: () => F.t("toolbox.tools_sub", "проверки без создания проекта"),
    back: true,
    nav: false,
    render: renderTools,
    mount: page => {
      if (st.tab === "log" && st.logList === null) loadLog();
      const mf = page.querySelector("#tbx-mail-form");
      if (mf)
        mf.addEventListener("submit", e => {
          e.preventDefault();
          st.mailDomain = page.querySelector("#tbx-mail-in").value.trim();
          if (!st.mailDomain) return;
          st.busy = true;
          st.mailErr = null;
          F.render(true);
          F.api
            .tool_mail_domain({ domain: st.mailDomain })
            .then(r => {
              st.mailRes = r;
              st.busy = false;
              F.render(true);
            })
            .catch(err => {
              st.mailErr = err.message || String(err);
              st.busy = false;
              F.render(true);
            });
        });
      const hf = page.querySelector("#tbx-host-form");
      if (hf)
        hf.addEventListener("submit", e => {
          e.preventDefault();
          st.hostInput = page.querySelector("#tbx-host-in").value.trim();
          if (!st.hostInput) return;
          st.busy = true;
          st.hostErr = null;
          F.render(true);
          F.api
            .tool_host({ url: st.hostInput })
            .then(r => {
              st.hostRes = r;
              st.busy = false;
              F.render(true);
            })
            .catch(err => {
              st.hostErr = err.message || String(err);
              st.busy = false;
              F.render(true);
            });
        });
      const sf = page.querySelector("#tbx-sec-form");
      if (sf) {
        const hibpCb = page.querySelector("#tbx-sec-hibp");
        if (hibpCb)
          hibpCb.addEventListener("change", () => {
            st.secHibp = !!hibpCb.checked;
          });
        sf.addEventListener("submit", e => {
          e.preventDefault();
          const val = page.querySelector("#tbx-sec-in").value;
          if (!val) return;
          st.busy = true;
          st.secErr = null;
          st.secInput = "";
          F.render(true);
          F.api
            .tool_secret({ value: val, hibp_opt_in: !!st.secHibp })
            .then(r => {
              st.secRes = r;
              st.busy = false;
              F.render(true);
            })
            .catch(err => {
              st.secErr = err.message || String(err);
              st.busy = false;
              F.render(true);
            });
        });
      }
    },
  });

  // ================= SCAN QUEUE (/queue) =================
  function loadQueue() {
    F.api
      .queue_list()
      .then(q => {
        st.queue = q;
        F.render(true);
      })
      .catch(() => {});
  }

  function renderQueue() {
    const q = st.queue;
    const projects = (F.projects || []).filter(p => !p.archived);
    return `
      <div class="card pad">
        <b>${esc(F.t("toolbox.queue_title", "Очередь сканов"))}</b>
        <p class="fhint">${esc(F.t("toolbox.queue_hint", "Последовательный запуск выбранных проектов без перекрытия лимитов и блокировки устройства."))}</p>
        <div class="seg v2-segg" role="radiogroup" aria-label="${esc(F.t("toolbox.profile", "Профиль"))}">${[
          ["passive", F.t("launch.profile_passive", "Пассивный")],
          ["std", F.t("launch.profile_std", "Стандартный")],
          ["full", F.t("launch.profile_full", "Полный")],
        ]
          .map(
            ([k, l]) =>
              `<button class="${st.qProfile === k ? "on" : ""}" role="radio" aria-checked="${st.qProfile === k}" data-act="tbx-qprof:${k}">${esc(l)}</button>`,
          )
          .join("")}</div>
        <div class="tbx-chips">${projects
          .map(
            p =>
              `<button class="chip ${st.qSel.has(p.id) ? "on" : ""}" data-act="tbx-qpick:${esc(p.id)}">${esc(p.name)}</button>`,
          )
          .join("")}</div>
        <div class="btnrow tbx-box">
          <button class="btn primary block" data-act="tbx-qadd" ${st.qSel.size ? "" : "disabled"}>${ic("plus")}${esc(F.t("toolbox.queue_add", { n: st.qSel.size }, "В очередь ({n})"))}</button>
        </div>
      </div>
      ${
        q
          ? `<div class="card pad tbx-box">
          <div class="tbx-qbar">
            <b>${esc(F.t("toolbox.queue_status", { s: q.paused ? F.t("toolbox.q_paused", "на паузе") : q.running ? F.t("toolbox.q_running", "выполняется") : q.pending ? F.t("toolbox.q_pending", "ожидание") : F.t("toolbox.q_empty", "пусто") }, "Статус: {s}"))}</b>
            <span class="pill ${q.paused ? "warn" : q.running ? "ok" : "mute"}">${q.percent || 0}% · ${q.done || 0}/${q.total || 0}</span>
          </div>
          <div class="pbar"><i style="width:${q.percent || 0}%"></i></div>
          <div class="btnrow tbx-box">
            ${
              q.paused
                ? `<button class="btn tonal" data-act="tbx-qresume">${ic("play")}${esc(F.t("toolbox.resume", "Продолжить"))}</button>`
                : `<button class="btn tonal" data-act="tbx-qpause" ${(q.items || []).length ? "" : "disabled"}>${ic("pause")}${esc(F.t("toolbox.pause", "Пауза"))}</button>`
            }
            <button class="btn" data-act="tbx-qclear" ${(q.items || []).length ? "" : "disabled"}>${ic("trash")}${esc(F.t("toolbox.clear", "Очистить"))}</button>
          </div>
        </div>
        <div class="list tbx-box">${(q.items || [])
          .map(it =>
            ui.row({
              lead: ui.leadIcon(it.status === "done" ? "check" : it.status === "error" ? "alert" : "scan"),
              title: esc(it.name || it.project),
              sub: `${esc(it.profile)} · ${esc(it.status)}${it.progress ? " · " + it.progress + "%" : ""}${it.error ? " · " + esc(it.error) : ""}`,
              tail: `<button class="ib" data-act="tbx-qdel:${esc(it.id)}" aria-label="${esc(F.t("toolbox.queue_remove", "Убрать из очереди"))}">${ic("x")}</button>`,
            }),
          )
          .join("")}</div>`
          : ""
      }`;
  }

  F.route("/queue", {
    title: () => F.t("toolbox.queue_title", "Очередь сканов"),
    sub: () => F.t("toolbox.queue_sub", "пакетный запуск проектов"),
    back: true,
    nav: false,
    render: renderQueue,
    live: (kind, ev) =>
      kind === "scan" && (ev.type === "queue" || ev.type === "done" || ev.type === "stopped"),
    mount: () => {
      if (!st.queue) loadQueue();
    },
  });

  F.on("scan", ev => {
    if (ev && ev.type === "queue") {
      st.queue = ev;
      if (F.current && F.current() === "/queue") F.render(true);
    }
  });

  Object.assign(F.actions, {
    "tbx-tab": t => {
      st.tab = t;
      if (t === "log") loadLog();
      F.render(true);
    },
    "tbx-reload-log": () => loadLog(),
    // In-memory journal of the quick tools: a plain confirm is enough (it is also lost on restart).
    "tbx-log-clear": () => {
      const n = (st.logList || []).length;
      F.sheet({
        title: F.t("toolbox.log_clear_q", "Очистить журнал инструментов?"),
        html: `<p class="lead">${esc(F.t("toolbox.log_clear_text", { n }, "Записей: {n}. Удаляются только запросы быстрых инструментов, проекты и их журнал запросов не затрагиваются."))}</p>`,
        footer: `<button class="btn" data-act="sheet-close">${esc(F.t("common.cancel", "Отмена"))}</button><button class="btn danger" data-act="tbx-log-clear-go">${ic("trash")}${esc(F.t("toolbox.log_clear", "Очистить"))}</button>`,
      });
    },
    "tbx-log-clear-go": () => {
      F.closeSheet();
      F.api.tool_log_clear().then(
        () => {
          st.logList = [];
          F.render(true);
          F.snack(F.t("toolbox.log_cleared", "Журнал инструментов очищен"));
          loadLog();
        },
        e =>
          F.snack(
            F.t("toolbox.log_clear_fail", { err: (e && e.message) || e }, "Не удалось очистить: {err}"),
          ),
      );
    },
    "tbx-pick-file": () => {
      F.api
        .platform_pick_files({ multiple: false })
        .catch(e => {
          F.snack(F.t("toolbox.no_file", { err: (e && e.message) || e }, "Файл не выбран: {err}"));
          return null;
        })
        .then(p => {
          const f = p && p.files && p.files[0];
          if (!f) return;
          st.busy = true;
          st.fileErr = null;
          F.render(true);
          F.api
            .tool_file({ path: f.path, name: f.name })
            .then(r => {
              st.fileRes = r;
              st.busy = false;
              F.render(true);
            })
            .catch(e => {
              st.fileErr = e.message || String(e);
              st.busy = false;
              F.render(true);
            });
        });
    },
    "tbx-demo-file": () => {
      st.busy = true;
      st.fileErr = null;
      F.render(true);
      F.api
        .tool_file({ path: "/demo/cache/contract.docx", name: "contract.docx" })
        .then(r => {
          st.fileRes = r;
          st.busy = false;
          F.render(true);
        })
        .catch(e => {
          st.fileErr = e.message || String(e);
          st.busy = false;
          F.render(true);
        });
    },
    "tbx-clean-file": () => {
      const cw = st.fileRes && st.fileRes.clean_with;
      if (!cw) return;
      // A local file outside any project: clean by path, then show the before/after check.
      const a = cw.args || {};
      F.api.doc_clean_file(a.path, a.name, F.hyg ? F.hyg.opts() : undefined).then(
        r => {
          const list = (r && r.cleaned) || [];
          if (F.hyg && list.length) F.hyg.showResults(list, "/tools");
          else F.snack(F.t("toolbox.clean_saved", "Очищенная копия сохранена"));
        },
        e => F.snack(F.t("toolbox.clean_err", { err: e.message || e }, "Ошибка очистки: {err}")),
      );
    },
    "tbx-qprof": p => {
      st.qProfile = p;
      F.render(true);
    },
    "tbx-qpick": id => {
      if (st.qSel.has(id)) st.qSel.delete(id);
      else st.qSel.add(id);
      F.render(true);
    },
    "tbx-qadd": () => {
      const ids = [...st.qSel];
      if (!ids.length) return;
      // "Full" turns on the active phase (ports, fuzzer, AXFR/NSEC) for every queued project: ask for an
      // explicit authorization first and show which targets will be probed.
      if (st.qProfile === "full") return activeSheet(ids);
      queueAdd(ids);
    },
    "tbx-qcons": (_, el) => {
      el.classList.toggle("on");
      el.setAttribute("aria-checked", el.classList.contains("on"));
      const b = document.getElementById("tbx-qgo");
      if (b) b.disabled = !el.classList.contains("on");
    },
    "tbx-qgo": () => {
      const ids = [...st.qSel];
      F.closeSheet();
      if (ids.length) queueAdd(ids);
    },
  });
  function activeSheet(ids) {
    const ps = (F.projects || []).filter(p => ids.includes(p.id));
    const rows = ps
      .map(
        p =>
          `<div class="row"><div class="body"><div class="t">${esc(p.name)}</div>${p.domain && p.domain !== p.name ? `<div class="s mono">${esc(p.domain)}</div>` : ""}</div></div>`,
      )
      .join("");
    F.sheet({
      title: F.t("toolbox.active_title", "Активная проверка"),
      html: `<div class="banner warn">${ic("alert")}<div><b>${esc(F.t("toolbox.active_b", "Профиль «Полный» включает активную фазу."))}</b> ${esc(F.t("toolbox.active_text", "Будут сканироваться порты, проверяться файлы на сайтах, перенос зоны DNS (AXFR) и обход NSEC. Это заметно для владельцев целей."))}</div></div>
        <div class="list">${rows}</div>
        <div class="card">${ui.check(false, esc(F.t("toolbox.active_consent", "У меня есть разрешение владельцев на активную проверку этих целей")), "tbx-qcons")}</div>`,
      footer: `<button class="btn" data-act="sheet-close">${esc(F.t("common.cancel", "Отмена"))}</button><button class="btn primary" id="tbx-qgo"
        data-act="tbx-qgo" disabled>${esc(F.t("toolbox.queue_add_btn", "Добавить в очередь"))}</button>`,
    });
  }
  function queueAdd(ids) {
    F.api.queue_add({ projects: ids, profile: st.qProfile }).then(
      r => {
        st.queue = r;
        st.qSel.clear();
        F.render(true);
        F.snack(F.t("toolbox.queue_added", { n: (r.added || []).length }, "Добавлено в очередь: {n}"));
      },
      e => F.snack(F.t("toolbox.queue_err", { err: e.message || e }, "Ошибка очереди: {err}")),
    );
  }
  const queueErr = e =>
    F.snack(F.t("toolbox.queue_err", { err: (e && e.message) || e }, "Ошибка очереди: {err}"));
  Object.assign(F.actions, {
    "tbx-qpause": () => {
      F.api.queue_pause().then(r => {
        st.queue = r;
        F.render(true);
        F.snack(F.t("toolbox.q_paused_snack", "Очередь на паузе"));
      }, queueErr);
    },
    "tbx-qresume": () => {
      F.api.queue_resume().then(r => {
        st.queue = r;
        F.render(true);
        F.snack(F.t("toolbox.q_resumed_snack", "Очередь продолжена"));
      }, queueErr);
    },
    "tbx-qdel": id => {
      F.api.queue_remove(id).then(r => {
        st.queue = r;
        F.render(true);
      }, queueErr);
    },
    "tbx-qclear": () => {
      F.api.queue_clear({ stop: false }).then(r => {
        st.queue = r;
        F.render(true);
        F.snack(F.t("toolbox.q_cleared_snack", "Очередь очищена"));
      }, queueErr);
    },
  });

  if (!F.menuItems.some(m => m.id === "tbx-tools"))
    F.menuItems.push(
      {
        id: "tbx-tools",
        order: 35,
        icon: "spark",
        label: () => F.t("toolbox.tools_title", "Быстрые инструменты"),
        sub: () => F.t("toolbox.menu_tools_sub", "Файл, почта, хост, пароль без проекта"),
        act: "go:/tools",
        chev: true,
      },
      {
        id: "tbx-queue",
        order: 36,
        icon: "tasks",
        label: () => F.t("toolbox.queue_title", "Очередь сканов"),
        sub: () => F.t("toolbox.menu_queue_sub", "Пакетный запуск нескольких проектов"),
        act: "go:/queue",
        chev: true,
      },
    );
})();
