// Projects screen (route /projects): the "New target" field, the list of recent projects, and project
// actions via long press or the ⋮ menu.
(function () {
  const F = window.FOCA,
    { ic, esc, ui } = F;

  // The project list comes from F.projects (project_list, see js/api.js); archiving is the `archived` flag
  // (F.api.project_update).
  // Reference cases (built-in samples) never show up among recent projects: "Open reference case" opens them.
  const activeList = () => F.projects.filter(p => !p.archived && !p.reference);
  const archivedList = () => F.projects.filter(p => p.archived);
  // Reference cases get their own section, so a case the user worked in (or imported twice) never vanishes.
  const referenceList = () => F.projects.filter(p => !p.archived && p.reference);
  const byId = id => F.projects.find(p => p.id === id);

  const plural = (n, one, few, many) => F.plural(n, one, few, many);
  /**
   * Maps a project risk score (0-100, or null when not yet assessed) to its badge style.
   * @param {number|null|undefined} score
   * @returns {{cls: string, label: string, icon: string}}
   */
  const riskLvl = score => {
    if (score == null) return { cls: "none", label: F.t("projects.no_data", "нет данных"), icon: "dot" };
    if (score >= 70) return { cls: "crit", label: F.t("projects.high", "высокий"), icon: "alert" };
    if (score >= 40) return { cls: "warn", label: F.t("projects.medium", "средний"), icon: "info" };
    return { cls: "ok", label: F.t("projects.low", "низкий"), icon: "check" };
  };

  /** Progress badge for a project card while a scan is running. */
  function scanBadge(live, progress) {
    const paused = live && F.scan.paused;
    const active = live && F.scan.active;
    let label = F.t("projects.scan_running", "Идёт скан");
    if (paused) label = F.t("projects.scan_paused", "Скан на паузе");
    else if (active) label = F.t("projects.active_scan", "Активный скан");
    return `<div class="pj-scan"><span class="pill ${active ? "crit" : "info"}">${ic(paused ? "pause" : "spin", paused ? "" : "spin")}${label} · ${progress}%</span><div class="pbar"><i style="width:${progress}%"></i></div></div>`;
  }
  function card(p) {
    const risk = riskLvl(p.risk);
    // Scan state: prefer live core events (F.scan.project), fall back to the project_list summary.
    const live = !!(F.scan && F.scan.running && F.scan.project === p.id);
    const scanning = live || (p.scanning && !(F.scan && F.scan.project === p.id && !F.scan.running));
    const progress = live ? Math.round(F.scan.progress || 0) : p.progress || 0;
    const meta = [
      p.findings
        ? plural(
            p.findings,
            F.t("projects.finding", "находка"),
            F.t("projects.findings", "находки"),
            F.t("projects.finding_many", "находок"),
          )
        : F.t("projects.no_findings", "Находок нет"),
      p.lastScan ? `${ic("clock")}${esc(p.lastScan)}` : F.t("projects.never_scanned", "Скан не запускался"),
    ];
    return `<div class="card pj-card tap" data-act="pj-open:${p.id}" data-pj="${p.id}" role="button"
      aria-label="${esc(p.name)}">
      <div class="pj-top">
        <div class="pj-risk ${risk.cls}"
          aria-label="${F.t("projects.risk_risk_label", { risk: p.risk ?? "-", label: risk.label }, "Риск {risk}, {label}")}"><b>${p.risk ?? "-"}</b><span>${ic(risk.icon)}${risk.label}</span></div>
        <div class="pj-body">
          <div class="pj-name">${esc(p.name)}</div>
          <div class="pj-client">${esc(p.client)}</div>
          <div class="pj-meta">${meta.map(m => `<span>${m}</span>`).join("")}</div>
        </div>
        <button class="ib pj-more" data-act="pj-menu:${p.id}"
          aria-label="${esc(F.t("projects.project_actions", "Действия с проектом"))}">${ic("more")}</button>
      </div>
      ${scanning ? scanBadge(live, progress) : ""}
    </div>`;
  }

  const emptyState = () =>
    ui.empty({
      icon: "folder",
      title: F.t("projects.no_projects", "Нет проектов"),
      text: F.t(
        "projects.create_your_first_project_enter",
        "Создайте первый проект: укажите домен, URL, IP-адрес или сеть CIDR.",
      ),
      action: `<button class="btn primary" data-act="pj-new">${ic("plus")}${esc(F.t("projects.new", "Новый проект"))}</button>`,
    });

  /** Card for the unsaved project draft left by the launch wizard. */
  function draftCard() {
    const d = F.launchDraft && F.launchDraft();
    if (!d || !(d.targets || []).length) return "";
    return `<div class="list pj-draft">${ui.row({
      lead: ui.leadIcon("note", "var(--accent)"),
      title: `${esc(F.t("projects.draft", "Черновик:"))} ${esc(d.pname || d.targets[0])}`,
      sub: `${plural(d.targets.length, F.t("projects.target", "цель"), F.t("projects.targets", "цели"), F.t("projects.target_many", "целей"))}${d.pclient ? " · " + esc(d.pclient) : ""} ${esc(F.t("projects.project_not_created_yet", "· проект ещё не создан"))}`,
      act: "pj-draft",
      tail: `<button class="ib" data-act="pj-draft-del" aria-label="${esc(F.t("projects.delete_draft", "Удалить черновик"))}">${ic("x")}</button>`,
    })}</div>`;
  }
  function referenceSection() {
    const refs = referenceList();
    return refs.length
      ? `${ui.secH(F.t("projects.reference_cases", "Эталонные кейсы"), refs.length)}
        <div class="pj-list pj-ref">${refs.map(card).join("")}</div>`
      : "";
  }
  function render() {
    const list = activeList();
    return `
      ${F.betaNote ? F.betaNote.card() : ""}
      <form class="pj-new" id="pj-new" autocomplete="off">
        <label class="flabel" for="pj-q">${esc(F.t("projects.new_target", "Новая цель"))}</label>
        <div class="pj-newrow">
          <div class="field pj-qf">${ic("target")}<textarea id="pj-q" rows="1" placeholder="${esc(F.t("projects.domain_url_ip_or_cidr", "Домен, URL, IP или CIDR"))}"
            enterkeyhint="go" autocapitalize="off" spellcheck="false" aria-describedby="pj-q-hint"></textarea></div>
          <button class="pj-go" type="submit" aria-label="${esc(F.t("projects.go_scan_setup", "Перейти к настройке скана"))}">${ic("chev")}</button>
        </div>
        <div class="fhint" id="pj-q-hint" aria-live="polite">${esc(F.t("projects.you_can_paste_several_lines_at", "Можно вставить список: каждая строка, значение через запятую или пробел станет отдельной целью."))}</div>
      </form>
      ${draftCard()}
      <div class="list pj-offline">${ui.row({
        lead: ui.leadIcon("folder", "var(--ok)"),
        title: F.t("menu.offline", "Разобрать файлы без сети"),
        sub: F.t(
          "projects.folder_files_or_zip_files_never",
          "Папка, файлы или ZIP · файлы не покидают устройство",
        ),
        act: "go:/import",
      })}${ui.row({
        lead: ui.leadIcon("spark", "var(--accent)"),
        title: F.t("projects.open_reference_case", "Открыть эталонный кейс"),
        sub: F.t(
          "projects.12_synthetic_documents_tov",
          "12 синтетических документов ТОВ «Приклад» · без интернета",
        ),
        act: "demo-case",
      })}${ui.row({
        lead: ui.leadIcon("globe", "var(--info)"),
        title: F.t("projects.quick_tools", "Быстрые инструменты"),
        sub: F.t(
          "projects.file_e_mail_host_password_hibp",
          "Файл, почта, хост, пароль (HIBP) · без создания проекта",
        ),
        act: "go:/tools",
      })}${ui.row({
        lead: ui.leadIcon("tasks"),
        title: F.t("projects.scan_queue", "Очередь сканов"),
        sub: F.t("projects.run_projects_one_after_another", "Пакетный последовательный запуск проектов"),
        act: "go:/queue",
      })}${ui.row({
        lead: ui.leadIcon("lock", "var(--ok)"),
        title: F.t("projects.import_enc", "Импорт .foca.enc"),
        sub: F.t("projects.decrypt_portable_encrypted", "Расшифровать переносимый криптоконтейнер проекта"),
        act: "pj-import-enc",
      })}</div>
      ${F.withStates(
        () =>
          list.length
            ? `
        ${ui.secH(F.t("projects.recent_projects", "Последние проекты"), list.length)}
        <div class="pj-list">${list.map(card).join("")}</div>
        <p class="pj-tip">${ic("info")}${esc(F.t("projects.long_press_card_open_its_actions", "Удерживайте карточку, чтобы открыть действия."))}</p>
        ${archivedList().length ? `<div class="list pj-arch">${ui.row({ lead: ui.leadIcon("save"), title: F.t("projects.archive", "Архив"), sub: plural(archivedList().length, F.t("projects.project", "проект"), F.t("projects.projects", "проекта"), F.t("projects.project_many", "проектов")), act: "pj-archive-list" })}</div>` : ""}
        ${referenceSection()}`
            : emptyState() +
              referenceSection() +
              (archivedList().length
                ? `<div class="list pj-arch">${ui.row({ lead: ui.leadIcon("save"), title: F.t("projects.archive", "Архив"), sub: plural(archivedList().length, F.t("projects.project", "проект"), F.t("projects.projects", "проекта"), F.t("projects.project_many", "проектов")), act: "pj-archive-list" })}</div>`
                : ""),
        {
          loading: "cards",
          empty: {
            icon: "folder",
            title: F.t("projects.no_projects", "Нет проектов"),
            text: F.t(
              "projects.create_your_first_project_enter_2",
              "Создайте первый проект: укажите домен, IP-адрес или организацию заказчика.",
            ),
            action: `<button class="btn primary" data-act="pj-new">${ic("plus")}${esc(F.t("projects.new", "Новый проект"))}</button>`,
          },
          error: {
            title: F.t("projects.could_not_open_project_storage", "Не удалось открыть хранилище проектов"),
            text: F.t(
              "projects.database_file_damaged_or_locked",
              "Файл базы повреждён или заблокирован. Попробуйте ещё раз.",
            ),
          },
        },
      )}`;
  }

  F.route("/projects", {
    title: () => F.t("projects.title", "Проекты"),
    nav: false,
    sub: () =>
      activeList().length && F.demo.mode === "normal"
        ? plural(
            activeList().length,
            F.t("projects.project", "проект"),
            F.t("projects.projects", "проекта"),
            F.t("projects.project_many", "проектов"),
          )
        : "",
    actions: () => [
      { icon: "gear", act: "go:/settings", label: F.t("menu.settings", "Настройки") },
      { icon: "more", act: "menu", label: F.t("app.menu", "Меню") },
    ],
    render,
    // Cards refresh on scan events and whenever the project list changes.
    live: (kind, ev) =>
      kind === "scan"
        ? ["started", "progress", "done", "stopped", "paused", "resumed"].includes(ev.type)
        : kind === "db",
    mount(page) {
      page.classList.add("pj-pg");
      const form = page.querySelector("#pj-new");
      const q = page.querySelector("#pj-q");
      const hint = page.querySelector("#pj-q-hint");
      const hint0 = hint.textContent;
      // A pasted list becomes several targets: preview how many and which ones the wizard will refuse.
      const preview = () => {
        const lt = F.launchTargets;
        const items = lt ? lt.split(q.value) : [];
        hint.classList.remove("err");
        if (items.length < 2) {
          hint.textContent = hint0;
          return;
        }
        const bad = items.filter(v => {
          const r = lt.parse(v);
          return r && r.err;
        });
        hint.textContent = [
          F.tp("projects.paste_n", items.length, { n: items.length }, "{n} цель|{n} цели|{n} целей"),
          bad.length
            ? F.t(
                "projects.paste_bad",
                { n: bad.length, v: bad.slice(0, 2).join(", ") },
                "с ошибкой: {n} ({v})",
              )
            : "",
        ]
          .filter(Boolean)
          .join(" · ");
        hint.classList.toggle("err", bad.length > 0);
      };
      q.addEventListener("input", preview);
      q.addEventListener("keydown", e => {
        // Enter starts the wizard like a one-line field; Shift+Enter adds a line.
        if (e.key === "Enter" && !e.shiftKey && !e.isComposing) {
          e.preventDefault();
          form.requestSubmit
            ? form.requestSubmit()
            : form.dispatchEvent(new Event("submit", { cancelable: true }));
        }
      });
      form.addEventListener("submit", e => {
        e.preventDefault();
        const v = q.value.trim();
        if (!v) {
          q.focus();
          hint.textContent = F.t("projects.enter_target_first", "Введите домен, URL, IP или CIDR.");
          hint.classList.add("err");
          return;
        }
        F.state.newTarget = v;
        F.go("/new");
      });
      // Long press on a card opens the action sheet.
      let pressTimer = null,
        x0 = 0,
        y0 = 0,
        fired = false;
      page.addEventListener("pointerdown", e => {
        const cardEl = e.target.closest("[data-pj]");
        if (!cardEl || e.target.closest(".pj-more")) return;
        fired = false;
        x0 = e.clientX;
        y0 = e.clientY;
        cardEl.classList.add("pressing");
        pressTimer = setTimeout(() => {
          fired = true;
          cardEl.classList.remove("pressing");
          try {
            navigator.vibrate && navigator.vibrate(20);
          } catch (x) {}
          menu(cardEl.dataset.pj);
        }, 520);
      });
      const cancel = () => {
        clearTimeout(pressTimer);
        page.querySelectorAll(".pressing").forEach(x => x.classList.remove("pressing"));
      };
      page.addEventListener("pointermove", e => {
        if (Math.abs(e.clientX - x0) > 10 || Math.abs(e.clientY - y0) > 10) cancel();
      });
      ["pointerup", "pointercancel", "pointerleave"].forEach(ev => page.addEventListener(ev, cancel));
      page.addEventListener(
        "click",
        e => {
          if (fired) {
            e.stopPropagation();
            e.preventDefault();
            fired = false;
          }
        },
        true,
      );
    },
  });

  function menu(id) {
    const p = byId(id);
    if (!p) return;
    F.sheet({
      cls: "la-sheet",
      title: p.name,
      html: `<p class="pj-sh-sub">${esc(p.client)}</p>
        <div class="srow" data-act="pj-open:${id}">${ic("open")}<span class="lbl">${esc(F.t("common.open", "Открыть"))}</span></div>
        <div class="srow"
          data-act="pj-props:${id}">${ic("note")}<span class="lbl">${esc(F.t("projects.properties", "Свойства"))}<small>${esc(F.t("projects.name_client_alternative_domains", "Имя, заказчик, альтернативные домены, заметки"))}</small></span></div>
        <div class="srow"
          data-act="pj-dup:${id}">${ic("copy")}<span class="lbl">${esc(F.t("projects.duplicate", "Дублировать"))}<small>${esc(F.t("projects.same_targets_settings_no_results", "Те же цели и настройки, без результатов"))}</small></span></div>
        <div class="srow"
          data-act="pj-archive:${id}">${ic("save")}<span class="lbl">${esc(F.t("projects.archive_2", "Архивировать"))}<small>${esc(F.t("projects.hide_from_list_data_kept", "Скрыть из списка, данные сохранятся"))}</small></span></div>
        <div class="srow"
          data-act="pj-export:${id}">${ic("export")}<span class="lbl">${esc(F.t("projects.export_foca_enc", "Экспорт .foca.enc"))}<small>${esc(F.t("projects.encrypted_container_chacha20", "Зашифрованный контейнер (ChaCha20-Poly1305)"))}</small></span></div>
        <div class="srow pj-danger"
          data-act="pj-del:${id}">${ic("eraser")}<span class="lbl">${esc(F.t("projects.secure_delete", "Безопасно удалить"))}<small>${esc(F.t("projects.wipe_files_beyond_recovery", "Затирание файлов без возможности восстановления"))}</small></span></div>`,
    });
  }

  /**
   * Project properties sheet: name, client and notes (project_update); alternative domains are stored as
   * "domain" scope targets (scope_set).
   * @param {string} id Project id.
   */
  F.projectProps = id => {
    const project = byId(id) || (F.db.project && F.db.project.id === id ? F.db.project : null);
    if (!project) return;
    F.api.scope_get(id).then(sc => {
      const meta = id === (F.db.project || {}).id ? F.db.project : null;
      const main = String((meta && meta.domain) || project.name).toLowerCase();
      const alt = (sc.targets || [])
        .filter(t => t.type === "domain" && String(t.v).toLowerCase() !== main)
        .map(t => t.v);
      F.sheet({
        cls: "la-sheet",
        title: F.t("projects.project_properties", "Свойства проекта"),
        full: true,
        html: `<label class="flabel"
          for="pp-name">${esc(F.t("projects.project_name", "Имя проекта"))}</label><div class="field">${ic("folder")}<input id="pp-name"
          value="${esc(project.name)}"></div>
          <label class="flabel"
            for="pp-client">${esc(F.t("projects.client", "Заказчик"))}</label><div class="field">${ic("la-org")}<input id="pp-client"
            value="${esc(project.client || "")}"></div>
          <label class="flabel"
            for="pp-alt">${esc(F.t("projects.alternative_domains", "Альтернативные домены"))}</label><div class="field pp-ta">${ic("domain")}<textarea id="pp-alt"
            rows="3" placeholder="${esc(F.t("projects.contoso_com_ua_one_per_line", "contoso.example.org: по одному в строке"))}" autocapitalize="off"
            spellcheck="false">${esc(alt.join("\n"))}</textarea></div>
          <p class="fhint">${F.t("projects.these_scope_targets_type_domain", { main: esc(main) }, "Это цели скоупа типа «домен». Основной домен: {main}.")}</p>
          <label class="flabel"
            for="pp-notes">${esc(F.t("projects.project_notes", "Заметки проекта"))}</label><div class="field pp-ta"><textarea id="pp-notes" rows="5"
            maxlength="2000"
            placeholder="${esc(F.t("projects.contacts_agreements_what_check", "Контакты, договорённости, что проверить"))}">${esc((meta && meta.notes) || project.notes || "")}</textarea></div>`,
        footer: `<button class="btn"
          data-act="sheet-close">${esc(F.t("common.cancel", "Отмена"))}</button><button class="btn primary"
          data-act="pj-props-save:${id}">${ic("check")}${esc(F.t("common.save", "Сохранить"))}</button>`,
        onMount: sh => {
          F.state.ppAlt = alt;
          F.state.ppTargets = sc.targets || [];
        },
      });
    });
  };
  Object.assign(F.actions, {
    "pj-props": id => {
      F.closeSheet();
      setTimeout(() => F.projectProps(id), 200);
    },
    "pj-props-save": id => {
      const fieldValue = k => (document.getElementById(k) || {}).value || "";
      const DOM = /^(?=.{3,253}$)([\p{L}\d]([\p{L}\d-]{0,61}[\p{L}\d])?\.)+\p{L}{2,}$/u;
      const want = [
        ...new Set(
          fieldValue("pp-alt")
            .split(/[\n,;\s]+/)
            .map(x => x.trim().toLowerCase())
            .filter(Boolean),
        ),
      ];
      const bad = want.filter(x => !DOM.test(x));
      if (bad.length) {
        F.snack(`${esc(F.t("projects.not_domain", "Не домен:"))} ${bad.join(", ")}`);
        return;
      }
      const name = fieldValue("pp-name").trim() || byId(id).name;
      const old = F.state.ppAlt || [],
        tg = F.state.ppTargets || [];
      const targets = tg
        .filter(t => !(t.type === "domain" && old.includes(t.v) && !want.includes(String(t.v).toLowerCase())))
        .concat(
          want
            .filter(v => !tg.some(t => String(t.v).toLowerCase() === v))
            .map(v => ({ v, type: "domain", active: false })),
        );
      F.closeSheet();
      F.api
        .project_update(id, { name, client: fieldValue("pp-client").trim(), notes: fieldValue("pp-notes") })
        .then(() => F.api.scope_set({ targets }, id))
        .then(() => {
          F.render(true);
          F.snack(F.t("projects.project_properties_saved", "Свойства проекта сохранены"));
        });
    },
    "pj-draft": () => {
      F.state.newDraft = true;
      F.go("/new");
    },
    "pj-draft-del": (_, el, e) => {
      e && e.stopPropagation();
      const d = F.launchDraft();
      F.api.settings_set({ ui: { new_draft: null } }).then(() => {
        F.render(true);
        F.snack(F.t("projects.draft_deleted", "Черновик удалён"), {
          action: () => F.api.settings_set({ ui: { new_draft: d } }).then(() => F.render(true)),
        });
      });
    },
    "pj-menu": id => menu(id),
    "pj-new": () => {
      F.state.newTarget = "";
      F.go("/new");
    },
    "pj-open": id => {
      const p = byId(id);
      if (!p) return;
      F.api.project_open(id).then(() => F.reset(["/projects", "/p/overview"]));
    },
    "pj-dup": id => {
      F.closeSheet();
      F.api.project_duplicate(id).then(copy => {
        F.render(true);
        F.snack(F.t("projects.project_duplicated", "Проект продублирован"), {
          action: () => F.api.project_delete(copy.id).then(() => F.render(true)),
        });
      });
    },
    "pj-archive": id => {
      F.closeSheet();
      F.api.project_update(id, { archived: true }).then(() => {
        F.render(true);
        F.snack(F.t("projects.project_moved_archive", "Проект перемещён в архив"), {
          action: () => F.api.project_update(id, { archived: false }).then(() => F.render(true)),
        });
      });
    },
    "pj-archive-list": () =>
      F.sheet({
        cls: "la-sheet",
        title: F.t("projects.archive", "Архив"),
        html: `<div class="list">${archivedList()
          .map(p =>
            ui.row({
              lead: ui.leadIcon("folder"),
              title: esc(p.name),
              sub: esc(p.client),
              tail: `<button class="btn sm tonal" data-act="pj-unarch:${p.id}">${esc(F.t("projects.restore", "Вернуть"))}</button>`,
            }),
          )
          .join("")}</div>`,
      }),
    "pj-unarch": id => {
      F.closeSheet();
      F.api.project_update(id, { archived: false }).then(() => {
        F.render(true);
        F.snack(F.t("projects.project_restored_from_archive", "Проект возвращён из архива"));
      });
    },
    "pj-export": id => {
      const p = byId(id);
      if (!p) return;
      F.state.pjExpFiles = false;
      F.sheet({
        cls: "la-sheet",
        title: F.t("projects.export_foca_enc", "Экспорт .foca.enc"),
        html: `<div class="list">${ui.row({ lead: ui.leadIcon("lock", "var(--ok)"), title: esc(p.name) + ".foca.enc", sub: `ChaCha20-Poly1305 + PBKDF2-HMAC-SHA256 · ${plural(p.docs || 0, F.t("projects.document", "документ"), F.t("projects.documents", "документа"), F.t("projects.document_many", "документов"))}, ${plural(p.findings || 0, F.t("projects.finding", "находка"), F.t("projects.findings", "находки"), F.t("projects.finding_many", "находок"))}` })}</div>
          <label class="flabel" for="pj-enc-pw">${esc(F.t("projects.encryption_password_min_6", "Пароль шифрования (мин. 6 символов)"))}</label>
          <div class="field">${ic("key")}<input id="pj-enc-pw" type="password" placeholder="${esc(F.t("projects.enter_password", "Введите пароль"))}" autocomplete="new-password"></div>
          <div class="list" style="margin-top:10px">${ui.check(false, F.t("projects.include_downloaded_document", "Включить скачанные файлы документов"), "pj-exp-files", F.t("projects.makes_container_larger", "Увеличит размер контейнера"))}</div>
          <div class="banner info"
            style="margin-top:12px">${ic("info")}<div>${esc(F.t("projects.password_not_stored_device", "Пароль не сохраняется на устройстве. Без него расшифровать контейнер невозможно."))}</div></div>`,
        footer: `<button class="btn"
          data-act="sheet-close">${esc(F.t("common.cancel", "Отмена"))}</button><button class="btn primary"
          data-act="pj-export-go:${id}">${ic("share")}${esc(F.t("projects.encrypt", "Зашифровать"))}</button>`,
      });
    },
    "pj-exp-files": (_, el) => {
      F.state.pjExpFiles = !F.state.pjExpFiles;
      el.classList.toggle("on", F.state.pjExpFiles);
      el.setAttribute("aria-checked", F.state.pjExpFiles);
    },
    "pj-export-go": id => {
      const pw = ((document.getElementById("pj-enc-pw") || {}).value || "").trim();
      if (pw.length < 6) {
        F.snack(F.t("projects.password_must_at_least_6", "Пароль должен содержать минимум 6 символов"));
        return;
      }
      F.api.project_export_encrypted(id, pw, !!F.state.pjExpFiles).then(
        res => {
          F.closeSheet();
          F.state.pjLastEnc = { path: res.path, name: res.name }; // The demo picker offers the last export.
          if (!F.isDemo && res.path) F.api.platform_share({ path: res.path, name: res.name });
          F.snack(`${esc(F.t("projects.container_created", "Создан контейнер"))} ${res.name}`);
        },
        e => F.snack(F.t("projects.export_error", "Ошибка экспорта: ") + (e.message || e)),
      );
    },
    "pj-import-enc": () => {
      F.state.pjImp = null;
      F.sheet({
        cls: "la-sheet",
        title: F.t("projects.import_enc", "Импорт .foca.enc"),
        html: `<p class="lead">${esc(F.t("projects.choose_file", "Выберите файл"))} <span class="mono">.foca.enc</span> ${esc(F.t("projects.enter_decryption_password", "и укажите пароль расшифровки. Проект импортируется как новый без перезаписи существующих."))}</p>
          <div class="list"><div class="row tap" data-act="pj-imp-pick" role="button" id="pj-imp-file">${ui.leadIcon("folder")}<div class="body"><div class="t">${esc(F.t("projects.choose_file_2", "Выбрать файл"))}</div><div class="s">${esc(F.t("projects.foca_enc_container_from_files", "Контейнер .foca.enc из «Файлов»"))}</div></div>${ic("chev", "chev")}</div></div>
          <label class="flabel" for="pj-imp-pw">${esc(F.t("projects.decryption_password", "Пароль расшифровки"))}</label>
          <div class="field">${ic("key")}<input id="pj-imp-pw" type="password" placeholder="${esc(F.t("projects.password", "Пароль контейнера"))}" autocomplete="current-password"></div>
          <label class="flabel" for="pj-imp-name">${esc(F.t("projects.new_project_name", "Новое имя проекта"))} <span class="muted">${esc(F.t("projects.optional", "(необязательно)"))}</span></label>
          <div class="field">${ic("note")}<input id="pj-imp-name" type="text" placeholder="${esc(F.t("projects.keep_original", "Оставить исходное"))}"></div>`,
        footer: `<button class="btn" data-act="sheet-close">${esc(F.t("common.cancel", "Отмена"))}</button><button class="btn primary" data-act="pj-import-enc-go">${ic("download")}${esc(F.t("projects.import", "Импортировать"))}</button>`,
      });
    },
    "pj-imp-pick": () => {
      const show = f => {
        F.state.pjImp = f;
        const el = document.querySelector("#pj-imp-file .body");
        if (el)
          el.innerHTML = `<div class="t mono">${esc(f.name)}</div><div class="s">${esc(F.t("projects.tap_choose_another_one", "Нажмите, чтобы выбрать другой"))}</div>`;
      };
      if (F.isDemo) {
        const last = F.state.pjLastEnc;
        if (!last)
          return F.snack(
            F.t("projects.demo_export_project_foca_enc", "Демо: сначала экспортируйте проект в .foca.enc"),
          );
        return show(last);
      }
      F.api.platform_pick_files({ multiple: false }).then(
        r => {
          const f = ((r && r.files) || [])[0];
          if (!f) return;
          if (!/\.foca\.enc$|\.enc$/i.test(f.name || ""))
            F.snack(F.t("projects.does_not_look_like_foca_enc", "Похоже, это не контейнер .foca.enc"));
          show({ path: f.path, name: f.name });
        },
        e => F.snack(F.t("projects.no_file_selected", "Файл не выбран: ") + (e.message || e)),
      );
    },
    "pj-import-enc-go": () => {
      const path = (F.state.pjImp && F.state.pjImp.path) || "";
      const pw = ((document.getElementById("pj-imp-pw") || {}).value || "").trim();
      const name = ((document.getElementById("pj-imp-name") || {}).value || "").trim();
      if (!path || !pw) {
        F.snack(F.t("projects.specify_file_password", "Укажите файл и пароль"));
        return;
      }
      F.api.project_import_encrypted(path, pw, name || undefined).then(
        r => {
          F.closeSheet();
          F.render(true);
          F.snack(
            `${F.t("projects.imported_project_name", { name: r.project.name }, "Импортирован проект «{name}»")}`,
          );
        },
        e => F.snack(F.t("projects.import_error", "Ошибка импорта: ") + (e.message || e)),
      );
    },
    "pj-del": id => {
      const p = byId(id);
      F.sheet({
        cls: "la-sheet",
        title: F.t("projects.delete_project", "Удалить проект?"),
        html: `<div class="banner crit">${ic("alert")}<div><b>${esc(p.name)}</b> ${esc(F.t("projects.all_findings_downloaded", "будет удалён вместе со всеми находками, скачанными документами и журналами. Отменить нельзя."))}</div></div>
          <p class="pj-sh-sub">${esc(F.t("projects.delete_hold_delete_button_1_2", "Чтобы удалить, удерживайте кнопку «Удалить» 1-2 секунды."))}</p>`,
        footer: `<button class="btn"
          data-act="sheet-close">${esc(F.t("common.cancel", "Отмена"))}</button><button class="btn danger hold"
          data-hold="pj-del-go:${id}"><span class="hold-fill"></span>${ic("eraser")}${esc(F.t("common.delete", "Удалить"))}</button>`,
      });
    },
    "pj-del-go": id => {
      F.closeSheet();
      F.api
        .project_delete(id)
        .then(() =>
          F.project && F.project.id === id && activeList()[0] ? F.api.project_open(activeList()[0].id) : null,
        )
        .then(() => {
          F.render(true);
          F.snack(F.t("projects.project_securely_deleted", "Проект безопасно удалён"));
        });
    },
  });
})();
