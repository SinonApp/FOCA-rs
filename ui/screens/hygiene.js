// Document hygiene (docs/API.md → "Гигиена документов"): grade A-F with fix steps, cleaning
// options, the before/after screen (/clean/result: field diff, verdict, warnings, "share a clean copy") and the
// check of files shared into the app from other apps (Android share sheet → /shared: no project, no network).
(function () {
  const F = window.FOCA,
    { ic, esc, ui } = F;

  // ================= texts (foca-meta IssueCode / FixCode / CleanWarning) =================
  const ISSUE = () => ({
    people: F.t("hygiene.issue_people", "Имена людей в метаданных: {samples}"),
    company: F.t("hygiene.issue_company", "Организация/руководитель в свойствах"),
    local_paths: F.t("hygiene.issue_local_paths", "Локальные пути (имя пользователя, структура диска)"),
    network_paths: F.t("hygiene.issue_network_paths", "Сетевые пути и серверы: {samples}"),
    internal_links: F.t("hygiene.issue_internal_links", "Ссылки в тексте на внутренние ресурсы"),
    printers: F.t("hygiene.issue_printers", "Имена принтеров"),
    emails: F.t("hygiene.issue_emails", "Адреса e-mail в метаданных"),
    software: F.t("hygiene.issue_software", "Программы и версии"),
    edit_history: F.t("hygiene.issue_edit_history", "Даты создания/изменения, время правки, число ревизий"),
    custom_properties: F.t("hygiene.issue_custom_properties", "Пользовательские свойства документа"),
    pdf_revisions: F.t("hygiene.issue_pdf_revisions", "Предыдущие ревизии в PDF: {count}"),
    pdf_removed_text: F.t(
      "hygiene.issue_pdf_removed_text",
      "Удалённый текст ещё есть в файле ({count} фрагм.)",
    ),
    bad_redaction: F.t(
      "hygiene.issue_bad_redaction",
      "Текст под чёрными плашками можно выделить (стр. {pages})",
    ),
    hidden_content: F.t("hygiene.issue_hidden_content", "Скрытый текст/строки/листы"),
    comments: F.t("hygiene.issue_comments", "Комментарии ({count})"),
    tracked_changes: F.t("hygiene.issue_tracked_changes", "Непринятые исправления ({count})"),
    gps: F.t("hygiene.issue_gps", "Координаты GPS"),
    camera: F.t("hygiene.issue_camera", "Модель камеры"),
    thumbnail_mismatch: F.t(
      "hygiene.issue_thumbnail_mismatch",
      "Миниатюра отличается от изображения (видно обрезанное/закрытое)",
    ),
    thumbnail: F.t("hygiene.issue_thumbnail", "Встроенная миниатюра"),
    xmp_history: F.t("hygiene.issue_xmp_history", "История правок XMP и идентификаторы документа"),
    rsids: F.t("hygiene.issue_rsids", "Идентификаторы сессий правки Word"),
    embedded_files: F.t("hygiene.issue_embedded_files", "Вложенные файлы ({count})"),
    macros: F.t("hygiene.issue_macros", "Макросы"),
    javascript: F.t("hygiene.issue_javascript", "JavaScript в PDF"),
    pii: F.t("hygiene.issue_pii", "Персональные данные в тексте: {kinds}"),
    secrets: F.t("hygiene.issue_secrets", "Секреты/ключи в документе: {kinds}"),
    signed: F.t("hygiene.issue_signed", "Документ подписан: очистка снимет подпись"),
    encrypted: F.t("hygiene.issue_encrypted", "Документ зашифрован: оценка неполная"),
  });
  const FIX = () => ({
    clean_metadata: F.t("hygiene.fix_clean_metadata", "Очистить метаданные"),
    rewrite_pdf: F.t("hygiene.fix_rewrite_pdf", "Пересохранить PDF без старых ревизий"),
    redact_properly: F.t(
      "hygiene.fix_redact_properly",
      "Удалить текст инструментом редактирования (стр. {pages}), затем очистить",
    ),
    remove_hidden_content: F.t(
      "hygiene.fix_remove_hidden_content",
      "Удалить скрытый текст, строки и листы в редакторе",
    ),
    review_links: F.t("hygiene.fix_review_links", "Проверить ссылки в тексте на внутренние ресурсы"),
    resolve_comments: F.t("hygiene.fix_resolve_comments", "Удалить или разрешить комментарии ({count})"),
    accept_tracked_changes: F.t(
      "hygiene.fix_accept_tracked_changes",
      "Принять или отклонить исправления ({count})",
    ),
    regenerate_thumbnail: F.t("hygiene.fix_regenerate_thumbnail", "Удалить миниатюру"),
    remove_embedded_files: F.t("hygiene.fix_remove_embedded_files", "Удалить вложения ({count})"),
    remove_macros: F.t("hygiene.fix_remove_macros", "Удалить макросы / сохранить без макросов"),
    remove_javascript: F.t("hygiene.fix_remove_javascript", "Удалить JavaScript"),
    review_pii: F.t("hygiene.fix_review_pii", "Проверить персональные данные: {kinds}"),
    revoke_secret: F.t(
      "hygiene.fix_revoke_secret",
      "Отозвать/сменить ключи: {kinds} и удалить их из документа",
    ),
    resign_after_cleaning: F.t(
      "hygiene.fix_resign_after_cleaning",
      "Подписать чистую копию заново, если нужна подпись",
    ),
    decrypt_to_assess: F.t("hygiene.fix_decrypt_to_assess", "Снять шифрование для полной проверки"),
    export_and_clean: F.t(
      "hygiene.fix_export_and_clean",
      "Формат не очищается здесь: экспортируйте в PDF/ODF/DOCX и очистите",
    ),
  });
  const WARN = () => ({
    signature_removed: F.t(
      "hygiene.warn_signature_removed",
      "Цифровая подпись снята ({count}). Чистая копия не подписана: при необходимости подпишите её заново.",
    ),
    revisions_collapsed: F.t(
      "hygiene.warn_revisions_collapsed",
      "Удалены предыдущие ревизии PDF ({count}); старый текст и метаданные больше не восстанавливаются.",
    ),
    javascript_removed: F.t("hygiene.warn_javascript_removed", "Удалены скрипты и автодействия ({count})."),
    embedded_files_removed: F.t("hygiene.warn_embedded_files_removed", "Удалены вложенные файлы ({count})."),
    embedded_files_kept: F.t(
      "hygiene.warn_embedded_files_kept",
      "Вложенные файлы оставлены по вашему выбору. У них могут быть свои метаданные.",
    ),
    annotation_authors_removed: F.t(
      "hygiene.warn_annotation_authors_removed",
      "Удалены авторы комментариев и правок ({count}); текст комментариев сохранён.",
    ),
    thumbnail_removed: F.t("hygiene.warn_thumbnail_removed", "Удалена миниатюра документа."),
    versions_removed: F.t("hygiene.warn_versions_removed", "Удалены сохранённые версии документа ({count})."),
    embedded_object_kept: F.t(
      "hygiene.warn_embedded_object_kept",
      "Встроенный объект «{name}» оставлен без изменений. Он может содержать метаданные.",
    ),
    encrypted_content_kept: F.t(
      "hygiene.warn_encrypted_content_kept",
      "Документ зашифрован: зашифрованные части оставлены как есть.",
    ),
  });
  const FIELD = () => ({
    author: F.t("hygiene.field_author", "Автор"),
    company: F.t("hygiene.field_company", "Организация"),
    manager: F.t("hygiene.field_manager", "Руководитель"),
    title: F.t("hygiene.field_title", "Заголовок"),
    subject: F.t("hygiene.field_subject", "Тема"),
    keywords: F.t("hygiene.field_keywords", "Ключевые слова"),
    created: F.t("hygiene.field_created", "Создан"),
    modified: F.t("hygiene.field_modified", "Изменён"),
    printed: F.t("hygiene.field_printed", "Напечатан"),
    software: F.t("hygiene.field_software", "Программа"),
    producer: "PDF Producer",
    creator: "PDF Creator",
    printer: F.t("hygiene.field_printer", "Принтер"),
    paths: F.t("hygiene.field_paths", "Пути"),
    "content.paths": F.t("hygiene.field_content_paths", "Пути в тексте"),
    gps: "GPS",
    camera: F.t("hygiene.field_camera", "Камера"),
    thumbnail: F.t("hygiene.field_thumbnail", "Миниатюра"),
    template: F.t("hygiene.field_template", "Шаблон"),
    "stats.pages": F.t("hygiene.field_stats_pages", "Страниц"),
    revisions: F.t("hygiene.field_revisions", "Ревизии"),
  });
  const fieldLabel = f => {
    if (FIELD()[f]) return FIELD()[f];
    const m = /^(people|xmp|fields|custom|stats)\.(.+)$/.exec(f);
    if (m)
      return (
        {
          people: F.t("hygiene.fgroup_people", "Люди"),
          xmp: "XMP",
          fields: F.t("hygiene.fgroup_fields", "Поле"),
          custom: F.t("hygiene.fgroup_custom", "Свойство"),
          stats: F.t("hygiene.fgroup_stats", "Статистика"),
        }[m[1]] +
        ": " +
        m[2]
      );
    return f;
  };
  const fill = (t, p) => String(t).replace(/\{(\w+)\}/g, (_, k) => (p[k] == null ? "" : p[k]));
  const params = i => ({
    samples: (i.samples || []).join(", "),
    count: i.count,
    kinds: ((i.fix && i.fix.params) || {}).kinds || "",
    pages: ((i.fix && i.fix.params) || {}).pages || "",
  });
  const issueText = i => fill(ISSUE()[i.code] || i.code, params(i)).replace(/:\s*$/, "");
  const fixText = f => fill(FIX()[f.code] || f.code, f.params || {}).replace(/\s*\(\)/, "");
  const warnText = w => fill(WARN()[w.code] || w.code, w);
  const SEV = { crit: "crit", high: "high", warn: "warn", low: "low", info: "info" };
  const gradeBadge = (g, big) =>
    g
      ? `<span class="hy-g g-${esc(g)} ${big ? "big" : ""}" role="img" aria-label="${esc(F.t("hygiene.grade_aria", { g }, "Грейд гигиены {g}"))}">${esc(g)}</span>`
      : `<span class="hy-g g-none" aria-label="${esc(F.t("hygiene.no_grade", "Нет грейда"))}">-</span>`;

  // ================= state =================
  const H = (F.state.hyg = F.state.hyg || {
    opts: { remove_embedded_files: true, remove_javascript: true, remove_annotation_authors: true },
    results: [],
    back: null,
    showAll: false,
    shared: [],
    rep: {},
    pending: false,
  });

  // Grades of project documents (hygiene_get { ids }), cached per project + ids, dropped on data changes.
  const CACHE = new Map();
  function forIds(ids) {
    const pid = F.db && F.db.project && F.db.project.id;
    if (!pid || !ids || !ids.length || !F.api.hygiene_get) return null;
    const key = pid + "|" + ids.join(",");
    if (CACHE.has(key)) return CACHE.get(key);
    CACHE.set(key, null);
    F.api.hygiene_get({ ids }).then(
      r => {
        CACHE.set(key, r);
        F.render(true);
      },
      e => CACHE.set(key, { error: e.message || String(e), docs: [], set: null }),
    );
    return null;
  }
  F.on("db", e => {
    if (e && (e.kind === "docs" || e.kind === "project" || e.kind === "reset")) CACHE.clear();
  });

  // ================= building blocks =================
  function optionsHtml(signed) {
    const row = (k, t, s) =>
      `<div class="row hy-opt">${ui.leadIcon(k === "remove_javascript" ? "st-code" : k === "remove_embedded_files" ? "folder" : "user")}<div class="body"><div class="t">${esc(t)}</div><div class="s">${esc(s)}</div></div>${ui.toggle(H.opts[k], "hy-opt:" + k, `aria-label="${esc(t)}"`)}</div>`;
    return `${ui.secH(F.t("hygiene.before_clean", "Перед очисткой"))}
      ${signed ? `<div class="banner warn hy-sig">${ic("alert")}<div><b>${esc(F.t("hygiene.signed_head", "Среди файлов есть подписанные."))}</b> ${esc(F.t("hygiene.signed_text", "Любая очистка снимает цифровую подпись. Чистая копия будет без подписи. Подпишите её заново, если подпись нужна."))}</div></div>` : ""}
      <div class="list">${row("remove_embedded_files", F.t("hygiene.opt_embedded", "Удалять вложения"), F.t("hygiene.opt_embedded_sub", "Файлы внутри PDF: у них свои метаданные"))}${row("remove_javascript", F.t("hygiene.opt_js", "Удалять скрипты"), F.t("hygiene.opt_js_sub", "JavaScript и автодействия в PDF"))}${row("remove_annotation_authors", F.t("hygiene.opt_authors", "Удалять авторов комментариев"), F.t("hygiene.opt_authors_sub", "Текст комментариев останется"))}</div>`;
  }
  // Fix steps without duplicates: automatic ones ("the cleaner fixes it") first, manual ones after.
  function stepsHtml(rep) {
    if (!rep || !(rep.issues || []).length) return "";
    const seen = new Set(),
      auto = [],
      manual = [];
    rep.issues.forEach(i => {
      if (!i.fix || seen.has(i.fix.code)) return;
      seen.add(i.fix.code);
      (i.fix.auto ? auto : manual).push(i.fix);
    });
    const li = (f, a) =>
      `<li class="${a ? "auto" : "man"}">${ic(a ? "check" : "alert")}<span>${esc(fixText(f))}${a ? ` <small>${esc(F.t("hygiene.auto_fix", "исправит очистка"))}</small>` : ""}</span></li>`;
    return `<ul class="hy-steps" aria-label="${esc(F.t("hygiene.steps_aria", "Шаги исправления"))}">${auto.map(f => li(f, true)).join("")}${manual.map(f => li(f, false)).join("")}</ul>`;
  }
  // Top issues by severity; "signed" / "encrypted" are neutral notes shown above them, outside the limit.
  function issuesHtml(rep, n) {
    const lim = n || 3;
    const notes = (rep.issues || []).filter(i => i.code === "signed" || i.code === "encrypted");
    const list = (rep.issues || []).filter(i => i.severity !== "info");
    const top = notes
      .map(i => `<p class="hy-note">${ic("info")}<span>${esc(issueText(i))}</span></p>`)
      .join("");
    if (!list.length)
      return `${top}<p class="hy-none">${ic("check")}${esc(F.t("hygiene.none", "Метаданных, которые выдают людей и инфраструктуру, не найдено."))}</p>`;
    return `${top}<ul class="hy-iss">${list
      .slice(0, lim)
      .map(i => `<li class="sev-${SEV[i.severity] || "low"}"><i></i><span>${esc(issueText(i))}</span></li>`)
      .join(
        "",
      )}${list.length > lim ? `<li class="more">${esc(F.t("hygiene.more", { n: list.length - lim }, "и ещё {n}"))}</li>` : ""}</ul>`;
  }
  const gradeHead = rep =>
    `<div class="hy-gh">${gradeBadge(rep.grade)}<span class="hy-sc">${rep.score}/100</span>${rep.cleanable ? "" : `<span class="pill mute">${esc(F.t("hygiene.not_cleanable", "не очищается"))}</span>`}</div>`;
  function setHtml(set) {
    if (!set || !set.documents) return "";
    const by = set.by_grade || {};
    const max = Math.max(1, ...Object.values(by));
    return `<div class="card pad hy-set">
      <div class="hy-set-h">${gradeBadge(set.grade, true)}<div><b>${esc(F.t("hygiene.set_title", "Гигиена набора"))}</b><span class="s">${esc(F.plural(set.documents, F.t("hygiene.file_one", "файл"), F.t("hygiene.file_few", "файла"), F.t("hygiene.file_many", "файлов")))} · ${esc(F.t("hygiene.set_stats", { score: set.score, worst: set.worst || "-" }, "средний балл {score} · худший {worst}"))}</span></div></div>
      <div class="hy-dist" aria-label="${esc(F.t("hygiene.dist_aria", "Распределение по грейдам"))}">${["A", "B", "C", "D", "E", "F"].map(g => `<span><i class="g-${g}" style="height:${Math.round(((by[g] || 0) / max) * 100)}%"></i><b>${by[g] || 0}</b><small>${g}</small></span>`).join("")}</div>
      ${
        (set.issues || []).length
          ? `<div class="hy-freq"><small>${esc(F.t("hygiene.most_common", "Чаще всего"))}</small>${set.issues
              .slice(0, 3)
              .map(
                i =>
                  `<span class="chip sev-${SEV[i.severity] || "low"}">${esc(issueText({ ...i, samples: [], fix: {} }).replace(/\s*\(\)|:\s*$/g, ""))} · ${i.documents}</span>`,
              )
              .join("")}</div>`
          : ""
      }
      ${F.helpBtn ? F.helpBtn("hygiene", F.t("hygiene.help_grade", "Как считается грейд")) : ""}
    </div>`;
  }

  // ================= before / after =================
  function verdict(r) {
    const v = r.verify;
    if (v && v.clean && r.clean)
      return `<div class="banner ok hy-verdict">${ic("check")}<div><b>${esc(F.t("hygiene.verdict_ok", "0 метаданных · файл валиден"))}</b>${v.pages_before != null ? ` <span class="s">${esc(F.t("hygiene.pages", { a: v.pages_before, b: v.pages_after ?? "?" }, "страниц: {a} → {b}"))}${v.text_preserved ? " · " + esc(F.t("hygiene.text_kept", "текст не изменён")) : ""}</span>` : ""}</div></div>`;
    if (v && !v.valid)
      return `<div class="banner bad hy-verdict">${ic("alert")}<div><b>${esc(F.t("hygiene.verdict_bad", "Копия не прошла самопроверку."))}</b> ${esc(v.error || "")} ${esc(F.t("hygiene.verdict_bad_tail", "Не публикуйте её."))}</div></div>`;
    const man = (r.manual || []).map(m =>
      m.kind === "secret"
        ? esc(
            F.t(
              "hygiene.manual_secret",
              { where: F.ftext ? F.ftext.field(m.where, "secret") : m.where },
              "Секрет в тексте ({where}), уберите вручную",
            ),
          )
        : m.kind === "remaining"
          ? esc(m.where)
          : esc(m.where),
    );
    return `<div class="banner warn hy-verdict">${ic("alert")}<div><b>${esc(v ? F.tp("hygiene.left_many", v.remaining, { n: v.remaining }, "Осталось: {n} поле метаданных|Осталось: {n} поля метаданных|Осталось: {n} полей метаданных") : F.t("hygiene.not_cleaned", "Очистка не выполнена"))}${man.length && v && !v.remaining ? " · " + esc(F.t("hygiene.need_manual", "нужно вручную")) : ""}</b>${man.length ? `<ul>${man.map(x => `<li>${x}</li>`).join("")}</ul>` : ""}</div></div>`;
  }
  function diffHtml(r, i) {
    const ch = ((r.verify && r.verify.changes) || []).filter(
      c => H.showAll || (c.sensitive && c.change !== "kept"),
    );
    const total = ((r.verify && r.verify.changes) || []).length;
    if (!total) return "";
    const CH = {
      removed: [F.t("hygiene.ch_removed", "удалено"), "bad"],
      changed: [F.t("hygiene.ch_changed", "изменено"), "warn"],
      kept: [F.t("hygiene.ch_kept", "оставлено"), "mute"],
      added: [F.t("hygiene.ch_added", "добавлено"), "info"],
    };
    return `${ui.secH(F.t("hygiene.changed_title", "Что изменилось"), F.t("hygiene.n_of", { n: ch.length, total }, "{n} из {total}"), `<button class="sec-a hy-all" data-act="hy-all">${esc(H.showAll ? F.t("hygiene.only_important", "Только важное") : F.t("hygiene.show_all", "Показать всё"))}</button>`)}
      <div class="list hy-diff" data-i="${i}">${ch
        .map(
          c =>
            `<div class="row hy-d ${c.change}"><div class="body"><div class="t">${esc(fieldLabel(c.field))} <span class="pill ${CH[c.change][1]}">${esc(CH[c.change][0])}</span></div><div class="hy-ba"><span class="k">${esc(F.t("hygiene.was", "было"))}</span><span class="mono v">${esc(c.before ?? "-")}</span></div><div class="hy-ba"><span class="k">${esc(F.t("hygiene.now", "стало"))}</span><span class="mono v ${c.change === "removed" ? "gone" : ""}">${c.change === "removed" ? "-" : esc(c.after ?? c.before ?? "-")}</span></div></div></div>`,
        )
        .join("")}</div>`;
  }
  function resultCard(r, i) {
    const warns = (r.verify && r.verify.warnings) || [];
    const sig = warns.filter(w => w.code === "signature_removed");
    const other = warns.filter(w => w.code !== "signature_removed");
    return `<div class="card pad hy-res">
      <div class="hy-res-h"><b class="hy-fn">${esc(r.name)}</b>${r.size ? `<span class="s">${Math.max(1, Math.round(r.size / 1024))} ${esc(F.t("hygiene.kb", "КБ"))}</span>` : ""}</div>
      <div class="hy-ba-g" aria-label="${esc(F.t("hygiene.before_after_aria", "Грейд до и после"))}">${gradeBadge(r.grade_before)}<span class="hy-arr">→</span>${gradeBadge(r.grade_after)}<span class="s">${esc(F.t("hygiene.grade_change", { a: r.grade_before || "-", b: r.grade_after || "-" }, "было {a} → стало {b}"))}</span></div>
      ${sig.map(w => `<div class="banner warn hy-sig">${ic("alert")}<div><b>${esc(F.t("hygiene.sig_removed", "Подпись снята."))}</b> ${esc(warnText(w))}</div></div>`).join("")}
      ${verdict(r)}
      ${other.length ? `<ul class="hy-warn">${other.map(w => `<li>${ic("info")}<span>${esc(warnText(w))}</span></li>`).join("")}</ul>` : ""}
      ${diffHtml(r, i)}
      <div class="btnrow hy-act">${r.path ? `<button class="btn primary" data-act="hy-share:${i}">${ic("share")}${esc(F.t("hygiene.share_clean", "Поделиться чистой копией"))}</button><button class="btn tonal" data-act="hy-save:${i}">${ic("download")}${esc(F.t("report.pdf.save", "В «Загрузки»"))}</button>` : `<span class="s">${esc(F.t("hygiene.no_copy", "Чистая копия не создана."))}</span>`}</div>
    </div>`;
  }
  F.route("/clean/result", {
    title: () => F.t("hygiene.result_title", "До / После"),
    sub: () => F.t("hygiene.result_sub", "Самопроверка чистой копии"),
    back: true,
    nav: false,
    hideMini: true,
    render: () => {
      if (!H.results.length)
        return ui.empty({
          icon: "eraser",
          title: F.t("hygiene.no_results", "Нет результатов очистки"),
          text: F.t("hygiene.no_results_text", "Очистите файл на экране проверки."),
        });
      const ok = H.results.filter(r => r.clean && r.verify && r.verify.clean).length;
      return `<div class="card pad hy-sum">${ic("shield")}<span>${esc(F.t("hygiene.sum_copies", "Очищено копий:"))} <b>${H.results.length}</b> · ${esc(F.t("hygiene.sum_clean", "полностью чистых:"))} <b>${ok}</b>. ${esc(F.t("hygiene.sum_tail", "Оригиналы не изменены, копии лежат в приватной папке приложения."))}</span></div>
        ${H.results.map(resultCard).join("")}`;
    },
  });
  // Shares a clean copy through the native share sheet; a copy that is not fully clean asks first.
  function share(i, force) {
    const r = H.results[+i];
    if (!r || !r.path) return;
    if (!force && !(r.clean && r.verify && r.verify.clean)) {
      F.sheet({
        title: F.t("hygiene.dirty_title", "Копия не полностью чистая"),
        html: `<p class="lead">${esc(F.t("hygiene.dirty_text", "В копии остались данные, которые очистка не убирает автоматически (секреты в тексте, непринятые правки или поля, которые не удалось удалить). Поделиться всё равно?"))}</p>`,
        footer: `<button class="btn" data-act="sheet-close">${esc(F.t("common.cancel", "Отмена"))}</button><button class="btn primary" data-act="hy-share-force:${i}">${esc(F.t("hygiene.share", "Поделиться"))}</button>`,
      });
      return;
    }
    F.closeSheet && F.closeSheet();
    F.api.platform_share({ path: r.path, name: r.name }).then(
      () => F.snack(F.t("hygiene.share_opened", "Открыт системный диалог «Поделиться»")),
      e => F.snack(F.t("hygiene.share_fail", { err: e.message || e }, "Не удалось поделиться: {err}")),
    );
  }
  Object.assign(F.actions, {
    "hy-opt": k => {
      H.opts[k] = !H.opts[k];
      F.render(true);
    },
    "hy-all": () => {
      H.showAll = !H.showAll;
      F.render(true);
    },
    "hy-share": i => share(i, false),
    "hy-share-force": i => share(i, true),
    "hy-save": i => {
      const r = H.results[+i];
      if (!r || !r.path) return;
      F.api.platform_save({ path: r.path, name: r.name }).then(
        x =>
          F.snack(
            x && x.ok
              ? F.t("hygiene.saved", "Сохранено в «Загрузки»")
              : F.t("hygiene.not_saved", "Не сохранено"),
          ),
        e => F.snack(F.t("hygiene.save_fail", { err: e.message || e }, "Не удалось сохранить: {err}")),
      );
    },
  });
  function showResults(list, back) {
    H.results = list || [];
    H.back = back || null;
    H.showAll = false;
    F.go("/clean/result");
  }

  // ================= files shared into the app (Android share sheet) =================
  // platform_shared_files returns the files the native side copied into the private cache (limits on count
  // and size, names without paths). They are graded and cleaned in place: no project, no network.
  function sharedRep(f) {
    if (H.rep[f.path] !== undefined) return H.rep[f.path];
    H.rep[f.path] = null;
    F.api.hygiene_get({ path: f.path, name: f.name }).then(
      r => {
        H.rep[f.path] = (r && r.docs && r.docs[0]) || { error: F.t("hygiene.no_answer", "нет ответа") };
        F.render(true);
      },
      e => {
        H.rep[f.path] = { error: e.message || String(e) };
        F.render(true);
      },
    );
    return null;
  }
  F.route("/shared", {
    title: () => F.t("hygiene.shared_title", "Проверка файла"),
    sub: () => F.t("hygiene.shared_sub", "Поделились с FOCA-rs"),
    back: true,
    nav: false,
    hideMini: true,
    render: () => {
      if (!H.shared.length)
        return ui.empty({
          icon: "share",
          title: F.t("hygiene.shared_none", "Нет полученных файлов"),
          text: F.t(
            "hygiene.shared_none_text",
            "Выберите «Поделиться → FOCA-rs» в Telegram, почте или файловом менеджере. Файл откроется здесь для проверки и очистки.",
          ),
        });
      const reps = H.shared.map(sharedRep);
      const ready = reps.filter(r => r && !r.error);
      const signed = ready.some(r => (r.issues || []).some(i => i.code === "signed"));
      return `<div class="card pad hy-sum">${ic("shield")}<span>${esc(F.t("hygiene.shared_note", "Файлы проверяются на устройстве и никуда не отправляются. Проект не создаётся."))}</span></div>
        ${H.skipped ? `<div class="banner info">${ic("info")}<div>${esc(F.t("hygiene.skipped", { n: H.skipped }, "Пропущено файлов: {n} (не документ, больше лимита или слишком много файлов)."))}</div></div>` : ""}
        ${H.shared
          .map((f, i) => {
            const r = reps[i];
            if (!r) return `<div class="card pad hy-file">${ui.skeletonList(1)}</div>`;
            if (r.error)
              return `<div class="card pad hy-file"><div class="hy-fh"><b class="hy-fn">${esc(f.name)}</b></div><div class="banner bad">${ic("alert")}<div>${esc(F.t("hygiene.parse_fail", { err: r.error }, "Файл не разобран: {err}"))}</div></div></div>`;
            return `<div class="card pad hy-file"><div class="hy-fh"><span class="ext ${esc(r.ext)}">${esc(r.ext || "?")}</span><b class="hy-fn">${esc(f.name)}</b></div>${gradeHead(r)}${issuesHtml(r, 5)}${stepsHtml(r)}${r.cleanable ? `<div class="btnrow"><button class="btn primary" data-act="hy-sh-clean:${i}">${ic("eraser")}${esc(F.t("hygiene.clean", "Очистить"))}</button></div>` : ""}</div>`;
          })
          .join("")}
        ${ready.some(r => r.cleanable) ? optionsHtml(signed) : ""}
        ${ready.filter(r => r.cleanable).length > 1 ? `<div class="btnrow"><button class="btn primary block" data-act="hy-sh-clean:all">${ic("eraser")}${esc(F.t("hygiene.clean_all", "Очистить все"))}</button></div>` : ""}
        ${F.helpBtn ? `<div class="btnrow">${F.helpBtn("share-target", F.t("hygiene.help_share", "Поделиться в FOCA-rs"))}</div>` : ""}`;
    },
  });
  F.actions["hy-sh-clean"] = arg => {
    const list =
      arg === "all"
        ? H.shared.filter(f => (H.rep[f.path] || {}).cleanable)
        : [H.shared[+arg]].filter(Boolean);
    if (!list.length) return;
    F.snack(F.t("hygiene.cleaning", "Очистка…"));
    list
      .reduce(
        (p, f) =>
          p.then(acc =>
            F.api.doc_clean_file(f.path, f.name, { ...H.opts }).then(
              r => acc.concat(r.cleaned || []),
              e =>
                acc.concat([
                  {
                    name: f.name,
                    path: null,
                    clean: false,
                    verify: null,
                    manual: [{ kind: "format", where: e.message || String(e) }],
                  },
                ]),
            ),
          ),
        Promise.resolve([]),
      )
      .then(res => showResults(res, "/shared"));
  };
  // A new batch of shared files: shown right away unless the lock or onboarding screen is on top (then after
  // it is left, see the route listener).
  const BLOCKING = ["/lock", "/terms", "/welcome", "/permissions"];
  function receive(r) {
    const files = (r && r.files) || [];
    if (!files.length) return;
    H.shared = files;
    H.skipped = (r && r.skipped) || 0;
    H.rep = {};
    if (BLOCKING.includes(F.current && F.current())) H.pending = true;
    else F.go("/shared");
  }
  F.on("route", ({ path }) => {
    if (H.pending && !BLOCKING.includes(path)) {
      H.pending = false;
      setTimeout(() => F.go("/shared"), 0);
    }
  });
  function pull() {
    if (!F.api.platform_shared_files) return;
    F.api.platform_shared_files().then(receive, () => {});
  }
  // Native event "shared" (onNewIntent while the app is open) and a pull at start (cold start: the intent
  // arrived before the WebView was ready).
  F.on("shared", pull);
  let tries = 0;
  const first = () => {
    if (F.current && F.current()) pull();
    else if (tries++ < 40) setTimeout(first, 250);
  };
  window.addEventListener("load", () => setTimeout(first, 300));

  F.hyg = {
    gradeBadge,
    gradeHead,
    issuesHtml,
    stepsHtml,
    setHtml,
    optionsHtml,
    forIds,
    opts: () => ({ ...H.opts }),
    showResults,
    receive,
    issueText,
    fixText,
  };
})();
