/*
 * Settings → Site crawl: limits of the crawler (depth, pages, time, rendered app pages), files on
 * public external storage linked from the site, images for EXIF and links inside downloaded
 * documents. Data: settings.crawl (docs/API.md). The wizard can override depth, pages, time,
 * storage and "continue crawl" for one scan.
 */
(function () {
  const F = window.FOCA;
  const { ui, esc } = F;
  const cr = () => (F.db.settings || {}).crawl || {};
  const DEF = {
    max_depth: 5,
    max_pages: 1000,
    max_minutes: 20,
    max_rendered: 30,
    max_images: 300,
    max_image_mb: 200,
    doc_link_depth: 2,
  };
  const val = k => (cr()[k] != null ? +cr()[k] : DEF[k]);
  const flag = (k, def) => (cr()[k] != null ? !!cr()[k] : def);
  const save = patch => {
    const s = F.db.settings || (F.db.settings = {});
    s.crawl = { ...(s.crawl || {}), ...patch };
    return F.api.settings_set({ crawl: patch });
  };
  /** Numeric input with ± buttons (F.numField from help.js); no hard caps, ui/js/limits.js warns. */
  const nf = (k, label, unit, note, step = 1) =>
    F.numField({
      id: "cr-" + k,
      label,
      unit,
      lim: "crawl." + k,
      step,
      note,
      help: "crawler",
      get: () => val(k),
      set: v => save({ [k]: v }),
    });
  const toggleRow = (k, def, icon, title, sub) =>
    ui.row({
      lead: ui.leadIcon(icon, flag(k, def) ? "var(--accent)" : ""),
      title: esc(title),
      sub: esc(sub),
      tail: ui.toggle(flag(k, def), `cr-t:${k}:${def ? 1 : 0}`, `aria-label="${esc(title)}"`),
    });
  function render() {
    return `
      <p class="lead st-lead">${esc(F.t("crawl.lead", "Обход идёт в профилях «Стандартный» и «Полный» по хостам скоупа: страницы, sitemap, документы и файлы, на которые ссылается сайт. Пассивный профиль сайт не обходит."))}</p>
      ${ui.secH(F.t("crawl.limits", "Лимиты обхода"))}
      <div class="card nfs st-nfs">
        ${nf("max_depth", F.t("crawl.nf_depth", "Глубина, уровней"), "", F.t("crawl.nf_depth_note", "сколько переходов по ссылкам от главной"))}
        ${nf("max_pages", F.t("crawl.nf_pages", "Страниц за скан, до"), "", F.t("crawl.nf_pages_note", "остаток продолжится в следующем скане"), 50)}
        ${nf("max_minutes", F.t("crawl.nf_minutes", "Время обхода, до"), F.t("crawl.nf_min", "мин"), F.t("crawl.nf_minutes_note", "потом обход останавливается сам"))}
        ${nf("max_rendered", F.t("crawl.nf_rendered", "Страниц-приложений через браузер"), "", F.t("crawl.nf_rendered_note", "сайты на React, Flutter и подобном"))}
      </div>
      <div class="list">${toggleRow("resume", true, "history", F.t("crawl.resume", "Продолжать незавершённый обход"), F.t("crawl.resume_sub", "Следующий скан начнёт с непройденных страниц"))}${toggleRow("nofollow", false, "filter", F.t("crawl.nofollow", "Учитывать rel=nofollow"), F.t("crawl.nofollow_sub", "Не переходить по ссылкам, которые сайт просит не обходить"))}</div>
      <p class="fhint">${esc(F.t("crawl.traps_hint", "Ловушки (календари, бесконечные фильтры, параметры сессий) обходятся по шаблону с лимитом; ссылки выхода и удаления не открываются. Если сайт отвечает 429/503, темп снижается, а при повторах обход хоста останавливается."))}</p>
      ${ui.secH(F.t("crawl.found", "Что собирать"))}
      <div class="list">${toggleRow("storage", true, "folder", F.t("crawl.storage", "Файлы во внешних хранилищах по ссылкам с сайта"), F.t("crawl.storage_sub", "Google Drive, Docs, OneDrive, Dropbox, SharePoint: только файлы, на которые ссылается сайт"))}${toggleRow("images", true, "camera", F.t("crawl.images", "Фотографии для EXIF"), F.t("crawl.images_sub", "JPEG, HEIC, TIFF и PNG с сайта; значки и миниатюры пропускаются"))}${toggleRow("doc_links", true, "link", F.t("crawl.doc_links", "Ссылки внутри документов"), F.t("crawl.doc_links_sub", "Документы и файлы хранилищ, на которые ссылаются скачанные документы"))}</div>
      <div class="card nfs st-nfs">
        ${nf("max_images", F.t("crawl.nf_images", "Изображений за скан, до"), "", F.t("crawl.nf_images_note", "сначала фото с камер"), 10)}
        ${nf("max_image_mb", F.t("crawl.nf_image_mb", "Трафик на изображения, до"), F.t("crawl.nf_mb", "МБ"), F.t("crawl.nf_image_mb_note", "не больше лимита мобильного трафика"), 10)}
        ${nf("doc_link_depth", F.t("crawl.nf_doc_depth", "Глубина ссылок из документов"), "", F.t("crawl.nf_doc_depth_note", "документ из документа из документа…"))}
      </div>
      <p class="fhint">${esc(F.t("crawl.storage_hint", "У каждого документа видно, откуда он: страница со ссылкой, документ или экспорт Google. Закрытые файлы хранилищ отмечаются как закрытые, это не ошибка."))}</p>`;
  }
  F.route("/settings/crawl", {
    title: () => F.t("crawl.title", "Обход сайта"),
    sub: () => F.t("crawl.sub", "Краулер, хранилища, изображения"),
    nav: false,
    back: true,
    actions: [],
    hideMini: true,
    live: (kind, ev) => kind === "db" && ev && ev.kind === "settings",
    render,
    mount: page => page.classList.add("st-pg"),
  });
  F.actions["cr-t"] = a => {
    const [k, def] = a.split(":");
    save({ [k]: !flag(k, def === "1") });
    F.render(true);
  };
})();
